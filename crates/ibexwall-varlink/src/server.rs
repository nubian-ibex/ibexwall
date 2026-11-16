// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! varlink server: accept loop, per-connection task, dispatch to a
//! handler with streaming replies, plus the org.varlink.service
//! bootstrap methods.

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::sync::Arc;

use serde_json::Value;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};

use crate::wire::{self, Reply as WireReply, Request, TransportError, VarlinkError};

/// One method call handed to a [`Handler`], including the connection's
/// peer credentials (SO_PEERCRED, ADR-0025).
#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub parameters: Value,
    pub more: bool,
    pub peer: Peer,
    /// Fires when the client hangs up or half-closes. A handler must not
    /// abandon work already under way for it (an Apply stopped halfway
    /// leaves the transaction `applying`); only waits that exist for the
    /// person at the other end, like a polkit password dialog, may stop.
    pub cancel: Cancel,
}

/// Receiving side of a call's hang-up signal.
#[derive(Debug, Clone)]
pub struct Cancel(tokio::sync::watch::Receiver<bool>);

impl Cancel {
    /// A signal and the sender that fires it.
    pub fn pair() -> (tokio::sync::watch::Sender<bool>, Self) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        (tx, Self(rx))
    }

    /// Completes once the client is gone.
    pub async fn cancelled(&self) {
        let mut rx = self.0.clone();
        // A dropped sender also means the connection is gone.
        let _ = rx.wait_for(|gone| *gone).await;
    }
}

/// Unix credentials of the connected peer, captured once at accept:
/// SO_PEERCRED gives the uid and pid of the process that made the
/// connection, and the start time is read from /proc at the same moment.
/// Reading the start time later (per call) would describe whatever
/// process holds the pid by then, not the one on the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Peer {
    pub uid: u32,
    pub pid: u32,
    /// Field 22 of `/proc/<pid>/stat`, bound to this connection. Zero
    /// when it could not be read; authorization fails closed on zero.
    pub start_time: u64,
}

/// Field 22 (starttime) of a `/proc/<pid>/stat` line. The comm field can
/// contain spaces and parentheses, so parsing starts after the last ')';
/// from there, starttime is the 20th token (the first is field 3,
/// state).
fn start_time_from_stat(stat: &str) -> u64 {
    let tail = stat.rsplit_once(')').map(|(_, tail)| tail).unwrap_or("");
    tail.split_whitespace()
        .nth(19)
        .and_then(|token| token.parse().ok())
        .unwrap_or(0)
}

fn proc_start_time(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map(|stat| start_time_from_stat(&stat))
        .unwrap_or(0)
}

/// A reply pushed by the handler (result frame or error frame).
#[derive(Debug, Clone)]
pub struct Reply {
    pub parameters: Value,
    pub continues: bool,
    pub error: Option<String>,
}

impl Reply {
    pub fn result(parameters: Value) -> Self {
        Self {
            parameters,
            continues: false,
            error: None,
        }
    }

    pub fn result_continues(parameters: Value) -> Self {
        Self {
            parameters,
            continues: true,
            error: None,
        }
    }

    pub fn error(name: impl Into<String>, parameters: Value) -> Self {
        Self {
            parameters,
            continues: false,
            error: Some(name.into()),
        }
    }

    fn to_wire(&self) -> WireReply {
        WireReply {
            parameters: self.parameters.clone(),
            continues: self.continues,
            error: self.error.clone(),
        }
    }
}

/// Interface metadata served for `org.varlink.service.*`.
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub url: String,
    /// interface name -> varlink IDL text (embedded from `spec/idl/`).
    pub interfaces: HashMap<String, String>,
}

/// Application dispatch. Push replies into `out`; push exactly one
/// non-continues reply for a call, or N-1 continues + one final
/// non-continues reply for a stream. Errors are pushed as a reply with
/// `error` set. Dropping the sender ends the reply sequence.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, call: Call, out: mpsc::Sender<Reply>) -> BoxHandle;
}

/// Tiny alias so the trait can stay object-safe without a futures dep.
pub mod futures_handle {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Pinned boxed future returned by [`crate::Handler::handle`].
    pub struct BoxHandle(Pin<Box<dyn Future<Output = ()> + Send>>);

    impl BoxHandle {
        pub fn new<F: Future<Output = ()> + Send + 'static>(fut: F) -> Self {
            Self(Box::pin(fut))
        }
    }

    impl Future for BoxHandle {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            self.0.as_mut().poll(cx)
        }
    }
}

use futures_handle::BoxHandle;

/// Resource limits for the accept loop. The defaults are generous for
/// the real clients (the app, the agent, the tray and short CLI calls)
/// and hostile to a local socket flood.
#[derive(Debug, Clone)]
pub struct ServeLimits {
    /// Concurrent connections kept open; extras are closed at accept.
    pub max_connections: usize,
    /// How long a connection may stay silent before its first complete
    /// frame.
    pub first_frame: std::time::Duration,
    /// How long an open connection may sit between requests. Long-lived
    /// subscriptions are inside a call, so they are not affected.
    pub idle: std::time::Duration,
    /// Concurrent connections one uid may hold, so a single local user
    /// cannot take every slot.
    pub max_per_uid: usize,
    /// Largest request frame accepted; replies are not limited by this.
    pub max_request_bytes: usize,
}

impl Default for ServeLimits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            first_frame: std::time::Duration::from_secs(120),
            idle: std::time::Duration::from_secs(600),
            max_per_uid: 16,
            max_request_bytes: 1024 * 1024,
        }
    }
}

// Linux errno values (there is no stable ErrorKind for them).
const EMFILE: i32 = 24;
const ENFILE: i32 = 23;

/// Serves `listener` forever with `info` and `handler`.
pub async fn serve(
    listener: UnixListener,
    info: ServiceInfo,
    handler: Arc<dyn Handler>,
) -> anyhow::Result<()> {
    serve_limited(listener, info, handler, ServeLimits::default()).await
}

/// Serves with explicit resource limits (tests use small ones).
pub async fn serve_limited(
    listener: UnixListener,
    info: ServiceInfo,
    handler: Arc<dyn Handler>,
    limits: ServeLimits,
) -> anyhow::Result<()> {
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let per_uid = Arc::new(std::sync::Mutex::new(HashMap::<u32, usize>::new()));
    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                // An exhausted file table is a local denial-of-service
                // pattern, not a reason for the daemon to die: back off
                // and keep serving. A reset connection is noise.
                let code = error.raw_os_error();
                if matches!(error.kind(), std::io::ErrorKind::ConnectionAborted)
                    || code == Some(EMFILE)
                    || code == Some(ENFILE)
                {
                    tracing::warn!(%error, "accept failed; backing off");
                    if code.is_some() {
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                    continue;
                }
                return Err(error.into());
            }
        };
        if active.fetch_add(1, std::sync::atomic::Ordering::AcqRel) >= limits.max_connections {
            active.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            // Dropping the stream closes it; the peer sees a short read.
            tracing::warn!("connection cap reached; closing an extra connection");
            continue;
        }
        // Unreadable credentials get no slot: `connection` refuses them too.
        let uid = rustix::net::sockopt::socket_peercred(&stream)
            .map(|cred| cred.uid.as_raw())
            .ok();
        if let Some(uid) = uid {
            let mut held = per_uid.lock().unwrap_or_else(|e| e.into_inner());
            let count = held.entry(uid).or_insert(0);
            if *count >= limits.max_per_uid {
                drop(held);
                active.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                tracing::warn!(uid, "per-user connection cap reached; closing");
                continue;
            }
            *count += 1;
        }
        let limits_for_task = limits.clone();
        let guard = ConnectionGuard {
            active: Arc::clone(&active),
            per_uid: uid.map(|uid| (uid, Arc::clone(&per_uid))),
        };
        let info = info.clone();
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            let _guard = guard;
            if let Err(err) = connection(stream, info, handler, limits_for_task.clone()).await {
                tracing::debug!(error = %err, "varlink connection ended");
            }
        });
    }
}

/// Open connections per uid.
type UidSlots = Arc<std::sync::Mutex<HashMap<u32, usize>>>;

/// Returns the slot when the connection task ends.
struct ConnectionGuard {
    active: Arc<std::sync::atomic::AtomicUsize>,
    per_uid: Option<(u32, UidSlots)>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.active
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        if let Some((uid, held)) = &self.per_uid {
            let mut held = held.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(count) = held.get_mut(uid) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    held.remove(uid);
                }
            }
        }
    }
}

/// Serves on an already-listening fd (systemd socket activation:
/// `LISTEN_FDS=1`, the socket is fd 3).
pub async fn serve_with_fd(
    fd: OwnedFd,
    info: ServiceInfo,
    handler: Arc<dyn Handler>,
) -> anyhow::Result<()> {
    use tokio::net::UnixListener as TokioListener;
    let std_listener = std::os::unix::net::UnixListener::from(fd);
    std_listener.set_nonblocking(true)?;
    let listener = TokioListener::from_std(std_listener)?;
    serve(listener, info, handler).await
}

async fn connection(
    stream: UnixStream,
    info: ServiceInfo,
    handler: Arc<dyn Handler>,
    limits: ServeLimits,
) -> anyhow::Result<()> {
    // Fail closed: a connection whose credentials cannot be read gets no
    // default identity (least of all uid 0).
    let peer = rustix::net::sockopt::socket_peercred(&stream)
        .map(|cred| Peer {
            uid: cred.uid.as_raw(),
            pid: cred.pid.as_raw_pid().unsigned_abs(),
            start_time: proc_start_time(cred.pid.as_raw_pid().unsigned_abs()),
        })
        .map_err(|error| anyhow::anyhow!("reading the peer credentials: {error}"))?;
    let (mut reader, mut writer) = stream.into_split();
    // One read may deliver several frames; the framer buffers the rest.
    let mut framer = wire::Framer::with_limit(limits.max_request_bytes);
    let mut got_first = false;
    loop {
        let read = framer.read_message(&mut reader);
        let raw = if got_first {
            match tokio::time::timeout(limits.idle, read).await {
                Ok(outcome) => outcome,
                Err(_elapsed) => return Ok(()),
            }
        } else {
            // A connection that never completes a first frame only holds
            // a slot and buffer; past this deadline it is closed quietly.
            match tokio::time::timeout(limits.first_frame, read).await {
                Ok(outcome) => {
                    got_first = true;
                    outcome
                }
                Err(_elapsed) => return Ok(()),
            }
        };
        let raw = match raw {
            Ok(raw) => raw,
            Err(TransportError::Closed) => return Ok(()),
            Err(TransportError::TooLarge | TransportError::Malformed(_)) => {
                // Protocol violation: answer once, then drop the peer.
                let err = VarlinkError::new(crate::service_errors::INVALID_MESSAGE, Value::Null);
                wire::write_message(&mut writer, &err.to_reply()).await?;
                return Ok(());
            }
            Err(TransportError::Io(e)) => return Err(e.into()),
        };
        let request: Request = match serde_json::from_slice(&raw) {
            Ok(r) => r,
            Err(e) => {
                let err = VarlinkError::new(
                    crate::service_errors::INVALID_MESSAGE,
                    Value::String(e.to_string()),
                );
                wire::write_message(&mut writer, &err.to_reply()).await?;
                continue;
            }
        };

        // org.varlink.service bootstrap answers do not reach the app.
        if request.method.starts_with("org.varlink.service.") {
            if request.oneway {
                continue;
            }
            let reply = bootstrap(&info, &request);
            wire::write_message(&mut writer, &reply.to_wire()).await?;
            continue;
        }

        let (tx, rx) = mpsc::channel::<Reply>(16);
        let (hangup, cancel) = Cancel::pair();
        let call = Call {
            method: request.method.clone(),
            parameters: request.parameters.clone(),
            more: request.more,
            peer,
            cancel,
        };
        // The handler runs detached: a hang-up must not drop it halfway
        // through an Apply or Rollback. It ends by dropping `tx`.
        tokio::spawn(handler.handle(call, tx));
        let mut stream = ReceiverStream::new(rx);

        let mut wrote_any = false;
        let mut watch_peer = true;
        // For oneway calls the replies are discarded. The `if` guard
        // prevents polling the peer check again after it fired.
        loop {
            tokio::select! {
                // A client that hangs up (or half-closes) mid-call only
                // cancels what exists for it, a polkit password dialog
                // (ADR-0045). The handler keeps running; a half-closed
                // client may still read the reply, and for a gone one the
                // write below fails and ends the connection. Data instead
                // of a hang-up is the next request, left for the framer.
                closed = peer_closed(&reader), if watch_peer => {
                    watch_peer = false;
                    if closed {
                        let _ = hangup.send(true);
                    }
                }
                item = stream.next() => match item {
                    Some(reply) => {
                        wrote_any = true;
                        if !request.oneway {
                            wire::write_message(&mut writer, &reply.to_wire()).await?;
                        }
                        if !reply.continues {
                            break;
                        }
                    }
                    None => {
                        // Handler dropped the sender without a final
                        // frame; close the sequence defensively.
                        if !request.oneway && !wrote_any {
                            let err = VarlinkError::new(
                                crate::service_errors::METHOD_NOT_IMPLEMENTED,
                                Value::Null,
                            );
                            wire::write_message(&mut writer, &err.to_reply()).await?;
                        }
                        break;
                    }
                },
            }
        }
    }
}

/// Waits until the peer either sends more data (false) or hangs up
/// (true), without consuming anything: the check peeks one byte.
async fn peer_closed(reader: &tokio::net::unix::OwnedReadHalf) -> bool {
    let stream: &UnixStream = reader.as_ref();
    loop {
        if stream.readable().await.is_err() {
            return true;
        }
        let peeked = stream.try_io(tokio::io::Interest::READABLE, || {
            let mut byte = [0u8; 1];
            rustix::net::recv(
                stream,
                &mut byte[..],
                rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
            )
            .map(|(read, _)| read)
            .map_err(std::io::Error::from)
        });
        match peeked {
            Ok(0) => return true,
            Ok(_) => return false,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => return true,
        }
    }
}

fn bootstrap(info: &ServiceInfo, request: &Request) -> Reply {
    match request.method.as_str() {
        "org.varlink.service.GetInfo" => Reply::result(serde_json::json!({
            "vendor": info.vendor,
            "product": info.product,
            "version": info.version,
            "url": info.url,
            "interfaces": info.interfaces.keys().collect::<Vec<_>>(),
        })),
        "org.varlink.service.GetInterfaceDescription" => {
            let name = request.parameters.get("interface").and_then(Value::as_str);
            match name.and_then(|n| info.interfaces.get(n)) {
                Some(idl) => Reply::result(serde_json::json!({ "interface": idl })),
                None => {
                    let err = VarlinkError::invalid_parameter("interface");
                    Reply {
                        parameters: err.parameters,
                        continues: false,
                        error: Some(err.name),
                    }
                }
            }
        }
        other => {
            let err = VarlinkError::method_not_found(other);
            Reply {
                parameters: err.parameters,
                continues: false,
                error: Some(err.name),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client;
    use std::time::Duration;

    fn tmp_socket() -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        dir.join(format!("ibexwall-varlink-test-{}.sock", std::process::id()))
    }

    struct Echo;

    static WORK_FINISHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    static WAIT_DROPPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    fn test_info() -> ServiceInfo {
        ServiceInfo {
            vendor: "Nubian Ibex".into(),
            product: "test".into(),
            version: "1".into(),
            url: "https://ibexwall.com".into(),
            interfaces: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn a_hang_up_cancels_the_dialog_wait_but_not_the_work() {
        let path = tmp_socket();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(serve(listener, test_info(), Arc::new(Echo)));

        let mut raw = UnixStream::connect(&path).await.unwrap();
        use tokio::io::AsyncWriteExt;
        raw.write_all(b"{\"method\":\"com.test.Wait\",\"parameters\":{}}\0")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!WAIT_DROPPED.load(std::sync::atomic::Ordering::SeqCst));
        drop(raw);
        for _ in 0..50 {
            if WAIT_DROPPED.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the dialog wait outlived its client");
    }

    #[tokio::test]
    async fn a_hang_up_does_not_stop_a_call_that_is_working() {
        let path = std::env::temp_dir().join(format!(
            "ibexwall-varlink-test-work-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(serve(listener, test_info(), Arc::new(Echo)));

        let mut raw = UnixStream::connect(&path).await.unwrap();
        use tokio::io::AsyncWriteExt;
        raw.write_all(b"{\"method\":\"com.test.Work\",\"parameters\":{}}\0")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(raw);
        for _ in 0..100 {
            if WORK_FINISHED.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the work was cut short by the hang-up");
    }

    #[tokio::test]
    async fn a_half_closed_client_still_gets_its_reply() {
        let path = std::env::temp_dir().join(format!(
            "ibexwall-varlink-test-half-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(serve(listener, test_info(), Arc::new(Echo)));

        let mut raw = UnixStream::connect(&path).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        raw.write_all(b"{\"method\":\"com.test.Work\",\"parameters\":{}}\0")
            .await
            .unwrap();
        raw.shutdown().await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), raw.read_to_end(&mut got))
            .await
            .expect("reply in time")
            .unwrap();
        assert!(String::from_utf8(got).unwrap().contains("done"));
    }

    #[tokio::test]
    async fn requests_sent_back_to_back_are_both_answered() {
        let path = tmp_socket();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(serve(listener, test_info(), Arc::new(Echo)));

        let mut raw = UnixStream::connect(&path).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        raw.write_all(
            b"{\"method\":\"com.test.Echo\",\"parameters\":{\"n\":1}}\0{\"method\":\"com.test.Echo\",\"parameters\":{\"n\":2}}\0",
        )
        .await
        .unwrap();
        let mut got = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while got.iter().filter(|&&b| b == 0).count() < 2 {
            let mut chunk = [0u8; 256];
            let n = tokio::time::timeout_at(deadline, raw.read(&mut chunk))
                .await
                .expect("both replies in time")
                .unwrap();
            assert!(n > 0, "the server closed early");
            got.extend_from_slice(&chunk[..n]);
        }
        let text = String::from_utf8(got).unwrap();
        assert!(
            text.contains("\"n\":1") && text.contains("\"n\":2"),
            "{text}"
        );
    }

    impl Handler for Echo {
        fn handle(&self, call: Call, out: mpsc::Sender<Reply>) -> BoxHandle {
            BoxHandle::new(async move {
                match call.method.as_str() {
                    "com.test.Echo" => {
                        let _ = out.send(Reply::result(call.parameters)).await;
                    }
                    "com.test.Peer" => {
                        let _ = out
                            .send(Reply::result(serde_json::json!({
                                "uid": call.peer.uid,
                                "pid": call.peer.pid,
                                "start_time": call.peer.start_time,
                            })))
                            .await;
                    }
                    "com.test.Stream" => {
                        for i in 0..3 {
                            let _ = out
                                .send(Reply::result_continues(serde_json::json!({ "i": i })))
                                .await;
                        }
                        let _ = out.send(Reply::result(serde_json::json!({ "i": 3 }))).await;
                    }
                    "com.test.Wait" => {
                        // Never answers; records when it is dropped.
                        struct Flag;
                        impl Drop for Flag {
                            fn drop(&mut self) {
                                WAIT_DROPPED.store(true, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                        let _flag = Flag;
                        // Like the polkit dialog: stops when the client goes.
                        call.cancel.cancelled().await;
                    }
                    "com.test.Work" => {
                        // Ignores the hang-up signal, like an Apply.
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        WORK_FINISHED.store(true, std::sync::atomic::Ordering::SeqCst);
                        let _ = out
                            .send(Reply::result(serde_json::json!({ "done": true })))
                            .await;
                    }
                    "com.test.Fail" => {
                        let _ = out
                            .send(Reply::error(
                                "com.test.Boom",
                                serde_json::json!({"why": "no"}),
                            ))
                            .await;
                    }
                    _ => {
                        let _ = out
                            .send(Reply::error(
                                crate::service_errors::METHOD_NOT_FOUND,
                                serde_json::json!({ "method": call.method }),
                            ))
                            .await;
                    }
                }
            })
        }
    }

    #[tokio::test]
    async fn serves_calls_streams_and_errors() {
        let path = tmp_socket();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let info = ServiceInfo {
            vendor: "Nubian Ibex".into(),
            product: "test".into(),
            version: "1".into(),
            url: "https://ibexwall.com".into(),
            interfaces: HashMap::new(),
        };
        tokio::spawn(serve(listener, info, Arc::new(Echo)));

        let mut conn = client::Client::connect(&path).await.unwrap();
        let value = conn
            .call("com.test.Echo", serde_json::json!({"hello": "world"}))
            .await
            .unwrap();
        assert_eq!(value, serde_json::json!({"hello": "world"}));

        // The peer identity is bound to this connection: the uid and pid
        // SO_PEERCRED reported at accept, plus a start time read at the
        // same moment, later than which no /proc re-read happens.
        let peer = conn
            .call("com.test.Peer", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(peer["pid"], std::process::id() as u64);
        assert!(peer["start_time"].as_u64().unwrap() > 0);
        let own_uid = std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert_eq!(peer["uid"], own_uid);

        let values = conn
            .call_all("com.test.Stream", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(values.len(), 4);

        let err = conn
            .call("com.test.Fail", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.name, "com.test.Boom");

        let err = conn
            .call("com.test.Nope", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.name, crate::service_errors::METHOD_NOT_FOUND);

        // Bootstrap works without app involvement.
        let value = conn
            .call("org.varlink.service.GetInfo", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(value["vendor"], "Nubian Ibex");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn start_time_parsing_skips_a_comm_full_of_spaces_and_parens() {
        // Fields after the comm: 3 (state) through 21, then starttime.
        let tail = (1..=19)
            .map(|i| i.to_string())
            .chain(std::iter::once("7777777".to_string()))
            .collect::<Vec<_>>()
            .join(" ");
        let stat = format!("12345 (weird (com m) name x) {tail}");
        assert_eq!(start_time_from_stat(&stat), 7_777_777);
        // A truncated line yields zero, which authorization treats as
        // "do not decide" (fail closed), never as a valid start time.
        assert_eq!(start_time_from_stat("12345 (short) R 1 2"), 0);
        assert_eq!(start_time_from_stat("no parenthesises at all"), 0);
    }

    #[test]
    fn the_own_start_time_is_readable() {
        let own = proc_start_time(std::process::id());
        assert!(own > 0, "our own /proc entry must parse");
    }

    #[tokio::test]
    async fn oversized_client_frame_is_answered_then_dropped() {
        let path = tmp_socket().with_extension("big");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let info = ServiceInfo {
            vendor: "t".into(),
            product: "t".into(),
            version: "0".into(),
            url: "".into(),
            interfaces: HashMap::new(),
        };
        tokio::spawn(serve(listener, info, Arc::new(Echo)));
        let mut conn = client::Client::connect(&path).await.unwrap();

        // Flood the socket with NUL-less garbage; the server must cut us
        // off (close or InvalidMessage) rather than hang.
        let blob = vec![b'{'; 4096];
        for _ in 0..8192 {
            match tokio::time::timeout(Duration::from_millis(200), conn.raw_write(&blob)).await {
                Ok(Ok(_)) => {}
                _ => break, // write blocked: server stopped reading
            }
        }

        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            conn.call("com.test.Echo", serde_json::json!({})),
        )
        .await;
        match outcome {
            // Defended: an error reply or a dropped connection.
            Ok(Err(_)) => {}
            Ok(Ok(value)) => {
                panic!("server should not answer after a protocol violation, got {value}")
            }
            // A hang means the server neither replied nor dropped us.
            Err(_) => panic!("server did not close the connection in time"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_silent_connection_is_closed_after_the_first_frame_deadline() {
        let path = tmp_socket().with_extension("idle");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let info = ServiceInfo {
            vendor: "t".into(),
            product: "t".into(),
            version: "0".into(),
            url: "".into(),
            interfaces: HashMap::new(),
        };
        let limits = ServeLimits {
            max_connections: 8,
            first_frame: Duration::from_millis(150),
            ..ServeLimits::default()
        };
        tokio::spawn(serve_limited(listener, info, Arc::new(Echo), limits));
        use tokio::io::AsyncReadExt as _;

        // A raw connection that never speaks: the server must close it
        // once the deadline passes, not hold the slot forever.
        let mut silent = tokio::net::UnixStream::connect(&path).await.unwrap();
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(3), silent.read(&mut buf)).await;
        match read {
            Ok(Ok(0)) | Ok(Err(_)) => { /* closed by the server: defended */ }
            Ok(Ok(n)) => panic!("expected a close, read {n} bytes"),
            Err(_) => panic!("the silent connection was never closed"),
        }

        // A client that speaks at once is served normally.
        let mut prompt = client::Client::connect(&path).await.unwrap();
        let value = prompt
            .call("com.test.Echo", serde_json::json!({"n": 5}))
            .await
            .unwrap();
        assert_eq!(value["n"], 5);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_connection_cap_closes_extras_and_frees_slots() {
        let path = tmp_socket().with_extension("cap");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let info = ServiceInfo {
            vendor: "t".into(),
            product: "t".into(),
            version: "0".into(),
            url: "".into(),
            interfaces: HashMap::new(),
        };
        let limits = ServeLimits {
            max_connections: 1,
            first_frame: Duration::from_secs(60),
            ..ServeLimits::default()
        };
        tokio::spawn(serve_limited(listener, info, Arc::new(Echo), limits));

        let mut first = client::Client::connect(&path).await.unwrap();
        let value = first
            .call("com.test.Echo", serde_json::json!({"n": 1}))
            .await
            .unwrap();
        assert_eq!(value["n"], 1);

        // Over the cap: accepted then closed, never served.
        let mut extra = client::Client::connect(&path).await.unwrap();
        let over = extra
            .call("com.test.Echo", serde_json::json!({"n": 2}))
            .await;
        assert!(over.is_err(), "an over-cap connection must not be served");

        // Dropping the held connection frees the slot for the next one.
        drop(first);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut again = client::Client::connect(&path).await.unwrap();
        let value = again
            .call("com.test.Echo", serde_json::json!({"n": 3}))
            .await
            .unwrap();
        assert_eq!(value["n"], 3);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn one_uid_cannot_take_more_than_its_share_of_slots() {
        let path = tmp_socket().with_extension("uid");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let limits = ServeLimits {
            max_per_uid: 1,
            ..ServeLimits::default()
        };
        tokio::spawn(serve_limited(listener, test_info(), Arc::new(Echo), limits));

        let mut first = client::Client::connect(&path).await.unwrap();
        first
            .call("com.test.Echo", serde_json::json!({"n": 1}))
            .await
            .unwrap();
        let mut extra = client::Client::connect(&path).await.unwrap();
        assert!(
            extra
                .call("com.test.Echo", serde_json::json!({"n": 2}))
                .await
                .is_err(),
            "a second connection from the same uid must be refused"
        );
        drop(first);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut again = client::Client::connect(&path).await.unwrap();
        again
            .call("com.test.Echo", serde_json::json!({"n": 3}))
            .await
            .unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_connection_idle_between_requests_is_closed() {
        let path = tmp_socket().with_extension("idle2");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let limits = ServeLimits {
            idle: Duration::from_millis(150),
            ..ServeLimits::default()
        };
        tokio::spawn(serve_limited(listener, test_info(), Arc::new(Echo), limits));

        let mut conn = client::Client::connect(&path).await.unwrap();
        conn.call("com.test.Echo", serde_json::json!({"n": 1}))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(
            conn.call("com.test.Echo", serde_json::json!({"n": 2}))
                .await
                .is_err(),
            "the idle connection should have been closed"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_request_above_the_request_limit_is_refused() {
        let path = tmp_socket().with_extension("reqmax");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let limits = ServeLimits {
            max_request_bytes: 1024,
            ..ServeLimits::default()
        };
        tokio::spawn(serve_limited(listener, test_info(), Arc::new(Echo), limits));

        let mut conn = client::Client::connect(&path).await.unwrap();
        let big = "x".repeat(4096);
        assert!(
            conn.call("com.test.Echo", serde_json::json!({ "blob": big }))
                .await
                .is_err()
        );
        let _ = std::fs::remove_file(&path);
    }

    async fn echo_server(name: &str) -> (std::path::PathBuf, ServiceInfo) {
        let path = tmp_socket().with_extension(name);
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let mut interfaces = HashMap::new();
        interfaces.insert("com.test".to_string(), "interface com.test\n".to_string());
        let info = ServiceInfo {
            vendor: "v".into(),
            product: "p".into(),
            version: "1".into(),
            url: "u".into(),
            interfaces,
        };
        tokio::spawn(serve(listener, info.clone(), Arc::new(Echo)));
        (path, info)
    }

    #[tokio::test]
    async fn serves_interface_descriptions_and_rejects_unknown_ones() {
        let (path, _) = echo_server("desc").await;
        let mut conn = client::Client::connect(&path).await.unwrap();
        let ok = conn
            .call(
                "org.varlink.service.GetInterfaceDescription",
                serde_json::json!({ "interface": "com.test" }),
            )
            .await
            .unwrap();
        assert!(
            ok["interface"]
                .as_str()
                .unwrap()
                .starts_with("interface com.test")
        );
        let err = conn
            .call(
                "org.varlink.service.GetInterfaceDescription",
                serde_json::json!({ "interface": "com.nope" }),
            )
            .await
            .unwrap_err();
        assert_eq!(err.name, crate::service_errors::INVALID_PARAMETER);
        let err = conn
            .call("org.varlink.service.Bogus", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.name, crate::service_errors::METHOD_NOT_FOUND);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn malformed_json_is_answered_and_the_connection_survives() {
        let (path, _) = echo_server("bad").await;
        let mut conn = client::Client::connect(&path).await.unwrap();
        conn.raw_write(b"{not json\0").await.unwrap();
        let err = conn
            .call("com.test.Echo", serde_json::json!({"a": 1}))
            .await
            .unwrap_err();
        // The first reply on the wire is the InvalidMessage answer.
        assert_eq!(err.name, crate::service_errors::INVALID_MESSAGE);
        let value = conn
            .call("com.test.Echo", serde_json::json!({"a": 2}))
            .await
            .unwrap();
        assert_eq!(value["a"], 1); // the earlier Echo is answered: the connection survived
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn oneway_calls_get_no_reply() {
        let (path, _) = echo_server("one").await;
        let mut conn = client::Client::connect(&path).await.unwrap();
        conn.raw_write(b"{\"method\":\"com.test.Echo\",\"parameters\":{},\"oneway\":true}\0")
            .await
            .unwrap();
        // The next real call must receive its own reply, not a stale one.
        let value = conn
            .call("com.test.Echo", serde_json::json!({"n": 7}))
            .await
            .unwrap();
        assert_eq!(value["n"], 7);
        let _ = std::fs::remove_file(&path);
    }
}
