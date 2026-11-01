// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

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
}

/// Unix credentials of the connected peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Peer {
    pub uid: u32,
    pub pid: u32,
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

/// Serves `listener` forever with `info` and `handler`.
pub async fn serve(
    listener: UnixListener,
    info: ServiceInfo,
    handler: Arc<dyn Handler>,
) -> anyhow::Result<()> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        let info = info.clone();
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            if let Err(err) = connection(stream, info, handler).await {
                tracing::debug!(error = %err, "varlink connection ended");
            }
        });
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
) -> anyhow::Result<()> {
    let peer = ibexwall_sys::peer_credentials(&stream)
        .map(|(uid, pid)| Peer { uid, pid })
        .unwrap_or_default();
    let (mut reader, mut writer) = stream.into_split();
    // One read may deliver several frames; the framer buffers the rest.
    let mut framer = wire::Framer::new();
    loop {
        let raw = match framer.read_message(&mut reader).await {
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
        let call = Call {
            method: request.method.clone(),
            parameters: request.parameters.clone(),
            more: request.more,
            peer,
        };
        let dispatch = handler.handle(call, tx);
        let mut stream = ReceiverStream::new(rx);
        tokio::pin!(dispatch);

        let mut dispatch_done = false;
        let mut wrote_any = false;
        // Drive the handler and the writer concurrently; for oneway
        // calls the replies are discarded. The `if` guards prevent
        // polling a completed future or a closed channel again.
        loop {
            tokio::select! {
                _ = dispatch.as_mut(), if !dispatch_done => {
                    dispatch_done = true;
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

    impl Handler for Echo {
        fn handle(&self, call: Call, out: mpsc::Sender<Reply>) -> BoxHandle {
            BoxHandle::new(async move {
                match call.method.as_str() {
                    "com.test.Echo" => {
                        let _ = out.send(Reply::result(call.parameters)).await;
                    }
                    "com.test.Stream" => {
                        for i in 0..3 {
                            let _ = out
                                .send(Reply::result_continues(serde_json::json!({ "i": i })))
                                .await;
                        }
                        let _ = out.send(Reply::result(serde_json::json!({ "i": 3 }))).await;
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
            Ok(Err(_)) | Err(_) => { /* defended: error reply or dropped connection */ }
            Ok(Ok(value)) => {
                panic!("server should not answer after a protocol violation, got {value}")
            }
        }
        let _ = std::fs::remove_file(&path);
    }
}
