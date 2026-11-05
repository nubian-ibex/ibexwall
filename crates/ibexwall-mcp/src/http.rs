// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The Streamable HTTP transport of MCP (2025-06-18), for an assistant on
//! another machine. What it adds to the stdio server is a front door, and
//! nothing behind it:
//!
//! - TLS only: there is no plain-HTTP mode, and the key file must not be
//!   readable by others. What crosses the network is encrypted end to end
//!   between the assistant's client and this process.
//! - a Bearer token (see `token.rs`) picks the client whose scopes apply;
//!   failed sign-ins are counted per address and refused past a limit;
//! - the `Origin` header must be allowed (a web page cannot reach it);
//! - one JSON-RPC message per POST, no server-initiated stream, no
//!   sessions; bodies and headers are bounded and every wait has a limit.
//!
//! Every request then goes through the same `Server` pipeline as stdio:
//! scopes, rate limit, the audit line before the work, redaction.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{ACCEPT, ALLOW, AUTHORIZATION, CONTENT_TYPE, ORIGIN, WWW_AUTHENTICATE};
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};

use ibexwall_sys::Clock;

use crate::config::{Config, Token};
use crate::server::SUPPORTED_VERSIONS;
use crate::token;

pub const MAX_BODY: usize = 1024 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WORK_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CONNECTIONS: usize = 64;

/// A hash to check against when the token id is unknown, so that a wrong id
/// and a wrong secret take the same time.
const DECOY: &str = "$argon2id$v=19$m=19456,t=2,p=1$ZGVjb3lkZWNveWRlY295$RGVjb3lEZWNveUhhc2hEZWNveUhhc2hEZWNveUhhc2g";

pub struct Job {
    pub token_id: String,
    pub client: String,
    pub body: String,
    pub reply: oneshot::Sender<Option<String>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    Allowed {
        token_id: String,
        client: String,
    },
    Refused {
        status: u16,
        challenge: bool,
        message: &'static str,
    },
}

fn refuse(status: u16, message: &'static str) -> Admission {
    Admission::Refused {
        status,
        challenge: status == 401,
        message,
    }
}

/// Who may come in: origin, token, expiry, and the failure counter.
pub struct Gate {
    config: Arc<Config>,
    failures: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl Gate {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            failures: Mutex::new(HashMap::new()),
        }
    }

    fn too_many_failures(&self, remote: IpAddr, now: Instant) -> bool {
        let mut map = self.failures.lock().expect("failures lock");
        let list = map.entry(remote).or_default();
        while list
            .front()
            .is_some_and(|at| now.duration_since(*at) >= Duration::from_secs(60))
        {
            list.pop_front();
        }
        list.len() as u32 >= self.config.http.max_failures_per_minute
    }

    fn record_failure(&self, remote: IpAddr, now: Instant) {
        let mut map = self.failures.lock().expect("failures lock");
        map.entry(remote).or_default().push_back(now);
        // The table cannot grow without bound under a spray of addresses.
        if map.len() > 4096 {
            map.retain(|_, list| {
                list.back()
                    .is_some_and(|at| now.duration_since(*at) < Duration::from_secs(60))
            });
        }
    }

    /// The decision for one request. Argon2 runs here, so call it off the
    /// async threads.
    pub fn check(
        &self,
        headers: &HeaderMap,
        remote: IpAddr,
        now: Instant,
        today: &str,
    ) -> Admission {
        if self.too_many_failures(remote, now) {
            return refuse(429, "too many failed sign-ins; wait a minute");
        }
        if let Some(origin) = headers.get(ORIGIN) {
            let allowed = origin
                .to_str()
                .is_ok_and(|o| self.config.http.allowed_origins.iter().any(|a| a == o));
            if !allowed {
                return refuse(403, "this origin is not allowed");
            }
        }
        let bearer = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        let Some((id, secret)) = bearer.and_then(token::parse) else {
            self.record_failure(remote, now);
            return refuse(401, "a Bearer token is required");
        };
        let record: Option<&Token> = self.config.tokens.iter().find(|t| t.id == id);
        let valid = match record {
            Some(t) => token::verify(&t.hash, secret) && !t.expired(today),
            None => {
                let _ = token::verify(DECOY, secret);
                false
            }
        };
        match (valid, record) {
            (true, Some(t)) => Admission::Allowed {
                token_id: t.id.clone(),
                client: t.client.clone(),
            },
            _ => {
                self.record_failure(remote, now);
                refuse(401, "the token is not valid")
            }
        }
    }
}

pub struct State {
    pub gate: Gate,
    pub jobs: mpsc::Sender<Job>,
}

fn reply(
    status: u16,
    content_type: &str,
    body: impl Into<Bytes>,
    challenge: bool,
    allow: bool,
) -> Response<Full<Bytes>> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(CONTENT_TYPE, content_type)
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff");
    if challenge {
        builder = builder.header(WWW_AUTHENTICATE, "Bearer");
    }
    if allow {
        builder = builder.header(ALLOW, "POST");
    }
    builder
        .body(Full::new(body.into()))
        .expect("a valid response")
}

fn text(status: u16, message: &str) -> Response<Full<Bytes>> {
    reply(
        status,
        "text/plain; charset=utf-8",
        message.to_string(),
        status == 401,
        status == 405,
    )
}

fn accepts_json(headers: &HeaderMap) -> bool {
    headers.get(ACCEPT).is_none_or(|v| {
        v.to_str().is_ok_and(|a| {
            a.contains("application/json") || a.contains("*/*") || a.contains("application/*")
        })
    })
}

pub async fn handle(
    state: Arc<State>,
    remote: SocketAddr,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(respond(state, remote, request).await)
}

async fn respond(
    state: Arc<State>,
    remote: SocketAddr,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    if parts.uri.path() != "/mcp" {
        return text(404, "not found");
    }
    if parts.method != Method::POST {
        // Nothing is pushed to the client, and there are no sessions.
        return text(405, "POST only");
    }
    // Sign in before the headers or the body are looked at.
    let gate_state = Arc::clone(&state);
    let headers = parts.headers.clone();
    let today = ibexwall_sys::format_rfc3339(ibexwall_sys::RealClock.unix_now())[..10].to_string();
    let admission = tokio::task::spawn_blocking(move || {
        gate_state
            .gate
            .check(&headers, remote.ip(), Instant::now(), &today)
    })
    .await;
    let (token_id, client) = match admission {
        Ok(Admission::Allowed { token_id, client }) => (token_id, client),
        Ok(Admission::Refused {
            status, message, ..
        }) => return text(status, message),
        Err(_) => return text(500, "internal error"),
    };
    if let Some(version) = parts.headers.get("mcp-protocol-version")
        && !version
            .to_str()
            .is_ok_and(|v| SUPPORTED_VERSIONS.contains(&v))
    {
        return text(400, "unsupported MCP-Protocol-Version");
    }
    if !parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"))
    {
        return text(415, "Content-Type must be application/json");
    }
    if !accepts_json(&parts.headers) {
        return text(406, "Accept must allow application/json");
    }
    let bytes =
        match tokio::time::timeout(READ_TIMEOUT, Limited::new(body, MAX_BODY).collect()).await {
            Ok(Ok(collected)) => collected.to_bytes(),
            Ok(Err(_)) => return text(413, "request too large"),
            Err(_) => return text(408, "request timeout"),
        };
    let Ok(body) = String::from_utf8(bytes.to_vec()) else {
        return text(400, "the body is not UTF-8");
    };
    let (tx, rx) = oneshot::channel();
    let job = Job {
        token_id,
        client,
        body,
        reply: tx,
    };
    if state.jobs.try_send(job).is_err() {
        return text(503, "busy");
    }
    match tokio::time::timeout(WORK_TIMEOUT, rx).await {
        Ok(Ok(Some(answer))) => reply(200, "application/json", answer, false, false),
        Ok(Ok(None)) => reply(202, "text/plain; charset=utf-8", Bytes::new(), false, false),
        _ => text(504, "the server did not answer in time"),
    }
}

/// One connection, already through TLS (or a test stream).
pub async fn serve_connection<I>(io: I, remote: SocketAddr, state: Arc<State>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service =
        hyper::service::service_fn(move |request| handle(Arc::clone(&state), remote, request));
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(READ_TIMEOUT)
        .max_buf_size(64 * 1024)
        .keep_alive(false)
        .serve_connection(TokioIo::new(io), service)
        .await;
}

/// The worker thread owns one `Server` per token (its scopes, its rate
/// limit) over the shared audit chain. Blocking work stays off the async
/// threads.
/// What answers one token's requests: a line in, the answer out (`None`
/// for a notification).
pub type Handler = Box<dyn FnMut(&str) -> Option<String> + Send>;

pub fn spawn_worker<F>(mut rx: mpsc::Receiver<Job>, mut make: F) -> std::thread::JoinHandle<()>
where
    F: FnMut(&str, &str) -> Handler + Send + 'static,
{
    std::thread::spawn(move || {
        let mut servers: HashMap<String, Handler> = HashMap::new();
        while let Some(job) = rx.blocking_recv() {
            let handler = servers
                .entry(job.token_id.clone())
                .or_insert_with(|| make(&job.client, &job.token_id));
            let _ = job.reply.send(handler(&job.body));
        }
    })
}

/// A TLS configuration from PEM files; refuses a private key that others can read.
pub fn tls_config(cert: &str, key: &str) -> Result<Arc<rustls::ServerConfig>, String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(key)
        .map_err(|e| format!("{key}: {e}"))?
        .permissions()
        .mode();
    if mode & 0o007 != 0 {
        return Err(format!("{key} is readable by everyone; chmod 640 or 600"));
    }
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("{cert}: {e}"))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{cert}: {e}"))?;
    if chain.is_empty() {
        return Err(format!("{cert} holds no certificate"));
    }
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{key}: {e}"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| e.to_string())?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Accepts connections until the process ends.
pub async fn serve(
    listener: tokio::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
    state: Arc<State>,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let Ok((stream, remote)) = listener.accept().await else {
            continue;
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let (acceptor, state) = (acceptor.clone(), Arc::clone(&state));
        tokio::spawn(async move {
            let _permit = permit;
            if let Ok(Ok(tls_stream)) =
                tokio::time::timeout(READ_TIMEOUT, acceptor.accept(stream)).await
            {
                serve_connection(tls_stream, remote, state).await;
            }
        });
    }
}

#[cfg(test)]
mod tests;
