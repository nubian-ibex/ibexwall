// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::audit::Audit;
use crate::redact::Redactor;
use crate::server::{Backend, Server};

struct Fixture {
    state: Arc<State>,
    token: String,
    expired_token: String,
}

struct Posture;

impl Backend for Posture {
    fn call(&mut self, method: &str, _: serde_json::Value) -> Result<serde_json::Value, String> {
        match method.rsplit('.').next() {
            Some("GetPosture") => {
                Ok(serde_json::json!({ "posture": { "score": 90, "protections": [] } }))
            }
            Some(other) => Err(format!("unexpected {other}")),
            None => Err("?".into()),
        }
    }
}

/// A real `Server` pipeline behind the door, with a fake core.
fn fixture(max_failures: u32, origins: &[&str]) -> Fixture {
    let live = token::create("k1x", "laptop", "reader", Some("2099-01-01"), None).unwrap();
    let old = token::create("old", "stale", "reader", Some("2020-01-01"), None).unwrap();
    let text = format!(
        "[http]\nenabled = true\nmax_failures_per_minute = {max_failures}\nallowed_origins = {origins:?}\n\n[[client]]\nname = \"reader\"\nscopes = [\"read:posture\"]\n\n{}\n{}\n",
        live.stanza, old.stanza
    );
    let config = Arc::new(Config::parse(&text).unwrap());
    let (tx, rx) = mpsc::channel(64);
    let audit = Arc::new(Mutex::new(Audit::new(Vec::<u8>::new(), 0, String::new())));
    let worker_config = Arc::clone(&config);
    spawn_worker(rx, move |client, id| {
        let mut server = Server::shared(
            (*worker_config).clone(),
            client,
            &format!("http:{id}"),
            Redactor::new(b"salt".to_vec(), &[], &[], &[]),
            Arc::clone(&audit),
            Posture,
        );
        Box::new(move |line| server.handle(line))
    });
    Fixture {
        state: Arc::new(State {
            gate: Gate::new(config),
            jobs: tx,
        }),
        token: live.token,
        expired_token: old.token,
    }
}

/// One raw HTTP/1.1 exchange over an in-memory stream: `(status, headers, body)`.
async fn exchange(state: &Arc<State>, request: String) -> (u16, String, String) {
    let (mut client, server) = tokio::io::duplex(256 * 1024);
    let remote: SocketAddr = "203.0.113.9:5555".parse().unwrap();
    tokio::spawn(serve_connection(server, remote, Arc::clone(state)));
    client.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    client.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    (status, head.to_ascii_lowercase(), body.to_string())
}

fn post(token: Option<&str>, extra: &str, body: &str) -> String {
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    format!(
        "POST /mcp HTTP/1.1\r\nHost: x\r\n{auth}Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

const INIT: &str =
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#;
const POSTURE: &str =
    r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_posture"}}"#;
const NOTE: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

#[tokio::test]
async fn a_valid_token_gets_the_same_pipeline_as_stdio_with_its_clients_scopes() {
    let f = fixture(10, &[]);
    let (status, head, body) = exchange(&f.state, post(Some(&f.token), "", INIT)).await;
    assert_eq!(status, 200, "{head}\n{body}");
    assert!(head.contains("application/json") && head.contains("no-store"));
    assert!(body.contains("ibexwall-mcp") && body.contains("2025-06-18"));
    let (status, _, body) = exchange(&f.state, post(Some(&f.token), "", POSTURE)).await;
    assert_eq!(status, 200);
    assert!(body.contains("score"), "{body}");
    // A tool the token's client has no scope for is refused by the pipeline.
    let events = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query_events","arguments":{"source":"apps"}}}"#;
    let (_, _, body) = exchange(&f.state, post(Some(&f.token), "", events)).await;
    assert!(body.contains("isError") && body.contains("scope"), "{body}");
    // A notification is accepted with nothing to say.
    let (status, _, body) = exchange(&f.state, post(Some(&f.token), "", NOTE)).await;
    assert_eq!((status, body.as_str()), (202, ""));
}

#[tokio::test]
async fn no_token_a_wrong_token_an_unknown_id_and_an_expired_token_are_all_refused() {
    let f = fixture(50, &[]);
    let wrong = format!("{}x", f.token);
    let unknown = "ibx_nope_abcdefghijklmnopqrstuvwxyz0123456789";
    for (token, why) in [
        (None, "none"),
        (Some(wrong.as_str()), "wrong"),
        (Some(unknown), "unknown"),
        (Some(f.expired_token.as_str()), "expired"),
        (Some("garbage"), "garbage"),
    ] {
        let (status, head, _) = exchange(&f.state, post(token, "", INIT)).await;
        assert_eq!(status, 401, "{why}");
        assert!(head.contains("www-authenticate: bearer"), "{why}");
    }
}

#[tokio::test]
async fn too_many_failures_from_one_address_close_the_door_even_to_a_good_token() {
    let f = fixture(3, &[]);
    for _ in 0..3 {
        assert_eq!(
            exchange(
                &f.state,
                post(
                    Some("ibx_nope_abcdefghijklmnopqrstuvwxyz0123456789"),
                    "",
                    INIT
                )
            )
            .await
            .0,
            401
        );
    }
    assert_eq!(
        exchange(&f.state, post(Some(&f.token), "", INIT)).await.0,
        429
    );
}

#[tokio::test]
async fn the_door_checks_the_path_method_origin_headers_and_size() {
    let f = fixture(50, &["https://app.example"]);
    let get = "GET /mcp HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".to_string();
    let (status, head, _) = exchange(&f.state, get).await;
    assert_eq!(status, 405);
    assert!(head.contains("allow: post"));
    let other = post(Some(&f.token), "", INIT).replace("/mcp", "/admin");
    assert_eq!(exchange(&f.state, other).await.0, 404);
    // A browser page from an origin nobody allowed.
    assert_eq!(
        exchange(
            &f.state,
            post(Some(&f.token), "Origin: https://evil.example\r\n", INIT)
        )
        .await
        .0,
        403
    );
    assert_eq!(
        exchange(
            &f.state,
            post(Some(&f.token), "Origin: https://app.example\r\n", INIT)
        )
        .await
        .0,
        200
    );
    assert_eq!(
        exchange(
            &f.state,
            post(Some(&f.token), "MCP-Protocol-Version: 1999-01-01\r\n", INIT)
        )
        .await
        .0,
        400
    );
    assert_eq!(
        exchange(
            &f.state,
            post(Some(&f.token), "MCP-Protocol-Version: 2025-06-18\r\n", INIT)
        )
        .await
        .0,
        200
    );
    let wrong_type = post(Some(&f.token), "", INIT)
        .replace("application/json\r\nAccept", "text/plain\r\nAccept");
    assert_eq!(exchange(&f.state, wrong_type).await.0, 415);
    let wrong_accept = post(Some(&f.token), "", INIT).replace(
        "Accept: application/json, text/event-stream",
        "Accept: text/html",
    );
    assert_eq!(exchange(&f.state, wrong_accept).await.0, 406);
    let big = "x".repeat(MAX_BODY + 10);
    assert_eq!(
        exchange(&f.state, post(Some(&f.token), "", &big)).await.0,
        413
    );
}

#[tokio::test]
async fn garbage_json_gets_a_json_rpc_error_not_a_crash() {
    let f = fixture(50, &[]);
    let (status, _, body) = exchange(&f.state, post(Some(&f.token), "", "{not json")).await;
    assert_eq!(status, 200);
    assert!(body.contains("-32700"), "{body}");
    let (status, _, body) = exchange(&f.state, post(Some(&f.token), "", "[1,2]")).await;
    assert_eq!(status, 200);
    assert!(body.contains("-32600"));
}

#[test]
fn a_tls_key_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("ibx-http-tls-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("k.pem");
    std::fs::write(&key, "x").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = tls_config(dir.join("c.pem").to_str().unwrap(), key.to_str().unwrap())
        .err()
        .unwrap();
    assert!(error.contains("readable by everyone"), "{error}");
    assert!(tls_config("/nonexistent/c.pem", "/nonexistent/k.pem").is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
