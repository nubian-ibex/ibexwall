// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use serde_json::json;

fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let root = std::env::temp_dir().join(format!(
        "ibx-asst-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    for (path, content) in files {
        let full = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, content).unwrap();
    }
    let sandbox = Sandbox::at(&root);
    (root, sandbox)
}

fn config(value: serde_json::Value) -> Config {
    serde_json::from_value(value).unwrap()
}

fn written(ops: Vec<Op>) -> (String, String, String) {
    match ops.into_iter().next() {
        Some(Op::FileWrite {
            content,
            mode,
            group,
            ..
        }) => (content, mode, group),
        other => panic!("expected a file write, got {other:?}"),
    }
}

const HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";
const TLS: [(&str, &str); 2] = [
    ("/etc/ibexwall/mcp/tls.crt", "x"),
    ("/etc/ibexwall/mcp/tls.key", "x"),
];

fn add_token(extra: serde_json::Value) -> serde_json::Value {
    let mut base = json!({ "action": "token_add", "client": "claude-code", "preset": "plan",
        "id": "k1x", "name": "laptop", "hash": HASH, "expires": "2099-01-01" });
    base.as_object_mut()
        .unwrap()
        .extend(extra.as_object().cloned().unwrap_or_default());
    base
}

#[test]
fn a_preset_creates_the_client_and_changes_it_without_touching_the_rest() {
    let existing = "# my notes\n[[client]]\nname = \"other\"\nscopes = [\"read:posture\"]\n";
    let (root, sandbox) = tree(&[(CONFIG, existing)]);
    let (text, mode, group) = written(
        plan(
            &sandbox,
            &config(json!({ "action": "client", "client": "opencode", "preset": "propose" })),
        )
        .unwrap(),
    );
    assert!(text.contains("# my notes"), "comments are kept");
    assert!(text.contains("name = \"other\""));
    assert!(text.contains("name = \"opencode\"") && text.contains("\"propose:*\""));
    // The file holds hashes: the assistants' group reads it, others do not.
    assert_eq!(
        (mode.as_str(), group.as_str()),
        ("0640", "ibexwall-assistants")
    );
    // Changing the preset replaces the scopes of that client only.
    let (root2, sandbox2) = tree(&[(CONFIG, &text)]);
    let (again, _, _) = written(
        plan(
            &sandbox2,
            &config(json!({ "action": "client", "client": "opencode", "preset": "read" })),
        )
        .unwrap(),
    );
    assert!(!again.contains("propose:*") && again.contains("read:posture"));
    assert_eq!(again.matches("name = \"opencode\"").count(), 1);
    for r in [root, root2] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

#[test]
fn a_token_stores_a_hash_binds_the_preset_and_never_a_secret() {
    let (root, sandbox) = tree(&[]);
    let (text, _, _) = written(plan(&sandbox, &config(add_token(json!({})))).unwrap());
    assert!(
        text.contains("id = \"k1x\"")
            && text.contains(HASH)
            && text.contains("expires = \"2099-01-01\"")
    );
    assert!(text.contains("name = \"claude-code\"") && text.contains("\"plan\""));
    assert!(
        !text.contains("propose:*"),
        "a token cannot carry more than its preset"
    );
    let doc = text.parse::<DocumentMut>().unwrap();
    assert_eq!(doc["token"].as_array_of_tables().unwrap().len(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn bad_tokens_are_refused_at_plan_time() {
    let (root, sandbox) = tree(&[]);
    for bad in [
        json!({ "id": "A" }),
        json!({ "name": "" }),
        json!({ "name": "has\"quote" }),
        json!({ "hash": "plain-secret-in-the-wrong-field" }),
        json!({ "expires": "tomorrow" }),
        json!({ "preset": "root" }),
        json!({ "preset": "" }),
        json!({ "client": "bad client" }),
    ] {
        assert!(
            plan(&sandbox, &config(add_token(bad.clone()))).is_err(),
            "{bad}"
        );
    }
    // A repeated id is refused.
    let (text, _, _) = written(plan(&sandbox, &config(add_token(json!({})))).unwrap());
    let (root2, again) = tree(&[(CONFIG, &text)]);
    assert!(plan(&again, &config(add_token(json!({})))).is_err());
    for r in [root, root2] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

#[test]
fn remote_access_needs_a_token_a_certificate_and_a_real_address() {
    let (root, none) = tree(&[]);
    let on = json!({ "action": "http", "enabled": true, "listen": "0.0.0.0:8765" });
    assert!(
        plan(&none, &config(on.clone()))
            .unwrap_err()
            .to_string()
            .contains("token")
    );
    let with_token = {
        let (text, _, _) = written(plan(&none, &config(add_token(json!({})))).unwrap());
        text
    };
    let (root2, no_tls) = tree(&[(CONFIG, &with_token)]);
    assert!(
        plan(&no_tls, &config(on.clone()))
            .unwrap_err()
            .to_string()
            .contains("tls-init")
    );
    let mut files = vec![(CONFIG, with_token.as_str())];
    files.extend(TLS);
    let (root3, ready) = tree(&files);
    let (text, _, _) = written(plan(&ready, &config(on)).unwrap());
    assert!(
        text.contains("[http]") && text.contains("enabled = true") && text.contains("0.0.0.0:8765")
    );
    assert!(
        plan(
            &ready,
            &config(json!({ "action": "http", "enabled": true, "listen": "nowhere" }))
        )
        .is_err()
    );
    // Turning it off needs none of that.
    let (off, _, _) = written(
        plan(
            &ready,
            &config(json!({ "action": "http", "enabled": false })),
        )
        .unwrap(),
    );
    assert!(off.contains("enabled = false"));
    for r in [root, root2, root3] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

#[test]
fn revoking_the_last_token_turns_the_transport_off() {
    let (root, sandbox) = tree(&[]);
    let (text, _, _) = written(plan(&sandbox, &config(add_token(json!({})))).unwrap());
    let text = format!("{text}\n[http]\nenabled = true\nlisten = \"127.0.0.1:8765\"\n");
    let (root2, with_http) = tree(&[(CONFIG, &text)]);
    let (after, _, _) = written(
        plan(
            &with_http,
            &config(json!({ "action": "token_revoke", "id": "k1x" })),
        )
        .unwrap(),
    );
    assert!(!after.contains("k1x") && after.contains("enabled = false"));
    // The client made for a key goes with it; one the person named stays.
    let text = format!(
        "{text}\n[[client]]\nname = \"remote-k1x\"\nscopes = [\"plan\"]\n\n[[client]]\nname = \"mine\"\nscopes = [\"plan\"]\n"
    );
    let (root3, both) = tree(&[(CONFIG, &text)]);
    let (cleaned, _, _) = written(
        plan(
            &both,
            &config(json!({ "action": "token_revoke", "id": "k1x" })),
        )
        .unwrap(),
    );
    assert!(!cleaned.contains("remote-k1x") && cleaned.contains("name = \"mine\""));
    std::fs::remove_dir_all(root3).unwrap();
    assert!(
        plan(
            &with_http,
            &config(json!({ "action": "token_revoke", "id": "nope" }))
        )
        .is_err()
    );
    assert!(plan(&with_http, &config(json!({ "action": "whatever" }))).is_err());
    for r in [root, root2] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

#[test]
fn the_screen_is_told_the_transport_and_each_token_without_its_hash() {
    let (root, sandbox) = tree(&[]);
    let (text, _, _) = written(plan(&sandbox, &config(add_token(json!({})))).unwrap());
    let (root2, with_token) = tree(&[(CONFIG, &text)]);
    let findings = report(&with_token, "2026-11-05T00:00:00Z");
    let http = findings.iter().find(|f| f.id == "assistant.http").unwrap();
    assert_eq!(http.args["enabled"], "false");
    let token = findings
        .iter()
        .find(|f| f.id == "assistant.token.k1x")
        .unwrap();
    assert_eq!(token.args["preset"], "plan");
    assert_eq!(token.args["name"], "laptop");
    assert!(
        findings
            .iter()
            .all(|f| !format!("{:?}", f.args).contains("argon2"))
    );
    assert!(report(&sandbox_empty(), "x").is_empty());
    for r in [root, root2] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

fn sandbox_empty() -> Sandbox {
    let (_root, sandbox) = tree(&[]);
    sandbox
}
