// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use serde_json::json;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

fn resolved_tree(name: &str) -> (PathBuf, Sandbox) {
    let root = std::env::temp_dir().join(format!("ibx-netdns-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::create_dir_all(root.join("run/systemd/resolve")).unwrap();
    std::fs::create_dir_all(root.join("proc/net")).unwrap();
    std::fs::create_dir_all(root.join("usr/bin")).unwrap();
    std::fs::write(
        root.join("etc/passwd"),
        "root:x:0:0:root:/root:/bin/bash\nibexwall-dns:x:990:988::/var/lib/ibexwall:/usr/sbin/nologin\n",
    )
    .unwrap();
    symlink(
        "../run/systemd/resolve/stub-resolv.conf",
        root.join("etc/resolv.conf"),
    )
    .unwrap();
    let sandbox = Sandbox::at(&root);
    (root, sandbox)
}

fn put(root: &std::path::Path, path: &str, content: &str) {
    let full = root.join(path.trim_start_matches('/'));
    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
    std::fs::write(full, content).unwrap();
}

fn settings_of(ops: &[Op]) -> Settings {
    let content = ops
        .iter()
        .find_map(|op| match op {
            Op::FileWrite { path, content, .. } if path.ends_with("resolver.json") => {
                Some(content.clone())
            }
            _ => None,
        })
        .expect("a settings file");
    serde_json::from_str(&content).unwrap()
}

#[test]
fn a_corporate_resolver_with_a_secondary_and_a_split_zone_is_planned() {
    let (_root, sandbox) = resolved_tree("custom");
    let config = Config::parse(json!({
        "servers": [
            { "ip": "10.0.0.2", "transport": "plain" },
            { "ip": "9.9.9.9", "server_name": "dns.quad9.net", "transport": "tls" },
        ],
        "routes": [{ "domains": ["corp.example"], "servers": [{ "ip": "10.0.0.2", "transport": "plain" }] }],
    }))
    .unwrap();
    let settings = settings_of(&plan(&sandbox, config).unwrap());
    // The order is the failover: the local one first, the encrypted one next.
    assert_eq!(settings.servers[0].transport, Transport::Plain);
    assert_eq!(settings.servers[1].transport, Transport::Tls);
    assert_eq!(settings.routes[0].domains, ["corp.example"]);
}

#[test]
fn plain_dns_to_a_public_address_and_bad_routes_are_refused_at_plan_time() {
    let (_root, sandbox) = resolved_tree("refuse");
    for bad in [
        json!({ "servers": [{ "ip": "8.8.8.8", "transport": "plain" }] }),
        json!({ "routes": [{ "domains": ["Bad_Domain"], "servers": [{ "ip": "10.0.0.2", "transport": "plain" }] }] }),
        json!({ "routes": [{ "domains": ["corp.example"], "servers": [] }] }),
        json!({ "routes": [{ "domains": ["corp.example"], "servers": [{ "ip": "1.1.1.1", "transport": "plain" }] }] }),
    ] {
        let config = Config::parse(bad.clone()).unwrap();
        assert!(plan(&sandbox, config).is_err(), "{bad}");
    }
}

#[test]
fn the_person_is_told_about_the_networks_servers_and_any_unencrypted_upstream() {
    let (root, sandbox) = resolved_tree("told");
    put(
        &root,
        "/run/systemd/resolve/resolv.conf",
        "nameserver 192.168.1.1\nnameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver 10.8.0.1\nsearch lan\n",
    );
    let report = evaluate(&sandbox);
    let network = report
        .findings
        .iter()
        .find(|f| f.id == "dns.network_servers")
        .unwrap();
    assert_eq!(network.args["servers"], "192.168.1.1, 10.8.0.1");
    assert_eq!(network.severity, Severity::Info);
    assert!(report.findings.iter().all(|f| f.id != "dns.plain_upstream"));

    put(
        &root,
        "/etc/ibexwall/dns/resolver.json",
        r#"{ "servers": [{ "ip": "10.0.0.2", "transport": "plain" }, { "ip": "9.9.9.9", "server_name": "dns.quad9.net", "transport": "tls" }] }"#,
    );
    let report = evaluate(&sandbox);
    let plain = report
        .findings
        .iter()
        .find(|f| f.id == "dns.plain_upstream")
        .unwrap();
    assert_eq!(plain.args["servers"], "10.0.0.2");
    // Information, never a failure: the score does not move.
    assert!(
        report
            .findings
            .iter()
            .filter(|f| f.id.starts_with("dns."))
            .all(|f| f.id == "dns.secure_resolver" || f.severity == Severity::Info)
    );
}

#[test]
fn plans_the_resolver_settings_dropin_and_unit_changes_in_order() {
    let (_root, sandbox) = resolved_tree("plan");
    let ops = plan(&sandbox, Config::default()).unwrap();
    let kinds: Vec<&str> = ops
        .iter()
        .map(|op| match op {
            Op::FileWrite { path, .. } if path.ends_with("resolver.json") => "settings",
            Op::FileWrite { path, .. } if path == names::ARTIFACT_RESOLVED => "dropin",
            Op::SystemdUnit {
                unit,
                action: UnitAction::Enable,
                ..
            } if unit == SERVICE => "enable-resolver",
            Op::SystemdUnit {
                unit,
                action: UnitAction::Restart,
                ..
            } if unit == RESOLVED => "restart-resolved",
            Op::NftFragment { .. } => "enforce",
            _ => "other",
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "settings",
            "dropin",
            "enable-resolver",
            "restart-resolved",
            "enforce"
        ]
    );
}

#[test]
fn the_planned_settings_are_exactly_what_the_resolver_reads() {
    let (_root, sandbox) = resolved_tree("contract");
    let config = Config::parse(json!({
        "provider": "cloudflare", "transport": "https",
        "lists": [{ "id": "hagezi-pro" }], "allow": ["fine.example"],
    }))
    .unwrap();
    let ops = plan(&sandbox, config).unwrap();
    let Op::FileWrite { content, .. } = &ops[0] else {
        panic!("settings first")
    };
    let settings: Settings = serde_json::from_str(content).unwrap();
    assert_eq!(settings.servers.len(), 2);
    assert!(
        settings
            .servers
            .iter()
            .all(|s| s.transport == Transport::Https)
    );
    assert_eq!(settings.lists[0].id, "hagezi-pro");
    assert!(settings.block_doh);
    let doh = settings.doh_list.expect("the endpoints list is planned");
    assert_eq!(doh.id, "doh_endpoints");
    assert!(
        doh.url
            .as_deref()
            .is_some_and(|url| url.starts_with("https://"))
    );
}

#[test]
fn enforcement_is_last_optional_and_exempts_only_the_resolver_user() {
    let (_root, sandbox) = resolved_tree("enforce");
    let ops = plan(&sandbox, Config::default()).unwrap();
    let Some(Op::NftFragment { fragment }) = ops.last() else {
        panic!("the nft fragment must come last");
    };
    // The core's own typed parser and prefix rule accept it.
    let parsed = ibexwall_sys::ops::parse_fragment(fragment).unwrap();
    assert!(
        parsed
            .chain_names()
            .iter()
            .all(|n| n.starts_with("net_dns_"))
    );
    let rules = &parsed.chains[0].rules;
    assert_eq!(rules[0].verdict, Verdict::Accept);
    assert!(rules[0].oif_loopback);
    assert_eq!(rules[1].uid_not, Some(990));
    assert_eq!(rules[1].dports, vec![53, 853]);
    assert_eq!(rules[1].verdict, Verdict::Reject);

    let off = Config::parse(json!({ "enforcement": false })).unwrap();
    let ops = plan(&sandbox, off).unwrap();
    assert_eq!(ops.len(), 4);
    let no_doh = Config::parse(json!({ "block_doh": false, "enforcement": false })).unwrap();
    assert!(no_doh.settings().unwrap().doh_list.is_none());
    assert!(!ops.iter().any(|op| matches!(op, Op::NftFragment { .. })));
}

#[test]
fn browser_policies_need_consent_and_follow_installed_browsers() {
    let (root, sandbox) = resolved_tree("browsers");
    for name in ["firefox", "google-chrome-stable", "brave-browser"] {
        std::fs::write(root.join(format!("usr/bin/{name}")), "#!/bin/sh\n").unwrap();
    }
    // Off by default: nothing is planned even with browsers present.
    assert!(
        !plan(&sandbox, Config::default())
            .unwrap()
            .iter()
            .any(|op| matches!(op, Op::BrowserPolicy { .. }))
    );

    let with = Config::parse(json!({ "browser_policies": true })).unwrap();
    let ops = plan(&sandbox, with).unwrap();
    let browsers: Vec<&str> = ops
        .iter()
        .filter_map(|op| match op {
            Op::BrowserPolicy { browser, policy } => {
                assert_eq!(
                    *policy,
                    ibexwall_sys::browser::doh_off(browser).expect("known browser")
                );
                Some(browser.as_str())
            }
            _ => None,
        })
        .collect();
    assert_eq!(browsers, ["firefox", "chrome", "brave"]);
    // An empty machine plans no browser ops at all.
    let bare_root =
        std::env::temp_dir().join(format!("ibx-netdns-nobrowsers-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&bare_root);
    std::fs::create_dir_all(bare_root.join("etc")).unwrap();
    std::fs::create_dir_all(bare_root.join("run/systemd/resolve")).unwrap();
    std::fs::create_dir_all(bare_root.join("proc/net")).unwrap();
    std::fs::write(
        bare_root.join("etc/passwd"),
        "ibexwall-dns:x:990:988::/var/lib/ibexwall:/usr/sbin/nologin\n",
    )
    .unwrap();
    symlink(
        "../run/systemd/resolve/stub-resolv.conf",
        bare_root.join("etc/resolv.conf"),
    )
    .unwrap();
    let ops = plan(
        &Sandbox::at(&bare_root),
        Config::parse(json!({ "browser_policies": true })).unwrap(),
    )
    .unwrap();
    assert!(!ops.iter().any(|op| matches!(op, Op::BrowserPolicy { .. })));
}

#[test]
fn the_failure_mode_is_planned_and_defaults_to_restore() {
    let (_root, sandbox) = resolved_tree("failmode");
    let ops = plan(&sandbox, Config::default()).unwrap();
    let Op::FileWrite { content, .. } = &ops[0] else {
        panic!("settings first")
    };
    let settings: Settings = serde_json::from_str(content).unwrap();
    assert_eq!(
        settings.on_failure,
        ibexwall_dns::config::FailureMode::Restore
    );

    let block = Config::parse(json!({ "on_failure": "block" })).unwrap();
    let ops = plan(&sandbox, block).unwrap();
    let Op::FileWrite { content, .. } = &ops[0] else {
        panic!("settings first")
    };
    let settings: Settings = serde_json::from_str(content).unwrap();
    assert_eq!(
        settings.on_failure,
        ibexwall_dns::config::FailureMode::Block
    );
}

#[test]
fn a_single_list_choice_resolves_like_the_array_form() {
    let (_root, _sandbox) = resolved_tree("onelist");
    let config = Config::parse(json!({ "list": "oisd-small" })).unwrap();
    let settings = config.settings().unwrap();
    assert_eq!(
        settings.lists,
        vec![ListRef {
            id: "oisd-small".into(),
            url: None
        }]
    );
    // A custom list id still needs a url and is refused.
    let bad = Config::parse(json!({ "list": "mine" })).unwrap();
    assert!(bad.settings().is_err());
}

#[test]
fn enforcement_needs_the_resolver_user_to_exist() {
    let (root, sandbox) = resolved_tree("nouser");
    std::fs::write(root.join("etc/passwd"), "root:x:0:0:root:/root:/bin/bash\n").unwrap();
    let err = plan(&sandbox, Config::default()).unwrap_err();
    assert!(format!("{err:?}").contains("enforcement"), "{err:?}");
    assert!(
        plan(
            &sandbox,
            Config::parse(json!({ "enforcement": false })).unwrap()
        )
        .is_ok()
    );
}

#[test]
fn uid_lookup_matches_the_whole_user_name() {
    let (root, sandbox) = resolved_tree("uid");
    std::fs::write(
        root.join("etc/passwd"),
        "ibexwall-dns2:x:5:5::/:/bin/false\nibexwall-dns:x:990:988::/:/bin/false\nbad:x:notanumber:1::/:/bin/false\n",
    )
    .unwrap();
    assert_eq!(uid_of(&sandbox, "ibexwall-dns"), Some(990));
    assert_eq!(uid_of(&sandbox, "bad"), None);
    assert_eq!(uid_of(&sandbox, "absent"), None);
}

#[test]
fn the_dropin_points_resolved_at_the_stub_and_never_falls_back_to_plain_dns() {
    let text = dropin_content();
    assert!(text.contains("DNS=127.0.0.153"));
    assert!(text.contains("Domains=~."));
    assert!(text.contains("\nFallbackDNS=\n"));
}

#[test]
fn bad_choices_are_refused_with_the_offending_field() {
    let (_root, sandbox) = resolved_tree("refuse");
    for (config, field) in [
        (json!({ "provider": "nope" }), "provider"),
        (
            json!({ "provider": "cloudflare", "transport": "quic" }),
            "transport",
        ),
        (
            json!({ "lists": [{ "id": "../x", "url": "https://a.example/l" }] }),
            "lists",
        ),
        (
            json!({ "lists": [{ "id": "mine", "url": "http://a.example/l" }] }),
            "lists",
        ),
        (json!({ "surprise": true }), "config"),
    ] {
        let err = Config::parse(config.clone())
            .and_then(|c| plan(&sandbox, c))
            .unwrap_err();
        assert!(format!("{err:?}").contains(field), "{config}: {err:?}");
    }
}

#[test]
fn unsupported_stacks_are_refused_not_guessed() {
    let root = std::env::temp_dir().join(format!("ibx-netdns-plain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    put(&root, "/etc/resolv.conf", "nameserver 192.0.2.1\n");
    let err = plan(&Sandbox::at(&root), Config::default()).unwrap_err();
    assert!(format!("{err:?}").contains("backend"));
}

#[test]
fn check_fails_until_the_dropin_exists_and_the_resolver_listens() {
    let (root, sandbox) = resolved_tree("check");
    assert_eq!(evaluate(&sandbox).results[0].outcome, CheckOutcome::Fail);
    assert_eq!(evaluate(&sandbox).findings.len(), 1);

    put(&root, names::ARTIFACT_RESOLVED, &dropin_content());
    assert_eq!(evaluate(&sandbox).results[0].outcome, CheckOutcome::Fail);

    let table = format!(
        "  sl  local_address rem_address   st\n   0: {} 00000000:0000 07 0\n",
        listening_hex()
    );
    put(&root, "/proc/net/udp", &table);
    let report = evaluate(&sandbox);
    assert_eq!(report.results[0].outcome, CheckOutcome::Pass);
    assert!(report.findings.is_empty());
}

#[test]
fn check_is_not_assessed_on_an_unsupported_stack() {
    let root = std::env::temp_dir().join(format!("ibx-netdns-na-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    put(&root, "/etc/resolv.conf", "nameserver 192.0.2.1\n");
    let report = evaluate(&Sandbox::at(&root));
    assert_eq!(report.results[0].outcome, CheckOutcome::NotAssessed);
    assert!(report.findings.is_empty());
}

#[test]
fn the_listening_address_matches_the_proc_encoding() {
    assert_eq!(listening_hex(), "9900007F:0035");
}
