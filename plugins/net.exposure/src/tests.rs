// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

const FIB: &str = "Main:
  +-- 0.0.0.0/0 3 0 5
Local:
  +-- 127.0.0.0/8 2 0 2
     |-- 127.0.0.0
        /32 link BROADCAST
     |-- 127.0.0.1
        /32 host LOCAL
  +-- 192.168.1.0/24 2 0 2
     |-- 192.168.1.5
        /32 host LOCAL
     |-- 192.168.1.255
        /32 link BROADCAST
";

const XML: &str = r#"<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql"/></port></ports></host>
<host><status state="up"/><address addr="192.168.1.5" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" method="table"/></port>
<port protocol="tcp" portid="631"><state state="open"/><service name="ipp"/></port>
<port protocol="tcp" portid="9999"><state state="closed"/></port>
<port protocol="udp" portid="68"><state state="open"/><service name="dhcpc"/></port>
</ports></host>
<host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host>
</nmaprun>"#;

fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let root = std::env::temp_dir().join(format!(
        "ibx-exp-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    for (path, text) in files {
        let full = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, text).unwrap();
    }
    let sandbox = Sandbox::at(&root);
    (root, sandbox)
}

fn scan() -> Config {
    Config {
        action: "scan".into(),
        every: String::new(),
    }
}

#[test]
fn only_the_machines_own_addresses_are_read_from_the_routing_table() {
    assert_eq!(local_addresses(FIB), ["127.0.0.1", "192.168.1.5"]);
    assert!(local_addresses("").is_empty());
    // A broadcast or network line is never a target.
    assert!(
        !local_addresses(FIB)
            .iter()
            .any(|a| a.ends_with(".255") || a.ends_with(".0"))
    );
}

#[test]
fn the_command_holds_only_those_addresses_and_there_is_nowhere_to_name_another() {
    let (root, sandbox) = tree(&[(NMAP, ""), ("/proc/net/fib_trie", FIB)]);
    let ops = plan(&sandbox, &scan()).unwrap();
    let Op::FileWrite { content, .. } = &ops[1] else {
        panic!("{ops:?}")
    };
    assert!(
        content.contains("-oX - 127.0.0.1 192.168.1.5\n")
            && content.contains("StandardOutput=truncate:/var/lib/ibexwall/exposure/nmap.xml\n"),
        "{content}"
    );
    assert!(content.contains("-sT -Pn -n --open"));
    // The config has no target field at all.
    assert!(
        serde_json::from_value::<Config>(
            serde_json::json!({ "action": "scan", "target": "8.8.8.8" })
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<Config>(
            serde_json::json!({ "action": "scan", "targets": ["10.0.0.1"] })
        )
        .is_err()
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn planning_needs_nmap_and_readable_addresses_and_a_valid_schedule() {
    let (r1, none) = tree(&[("/proc/net/fib_trie", FIB)]);
    assert!(
        plan(&none, &scan())
            .unwrap_err()
            .to_string()
            .contains("installs no software")
    );
    let (r2, blind) = tree(&[(NMAP, "")]);
    assert!(plan(&blind, &scan()).is_err());
    let (r3, ok) = tree(&[(NMAP, ""), ("/proc/net/fib_trie", FIB)]);
    for bad in [
        Config {
            action: "run".into(),
            every: String::new(),
        },
        Config {
            action: "scan".into(),
            every: "monthly".into(),
        },
    ] {
        assert!(plan(&ok, &bad).is_err());
    }
    let timed = plan(
        &ok,
        &Config {
            action: "schedule".into(),
            every: "hourly".into(),
        },
    )
    .unwrap();
    assert!(timed.iter().any(|o| matches!(
        o,
        Op::SystemdUnit {
            action: UnitAction::Enable,
            ..
        }
    )));
    for r in [r1, r2, r3] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

#[test]
fn open_tcp_ports_on_real_addresses_are_listed_grouped_and_loopback_is_left_out() {
    let found = parse(XML);
    let summary: Vec<(u16, &str, Vec<&str>)> = found
        .iter()
        .map(|p| {
            (
                p.port,
                p.service.as_str(),
                p.addresses.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (22, "ssh", vec!["192.168.1.5", "10.0.0.9"]),
            (631, "ipp", vec!["192.168.1.5"]),
        ],
        "closed, UDP and loopback-only entries are not listed"
    );
    // The tags nmap really writes around a host do not split it.
    let real = r#"<nmaprun><hosthint><status state="up"/><address addr="10.0.2.15" addrtype="ipv4"/></hosthint>
<host starttime="1" endtime="2"><status state="up" reason="user-set"/><address addr="10.0.2.15" addrtype="ipv4"/><hostnames></hostnames>
<ports><extraports state="closed" count="65534"/><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" method="table" conf="3"/></port></ports><times srtt="1"/></host></nmaprun>"#;
    assert_eq!(parse(real)[0].port, 22);
    assert!(parse("").is_empty() && parse("<nmaprun></nmaprun>").is_empty());
    assert!(parse("<host><address addr=\"1.2.3.4\"/><port protocol=\"tcp\" portid=\"x\"><state state=\"open\"/></port>").is_empty());
}

#[test]
fn findings_are_information_and_the_note_says_what_to_do() {
    let (r1, none) = tree(&[("/etc/os-release", "ID=debian\n")]);
    let notes = evaluate(&none, "x");
    let note = notes.iter().find(|f| f.id == "detect.exposure").unwrap();
    assert_eq!(
        (note.summary_key.as_str(), note.args["install"].as_str()),
        ("detect-exposure-none", "sudo apt install nmap")
    );
    let (r2, scanned) = tree(&[(NMAP, ""), (XML_PATH, XML)]);
    let all = evaluate(&scanned, "x");
    assert!(all.iter().all(|f| f.severity == Severity::Info));
    let ssh = all.iter().find(|f| f.id == "exposure.tcp.22").unwrap();
    assert_eq!(ssh.args["addresses"], "192.168.1.5, 10.0.0.9");
    assert_eq!(
        all.iter()
            .find(|f| f.id == "detect.exposure")
            .unwrap()
            .summary_key,
        "detect-exposure-scanned"
    );
    for r in [r1, r2] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

const XML_PATH: &str = "/var/lib/ibexwall/exposure/nmap.xml";
