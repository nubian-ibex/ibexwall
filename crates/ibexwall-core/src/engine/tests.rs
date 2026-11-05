// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::state::State;
use ibexwall_proto::UnitAction;
use ibexwall_sys::{
    Enabled, FakeClock, FakeFs, FakeNft, FakeSysctl, FakeSystemd, Fs, Nft, SysBundle, Sysctl,
    UnitSnapshot,
};
use serde_json::json;
use std::path::Path;
use std::sync::Arc;

struct Rig {
    engine: Engine,
    fs: Arc<FakeFs>,
    systemd: Arc<FakeSystemd>,
    sysctl: Arc<FakeSysctl>,
    nft: Arc<FakeNft>,
    runner: Arc<ibexwall_sys::firewall::FakeRunner>,
    state: State,
    dir: std::path::PathBuf,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn rig(name: &str, allow_system: bool) -> Rig {
    let dir = std::env::temp_dir().join(format!("ibx-engine-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let fs = Arc::new(FakeFs::new());
    let systemd = Arc::new(FakeSystemd::new());
    let sysctl = Arc::new(FakeSysctl::new());
    let nft = Arc::new(FakeNft::new());
    let runner = Arc::new(ibexwall_sys::firewall::FakeRunner::new());
    let engine = Engine::with(SysBundle {
        fs: fs.clone(),
        runner: runner.clone(),
        systemd: systemd.clone(),
        sysctl: sysctl.clone(),
        clock: Arc::new(FakeClock::new(1_793_534_400)),
        allow_system_executors: allow_system,
        nft: nft.clone(),
        use_transient_executor: false,
    });
    Rig {
        engine,
        fs,
        systemd,
        sysctl,
        nft,
        runner,
        state: State::open(&dir).unwrap(),
        dir,
    }
}

fn write(path: &str, content: &str) -> Op {
    Op::FileWrite {
        path: path.into(),
        content: content.into(),
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    }
}

#[test]
fn file_write_over_existing_file_rolls_back_to_prior_content() {
    let rig = rig("fw", false);
    let path = "/etc/sysctl.d/90-ibexwall-test.conf";
    rig.fs.seed(Path::new(path), b"old\n");
    let ops = vec![write(path, "new\n")];
    rig.engine.snapshot(&rig.state, "tx1", &ops, &[]).unwrap();
    rig.engine.execute(None, &ops).unwrap();
    assert_eq!(rig.fs.read(Path::new(path)).unwrap(), b"new\n");
    rig.engine.rollback(&rig.state, "tx1").unwrap();
    assert_eq!(rig.fs.read(Path::new(path)).unwrap(), b"old\n");
}

#[test]
fn a_flatpak_network_block_is_undone_byte_for_byte() {
    let rig = rig("fp", false);
    let overrides = "/var/lib/flatpak/overrides";
    let mine = format!("{overrides}/org.example.Mine");
    let fresh = format!("{overrides}/org.example.Fresh");
    let before = b"[Context]\nshared=ipc;\nfilesystems=home;\n";
    rig.fs.seed(Path::new(&mine), before);
    let block = |app: &str| Op::FlatpakOverride {
        app_id: app.into(),
        args: vec!["--unshare=network".into()],
    };
    let ops = vec![block("org.example.Mine"), block("org.example.Fresh")];
    rig.engine.snapshot(&rig.state, "txf", &ops, &[]).unwrap();
    rig.engine.execute(None, &ops).unwrap();
    assert_eq!(
        rig.fs.read(Path::new(&mine)).unwrap(),
        b"[Context]\nshared=ipc;!network;\nfilesystems=home;\n"
    );
    assert_eq!(
        rig.fs.read(Path::new(&fresh)).unwrap(),
        b"[Context]\nshared=!network;\n"
    );
    rig.engine.rollback(&rig.state, "txf").unwrap();
    // What the administrator had comes back exactly; what we created
    // is gone.
    assert_eq!(rig.fs.read(Path::new(&mine)).unwrap(), before);
    assert!(!rig.fs.exists(Path::new(&fresh)));
}

fn fw(backend: &str, action: serde_json::Value) -> Op {
    Op::FirewallAdapter {
        backend: backend.into(),
        action,
    }
}

#[test]
fn a_firewalld_change_runs_the_fixed_argv_and_rolls_back_with_a_reload() {
    let rig = rig("fwd", true);
    let zone = "/etc/firewalld/zones/public.xml";
    let before = b"<zone>\n  <service name=\"ssh\"/>\n</zone>\n";
    rig.fs.seed(Path::new(zone), before);
    let ops = vec![fw(
        "firewalld",
        serde_json::json!({"action": "allow_port", "port": 8080, "proto": "tcp"}),
    )];
    rig.engine.snapshot(&rig.state, "txw1", &ops, &[]).unwrap();
    rig.engine.execute(None, &ops).unwrap();
    assert_eq!(
        rig.runner.calls(),
        vec![
            vec![
                "/usr/bin/firewall-cmd",
                "--permanent",
                "--add-port=8080/tcp"
            ],
            vec!["/usr/bin/firewall-cmd", "--add-port=8080/tcp"],
        ]
    );
    // What firewalld itself would have written.
    rig.fs.seed(Path::new(zone), b"<zone>changed</zone>\n");
    rig.engine.rollback(&rig.state, "txw1").unwrap();
    assert_eq!(rig.fs.read(Path::new(zone)).unwrap(), before);
    assert_eq!(
        rig.runner.calls().last().unwrap(),
        &vec!["/usr/bin/firewall-cmd", "--reload"]
    );
}

#[test]
fn a_default_zone_change_is_undone_with_the_conf_file_and_a_reload() {
    let rig = rig("fwdz", true);
    let conf = "/etc/firewalld/firewalld.conf";
    let before = b"DefaultZone=public\nLockdown=no\n";
    rig.fs.seed(Path::new(conf), before);
    let ops = vec![fw(
        "firewalld",
        serde_json::json!({"action": "set_default_zone", "name": "home"}),
    )];
    rig.engine.snapshot(&rig.state, "txdz", &ops, &[]).unwrap();
    rig.engine.execute(None, &ops).unwrap();
    assert_eq!(
        rig.runner.calls(),
        vec![vec!["/usr/bin/firewall-cmd", "--set-default-zone=home"]]
    );
    rig.fs
        .seed(Path::new(conf), b"DefaultZone=home\nLockdown=no\n");
    rig.engine.rollback(&rig.state, "txdz").unwrap();
    assert_eq!(rig.fs.read(Path::new(conf)).unwrap(), before);
    assert_eq!(
        rig.runner.calls().last().unwrap(),
        &vec!["/usr/bin/firewall-cmd", "--reload"]
    );
}

#[test]
fn a_zone_file_that_did_not_exist_is_removed_by_rollback() {
    let rig = rig("fwn", true);
    let zone = "/etc/firewalld/zones/public.xml";
    let ops = vec![fw(
        "firewalld",
        serde_json::json!({"action": "allow_service", "name": "http"}),
    )];
    rig.engine.snapshot(&rig.state, "txw2", &ops, &[]).unwrap();
    rig.engine.execute(None, &ops).unwrap();
    rig.fs.seed(Path::new(zone), b"<zone/>");
    rig.engine.rollback(&rig.state, "txw2").unwrap();
    assert!(!rig.fs.exists(Path::new(zone)));
}

#[test]
fn the_default_zone_comes_from_firewalld_conf() {
    let rig = rig("fwz", true);
    rig.fs.seed(
        Path::new("/etc/firewalld/firewalld.conf"),
        b"DefaultZone=FedoraWorkstation\n",
    );
    rig.fs.seed(
        Path::new("/etc/firewalld/zones/FedoraWorkstation.xml"),
        b"<zone/>",
    );
    let ops = vec![fw(
        "firewalld",
        serde_json::json!({"action": "remove_port", "port": 1, "proto": "udp"}),
    )];
    let manifest = rig.engine.snapshot(&rig.state, "txw3", &ops, &[]).unwrap();
    let paths: Vec<_> = manifest
        .entries
        .iter()
        .filter_map(|entry| match entry {
            ibexwall_sys::ops::SnapshotEntry::File { path, prior, .. } => {
                Some((path.clone(), prior.is_some()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        paths,
        vec![(
            "/etc/firewalld/zones/FedoraWorkstation.xml".to_string(),
            true
        )]
    );
}

#[test]
fn ufw_snapshots_both_rule_files_and_needs_its_directory_and_the_lock() {
    let rig = rig("ufw", true);
    rig.fs.seed(Path::new("/etc/ufw/user.rules"), b"v4\n");
    rig.fs.seed(Path::new("/etc/ufw/user6.rules"), b"v6\n");
    let ops = vec![fw(
        "ufw",
        serde_json::json!({"action": "allow_port", "port": 22, "proto": "tcp"}),
    )];
    let manifest = rig.engine.snapshot(&rig.state, "txu1", &ops, &[]).unwrap();
    assert_eq!(
        ibexwall_sys::write_directories(&ops),
        vec!["/etc/ufw".to_string(), "/run/xtables.lock".to_string()]
    );
    assert_eq!(
        snapshot_write_directories(&manifest),
        vec!["/etc/ufw".to_string(), "/run/xtables.lock".to_string()]
    );
    rig.engine.execute(None, &ops).unwrap();
    assert_eq!(
        rig.runner.calls(),
        vec![vec!["/usr/sbin/ufw", "allow", "22/tcp"]]
    );
    rig.fs.seed(Path::new("/etc/ufw/user.rules"), b"changed\n");
    rig.engine.rollback(&rig.state, "txu1").unwrap();
    assert_eq!(
        rig.fs.read(Path::new("/etc/ufw/user.rules")).unwrap(),
        b"v4\n"
    );
    assert_eq!(
        rig.runner.calls().last().unwrap(),
        &vec!["/usr/sbin/ufw", "reload"]
    );
}

#[test]
fn a_sandbox_never_runs_a_firewall_tool() {
    let rig = rig("fws", false);
    let ops = vec![fw(
        "firewalld",
        serde_json::json!({"action": "allow_port", "port": 1, "proto": "tcp"}),
    )];
    assert!(rig.engine.execute(None, &ops).is_err());
    assert!(rig.runner.calls().is_empty());
}

#[test]
fn a_failing_tool_stops_the_op_and_names_it() {
    let rig = rig("fwf", true);
    *rig.runner.fail_on.lock().expect("lock poisoned") = Some("--add-port".into());
    let ops = vec![fw(
        "firewalld",
        serde_json::json!({"action": "allow_port", "port": 9, "proto": "tcp"}),
    )];
    let error = rig.engine.execute(None, &ops).unwrap_err();
    assert!(format!("{error:#}").contains("firewall.adapter"));
}

#[test]
fn nft_chains_survive_a_restart_through_the_persisted_file() {
    let rig = rig("nfp", true);
    let file = rig.dir.join("nft-active.json");
    // Nothing active: nothing to write, and a stale file is removed.
    std::fs::write(&file, b"{}").unwrap();
    rig.engine.persist_nft(&file).unwrap();
    assert!(!file.exists());

    let fragment = serde_json::json!({ "chains": [
        { "name": "net_firewall_input", "rules": [] },
        { "name": "net_dns_guard", "rules": [] },
    ] });
    rig.engine
        .execute(None, &[Op::NftFragment { fragment }])
        .unwrap();
    rig.engine.persist_nft(&file).unwrap();
    assert!(file.exists());

    // A reboot empties nftables; the file brings the chains back.
    rig.nft.restore("net_firewall_input", None).unwrap();
    rig.nft.restore("net_dns_guard", None).unwrap();
    assert_eq!(rig.engine.restore_nft(&file).unwrap(), 2);
    assert!(rig.nft.has("net_firewall_input") && rig.nft.has("net_dns_guard"));
    // Chains that are already there are left alone.
    assert_eq!(rig.engine.restore_nft(&file).unwrap(), 0);
    // No file, no problem.
    assert_eq!(
        rig.engine
            .restore_nft(&rig.dir.join("missing.json"))
            .unwrap(),
        0
    );
}

#[test]
fn a_sandbox_never_persists_or_restores_chains() {
    let rig = rig("nfs", false);
    let file = rig.dir.join("nft-active.json");
    rig.engine.persist_nft(&file).unwrap();
    assert!(!file.exists());
    std::fs::write(&file, b"{\"x\": {}}").unwrap();
    assert_eq!(rig.engine.restore_nft(&file).unwrap(), 0);
}

#[test]
fn file_write_creating_a_file_is_undone_by_removal() {
    let rig = rig("fc", false);
    let path = "/etc/ibexwall-tests/new.conf";
    let ops = vec![write(path, "x\n")];
    rig.engine.snapshot(&rig.state, "tx2", &ops, &[]).unwrap();
    rig.engine.execute(None, &ops).unwrap();
    assert!(rig.fs.exists(Path::new(path)));
    rig.engine.rollback(&rig.state, "tx2").unwrap();
    assert!(!rig.fs.exists(Path::new(path)));
}

#[test]
fn file_remove_is_restored_from_the_snapshot() {
    let rig = rig("fr", false);
    let path = "/etc/ibexwall-tests/keep.conf";
    rig.fs.seed(Path::new(path), b"keep\n");
    let ops = vec![Op::FileRemove { path: path.into() }];
    rig.engine.snapshot(&rig.state, "tx3", &ops, &[]).unwrap();
    rig.engine.execute(None, &ops).unwrap();
    assert!(!rig.fs.exists(Path::new(path)));
    rig.engine.rollback(&rig.state, "tx3").unwrap();
    assert_eq!(rig.fs.read(Path::new(path)).unwrap(), b"keep\n");
}

#[test]
fn tampered_snapshot_blob_aborts_the_rollback() {
    let rig = rig("tb", false);
    let path = "/etc/ibexwall-tests/t.conf";
    rig.fs.seed(Path::new(path), b"orig\n");
    let ops = vec![write(path, "new\n")];
    rig.engine.snapshot(&rig.state, "tx4", &ops, &[]).unwrap();
    rig.engine.execute(None, &ops).unwrap();
    let blob = rig.state.snapshots_dir().join("tx4/files/000.bin");
    std::fs::write(&blob, b"evil\n").unwrap();
    let err = rig.engine.rollback(&rig.state, "tx4").unwrap_err();
    assert!(err.to_string().contains("integrity"), "{err}");
    // The live file was not overwritten with tampered data.
    assert_eq!(rig.fs.read(Path::new(path)).unwrap(), b"new\n");
}

#[test]
fn rollback_without_a_snapshot_fails() {
    let rig = rig("ns", false);
    assert!(rig.engine.rollback(&rig.state, "missing").is_err());
}

#[test]
fn unit_state_is_restored_for_each_prior_state() {
    for (enabled, active) in [
        (Enabled::Enabled, true),
        (Enabled::Enabled, false),
        (Enabled::Disabled, true),
        (Enabled::Disabled, false),
        (Enabled::Masked, false),
        (Enabled::Static, true),
        (Enabled::NotFound, false),
    ] {
        let rig = rig("unit", false);
        rig.systemd
            .seed("ibexwall-test.service", UnitSnapshot { enabled, active });
        let ops = vec![Op::SystemdUnit {
            unit: "ibexwall-test.service".into(),
            action: UnitAction::Restart,
            now: None,
        }];
        rig.engine.snapshot(&rig.state, "txu", &ops, &[]).unwrap();
        rig.engine.execute(None, &ops).unwrap();
        rig.engine.rollback(&rig.state, "txu").unwrap();
        let after = rig.systemd.get("ibexwall-test.service");
        assert_eq!(after.active, active, "{enabled:?}/{active}");
        if matches!(
            enabled,
            Enabled::Enabled | Enabled::Disabled | Enabled::Masked
        ) {
            assert_eq!(after.enabled, enabled);
        }
    }
}

#[test]
fn rolling_back_a_restart_does_not_touch_the_units_enablement() {
    // Ubuntu's ssh.service is "disabled" (its socket is what is
    // enabled); disabling it again would fail under the executor and
    // changes nothing the transaction did.
    let rig = rig("unit2", false);
    rig.systemd.seed(
        "ibexwall-test.service",
        UnitSnapshot {
            enabled: Enabled::Disabled,
            active: true,
        },
    );
    let ops = vec![Op::SystemdUnit {
        unit: "ibexwall-test.service".into(),
        action: UnitAction::Restart,
        now: None,
    }];
    rig.engine.snapshot(&rig.state, "txu2", &ops, &[]).unwrap();
    rig.engine.execute(None, &ops).unwrap();
    rig.engine.rollback(&rig.state, "txu2").unwrap();
    let log = rig.systemd.log.snapshot().join("\n");
    assert!(!log.contains("Disable"), "{log}");
    assert!(!log.contains("Enable"), "{log}");
    assert!(rig.systemd.get("ibexwall-test.service").active);
}

#[test]
fn rolling_back_a_one_way_sysctl_does_not_try_to_undo_it() {
    let rig = rig("oneway", false);
    rig.sysctl.seed("kernel.kexec_load_disabled", "0");
    let ops = vec![Op::SysctlSet {
        key: "kernel.kexec_load_disabled".into(),
        value: "1".into(),
    }];
    rig.engine.snapshot(&rig.state, "txow", &ops, &[]).unwrap();
    rig.engine.execute(None, &ops).unwrap();
    rig.engine.rollback(&rig.state, "txow").unwrap();
    // Nothing wrote the prior value back (the kernel would refuse).
    let log = rig.sysctl.log.snapshot();
    assert_eq!(log.len(), 1, "{log:?}");
    assert!(log[0].contains("kexec_load_disabled = 1"));
}

fn nft_guard(rules: usize) -> Op {
    Op::NftFragment {
        fragment: json!({ "chains": [{
            "name": "dev_echo_guard",
            "rules": (0..rules).map(|_| json!({ "verdict": "accept" })).collect::<Vec<_>>(),
        }] }),
    }
}

#[test]
fn a_new_nft_chain_is_removed_by_rollback() {
    let rig = rig("nft1", true);
    let ops = vec![nft_guard(2)];
    rig.engine.snapshot(&rig.state, "txn1", &ops, &[]).unwrap();
    rig.engine.execute(None, &ops).unwrap();
    assert!(rig.nft.has("dev_echo_guard"));
    rig.engine.rollback(&rig.state, "txn1").unwrap();
    assert!(!rig.nft.has("dev_echo_guard"));
}

#[test]
fn an_existing_nft_chain_is_restored_as_it_was() {
    let rig = rig("nft2", true);
    let first = vec![nft_guard(1)];
    rig.engine.snapshot(&rig.state, "txa", &first, &[]).unwrap();
    rig.engine.execute(None, &first).unwrap();
    let before = rig.nft.capture("dev_echo_guard").unwrap();

    let second = vec![nft_guard(5)];
    rig.engine
        .snapshot(&rig.state, "txb", &second, &[])
        .unwrap();
    rig.engine.execute(None, &second).unwrap();
    assert_ne!(rig.nft.capture("dev_echo_guard").unwrap(), before);
    rig.engine.rollback(&rig.state, "txb").unwrap();
    assert_eq!(rig.nft.capture("dev_echo_guard").unwrap(), before);
}

#[test]
fn nft_is_refused_without_system_executors() {
    let rig = rig("nft3", false);
    assert!(rig.engine.execute(None, &[nft_guard(1)]).is_err());
    assert!(!rig.nft.has("dev_echo_guard"));
}

#[test]
fn a_restarted_unit_is_restarted_again_after_files_are_restored() {
    // A service that reads a config file must reload the restored
    // content: the restart goes after the file inverses, not before.
    let rig = rig("rs", false);
    rig.systemd.seed(
        "ibexwall-test.service",
        UnitSnapshot {
            enabled: Enabled::Enabled,
            active: true,
        },
    );
    let ops = vec![
        Op::FileWrite {
            path: "/etc/ibexwall-tests/a.conf".into(),
            content: "new\n".into(),
            mode: "0644".into(),
            owner: "root".into(),
            group: "root".into(),
        },
        Op::SystemdUnit {
            unit: "ibexwall-test.service".into(),
            action: UnitAction::Restart,
            now: None,
        },
    ];
    rig.engine.snapshot(&rig.state, "txr", &ops, &[]).unwrap();
    rig.engine.execute(None, &ops).unwrap();
    let before = rig.systemd.log.len();
    rig.engine.rollback(&rig.state, "txr").unwrap();
    let during_rollback = rig.systemd.log.snapshot()[before..].to_vec();
    assert_eq!(
        during_rollback.last().map(String::as_str),
        Some("Restart ibexwall-test.service now=false"),
        "{during_rollback:?}"
    );
}

#[test]
fn a_unit_that_was_stopped_is_not_restarted_by_rollback() {
    let rig = rig("rs2", false);
    rig.systemd.seed(
        "ibexwall-test.service",
        UnitSnapshot {
            enabled: Enabled::Enabled,
            active: false,
        },
    );
    let ops = vec![Op::SystemdUnit {
        unit: "ibexwall-test.service".into(),
        action: UnitAction::Restart,
        now: None,
    }];
    rig.engine.snapshot(&rig.state, "txr2", &ops, &[]).unwrap();
    rig.engine.execute(None, &ops).unwrap();
    let before = rig.systemd.log.len();
    rig.engine.rollback(&rig.state, "txr2").unwrap();
    let during = rig.systemd.log.snapshot()[before..].to_vec();
    assert!(
        !during.iter().any(|e| e.starts_with("Restart")),
        "{during:?}"
    );
}

#[test]
fn sysctl_value_is_restored_and_unknown_keys_are_skipped() {
    let rig = rig("sc", false);
    rig.sysctl.seed("vm.swappiness", "60");
    let ops = vec![
        Op::SysctlSet {
            key: "vm.swappiness".into(),
            value: "10".into(),
        },
        Op::SysctlSet {
            key: "vm.unknown_key".into(),
            value: "1".into(),
        },
    ];
    rig.engine.snapshot(&rig.state, "txs", &ops, &[]).unwrap();
    rig.engine.execute(None, &ops).unwrap();
    assert_eq!(rig.sysctl.get("vm.swappiness").unwrap(), "10");
    rig.engine.rollback(&rig.state, "txs").unwrap();
    assert_eq!(rig.sysctl.get("vm.swappiness").unwrap(), "60");
}

#[test]
fn a_symmetric_exec_is_re_run_by_the_rollback_after_the_files() {
    let rig = rig("sym", false);
    let ops = vec![Op::Exec {
        path: "/usr/bin/true".into(),
        args: vec![],
    }];
    let manifest = rig
        .engine
        .snapshot(&rig.state, "txs", &ops, &[("/usr/bin/true".into(), vec![])])
        .unwrap();
    assert!(matches!(manifest.entries[0], SnapshotEntry::Reload { .. }));
    // The same exec without the manifest's word stays inverse-less.
    let plain = rig.engine.snapshot(&rig.state, "txp", &ops, &[]).unwrap();
    assert!(matches!(plain.entries[0], SnapshotEntry::NoInverse { .. }));
}

#[test]
fn exec_and_other_ops_have_no_system_inverse() {
    let rig = rig("ni", false);
    let ops = vec![Op::Exec {
        path: "/usr/bin/true".into(),
        args: vec![],
    }];
    let manifest = rig.engine.snapshot(&rig.state, "txn", &ops, &[]).unwrap();
    assert!(matches!(
        manifest.entries[0],
        SnapshotEntry::NoInverse { .. }
    ));
    rig.engine.rollback(&rig.state, "txn").unwrap();
}

#[test]
fn execute_stops_at_the_first_failing_op() {
    let rig = rig("ef", false);
    let ops = vec![
        Op::Exec {
            path: "/usr/bin/true".into(),
            args: vec![],
        }, // sandbox-blocked
        write("/etc/ibexwall-tests/never.conf", "x"),
    ];
    assert!(rig.engine.execute(None, &ops).is_err());
    assert!(!rig.fs.exists(Path::new("/etc/ibexwall-tests/never.conf")));
}

#[test]
fn a_private_file_is_never_printed_into_a_preview() {
    let rig = rig("pv-private", false);
    let secret = "PrivateKey = c2VjcmV0LWtleS1ub3Qtb25seS1hLXRlc3Q=";
    let ops = vec![
        Op::FileWrite {
            path: "/etc/vpn.nmconnection".into(),
            content: format!("[wireguard]\n{secret}\n"),
            mode: "0600".into(),
            owner: "root".into(),
            group: "root".into(),
        },
        write("/etc/public.conf", "visible"),
    ];
    let preview = rig.engine.preview(&ops);
    let hidden = preview[0].diff.clone().unwrap();
    assert!(!hidden.contains("c2VjcmV0") && hidden.contains("private file, 2 lines hidden"));
    assert_eq!(preview[1].diff.as_deref(), Some("+visible"));
}

#[test]
fn preview_describes_every_op_kind() {
    let rig = rig("pv", false);
    let ops = vec![
        write("/etc/a.conf", "l1\nl2"),
        Op::FileRemove {
            path: "/etc/b.conf".into(),
        },
        Op::SystemdUnit {
            unit: "u.service".into(),
            action: UnitAction::Stop,
            now: None,
        },
        Op::SysctlSet {
            key: "k.x".into(),
            value: "1".into(),
        },
        Op::NftFragment {
            fragment: json!({ "chains": [{ "name": "dev_echo_c", "rules": [] }] }),
        },
        Op::NftFragment {
            fragment: json!({}),
        },
        Op::FirewallAdapter {
            backend: "ufw".into(),
            action: json!({}),
        },
        Op::DnsBackend {
            backend: "resolved".into(),
            action: json!({}),
        },
        Op::FlatpakOverride {
            app_id: "org.x.App".into(),
            args: vec!["--unshare=network".into()],
        },
        Op::SnapInterface {
            snap: "s".into(),
            interface: "network".into(),
            connect: false,
        },
        Op::BrowserPolicy {
            browser: "firefox".into(),
            policy: json!({"a": 1}),
        },
        Op::NmSetting {
            key: "k".into(),
            value: json!(1),
        },
        Op::PackageInstall {
            package: "chrony".into(),
        },
        Op::Exec {
            path: "/usr/bin/x".into(),
            args: vec![],
        },
    ];
    let preview = rig.engine.preview(&ops);
    assert_eq!(preview.len(), ops.len());
    assert_eq!(preview[0].diff.as_deref(), Some("+l1\n+l2"));
    assert!(preview[1].diff.as_deref().unwrap().contains("removed"));
    assert_eq!(preview[4].target, "dev_echo_c");
    assert_eq!(preview[5].target, "fragment");
    assert_eq!(preview[8].target, "org.x.App");
    assert_eq!(preview[9].target, "s:network");
    assert!(preview[12].risk.contains(&RiskFlag::Irreversible));
    assert_eq!(flags_from(&ops[12..13]), vec![RiskFlag::Irreversible]);
}

#[test]
fn default_engine_is_bound_to_the_real_root_or_sandbox() {
    let engine = Engine::default();
    assert_eq!(
        engine.sys.allow_system_executors,
        ibexwall_proto::names::root() == Path::new("/")
    );
    let sandboxed = ibexwall_sys::SysBundle::real_under(Path::new("/tmp/some-root"));
    assert!(!sandboxed.allow_system_executors);
}
