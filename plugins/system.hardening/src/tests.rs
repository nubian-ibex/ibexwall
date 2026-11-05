// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeSet;

use super::*;

fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let root = std::env::temp_dir().join(format!(
        "ibx-hard-{}-{}",
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

#[test]
fn the_catalog_is_complete_bilingual_sourced_and_honest_about_risk() {
    let catalog = catalog();
    assert_eq!(catalog.version, 1);
    assert!(catalog.items.len() >= 20);
    let mut ids = BTreeSet::new();
    for item in &catalog.items {
        assert!(ids.insert(item.id.clone()), "{} twice", item.id);
        assert_eq!(
            item.doc, item.id,
            "the page on the site is named after the item"
        );
        assert!(
            ["low", "medium", "high"].contains(&item.risk.as_str()),
            "{}",
            item.id
        );
        for (what, text) in [("title", &item.title), ("summary", &item.summary)] {
            assert!(
                text.en.len() > 8 && text.pt_br.len() > 8,
                "{} {what}",
                item.id
            );
            assert_ne!(text.en, text.pt_br, "{} {what} is not translated", item.id);
        }
        // What may break is stated wherever something can.
        assert!(
            item.risk == "low" || item.breaks.is_some(),
            "{}: a {} risk item must say what it can break",
            item.id,
            item.risk
        );
        assert!(
            !(item.recommended && item.risk == "high"),
            "{}: a high-risk item is never pre-ticked",
            item.id
        );
        assert!(!item.sources.is_empty(), "{} cites nothing", item.id);
        for source in &item.sources {
            assert!(
                source.url.starts_with("https://")
                    && !source.name.is_empty()
                    && !source.section.is_empty()
            );
        }
        // The house rule: no em or en dashes in anything the person reads.
        let all = format!(
            "{} {} {} {}",
            item.title.en, item.title.pt_br, item.summary.en, item.summary.pt_br
        );
        assert!(
            !all.contains('\u{2014}') && !all.contains('\u{2013}'),
            "{}",
            item.id
        );
    }
}

#[test]
fn every_item_can_be_applied_by_the_plugin_that_owns_it_and_its_probe_agrees() {
    use ibexwall_plugin_sysctl as sysctl;
    let (root, empty) = tree(&[]);
    for item in &catalog().items {
        match item.apply.plugin.as_str() {
            "system.sysctl" => {
                let config: sysctl::Config = serde_json::from_value(item.apply.patch.clone())
                    .unwrap_or_else(|e| panic!("{}: {e}", item.id));
                let ops =
                    sysctl::plan(&empty, &config).unwrap_or_else(|e| panic!("{}: {e}", item.id));
                assert!(!ops.is_empty());
                // What is applied is exactly what is probed.
                let Probe::Sysctl { keys } = &item.probe else {
                    panic!("{}: a sysctl item has a sysctl probe", item.id)
                };
                let applied: BTreeSet<(String, String)> = config.keys.clone().into_iter().collect();
                let probed: BTreeSet<(String, String)> = keys
                    .iter()
                    .map(|k| (k.key.clone(), k.want.clone()))
                    .collect();
                assert_eq!(applied, probed, "{}", item.id);
            }
            "system.modules" => {
                let config: ibexwall_plugin_modules::Config =
                    serde_json::from_value(item.apply.patch.clone())
                        .unwrap_or_else(|e| panic!("{}: {e}", item.id));
                ibexwall_plugin_modules::plan(&empty, &config)
                    .unwrap_or_else(|e| panic!("{}: {e}", item.id));
                let Probe::Modules { group } = &item.probe else {
                    panic!("{}: a modules item has a modules probe", item.id)
                };
                assert_eq!(config.block, vec![group.clone()], "{}", item.id);
            }
            "system.mounts" => {
                let config: ibexwall_plugin_mounts::Config =
                    serde_json::from_value(item.apply.patch.clone())
                        .unwrap_or_else(|e| panic!("{}: {e}", item.id));
                assert!(config.tmp_noexec);
            }
            other => panic!("{}: unknown plugin {other}", item.id),
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn sysctl_probes_tell_applied_open_and_unknown_and_accept_a_stricter_value() {
    let at_least = Probe::Sysctl {
        keys: vec![KeyWant {
            key: "kernel.perf_event_paranoid".into(),
            want: "2".into(),
            at_least: true,
        }],
    };
    let exact = Probe::Sysctl {
        keys: vec![KeyWant {
            key: "kernel.sysrq".into(),
            want: "0".into(),
            at_least: false,
        }],
    };
    let (r1, stricter) = tree(&[("/proc/sys/kernel/perf_event_paranoid", "3\n")]);
    assert_eq!(status(&stricter, &at_least), Status::Applied);
    let (r2, weaker) = tree(&[
        ("/proc/sys/kernel/perf_event_paranoid", "1\n"),
        ("/proc/sys/kernel/sysrq", "176\n"),
    ]);
    assert_eq!(status(&weaker, &at_least), Status::Open);
    assert_eq!(status(&weaker, &exact), Status::Open);
    // A key the kernel does not have is "cannot tell", never "applied".
    let (r3, none) = tree(&[]);
    assert_eq!(status(&none, &exact), Status::Unknown);
    let (r4, set) = tree(&[("/proc/sys/kernel/sysrq", "0\n")]);
    assert_eq!(status(&set, &exact), Status::Applied);
    for r in [r1, r2, r3, r4] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

#[test]
fn a_module_group_counts_only_when_every_module_is_kept_out_and_comments_do_not_count() {
    let group = ibexwall_plugin_modules::GROUPS
        .iter()
        .find(|g| g.id == "bluetooth")
        .unwrap();
    let all: String = group
        .modules
        .iter()
        .map(|m| format!("install {m} /bin/false\n"))
        .collect();
    let (r1, full) = tree(&[("/etc/modprobe.d/x.conf", &all)]);
    assert_eq!(
        status(
            &full,
            &Probe::Modules {
                group: "bluetooth".into()
            }
        ),
        Status::Applied
    );
    let (r2, half) = tree(&[("/etc/modprobe.d/x.conf", "install bluetooth /bin/false\n")]);
    assert_eq!(
        status(
            &half,
            &Probe::Modules {
                group: "bluetooth".into()
            }
        ),
        Status::Open
    );
    let (r3, commented) = tree(&[(
        "/etc/modprobe.d/x.conf",
        &all.replace("install", "# install"),
    )]);
    assert_eq!(
        status(
            &commented,
            &Probe::Modules {
                group: "bluetooth".into()
            }
        ),
        Status::Open
    );
    // A dash and an underscore name the same module.
    let (r4, dashed) = tree(&[("/etc/modprobe.d/x.conf", "install n_hdlc /bin/false\n")]);
    assert!(blocked(&module_files(&dashed), "n-hdlc"));
    assert_eq!(
        status(
            &full,
            &Probe::Modules {
                group: "no-such-group".into()
            }
        ),
        Status::Unknown
    );
    for r in [r1, r2, r3, r4] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

#[test]
fn a_mount_option_counts_only_on_that_mount_point() {
    let probe = Probe::MountOption {
        path: "/tmp".into(),
        option: "noexec".into(),
    };
    let (r1, on) = tree(&[(
        "/proc/mounts",
        "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n",
    )]);
    assert_eq!(status(&on, &probe), Status::Applied);
    let (r2, off) = tree(&[(
        "/proc/mounts",
        "tmpfs /tmp tmpfs rw,nosuid 0 0\n/dev/sda1 / ext4 rw,noexec 0 0\n",
    )]);
    assert_eq!(status(&off, &probe), Status::Open);
    let (r3, nomount) = tree(&[("/proc/mounts", "/dev/sda1 / ext4 rw 0 0\n")]);
    assert_eq!(status(&nomount, &probe), Status::Open);
    for r in [r1, r2, r3] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

#[test]
fn the_finding_lists_what_is_applied_open_and_unknown_as_information() {
    let (root, sandbox) = tree(&[
        ("/proc/sys/kernel/kptr_restrict", "2\n"),
        ("/proc/sys/kernel/dmesg_restrict", "0\n"),
    ]);
    let note = evaluate(&sandbox, "x");
    assert_eq!(note.severity, Severity::Info);
    assert!(
        note.args["applied"]
            .split(',')
            .any(|i| i == "kernel.kptr-restrict")
    );
    assert!(
        note.args["open"]
            .split(',')
            .any(|i| i == "kernel.dmesg-restrict")
    );
    assert!(
        note.args["unknown"].split(',').any(|i| i == "kernel.sysrq"),
        "no such key in this tree"
    );
    let total: usize = note.args["total"].parse().unwrap();
    let counted: usize = ["applied", "open", "unknown"]
        .iter()
        .map(|k| note.args[*k].split(',').filter(|s| !s.is_empty()).count())
        .sum();
    assert_eq!(total, counted);
    std::fs::remove_dir_all(root).unwrap();
}
