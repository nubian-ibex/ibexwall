// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let root = std::env::temp_dir().join(format!(
        "ibx-mod-{}-{}",
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

fn config(block: &[&str], unblock: &[&str]) -> Config {
    Config {
        block: block.iter().map(|s| s.to_string()).collect(),
        unblock: unblock.iter().map(|s| s.to_string()).collect(),
    }
}

fn content(ops: Vec<Op>) -> String {
    match ops.into_iter().next() {
        Some(Op::FileWrite { content, .. }) => content,
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_group_becomes_install_lines_that_fail_instead_of_loading() {
    let (root, sandbox) = tree(&[]);
    let text = content(
        plan(
            &sandbox,
            &config(&["net-protocols", "network-filesystems"], &[]),
        )
        .unwrap(),
    );
    assert!(text.contains("# group: net-protocols") && text.contains("install dccp /bin/false"));
    assert!(
        text.contains("install nfs /bin/true"),
        "network filesystems use /bin/true, as the guide does"
    );
    assert!(!text.contains("bluetooth"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_later_change_keeps_what_was_blocked_and_unblocking_the_last_group_removes_the_file() {
    let (root, sandbox) = tree(&[]);
    let first = content(plan(&sandbox, &config(&["bluetooth"], &[])).unwrap());
    let (root2, second_box) = tree(&[(DROP_IN, &first)]);
    let both = content(plan(&second_box, &config(&["vivid"], &[])).unwrap());
    assert!(both.contains("# group: bluetooth") && both.contains("# group: vivid"));
    let (root3, third_box) = tree(&[(DROP_IN, &both)]);
    let one = content(plan(&third_box, &config(&[], &["bluetooth"])).unwrap());
    assert!(!one.contains("bluetooth") && one.contains("vivid"));
    let (root4, last_box) = tree(&[(DROP_IN, &first)]);
    assert!(matches!(
        plan(&last_box, &config(&[], &["bluetooth"])).unwrap()[..],
        [Op::FileRemove { .. }]
    ));
    assert!(
        plan(&sandbox, &config(&[], &["bluetooth"])).is_err(),
        "nothing to unblock"
    );
    for r in [root, root2, root3, root4] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

#[test]
fn only_known_groups_are_accepted_and_no_module_name_comes_from_the_caller() {
    let (root, sandbox) = tree(&[]);
    for bad in [
        config(&["../../etc/passwd"], &[]),
        config(&["dccp"], &[]),
        config(&[], &["x"]),
        config(&[], &[]),
    ] {
        assert!(plan(&sandbox, &bad).is_err());
    }
    assert!(serde_json::from_value::<Config>(serde_json::json!({ "modules": ["dccp"] })).is_err());
    for g in GROUPS {
        for module in g.modules {
            assert!(
                module
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                "{module}"
            );
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
