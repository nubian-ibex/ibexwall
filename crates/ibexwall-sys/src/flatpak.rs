// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Flatpak network override: one known file per application, one exact
//! change. A plugin names an application and `--unshare=network`; the core
//! maps that to the file Flatpak itself reads, never free-form content.
//!
//! Verified 2026-11-03 against Flatpak 1.14.6 (Ubuntu 24.04), 1.16.6
//! (Debian 13, Ubuntu 26.04) and 1.18.4 (Fedora 44, Arch): the system-wide
//! `flatpak override --unshare=network <app>` writes
//! `/var/lib/flatpak/overrides/<app>` (0644 root) containing
//! `[Context]\nshared=!network;\n`, and merges into an existing file by
//! editing the `shared=` list. The order of the entries inside the list
//! differs between Flatpak versions, which it reads either way; this module
//! keeps what an administrator already had and appends. Documentation:
//! <https://docs.flatpak.org/en/latest/flatpak-command-reference.html>
//! (`flatpak-override`: overrides are text files, system-wide by default).

/// Where the default system-wide installation keeps overrides.
pub const OVERRIDES_DIR: &str = "/var/lib/flatpak/overrides";

/// The only argument list the executor accepts.
pub const UNSHARE_NETWORK: &str = "--unshare=network";

/// Reverse-DNS application ids: at least three non-empty elements joined by
/// dots, each made of letters, digits, `_` and `-`. The shape is what
/// matters here: it keeps `..`, `/` and newlines out of the file name.
pub fn valid_app_id(id: &str) -> bool {
    let elements: Vec<&str> = id.split('.').collect();
    id.len() <= 255
        && elements.len() >= 3
        && elements.iter().all(|element| {
            !element.is_empty()
                && element
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

/// The override file for `app_id`, or `None` when the id is not valid.
pub fn override_path(app_id: &str) -> Option<String> {
    valid_app_id(app_id).then(|| format!("{OVERRIDES_DIR}/{app_id}"))
}

/// True when `args` is exactly the one supported change.
pub fn args_allowed(args: &[String]) -> bool {
    args.len() == 1 && args[0] == UNSHARE_NETWORK
}

/// The override file content that blocks network access, given what the
/// file held before (`None`: it did not exist). Everything else in the
/// file is kept; content that already blocks the network comes back
/// unchanged, byte for byte.
pub fn unshare_network(existing: Option<&str>) -> String {
    let Some(text) = existing.filter(|text| !text.is_empty()) else {
        return "[Context]\nshared=!network;\n".into();
    };
    let lines: Vec<&str> = text.split_inclusive('\n').collect();

    let header = lines
        .iter()
        .position(|line| line.trim_end_matches(['\r', '\n']) == "[Context]");
    let Some(header) = header else {
        // No [Context] group yet: append one, keeping what is there.
        let mut out = text.to_string();
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("[Context]\nshared=!network;\n");
        return out;
    };

    let end = lines[header + 1..]
        .iter()
        .position(|line| line.trim_start().starts_with('['))
        .map_or(lines.len(), |offset| header + 1 + offset);

    let shared = (header + 1..end).find(|&index| {
        let line = lines[index];
        line.split_once('=')
            .is_some_and(|(key, _)| key.trim() == "shared")
    });

    let mut out = String::new();
    for (index, line) in lines.iter().enumerate() {
        if Some(index) == shared {
            let value = line.split_once('=').map_or("", |(_, value)| value);
            let mut entries: Vec<&str> = value
                .trim_end_matches(['\r', '\n'])
                .split(';')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .collect();
            if entries.contains(&"!network") && !entries.contains(&"network") {
                return text.to_string();
            }
            entries.retain(|entry| *entry != "network");
            if !entries.contains(&"!network") {
                entries.push("!network");
            }
            out.push_str("shared=");
            for entry in entries {
                out.push_str(entry);
                out.push(';');
            }
            out.push('\n');
        } else {
            out.push_str(line);
        }
        if index == header && shared.is_none() {
            // `shared` is the first key Flatpak writes in the group.
            if !line.ends_with('\n') {
                out.push('\n');
            }
            out.push_str("shared=!network;\n");
        }
    }
    out
}

/// Whether `existing` already blocks the network for the application.
pub fn network_blocked(existing: Option<&str>) -> bool {
    existing.is_some_and(|text| unshare_network(Some(text)) == text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_ids_are_reverse_dns_and_cannot_escape_the_directory() {
        for good in ["org.mozilla.firefox", "com.github.foo-bar", "org.a_b.C1"] {
            assert!(valid_app_id(good), "{good}");
        }
        for bad in [
            "",
            "firefox",
            "org.firefox",
            "../etc/passwd",
            "org..firefox",
            "org.mozilla.firefox/",
            "org.moz illa.x",
            ".org.mozilla.x",
            "org.mozilla.x\n",
            &format!("org.mozilla.{}", "a".repeat(300)),
        ] {
            assert!(!valid_app_id(bad), "{bad:?}");
        }
        assert_eq!(
            override_path("org.mozilla.firefox").as_deref(),
            Some("/var/lib/flatpak/overrides/org.mozilla.firefox")
        );
        assert_eq!(override_path("../x"), None);
    }

    #[test]
    fn only_the_one_argument_is_allowed() {
        assert!(args_allowed(&["--unshare=network".into()]));
        assert!(!args_allowed(&[]));
        assert!(!args_allowed(&["--share=network".into()]));
        assert!(!args_allowed(&[
            "--unshare=network".into(),
            "--filesystem=host".into()
        ]));
        assert!(!args_allowed(&["--filesystem=host".into()]));
    }

    #[test]
    fn a_new_file_matches_what_flatpak_writes() {
        // Byte for byte what `flatpak override --unshare=network` wrote on
        // Flatpak 1.14.6, 1.16.6 and 1.18.4 (27 bytes).
        let content = unshare_network(None);
        assert_eq!(content, "[Context]\nshared=!network;\n");
        assert_eq!(content.len(), 27);
        assert_eq!(unshare_network(Some("")), content);
    }

    #[test]
    fn it_keeps_what_the_administrator_had() {
        // The file Flatpak wrote for `--filesystem=home --share=ipc`.
        let before = "[Context]\nshared=ipc;\nfilesystems=home;\n";
        let after = unshare_network(Some(before));
        assert_eq!(
            after,
            "[Context]\nshared=ipc;!network;\nfilesystems=home;\n"
        );
        assert!(network_blocked(Some(&after)));
    }

    #[test]
    fn it_adds_shared_first_when_only_other_keys_exist() {
        let before = "[Context]\nfilesystems=home;\n";
        assert_eq!(
            unshare_network(Some(before)),
            "[Context]\nshared=!network;\nfilesystems=home;\n"
        );
    }

    #[test]
    fn it_replaces_an_explicit_share_of_the_network() {
        // The file Flatpak wrote for `--share=network`.
        assert_eq!(
            unshare_network(Some("[Context]\nshared=network;\n")),
            "[Context]\nshared=!network;\n"
        );
        assert_eq!(
            unshare_network(Some("[Context]\nshared=network;ipc;\n")),
            "[Context]\nshared=ipc;!network;\n"
        );
    }

    #[test]
    fn it_adds_a_context_group_after_other_groups() {
        let before = "[Session Bus Policy]\norg.x=talk\n";
        assert_eq!(
            unshare_network(Some(before)),
            "[Session Bus Policy]\norg.x=talk\n[Context]\nshared=!network;\n"
        );
        // A file that lacks a final newline still ends up well formed.
        assert_eq!(
            unshare_network(Some("[Environment]\nA=b")),
            "[Environment]\nA=b\n[Context]\nshared=!network;\n"
        );
    }

    #[test]
    fn it_only_touches_the_first_context_group_and_stops_at_the_next_group() {
        let before = "[Context]\nsockets=x11;\n[Session Bus Policy]\nshared=keepme\n";
        let after = unshare_network(Some(before));
        assert_eq!(
            after,
            "[Context]\nshared=!network;\nsockets=x11;\n[Session Bus Policy]\nshared=keepme\n"
        );
    }

    #[test]
    fn an_already_blocked_file_is_returned_unchanged() {
        for blocked in [
            "[Context]\nshared=!network;\n",
            "[Context]\nshared=!network;ipc;\nfilesystems=home;\n",
            "[Context]\nshared = !network;\n",
        ] {
            assert_eq!(unshare_network(Some(blocked)), blocked);
            assert!(network_blocked(Some(blocked)));
        }
        assert!(!network_blocked(None));
        assert!(!network_blocked(Some("[Context]\nshared=network;\n")));
        assert!(!network_blocked(Some("")));
    }

    #[test]
    fn merging_twice_changes_nothing_the_second_time() {
        for before in [
            None,
            Some("[Context]\nshared=ipc;\n"),
            Some("[Context]\nfilesystems=home;\n"),
            Some("[Other]\nA=b\n"),
        ] {
            let once = unshare_network(before);
            assert_eq!(unshare_network(Some(&once)), once);
        }
    }
}
