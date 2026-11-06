// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The shape shared by the plugins that run an outside scanner (rkhunter,
//! OpenSCAP, nmap, ClamAV): a oneshot service that runs it as root with a
//! read-only system and writes its report under a state directory, an
//! optional timer, and a check that reads the report later. The plugin
//! never runs the tool itself and never installs it.

/// A plain absolute path: no `..`, no spaces or shell characters.
pub fn safe_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains("..")
        && path.len() <= 200
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'+'))
}

/// `hourly`, `daily` or `weekly`; empty means daily.
pub fn schedule(every: &str) -> Option<&'static str> {
    match every {
        "" | "daily" => Some("daily"),
        "hourly" => Some("hourly"),
        "weekly" => Some("weekly"),
        _ => None,
    }
}

pub struct Service<'a> {
    /// Who wrote the unit, for the header (`endpoint.rootkit`).
    pub plugin: &'a str,
    pub description: &'a str,
    /// `ibexwall/rootkit`: a directory under /var/lib the unit may write.
    pub state_dir: &'a str,
    /// Extra places the tool writes (its own database), read-write.
    pub writable: &'a [&'a str],
    /// Lines run in order. A scanner exits non-zero when it finds
    /// something: that is its result, so each starts with `-`.
    pub commands: &'a [String],
    /// Wall-clock limit, as systemd takes it (`30min`).
    pub timeout: &'a str,
    /// A scanner that looks for what is hidden in /dev and /tmp has to see
    /// the real ones; the others run with private copies.
    pub host_view: bool,
    /// Some tools run in an SELinux domain of their own (nmap does, as
    /// traceroute_t), and the transition is refused under NoNewPrivileges.
    /// Those units say so; the rest keep it on.
    pub no_new_privileges: bool,
}

pub fn service_unit(s: &Service<'_>) -> String {
    let mut out = format!(
        "# Managed by IbexWall ({}).\n[Unit]\nDescription={}\n\n[Service]\nType=oneshot\nStateDirectory={}\nNice=10\nIOSchedulingClass=idle\nTimeoutStartSec={}\nProtectSystem=strict\nProtectHome=read-only\n",
        s.plugin, s.description, s.state_dir, s.timeout
    );
    if s.no_new_privileges {
        out.push_str("NoNewPrivileges=yes\n");
    }
    if !s.host_view {
        out.push_str("PrivateDevices=yes\nPrivateTmp=yes\n");
    }
    if !s.writable.is_empty() {
        out.push_str(&format!("ReadWritePaths=-{}\n", s.writable.join(" -")));
    }
    for command in s.commands {
        out.push_str(&format!("ExecStart={command}\n"));
    }
    out
}

pub fn timer_unit(plugin: &str, description: &str, every: &str) -> String {
    format!(
        "# Managed by IbexWall ({plugin}).\n[Unit]\nDescription={description}, {every}\n\n[Timer]\nOnCalendar={every}\nPersistent=true\nRandomizedDelaySec=15m\n\n[Install]\nWantedBy=timers.target\n"
    )
}

/// Keeps a line of a tool's output short and plain before it becomes text a
/// person reads: control characters and markup are dropped.
pub fn clean_line(line: &str, max: usize) -> String {
    line.chars()
        .filter(|c| !c.is_control())
        .map(|c| if matches!(c, '<' | '>') { ' ' } else { c })
        .take(max)
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_schedules_and_lines_are_checked() {
        assert!(
            safe_path("/var/lib/ibexwall/x")
                && !safe_path("/a/../b")
                && !safe_path("rel")
                && !safe_path("/a b")
                && !safe_path("/a;b")
        );
        assert_eq!(
            (schedule(""), schedule("weekly"), schedule("monthly")),
            (Some("daily"), Some("weekly"), None)
        );
        let line = clean_line("  Warning: <b>x</b>\u{1b}[0m\n", 100);
        assert!(
            line.starts_with("Warning:") && !line.contains(['<', '>', '\u{1b}', '\n']),
            "{line}"
        );
        assert_eq!(clean_line(&"a".repeat(500), 10).len(), 10);
    }

    #[test]
    fn the_service_is_a_read_only_oneshot_whose_scanner_may_exit_non_zero() {
        let unit = service_unit(&Service {
            plugin: "endpoint.rootkit",
            description: "IbexWall rootkit scan",
            state_dir: "ibexwall/rootkit",
            writable: &["/var/lib/rkhunter"],
            commands: &["-/usr/bin/rkhunter --check".to_string()],
            timeout: "30min",
            host_view: false,
            no_new_privileges: true,
        });
        for want in [
            "Type=oneshot",
            "ProtectSystem=strict",
            "NoNewPrivileges=yes",
            "ReadWritePaths=-/var/lib/rkhunter",
            "ExecStart=-/usr/bin/rkhunter --check",
            "TimeoutStartSec=30min",
        ] {
            assert!(unit.contains(want), "{want}\n{unit}");
        }
        assert!(timer_unit("p", "d", "daily").contains("OnCalendar=daily"));
    }
}
