// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Per-app network modes and how they become the rules the eBPF hooks
//! enforce (spec 4.7). Precedence: an organization lock beats an explicit
//! app rule, which beats the default for apps nobody decided about; the
//! lock layer is the core's and arrives as `locked`.

use std::collections::HashMap;

use ibexwall_identity::AppKind;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::store::{AppSummary, Error};

/// The migration the core applies after the rollups' one.
pub const POLICY_SCHEMA: &str = "CREATE TABLE app_modes (
         app_key TEXT PRIMARY KEY,
         mode TEXT NOT NULL,
         updated_at INTEGER NOT NULL
     );
     CREATE TABLE app_destination_modes (
         app_key TEXT NOT NULL,
         destination TEXT NOT NULL,
         port INTEGER NOT NULL,
         mode TEXT NOT NULL,
         updated_at INTEGER NOT NULL,
         PRIMARY KEY (app_key, destination, port)
     );
     CREATE TABLE net_settings (
         key TEXT PRIMARY KEY,
         value TEXT NOT NULL
     );";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Free access.
    Allow,
    /// Free access, everything recorded (the default).
    Monitor,
    /// The first connection waits for the user.
    Ask,
    /// No access.
    Block,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Allow => "allow",
            Mode::Monitor => "monitor",
            Mode::Ask => "ask",
            Mode::Block => "block",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [Mode::Allow, Mode::Monitor, Mode::Ask, Mode::Block]
            .into_iter()
            .find(|mode| mode.name() == text)
    }

    /// What the kernel does: allow and monitor are the same to it.
    pub fn verdict(self) -> &'static str {
        match self {
            Mode::Allow | Mode::Monitor => "allow",
            Mode::Ask => "ask",
            Mode::Block => "block",
        }
    }
}

/// One rule as the loader takes it. Exactly one matcher, or none for the
/// default.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KernelRule {
    /// The executable path, whole.
    pub exe_exact: Option<String>,
    /// A path prefix of the executable (kept for the spike's rule files).
    pub exe_prefix: Option<String>,
    /// Matches any cgroup whose path contains this text (Flatpak scopes
    /// carry a changing number, containers a changing id).
    pub cgroup_contains: Option<String>,
    /// A cgroup path prefix.
    pub cgroup_prefix: Option<String>,
    /// `allow`, `block` or `ask`.
    pub verdict: String,
}

/// The cgroup text that identifies an app of a kind that lives in its own
/// cgroup; `None` for programs identified by their executable.
pub fn cgroup_marker(app: &AppSummary) -> Option<String> {
    match app.kind {
        AppKind::Flatpak => Some(format!("app-flatpak-{}-", app.id)),
        AppKind::Snap => Some(format!("{}-", app.id)),
        AppKind::SystemService => Some(format!("/{}", app.id)),
        AppKind::Container => app.id.strip_prefix("container:").map(|id| format!("-{id}")),
        _ => None,
    }
}

/// The rule that enforces `mode` for `app`, if the app can be matched.
pub fn rule_for(app: &AppSummary, mode: Mode) -> Option<KernelRule> {
    let verdict = mode.verdict().to_string();
    if let Some(marker) = cgroup_marker(app) {
        return Some(KernelRule {
            cgroup_contains: Some(marker),
            verdict,
            ..KernelRule::default()
        });
    }
    app.exe_path.as_ref().map(|path| KernelRule {
        exe_exact: Some(path.clone()),
        verdict,
        ..KernelRule::default()
    })
}

/// Everything the loader needs: the rules, then the default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub rules: Vec<KernelRule>,
    /// What an app nobody decided about gets: `allow` or `ask`.
    pub default: String,
}

/// Builds the policy from the apps seen and the modes chosen. `locked`
/// apps (organization rules) override the user's choice. A mode only needs
/// a rule when it differs from the default.
pub fn build(
    apps: &[AppSummary],
    modes: &HashMap<String, Mode>,
    default: Mode,
    locked: &HashMap<String, Mode>,
) -> Policy {
    let default_verdict = default.verdict();
    let mut rules = Vec::new();
    for app in apps {
        let mode = locked
            .get(&app.key)
            .or_else(|| modes.get(&app.key))
            .copied();
        let Some(mode) = mode else { continue };
        if mode.verdict() == default_verdict {
            continue;
        }
        if let Some(rule) = rule_for(app, mode) {
            rules.push(rule);
        }
    }
    Policy {
        rules,
        default: default_verdict.to_string(),
    }
}

pub fn set_mode(conn: &Connection, app_key: &str, mode: Mode, now: i64) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO app_modes (app_key, mode, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT (app_key) DO UPDATE SET mode = excluded.mode, updated_at = excluded.updated_at",
        params![app_key, mode.name(), now],
    )?;
    Ok(())
}

pub fn clear_mode(conn: &Connection, app_key: &str) -> Result<(), Error> {
    conn.execute("DELETE FROM app_modes WHERE app_key = ?1", params![app_key])?;
    Ok(())
}

pub fn modes(conn: &Connection) -> Result<HashMap<String, Mode>, Error> {
    let mut stmt = conn.prepare("SELECT app_key, mode FROM app_modes")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut out = HashMap::new();
    for row in rows {
        let (key, text) = row?;
        if let Some(mode) = Mode::parse(&text) {
            out.insert(key, mode);
        }
    }
    Ok(out)
}

/// The mode for apps nobody decided about (`monitor` until changed).
pub fn default_mode(conn: &Connection) -> Result<Mode, Error> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM net_settings WHERE key = 'unknown_apps'",
            [],
            |row| row.get(0),
        )
        .ok();
    Ok(value
        .as_deref()
        .and_then(Mode::parse)
        .unwrap_or(Mode::Monitor))
}

pub fn set_default_mode(conn: &Connection, mode: Mode) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO net_settings (key, value) VALUES ('unknown_apps', ?1)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![mode.name()],
    )?;
    Ok(())
}

/// Remembers a decision for one destination of one app ("this
/// destination" scope).
pub fn set_destination_mode(
    conn: &Connection,
    app_key: &str,
    destination: &str,
    port: u16,
    mode: Mode,
    now: i64,
) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO app_destination_modes (app_key, destination, port, mode, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (app_key, destination, port)
         DO UPDATE SET mode = excluded.mode, updated_at = excluded.updated_at",
        params![app_key, destination, port, mode.name(), now],
    )?;
    Ok(())
}

pub fn destination_modes(
    conn: &Connection,
    app_key: &str,
) -> Result<Vec<(String, u16, Mode)>, Error> {
    let mut stmt = conn
        .prepare("SELECT destination, port, mode FROM app_destination_modes WHERE app_key = ?1")?;
    let rows = stmt.query_map(params![app_key], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, u16>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (destination, port, text) = row?;
        if let Some(mode) = Mode::parse(&text) {
            out.push((destination, port, mode));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(key: &str, kind: AppKind, id: &str, exe: Option<&str>) -> AppSummary {
        AppSummary {
            key: key.into(),
            kind,
            id: id.into(),
            exe_path: exe.map(str::to_string),
            package: None,
            first_seen: 0,
            last_seen: 0,
            connections: 0,
            destinations: 0,
        }
    }

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(POLICY_SCHEMA).unwrap();
        conn
    }

    #[test]
    fn modes_parse_and_map_to_kernel_verdicts() {
        for mode in [Mode::Allow, Mode::Monitor, Mode::Ask, Mode::Block] {
            assert_eq!(Mode::parse(mode.name()), Some(mode));
        }
        assert_eq!(Mode::parse("deny"), None);
        assert_eq!(Mode::Monitor.verdict(), "allow");
        assert_eq!(Mode::Allow.verdict(), "allow");
        assert_eq!(Mode::Ask.verdict(), "ask");
        assert_eq!(Mode::Block.verdict(), "block");
    }

    #[test]
    fn each_kind_of_app_is_matched_the_way_it_can_be() {
        let flatpak = app("flatpak:org.a.B", AppKind::Flatpak, "org.a.B", None);
        assert_eq!(
            rule_for(&flatpak, Mode::Block)
                .unwrap()
                .cgroup_contains
                .as_deref(),
            Some("app-flatpak-org.a.B-")
        );
        let service = app(
            "service:ssh.service",
            AppKind::SystemService,
            "ssh.service",
            None,
        );
        assert_eq!(
            rule_for(&service, Mode::Block)
                .unwrap()
                .cgroup_contains
                .as_deref(),
            Some("/ssh.service")
        );
        let container = app(
            "container:0123456789ab",
            AppKind::Container,
            "container:0123456789ab",
            None,
        );
        assert_eq!(
            rule_for(&container, Mode::Ask)
                .unwrap()
                .cgroup_contains
                .as_deref(),
            Some("-0123456789ab")
        );
        let cli = app("cli:/usr/bin/curl", AppKind::Cli, "", Some("/usr/bin/curl"));
        let rule = rule_for(&cli, Mode::Block).unwrap();
        assert_eq!(rule.exe_exact.as_deref(), Some("/usr/bin/curl"));
        assert_eq!(rule.verdict, "block");
        // No cgroup identity and no executable: nothing to match.
        assert!(rule_for(&app("cli:?", AppKind::Cli, "", None), Mode::Block).is_none());
    }

    #[test]
    fn only_what_differs_from_the_default_needs_a_rule() {
        let apps = vec![
            app("cli:/usr/bin/curl", AppKind::Cli, "", Some("/usr/bin/curl")),
            app("cli:/usr/bin/wget", AppKind::Cli, "", Some("/usr/bin/wget")),
            app("cli:/usr/bin/git", AppKind::Cli, "", Some("/usr/bin/git")),
        ];
        let modes = HashMap::from([
            ("cli:/usr/bin/curl".to_string(), Mode::Block),
            ("cli:/usr/bin/wget".to_string(), Mode::Allow),
        ]);
        let policy = build(&apps, &modes, Mode::Monitor, &HashMap::new());
        assert_eq!(policy.default, "allow");
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].exe_exact.as_deref(), Some("/usr/bin/curl"));
        // With an "ask by default" world, an explicit allow becomes a rule.
        let policy = build(&apps, &modes, Mode::Ask, &HashMap::new());
        assert_eq!(policy.default, "ask");
        let verdicts: Vec<_> = policy.rules.iter().map(|r| r.verdict.as_str()).collect();
        assert_eq!(verdicts, ["block", "allow"]);
    }

    #[test]
    fn an_organization_lock_beats_the_users_choice() {
        let apps = vec![app(
            "cli:/usr/bin/curl",
            AppKind::Cli,
            "",
            Some("/usr/bin/curl"),
        )];
        let modes = HashMap::from([("cli:/usr/bin/curl".to_string(), Mode::Allow)]);
        let locked = HashMap::from([("cli:/usr/bin/curl".to_string(), Mode::Block)]);
        let policy = build(&apps, &modes, Mode::Monitor, &locked);
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].verdict, "block");
    }

    #[test]
    fn modes_persist_and_a_missing_default_is_monitor() {
        let conn = db();
        assert_eq!(default_mode(&conn).unwrap(), Mode::Monitor);
        set_mode(&conn, "cli:/x", Mode::Block, 1).unwrap();
        set_mode(&conn, "cli:/x", Mode::Ask, 2).unwrap();
        set_mode(&conn, "flatpak:a.b.c", Mode::Allow, 3).unwrap();
        let all = modes(&conn).unwrap();
        assert_eq!(all["cli:/x"], Mode::Ask);
        assert_eq!(all.len(), 2);
        clear_mode(&conn, "cli:/x").unwrap();
        assert_eq!(modes(&conn).unwrap().len(), 1);
        set_default_mode(&conn, Mode::Ask).unwrap();
        assert_eq!(default_mode(&conn).unwrap(), Mode::Ask);
        // A corrupt stored value falls back, never panics.
        conn.execute("UPDATE net_settings SET value = 'garbage'", [])
            .unwrap();
        assert_eq!(default_mode(&conn).unwrap(), Mode::Monitor);
    }

    #[test]
    fn destination_decisions_are_remembered_per_app() {
        let conn = db();
        set_destination_mode(&conn, "cli:/x", "example.com", 443, Mode::Allow, 1).unwrap();
        set_destination_mode(&conn, "cli:/x", "example.com", 443, Mode::Block, 2).unwrap();
        set_destination_mode(&conn, "cli:/x", "203.0.113.7", 80, Mode::Allow, 3).unwrap();
        set_destination_mode(&conn, "cli:/y", "example.com", 443, Mode::Allow, 4).unwrap();
        let mut found = destination_modes(&conn, "cli:/x").unwrap();
        found.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            found,
            vec![
                ("203.0.113.7".to_string(), 80, Mode::Allow),
                ("example.com".to_string(), 443, Mode::Block),
            ]
        );
    }
}
