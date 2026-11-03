// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Per-app rollups. Counts, first seen and last seen only: no per-event
//! history is kept, and nothing here is sent anywhere (zero telemetry).

use ibexwall_identity::{AppKind, Identity};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

/// The migration the core applies; kept next to the code that uses it.
pub const SCHEMA: &str = "CREATE TABLE apps (
         key TEXT PRIMARY KEY,
         kind TEXT NOT NULL,
         id TEXT NOT NULL,
         exe_path TEXT,
         exe_hash TEXT,
         package TEXT,
         first_seen INTEGER NOT NULL,
         last_seen INTEGER NOT NULL,
         connections INTEGER NOT NULL DEFAULT 0
     );
     CREATE TABLE app_destinations (
         app_key TEXT NOT NULL REFERENCES apps(key) ON DELETE CASCADE,
         destination TEXT NOT NULL,
         port INTEGER NOT NULL,
         count INTEGER NOT NULL DEFAULT 0,
         first_seen INTEGER NOT NULL,
         last_seen INTEGER NOT NULL,
         PRIMARY KEY (app_key, destination, port)
     );";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
}

/// One connection attempt, already identified and correlated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub identity: Identity,
    pub exe_path: Option<String>,
    pub exe_hash: Option<String>,
    pub package: Option<String>,
    /// The domain the destination was answered for, when known; without
    /// one the destination is stored by address.
    pub domain: Option<String>,
    pub address: String,
    pub port: u16,
    /// Unix seconds.
    pub now: i64,
    /// When the package manager's database last changed (unix seconds);
    /// a hash change after this moment is an update, not tampering.
    pub package_db_changed: Option<i64>,
}

/// Something worth telling the user. Fields are untrusted data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "alert", rename_all = "snake_case")]
pub enum Alert {
    /// An application connected for the first time.
    FirstConnection { app: String, kind: AppKind },
    /// Same path, different content, and no package transaction explains it.
    BinaryChanged {
        app: String,
        exe_path: String,
        old_hash: String,
        new_hash: String,
    },
}

/// One row for the Apps screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSummary {
    pub key: String,
    pub kind: AppKind,
    pub id: String,
    pub exe_path: Option<String>,
    pub package: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub connections: i64,
    pub destinations: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationSummary {
    /// A domain, or the bare address when no answer was correlated.
    pub destination: String,
    pub resolved: bool,
    pub port: u16,
    pub count: i64,
    pub first_seen: i64,
    pub last_seen: i64,
}

/// The stable key of an app: its identity, or the exe for CLI and unknown.
pub fn app_key(identity: &Identity, exe_path: Option<&str>) -> String {
    match identity.kind {
        AppKind::Cli | AppKind::Unknown => {
            format!("{}:{}", kind_name(identity.kind), exe_path.unwrap_or("?"))
        }
        kind => format!("{}:{}", kind_name(kind), identity.id),
    }
}

fn kind_name(kind: AppKind) -> &'static str {
    match kind {
        AppKind::Flatpak => "flatpak",
        AppKind::Snap => "snap",
        AppKind::DesktopApp => "app",
        AppKind::SystemService => "service",
        AppKind::Container => "container",
        AppKind::Cli => "cli",
        AppKind::Unknown => "unknown",
    }
}

fn kind_from(name: &str) -> AppKind {
    match name {
        "flatpak" => AppKind::Flatpak,
        "snap" => AppKind::Snap,
        "app" => AppKind::DesktopApp,
        "service" => AppKind::SystemService,
        "container" => AppKind::Container,
        "cli" => AppKind::Cli,
        _ => AppKind::Unknown,
    }
}

/// Destinations without a correlated domain are stored as `ip:<addr>` so
/// a domain can never be confused with an address.
fn destination_key(observation: &Observation) -> String {
    match &observation.domain {
        Some(domain) => domain.clone(),
        None => format!("ip:{}", observation.address),
    }
}

/// Records one observation and returns the alerts it raises.
pub fn record(conn: &Connection, observation: &Observation) -> Result<Vec<Alert>, Error> {
    let key = app_key(&observation.identity, observation.exe_path.as_deref());
    let now = observation.now;
    let mut alerts = Vec::new();

    let known: Option<(Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT exe_path, exe_hash FROM apps WHERE key = ?1",
            params![key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })?;

    match known {
        None => {
            conn.execute(
                "INSERT INTO apps (key, kind, id, exe_path, exe_hash, package, first_seen, last_seen, connections)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 1)",
                params![
                    key,
                    kind_name(observation.identity.kind),
                    observation.identity.id,
                    observation.exe_path,
                    observation.exe_hash,
                    observation.package,
                    now
                ],
            )?;
            alerts.push(Alert::FirstConnection {
                app: key.clone(),
                kind: observation.identity.kind,
            });
        }
        Some((old_path, old_hash)) => {
            let changed = match (&old_hash, &observation.exe_hash) {
                (Some(old), Some(new)) if old != new && old_path == observation.exe_path => {
                    Some((old.clone(), new.clone()))
                }
                _ => None,
            };
            if let Some((old, new)) = changed {
                let explained = observation.package_db_changed.is_some_and(|changed_at| {
                    let last_seen: i64 = conn
                        .query_row(
                            "SELECT last_seen FROM apps WHERE key = ?1",
                            params![key],
                            |row| row.get(0),
                        )
                        .unwrap_or(0);
                    changed_at >= last_seen
                });
                if !explained {
                    alerts.push(Alert::BinaryChanged {
                        app: key.clone(),
                        exe_path: observation.exe_path.clone().unwrap_or_default(),
                        old_hash: old,
                        new_hash: new,
                    });
                }
            }
            // The newest hash and package replace the old ones either way,
            // so the same change alerts once, not on every connection.
            conn.execute(
                "UPDATE apps SET last_seen = ?2, connections = connections + 1,
                     exe_hash = COALESCE(?3, exe_hash),
                     package = COALESCE(?4, package),
                     exe_path = COALESCE(?5, exe_path)
                 WHERE key = ?1",
                params![
                    key,
                    now,
                    observation.exe_hash,
                    observation.package,
                    observation.exe_path
                ],
            )?;
        }
    }

    conn.execute(
        "INSERT INTO app_destinations (app_key, destination, port, count, first_seen, last_seen)
         VALUES (?1, ?2, ?3, 1, ?4, ?4)
         ON CONFLICT (app_key, destination, port)
         DO UPDATE SET count = count + 1, last_seen = excluded.last_seen",
        params![key, destination_key(observation), observation.port, now],
    )?;
    Ok(alerts)
}

/// Apps ordered by most recent activity.
pub fn list_apps(conn: &Connection) -> Result<Vec<AppSummary>, Error> {
    let mut stmt = conn.prepare(
        "SELECT a.key, a.kind, a.id, a.exe_path, a.package, a.first_seen, a.last_seen, a.connections,
                (SELECT COUNT(*) FROM app_destinations d WHERE d.app_key = a.key)
         FROM apps a ORDER BY a.last_seen DESC, a.key",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(AppSummary {
            key: row.get(0)?,
            kind: kind_from(&row.get::<_, String>(1)?),
            id: row.get(2)?,
            exe_path: row.get(3)?,
            package: row.get(4)?,
            first_seen: row.get(5)?,
            last_seen: row.get(6)?,
            connections: row.get(7)?,
            destinations: row.get(8)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// One app's destinations, busiest first.
pub fn list_destinations(
    conn: &Connection,
    app_key: &str,
) -> Result<Vec<DestinationSummary>, Error> {
    let mut stmt = conn.prepare(
        "SELECT destination, port, count, first_seen, last_seen FROM app_destinations
         WHERE app_key = ?1 ORDER BY count DESC, destination",
    )?;
    let rows = stmt.query_map(params![app_key], |row| {
        let destination: String = row.get(0)?;
        let (destination, resolved) = match destination.strip_prefix("ip:") {
            Some(address) => (address.to_string(), false),
            None => (destination, true),
        };
        Ok(DestinationSummary {
            destination,
            resolved,
            port: row.get(1)?,
            count: row.get(2)?,
            first_seen: row.get(3)?,
            last_seen: row.get(4)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Retention: forgets apps (and their destinations) idle since `before`.
pub fn prune(conn: &Connection, before: i64) -> Result<usize, Error> {
    // Destinations go through ON DELETE CASCADE, which needs the pragma.
    conn.execute("PRAGMA foreign_keys = ON", [])?;
    Ok(conn.execute("DELETE FROM apps WHERE last_seen < ?1", params![before])?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn
    }

    fn observation(now: i64) -> Observation {
        Observation {
            identity: Identity {
                kind: AppKind::Flatpak,
                id: "org.mozilla.firefox".into(),
            },
            exe_path: Some("/app/lib/firefox/firefox".into()),
            exe_hash: Some("aa".into()),
            package: None,
            domain: Some("example.com".into()),
            address: "93.184.216.34".into(),
            port: 443,
            now,
            package_db_changed: None,
        }
    }

    #[test]
    fn the_first_connection_alerts_once() {
        let conn = db();
        let first = record(&conn, &observation(100)).unwrap();
        assert_eq!(
            first,
            vec![Alert::FirstConnection {
                app: "flatpak:org.mozilla.firefox".into(),
                kind: AppKind::Flatpak
            }]
        );
        assert!(record(&conn, &observation(101)).unwrap().is_empty());
    }

    #[test]
    fn counts_and_times_roll_up_per_destination() {
        let conn = db();
        record(&conn, &observation(100)).unwrap();
        record(&conn, &observation(160)).unwrap();
        let mut other = observation(170);
        other.domain = None;
        other.address = "203.0.113.7".into();
        other.port = 8080;
        record(&conn, &other).unwrap();

        let apps = list_apps(&conn).unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].connections, 3);
        assert_eq!(apps[0].destinations, 2);
        assert_eq!((apps[0].first_seen, apps[0].last_seen), (100, 170));

        let destinations = list_destinations(&conn, "flatpak:org.mozilla.firefox").unwrap();
        assert_eq!(destinations[0].destination, "example.com");
        assert!(destinations[0].resolved);
        assert_eq!(destinations[0].count, 2);
        assert_eq!(
            (destinations[0].first_seen, destinations[0].last_seen),
            (100, 160)
        );
        assert_eq!(destinations[1].destination, "203.0.113.7");
        assert!(!destinations[1].resolved);
        assert_eq!(destinations[1].port, 8080);
    }

    #[test]
    fn a_changed_binary_without_a_package_transaction_alerts() {
        let conn = db();
        record(&conn, &observation(100)).unwrap();
        let mut changed = observation(200);
        changed.exe_hash = Some("bb".into());
        let alerts = record(&conn, &changed).unwrap();
        assert_eq!(
            alerts,
            vec![Alert::BinaryChanged {
                app: "flatpak:org.mozilla.firefox".into(),
                exe_path: "/app/lib/firefox/firefox".into(),
                old_hash: "aa".into(),
                new_hash: "bb".into()
            }]
        );
        // The new hash is now the baseline: no repeat alert.
        assert!(record(&conn, &changed).unwrap().is_empty());
    }

    #[test]
    fn a_package_update_explains_a_new_hash() {
        let conn = db();
        record(&conn, &observation(100)).unwrap();
        let mut updated = observation(200);
        updated.exe_hash = Some("bb".into());
        updated.package_db_changed = Some(150);
        assert!(record(&conn, &updated).unwrap().is_empty());
        // Package activity from before the app was last seen explains nothing.
        let mut stale = observation(300);
        stale.exe_hash = Some("cc".into());
        stale.package_db_changed = Some(50);
        assert_eq!(record(&conn, &stale).unwrap().len(), 1);
    }

    #[test]
    fn a_missing_hash_never_alerts() {
        let conn = db();
        record(&conn, &observation(100)).unwrap();
        let mut blind = observation(200);
        blind.exe_hash = None;
        assert!(record(&conn, &blind).unwrap().is_empty());
        // And it does not erase the baseline.
        let mut again = observation(210);
        again.exe_hash = Some("aa".into());
        assert!(record(&conn, &again).unwrap().is_empty());
    }

    #[test]
    fn cli_programs_are_keyed_by_exe() {
        let identity = Identity {
            kind: AppKind::Cli,
            id: String::new(),
        };
        assert_eq!(
            app_key(&identity, Some("/usr/bin/curl")),
            "cli:/usr/bin/curl"
        );
        assert_eq!(app_key(&identity, None), "cli:?");
        let conn = db();
        let mut a = observation(1);
        a.identity = identity.clone();
        a.exe_path = Some("/usr/bin/curl".into());
        let mut b = a.clone();
        b.exe_path = Some("/usr/bin/wget".into());
        record(&conn, &a).unwrap();
        record(&conn, &b).unwrap();
        assert_eq!(list_apps(&conn).unwrap().len(), 2);
    }

    #[test]
    fn hostile_text_is_stored_as_data() {
        let conn = db();
        let mut o = observation(1);
        o.domain = Some("x'; DROP TABLE apps;--".into());
        o.exe_path = Some("/tmp/'; DROP TABLE apps;--".into());
        record(&conn, &o).unwrap();
        assert_eq!(list_apps(&conn).unwrap().len(), 1);
    }

    #[test]
    fn prune_forgets_idle_apps_and_their_destinations() {
        let conn = db();
        record(&conn, &observation(100)).unwrap();
        let mut other = observation(900);
        other.identity.id = "org.example.fresh".into();
        record(&conn, &other).unwrap();
        assert_eq!(prune(&conn, 500).unwrap(), 1);
        let apps = list_apps(&conn).unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].id, "org.example.fresh");
        let orphans: i64 = conn
            .query_row("SELECT COUNT(*) FROM app_destinations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(orphans, 1);
    }
}
