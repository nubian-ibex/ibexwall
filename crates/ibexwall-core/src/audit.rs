// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Append-only audit log with a SHA-256 hash chain over JCS entries
//! (spec §4.4): `hash = SHA-256(prev_hash || JCS(entry))`.
//! `ibexctl audit verify` walks the chain; any tampering breaks it.

use anyhow::Result;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: i64,
    pub ts: String,
    pub actor: String,
    pub plugin: String,
    #[serde(default)]
    pub transaction: Option<String>,
    pub ops_digest: String,
    pub result: String,
    #[serde(default)]
    pub hash: String,
}

/// The table is made on first use, so a fresh install has none: reading it
/// then is an empty chain, not an error.
fn ensure_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS audit_log (
             seq INTEGER PRIMARY KEY AUTOINCREMENT,
             ts TEXT NOT NULL,
             actor TEXT NOT NULL,
             plugin TEXT NOT NULL,
             tx_id TEXT,
             ops_digest TEXT NOT NULL,
             result TEXT NOT NULL,
             prev_hash TEXT NOT NULL,
             hash TEXT NOT NULL
         )",
        [],
    )?;
    Ok(())
}

/// The newest `limit` entries, newest first (the chain's own columns, no
/// hashes).
pub fn tail(conn: &Connection, limit: usize) -> Result<Vec<AuditEntry>> {
    ensure_table(conn)?;
    let mut stmt = conn.prepare(
        "SELECT seq, ts, actor, plugin, tx_id, ops_digest, result FROM audit_log
         ORDER BY seq DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit as i64], |row| {
        Ok(AuditEntry {
            seq: row.get(0)?,
            ts: row.get(1)?,
            actor: row.get(2)?,
            plugin: row.get(3)?,
            transaction: row.get(4)?,
            ops_digest: row.get(5)?,
            result: row.get(6)?,
            hash: String::new(),
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// Appends one entry, computing and storing its chain hash.
pub fn append(
    conn: &Connection,
    ts: &str,
    actor: &str,
    plugin: &str,
    transaction: Option<&str>,
    ops_digest: &str,
    result: &str,
) -> Result<String> {
    let tx = conn.unchecked_transaction()?;
    ensure_table(&tx)?;
    let prev_hash: String = tx
        .query_row(
            "SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| "0".repeat(64));

    let entry = AuditEntry {
        // seq is storage metadata; the digest excludes it.
        seq: 0,
        ts: ts.to_string(),
        actor: actor.to_string(),
        plugin: plugin.to_string(),
        transaction: transaction.map(str::to_string),
        ops_digest: ops_digest.to_string(),
        result: result.to_string(),
        hash: String::new(),
    };
    let hash = compute_hash(&prev_hash, &entry);
    tx.execute(
        "INSERT INTO audit_log (ts, actor, plugin, tx_id, ops_digest, result, prev_hash, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            ts,
            actor,
            plugin,
            transaction,
            ops_digest,
            result,
            prev_hash,
            hash
        ],
    )?;
    let seq = tx.last_insert_rowid();
    // Anchor the head outside the log: deleting the newest rows leaves a
    // self-consistent prefix, and the anchor is how verify detects it.
    tx.execute(
        "CREATE TABLE IF NOT EXISTS audit_anchor (
             id INTEGER PRIMARY KEY CHECK (id = 1),
             seq INTEGER NOT NULL,
             hash TEXT NOT NULL
         )",
        [],
    )?;
    tx.execute(
        "INSERT INTO audit_anchor (id, seq, hash) VALUES (1, ?1, ?2)
         ON CONFLICT(id) DO UPDATE SET seq = excluded.seq, hash = excluded.hash",
        rusqlite::params![seq, hash],
    )?;
    tx.commit()?;
    Ok(hash)
}

fn compute_hash(prev_hash: &str, entry: &AuditEntry) -> String {
    // The chain hashes the entry content only; `seq` and `hash` are
    // storage metadata and excluded from the digest.
    let payload = serde_json::json!({
        "ts": entry.ts,
        "actor": entry.actor,
        "plugin": entry.plugin,
        "transaction": entry.transaction,
        "ops_digest": entry.ops_digest,
        "result": entry.result,
    });
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(serde_jcs::to_vec(&payload).expect("audit payload serializes"));
    hex::encode(hasher.finalize())
}

#[derive(Debug, PartialEq)]
pub enum Verification {
    Valid { entries: usize },
    Broken { seq: i64, reason: String },
}

/// Walks the whole chain: re-computes every hash and checks linkage.
pub fn verify(conn: &Connection) -> Result<Verification> {
    ensure_table(conn)?;
    let mut stmt = conn.prepare(
        "SELECT seq, ts, actor, plugin, tx_id, ops_digest, result, prev_hash, hash
         FROM audit_log ORDER BY seq",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
        ))
    })?;

    let mut expected_prev: String = "0".repeat(64);
    let mut count = 0usize;
    let mut last_seq = 0i64;
    let mut last_hash = "0".repeat(64);
    for row in rows {
        let (seq, ts, actor, plugin, transaction, ops_digest, result, prev_hash, hash) = row?;
        count += 1;
        if prev_hash != expected_prev {
            return Ok(Verification::Broken {
                seq,
                reason: format!("prev_hash mismatch: stored {prev_hash}, expected {expected_prev}"),
            });
        }
        let entry = AuditEntry {
            seq,
            ts,
            actor,
            plugin,
            transaction,
            ops_digest,
            result,
            hash: String::new(),
        };
        let computed = compute_hash(&expected_prev, &entry);
        if computed != hash {
            return Ok(Verification::Broken {
                seq,
                reason: format!("hash mismatch at seq {seq}: stored {hash}, computed {computed}"),
            });
        }
        expected_prev = hash.clone();
        last_seq = seq;
        last_hash = hash;
    }
    // The anchor records the true head; if the newest rows were deleted
    // the prefix still hashes, so only the anchor can tell.
    let anchored: Option<(i64, String)> = conn
        .query_row(
            "SELECT seq, hash FROM audit_anchor WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();
    if let Some((seq, hash)) = anchored
        && (seq != last_seq || hash != last_hash)
    {
        return Ok(Verification::Broken {
            seq: last_seq,
            reason: format!("the chain head was truncated: anchor points at seq {seq}"),
        });
    }
    Ok(Verification::Valid { entries: count })
}

/// SHA-256 over the serialized ops (digest stored in audit entries).
pub fn ops_digest(ops: &[ibexwall_proto::Op]) -> String {
    let bytes = serde_jcs::to_vec(&ops).unwrap_or_default();
    hex::encode(Sha256::digest(&bytes))
}

/// The head hash of the audit chain, for an export that binds evidence
/// to the history. `None` when the chain is empty.
pub fn head_hash(conn: &Connection) -> Option<String> {
    conn.query_row("SELECT hash FROM audit_anchor WHERE id = 1", [], |row| {
        row.get(0)
    })
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE audit_log (
                 seq INTEGER PRIMARY KEY AUTOINCREMENT,
                 ts TEXT NOT NULL, actor TEXT NOT NULL, plugin TEXT NOT NULL,
                 tx_id TEXT, ops_digest TEXT NOT NULL, result TEXT NOT NULL,
                 prev_hash TEXT NOT NULL, hash TEXT NOT NULL)",
            [],
        )
        .unwrap();
        conn
    }

    #[test]
    fn a_fresh_database_has_a_valid_empty_chain() {
        let conn = Connection::open_in_memory().unwrap();
        assert!(matches!(
            verify(&conn).unwrap(),
            Verification::Valid { entries: 0 }
        ));
        assert!(tail(&conn, 10).unwrap().is_empty());
    }

    #[test]
    fn chain_verifies_when_intact() {
        let conn = conn();
        for i in 0..5 {
            append(
                &conn,
                "2026-11-01T12:00:00Z",
                "user:1000",
                "dev.echo",
                Some("tx"),
                &format!("d{i}"),
                "ok",
            )
            .unwrap();
        }
        match verify(&conn).unwrap() {
            Verification::Valid { entries } => assert_eq!(entries, 5),
            other => panic!("expected valid chain, got {other:?}"),
        }
    }

    #[test]
    fn chain_detects_tampering() {
        let conn = conn();
        append(
            &conn,
            "2026-11-01T12:00:00Z",
            "user:1000",
            "dev.echo",
            None,
            "d1",
            "ok",
        )
        .unwrap();
        append(
            &conn,
            "2026-11-01T12:00:01Z",
            "user:1000",
            "dev.echo",
            None,
            "d2",
            "ok",
        )
        .unwrap();
        // Tamper: flip the first entry's result.
        conn.execute("UPDATE audit_log SET result = 'evil' WHERE seq = 1", [])
            .unwrap();
        match verify(&conn).unwrap() {
            Verification::Broken { seq, reason } => {
                assert_eq!(seq, 1);
                assert!(reason.contains("hash mismatch"));
            }
            other => panic!("expected broken chain, got {other:?}"),
        }
    }

    #[test]
    fn chain_detects_truncation() {
        let conn = conn();
        append(&conn, "t", "user:0", "p", None, "d", "ok").unwrap();
        append(&conn, "t", "user:0", "p", None, "d", "ok").unwrap();
        conn.execute("DELETE FROM audit_log WHERE seq = 1", [])
            .unwrap();
        match verify(&conn).unwrap() {
            Verification::Broken { seq: 2, .. } => {}
            other => panic!("expected broken chain, got {other:?}"),
        }
    }

    #[test]
    fn chain_detects_a_deleted_tail() {
        let conn = conn();
        append(&conn, "t", "user:0", "p", None, "d1", "ok").unwrap();
        append(&conn, "t", "user:0", "p", None, "d2", "ok").unwrap();
        // Deleting the newest row leaves a self-consistent prefix; only
        // the anchor can tell the head was cut off.
        conn.execute("DELETE FROM audit_log WHERE seq = 2", [])
            .unwrap();
        match verify(&conn).unwrap() {
            Verification::Broken { reason, .. } => {
                assert!(reason.contains("truncated"), "{reason}")
            }
            other => panic!("expected a truncated-chain verdict, got {other:?}"),
        }
    }
}
