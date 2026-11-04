// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The proposal queue (spec 4.12). A client (the MCP assistant) proposes a
//! change to a plugin; the core plans it at once, so the human sees the real
//! operations, and keeps the proposal until someone with
//! `com.ibexwall.proposals.decide` approves or rejects it. Approving plans
//! again from the stored patch and refuses when the operations are not the
//! ones that were reviewed. The client's name and the AI's justification are
//! untrusted text: stored and shown as data, never executed.

use anyhow::Result;
use ibexwall_proto::{Event, Plan, Proposal, ProposalStatus, Severity};
use ibexwall_sys::{Clock, format_rfc3339};
use serde_json::Value;

use crate::Core;

/// Pending proposals the queue holds at once, and per client: a client that
/// floods the queue gets refused, it cannot bury the human's review.
pub const MAX_PENDING: usize = 20;
pub const MAX_PENDING_PER_CLIENT: usize = 8;
/// A proposal nobody decided in this long is expired.
pub const EXPIRY_SECS: i64 = 24 * 3600;
/// Longest justification kept.
pub const MAX_JUSTIFICATION: usize = 2000;

fn status_name(status: ProposalStatus) -> &'static str {
    match status {
        ProposalStatus::Pending => "pending",
        ProposalStatus::Approved => "approved",
        ProposalStatus::Rejected => "rejected",
        ProposalStatus::Expired => "expired",
    }
}

/// Control characters out, bounded: logs and terminals never see the raw text.
pub fn clean(text: &str, max: usize) -> String {
    text.chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .take(max)
        .collect()
}

fn row_to_proposal(json: &str, status: &str, decided: Option<i64>) -> Option<Proposal> {
    let mut proposal: Proposal = serde_json::from_str(json).ok()?;
    proposal.status = match status {
        "approved" => ProposalStatus::Approved,
        "rejected" => ProposalStatus::Rejected,
        "expired" => ProposalStatus::Expired,
        _ => ProposalStatus::Pending,
    };
    proposal.decided_at = decided.map(format_rfc3339);
    Some(proposal)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("too many proposals are waiting")]
    Full,
    #[error("this client has too many proposals waiting")]
    ClientFull,
    #[error("the change cannot be rolled back, so it cannot be proposed")]
    Irreversible,
    #[error("no such proposal")]
    NotFound,
    #[error("the proposal was already decided")]
    Decided,
    #[error("the plan changed since it was reviewed")]
    Stale,
    #[error("{0}")]
    Other(String),
}

impl Core {
    /// Pending proposals past their expiry become `expired`.
    fn expire_proposals(&self, now: i64) -> Result<()> {
        self.state.with_conn(|conn| {
            conn.execute(
                "UPDATE proposals SET status = 'expired' WHERE status = 'pending' AND created_at < ?1",
                [now - EXPIRY_SECS],
            )?;
            Ok(())
        })
    }

    pub fn list_proposals(&self, status: Option<&str>) -> Result<Vec<Proposal>> {
        let now = ibexwall_sys::RealClock.unix_now();
        self.expire_proposals(now)?;
        self.state.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT json, status, decided_at FROM proposals
                 WHERE (?1 IS NULL OR status = ?1) ORDER BY created_at DESC, id DESC LIMIT 200",
            )?;
            let rows = stmt.query_map([status], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (json, status, decided) = row?;
                if let Some(p) = row_to_proposal(&json, &status, decided) {
                    out.push(p);
                }
            }
            Ok(out)
        })
    }

    /// Stores a proposal for a plan the caller already built.
    pub fn create_proposal(
        &self,
        client: &str,
        plan: &Plan,
        patch: Value,
        justification: &str,
        ops_digest: &str,
    ) -> Result<Proposal, Error> {
        let now = ibexwall_sys::RealClock.unix_now();
        self.expire_proposals(now)
            .map_err(|e| Error::Other(e.to_string()))?;
        // The assistant may only propose what a human can take back.
        if plan.reversible == ibexwall_proto::Reversible::Irreversible {
            return Err(Error::Irreversible);
        }
        let client = clean(client, 60);
        let pending = self
            .list_proposals(Some("pending"))
            .map_err(|e| Error::Other(e.to_string()))?;
        if pending.len() >= MAX_PENDING {
            return Err(Error::Full);
        }
        if pending.iter().filter(|p| p.client == client).count() >= MAX_PENDING_PER_CLIENT {
            return Err(Error::ClientFull);
        }
        let proposal = Proposal {
            id: format!(
                "prop-{:x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ),
            client: client.clone(),
            plugin: plan.plugin.clone(),
            plan_id: plan.id.clone(),
            patch,
            preview: plan.ops.clone(),
            may_affect_keys: plan.may_affect_keys.clone(),
            reversible: plan.reversible,
            risk: plan.risk.clone(),
            requires_confirm: plan.requires_confirm,
            justification: clean(justification, MAX_JUSTIFICATION),
            status: ProposalStatus::Pending,
            created_at: format_rfc3339(now),
            decided_at: None,
        };
        let json = serde_json::to_string(&proposal).map_err(|e| Error::Other(e.to_string()))?;
        self.state
            .with_conn(|conn| {
                conn.execute(
                    "INSERT INTO proposals (id, client, plugin, json, ops_digest, status, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
                    rusqlite::params![proposal.id, client, proposal.plugin, json, ops_digest, now],
                )?;
                Ok(())
            })
            .map_err(|e: anyhow::Error| Error::Other(e.to_string()))?;
        self.audit(
            &format!("mcp:{client}"),
            &proposal.plugin,
            None,
            ops_digest,
            "proposal-created",
        );
        self.publish_proposal_event("proposals.created", &proposal);
        Ok(proposal)
    }

    /// `(proposal, stored ops digest)` of a pending proposal.
    pub fn pending_proposal(&self, id: &str) -> Result<(Proposal, String), Error> {
        let now = ibexwall_sys::RealClock.unix_now();
        self.expire_proposals(now)
            .map_err(|e| Error::Other(e.to_string()))?;
        let row = self.state.with_conn(|conn| {
            conn.query_row(
                "SELECT json, status, decided_at, ops_digest FROM proposals WHERE id = ?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
        });
        let (json, status, decided, digest) = row.map_err(|_| Error::NotFound)?;
        let proposal = row_to_proposal(&json, &status, decided).ok_or(Error::NotFound)?;
        if proposal.status != ProposalStatus::Pending {
            return Err(Error::Decided);
        }
        Ok((proposal, digest))
    }

    pub fn mark_proposal(&self, id: &str, status: ProposalStatus) {
        let now = ibexwall_sys::RealClock.unix_now();
        let _ = self.state.with_conn(|conn| {
            conn.execute(
                "UPDATE proposals SET status = ?2, decided_at = ?3 WHERE id = ?1",
                rusqlite::params![id, status_name(status), now],
            )
        });
    }

    pub fn publish_proposal_event(&self, kind: &str, proposal: &Proposal) {
        let event = Event {
            ts: format_rfc3339(ibexwall_sys::RealClock.unix_now()),
            source: "proposals".into(),
            kind: kind.into(),
            severity: Severity::Info,
            app: None,
            data: serde_json::json!({ "proposal": proposal.id, "plugin": proposal.plugin }),
            untrusted: serde_json::json!({ "client": proposal.client }),
        };
        self.events.publish(event.clone());
        if let Err(error) = self.state.append_event(&event) {
            tracing::error!(%error, "event persist failed");
        }
    }
}
