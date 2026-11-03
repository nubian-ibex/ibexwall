// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Ask mode in the core (spec 4.7, ADR-0035, ADR-0036): the monitor unit
//! holds the first packet of a connection and tells us who is asking; we
//! keep the question until someone answers, remember the answers the user
//! wants remembered, and send the decision back. Nobody answering is not an
//! error: the unit applies the fallback (open by default) when time is up.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use serde::Deserialize;

use ibexwall_apps::policy::{self, Mode};
use ibexwall_identity::{AppKind, Identity};
use ibexwall_proto::{Event, Prompt, Severity};
use ibexwall_sys::format_rfc3339;

use crate::Core;

/// A request line from the unit.
#[derive(Debug, Deserialize)]
pub struct AskEnvelope {
    pub ask: AskLine,
}

#[derive(Debug, Deserialize)]
pub struct AskLine {
    #[serde(default)]
    pub exe: Option<String>,
    pub dst: String,
    pub port: u16,
    pub kind: AppKind,
    #[serde(default)]
    pub id: String,
    pub ask_id: u16,
}

struct Pending {
    prompt: Prompt,
    /// Retransmissions and parallel connections of the same question.
    ask_ids: Vec<u16>,
    created: i64,
    timeout: i64,
}

/// What the user decides, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// This connection only.
    Once,
    /// This app and this destination, from now on.
    Destination,
    /// This app, always (its mode changes).
    Always,
}

impl Scope {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "once" => Some(Self::Once),
            "destination" => Some(Self::Destination),
            "always" => Some(Self::Always),
            _ => None,
        }
    }
}

#[derive(Default)]
pub struct Asks {
    next: AtomicU64,
    pending: Mutex<HashMap<u64, Pending>>,
}

/// Most questions kept at once; more are left to the fallback.
const MAX_PENDING: usize = 64;

fn answer_line(ask_id: u16, allow: bool) -> String {
    serde_json::json!({ "answer": {
        "id": ask_id,
        "decision": if allow { "allow" } else { "block" },
    }})
    .to_string()
}

impl crate::monitor::Monitor {
    /// A held connection. Answered at once when a stored decision covers
    /// it; otherwise it becomes a question for the user.
    pub fn handle_ask(&self, core: &Core, ask: AskLine, now: i64) -> Result<()> {
        let Ok(ip) = ask.dst.parse::<IpAddr>() else {
            return Ok(());
        };
        let identity = Identity {
            kind: ask.kind,
            id: ask.id,
        };
        let exe = ask.exe.filter(|path| !path.is_empty());
        let app = ibexwall_apps::app_key(&identity, exe.as_deref());
        let domain = self.lookup_domain(ip, now);
        let destination = domain.unwrap_or_else(|| ip.to_string());

        let (mode, default, remembered, timeout) = core.state.with_conn(|conn| {
            Ok::<_, ibexwall_apps::store::Error>((
                policy::modes(conn)?.get(&app).copied(),
                policy::default_mode(conn)?,
                policy::destination_modes(conn, &app)?,
                policy::DEFAULT_ASK_TIMEOUT_SECS as i64,
            ))
        })?;

        // The policy the unit enforces can lag a change by a moment: the
        // stored mode is the truth.
        let effective = mode.unwrap_or(default);
        if effective != Mode::Ask {
            self.send_to_unit(answer_line(ask.ask_id, effective != Mode::Block));
            return Ok(());
        }
        if let Some((_, _, mode)) = remembered
            .iter()
            .find(|(d, p, _)| *d == destination && *p == ask.port)
        {
            self.send_to_unit(answer_line(ask.ask_id, *mode != Mode::Block));
            return Ok(());
        }

        let mut pending = self.asks.pending.lock().unwrap();
        pending.retain(|_, p| now < p.created + p.timeout);
        if let Some(existing) = pending.values_mut().find(|p| {
            p.prompt.app == app && p.prompt.destination == destination && p.prompt.port == ask.port
        }) {
            existing.ask_ids.push(ask.ask_id);
            return Ok(());
        }
        if pending.len() >= MAX_PENDING {
            // Too many questions: leave this one to the unit's fallback.
            return Ok(());
        }
        let id = self.asks.next.fetch_add(1, Ordering::SeqCst) + 1;
        let prompt = Prompt {
            id: id.to_string(),
            app: app.clone(),
            kind: serde_json::to_value(ask.kind)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "unknown".into()),
            exe_path: exe.clone(),
            destination: destination.clone(),
            address: ip.to_string(),
            port: ask.port,
            created: format_rfc3339(now),
            expires: format_rfc3339(now + timeout),
        };
        pending.insert(
            id,
            Pending {
                prompt,
                ask_ids: vec![ask.ask_id],
                created: now,
                timeout,
            },
        );
        drop(pending);

        let event = Event {
            ts: format_rfc3339(now),
            source: "apps".into(),
            kind: "apps.ask".into(),
            severity: Severity::Info,
            app: Some(app),
            data: serde_json::json!({ "prompt": id.to_string() }),
            untrusted: serde_json::json!({
                "exe_path": exe,
                "destination": destination,
                "port": ask.port,
            }),
        };
        core.events.publish(event.clone());
        if let Err(error) = core.state.append_event(&event) {
            tracing::error!(%error, "event persist failed");
        }
        Ok(())
    }

    /// The open questions, oldest first.
    pub fn prompts(&self, now: i64) -> Vec<Prompt> {
        let mut pending = self.asks.pending.lock().unwrap();
        pending.retain(|_, p| now < p.created + p.timeout);
        let mut all: Vec<(u64, Prompt)> = pending
            .iter()
            .map(|(id, p)| (*id, p.prompt.clone()))
            .collect();
        all.sort_by_key(|(id, _)| *id);
        all.into_iter().map(|(_, prompt)| prompt).collect()
    }

    /// The user's answer. `false` when there is no such question (already
    /// answered, or it timed out and the fallback applied).
    pub fn answer_prompt(
        &self,
        core: &Core,
        id: &str,
        allow: bool,
        scope: Scope,
        now: i64,
    ) -> Result<bool> {
        let Ok(number) = id.parse::<u64>() else {
            return Ok(false);
        };
        let Some(pending) = self.asks.pending.lock().unwrap().remove(&number) else {
            return Ok(false);
        };
        for ask_id in &pending.ask_ids {
            self.send_to_unit(answer_line(*ask_id, allow));
        }
        let mode = if allow { Mode::Allow } else { Mode::Block };
        let prompt = &pending.prompt;
        match scope {
            Scope::Once => {}
            Scope::Destination => {
                core.state.with_conn(|conn| {
                    policy::set_destination_mode(
                        conn,
                        &prompt.app,
                        &prompt.destination,
                        prompt.port,
                        mode,
                        now,
                    )
                })?;
            }
            Scope::Always => crate::monitor::set_app_mode(core, &prompt.app, mode)?,
        }
        Ok(true)
    }
}
