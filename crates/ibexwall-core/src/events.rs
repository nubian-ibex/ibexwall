// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Event bus: broadcast to subscribers (`Subscribe` with `more`) plus a
//! persistent ring in SQLite (written by the API layer).

use ibexwall_proto::Event;
use tokio::sync::broadcast;

pub struct Bus {
    sender: broadcast::Sender<Event>,
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}

impl Bus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(256);
        Self { sender }
    }

    /// Publishes to live subscribers; the caller persists the event.
    pub fn publish(&self, event: Event) {
        // A dropped or slow subscriber must never block the daemon.
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: &str) -> Event {
        Event {
            ts: "2026-11-01T12:00:00Z".into(),
            source: "test".into(),
            kind: kind.into(),
            severity: ibexwall_proto::Severity::Info,
            app: None,
            data: serde_json::Value::Null,
            untrusted: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn subscribers_receive_events() {
        let bus = Bus::new();
        let mut receiver = bus.subscribe();
        bus.publish(event("one"));
        let received = receiver.recv().await.unwrap();
        assert_eq!(received.kind, "one");
    }

    #[tokio::test]
    async fn slow_subscribers_do_not_block() {
        let bus = Bus::new();
        let _quiet = bus.subscribe();
        for i in 0..1000 {
            bus.publish(event(&format!("e{i}")));
        }
        // The publisher never blocked: reaching here is the assertion.
    }
}
