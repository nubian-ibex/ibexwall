// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Ask mode (ADR-0035): the first packet of a flow from an app in Ask mode
//! waits in the NFQUEUE until the user answers through the core. The
//! bookkeeping is the `Broker` (pure, tested); the rest is the queue loop.
//!
//! Everything fails open: a flow nobody knows is accepted, a flow nobody
//! answered is released with the configured fallback after the timeout,
//! and with no listener at all the kernel's `bypass` accepts.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// What happens to a held flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block,
}

impl Decision {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "allow" => Some(Self::Allow),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
}

/// A packet to release and the mark it carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Held {
    pub packet: u32,
    pub mark: u32,
}

/// What the broker says about a packet that just arrived.
#[derive(Debug, PartialEq, Eq)]
pub enum Arrival {
    /// First packet of a flow: ask the user.
    New,
    /// The flow is already waiting (a retransmission): hold it too.
    Waiting,
    /// The flow was answered a moment ago: release at once.
    Answered(Decision),
}

enum Flow {
    Pending { held: Vec<Held>, since: Instant },
    Answered { decision: Decision, at: Instant },
}

/// How long an answered flow is remembered, for late retransmissions.
const REMEMBER: Duration = Duration::from_secs(60);

pub struct Broker {
    flows: Mutex<HashMap<u16, Flow>>,
    settings: Mutex<(Duration, Decision)>,
}

impl Broker {
    pub fn new(timeout: Duration, fallback: Decision) -> Self {
        Self {
            flows: Mutex::new(HashMap::new()),
            settings: Mutex::new((timeout, fallback)),
        }
    }

    /// The core pushes these with every policy.
    pub fn configure(&self, timeout: Duration, fallback: Decision) {
        *self.settings.lock().expect("lock poisoned") = (timeout, fallback);
    }

    pub fn arrive(&self, id: u16, held: Held, now: Instant) -> Arrival {
        let mut flows = self.flows.lock().expect("lock poisoned");
        flows.retain(|_, flow| match flow {
            Flow::Answered { at, .. } => now.duration_since(*at) < REMEMBER,
            Flow::Pending { .. } => true,
        });
        match flows.get_mut(&id) {
            Some(Flow::Pending { held: list, .. }) => {
                list.push(held);
                Arrival::Waiting
            }
            Some(Flow::Answered { decision, .. }) => Arrival::Answered(*decision),
            None => {
                flows.insert(
                    id,
                    Flow::Pending {
                        held: vec![held],
                        since: now,
                    },
                );
                Arrival::New
            }
        }
    }

    /// The user's answer: the packets to release (empty when the flow is
    /// not waiting, e.g. it already timed out).
    pub fn answer(&self, id: u16, decision: Decision, now: Instant) -> Vec<Held> {
        let mut flows = self.flows.lock().expect("lock poisoned");
        match flows.get(&id) {
            Some(Flow::Pending { .. }) => {}
            _ => return vec![],
        }
        let Some(Flow::Pending { held, .. }) =
            flows.insert(id, Flow::Answered { decision, at: now })
        else {
            return vec![];
        };
        held
    }

    /// Flows nobody answered in time get the fallback.
    pub fn expire(&self, now: Instant) -> Vec<(Decision, Vec<Held>)> {
        let (timeout, fallback) = *self.settings.lock().expect("lock poisoned");
        let mut flows = self.flows.lock().expect("lock poisoned");
        let due: Vec<u16> = flows
            .iter()
            .filter(|(_, flow)| {
                matches!(flow, Flow::Pending { since, .. } if now.duration_since(*since) >= timeout)
            })
            .map(|(id, _)| *id)
            .collect();
        let mut out = Vec::new();
        for id in due {
            if let Some(Flow::Pending { held, .. }) = flows.insert(
                id,
                Flow::Answered {
                    decision: fallback,
                    at: now,
                },
            ) {
                out.push((fallback, held));
            }
        }
        out
    }
}

/// The queue and the broker, shared with the thread that reads answers.
pub struct Ask {
    queue: ibexwall_nfq::Queue,
    broker: Broker,
}

fn refused_mark(mark: u32) -> u32 {
    (mark & 0xff00_0000) | ibexwall_net_common::REFUSED_MARK_VALUE | (mark & 0xffff)
}

impl Ask {
    fn release(&self, decision: Decision, held: &[Held]) {
        for packet in held {
            let mark = (decision == Decision::Block).then(|| refused_mark(packet.mark));
            let _ = self
                .queue
                .verdict(packet.packet, ibexwall_nfq::Verdict::Accept, mark);
        }
    }

    /// An answer from the user (through the core).
    pub fn answer(&self, id: u16, decision: Decision) {
        let held = self.broker.answer(id, decision, Instant::now());
        self.release(decision, &held);
    }

    pub fn configure(&self, timeout: Duration, fallback: Decision) {
        self.broker.configure(timeout, fallback);
    }
}

/// A flow as the eBPF hook recorded it.
pub struct Flow4 {
    pub pid: u32,
    pub cgroup_id: u64,
}

/// Binds the queue and serves it on a thread of its own. `ask_user` is
/// called once per new flow with its pid, cgroup id, id and destination;
/// the answer comes back through [`Ask::answer`].
pub fn start(
    flows: aya::maps::HashMap<aya::maps::MapData, u32, [u8; ibexwall_net_common::ASK_FLOW_LEN]>,
    ask_user: impl Fn(u16, Flow4, Option<ibexwall_nfq::Destination>) + Send + 'static,
) -> Result<Arc<Ask>> {
    let queue = ibexwall_nfq::Queue::open(ibexwall_net_common::ASK_QUEUE)
        .context("binding the Ask queue (needs CAP_NET_ADMIN)")?;
    let ask = Arc::new(Ask {
        queue,
        broker: Broker::new(Duration::from_secs(30), Decision::Allow),
    });
    eprintln!(
        "ibexwall-ebpf-loader: Ask queue {} bound",
        ibexwall_net_common::ASK_QUEUE
    );
    let serving = Arc::clone(&ask);
    std::thread::spawn(move || {
        loop {
            let packets = match serving.queue.recv(Duration::from_millis(250)) {
                Ok(packets) => packets,
                Err(error) => {
                    eprintln!("ibexwall-ebpf-loader: ask queue stopped: {error}");
                    return;
                }
            };
            for packet in packets {
                let id = (packet.mark & 0xffff) as u16;
                let Some(flow) = flows.get(&u32::from(id), 0).ok() else {
                    // Unknown: the network stays open.
                    let _ = serving
                        .queue
                        .verdict(packet.id, ibexwall_nfq::Verdict::Accept, None);
                    continue;
                };
                let held = Held {
                    packet: packet.id,
                    mark: packet.mark,
                };
                match serving.broker.arrive(id, held, Instant::now()) {
                    Arrival::New => ask_user(
                        id,
                        Flow4 {
                            pid: u32::from_le_bytes(flow[..4].try_into().expect("four bytes")),
                            cgroup_id: u64::from_le_bytes(
                                flow[4..12].try_into().expect("eight bytes"),
                            ),
                        },
                        packet.destination(),
                    ),
                    Arrival::Waiting => {}
                    Arrival::Answered(decision) => serving.release(decision, &[held]),
                }
            }
            for (decision, held) in serving.broker.expire(Instant::now()) {
                serving.release(decision, &held);
            }
        }
    });
    Ok(ask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(packet: u32) -> Held {
        Held {
            packet,
            mark: 0x0001_0007,
        }
    }

    #[test]
    fn the_first_packet_asks_and_a_retransmission_waits_with_it() {
        let broker = Broker::new(Duration::from_secs(30), Decision::Allow);
        let now = Instant::now();
        assert_eq!(broker.arrive(7, held(1), now), Arrival::New);
        assert_eq!(broker.arrive(7, held(2), now), Arrival::Waiting);
        let released = broker.answer(7, Decision::Block, now);
        assert_eq!(released, vec![held(1), held(2)]);
        // A late retransmission gets the same answer at once.
        assert_eq!(
            broker.arrive(7, held(3), now),
            Arrival::Answered(Decision::Block)
        );
    }

    #[test]
    fn flows_are_independent() {
        let broker = Broker::new(Duration::from_secs(30), Decision::Allow);
        let now = Instant::now();
        assert_eq!(broker.arrive(1, held(1), now), Arrival::New);
        assert_eq!(broker.arrive(2, held(2), now), Arrival::New);
        assert_eq!(broker.answer(2, Decision::Allow, now), vec![held(2)]);
        assert_eq!(broker.answer(1, Decision::Block, now), vec![held(1)]);
    }

    #[test]
    fn an_answer_for_nothing_waiting_releases_nothing() {
        let broker = Broker::new(Duration::from_secs(30), Decision::Allow);
        let now = Instant::now();
        assert!(broker.answer(9, Decision::Block, now).is_empty());
        broker.arrive(9, held(1), now);
        assert_eq!(broker.answer(9, Decision::Allow, now).len(), 1);
        // Answering twice does not release twice.
        assert!(broker.answer(9, Decision::Block, now).is_empty());
    }

    #[test]
    fn an_unanswered_flow_gets_the_fallback_after_the_timeout() {
        let broker = Broker::new(Duration::from_secs(10), Decision::Block);
        let start = Instant::now();
        broker.arrive(5, held(1), start);
        assert!(broker.expire(start + Duration::from_secs(9)).is_empty());
        let due = broker.expire(start + Duration::from_secs(10));
        assert_eq!(due, vec![(Decision::Block, vec![held(1)])]);
        // Only once.
        assert!(broker.expire(start + Duration::from_secs(11)).is_empty());
        // A late answer from the user changes nothing.
        assert!(broker.answer(5, Decision::Allow, start).is_empty());
    }

    #[test]
    fn the_core_can_change_the_timeout_and_fallback() {
        let broker = Broker::new(Duration::from_secs(60), Decision::Allow);
        let start = Instant::now();
        broker.arrive(5, held(1), start);
        broker.configure(Duration::from_secs(1), Decision::Block);
        let due = broker.expire(start + Duration::from_secs(1));
        assert_eq!(due[0].0, Decision::Block);
    }

    #[test]
    fn answered_flows_are_forgotten_after_a_while() {
        let broker = Broker::new(Duration::from_secs(30), Decision::Allow);
        let start = Instant::now();
        broker.arrive(5, held(1), start);
        broker.answer(5, Decision::Allow, start);
        // The same id again, long after: a new flow, asked again.
        assert_eq!(
            broker.arrive(5, held(2), start + REMEMBER + Duration::from_secs(1)),
            Arrival::New
        );
    }

    #[test]
    fn decisions_parse_only_known_words() {
        assert_eq!(Decision::parse("allow"), Some(Decision::Allow));
        assert_eq!(Decision::parse("block"), Some(Decision::Block));
        assert_eq!(Decision::parse("deny"), None);
        assert_eq!(refused_mark(0xab01_0007), 0xab02_0007);
    }
}
