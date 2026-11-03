// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! A small NFQUEUE client: bind a queue, receive the packets nftables
//! queues, answer each with accept or drop (and optionally a new mark).
//! Netlink by hand over `rustix`, so there is no C library to install and
//! no unsafe code. The message building and parsing are pure and tested;
//! the socket is a thin shell.
//!
//! The queue is configured to fail open: when the userspace side is slow
//! or gone, the kernel accepts instead of holding packets (spec 4.7).

use std::io;
use std::os::fd::OwnedFd;
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{self, AddressFamily, SocketType};

const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NFNL_SUBSYS_QUEUE: u16 = 3;
const NFQNL_MSG_PACKET: u16 = 0;
const NFQNL_MSG_VERDICT: u16 = 1;
const NFQNL_MSG_CONFIG: u16 = 2;

const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_MARK: u16 = 3;
const NFQA_PAYLOAD: u16 = 10;
const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQA_CFG_MASK: u16 = 4;
const NFQA_CFG_FLAGS: u16 = 5;

const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_COPY_PACKET: u8 = 2;
const NFQA_CFG_F_FAIL_OPEN: u32 = 1;

/// What to do with a held packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
}

/// One queued packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub id: u32,
    /// The packet's mark (the socket mark the eBPF hook set).
    pub mark: u32,
    /// The IP packet, from its header.
    pub payload: Vec<u8>,
}

/// Where a packet is going: address text and port, when it can be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub address: std::net::IpAddr,
    pub port: u16,
}

impl Packet {
    /// The destination of a TCP or UDP packet, IPv4 or IPv6.
    pub fn destination(&self) -> Option<Destination> {
        let p = &self.payload;
        match p.first()? >> 4 {
            4 if p.len() >= 20 => {
                let ihl = usize::from(p[0] & 0x0f) * 4;
                let port = u16::from_be_bytes([*p.get(ihl + 2)?, *p.get(ihl + 3)?]);
                let address = std::net::Ipv4Addr::new(p[16], p[17], p[18], p[19]);
                Some(Destination {
                    address: address.into(),
                    port,
                })
            }
            6 if p.len() >= 44 => {
                let octets: [u8; 16] = p[24..40].try_into().ok()?;
                let port = u16::from_be_bytes([p[42], p[43]]);
                Some(Destination {
                    address: std::net::Ipv6Addr::from(octets).into(),
                    port,
                })
            }
            _ => None,
        }
    }
}

fn pad4(len: usize) -> usize {
    (len + 3) & !3
}

/// One netlink attribute, padded to four bytes.
fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
    let len = 4 + payload.len();
    let mut out = Vec::with_capacity(pad4(len));
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(pad4(len), 0);
    out
}

/// A netfilter netlink message: header, `nfgenmsg` (family 0, version 0,
/// the queue number big endian) and the attributes.
fn message(msg: u16, flags: u16, seq: u32, queue: u16, attrs: &[u8]) -> Vec<u8> {
    let len = 16 + 4 + attrs.len();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&(len as u32).to_ne_bytes());
    out.extend_from_slice(&((NFNL_SUBSYS_QUEUE << 8) | msg).to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes()); // port id: the kernel fills it
    out.extend_from_slice(&[0, 0]); // nfgen_family, version
    out.extend_from_slice(&queue.to_be_bytes());
    out.extend_from_slice(attrs);
    out
}

/// The four configuration messages: bind, copy whole packets, a bounded
/// queue, fail open when it is full.
pub fn config_messages(queue: u16) -> Vec<Vec<u8>> {
    let request = NLM_F_REQUEST | NLM_F_ACK;
    let bind = attr(NFQA_CFG_CMD, &[NFQNL_CFG_CMD_BIND, 0, 0, 0]);
    let mut params = Vec::from(0xffffu32.to_be_bytes());
    params.push(NFQNL_COPY_PACKET);
    let params = attr(NFQA_CFG_PARAMS, &params);
    let maxlen = attr(NFQA_CFG_QUEUE_MAXLEN, &1024u32.to_be_bytes());
    let mut flags = attr(NFQA_CFG_FLAGS, &NFQA_CFG_F_FAIL_OPEN.to_be_bytes());
    flags.extend(attr(NFQA_CFG_MASK, &NFQA_CFG_F_FAIL_OPEN.to_be_bytes()));
    [bind, params, maxlen, flags]
        .into_iter()
        .enumerate()
        .map(|(i, attrs)| message(NFQNL_MSG_CONFIG, request, i as u32 + 1, queue, &attrs))
        .collect()
}

/// The message that answers packet `id`, optionally setting its mark.
pub fn verdict_message(queue: u16, id: u32, verdict: Verdict, mark: Option<u32>) -> Vec<u8> {
    let code: u32 = match verdict {
        Verdict::Drop => 0,
        Verdict::Accept => 1,
    };
    let mut header = Vec::from(code.to_be_bytes());
    header.extend_from_slice(&id.to_be_bytes());
    let mut attrs = attr(NFQA_VERDICT_HDR, &header);
    if let Some(mark) = mark {
        attrs.extend(attr(NFQA_MARK, &mark.to_be_bytes()));
    }
    message(NFQNL_MSG_VERDICT, NLM_F_REQUEST, 0, queue, &attrs)
}

/// What one received datagram held.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub packets: Vec<Packet>,
    /// An error the kernel reported (errno, positive) in an ack.
    pub error: Option<i32>,
}

/// Parses every message in a datagram; messages that are not ours or are
/// malformed are skipped, never trusted.
pub fn parse(buffer: &[u8]) -> Parsed {
    let mut parsed = Parsed::default();
    let mut at = 0;
    while at + 16 <= buffer.len() {
        let len = u32::from_ne_bytes(buffer[at..at + 4].try_into().expect("four bytes")) as usize;
        if len < 16 || at + len > buffer.len() {
            break;
        }
        let kind = u16::from_ne_bytes([buffer[at + 4], buffer[at + 5]]);
        let body = &buffer[at + 16..at + len];
        if kind == NLMSG_ERROR {
            if body.len() >= 4 {
                let errno = i32::from_ne_bytes(body[..4].try_into().expect("four bytes"));
                if errno != 0 {
                    parsed.error = Some(-errno);
                }
            }
        } else if kind == (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET
            && let Some(packet) = parse_packet(body)
        {
            parsed.packets.push(packet);
        }
        at += pad4(len);
    }
    parsed
}

fn parse_packet(body: &[u8]) -> Option<Packet> {
    // nfgenmsg (4 bytes), then attributes.
    let mut at = 4;
    let (mut id, mut mark, mut payload) = (None, 0u32, Vec::new());
    while at + 4 <= body.len() {
        let len = usize::from(u16::from_ne_bytes([body[at], body[at + 1]]));
        let kind = u16::from_ne_bytes([body[at + 2], body[at + 3]]) & 0x3fff;
        if len < 4 || at + len > body.len() {
            break;
        }
        let data = &body[at + 4..at + len];
        match kind {
            NFQA_PACKET_HDR if data.len() >= 4 => {
                id = Some(u32::from_be_bytes(
                    data[..4].try_into().expect("four bytes"),
                ));
            }
            NFQA_MARK if data.len() >= 4 => {
                mark = u32::from_be_bytes(data[..4].try_into().expect("four bytes"));
            }
            NFQA_PAYLOAD => payload = data.to_vec(),
            _ => {}
        }
        at += pad4(len);
    }
    Some(Packet {
        id: id?,
        mark,
        payload,
    })
}

/// A bound queue.
pub struct Queue {
    fd: OwnedFd,
    number: u16,
}

impl Queue {
    /// Binds `number` and configures it (fail open). Needs `CAP_NET_ADMIN`.
    pub fn open(number: u16) -> io::Result<Self> {
        let fd = net::socket(
            AddressFamily::NETLINK,
            SocketType::RAW,
            Some(net::netlink::NETFILTER),
        )?;
        net::bind(&fd, &SocketAddrNetlink::new(0, 0))?;
        let queue = Self { fd, number };
        for (step, message) in config_messages(number).into_iter().enumerate() {
            net::send(&queue.fd, &message, net::SendFlags::empty())?;
            // Each request is acknowledged; a refusal (queue already bound
            // by someone else, no permission) is reported here.
            let mut buffer = [0u8; 4096];
            let received = net::recv(&queue.fd, &mut buffer, net::RecvFlags::empty())?;
            if let Some(errno) = parse(&buffer[..received.0.min(buffer.len())]).error {
                let cause = io::Error::from_raw_os_error(errno);
                return Err(io::Error::new(
                    cause.kind(),
                    format!(
                        "configuration step {} of queue {number} refused: {cause}",
                        step + 1
                    ),
                ));
            }
        }
        Ok(queue)
    }

    /// Waits up to `timeout` for packets; empty when nothing came.
    pub fn recv(&self, timeout: Duration) -> io::Result<Vec<Packet>> {
        let mut poller = [PollFd::new(&self.fd, PollFlags::IN)];
        let wait = Timespec {
            tv_sec: timeout.as_secs() as i64,
            tv_nsec: i64::from(timeout.subsec_nanos()),
        };
        if rustix::event::poll(&mut poller, Some(&wait))? == 0 {
            return Ok(vec![]);
        }
        let mut buffer = vec![0u8; 65536 + 4096];
        let received = net::recv(&self.fd, &mut buffer, net::RecvFlags::empty())?;
        Ok(parse(&buffer[..received.0.min(buffer.len())]).packets)
    }

    /// Answers a packet.
    pub fn verdict(&self, id: u32, verdict: Verdict, mark: Option<u32>) -> io::Result<()> {
        let message = verdict_message(self.number, id, verdict, mark);
        net::send(&self.fd, &message, net::SendFlags::empty())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A packet message as the kernel sends it.
    fn packet_message(id: u32, mark: u32, payload: &[u8]) -> Vec<u8> {
        let mut hdr = Vec::from(id.to_be_bytes());
        hdr.extend_from_slice(&[0x08, 0x00, 0x03]); // ethertype IP, hook 3
        let mut attrs = attr(NFQA_PACKET_HDR, &hdr);
        attrs.extend(attr(NFQA_MARK, &mark.to_be_bytes()));
        attrs.extend(attr(NFQA_PAYLOAD, payload));
        message(NFQNL_MSG_PACKET, 0, 0, 7, &attrs)
    }

    fn ipv4_tcp(dst: [u8; 4], port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[9] = 6;
        p[16..20].copy_from_slice(&dst);
        p[22..24].copy_from_slice(&port.to_be_bytes());
        p
    }

    #[test]
    fn config_binds_the_queue_and_asks_to_fail_open() {
        let messages = config_messages(4242);
        assert_eq!(messages.len(), 4);
        // Bind: length, type (queue subsystem, config), request+ack, the
        // queue number big endian after the two zero bytes.
        let bind = &messages[0];
        assert_eq!(
            u32::from_ne_bytes(bind[0..4].try_into().unwrap()) as usize,
            bind.len()
        );
        assert_eq!(u16::from_ne_bytes([bind[4], bind[5]]), 0x0302);
        assert_eq!(
            u16::from_ne_bytes([bind[6], bind[7]]),
            NLM_F_REQUEST | NLM_F_ACK
        );
        assert_eq!(&bind[16..20], &[0, 0, 0x10, 0x92]);
        // The attribute: cmd = bind.
        assert_eq!(u16::from_ne_bytes([bind[22], bind[23]]), NFQA_CFG_CMD);
        assert_eq!(bind[24], NFQNL_CFG_CMD_BIND);
        // Every message length is a multiple of four and matches its header.
        for m in &messages {
            assert_eq!(m.len() % 4, 0);
            assert_eq!(
                u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize,
                m.len()
            );
        }
        // The last one carries flags and mask for fail open.
        let flags = &messages[3];
        assert!(
            flags
                .windows(4)
                .any(|w| w == NFQA_CFG_F_FAIL_OPEN.to_be_bytes())
        );
    }

    #[test]
    fn a_verdict_names_the_packet_and_may_set_a_mark() {
        let accept = verdict_message(7, 0xdead_beef, Verdict::Accept, None);
        assert_eq!(u16::from_ne_bytes([accept[4], accept[5]]), 0x0301);
        assert_eq!(&accept[20..22], &[12, 0]);
        assert_eq!(
            u16::from_ne_bytes([accept[22], accept[23]]),
            NFQA_VERDICT_HDR
        );
        assert_eq!(&accept[24..28], &1u32.to_be_bytes());
        assert_eq!(&accept[28..32], &0xdead_beefu32.to_be_bytes());
        let drop = verdict_message(7, 1, Verdict::Drop, Some(0x0002_0000));
        assert_eq!(&drop[24..28], &0u32.to_be_bytes());
        assert!(drop.windows(4).any(|w| w == 0x0002_0000u32.to_be_bytes()));
        assert_eq!(drop.len(), 16 + 4 + 12 + 8);
    }

    #[test]
    fn packets_are_parsed_with_id_mark_and_destination() {
        let payload = ipv4_tcp([203, 0, 113, 9], 443);
        let datagram = packet_message(77, 0x0001_abcd, &payload);
        let parsed = parse(&datagram);
        assert_eq!(parsed.error, None);
        assert_eq!(parsed.packets.len(), 1);
        let packet = &parsed.packets[0];
        assert_eq!((packet.id, packet.mark), (77, 0x0001_abcd));
        let destination = packet.destination().unwrap();
        assert_eq!(destination.address.to_string(), "203.0.113.9");
        assert_eq!(destination.port, 443);
    }

    #[test]
    fn several_messages_in_one_datagram_are_all_read() {
        let mut datagram = packet_message(1, 0, &ipv4_tcp([1, 1, 1, 1], 80));
        datagram.extend(packet_message(2, 0, &ipv4_tcp([2, 2, 2, 2], 81)));
        let ids: Vec<u32> = parse(&datagram).packets.iter().map(|p| p.id).collect();
        assert_eq!(ids, [1, 2]);
    }

    #[test]
    fn ipv6_destinations_are_read() {
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[6] = 6;
        p[24..40]
            .copy_from_slice(&std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        p[42..44].copy_from_slice(&853u16.to_be_bytes());
        let packet = Packet {
            id: 1,
            mark: 0,
            payload: p,
        };
        let destination = packet.destination().unwrap();
        assert_eq!(destination.address.to_string(), "2001:db8::1");
        assert_eq!(destination.port, 853);
    }

    #[test]
    fn a_kernel_error_is_reported() {
        // NLMSG_ERROR with errno -1 (EPERM) and the echoed header.
        let mut m = Vec::new();
        m.extend_from_slice(&36u32.to_ne_bytes());
        m.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
        m.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        m.extend_from_slice(&(-1i32).to_ne_bytes());
        m.extend_from_slice(&[0u8; 16]);
        assert_eq!(parse(&m).error, Some(1));
        // An ack (errno 0) is not an error.
        let mut ack = m.clone();
        ack[16..20].copy_from_slice(&0i32.to_ne_bytes());
        assert_eq!(parse(&ack).error, None);
    }

    #[test]
    fn garbage_never_panics_and_yields_nothing() {
        for junk in [
            vec![],
            vec![0xff; 7],
            vec![0xff; 64],
            {
                let mut m = packet_message(1, 0, &[1, 2, 3]);
                m.truncate(m.len() - 5);
                m
            },
            {
                let mut m = packet_message(1, 0, &[1, 2, 3]);
                m[0..4].copy_from_slice(&u32::MAX.to_ne_bytes());
                m
            },
        ] {
            assert!(parse(&junk).packets.is_empty(), "{junk:?}");
        }
        // A packet with no readable destination is still a packet.
        let odd = Packet {
            id: 1,
            mark: 0,
            payload: vec![0x45, 1, 2],
        };
        assert!(odd.destination().is_none());
        assert!(
            Packet {
                id: 1,
                mark: 0,
                payload: vec![]
            }
            .destination()
            .is_none()
        );
    }
}
