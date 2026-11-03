// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tells the core which addresses were answered for which name, so the
//! connection monitor can show a domain instead of a bare address.
//!
//! Best effort and one way: a datagram per answer, errors ignored (the
//! core may be down or busy) and never allowed to slow a DNS reply. Names
//! travel only to the local core socket and live in its memory until the
//! record's TTL plus a grace period; nothing is written to disk here.

use std::net::IpAddr;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;

/// The wire form of one answer: a JSON object, one per datagram.
pub fn encode(name: &str, ip: IpAddr, ttl: u32) -> String {
    serde_json::json!({ "domain": name, "ip": ip.to_string(), "ttl": ttl }).to_string()
}

pub struct AnswerSink {
    socket: UnixDatagram,
    target: PathBuf,
}

impl AnswerSink {
    /// An unbound, non-blocking sender aimed at `target`.
    pub fn new(target: PathBuf) -> std::io::Result<Self> {
        let socket = UnixDatagram::unbound()?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket, target })
    }

    /// Reports every address in `answers` for `name`.
    pub fn report(&self, name: &str, answers: impl IntoIterator<Item = (IpAddr, u32)>) {
        for (ip, ttl) in answers {
            // Full buffers and a missing listener both mean "drop it".
            let _ = self
                .socket
                .send_to(encode(name, ip, ttl).as_bytes(), &self.target);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_one_json_object() {
        let line = encode("example.com.", "93.184.216.34".parse().unwrap(), 60);
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["domain"], "example.com.");
        assert_eq!(value["ip"], "93.184.216.34");
        assert_eq!(value["ttl"], 60);
    }

    #[test]
    fn delivers_datagrams_and_survives_a_missing_listener() {
        let dir = std::env::temp_dir().join(format!("ibexwall-answers-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("answers.sock");
        let _ = std::fs::remove_file(&path);

        let sink = AnswerSink::new(path.clone()).unwrap();
        // Nobody listens yet: reporting must not fail or block.
        sink.report("a.example.", [("1.2.3.4".parse().unwrap(), 30)]);

        let listener = UnixDatagram::bind(&path).unwrap();
        listener.set_nonblocking(false).unwrap();
        sink.report(
            "b.example.",
            [
                ("2001:db8::1".parse().unwrap(), 20),
                ("5.6.7.8".parse().unwrap(), 10),
            ],
        );
        let mut buffer = [0u8; 512];
        let n = listener.recv(&mut buffer).unwrap();
        let first: serde_json::Value = serde_json::from_slice(&buffer[..n]).unwrap();
        assert_eq!(first["ip"], "2001:db8::1");
        let n = listener.recv(&mut buffer).unwrap();
        let second: serde_json::Value = serde_json::from_slice(&buffer[..n]).unwrap();
        assert_eq!(
            (second["ip"].as_str(), second["domain"].as_str()),
            (Some("5.6.7.8"), Some("b.example."))
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
