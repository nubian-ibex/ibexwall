// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#![allow(clippy::unwrap_used)]

//! Latency benchmark for the acceptance targets (spec section 11):
//! warm p99 <= 2 ms with cache, and uncached overhead <= 5 ms versus the
//! encrypted upstream directly.
//!
//! Usage (inside the machine whose stub is 127.0.0.153:53):
//!   bench warm  [count]        - same name through the stub (cache hits)
//!   bench cold  [count]        - unique names through the stub
//!   bench direct <ip> <name> [count] - unique names straight over DoT
//!
//! Prints `p50_ms p99_ms` on one line so a test can read it.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use hickory_server::proto::op::{Message, Query};
use hickory_server::proto::rr::{Name, RecordType};

fn query(name: &str) -> Vec<u8> {
    let mut message = Message::query();
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    message.to_vec().unwrap()
}

async fn ask_udp(addr: SocketAddr, name: &str) -> Duration {
    // One socket per query: like distinct applications, no pipelining.
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let started = Instant::now();
    socket.send_to(&query(name), addr).await.unwrap();
    let mut buffer = [0u8; 1500];
    let _ = tokio::time::timeout(Duration::from_secs(4), socket.recv_from(&mut buffer))
        .await
        .expect("the resolver answered");
    started.elapsed()
}

fn percentile(mut samples: Vec<Duration>, which: f64) -> f64 {
    samples.sort_unstable();
    let index = ((samples.len() as f64 - 1.0) * which).round() as usize;
    samples[index].as_secs_f64() * 1000.0
}

fn report(samples: Vec<Duration>) -> String {
    format!(
        "{:.3} {:.3}",
        percentile(samples.clone(), 0.5),
        percentile(samples, 0.99)
    )
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().expect("mode: warm | cold | direct");
    let count: usize = if mode == "warm" || mode == "cold" {
        args.next().unwrap_or_else(|| "300".into()).parse().unwrap()
    } else {
        0
    };
    match mode.as_str() {
        "warm" => {
            // The name is resolved once and then served from the cache.
            let addr: SocketAddr = "127.0.0.153:53".parse().unwrap();
            ask_udp(addr, "example.com.").await;
            let mut samples = Vec::with_capacity(count);
            for _ in 0..count {
                samples.push(ask_udp(addr, "example.com.").await);
            }
            println!("warm {}", report(samples));
        }
        "cold" => {
            let addr: SocketAddr = "127.0.0.153:53".parse().unwrap();
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let mut samples = Vec::with_capacity(count);
            for i in 0..count {
                let name = format!("{stamp}-{i}.example.com.");
                samples.push(ask_udp(addr, &name).await);
            }
            println!("cold {}", report(samples));
        }
        "direct" => {
            // Same unique names, but straight to the encrypted upstream,
            // so the difference to `cold` is the stub's own overhead.
            let ip: std::net::IpAddr = args.next().expect("upstream ip").parse().unwrap();
            let server_name = args.next().expect("certificate name");
            let count: usize = args.next().unwrap_or_else(|| "300".into()).parse().unwrap();
            let server = ibexwall_dns::config::Server {
                ip,
                server_name,
                transport: ibexwall_dns::config::Transport::Tls,
                path: None,
            };
            let resolver = ibexwall_dns::config::build_resolver(&[server]).unwrap();
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let mut samples = Vec::with_capacity(count);
            for i in 0..count {
                let unique = format!("{stamp}-{i}.example.com.");
                let started = Instant::now();
                let _ = resolver.lookup(unique.as_str(), RecordType::A).await;
                samples.push(started.elapsed());
            }
            println!("direct {}", report(samples));
        }
        other => panic!("unknown mode `{other}`"),
    }
}
