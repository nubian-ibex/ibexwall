// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Spike S3-a probe: resolves a name over each encrypted transport against
//! one real provider and prints latency. Usage:
//! `cargo run -p ibexwall-dns --example probe -- <ip> <server_name> [name]`

use std::time::Instant;

use hickory_server::proto::rr::RecordType;
use ibexwall_dns::config::{Server, Transport, build_resolver};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let ip = args.next().expect("ip").parse().expect("valid ip");
    let server_name = args.next().expect("server name");
    let name = args.next().unwrap_or_else(|| "example.com.".into());

    for transport in [
        Transport::Tls,
        Transport::Https,
        Transport::Quic,
        Transport::H3,
    ] {
        let server = Server {
            ip,
            server_name: server_name.clone(),
            transport,
            path: None,
        };
        let resolver = build_resolver(&[server]).expect("resolver");
        let started = Instant::now();
        let first = resolver.lookup(name.as_str(), RecordType::A).await;
        let cold = started.elapsed();
        match first {
            Ok(lookup) => {
                let answers = lookup.answers().len();
                // A different name avoids the local cache but reuses the
                // established connection: the steady-state latency.
                let started = Instant::now();
                let _ = resolver.lookup("www.wikipedia.org.", RecordType::A).await;
                println!(
                    "{transport:?}: ok, {answers} answers, cold {cold:?}, warm {:?}",
                    started.elapsed()
                );
            }
            Err(error) => println!("{transport:?}: FAILED after {cold:?}: {error}"),
        }
    }
}
