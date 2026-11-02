// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Runs the real `ibexwall-dns` binary with a settings file and talks to
//! it over UDP and TCP. Blocked names and the canary never need the
//! upstream, so the test does not touch the network.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hickory_server::proto::op::{Message, Query, ResponseCode};
use hickory_server::proto::rr::{Name, RecordType};

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn query(name: &str) -> Vec<u8> {
    let mut message = Message::query();
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    message.to_vec().unwrap()
}

fn over_udp(addr: SocketAddr, name: &str) -> Option<Message> {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    socket.send_to(&query(name), addr).unwrap();
    let mut buffer = [0u8; 1500];
    let (len, _) = socket.recv_from(&mut buffer).ok()?;
    Message::from_vec(&buffer[..len]).ok()
}

fn over_tcp(addr: SocketAddr, name: &str) -> Message {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let wire = query(name);
    stream
        .write_all(&(wire.len() as u16).to_be_bytes())
        .unwrap();
    stream.write_all(&wire).unwrap();
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).unwrap();
    let mut body = vec![0u8; u16::from_be_bytes(length) as usize];
    stream.read_exact(&mut body).unwrap();
    Message::from_vec(&body).unwrap()
}

#[test]
fn serves_blocks_and_the_canary_over_udp_and_tcp() {
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("ibexwall-dns-test-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("resolver.json");
    std::fs::write(
        &config,
        format!(
            r#"{{ "listen": "127.0.0.1:{port}",
                 "servers": [{{ "ip": "192.0.2.1", "server_name": "dns.example",
                                "transport": "tls" }}],
                 "block": ["ads.example"] }}"#
        ),
    )
    .unwrap();

    let _daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_ibexwall-dns"))
            .arg("--config")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let first = loop {
        if let Some(answer) = over_udp(addr, "ads.example.") {
            break answer;
        }
        assert!(Instant::now() < deadline, "resolver did not start");
    };
    assert_eq!(first.metadata.response_code, ResponseCode::NXDomain);

    let canary = over_udp(addr, "use-application-dns.net.").unwrap();
    assert_eq!(canary.metadata.response_code, ResponseCode::NXDomain);
    let tcp = over_tcp(addr, "sub.ads.example.");
    assert_eq!(tcp.metadata.response_code, ResponseCode::NXDomain);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn refuses_to_start_without_a_valid_settings_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_ibexwall-dns"))
        .arg("--config")
        .arg("/nonexistent/ibexwall-dns.json")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("reading"));
}
