// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! End to end over loopback: a fake upstream, the real handler behind a
//! real hickory server, and a raw UDP client. The encrypted transports are
//! covered by unit tests on the config and by the VM phase; here the
//! point is the decision and answer logic on the wire.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use hickory_server::Server;
use hickory_server::proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_server::proto::rr::{Name, RData, Record, RecordType};
use hickory_server::resolver::Resolver;
use hickory_server::resolver::config::{
    ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig,
};
use hickory_server::resolver::net::runtime::TokioRuntimeProvider;
use ibexwall_dns::handler::Handler;
use ibexwall_dns::policy::{BlockResponse, Policy};
use tokio::net::UdpSocket;

const UPSTREAM_ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 7);

/// Answers A queries with a fixed address, `missing.test` with NXDOMAIN
/// and `nodata.test` with an empty NOERROR.
async fn fake_upstream() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let Ok(request) = Message::from_vec(&buffer[..len]) else {
                continue;
            };
            let mut response = Message::response(request.metadata.id, OpCode::Query);
            response.metadata.recursion_desired = true;
            response.metadata.recursion_available = true;
            response.add_queries(request.queries.clone());
            let query = &request.queries[0];
            let name = query.name().to_string();
            if name.starts_with("missing.test") {
                response.metadata.response_code = ResponseCode::NXDomain;
            } else if query.query_type() == RecordType::A && !name.starts_with("nodata.test") {
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    30,
                    RData::A(UPSTREAM_ANSWER.into()),
                ));
            }
            let _ = socket.send_to(&response.to_vec().unwrap(), peer).await;
        }
    });
    addr
}

struct Rig {
    addr: SocketAddr,
    handler: Handler,
}

async fn rig(response: BlockResponse) -> Rig {
    let upstream = fake_upstream().await;
    let mut connection = ConnectionConfig::udp();
    connection.port = upstream.port();
    let server = NameServerConfig::new(IpAddr::V4(Ipv4Addr::LOCALHOST), true, vec![connection]);
    let mut builder = Resolver::builder_with_config(
        ResolverConfig::from_parts(None, vec![], vec![server]),
        TokioRuntimeProvider::default(),
    );
    builder.options_mut().use_hosts_file = ResolveHosts::Never;
    builder.options_mut().timeout = Duration::from_secs(2);
    builder.options_mut().attempts = 1;
    let resolver = builder.build().unwrap();

    let mut policy = Policy::new(response, true);
    policy.block(["ads.test".to_string()]);
    policy.allow(["fine.ads.test".to_string()]);
    let handler = Handler::new(policy, resolver);

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let mut server = Server::new(handler.clone());
    server.register_socket(socket);
    tokio::spawn(async move {
        let _ = server.block_until_done().await;
    });
    Rig { addr, handler }
}

async fn ask(addr: SocketAddr, name: &str, record_type: RecordType) -> Message {
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut message = Message::query();
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), record_type));
    client
        .send_to(&message.to_vec().unwrap(), addr)
        .await
        .unwrap();
    let mut buffer = [0u8; 1500];
    let (len, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buffer))
        .await
        .expect("no answer from the resolver")
        .unwrap();
    Message::from_vec(&buffer[..len]).unwrap()
}

fn first_a(message: &Message) -> Option<Ipv4Addr> {
    message
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
}

#[tokio::test]
async fn forwards_allowed_names_to_the_upstream() {
    let rig = rig(BlockResponse::NxDomain).await;
    let answer = ask(rig.addr, "good.test.", RecordType::A).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
    assert_eq!(first_a(&answer), Some(UPSTREAM_ANSWER));
    assert_eq!(rig.handler.counters.snapshot().forwarded, 1);
}

#[tokio::test]
async fn blocked_names_get_nxdomain_without_reaching_the_upstream() {
    let rig = rig(BlockResponse::NxDomain).await;
    for name in ["ads.test.", "deep.sub.ads.test."] {
        let answer = ask(rig.addr, name, RecordType::A).await;
        assert_eq!(
            answer.metadata.response_code,
            ResponseCode::NXDomain,
            "{name}"
        );
        assert!(answer.answers.is_empty());
    }
    let counters = rig.handler.counters.snapshot();
    assert_eq!((counters.blocked_list, counters.forwarded), (2, 0));
}

#[tokio::test]
async fn null_address_mode_answers_zero_addresses() {
    let rig = rig(BlockResponse::NullAddress).await;
    let a = ask(rig.addr, "ads.test.", RecordType::A).await;
    assert_eq!(first_a(&a), Some(Ipv4Addr::UNSPECIFIED));
    let aaaa = ask(rig.addr, "ads.test.", RecordType::AAAA).await;
    assert!(matches!(&aaaa.answers[0].data, RData::AAAA(v6) if v6.0.is_unspecified()));
    let mx = ask(rig.addr, "ads.test.", RecordType::MX).await;
    assert_eq!(mx.metadata.response_code, ResponseCode::NoError);
    assert!(mx.answers.is_empty());
}

#[tokio::test]
async fn firefox_canary_is_always_nxdomain() {
    // Even in null-address mode: browsers key on NXDOMAIN.
    let rig = rig(BlockResponse::NullAddress).await;
    let answer = ask(rig.addr, "use-application-dns.net.", RecordType::A).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(rig.handler.counters.snapshot().blocked_canary, 1);
}

#[tokio::test]
async fn allowlist_overrides_a_block() {
    let rig = rig(BlockResponse::NxDomain).await;
    let answer = ask(rig.addr, "fine.ads.test.", RecordType::A).await;
    assert_eq!(first_a(&answer), Some(UPSTREAM_ANSWER));
}

#[tokio::test]
async fn upstream_nxdomain_and_nodata_are_relayed_faithfully() {
    let rig = rig(BlockResponse::NxDomain).await;
    let missing = ask(rig.addr, "missing.test.", RecordType::A).await;
    assert_eq!(missing.metadata.response_code, ResponseCode::NXDomain);
    let nodata = ask(rig.addr, "nodata.test.", RecordType::A).await;
    assert_eq!(nodata.metadata.response_code, ResponseCode::NoError);
    assert!(nodata.answers.is_empty());
}

#[tokio::test]
async fn policy_swap_takes_effect_for_new_queries() {
    let rig = rig(BlockResponse::NxDomain).await;
    assert_eq!(
        ask(rig.addr, "new.test.", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    let mut policy = Policy::new(BlockResponse::NxDomain, true);
    policy.block(["new.test".to_string()]);
    rig.handler.set_policy(policy);
    assert_eq!(
        ask(rig.addr, "new.test.", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
}
