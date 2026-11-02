// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The request handler: block locally, forward the rest. It keeps
//! counters per category and never logs query names.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use hickory_server::proto::op::{Header, HeaderCounts, Metadata, ResponseCode};
use hickory_server::proto::rr::{RData, Record, RecordType};
use hickory_server::resolver::Resolver;
use hickory_server::resolver::net::runtime::TokioRuntimeProvider;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;

use crate::policy::{BlockResponse, Category, Policy, Verdict};

/// TTL of locally generated answers; short so list changes show quickly.
const BLOCK_TTL: u32 = 60;

/// Per-category block counts and totals (no names, ever).
#[derive(Debug, Default)]
pub struct Counters {
    pub forwarded: AtomicU64,
    pub blocked_list: AtomicU64,
    pub blocked_canary: AtomicU64,
    pub blocked_doh: AtomicU64,
    pub upstream_errors: AtomicU64,
}

/// Plain snapshot for status reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CounterSnapshot {
    pub forwarded: u64,
    pub blocked_list: u64,
    pub blocked_canary: u64,
    pub blocked_doh: u64,
    pub upstream_errors: u64,
}

impl Counters {
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            forwarded: self.forwarded.load(Ordering::Relaxed),
            blocked_list: self.blocked_list.load(Ordering::Relaxed),
            blocked_canary: self.blocked_canary.load(Ordering::Relaxed),
            blocked_doh: self.blocked_doh.load(Ordering::Relaxed),
            upstream_errors: self.upstream_errors.load(Ordering::Relaxed),
        }
    }

    fn count_block(&self, category: Category) {
        let counter = match category {
            Category::List => &self.blocked_list,
            Category::Canary => &self.blocked_canary,
            Category::DohEndpoint => &self.blocked_doh,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Cheap to clone: the server owns one clone while the daemon keeps another
/// to swap the policy and read counters.
#[derive(Clone)]
pub struct Handler {
    policy: Arc<RwLock<Arc<Policy>>>,
    resolver: Resolver<TokioRuntimeProvider>,
    pub counters: Arc<Counters>,
}

impl Handler {
    pub fn new(policy: Policy, resolver: Resolver<TokioRuntimeProvider>) -> Self {
        Self {
            policy: Arc::new(RwLock::new(Arc::new(policy))),
            resolver,
            counters: Arc::new(Counters::default()),
        }
    }

    /// Swaps the whole policy atomically (list updates).
    pub fn set_policy(&self, policy: Policy) {
        *self.policy.write().expect("policy lock") = Arc::new(policy);
    }

    fn policy(&self) -> Arc<Policy> {
        Arc::clone(&self.policy.read().expect("policy lock"))
    }
}

fn failed(request: &Request, code: ResponseCode) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.response_code = code;
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts::default(),
    })
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: hickory_server::net::runtime::Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let Ok(info) = request.request_info() else {
            return failed(request, ResponseCode::FormErr);
        };
        let name = info.query.name().to_string();
        let query_type = info.query.query_type();
        let policy = self.policy();
        let builder = MessageResponseBuilder::from_message_request(request);

        let result = match policy.decide(&name) {
            Verdict::Block(category) => {
                self.counters.count_block(category);
                let metadata = Metadata::response_from_request(&request.metadata);
                match block_answer(
                    policy.response,
                    category,
                    info.query.name().into(),
                    query_type,
                ) {
                    Blocked::NxDomain => {
                        let response = builder.error_msg(&metadata, ResponseCode::NXDomain);
                        response_handle.send_response(response).await
                    }
                    Blocked::Records(records) => {
                        let response = builder.build(metadata, records.iter(), [], [], []);
                        response_handle.send_response(response).await
                    }
                }
            }
            Verdict::Forward => match self.resolver.lookup(name, query_type).await {
                Ok(lookup) => {
                    self.counters.forwarded.fetch_add(1, Ordering::Relaxed);
                    let metadata = Metadata::response_from_request(&request.metadata);
                    let response = builder.build(metadata, lookup.answers().iter(), [], [], []);
                    response_handle.send_response(response).await
                }
                Err(error) if error.is_nx_domain() => {
                    self.counters.forwarded.fetch_add(1, Ordering::Relaxed);
                    let response = builder.error_msg(&request.metadata, ResponseCode::NXDomain);
                    response_handle.send_response(response).await
                }
                Err(error) if error.is_no_records_found() => {
                    // NODATA: the name exists, the type has no records.
                    self.counters.forwarded.fetch_add(1, Ordering::Relaxed);
                    let metadata = Metadata::response_from_request(&request.metadata);
                    let response = builder.build_no_records(metadata);
                    response_handle.send_response(response).await
                }
                Err(_) => {
                    self.counters
                        .upstream_errors
                        .fetch_add(1, Ordering::Relaxed);
                    let response = builder.error_msg(&request.metadata, ResponseCode::ServFail);
                    response_handle.send_response(response).await
                }
            },
        };
        result.unwrap_or_else(|_| failed(request, ResponseCode::ServFail))
    }
}

enum Blocked {
    NxDomain,
    Records(Vec<Record>),
}

/// The local answer for a blocked name. The canary and DoH endpoints are
/// always NXDOMAIN (that is what browsers key on); list hits follow the
/// configured response.
fn block_answer(
    response: BlockResponse,
    category: Category,
    name: hickory_server::proto::rr::Name,
    query_type: RecordType,
) -> Blocked {
    if category != Category::List || response == BlockResponse::NxDomain {
        return Blocked::NxDomain;
    }
    let rdata = match query_type {
        RecordType::A => RData::A(Ipv4Addr::UNSPECIFIED.into()),
        RecordType::AAAA => RData::AAAA(Ipv6Addr::UNSPECIFIED.into()),
        // No address to give for other types: answer empty (NODATA).
        _ => return Blocked::Records(vec![]),
    };
    Blocked::Records(vec![Record::from_rdata(name, BLOCK_TTL, rdata)])
}
