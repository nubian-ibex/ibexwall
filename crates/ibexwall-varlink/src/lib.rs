// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! In-repo varlink implementation (ADR-0024): NUL-delimited JSON
//! messages, `more`/`continues` streaming and named errors, over tokio
//! unix sockets. The authoritative interface descriptions are the
//! generated files in `spec/idl/`.

mod client;
mod server;
mod wire;

pub use client::{CallStream, Client, call, call_more};
pub use server::{
    futures_handle, serve, serve_with_fd, Call, Handler, Peer, Reply, ServiceInfo,
};
pub use wire::{MAX_MESSAGE_BYTES, Reply as WireReply, Request, VarlinkError};

/// Standard org.varlink.service error names.
pub mod service_errors {
    pub const INVALID_PARAMETER: &str = "org.varlink.service.InvalidParameter";
    pub const METHOD_NOT_FOUND: &str = "org.varlink.service.MethodNotFound";
    pub const METHOD_NOT_IMPLEMENTED: &str = "org.varlink.service.MethodNotImplemented";
    pub const INVALID_MESSAGE: &str = "org.varlink.service.InvalidMessage";
}
