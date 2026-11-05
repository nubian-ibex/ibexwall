// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The IbexWall MCP server (spec 4.12). It runs as the user, talks to the
//! core over its socket, and exposes a constant list of tools that read
//! posture, findings and events and propose changes. There is no tool that
//! applies, reverts, approves or changes scopes: what is not in the list
//! cannot be called.

pub mod admin;
pub mod audit;
pub mod config;
pub mod http;
pub mod ratelimit;
pub mod redact;
pub mod server;
pub mod token;
pub mod tools;
