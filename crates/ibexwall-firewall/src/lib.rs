// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The unified view of the inbound firewall (spec 4.7): which manager owns
//! it, what it allows today, and the small set of typed changes IbexWall
//! may ask of it. Pure logic: files in, structures out, argv out. Every
//! string from a configuration file is untrusted display data.

pub mod action;
pub mod model;
pub mod parse;

pub use action::{ActionError, FirewallAction, argv, reload_argv, snapshot_paths, validate};
pub use model::{Backend, PortRule, Proto, State};
