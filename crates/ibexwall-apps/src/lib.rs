// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which program talks to which domain: correlation and rollups for the
//! monitor mode (phase F4). Pure logic over a SQLite connection the
//! caller owns, so it is testable without a kernel.

pub mod correlate;
pub mod policy;
pub mod store;

pub use correlate::{Correlator, normalize_domain};
pub use store::{
    Alert, AppSummary, DestinationSummary, Error, Observation, SCHEMA, app_key, list_apps,
    list_destinations, prune, record,
};
