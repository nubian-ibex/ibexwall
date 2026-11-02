// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ibexwall-dns`: the local forwarding resolver. It answers blocked names
//! itself and forwards everything else over an encrypted upstream.

pub mod config;
pub mod handler;
pub mod policy;
