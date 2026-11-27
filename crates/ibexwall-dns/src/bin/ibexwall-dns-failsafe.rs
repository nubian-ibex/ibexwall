// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! A separate entry point for the failsafe, so the SELinux policy can give
//! it a domain of its own: the resolver's domain must not be allowed to
//! restore the person's DNS, and this one is permissive (see the policy).

fn main() {
    let root = ibexwall_proto::names::root();
    if let Err(error) = ibexwall_dns::failsafe::run(&root) {
        eprintln!("ibexwall-dns-failsafe: {error:#}");
        std::process::exit(1);
    }
}
