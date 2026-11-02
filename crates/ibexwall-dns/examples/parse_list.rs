// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parses a list file with the production parser and prints the counts.
//! Usage: `cargo run -p ibexwall-dns --example parse_list -- <file>`

use std::time::Instant;

fn main() {
    let path = std::env::args().nth(1).expect("path to a list file");
    let bytes = std::fs::read(&path).expect("readable file");
    let started = Instant::now();
    match ibexwall_dns::blocklist::parse(&bytes) {
        Ok(parsed) => println!(
            "{path}: {} block, {} allow, {} skipped, {:?}",
            parsed.block.len(),
            parsed.allow.len(),
            parsed.skipped,
            started.elapsed()
        ),
        Err(error) => println!("{path}: error: {error}"),
    }
}
