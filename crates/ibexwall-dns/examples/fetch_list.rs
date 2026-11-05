// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#![allow(clippy::unwrap_used)]

//! Updates one list into a directory with the production fetcher.
//! Usage: `cargo run -p ibexwall-dns --example fetch_list -- <dir> <id> [url]`

use ibexwall_dns::lists::{HttpsFetcher, ListRef, Store, update};

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("directory");
    let id = args.next().expect("list id");
    let url = args.next();
    let store = Store::new(dir);
    match update(&store, &HttpsFetcher::default(), &ListRef { id, url }) {
        Ok(entries) => println!("ok: {entries} entries stored"),
        Err(error) => println!("error: {error}"),
    }
}
