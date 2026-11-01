// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Developer tasks: `cargo xtask <command>`.

mod devkey;
mod idl;
mod schemas;
mod vm;

const HELP: &str = "\
IbexWall developer tasks

Usage: cargo xtask <COMMAND>

Commands:
  schemas [--check]  Export JSON Schemas and varlink IDL to spec/
                     (--check fails if committed files differ)
  vm-test [--distro <distro>]
                     Boot a QEMU/KVM VM and run the smoke test (F0: fedora)
  devkey             Generate the dev plugin-signing key and sign
                     plugins/*/plugin.toml (dev builds only)
";

fn main() {
    // `cargo xtask <cmd>` expands to `cargo run -p xtask -- <cmd>`, so
    // argv[1] is already the command.
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("schemas") => {
            let check = args.any(|a| a == "--check");
            if let Err(err) = schemas::run(check) {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
        }
        Some("vm-test") => {
            let distro = match args.next() {
                Some(a) if a == "--distro" => args.next().unwrap_or_else(|| "fedora".into()),
                _ => "fedora".into(),
            };
            if let Err(err) = vm::run(&distro) {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
        }
        Some("devkey") => {
            if let Err(err) = devkey::run() {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
        }
        Some(other) => {
            eprintln!("error: unknown command `{other}`\n\n{HELP}");
            std::process::exit(2);
        }
        None => print!("{HELP}"),
    }
}
