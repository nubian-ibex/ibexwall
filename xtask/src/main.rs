// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Developer tasks: `cargo xtask <command>`.

// Developer tooling, not shipped: a failed unwrap here is a clear stop.
#![allow(clippy::unwrap_used)]

mod devkey;
mod ebpf;
mod egress;
mod f1;
mod f2;
mod f3;
mod f4;
mod f5;
mod f6;
mod f7;
mod f8;
mod f9;
mod fixtures;
mod idl;
mod schemas;
mod vm;

const HELP: &str = "\
IbexWall developer tasks

Usage: cargo xtask <COMMAND>

Commands:
  schemas [--check]  Export JSON Schemas and varlink IDL to spec/
                     (--check fails if committed files differ)
  vm-test [--distro <distro>] [--phase f0|f1|f2|f3|f4|f5|f6|f7|f8|f9|fixtures]
                     Boot a QEMU/KVM VM; phase f0 runs the smoke test,
                     f1 provisions the daemon and runs acceptance tests
  ebpf               Build the eBPF programs into target/bpf/ (nightly,
                     rust-src and bpf-linker required)
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
        Some("ebpf") => {
            if let Err(err) = ebpf::run() {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
        }
        Some("vm-test") => {
            let mut distro = "fedora".to_string();
            let mut phase = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--distro" => distro = args.next().unwrap_or(distro),
                    "--phase" => phase = args.next(),
                    other => {
                        eprintln!("error: unknown vm-test flag `{other}`");
                        std::process::exit(2);
                    }
                }
            }
            let result = match phase.as_deref() {
                None | Some("f0") | Some("f1") | Some("f2") | Some("f3") | Some("f4")
                | Some("f5") | Some("f6") | Some("f7") | Some("f8") | Some("f9")
                | Some("fixtures") => vm::run(&distro, phase.as_deref()),
                Some(other) => {
                    eprintln!("error: unknown phase `{other}`");
                    std::process::exit(2);
                }
            };
            if let Err(err) = result {
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
