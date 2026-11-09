// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Developer tasks: `cargo xtask <command>`.

// Developer tooling, not shipped: a failed unwrap here is a clear stop.
#![allow(clippy::unwrap_used)]

mod desktop;
mod devkey;
mod ebpf;
mod egress;
mod f1;
mod f10;
mod f11a;
mod f11b;
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
mod mac;
mod plugin_units;
mod release;
mod schemas;
mod stage;
mod vm;

const HELP: &str = "\
IbexWall developer tasks

Usage: cargo xtask <COMMAND>

Commands:
  schemas [--check]  Export JSON Schemas and varlink IDL to spec/
                     (--check fails if committed files differ)
  vm-test [--distro <distro>] [--phase f0|f1|f2|f3|f4|f5|f6|f7|f8|f9|f10|f11a|f11b|fixtures]
                     Boot a QEMU/KVM VM; phase f0 runs the smoke test,
                     f1 provisions the daemon and runs acceptance tests
  ebpf               Build the eBPF programs into target/bpf/ (nightly,
                     rust-src and bpf-linker required)
  stage              Lay IbexWall out as installed under one directory, for the
                     packages (--destdir, --key-dir, --skip-build, --no-desktop,
                     --target-dir)
  release --version V [--key-dir D] [--out DIR] [--skip-build]
                     Build the release artifacts, their SBOM and provenance,
                     checksum and sign them (the key is the maintainer's)
  verify-release DIR PUBKEY
                     Check the checksums and signatures of a release
  repro [--key-dir D] [--with-desktop]
                     Build twice from copies of HEAD and compare every file
  plugin-units       Write the systemd socket and service unit of every plugin
                     (--out DIR, default target/plugin-units)
  releasekey --out DIR
                     Generate a fresh official release key (minisign, ed25519)
                     without signing anything or touching the dev key
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
                | Some("f5") | Some("f6") | Some("f7") | Some("f8") | Some("f9") | Some("f10")
                | Some("f11a") | Some("f11b") | Some("desktop") | Some("selinux")
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
        Some("plugin-units") => {
            let mut out = std::path::PathBuf::from("target/plugin-units");
            while let Some(arg) = args.next() {
                if arg == "--out" {
                    out = args.next().unwrap_or_default().into();
                }
            }
            if let Err(err) = plugin_units::run(&out) {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
        }
        Some("stage") => {
            let mut options = stage::Options {
                destdir: "target/stage/root".into(),
                key_dir: "target/devkey".into(),
                build: true,
                desktop: true,
                target_dir: None,
                build_env: Vec::new(),
            };
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--destdir" => options.destdir = args.next().unwrap_or_default().into(),
                    "--key-dir" => options.key_dir = args.next().unwrap_or_default().into(),
                    "--skip-build" => options.build = false,
                    "--no-desktop" => options.desktop = false,
                    "--target-dir" => {
                        options.target_dir = Some(args.next().unwrap_or_default().into());
                    }
                    other => {
                        eprintln!("error: unknown stage flag `{other}`");
                        std::process::exit(2);
                    }
                }
            }
            if let Err(err) = stage::run_stage(&options) {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
        }
        Some("releasekey") => {
            let mut out: std::path::PathBuf = "target/releasekey".into();
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--out" => out = args.next().unwrap_or_default().into(),
                    other => {
                        eprintln!("error: unknown releasekey flag `{other}`");
                        std::process::exit(2);
                    }
                }
            }
            if let Err(err) = devkey::run_release(&out) {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
        }
        Some("release") => {
            let mut options = release::Release {
                version: String::new(),
                key_dir: "target/devkey".into(),
                out: "target/release-artifacts".into(),
                build: true,
            };
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--version" => options.version = args.next().unwrap_or_default(),
                    "--key-dir" => options.key_dir = args.next().unwrap_or_default().into(),
                    "--out" => options.out = args.next().unwrap_or_default().into(),
                    "--skip-build" => options.build = false,
                    other => {
                        eprintln!("error: unknown release flag `{other}`");
                        std::process::exit(2);
                    }
                }
            }
            if options.version.is_empty() {
                eprintln!("error: --version is required");
                std::process::exit(2);
            }
            if let Err(err) = release::run_release(&options) {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
        }
        Some("verify-release") => {
            let dir = args.next().unwrap_or_default();
            let key = args.next().unwrap_or_default();
            if let Err(err) = release::verify(dir.as_ref(), key.as_ref()) {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
        }
        Some("repro") => {
            let mut key_dir: std::path::PathBuf = "target/devkey".into();
            let mut desktop = false;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--key-dir" => key_dir = args.next().unwrap_or_default().into(),
                    "--with-desktop" => desktop = true,
                    other => {
                        eprintln!("error: unknown repro flag `{other}`");
                        std::process::exit(2);
                    }
                }
            }
            let key_dir = key_dir.canonicalize().unwrap_or(key_dir);
            if let Err(err) = release::repro(&key_dir, desktop) {
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
