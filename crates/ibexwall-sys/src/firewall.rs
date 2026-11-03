// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Runs the firewall tools the core allows: exactly the binaries in
//! `ibexwall_firewall::action`, with an argv the core itself built. Never a
//! shell, never anything else.

use std::process::{Command, Stdio};
use std::sync::Mutex;

use anyhow::{Result, bail};

use ibexwall_firewall::action::{FIREWALL_CMD, UFW};

pub trait Runner: Send + Sync {
    fn run(&self, argv: &[String]) -> Result<()>;
}

/// Only these programs may run, whatever the caller asks for.
fn allowed(program: &str) -> bool {
    program == FIREWALL_CMD || program == UFW
}

pub struct RealRunner;

impl Runner for RealRunner {
    fn run(&self, argv: &[String]) -> Result<()> {
        let Some((program, args)) = argv.split_first() else {
            bail!("empty command");
        };
        if !allowed(program) {
            bail!("`{program}` is not an allowed firewall tool");
        }
        let output = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .output()?;
        if !output.status.success() {
            bail!(
                "{} failed ({}): {}{}",
                program,
                output.status,
                String::from_utf8_lossy(&output.stderr).trim(),
                String::from_utf8_lossy(&output.stdout).trim()
            );
        }
        Ok(())
    }
}

/// Records what would have run; for tests.
#[derive(Default)]
pub struct FakeRunner {
    pub calls: Mutex<Vec<Vec<String>>>,
    /// Fails any command containing this word.
    pub fail_on: Mutex<Option<String>>,
}

impl FakeRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }
}

impl Runner for FakeRunner {
    fn run(&self, argv: &[String]) -> Result<()> {
        if !argv.first().is_some_and(|program| allowed(program)) {
            bail!("not an allowed firewall tool: {argv:?}");
        }
        if let Some(word) = self.fail_on.lock().unwrap().as_deref()
            && argv.iter().any(|arg| arg.contains(word))
        {
            bail!("simulated failure for {argv:?}");
        }
        self.calls.lock().unwrap().push(argv.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_two_tools_may_run() {
        let runner = RealRunner;
        for argv in [
            vec!["/bin/sh".to_string(), "-c".into(), "true".into()],
            vec!["/usr/bin/nft".to_string()],
            vec![],
        ] {
            assert!(runner.run(&argv).is_err(), "{argv:?}");
        }
        let fake = FakeRunner::new();
        assert!(fake.run(&["/bin/true".to_string()]).is_err());
        fake.run(&[FIREWALL_CMD.to_string(), "--reload".into()])
            .unwrap();
        assert_eq!(fake.calls().len(), 1);
        *fake.fail_on.lock().unwrap() = Some("--reload".into());
        assert!(
            fake.run(&[FIREWALL_CMD.to_string(), "--reload".into()])
                .is_err()
        );
    }
}
