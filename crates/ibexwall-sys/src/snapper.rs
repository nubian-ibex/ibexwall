// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! System snapshots through the person's own snapper (ADR-0050): IbexWall
//! asks for a pair around a risky change and nothing else. It never writes a
//! snapper configuration, deletes a snapshot or restores one.

use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail, ensure};

use crate::log::OpLog;

/// The configuration used, snapper's own default; it must cover `/`.
const CONFIG: &str = "root";
const SNAPPER: &str = "/usr/bin/snapper";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotKind {
    Pre,
    /// Closes the pair opened by the `pre` snapshot with this number.
    Post(u32),
}

pub trait SystemSnapshots: Send + Sync {
    /// `Err` says why snapshots cannot be taken on this machine.
    fn available(&self) -> anyhow::Result<()>;
    /// Takes a snapshot for one transaction and returns its number.
    fn create(&self, kind: SnapshotKind, transaction: &str) -> anyhow::Result<u32>;
}

/// A hung D-Bus call must not hold an apply for ever.
const LIMIT: Duration = Duration::from_secs(120);

/// The snapper command line, run by the daemon like the firewall tools: it
/// only talks to `snapperd` over D-Bus. Disabled under a sandbox root.
#[derive(Debug, Clone)]
pub struct RealSnapper {
    enabled: bool,
}

impl RealSnapper {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    fn run(&self, args: &[String]) -> anyhow::Result<String> {
        ensure!(
            self.enabled,
            "system snapshots are disabled under IBEXWALL_ROOT"
        );
        ensure!(
            std::path::Path::new(SNAPPER).is_file(),
            "snapper is not installed"
        );
        let mut child = Command::new(SNAPPER)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("starting snapper")?;
        // The answers are a few lines: they fit in the pipes while we wait.
        let deadline = Instant::now() + LIMIT;
        while child.try_wait()?.is_none() {
            if Instant::now() > deadline {
                child.kill().context("stopping a hung snapper")?;
                child.wait()?;
                bail!("snapper did not answer within {} s", LIMIT.as_secs());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            bail!(
                "snapper failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

impl SystemSnapshots for RealSnapper {
    fn available(&self) -> anyhow::Result<()> {
        let listing = self.run(&["--jsonout".into(), "list-configs".into()])?;
        ensure!(
            covers_root(&listing)?,
            "snapper has no `{CONFIG}` configuration for /"
        );
        Ok(())
    }

    fn create(&self, kind: SnapshotKind, transaction: &str) -> anyhow::Result<u32> {
        let printed = self.run(&create_args(kind, transaction)?)?;
        printed
            .trim()
            .parse()
            .with_context(|| format!("snapper printed no snapshot number: {printed:?}"))
    }
}

/// Whether `list-configs` (JSON) has our configuration on the root.
fn covers_root(listing: &str) -> anyhow::Result<bool> {
    let value: serde_json::Value =
        serde_json::from_str(listing).context("reading the snapper configurations")?;
    Ok(value["configs"].as_array().is_some_and(|configs| {
        configs
            .iter()
            .any(|c| c["config"] == CONFIG && c["subvolume"] == "/")
    }))
}

fn create_args(kind: SnapshotKind, transaction: &str) -> anyhow::Result<Vec<String>> {
    // The id goes into argv and into snapper's userdata, where `,` and `=`
    // separate fields.
    ensure!(
        !transaction.is_empty()
            && transaction
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "unexpected transaction id"
    );
    let mut args: Vec<String> = ["-c", CONFIG, "create", "--type"].map(String::from).into();
    match kind {
        SnapshotKind::Pre => args.push("pre".into()),
        SnapshotKind::Post(pre) => {
            args.extend(["post".into(), "--pre-number".into(), pre.to_string()]);
        }
    }
    args.extend([
        "--print-number".into(),
        "--cleanup-algorithm".into(),
        "number".into(),
        "--description".into(),
        format!("IbexWall change {transaction}"),
        "--userdata".into(),
        format!("ibexwall_tx={transaction}"),
    ]);
    Ok(args)
}

/// Records what was asked, numbers snapshots from 1 and fails on demand.
#[derive(Default)]
pub struct FakeSnapshots {
    pub log: OpLog,
    state: Mutex<FakeState>,
}

#[derive(Default)]
struct FakeState {
    next: u32,
    unavailable: Option<String>,
    failing: Option<String>,
    failing_post: Option<String>,
}

impl FakeSnapshots {
    pub fn set_unavailable(&self, reason: Option<&str>) {
        self.state.lock().expect("lock poisoned").unavailable = reason.map(Into::into);
    }

    /// Makes every later `create` fail with `reason` (`None` heals it).
    pub fn set_failing(&self, reason: Option<&str>) {
        self.state.lock().expect("lock poisoned").failing = reason.map(Into::into);
    }

    /// The same, for the snapshot that closes a pair.
    pub fn set_failing_post(&self, reason: Option<&str>) {
        self.state.lock().expect("lock poisoned").failing_post = reason.map(Into::into);
    }
}

impl SystemSnapshots for FakeSnapshots {
    fn available(&self) -> anyhow::Result<()> {
        match &self.state.lock().expect("lock poisoned").unavailable {
            Some(reason) => bail!("{reason}"),
            None => Ok(()),
        }
    }

    fn create(&self, kind: SnapshotKind, transaction: &str) -> anyhow::Result<u32> {
        let mut state = self.state.lock().expect("lock poisoned");
        if let Some(reason) = &state.failing {
            bail!("{reason}");
        }
        if let (SnapshotKind::Post(_), Some(reason)) = (kind, &state.failing_post) {
            bail!("{reason}");
        }
        state.next += 1;
        self.log
            .push(format!("{kind:?} {transaction} -> {}", state.next));
        Ok(state.next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_root_configuration_on_the_root_counts() {
        // Recorded from snapper 0.13 on the Fedora and Arch guests.
        assert!(!covers_root(r#"{"configs":[]}"#).unwrap());
        assert!(covers_root(r#"{"configs":[{"config":"root","subvolume":"/"}]}"#).unwrap());
        assert!(!covers_root(r#"{"configs":[{"config":"root","subvolume":"/srv"}]}"#).unwrap());
        assert!(!covers_root(r#"{"configs":[{"config":"home","subvolume":"/"}]}"#).unwrap());
        assert!(covers_root("not json").is_err());
    }

    #[test]
    fn the_commands_are_fixed_and_the_id_cannot_add_fields() {
        let pre = create_args(SnapshotKind::Pre, "tx-1a").unwrap().join(" ");
        assert_eq!(
            pre,
            "-c root create --type pre --print-number --cleanup-algorithm number \
             --description IbexWall change tx-1a --userdata ibexwall_tx=tx-1a"
        );
        let post = create_args(SnapshotKind::Post(7), "tx-1a").unwrap();
        assert_eq!(post[3..7], ["--type", "post", "--pre-number", "7"]);
        for hostile in ["", "a,b=c", "a b", "--help;"] {
            assert!(
                create_args(SnapshotKind::Pre, hostile).is_err(),
                "{hostile}"
            );
        }
    }

    #[test]
    fn a_sandbox_root_never_runs_snapper() {
        let error = RealSnapper::new(false).available().unwrap_err();
        assert!(error.to_string().contains("IBEXWALL_ROOT"));
    }
}
