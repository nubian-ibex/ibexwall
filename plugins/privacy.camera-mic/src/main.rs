// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `privacy.camera-mic`: who is using the camera or the microphone right
//! now. A snapshot read from the kernel's own records, with no command and
//! no audio server involved: a program that has a `/dev/video*` node open
//! is using a camera; an ALSA capture substream in the `RUNNING` state
//! (`/proc/asound/card*/pcm*c/sub*/status`, which names the owner) is
//! recording from a microphone. PipeWire-level portals sit on top of
//! these, so what applications are doing through them shows here too.
//!
//! The continuous event stream the spec calls a monitor needs the
//! plugin SDK's monitor interface, which does not exist yet: the session
//! agent can poll this check meanwhile. Findings are informational (a
//! camera in use is not a fault) and never count against the score.
//! Process names are chosen by the program and travel as arguments only.

use std::collections::{BTreeMap, BTreeSet};

use ibexwall_proto::{CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Severity};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde_json::Value;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(CameraMic)) {
        eprintln!("ibexwall-plugin-camera-mic: {err}");
        std::process::exit(1);
    }
}

struct CameraMic;

impl Plugin for CameraMic {
    fn id(&self) -> &'static str {
        "privacy.camera-mic"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }
}

fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(80)
        .collect()
}

fn process_name(sandbox: &Sandbox, pid: &str) -> String {
    sandbox
        .read(&format!("/proc/{pid}/comm"))
        .map(|c| clean(c.trim()))
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn pids(sandbox: &Sandbox) -> Vec<String> {
    sandbox
        .list("/proc")
        .into_iter()
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        .collect()
}

/// `(pid, device)` of programs holding a video node open.
fn cameras(sandbox: &Sandbox) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for pid in pids(sandbox) {
        for fd in sandbox.list(&format!("/proc/{pid}/fd")) {
            if let Some(target) = sandbox.read_link(&format!("/proc/{pid}/fd/{fd}"))
                && let Some(device) = target.strip_prefix("/dev/")
                && device.starts_with("video")
                && device[5..].bytes().all(|b| b.is_ascii_digit())
            {
                out.insert((pid.clone(), format!("/dev/{device}")));
            }
        }
    }
    out
}

/// `(pid, card/pcm)` of ALSA capture substreams that are running.
fn microphones(sandbox: &Sandbox) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for card in sandbox.list("/proc/asound") {
        if !card.starts_with("card") {
            continue;
        }
        for pcm in sandbox.list(&format!("/proc/asound/{card}")) {
            // `pcm0c` is capture, `pcm0p` playback.
            if !(pcm.starts_with("pcm") && pcm.ends_with('c')) {
                continue;
            }
            for sub in sandbox.list(&format!("/proc/asound/{card}/{pcm}")) {
                if !sub.starts_with("sub") {
                    continue;
                }
                let Some(status) = sandbox.read(&format!("/proc/asound/{card}/{pcm}/{sub}/status"))
                else {
                    continue;
                };
                let mut running = false;
                let mut owner = None;
                for line in status.lines() {
                    if let Some(state) = line.strip_prefix("state:") {
                        running = state.trim() == "RUNNING";
                    }
                    if let Some(pid) = line.strip_prefix("owner_pid") {
                        owner = pid
                            .trim_start_matches([' ', ':', '\t'])
                            .trim()
                            .parse::<u32>()
                            .ok();
                    }
                }
                if running {
                    out.insert((
                        owner.map(|p| p.to_string()).unwrap_or_default(),
                        format!("{card}/{pcm}"),
                    ));
                }
            }
        }
    }
    out
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let id = "camera_mic.in_use";
    if sandbox.list("/proc").is_empty() {
        return CheckReport {
            results: vec![CheckResult {
                id: id.into(),
                severity: Severity::Info,
                outcome: CheckOutcome::NotAssessed,
            }],
            findings: vec![],
        };
    }
    let mut findings = Vec::new();
    let mut add = |kind: &str, pid: &str, device: &str| {
        let mut args = BTreeMap::new();
        args.insert("process".to_string(), process_name(sandbox, pid));
        args.insert("pid".to_string(), pid.to_string());
        args.insert("device".to_string(), device.to_string());
        findings.push(Finding {
            id: format!("cameramic.{kind}.{pid}.{}", device.replace('/', "_")),
            plugin: "privacy.camera-mic".into(),
            severity: Severity::Info,
            title_key: format!("cameramic-{kind}-title"),
            summary_key: format!("cameramic-{kind}-summary"),
            args,
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        });
    };
    for (pid, device) in cameras(sandbox) {
        add("camera", &pid, &device);
    }
    for (pid, device) in microphones(sandbox) {
        add("mic", &pid, &device);
    }
    CheckReport {
        results: vec![CheckResult {
            id: id.into(),
            severity: Severity::Info,
            outcome: CheckOutcome::Pass,
        }],
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-cam-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("proc")).unwrap();
        (root.clone(), Sandbox::at(root))
    }

    fn put(root: &std::path::Path, path: &str, text: &str) {
        let full = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, text).unwrap();
    }

    fn open_fd(root: &std::path::Path, pid: &str, fd: &str, target: &str) {
        let dir = root.join(format!("proc/{pid}/fd"));
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(target, dir.join(fd)).unwrap();
    }

    #[test]
    fn a_program_holding_a_video_node_is_using_a_camera() {
        let (root, sandbox) = tree();
        put(&root, "/proc/4321/comm", "zoom\n");
        open_fd(&root, "4321", "7", "/dev/video0");
        open_fd(&root, "4321", "8", "/dev/null");
        put(&root, "/proc/99/comm", "bash\n");
        open_fd(&root, "99", "0", "/dev/pts/1");
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.findings.len(), 1);
        let f = &report.findings[0];
        assert_eq!(f.title_key, "cameramic-camera-title");
        assert_eq!(f.args["process"], "zoom");
        assert_eq!(f.args["device"], "/dev/video0");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(
            report.results[0].outcome,
            CheckOutcome::Pass,
            "in use is not a fault"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn only_running_capture_substreams_are_microphones() {
        let (root, sandbox) = tree();
        put(&root, "/proc/55/comm", "arecord\n");
        put(
            &root,
            "/proc/asound/card0/pcm0c/sub0/status",
            "state: RUNNING\nowner_pid   : 55\n",
        );
        put(&root, "/proc/asound/card0/pcm0c/sub1/status", "closed\n");
        put(
            &root,
            "/proc/asound/card0/pcm0p/sub0/status",
            "state: RUNNING\nowner_pid   : 77\n",
        );
        put(
            &root,
            "/proc/asound/card1/pcm0c/sub0/status",
            "state: PREPARED\nowner_pid   : 88\n",
        );
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].title_key, "cameramic-mic-title");
        assert_eq!(report.findings[0].args["process"], "arecord");
        assert_eq!(report.findings[0].args["device"], "card0/pcm0c");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nothing_in_use_is_a_clean_pass_and_no_proc_is_not_assessed() {
        let (root, sandbox) = tree();
        put(&root, "/proc/1/comm", "init\n");
        let report = evaluate(&sandbox, "now");
        assert!(report.findings.is_empty());
        assert_eq!(report.results[0].outcome, CheckOutcome::Pass);
        std::fs::remove_dir_all(root).unwrap();
        let root = std::env::temp_dir().join("ibx-cam-empty");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        assert_eq!(
            evaluate(&Sandbox::at(&root), "now").results[0].outcome,
            CheckOutcome::NotAssessed
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_hostile_process_name_stays_plain_text() {
        let (root, sandbox) = tree();
        put(&root, "/proc/5/comm", "<b>x</b>\u{1b}[31m\n");
        open_fd(&root, "5", "3", "/dev/video2");
        let report = evaluate(&sandbox, "now");
        let name = &report.findings[0].args["process"];
        assert!(!name.contains('\u{1b}'));
        assert_eq!(report.findings[0].summary_key, "cameramic-camera-summary");
        std::fs::remove_dir_all(root).unwrap();
    }
}
