// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F1 VM suite: provisions a real daemon + CLI + dev plugin into the
//! Fedora VM and runs the acceptance scenarios from the spec (§15 F1)
//! as scripts, including chaos (kill -9 mid-apply) and audit tamper
//! detection. The dev host is never touched.

use std::io::Write;
use std::path::Path;

use anyhow::{Result, bail};

use super::vm::{Vm, run_capture};

pub fn run(vm: &Vm, workspace: &Path) -> Result<()> {
    println!("== f1: build + devkey ==");
    run_capture(
        "cargo",
        [
            "build",
            "--release",
            "-p",
            "ibexwall-core",
            "-p",
            "ibexwall-cli",
            "-p",
            "ibexwall-plugin-echo",
        ],
        None,
        "building release binaries",
    )?;
    crate::devkey::run()?;

    let release = workspace.join("target/release");
    let plugin = workspace.join("plugins/dev.echo");

    println!("== f1: provision ==");
    vm.ssh("rpm -q polkit >/dev/null 2>&1 || sudo dnf install -y polkit >/dev/null 2>&1; sudo systemctl start polkit.service 2>&1 || true")?;
    vm.ssh("sudo mkdir -p /usr/lib/ibexwall/plugins/dev.echo /etc/ibexwall /var/lib/ibexwall /run/ibexwall /usr/share/polkit-1/actions")?;
    pipe_file(
        vm,
        &release.join("ibexwalld"),
        "sudo tee /usr/bin/ibexwalld >/dev/null && sudo chmod 755 /usr/bin/ibexwalld",
    )?;
    pipe_file(
        vm,
        &release.join("ibexctl"),
        "sudo tee /usr/bin/ibexctl >/dev/null && sudo chmod 755 /usr/bin/ibexctl",
    )?;
    pipe_file(
        vm,
        &release.join("ibexwall-plugin-echo"),
        "sudo tee /usr/lib/ibexwall/plugins/dev.echo/ibexwall-plugin-echo >/dev/null && sudo chmod 755 /usr/lib/ibexwall/plugins/dev.echo/ibexwall-plugin-echo",
    )?;
    pipe_file(
        vm,
        &plugin.join("plugin.toml"),
        "sudo tee /usr/lib/ibexwall/plugins/dev.echo/plugin.toml >/dev/null",
    )?;
    pipe_file(
        vm,
        &plugin.join("plugin.toml.sig"),
        "sudo tee /usr/lib/ibexwall/plugins/dev.echo/plugin.toml.sig >/dev/null",
    )?;
    pipe_file(
        vm,
        &workspace.join("target/devkey/dev.pub"),
        "sudo mkdir -p /etc/ibexwall/trust && sudo tee /etc/ibexwall/trust/dev.pub >/dev/null",
    )?;
    pipe_data(
        vm,
        include_str!("../../packaging/polkit/com.ibexwall.policy"),
        "sudo tee /usr/share/polkit-1/actions/com.ibexwall.policy >/dev/null",
    )?;
    pipe_data(
        vm,
        include_str!("../../packaging/systemd/ibexwalld.service"),
        "sudo tee /etc/systemd/system/ibexwalld.service >/dev/null",
    )?;
    pipe_data(
        vm,
        include_str!("../../packaging/systemd/ibexwalld.socket"),
        "sudo tee /etc/systemd/system/ibexwalld.socket >/dev/null",
    )?;
    // Test-only drop-in: trust the dev plugin key (not packaged).
    pipe_data(
        vm,
        "[Service]\nExecStart=\nExecStart=/usr/bin/ibexwalld --dev-key=/etc/ibexwall/trust/dev.pub\n",
        "sudo mkdir -p /etc/systemd/system/ibexwalld.service.d && sudo tee /etc/systemd/system/ibexwalld.service.d/dev.conf >/dev/null",
    )?;
    start_daemon(vm)?;

    let mut failures = 0;
    macro_rules! scenario {
        ($name:expr, $script:expr) => {
            if !run_script(vm, $name, $script) {
                failures += 1;
            }
        };
    }

    scenario!(
        "s0 enable plugin + status",
        r#"
set -e
sudo ibexctl plugins enable dev.echo
sudo ibexctl status --json | grep -q '"api"'
"#
    );

    scenario!(
        "s1 plan/apply/commit + byte-for-byte rollback",
        r#"
set -e
F=/etc/sysctl.d/90-ibexwall-test.conf
sudo rm -f $F
P=$(sudo ibexctl plan dev.echo --set template=dropin_file --json | tee /dev/stderr | python3 -c 'import json,sys;print(json.load(sys.stdin)["plan"]["id"])')
OUT=$(sudo ibexctl apply $P --json 2>&1) || { echo "APPLY FAILED: $OUT" >&2; sudo journalctl -u ibexwalld -n 15 --no-pager >&2; exit 1; }
echo "$OUT" | grep -q '"state": "committed"'
sudo test -f $F
TX=$(echo "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["transaction"]["id"])')
sudo ibexctl rollback $TX --json >/dev/null
sudo test ! -f $F
"#
    );

    scenario!(
        "s2 sysctl set + persist + rollback",
        r#"
set -e
P=$(sudo ibexctl plan dev.echo --set template=sysctl --json | tee /dev/stderr | python3 -c 'import json,sys;print(json.load(sys.stdin)["plan"]["id"])')
OUT=$(sudo ibexctl apply $P --json 2>&1) || { echo "APPLY FAILED: $OUT" >&2; sudo journalctl -u ibexwalld -n 15 --no-pager >&2; exit 1; }
echo "$OUT" | grep -q committed
grep -q 'vm.swappiness = 10' /etc/sysctl.d/90-ibexwall-test.conf
[ "$(cat /proc/sys/vm/swappiness)" = "10" ]
TX=$(echo "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["transaction"]["id"])')
sudo ibexctl rollback $TX --json >/dev/null
[ "$(cat /proc/sys/vm/swappiness)" != "10" ]
"#
    );

    scenario!(
        "s3 kill -9 mid-apply -> rollback on restart",
        r#"
set -e
P=$(sudo ibexctl plan dev.echo --set template=slow --json | tee /dev/stderr | python3 -c 'import json,sys;print(json.load(sys.stdin)["plan"]["id"])')
(sudo ibexctl apply $P --json >/tmp/apply.out 2>&1 &)
sleep 2
sudo kill -9 "$(systemctl show -p MainPID --value ibexwalld.service)"
sleep 1
# systemd restarts the service (Restart=on-failure) or the socket
# re-activates it on the next call; recovery runs at startup.
for i in $(seq 1 20); do sudo ibexctl status --json >/dev/null 2>&1 && break; sleep 1; done
sudo ibexctl history --json | grep -q rolled_back
"#
    );

    scenario!(
        "s4 network change without confirm auto-reverts",
        r#"
set -e
P=$(sudo ibexctl plan dev.echo --set template=network --json | tee /dev/stderr | python3 -c 'import json,sys;print(json.load(sys.stdin)["plan"]["id"])')
sudo ibexctl apply $P --confirm-timeout 10 --json | grep -q pending_confirm
sudo test -f /etc/NetworkManager/conf.d/50-ibexwall-test.conf
sleep 15
sudo test ! -f /etc/NetworkManager/conf.d/50-ibexwall-test.conf
"#
    );

    scenario!(
        "s5 unauthorized user gets exit 3 (permission denied)",
        r#"
P=$(sudo ibexctl plan dev.echo --set template=dropin_file --json | tee /dev/stderr | python3 -c 'import json,sys;print(json.load(sys.stdin)["plan"]["id"])')
OUT=$(ibexctl apply $P --json 2>&1)
RC=$?
echo "rc=$RC out=$OUT" >&2
[ "$RC" -eq 3 ]
"#
    );

    scenario!(
        "s6 audit verify detects tampering",
        r#"
set -e
sudo ibexctl audit verify >/dev/null
sudo python3 - <<'EOF'
import sqlite3
c = sqlite3.connect("/var/lib/ibexwall/state.db")
c.execute("UPDATE audit_log SET result='tampered' WHERE seq=2")
c.commit()
EOF
sudo ibexctl audit verify >/dev/null 2>&1 && exit 1 || exit 0
"#
    );

    scenario!(
        "s7 out-of-manifest operation refused",
        r#"
sudo ibexctl plan dev.echo --set template=out_of_manifest --json >/dev/null 2>&1
RC=$?
[ "$RC" -ne 0 ] && [ "$RC" -ne 2 ]
"#
    );

    if failures == 0 {
        println!("PASS: f1 acceptance suite (all scenarios)");
        Ok(())
    } else {
        bail!("{failures} f1 scenario(s) failed")
    }
}

fn start_daemon(vm: &Vm) -> Result<()> {
    vm.ssh("sudo systemctl daemon-reload && sudo systemctl start ibexwalld.socket")?;
    for _ in 0..30 {
        if vm.ssh("sudo ibexctl status --json").is_ok() {
            println!("daemon is up (socket activation)");
            let analysis = vm
                .ssh("systemd-analyze security ibexwalld.service --no-pager 2>&1 | tail -4")
                .unwrap_or_default();
            println!("systemd-analyze security ibexwalld.service:\n{analysis}");
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let log = vm
        .ssh("sudo journalctl -u ibexwalld -n 30 --no-pager")
        .unwrap_or_default();
    bail!("daemon did not come up; journal:\n{log}");
}

fn pipe_file(vm: &Vm, local: &Path, remote_cmd: &str) -> Result<()> {
    vm.ssh_pipe(local, remote_cmd).map(|_| ())
}

fn pipe_data(vm: &Vm, data: &str, remote_cmd: &str) -> Result<()> {
    let mut child = vm
        .ssh_base()
        .arg(remote_cmd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(data.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "pipe_data failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn run_script(vm: &Vm, name: &str, script: &str) -> bool {
    let mut child = match vm
        .ssh_base()
        .arg("bash -s")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            eprintln!("FAIL: {name}: spawn ssh: {err}");
            return false;
        }
    };
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(script.as_bytes());
    }
    let output = child.wait_with_output().expect("wait ssh bash");
    if output.status.success() {
        println!("PASS: {name}");
        true
    } else {
        eprintln!(
            "FAIL: {name} (exit {})\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn polkit_policy_declares_every_action_in_names() {
        let policy = include_str!("../../packaging/polkit/com.ibexwall.policy");
        for action in ibexwall_proto::names::polkit_actions() {
            assert!(
                policy.contains(&format!("<action id=\"{action}\">")),
                "packaging/polkit is missing `{action}`"
            );
        }
    }
}
