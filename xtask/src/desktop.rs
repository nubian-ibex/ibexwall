// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `desktop` VM phase: IbexWall as a person without root uses it
//! (v0.1.1, ADR-0045). Every other phase runs as root, which polkit
//! allows without asking, so none of them could see that a person at
//! the desktop was refused every change.
//!
//! A cloud VM has no graphical session, so two things stand in for one:
//! a test polkit rule gives the test user what an active session gets
//! by default (read and plan allowed, changes after a password), and a
//! small driver plays both the person at a terminal and the session's
//! authentication agent (`pkttyagent`), each on its own pseudo-terminal.

use std::path::Path;

use anyhow::{Context, Result, bail};

use super::f1::{pipe_data, pipe_file, run_script};
use super::f11b::{BUILD, INSTALL, LIB, stage_and_pack};
use super::vm::Vm;

/// Runs a command as the test user on a terminal, with or without an
/// agent that answers the password prompt, and exits with its status.
/// Usage: drive.py agent-ok|agent-wrong|no-agent COMMAND...
const DRIVER: &str = r#"
import os, pty, re, select, shlex, sys, time

USER = "ibxuser"
mode, command = sys.argv[1], sys.argv[2:]
password = {"agent-ok": "ibx-Test-pass-1", "agent-wrong": "not-the-password"}.get(mode)

def spawn(argv):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    return pid, fd

def read(fd, timeout):
    ready, _, _ = select.select([fd], [], [], max(timeout, 0))
    if not ready:
        return None
    try:
        return os.read(fd, 4096)
    except OSError:
        return b""

# The command waits two seconds so the agent is registered for it first;
# exec keeps the pid the agent is registered for.
inner = "echo IBXPID=$$; sleep 2; exec " + " ".join(shlex.quote(c) for c in command)
cpid, cfd = spawn(["sudo", "-u", USER, "sh", "-c", inner])
out = b""
deadline = time.time() + 15
while not re.search(rb"IBXPID=(\d+)\r?\n", out):
    chunk = read(cfd, deadline - time.time())
    if not chunk:
        sys.exit("the command did not start")
    out += chunk
target = re.search(rb"IBXPID=(\d+)", out).group(1).decode()
out = out.split(b"\n", 1)[1] if b"\n" in out else b""

agent = None
if password is not None:
    agent = spawn(["sudo", "-u", USER, "pkttyagent", "--process", target])

agent_log = b""
status = None
deadline = time.time() + 90
while time.time() < deadline:
    fds = [cfd] + ([agent[1]] if agent else [])
    ready, _, _ = select.select(fds, [], [], 0.5)
    for fd in ready:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            chunk = b""
        if fd == cfd:
            out += chunk
        else:
            agent_log += chunk
            if b"assword" in chunk:
                os.write(fd, password.encode() + b"\n")
    done, raw = os.waitpid(cpid, os.WNOHANG)
    if done:
        while True:
            chunk = read(cfd, 0.2)
            if not chunk:
                break
            out += chunk
        status = os.waitstatus_to_exitcode(raw)
        break

if agent:
    try:
        os.kill(agent[0], 15)
    except ProcessLookupError:
        pass
sys.stdout.write(out.decode(errors="replace"))
sys.stderr.write(agent_log.decode(errors="replace"))
sys.exit(124 if status is None else status)
"#;

/// A fresh install: a valid empty audit chain, no warning at start, and
/// the resolver's answers socket open to the resolver only.
const FRESH: &str = r#"
sudo ibexctl audit verify --json | grep -q '"valid": true' || { echo "A FRESH AUDIT CHAIN IS NOT VALID"; sudo ibexctl audit verify --json; exit 1; }
warns=$(sudo journalctl -u ibexwalld -b -o cat --no-pager | grep -E ' (WARN|ERROR) ' || true)
if [ -n "$warns" ]; then echo "THE DAEMON WARNED AT START:"; echo "$warns"; exit 1; fi
sock=/run/ibexwall/answers.sock
sudo test -S $sock || { echo "NO ANSWERS SOCKET"; exit 1; }
mode=$(sudo stat -c '%a %G' $sock)
[ "$mode" = "660 ibexwall-dns" ] || { echo "THE ANSWERS SOCKET IS $mode"; exit 1; }
send='import socket,sys; s=socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); s.sendto(b"{\"domain\":\"x.test.\",\"ip\":\"203.0.113.9\",\"ttl\":60}", sys.argv[1])'
sudo -u ibexwall-dns python3 -c "$send" $sock || { echo "THE RESOLVER CANNOT SEND"; exit 1; }
echo "METRIC: fresh install: empty chain valid, no warning at start, answers socket 660 ibexwall-dns"
"#;

/// The test user and the rule that stands in for an active session.
const PERSON: &str = r#"
id ibxuser >/dev/null 2>&1 || sudo useradd -m ibxuser
echo 'ibxuser:ibx-Test-pass-1' | sudo chpasswd
command -v pkttyagent >/dev/null || { [ $FAM = deb ] && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq pkexec >/dev/null; }
command -v pkttyagent >/dev/null || { echo "NO pkttyagent ON THIS MACHINE"; exit 1; }
# Newer polkit runs the password helper from a socket unit instead of a
# setuid binary; a freshly installed polkit has not started it yet.
if systemctl list-unit-files polkit-agent-helper.socket >/dev/null 2>&1; then
  sudo systemctl enable --now polkit-agent-helper.socket >/dev/null 2>&1 || true
fi
sudo install -d -m 755 /etc/polkit-1/rules.d
sudo tee /etc/polkit-1/rules.d/00-ibexwall-test.rules >/dev/null <<'JS'
// Test only: the defaults an active desktop session gets for IbexWall.
polkit.addRule(function(action, subject) {
  if (subject.user != "ibxuser" || action.id.indexOf("com.ibexwall.") != 0) {
    return polkit.Result.NOT_HANDLED;
  }
  if (action.id == "com.ibexwall.read" || action.id == "com.ibexwall.plan") {
    return polkit.Result.YES;
  }
  return polkit.Result.AUTH_SELF;
});
JS
sleep 3
sudo -u ibxuser ibexctl status >/dev/null || { echo "THE PERSON CANNOT READ"; exit 1; }
if echo '{}' | sudo -u ibxuser python3 -c 'import socket; s=socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); s.sendto(b"{}", "/run/ibexwall/answers.sock")' 2>/dev/null; then
  echo "A PERSON CAN SEND RESOLVER ANSWERS"; exit 1
fi
echo "METRIC: a person without root reads the status and cannot feed the monitor"
"#;

const QUIET: &str = r#"
if out=$(sudo -u ibxuser ibexctl --json plugins enable system.audit 2>&1 </dev/null); then
  echo "A CHANGE WENT THROUGH WITHOUT A PASSWORD"; exit 1
fi
echo "$out" | grep -q 'AuthenticationRequired' || { echo "EXPECTED AuthenticationRequired, GOT: $out"; exit 1; }
echo "$out" | grep -q '"interactive_possible": true' || { echo "EXPECTED interactive_possible true: $out"; exit 1; }
echo "METRIC: without the flag a change answers AuthenticationRequired (interactive possible)"
"#;

const AGENT_OK: &str = r#"
out=$(python3 /tmp/ibx-drive.py agent-ok ibexctl --json plugins enable system.audit 2>/tmp/agent.log) || {
  echo "THE AUTHENTICATED CHANGE FAILED: $out"; cat /tmp/agent.log; exit 1;
}
grep -q 'AUTHENTICATING FOR com.ibexwall.plugins.manage' /tmp/agent.log || { echo "THE AGENT WAS NOT ASKED"; cat /tmp/agent.log; exit 1; }
sudo ibexctl plugins list | grep -Eq '^system\.audit +on' || { echo "THE PLUGIN IS NOT ON"; sudo ibexctl plugins list; exit 1; }
echo "METRIC: the agent asked for the password and the change went through"
"#;

const AGENT_WRONG: &str = r#"
if out=$(python3 /tmp/ibx-drive.py agent-wrong ibexctl --json plugins disable system.audit 2>/tmp/agent.log); then
  echo "A WRONG PASSWORD WAS ACCEPTED: $out"; exit 1
fi
echo "$out" | grep -q 'PermissionDenied' || { echo "EXPECTED PermissionDenied, GOT: $out"; cat /tmp/agent.log; exit 1; }
sudo ibexctl plugins list | grep -Eq '^system\.audit +on' || { echo "THE REFUSED CHANGE HAPPENED"; exit 1; }
echo "METRIC: a wrong password is a refusal and changes nothing"
"#;

const NO_AGENT: &str = r#"
if out=$(python3 /tmp/ibx-drive.py no-agent ibexctl --json plugins disable system.audit 2>/dev/null); then
  echo "A CHANGE WENT THROUGH WITH NO AGENT: $out"; exit 1
fi
echo "$out" | grep -q 'AuthenticationRequired' || { echo "EXPECTED AuthenticationRequired, GOT: $out"; exit 1; }
echo "$out" | grep -q '"interactive_possible": false' || { echo "EXPECTED interactive_possible false: $out"; exit 1; }
sudo rm -f /etc/polkit-1/rules.d/00-ibexwall-test.rules
echo "METRIC: with no agent a change says no dialog could be shown"
"#;

/// The administrators group: shipped empty; a member changes IbexWall
/// without a password, and leaving the group takes that away.
const ADMINS: &str = r#"
getent group ibexwall-admins >/dev/null || { echo "NO ibexwall-admins GROUP"; exit 1; }
[ -z "$(getent group ibexwall-admins | cut -d: -f4)" ] || { echo "THE GROUP IS NOT EMPTY"; exit 1; }
sudo gpasswd -a ibxuser ibexwall-admins >/dev/null
out=$(sudo -u ibxuser ibexctl --json plugins disable system.audit 2>&1 </dev/null) || {
  echo "A MEMBER WAS REFUSED: $out"; sudo gpasswd -d ibxuser ibexwall-admins >/dev/null; exit 1;
}
sudo gpasswd -d ibxuser ibexwall-admins >/dev/null
sudo ibexctl plugins list | grep -Eq '^system\.audit +off' || { echo "THE CHANGE DID NOT HAPPEN"; exit 1; }
if sudo -u ibxuser ibexctl --json plugins enable system.audit </dev/null >/dev/null 2>&1; then
  echo "A FORMER MEMBER STILL CHANGES WITHOUT A PASSWORD"; exit 1
fi
echo "METRIC: ibexwall-admins ships empty; a member changes without a password, and no longer once removed"
"#;

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== desktop: stage ==");
    let input = stage_and_pack(workspace)?;
    println!("== desktop: provision ==");
    vm.ssh(install)
        .context("installing python3 and polkit in the VM")?;
    pipe_file(vm, &input, "cat > /tmp/ibx-input.tar.gz")?;
    pipe_data(vm, DRIVER, "cat > /tmp/ibx-drive.py")?;

    let mut failures = 0;
    macro_rules! scenario {
        ($name:expr, $body:expr) => {
            if !run_script(vm, $name, &[LIB, $body].concat()) {
                failures += 1;
            }
        };
    }
    scenario!("d0 the packages build on this distribution", BUILD);
    scenario!("d1 the packages install", INSTALL);
    scenario!("d2 a fresh install is clean", FRESH);
    scenario!("d3 a person without root can read", PERSON);
    scenario!(
        "d4 a change without the flag asks for authentication",
        QUIET
    );
    scenario!("d5 the agent asks and the change goes through", AGENT_OK);
    scenario!("d6 a wrong password is a refusal", AGENT_WRONG);
    scenario!("d7 no agent, no dialog", NO_AGENT);
    scenario!("d8 the administrators group", ADMINS);

    if failures == 0 {
        println!("PASS: desktop suite (all scenarios)");
        Ok(())
    } else {
        bail!("{failures} desktop scenario(s) failed")
    }
}
