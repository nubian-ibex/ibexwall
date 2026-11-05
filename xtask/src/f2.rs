// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F2 VM phase: the real check plugins (system.posture, system.ports)
//! running through the daemon on each distro, plus the API shape the UI
//! consumes (posture with results, plugin manifest for permissions).

use std::path::Path;

use anyhow::Result;

use super::f1::{install_plugin, provision, run_script};
use super::vm::{Vm, run_capture};

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== f2: build ==");
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
            "ibexwall-exec",
            "-p",
            "ibexwall-plugin-echo",
            "-p",
            "ibexwall-plugins",
        ],
        None,
        "building release binaries",
    )?;
    crate::devkey::run()?;
    provision(vm, workspace, install)?;
    // The check plugins are additional to dev.echo.
    install_plugin(vm, workspace, "system.posture")?;
    install_plugin(vm, workspace, "system.ports")?;
    super::f1::start_daemon(vm)?;

    let mut failures = 0;
    macro_rules! scenario {
        ($name:expr, $script:expr) => {
            if !run_script(vm, $name, $script) {
                failures += 1;
            }
        };
    }

    scenario!(
        "p0 enable the check plugins",
        r#"
set -e
sudo ibexctl plugins enable system.posture
sudo ibexctl plugins enable system.ports
sudo ibexctl plugins list --json | grep -c '"id": "system.posture"'
"#
    );

    // check exits 10 when findings exist (by design).
    scenario!(
        "p1 checks produce findings",
        r#"
sudo ibexctl check --json >/tmp/p1.out 2>&1; RC=$?
if [ "$RC" -ne 10 ] && [ "$RC" -ne 0 ]; then
  head -c 400 /tmp/p1.out
  sudo journalctl -b --no-pager | grep -E "ibexwall-plugin-[a-z-]+\.service.*(Failed|failed)" | tail -6
  exit 1
fi
sudo ibexctl findings --json | python3 -c '
import json,sys
findings=json.load(sys.stdin)["findings"]
assert findings, "no findings reported"
ids={f["id"] for f in findings}
# Every distro honestly fails firewall (no firewall in cloud images) and
# reports ports (ssh listens on all interfaces).
assert "posture.firewall" in ids, ids
assert any(i.startswith("ports.") for i in ids), ids
print("findings ok:", len(findings))'
"#
    );

    // M3 (F10): a plugin is not a child of the daemon. Its socket unit starts
    // it in its own service, as a dynamic user, with only the capabilities
    // its manifest declares.
    scenario!(
        "p3 each plugin runs in its own sandboxed unit, not as a child of the daemon",
        r#"
sudo ibexctl check --json >/dev/null 2>&1 || true
for u in ibexwall-plugin-posture ibexwall-plugin-ports; do
  systemctl is-active --quiet $u.service || { echo "$u IS NOT RUNNING AS ITS OWN UNIT"; exit 1; }
  P=$(systemctl show $u.service -p MainPID --value)
  [ "$P" -gt 0 ] || { echo "NO PID FOR $u"; exit 1; }
  [ "$(ps -o ppid= -p $P | tr -d ' ')" = 1 ] || { echo "$u IS NOT A CHILD OF SYSTEMD"; exit 1; }
  [ "$(ps -o user= -p $P | tr -d ' ')" != root ] || { echo "$u RUNS AS ROOT"; exit 1; }
  [ "$(systemctl show $u.service -p DynamicUser --value)" = yes ] || { echo "$u IS NOT A DYNAMIC USER"; exit 1; }
  [ "$(systemctl show $u.service -p NoNewPrivileges --value)" = yes ] || { echo "$u CAN GAIN PRIVILEGES"; exit 1; }
  echo "METRIC: $u: $(systemd-analyze security $u.service --no-pager 2>&1 | tail -1)"
done
DAEMON=$(systemctl show ibexwalld.service -p MainPID --value)
[ -z "$(pgrep -P $DAEMON)" ] || { echo "THE DAEMON HAS CHILD PROCESSES: $(pgrep -P $DAEMON | tr '\n' ' ')"; exit 1; }
echo "METRIC: the daemon has no plugin children; plugins are units under systemd"
"#
    );

    // The UI renders the score and every outcome from GetPosture, and
    // permissions from GetPlugin. Drive the socket directly (the same
    // bytes the Tauri commands forward).
    scenario!(
        "p2 posture carries results and manifest for the UI",
        r#"
set -e
sudo python3 - <<'EOF'
import json, socket
s=socket.socket(socket.AF_UNIX); s.connect("/run/ibexwall/core.sock")
def call(method, params=None):
    s.sendall((json.dumps({"method":method,"parameters":params or {}})+"\0").encode())
    data=b""
    while not data.endswith(b"\0"): data+=s.recv(1<<20)
    r=json.loads(data[:-1])
    assert "error" not in r, r
    return r["parameters"]
posture=call("com.ibexwall.Core.GetPosture")["posture"]
assert posture["score"] is not None, posture
results=posture["results"]
assert results, "no check results"
outcomes={r["outcome"] for r in results}
assert "not_assessed" in outcomes, outcomes
assert any(r["id"].startswith("posture.") for r in results)
assert any(r["id"].startswith("ports.") for r in results)
print("posture score:", posture["score"], "results:", len(results))
man=call("com.ibexwall.Core.GetPlugin", {"id":"system.posture"})["manifest"]
priv=man["privileges"]
assert priv["write_paths"] == [], priv
print("manifest permissions ok")
EOF
"#
    );

    if failures == 0 {
        println!("PASS: f2 phase (all scenarios)");
        Ok(())
    } else {
        anyhow::bail!("{failures} f2 scenario(s) failed")
    }
}
