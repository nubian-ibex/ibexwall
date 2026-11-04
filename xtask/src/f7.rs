// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F7 VM phase: hardening and system plugins, each with check, plan,
//! apply and rollback on a real machine.

use std::path::Path;

use anyhow::Result;

use super::f1::{install_plugin, provision, run_script, start_daemon};
use super::vm::{Vm, run_capture};

/// Reads the transaction or plan id out of `ibexctl --json` output.
const JSON_ID: &str = "python3 -c 'import json,sys;d=json.JSONDecoder().raw_decode(sys.stdin.read())[0];t=d.get(\"plan\") or d.get(\"transaction\");print(t[\"id\"] if isinstance(t,dict) else t)'";

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== f7: build ==");
    run_capture(
        "cargo",
        [
            "build",
            "--release",
            "-p",
            "ibexwall-plugin-sysctl",
            "-p",
            "ibexwall-exec",
            "-p",
            "ibexwall-cli",
            "-p",
            "ibexwall-core",
            "--bins",
        ],
        None,
        "building the plugins",
    )?;
    crate::devkey::run()?;
    provision(vm, workspace, install)?;
    install_plugin(vm, workspace, "system.sysctl")?;
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
        "m1 system.sysctl: check reports, apply hardens, rollback restores",
        &format!(
            r#"
set -e
DROP_IN=/etc/sysctl.d/70-ibexwall-sysctl.conf

# Plugins start disabled (the core never runs what nobody turned on).
sudo ibexctl plugins enable system.sysctl >/dev/null

# A divergent prior state, so the change has something to do.
sudo sysctl -w kernel.kptr_restrict=1 >/dev/null
sudo sysctl -w kernel.dmesg_restrict=0 >/dev/null
K1=$(cat /proc/sys/kernel/kptr_restrict); D1=$(cat /proc/sys/kernel/dmesg_restrict)
[ "$K1" = 1 ] && [ "$D1" = 0 ] || {{ echo "CANNOT SET THE PRIOR STATE: $K1 $D1"; exit 1; }}

# The distro's own files must not change.
FILES=$(sudo ls /etc/sysctl.d 2>/dev/null)
digest() {{ sudo sh -c 'cat /etc/sysctl.d/* 2>/dev/null | sha256sum'; }}
BEFORE=$(digest)

# The check sees the gap, with the live and the reference values.
sudo ibexctl check system.sysctl --json > /tmp/f7-check1.json || true
python3 - <<'EOF'
import json
d = json.load(open("/tmp/f7-check1.json"))
findings = d["findings"]
ours = [f for f in findings if f["id"] == "sysctl.kernel.kptr_restrict"]
assert ours, findings
assert ours[0]["args"]["current"] == "1" and ours[0]["args"]["want"] == "2", ours[0]
remediation = ours[0]["remediation"]
assert remediation and remediation["plan_template"] == "sysctl.harden", remediation
EOF

P=$(sudo ibexctl plan system.sysctl --set preset=recommended --json 2>&1 | tee /dev/stderr | {JSON_ID}) || {{ echo "PLAN FAILED"; exit 1; }}
# Network sysctls are connectivity changes: the engine asks for a confirm.
OUT=$(sudo ibexctl apply $P --confirm-timeout 300 --json 2>&1 || true)
TX=$(echo "$OUT" | {JSON_ID})
if [ -z "$TX" ]; then echo "APPLY FAILED: $OUT"; sudo journalctl -u ibexwalld -n 25 --no-pager; exit 1; fi
if echo "$OUT" | grep -q pending_confirm; then sudo ibexctl confirm "$TX" >/dev/null || {{ echo "CONFIRM FAILED"; exit 1; }}; fi

# Runtime values now, and the drop-in owns the choice for the next boot.
[ "$(cat /proc/sys/kernel/kptr_restrict)" = 2 ] || {{ echo "kptr_restrict NOT APPLIED"; exit 1; }}
[ "$(cat /proc/sys/kernel/dmesg_restrict)" = 1 ] || {{ echo "dmesg_restrict NOT APPLIED"; exit 1; }}
sudo test -f $DROP_IN || {{ echo "DROP-IN MISSING"; exit 1; }}
sudo grep -q '^kernel.kptr_restrict = 2$' $DROP_IN
sudo grep -q '^net.ipv4.tcp_syncookies = 1$' $DROP_IN
sudo grep -q '^# Managed by IbexWall' $DROP_IN
if sudo grep -qE '^(kernel.kexec_load_disabled|net.ipv4.conf.all.rp_filter|kernel.sysrq)' $DROP_IN; then
  echo "AN OPT-IN KEY WAS APPLIED BY THE DEFAULT PRESET"; exit 1
fi
echo "METRIC: applied, drop-in holds $(sudo grep -c '=' $DROP_IN) keys"

# The check agrees the gap closed.
sudo ibexctl check system.sysctl --json > /tmp/f7-check2.json || true
python3 -c 'import json,sys; d=json.load(open("/tmp/f7-check2.json")); assert not d["findings"], d["findings"]'

# Distro files untouched; only ours was added.
AFTER=$(sudo ls /etc/sysctl.d)
[ "$FILES" = "$(echo "$AFTER" | grep -v 70-ibexwall-sysctl.conf)" ] || {{ echo "FILE LIST CHANGED: $FILES vs $AFTER"; exit 1; }}

sudo ibexctl rollback "$TX" --json > /tmp/f7-rollback.json 2>/tmp/f7-rollback.err || {{ echo "ROLLBACK FAILED"; cat /tmp/f7-rollback.json /tmp/f7-rollback.err; sudo journalctl -u ibexwalld -n 10 --no-pager; sudo journalctl -u "ibexwall-exec-*" --no-pager -n 30 | tail -22; sudo systemctl list-units "ibexwall-exec*" --all --no-pager; exit 1; }}
[ "$(cat /proc/sys/kernel/kptr_restrict)" = "$K1" ] || {{ echo "kptr_restrict NOT RESTORED"; exit 1; }}
[ "$(cat /proc/sys/kernel/dmesg_restrict)" = "$D1" ] || {{ echo "dmesg_restrict NOT RESTORED"; exit 1; }}
sudo test ! -e $DROP_IN || {{ echo "DROP-IN SURVIVED THE ROLLBACK"; exit 1; }}
[ "$(digest)" = "$BEFORE" ] || {{ echo "DISTRO FILES CHANGED"; exit 1; }}
echo "METRIC: rollback restored $K1/$D1 and removed the drop-in"

# The one-way kexec lock is offered, flagged, and not applied by default.
P=$(sudo ibexctl plan system.sysctl --set include=kernel.kexec_load_disabled --json)
echo "$P" | python3 -c '
import json,sys
d = json.load(sys.stdin)
ops = d["plan"]["ops"]
assert any(op["op"] == "sysctl.set" and op["target"] == "kernel.kexec_load_disabled = 1" for op in ops), ops
'
[ "$(cat /proc/sys/kernel/kexec_load_disabled)" = 0 ] || {{ echo "KEXEC WAS APPLIED BY A PLAN"; exit 1; }}
if sudo ibexctl plan system.sysctl --set preset=maximum --json >/dev/null 2>&1; then echo "UNKNOWN PRESET ACCEPTED"; exit 1; fi
if sudo ibexctl plan system.sysctl --set keys.nope=1 --json >/dev/null 2>&1; then echo "UNKNOWN KEY ACCEPTED"; exit 1; fi
"#,
            JSON_ID = JSON_ID
        )
    );

    if failures == 0 {
        println!("PASS: f7 (all scenarios)");
        Ok(())
    } else {
        anyhow::bail!("{failures} f7 scenario(s) failed")
    }
}
