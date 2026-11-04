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
            "ibexwall-plugin-coredump",
            "-p",
            "ibexwall-plugin-mounts",
            "-p",
            "ibexwall-plugin-ssh",
            "-p",
            "ibexwall-plugin-accounts",
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
    for id in [
        "system.sysctl",
        "system.coredump",
        "system.mounts",
        "system.ssh",
        "system.accounts",
    ] {
        install_plugin(vm, workspace, id)?;
    }
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

    // Shared by the scenarios below: plan, apply (confirming when the
    // engine asks) and print the transaction id.
    let lib = format!(
        r#"
set -e
change() {{
  PLUGIN=$1; shift
  P=$(sudo ibexctl plan "$PLUGIN" "$@" --json 2>/tmp/plan.err | {JSON_ID}) || {{ echo "PLAN FAILED: $(cat /tmp/plan.err)"; return 1; }}
  OUT=$(sudo ibexctl apply "$P" --confirm-timeout 300 --json 2>&1 || true)
  TX=$(echo "$OUT" | {JSON_ID})
  [ -n "$TX" ] || {{ echo "APPLY FAILED: $OUT"; sudo journalctl -u ibexwalld -n 20 --no-pager; return 1; }}
  if echo "$OUT" | grep -q pending_confirm; then sudo ibexctl confirm "$TX" >/dev/null || {{ echo "CONFIRM FAILED"; return 1; }}; fi
}}
findings() {{ sudo ibexctl check "$1" --json 2>/dev/null | python3 -c 'import json,sys; print(" ".join(f["id"] for f in json.load(sys.stdin)["findings"]))'; }}
"#,
        JSON_ID = JSON_ID
    );

    scenario!(
        "m2a system.coredump: stored dumps are found, turned off by a drop-in, and restored",
        &format!(
            r#"{lib}
sudo ibexctl plugins enable system.coredump >/dev/null
if ! command -v coredumpctl >/dev/null; then
  if command -v apt-get >/dev/null; then sudo apt-get update -qq; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd-coredump; fi
  sudo sysctl --system >/dev/null 2>&1 || true
fi
PIPED=no; grep -q systemd-coredump /proc/sys/kernel/core_pattern && PIPED=yes
echo "METRIC: core_pattern piped to systemd-coredump: $PIPED"
D=/etc/systemd/coredump.conf.d/70-ibexwall.conf
if [ "$PIPED" = yes ]; then
  F=$(findings system.coredump)
  echo "$F" | grep -q coredump.stored || {{ echo "NO FINDING FOR STORED DUMPS: [$F]"; exit 1; }}
fi
change system.coredump
sudo test -f $D && sudo grep -q '^Storage=none' $D || {{ echo "DROP-IN MISSING"; exit 1; }}
# systemd's own view of the merged configuration.
sudo systemd-analyze cat-config systemd/coredump.conf 2>/dev/null | grep -q '^Storage=none' || {{ echo "SYSTEMD DOES NOT SEE Storage=none"; exit 1; }}
[ -z "$(findings system.coredump)" ] || {{ echo "FINDING SURVIVED THE CHANGE"; exit 1; }}
sudo ibexctl rollback "$TX" --json >/dev/null || {{ echo "ROLLBACK FAILED"; exit 1; }}
sudo test ! -e $D || {{ echo "DROP-IN SURVIVED THE ROLLBACK"; exit 1; }}
"#
        )
    );

    scenario!(
        "m2b system.mounts: options found missing, drop-ins written for the next boot, nothing remounted, rolled back",
        &format!(
            r#"{lib}
sudo ibexctl plugins enable system.mounts >/dev/null
BEFORE=$(grep -E ' (/tmp|/dev/shm) ' /proc/mounts)
echo "METRIC: mounts: $(echo "$BEFORE" | tr '\n' ';' | cut -c1-160)"
F=$(findings system.mounts)
echo "METRIC: findings before: [$F]"
SHM_OK=$(grep ' /dev/shm ' /proc/mounts | grep -c 'noexec' || true)
if [ "$SHM_OK" = 0 ]; then echo "$F" | grep -q 'mounts.shm' || {{ echo "NO FINDING FOR /dev/shm"; exit 1; }}; fi
change system.mounts
D=/etc/systemd/system/dev-shm.mount.d/70-ibexwall.conf
sudo grep -q 'noexec' $D || {{ echo "SHM DROP-IN MISSING OR WRONG"; sudo cat $D; exit 1; }}
# Nothing is remounted now: the live table is exactly what it was.
[ "$(grep -E ' (/tmp|/dev/shm) ' /proc/mounts)" = "$BEFORE" ] || {{ echo "A LIVE MOUNT CHANGED"; exit 1; }}
[ -z "$(findings system.mounts)" ] || {{ echo "FINDINGS REMAIN AFTER THE DROP-INS: $(findings system.mounts)"; exit 1; }}
sudo ibexctl rollback "$TX" --json >/dev/null || {{ echo "ROLLBACK FAILED"; exit 1; }}
sudo test ! -e $D || {{ echo "DROP-IN SURVIVED THE ROLLBACK"; exit 1; }}
sudo test ! -e /etc/systemd/system/tmp.mount.d/70-ibexwall.conf || {{ echo "TMP DROP-IN SURVIVED"; exit 1; }}
"#
        )
    );

    scenario!(
        "m2c system.ssh: effective settings are read, a drop-in tightens them, sshd validates and keeps our session, rollback restores",
        &format!(
            r#"{lib}
sudo ibexctl plugins enable system.ssh >/dev/null
sudo test -e /run/sshd.pid || sudo systemctl start sshd 2>/dev/null || sudo systemctl start ssh
SSHD=$(command -v sshd || echo /usr/sbin/sshd)
trap 'sudo rm -f /etc/ssh/sshd_config.d/50-f7test.conf /etc/ssh/sshd_config.d/00-ibexwall.conf' EXIT
# Something to find, in a distro-style drop-in (first value wins).
sudo mkdir -p /etc/ssh/sshd_config.d
printf 'X11Forwarding yes
PermitRootLogin yes
' | sudo tee /etc/ssh/sshd_config.d/50-f7test.conf >/dev/null
sudo systemctl restart sshd 2>/dev/null || sudo systemctl restart ssh
F=$(findings system.ssh)
echo "METRIC: ssh findings: [$F]"
echo "$F" | grep -q ssh.root || {{ echo "ROOT LOGIN NOT FOUND"; exit 1; }}
echo "$F" | grep -q ssh.x11 || {{ echo "X11 NOT FOUND"; exit 1; }}
# sshd's own opinion agrees with the check before the change.
sudo $SSHD -T | grep -qi '^permitrootlogin yes' || {{ echo "SSHD DISAGREES (before): $(sudo $SSHD -T 2>&1 | grep -i -E 'permitroot|x11|error' | head -3); files: $(sudo grep -r -i -H PermitRootLogin /etc/ssh | head -5)"; exit 1; }}
change system.ssh
sudo grep -q 'PermitRootLogin prohibit-password' /etc/ssh/sshd_config.d/00-ibexwall.conf || {{ echo "DROP-IN WRONG"; exit 1; }}
[ "$(sudo stat -c '%a' /etc/ssh/sshd_config.d/00-ibexwall.conf)" = 600 ] || {{ echo "WRONG MODE"; exit 1; }}
sudo $SSHD -T | grep -Eqi '^permitrootlogin (prohibit-password|without-password)' || {{ echo "SSHD DID NOT TAKE THE CHANGE"; exit 1; }}
sudo $SSHD -T | grep -qi '^x11forwarding no' || {{ echo "X11 NOT TIGHTENED"; exit 1; }}
[ -z "$(findings system.ssh | tr ' ' '\n' | grep -E 'ssh.(root|x11)')" ] || {{ echo "FINDINGS REMAIN"; exit 1; }}
# This very session (and a new one) still works.
true
sudo ibexctl rollback "$TX" --json >/tmp/rb.json 2>&1 || {{ echo "ROLLBACK FAILED: $(cat /tmp/rb.json)"; sudo journalctl -u 'ibexwall-exec-*' -n 12 --no-pager; exit 1; }}
sudo test ! -e /etc/ssh/sshd_config.d/00-ibexwall.conf || {{ echo "DROP-IN SURVIVED"; exit 1; }}
sudo $SSHD -T | grep -qi '^permitrootlogin yes' || {{ echo "SSHD NOT BACK TO THE PRIOR STATE"; exit 1; }}
# A configuration sshd refuses never stays: invalid input is refused at plan time.
if sudo ibexctl plan system.ssh --set nosuch=1 --json >/dev/null 2>&1; then echo "UNKNOWN SETTING ACCEPTED"; exit 1; fi
"#
        )
    );

    scenario!(
        "m2d system.accounts: an empty-password account and the lockout state are reported",
        &format!(
            r#"{lib}
sudo ibexctl plugins enable system.accounts >/dev/null
trap 'sudo userdel -r f7empty >/dev/null 2>&1 || true' EXIT
sudo userdel -r f7empty >/dev/null 2>&1 || true
sudo useradd -m -s /bin/bash f7empty
sudo passwd -d f7empty >/dev/null
F=$(findings system.accounts)
echo "METRIC: accounts findings: [$F]"
echo "$F" | grep -q 'accounts.empty.f7empty' || {{ echo "EMPTY PASSWORD NOT FOUND"; exit 1; }}
echo "$F" | grep -q 'accounts.uid0' && {{ echo "A FALSE UID 0 FINDING"; exit 1; }}
sudo ibexctl check system.accounts --json | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert any(f["id"]=="accounts.empty.f7empty" and f["severity"]=="high" for f in d["findings"]), d
'
sudo userdel -r f7empty
[ -z "$(findings system.accounts | tr ' ' '\n' | grep accounts.empty)" ] || {{ echo "FINDING SURVIVED THE ACCOUNT"; exit 1; }}
"#
        )
    );

    if failures == 0 {
        println!("PASS: f7 (all scenarios)");
        Ok(())
    } else {
        anyhow::bail!("{failures} f7 scenario(s) failed")
    }
}
