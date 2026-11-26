// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `snapshots` VM phase (ADR-0050): the installed daemon asks a real
//! snapper for a pair around a risky change, changes nothing when it cannot,
//! and never touches what snapper holds. On a guest whose root is not btrfs
//! it only checks that the switch is refused with a reason.

use std::path::Path;

use anyhow::{Context, Result, bail};

use super::f1::{pipe_file, run_script};
use super::f11b::{BUILD, INSTALL, LIB, stage_and_pack};
use super::vm::Vm;

const COMMON: &str = r#"
btrfs_root() { [ "$(findmnt -no FSTYPE /)" = btrfs ]; }
field() { python3 -c 'import json,sys;t=sys.stdin.read();d=json.JSONDecoder().raw_decode(t[t.find("{"):])[0]
for k in sys.argv[1].split("."): d=d[k]
print(d)' "$1"; }
# Plans a sysctl change; a `net.` key carries the network risk flag.
plan_sysctl() { sudo ibexctl plan system.sysctl --set "keys={\"$1\":\"$2\"}" --json 2>&1 | tee /tmp/plan.out; }
snapshots() { sudo snapper --no-headers -c root list --columns number --disable-used-space | tr -d ' ' | grep -v '^0$' | wc -l; }
"#;

const REFUSED: &str = r#"
sudo ibexctl plugins enable system.sysctl >/dev/null
if sudo ibexctl snapshots on >/tmp/on.out 2>&1; then echo "TURNED ON WITHOUT SNAPPER"; cat /tmp/on.out; exit 1; fi
grep -q 'snapper is not installed' /tmp/on.out || { echo "NO REASON GIVEN:"; cat /tmp/on.out; exit 1; }
sudo ibexctl snapshots status | grep -q '^system snapshots: off' || { echo "NOT OFF"; exit 1; }
echo "METRIC: without snapper the switch is refused: $(grep -o 'snapper is not installed' /tmp/on.out)"
"#;

const CONFIGURE: &str = r#"
btrfs_root || { echo "METRIC: / is not btrfs: the rest does not apply"; exit 0; }
case $FAM in
rpm) sudo dnf install -y -q snapper >/tmp/snapper.log 2>&1 ;;
arch) sudo pacman -S --noconfirm --needed snapper >/tmp/snapper.log 2>&1 ;;
deb) sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq snapper >/tmp/snapper.log 2>&1 ;;
esac || { tail -20 /tmp/snapper.log; exit 1; }
if sudo ibexctl snapshots on >/tmp/on.out 2>&1; then echo "TURNED ON WITHOUT A CONFIGURATION"; exit 1; fi
grep -q 'configuration for /' /tmp/on.out || { echo "NO REASON GIVEN:"; cat /tmp/on.out; sudo journalctl -b --no-pager -o cat | grep -iE 'avc|denied|transient|dbus|snapper|ibexwall' | tail -25 | cut -c1-300; exit 1; }
sudo snapper -c root create-config /
sudo ibexctl snapshots on >/tmp/on.out 2>&1 || { echo "NOT TURNED ON:"; cat /tmp/on.out; sudo journalctl -b --no-pager -o cat | grep -iE 'avc|denied|transient|dbus|snapper|ibexwall' | tail -25 | cut -c1-300; exit 1; }
echo "METRIC: $(tail -1 /tmp/on.out) with $(snapper --version | head -1)"
"#;

const CALM: &str = r#"
btrfs_root || exit 0
N=$(snapshots)
P=$(plan_sysctl kernel.kptr_restrict 2)
[ "$(echo "$P" | field plan.system_snapshot)" = False ] || { echo "A CALM PLAN PROMISES A SNAPSHOT: $P"; exit 1; }
sudo ibexctl apply "$(echo "$P" | field plan.id)" >/dev/null 2>&1 || { echo "APPLY FAILED"; exit 1; }
[ "$(snapshots)" = "$N" ] || { echo "A CALM CHANGE TOOK A SNAPSHOT"; sudo snapper list; exit 1; }
echo "METRIC: a change without risk takes no snapshot"
"#;

const PAIR: &str = r#"
btrfs_root || exit 0
sudo sysctl -w net.ipv4.tcp_rfc1337=0 >/dev/null
N=$(snapshots)
P=$(plan_sysctl net.ipv4.tcp_rfc1337 1)
[ "$(echo "$P" | field plan.system_snapshot)" = True ] || { echo "A RISKY PLAN PROMISES NOTHING: $P"; exit 1; }
# Exit status 5: the change waits to be kept.
OUT=$(sudo ibexctl apply "$(echo "$P" | field plan.id)" --confirm-timeout 300 --json 2>/tmp/apply.err || true)
PRE=$(echo "$OUT" | field system_snapshot.pre) || { echo "NO PAIR: $OUT"; cat /tmp/apply.err; sudo journalctl -u ibexwalld -n 15 --no-pager | cut -c1-240; exit 1; }
POST=$(echo "$OUT" | field system_snapshot.post)
TX=$(echo "$OUT" | field transaction.id)
sudo ibexctl confirm "$TX" >/dev/null
[ "$(snapshots)" = $((N + 2)) ] || { echo "NOT TWO NEW SNAPSHOTS"; sudo snapper list; exit 1; }
sudo snapper --jsonout -c root list --columns number,type,pre-number,cleanup,userdata --disable-used-space | python3 -c '
import json,sys
pre,post,tx=int(sys.argv[1]),int(sys.argv[2]),sys.argv[3]
rows={r["number"]:r for r in json.load(sys.stdin)["root"]}
assert rows[pre]["type"]=="pre" and rows[post]["type"]=="post" and rows[post]["pre-number"]==pre, rows
assert all(rows[n]["cleanup"]=="number" and rows[n]["userdata"]=={"ibexwall_tx":tx} for n in (pre,post)), rows
' "$PRE" "$POST" "$TX"
# The first snapshot holds the machine as it was, with the settings file.
sudo test -f "/.snapshots/$PRE/snapshot/etc/ibexwall/state-export.json" || { echo "THE SETTINGS FILE IS NOT IN THE SNAPSHOT"; exit 1; }
sudo snapper -c root status "$PRE..$POST" | grep -q '/etc/sysctl.d/70-ibexwall-sysctl.conf' || { echo "THE PAIR DOES NOT SEE THE CHANGE"; sudo snapper -c root status "$PRE..$POST" | head; exit 1; }
sudo ibexctl history | grep "$TX" | grep -q "snapshot #$PRE-#$POST" || { echo "HISTORY DOES NOT NAME THEM"; sudo ibexctl history; exit 1; }
echo "$PRE $POST" > /tmp/pair
echo "METRIC: pre $PRE and post $POST around $TX, named in History"
"#;

const BROKEN: &str = r#"
btrfs_root || exit 0
sudo sysctl -w net.ipv4.tcp_rfc1337=0 >/dev/null
sudo systemctl mask --now snapperd.service >/dev/null 2>&1
trap 'sudo systemctl unmask snapperd.service >/dev/null 2>&1' EXIT
P=$(plan_sysctl net.ipv4.tcp_rfc1337 1)
if sudo ibexctl apply "$(echo "$P" | field plan.id)" >/tmp/apply.out 2>&1; then echo "APPLIED WITH A BROKEN SNAPPER"; exit 1; fi
grep -q 'SnapshotFailed' /tmp/apply.out && grep -q 'nothing was changed' /tmp/apply.out || { echo "THE REFUSAL DOES NOT SAY WHY:"; cat /tmp/apply.out; exit 1; }
[ "$(cat /proc/sys/net/ipv4/tcp_rfc1337)" = 0 ] || { echo "SOMETHING CHANGED"; exit 1; }
# The way out works with snapper still broken.
sudo ibexctl snapshots off >/dev/null || { echo "CANNOT TURN OFF"; exit 1; }
P=$(plan_sysctl net.ipv4.tcp_rfc1337 1)
sudo ibexctl apply "$(echo "$P" | field plan.id)" --confirm-timeout 300 >/dev/null 2>&1 || [ $? = 5 ] || { echo "CANNOT APPLY WITH SNAPSHOTS OFF"; exit 1; }
echo "METRIC: a broken snapper stops the apply with a reason; turning the switch off lets it through"
"#;

const REMOVE: &str = r#"
btrfs_root || exit 0
N=$(snapshots)
CONF=$(sudo sha256sum /etc/snapper/configs/root)
case $FAM in
rpm) sudo dnf remove -y -q ibexwall ibexwall-desktop ibexwall-mcp >/tmp/remove.log 2>&1 ;;
arch) sudo pacman -Rns --noconfirm ibexwall-mcp ibexwall-desktop ibexwall >/tmp/remove.log 2>&1 ;;
deb) sudo DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq ibexwall ibexwall-desktop ibexwall-mcp >/tmp/remove.log 2>&1 ;;
esac || { tail -20 /tmp/remove.log; exit 1; }
[ "$(snapshots)" = "$N" ] || { echo "SNAPSHOTS CHANGED ON REMOVAL"; sudo snapper list; exit 1; }
[ "$(sudo sha256sum /etc/snapper/configs/root)" = "$CONF" ] || { echo "THE SNAPPER CONFIGURATION CHANGED"; exit 1; }
echo "METRIC: removal keeps the person's snapshots and configuration"
"#;

const REFUSALS: &str = r#"
sleep 3
FOUND=$(sudo journalctl -b --no-pager -o cat | grep -E 'apparmor="DENIED"|avc: +denied' | grep ibexwall | head -5 || true)
[ -z "$FOUND" ] || { echo "REFUSED:"; echo "$FOUND" | cut -c1-300; exit 1; }
echo "METRIC: nothing naming IbexWall was refused"
"#;

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== snapshots: stage ==");
    let input = stage_and_pack(workspace)?;
    println!("== snapshots: provision ==");
    vm.ssh(install)
        .context("installing python3 and polkit in the VM")?;
    pipe_file(vm, &input, "cat > /tmp/ibx-input.tar.gz")?;

    let mut failures = 0;
    macro_rules! scenario {
        ($name:expr, $body:expr) => {
            if !run_script(vm, $name, &[LIB, COMMON, $body].concat()) {
                failures += 1;
            }
        };
    }
    scenario!("n0 the packages build on this distribution", BUILD);
    scenario!("n1 the packages install", INSTALL);
    scenario!("n2 without snapper the switch is refused", REFUSED);
    scenario!(
        "n3 snapper with a root configuration turns it on",
        CONFIGURE
    );
    scenario!("n4 a change without risk takes no snapshot", CALM);
    scenario!("n5 a risky change is surrounded by a pair", PAIR);
    scenario!("n6 a broken snapper stops the apply", BROKEN);
    scenario!("n7 removal leaves snapper alone", REMOVE);
    scenario!("n8 nothing was refused", REFUSALS);

    if failures == 0 {
        println!("PASS: snapshots suite (all scenarios)");
        Ok(())
    } else {
        bail!("{failures} snapshots scenario(s) failed")
    }
}
