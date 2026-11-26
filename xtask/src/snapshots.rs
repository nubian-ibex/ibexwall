// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `--phase snapshots` (v0.6, ADR-0050): what snapper does on each guest,
//! run the way IbexWall's executor would run it.

use std::path::Path;

use anyhow::{Result, bail};

use super::f1::run_script;
use super::vm::Vm;

/// The sandbox of `ibexwall-exec`'s transient unit (ibexwall-sys).
const LIB: &str = r#"
set -e
sandboxed() {
  sudo systemd-run --quiet --collect --wait --pipe -p Type=oneshot \
    -p NoNewPrivileges=yes -p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes \
    -p SystemCallFilter=@system-service -p 'RestrictAddressFamilies=AF_UNIX AF_NETLINK' -- "$@"
}
fstype() { findmnt -no FSTYPE /; }
"#;

const FILESYSTEM: &str = r#"
echo "METRIC: $(. /etc/os-release; echo $ID $VERSION_ID): / is $(fstype) ($(findmnt -no OPTIONS / | tr ',' '\n' | grep -E '^subvol=' || echo no subvolume))"
"#;

const CONFIGURE: &str = r#"
[ "$(fstype)" = btrfs ] || { echo "METRIC: not btrfs: nothing to configure here"; exit 0; }
if command -v dnf >/dev/null; then sudo dnf install -y -q snapper >/tmp/snapper.log 2>&1
elif command -v pacman >/dev/null; then sudo pacman -Sy --noconfirm --needed snapper >/tmp/snapper.log 2>&1
else sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq snapper >/tmp/snapper.log 2>&1
fi || { tail -20 /tmp/snapper.log; exit 1; }
echo "METRIC: $(snapper --version | head -1)"
echo "METRIC: configs before: $(sudo snapper --jsonout list-configs | tr -d ' \n')"
sudo snapper -c root create-config /
echo "METRIC: configs after: $(sudo snapper --jsonout list-configs | tr -d ' \n')"
"#;

const PAIR: &str = r#"
[ "$(fstype)" = btrfs ] || exit 0
PRE=$(sandboxed /usr/bin/snapper -c root create --type pre --print-number --cleanup-algorithm number --description "IbexWall change tx-spike" --userdata ibexwall_tx=tx-spike)
echo marker | sudo tee /etc/ibexwall-spike >/dev/null
POST=$(sandboxed /usr/bin/snapper -c root create --type post --pre-number "$PRE" --print-number --cleanup-algorithm number --description "IbexWall change tx-spike" --userdata ibexwall_tx=tx-spike)
echo "METRIC: sandboxed pair: pre $PRE post $POST"
sudo snapper -c root status "$PRE..$POST" | grep -q /etc/ibexwall-spike || { echo "THE PAIR DOES NOT SEE THE CHANGE"; sudo snapper -c root status "$PRE..$POST" | head; exit 1; }
sandboxed /usr/bin/snapper --jsonout -c root list --columns number,type,pre-number,cleanup,userdata --disable-used-space | tr -d ' \n' | sed 's/^/METRIC: list: /'
echo
sudo rm -f /etc/ibexwall-spike
"#;

const BROKEN: &str = r#"
[ "$(fstype)" = btrfs ] || exit 0
sudo systemctl mask --now snapperd.service >/dev/null 2>&1
set +e
OUT=$(sandboxed /usr/bin/snapper -c root create --type pre --print-number --description x 2>&1); RC=$?
set -e
sudo systemctl unmask snapperd.service >/dev/null 2>&1
echo "METRIC: with snapperd masked: exit $RC: $(echo "$OUT" | head -2 | tr '\n' ' ')"
[ "$RC" != 0 ] || { echo "A BROKEN SNAPPER REPORTED SUCCESS"; exit 1; }
set +e
OUT=$(sandboxed /usr/bin/snapper -c nothere create --type pre --print-number 2>&1); RC=$?
set -e
echo "METRIC: unknown config: exit $RC: $(echo "$OUT" | head -1)"
"#;

const REFUSALS: &str = r#"
sleep 3
N=$(sudo journalctl -b --no-pager -o cat | grep -E 'apparmor="DENIED"|avc: +denied' | grep -ci snap || true)
echo "METRIC: refusals naming snapper since boot: $N"
sudo journalctl -b --no-pager -o cat | grep -E 'apparmor="DENIED"|avc: +denied' | grep -i snap | head -5 | cut -c1-250 | sed 's/^/METRIC: /'
"#;

pub fn run(vm: &Vm, _workspace: &Path) -> Result<()> {
    println!("== snapshots ==");
    let mut failures = 0;
    for (name, body) in [
        ("n0 the root file system", FILESYSTEM),
        ("n1 snapper installs and takes a root config", CONFIGURE),
        ("n2 a pre/post pair from the executor's sandbox", PAIR),
        ("n3 a broken snapper fails with a reason", BROKEN),
        ("n4 nothing was refused", REFUSALS),
    ] {
        if !run_script(vm, name, &[LIB, body].concat()) {
            failures += 1;
        }
    }
    if failures == 0 {
        println!("PASS: snapshots suite (all scenarios)");
        Ok(())
    } else {
        bail!("{failures} snapshots scenario(s) failed")
    }
}
