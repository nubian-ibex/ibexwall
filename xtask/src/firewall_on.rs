// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `firewall-on` VM phase (ADR-0046): an installed firewall manager
//! that is off is turned on through IbexWall, over SSH, without losing
//! the session; a rollback turns it off again; and a change nobody keeps
//! undoes itself when the confirm timeout runs out. Every scenario after
//! the first opens a new SSH connection, so a firewall that cut SSH would
//! fail them all.

use std::path::Path;

use anyhow::{Context, Result, bail};

use super::f1::{pipe_file, run_script};
use super::f11b::{BUILD, INSTALL, LIB, stage_and_pack};
use super::vm::Vm;

const COMMON: &str = r#"
case $FAM in
deb) MGR=ufw ;;
*) MGR=firewalld ;;
esac
is_on() {
  case $MGR in
  ufw) sudo ufw status | grep -q 'Status: active' ;;
  firewalld) sudo firewall-cmd --state 2>/dev/null | grep -q running ;;
  esac
}
id_of() { python3 -c 'import json,sys;d=json.JSONDecoder().raw_decode(sys.stdin.read())[0];t=d.get("plan") or d.get("transaction");print(t["id"] if isinstance(t,dict) else t)'; }
plan_on() {
  sudo ibexctl plan net.firewall --set enable_manager=true --json 2>&1 | tee /tmp/plan.out | id_of
}
"#;

/// The manager installed and off, the plugin on.
const PREPARE: &str = r#"
case $MGR in
ufw)
  command -v ufw >/dev/null || sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq ufw >/dev/null
  sudo ufw --force disable >/dev/null
  ;;
firewalld)
  case $FAM in
  rpm) sudo dnf install -y -q firewalld >/dev/null ;;
  arch) sudo pacman -S --noconfirm --needed firewalld >/dev/null ;;
  esac
  sudo systemctl disable --now firewalld >/dev/null 2>&1 || true
  ;;
esac
sudo systemctl restart ibexwalld
sleep 2
sudo ibexctl --no-ask-password plugins enable net.firewall >/dev/null
if is_on; then echo "THE FIREWALL WAS ON BEFORE THE TEST"; exit 1; fi
sudo ibexctl firewall status | head -3
echo "METRIC: $MGR installed and off, net.firewall on"
"#;

const TURN_ON: &str = r#"
if sudo ibexctl plan net.firewall --set allow=8080/tcp --json >/dev/null 2>&1; then
  echo "A PLAN WENT THROUGH WHILE THE MANAGER IS OFF"; exit 1
fi
P=$(plan_on); case "$P" in plan-*) ;; *) echo "PLAN FAILED"; cat /tmp/plan.out; exit 1 ;; esac
# apply exits non-zero while a change waits to be kept.
OUT=$(sudo ibexctl apply "$P" --confirm-timeout 300 --json 2>&1 || true)
TX=$(echo "$OUT" | id_of); case "$TX" in tx-*) ;; *) echo "APPLY FAILED: $OUT"; exit 1 ;; esac
if echo "$OUT" | grep -q pending_confirm; then sudo ibexctl confirm "$TX" >/dev/null; fi
is_on || { echo "THE FIREWALL IS NOT ON"; sudo ibexctl firewall status; exit 1; }
case $MGR in
ufw) sudo ufw status | grep -Eq '^22/tcp +ALLOW' || { echo "SSH IS NOT ALLOWED"; sudo ufw status; exit 1; } ;;
firewalld) sudo firewall-cmd --list-ports | grep -q '22/tcp' || { echo "SSH IS NOT ALLOWED"; sudo firewall-cmd --list-all; exit 1; } ;;
esac
echo "$TX" > /tmp/fw-tx
echo "METRIC: $MGR turned on through IbexWall, 22/tcp kept"
"#;

const STILL_HERE: &str = r#"
is_on || { echo "THE FIREWALL WENT OFF BY ITSELF"; exit 1; }
echo "METRIC: a new SSH connection reaches the machine with $MGR on"
"#;

const ROLL_BACK: &str = r#"
sudo ibexctl rollback "$(cat /tmp/fw-tx)" --json >/tmp/rb.out 2>&1 || {
  echo "THE ROLLBACK FAILED"; cat /tmp/rb.out
  sudo journalctl -b --no-pager -o cat | grep -A3 -i 'rollback' | tail -20
  exit 1
}
if is_on; then echo "STILL ON AFTER THE ROLLBACK"; exit 1; fi
if [ $MGR = firewalld ] && systemctl is-enabled firewalld 2>/dev/null | grep -qx enabled; then
  echo "FIREWALLD STAYS ENABLED AFTER THE ROLLBACK"; exit 1
fi
echo "METRIC: the rollback turned $MGR off again"
"#;

const TIMEOUT: &str = r#"
P=$(plan_on); case "$P" in plan-*) ;; *) echo "PLAN FAILED"; cat /tmp/plan.out; exit 1 ;; esac
OUT=$(sudo ibexctl apply "$P" --confirm-timeout 20 --json 2>&1 || true)
echo "$OUT" | grep -q pending_confirm || { echo "NO CONFIRMATION WAS ASKED: $OUT"; exit 1; }
is_on || { echo "THE FIREWALL IS NOT ON WHILE WAITING"; exit 1; }
for _ in $(seq 1 30); do is_on || break; sleep 2; done
if is_on; then echo "THE UNKEPT CHANGE DID NOT UNDO ITSELF"; exit 1; fi
echo "METRIC: a change nobody kept turned $MGR off again after the timeout"
"#;

/// A port inside a range the manager already allows is not a change: the
/// plan says so instead of failing its check and rolling back.
const RANGE: &str = r#"
P=$(plan_on); case "$P" in plan-*) ;; *) echo "PLAN FAILED"; cat /tmp/plan.out; exit 1 ;; esac
OUT=$(sudo ibexctl apply "$P" --confirm-timeout 300 --json 2>&1 || true)
TX=$(echo "$OUT" | id_of)
if echo "$OUT" | grep -q pending_confirm; then sudo ibexctl confirm "$TX" >/dev/null; fi
case $MGR in
ufw) sudo ufw allow 2000:3000/tcp >/dev/null ;;
firewalld) sudo firewall-cmd -q --permanent --add-port=2000-3000/tcp ;;
esac
OUT=$(sudo ibexctl plan net.firewall --set allow=2500/tcp --json 2>&1 || true)
echo "$OUT" | grep -q 'already allowed by' || { echo "EXPECTED 'already allowed by': $OUT"; exit 1; }
echo "$OUT" | grep -q 'InvalidArgument' || { echo "EXPECTED InvalidArgument: $OUT"; exit 1; }
case $MGR in
ufw) sudo ufw delete allow 2000:3000/tcp >/dev/null ;;
firewalld) sudo firewall-cmd -q --permanent --remove-port=2000-3000/tcp ;;
esac
sudo ibexctl rollback "$TX" --json >/dev/null
echo "METRIC: a port inside an allowed range is reported as already allowed"
"#;

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== firewall-on: stage ==");
    let input = stage_and_pack(workspace)?;
    println!("== firewall-on: provision ==");
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
    scenario!("w0 the packages build on this distribution", BUILD);
    scenario!("w1 the packages install", INSTALL);
    scenario!("w2 the manager is installed and off", PREPARE);
    scenario!("w3 IbexWall turns it on, keeping SSH", TURN_ON);
    scenario!("w4 a new SSH connection still gets in", STILL_HERE);
    scenario!("w5 a rollback turns it off again", ROLL_BACK);
    scenario!("w6 a change nobody keeps undoes itself", TIMEOUT);
    scenario!("w7 a port a range already allows", RANGE);

    if failures == 0 {
        println!("PASS: firewall-on suite (all scenarios)");
        Ok(())
    } else {
        bail!("{failures} firewall-on scenario(s) failed")
    }
}
