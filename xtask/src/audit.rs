// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `--phase audit`: the checks of the 2026-11-15 audit that only a real
//! machine can answer. Each scenario states the finding it covers (A-nn,
//! see planning/15-auditoria-2026-11-15.md) and leaves the machine as it
//! found it.

use std::path::Path;

use anyhow::{Context, Result, bail};

use super::f1::{pipe_file, run_script};
use super::f11b::{BUILD, INSTALL, LIB, stage_and_pack};
use super::vm::Vm;

const COMMON: &str = r#"
id_of() { python3 -c 'import json,sys;d=json.JSONDecoder().raw_decode(sys.stdin.read())[0];t=d.get("plan") or d.get("transaction");print(t["id"] if isinstance(t,dict) else t)'; }
# The change goes through and is kept; prints the transaction id.
apply_keep() {
  OUT=$(sudo ibexctl apply "$1" --confirm-timeout 300 --json 2>&1 || true)
  T=$(echo "$OUT" | id_of); case "$T" in tx-*) ;; *) echo "APPLY FAILED: $OUT" >&2; return 1 ;; esac
  if echo "$OUT" | grep -q pending_confirm; then sudo ibexctl confirm "$T" >/dev/null; fi
  echo "$T"
}
"#;

/// A-17: a truncated org.toml must not keep the daemon from starting.
const CORRUPT_CONFIG: &str = r#"
sudo install -d -m 0755 /etc/ibexwall
printf 'lock = ["net.dns.*"\n[plugins."net.fi' | sudo tee /etc/ibexwall/org.toml >/dev/null
sudo systemctl restart ibexwalld
for _ in $(seq 1 20); do sudo ibexctl status >/dev/null 2>&1 && break; sleep 1; done
out=$(sudo ibexctl status 2>&1) || { echo "THE DAEMON DID NOT START WITH A BAD org.toml"; sudo journalctl -u ibexwalld -n 15 --no-pager; sudo rm -f /etc/ibexwall/org.toml; exit 1; }
echo "$out" | grep -q 'org.toml' || { echo "THE BAD FILE IS NOT REPORTED: $out"; sudo rm -f /etc/ibexwall/org.toml; exit 1; }
sudo test -e /etc/ibexwall/org.toml || { echo "THE BAD FILE WAS REMOVED"; exit 1; }
sudo rm -f /etc/ibexwall/org.toml
sudo systemctl restart ibexwalld
for _ in $(seq 1 20); do sudo ibexctl status >/dev/null 2>&1 && break; sleep 1; done
sudo ibexctl status | grep -q 'nothing degraded' || { echo "STILL DEGRADED AFTER REMOVING THE FILE"; sudo ibexctl status; exit 1; }
echo "METRIC: a truncated org.toml is reported as degraded and does not stop the daemon"
"#;

/// A-25: the /dev/shm verdict comes from the host mount table, not from
/// the plugin's private namespace.
const SHM: &str = r#"
sudo ibexctl --no-ask-password plugins enable system.mounts >/dev/null 2>&1 || true
shm_open() { sudo ibexctl check >/dev/null 2>&1; sudo ibexctl --json findings | python3 -c 'import json,sys;print("yes" if any(f["id"]=="mounts.shm.open" for f in json.load(sys.stdin)["findings"]) else "no")'; }
orig=$(findmnt -no OPTIONS /dev/shm) || { echo "METRIC: no /dev/shm mount, nothing to check"; exit 0; }
sudo mount -o remount,noexec,nosuid,nodev /dev/shm
closed=$(shm_open)
sudo mount -o remount,exec,suid,dev /dev/shm
open=$(shm_open)
echo "METRIC: /dev/shm originally $orig; with noexec,nosuid,nodev the finding is $closed, with exec,suid,dev it is $open"
[ "$closed" = no ] || { echo "THE FINDING STAYS WHILE /dev/shm IS LOCKED DOWN (the verdict is not from the host mounts)"; exit 1; }
[ "$open" = yes ] || { echo "NO FINDING WHILE /dev/shm IS OPEN"; exit 1; }
"#;

/// A-03: password sign-in is not turned off for a machine nobody can
/// sign in to with a key; with a key, the plan also turns off
/// keyboard-interactive and the effective sshd config agrees.
const SSH_LOCKOUT: &str = r#"
command -v sshd >/dev/null || [ -x /usr/sbin/sshd ] || { echo "METRIC: no sshd on this machine"; exit 0; }
sudo ibexctl --no-ask-password plugins enable system.ssh >/dev/null 2>&1 || true
keys=$(sudo find /root /home -maxdepth 3 -name authorized_keys 2>/dev/null)
back=/tmp/ibx-keys-back; sudo rm -rf $back; sudo mkdir -p $back
restore() { for f in $keys; do [ -e "$back/$(echo $f | tr / _)" ] && sudo mv "$back/$(echo $f | tr / _)" "$f"; done; }
trap restore EXIT
for f in $keys; do sudo mv "$f" "$back/$(echo $f | tr / _)"; done
if sudo ibexctl plan system.ssh --set password_auth=false --json >/tmp/ssh-plan.out 2>&1; then
  echo "THE PLAN WENT THROUGH WITH NO AUTHORIZED KEY ON THE MACHINE"; cat /tmp/ssh-plan.out; exit 1
fi
restore; trap - EXIT
[ -z "$keys" ] && { echo "METRIC: no authorized_keys on this machine, only the refusal was checked"; exit 0; }
confirm=""
if ! sudo ibexctl plan system.ssh --set password_auth=false --json >/tmp/ssh-plan2.out 2>&1; then
  # Where AppArmor hides ~/.ssh from the plugin (Ubuntu, Debian) a machine
  # with keys looks like one without; the person then says they checked.
  if [ $FAM = deb ] && grep -q 'confirm_keys' /tmp/ssh-plan2.out; then
    confirm="--set confirm_keys=true"
    echo "NOTE: the plugin cannot see ~/.ssh under AppArmor, retrying with confirm_keys=true"
    sudo ibexctl plan system.ssh --set password_auth=false $confirm --json >/tmp/ssh-plan2.out 2>&1 || { echo "PLAN WITH confirm_keys FAILED"; cat /tmp/ssh-plan2.out; exit 1; }
  else
    echo "PLAN WITH A KEY FAILED"; cat /tmp/ssh-plan2.out; ls -la $keys; exit 1
  fi
fi
P=$(id_of </tmp/ssh-plan2.out)
before=$(sudo sshd -T 2>/dev/null | tr 'A-Z' 'a-z' | grep -E '^(passwordauthentication|kbdinteractiveauthentication) ')
TX=$(apply_keep "$P") || exit 1
eff=$(sudo sshd -T 2>/dev/null | tr 'A-Z' 'a-z')
echo "$eff" | grep -q '^passwordauthentication no' || { echo "PASSWORD AUTH IS STILL ON"; echo "$eff" | grep -i auth; sudo ibexctl rollback "$TX" --json >/dev/null; exit 1; }
echo "$eff" | grep -q '^kbdinteractiveauthentication no' || { echo "KEYBOARD-INTERACTIVE IS STILL ON"; sudo ibexctl rollback "$TX" --json >/dev/null; exit 1; }
sudo ibexctl rollback "$TX" --json >/dev/null || { echo "ROLLBACK FAILED"; exit 1; }
# Cloud images often ship with passwords already off: the undo must give
# back what was there, whatever that was.
after=$(sudo sshd -T 2>/dev/null | tr 'A-Z' 'a-z' | grep -E '^(passwordauthentication|kbdinteractiveauthentication) ')
[ "$before" = "$after" ] || { echo "THE ROLLBACK DID NOT RESTORE SSHD: before: $before after: $after"; exit 1; }
echo "METRIC: password sign-in is refused without a key, and with one it turns off password and keyboard-interactive, and the undo restores both"
"#;

/// A-01: a client that hangs up in the middle of an apply must not leave
/// the transaction stuck in `applying`.
const HANG_UP: &str = r#"
states() { sudo ibexctl --json history | python3 -c 'import json,sys;print(" ".join(x["result"] for x in json.load(sys.stdin)["entries"]))'; }
for delay in 0.05 0.15 0.4; do
  P=$(sudo ibexctl plan system.sysctl --set preset=recommended --json 2>&1 | id_of); case "$P" in plan-*) ;; *) echo "NO PLAN: $P"; exit 1 ;; esac
  sudo timeout -s KILL $delay ibexctl --no-ask-password apply "$P" --confirm-timeout 300 --json >/dev/null 2>&1 || true
  sleep 6
  now=$(states)
  echo "  after a kill at ${delay}s the states are: $now"
  case " $now " in *" applying "*) echo "A TRANSACTION IS STUCK IN applying AFTER A HANG-UP (kill at ${delay}s)"; exit 1 ;; esac
  # Put things back before the next round: undo whatever got committed or is waiting.
  for tx in $(sudo ibexctl --json history | python3 -c 'import json,sys;print(" ".join(x["transaction"] for x in json.load(sys.stdin)["entries"] if x["result"] in ("committed","pending_confirm")))'); do
    sudo ibexctl rollback "$tx" --json >/dev/null 2>&1 || true
  done
done
echo "METRIC: a client killed 50, 150 and 400 ms into an apply leaves no transaction stuck in applying"
"#;

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== audit: stage ==");
    let input = stage_and_pack(workspace)?;
    println!("== audit: provision ==");
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
    scenario!("x0 the packages build on this distribution", BUILD);
    scenario!("x1 the packages install", INSTALL);
    scenario!(
        "x2 a corrupt config file does not stop the daemon (A-17)",
        CORRUPT_CONFIG
    );
    scenario!(
        "x3 the /dev/shm verdict follows the host mounts (A-25)",
        SHM
    );
    scenario!("x4 password sign-in needs a key first (A-03)", SSH_LOCKOUT);
    scenario!(
        "x5 a hang-up mid-apply leaves nothing stuck (A-01)",
        HANG_UP
    );

    if failures == 0 {
        println!("PASS: audit suite (all scenarios)");
        Ok(())
    } else {
        bail!("{failures} audit scenario(s) failed")
    }
}
