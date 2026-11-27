// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `--phase audit`: the checks of the 2026-11-15 audit that only a real
//! machine can answer. Each scenario states the finding it covers (A-nn,
//! see planning/15-auditoria-2026-11-15.md) and leaves the machine as it
//! found it.

use std::path::Path;

use anyhow::{Context, Result, bail};

use super::desktop::{DRIVER, PERSON};
use super::f1::{pipe_data, pipe_file, run_script};
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
pkg() {
  case $FAM in
  rpm) sudo dnf install -y -q "$@" >/tmp/pkg.log 2>&1 ;;
  deb) sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq --no-install-recommends "$@" >/tmp/pkg.log 2>&1 ;;
  arch) sudo pacman -S --noconfirm --needed "$@" >/tmp/pkg.log 2>&1 ;;
  esac || { echo "INSTALLING $* FAILED"; tail -15 /tmp/pkg.log; return 1; }
}
enable() { for p in "$@"; do sudo ibexctl --no-ask-password plugins enable "$p" >/dev/null || return 1; done; }
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

/// A-25: every verdict about /tmp and /dev/shm matches the host's own
/// mount table (PID 1), whatever the plugin sees inside its sandbox.
const MOUNTS: &str = r#"
enable system.posture system.hardening system.mounts
cat >/var/tmp/ibx-verdicts.py <<'PY'
import json, socket, sys
host = {}
for line in open("/proc/1/mountinfo"):
    head, tail = line.split(" - ", 1)
    h, t = head.split(), tail.split()
    host[h[4]] = (t[0], set(h[5].split(",")))  # the last entry wins
def rpc(method):
    s = socket.socket(socket.AF_UNIX)
    s.connect("/run/ibexwall/core.sock")
    s.sendall(json.dumps({"method": "com.ibexwall.Core." + method, "parameters": {}}).encode() + b"\0")
    buf = b""
    while not buf.endswith(b"\0"):
        buf += s.recv(65536)
    return json.loads(buf[:-1])["parameters"]
results = {r["id"]: r["outcome"] for r in rpc("GetPosture")["posture"]["results"]}
findings = {f["id"]: f for f in rpc("ListFindings")["findings"]}
def opts(point):
    return host.get(point, (None, set()))[1]
def verdict(ok):
    return "pass" if ok else "fail"
want = {
    "posture.tmp_mount": verdict("/tmp" in host and {"nodev", "nosuid"} <= opts("/tmp")),
    "posture.shm_mount": verdict({"nodev", "nosuid"} <= opts("/dev/shm")),
    "mounts.tmp": "not_applicable" if host.get("/tmp", ("",))[0] != "tmpfs"
        else verdict({"nodev", "nosuid"} <= opts("/tmp")),
    "mounts.shm": verdict({"nodev", "nosuid", "noexec"} <= opts("/dev/shm")),
}
bad = [f"{k}: {results.get(k)} (host says {v})" for k, v in want.items() if results.get(k) != v]
applied = findings["hardening.state"]["args"]["applied"].split(",")
if ("mounts.tmp-noexec" in applied) != ("noexec" in opts("/tmp")):
    bad.append(f"hardening mounts.tmp-noexec applied={'mounts.tmp-noexec' in applied}")
separate = findings.get("posture.tmp_mount", {}).get("args", {}).get("separate")
if separate is not None and (separate == "yes") != ("/tmp" in host):
    bad.append(f"posture.tmp_mount separate={separate}")
def show(point):
    fstype, options = host.get(point, ("not a mount", set()))
    return f"{fstype} {','.join(sorted(options))}"
print(f"host /tmp: {show('/tmp')} | /dev/shm: {show('/dev/shm')}")
print("verdicts:", " ".join(f"{k}={results.get(k)}" for k in want),
      f"tmp-noexec-applied={'mounts.tmp-noexec' in applied}")
if bad:
    sys.exit("WRONG VERDICTS: " + "; ".join(bad))
PY
state() {
  sudo ibexctl check >/dev/null 2>&1 || true
  out=$(sudo python3 /var/tmp/ibx-verdicts.py) || { echo "$out"; return 1; }
  echo "$out" | sed "s/^/METRIC: $1: /"
}
had_tmp=no; findmnt -no TARGET /tmp >/dev/null && had_tmp=yes
tmp_orig=$(findmnt -no OPTIONS /tmp || true); shm_orig=$(findmnt -no OPTIONS /dev/shm)
restore() {
  if [ $had_tmp = yes ]; then sudo mount -o "remount,exec,suid,dev" /tmp; sudo mount -o "remount,$tmp_orig" /tmp || true
  elif findmnt -no TARGET /tmp >/dev/null; then sudo umount -l /tmp; fi
  sudo mount -o "remount,exec,suid,dev" /dev/shm; sudo mount -o "remount,$shm_orig" /dev/shm || true
}
trap restore EXIT
state original
pid=$(systemctl show -p MainPID --value ibexwall-plugin-posture.service)
[ "$pid" != 0 ] && echo "METRIC: inside the plugin sandbox: $(sudo nsenter -t $pid -m awk '$2=="/tmp"||$2=="/dev/shm"{print $2" "$3" "$4}' /proc/self/mounts | tr '\n' ';')"
[ $had_tmp = yes ] || sudo mount -t tmpfs tmpfs /tmp
sudo mount -o remount,noexec,nosuid,nodev /tmp
sudo mount -o remount,noexec,nosuid,nodev /dev/shm
state locked
sudo mount -o remount,exec,suid,dev /tmp
sudo mount -o remount,exec,suid,dev /dev/shm
state open
restore; trap - EXIT
state restored
"#;

/// A-24 in the light of A-25: a mounted file system the sandbox covers
/// (/home, /tmp) still keeps its module group from being blocked.
const MODULES_IN_USE: &str = r#"
enable system.modules
command -v mkudffs >/dev/null || [ -x /usr/sbin/mkudffs ] || pkg udftools || { echo "METRIC: no udftools here, not checked"; exit 0; }
if ! sudo modprobe udf 2>/dev/null; then echo "METRIC: this kernel has no udf module, not checked"; exit 0; fi
img=/var/tmp/ibx-udf.img
sudo rm -f $img; sudo truncate -s 8M $img; sudo mkudffs $img >/dev/null
point=
restore() { [ -n "$point" ] && sudo umount "$point" && sudo rmdir "$point"; sudo rm -f $img; }
trap restore EXIT
# The plugin must already be running: its namespace predates the mount.
sudo ibexctl plan system.modules --set 'block=["rare-filesystems"]' >/dev/null || { echo "NOTHING IS MOUNTED AND THE PLAN WAS REFUSED"; exit 1; }
for point in /mnt/ibx-udf /home/ibx-udf /tmp/ibx-udf; do
  sudo mkdir -p $point; sudo mount -o loop -t udf $img $point
  if out=$(sudo ibexctl plan system.modules --set 'block=["rare-filesystems"]' 2>&1); then
    echo "udf IS MOUNTED ON $point AND BLOCKING IT WAS PLANNED"; exit 1
  fi
  echo "$out" | grep -q 'mounted or in /etc/fstab' || { echo "REFUSED FOR ANOTHER REASON: $out"; exit 1; }
  sudo umount $point; sudo rmdir $point; point=
done
echo "METRIC: a udf mount under /mnt, /home or /tmp, made after the plugin started, keeps udf from being blocked"
"#;

/// A-03: which accounts' keys count, so nobody is locked out.
const SSH_ACCOUNTS: &str = r#"
command -v sshd >/dev/null || [ -x /usr/sbin/sshd ] || { echo "METRIC: no sshd on this machine"; exit 0; }
enable system.ssh
back=/var/tmp/ibx-keys-back; sudo rm -rf $back; sudo mkdir -p $back
keys=$(sudo find /root /home -maxdepth 3 -name authorized_keys 2>/dev/null)
restore() {
  sudo rm -f /etc/ssh/sshd_config.d/00-ibxtest.conf /root/.ssh/authorized_keys
  for f in $keys; do b="$back/$(echo $f | tr / _)"; if sudo test -e "$b"; then sudo mv "$b" "$f"; fi; done
  sudo userdel -r ibxssh >/dev/null 2>&1 || true
}
trap restore EXIT
for f in $keys; do sudo mv "$f" "$back/$(echo $f | tr / _)"; done
rm -f /tmp/ibx-key /tmp/ibx-key.pub; ssh-keygen -q -t ed25519 -N '' -f /tmp/ibx-key
tryplan() {
  if sudo ibexctl plan system.ssh --set password_auth=false "$@" >/tmp/ssh-try.out 2>&1; then echo accepted
  elif grep -q 'confirm_keys\|authorized' /tmp/ssh-try.out; then echo refused
  else echo error; fi
}
# put HOME OWNER LINE
put() {
  sudo install -d -m 0700 -o $2 -g $2 $1/.ssh
  echo "$3" | sudo tee $1/.ssh/authorized_keys >/dev/null
  sudo chown $2:$2 $1/.ssh/authorized_keys; sudo chmod 600 $1/.ssh/authorized_keys
  if command -v restorecon >/dev/null; then sudo restorecon -R $1/.ssh; fi
}
# Where AppArmor hides ~/.ssh the plugin cannot see any key.
if [ $FAM = deb ]; then yes=refused; else yes=accepted; fi
check() {
  got=$(tryplan); echo "METRIC: $1: $got"
  [ "$got" = "$2" ] || { echo "$1: EXPECTED $2, GOT $got"; cat /tmp/ssh-try.out; sudo ausearch -m avc -ts recent 2>/dev/null | tail -5; exit 1; }
}
check "no key anywhere" refused
sudo useradd -m -s "$(command -v nologin)" ibxssh
put /home/ibxssh ibxssh "$(cat /tmp/ibx-key.pub)"
check "a key of an account that cannot sign in" refused
sudo usermod -s /bin/bash ibxssh
check "a key of a /home account" $yes
put /home/ibxssh ibxssh '# no key here'
check "an authorized_keys with only a comment" refused
sudo rm /home/ibxssh/.ssh/authorized_keys
put /root root "$(cat /tmp/ibx-key.pub)"
check "a key of root alone" $yes
echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/00-ibxtest.conf >/dev/null
check "a key of root alone with root sign-in off" refused
sudo rm /etc/ssh/sshd_config.d/00-ibxtest.conf
got=$(tryplan --set confirm_keys=true); echo "METRIC: confirm_keys=true: $got"; [ "$got" = accepted ] || { cat /tmp/ssh-try.out; exit 1; }
"#;

/// A-01 with a password dialog in the way: a client that dies while the
/// dialog waits changes nothing, and one that dies just after the password
/// leaves a change that is either complete or undone.
const HANG_UP_DIALOG: &str = r#"
enable system.sysctl
history() { sudo ibexctl --json history | python3 -c 'import json,sys;print("\n".join(x["transaction"]+" "+x["result"] for x in json.load(sys.stdin)["entries"]))' | sort; }
files() { sudo find /etc/sysctl.d -name '*ibexwall*' | sort; }
newer() { history | grep -vxF -f /tmp/h.before || true; }
plan() { sudo -u ibxuser ibexctl --json plan system.sysctl --set preset=recommended | id_of; }
history >/tmp/h.before; before=$(files)
P=$(plan)
python3 /tmp/ibx-drive.py hang-prompt ibexctl apply "$P" --confirm-timeout 15 >/dev/null 2>/tmp/agent.log || { echo "THE DRIVER FAILED"; cat /tmp/agent.log; exit 1; }
grep -q 'client killed' /tmp/agent.log || { echo "THE DIALOG NEVER APPEARED"; cat /tmp/agent.log; exit 1; }
sed -n '/client killed/,$p' /tmp/agent.log | tr -d '\r' | grep -v '^$' | sed 's/^/METRIC: agent: /'
sleep 3
[ -z "$(newer)" ] || { echo "A TRANSACTION APPEARED: $(newer)"; exit 1; }
[ "$(files)" = "$before" ] || { echo "THE MACHINE CHANGED: $(files)"; exit 1; }
if sed -n '/password typed/,$p' /tmp/agent.log | grep -q 'AUTHENTICATION COMPLETE'; then
  echo "THE LATE PASSWORD OF A DEAD CLIENT AUTHENTICATED"; exit 1
fi
sed -n '/client killed/,$p' /tmp/agent.log | grep -qiE 'cancel|FAILED' || { echo "THE DIALOG DID NOT REFUSE THE LATE PASSWORD"; cat /tmp/agent.log; sudo journalctl -u polkit -n 10 --no-pager; exit 1; }
# The plan was not spent and nothing holds the engine.
TX=$(apply_keep "$P") || exit 1
sudo ibexctl rollback "$TX" >/dev/null
echo "METRIC: a client killed with the dialog open: dialog cancelled, nothing changed, the plan still applies"
for delay in 0 0.1 0.4 1.5; do
  history >/tmp/h.before; before=$(files)
  P=$(plan)
  python3 /tmp/ibx-drive.py hang-after:$delay ibexctl apply "$P" --confirm-timeout 15 >/dev/null 2>/tmp/agent.log || { cat /tmp/agent.log; exit 1; }
  sleep 25
  now=$(newer | awk '{print $2}' | tr '\n' ' ')
  echo "METRIC: killed ${delay}s after the password: ${now:-no transaction}"
  case "$now" in
  "") [ "$(files)" = "$before" ] || { echo "NO TRANSACTION BUT THE MACHINE CHANGED"; exit 1; } ;;
  "rolled_back ") [ "$(files)" = "$before" ] || { echo "ROLLED BACK BUT FILES REMAIN: $(files)"; exit 1; } ;;
  "committed ")
    [ "$(files)" != "$before" ] || { echo "COMMITTED BUT NOTHING IS THERE"; exit 1; }
    sudo ibexctl rollback "$(newer | awk '{print $1}')" >/dev/null ;;
  *) echo "HALF APPLIED OR STUCK: $now"; exit 1 ;;
  esac
done
sudo rm -f /etc/polkit-1/rules.d/00-ibexwall-test.rules
"#;

/// A-29: containers under the kill switch. Through the tunnel and to the
/// addresses on the allow list they work, replies included; anything else
/// on the physical network stays blocked.
const CONTAINERS: &str = r#"
enable net.vpn
case $FAM in
rpm) CT=podman; pkg podman wireguard-tools ;;
deb) CT=docker; pkg docker.io wireguard-tools iptables; sudo systemctl enable --now docker >/dev/null 2>&1 ;;
arch) CT=docker; pkg docker wireguard-tools; sudo systemctl enable --now docker >/dev/null 2>&1 ;;
esac
if [ -e /etc/apparmor.d/wg ] && command -v apparmor_parser >/dev/null; then sudo apparmor_parser -R /etc/apparmor.d/wg 2>/dev/null || true; fi
IMG=docker.io/library/busybox
for _ in 1 2 3; do sudo $CT pull -q $IMG >/dev/null 2>&1 && break; sleep 10; done
sudo $CT image inspect $IMG >/dev/null || { echo "THE IMAGE COULD NOT BE PULLED"; exit 1; }
PEER=${SSH_CLIENT%% *}
KS=
cleanup() {
  [ -n "$KS" ] && sudo ibexctl rollback "$KS" >/dev/null 2>&1
  sudo $CT rm -f ibxc ibxweb >/dev/null 2>&1 || true
  # The tunnel may already be down (the script deletes it mid-run).
  sudo ip link del wg-ibx 2>/dev/null || true
  for ns in ibxprov ibxlan; do sudo ip netns pids $ns 2>/dev/null | xargs -r sudo kill; sudo ip netns del $ns 2>/dev/null || true; done
  true
}
trap cleanup EXIT
# A VPN provider and hosts on the local network, in namespaces.
mk_ns() { # ns link hostaddr nsaddr...
  ns=$1; l=$2; h=$3; shift 3
  sudo ip netns add $ns; sudo ip link add ${l}h type veth peer name ${l}n; sudo ip link set ${l}n netns $ns
  sudo ip addr add $h dev ${l}h; sudo ip link set ${l}h up
  for a in "$@"; do sudo ip netns exec $ns ip addr add $a dev ${l}n; done
  sudo ip netns exec $ns ip link set ${l}n up; sudo ip netns exec $ns ip link set lo up
}
mk_ns ibxprov ibxp 10.99.0.1/24 10.99.0.2/24
mk_ns ibxlan ibxl 10.55.0.1/24 10.55.0.2/24 10.55.0.3/24
SK=$(wg genkey); CK=$(wg genkey)
sudo ip netns exec ibxprov ip link add wgs type wireguard
echo "$SK" | sudo ip netns exec ibxprov wg set wgs listen-port 51820 private-key /dev/stdin peer "$(echo $CK | wg pubkey)" allowed-ips 10.100.0.2/32
sudo ip netns exec ibxprov ip addr add 10.100.0.1/24 dev wgs; sudo ip netns exec ibxprov ip link set wgs up
sudo mkdir -p /var/empty
for ns in ibxprov ibxlan; do sudo ip netns exec $ns setsid -f python3 -m http.server 8000 -d /var/empty </dev/null >/dev/null 2>&1; done
tunnel_up() {
  sudo ip link add wg-ibx type wireguard
  echo "$CK" | sudo wg set wg-ibx private-key /dev/stdin peer "$(echo $SK | wg pubkey)" allowed-ips 0.0.0.0/0 endpoint 10.99.0.2:51820 persistent-keepalive 3
  sudo ip addr add 10.100.0.2/24 dev wg-ibx; sudo ip link set wg-ibx up
  sudo ip route add 0.0.0.0/1 dev wg-ibx; sudo ip route add 128.0.0.0/1 dev wg-ibx
  for _ in $(seq 1 20); do ping -c1 -W1 10.100.0.1 >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
tunnel_up || { echo "THE TEST TUNNEL DID NOT COME UP"; exit 1; }
sudo $CT run -d --name ibxweb -p 8088:80 $IMG httpd -f -p 80 -h /etc >/dev/null
sudo $CT run -d --name ibxc $IMG sleep 3600 >/dev/null
WEB=$(sudo $CT inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ibxweb)
[ -n "$WEB" ] || { echo "NO CONTAINER ADDRESS"; exit 1; }
from_ct() { sudo $CT exec ibxc timeout 5 wget -q -T 4 -O /dev/null "$1" >/dev/null 2>&1; }
yn() { if "$@"; then echo yes; else echo no; fi; }
sibling() { from_ct "http://$WEB/hostname"; }
published() { curl -s -m 4 -o /dev/null "http://127.0.0.1:8088/hostname"; }
for u in 10.100.0.1:8000 10.55.0.2:8000 10.55.0.3:8000; do from_ct http://$u/ || { echo "BEFORE THE KILL SWITCH A CONTAINER CANNOT REACH $u"; sudo $CT exec ibxc ip route; sudo nft list ruleset | head -80; exit 1; }; done
echo "METRIC: $CT before: tunnel and both local hosts reachable; sibling container: $(yn sibling); host to published port: $(yn published); bridge-nf-call-iptables: $(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || echo not loaded)"
KS=$(apply_keep "$(sudo ibexctl plan net.vpn --set action=killswitch --set endpoints=10.99.0.2:51820 --set "allow=[\"$PEER\",\"10.55.0.2\"]" --json | id_of)") || exit 1
from_ct http://10.100.0.1:8000/ || { echo "A CONTAINER CANNOT REACH THE TUNNEL UNDER THE KILL SWITCH"; sudo nft list table inet ibexwall; exit 1; }
if from_ct http://10.55.0.3:8000/; then echo "A CONTAINER REACHED A LOCAL HOST THAT IS NOT ALLOWED"; exit 1; fi
curl -s -m 4 -o /dev/null http://10.55.0.2:8000/ || { echo "THE HOST CANNOT REACH THE ALLOWED HOST"; exit 1; }
from_ct http://10.55.0.2:8000/ || { echo "A CONTAINER CANNOT REACH AN ALLOWED HOST (replies dropped?)"; sudo nft list table inet ibexwall; exit 1; }
echo "METRIC: $CT under the kill switch: tunnel yes, allowed host yes, other local host no"
echo "METRIC: $CT under the kill switch, traffic that never leaves this machine: sibling container: $(yn sibling); host to published port: $(yn published)"
sudo ip link del wg-ibx
for u in 10.100.0.1:8000 10.55.0.3:8000 1.1.1.1:443; do if from_ct http://$u/; then echo "TUNNEL DOWN AND A CONTAINER STILL REACHES $u"; exit 1; fi; done
from_ct http://10.55.0.2:8000/ || { echo "TUNNEL DOWN: THE ALLOWED HOST IS GONE"; exit 1; }
sudo ibexctl rollback "$KS" >/dev/null; KS=
from_ct http://10.55.0.3:8000/ || { echo "AFTER THE UNDO A CONTAINER CANNOT REACH THE LOCAL NETWORK"; exit 1; }
echo "METRIC: $CT with the tunnel down: only the allowed host; the undo gives everything back"
"#;

/// A-29: a DHCP lease survives the kill switch, although the unicast
/// renewal is dropped, because the client then asks by broadcast.
const DHCP: &str = r#"
enable net.vpn
case $FAM in deb) pkg dnsmasq-base ;; *) pkg dnsmasq ;; esac
PEER=${SSH_CLIENT%% *}
KS=
cleanup() {
  [ -n "$KS" ] && sudo ibexctl rollback "$KS" >/dev/null 2>&1
  sudo nft delete table inet ibxcount 2>/dev/null
  command -v nmcli >/dev/null && sudo nmcli connection delete ibxdh >/dev/null 2>&1
  sudo rm -f /etc/systemd/network/10-ibxdh.network
  sudo ip netns pids ibxdhcp 2>/dev/null | xargs -r sudo kill; sudo ip netns del ibxdhcp 2>/dev/null
  true
}
trap cleanup EXIT
sudo ip netns add ibxdhcp
sudo ip link add ibxdh0 type veth peer name ibxdh1; sudo ip link set ibxdh1 netns ibxdhcp
sudo ip netns exec ibxdhcp ip addr add 10.77.0.1/24 dev ibxdh1; sudo ip netns exec ibxdhcp ip link set ibxdh1 up
# Two minutes is the shortest lease dnsmasq grants: renewal at 60 s,
# rebinding at about 105 s.
sudo rm -f /tmp/ibx-dnsmasq.log /tmp/ibx-dnsmasq.leases
sudo ip netns exec ibxdhcp "$(command -v dnsmasq || echo /usr/sbin/dnsmasq)" --conf-file=/dev/null --port=0 --interface=ibxdh1 --bind-interfaces --user=root \
  --dhcp-range=10.77.0.50,10.77.0.60,255.255.255.0,120 --dhcp-option=3 --dhcp-leasefile=/tmp/ibx-dnsmasq.leases \
  --log-dhcp --log-facility=/tmp/ibx-dnsmasq.log || { echo "DNSMASQ DID NOT START"; exit 1; }
if systemctl is-active -q NetworkManager; then
  client=NetworkManager
  sudo ip link set ibxdh0 up
  sudo nmcli connection add type ethernet ifname ibxdh0 con-name ibxdh ipv4.method auto ipv4.never-default yes ipv6.method disabled >/dev/null
  sudo nmcli device set ibxdh0 managed yes; sudo nmcli connection up ibxdh >/dev/null
else
  client=systemd-networkd
  printf '[Match]\nName=ibxdh0\n[Network]\nDHCP=ipv4\nIPv6AcceptRA=no\n[DHCPv4]\nUseRoutes=no\nUseDNS=no\n' | sudo tee /etc/systemd/network/10-ibxdh.network >/dev/null
  sudo networkctl reload; sudo ip link set ibxdh0 up
fi
addr() { ip -4 -o addr show ibxdh0 | awk '{print $4}'; }
for _ in $(seq 1 30); do [ -n "$(addr)" ] && break; sleep 1; done
[ -n "$(addr)" ] || { echo "NO LEASE BEFORE THE TEST"; sudo cat /tmp/ibx-dnsmasq.log; exit 1; }
first=$(addr)
sudo nft -f - <<'NFT'
table inet ibxcount {
  chain out { type filter hook output priority -300; ip daddr 10.77.0.1 udp dport 67 counter; }
}
NFT
KS=$(apply_keep "$(sudo ibexctl plan net.vpn --set action=killswitch --set endpoints=192.0.2.1:51820 --set "allow=[\"$PEER\"]" --json | id_of)") || exit 1
acks=$(sudo grep -c 'DHCPACK(ibxdh1)' /tmp/ibx-dnsmasq.log)
start=$(date +%s)
echo "METRIC: $client got $first, lease 120 s, kill switch on"
# Three lease times, watching that the address never goes away.
lost=0
for _ in $(seq 1 72); do [ -n "$(addr)" ] || lost=$((lost+1)); sleep 5; done
renewed=$(( $(sudo grep -c 'DHCPACK(ibxdh1)' /tmp/ibx-dnsmasq.log) - acks ))
tries=$(sudo nft list table inet ibxcount | grep -o 'packets [0-9]*' | awk '{print $2}')
echo "METRIC: after $(( $(date +%s) - start )) s: address $(addr), samples without an address $lost/72, renewals acknowledged $renewed, unicast renewal packets tried (and dropped) $tries"
sudo grep -E 'DHCP(REQUEST|ACK|DISCOVER)\(' /tmp/ibx-dnsmasq.log | tail -6 | sed 's/^/METRIC: server: /'
[ "$lost" = 0 ] && [ -n "$(addr)" ] || { echo "THE LEASE WAS LOST UNDER THE KILL SWITCH"; sudo cat /tmp/ibx-dnsmasq.log; exit 1; }
[ "$renewed" -ge 2 ] || { echo "THE LEASE WAS NOT RENEWED UNDER THE KILL SWITCH"; sudo cat /tmp/ibx-dnsmasq.log; exit 1; }
"#;

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== audit: stage ==");
    let input = stage_and_pack(workspace)?;
    println!("== audit: provision ==");
    vm.ssh(install)
        .context("installing python3 and polkit in the VM")?;
    pipe_file(vm, &input, "cat > /tmp/ibx-input.tar.gz")?;
    pipe_data(vm, DRIVER, "cat > /tmp/ibx-drive.py")?;

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
    scenario!(
        "x6 mount verdicts follow the host in every state (A-25)",
        MOUNTS
    );
    scenario!(
        "x7 a hidden mount still blocks a module group (A-24)",
        MODULES_IN_USE
    );
    scenario!("x8 whose keys let passwords go (A-03)", SSH_ACCOUNTS);
    scenario!("x9 a person who can be asked for a password", PERSON);
    scenario!(
        "x10 a hang-up around the password dialog (A-01)",
        HANG_UP_DIALOG
    );
    scenario!("x11 containers under the kill switch (A-29)", CONTAINERS);
    scenario!("x12 a DHCP lease under the kill switch (A-29)", DHCP);

    if failures == 0 {
        println!("PASS: audit suite (all scenarios)");
        Ok(())
    } else {
        bail!("{failures} audit scenario(s) failed")
    }
}
