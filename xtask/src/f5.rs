// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F5 VM phase: the inbound firewall on real firewalld and ufw machines.

use std::path::Path;

use anyhow::Result;

use super::f1::{install_plugin, provision, run_script, start_daemon};
use super::vm::{Vm, run_capture};

/// Reads the transaction or plan id out of `ibexctl --json` output.
const JSON_ID: &str = "python3 -c 'import json,sys;d=json.JSONDecoder().raw_decode(sys.stdin.read())[0];t=d.get(\"plan\") or d.get(\"transaction\");print(t[\"id\"] if isinstance(t,dict) else t)'";

/// Shell helpers every scenario shares. A network namespace with its own
/// interface plays "another computer": traffic to this machine's own
/// address arrives on the loopback interface and would prove nothing.
const LIB: &str = r#"
set -e
install() {
  if command -v dnf >/dev/null; then sudo dnf install -y -q "$@"
  elif command -v apt-get >/dev/null; then sudo apt-get update -qq; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
  elif command -v pacman >/dev/null; then sudo pacman -Sy --noconfirm --needed "$@"
  fi
}
peer_up() {
  sudo ip netns del peer 2>/dev/null || true
  sudo ip link del ext0 2>/dev/null || true
  sudo ip netns add peer
  sudo ip link add ext0 type veth peer name ext1
  sudo ip link set ext1 netns peer
  sudo ip addr add 192.0.2.1/24 dev ext0
  sudo ip link set ext0 up
  sudo ip netns exec peer ip addr add 192.0.2.2/24 dev ext1
  sudo ip netns exec peer ip link set ext1 up
  sudo ip netns exec peer ip link set lo up
}
peer_down() { sudo ip netns del peer 2>/dev/null || true; sudo ip link del ext0 2>/dev/null || true; }
# Can the other computer reach this one on a TCP port?
peer_can() {
  sudo ip netns exec peer python3 -c "
import socket, sys
s = socket.socket(); s.settimeout(3)
try: s.connect(('192.0.2.1', $1))
except Exception: sys.exit(1)"
}
serve() { sudo sh -c "nohup python3 -m http.server $1 --bind 0.0.0.0 >/dev/null 2>&1 & echo \$! >> /tmp/servers.pid"; sleep 1; }
unserve() { [ -f /tmp/servers.pid ] && sudo kill $(cat /tmp/servers.pid) 2>/dev/null || true; sudo rm -f /tmp/servers.pid; }
# plan, apply and (if asked) confirm; prints the transaction id
tx_apply() {
  local sets=""
  for a in "$@"; do sets="$sets --set $a"; done
  local P OUT TX
  P=$(sudo ibexctl plan net.firewall $sets --json 2>&1 | tee /tmp/plan.out | @JSON_ID@) || { cat /tmp/plan.out >&2; return 1; }
  case "$P" in plan-*) ;; *) echo "PLAN FAILED:" >&2; cat /tmp/plan.out >&2; return 1 ;; esac
  OUT=$(sudo ibexctl apply $P --confirm-timeout 300 --json 2>/tmp/apply.err || true)
  TX=$(echo "$OUT" | @JSON_ID@) || { echo "APPLY FAILED: $OUT" >&2; cat /tmp/apply.err >&2; return 1; }
  case "$TX" in tx-*) ;; *) echo "APPLY GAVE NO TRANSACTION: $OUT" >&2; cat /tmp/apply.err >&2; sudo journalctl -u ibexwalld -n 15 --no-pager >&2; return 1 ;; esac
  if echo "$OUT" | grep -q pending_confirm; then sudo ibexctl confirm "$TX" >&2; fi
  echo "$TX"
}
# Some cloud images run systemd-resolved with no upstream server; QEMU's
# user network offers one at 10.0.2.3 (the VM only).
ensure_dns() {
  if ! getent hosts registry-1.docker.io >/dev/null; then
    sudo mkdir -p /etc/systemd/resolved.conf.d
    printf '[Resolve]\nDNS=10.0.2.3\n' | sudo tee /etc/systemd/resolved.conf.d/10-vm-upstream.conf >/dev/null
    sudo systemctl restart systemd-resolved
    sleep 2
  fi
}
peer_serve() {
  sudo sh -c 'nohup ip netns exec peer python3 -m http.server 7000 --bind 192.0.2.2 >/tmp/peer-server.log 2>&1 & echo $! > /tmp/peer-server.pid'
  for i in $(seq 1 20); do
    if sudo ip netns exec peer ss -ltn | grep -q ':7000'; then return 0; fi
    sleep 0.5
  done
  { echo "peer server never listened"
    echo "log: $(sudo cat /tmp/peer-server.log | tail -5 | tr '\n' '|')"
    echo "pid $(sudo cat /tmp/peer-server.pid): $(ps -o pid,stat,cmd -p $(sudo cat /tmp/peer-server.pid) 2>&1 | tail -1)"
    echo "ss: $(sudo ip netns exec peer ss -ltnp | tr '\n' '|')"; } >&2
  return 1
}
# With Docker running: a published port still answers the other computer,
# and the container still reaches out through the host.
docker_ok() {
  peer_can 8088 || { echo "DOCKER PUBLISHED PORT NOT REACHABLE"; return 1; }
  sudo docker exec web wget -q -T 4 -O /dev/null http://192.0.2.2:7000/ || {
    echo "CONTAINER CANNOT REACH OUT"
    { echo "-- peer listeners:"; sudo ip netns exec peer ss -ltn
      echo "-- peer server pid: $(sudo cat /tmp/peer-server.pid 2>/dev/null) log: $(sudo cat /tmp/peer-server.log 2>/dev/null | tail -3)"
      echo "-- peer addr: $(sudo ip netns exec peer ip -br addr)"
      echo "-- ip_forward: $(cat /proc/sys/net/ipv4/ip_forward)"
      echo "-- tables:"; sudo nft list tables
      echo "-- container route:"; sudo docker exec web ip route; } >&2
    return 1
  }
}
# nft ruleset without our own table, canonical, for the "nothing else touched" proof
foreign_rules() {
  sudo nft -j list ruleset | python3 -c "
import json, sys
d = json.load(sys.stdin)['nftables']
keep = [i for i in d if 'metainfo' not in i and i.get('table', {}).get('name') != 'ibexwall' and i.get('chain', {}).get('table') != 'ibexwall' and i.get('rule', {}).get('table') != 'ibexwall']
def strip(v):
    # Counters change with every packet; the rules themselves are what matter.
    if isinstance(v, dict): return {k: strip(x) for k, x in v.items() if k not in ('handle', 'packets', 'bytes')}
    if isinstance(v, list): return [strip(x) for x in v]
    return v
print(json.dumps(strip(keep), sort_keys=True))"
}
"#;

fn lib() -> String {
    LIB.replace("@JSON_ID@", JSON_ID)
}

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== f5: build ==");
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
            "--bins",
        ],
        None,
        "building release binaries",
    )?;
    crate::devkey::run()?;
    provision(vm, workspace, install)?;
    install_plugin(vm, workspace, "net.firewall")?;
    start_daemon(vm)?;

    let mut failures = 0;
    macro_rules! scenario {
        ($name:expr, $script:expr) => {
            if !run_script(vm, $name, $script) {
                failures += 1;
            }
        };
    }

    // Nothing manages the firewall yet on a fresh Debian or Arch image:
    // run before any manager is installed.
    scenario!(
        "p3 basic inbound protection in IbexWall's own table, and nothing else touched",
        &format!(
            "{}{}",
            lib(),
            r#"
if [ -x /usr/bin/firewall-cmd ] || [ -x /usr/sbin/ufw ]; then
  echo "METRIC: skipped, a firewall manager is installed on this image"; exit 0
fi
command -v nft >/dev/null || install nftables
sudo ibexctl plugins enable net.firewall
peer_up
trap 'unserve; peer_down' EXIT
BEFORE=$(foreign_rules)

# Without a deliberate yes the plugin refuses to take over.
if sudo ibexctl plan net.firewall --set allow=8080 >/dev/null 2>&1; then echo "PLANNED WITHOUT enable_basic"; exit 1; fi

TX1=$(tx_apply enable_basic=true)
sudo nft list chain inet ibexwall net_firewall_input | grep -q "ct state established,related accept" || { echo "NO ESTABLISHED RULE"; sudo nft list ruleset >&2; exit 1; }
sudo nft list chain inet ibexwall net_firewall_input | tail -3 | grep -q drop || { echo "NO FINAL DROP"; exit 1; }
sudo test -f /etc/ibexwall/firewall/inbound.json

# Started after the protection, so they are not among the kept-open ports.
serve 8080; serve 9090
peer_can 22 || { echo "SSH WAS CUT OFF"; exit 1; }
if peer_can 8080; then echo "8080 WAS REACHABLE"; exit 1; fi
if peer_can 9090; then echo "9090 WAS REACHABLE"; exit 1; fi

TX2=$(tx_apply allow=8080/tcp)
sudo ibexctl firewall status | grep -q 'nftables (active)' || { echo "status NOT ACTIVE"; sudo ibexctl firewall status >&2; exit 1; }
sudo ibexctl firewall status | grep -q 'allowed ports:.*8080/tcp' || { echo "status MISSING 8080"; sudo ibexctl firewall status >&2; exit 1; }
peer_can 8080 || { echo "8080 STILL BLOCKED"; sudo nft list chain inet ibexwall net_firewall_input >&2; exit 1; }
if peer_can 9090; then echo "9090 OPENED BY MISTAKE"; exit 1; fi
[ "$(foreign_rules)" = "$BEFORE" ] || { echo "A FOREIGN TABLE CHANGED"; exit 1; }

# nftables keeps nothing across a reboot: lose the table, restart the daemon.
sudo nft delete table inet ibexwall
sudo systemctl restart ibexwalld
for i in $(seq 1 30); do sudo ibexctl status --json >/dev/null 2>&1 && break; sleep 1; done
sudo nft list chain inet ibexwall net_firewall_input >/dev/null || { echo "CHAIN NOT RESTORED AFTER RESTART"; exit 1; }
peer_can 8080 || { echo "8080 BLOCKED AFTER RESTORE"; exit 1; }
if peer_can 9090; then echo "9090 REACHABLE AFTER RESTORE"; exit 1; fi

# Undo both: the machine is exactly as it was.
sudo ibexctl rollback "$TX2" --json >/dev/null
if peer_can 8080; then echo "8080 REACHABLE AFTER UNDOING ITS ALLOW"; exit 1; fi
sudo ibexctl rollback "$TX1" --json >/dev/null
peer_can 9090 || { echo "STILL BLOCKED AFTER FULL ROLLBACK"; exit 1; }
if sudo nft list table inet ibexwall >/dev/null 2>&1; then echo "OUR TABLE SURVIVED ROLLBACK"; sudo nft list ruleset >&2; exit 1; fi
sudo test ! -e /etc/ibexwall/firewall/inbound.json || { echo "SETTINGS FILE SURVIVED"; exit 1; }
[ "$(foreign_rules)" = "$BEFORE" ] || { echo "A FOREIGN TABLE CHANGED AFTER ROLLBACK"; exit 1; }
sudo test ! -e /var/lib/ibexwall/nft-active.json || { echo "STALE PERSISTED CHAINS"; exit 1; }
"#
        )
    );

    scenario!(
        "p4 Docker keeps working: published ports, container traffic, foreign tables untouched",
        &format!(
            "{}{}",
            lib(),
            r#"
ensure_dns
if ! command -v docker >/dev/null; then
  if command -v dnf >/dev/null; then install moby-engine
  elif command -v apt-get >/dev/null; then install docker.io
  elif command -v pacman >/dev/null; then install docker
  fi
fi
sudo systemctl enable --now docker
sleep 3
command -v nft >/dev/null || install nftables
peer_up
peer_serve
sudo docker rm -f web >/dev/null 2>&1 || true
sudo docker run -d --name web -p 8088:80 docker.io/library/busybox httpd -f -h / -p 80 >/dev/null
sleep 2
docker_ok
FOREIGN=$(foreign_rules)
echo "METRIC: docker $(sudo docker --version | cut -c1-40), foreign tables: $(sudo nft list tables | tr '\n' ',' | cut -c1-120)"

# Only when nothing else manages the firewall: IbexWall's own protection
# in front of a running Docker.
if [ ! -x /usr/bin/firewall-cmd ] && [ ! -x /usr/sbin/ufw ]; then
  sudo ibexctl plugins enable net.firewall
  TX=$(tx_apply enable_basic=true)
  GW=$(sudo docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
  docker_ok
  [ "$(foreign_rules)" = "$FOREIGN" ] || { echo "DOCKER'S TABLES CHANGED"; exit 1; }
  # Not "another computer": the bridge is trusted, so a container can reach
  # a host service the firewall would refuse from outside.
  sudo sh -c "nohup python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 & echo \$! > /tmp/h8080.pid"; sleep 1
  sudo docker exec web wget -q -T 4 -O /dev/null http://$GW:8080/ || { echo "CONTAINER CANNOT REACH THE HOST"; exit 1; }
  if peer_can 8080; then echo "8080 REACHABLE FROM OUTSIDE"; exit 1; fi
  sudo kill $(cat /tmp/h8080.pid) 2>/dev/null || true
  sudo ibexctl rollback "$TX" --json >/dev/null
  docker_ok
  [ "$(foreign_rules)" = "$FOREIGN" ] || { echo "DOCKER'S TABLES CHANGED AFTER ROLLBACK"; exit 1; }
else
  echo "METRIC: nft mode skipped here; the manager scenarios check Docker too"
fi
sudo kill $(cat /tmp/peer-server.pid) 2>/dev/null || true
peer_down
"#
        )
    );

    // Tailscale and NetBird are not installed here (they need an account and
    // a coordination server); what matters to the firewall is the interface
    // their traffic arrives on, so a veth named like theirs stands in.
    scenario!(
        "p5 VPN-style interfaces stay open, other computers do not, a foreign table stays intact",
        &format!(
            "{}{}",
            lib(),
            r#"
if [ -x /usr/bin/firewall-cmd ] || [ -x /usr/sbin/ufw ]; then
  echo "METRIC: skipped, a firewall manager owns inbound rules on this image"; exit 0
fi
command -v nft >/dev/null || install nftables
sudo ibexctl plugins enable net.firewall
peer_up
sudo ip netns del vpn 2>/dev/null || true
sudo ip link del tailscale0 2>/dev/null || true
sudo ip netns add vpn
sudo ip link add tailscale0 type veth peer name ts1
sudo ip link set ts1 netns vpn
sudo ip addr add 100.64.0.1/24 dev tailscale0
sudo ip link set tailscale0 up
sudo ip netns exec vpn ip addr add 100.64.0.2/24 dev ts1
sudo ip netns exec vpn ip link set ts1 up
trap 'unserve; peer_down; sudo ip netns del vpn 2>/dev/null || true; sudo ip link del tailscale0 2>/dev/null || true; sudo nft delete table ip ts_test 2>/dev/null || true' EXIT
# A table that is not ours, as another program would leave it.
sudo nft add table ip ts_test
sudo nft add chain ip ts_test ts-input '{ type filter hook input priority 0; policy accept; }'
sudo nft add rule ip ts_test ts-input iifname tailscale0 accept
FOREIGN=$(foreign_rules)

TX=$(tx_apply enable_basic=true)
serve 9090
if peer_can 9090; then echo "OTHER COMPUTER REACHED 9090"; exit 1; fi
sudo ip netns exec vpn python3 -c "
import socket
s = socket.socket(); s.settimeout(3)
s.connect(('100.64.0.1', 9090))" || { echo "VPN INTERFACE TRAFFIC WAS DROPPED"; exit 1; }
[ "$(foreign_rules)" = "$FOREIGN" ] || { echo "THE FOREIGN TABLE CHANGED"; exit 1; }
sudo ibexctl rollback "$TX" --json >/dev/null
[ "$(foreign_rules)" = "$FOREIGN" ] || { echo "THE FOREIGN TABLE CHANGED BY ROLLBACK"; exit 1; }
"#
        )
    );

    scenario!(
        "p1 firewalld: a port opens natively and closes again byte for byte",
        &format!(
            "{}{}",
            lib(),
            r#"
install firewalld
sudo systemctl disable --now ufw 2>/dev/null || true
sudo systemctl enable --now firewalld
sleep 2
sudo ibexctl plugins enable net.firewall
peer_up
trap 'unserve; peer_down' EXIT
serve 8080
# Docker and firewalld: containers need docker0 in the trusted zone (the
# documented arrangement). That is the administrator's setup, not ours; it
# must survive our changes and our reload.
if sudo docker ps >/dev/null 2>&1; then
  peer_serve
  if ! docker_ok >/dev/null 2>&1; then
    echo "METRIC: firewalld alone breaks container traffic; docker0 goes to the trusted zone, as documented"
    sudo firewall-cmd --permanent --zone=trusted --add-interface=docker0 >/dev/null
    sudo firewall-cmd --reload >/dev/null
    sleep 2
  fi
  docker_ok || { echo "DOCKER NOT WORKING EVEN WITH docker0 TRUSTED"; sudo firewall-cmd --list-all-zones >&2; exit 1; }
fi
Z=$(sudo firewall-cmd --get-default-zone)
ZF=/etc/firewalld/zones/$Z.xml
HASH_BEFORE=$(sudo sha256sum $ZF 2>/dev/null | cut -d' ' -f1 || true)
if peer_can 8080; then echo "8080 WAS REACHABLE BEFORE"; exit 1; fi

TX=$(tx_apply allow=8080/tcp)
sudo firewall-cmd --list-ports | grep -q '8080/tcp' || { echo "NOT IN RUNTIME"; sudo firewall-cmd --list-all >&2; echo "permanent: $(sudo firewall-cmd --permanent --list-ports)" >&2; sudo journalctl -u ibexwalld -n 25 --no-pager >&2; cat /tmp/apply.err >&2; exit 1; }
sudo firewall-cmd --permanent --list-ports | grep -q '8080/tcp' || { echo "NOT PERMANENT"; exit 1; }
peer_can 8080 || { echo "8080 STILL BLOCKED"; exit 1; }
if sudo docker ps >/dev/null 2>&1; then peer_serve; docker_ok || { sudo nft list tables >&2; exit 1; }; echo "METRIC: docker still fine under firewalld"; fi
echo "METRIC: firewall-cmd --list-all after apply: $(sudo firewall-cmd --list-all | tr '\n' '|' | cut -c1-300)"

sudo ibexctl rollback "$TX" --json >/dev/null
if sudo firewall-cmd --list-ports | grep -q '8080/tcp'; then echo "STILL IN RUNTIME AFTER ROLLBACK"; exit 1; fi
if sudo firewall-cmd --permanent --list-ports | grep -q '8080/tcp'; then echo "STILL PERMANENT AFTER ROLLBACK"; exit 1; fi
if peer_can 8080; then echo "8080 REACHABLE AFTER ROLLBACK"; exit 1; fi
HASH_AFTER=$(sudo sha256sum $ZF 2>/dev/null | cut -d' ' -f1 || true)
[ "$HASH_BEFORE" = "$HASH_AFTER" ] || { echo "ZONE FILE NOT RESTORED: '$HASH_BEFORE' vs '$HASH_AFTER'"; exit 1; }
if sudo docker ps >/dev/null 2>&1; then docker_ok || { echo "DOCKER BROKEN BY THE ROLLBACK'S RELOAD"; sudo firewall-cmd --list-all-zones >&2; exit 1; }; fi

# A service, and removing something that is there (a risky change: confirmed).
TX=$(tx_apply allow_service=http)
sudo firewall-cmd --list-services | grep -q http || { echo "SERVICE MISSING"; exit 1; }
TX2=$(tx_apply remove_service=http)
if sudo firewall-cmd --list-services | grep -qw http; then echo "SERVICE STILL THERE"; exit 1; fi
sudo ibexctl rollback "$TX2" --json >/dev/null
sudo firewall-cmd --list-services | grep -qw http || { echo "SERVICE NOT BACK AFTER UNDO"; exit 1; }
sudo ibexctl rollback "$TX" --json >/dev/null
HASH_AFTER=$(sudo sha256sum $ZF 2>/dev/null | cut -d' ' -f1 || true)
[ "$HASH_BEFORE" = "$HASH_AFTER" ] || { echo "ZONE FILE NOT RESTORED (2): '$HASH_BEFORE' vs '$HASH_AFTER'"; exit 1; }
# The command line says the same as the manager does, and can change it.
sudo ibexctl firewall status | grep -q 'firewalld (active)' || { echo "ibexctl firewall status WRONG"; sudo ibexctl firewall status >&2; exit 1; }
if sudo ibexctl firewall allow 9091/tcp | grep -q "apply with"; then :; else echo "allow WITHOUT --yes DID NOT ONLY PLAN"; exit 1; fi
if sudo firewall-cmd --list-ports | grep -q 9091; then echo "allow WITHOUT --yes CHANGED THE FIREWALL"; exit 1; fi
# The plugin asks for confirmation (exit status 5), like any firewall change.
DONE=$(sudo ibexctl firewall allow 9091/tcp --yes 2>&1 || true)
TXC=$(echo "$DONE" | grep -o 'tx-[a-z0-9-]*' | head -1)
test -n "$TXC" || { echo "NO TRANSACTION: $DONE"; exit 1; }
if echo "$DONE" | grep -q "awaiting confirmation"; then sudo ibexctl confirm "$TXC" >/dev/null; fi
sudo firewall-cmd --list-ports | grep -q 9091/tcp || { echo "allow --yes DID NOT APPLY: $DONE"; exit 1; }
sudo ibexctl firewall status | grep -q '9091/tcp' || { echo "status DOES NOT SHOW 9091"; exit 1; }
sudo ibexctl rollback "$TXC" --json >/dev/null
if sudo firewall-cmd --list-ports | grep -q 9091; then echo "9091 SURVIVED ROLLBACK"; exit 1; fi
# NetworkManager, where it runs, names the networks and a profile for each.
if systemctl is-active --quiet NetworkManager; then
  sudo ibexctl firewall status --json > /tmp/fw.json
  python3 - <<'EOF'
import json
d = json.load(open("/tmp/fw.json"))["firewall"]
nets = d["networks"]
assert nets, d
wired = [n for n in nets if n["kind"] == "wired"]
assert wired and wired[0]["recommended"] == "public" and wired[0]["warning"] is None, nets
print("METRIC: networks seen through NetworkManager:", [(n["kind"], n["recommended"]) for n in nets])
EOF
else
  echo "METRIC: NetworkManager not running here; no networks listed"
fi
# Profiles map to zones this firewalld ships.
ZONE_BEFORE=$(sudo firewall-cmd --get-default-zone)
sudo ibexctl firewall profile | grep -q 'travel' || { echo "profile list WRONG"; exit 1; }
DONE=$(sudo ibexctl firewall profile home --yes 2>&1 || true)
TXP=$(echo "$DONE" | grep -o 'tx-[a-z0-9-]*' | head -1)
test -n "$TXP" || { echo "NO PROFILE TRANSACTION: $DONE"; exit 1; }
if echo "$DONE" | grep -q "awaiting confirmation"; then sudo ibexctl confirm "$TXP" >/dev/null; fi
[ "$(sudo firewall-cmd --get-default-zone)" = home ] || { echo "DEFAULT ZONE NOT home"; exit 1; }
sudo ibexctl firewall status | grep -q 'zone home' || { echo "status DOES NOT SHOW THE ZONE"; sudo ibexctl firewall status >&2; exit 1; }
sudo ibexctl rollback "$TXP" --json >/dev/null
[ "$(sudo firewall-cmd --get-default-zone)" = "$ZONE_BEFORE" ] || { echo "DEFAULT ZONE NOT RESTORED"; exit 1; }
sudo systemctl disable --now firewalld
"#
        )
    );

    scenario!(
        "p2 ufw: a port opens natively and closes again byte for byte",
        &format!(
            "{}{}",
            lib(),
            r#"
. /etc/os-release
# Fedora's ufw keeps its rules elsewhere and Fedora ships firewalld: skip.
if [ "$ID" = fedora ]; then echo "METRIC: ufw skipped on fedora (firewalld is native there)"; exit 0; fi
install ufw
sudo systemctl disable --now firewalld 2>/dev/null || true
# Rules first, then enable, so enabling cannot cut the session.
sudo ufw allow 22/tcp >/dev/null
sudo ufw --force enable >/dev/null
sudo ibexctl plugins enable net.firewall
peer_up
trap 'unserve; peer_down; sudo ufw --force disable >/dev/null 2>&1 || true' EXIT
serve 8080
BEFORE4=$(sudo sha256sum /etc/ufw/user.rules | cut -d' ' -f1)
BEFORE6=$(sudo sha256sum /etc/ufw/user6.rules | cut -d' ' -f1)
if peer_can 8080; then echo "8080 WAS REACHABLE BEFORE"; exit 1; fi

TX=$(tx_apply allow=8080/tcp)
sudo ufw status | grep -q '8080/tcp' || { echo "NOT IN ufw status"; sudo ufw status >&2; exit 1; }
peer_can 8080 || { echo "8080 STILL BLOCKED"; exit 1; }
if sudo docker ps >/dev/null 2>&1; then peer_serve; docker_ok || { sudo nft list tables >&2; exit 1; }; echo "METRIC: docker still fine under ufw"; fi
echo "METRIC: ufw status after apply: $(sudo ufw status | tr '\n' '|' | cut -c1-200)"

sudo ibexctl rollback "$TX" --json >/dev/null
if sudo ufw status | grep -q '8080/tcp'; then echo "STILL IN ufw status AFTER ROLLBACK"; exit 1; fi
if peer_can 8080; then echo "8080 REACHABLE AFTER ROLLBACK"; exit 1; fi
[ "$(sudo sha256sum /etc/ufw/user.rules | cut -d' ' -f1)" = "$BEFORE4" ] || { echo "user.rules NOT RESTORED"; exit 1; }
[ "$(sudo sha256sum /etc/ufw/user6.rules | cut -d' ' -f1)" = "$BEFORE6" ] || { echo "user6.rules NOT RESTORED"; exit 1; }
"#
        )
    );

    if failures == 0 {
        println!("PASS: f5 (all scenarios)");
        Ok(())
    } else {
        anyhow::bail!("{failures} f5 scenario(s) failed")
    }
}
