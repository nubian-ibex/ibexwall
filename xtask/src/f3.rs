// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F3 VM phase: the secure DNS stack on a real systemd-resolved machine.
//! Real resolver, real encrypted upstream (Quad9 over DoT), real packet
//! capture, real kill and rollback. Needs outbound network in the VM.

use std::path::Path;

use anyhow::Result;

use super::f1::{
    install_binary, install_plugin, pipe_data, pipe_file, provision, run_script, start_daemon,
};
use super::vm::{Vm, run_capture};

/// Reads the transaction or plan id out of `ibexctl --json` output.
const JSON_ID: &str = "python3 -c 'import json,sys;d=json.JSONDecoder().raw_decode(sys.stdin.read())[0];t=d.get(\"plan\") or d.get(\"transaction\");print(t[\"id\"] if isinstance(t,dict) else t)'";

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== f3: build ==");
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
            "-p",
            "ibexwall-dns",
            "--bins",
            "--examples",
        ],
        None,
        "building release binaries",
    )?;
    crate::devkey::run()?;
    provision(vm, workspace, install)?;
    install_plugin(vm, workspace, "net.dns")?;
    install_binary(
        vm,
        &workspace.join("target/release/ibexwall-dns"),
        "/usr/bin/ibexwall-dns",
    )?;
    pipe_file(
        vm,
        &workspace.join("target/release/examples/bench"),
        "sudo tee /usr/bin/ibexwall-dns-bench >/dev/null && sudo chmod 755 /usr/bin/ibexwall-dns-bench",
    )?;
    for (data, target) in [
        (
            include_str!("../../packaging/systemd/ibexwall-dns.service"),
            "/etc/systemd/system/ibexwall-dns.service",
        ),
        (
            include_str!("../../packaging/systemd/ibexwall-dns-failsafe.service"),
            "/etc/systemd/system/ibexwall-dns-failsafe.service",
        ),
        (
            include_str!("../../packaging/sysusers.d/ibexwall-dns.conf"),
            "/usr/lib/sysusers.d/ibexwall-dns.conf",
        ),
        (
            include_str!("../../packaging/tmpfiles.d/ibexwall.conf"),
            "/usr/lib/tmpfiles.d/ibexwall.conf",
        ),
    ] {
        pipe_data(vm, data, &format!("sudo tee {target} >/dev/null"))?;
    }
    // The user must exist before tmpfiles can own its directories.
    vm.ssh("sudo systemd-sysusers /usr/lib/sysusers.d/ibexwall-dns.conf")?;
    vm.ssh("sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/ibexwall.conf")?;
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
        "d0 resolved stack, tools and baseline",
        r#"
set -e
if [ ! -e /usr/lib/systemd/system/systemd-resolved.service ] && [ ! -e /lib/systemd/system/systemd-resolved.service ]; then
  if command -v apt-get >/dev/null; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq systemd-resolved
  fi
fi
if ! command -v nft >/dev/null; then
  if command -v dnf >/dev/null; then sudo dnf install -y -q nftables
  elif command -v apt-get >/dev/null; then sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq nftables
  elif command -v pacman >/dev/null; then sudo pacman -S --noconfirm --needed nftables
  fi
fi
if ! command -v tcpdump >/dev/null; then
  if command -v dnf >/dev/null; then sudo dnf install -y -q tcpdump
  elif command -v apt-get >/dev/null; then sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq tcpdump
  elif command -v pacman >/dev/null; then sudo pacman -S --noconfirm --needed tcpdump
  fi
fi
sudo systemctl enable --now systemd-resolved
sudo ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
for i in 1 2 3 4 5 6 7 8 9 10; do getent hosts example.com >/dev/null && break; sleep 1; done
getent hosts example.com
sudo mkdir -p /etc/systemd/resolved.conf.d
sudo sh -c 'cat /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/* 2>/dev/null | sha256sum' > /tmp/ibx-dns-baseline
cat /tmp/ibx-dns-baseline
sudo nft list ruleset | sha256sum > /tmp/ibx-nft-baseline
"#
    );

    scenario!(
        "d0b net.dns says how DNS works today, as information, before anything changes",
        r#"
sudo ibexctl plugins enable net.dns >/dev/null
sudo ibexctl check net.dns --json >/tmp/detect-dns.json 2>&1 || true
python3 - <<'PYEOF'
import json
d = json.JSONDecoder().raw_decode(open("/tmp/detect-dns.json").read())[0]
notes = [x for x in d["findings"] if x["id"] == "detect.dns"]
assert len(notes) == 1, [x["id"] for x in d["findings"]]
n = notes[0]
assert n["severity"] == "info", n
case = n["args"]["case"]
assert case in ("resolved-plain", "resolved-tls"), n["args"]
assert n["args"]["stack"] == "systemd-resolved", n["args"]
assert ("patch" in n["args"]) == (case == "resolved-plain"), n["args"]
if case == "resolved-plain":
    assert json.loads(n["args"]["patch"])["transport"] == "tls"
print("METRIC: detect.dns says", case)
PYEOF
"#
    );

    scenario!(
        "d0c a running dnscrypt-proxy is recognised: no change is offered and the check passes",
        r#"
set -e
if command -v dnf >/dev/null; then sudo dnf install -y -q dnscrypt-proxy >/dev/null
elif command -v apt-get >/dev/null; then sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq dnscrypt-proxy >/dev/null
else sudo pacman -S --noconfirm --needed dnscrypt-proxy >/dev/null; fi
CONF=/etc/dnscrypt-proxy/dnscrypt-proxy.toml
sudo test -f $CONF || { echo "NO CONFIG AT $CONF"; exit 1; }
# A self-contained setup (one static resolver, no list to download, no probe
# of the network) so the proxy starts the same way on every distribution and
# sends no clear DNS of its own. Where the package starts it by its socket
# (Debian, Ubuntu, Arch), that is how it runs here, and the system resolver
# is pointed at the socket's address.
sudo cp $CONF /tmp/dnscrypt-proxy.toml.orig
SOCKET_ADDR=$(systemctl show dnscrypt-proxy.socket -p Listen --value 2>/dev/null | head -1 | sed -E 's/ \(.*//')
if [ -n "$SOCKET_ADDR" ]; then LISTEN="[]"; ADDR=${SOCKET_ADDR%:*}; else LISTEN="['127.0.0.1:53']"; ADDR=127.0.0.1; fi
sudo tee $CONF >/dev/null <<TOMLEOF
listen_addresses = $LISTEN
server_names = ['cf']
ignore_system_dns = true
netprobe_timeout = -1
require_dnssec = true
require_nolog = true
require_nofilter = true
[static.'cf']
stamp = 'sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5'
TOMLEOF
if [ -n "$SOCKET_ADDR" ]; then
  sudo systemctl stop dnscrypt-proxy.service
  sudo systemctl enable --now dnscrypt-proxy.socket >/dev/null 2>&1
  # A first query starts the proxy through its socket.
  python3 - "$ADDR" <<'PYEOF' || true
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
try:
    s.sendto(q, (sys.argv[1], 53))
    s.recv(512)
except OSError:
    pass
PYEOF
else
  sudo systemctl restart dnscrypt-proxy.service
fi
sleep 4
systemctl is-active --quiet dnscrypt-proxy.service || systemctl is-active --quiet dnscrypt-proxy.socket || { echo "dnscrypt-proxy DID NOT STAY UP"; systemctl status dnscrypt-proxy.service --no-pager | head -8; sudo journalctl -u dnscrypt-proxy -n 12 --no-pager | cut -c1-200; exit 1; }
sudo mkdir -p /etc/systemd/resolved.conf.d
printf "[Resolve]\nDNS=$ADDR\nDomains=~.\n" | sudo tee /etc/systemd/resolved.conf.d/90-test-dnscrypt.conf >/dev/null
sudo systemctl restart systemd-resolved
cleanup() {
  sudo rm -f /etc/systemd/resolved.conf.d/90-test-dnscrypt.conf
  sudo systemctl restart systemd-resolved
  sudo systemctl disable --now dnscrypt-proxy.service dnscrypt-proxy.socket >/dev/null 2>&1 || true
  sudo cp /tmp/dnscrypt-proxy.toml.orig $CONF
}
trap cleanup EXIT
sudo ibexctl plugins enable net.dns >/dev/null
sudo ibexctl check net.dns --json >/tmp/detect-proxy.json 2>&1 || true
python3 - <<'PYEOF'
import json
d = json.JSONDecoder().raw_decode(open("/tmp/detect-proxy.json").read())[0]
n = [x for x in d["findings"] if x["id"] == "detect.dns"]
assert len(n) == 1, [x["id"] for x in d["findings"]]
a = n[0]["args"]
assert a["case"] == "proxy", a
assert a["proxy"] == "dnscrypt-proxy" and "patch" not in a, a
assert "dns.secure_resolver" not in [x["id"] for x in d["findings"]], d["findings"]
print("METRIC: dnscrypt-proxy recognised, resolvers", a["resolvers"])
PYEOF
if sudo ibexctl plan net.dns --set provider=quad9 --set transport=tls --json >/tmp/plan-proxy.json 2>&1; then
  echo "A PLAN WAS OFFERED OVER DNSCRYPT"; cat /tmp/plan-proxy.json; exit 1
fi
grep -q dnscrypt-proxy /tmp/plan-proxy.json || { echo "THE REFUSAL DOES NOT NAME THE PROXY"; cat /tmp/plan-proxy.json; exit 1; }
echo "METRIC: a plan over dnscrypt-proxy is refused with a reason"
"#
    );

    scenario!(
        "d1 plan and apply: resolver up, resolved points at it",
        &format!(
            r#"
set -e
sudo ibexctl plugins enable net.dns
P=$(sudo ibexctl plan net.dns --set provider=quad9 --set transport=tls --json | {JSON_ID})
OUT=$(sudo ibexctl apply $P --confirm-timeout 300 --json 2>/dev/null || true)
echo "$OUT" | grep -q pending_confirm || {{ echo "APPLY FAILED: $OUT" >&2; sudo journalctl -u ibexwalld -u ibexwall-dns -n 25 --no-pager >&2; exit 1; }}
TX=$(echo "$OUT" | {JSON_ID})
echo "$TX" > /tmp/ibx-dns-tx
systemctl is-active --quiet ibexwall-dns
for i in 1 2 3 4 5 6 7 8 9 10; do getent hosts example.com >/dev/null && break; sleep 1; done
getent hosts example.com
resolvectl status | grep -q 127.0.0.153
sudo ibexctl confirm "$TX"
sudo cat /etc/systemd/resolved.conf.d/50-ibexwall.conf
"#
        )
    );

    scenario!(
        "d2 no clear DNS leaves the machine; the upstream is encrypted",
        r#"
set -e
sudo rm -f /tmp/ibx-dns.txt
( sudo timeout -s INT 14 tcpdump -i any -nn -l 'port 53 or port 853' > /tmp/ibx-dns.txt 2>/dev/null & )
sleep 3
for n in wikipedia.org debian.org kernel.org archlinux.org fedoraproject.org gnu.org; do getent hosts $n >/dev/null || true; done
sleep 12
echo "captured lines: $(wc -l < /tmp/ibx-dns.txt)"
# Anything that is not loopback and not the encrypted port is clear DNS.
PKTS=$(grep -E '^[0-9][0-9:.]+ ' /tmp/ibx-dns.txt)
LEAK=$(echo "$PKTS" | grep -Ev '127\.0\.0\.|\.853[: ]|\.853$' | grep -c . || true)
echo "clear DNS lines: $LEAK"
if [ "$LEAK" -ne 0 ]; then echo "$PKTS" | grep -Ev '127\.0\.0\.|\.853[: ]|\.853$' | head -6; resolvectl status | head -30; fi
[ "$LEAK" -eq 0 ]
echo "$PKTS" | grep -Eq '\.853[: ]|\.853$'
"#
    );

    scenario!(
        "d2b clear DNS and DoT are refused for everyone but the resolver",
        r#"
set -e
python3 - <<'EOF'
import socket
QUERY = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
def refused(kind, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if kind == "udp" else socket.SOCK_STREAM)
    sock.settimeout(4)
    try:
        sock.connect(("9.9.9.9", port))
        if kind == "udp":
            sock.send(QUERY)
            sock.recv(512)
        return False
    except (ConnectionRefusedError, PermissionError):
        # Refused by the local output hook: TCP sees ECONNREFUSED, UDP EPERM.
        return True
    except OSError as error:
        print("unexpected", kind, port, error)
        return False
results = {(k, p): refused(k, p) for k in ("udp", "tcp") for p in (53, 853)}
print(results)
assert all(results.values()), results
EOF
sudo python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(4)
try:
    s.connect(("9.9.9.9", 53))
except ConnectionRefusedError:
    sys.exit(0)
sys.exit(1)'
getent hosts example.com >/dev/null
sudo nft list chain inet ibexwall net_dns_guard
"#
    );

    scenario!(
        "d3 the Firefox DoH canary answers NXDOMAIN",
        r#"
set -e
OUT=$(resolvectl query use-application-dns.net 2>&1 || true)
echo "$OUT"
echo "$OUT" | grep -Eqi 'not found|nxdomain|no such name'
! getent hosts use-application-dns.net
getent hosts example.com >/dev/null
"#
    );

    scenario!(
        "d3b known DoH endpoints stop resolving once the list loads",
        r#"
set -e
# The endpoints list downloads shortly after the resolver starts.
for i in $(seq 1 40); do
  OUT=$(resolvectl query dns.google 2>&1 || true)
  echo "$OUT" | grep -Eqi 'not found|nxdomain|no such name' && break
  sleep 3
done
echo "$OUT"
echo "$OUT" | grep -Eqi 'not found|nxdomain|no such name' || { sudo journalctl -u ibexwall-dns -n 25 --no-pager >&2; sudo ls -la /var/lib/ibexwall/blocklists >&2; sudo cat /etc/ibexwall/dns/resolver.json >&2; exit 1; }
! getent hosts dns.google
getent hosts example.com >/dev/null
sudo cat /run/ibexwall/dns/status.json
"#
    );

    scenario!(
        "d8 latency: warm p99 within 2 ms and cold overhead within 5 ms",
        r#"
set -e
WARM=$(ibexwall-dns-bench warm 300)
echo "warm p50/p99: $WARM"
P99=$(echo "$WARM" | cut -d' ' -f2)
python3 -c "raise SystemExit(0 if $P99 <= 2.0 else 1)"
COLD=$(ibexwall-dns-bench cold 150)
# Direct DoT is only allowed for the resolver user (that is the point of
# the enforcement); measure from inside that exemption.
DIRECT=$(sudo -u ibexwall-dns ibexwall-dns-bench direct 9.9.9.9 dns.quad9.net 150)
echo "cold p50/p99: $COLD  direct p50/p99: $DIRECT"
python3 - <<EOF
cold = float("$COLD".split()[1])
direct = float("$DIRECT".split()[1])
overhead = cold - direct
print(f"uncached overhead: {overhead:.3f} ms")
raise SystemExit(0 if overhead <= 5.0 else 1)
EOF
"#
    );

    scenario!(
        "d9 browser policy files are written and rolled back",
        &format!(
            r#"
set -e
# A stand-in browser: what is tested is IbexWall's own file handling. The
# machine is not assumed clean: the change must restore exactly what was
# there before, whatever that was.
sudo touch /usr/bin/brave-browser && sudo chmod 755 /usr/bin/brave-browser
BEFORE=$(sudo sh -c 'cat /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/* 2>/dev/null | sha256sum')
EB=$(systemctl is-enabled ibexwall-dns 2>&1 || true)
AB=$(systemctl is-active ibexwall-dns 2>&1 || true)
P=$(sudo ibexctl plan net.dns --set provider=quad9 --set transport=tls --set browser_policies=true --json 2>&1 | tee /dev/stderr | {JSON_ID}) || {{ echo "PLAN FAILED"; exit 1; }}
OUT=$(sudo ibexctl apply $P --confirm-timeout 300 --json 2>/dev/null || true)
echo "$OUT" | grep -q pending_confirm || {{ echo "APPLY OUTPUT: $OUT"; exit 1; }}
TX=$(echo "$OUT" | {JSON_ID})
sudo ibexctl confirm "$TX"
sudo test -f /etc/brave/policies/managed/ibexwall-dns.json
sudo python3 -c 'import json,sys; d=json.load(open("/etc/brave/policies/managed/ibexwall-dns.json")); sys.exit(0 if d == {{"DnsOverHttpsMode": "off"}} else 1)' || {{ echo "WRONG POLICY CONTENT"; sudo cat /etc/brave/policies/managed/ibexwall-dns.json >&2; exit 1; }}
sudo ibexctl rollback "$TX" --json >/dev/null || {{ echo "ROLLBACK FAILED"; exit 1; }}
sudo test ! -e /etc/brave/policies/managed/ibexwall-dns.json || {{ echo "POLICY FILE SURVIVED ROLLBACK"; exit 1; }}
AFTER=$(sudo sh -c 'cat /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/* 2>/dev/null | sha256sum')
[ "$AFTER" = "$BEFORE" ] || {{ echo "RESOLVED CONFIG CHANGED: $AFTER vs $BEFORE"; exit 1; }}
EA=$(systemctl is-enabled ibexwall-dns 2>&1 || true)
AA=$(systemctl is-active ibexwall-dns 2>&1 || true)
[ "$EA" = "$EB" ] || {{ echo "UNIT ENABLED CHANGED: $EA vs $EB"; exit 1; }}
[ "$AA" = "$AB" ] || {{ echo "UNIT ACTIVE CHANGED: $AA vs $AB"; exit 1; }}
sudo rm -f /usr/bin/brave-browser
"#
        )
    );

    scenario!(
        "d4 killing the resolver once recovers on its own",
        r#"
set -e
sudo systemctl kill --kill-whom=main -s KILL ibexwall-dns.service
for i in $(seq 1 20); do systemctl is-active --quiet ibexwall-dns && break; sleep 1; done
systemctl is-active --quiet ibexwall-dns
for i in $(seq 1 15); do getent hosts example.com >/dev/null && break; sleep 1; done
getent hosts example.com
"#
    );

    scenario!(
        "d5 a resolver that cannot stay up triggers the failsafe",
        r#"
set -e
for i in 1 2 3 4 5 6; do
  for w in $(seq 1 6); do systemctl is-active --quiet ibexwall-dns && break; sleep 1; done
  sudo systemctl kill --kill-whom=main -s KILL ibexwall-dns.service 2>/dev/null || true
  sleep 0.3
done
for i in $(seq 1 40); do [ ! -e /etc/systemd/resolved.conf.d/50-ibexwall.conf ] && break; sleep 1; done
[ ! -e /etc/systemd/resolved.conf.d/50-ibexwall.conf ] || { sudo systemctl status ibexwall-dns ibexwall-dns-failsafe --no-pager >&2; exit 1; }
for i in $(seq 1 15); do getent hosts example.com >/dev/null && break; sleep 1; done
getent hosts example.com || { resolvectl status 2>&1 | head -20 >&2; resolvectl query example.com 2>&1 >&2 || true; sudo journalctl -u systemd-resolved -u ibexwall-dns-failsafe -n 20 --no-pager >&2; exit 1; }
! resolvectl status | grep -q 127.0.0.153
! sudo nft list chain inet ibexwall net_dns_guard 2>/dev/null
"#
    );

    scenario!(
        "d6 rollback after the failsafe restores the original files byte for byte",
        r#"
set -e
chk() { "$@" || { echo "CHECK FAILED: $*" >&2; exit 1; }; }
TX=$(cat /tmp/ibx-dns-tx)
sudo systemctl reset-failed ibexwall-dns.service 2>/dev/null || true
sudo ibexctl rollback "$TX" --json >/tmp/ibx-rb.out 2>/tmp/ibx-rb.err || { echo "ROLLBACK FAILED"; cat /tmp/ibx-rb.out /tmp/ibx-rb.err >&2; sudo journalctl -u ibexwalld -n 25 --no-pager >&2; exit 1; }
chk sudo test ! -e /etc/ibexwall/dns/resolver.json
chk sudo test ! -e /etc/systemd/resolved.conf.d/50-ibexwall.conf
STATE=$(systemctl is-enabled ibexwall-dns 2>&1 || true)
echo "unit state after rollback: $STATE" >&2
if [ "$STATE" = "enabled" ]; then sudo cat /var/lib/ibexwall/snapshots/$TX/manifest.json >&2; sudo journalctl -u ibexwalld -u ibexwall-exec-'*' -n 40 --no-pager >&2; ls -la /etc/systemd/system/multi-user.target.wants/ >&2; fi
chk [ "$STATE" != "enabled" ]
NOW=$(sudo sh -c 'cat /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/* 2>/dev/null | sha256sum')
echo "now=$NOW base=$(cat /tmp/ibx-dns-baseline)"
chk [ "$NOW" = "$(cat /tmp/ibx-dns-baseline)" ]
chk [ "$(sudo nft list ruleset | sha256sum)" = "$(cat /tmp/ibx-nft-baseline)" ]
for i in $(seq 1 15); do getent hosts example.com >/dev/null && break; sleep 1; done
chk getent hosts example.com
"#
    );

    scenario!(
        "d7 a fresh apply and rollback round trip is exact",
        &format!(
            r#"
set -e
sudo systemctl reset-failed ibexwall-dns.service 2>/dev/null || true
P=$(sudo ibexctl plan net.dns --set provider=cloudflare --set transport=https --set list=oisd-small --json 2>&1 | tee /dev/stderr | {JSON_ID}) || {{ echo "PLAN FAILED"; exit 1; }}
echo "plan id: $P" >&2
OUT=$(sudo ibexctl apply $P --confirm-timeout 300 --json 2>/dev/null || true)
TX=$(echo "$OUT" | {JSON_ID}) || {{ echo "APPLY OUTPUT: $OUT"; exit 1; }}
echo "tx: $TX" >&2
for i in 1 2 3 4 5 6 7 8 9 10; do getent hosts example.com >/dev/null && break; sleep 1; done
getent hosts example.com
sudo ibexctl confirm "$TX" || {{ echo "CONFIRM FAILED"; sudo ibexctl history --json | tail -5 >&2; exit 1; }}
sudo test -f /etc/systemd/resolved.conf.d/50-ibexwall.conf
# The chosen list must actually block: wait for the download, then probe.
BLOCKED=0
for i in $(seq 1 40); do
  if ! getent hosts ads.yahoo.com >/dev/null 2>&1; then BLOCKED=1; break; fi
  sleep 3
done
[ "$BLOCKED" -eq 1 ]
getent hosts example.com >/dev/null
sudo ibexctl rollback "$TX" --json >/dev/null || {{ echo "ROLLBACK FAILED"; sudo journalctl -u ibexwalld -n 15 --no-pager >&2; exit 1; }}
NOW=$(sudo sh -c 'cat /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/* 2>/dev/null | sha256sum')
[ "$NOW" = "$(cat /tmp/ibx-dns-baseline)" ]
[ "$(sudo nft list ruleset | sha256sum)" = "$(cat /tmp/ibx-nft-baseline)" ]
sudo test ! -e /etc/ibexwall/dns/resolver.json
STATE=$(systemctl is-enabled ibexwall-dns 2>&1 || true)
[ "$STATE" != "enabled" ] || {{ echo "unit still enabled after rollback" >&2; exit 1; }}
! systemctl is-active --quiet ibexwall-dns
for i in $(seq 1 15); do getent hosts example.com >/dev/null && break; sleep 1; done
getent hosts example.com
"#
        )
    );

    scenario!(
        "d10 on_failure=block fails closed and rolls back clean",
        &format!(
            r#"
set -e
P=$(sudo ibexctl plan net.dns --set provider=quad9 --set transport=tls --set on_failure=block --json 2>/dev/null | {JSON_ID})
OUT=$(sudo ibexctl apply $P --confirm-timeout 300 --json 2>/dev/null || true)
echo "$OUT" | grep -q pending_confirm || {{ echo "APPLY OUTPUT: $OUT"; exit 1; }}
TX=$(echo "$OUT" | {JSON_ID})
for i in $(seq 1 15); do getent hosts example.com >/dev/null && break; sleep 1; done
sudo ibexctl confirm "$TX"
sudo grep -q '"on_failure": "block"' /etc/ibexwall/dns/resolver.json || sudo grep -q '"on_failure":"block"' /etc/ibexwall/dns/resolver.json
# Kill until the failsafe runs: with block mode nothing is removed.
for i in 1 2 3 4 5 6; do
  for w in $(seq 1 6); do systemctl is-active --quiet ibexwall-dns && break; sleep 1; done
  sudo systemctl kill --kill-whom=main -s KILL ibexwall-dns.service 2>/dev/null || true
  sleep 0.3
done
for i in $(seq 1 40); do sudo test -f /etc/systemd/resolved.conf.d/50-ibexwall.conf || break; sleep 1; done
sudo test -f /etc/systemd/resolved.conf.d/50-ibexwall.conf
sudo nft list chain inet ibexwall net_dns_guard >/dev/null 2>&1
# Fail closed: no DNS while the resolver is down and enforcement stays.
if getent hosts example.com >/dev/null 2>&1; then echo "DNS STILL WORKS (expected fail closed)"; exit 1; fi
sudo systemctl reset-failed ibexwall-dns.service
sudo ibexctl rollback "$TX" --json >/dev/null
sudo test ! -e /etc/systemd/resolved.conf.d/50-ibexwall.conf
! sudo nft list chain inet ibexwall net_dns_guard 2>/dev/null
for i in $(seq 1 20); do getent hosts example.com >/dev/null && break; sleep 1; done
getent hosts example.com
"#
        )
    );

    // The corporate case: a local resolver for an internal zone (split DNS)
    // next to the encrypted default, and the person told about it.
    scenario!(
        "d11 a local resolver answers only its own zone; everything else stays encrypted; the plain upstream is announced",
        &r#"
set -e
sudo ip link add ibxdns0 type dummy 2>/dev/null || true
sudo ip addr add 10.77.0.2/24 dev ibxdns0 2>/dev/null || true
sudo ip link set ibxdns0 up
cat > /tmp/ibx-corp-dns.py <<'PYEOF'
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.77.0.2", 53))
log = open("/run/ibx-corp-dns.log", "a", buffering=1)
while True:
    data, addr = s.recvfrom(512)
    i = 12; labels = []
    while data[i]:
        labels.append(data[i+1:i+1+data[i]].decode()); i += data[i] + 1
    qtype = struct.unpack(">H", data[i+1:i+3])[0]
    log.write(".".join(labels) + "\n")
    question = data[12:i+5]
    if qtype == 1 and labels[-2:] == ["corp", "example"]:
        head = data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04\x0a\x09\x09\x09"
        s.sendto(head + question + answer, addr)
    else:
        s.sendto(data[:2] + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" + question, addr)
PYEOF
sudo rm -f /run/ibx-corp-dns.log
sudo python3 /tmp/ibx-corp-dns.py >/tmp/ibx-corp-dns.out 2>&1 &
STUB=$!
trap 'sudo kill $STUB 2>/dev/null || true; sudo ip link del ibxdns0 2>/dev/null || true' EXIT
sleep 1

P=$(sudo ibexctl plan net.dns --set provider=quad9 --set transport=tls --set 'routes=[{"domains":["corp.example"],"servers":[{"ip":"10.77.0.2","transport":"plain"}]}]' --json 2>/tmp/d11.err | @JSON_ID@) || { echo "PLAN FAILED: $(cat /tmp/d11.err)"; exit 1; }
OUT=$(sudo ibexctl apply $P --confirm-timeout 300 --json 2>/dev/null || true)
TX=$(echo "$OUT" | @JSON_ID@) || { echo "APPLY OUTPUT: $OUT"; exit 1; }
for i in $(seq 1 15); do getent hosts example.com >/dev/null && break; sleep 1; done
sudo ibexctl confirm "$TX" >/dev/null 2>&1 || true

# The internal zone is answered by the local server; the public name is not.
ANSWER=$(getent hosts git.corp.example | awk '{print $1}')
[ "$ANSWER" = 10.9.9.9 ] || { echo "SPLIT DNS DID NOT ANSWER: [$ANSWER]"; echo "--- stub log:"; sudo cat /run/ibx-corp-dns.log; echo "--- stub out:"; cat /tmp/ibx-corp-dns.out | tail -5; echo "--- resolver:"; sudo journalctl -u ibexwall-dns -n 8 --no-pager; echo "--- settings:"; sudo cat /etc/ibexwall/dns/resolver.json | head -c 600; echo; echo "--- direct:"; python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
q=bytes.fromhex('1234010000010000000000000367697404636f727007657861 6d706c6500000100 01'.replace(' ',''))
s.sendto(q,('10.77.0.2',53)); print(s.recvfrom(512)[0][:20].hex())" 2>&1 | tail -2; echo "--- via stub:"; getent hosts git.corp.example; dig +short @127.0.0.153 git.corp.example 2>&1 | head -3; exit 1; }
getent hosts example.com >/dev/null || { echo "THE ENCRYPTED DEFAULT DOES NOT ANSWER"; exit 1; }
if sudo grep -q '^example.com' /run/ibx-corp-dns.log; then echo "A PUBLIC NAME REACHED THE CORPORATE SERVER"; sudo cat /run/ibx-corp-dns.log; exit 1; fi
sudo grep -q '^git.corp.example' /run/ibx-corp-dns.log || { echo "THE CORPORATE SERVER WAS NOT ASKED"; exit 1; }
echo "METRIC: git.corp.example -> $ANSWER from the local server; example.com never reached it"
# The journal holds no query names: the resolver must not record browsing.
if sudo journalctl -u ibexwall-dns --no-pager | grep -qE 'corp\.example|example\.com'; then echo "QUERY NAMES ARE IN THE JOURNAL"; sudo journalctl -u ibexwall-dns --no-pager | grep -E 'corp\.example|example\.com' | head -3; exit 1; fi
echo "METRIC: no query name in the resolver's journal"

# The person is told that part of their DNS is unencrypted, and where.
sudo ibexctl check net.dns --json > /tmp/d11-check.json 2>/dev/null || true
python3 -c '
import json
f = {x["id"]: x for x in json.load(open("/tmp/d11-check.json"))["findings"]}
assert "dns.plain_upstream" in f, list(f)
assert f["dns.plain_upstream"]["args"]["servers"] == "10.77.0.2", f["dns.plain_upstream"]
assert f["dns.plain_upstream"]["severity"] == "info"
print("announced")'
echo "METRIC: the check announces the unencrypted local upstream (10.77.0.2) as information"

# Plain DNS to a public address is refused at plan time.
if sudo ibexctl plan net.dns --set 'servers=[{"ip":"8.8.8.8","transport":"plain"}]' --json >/dev/null 2>&1; then echo "PLAIN DNS TO A PUBLIC ADDRESS WAS PLANNED"; exit 1; fi

sudo ibexctl rollback "$TX" --json >/dev/null || { echo "ROLLBACK FAILED"; exit 1; }
sudo test ! -e /etc/ibexwall/dns/resolver.json
for i in $(seq 1 15); do getent hosts example.com >/dev/null && break; sleep 1; done
getent hosts example.com
"#.replace("@JSON_ID@", JSON_ID)
    );

    if failures == 0 {
        println!("PASS: f3 phase (all scenarios)");
        Ok(())
    } else {
        anyhow::bail!("{failures} f3 scenario(s) failed")
    }
}
