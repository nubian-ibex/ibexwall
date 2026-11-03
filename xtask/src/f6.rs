// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F6 VM phase: per-app enforcement. First the verdict maps and a real
//! block; the Ask mechanics land with the S6-a spike.

use std::path::Path;

use anyhow::Result;

use super::f1::install_binary;
use super::vm::{Vm, run_capture};

pub fn run(vm: &Vm, workspace: &Path) -> Result<()> {
    println!("== f6: build ==");
    run_capture(
        "cargo",
        ["build", "--release", "-p", "ibexwall-ebpf-loader"],
        None,
        "building the loader",
    )?;
    crate::ebpf::run()?;
    install_binary(
        vm,
        &workspace.join("target/release/ibexwall-ebpf-loader"),
        "/usr/bin/ibexwall-ebpf-loader",
    )?;
    vm.ssh("sudo mkdir -p /usr/lib/ibexwall/ebpf")?;
    super::f1::pipe_file(
        vm,
        &workspace.join("target/bpf/ibexwall-ebpf.o"),
        "sudo tee /usr/lib/ibexwall/ebpf/ibexwall-ebpf.o >/dev/null",
    )?;

    let mut failures = 0;
    macro_rules! scenario {
        ($name:expr, $script:expr) => {
            if !super::f1::run_script(vm, $name, $script) {
                failures += 1;
            }
        };
    }

    scenario!(
        "v0 a blocked program cannot connect, everything else still can",
        r#"
set -e
sudo tee /tmp/rules.json >/dev/null <<'EOF'
[
  {"exe_prefix": "/usr/bin/curl", "verdict": "block"},
  {"cgroup_prefix": "/system.slice/ibx-victim.service", "verdict": "block"},
  {"exe_prefix": "/tmp/blocked/", "verdict": "block"}
]
EOF
sudo sh -c 'nohup /usr/bin/ibexwall-ebpf-loader --rules /tmp/rules.json >/tmp/f6.json 2>/tmp/f6.err & echo $! >/tmp/f6.pid'
sleep 2
sudo kill -0 $(cat /tmp/f6.pid) || { echo "LOADER DIED"; cat /tmp/f6.err; exit 1; }

can() {
  timeout 6 "$@" >/dev/null 2>&1
}

# The blocked program: TCP to a real peer, and its own report says the
# connection failed (EPERM, not a timeout).
if can curl -s -o /dev/null http://10.0.2.3:53/; then echo "BLOCKED CURL CONNECTED (TCP)"; exit 1; fi
START=$(date +%s%N)
RC=0; curl -sS -o /dev/null http://10.0.2.3:53/ 2>/tmp/curl.err || RC=$?
MS=$(( ($(date +%s%N) - START) / 1000000 ))
# Blocked means refused at once (curl exit 7 in well under a second), not a
# timeout and not a reply.
[ "$RC" = 7 ] && [ "$MS" -lt 1500 ] || { echo "curl: rc=$RC in ${MS} ms: $(cat /tmp/curl.err)"; exit 1; }

# UDP too: a DNS lookup that must fail fast with EPERM.
if can getent hosts blocked.example.test; then echo "BLOCKED CURL GOT DNS (UDP)"; exit 1; fi

# A blocked systemd unit (cgroup rule).
sudo systemd-run --quiet --wait --unit=ibx-victim curl -s -o /dev/null --max-time 3 http://10.0.2.3:53/ && { echo "BLOCKED SERVICE CONNECTED"; exit 1; } || true

# A copy of python under a path the rule covers: TCP and UDP (with and
# without connect, the QUIC path), over IPv4 and IPv6, all refused; the
# original python still works on the same sockets.
sudo mkdir -p /tmp/blocked
PY=$(readlink -f $(command -v python3))
sudo cp "$PY" /tmp/blocked/python3
sudo chmod 755 /tmp/blocked/python3
cat > /tmp/probe.py <<'EOF'
import socket, sys
results = {}
def attempt(name, family, kind, connect_first, addr):
    s = socket.socket(family, kind)
    s.settimeout(3)
    try:
        if kind == socket.SOCK_STREAM or connect_first:
            s.connect(addr)
        else:
            s.sendto(b"x", addr)
        results[name] = "ok"
    except PermissionError:
        results[name] = "EPERM"
    except OSError:
        results[name] = "other"   # refused, unreachable: not a verdict
v4, v6 = ("10.0.2.3", 53), ("2001:db8::1", 53, 0, 0)
attempt("tcp4", socket.AF_INET, socket.SOCK_STREAM, True, v4)
attempt("udp4-connect", socket.AF_INET, socket.SOCK_DGRAM, True, v4)
attempt("udp4-sendto", socket.AF_INET, socket.SOCK_DGRAM, False, v4)
attempt("udp4-quic", socket.AF_INET, socket.SOCK_DGRAM, False, ("10.0.2.3", 443))
attempt("tcp6", socket.AF_INET6, socket.SOCK_STREAM, True, v6)
attempt("udp6-sendto", socket.AF_INET6, socket.SOCK_DGRAM, False, v6)
print(" ".join(f"{k}={v}" for k, v in results.items()))
EOF
BLOCKED=$(/tmp/blocked/python3 /tmp/probe.py)
echo "METRIC: blocked copy: $BLOCKED"
for k in tcp4 udp4-connect udp4-sendto udp4-quic tcp6 udp6-sendto; do
  echo "$BLOCKED" | grep -q "$k=EPERM" || { echo "NOT REFUSED: $k ($BLOCKED)"; exit 1; }
done
OPEN=$(python3 /tmp/probe.py)
echo "$OPEN" | grep -q EPERM && { echo "THE ORIGINAL PYTHON WAS BLOCKED TOO: $OPEN"; exit 1; }

# Everyone else still can: another program, the resolver, IPv6.
python3 - <<'EOF'
import socket
s = socket.socket(); s.settimeout(5)
s.connect(("10.0.2.3", 53))  # refused is fine: the point is no EPERM
EOF
getent hosts fedoraproject.org >/dev/null
python3 - <<'EOF'
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(5)
try: s.connect(("2001:db8::1", 9))
except PermissionError: raise SystemExit("IPv6 was blocked for everyone")
except OSError: pass
EOF

# A rule file with an unknown verdict is refused before anything loads.
echo '[{"exe_prefix": "/x", "verdict": "maybe"}]' > /tmp/bad.json
if /usr/bin/ibexwall-ebpf-loader --rules /tmp/bad.json >/dev/null 2>&1; then echo "BAD VERDICT ACCEPTED"; exit 1; fi

sudo kill $(cat /tmp/f6.pid)
sleep 1
"#
    );

    scenario!(
        "v1 stopping the monitor leaves the network open",
        r#"
set -e
# No rules: just the monitor running.
sudo sh -c 'nohup /usr/bin/ibexwall-ebpf-loader >/tmp/f6b.json 2>/dev/null & echo $! >/tmp/f6b.pid'
sleep 2
sudo kill $(cat /tmp/f6b.pid)
sleep 2
# The links die with the loader; whatever comes after must be able to
# connect, blocked program included.
curl -s -o /dev/null --max-time 5 http://10.0.2.3:53/ 2>/tmp/curl2.err || true
if grep -qi "permission denied\|operation not permitted" /tmp/curl2.err; then
  echo "NETWORK STILL BLOCKED AFTER THE MONITOR STOPPED"; cat /tmp/curl2.err; exit 1
fi
getent hosts fedoraproject.org >/dev/null || { echo "DNS BROKEN AFTER STOP"; exit 1; }
"#
    );

    scenario!(
        "a0 Ask: the first packet waits for the answer, then goes or is refused; no listener means open",
        r#"
set -e
command -v nft >/dev/null || { if command -v dnf >/dev/null; then sudo dnf install -y -q nftables; elif command -v apt-get >/dev/null; then sudo apt-get update -qq; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables; elif command -v pacman >/dev/null; then sudo pacman -Sy --noconfirm --needed nftables; fi; }
HOST_IP=$(ip -4 -o addr show scope global | awk 'NR==1{split($4,a,"/"); print a[1]}')
test -n "$HOST_IP" || { echo "no global IPv4"; exit 1; }
sudo nft delete table inet ibexwall_spike 2>/dev/null || true
sudo nft add table inet ibexwall_spike
sudo nft add chain inet ibexwall_spike ask '{ type filter hook output priority 5; policy accept; }'
sudo nft add rule inet ibexwall_spike ask ct state new meta mark and 0xff0000 == 0x10000 counter queue num 4242 bypass
# A queue verdict resumes at the next hook entry, not the next rule: the
# refusal lives in a chain that runs after the queue chain.
sudo nft add chain inet ibexwall_spike refuse '{ type filter hook output priority 6; policy accept; }'
sudo nft add rule inet ibexwall_spike refuse meta mark and 0xff0000 == 0x20000 counter reject
trap 'sudo nft delete table inet ibexwall_spike 2>/dev/null || true; sudo kill $(cat /tmp/ask.pid) 2>/dev/null || true; sudo pkill -x python3 2>/dev/null || true' EXIT

sudo mkdir -p /tmp/asked
PY=$(readlink -f $(command -v python3))
sudo cp "$PY" /tmp/asked/python3 && sudo chmod 755 /tmp/asked/python3
sudo tee /tmp/ask-rules.json >/dev/null <<'EOF'
[{"exe_prefix": "/tmp/asked/", "verdict": "ask"}]
EOF
sudo sh -c "nohup python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 &"
sleep 2
cat > /tmp/timed.py <<EOF
import socket, sys, time
t = time.monotonic()
s = socket.socket(); s.settimeout(8)
try:
    s.connect(("$HOST_IP", 8080)); out = "connected"
except ConnectionRefusedError:
    out = "refused"
except Exception as e:
    out = type(e).__name__
print(out, int((time.monotonic() - t) * 1000))
EOF
start_loader() {
  sudo kill $(cat /tmp/ask.pid) 2>/dev/null || true; sleep 1
  sudo sh -c "nohup /usr/bin/ibexwall-ebpf-loader --rules /tmp/ask-rules.json $* >/tmp/ask.out 2>/tmp/ask.err & echo \$! >/tmp/ask.pid"
  sleep 3
  sudo kill -0 $(cat /tmp/ask.pid) || { echo "LOADER DIED"; cat /tmp/ask.err; exit 1; }
}
ms() { echo "$1" | awk '{print $2}'; }

# Allowed after a 2 s wait: held, then the connection completes.
start_loader --ask-default allow --ask-delay-ms 2000
R=$(/tmp/asked/python3 /tmp/timed.py)
echo "METRIC: ask allow: $R"
echo "$R" | grep -q '^connected' || { echo "NOT CONNECTED AFTER ALLOW: $R"; cat /tmp/ask.err; exit 1; }
[ "$(ms "$R")" -ge 1800 ] && [ "$(ms "$R")" -lt 6000 ] || { echo "NOT HELD ABOUT 2 s: $R"; echo "-- loader:"; cat /tmp/ask.err; echo "-- chain:"; sudo nft list chain inet ibexwall_spike ask; exit 1; }
# Everything else is not asked and not slowed.
R=$(python3 /tmp/timed.py)
[ "$(ms "$R")" -lt 500 ] && echo "$R" | grep -q '^connected' || { echo "OTHER PROGRAM WAS SLOWED: $R"; exit 1; }

# Refused after a 1 s wait: reset, not a silent hang.
start_loader --ask-default block --ask-delay-ms 1000
R=$(/tmp/asked/python3 /tmp/timed.py)
echo "METRIC: ask block: $R"
echo "$R" | grep -q '^refused' || { echo "NOT REFUSED AFTER BLOCK: $R"; cat /tmp/ask.err; exit 1; }
[ "$(ms "$R")" -ge 900 ] && [ "$(ms "$R")" -lt 4000 ] || { echo "REFUSAL TIMING WRONG: $R"; exit 1; }
grep -q '"decision":"block"' /tmp/ask.err || { echo "NO ASK EVENT LOGGED"; cat /tmp/ask.err; exit 1; }

# Nobody listening on the queue: the kernel accepts (bypass), at once.
start_loader --ask-disabled
R=$(/tmp/asked/python3 /tmp/timed.py)
echo "METRIC: ask without a listener: $R"
echo "$R" | grep -q '^connected' && [ "$(ms "$R")" -lt 500 ] || { echo "FAIL-OPEN BROKEN: $R"; exit 1; }
"#
    );

    if failures == 0 {
        println!("PASS: f6 (all scenarios)");
        Ok(())
    } else {
        anyhow::bail!("{failures} f6 scenario(s) failed")
    }
}
