// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F6 VM phase: per-app enforcement. First the verdict maps and a real
//! block; the Ask mechanics land with the S6-a spike.

use std::path::Path;

use anyhow::Result;

use super::f1::{install_binary, provision, start_daemon};
use super::vm::{Vm, run_capture};

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== f6: build ==");
    run_capture(
        "cargo",
        [
            "build",
            "--release",
            "-p",
            "ibexwall-ebpf-loader",
            "-p",
            "ibexwall-core",
            "-p",
            "ibexwall-cli",
            "-p",
            "ibexwall-exec",
            "-p",
            "ibexwall-plugin-echo",
            "--bins",
        ],
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

    // From here on the whole stack: the packaged core and monitor unit,
    // with the modes chosen through ibexctl.
    crate::devkey::run()?;
    provision(vm, workspace, install)?;
    super::f1::pipe_file(
        vm,
        &workspace.join("packaging/systemd/ibexwall-monitor.service"),
        "sudo tee /etc/systemd/system/ibexwall-monitor.service >/dev/null",
    )?;
    start_daemon(vm)?;

    scenario!(
        "m3 a mode chosen with ibexctl is enforced, survives restarts, and fails open",
        r#"
set -e
sudo pkill -x python3 2>/dev/null || true
HOST_IP=$(ip -4 -o addr show scope global | awk 'NR==1{split($4,a,"/"); print a[1]}')
test -n "$HOST_IP" || { echo "no global IPv4"; exit 1; }
sudo sh -c "nohup python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 &"
trap 'sudo pkill -x python3 2>/dev/null || true' EXIT
sleep 2
URL=http://$HOST_IP:8080/
reach() { curl -s -o /dev/null --max-time 4 "$URL"; }
# Polls instead of sleeping: the policy travels core -> unit -> maps.
until_reach() { for i in $(seq 1 40); do reach && return 0; sleep 0.5; done; return 1; }
until_refused() { for i in $(seq 1 40); do reach || return 0; sleep 0.5; done; return 1; }

sudo systemctl start ibexwall-monitor.service
for i in $(seq 1 40); do
  sudo ibexctl apps list --json | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["monitor"]["running"] else 1)' && break
  sleep 0.5
done
reach || { echo "CURL FAILED BEFORE ANY RULE"; exit 1; }

# A service: matched by its cgroup, which every kernel can do. The unit
# exists before the rule (a cgroup created after it has a short grace).
sudo systemctl reset-failed ibx-m3 2>/dev/null || true
sudo systemd-run --quiet --unit=ibx-m3 sh -c "while true; do if curl -s -o /dev/null --max-time 2 $URL; then touch /tmp/m3.ok; else rm -f /tmp/m3.ok; fi; sleep 0.5; done"
trap 'sudo systemctl stop ibx-m3 2>/dev/null || true; sudo pkill -x python3 2>/dev/null || true' EXIT
for i in $(seq 1 40); do
  sudo ibexctl apps list | grep -q 'service:ibx-m3.service' && break
  sleep 0.5
done
sudo ibexctl apps list | grep -q 'service:ibx-m3.service' || { echo "SERVICE NEVER APPEARED"; sudo ibexctl apps list; exit 1; }
svc_works() { for i in $(seq 1 40); do [ -e /tmp/m3.ok ] && return 0; sleep 0.5; done; return 1; }
svc_stopped() { for i in $(seq 1 40); do [ ! -e /tmp/m3.ok ] && return 0; sleep 0.5; done; return 1; }
svc_works || { echo "SERVICE CURL FAILED BEFORE ANY RULE"; exit 1; }
sudo ibexctl apps set service:ibx-m3.service block
svc_stopped || { echo "SERVICE NOT BLOCKED"; sudo journalctl -u ibexwall-monitor -n 20 --no-pager; exit 1; }
reach || { echo "BLOCKING THE SERVICE BLOCKED OTHERS"; exit 1; }
echo "METRIC: service blocked through its cgroup, others unaffected"
sudo ibexctl apps set service:ibx-m3.service allow
svc_works || { echo "SERVICE NOT REOPENED"; exit 1; }

# Stopping the monitor leaves the network open; starting it again closes
# the service again, from the stored mode (fail open, then restored).
sudo ibexctl apps set service:ibx-m3.service block
svc_stopped || { echo "SERVICE NOT BLOCKED AGAIN"; exit 1; }
sudo systemctl stop ibexwall-monitor.service
svc_works || { echo "STOPPING THE MONITOR LEFT THE SERVICE BLOCKED"; exit 1; }
sudo systemctl start ibexwall-monitor.service
svc_stopped || { echo "BLOCK NOT RESTORED WHEN THE MONITOR CAME BACK"; exit 1; }
sudo ibexctl apps set service:ibx-m3.service allow
svc_works || { echo "SERVICE NOT REOPENED (2)"; exit 1; }
sudo systemctl stop ibx-m3

# A terminal program: matched by the executable path the kernel saw at
# exec. Needs the exec tracepoint, which some kernels (Debian's
# perf_event_paranoid=3) only give to CAP_SYS_ADMIN: then it is reported
# as unavailable, not silently skipped.
if sudo journalctl -u ibexwall-monitor --no-pager | grep -q 'degraded: kernel-side exec capture'; then
  echo "METRIC: exe rules unavailable on this kernel (reported as degraded)"
else
for i in $(seq 1 40); do
  sudo ibexctl apps list | grep -q 'cli:/usr/bin/curl' && break
  reach >/dev/null 2>&1 || true
  sleep 0.5
done
sudo ibexctl apps list | grep -q 'cli:/usr/bin/curl' || { echo "CURL NEVER APPEARED"; sudo ibexctl apps list; exit 1; }

# Block it: refused, the shown mode follows, others are untouched.
sudo ibexctl apps set cli:/usr/bin/curl block
until_refused || { echo "CURL NOT BLOCKED"; sudo journalctl -u ibexwall-monitor -n 20 --no-pager; exit 1; }
sudo ibexctl apps list | grep 'cli:/usr/bin/curl' | grep -q block || { echo "MODE NOT SHOWN"; sudo ibexctl apps list; exit 1; }
python3 -c "import urllib.request; urllib.request.urlopen('$URL', timeout=4)" || { echo "ANOTHER PROGRAM WAS BLOCKED"; exit 1; }
echo "METRIC: curl blocked through ibexctl, python unaffected"

# Back to allow: reachable again, with no restart.
sudo ibexctl apps set cli:/usr/bin/curl allow
until_reach || { echo "ALLOW DID NOT REOPEN"; exit 1; }

# The choice persists: restart the core, the unit reconnects and gets it.
sudo ibexctl apps set cli:/usr/bin/curl block
until_refused || { echo "NOT BLOCKED AGAIN"; exit 1; }
sudo systemctl restart ibexwalld.service
for i in $(seq 1 60); do sudo ibexctl status --json >/dev/null 2>&1 && break; sleep 0.5; done
# The old unit only notices the core is gone at its next write, then
# systemd restarts it (a short fail-open gap). Wait for the new
# connection, then the policy it receives must close curl again.
for i in $(seq 1 80); do
  sudo ibexctl apps list --json 2>/dev/null | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["monitor"]["running"] else 1)' && break
  reach >/dev/null 2>&1 || true
  sleep 0.5
done
until_refused || { echo "BLOCK LOST ACROSS A CORE RESTART"; sudo ibexctl apps list; sudo systemctl status ibexwall-monitor --no-pager | head -12; sudo journalctl -u ibexwall-monitor -n 15 --no-pager; sudo journalctl -u ibexwalld -n 15 --no-pager; exit 1; }
echo "METRIC: block survived a core restart"

fi

# An unknown mode is refused by the CLI, nothing changes.
if sudo ibexctl apps set service:ibx-m3.service deny >/dev/null 2>&1; then echo "BAD MODE ACCEPTED"; exit 1; fi
"#
    );

    scenario!(
        "m4 Ask holds a connection until it is answered, remembers, times out open, and fails open",
        r#"
set -e
HOST_IP=$(ip -4 -o addr show scope global | awk 'NR==1{split($4,a,"/"); print a[1]}')
sudo pkill -x python3 2>/dev/null || true
sudo sh -c "nohup python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 &"
sudo sh -c "nohup python3 -m http.server 8081 --bind 0.0.0.0 >/dev/null 2>&1 &"
trap 'sudo systemctl stop ibx-m4 2>/dev/null || true; sudo pkill -x python3 2>/dev/null || true' EXIT
sleep 2
sudo systemctl start ibexwall-monitor.service
echo "http://$HOST_IP:8080/" > /tmp/m4.url
cat > /tmp/m4.sh <<'EOF'
while true; do
  s=$(date +%s%N)
  curl -s -o /dev/null --max-time 90 "$(cat /tmp/m4.url)"
  rc=$?
  e=$(( ($(date +%s%N) - s) / 1000000 ))
  echo "$rc $e" >> /tmp/m4.log
  sleep 1
done
EOF
# Root appends to it: a file made by another user in /tmp is refused
# (fs.protected_regular), so root creates it.
sudo rm -f /tmp/m4.log; sudo sh -c ': > /tmp/m4.log'
# m3 left curl blocked by its path; the service under test uses curl too.
sudo ibexctl apps set cli:/usr/bin/curl allow >/dev/null 2>&1 || true
sudo systemctl reset-failed ibx-m4 2>/dev/null || true
sudo systemd-run --quiet --unit=ibx-m4 sh /tmp/m4.sh
APP=service:ibx-m4.service
for i in $(seq 1 60); do sudo ibexctl apps list | grep -q "$APP" && break; sleep 0.5; done
sudo ibexctl apps list | grep -q "$APP" || { echo "SERVICE NEVER APPEARED"; exit 1; }

lines() { wc -l < /tmp/m4.log; }
wait_lines() { for i in $(seq 1 $2); do [ "$(lines)" -ge "$1" ] && return 0; sleep 0.5; done; return 1; }
last_rc() { tail -n 1 /tmp/m4.log | cut -d' ' -f1; }
last_ms() { tail -n 1 /tmp/m4.log | cut -d' ' -f2; }
prompt_id() { sudo ibexctl prompts list --json | python3 -c 'import json,sys; p=json.load(sys.stdin)["prompts"]; print(p[0]["id"] if p else "")'; }
wait_prompt() { for i in $(seq 1 60); do id=$(prompt_id); if [ -n "$id" ]; then echo "$id"; return 0; fi; sleep 0.5; done; return 1; }
no_prompts() { [ -z "$(prompt_id)" ]; }
fail() { echo "$1"; echo "-- log:"; cat /tmp/m4.log; echo "-- prompts:"; sudo ibexctl prompts list; sudo journalctl -u ibexwall-monitor -n 15 --no-pager; echo "-- core:"; sudo journalctl -u ibexwalld -n 25 --no-pager; exit 1; }

wait_lines 2 20 || fail "SERVICE NEVER CONNECTED"
[ "$(last_rc)" = 0 ] || fail "SERVICE FAILED BEFORE ASK"

# Ask: the connection is held, not failed.
sudo ibexctl apps set $APP ask
ID=$(wait_prompt) || fail "NO QUESTION APPEARED"
sudo nft list chain inet ibexwall apps_ask >/dev/null || fail "ASK CHAIN MISSING"
N=$(lines)
sleep 2
[ "$(lines)" = "$N" ] || fail "THE CONNECTION WAS NOT HELD"
sudo ibexctl prompts answer $ID allow --scope once
wait_lines $((N + 1)) 20 || fail "ALLOW DID NOT RELEASE THE CONNECTION"
[ "$(last_rc)" = 0 ] && [ "$(last_ms)" -ge 1500 ] || fail "ALLOW: rc=$(last_rc) after $(last_ms) ms"
echo "METRIC: held then released: $(last_ms) ms"

# Block once: refused at once, and the next connection asks again.
ID=$(wait_prompt) || fail "NO SECOND QUESTION"
N=$(lines)
sudo ibexctl prompts answer $ID block --scope once
wait_lines $((N + 1)) 20 || fail "BLOCK DID NOT END THE CONNECTION"
[ "$(last_rc)" != 0 ] || fail "BLOCK LET IT THROUGH"
echo "METRIC: refused, curl exit $(last_rc)"

# Allow this destination: the next connection is not asked at all.
ID=$(wait_prompt) || fail "NO THIRD QUESTION"
N=$(lines)
sudo ibexctl prompts answer $ID allow --scope destination
wait_lines $((N + 1)) 20 || fail "DESTINATION ALLOW DID NOT RELEASE"
wait_lines $((N + 2)) 20 || fail "THE NEXT CONNECTION WAS HELD"
no_prompts || fail "A REMEMBERED DESTINATION ASKED AGAIN"
[ "$(last_rc)" = 0 ] && [ "$(last_ms)" -lt 1000 ] || fail "REMEMBERED: rc=$(last_rc) after $(last_ms) ms"

# Nobody answers: the fallback (open) applies after the timeout.
echo "http://$HOST_IP:8081/" > /tmp/m4.url
ID=$(wait_prompt) || fail "NO QUESTION FOR THE NEW DESTINATION"
N=$(lines)
wait_lines $((N + 1)) 100 || fail "THE UNANSWERED CONNECTION NEVER ENDED"
[ "$(last_rc)" = 0 ] || fail "TIMEOUT: rc=$(last_rc)"
[ "$(last_ms)" -ge 25000 ] && [ "$(last_ms)" -lt 45000 ] || fail "TIMEOUT AFTER $(last_ms) ms"
echo "METRIC: unanswered, released open after $(last_ms) ms"
# The loop asks again at once, as a new question; the old one is gone.
[ "$(prompt_id)" != "$ID" ] || fail "THE EXPIRED QUESTION IS STILL LISTED"

# Always block: the mode changes, no more questions, refused.
echo "http://$HOST_IP:8080/" > /tmp/m4.url
ID=$(wait_prompt) || true
if [ -n "$ID" ]; then sudo ibexctl prompts answer $ID block --scope always; else sudo ibexctl apps set $APP block; fi
sudo ibexctl apps list | grep "$APP" | grep -q block || fail "MODE NOT BLOCK"
N=$(lines)
wait_lines $((N + 2)) 40 || fail "NO CONNECTIONS AFTER BLOCK"
[ "$(last_rc)" != 0 ] || fail "ALWAYS BLOCK LET IT THROUGH"
no_prompts || fail "A BLOCKED APP ASKED"

# Back to allow: the Ask chains are gone (nothing is in Ask mode).
sudo ibexctl apps set $APP allow
for i in $(seq 1 20); do sudo nft list chain inet ibexwall apps_ask >/dev/null 2>&1 || break; sleep 0.5; done
if sudo nft list chain inet ibexwall apps_ask >/dev/null 2>&1; then fail "THE ASK CHAIN SURVIVED"; fi

# The daemon goes away while a connection is being asked: the network opens.
# (8080 is a remembered destination; 8081 is not.)
echo "http://$HOST_IP:8081/" > /tmp/m4.url
sudo ibexctl apps set $APP ask
ID=$(wait_prompt) || fail "NO QUESTION BEFORE STOPPING THE DAEMON"
N=$(lines)
sudo systemctl stop ibexwalld.service ibexwalld.socket
wait_lines $((N + 1)) 120 || fail "STOPPING THE DAEMON LEFT THE CONNECTION HELD"
[ "$(last_rc)" = 0 ] && [ "$(last_ms)" -lt 20000 ] || fail "AFTER THE DAEMON STOPPED: rc=$(last_rc) after $(last_ms) ms"
echo "METRIC: daemon stopped, connection completed after $(last_ms) ms"
"#
    );

    scenario!(
        "c0 Docker and Podman containers: blocked by mode, nobody else touched, foreign nft tables unchanged",
        r#"
set -e
install() {
  if command -v dnf >/dev/null; then sudo dnf install -y -q "$@"
  elif command -v apt-get >/dev/null; then sudo apt-get update -qq; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
  elif command -v pacman >/dev/null; then sudo pacman -Sy --noconfirm --needed "$@"
  fi
}
if ! getent hosts registry-1.docker.io >/dev/null; then
  sudo mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]
DNS=10.0.2.3
' | sudo tee /etc/systemd/resolved.conf.d/10-vm-upstream.conf >/dev/null
  sudo systemctl restart systemd-resolved
  sleep 2
fi
command -v podman >/dev/null || install podman
if ! command -v docker >/dev/null; then
  if command -v dnf >/dev/null; then install moby-engine || install docker
  elif command -v apt-get >/dev/null; then install docker.io
  elif command -v pacman >/dev/null; then install docker
  fi
fi
sudo systemctl enable --now docker
HOST_IP=$(ip -4 -o addr show scope global | awk 'NR==1{split($4,a,"/"); print a[1]}')
sudo pkill -x python3 2>/dev/null || true
sudo sh -c "nohup python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 &"
trap 'sudo docker rm -f ibx-d >/dev/null 2>&1 || true; sudo podman rm -f ibx-p >/dev/null 2>&1 || true; sudo pkill -x python3 2>/dev/null || true' EXIT
sleep 2
sudo systemctl start ibexwall-monitor.service
sudo ibexctl apps set cli:/usr/bin/curl allow >/dev/null 2>&1 || true

# Foreign tables, without counters and handles: the comparison that matters.
foreign() { sudo nft list ruleset | awk '/^table inet ibexwall /{skip=1} /^table /{ if ($0 !~ /^table inet ibexwall /) skip=0 } !skip' | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/; s/# handle [0-9]+//'; }

LOOP="while true; do if wget -q -T 3 -O /dev/null http://$HOST_IP:8080/; then touch /ok; else rm -f /ok; fi; sleep 1; done"
sudo docker rm -f ibx-d >/dev/null 2>&1 || true
sudo podman rm -f ibx-p >/dev/null 2>&1 || true
sudo docker run -d --name ibx-d docker.io/library/busybox sh -c "$LOOP" >/dev/null
sudo podman run -d --name ibx-p docker.io/library/busybox sh -c "$LOOP" >/dev/null
works() { sudo $1 exec $2 test -e /ok; }
until_works() { for i in $(seq 1 40); do works $1 $2 && return 0; sleep 0.5; done; return 1; }
until_stopped() { for i in $(seq 1 40); do works $1 $2 || return 0; sleep 0.5; done; return 1; }
until_works docker ibx-d || { echo "DOCKER CONTAINER CANNOT REACH THE HOST"; exit 1; }
until_works podman ibx-p || { echo "PODMAN CONTAINER CANNOT REACH THE HOST"; exit 1; }
for i in $(seq 1 60); do
  [ "$(sudo ibexctl apps list | grep -c '^container:')" -ge 2 ] && break
  sleep 0.5
done
APPS=$(sudo ibexctl apps list | grep '^container:' | awk '{print $1}')
[ "$(echo "$APPS" | wc -l)" -ge 2 ] || { echo "CONTAINERS NOT ATTRIBUTED"; sudo ibexctl apps list; exit 1; }
BEFORE=$(foreign)
echo "METRIC: foreign tables: $(sudo nft list tables | grep -v ibexwall | tr '
' ',' | cut -c1-100)"

# The id of each container as the monitor names it (its identity already
# starts with `container:`, and the app key adds the kind in front).
DID=container:container:$(sudo docker inspect -f '{{.Id}}' ibx-d | cut -c1-12)
PID=container:container:$(sudo podman inspect -f '{{.Id}}' ibx-p | cut -c1-12)
echo "$APPS" | grep -qx "$DID" || { echo "DOCKER CONTAINER NOT NAMED $DID"; echo "$APPS"; exit 1; }
echo "$APPS" | grep -qx "$PID" || { echo "PODMAN CONTAINER NOT NAMED $PID"; echo "$APPS"; exit 1; }

# Block one; the other keeps working.
sudo ibexctl apps set "$DID" block
until_stopped docker ibx-d || { echo "DOCKER CONTAINER NOT BLOCKED"; exit 1; }
works podman ibx-p || { echo "BLOCKING DOCKER'S CONTAINER BLOCKED PODMAN'S"; exit 1; }
sudo ibexctl apps set "$DID" allow
until_works docker ibx-d || { echo "DOCKER CONTAINER NOT REOPENED"; exit 1; }
sudo ibexctl apps set "$PID" block
until_stopped podman ibx-p || { echo "PODMAN CONTAINER NOT BLOCKED"; exit 1; }
works docker ibx-d || { echo "BLOCKING PODMAN'S CONTAINER BLOCKED DOCKER'S"; exit 1; }
echo "METRIC: a container is blocked, the other runtime's is not"
sudo ibexctl apps set "$PID" allow
until_works podman ibx-p || { echo "PODMAN CONTAINER NOT REOPENED"; exit 1; }

# Ask for a service puts our chains in place; nothing foreign changes.
sudo systemctl reset-failed ibx-c0 2>/dev/null || true
sudo systemd-run --quiet --unit=ibx-c0 sh -c "while true; do curl -s -o /dev/null --max-time 2 http://$HOST_IP:8080/; sleep 1; done"
for i in $(seq 1 40); do sudo ibexctl apps list | grep -q 'service:ibx-c0.service' && break; sleep 0.5; done
sudo ibexctl apps set service:ibx-c0.service ask
for i in $(seq 1 20); do sudo nft list chain inet ibexwall apps_ask >/dev/null 2>&1 && break; sleep 0.5; done
sudo nft list chain inet ibexwall apps_ask >/dev/null || { echo "ASK CHAIN MISSING"; exit 1; }
works docker ibx-d && works podman ibx-p || { echo "THE ASK CHAIN BROKE A CONTAINER"; exit 1; }
sudo ibexctl apps set service:ibx-c0.service allow
sudo systemctl stop ibx-c0
for i in $(seq 1 20); do sudo nft list chain inet ibexwall apps_ask >/dev/null 2>&1 || break; sleep 0.5; done
AFTER=$(foreign)
[ "$BEFORE" = "$AFTER" ] || { echo "FOREIGN NFT TABLES CHANGED"; diff <(echo "$BEFORE") <(echo "$AFTER") | head -20; exit 1; }
works docker ibx-d && works podman ibx-p || { echo "A CONTAINER LOST ITS NETWORK"; exit 1; }
echo "METRIC: foreign nftables untouched, both runtimes fine"
"#
    );

    scenario!(
        "p0 performance: 5000 connections a second are all counted, the core stays small and cheap",
        r#"
set -e
HOST_IP=$(ip -4 -o addr show scope global | awk 'NR==1{split($4,a,"/"); print a[1]}')
sudo pkill -x python3 2>/dev/null || true
sudo systemctl restart ibexwall-monitor.service
for i in $(seq 1 40); do
  sudo ibexctl apps list --json | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["monitor"]["running"] else 1)' && break
  sleep 0.5
done
# The core idles: no polling, a small resident set.
sleep 5
RSS_KB=$(ps -o rss= -C ibexwalld | head -1 | tr -d ' ')
echo "METRIC: core idle RSS: $((RSS_KB / 1024)) MB"
[ "$RSS_KB" -le 40960 ] || { echo "CORE TOO BIG AT IDLE: $RSS_KB kB"; exit 1; }
ticks() { awk '{print $14 + $15}' /proc/$1/stat; }
CORE=$(pidof ibexwalld | awk '{print $1}')
LOADER=$(pidof ibexwall-ebpf-loader | awk '{print $1}')
C0=$(ticks $CORE); L0=$(ticks $LOADER)

cat > /tmp/sink.py <<'EOF'
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9090)); s.listen(8192)
while True:
    c, _ = s.accept(); c.close()
EOF
sudo sh -c "nohup python3 /tmp/sink.py >/dev/null 2>&1 &"
sleep 1
cat > /tmp/storm.py <<EOF
import socket, struct, sys, time
RATE, SECONDS = 5000, 4
ok = 0
start = time.perf_counter()
n = 0
while time.perf_counter() - start < SECONDS:
    due = start + n / RATE
    now = time.perf_counter()
    if now < due:
        time.sleep(due - now)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    try:
        s.connect(("$HOST_IP", 9090)); ok += 1
    except OSError:
        pass
    s.close()
    n += 1
print(ok, n, round(n / (time.perf_counter() - start)))
EOF
BEFORE=$(sudo ibexctl apps list --json | python3 -c 'import json,sys; print(sum(a["connections"] for a in json.load(sys.stdin)["apps"] if "python3" in a["key"]))')
OUT=$(python3 /tmp/storm.py)
OK=$(echo $OUT | cut -d' ' -f1); RATE=$(echo $OUT | cut -d' ' -f3)
echo "METRIC: storm: $OK connections at $RATE per second"
[ "$RATE" -ge 4000 ] || { echo "THE STORM RAN TOO SLOWLY TO PROVE ANYTHING: $OUT"; exit 1; }
# Let the pipeline drain, then count what the core recorded.
GOT=0
for i in $(seq 1 40); do
  AFTER=$(sudo ibexctl apps list --json | python3 -c 'import json,sys; print(sum(a["connections"] for a in json.load(sys.stdin)["apps"] if "python3" in a["key"]))')
  GOT=$((AFTER - BEFORE))
  [ "$GOT" -ge "$OK" ] && break
  sleep 0.5
done
echo "METRIC: recorded $GOT of $OK"
[ "$((GOT * 1000))" -ge "$((OK * 999))" ] || { echo "EVENTS WERE LOST: $GOT of $OK"; exit 1; }
C1=$(ticks $CORE); L1=$(ticks $LOADER)
HZ=$(getconf CLK_TCK)
echo "METRIC: cpu during the storm: core $(( (C1 - C0) * 100 / HZ / 5 ))%, loader $(( (L1 - L0) * 100 / HZ / 5 ))% of one cpu (about 5 s)"
RSS_KB=$(ps -o rss= -C ibexwalld | head -1 | tr -d ' ')
echo "METRIC: core RSS after the storm: $((RSS_KB / 1024)) MB"
"#
    );

    if failures == 0 {
        println!("PASS: f6 (all scenarios)");
        Ok(())
    } else {
        anyhow::bail!("{failures} f6 scenario(s) failed")
    }
}
