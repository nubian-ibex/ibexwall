// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F4 spike S4-a: can the aya connect monitor load, attach and attribute
//! on every distro's kernel? Monitor only, one scenario per machine plus
//! a rough overhead measurement (the precise target lands with M2).

use std::path::Path;

use anyhow::Result;

use super::f1::{install_binary, install_plugin, pipe_file, provision, run_script, start_daemon};
use super::vm::{Vm, run_capture};

/// Reads the transaction or plan id out of `ibexctl --json` output.
const JSON_ID: &str = "python3 -c 'import json,sys;d=json.JSONDecoder().raw_decode(sys.stdin.read())[0];t=d.get(\"plan\") or d.get(\"transaction\");print(t[\"id\"] if isinstance(t,dict) else t)'";

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== f4 (spike): build ==");
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
            "-p",
            "ibexwall-plugin-flatpak-network",
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
    pipe_file(
        vm,
        &workspace.join("target/bpf/ibexwall-ebpf.o"),
        "sudo tee /usr/lib/ibexwall/ebpf/ibexwall-ebpf.o >/dev/null",
    )?;

    let mut failures = 0;
    macro_rules! scenario {
        ($name:expr, $script:expr) => {
            if !run_script(vm, $name, $script) {
                failures += 1;
            }
        };
    }

    scenario!(
        "e0 the monitor loads, attaches and attributes connects",
        r#"
set -e
test -e /sys/fs/cgroup/cgroup.controllers || { echo "no cgroup v2"; uname -a; exit 1; }
sudo sh -c 'nohup /usr/bin/ibexwall-ebpf-loader >/tmp/ev.json 2>/tmp/ev.err & echo $! >/tmp/loader.pid'
sleep 2
# The loader logs its banner to stderr; being alive is the health check.
sudo kill -0 $(cat /tmp/loader.pid) || { echo "LOADER DIED"; cat /tmp/ev.err; exit 1; }
python3 - <<'EOF'
import socket
for host, port, family in [("149.112.112.112", 443, socket.AF_INET), ("2620:fe::9", 853, socket.AF_INET6), ("1.1.1.1", 80, socket.AF_INET)]:
    s = socket.socket(family, socket.SOCK_STREAM); s.settimeout(5)
    try: s.connect((host, port))
    except OSError: pass
import time
time.sleep(2)  # stay alive so the monitor can resolve this process
EOF
curl -s -o /dev/null --max-time 8 http://203.0.113.1/ || true
sleep 3
sudo kill $(cat /tmp/loader.pid) 2>/dev/null || true
sleep 1
cat /tmp/ev.err >&2
python3 - <<'EOF'
import json
events = [json.loads(line) for line in open("/tmp/ev.json") if line.strip()]
print(f"{len(events)} events")
assert events, "no events recorded"
for event in events:
    assert event["port"] < 65536, event
    assert event["pid"] > 1, event
# Unrelated host processes may exit before /proc is read; ours stay alive.
ours = [e for e in events if e["comm"] in ("python3", "curl")]
assert ours and all(e["cgroup"] for e in ours), ours
py = [e for e in events if e["exe"] and "python3" in e["exe"]]
curl = [e for e in events if e["exe"] and e["exe"].endswith("/curl")]
assert any(e["dst"] == "149.112.112.112" and e["port"] == 443 for e in py), py
assert any(e["dst"] == "2620:fe::9" and e["port"] == 853 for e in py), py
assert any(e["port"] == 80 for e in curl), curl
# The kernel's own record of the exec, independent of /proc timing.
assert any((e["exe_kernel"] or "").endswith("/curl") for e in curl), curl
assert any((e["exe_kernel"] or "").startswith("/usr/bin/python3") for e in py), py
# Identity per section 4.9: a terminal session is a CLI, identified by its
# exe; the distro package manager names the owner; the hash is SHA-256.
assert all(e["kind"] == "cli" for e in curl), curl
assert any(e["package"] == "curl" for e in curl), [e["package"] for e in curl]
assert all(e["exe_hash"] and len(e["exe_hash"]) == 64 for e in curl), curl
print("attribution ok: python3 and curl events with the right destinations and kernel-side exe")
EOF
"#
    );

    scenario!(
        "e1 overhead of the monitor on a connect loop stays small",
        r#"
set -e
cat > /tmp/loop.py <<'EOF'
import socket, time
start = time.process_time()
for _ in range(1000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try: s.connect(("127.0.0.1", 9))
    except OSError: pass
    s.close()
print(f"{time.process_time() * 1000:.1f}")
EOF
# The loop prints its own CPU time (process_time): the in-kernel hook
# cost is charged to the connecting process, so this is the real per
# connect overhead, not scheduler noise. Best of five on each side.
for i in 1 2 3 4 5; do python3 /tmp/loop.py; done > /tmp/t-off
sudo sh -c 'nohup /usr/bin/ibexwall-ebpf-loader >/dev/null 2>/dev/null & echo $! >/tmp/loader.pid'
sleep 2
LP=$(cat /tmp/loader.pid)
# schedstat field 1 is nanoseconds on cpu (stat's ticks are 10 ms granular).
loader_ns() { awk '{print $1}' /proc/$1/schedstat 2>/dev/null || echo 0; }
LOADER_BEFORE=$(loader_ns $LP)
for i in 1 2 3 4 5; do python3 /tmp/loop.py; done > /tmp/t-on
LOADER_AFTER=$(loader_ns $LP)
sudo kill $LP 2>/dev/null || true
python3 - <<EOF
off = min(float(x) for x in open("/tmp/t-off").read().split())
on = min(float(x) for x in open("/tmp/t-on").read().split())
per_connect_us = (on - off) * 1000 / 1000
loader_cpu_ms = ($LOADER_AFTER - $LOADER_BEFORE) / 1e6
per_event_us = loader_cpu_ms * 1000 / 5000
print(f"1000 refused connects, best of 5: {off:.1f} -> {on:.1f} ms CPU, {per_connect_us:.2f} us/connect in the hook")
print(f"loader CPU for 5000 events: {loader_cpu_ms:.1f} ms ({per_event_us:.2f} us/event)")
assert per_connect_us < 3.0, f"hook overhead too high: {per_connect_us:.2f} us/connect"
assert per_event_us < 20.0, f"loader CPU too high: {per_event_us:.2f} us/event"
EOF
"#
    );

    // The real packaging: the unit's hardening must still allow what the
    // monitor does (load, attach, read other users' processes, hash).
    pipe_file(
        vm,
        Path::new(&format!(
            "{}/packaging/systemd/ibexwall-monitor.service",
            workspace.display()
        )),
        "sudo tee /etc/systemd/system/ibexwall-monitor.service >/dev/null",
    )?;
    scenario!(
        "e2 the hardened unit loads, attaches and feeds a socket",
        r#"
set -e
sudo mkdir -p /run/ibexwall /etc/systemd/system/ibexwall-monitor.service.d
# Test-only: keep the unit's stderr where a failure can show it.
printf '[Service]\nStandardError=file:/run/ibexwall-monitor.err\n' | sudo tee /etc/systemd/system/ibexwall-monitor.service.d/test.conf >/dev/null
sudo systemctl daemon-reload
# A stand-in for the core: a root-owned stream socket that keeps every line.
cat > /tmp/core.py <<'EOF'
import os, socket
path = "/run/ibexwall/monitor.sock"
if os.path.exists(path): os.unlink(path)
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path); os.chmod(path, 0o600); server.listen(1)
conn, _ = server.accept()
with open("/tmp/core.json", "wb") as out:
    while True:
        data = conn.recv(65536)
        if not data: break
        out.write(data); out.flush()
EOF
sudo sh -c 'nohup python3 /tmp/core.py >/dev/null 2>&1 & echo $! >/tmp/core.pid'
for i in $(seq 1 20); do [ -S /run/ibexwall/monitor.sock ] && break; sleep 0.25; done
sudo systemctl start ibexwall-monitor.service
sleep 3
systemctl is-active --quiet ibexwall-monitor.service || { sudo systemctl status ibexwall-monitor --no-pager >&2 || true; sudo cat /run/ibexwall-monitor.err >&2 || true
  exit 1; }
curl -s -o /dev/null --max-time 6 http://203.0.113.1/ || true
# Processes that connect and exit at once: the loader usually loses the race
# against /proc, so identity must come from the kernel's own record.
for i in $(seq 1 20); do
  python3 -c 'import socket; s = socket.socket(); s.setblocking(False); s.connect_ex(("198.51.100.9", 80))'
done
sleep 3
sudo systemctl stop ibexwall-monitor.service
sudo kill $(cat /tmp/core.pid) 2>/dev/null || true
python3 - <<'EOF'
import json
events = [json.loads(line) for line in open("/tmp/core.json") if line.strip()]
curl = [e for e in events if e.get("comm") == "curl" and e.get("dst") == "203.0.113.1"]
assert curl, [e["comm"] for e in events]
assert curl[0]["kind"] == "cli", curl[0]
assert curl[0]["exe"].endswith("/curl"), curl[0]
assert curl[0]["package"] == "curl", curl[0]
assert curl[0]["exe_hash"] and len(curl[0]["exe_hash"]) == 64, curl[0]
quick = [e for e in events if e.get("dst") == "198.51.100.9"]
assert len(quick) >= 15, len(quick)
assert all(e["kind"] == "cli" for e in quick), [e for e in quick if e["kind"] != "cli"][:2]
# Without the kernel's exec record (degraded) a lost race leaves no path.
if not any(e.get("meta") == "degraded" for e in events):
    assert all((e["exe_kernel"] or "").startswith("/usr/bin/python3") for e in quick), quick[:2]
degraded = [e for e in events if e.get("meta") == "degraded"]
# Measured 2026-11-03: Debian's perf_event_paranoid=3 wants CAP_SYS_ADMIN for
# the exec tracepoint; the other four attach with CAP_PERFMON alone.
distro = dict(l.strip().split("=", 1) for l in open("/etc/os-release") if "=" in l)["ID"].strip('"')
assert bool(degraded) == (distro == "debian"), (distro, degraded)
print(f"hardened unit ok: {len(events)} lines, curl attributed to {curl[0]['package']}; degraded: {degraded[0]['reason'] if degraded else 'no'}")
EOF
"#
    );

    // From here on the real daemon runs (it binds the same monitor socket
    // the e2 stand-in used), so the Flatpak block goes through the whole
    // stack: plan, apply, the executor in its transient unit, rollback.
    crate::devkey::run()?;
    provision(vm, workspace, install)?;
    install_plugin(vm, workspace, "apps.flatpak-network")?;
    start_daemon(vm)?;

    scenario!(
        "m4 a Flatpak network block applies, flatpak reads it, and rolls back byte for byte",
        &format!(
            r#"
set -e
if ! command -v flatpak >/dev/null; then
  if command -v dnf >/dev/null; then sudo dnf install -y -q flatpak
  elif command -v apt-get >/dev/null; then sudo apt-get update -qq; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq flatpak
  elif command -v pacman >/dev/null; then sudo pacman -Sy --noconfirm --needed flatpak
  fi
fi
D=/var/lib/flatpak/overrides
# Two installed apps (the plugin only accepts installed ones): one with an
# administrator's override already in place, one without any.
sudo mkdir -p /var/lib/flatpak/app/org.ibexwall.Mine /var/lib/flatpak/app/org.ibexwall.Fresh $D
printf '[Context]\nshared=ipc;\nfilesystems=home;\n' | sudo tee $D/org.ibexwall.Mine >/dev/null
BEFORE=$(sudo sha256sum $D/org.ibexwall.Mine | cut -d' ' -f1)
sudo ibexctl plugins enable apps.flatpak-network

# An app that is not installed, and an invalid id, are refused at plan time.
if sudo ibexctl plan apps.flatpak-network --set app=org.ibexwall.Typo >/dev/null 2>&1; then echo "UNINSTALLED APP WAS PLANNED"; exit 1; fi
if sudo ibexctl plan apps.flatpak-network --set app=../../etc/passwd >/dev/null 2>&1; then echo "INVALID ID WAS PLANNED"; exit 1; fi

P=$(sudo ibexctl plan apps.flatpak-network --set app=org.ibexwall.Mine --json 2>&1 | tee /dev/stderr | {JSON_ID}) || {{ echo "PLAN FAILED"; exit 1; }}
OUT=$(sudo ibexctl apply $P --json 2>&1) || {{ echo "APPLY FAILED: $OUT"; sudo journalctl -u ibexwalld -n 25 --no-pager >&2; exit 1; }}
TX=$(echo "$OUT" | {JSON_ID})

# Flatpak's own view of the override file we wrote.
SHOWN=$(sudo flatpak override --system --show org.ibexwall.Mine)
echo "$SHOWN" | grep -q '!network' || {{ echo "FLATPAK DOES NOT SEE THE BLOCK: $SHOWN"; exit 1; }}
echo "$SHOWN" | grep -q 'ipc' || {{ echo "FLATPAK LOST THE ADMIN'S ipc: $SHOWN"; exit 1; }}
echo "$SHOWN" | grep -q 'home' || {{ echo "FLATPAK LOST THE ADMIN'S home: $SHOWN"; exit 1; }}
MODE=$(sudo stat -c '%a %U:%G' $D/org.ibexwall.Mine)
[ "$MODE" = "644 root:root" ] || {{ echo "WRONG MODE $MODE"; exit 1; }}

sudo ibexctl rollback "$TX" --json >/dev/null || {{ echo "ROLLBACK FAILED"; exit 1; }}
AFTER=$(sudo sha256sum $D/org.ibexwall.Mine | cut -d' ' -f1)
[ "$AFTER" = "$BEFORE" ] || {{ echo "NOT BYTE FOR BYTE: $AFTER vs $BEFORE"; sudo cat $D/org.ibexwall.Mine >&2; exit 1; }}

# An app with no override file at all: created by apply, removed by rollback.
P=$(sudo ibexctl plan apps.flatpak-network --set app=org.ibexwall.Fresh --json | {JSON_ID})
OUT=$(sudo ibexctl apply $P --json 2>&1) || {{ echo "APPLY (fresh) FAILED: $OUT"; exit 1; }}
TX=$(echo "$OUT" | {JSON_ID})
[ "$(sudo cat $D/org.ibexwall.Fresh)" = "$(printf '[Context]\nshared=!network;')" ] || {{ echo "FRESH FILE WRONG"; sudo cat $D/org.ibexwall.Fresh >&2; exit 1; }}
sudo flatpak override --system --show org.ibexwall.Fresh | grep -q '!network'
sudo ibexctl rollback "$TX" --json >/dev/null
sudo test ! -e $D/org.ibexwall.Fresh || {{ echo "FRESH FILE SURVIVED ROLLBACK"; exit 1; }}
"#,
            JSON_ID = JSON_ID
        )
    );

    if failures == 0 {
        println!("PASS: f4 spike (all scenarios)");
        Ok(())
    } else {
        anyhow::bail!("{failures} f4 scenario(s) failed")
    }
}
