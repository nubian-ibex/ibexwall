// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F4 spike S4-a: can the aya connect monitor load, attach and attribute
//! on every distro's kernel? Monitor only, one scenario per machine plus
//! a rough overhead measurement (the precise target lands with M2).

use std::path::Path;

use anyhow::Result;

use super::f1::{install_binary, pipe_file, run_script};
use super::vm::{Vm, run_capture};

pub fn run(vm: &Vm, workspace: &Path) -> Result<()> {
    println!("== f4 (spike): build ==");
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

    if failures == 0 {
        println!("PASS: f4 spike (all scenarios)");
        Ok(())
    } else {
        anyhow::bail!("{failures} f4 scenario(s) failed")
    }
}
