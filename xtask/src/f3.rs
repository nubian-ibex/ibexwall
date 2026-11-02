// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F3 VM phase: the secure DNS stack on a real systemd-resolved machine.
//! Real resolver, real encrypted upstream (Quad9 over DoT), real packet
//! capture, real kill and rollback. Needs outbound network in the VM.

use std::path::Path;

use anyhow::Result;

use super::f1::{install_binary, install_plugin, pipe_data, provision, run_script, start_daemon};
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
            "ibexwall-plugin-dns",
            "-p",
            "ibexwall-dns",
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
    ] {
        pipe_data(vm, data, &format!("sudo tee {target} >/dev/null"))?;
    }
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
if ! command -v tcpdump >/dev/null; then
  if command -v dnf >/dev/null; then sudo dnf install -y -q tcpdump
  elif command -v apt-get >/dev/null; then sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq tcpdump
  elif command -v pacman >/dev/null; then sudo pacman -S --noconfirm --needed tcpdump
  fi
fi
sudo systemctl enable --now systemd-resolved
sudo ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
sudo systemd-sysusers /usr/lib/sysusers.d/ibexwall-dns.conf
for i in 1 2 3 4 5 6 7 8 9 10; do getent hosts example.com >/dev/null && break; sleep 1; done
getent hosts example.com
sudo mkdir -p /etc/systemd/resolved.conf.d
sudo sh -c 'cat /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/* 2>/dev/null | sha256sum' > /tmp/ibx-dns-baseline
cat /tmp/ibx-dns-baseline
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
getent hosts example.com
! resolvectl status | grep -q 127.0.0.153
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
P=$(sudo ibexctl plan net.dns --set provider=cloudflare --set transport=https --json | {JSON_ID})
OUT=$(sudo ibexctl apply $P --confirm-timeout 300 --json 2>/dev/null || true)
TX=$(echo "$OUT" | {JSON_ID})
for i in 1 2 3 4 5 6 7 8 9 10; do getent hosts example.com >/dev/null && break; sleep 1; done
getent hosts example.com
sudo ibexctl confirm "$TX"
sudo test -f /etc/systemd/resolved.conf.d/50-ibexwall.conf
sudo ibexctl rollback "$TX" --json >/dev/null
NOW=$(sudo sh -c 'cat /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/* 2>/dev/null | sha256sum')
[ "$NOW" = "$(cat /tmp/ibx-dns-baseline)" ]
sudo test ! -e /etc/ibexwall/dns/resolver.json
STATE=$(systemctl is-enabled ibexwall-dns 2>&1 || true)
[ "$STATE" != "enabled" ] || {{ echo "unit still enabled after rollback" >&2; exit 1; }}
! systemctl is-active --quiet ibexwall-dns
for i in $(seq 1 15); do getent hosts example.com >/dev/null && break; sleep 1; done
getent hosts example.com
"#
        )
    );

    if failures == 0 {
        println!("PASS: f3 phase (all scenarios)");
        Ok(())
    } else {
        anyhow::bail!("{failures} f3 scenario(s) failed")
    }
}
