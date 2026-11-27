// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `dns-nm` VM phase (ADR-0051), with the packages installed so that
//! AppArmor or SELinux confine what they confine on a real machine. It
//! covers the failsafe on systemd-resolved, then switches the guest to
//! NetworkManager alone, and then leaves a setup behind with Secure DNS
//! applied to it. Guests: Fedora and Arch.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use super::f1::{pipe_file, run_script};
use super::f11b::{BUILD, INSTALL, LIB, stage_and_pack};
use super::vm::Vm;

const COMMON: &str = r#"
id_of() { python3 -c 'import json,sys;d=json.JSONDecoder().raw_decode(sys.stdin.read())[0];t=d.get("plan") or d.get("transaction");sys.exit("not a change" if t is None else 0) if not isinstance(t,dict) or not t.get("id") else print(t["id"])'; }
# Applies Secure DNS and keeps it; sets TX.
apply_dns() {
  sudo ibexctl plugins enable net.dns >/dev/null
  P=$(sudo ibexctl plan net.dns --set provider=quad9 --set transport=tls --json | id_of) || { echo "PLAN FAILED"; sudo ibexctl plan net.dns --set provider=quad9 --set transport=tls || true; exit 1; }
  OUT=$(sudo ibexctl apply "$P" --confirm-timeout 300 --json 2>&1 || true)
  echo "$OUT" | grep -q pending_confirm || { echo "APPLY FAILED: $OUT"; why; exit 1; }
  TX=$(echo "$OUT" | id_of)
  sudo ibexctl confirm "$TX" >/dev/null
}
why() {
  sudo journalctl -b -u ibexwalld -u ibexwall-dns -u ibexwall-dns-failsafe -u NetworkManager --no-pager -o cat | tail -25 | cut -c1-260
  sudo journalctl -b --no-pager -o cat | grep -E 'apparmor="DENIED"|avc: +denied' | tail -12 | cut -c1-300
  ls -l /etc/resolv.conf; cat /etc/resolv.conf
}
resolves() { for _ in $(seq 1 20); do getent hosts "${1:-example.com}" >/dev/null && return 0; sleep 1; done; return 1; }
servers() { grep -E '^nameserver' /etc/resolv.conf | sort | tr '\n' ' '; }
guard() { sudo nft list chain inet ibexwall net_dns_guard >/dev/null 2>&1; }
# The guest image restores the resolved symlink on every boot (even with
# manage_resolv_conf false): noise of the test guest, not the product. With
# resolved down the link is dangling, so nobody can resolve; hand the file
# to NetworkManager instead.
clear_stale_link() {
  echo "METRIC: resolv.conf: $(ls -l /etc/resolv.conf 2>&1), resolved $(systemctl is-active systemd-resolved 2>&1)"
  if [ ! -f /etc/resolv.conf ]; then
    sudo rm -f /etc/resolv.conf
    sudo systemctl restart NetworkManager
    sleep 5
  fi
}
kill_resolver_until_it_gives_up() {
  for _ in 1 2 3 4 5 6; do
    for _ in $(seq 1 6); do systemctl is-active --quiet ibexwall-dns && break; sleep 1; done
    sudo systemctl kill --kill-whom=main -s KILL ibexwall-dns.service 2>/dev/null || true
    sleep 0.3
  done
}
check_outcome() { sudo ibexctl check net.dns --json 2>/dev/null | python3 -c 'import json,sys;d=json.JSONDecoder().raw_decode(sys.stdin.read())[0];ids=[f["id"] for f in d["findings"]];print("stale" if "dns.stale_settings" in ids else "fail" if "dns.secure_resolver" in ids else "pass")'; }
refusals() {
  sleep 2
  FOUND=$(sudo journalctl -b --no-pager -o cat | grep -E 'apparmor="DENIED"|avc: +denied' | grep -E 'ibexwall|resolv|NetworkManager' | head -6 || true)
  [ -z "$FOUND" ] || { echo "REFUSED:"; echo "$FOUND" | cut -c1-300; exit 1; }
}
"#;

const TOOLS: &str = r#"
case $FAM in
rpm) sudo dnf install -y -q tcpdump nftables >/tmp/tools.log 2>&1 ;;
arch) sudo pacman -S --noconfirm --needed networkmanager tcpdump nftables >/tmp/tools.log 2>&1 ;;
esac || { tail -20 /tmp/tools.log; exit 1; }
systemctl is-active --quiet systemd-resolved || sudo systemctl enable --now systemd-resolved
resolves || { echo "NO NAMES BEFORE ANYTHING"; why; exit 1; }
if [ "$FAM" = rpm ]; then echo "METRIC: SELinux $(getenforce)"; fi
"#;

const FAILSAFE_RESOLVED: &str = r#"
# Whatever happens below, the next scenario starts from a clean machine.
# set -e makes a failing trap command the scenario's exit status, so every
# step in the cleanup may fail.
trap 'sudo systemctl reset-failed ibexwall-dns.service ibexwall-dns-failsafe.service >/dev/null 2>&1 || true; if [ -n "${TX:-}" ]; then sudo ibexctl rollback "$TX" >/dev/null 2>&1 || true; fi; sudo rm -f /etc/systemd/resolved.conf.d/50-ibexwall.conf || true; sudo systemctl restart systemd-resolved || true' EXIT
apply_dns
resolvectl status | grep -q 127.0.0.153 || { echo "RESOLVED DOES NOT USE THE RESOLVER"; why; exit 1; }
kill_resolver_until_it_gives_up
for _ in $(seq 1 40); do [ ! -e /etc/systemd/resolved.conf.d/50-ibexwall.conf ] && break; sleep 1; done
[ ! -e /etc/systemd/resolved.conf.d/50-ibexwall.conf ] || { echo "THE FAILSAFE DID NOT REMOVE THE DROP-IN"; why; exit 1; }
resolves || { echo "NO NAMES AFTER THE FAILSAFE"; why; exit 1; }
if guard; then echo "THE BLOCK SURVIVED THE FAILSAFE"; exit 1; fi
sudo systemctl reset-failed ibexwall-dns.service
sudo ibexctl rollback "$TX" >/dev/null || { echo "UNDO AFTER THE FAILSAFE FAILED"; why; exit 1; }
resolves || { echo "NO NAMES AFTER THE UNDO"; why; exit 1; }
refusals
echo "METRIC: with the packages, the failsafe restores systemd-resolved"
"#;

// The cloud image restores its own /etc/resolv.conf on every boot, which
// would undo the switch. This takes effect at the next boot, so the SSH
// session is never cut half way.
const NO_CLOUD_RESOLV: &str = r#"
sudo install -d -m 0755 /etc/cloud/cloud.cfg.d
printf 'manage_resolv_conf: false\n' | sudo tee /etc/cloud/cloud.cfg.d/99-ibexwall.cfg >/dev/null
sudo rm -f /etc/resolv.conf
"#;

// Takes effect at the next boot, so the SSH session is never cut half way.
const TO_NETWORK_MANAGER: &str = r#"
sudo systemctl disable systemd-resolved.service >/dev/null 2>&1 || true
sudo systemctl disable systemd-resolved-varlink.socket systemd-resolved-monitor.socket >/dev/null 2>&1 || true
sudo rm -f /etc/resolv.conf
if [ "$FAM" = arch ]; then
  sudo systemctl disable systemd-networkd.service systemd-networkd.socket systemd-networkd-wait-online.service >/dev/null 2>&1 || true
  sudo systemctl enable NetworkManager.service >/dev/null
fi
"#;

const NM_BASELINE: &str = r#"
clear_stale_link
systemctl is-active --quiet NetworkManager || { echo "NETWORKMANAGER IS NOT RUNNING"; why; exit 1; }
if systemctl is-active --quiet systemd-resolved; then echo "RESOLVED STILL RUNS"; exit 1; fi
resolves || { echo "NO NAMES WITH NETWORKMANAGER ALONE"; why; exit 1; }
servers > /var/tmp/ibx-nm-servers
echo "METRIC: NetworkManager alone, $(NetworkManager --version), servers: $(cat /var/tmp/ibx-nm-servers)"
"#;

const NM_APPLY: &str = r#"
clear_stale_link
sudo ibexctl plugins enable net.dns >/dev/null
sudo ibexctl check net.dns --json | grep -q detect-dns-nm-plain || { echo "NOT DETECTED AS NETWORKMANAGER"; sudo ibexctl check net.dns --json; why; exit 1; }
apply_dns
[ "$(servers)" = "nameserver 127.0.0.153 " ] || { echo "RESOLV.CONF: $(servers)"; why; exit 1; }
resolves wikipedia.org || { echo "NO NAMES THROUGH THE RESOLVER"; why; exit 1; }
[ "$(check_outcome)" = pass ] || { echo "THE CHECK DOES NOT PASS: $(check_outcome)"; why; exit 1; }
echo "$TX" > /var/tmp/ibx-nm-tx
echo "METRIC: applied; resolv.conf names the resolver alone"
"#;

const NO_LEAK: &str = r#"
sudo rm -f /tmp/ibx-dns.txt
( sudo timeout -s INT 14 tcpdump -i any -nn -l 'port 53 or port 853' > /tmp/ibx-dns.txt 2>/dev/null & )
sleep 3
for n in wikipedia.org debian.org kernel.org archlinux.org fedoraproject.org gnu.org; do getent hosts $n >/dev/null || true; done
sleep 12
PKTS=$(grep -E '^[0-9][0-9:.]+ ' /tmp/ibx-dns.txt)
LEAK=$(echo "$PKTS" | grep -Ev '127\.0\.0\.|\.853[: ]|\.853$' | grep -c . || true)
[ "$LEAK" -eq 0 ] || { echo "CLEAR DNS LEFT THE MACHINE:"; echo "$PKTS" | grep -Ev '127\.0\.0\.|\.853[: ]|\.853$' | head -6; exit 1; }
echo "$PKTS" | grep -Eq '\.853[: ]|\.853$' || { echo "NOTHING ENCRYPTED WAS SEEN"; exit 1; }
python3 - <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(4)
try:
    s.connect(("9.9.9.9", 53)); raise SystemExit("CLEAR DNS WAS NOT REFUSED")
except (ConnectionRefusedError, PermissionError):
    pass
EOF
sudo systemctl restart NetworkManager
sleep 8
[ "$(servers)" = "nameserver 127.0.0.153 " ] || { echo "A RESTART OF NETWORKMANAGER LOST IT: $(servers)"; exit 1; }
resolves || { echo "NO NAMES AFTER THE RESTART"; why; exit 1; }
refusals
echo "METRIC: no clear DNS on the wire, refused for others, kept across a NetworkManager restart"
"#;

const NM_AFTER_REBOOT: &str = r#"
clear_stale_link
[ "$(servers)" = "nameserver 127.0.0.153 " ] || { echo "A REBOOT LOST IT: $(servers)"; why; exit 1; }
resolves || { echo "NO NAMES AFTER THE REBOOT"; why; exit 1; }
[ "$(check_outcome)" = pass ] || { echo "THE CHECK DOES NOT PASS AFTER THE REBOOT"; why; exit 1; }
TX=$(cat /var/tmp/ibx-nm-tx)
sudo ibexctl rollback "$TX" >/dev/null || { echo "UNDO FAILED"; why; exit 1; }
[ ! -e /etc/NetworkManager/conf.d/50-ibexwall-dns.conf ] || { echo "THE FILE SURVIVED THE UNDO"; exit 1; }
for _ in $(seq 1 10); do [ "$(servers)" = "$(cat /var/tmp/ibx-nm-servers)" ] && break; sleep 1; done
[ "$(servers)" = "$(cat /var/tmp/ibx-nm-servers)" ] || { echo "SERVERS NOT RESTORED: $(servers)"; why; exit 1; }
if guard; then echo "THE BLOCK SURVIVED THE UNDO"; exit 1; fi
resolves || { echo "NO NAMES AFTER THE UNDO"; why; exit 1; }
refusals
echo "METRIC: kept across a reboot; the undo restores the network's servers"
"#;

const NM_FAILSAFE: &str = r#"
trap 'sudo systemctl reset-failed ibexwall-dns.service ibexwall-dns-failsafe.service >/dev/null 2>&1 || true; if [ -n "${TX:-}" ]; then sudo ibexctl rollback "$TX" >/dev/null 2>&1 || true; fi; sudo rm -f /etc/NetworkManager/conf.d/50-ibexwall-dns.conf /etc/systemd/resolved.conf.d/50-ibexwall.conf || true; nmcli general reload >/dev/null 2>&1 || true' EXIT
apply_dns
kill_resolver_until_it_gives_up
for _ in $(seq 1 40); do [ ! -e /etc/NetworkManager/conf.d/50-ibexwall-dns.conf ] && break; sleep 1; done
[ ! -e /etc/NetworkManager/conf.d/50-ibexwall-dns.conf ] || { echo "THE FAILSAFE DID NOT REMOVE THE FILE"; why; exit 1; }
resolves || { echo "NO NAMES AFTER THE FAILSAFE"; why; exit 1; }
if guard; then echo "THE BLOCK SURVIVED THE FAILSAFE"; exit 1; fi
[ "$(servers)" = "$(cat /var/tmp/ibx-nm-servers)" ] || { echo "SERVERS NOT RESTORED: $(servers)"; why; exit 1; }
sudo systemctl reset-failed ibexwall-dns.service
sudo ibexctl rollback "$TX" >/dev/null || { echo "UNDO AFTER THE FAILSAFE FAILED"; why; exit 1; }
refusals
echo "METRIC: the failsafe restores NetworkManager"
"#;

// Back to systemd-resolved, apply, then leave it again by hand.
const LEAVE_THE_SETUP: &str = r#"
sudo systemctl enable --now systemd-resolved >/dev/null 2>&1
sudo ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
sudo systemctl restart NetworkManager
resolves || { echo "NO NAMES BACK ON RESOLVED"; why; exit 1; }
apply_dns
echo "$TX" > /var/tmp/ibx-stale-tx
sudo systemctl disable --now systemd-resolved.service >/dev/null 2>&1
sudo systemctl disable systemd-resolved-varlink.socket systemd-resolved-monitor.socket >/dev/null 2>&1 || true
sudo rm -f /etc/resolv.conf
sudo systemctl restart NetworkManager
"#;

const STALE: &str = r#"
sudo rm -f /etc/NetworkManager/conf.d/50-ibexwall-dns.conf
if getent hosts example.com >/dev/null 2>&1; then echo "METRIC: names still resolve here"; else echo "METRIC: no name resolves, as found on a real machine"; fi
# No check is asked for: the daemon's own, after the boot, must say it.
sudo ibexctl --json findings | grep -q 'dns.stale_settings' || { echo "NOT SAID AFTER THE BOOT"; sudo ibexctl findings; why; exit 1; }
TX=$(cat /var/tmp/ibx-stale-tx)
sudo ibexctl rollback "$TX" >/dev/null || { echo "UNDO FAILED"; why; exit 1; }
resolves || { echo "NO NAMES AFTER THE UNDO"; why; exit 1; }
if guard; then echo "THE BLOCK SURVIVED THE UNDO"; exit 1; fi
if sudo ibexctl --json findings | grep -q 'dns.stale_settings'; then echo "STILL SAID RIGHT AFTER THE UNDO"; exit 1; fi
refusals
echo "METRIC: leaving the setup is reported after a boot, and the undo restores names"
"#;

const REMOVE: &str = r#"
clear_stale_link
sudo systemctl disable --now systemd-resolved.service >/dev/null 2>&1 || true
sudo rm -f /etc/resolv.conf
sudo systemctl restart NetworkManager
resolves || { echo "NO NAMES BEFORE THE REMOVAL TEST"; why; exit 1; }
BEFORE=$(servers)
apply_dns
case $FAM in
rpm) sudo dnf remove -y -q ibexwall ibexwall-desktop ibexwall-mcp >/tmp/remove.log 2>&1 ;;
arch) sudo pacman -Rns --noconfirm ibexwall-mcp ibexwall-desktop ibexwall >/tmp/remove.log 2>&1 ;;
esac || { tail -20 /tmp/remove.log; exit 1; }
[ ! -e /etc/NetworkManager/conf.d/50-ibexwall-dns.conf ] || { echo "THE FILE SURVIVED THE REMOVAL"; exit 1; }
for _ in $(seq 1 10); do [ "$(servers)" = "$BEFORE" ] && break; sleep 1; done
[ "$(servers)" = "$BEFORE" ] || { echo "SERVERS NOT RESTORED BY THE REMOVAL: $(servers)"; why; exit 1; }
if guard; then echo "THE BLOCK SURVIVED THE REMOVAL"; exit 1; fi
resolves || { echo "NO NAMES AFTER THE REMOVAL"; why; exit 1; }
refusals
echo "METRIC: removing the packages with Secure DNS applied restores NetworkManager"
"#;

fn reboot(vm: &Vm) -> Result<()> {
    let boot = |vm: &Vm| vm.ssh("cat /proc/sys/kernel/random/boot_id");
    let before = boot(vm).context("reading the boot id")?;
    // The connection drops as the guest goes down.
    let _ = vm.ssh("sudo systemctl reboot");
    for _ in 0..90 {
        std::thread::sleep(Duration::from_secs(4));
        if boot(vm).is_ok_and(|now| now != before) {
            // Let the boot finish, and with it the daemon's first checks.
            let _ = vm.ssh("sudo systemctl is-system-running --wait");
            std::thread::sleep(Duration::from_secs(10));
            return Ok(());
        }
    }
    crate::vm::keep_work_on_fail();
    bail!("the guest did not come back from a reboot");
}

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== dns-nm: stage ==");
    let input = stage_and_pack(workspace)?;
    println!("== dns-nm: provision ==");
    vm.ssh(install)
        .context("installing python3 and polkit in the VM")?;
    pipe_file(vm, &input, "cat > /tmp/ibx-input.tar.gz")?;

    let mut failures = 0;
    macro_rules! scenario {
        ($name:expr, $body:expr) => {
            if !run_script(vm, $name, &[LIB, COMMON, $body].concat()) {
                failures += 1;
            }
        };
    }
    scenario!("m0 the packages build on this distribution", BUILD);
    scenario!("m1 the packages install", INSTALL);
    scenario!("m2 tools, and systemd-resolved to start from", TOOLS);
    scenario!(
        "m3 the packaged failsafe restores systemd-resolved",
        FAILSAFE_RESOLVED
    );
    scenario!(
        "m4a stop the cloud image from managing resolv.conf",
        NO_CLOUD_RESOLV
    );
    scenario!(
        "m4 switch the guest to NetworkManager alone",
        TO_NETWORK_MANAGER
    );
    reboot(vm)?;
    scenario!("m5 NetworkManager alone resolves", NM_BASELINE);
    scenario!("m6 Secure DNS applies through NetworkManager", NM_APPLY);
    scenario!("m7 no clear DNS leaves the machine", NO_LEAK);
    reboot(vm)?;
    scenario!(
        "m8 it survives a reboot and undoes cleanly",
        NM_AFTER_REBOOT
    );
    scenario!(
        "m9 a resolver that cannot stay up triggers the failsafe",
        NM_FAILSAFE
    );
    scenario!(
        "m10 apply on systemd-resolved, then leave it by hand",
        LEAVE_THE_SETUP
    );
    reboot(vm)?;
    scenario!("m11 the app says so, and the undo restores names", STALE);
    scenario!("m12 removal restores NetworkManager", REMOVE);

    if failures > 0 {
        bail!("{failures} dns-nm scenario(s) failed");
    }
    println!("OK: dns-nm passed");
    Ok(())
}
