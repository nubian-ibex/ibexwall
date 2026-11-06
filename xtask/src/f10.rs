// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F10 VM phase: the packages. The package is built on the distro itself
//! (rpm on Fedora, deb on Debian and Ubuntu, pacman on Arch) from the staged
//! tree, installed, used (a few real changes through the packaged daemon),
//! upgraded, removed, and the machine is checked for what was left. Scenario
//! scripts are plain strings, so shell and JSON braces stay as written.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use super::f1::{pipe_file, run_script};
use super::vm::Vm;

/// Shared by the scenarios: which package family this machine is, and where
/// the built packages are.
const LIB: &str = r#"
set -eE
if command -v dnf >/dev/null; then FAM=rpm
elif command -v apt-get >/dev/null; then FAM=deb
elif command -v pacman >/dev/null; then FAM=arch
else echo "UNKNOWN PACKAGE FAMILY"; exit 1; fi
OUT1=/tmp/ibx/out1
OUT2=/tmp/ibx/out2
# What AppArmor refused, newest last, for a scenario that failed.
aa_dump() { sudo journalctl --no-pager 2>/dev/null | grep 'apparmor="DENIED"' | grep ibexwall | tail -25 | sed -E 's/.*(operation=)/\1/' | cut -c1-260; }
# And what SELinux refused.
sel_dump() { sudo grep -h 'type=AVC' /var/log/audit/audit.log 2>/dev/null | grep -E 'ibexwall' | tail -40 | sed -E 's/.*avc: *//' | sed -E 's/ pid=[0-9]+//; s/ ino=[0-9]+//; s/ dev="[^"]*"//; s/ tclass=/ class=/' | cut -c1-300; }
trap 'rc=$?; [ $rc = 0 ] || { aa_dump; sel_dump; }' EXIT
apply_change() {
  PLUGIN=$1; shift
  P=$(sudo ibexctl plan "$PLUGIN" "$@" --json 2>/dev/null | python3 -c 'import json,sys;t=sys.stdin.read();i=t.find("{");d=json.JSONDecoder().raw_decode(t[i:])[0];print(d["plan"]["id"] if "plan" in d else d["id"])') || return 1
  OUT=$(sudo ibexctl apply "$P" --confirm-timeout 300 --json 2>&1 || true)
  TX=$(echo "$OUT" | python3 -c 'import json,sys;t=sys.stdin.read();i=t.find("{");d=json.JSONDecoder().raw_decode(t[i:])[0];print(d["transaction"]["id"])' 2>/dev/null) || return 1
  echo "$OUT" | grep -q pending_confirm && sudo ibexctl confirm "$TX" >/dev/null 2>&1
  return 0
}
change() { apply_change "$@"; }
# Everything the packages put or leave on the machine that carries the name.
leftovers() {
  sudo find /usr /etc /var /opt /lib /lib64 /boot -xdev \( -name '*ibexwall*' -o -name '*ibexctl*' \) 2>/dev/null | grep -vE '^/(var/lib/ibexwall(-mcp)?|etc/ibexwall|var/lib/cloud/instances/ibexwall[^/]*|var/lib/dpkg/info/ibexwall[^/]*)(/|$)' | sort || true
}
"#;

/// Builds the packages from the staged tree: the version being tested into
/// /tmp/ibx/out1 and a higher one, for the upgrade, into /tmp/ibx/out2.
const BUILD: &str = r#"
rm -rf /tmp/ibx && mkdir -p /tmp/ibx/out1 /tmp/ibx/out2 && tar xzf /tmp/ibx-input.tar.gz -C /tmp/ibx
cd /tmp/ibx
case $FAM in
rpm)
  sudo dnf install -y -q rpm-build systemd-rpm-macros selinux-policy-devel make >/dev/null
  rpmbuild -bb --quiet --define "_topdir /tmp/ibx/rpmbuild" --define 'prebuilt_stage /tmp/ibx/stage' --define 'selinux_src /tmp/ibx/packaging/selinux' packaging/rpm/ibexwall.spec
  cp rpmbuild/RPMS/*/*.rpm out1/
  rpmbuild -bb --quiet --define "_topdir /tmp/ibx/rpmbuild2" --define 'dist .upg' --define 'prebuilt_stage /tmp/ibx/stage' --define 'selinux_src /tmp/ibx/packaging/selinux' packaging/rpm/ibexwall.spec
  cp rpmbuild2/RPMS/*/*.rpm out2/
  ;;
deb)
  sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq debhelper dpkg-dev fakeroot make >/dev/null
  for v in 0.1.0 0.1.1; do
    rm -rf src && mkdir src && cp -r packaging/deb/debian src/debian
    sed -i "1s/(0.1.0)/($v)/" src/debian/changelog
    (cd src && IBEXWALL_STAGE=/tmp/ibx/stage dpkg-buildpackage -b -us -uc -d >/tmp/ibx/dpkg-$v.log 2>&1) || { tail -30 /tmp/ibx/dpkg-$v.log; exit 1; }
    if [ $v = 0.1.0 ]; then mv ibexwall*_$v_*.deb out1/ 2>/dev/null || mv *_0.1.0_*.deb out1/; else mv *_0.1.1_*.deb out2/; fi
  done
  ;;
arch)
  sudo pacman -Sy --noconfirm --needed fakeroot binutils >/dev/null
  for r in 1 2; do
    rm -rf pkg$r && mkdir pkg$r && cp packaging/arch/PKGBUILD packaging/arch/ibexwall.install pkg$r/
    sed -i "s/^pkgrel=1/pkgrel=$r/" pkg$r/PKGBUILD
    (cd pkg$r && IBEXWALL_STAGE=/tmp/ibx/stage PKGDEST=/tmp/ibx/out$r makepkg -f --nodeps --skipinteg --nocheck >/tmp/ibx/makepkg-$r.log 2>&1) || { tail -30 /tmp/ibx/makepkg-$r.log; exit 1; }
  done
  ;;
esac
echo "METRIC: built $(ls out1 | wc -l) packages ($FAM), and the same again as an upgrade"
ls -la out1
"#;

/// Installs the three packages, checks what the install did and that the
/// installed files are as packaged.
const INSTALL: &str = r#"
cd /tmp/ibx
case $FAM in
rpm) sudo dnf install -y -q out1/*.rpm >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log; exit 1; } ;;
deb) sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq ./out1/*.deb >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log; exit 1; } ;;
arch) sudo pacman -U --noconfirm out1/*.pkg.tar.zst >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log; exit 1; } ;;
esac
for b in ibexwalld ibexctl ibexwall-exec ibexwall-dns ibexwall-mcp ibexwall-desktop ibexwall-agent ibexwall-ebpf-loader; do
  [ -x /usr/bin/$b ] || { echo "MISSING /usr/bin/$b"; exit 1; }
done
[ -x /usr/libexec/ibexwall/ibexwall-plugins ] || { echo "MISSING THE PLUGIN BINARY"; exit 1; }

# Nothing the package installed differs from what it shipped.
case $FAM in
rpm) rpm -V ibexwall ibexwall-desktop ibexwall-mcp | grep -v '^\.\.\.\.\.\.\.\.\.  c ' && { echo "RPM -V FOUND DIFFERENCES"; exit 1; } || true ;;
deb) dpkg --verify ibexwall ibexwall-desktop ibexwall-mcp | grep -v ' c ' && { echo "DPKG --VERIFY FOUND DIFFERENCES"; exit 1; } || true ;;
arch) sudo pacman -Qkk ibexwall ibexwall-desktop ibexwall-mcp 2>&1 | grep -E 'warning|error' | grep -v 'Permission' && { echo "PACMAN -Qkk FOUND DIFFERENCES"; exit 1; } || true ;;
esac

# The users, the sockets, and the daemon answering with no --dev-key.
getent group ibexwall-assistants >/dev/null && getent passwd ibexwall-dns >/dev/null && getent passwd ibexwall-mcp >/dev/null || { echo "A SYSTEM USER OR GROUP IS MISSING"; exit 1; }
systemctl is-enabled ibexwalld.socket >/dev/null || { echo "ibexwalld.socket IS NOT ENABLED"; exit 1; }
systemctl is-active ibexwalld.socket >/dev/null || { echo "ibexwalld.socket IS NOT LISTENING"; exit 1; }
N=$(wc -l < /usr/lib/ibexwall/sockets.list)
A=$(for s in $(cat /usr/lib/ibexwall/sockets.list); do systemctl is-active $s; done | grep -c '^active$')
[ "$N" = "$A" ] || { echo "ONLY $A OF $N SOCKETS ARE LISTENING"; exit 1; }
sudo ibexctl status >/dev/null || { echo "THE DAEMON DID NOT ANSWER"; sudo journalctl -u ibexwalld -n 20 --no-pager; exit 1; }
sudo ibexctl plugins list --json > /tmp/plugins.json
python3 - <<'PYEOF'
import json
d = json.JSONDecoder().raw_decode(open("/tmp/plugins.json").read())[0]
plugins = d["plugins"] if isinstance(d, dict) else d
ids = {p["id"] for p in plugins}
assert len(ids) >= 30, sorted(ids)
bad = [p["id"] for p in plugins if p["status"] != "ok"]
assert not bad, bad
print(len(ids))
PYEOF
echo "METRIC: installed three packages; $N plugin sockets listening; the daemon answers; $(sudo ibexctl plugins list --json | python3 -c 'import json,sys;d=json.JSONDecoder().raw_decode(sys.stdin.read())[0];print(len(d["plugins"] if isinstance(d,dict) else d))') plugins verified against the embedded key"
"#;

/// A packaged plugin runs as a dynamic user under its own unit and the core
/// accepts its signature (no --dev-key anywhere).
const PLUGINS: &str = r#"
sudo ibexctl plugins enable system.posture >/dev/null
sudo ibexctl check system.posture --json >/tmp/posture.json 2>&1 || true
python3 - <<'PYEOF'
import json
d = json.JSONDecoder().raw_decode(open("/tmp/posture.json").read())[0]
assert "findings" in d, d
PYEOF
systemctl is-active --quiet ibexwall-plugin-posture.service || { echo "THE PLUGIN IS NOT RUNNING AS ITS OWN UNIT"; exit 1; }
[ "$(systemctl show ibexwall-plugin-posture.service -p DynamicUser --value)" = yes ] || { echo "THE PLUGIN IS NOT A DYNAMIC USER"; exit 1; }
if pgrep -f 'ibexwalld --dev-key' >/dev/null; then echo "THE DAEMON RUNS WITH --dev-key"; exit 1; fi
# A tampered manifest is refused: the embedded key vouches only for what was shipped.
sudo cp /usr/lib/ibexwall/plugins/system.posture/plugin.toml /tmp/plugin.toml.orig
printf '%s\n' '# tampered' | sudo tee -a /usr/lib/ibexwall/plugins/system.posture/plugin.toml >/dev/null
if sudo ibexctl check system.posture --json >/dev/null 2>&1; then echo "A TAMPERED MANIFEST WAS ACCEPTED"; exit 1; fi
sudo cp /tmp/plugin.toml.orig /usr/lib/ibexwall/plugins/system.posture/plugin.toml
sudo ibexctl check system.posture --json >/dev/null 2>&1 || true
echo "METRIC: a packaged plugin verifies against the embedded key, runs as a dynamic user, and a tampered manifest is refused"
"#;

/// Every IbexWall unit, rated by systemd. Documented, not gated.
const SECURITY: &str = r#"
for u in $(systemctl list-unit-files 'ibexwall*.service' --no-legend | awk '{print $1}'); do
  echo "METRIC: $u: $(systemd-analyze security "$u" --no-pager 2>&1 | tail -1 | sed 's/^→ //')"
done
"#;

/// Real changes through the packaged daemon: a kernel setting, a module
/// group and the inbound firewall.
const USE: &str = r#"
for p in system.sysctl system.modules net.firewall; do sudo ibexctl plugins enable $p >/dev/null 2>/tmp/enable.err || { echo "ENABLING $p FAILED: $(cat /tmp/enable.err)"; aa_dump; sudo journalctl -u ibexwalld -n 8 --no-pager | cut -c1-240; exit 1; }; done
sudo sh -c 'command -v nft' >/dev/null || { echo "nft IS MISSING (a dependency)"; exit 1; }
RFC_BEFORE=$(cat /proc/sys/net/ipv4/tcp_rfc1337)
echo "$RFC_BEFORE" > /tmp/rfc-before
[ "$RFC_BEFORE" = 0 ] || sudo sysctl -w net.ipv4.tcp_rfc1337=0 >/dev/null
echo 0 > /tmp/rfc-before
change system.sysctl --set 'keys={"net.ipv4.tcp_rfc1337":"1"}'
change system.modules --set 'block=["vivid"]'
# With a firewall manager installed the plugin works through it and the
# machine keeps its own rules (Ubuntu has ufw); only a machine without one
# gets IbexWall's own table, so that is the case to prove here.
if [ -x /usr/sbin/ufw ] || [ -x /usr/bin/firewall-cmd ]; then
  echo no > /tmp/fw-applied
else
  change net.firewall --set enable_basic=true
  echo yes > /tmp/fw-applied
fi
[ "$(cat /proc/sys/net/ipv4/tcp_rfc1337)" = 1 ]
sudo test -f /etc/sysctl.d/70-ibexwall-sysctl.conf
sudo test -f /etc/modprobe.d/70-ibexwall-modules.conf
if [ "$(cat /tmp/fw-applied)" = yes ]; then
  sudo nft list table inet ibexwall >/dev/null || { echo "THE FIREWALL TABLE IS MISSING"; exit 1; }
fi
echo "METRIC: changes applied through the packaged daemon (sysctl, modules, firewall: $(cat /tmp/fw-applied))"
"#;

/// AppArmor: the profiles load, the services run under them, and an ordinary
/// workload (every plugin checked, three changes made and undone) draws no
/// denial. Skipped where AppArmor is not the machine's access control.
const APPARMOR: &str = r#"
if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" != Y ] || ! command -v apparmor_parser >/dev/null 2>&1; then
  echo "METRIC: AppArmor is not active on this machine: skipped"; exit 0
fi
[ "$FAM" = deb ] && dpkg -s ibexwall-apparmor >/dev/null 2>&1 || { echo "ibexwall-apparmor IS NOT INSTALLED"; exit 1; }
for f in usr.bin.ibexwalld usr.bin.ibexwall-dns usr.bin.ibexwall-mcp usr.libexec.ibexwall.ibexwall-plugins; do
  [ -L /etc/apparmor.d/$f ] || { echo "$f IS NOT LINKED INTO /etc/apparmor.d"; exit 1; }
done
sudo aa-status 2>/dev/null | grep -q ibexwalld || sudo cat /sys/kernel/security/apparmor/profiles | grep -q '^ibexwalld ' || { echo "THE PROFILES ARE NOT LOADED"; exit 1; }
sudo systemctl restart ibexwalld.service || { sudo journalctl -u ibexwalld -n 15 --no-pager | cut -c1-250; sudo journalctl -k -n 10 --no-pager | grep -i apparmor | cut -c1-300; exit 1; }
for u in $(systemctl list-units 'ibexwall-plugin-*.service' --no-legend | awk '{print $1}'); do sudo systemctl restart $u 2>/dev/null || true; done
sudo dmesg -C 2>/dev/null || true
MARK=$(date '+%Y-%m-%d %H:%M:%S')
# Every plugin answers a check.
for p in $(sudo ibexctl plugins list --json | python3 -c 'import json,sys;d=json.JSONDecoder().raw_decode(sys.stdin.read())[0];print(" ".join(p["id"] for p in (d["plugins"] if isinstance(d,dict) else d)))'); do
  sudo ibexctl plugins enable $p >/dev/null 2>&1 || true
  sudo ibexctl check $p --json >/dev/null 2>&1 || true
done
change system.sysctl --set 'keys={"net.ipv4.tcp_rfc1337":"1"}'
change system.modules --set 'block=["vivid"]'
if [ ! -x /usr/sbin/ufw ] && [ ! -x /usr/bin/firewall-cmd ]; then change net.firewall --set enable_basic=true; fi
# What runs under which profile, read from the kernel.
confined() {
  PID=$(pgrep -x "$1" | head -1)
  [ -n "$PID" ] || { echo "$1 IS NOT RUNNING"; return 1; }
  echo "METRIC: $1 runs as: $(sudo cat /proc/$PID/attr/current)"
  sudo cat /proc/$PID/attr/current | grep -qE "^$2( |//)" || { echo "$1 IS NOT UNDER THE $2 PROFILE"; return 1; }
}
confined ibexwalld ibexwalld
# The resolver answers a few queries while it is on.
if apply_change net.dns --set provider=quad9 --set transport=tls; then
  for i in 1 2 3; do resolvectl query example.com >/dev/null 2>&1 || true; sleep 1; done
  confined ibexwall-dns ibexwall-dns
  sudo ibexctl rollback "$TX" >/dev/null 2>&1 || true
else
  echo "THE RESOLVER COULD NOT BE TURNED ON"; aa_dump; exit 1
fi
# The MCP server, as an assistant's client would start it, answers a request
# under its profile (the HTTPS mode is the same binary and is off here).
( printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"a1","version":"1"}}}'; sleep 6 ) | sudo systemd-run --wait --pipe -q -p User=ibexwall-mcp -p SupplementaryGroups=ibexwall-assistants -p StateDirectory=ibexwall-mcp -p AppArmorProfile=ibexwall-mcp /usr/bin/ibexwall-mcp --client a1 --state-dir /var/lib/ibexwall-mcp > /tmp/a1-mcp.out 2>/tmp/a1-mcp.err &
sleep 3
confined ibexwall-mcp ibexwall-mcp
wait
grep -q '"result"' /tmp/a1-mcp.out || { echo "THE MCP SERVER DID NOT ANSWER: $(cat /tmp/a1-mcp.out /tmp/a1-mcp.err | head -5)"; exit 1; }
# A plugin runs under its own profile.
sudo ibexctl check system.posture --json >/dev/null 2>&1 || true
PLUGIN_PID=$(systemctl show ibexwall-plugin-posture.service -p MainPID --value)
echo "METRIC: a plugin runs as: $(sudo cat /proc/$PLUGIN_PID/attr/current)"
sudo cat /proc/$PLUGIN_PID/attr/current | grep -qE "^ibexwall-plugins( |//)" || { echo "A PLUGIN IS NOT UNDER ITS PROFILE"; exit 1; }
sleep 2
sudo journalctl --since "$MARK" --no-pager 2>/dev/null | grep -E 'apparmor="(ALLOWED|DENIED)"' | grep ibexwall > /tmp/aa.log || true
N=$(wc -l < /tmp/aa.log)
python3 - <<'PYEOF'
import re, collections
seen = collections.OrderedDict()
for line in open('/tmp/aa.log'):
    f = dict(re.findall(r'(\w+)="([^"]*)"', line))
    key = (f.get('profile'), f.get('operation'), f.get('name') or f.get('family', '') + ':' + f.get('sock_type', ''), f.get('requested_mask') or f.get('capname', ''), f.get('apparmor'))
    seen[key] = seen.get(key, 0) + 1
for (profile, op, name, mask, status), n in sorted(seen.items(), key=lambda kv: [str(x) for x in kv[0]]):
    print(f"METRIC: AA {status} {profile} {op} {name} {mask}")
PYEOF
echo "METRIC: $N AppArmor events for the ibexwall profiles"
test "$N" = 0 || { echo "THE PROFILES LOGGED $N EVENTS"; exit 1; }
"#;

/// SELinux: the module is loaded, the resolver, the MCP server and the
/// plugins run in their own domains, and an ordinary workload draws no denial.
/// Skipped where SELinux is not the machine's access control.
const SELINUX: &str = r#"
if [ "$(getenforce 2>/dev/null)" != Enforcing ]; then echo "METRIC: SELinux is not enforcing on this machine: skipped"; exit 0; fi
[ "$FAM" = rpm ] && rpm -q ibexwall-selinux >/dev/null 2>&1 || { echo "ibexwall-selinux IS NOT INSTALLED"; exit 1; }
sudo semodule -l | grep -q '^ibexwall' || { echo "THE MODULE IS NOT LOADED"; exit 1; }
sudo systemctl restart ibexwalld.service
for u in $(systemctl list-units 'ibexwall-plugin-*.service' --no-legend | awk '{print $1}'); do sudo systemctl restart $u 2>/dev/null || true; done
sudo semodule -DB
AUDIT_BEFORE=$(sudo sh -c 'wc -l < /var/log/audit/audit.log')
for p in $(sudo ibexctl plugins list --json | python3 -c 'import json,sys;d=json.JSONDecoder().raw_decode(sys.stdin.read())[0];print(" ".join(p["id"] for p in (d["plugins"] if isinstance(d,dict) else d)))'); do
  sudo ibexctl plugins enable $p >/dev/null 2>&1 || true
  sudo ibexctl check $p --json >/dev/null 2>&1 || true
done
change system.sysctl --set 'keys={"net.ipv4.tcp_rfc1337":"1"}'
change system.modules --set 'block=["vivid"]'
if [ ! -x /usr/sbin/ufw ] && [ ! -x /usr/bin/firewall-cmd ]; then change net.firewall --set enable_basic=true; fi
domain_of() {
  case "$1" in
    *.service) PID=$(systemctl show "$1" -p MainPID --value) ;;
    *) PID=$(pgrep -x "$1" | head -1) ;;
  esac
  [ -n "$PID" ] && [ "$PID" != 0 ] || { echo "$1 IS NOT RUNNING: $(cat /tmp/s1-mcp.err /tmp/s1-mcp.out 2>/dev/null | head -4)"; return 1; }
  CTX=$(sudo cat /proc/$PID/attr/current | tr -d '\0')
  echo "METRIC: $1 runs as $CTX"
  echo "$CTX" | grep -q ":$2:" || {  echo "$1 IS NOT IN THE $2 DOMAIN ($(ls -Z $(sudo readlink /proc/$PID/exe) | head -1))"; sudo grep -h type=AVC /var/log/audit/audit.log | tail -6 | sed -E "s/.*avc: *//" | cut -c1-320; return 1; }
}
if apply_change net.dns --set provider=quad9 --set transport=tls; then
  for i in 1 2 3; do resolvectl query example.com >/dev/null 2>&1 || true; sleep 1; done
  domain_of ibexwall-dns.service ibexwall_dns_t
  sudo ibexctl rollback "$TX" >/dev/null 2>&1 || true
else
  echo "THE RESOLVER COULD NOT BE TURNED ON"; exit 1
fi
sudo install -d -o ibexwall-mcp -m 0700 /var/lib/ibexwall-mcp
sudo restorecon -R /var/lib/ibexwall-mcp
# The MCP server, as an assistant's client would start it, answers a request.
# The domain it starts in is what the policy computes for init starting it.
EXEC=$(selinuxexeccon /usr/bin/ibexwall-mcp system_u:system_r:init_t:s0 2>&1)
echo "METRIC: ibexwall-mcp would start as $EXEC"
echo "$EXEC" | grep -q ':ibexwall_mcp_t:' || { echo "THE MCP SERVER WOULD NOT START IN ITS DOMAIN"; exit 1; }
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"s1","version":"1"}}}' > /tmp/s1-in
chmod 644 /tmp/s1-in
cat /tmp/s1-in | sudo systemd-run --wait --pipe -q -p User=ibexwall-mcp -p SupplementaryGroups=ibexwall-assistants /usr/bin/ibexwall-mcp --client s1 --state-dir /var/lib/ibexwall-mcp 2>&1 | cat > /tmp/s1-out || true
grep -q '"result"' /tmp/s1-out || { echo "THE MCP SERVER DID NOT ANSWER: $(head -c 300 /tmp/s1-out /tmp/s1-err)"; exit 1; }
sudo ibexctl check system.posture --json >/dev/null 2>&1 || true
PLUGIN_PID=$(systemctl show ibexwall-plugin-posture.service -p MainPID --value)
CTX=$(sudo cat /proc/$PLUGIN_PID/attr/current)
echo "METRIC: a plugin runs as $CTX"
echo "$CTX" | grep -q ':ibexwall_plugin_t:' || { echo "A PLUGIN IS NOT IN ITS DOMAIN"; exit 1; }
sleep 2
sudo tail -n +$((AUDIT_BEFORE+1)) /var/log/audit/audit.log 2>/dev/null | grep 'type=AVC' | grep -E 'ibexwall_|ibexwall-' | sed -E 's/.*avc: *//' > /tmp/avc.log || true
N=$(wc -l < /tmp/avc.log)
python3 - <<'PYEOF'
import re, collections
seen = collections.OrderedDict()
for line in open('/tmp/avc.log'):
    m = re.search(r'avc:\s+(\w+)\s+\{ ([^}]*) \} for.*?comm="([^"]*)".*?(?:name="([^"]*)")?.*?scontext=(\S+) tcontext=(\S+) tclass=(\S+) permissive=(\d)', line)
    if not m:
        seen[line.strip()[-200:]] = 1
        continue
    kind, perms, comm, name, scon, tcon, tclass, perm = m.groups()
    scon = scon.split(':')[2]; tcon = tcon.split(':')[2]
    seen[(kind, scon, tcon, tclass, perms, perm)] = 1
for key in seen:
    print("METRIC: AVC", *key) if isinstance(key, tuple) else print("METRIC: AVC raw", key)
PYEOF
sudo semodule -B
echo "METRIC: $N AVC events for the ibexwall domains"
test "$N" = 0 || { echo "THE DOMAINS DREW $N AVC EVENTS"; exit 1; }
"#;

/// A smoke of the earlier phases against the installed packages: the checks
/// of F2, the DNS of F3, the notes of F7, the assistant server of F8, and
/// the engine's own books. The firewall of F5 is USE, just before it.
const SMOKE: &str = r#"
set -e
# F2: every enabled check plugin answers, and a finding is a finding.
sudo ibexctl check --json >/tmp/s2-check.json 2>/dev/null || true
python3 - <<'PYEOF'
import json
d = json.JSONDecoder().raw_decode(open("/tmp/s2-check.json").read())[0]
ids = {f["id"] for f in d["findings"]}
assert any(i.startswith("posture.") for i in ids), sorted(ids)[:8]
print("check:", len(ids), "findings")
PYEOF

# F7: the notes are there, as information.
for p in system.posture system.ssh system.sysctl net.dns; do
  sudo ibexctl plugins enable $p >/dev/null 2>&1 || true
done
for p in system.ssh system.sysctl net.dns; do
  sudo ibexctl check $p --json 2>/dev/null | grep -q "detect\." || { echo "NO NOTE FROM $p"; exit 1; }
done
echo "notes: ssh, sysctl and dns say what they found"

# F3: Secure DNS through the packaged resolver, a real query, then undone.
apply_change net.dns --set provider=quad9 --set transport=tls
systemctl is-active --quiet ibexwall-dns.service || { echo "THE PACKAGED RESOLVER IS NOT UP"; exit 1; }
Q=$(resolvectl query example.com 2>&1 | head -1)
echo "$Q" | grep -q "example.com" || { echo "THE RESOLVER DID NOT ANSWER: $Q"; exit 1; }
sudo ibexctl rollback "$TX" >/dev/null
if systemctl is-active --quiet ibexwall-dns.service; then echo "THE RESOLVER STAYED UP AFTER THE ROLLBACK"; exit 1; fi
echo "dns: the resolver answered and was undone"

# F8: the assistant server answers a request over the control socket. Its
# state directory is created with the right owner, and the right label where
# the machine uses SELinux.
sudo install -d -o ibexwall-mcp -m 0700 /var/lib/ibexwall-mcp
command -v restorecon >/dev/null 2>&1 && sudo restorecon -R /var/lib/ibexwall-mcp || true
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"s2","version":"1"}}}' > /tmp/s2-in
cat /tmp/s2-in | sudo systemd-run --wait --pipe -q -p User=ibexwall-mcp -p SupplementaryGroups=ibexwall-assistants /usr/bin/ibexwall-mcp --client s2 --state-dir /var/lib/ibexwall-mcp 2>/dev/null | grep -q '"result"' || { echo "THE MCP SERVER DID NOT ANSWER"; exit 1; }
echo "assistant: the packaged MCP server answered an initialize"

# The engine's own books: history counts what USE did, and the chain is intact.
sudo ibexctl history --json 2>/dev/null | grep -q committed || { echo "THE HISTORY IS EMPTY"; exit 1; }
sudo ibexctl audit verify >/dev/null || { echo "THE AUDIT CHAIN DOES NOT VERIFY"; exit 1; }
echo "METRIC: smoke of F2, F3, F7, F8 and the engine's books, all through the installed packages"
"#;

/// Upgrade: a higher version over the installed one; the changes made, the
/// history and the firewall survive, and the daemon runs the new files.
const UPGRADE: &str = r#"
cd /tmp/ibx
BEFORE=$(systemctl show ibexwalld.service -p ActiveEnterTimestampMonotonic --value)
case $FAM in
rpm) sudo dnf upgrade -y -q out2/*.rpm >/tmp/upgrade.log 2>&1 || { tail -20 /tmp/upgrade.log; exit 1; } ;;
deb) sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq ./out2/*.deb >/tmp/upgrade.log 2>&1 || { tail -20 /tmp/upgrade.log; exit 1; } ;;
arch) sudo pacman -U --noconfirm out2/*.pkg.tar.zst >/tmp/upgrade.log 2>&1 || { tail -20 /tmp/upgrade.log; exit 1; } ;;
esac
case $FAM in
rpm) rpm -q ibexwall | grep -q upg || { echo "THE UPGRADE IS NOT INSTALLED: $(rpm -q ibexwall)"; exit 1; } ;;
deb) dpkg-query -W -f='${Version}' ibexwall | grep -q '^0.1.1' || { echo "THE UPGRADE IS NOT INSTALLED"; exit 1; } ;;
arch) pacman -Q ibexwall | grep -q -- '-2$' || { echo "THE UPGRADE IS NOT INSTALLED: $(pacman -Q ibexwall)"; exit 1; } ;;
esac
sudo ibexctl status >/dev/null || { echo "THE DAEMON DOES NOT ANSWER AFTER THE UPGRADE"; exit 1; }
AFTER=$(systemctl show ibexwalld.service -p ActiveEnterTimestampMonotonic --value)
[ "$BEFORE" != "$AFTER" ] || { echo "THE DAEMON WAS NOT RESTARTED ON THE NEW FILES"; exit 1; }
[ "$(cat /proc/sys/net/ipv4/tcp_rfc1337)" = 1 ] || { echo "A SETTING WAS LOST"; exit 1; }
sudo test -f /etc/sysctl.d/70-ibexwall-sysctl.conf && sudo test -f /etc/modprobe.d/70-ibexwall-modules.conf
if [ "$(cat /tmp/fw-applied)" = yes ]; then
  sudo nft list table inet ibexwall >/dev/null || { echo "THE FIREWALL TABLE WAS LOST IN THE UPGRADE"; exit 1; }
fi
sudo ibexctl history --json 2>/dev/null | grep -c committed | grep -qE '^[2-9]' || { echo "THE HISTORY WAS LOST"; sudo ibexctl history; exit 1; }
N=$(wc -l < /usr/lib/ibexwall/sockets.list)
A=$(for s in $(cat /usr/lib/ibexwall/sockets.list); do systemctl is-active $s; done | grep -c '^active$')
[ "$N" = "$A" ] || { echo "ONLY $A OF $N SOCKETS LISTEN AFTER THE UPGRADE"; exit 1; }
sudo ibexctl plugins enable system.posture >/dev/null
sudo ibexctl check system.posture --json >/dev/null 2>&1 || true
systemctl is-active --quiet ibexwall-plugin-posture.service || { echo "A PLUGIN DOES NOT START AFTER THE UPGRADE"; exit 1; }
echo "METRIC: upgraded in place: the daemon restarted on the new files, the changes, the history and the firewall survived"
"#;

/// Removal: the changes are undone, the units go, the user's data stays.
const REMOVE: &str = r#"
cd /tmp/ibx
case $FAM in
rpm) sudo dnf remove -y -q ibexwall ibexwall-desktop ibexwall-mcp >/tmp/remove.log 2>&1 || { tail -20 /tmp/remove.log; exit 1; } ;;
deb) sudo DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq ibexwall ibexwall-desktop ibexwall-mcp >/tmp/remove.log 2>&1 || { tail -20 /tmp/remove.log; exit 1; } ;;
arch) sudo pacman -Rns --noconfirm ibexwall-mcp ibexwall-desktop ibexwall >/tmp/remove.log 2>&1 || { tail -20 /tmp/remove.log; exit 1; } ;;
esac
cat /tmp/remove.log | grep -i "undid\|could not undo" || true

# The machine is as it was.
[ "$(cat /proc/sys/net/ipv4/tcp_rfc1337)" = "$(cat /tmp/rfc-before)" ] || { echo "THE KERNEL SETTING WAS NOT PUT BACK: $(cat /proc/sys/net/ipv4/tcp_rfc1337)"; exit 1; }
sudo test ! -e /etc/sysctl.d/70-ibexwall-sysctl.conf || { echo "THE SYSCTL DROP-IN SURVIVED"; exit 1; }
sudo test ! -e /etc/modprobe.d/70-ibexwall-modules.conf || { echo "THE MODPROBE DROP-IN SURVIVED"; exit 1; }
if sudo nft list table inet ibexwall >/dev/null 2>&1; then echo "THE FIREWALL TABLE SURVIVED"; sudo nft list table inet ibexwall; exit 1; fi
sudo test ! -e /etc/ibexwall/firewall/inbound.json || { echo "THE FIREWALL SETTINGS SURVIVED"; exit 1; }
if systemctl list-unit-files 'ibexwall*' --no-legend | grep -q .; then echo "UNITS REMAIN: $(systemctl list-unit-files 'ibexwall*' --no-legend | tr '\n' ' ')"; exit 1; fi
if pgrep -f 'ibexwall' >/dev/null; then echo "PROCESSES REMAIN: $(pgrep -fa ibexwall | head -3)"; exit 1; fi
LEFT=$(leftovers)
[ -z "$LEFT" ] || { echo "FILES REMAIN:"; echo "$LEFT"; exit 1; }
# The user's data is kept until a purge.
sudo test -f /var/lib/ibexwall/state.db || { echo "THE STATE WAS REMOVED WITH THE PACKAGE"; exit 1; }
echo "METRIC: removed: the three changes undone, no unit, process or file left; the state and audit chain kept"
"#;

/// Debian has a purge, which also removes what was kept.
const PURGE: &str = r#"
[ "$FAM" = deb ] || { echo "METRIC: no purge on this family: the kept data is /var/lib/ibexwall and /etc/ibexwall"; exit 0; }
sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq ibexwall >/tmp/purge.log 2>&1 || { cat /tmp/purge.log; exit 1; }
for d in /var/lib/ibexwall /var/lib/ibexwall-mcp /etc/ibexwall; do
  sudo test ! -e $d || { echo "$d SURVIVED THE PURGE"; exit 1; }
done
echo "METRIC: purged: the user's data is gone too"
"#;

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== f10: stage ==");
    crate::stage::run_stage(&crate::stage::Options {
        destdir: workspace.join("target/stage/root"),
        key_dir: workspace.join("target/devkey"),
        build: true,
        desktop: true,
        target_dir: None,
        build_env: Vec::new(),
    })?;
    // One archive: the staged tree and the packaging files, laid out as the
    // build script expects (/tmp/ibx/stage/{root,stage-lists}, /tmp/ibx/packaging).
    let input = workspace.join("target/stage/pkg-input.tar.gz");
    let status = Command::new("tar")
        .arg("czf")
        .arg(&input)
        .args([
            "--transform=s,^root,stage/root,",
            "--transform=s,^stage-lists,stage/stage-lists,",
            "-C",
            "target/stage",
            "root",
            "stage-lists",
            "-C",
            "../..",
            "packaging",
        ])
        .current_dir(workspace)
        .status()
        .context("packing the staged tree")?;
    if !status.success() {
        bail!("packing the staged tree failed");
    }

    println!("== f10: provision ==");
    vm.ssh(install)
        .context("installing python3 and polkit in the VM")?;
    pipe_file(vm, &input, "cat > /tmp/ibx-input.tar.gz")?;

    let mut failures = 0;
    macro_rules! scenario {
        ($name:expr, $body:expr) => {
            if !run_script(vm, $name, &[LIB, $body].concat()) {
                failures += 1;
            }
        };
    }
    scenario!("b0 the packages build on this distribution", BUILD);
    scenario!(
        "i1 the packages install: users, sockets, daemon and plugins, files as shipped",
        INSTALL
    );
    scenario!(
        "i2 a packaged plugin verifies against the embedded key and runs under its own unit",
        PLUGINS
    );
    scenario!("i3 every unit, rated by systemd", SECURITY);
    scenario!("u1 changes made through the packaged daemon", USE);
    scenario!(
        "s2 a smoke of the earlier phases against the installed packages",
        SMOKE
    );
    scenario!(
        "a1 the AppArmor profiles load and the workload draws no event",
        APPARMOR
    );
    scenario!(
        "s1 the SELinux domains hold and the workload draws no denial",
        SELINUX
    );
    scenario!(
        "u2 an upgrade keeps the changes, the history and the firewall, and runs the new files",
        UPGRADE
    );
    scenario!(
        "r1 removal undoes the changes and leaves no unit, process or file",
        REMOVE
    );
    scenario!("r2 a purge removes the user's data too", PURGE);

    if failures == 0 {
        println!("PASS: f10 acceptance suite (all scenarios)");
        Ok(())
    } else {
        bail!("{failures} f10 scenario(s) failed")
    }
}

/// Development aid: builds the SELinux module on the machine and loads it,
/// printing what the compiler says. `cargo xtask vm-test --distro fedora
/// --phase selinux`.
pub fn run_selinux_build(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    let tar = workspace.join("target/stage/selinux-src.tar.gz");
    std::fs::create_dir_all(tar.parent().expect("a parent"))?;
    let status = Command::new("tar")
        .arg("czf")
        .arg(&tar)
        .args(["-C", "packaging", "selinux"])
        .current_dir(workspace)
        .status()?;
    if !status.success() {
        bail!("packing the policy sources failed");
    }
    vm.ssh(install)?;
    pipe_file(vm, &tar, "cat > /tmp/selinux-src.tar.gz")?;
    let script = r#"
set -e
sudo dnf install -y -q selinux-policy-devel >/dev/null
rm -rf /tmp/sel && mkdir /tmp/sel && tar xzf /tmp/selinux-src.tar.gz -C /tmp/sel && cd /tmp/sel/selinux
make -f /usr/share/selinux/devel/Makefile ibexwall.pp 2>&1 | tail -40 | sed 's/^/METRIC: /'
test -f ibexwall.pp && echo METRIC: BUILT
echo METRIC: $(getenforce)
"#;
    let ok = run_script(vm, "selinux module builds", script);
    if ok {
        Ok(())
    } else {
        bail!("the module did not build")
    }
}
