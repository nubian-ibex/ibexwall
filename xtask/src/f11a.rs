// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F11a VM phase: compliance. The staged tree is packaged and installed on
//! the distro, then the shipped profiles are evaluated against the machine
//! twice: once as shipped (the default) and once after a hardening change,
//! to prove the verdict moves with the real state. Scenario scripts are
//! plain strings, so shell and JSON braces stay as written.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use super::f1::{pipe_file, run_script};
use super::vm::Vm;

/// Which package family this machine is, and the helper to apply one change
/// through the packaged daemon.
const LIB: &str = r#"
set -eE
if command -v dnf >/dev/null; then FAM=rpm
elif command -v apt-get >/dev/null; then FAM=deb
elif command -v pacman >/dev/null; then FAM=arch
else echo "UNKNOWN PACKAGE FAMILY"; exit 1; fi
# The first `{` after any banner text is the JSON reply.
first_json() { python3 -c 'import json,sys;t=sys.stdin.read();print(json.JSONDecoder().raw_decode(t[t.find("{"):])[0])'; }
change() {
  PLUGIN=$1; shift
  P=$(sudo ibexctl plan "$PLUGIN" "$@" --json 2>/tmp/plan.err | python3 -c 'import json,sys;t=sys.stdin.read();d=json.JSONDecoder().raw_decode(t[t.find("{"):])[0];print(d["plan"]["id"] if "plan" in d else d["id"])') || { echo "PLAN FAILED: $(cat /tmp/plan.err)"; return 1; }
  OUT=$(sudo ibexctl apply "$P" --confirm-timeout 300 --json 2>&1 || true)
  TX=$(echo "$OUT" | python3 -c 'import json,sys;t=sys.stdin.read();d=json.JSONDecoder().raw_decode(t[t.find("{"):])[0];print(d["transaction"]["id"])' 2>/dev/null) || { echo "APPLY FAILED: $(echo "$OUT" | head -c 400)"; return 1; }
  echo "$OUT" | grep -q pending_confirm && sudo ibexctl confirm "$TX" >/dev/null 2>&1
  return 0
}
# The raw report for one profile, as parsed JSON on stdout.
report() {
  sudo ibexctl compliance show "$1" --json 2>/dev/null \
    | python3 -c 'import json,sys;t=sys.stdin.read();d=json.JSONDecoder().raw_decode(t[t.find("{"):])[0];print(json.dumps(d["report"] if isinstance(d,dict) and "report" in d else d))'
}
"#;

/// Builds the package from the staged tree, one version into /tmp/ibx/out1.
const BUILD: &str = r#"
rm -rf /tmp/ibx && mkdir -p /tmp/ibx/out1 && tar xzf /tmp/ibx-input.tar.gz -C /tmp/ibx
cd /tmp/ibx
case $FAM in
rpm)
  sudo dnf install -y -q rpm-build systemd-rpm-macros selinux-policy-devel make >/dev/null
  rpmbuild -bb --quiet --define "_topdir /tmp/ibx/rpmbuild" --define 'prebuilt_stage /tmp/ibx/stage' --define 'selinux_src /tmp/ibx/packaging/selinux' packaging/rpm/ibexwall.spec
  cp rpmbuild/RPMS/*/*.rpm out1/
  ;;
deb)
  sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq debhelper dpkg-dev fakeroot make >/dev/null
  rm -rf src && mkdir src && cp -r packaging/deb/debian src/debian
  (cd src && IBEXWALL_STAGE=/tmp/ibx/stage dpkg-buildpackage -b -us -uc -d >/tmp/ibx/dpkg.log 2>&1) || { tail -30 /tmp/ibx/dpkg.log; exit 1; }
  mv ibexwall*_0.1.0_*.deb out1/ 2>/dev/null || mv *_0.1.0_*.deb out1/
  ;;
arch)
  sudo pacman -Sy --noconfirm --needed fakeroot binutils >/dev/null
  rm -rf pkg1 && mkdir pkg1 && cp packaging/arch/PKGBUILD packaging/arch/ibexwall.install pkg1/
  (cd pkg1 && IBEXWALL_STAGE=/tmp/ibx/stage PKGDEST=/tmp/ibx/out1 makepkg -f --nodeps --skipinteg --nocheck >/tmp/ibx/makepkg.log 2>&1) || { tail -30 /tmp/ibx/makepkg.log; exit 1; }
  ;;
esac
echo "METRIC: built $(ls out1 | wc -l) packages ($FAM)"
"#;

/// Installs the package and proves the shipped profiles are present and
/// loadable through the daemon.
const INSTALL: &str = r#"
cd /tmp/ibx
case $FAM in
rpm) sudo dnf install -y -q out1/*.rpm >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log; exit 1; } ;;
deb) sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq ./out1/*.deb >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log; exit 1; } ;;
arch) sudo pacman -U --noconfirm out1/*.pkg.tar.zst >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log; exit 1; } ;;
esac
sudo ibexctl status >/dev/null || { echo "THE DAEMON DID NOT ANSWER"; sudo journalctl -u ibexwalld -n 20 --no-pager; exit 1; }
for f in ibexwall-baseline lgpd cmn-4893 nist-800-53 nist-800-171 iso-27001; do
  [ -f "/usr/lib/ibexwall/profiles/$f.yaml" ] || { echo "MISSING PROFILE $f"; exit 1; }
done
sudo ibexctl compliance list --json 2>/dev/null > /tmp/profiles.json
python3 - <<'PY'
import json
raw = open('/tmp/profiles.json').read()
d = json.JSONDecoder().raw_decode(raw[raw.find("{"):])[0]
names = {p["framework"] for p in (d["profiles"] if isinstance(d, dict) else d)}
assert "IbexWall Baseline" in names, names
assert len(names) >= 6, names
print(len(names))
PY
echo "METRIC: installed; six profiles shipped and listed"
"#;

/// The default machine: every plugin enabled, every check run, and the
/// baseline reports a full, honest picture.
const REPORT: &str = r#"
sudo ibexctl plugins list --json 2>/dev/null | python3 -c 'import json,sys;t=sys.stdin.read();d=json.JSONDecoder().raw_decode(t[t.find("{"):])[0];print(" ".join(p["id"] for p in (d["plugins"] if isinstance(d,dict) else d)))' >/tmp/plugin-ids
for p in $(cat /tmp/plugin-ids); do sudo ibexctl plugins enable "$p" >/dev/null 2>&1 || true; done
for p in $(cat /tmp/plugin-ids); do sudo ibexctl check "$p" --json >/dev/null 2>&1 || true; done
report "IbexWall Baseline" > /tmp/report.json
python3 - <<'PY'
import json
report = json.load(open("/tmp/report.json"))
assert report["framework"] == "IbexWall Baseline"
controls = report["controls"]
assert len(controls) == 26, len(controls)
by = {}
for c in controls:
    by[c["status"]] = by.get(c["status"], 0) + 1
# Two organizational controls must ask a person, never claim a pass.
assert by.get("needs_attestation") == 2, by
# The automated controls split across states, never collapse to one lie.
assert set(by) - {"needs_attestation"}, by
print(len(controls), by)
PY
echo "METRIC: the baseline reports 26 controls with honest states"
"#;

/// A hardening change made through the daemon flips its check from fail to
/// pass, and the report moves with it.
const FLIP: &str = r#"
outcome() {
  python3 - "$1" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
for c in report["controls"]:
    for chk in c.get("checks", []):
        if chk["id"] == "sysctl.hardening":
            print(chk["outcome"])
            raise SystemExit
print("missing")
PY
}
report "IbexWall Baseline" > /tmp/report-before.json
BEFORE=$(outcome /tmp/report-before.json)
change system.sysctl --set preset=recommended || { echo "THE SYSCtl PRESET DID NOT APPLY"; exit 1; }
sudo ibexctl check system.sysctl --json >/dev/null 2>&1 || true
report "IbexWall Baseline" > /tmp/report-after.json
AFTER=$(outcome /tmp/report-after.json)
echo "METRIC: sysctl.hardening $BEFORE -> $AFTER"
[ "$BEFORE" = fail ] || { echo "EXPECTED sysctl.hardening TO START AS fail, GOT $BEFORE"; exit 1; }
[ "$AFTER" = pass ] || { echo "sysctl.hardening DID NOT FLIP TO pass (got $AFTER)"; exit 1; }
"#;

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== f11a: stage ==");
    crate::stage::run_stage(&crate::stage::Options {
        destdir: workspace.join("target/stage/root"),
        key_dir: workspace.join("target/devkey"),
        build: true,
        desktop: true,
        target_dir: None,
        build_env: Vec::new(),
    })?;
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

    println!("== f11a: provision ==");
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
    scenario!("c0 the package builds on this distribution", BUILD);
    scenario!(
        "c1 the package installs and the shipped profiles are listed",
        INSTALL
    );
    scenario!("c2 the baseline evaluates with honest states", REPORT);
    scenario!("c3 a hardening change flips its check", FLIP);

    if failures == 0 {
        println!("PASS: f11a compliance suite (all scenarios)");
        Ok(())
    } else {
        bail!("{failures} f11a scenario(s) failed")
    }
}
