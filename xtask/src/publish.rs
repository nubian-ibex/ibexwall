// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the package repositories are fed from a published release:
//! `cargo xtask aur` writes the directory the AUR takes (`PKGBUILD`,
//! `.SRCINFO` and the install script); COPR makes its source RPM itself
//! (`.copr/Makefile`). Nothing here pushes anywhere.
//!
//! The VM phases `aur` (on Arch) and `copr` (on Fedora) do what a user and
//! COPR would do with the release of this checkout's version, which has to
//! be published.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::f1::{pipe_file, run_script};
use crate::f10::LIB;
use crate::vm::{Vm, run_capture, workspace_root};

const RELEASES: &str = "https://github.com/nubian-ibex/ibexwall/releases/download";

/// The release packages the AUR package installs, and their placeholders.
const AUR_SOURCES: [(&str, &str); 3] = [
    ("ibexwall", "@SHA256_CORE@"),
    ("ibexwall-desktop", "@SHA256_DESKTOP@"),
    ("ibexwall-mcp", "@SHA256_MCP@"),
];

/// `PKGBUILD` and `.SRCINFO` for a release, from its `SHA256SUMS`.
fn render(version: &str, pkgrel: u32, sums: &str) -> Result<(String, String)> {
    // The version ends up in a shell script and in URLs.
    if version.is_empty() || !version.chars().all(|c| c.is_ascii_digit() || c == '.') {
        bail!("`{version}` is not a release version (digits and dots)");
    }
    let dir = workspace_root().join("packaging/arch/aur");
    let read =
        |name: &str| std::fs::read_to_string(dir.join(name)).with_context(|| name.to_string());
    let mut pkgbuild = read("PKGBUILD.in")?;
    // makepkg writes no comments into a .SRCINFO.
    let mut srcinfo: String = read("SRCINFO.in")?
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect();
    let mut values = vec![
        ("@VERSION@", version.to_string()),
        ("@PKGREL@", pkgrel.to_string()),
    ];
    for (package, placeholder) in AUR_SOURCES {
        let file = format!("{package}-{version}-1-x86_64.pkg.tar.zst");
        let sum = sums
            .lines()
            .filter_map(|l| l.split_once("  "))
            .find(|(_, name)| *name == file)
            .map(|(sum, _)| sum)
            .filter(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
            .with_context(|| format!("SHA256SUMS has no checksum for {file}"))?;
        values.push((placeholder, sum.to_string()));
    }
    for (placeholder, value) in &values {
        pkgbuild = pkgbuild.replace(placeholder, value);
        srcinfo = srcinfo.replace(placeholder, value);
    }
    Ok((pkgbuild, srcinfo))
}

/// `cargo xtask aur`: reads the published release's checksums, believes them
/// only if the release key signed them, and writes the AUR directory.
pub fn aur(version: &str, pkgrel: u32, out: &Path) -> Result<()> {
    let fetch = |name: &str| {
        let url = format!("{RELEASES}/v{version}/{name}");
        run_capture("curl", ["-fsSL", &url], None, &format!("fetching {url}"))
    };
    let sums = fetch("SHA256SUMS")?;
    let signature = fetch("SHA256SUMS.minisig")?;
    let key_file = workspace_root().join("packaging/release.pub");
    crate::release::check_signature(
        &std::fs::read_to_string(&key_file).with_context(|| key_file.display().to_string())?,
        sums.as_bytes(),
        &signature,
    )
    .context("SHA256SUMS of the release")?;
    let (pkgbuild, srcinfo) = render(version, pkgrel, &sums)?;
    std::fs::create_dir_all(out)?;
    std::fs::write(out.join("PKGBUILD"), pkgbuild)?;
    std::fs::write(out.join(".SRCINFO"), srcinfo)?;
    std::fs::copy(
        workspace_root().join("packaging/arch/ibexwall.install"),
        out.join("ibexwall.install"),
    )?;
    let shown: PathBuf = out.canonicalize()?;
    println!(
        "AUR directory for ibexwall-bin {version}-{pkgrel}: {}",
        shown.display()
    );
    Ok(())
}

/// The installed release answers: its version, its socket and every plugin.
const ANSWERS: &str = r#"
ibexctl --version | grep -qF "$1" || { echo "NOT VERSION $1: $(ibexctl --version)"; exit 1; }
systemctl is-active ibexwalld.socket >/dev/null || { echo "ibexwalld.socket IS NOT LISTENING"; exit 1; }
sudo ibexctl status >/dev/null || { echo "THE DAEMON DID NOT ANSWER"; sudo journalctl -u ibexwalld -n 20 --no-pager; exit 1; }
sudo ibexctl plugins list --json > /tmp/plugins.json
python3 - <<'PYEOF'
import json
d = json.JSONDecoder().raw_decode(open("/tmp/plugins.json").read())[0]
plugins = d["plugins"] if isinstance(d, dict) else d
bad = [p["id"] for p in plugins if p["status"] != "ok"]
assert len(plugins) >= 30 and not bad, (len(plugins), bad)
print(f"METRIC: the daemon answers and verifies {len(plugins)} plugins against the embedded key")
PYEOF
"#;

/// Nothing of IbexWall's is left but the user's data.
const GONE: &str = r#"
if systemctl list-unit-files 'ibexwall*' --no-legend | grep -q .; then echo "UNITS REMAIN"; exit 1; fi
LEFT=$(leftovers)
[ -z "$LEFT" ] || { echo "FILES REMAIN:"; echo "$LEFT"; exit 1; }
echo "METRIC: removed: no unit or file left"
"#;

/// `makepkg` on the generated directory, as an AUR user runs it.
const AUR_BUILD: &str = r#"
[ "$FAM" = arch ] || { echo "THE aur PHASE RUNS ON --distro arch"; exit 1; }
sudo pacman -S --noconfirm --needed fakeroot binutils namcap >/tmp/tools.log 2>&1 || { tail -20 /tmp/tools.log; exit 1; }
rm -rf /var/tmp/aur && mkdir -p /var/tmp/aur && tar -C /var/tmp/aur -xzf /tmp/ibx-aur.tar.gz
cd /var/tmp/aur
makepkg --printsrcinfo > /tmp/srcinfo
diff -u .SRCINFO /tmp/srcinfo || { echo ".SRCINFO IS NOT WHAT makepkg WRITES"; exit 1; }
echo "METRIC: .SRCINFO is what makepkg --printsrcinfo writes"
makepkg -si --noconfirm >/tmp/makepkg.log 2>&1 || { tail -30 /tmp/makepkg.log; exit 1; }
grep -E 'Passed|FAILED' /tmp/makepkg.log | sed 's/^ */METRIC: sha256: /'
echo "METRIC: makepkg -si downloaded, checked, built and installed $(pacman -Qq | grep -c '^ibexwall') packages"
{ namcap PKGBUILD ./*-bin-*.pkg.tar.zst 2>&1 || true; } | grep -E ' (E|W): ' | cut -c1-200 | head -40 | sed 's/^/METRIC: namcap: /'
"#;

/// The installed files are the release's.
const AUR_CHECK: &str = r#"
cd /var/tmp/aur
META='.BUILDINFO .INSTALL .MTREE .PKGINFO'
EXCLUDE=$(for m in $META; do printf -- '--exclude %s ' "$m"; done)
# Names, kinds, modes and link targets of a tree, without pacman's metadata.
tree() { (cd "$1" && find . -mindepth 1 ! -name .BUILDINFO ! -name .INSTALL ! -name .MTREE ! -name .PKGINFO -printf '%M %l %p\n' | LC_ALL=C sort); }
for p in ibexwall ibexwall-desktop ibexwall-mcp; do
  rm -rf /var/tmp/orig && mkdir /var/tmp/orig
  bsdtar -xf "$p-$1-1-x86_64.pkg.tar.zst" -C /var/tmp/orig $EXCLUDE
  diff <(tree /var/tmp/orig) <(tree pkg/$p-bin) || { echo "$p-bin DIFFERS IN NAMES OR MODES"; exit 1; }
  diff -r --no-dereference -x .BUILDINFO -x .INSTALL -x .MTREE -x .PKGINFO /var/tmp/orig pkg/$p-bin || { echo "$p-bin DIFFERS IN CONTENT"; exit 1; }
  sudo pacman -Qkk $p-bin > /tmp/qkk 2>&1 || { cat /tmp/qkk; exit 1; }
  echo "METRIC: $(tail -1 /tmp/qkk)"
done
echo "METRIC: the three -bin packages hold the release packages' files, with the same modes"
"#;

const AUR_REMOVE: &str = r#"
sudo pacman -Rns --noconfirm ibexwall-mcp-bin ibexwall-desktop-bin ibexwall-bin >/tmp/remove.log 2>&1 || { tail -20 /tmp/remove.log; exit 1; }
# This test's own copies, which the search below would find.
rm -rf /var/tmp/aur /var/tmp/orig
"#;

const COPR_TOOLS: &str = r#"
[ "$FAM" = rpm ] || { echo "THE copr PHASE RUNS ON --distro fedora"; exit 1; }
sudo dnf install -y -q mock minisign >/tmp/tools.log 2>&1 || { tail -20 /tmp/tools.log; exit 1; }
sudo usermod -aG mock "$USER"
"#;

/// The source RPM, made the way COPR's "make srpm" method makes it: the
/// Makefile of a checkout, as root, in a clean chroot with network. A key
/// that did not sign the release has to stop it.
const COPR_SRPM: &str = r#"
W=/var/tmp/ibx
rm -rf $W && mkdir -p $W/repo $W/other && tar -C $W/repo -xzf /tmp/ibx-copr.tar.gz
cp -r $W/repo/. $W/other/
minisign -G -W -f -p $W/other/packaging/release.pub -s $W/other.key >/dev/null
# COPR's own configuration of that chroot (rpmbuild/mock-source-build.cfg.j2
# in fedora-copr/copr): the default one, plus make and dnf, with network.
C=$W/srpm.cfg
cat > $C <<'CFGEOF'
include('/etc/mock/default.cfg')
config_opts['root'] = 'make-srpm-method'
config_opts['rpmbuild_networking'] = True
config_opts['use_host_resolv'] = True
config_opts['chroot_additional_packages'] = 'make dnf'
config_opts['use_bootstrap'] = False
CFGEOF
mock -r $C --init >/tmp/mock-init.log 2>&1 || { tail -30 /tmp/mock-init.log; exit 1; }
mock -r $C --copyin $W/repo /var/tmp/repo >/dev/null 2>&1
mock -r $C --copyin $W/other /var/tmp/other >/dev/null 2>&1
if mock -r $C --enable-network --chroot 'make -f /var/tmp/other/.copr/Makefile srpm outdir=/var/tmp/refused' >/tmp/refused.log 2>&1; then echo "A RELEASE SIGNED BY ANOTHER KEY WAS ACCEPTED"; exit 1; fi
grep -hiE 'signature verification failed|key id' /tmp/refused.log | head -2 | sed 's/^/METRIC: another key: /'
grep -qiE 'signature verification failed|key id' /tmp/refused.log || { echo "REFUSED, BUT NOT FOR THE SIGNATURE"; tail -20 /tmp/refused.log; exit 1; }
mock -r $C --enable-network --chroot 'cd /var/tmp/repo && make -f /var/tmp/repo/.copr/Makefile srpm outdir="/var/tmp/out" spec=""' >/tmp/srpm.log 2>&1 || { tail -30 /tmp/srpm.log; exit 1; }
mock -r $C --copyout /var/tmp/out $W/srpm >/dev/null 2>&1
echo "METRIC: SRPM $(cd $W/srpm && ls) ($(du -h $W/srpm/*.src.rpm | cut -f1))"
mock -r $C --scrub=chroot >/dev/null 2>&1
"#;

/// The source RPM built in clean chroots without network, as COPR builds it,
/// for this Fedora and the one before; the payload is the release's.
const COPR_BUILD: &str = r#"
W=/var/tmp/ibx
F=$(rpm -E %fedora)
for r in $F $((F-1)); do
  C=fedora-$r-x86_64
  mock -r $C --rebuild $W/srpm/*.src.rpm --resultdir $W/result-$r >/tmp/build-$r.log 2>&1 || { tail -20 /tmp/build-$r.log; tail -40 $W/result-$r/build.log; exit 1; }
  echo "METRIC: $C built: $(cd $W/result-$r && ls *.x86_64.rpm | tr '\n' ' ')"
  mock -r $C --scrub=chroot >/dev/null 2>&1
done
U=https://github.com/nubian-ibex/ibexwall/releases/download/v$1
mkdir -p $W/published && cd $W/published
curl -fsSL -o SHA256SUMS $U/SHA256SUMS
payload() { rpm -qp --qf '[%{FILEDIGESTS} %{FILEMODES:perms} %{FILEUSERNAME}:%{FILEGROUPNAME} %{FILEFLAGS} %{FILELINKTOS} %{FILENAMES}\n]' "$1"; }
needs() { rpm -qp --requires --recommends --suggests "$1" | sed -E 's/\.fc[0-9]+$//' | LC_ALL=C sort -u; }
for p in ibexwall ibexwall-desktop ibexwall-mcp; do
  f=$(awk -v re="^$p-$1-1[.].*[.]x86_64[.]rpm\$" '$2 ~ re { print $2 }' SHA256SUMS)
  curl -fsSL -o "$f" "$U/$f"
  grep "  $f\$" SHA256SUMS | sha256sum -c --quiet -
  for r in $F $((F-1)); do
    b=$(ls $W/result-$r/$p-$1-1.*.x86_64.rpm)
    diff <(payload "$f") <(payload "$b") || { echo "$p (fc$r) DOES NOT HOLD THE RELEASE'S FILES"; exit 1; }
    echo "METRIC: $p fc$r: dependencies that differ from the release's: $({ diff <(needs "$f") <(needs "$b") || true; } | grep -c '^[<>]' || true) $({ diff <(needs "$f") <(needs "$b") || true; } | grep '^[<>]' | tr '\n' ' ')"
  done
done
echo "METRIC: both builds hold the published packages' files, with the same digests and modes"
"#;

const COPR_INSTALL: &str = r#"
cd /var/tmp/ibx/result-$(rpm -E %fedora)
mark_refusals
sudo dnf install -y -q ./*.x86_64.rpm >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log; exit 1; }
no_refusals INSTALLING
sudo semodule -l | grep -q '^ibexwall' || { echo "THE SELINUX MODULE IS NOT LOADED"; exit 1; }
rpm -V ibexwall ibexwall-desktop ibexwall-mcp ibexwall-selinux | grep -v '^\.\.\.\.\.\.\.\.\.  c ' && { echo "RPM -V FOUND DIFFERENCES"; exit 1; } || true
echo "METRIC: installed with the SELinux module loaded ($(getenforce)): $(rpm -qa 'ibexwall*' | sort | tr '\n' ' ')"
"#;

const COPR_REMOVE: &str = r#"
mark_refusals
sudo dnf remove -y -q ibexwall ibexwall-desktop ibexwall-mcp ibexwall-selinux >/tmp/remove.log 2>&1 || { tail -20 /tmp/remove.log; exit 1; }
no_refusals REMOVING
# This test's own builds, which the search below would find.
sudo rm -rf /var/tmp/ibx /var/lib/mock /var/cache/mock
"#;

/// A scenario whose script gets the release's version as `$1`.
fn scenario(vm: &Vm, name: &str, version: &str, body: &[&str]) -> bool {
    let script = format!("set -- {version}\n{LIB}{}", body.concat());
    run_script(vm, name, &script)
}

/// Sends `members` of `dir` to the VM as /tmp/`name`.
fn send(vm: &Vm, dir: &Path, members: &[&str], name: &str) -> Result<()> {
    let archive = workspace_root().join("target").join(name);
    let mut args = vec![
        "czf".to_string(),
        archive.display().to_string(),
        "-C".to_string(),
        dir.display().to_string(),
    ];
    args.extend(members.iter().map(|m| (*m).to_string()));
    run_capture("tar", &args, None, "packing")?;
    pipe_file(vm, &archive, &format!("cat > /tmp/{name}"))
}

/// Runs the scenarios in order; each one needs the one before it.
fn suite(vm: &Vm, phase: &str, scenarios: &[(&str, &[&str])]) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    for (name, body) in scenarios {
        if !scenario(vm, name, version, body) {
            bail!("{phase} failed at: {name}");
        }
    }
    println!("PASS: {phase} (all scenarios)");
    Ok(())
}

pub fn run_aur(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    let out = workspace.join("target/aur");
    aur(env!("CARGO_PKG_VERSION"), 1, &out)?;
    vm.ssh(install)
        .context("installing python3 and polkit in the VM")?;
    send(
        vm,
        &out,
        &["PKGBUILD", ".SRCINFO", "ibexwall.install"],
        "ibx-aur.tar.gz",
    )?;
    suite(
        vm,
        "aur",
        &[
            ("p1 makepkg installs the AUR directory", &[AUR_BUILD]),
            (
                "p2 the installed files are the release's and the daemon answers",
                &[AUR_CHECK, ANSWERS],
            ),
            ("p3 removal leaves nothing", &[AUR_REMOVE, GONE]),
        ],
    )
}

pub fn run_copr(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    vm.ssh(install)
        .context("installing python3 and polkit in the VM")?;
    send(vm, workspace, &[".copr", "packaging"], "ibx-copr.tar.gz")?;
    suite(
        vm,
        "copr",
        &[
            ("c0 mock and minisign", &[COPR_TOOLS]),
            ("c1 make srpm, as COPR runs it", &[COPR_SRPM]),
            (
                "c2 the SRPM builds without network on two Fedora releases",
                &[COPR_BUILD],
            ),
            (
                "c3 the built packages install and work",
                &[COPR_INSTALL, ANSWERS],
            ),
            ("c4 removal leaves nothing", &[COPR_REMOVE, GONE]),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sums() -> String {
        ["ibexwall", "ibexwall-desktop", "ibexwall-mcp"]
            .iter()
            .zip(["a", "b", "c"])
            .map(|(p, c)| format!("{}  {p}-1.2.3-1-x86_64.pkg.tar.zst\n", c.repeat(64)))
            .collect()
    }

    #[test]
    fn the_aur_files_carry_the_release_and_its_checksums() {
        let (pkgbuild, srcinfo) = render("1.2.3", 2, &sums()).unwrap();
        for text in [&pkgbuild, &srcinfo] {
            assert!(!text.contains("@VERSION@") && !text.contains("@SHA256"));
            assert!(!text.contains("@PKGREL@"));
            for c in ["a", "b", "c"] {
                assert!(text.contains(&c.repeat(64)));
            }
        }
        assert!(pkgbuild.contains("pkgver=1.2.3\npkgrel=2\n"));
        assert!(srcinfo.starts_with("pkgbase = ibexwall-bin\n\tpkgver = 1.2.3\n"));
        assert!(srcinfo.contains("\tdepends = ibexwall-bin=1.2.3-2\n"));
    }

    #[test]
    fn a_version_that_is_not_one_or_a_missing_checksum_is_refused() {
        assert!(render("1.2.3'; rm", 1, &sums()).is_err());
        assert!(render("", 1, &sums()).is_err());
        let error = render("1.2.4", 1, &sums()).unwrap_err().to_string();
        assert!(error.contains("ibexwall-1.2.4-1"), "{error}");
    }

    /// The `-bin` package installs what the Arch package installs, so it
    /// needs the same things.
    #[test]
    fn the_aur_package_depends_on_what_the_release_package_depends_on() {
        let read = |p: &str| std::fs::read_to_string(workspace_root().join(p)).unwrap();
        let needs = |text: &str| -> Vec<String> {
            text.lines()
                .map(str::trim)
                .filter(|l| {
                    ["pkgdesc=", "depends=", "optdepends=", "install="]
                        .iter()
                        .any(|k| l.starts_with(k))
                })
                .map(|l| l.replace("ibexwall-bin=", "ibexwall="))
                .collect()
        };
        let release = needs(&read("packaging/arch/PKGBUILD"));
        assert!(!release.is_empty());
        assert_eq!(needs(&read("packaging/arch/aur/PKGBUILD.in")), release);
    }
}
