// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F11b VM phase: managed-mode policy contracts. A test trust anchor
//! and signed bundle are generated on the host (Rust, no Python crypto
//! needed on the VM), the bundle is applied through the installed
//! daemon, the locks refuse a user change, and a tampered bundle is
//! rejected.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};

use super::f1::{pipe_data, pipe_file, run_script};
use super::vm::Vm;

/// Generates a deterministic test keypair and signed bundle on the host,
/// returning (anchor_path, bundle_json_text).
fn generate_test_bundle(workspace: &Path) -> Result<(PathBuf, String)> {
    let dir = workspace.join("target/f11b");
    std::fs::create_dir_all(&dir)?;
    let trust = dir.join("trust");
    std::fs::create_dir_all(&trust)?;

    let seed: [u8; 32] = *b"f11b-test-key-000000000000000000"; // 32 bytes
    let key = SigningKey::from_bytes(&seed);
    let key_id = "test-org-2026";

    let mut pub_bytes = Vec::with_capacity(42);
    pub_bytes.extend_from_slice(&[0x45, 0x64]);
    use sha2::Digest as _;
    let kid = sha2::Sha256::digest(key.verifying_key().as_bytes());
    pub_bytes.extend_from_slice(&kid[..8]);
    pub_bytes.extend_from_slice(key.verifying_key().as_bytes());
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(&pub_bytes);
    let anchor_text = format!("untrusted comment: f11b test key\n{pub_b64}\n");
    let anchor_path = trust.join(format!("{key_id}.pub"));
    std::fs::write(&anchor_path, &anchor_text)?;

    let mut bundle = serde_json::json!({
        "schema": "com.ibexwall.policy/v1",
        "org": { "id": "test-org", "name": "Test Org" },
        "version": 1,
        "issued_at": "2026-11-01T12:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
        "settings": { "net.dns": { "upstream": "https://dns.test.internal/dns-query" } },
        "locks": ["net.dns.upstream"],
        "report": { "include": ["posture", "findings"] },
    });
    let mut payload = bundle.clone();
    payload.as_object_mut().map(|o| o.remove("signature"));
    let payload_bytes = serde_jcs::to_vec(&payload)?;
    let sig = key.sign(&payload_bytes);
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    bundle["signature"] = serde_json::json!({
        "alg": "ed25519",
        "key_id": key_id,
        "value": sig_b64,
    });
    let bundle_text = serde_json::to_string_pretty(&bundle)?;
    Ok((anchor_path, bundle_text))
}

pub(crate) const LIB: &str = r#"
set -eE
if command -v dnf >/dev/null; then FAM=rpm
elif command -v apt-get >/dev/null; then FAM=deb
elif command -v pacman >/dev/null; then FAM=arch
else echo "UNKNOWN PACKAGE FAMILY"; exit 1; fi
"#;

pub(crate) const BUILD: &str = r#"
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
  mv ./*.deb out1/
  ;;
arch)
  sudo pacman -Sy --noconfirm --needed fakeroot binutils >/dev/null
  rm -rf pkg1 && mkdir pkg1 && cp packaging/arch/PKGBUILD packaging/arch/ibexwall.install pkg1/
  (cd pkg1 && IBEXWALL_STAGE=/tmp/ibx/stage PKGDEST=/tmp/ibx/out1 makepkg -f --nodeps --skipinteg --nocheck >/tmp/ibx/makepkg.log 2>&1) || { tail -30 /tmp/ibx/makepkg.log; exit 1; }
  ;;
esac
echo "METRIC: built $(ls out1 | wc -l) packages ($FAM)"
"#;

pub(crate) const INSTALL: &str = r#"
cd /tmp/ibx
case $FAM in
rpm) sudo dnf install -y -q out1/*.rpm >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log; exit 1; } ;;
deb) sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq ./out1/*.deb >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log; exit 1; } ;;
arch) sudo pacman -U --noconfirm out1/*.pkg.tar.zst >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log; exit 1; } ;;
esac
sudo ibexctl status >/dev/null || { echo "THE DAEMON DID NOT ANSWER"; sudo journalctl -u ibexwalld -n 20 --no-pager; exit 1; }
echo "METRIC: installed"
"#;

const POLICY: &str = r#"
# Place the trust anchor and apply the signed bundle through the daemon.
sudo mkdir -p /etc/ibexwall/trust
sudo cp /tmp/ibx-anchor.pub /etc/ibexwall/trust/test-org-2026.pub
sudo ibexctl policy apply-bundle /tmp/ibx-bundle.json --json 2>/tmp/apply.out || {
  echo "APPLY FAILED: $(cat /tmp/apply.out)"
  exit 1
}
# The lock must refuse a user change (net.dns.upstream is locked).
if sudo ibexctl plan net.dns --set preset=recommended --json 2>/dev/null; then
  echo "A LOCKED KEY WAS ALLOWED"; exit 1
fi
echo "METRIC: bundle applied and locks hold"
"#;

const REFUSE: &str = r#"
# Tamper with the locks field: the signature must fail.
cp /tmp/ibx-bundle.json /tmp/tampered.json
python3 - <<'PY'
import json
b = json.load(open('/tmp/tampered.json'))
b['locks'].append('net.firewall.*')
json.dump(b, open('/tmp/tampered.json','w'))
PY
if sudo ibexctl policy apply-bundle /tmp/tampered.json --json 2>/dev/null; then
  echo "A TAMPERED BUNDLE WAS ACCEPTED"; exit 1
fi
echo "METRIC: tampered bundle refused"
"#;

/// Stages the tree and packs it with the packaging sources, as the
/// package builds in the VM expect it.
pub(crate) fn stage_and_pack(workspace: &Path) -> Result<PathBuf> {
    crate::stage::run_stage(&crate::stage::Options {
        destdir: workspace.join("target/stage/root"),
        key_dir: workspace.join("target/devkey"),
        build: true,
        desktop: true,
        target_dir: None,
        build_env: Vec::new(),
    })?;
    let input = workspace.join("target/stage/pkg-input.tar.gz");
    let status = std::process::Command::new("tar")
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
    Ok(input)
}

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== f11b: stage ==");
    let input = stage_and_pack(workspace)?;

    let (anchor_path, bundle_text) = generate_test_bundle(workspace)?;
    println!("== f11b: provision ==");
    vm.ssh(install)
        .context("installing python3 and polkit in the VM")?;
    pipe_file(vm, &input, "cat > /tmp/ibx-input.tar.gz")?;
    pipe_data(vm, &bundle_text, "cat > /tmp/ibx-bundle.json")?;
    pipe_file(vm, &anchor_path, "cat > /tmp/ibx-anchor.pub")?;

    let mut failures = 0;
    macro_rules! scenario {
        ($name:expr, $body:expr) => {
            if !run_script(vm, $name, &[LIB, $body].concat()) {
                failures += 1;
            }
        };
    }
    scenario!("p0 the package builds on this distribution", BUILD);
    scenario!("p1 the package installs", INSTALL);
    scenario!("p2 a bundle applies and locks hold", POLICY);
    scenario!("p3 a tampered bundle is refused", REFUSE);

    if failures == 0 {
        println!("PASS: f11b managed-mode suite (all scenarios)");
        Ok(())
    } else {
        bail!("{failures} f11b scenario(s) failed")
    }
}
