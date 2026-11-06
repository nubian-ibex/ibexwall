// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The supply chain of a release: `cargo xtask release` builds the artifacts,
//! lists what is in them (a CycloneDX SBOM), says how they were made (an
//! in-toto statement with a SLSA provenance predicate), checksums and signs
//! them, and checks its own signatures. `cargo xtask verify-release` is what
//! anyone does with the result, and `cargo xtask repro` builds twice in
//! different directories and compares.
//!
//! The signing key is the maintainer's: `--key-dir` holds `dev.pub` and
//! `dev.key` (the names the plugin signing uses). The key never enters the
//! repository, and a release made with the development key says so in its
//! signatures.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::devkey;
use crate::stage::{self, Options};

pub struct Release {
    pub version: String,
    pub key_dir: PathBuf,
    pub out: PathBuf,
    pub build: bool,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .expect("the workspace exists")
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn command_output(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(root())
        .output()
        .with_context(|| format!("running {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// The commit time of HEAD: every timestamp in a release comes from it, so
/// building the same commit twice gives the same bytes.
pub fn source_date_epoch() -> Result<String> {
    if let Ok(value) = std::env::var("SOURCE_DATE_EPOCH") {
        return Ok(value);
    }
    command_output("git", &["log", "-1", "--format=%ct"])
}

fn rfc3339(epoch: &str) -> String {
    let seconds: i64 = epoch.parse().unwrap_or(0);
    ibexwall_sys::format_rfc3339(seconds)
}

/// The environment of a build that gives the same bytes anywhere: the
/// timestamp fixed, and the paths of the source tree and of the cargo
/// registry replaced in what the compiler records.
pub fn reproducible_env(epoch: &str, source: &Path) -> Vec<(String, String)> {
    let home = std::env::var("CARGO_HOME").unwrap_or_else(|_| {
        format!(
            "{}/.cargo",
            std::env::var("HOME").unwrap_or_else(|_| "/root".into())
        )
    });
    vec![
        ("SOURCE_DATE_EPOCH".into(), epoch.into()),
        (
            "RUSTFLAGS".into(),
            format!(
                "--remap-path-prefix={}=/build --remap-path-prefix={home}=/cargo",
                source.display()
            ),
        ),
        ("CARGO_INCREMENTAL".into(), "0".into()),
    ]
}

// SBOM.

/// A component of the CycloneDX document.
struct Component {
    name: String,
    version: String,
    purl: String,
    license: Option<String>,
    sha256: Option<String>,
    sha512: Option<String>,
    repository: Option<String>,
}

type Graph = BTreeMap<String, Vec<String>>;

fn is_normal_or_build(dep: &Value) -> bool {
    dep["dep_kinds"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|k| k["kind"].is_null() || k["kind"] == "build")
}

fn cargo_components(manifest: Option<&Path>) -> Result<(Vec<Component>, Graph)> {
    let mut args = vec![
        "metadata",
        "--format-version",
        "1",
        "--locked",
        "--filter-platform",
        "x86_64-unknown-linux-gnu",
    ];
    let manifest_text;
    if let Some(path) = manifest {
        manifest_text = path.display().to_string();
        args.extend(["--manifest-path", &manifest_text]);
    }
    let metadata: Value = serde_json::from_str(&command_output("cargo", &args)?)?;
    let packages = metadata["packages"].as_array().context("packages")?;
    let by_id: BTreeMap<&str, &Value> = packages
        .iter()
        .filter_map(|p| Some((p["id"].as_str()?, p)))
        .collect();
    let nodes = metadata["resolve"]["nodes"].as_array().context("nodes")?;
    let node_of: BTreeMap<&str, &Value> = nodes
        .iter()
        .filter_map(|n| Some((n["id"].as_str()?, n)))
        .collect();

    // What the shipped binaries are built from: normal and build dependencies
    // of the workspace members, never the dev-only ones.
    let members: Vec<&str> = metadata["workspace_members"]
        .as_array()
        .context("members")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut reach: BTreeSet<&str> = BTreeSet::new();
    let mut queue: Vec<&str> = members.clone();
    while let Some(id) = queue.pop() {
        if !reach.insert(id) {
            continue;
        }
        let Some(node) = node_of.get(id) else {
            continue;
        };
        for dep in node["deps"].as_array().into_iter().flatten() {
            if let (true, Some(next)) = (is_normal_or_build(dep), dep["pkg"].as_str()) {
                queue.push(next);
            }
        }
    }

    let purl = |p: &Value| {
        format!(
            "pkg:cargo/{}@{}",
            p["name"].as_str().unwrap_or(""),
            p["version"].as_str().unwrap_or("")
        )
    };
    let lock = read_lock();
    let mut components = Vec::new();
    let mut graph: Graph = BTreeMap::new();
    for id in &reach {
        let Some(package) = by_id.get(id) else {
            continue;
        };
        let reference = purl(package);
        let mut deps: Vec<String> = node_of
            .get(id)
            .map(|n| {
                n["deps"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|d| is_normal_or_build(d))
                    .filter_map(|d| by_id.get(d["pkg"].as_str()?).map(|p| purl(p)))
                    .collect()
            })
            .unwrap_or_default();
        deps.sort();
        deps.dedup();
        graph.insert(reference.clone(), deps);
        if members.contains(id) {
            continue;
        }
        let name = package["name"].as_str().unwrap_or("").to_string();
        let version = package["version"].as_str().unwrap_or("").to_string();
        components.push(Component {
            sha256: lock.get(&(name.clone(), version.clone())).cloned(),
            name,
            version,
            purl: reference,
            license: package["license"].as_str().map(str::to_string),
            sha512: None,
            repository: package["repository"].as_str().map(str::to_string),
        });
    }
    Ok((components, graph))
}

/// The checksums Cargo.lock records for registry crates (SHA-256 of the
/// `.crate` file), by name and version.
fn read_lock() -> BTreeMap<(String, String), String> {
    let mut out = BTreeMap::new();
    for lock in ["Cargo.lock", "ui/src-tauri/Cargo.lock"] {
        let Ok(text) = std::fs::read_to_string(root().join(lock)) else {
            continue;
        };
        let value: toml::Table = text.parse().unwrap_or_default();
        for package in value
            .get("package")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let field = |k: &str| {
                package
                    .get(k)
                    .and_then(toml::Value::as_str)
                    .map(str::to_string)
            };
            if let (Some(name), Some(version), Some(sum)) =
                (field("name"), field("version"), field("checksum"))
            {
                out.insert((name, version), sum);
            }
        }
    }
    out
}

/// The production dependencies of the interface, from pnpm's lock file: what
/// the bundled JavaScript is made of. The lock's format is regular enough to
/// read without a YAML parser.
fn npm_components() -> Result<Vec<Component>> {
    let text =
        std::fs::read_to_string(root().join("ui/pnpm-lock.yaml")).context("ui/pnpm-lock.yaml")?;
    let mut section = "";
    let mut integrity: BTreeMap<String, String> = BTreeMap::new();
    let mut snapshot_deps: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current = String::new();
    let mut in_deps = false;
    let mut prod_roots: Vec<String> = Vec::new();
    let mut in_importer_prod = false;
    let mut pending_name = String::new();
    for line in text.lines() {
        if !line.starts_with(' ') && line.ends_with(':') {
            section = match line.trim_end_matches(':') {
                "importers" => "importers",
                "packages" => "packages",
                "snapshots" => "snapshots",
                _ => "",
            };
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        match section {
            "importers" => {
                if indent == 4 {
                    in_importer_prod = trimmed == "dependencies:";
                } else if in_importer_prod && indent == 6 && trimmed.ends_with(':') {
                    pending_name = trimmed.trim_end_matches(':').trim_matches('\'').to_string();
                } else if in_importer_prod
                    && indent == 8
                    && let Some(version) = trimmed.strip_prefix("version: ")
                {
                    prod_roots.push(format!("{pending_name}@{version}"));
                }
            }
            "packages" => {
                if indent == 2 && trimmed.ends_with(':') {
                    current = trimmed.trim_end_matches(':').trim_matches('\'').to_string();
                } else if let Some(rest) = trimmed.strip_prefix("resolution: {integrity: ") {
                    let value = rest.split([',', '}']).next().unwrap_or("").to_string();
                    integrity.insert(current.clone(), value);
                }
            }
            "snapshots" => {
                if indent == 2 && trimmed.ends_with(':') {
                    current = trimmed.trim_end_matches(':').trim_matches('\'').to_string();
                    in_deps = false;
                } else if indent == 4 {
                    in_deps = trimmed == "dependencies:" || trimmed == "optionalDependencies:";
                } else if in_deps
                    && indent == 6
                    && let Some((name, version)) = trimmed.split_once(": ")
                {
                    let name = name.trim_matches('\'');
                    snapshot_deps
                        .entry(current.clone())
                        .or_default()
                        .push(format!("{name}@{}", version.trim_matches('\'')));
                }
            }
            _ => {}
        }
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue = prod_roots;
    while let Some(key) = queue.pop() {
        if !seen.insert(key.clone()) {
            continue;
        }
        queue.extend(snapshot_deps.get(&key).cloned().unwrap_or_default());
    }
    let mut out = Vec::new();
    for key in seen {
        // `name@1.2.3(peer@...)` is one install; the package is `name@1.2.3`.
        let plain = key.split('(').next().unwrap_or(&key);
        let Some((name, version)) = plain.rsplit_once('@') else {
            continue;
        };
        let sri = integrity.get(plain).cloned().unwrap_or_default();
        let sha512 = sri.strip_prefix("sha512-").and_then(base64_to_hex);
        out.push(Component {
            name: name.to_string(),
            version: version.to_string(),
            purl: format!("pkg:npm/{}@{version}", name.replace('@', "%40")),
            license: None,
            sha256: None,
            sha512,
            repository: None,
        });
    }
    out.sort_by(|a, b| a.purl.cmp(&b.purl));
    out.dedup_by(|a, b| a.purl == b.purl);
    Ok(out)
}

fn base64_to_hex(text: &str) -> Option<String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .ok()
        .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// The CycloneDX 1.6 document for a release.
pub fn sbom(version: &str, epoch: &str) -> Result<Value> {
    let root = root();
    let (mut components, mut graph) = cargo_components(None)?;
    let (desktop, desktop_graph) = cargo_components(Some(&root.join("ui/src-tauri/Cargo.toml")))?;
    let known: BTreeSet<String> = components.iter().map(|c| c.purl.clone()).collect();
    components.extend(desktop.into_iter().filter(|c| !known.contains(&c.purl)));
    for (key, deps) in desktop_graph {
        let entry = graph.entry(key).or_default();
        entry.extend(deps);
        entry.sort();
        entry.dedup();
    }
    components.extend(npm_components()?);
    components.sort_by(|a, b| a.purl.cmp(&b.purl));
    components.dedup_by(|a, b| a.purl == b.purl);

    let rendered: Vec<Value> = components
        .iter()
        .map(|c| {
            let mut value = json!({
                "type": "library",
                "bom-ref": c.purl,
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
            });
            if let Some(license) = &c.license {
                // An SPDX expression, as Cargo records it.
                value["licenses"] = json!([{ "expression": license }]);
            }
            let mut hashes = Vec::new();
            if let Some(h) = &c.sha256 {
                hashes.push(json!({ "alg": "SHA-256", "content": h }));
            }
            if let Some(h) = &c.sha512 {
                hashes.push(json!({ "alg": "SHA-512", "content": h }));
            }
            if !hashes.is_empty() {
                value["hashes"] = Value::Array(hashes);
            }
            if let Some(repo) = &c.repository {
                value["externalReferences"] = json!([{ "type": "vcs", "url": repo }]);
            }
            value
        })
        .collect();
    let dependencies: Vec<Value> = graph
        .into_iter()
        .map(|(reference, deps)| json!({ "ref": reference, "dependsOn": deps }))
        .collect();
    // A serial number derived from the content, so the same inputs give the same document.
    let serial = {
        let digest = sha256_hex(serde_json::to_string(&rendered)?.as_bytes());
        format!(
            "urn:uuid:{}-{}-{}-{}-{}",
            &digest[0..8],
            &digest[8..12],
            &digest[12..16],
            &digest[16..20],
            &digest[20..32]
        )
    };
    Ok(json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": rfc3339(epoch),
            "tools": { "components": [{ "type": "application", "name": "ibexwall xtask" }] },
            "component": {
                "type": "application",
                "bom-ref": format!("pkg:github/nubian-ibex/ibexwall@{version}"),
                "name": "ibexwall",
                "version": version,
                "licenses": [{ "expression": "GPL-3.0-or-later" }],
            },
        },
        "components": rendered,
        "dependencies": dependencies,
    }))
}

// Provenance.

/// An in-toto statement whose predicate is SLSA provenance v1: what was built,
/// from which commit and inputs, by what. A build on this machine says so
/// (`local`); the CI release workflow adds GitHub's own attestation next to it.
pub fn provenance(
    version: &str,
    epoch: &str,
    subjects: &BTreeMap<String, String>,
) -> Result<Value> {
    let commit = command_output("git", &["rev-parse", "HEAD"])?;
    let dirty = !command_output("git", &["status", "--porcelain"])?.is_empty();
    let digest_of = |relative: &str| {
        std::fs::read(root().join(relative))
            .map(|bytes| sha256_hex(&bytes))
            .unwrap_or_default()
    };
    let builder = if std::env::var("GITHUB_ACTIONS").is_ok() {
        format!(
            "{}/{}/.github/workflows/release.yml",
            std::env::var("GITHUB_SERVER_URL").unwrap_or_else(|_| "https://github.com".into()),
            std::env::var("GITHUB_REPOSITORY").unwrap_or_default()
        )
    } else {
        "local".to_string()
    };
    Ok(json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects
            .iter()
            .map(|(name, sha)| json!({ "name": name, "digest": { "sha256": sha } }))
            .collect::<Vec<_>>(),
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/nubian-ibex/ibexwall/blob/main/docs/release.md#build-type",
                "externalParameters": {
                    "source": { "uri": "git+https://github.com/nubian-ibex/ibexwall", "digest": { "gitCommit": commit } },
                    "version": version,
                    "workingTreeClean": !dirty,
                },
                "internalParameters": {
                    "rustc": command_output("rustc", &["-V"])?,
                    "cargo": command_output("cargo", &["-V"])?,
                    "sourceDateEpoch": epoch,
                },
                "resolvedDependencies": [
                    { "name": "Cargo.lock", "digest": { "sha256": digest_of("Cargo.lock") } },
                    { "name": "ui/pnpm-lock.yaml", "digest": { "sha256": digest_of("ui/pnpm-lock.yaml") } },
                    { "name": "ui/src-tauri/Cargo.lock", "digest": { "sha256": digest_of("ui/src-tauri/Cargo.lock") } },
                    { "name": "rust-toolchain.toml", "digest": { "sha256": digest_of("rust-toolchain.toml") } },
                ],
            },
            "runDetails": {
                "builder": { "id": builder },
                "metadata": {
                    "invocationId": std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".into()),
                    "finishedOn": rfc3339(epoch),
                },
            },
        },
    }))
}

// The release.

fn tar_gz(dir: &Path, name: &str, epoch: &str, into: &Path) -> Result<()> {
    // GNU tar, with the order, owners and times fixed, and gzip without a name
    // or time: the same tree gives the same bytes.
    let tar = into.with_extension("tar");
    let status = Command::new("tar")
        .args([
            "--sort=name",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            &format!("--mtime=@{epoch}"),
            "--format=gnu",
            "-cf",
        ])
        .arg(&tar)
        .arg("-C")
        .arg(dir)
        .arg(name)
        .status()
        .context("tar")?;
    if !status.success() {
        bail!("tar failed");
    }
    let output = Command::new("gzip")
        .args(["-n", "-9", "-c"])
        .arg(&tar)
        .output()?;
    if !output.status.success() {
        bail!("gzip failed");
    }
    std::fs::write(into, output.stdout)?;
    std::fs::remove_file(tar)?;
    Ok(())
}

fn source_archive(version: &str, into: &Path) -> Result<()> {
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "git archive --format=tar --prefix=ibexwall-{version}/ HEAD | gzip -n -9 > '{}'",
            into.display()
        ))
        .current_dir(root())
        .status()?;
    if !status.success() {
        bail!("git archive failed");
    }
    Ok(())
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

pub fn run_release(options: &Release) -> Result<()> {
    let root = root();
    let epoch = source_date_epoch()?;
    std::fs::create_dir_all(&options.out)?;
    let out = options.out.canonicalize()?;
    let version = &options.version;
    let pair = devkey::ensure_keypair(
        &options.key_dir.join("dev.pub"),
        &options.key_dir.join("dev.key"),
    )?;

    let staging = out.join("stage");
    stage::run_stage(&Options {
        destdir: staging.join("root"),
        key_dir: options.key_dir.clone(),
        build: options.build,
        desktop: true,
        target_dir: None,
        build_env: reproducible_env(&epoch, &root),
    })?;

    let mut artifacts: Vec<PathBuf> = Vec::new();
    let tree = out.join(format!("ibexwall-{version}-x86_64-linux.tar.gz"));
    // The tree is archived under a directory of the release's name.
    let named = staging.join(format!("ibexwall-{version}-x86_64-linux"));
    let _ = std::fs::remove_dir_all(&named);
    std::fs::rename(staging.join("root"), &named)?;
    tar_gz(
        &staging,
        &format!("ibexwall-{version}-x86_64-linux"),
        &epoch,
        &tree,
    )?;
    artifacts.push(tree);

    let source = out.join(format!("ibexwall-{version}.tar.gz"));
    source_archive(version, &source)?;
    artifacts.push(source);

    let ebpf = out.join(format!("ibexwall-ebpf-{version}.o"));
    std::fs::copy(root.join("target/bpf/ibexwall-ebpf.o"), &ebpf)?;
    artifacts.push(ebpf);

    let sbom_path = out.join(format!("ibexwall-{version}.cdx.json"));
    std::fs::write(
        &sbom_path,
        serde_json::to_string_pretty(&sbom(version, &epoch)?)? + "\n",
    )?;
    artifacts.push(sbom_path);

    let mut subjects = BTreeMap::new();
    for path in &artifacts {
        subjects.insert(file_name(path), sha256_hex(&std::fs::read(path)?));
    }
    let statement = out.join(format!("ibexwall-{version}.intoto.json"));
    std::fs::write(
        &statement,
        serde_json::to_string_pretty(&provenance(version, &epoch, &subjects)?)? + "\n",
    )?;
    artifacts.push(statement);

    // The checksums, then a signature for every file and for the checksums.
    let mut names: Vec<String> = artifacts.iter().map(|p| file_name(p)).collect();
    names.sort();
    let mut sums = String::new();
    for name in &names {
        sums.push_str(&format!(
            "{}  {name}\n",
            sha256_hex(&std::fs::read(out.join(name))?)
        ));
    }
    std::fs::write(out.join("SHA256SUMS"), &sums)?;
    names.push("SHA256SUMS".into());
    for name in &names {
        let data = std::fs::read(out.join(name))?;
        let signature = devkey::sign_labelled(
            &pair,
            &data,
            &format!("ibexwall {version} {name}"),
            "ibexwall release signature",
        );
        std::fs::write(out.join(format!("{name}.minisig")), signature)?;
    }
    std::fs::copy(
        options.key_dir.join("dev.pub"),
        out.join("ibexwall-release.pub"),
    )?;
    // The staged tree is in the archive; the copy is only a work area.
    let _ = std::fs::remove_dir_all(&staging);
    println!(
        "release {version}: {} files in {}",
        names.len() * 2,
        out.display()
    );
    verify(&out, &out.join("ibexwall-release.pub"))
}

/// What anyone does with a release: the checksums match the files, and every
/// signature is by the key they hold.
pub fn verify(dir: &Path, public_key: &Path) -> Result<()> {
    let key = minisign_verify::PublicKey::decode(&std::fs::read_to_string(public_key)?)
        .map_err(|e| anyhow::anyhow!("public key: {e}"))?;
    let check_signature = |name: &str| -> Result<()> {
        let data = std::fs::read(dir.join(name)).with_context(|| name.to_string())?;
        let text = std::fs::read_to_string(dir.join(format!("{name}.minisig")))
            .with_context(|| format!("{name}.minisig"))?;
        let signature = minisign_verify::Signature::decode(&text)
            .map_err(|e| anyhow::anyhow!("{name}.minisig: {e}"))?;
        key.verify(&data, &signature, false)
            .map_err(|e| anyhow::anyhow!("{name}: the signature does not verify: {e}"))
    };
    // The list of checksums is signed first: nothing in it is believed before that.
    check_signature("SHA256SUMS")?;
    let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).context("SHA256SUMS")?;
    let mut names = Vec::new();
    for line in sums.lines() {
        let (sum, name) = line.split_once("  ").context("a line of SHA256SUMS")?;
        let data = std::fs::read(dir.join(name)).with_context(|| name.to_string())?;
        if sha256_hex(&data) != sum {
            bail!("{name}: the checksum does not match");
        }
        check_signature(name)?;
        names.push(name.to_string());
    }
    println!(
        "verified: {} checksums and {} signatures in {}",
        names.len(),
        names.len() + 1,
        dir.display()
    );
    Ok(())
}

// Reproducibility.

/// The SHA-256 of every file under `dir`, by relative path.
fn tree_digest(dir: &Path) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            let relative = entry.path().strip_prefix(dir)?.display().to_string();
            if kind.is_dir() {
                stack.push(entry.path());
            } else if kind.is_symlink() {
                out.insert(
                    relative,
                    format!("link:{}", std::fs::read_link(entry.path())?.display()),
                );
            } else {
                out.insert(relative, sha256_hex(&std::fs::read(entry.path())?));
            }
        }
    }
    Ok(out)
}

fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

/// Builds the staged tree twice, from copies of HEAD in different
/// directories with different target directories, and compares every file.
pub fn repro(key_dir: &Path, with_desktop: bool) -> Result<()> {
    let epoch = source_date_epoch()?;
    let base = std::env::temp_dir().join(format!("ibexwall-repro-{}", std::process::id()));
    let mut trees = Vec::new();
    for name in ["a", "b"] {
        let dir = base.join(name);
        let source = dir.join("src");
        std::fs::create_dir_all(&source)?;
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "git archive HEAD | tar -x -C '{}'",
                source.display()
            ))
            .current_dir(root())
            .status()?;
        if !status.success() {
            bail!("could not copy the source");
        }
        // What the build needs and git does not track.
        std::fs::create_dir_all(source.join("target/bpf"))?;
        std::fs::copy(
            root().join("target/bpf/ibexwall-ebpf.o"),
            source.join("target/bpf/ibexwall-ebpf.o"),
        )?;
        if with_desktop {
            copy_dir(&root().join("ui/dist"), &source.join("ui/dist"))?;
        }
        println!("== repro: build {name} in {}", source.display());
        let mut command = Command::new("cargo");
        command
            .args(["run", "-q", "-p", "xtask", "--", "stage", "--destdir"])
            .arg(dir.join("root"))
            .arg("--key-dir")
            .arg(key_dir)
            .arg("--target-dir")
            .arg(dir.join("target"))
            .current_dir(&source)
            .env("CARGO_INCREMENTAL", "0");
        if !with_desktop {
            command.arg("--no-desktop");
        }
        for (key, value) in reproducible_env(&epoch, &source) {
            command.env(key, value);
        }
        if !command.status()?.success() {
            bail!("build {name} failed");
        }
        trees.push(tree_digest(&dir.join("root"))?);
    }
    let (a, b) = (&trees[0], &trees[1]);
    let differing: Vec<&String> = a
        .keys()
        .chain(b.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|k| a.get(*k) != b.get(*k))
        .collect();
    if differing.is_empty() {
        println!("reproducible: {} files, identical", a.len());
        let _ = std::fs::remove_dir_all(&base);
        return Ok(());
    }
    for name in &differing {
        println!("differs: {name}");
    }
    bail!(
        "{} of {} files differ between the two builds (kept in {})",
        differing.len(),
        a.len(),
        base.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sbom_lists_the_crates_and_the_bundled_packages_with_their_hashes() {
        let document = sbom("0.1.0", "1700000000").unwrap();
        assert_eq!(document["bomFormat"], "CycloneDX");
        assert_eq!(document["specVersion"], "1.6");
        let components = document["components"].as_array().unwrap();
        let serde = components
            .iter()
            .find(|c| c["name"] == "serde" && c["purl"].as_str().unwrap().starts_with("pkg:cargo/"))
            .expect("serde is in the SBOM");
        assert_eq!(serde["hashes"][0]["alg"], "SHA-256");
        assert_eq!(serde["hashes"][0]["content"].as_str().unwrap().len(), 64);
        assert!(serde["licenses"][0]["expression"].is_string());
        // The interface's bundled runtime dependencies are there too.
        assert!(
            components.iter().any(|c| c["purl"]
                .as_str()
                .unwrap()
                .starts_with("pkg:npm/%40fluent/bundle@")),
            "the fluent bundle"
        );
        // And nothing that only the tests use.
        assert!(!components.iter().any(|c| c["name"] == "vitest"));
        // The timestamp is the commit's, not the clock's.
        assert_eq!(document["metadata"]["timestamp"], "2023-11-14T22:13:20Z");
        // The same inputs give the same document.
        assert_eq!(document, sbom("0.1.0", "1700000000").unwrap());
        for dep in document["dependencies"].as_array().unwrap() {
            assert!(dep["ref"].is_string());
        }
    }

    #[test]
    fn provenance_names_the_subjects_the_source_and_the_inputs() {
        let subjects = BTreeMap::from([("a.tar.gz".to_string(), "ab".repeat(32))]);
        let statement = provenance("0.1.0", "1700000000", &subjects).unwrap();
        assert_eq!(statement["_type"], "https://in-toto.io/Statement/v1");
        assert_eq!(statement["predicateType"], "https://slsa.dev/provenance/v1");
        assert_eq!(statement["subject"][0]["name"], "a.tar.gz");
        let definition = &statement["predicate"]["buildDefinition"];
        assert_eq!(
            definition["externalParameters"]["source"]["digest"]["gitCommit"]
                .as_str()
                .unwrap()
                .len(),
            40
        );
        assert_eq!(definition["resolvedDependencies"][0]["name"], "Cargo.lock");
        assert_eq!(
            definition["resolvedDependencies"][0]["digest"]["sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert!(statement["predicate"]["runDetails"]["builder"]["id"].is_string());
    }

    #[test]
    fn a_release_is_verified_by_its_checksums_and_signatures_and_a_change_is_caught() {
        let dir = std::env::temp_dir().join(format!("ibx-release-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pair = devkey::ensure_keypair(&dir.join("k.pub"), &dir.join("k.key")).unwrap();
        std::fs::write(dir.join("a.txt"), b"artifact").unwrap();
        std::fs::write(
            dir.join("SHA256SUMS"),
            format!("{}  a.txt\n", sha256_hex(b"artifact")),
        )
        .unwrap();
        for name in ["a.txt", "SHA256SUMS"] {
            let data = std::fs::read(dir.join(name)).unwrap();
            std::fs::write(
                dir.join(format!("{name}.minisig")),
                devkey::sign_labelled(&pair, &data, name, "ibexwall release signature"),
            )
            .unwrap();
        }
        verify(&dir, &dir.join("k.pub")).unwrap();
        // A changed artifact fails its checksum; a changed checksum list fails its signature.
        std::fs::write(dir.join("a.txt"), b"tampered").unwrap();
        assert!(
            verify(&dir, &dir.join("k.pub"))
                .unwrap_err()
                .to_string()
                .contains("checksum")
        );
        std::fs::write(dir.join("a.txt"), b"artifact").unwrap();
        std::fs::write(
            dir.join("SHA256SUMS"),
            format!("{}  a.txt\n\n", sha256_hex(b"artifact")),
        )
        .unwrap();
        assert!(
            verify(&dir, &dir.join("k.pub"))
                .unwrap_err()
                .to_string()
                .contains("signature")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
