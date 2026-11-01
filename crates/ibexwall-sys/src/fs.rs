// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Filesystem access. Real writes are atomic (tmp + fsync + rename) and
//! refuse symlinked parent paths via `openat2(RESOLVE_NO_SYMLINKS)`
//! (SEC-04).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rustix::fs::{self as rfs, Mode, OFlags};

use crate::log::OpLog;

/// Mode/owner metadata needed by snapshots and restores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMeta {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

pub trait Fs: Send + Sync {
    fn exists(&self, path: &Path) -> bool;
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn metadata(&self, path: &Path) -> io::Result<FileMeta>;
    /// Atomic write: temp file + fsync + rename; refuses symlinked
    /// parents; applies mode and (optionally) owner.
    fn write_atomic(
        &self,
        path: &Path,
        content: &[u8],
        mode: u32,
        owner: Option<(u32, u32)>,
    ) -> io::Result<()>;
    fn remove(&self, path: &Path) -> io::Result<()>;
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;
}

/// Opens `dir` component by component from `/`, each step relative to
/// the previous fd with `O_NOFOLLOW`, so no symlink anywhere in the path
/// is ever followed and nothing can be swapped in between steps.
///
/// Used instead of `openat2(RESOLVE_NO_SYMLINKS)`: systemd's
/// `RestrictSUIDSGID=` makes `openat2` return ENOSYS inside hardened
/// units (its mode argument cannot be inspected by seccomp).
fn open_dir_no_symlinks(dir: &Path) -> io::Result<std::os::fd::OwnedFd> {
    use std::path::Component;
    let flags = OFlags::DIRECTORY | OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut current = rfs::open("/", flags, Mode::empty())?;
    for component in dir.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                current = rfs::openat(&current, name, flags, Mode::empty())?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path must be absolute and normalized",
                ));
            }
        }
    }
    Ok(current)
}

/// Real filesystem with sandbox translation: operation paths arrive in
/// production form (`/etc/...`); under a sandbox root they are mapped
/// below it, so unprivileged runs never touch the host.
#[derive(Debug, Clone)]
pub struct RealFs {
    root: PathBuf,
}

impl Default for RealFs {
    fn default() -> Self {
        Self {
            root: ibexwall_proto::names::root(),
        }
    }
}

impl RealFs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_root(root: PathBuf) -> Self {
        Self { root }
    }

    fn translate(&self, path: &Path) -> PathBuf {
        if self.root == Path::new("/") {
            path.to_path_buf()
        } else {
            self.root.join(path.strip_prefix("/").unwrap_or(path))
        }
    }
}

impl Fs for RealFs {
    fn exists(&self, path: &Path) -> bool {
        self.translate(path).exists()
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        File::open(self.translate(path))?.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn metadata(&self, path: &Path) -> io::Result<FileMeta> {
        let meta = std::fs::metadata(self.translate(path))?;
        Ok(FileMeta {
            mode: meta.mode() & 0o7777,
            uid: meta.uid(),
            gid: meta.gid(),
        })
    }

    fn write_atomic(
        &self,
        path: &Path,
        content: &[u8],
        mode: u32,
        owner: Option<(u32, u32)>,
    ) -> io::Result<()> {
        let path = &self.translate(path);
        let parent = path.parent().ok_or_else(|| {
            io::Error::other(format!("write_atomic: `{}` has no parent", path.display()))
        })?;
        let name = path.file_name().ok_or_else(|| {
            io::Error::other(format!(
                "write_atomic: `{}` has no file name",
                path.display()
            ))
        })?;

        let dir_fd = open_dir_no_symlinks(parent)
            .map_err(|e| io::Error::other(format!("open parent {}: {e}", parent.display())))?;
        let tmp_name = format!(
            ".{}.ibexwall.tmp.{}",
            name.to_string_lossy(),
            std::process::id()
        );
        // A leftover from a crashed earlier write must not block us.
        let _ = rfs::unlinkat(&dir_fd, &tmp_name, rfs::AtFlags::empty());
        let tmp_fd = rfs::openat(
            &dir_fd,
            &tmp_name,
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY,
            Mode::from_bits_truncate(mode),
        )
        .map_err(|e| io::Error::other(format!("openat tmp: {e}")))?;
        let staged = (|| -> io::Result<()> {
            let mut file = File::from(tmp_fd);
            file.write_all(content)
                .map_err(|e| io::Error::other(format!("write_all: {e}")))?;
            // The creation mode is subject to umask; set it exactly.
            file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(mode))
                .map_err(|e| io::Error::other(format!("chmod: {e}")))?;
            if let Some((uid, gid)) = owner {
                // fchown on the staged fd: the final path may not exist yet.
                std::os::unix::fs::fchown(&file, Some(uid), Some(gid))
                    .map_err(|e| io::Error::other(format!("chown {uid}:{gid}: {e}")))?;
            }
            file.sync_all()
                .map_err(|e| io::Error::other(format!("sync_all: {e}")))?;
            Ok(())
        })();
        if let Err(e) = staged {
            let _ = rfs::unlinkat(&dir_fd, &tmp_name, rfs::AtFlags::empty());
            return Err(e);
        }
        if let Err(e) = rfs::renameat(&dir_fd, &tmp_name, &dir_fd, name) {
            let _ = rfs::unlinkat(&dir_fd, &tmp_name, rfs::AtFlags::empty());
            return Err(io::Error::other(format!("renameat: {e}")));
        }
        rfs::fsync(dir_fd.as_fd()).map_err(|e| io::Error::other(format!("fsync dir: {e}")))?;
        Ok(())
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        match std::fs::remove_file(self.translate(path)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(self.translate(path))
    }
}

#[derive(Debug, Clone)]
struct FakeFile {
    content: Vec<u8>,
    meta: FileMeta,
}

/// In-memory filesystem with an operation log; paths are compared
/// verbatim (callers build them via `names`, so sandboxed paths line
/// up).
#[derive(Debug, Default)]
pub struct FakeFs {
    files: Mutex<BTreeMap<PathBuf, FakeFile>>,
    pub log: OpLog,
}

impl FakeFs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed(&self, path: &Path, content: &[u8]) {
        self.files.lock().unwrap().insert(
            path.to_path_buf(),
            FakeFile {
                content: content.to_vec(),
                meta: FileMeta {
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                },
            },
        );
    }
}

impl Fs for FakeFs {
    fn exists(&self, path: &Path) -> bool {
        self.files.lock().unwrap().contains_key(path)
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.files
            .lock()
            .unwrap()
            .get(path)
            .map(|f| f.content.clone())
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn metadata(&self, path: &Path) -> io::Result<FileMeta> {
        self.files
            .lock()
            .unwrap()
            .get(path)
            .map(|f| f.meta)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn write_atomic(
        &self,
        path: &Path,
        content: &[u8],
        mode: u32,
        owner: Option<(u32, u32)>,
    ) -> io::Result<()> {
        self.log.push(format!("write {}", path.display()));
        let mut files = self.files.lock().unwrap();
        let mut meta = files.get(path).map(|f| f.meta).unwrap_or(FileMeta {
            mode: 0o644,
            uid: 0,
            gid: 0,
        });
        meta.mode = mode;
        if let Some((uid, gid)) = owner {
            meta.uid = uid;
            meta.gid = gid;
        }
        files.insert(
            path.to_path_buf(),
            FakeFile {
                content: content.to_vec(),
                meta,
            },
        );
        Ok(())
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        self.log.push(format!("remove {}", path.display()));
        self.files.lock().unwrap().remove(path);
        Ok(())
    }

    fn create_dir_all(&self, _path: &Path) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ibexwall-sys-fs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn real_fs_writes_atomically_with_mode() {
        let dir = tempdir();
        let target = dir.join("90-ibexwall.conf");
        let fs = RealFs::new();
        fs.write_atomic(&target, b"kernel.kptr_restrict = 2\n", 0o644, None)
            .unwrap();
        assert_eq!(
            RealFs::new().read(&target).unwrap(),
            b"kernel.kptr_restrict = 2\n"
        );
        assert_eq!(RealFs::new().metadata(&target).unwrap().mode, 0o644);

        // Overwrite in place (rename replaces).
        fs.write_atomic(&target, b"vm.swappiness = 10\n", 0o600, None)
            .unwrap();
        assert_eq!(
            RealFs::new().read(&target).unwrap(),
            b"vm.swappiness = 10\n"
        );
        assert_eq!(RealFs::new().metadata(&target).unwrap().mode, 0o600);

        // No temp leftovers.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn real_fs_refuses_symlinked_parents() {
        let dir = tempdir();
        let real = dir.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = RealFs::new().write_atomic(&link.join("evil.conf"), b"x\n", 0o644, None);
        assert!(err.is_err(), "writing through a symlinked parent must fail");
        assert!(!real.join("evil.conf").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fake_fs_roundtrip_and_log() {
        let fake = FakeFs::new();
        let path = Path::new("/etc/sysctl.d/90-ibexwall.conf");
        assert!(!fake.exists(path));
        fake.write_atomic(path, b"a = 1\n", 0o644, None).unwrap();
        assert!(fake.exists(path));
        assert_eq!(fake.read(path).unwrap(), b"a = 1\n");
        fake.remove(path).unwrap();
        assert!(!fake.exists(path));
        assert_eq!(
            fake.log.snapshot(),
            vec![
                "write /etc/sysctl.d/90-ibexwall.conf",
                "remove /etc/sysctl.d/90-ibexwall.conf"
            ]
        );
    }

    #[test]
    fn nested_sandbox_shape_writes() {
        let dir = tempdir();
        let nested = dir.join("root/etc/sysctl.d");
        std::fs::create_dir_all(&nested).unwrap();
        let target = Path::new("/etc/sysctl.d/probe.conf");
        let fs = RealFs::with_root(dir.join("root"));
        fs.write_atomic(target, b"probe\n", 0o644, None).unwrap();
        assert_eq!(fs.read(target).unwrap(), b"probe\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_is_idempotent_when_missing() {
        let dir = tempdir();
        let target = dir.join("missing.conf");
        RealFs::new().remove(&target).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
