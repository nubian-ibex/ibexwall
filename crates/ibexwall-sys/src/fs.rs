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

use rustix::fs::{self as rfs, Mode, OFlags, ResolveFlags};

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

#[derive(Debug, Default)]
pub struct RealFs;

impl Fs for RealFs {
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        File::open(path)?.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn metadata(&self, path: &Path) -> io::Result<FileMeta> {
        let meta = std::fs::metadata(path)?;
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
        let parent = path.parent().ok_or_else(|| {
            io::Error::other(format!("write_atomic: `{}` has no parent", path.display()))
        })?;
        let name = path.file_name().ok_or_else(|| {
            io::Error::other(format!(
                "write_atomic: `{}` has no file name",
                path.display()
            ))
        })?;

        // Open the parent directory refusing any symlink in its path.
        // RDONLY (not O_PATH): fsync(2) rejects O_PATH descriptors.
        let dir_fd = rfs::openat2(
            rfs::CWD,
            parent,
            OFlags::DIRECTORY | OFlags::RDONLY,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )?;

        // Write the content to a fresh temp file, fsync, then rename.
        let tmp_name = format!(
            ".{}.ibexwall.tmp.{}",
            name.to_string_lossy(),
            std::process::id()
        );
        let tmp_fd = rfs::openat(
            &dir_fd,
            &tmp_name,
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY,
            Mode::from_bits_truncate(mode),
        )?;
        {
            let mut file = File::from(tmp_fd);
            file.write_all(content)?;
            file.sync_all()?;
        }
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
        }
        rfs::renameat(&dir_fd, &tmp_name, &dir_fd, name)?;
        rfs::fsync(dir_fd.as_fd())?;
        Ok(())
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)
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
        RealFs
            .write_atomic(&target, b"kernel.kptr_restrict = 2\n", 0o644, None)
            .unwrap();
        assert_eq!(RealFs.read(&target).unwrap(), b"kernel.kptr_restrict = 2\n");
        assert_eq!(RealFs.metadata(&target).unwrap().mode, 0o644);

        // Overwrite in place (rename replaces).
        RealFs
            .write_atomic(&target, b"vm.swappiness = 10\n", 0o600, None)
            .unwrap();
        assert_eq!(RealFs.read(&target).unwrap(), b"vm.swappiness = 10\n");
        assert_eq!(RealFs.metadata(&target).unwrap().mode, 0o600);

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

        let err = RealFs.write_atomic(&link.join("evil.conf"), b"x\n", 0o644, None);
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
    fn remove_is_idempotent_when_missing() {
        let dir = tempdir();
        let target = dir.join("missing.conf");
        RealFs.remove(&target).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
