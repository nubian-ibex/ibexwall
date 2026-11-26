// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Saving the exported state file (ADR-0049) as the person using the app.

use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// Writes the file into `dir`, readable by its owner only, and returns the
/// path. Never overwrites: a second export of the day gets a suffix.
pub(crate) fn save(dir: &Path, file: &Value) -> io::Result<PathBuf> {
    // The date comes from the daemon's reply: keep only what a date has, so
    // the name can never reach outside `dir`.
    let date: String = file["exported_at"]
        .as_str()
        .unwrap_or_default()
        .chars()
        .take(10)
        .filter(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    let text = serde_json::to_string_pretty(file)? + "\n";
    for n in 1..100 {
        let suffix = if n == 1 {
            String::new()
        } else {
            format!("-{n}")
        };
        let path = dir.join(format!("ibexwall-state-{date}{suffix}.json"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut out) => {
                out.write_all(text.as_bytes())?;
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other("too many state files for this day"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn saving_never_overwrites_and_stays_in_the_folder() {
        let dir = std::env::temp_dir().join(format!("ibexwall-statefile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = json!({ "exported_at": "2026-11-26T12:00:00Z", "schema": 1 });
        let first = save(&dir, &file).unwrap();
        let second = save(&dir, &file).unwrap();
        assert_eq!(first, dir.join("ibexwall-state-2026-11-26.json"));
        assert_eq!(second, dir.join("ibexwall-state-2026-11-26-2.json"));
        let written: Value = serde_json::from_slice(&std::fs::read(&first).unwrap()).unwrap();
        assert_eq!(written, file);

        let hostile = save(&dir, &json!({ "exported_at": "../../etc/" })).unwrap();
        assert_eq!(hostile.parent(), Some(dir.as_path()));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
