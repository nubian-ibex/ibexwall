// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The assistant's call log. Every call writes a `call` line BEFORE it runs
//! and a `result` line after; if the first line cannot be written the call is
//! refused, so no action of the assistant goes unrecorded. Each line carries
//! the SHA-256 of the previous line, so a removed or edited line is
//! detectable with `verify`. Parameters are logged after redaction and cut
//! to a bounded size.

use std::io::Write;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub const MAX_LOGGED_PARAMS: usize = 2000;

pub struct Audit<W: Write> {
    writer: W,
    seq: u64,
    prev: String,
    /// Read handle on the log file when other processes may append to it.
    shared: Option<std::fs::File>,
}

/// Cut on a character boundary.
pub fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

fn hash(line: &str) -> String {
    hex::encode(Sha256::digest(line.as_bytes()))
}

impl<W: Write> Audit<W> {
    /// `seq` and `prev` continue an existing log (see `resume`).
    pub fn new(writer: W, seq: u64, prev: String) -> Self {
        Self {
            writer,
            seq,
            prev,
            shared: None,
        }
    }

    /// Two MCP processes (two clients) append to the same file. With the file
    /// given here, every append takes an exclusive lock and continues from the
    /// tail on disk, so the chain never forks.
    pub fn shared_with(mut self, file: std::fs::File) -> Self {
        self.shared = Some(file);
        self
    }

    /// Last line of the file, read from its final bytes (lines are bounded).
    fn disk_tail(file: &mut std::fs::File) -> std::io::Result<(u64, String)> {
        use std::io::{Read, Seek, SeekFrom};
        let len = file.seek(SeekFrom::End(0))?;
        let start = len.saturating_sub(32 * 1024);
        file.seek(SeekFrom::Start(start))?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Ok(Self::resume(&String::from_utf8_lossy(&buf)))
    }

    /// `(seq, prev hash)` from the text of an existing log.
    pub fn resume(existing: &str) -> (u64, String) {
        match existing.lines().rev().find(|l| !l.trim().is_empty()) {
            Some(last) => {
                let seq = serde_json::from_str::<Value>(last)
                    .ok()
                    .and_then(|v| v["seq"].as_u64())
                    .unwrap_or(0);
                (seq, hash(last))
            }
            None => (0, String::new()),
        }
    }

    pub fn append(&mut self, ts: &str, fields: Map<String, Value>) -> std::io::Result<u64> {
        let Some(mut file) = self.shared.take() else {
            return self.write_line(ts, fields);
        };
        let result = file.lock().and_then(|()| {
            let (seq, prev) = Self::disk_tail(&mut file)?;
            self.seq = seq;
            self.prev = prev;
            self.write_line(ts, fields)
        });
        // The lock is released when the handle closes or here, whichever first.
        let _ = file.unlock();
        self.shared = Some(file);
        result
    }

    fn write_line(&mut self, ts: &str, mut fields: Map<String, Value>) -> std::io::Result<u64> {
        self.seq += 1;
        fields.insert("seq".into(), json!(self.seq));
        fields.insert("ts".into(), json!(ts));
        fields.insert("prev".into(), json!(self.prev));
        let line = Value::Object(fields).to_string();
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        self.prev = hash(&line);
        Ok(self.seq)
    }

    pub fn call(
        &mut self,
        ts: &str,
        client: &str,
        tool: &str,
        params: &Value,
    ) -> std::io::Result<u64> {
        self.call_via(ts, client, "stdio", tool, params)
    }

    /// `via` says how the client came in: `stdio`, or `http:<token id>`.
    pub fn call_via(
        &mut self,
        ts: &str,
        client: &str,
        via: &str,
        tool: &str,
        params: &Value,
    ) -> std::io::Result<u64> {
        let mut m = Map::new();
        m.insert("phase".into(), json!("call"));
        m.insert("client".into(), json!(client));
        m.insert("via".into(), json!(via));
        m.insert("tool".into(), json!(tool));
        m.insert(
            "params".into(),
            json!(truncate(&params.to_string(), MAX_LOGGED_PARAMS)),
        );
        self.append(ts, m)
    }

    pub fn result(&mut self, ts: &str, call: u64, outcome: &str) -> std::io::Result<u64> {
        let mut m = Map::new();
        m.insert("phase".into(), json!("result"));
        m.insert("call".into(), json!(call));
        m.insert("outcome".into(), json!(truncate(outcome, 300)));
        self.append(ts, m)
    }
}

/// Checks the chain of a whole log: `Ok(lines)` or the line that breaks it.
pub fn verify(text: &str) -> Result<usize, usize> {
    let mut prev = String::new();
    let mut count = 0;
    for (index, line) in text.lines().enumerate() {
        let value: Value = serde_json::from_str(line).map_err(|_| index + 1)?;
        if value["prev"].as_str() != Some(prev.as_str())
            || value["seq"].as_u64() != Some(index as u64 + 1)
        {
            return Err(index + 1);
        }
        prev = hash(line);
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> String {
        let mut audit = Audit::new(Vec::new(), 0, String::new());
        let c = audit
            .call("t", "claude-code", "get_posture", &json!({}))
            .unwrap();
        audit.result("t", c, "ok").unwrap();
        let c = audit
            .call("t", "claude-code", "propose_change", &json!({"a": 1}))
            .unwrap();
        audit.result("t", c, "ok").unwrap();
        String::from_utf8(audit.writer).unwrap()
    }

    #[test]
    fn an_intact_log_verifies() {
        assert_eq!(verify(&log()), Ok(4));
    }

    #[test]
    fn a_removed_or_edited_line_is_found() {
        let text = log();
        let lines: Vec<&str> = text.lines().collect();
        let removed = format!("{}\n{}\n{}\n", lines[0], lines[2], lines[3]);
        assert_eq!(verify(&removed), Err(2));
        let edited = text.replacen("get_posture", "list_findings", 1);
        assert_eq!(verify(&edited), Err(2));
    }

    #[test]
    fn a_log_continues_after_a_restart() {
        let text = log();
        let (seq, prev) = Audit::<Vec<u8>>::resume(&text);
        let mut audit = Audit::new(Vec::new(), seq, prev);
        audit.call("t", "c", "x", &json!({})).unwrap();
        let joined = format!("{text}{}", String::from_utf8(audit.writer).unwrap());
        assert_eq!(verify(&joined), Ok(5));
    }

    #[test]
    fn two_processes_on_one_file_keep_one_chain() {
        let path = std::env::temp_dir().join(format!("ibexwall-audit-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let open = || {
            let w = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap();
            let r = std::fs::File::open(&path).unwrap();
            Audit::new(w, 0, String::new()).shared_with(r)
        };
        let (mut a, mut b) = (open(), open());
        for _ in 0..3 {
            a.call("t", "a", "x", &json!({})).unwrap();
            b.call("t", "b", "x", &json!({})).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(verify(&text), Ok(6));
    }

    #[test]
    fn logged_parameters_are_bounded() {
        let mut audit = Audit::new(Vec::new(), 0, String::new());
        audit
            .call("t", "c", "x", &json!({ "big": "a".repeat(100_000) }))
            .unwrap();
        assert!(audit.writer.len() < 3000);
    }

    #[test]
    fn a_failing_writer_is_an_error_not_a_silent_skip() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(
            Audit::new(Broken, 0, String::new())
                .call("t", "c", "x", &json!({}))
                .is_err()
        );
    }
}
