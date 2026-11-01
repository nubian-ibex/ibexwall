// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Wire format: one JSON document per message, terminated by a NUL byte.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Hard cap for a single message (plans carry file content).
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub method: String,
    #[serde(default)]
    pub parameters: Value,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub oneway: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub more: bool,
}

/// One reply frame; either a result (`parameters`, `continues`) or a
/// named error (`error` + `parameters`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reply {
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub parameters: Value,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub continues: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Reply {
    pub fn result(parameters: Value) -> Self {
        Self {
            parameters,
            continues: false,
            error: None,
        }
    }

    pub fn result_continues(parameters: Value) -> Self {
        Self {
            parameters,
            continues: true,
            error: None,
        }
    }
}

/// Named varlink error as returned to clients.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("varlink error `{name}`: {parameters}")]
pub struct VarlinkError {
    pub name: String,
    pub parameters: Value,
}

impl VarlinkError {
    pub fn new(name: impl Into<String>, parameters: Value) -> Self {
        Self {
            name: name.into(),
            parameters,
        }
    }

    pub fn invalid_parameter(field: &str) -> Self {
        Self::new(
            crate::service_errors::INVALID_PARAMETER,
            serde_json::json!({ "parameter": field }),
        )
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            crate::service_errors::METHOD_NOT_FOUND,
            serde_json::json!({ "method": method }),
        )
    }

    pub fn to_reply(&self) -> Reply {
        Reply {
            parameters: self.parameters.clone(),
            continues: false,
            error: Some(self.name.clone()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connection closed")]
    Closed,
    #[error("message exceeds {MAX_MESSAGE_BYTES} bytes")]
    TooLarge,
    #[error("malformed message: {0}")]
    Malformed(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Buffered NUL-delimited reader. A single socket read may deliver
/// several frames; leftover bytes stay buffered for the next call.
/// `pending` counts bytes of the current message already confirmed
/// NUL-free, so each byte is scanned at most once per message.
#[derive(Debug, Default)]
pub struct Framer {
    buf: Vec<u8>,
    pos: usize,
    pending: usize,
}

impl Framer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads one complete message (bytes without the NUL terminator).
    pub async fn read_message<R: AsyncReadExt + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Vec<u8>, TransportError> {
        loop {
            let unscanned = self.pos + self.pending;
            if let Some(r) = self.buf[unscanned..].iter().position(|&b| b == 0) {
                let nul = unscanned + r;
                let message = self.buf[self.pos..nul].to_vec();
                if message.len() > MAX_MESSAGE_BYTES {
                    return Err(TransportError::TooLarge);
                }
                self.pos = nul + 1;
                self.pending = 0;
                if self.pos == self.buf.len() {
                    self.buf.clear();
                    self.pos = 0;
                } else if self.pos > 64 * 1024 {
                    self.buf.drain(..self.pos);
                    self.pos = 0;
                }
                return Ok(message);
            }
            self.pending = self.buf.len() - self.pos;
            if self.pending > MAX_MESSAGE_BYTES {
                return Err(TransportError::TooLarge);
            }
            let mut chunk = [0u8; 8192];
            let n = reader.read(&mut chunk).await?;
            if n == 0 {
                return Err(if self.pos == self.buf.len() {
                    TransportError::Closed
                } else {
                    TransportError::Malformed("connection closed mid-message".into())
                });
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// Writes one message as JSON + NUL.
pub async fn write_message<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    value: &impl Serialize,
) -> Result<(), TransportError> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|e| TransportError::Malformed(e.to_string()))?;
    bytes.push(0);
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrips_a_request_with_nul_inside_parameters() {
        let (mut client, mut server) = tokio::io::duplex(8192);
        let request = Request {
            method: "com.ibexwall.Core.Apply".into(),
            parameters: serde_json::json!({ "plan_id": "abc\u{0}def" }),
            oneway: false,
            more: false,
        };
        write_message(&mut client, &request).await.unwrap();
        let mut framer = Framer::new();
        let raw = framer.read_message(&mut server).await.unwrap();
        let back: Request = serde_json::from_slice(&raw).unwrap();
        assert_eq!(back, request);
    }

    #[tokio::test]
    async fn several_frames_in_one_chunk_are_not_lost() {
        let (mut client, mut server) = tokio::io::duplex(8192);
        for i in 0..4 {
            let request = Request {
                method: format!("com.test.M{i}"),
                parameters: serde_json::json!({ "i": i }),
                oneway: false,
                more: false,
            };
            write_message(&mut client, &request).await.unwrap();
        }
        // Server-side framer must recover all four even though one read
        // likely delivered several of them.
        let mut framer = Framer::new();
        for i in 0..4 {
            let raw = framer.read_message(&mut server).await.unwrap();
            let back: Request = serde_json::from_slice(&raw).unwrap();
            assert_eq!(back.method, format!("com.test.M{i}"));
            assert_eq!(back.parameters["i"], i);
        }
    }

    #[tokio::test]
    async fn rejects_oversized_messages() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let blob = vec![b'x'; MAX_MESSAGE_BYTES + 1024];
            let _ = client.write_all(&blob).await;
        });
        let mut framer = Framer::new();
        let err = framer.read_message(&mut server).await.unwrap_err();
        assert!(matches!(err, TransportError::TooLarge));
    }

    #[tokio::test]
    async fn replies_skip_empty_fields() {
        let text = serde_json::to_string(&Reply::result(serde_json::json!({"ok": true}))).unwrap();
        assert!(!text.contains("continues"));
        assert!(!text.contains("error"));
    }
}
