// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! varlink client over a unix socket.

use std::path::Path;

use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

use crate::wire::{Framer, Reply, Request, TransportError, VarlinkError};

/// Read side of a client connection: the socket half plus the framer
/// buffer (leftover bytes from a previous read must survive between
/// frames).
struct ReadSide {
    half: OwnedReadHalf,
    framer: Framer,
}

pub struct Client {
    reader: Option<ReadSide>,
    writer: OwnedWriteHalf,
}

impl Client {
    pub async fn connect(path: &Path) -> anyhow::Result<Self> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self::from(stream))
    }

    fn from(stream: UnixStream) -> Self {
        let (half, writer) = stream.into_split();
        Self {
            reader: Some(ReadSide {
                half,
                framer: Framer::new(),
            }),
            writer,
        }
    }

    async fn send(&mut self, method: &str, parameters: Value, more: bool) -> anyhow::Result<()> {
        let request = Request {
            method: method.into(),
            parameters,
            oneway: false,
            more,
        };
        let mut bytes = serde_json::to_vec(&request)?;
        bytes.push(0);
        self.writer.write_all(&bytes).await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn read_reply(&mut self) -> Result<Reply, VarlinkError> {
        let Some(read_side) = self.reader.as_mut() else {
            return Err(VarlinkError::new(
                "org.varlink.service.ConnectionClosed",
                Value::Null,
            ));
        };
        match read_side.framer.read_message(&mut read_side.half).await {
            Ok(raw) => {
                let reply: Reply = serde_json::from_slice(&raw).map_err(|e| {
                    VarlinkError::new(
                        crate::service_errors::INVALID_MESSAGE,
                        Value::String(e.to_string()),
                    )
                })?;
                match reply.error {
                    Some(name) => Err(VarlinkError::new(name, reply.parameters)),
                    None => Ok(reply),
                }
            }
            Err(TransportError::Closed) => Err(VarlinkError::new(
                "org.varlink.service.ConnectionClosed",
                Value::Null,
            )),
            Err(TransportError::TooLarge | TransportError::Malformed(_)) => Err(VarlinkError::new(
                crate::service_errors::INVALID_MESSAGE,
                Value::Null,
            )),
            Err(TransportError::Io(e)) => Err(VarlinkError::new(
                "org.varlink.service.IoError",
                Value::String(e.to_string()),
            )),
        }
    }

    /// Single reply call (the common case).
    pub async fn call(&mut self, method: &str, parameters: Value) -> Result<Value, VarlinkError> {
        self.send(method, parameters, false).await.map_err(io_err)?;
        let reply = self.read_reply().await?;
        Ok(reply.parameters)
    }

    /// Collects a `more` call into all its frames; the connection stays
    /// usable afterwards.
    pub async fn call_all(
        &mut self,
        method: &str,
        parameters: Value,
    ) -> Result<Vec<Value>, VarlinkError> {
        let mut stream = self.call_more(method, parameters).await?;
        let mut out = Vec::new();
        loop {
            match stream.next_reply().await {
                Ok(Some(value)) => out.push(value),
                Ok(None) => break,
                Err(err) => {
                    self.reader = stream.take_reader();
                    return Err(err);
                }
            }
        }
        self.reader = stream.take_reader();
        Ok(out)
    }

    /// Streaming call: returns the first frame; pull the rest with
    /// [`CallStream::next_reply`] until it returns `None`.
    pub async fn call_more(
        &mut self,
        method: &str,
        parameters: Value,
    ) -> Result<CallStream, VarlinkError> {
        self.send(method, parameters, true).await.map_err(io_err)?;
        let reply = self.read_reply().await?;
        Ok(CallStream {
            reader: self.reader.take(),
            first: Some(reply),
            finished: false,
        })
    }

    // Test helpers ----------------------------------------------------

    pub async fn raw_write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.writer.write_all(bytes).await?;
        self.writer.flush().await?;
        Ok(bytes.len())
    }
}

pub struct CallStream {
    reader: Option<ReadSide>,
    first: Option<Reply>,
    finished: bool,
}

impl CallStream {
    pub async fn next_reply(&mut self) -> Result<Option<Value>, VarlinkError> {
        if self.finished {
            return Ok(None);
        }
        let reply = match self.first.take() {
            Some(reply) => reply,
            None => {
                let Some(read_side) = self.reader.as_mut() else {
                    self.finished = true;
                    return Ok(None);
                };
                match read_side.framer.read_message(&mut read_side.half).await {
                    Ok(raw) => {
                        let reply: Reply = serde_json::from_slice(&raw).map_err(|e| {
                            VarlinkError::new(
                                crate::service_errors::INVALID_MESSAGE,
                                Value::String(e.to_string()),
                            )
                        })?;
                        reply
                    }
                    Err(TransportError::Closed) => {
                        self.finished = true;
                        return Ok(None);
                    }
                    Err(other) => {
                        self.finished = true;
                        return Err(VarlinkError::new(
                            crate::service_errors::INVALID_MESSAGE,
                            Value::String(other.to_string()),
                        ));
                    }
                }
            }
        };
        if let Some(name) = reply.error {
            self.finished = true;
            return Err(VarlinkError::new(name, reply.parameters));
        }
        if !reply.continues {
            self.finished = true;
        }
        Ok(Some(reply.parameters))
    }

    /// Returns the read side so the owning client can continue with
    /// other calls once the stream is finished.
    fn take_reader(&mut self) -> Option<ReadSide> {
        self.reader.take()
    }
}

fn io_err(e: impl std::fmt::Display) -> VarlinkError {
    VarlinkError::new("org.varlink.service.IoError", Value::String(e.to_string()))
}

/// Convenience: connect, single call, disconnect.
pub async fn call(path: &Path, method: &str, parameters: Value) -> Result<Value, VarlinkError> {
    let mut client = Client::connect(path).await.map_err(io_err)?;
    client.call(method, parameters).await
}

/// Convenience: connect, streaming call, collect all frames.
pub async fn call_more(
    path: &Path,
    method: &str,
    parameters: Value,
) -> Result<Vec<Value>, VarlinkError> {
    let mut client = Client::connect(path).await.map_err(io_err)?;
    client.call_all(method, parameters).await
}
