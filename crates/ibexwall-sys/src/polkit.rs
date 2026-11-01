// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Per-method authorization via polkit (ADR-0025). The real
//! implementation calls `CheckAuthorization` on the system bus with a
//! `unix-process` subject (pid + start time, never a bare PID) and
//! **no** interactive flag: if an authorization prompt would be needed,
//! we report NotAuthorized and let clients surface it.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use crate::identity::Identity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Authorized,
    NotAuthorized,
}

pub type CheckFuture = Pin<Box<dyn Future<Output = anyhow::Result<Decision>> + Send>>;

pub trait Polkit: Send + Sync {
    fn check(&self, action: String, identity: Identity) -> CheckFuture;
}

impl Polkit for Box<dyn Polkit> {
    fn check(&self, action: String, identity: Identity) -> CheckFuture {
        (**self).check(action, identity)
    }
}

#[derive(Debug, Default)]
pub struct RealPolkit;

impl Polkit for RealPolkit {
    fn check(&self, action: String, identity: Identity) -> CheckFuture {
        Box::pin(async move {
            // Fail closed on identity anomalies (missing start time).
            if identity.start_time == 0 {
                return Ok(Decision::NotAuthorized);
            }
            // Root bypasses polkit in practice; keep the fast path.
            if identity.uid == 0 {
                return Ok(Decision::Authorized);
            }

            let mut subject: HashMap<&str, zbus::zvariant::Variant> = HashMap::new();
            subject.insert("pid", zbus::zvariant::Variant::U32(identity.pid));
            subject.insert(
                "start-time",
                zbus::zvariant::Variant::U64(identity.start_time),
            );
            // CheckAuthorization signature: ((sa{sv})sa{ss}us); the subject
            // is a struct and the details map is a{ss}.
            let details: HashMap<&str, &str> = HashMap::new();
            let body = (
                ("unix-process", subject),
                action.as_str(),
                details,
                0u32, // flags: no interactive prompt
                "",
            );

            let connection = zbus::Connection::system().await?;
            let reply = connection
                .call_method(
                    Some("org.freedesktop.PolicyKit1"),
                    "/org/freedesktop/PolicyKit1/Authority",
                    Some("org.freedesktop.PolicyKit1.Authority"),
                    "CheckAuthorization",
                    &body,
                )
                .await?;
            // Reply is one struct: (is_authorized, is_challenge, details)
            let ((authorized, _challenge, _details),): ((bool, bool, HashMap<String, String>),) =
                reply.body().deserialize()?;
            Ok(if authorized {
                Decision::Authorized
            } else {
                Decision::NotAuthorized
            })
        })
    }
}

/// Configurable fake: allow-list of `(uid, action)` pairs.
#[derive(Debug, Default)]
pub struct FakePolkit {
    allowed: HashMap<(u32, String), ()>,
}

impl FakePolkit {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(&mut self, uid: u32, action: &str) {
        self.allowed.insert((uid, action.into()), ());
    }
}

impl Polkit for FakePolkit {
    fn check(&self, action: String, identity: Identity) -> CheckFuture {
        let allowed = self.allowed.contains_key(&(identity.uid, action.clone()));
        Box::pin(async move {
            Ok(if allowed {
                Decision::Authorized
            } else {
                Decision::NotAuthorized
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(uid: u32) -> Identity {
        Identity {
            uid,
            pid: 4242,
            start_time: 99_887_766,
        }
    }

    #[tokio::test]
    async fn fake_polkit_allows_only_listed_pairs() {
        let mut polkit = FakePolkit::new();
        polkit.allow(1000, "com.ibexwall.read");
        let allowed = polkit
            .check("com.ibexwall.read".into(), identity(1000))
            .await
            .unwrap();
        assert_eq!(allowed, Decision::Authorized);
        let denied = polkit
            .check("com.ibexwall.apply".into(), identity(1000))
            .await
            .unwrap();
        assert_eq!(denied, Decision::NotAuthorized);
        let other_user = polkit
            .check("com.ibexwall.read".into(), identity(1001))
            .await
            .unwrap();
        assert_eq!(other_user, Decision::NotAuthorized);
    }

    #[tokio::test]
    async fn real_polkit_fails_closed_without_start_time() {
        let identity = Identity {
            uid: 1000,
            pid: 1,
            start_time: 0,
        };
        let decision = RealPolkit
            .check("com.ibexwall.read".into(), identity)
            .await
            .unwrap();
        assert_eq!(decision, Decision::NotAuthorized);
    }
}
