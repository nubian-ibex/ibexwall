// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Per-method authorization via polkit. The real implementation calls
//! `CheckAuthorization` on the system bus with a `unix-process` subject
//! carrying the pid, the start time and the uid, all captured when the
//! connection was accepted (never a bare PID, and never a start time
//! re-read later). A check is interactive only when the client asked for
//! it (ADR-0045): polkit then asks the agent of the caller's session for
//! a password, and the check is cancelled if the caller goes away or no
//! one answers within [`INTERACTIVE_TIMEOUT`].
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use crate::identity::Identity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Authorized,
    /// Refused: by a rule, by the defaults, or by the person.
    NotAuthorized,
    /// Allowed only after the person authenticates, which this check did
    /// not do: it was not interactive, or no agent answered.
    Challenge,
}

/// How long an interactive check may wait for the person.
pub const INTERACTIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

pub type CheckFuture = Pin<Box<dyn Future<Output = anyhow::Result<Decision>> + Send>>;

pub trait Polkit: Send + Sync {
    /// A check that never asks the person.
    fn check(&self, action: String, identity: Identity) -> CheckFuture {
        self.check_with(action, identity, false)
    }

    /// A check that may ask the person when `interactive` is set.
    fn check_with(&self, action: String, identity: Identity, interactive: bool) -> CheckFuture;
}

impl Polkit for Box<dyn Polkit> {
    fn check_with(&self, action: String, identity: Identity, interactive: bool) -> CheckFuture {
        (**self).check_with(action, identity, interactive)
    }
}

#[derive(Debug, Default)]
pub struct RealPolkit;

/// The `unix-process` subject: pid, start time and uid of the accepted
/// connection. The uid is included so polkit never re-reads it from
/// /proc at check time, which would describe whatever runs under the
/// pid then instead of the caller.
fn unix_process_subject(
    identity: Identity,
) -> HashMap<&'static str, zbus::zvariant::Variant<'static>> {
    let mut subject: HashMap<&str, zbus::zvariant::Variant> = HashMap::new();
    subject.insert("pid", zbus::zvariant::Variant::U32(identity.pid));
    subject.insert(
        "start-time",
        zbus::zvariant::Variant::U64(identity.start_time),
    );
    subject.insert("uid", zbus::zvariant::Variant::U32(identity.uid));
    subject
}

const AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const AUTHORITY: &str = "org.freedesktop.PolicyKit1.Authority";
const POLKIT: &str = "org.freedesktop.PolicyKit1";
/// `CheckAuthorizationFlags.AllowUserInteraction`.
const ALLOW_USER_INTERACTION: u32 = 1;

/// Cancels a pending interactive check when its future is dropped (the
/// client went away, or the timeout fired), so the password dialog does
/// not outlive the request.
struct CancelOnDrop {
    id: Option<String>,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else { return };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        runtime.spawn(async move {
            if let Ok(connection) = zbus::Connection::system().await {
                let _ = connection
                    .call_method(
                        Some(POLKIT),
                        AUTHORITY_PATH,
                        Some(AUTHORITY),
                        "CancelCheckAuthorization",
                        &(id.as_str(),),
                    )
                    .await;
            }
        });
    }
}

fn cancellation_id(identity: &Identity) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("ibexwall-{}-{}-{nanos}", identity.pid, identity.start_time)
}

impl Polkit for RealPolkit {
    fn check_with(&self, action: String, identity: Identity, interactive: bool) -> CheckFuture {
        Box::pin(async move {
            // Fail closed on identity anomalies (missing start time).
            if identity.start_time == 0 {
                return Ok(Decision::NotAuthorized);
            }
            // Root bypasses polkit in practice; keep the fast path.
            if identity.uid == 0 {
                return Ok(Decision::Authorized);
            }

            let subject = unix_process_subject(identity);
            let (flags, id) = if interactive {
                (ALLOW_USER_INTERACTION, cancellation_id(&identity))
            } else {
                (0, String::new())
            };
            // CheckAuthorization signature: ((sa{sv})sa{ss}us); the subject
            // is a struct and the details map is a{ss}.
            let details: HashMap<&str, &str> = HashMap::new();
            let body = (
                ("unix-process", subject),
                action.as_str(),
                details,
                flags,
                id.as_str(),
            );

            let connection = zbus::Connection::system().await?;
            let mut guard = CancelOnDrop {
                id: interactive.then(|| id.clone()),
            };
            let call = connection.call_method(
                Some(POLKIT),
                AUTHORITY_PATH,
                Some(AUTHORITY),
                "CheckAuthorization",
                &body,
            );
            let reply = match tokio::time::timeout(INTERACTIVE_TIMEOUT, call).await {
                // No one answered: the guard cancels the dialog.
                Err(_elapsed) => return Ok(Decision::Challenge),
                Ok(Err(zbus::Error::MethodError(name, _, _)))
                    if name.as_str() == "org.freedesktop.PolicyKit1.Error.Cancelled" =>
                {
                    guard.id = None;
                    return Ok(Decision::NotAuthorized);
                }
                Ok(reply) => reply?,
            };
            guard.id = None;
            // Reply is one struct: (is_authorized, is_challenge, details)
            let ((authorized, challenge, _details),): ((bool, bool, HashMap<String, String>),) =
                reply.body().deserialize()?;
            Ok(if authorized {
                Decision::Authorized
            } else if challenge {
                Decision::Challenge
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
    /// Pairs that need the person: a non-interactive check gets a
    /// challenge, an interactive one gets the stored answer.
    challenged: HashMap<(u32, String), bool>,
}

impl FakePolkit {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(&mut self, uid: u32, action: &str) {
        self.allowed.insert((uid, action.into()), ());
    }

    /// `action` needs authentication for `uid`; when asked interactively
    /// the person answers `answer` (true: authenticated, false: refused).
    pub fn challenge(&mut self, uid: u32, action: &str, answer: bool) {
        self.challenged.insert((uid, action.into()), answer);
    }
}

impl Polkit for FakePolkit {
    fn check_with(&self, action: String, identity: Identity, interactive: bool) -> CheckFuture {
        let key = (identity.uid, action);
        let decision = if self.allowed.contains_key(&key) {
            Decision::Authorized
        } else {
            match (self.challenged.get(&key), interactive) {
                (Some(true), true) => Decision::Authorized,
                (Some(false), true) => Decision::NotAuthorized,
                (Some(_), false) => Decision::Challenge,
                (None, _) => Decision::NotAuthorized,
            }
        };
        Box::pin(async move { Ok(decision) })
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
    async fn fake_polkit_challenges_until_asked() {
        let mut polkit = FakePolkit::new();
        polkit.challenge(1000, "com.ibexwall.apply", true);
        polkit.challenge(1000, "com.ibexwall.rollback", false);
        let quiet = polkit
            .check("com.ibexwall.apply".into(), identity(1000))
            .await
            .unwrap();
        assert_eq!(quiet, Decision::Challenge);
        let asked = polkit
            .check_with("com.ibexwall.apply".into(), identity(1000), true)
            .await
            .unwrap();
        assert_eq!(asked, Decision::Authorized);
        let refused = polkit
            .check_with("com.ibexwall.rollback".into(), identity(1000), true)
            .await
            .unwrap();
        assert_eq!(refused, Decision::NotAuthorized);
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

    #[test]
    fn the_subject_carries_the_connection_identity() {
        let identity = Identity {
            uid: 1000,
            pid: 4242,
            start_time: 99_999,
        };
        let subject = unix_process_subject(identity);
        assert_eq!(subject["pid"], zbus::zvariant::Variant::U32(4242));
        assert_eq!(subject["start-time"], zbus::zvariant::Variant::U64(99_999));
        // Without the uid, polkit re-reads it from /proc at check time
        // and the check can be decided about another process.
        assert_eq!(subject["uid"], zbus::zvariant::Variant::U32(1000));
    }
}
