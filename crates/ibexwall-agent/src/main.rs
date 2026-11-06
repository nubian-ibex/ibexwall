// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ibexwall-agent`: runs in the user session (no root). It watches the
//! event stream and raises a desktop notification for new high or critical
//! findings. It also builds the application inventory from `.desktop`
//! files; the core never reads home directories.

mod desktop;

use std::path::PathBuf;

use anyhow::Result;
use ibexwall_proto::names;
use serde_json::json;

fn main() {
    if let Err(err) = ibexwall_agent::run() {
        eprintln!("ibexwall-agent: {err:#}");
        std::process::exit(1);
    }
}

/// Library form so tests can drive the pieces without spawning.
pub mod ibexwall_agent {
    use super::*;

    pub fn run() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(amain())
    }

    async fn amain() -> Result<()> {
        init_tracing();
        let socket = names::core_socket();
        let mut client = ibexwall_varlink::Client::connect(&socket).await?;

        // The inventory is printed once (stdout is captured by the
        // journal); sending it to the core arrives with net.apps in F4.
        for entry in super::desktop::scan(&xdg_data_dirs()) {
            tracing::info!(id = %entry.id, "inventory");
        }

        // Captive portal watch (NetworkManager connectivity state); a
        // portal login page may not load while DNS enforcement is on.
        tokio::spawn(super::ibexwall_agent::watch_portals());

        // Live events; a high or critical finding raises a notification.
        let mut stream = client
            .call_more("com.ibexwall.Core.Subscribe", json!({}))
            .await?;
        while let Some(event) = stream.next_reply().await? {
            if let Some(finding) = finding_from(&event) {
                notify(&finding).await?;
            }
            if let Some((summary, body)) = ask_notification_for(&session_language(), &event) {
                // The notification waits for a click on its own task; a failed
                // one must not end the watch.
                tokio::spawn(async move {
                    if let Err(error) = notify_ask(&summary, &body).await {
                        tracing::warn!(%error, "ask notification failed");
                    }
                });
            }
        }
        Ok(())
    }

    /// Extracts a notifiable finding summary from an event, if it is one.
    pub fn finding_from(event: &serde_json::Value) -> Option<String> {
        let kind = event.get("kind")?.as_str()?;
        if !kind.starts_with("finding.") {
            return None;
        }
        let severity = event.get("severity")?.as_str()?;
        let notify = matches!(severity, "high" | "critical");
        notify.then(|| format!("{kind}: {severity}"))
    }

    /// Polls NetworkManager's connectivity: 2 means a captive portal was
    /// detected. One notification per portal episode, with the relief
    /// steps; nothing is ever applied automatically.
    pub async fn watch_portals() {
        loop {
            match portal_state().await {
                Ok(in_portal) => {
                    if in_portal
                        && !LAST_PORTAL.swap(in_portal, std::sync::atomic::Ordering::Relaxed)
                    {
                        let (summary, body) = portal_notification();
                        if let Err(error) = notify_with(summary, body).await {
                            tracing::warn!(%error, "portal notification failed");
                        }
                    } else {
                        LAST_PORTAL.store(in_portal, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                Err(error) => tracing::debug!(%error, "reading connectivity failed"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }

    static LAST_PORTAL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    async fn portal_state() -> Result<bool> {
        let connection = zbus::Connection::system().await?;
        let portal = zbus::Proxy::new(
            &connection,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        )
        .await?
        .get_property::<u32>("Connectivity")
        .await?;
        // NM_CONNECTIVITY_PORTAL, per NetworkManager's D-Bus reference.
        Ok(portal == 2)
    }

    fn session_language() -> String {
        std::env::var("LC_ALL")
            .or_else(|_| std::env::var("LC_MESSAGES"))
            .or_else(|_| std::env::var("LANG"))
            .unwrap_or_default()
    }

    /// The portal notice, in the session language.
    pub fn portal_notification() -> (&'static str, &'static str) {
        portal_notification_for(&session_language())
    }

    /// Control characters and length: the app and destination come from
    /// other programs and the network.
    fn plain(text: &str) -> String {
        text.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(120)
            .collect()
    }

    /// The language a session asks for (`pt_BR.UTF-8` is `pt`), among the
    /// ones the app ships; English otherwise.
    fn language_of(lang: &str) -> &'static str {
        let code = lang.to_lowercase();
        ["pt", "es", "fr", "de"]
            .into_iter()
            .find(|l| code.starts_with(l))
            .unwrap_or("en")
    }

    /// A held connection (Ask mode) is time-limited, so it is announced;
    /// answering happens in IbexWall, never from the notification.
    pub fn ask_notification_for(lang: &str, event: &serde_json::Value) -> Option<(String, String)> {
        if event.get("kind")?.as_str()? != "apps.ask" {
            return None;
        }
        let app = plain(event.get("app")?.as_str()?);
        let untrusted = event.get("untrusted")?;
        let destination = plain(untrusted.get("destination")?.as_str()?);
        let port = untrusted.get("port")?.as_u64()?;
        let (summary, rest) = match language_of(lang) {
            "pt" => (
                "Um programa quer se conectar",
                "Abra o IbexWall para permitir ou bloquear.",
            ),
            "es" => (
                "Un programa quiere conectarse",
                "Abre IbexWall para permitirlo o bloquearlo.",
            ),
            "fr" => (
                "Un programme veut se connecter",
                "Ouvrez IbexWall pour l'autoriser ou le bloquer.",
            ),
            "de" => (
                "Ein Programm möchte eine Verbindung aufbauen",
                "Öffnen Sie IbexWall, um sie zu erlauben oder zu blockieren.",
            ),
            _ => (
                "A program wants to connect",
                "Open IbexWall to allow or block.",
            ),
        };
        let to = match language_of(lang) {
            "pt" => "para",
            "es" => "a",
            "fr" => "vers",
            "de" => "zu",
            _ => "to",
        };
        Some((
            summary.to_string(),
            format!("{app} {to} {destination}:{port}. {rest}"),
        ))
    }

    /// Pure form for tests: the language string decides the wording. The
    /// quoted setting name is the label the app shows in the same language.
    pub fn portal_notification_for(lang: &str) -> (&'static str, &'static str) {
        match language_of(lang) {
            "pt" => (
                "Portal de login detectado",
                "Esta rede exige um login antes de permitir o tráfego, e a página pode não abrir enquanto o DNS seguro recusa DNS sem criptografia. Para entrar: abra o IbexWall, desligue 'Recusar DNS sem criptografia', faça o login e ligue novamente.",
            ),
            "es" => (
                "Red con inicio de sesión detectada",
                "Esta red exige iniciar sesión antes de permitir el tráfico, y la página puede no cargar mientras el DNS seguro rechaza el DNS sin cifrar. Para entrar: abre IbexWall, desactiva 'Rechazar DNS sin cifrar', inicia sesión y vuelve a activarlo.",
            ),
            "fr" => (
                "Réseau avec connexion détecté",
                "Ce réseau exige une connexion avant d'autoriser le trafic, et la page peut ne pas s'ouvrir tant que le DNS sécurisé refuse le DNS non chiffré. Pour vous connecter : ouvrez IbexWall, désactivez 'Refuser le DNS non chiffré', connectez-vous, puis réactivez-le.",
            ),
            "de" => (
                "Netzwerk mit Anmeldung erkannt",
                "Dieses Netzwerk verlangt eine Anmeldung, bevor es Datenverkehr zulässt, und die Seite lädt womöglich nicht, solange das sichere DNS unverschlüsseltes DNS ablehnt. So melden Sie sich an: Öffnen Sie IbexWall, schalten Sie 'Unverschlüsseltes DNS ablehnen' aus, melden Sie sich an und schalten Sie es wieder ein.",
            ),
            _ => (
                "Sign-in network detected",
                "This network needs a login before it allows traffic, and the page may not load while Secure DNS refuses unencrypted DNS. To sign in: open IbexWall, turn off 'Refuse unencrypted DNS', sign in, then turn it back on.",
            ),
        }
    }

    async fn notify(summary: &str) -> Result<()> {
        notify_with(summary, "").await
    }

    /// A held connection: urgent, and a click opens the prompt window
    /// (`ibexwall --prompt`). Nothing is answered from the notification.
    async fn notify_ask(summary: &str, body: &str) -> Result<()> {
        use futures_util::StreamExt as _;
        let connection = zbus::Connection::session().await?;
        let proxy = zbus::Proxy::new(
            &connection,
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
        )
        .await?;
        // Subscribe first: a click can come before Notify returns.
        let mut invoked = proxy.receive_signal("ActionInvoked").await?;
        let label = if session_language().to_lowercase().starts_with("pt") {
            "Responder"
        } else {
            "Answer"
        };
        let mut hints = std::collections::HashMap::<&str, zbus::zvariant::Variant>::new();
        hints.insert("urgency", zbus::zvariant::Variant::U8(2));
        let id: u32 = proxy
            .call(
                "Notify",
                &(
                    "IbexWall",
                    0u32,
                    "ibexwall",
                    summary,
                    body,
                    vec!["default", label],
                    hints,
                    // The question expires on its own after the timeout.
                    35_000i32,
                ),
            )
            .await?;
        let wait = async {
            while let Some(signal) = invoked.next().await {
                let Ok((notification, action)) = signal.body().deserialize::<(u32, String)>()
                else {
                    continue;
                };
                if notification == id && action == "default" {
                    return true;
                }
            }
            false
        };
        if tokio::time::timeout(std::time::Duration::from_secs(40), wait)
            .await
            .unwrap_or(false)
        {
            std::process::Command::new("ibexwall")
                .arg("--prompt")
                .spawn()?;
        }
        Ok(())
    }

    async fn notify_with(summary: &str, body: &str) -> Result<()> {
        // Desktop notification via the standard interface. Body is plain
        // text; notification servers do not interpret markup from us.
        let connection = zbus::Connection::session().await?;
        connection
            .call_method(
                Some("org.freedesktop.Notifications"),
                "/org/freedesktop/Notifications",
                Some("org.freedesktop.Notifications"),
                "Notify",
                &(
                    "IbexWall",
                    0u32,
                    "ibexwall",
                    "IbexWall",
                    if body.is_empty() { summary } else { body },
                    Vec::<String>::new(),
                    std::collections::HashMap::<String, zbus::zvariant::Variant>::new(),
                    -1i32,
                ),
            )
            .await?;
        Ok(())
    }

    fn init_tracing() {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .init();
    }
}

/// `$XDG_DATA_DIRS` plus the user's own data dir (first wins for dedup).
fn xdg_data_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var("XDG_DATA_DIRS")
        .unwrap_or_else(|_| "/usr/local/share:/usr/share".into())
        .split(':')
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .collect();
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(home).join(".local/share"));
    }
    dirs
}

#[cfg(test)]
mod tests {
    use super::ibexwall_agent::{ask_notification_for, finding_from, portal_notification_for};

    #[test]
    fn a_held_connection_is_announced_in_both_languages_and_as_plain_text() {
        let event = serde_json::json!({
            "kind": "apps.ask", "app": "cli:/usr/bin/curl",
            "untrusted": { "destination": "evil\u{1b}[31m.example", "port": 443 },
        });
        let (summary, body) = ask_notification_for("en_US.UTF-8", &event).unwrap();
        assert_eq!(summary, "A program wants to connect");
        assert!(
            body.contains("cli:/usr/bin/curl to evil [31m.example:443"),
            "{body}"
        );
        assert!(!body.contains('\u{1b}'));
        let (summary, body) = ask_notification_for("pt_BR.UTF-8", &event).unwrap();
        assert_eq!(summary, "Um programa quer se conectar");
        assert!(body.contains("Abra o IbexWall"));
        for (lang, summary_start, word) in [
            ("es_MX.UTF-8", "Un programa", " a "),
            ("fr_CA.UTF-8", "Un programme", " vers "),
            ("de_AT.UTF-8", "Ein Programm", " zu "),
        ] {
            let (summary, body) = ask_notification_for(lang, &event).unwrap();
            assert!(summary.starts_with(summary_start), "{lang}: {summary}");
            assert!(body.contains(word), "{lang}: {body}");
        }
        // Only questions are announced, and only well formed ones.
        assert!(
            ask_notification_for("", &serde_json::json!({ "kind": "apps.first_connection" }))
                .is_none()
        );
        assert!(ask_notification_for("", &serde_json::json!({ "kind": "apps.ask" })).is_none());
    }

    #[test]
    fn only_high_and_critical_findings_are_notifiable() {
        for (severity, expected) in [
            ("critical", true),
            ("high", true),
            ("medium", false),
            ("low", false),
            ("info", false),
        ] {
            let event = serde_json::json!({ "kind": "finding.new", "severity": severity });
            assert_eq!(finding_from(&event).is_some(), expected, "{severity}");
        }
        assert!(finding_from(&serde_json::json!({ "kind": "transaction.committed" })).is_none());
        assert!(finding_from(&serde_json::json!({})).is_none());
    }

    #[test]
    fn the_portal_notice_names_the_relief_steps_in_both_languages() {
        // The notice tells the user what to do; it never applies anything.
        for (lang, marker) in [
            ("en_US.UTF-8", "Refuse unencrypted DNS"),
            ("pt_BR.UTF-8", "Recusar DNS sem criptografia"),
            ("es_ES.UTF-8", "Rechazar DNS sin cifrar"),
            ("fr_FR.UTF-8", "Refuser le DNS non chiffré"),
            ("de_DE.UTF-8", "Unverschlüsseltes DNS ablehnen"),
        ] {
            let (summary, body) = portal_notification_for(lang);
            assert!(body.contains(marker), "{lang}: {body}");
            assert!(!summary.is_empty());
        }
        // An unknown language falls back to English.
        assert!(portal_notification_for("").0.contains("Sign-in"));
    }
}
