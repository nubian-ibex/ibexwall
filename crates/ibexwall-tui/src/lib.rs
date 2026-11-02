// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Terminal UI (`ibexctl tui`): overview with live events, plugins and
//! history. Same varlink API as the desktop app.

mod model;
mod view;

use std::path::Path;
use std::time::Duration;

use anyhow::Result;

use ibexwall_varlink::Client;

pub use model::{AppModel, Tab};
pub use view::draw;

/// Key actions for the event loop (kept testable without a terminal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Quit,
    NextTab,
    PrevTab,
    Refresh,
    Other,
}

pub fn key_from(code: crossterm::event::KeyCode, ch: char) -> Key {
    match (code, ch) {
        (crossterm::event::KeyCode::Char('q') | crossterm::event::KeyCode::Esc, _) => Key::Quit,
        (crossterm::event::KeyCode::Char('j') | crossterm::event::KeyCode::Tab, _) => Key::NextTab,
        (crossterm::event::KeyCode::Char('k'), _) => Key::PrevTab,
        (crossterm::event::KeyCode::Char('r'), _) => Key::Refresh,
        _ => Key::Other,
    }
}

/// Polls input for at most `timeout`, returning the key (or None).
pub fn poll_key(timeout: Duration) -> Result<Option<Key>> {
    if !crossterm::event::poll(timeout)? {
        return Ok(None);
    }
    match crossterm::event::read()? {
        crossterm::event::Event::Key(event) => {
            let ch = match event.code {
                crossterm::event::KeyCode::Char(c) => c,
                _ => '\0',
            };
            Ok(Some(key_from(event.code, ch)))
        }
        _ => Ok(None),
    }
}

/// Runs the TUI against the daemon socket until the user quits.
pub fn run(socket: &Path) -> Result<()> {
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, socket);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, socket: &Path) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // Initial load; a daemon that is down shows the error state, not a crash.
    let mut model = AppModel {
        loading: true,
        ..AppModel::default()
    };
    if let Err(err) = runtime.block_on(refresh(socket, &mut model)) {
        model.error = Some(format!("{err:#}"));
    }
    model.loading = false;

    loop {
        terminal.draw(|frame| view::draw(frame, &model))?;
        match poll_key(Duration::from_millis(250))? {
            Some(Key::Quit) => return Ok(()),
            Some(Key::NextTab) => model.tab = model.tab.next(),
            Some(Key::PrevTab) => model.tab = model.tab.prev(),
            Some(Key::Refresh) | None => {
                if let Err(err) = runtime.block_on(refresh(socket, &mut model)) {
                    model.error = Some(format!("{err:#}"));
                }
            }
            Some(Key::Other) => {}
        }
    }
}

/// Reloads everything for the active tab (and always the overview data).
async fn refresh(socket: &Path, model: &mut AppModel) -> Result<()> {
    let mut client = Client::connect(socket).await?;
    model.error = None;

    let posture = client
        .call("com.ibexwall.Core.GetPosture", serde_json::json!({}))
        .await?;
    model.score = posture["posture"]["score"].as_u64().map(|s| s as u16);
    model.open_findings = posture["posture"]["open_findings"].as_u64().unwrap_or(0) as u32;
    model.checked_at = posture["posture"]["generated_at"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    let plugins = client
        .call("com.ibexwall.Core.ListPlugins", serde_json::json!({}))
        .await?;
    model.plugins.clear();
    for plugin in plugins["plugins"].as_array().unwrap_or(&Vec::new()).iter() {
        model.plugins.push(crate::model::PluginRow {
            id: plugin["id"].as_str().unwrap_or_default().to_string(),
            enabled: plugin["enabled"].as_bool().unwrap_or(false),
            kind: plugin["kinds"][0].as_str().unwrap_or("check").to_string(),
            origin: plugin["origin"].as_str().unwrap_or("?").to_string(),
        });
    }

    let history = client
        .call(
            "com.ibexwall.Core.History",
            serde_json::json!({ "limit": 20 }),
        )
        .await?;
    model.history.clear();
    for entry in history["entries"].as_array().unwrap_or(&Vec::new()).iter() {
        model.history.push(crate::model::HistoryRow {
            plugin: entry["plugin"].as_str().unwrap_or_default().to_string(),
            result: entry["result"].as_str().unwrap_or_default().to_string(),
            actor: entry["actor"].as_str().unwrap_or_default().to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_map_to_actions() {
        use crossterm::event::KeyCode;
        assert_eq!(key_from(KeyCode::Char('q'), 'q'), Key::Quit);
        assert_eq!(key_from(KeyCode::Esc, '\0'), Key::Quit);
        assert_eq!(key_from(KeyCode::Char('j'), 'j'), Key::NextTab);
        assert_eq!(key_from(KeyCode::Tab, '\0'), Key::NextTab);
        assert_eq!(key_from(KeyCode::Char('k'), 'k'), Key::PrevTab);
        assert_eq!(key_from(KeyCode::Char('r'), 'r'), Key::Refresh);
        assert_eq!(key_from(KeyCode::Down, '\0'), Key::Other);
    }

    #[test]
    fn tabs_cycle_in_both_directions() {
        assert_eq!(Tab::Overview.next(), Tab::Plugins);
        assert_eq!(Tab::Plugins.next(), Tab::History);
        assert_eq!(Tab::History.next(), Tab::Overview);
        assert_eq!(Tab::Overview.prev(), Tab::History);
    }

    #[test]
    fn headline_is_honest_without_a_score_or_a_daemon() {
        let mut model = AppModel::default();
        assert_eq!(model.headline(), "No check has run yet");
        model.loading = true;
        assert_eq!(model.headline(), "Loading…");
        model.loading = false;
        model.error = Some("refused".into());
        assert!(model.headline().contains("Cannot reach ibexwalld"));
        model.error = None;
        model.score = Some(72);
        model.open_findings = 3;
        assert_eq!(model.headline(), "Score 72/100 · 3 open finding(s)");
    }

    #[test]
    fn overview_renders_the_headline_as_text() {
        use ratatui::backend::TestBackend;
        let model = AppModel {
            score: Some(88),
            open_findings: 2,
            ..AppModel::default()
        };
        let mut terminal = ratatui::Terminal::new(TestBackend::new(60, 12)).unwrap();
        terminal.draw(|frame| draw(frame, &model)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let content: String = buffer
            .content()
            .iter()
            .map(|cell| cell.symbol().to_string())
            .collect();
        assert!(content.contains("Score 88/100 · 2 open finding(s)"));
        assert!(content.contains("Overview (j/k)"));
    }
}
