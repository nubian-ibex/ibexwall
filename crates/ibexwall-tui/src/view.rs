// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Rendering. All text is drawn as text; no untrusted string is ever
//! interpreted as markup (ratatui has none, which is the point).

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, Paragraph, Tabs};

use crate::model::AppModel;

pub fn draw(frame: &mut Frame, model: &AppModel) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)])
        .split(frame.area());

    let titles = ["Overview (j/k)", "Apps", "Firewall", "Plugins", "History"];
    let selected = match model.tab {
        crate::model::Tab::Overview => 0,
        crate::model::Tab::Apps => 1,
        crate::model::Tab::Firewall => 2,
        crate::model::Tab::Plugins => 3,
        crate::model::Tab::History => 4,
    };
    frame.render_widget(
        Tabs::new(titles)
            .select(selected)
            .highlight_style(Style::default().fg(Color::Green)),
        chunks[0],
    );

    match model.tab {
        crate::model::Tab::Overview => draw_overview(frame, model, chunks[1]),
        crate::model::Tab::Apps => draw_apps(frame, model, chunks[1]),
        crate::model::Tab::Firewall => draw_firewall(frame, model, chunks[1]),
        crate::model::Tab::Plugins => draw_plugins(frame, model, chunks[1]),
        crate::model::Tab::History => draw_history(frame, model, chunks[1]),
    }
}

fn draw_overview(frame: &mut Frame, model: &AppModel, area: ratatui::layout::Rect) {
    let block = Block::default().borders(Borders::ALL).title("IbexWall");
    let style = match (model.loading, &model.error) {
        (true, _) => Style::default().fg(Color::Gray),
        (false, None) if model.score.unwrap_or(0) >= 90 => Style::default().fg(Color::Green),
        (false, None) => Style::default().fg(Color::Yellow),
        (false, Some(_)) => Style::default().fg(Color::Red),
    };
    let text = vec![
        Line::styled(model.headline(), style),
        Line::from(""),
        Line::from(Span::styled(
            "Nothing changes without your approval · everything is reversible",
            Style::default().add_modifier(Modifier::DIM),
        )),
        Line::from(""),
        Line::from("j/k or Tab: switch tab · r: refresh · q: quit"),
    ];
    frame.render_widget(Paragraph::new(text).block(block), area);
}

/// The monitor's state first (it explains an empty list), then the apps.
pub fn apps_lines(model: &AppModel) -> Vec<String> {
    let mut lines = Vec::new();
    match &model.monitor {
        Some((true, reason)) if reason.is_empty() => lines.push("monitor: running".into()),
        Some((true, reason)) => lines.push(format!("monitor: running ({reason})")),
        Some((false, reason)) => lines.push(format!("monitor: off ({reason})")),
        None => lines.push("monitor: unknown".into()),
    }
    // Waiting connections come before the list: they are time-limited.
    for prompt in &model.prompts {
        lines.push(format!(
            "WAITING #{}: {} -> {}:{}   (y: allow once, b: block once)",
            prompt.id, prompt.app, prompt.destination, prompt.port
        ));
    }
    if model.apps.is_empty() {
        lines.push("no applications seen yet".into());
    }
    for (index, app) in model.apps.iter().enumerate() {
        let cursor = if index == model.selected { '>' } else { ' ' };
        lines.push(format!(
            "{cursor}{:<38} {:<14} {:<8} {:>5} conns {:>4} dests  {}",
            app.key, app.kind, app.mode, app.connections, app.destinations, app.last_seen
        ));
    }
    if !model.apps.is_empty() {
        lines.push("up/down: select · 1 allow · 2 monitor · 3 ask · 4 block".into());
    }
    if let Some(notice) = &model.notice {
        lines.push(notice.clone());
    }
    lines
}

fn draw_apps(frame: &mut Frame, model: &AppModel, area: ratatui::layout::Rect) {
    let rows: Vec<Line> = apps_lines(model).into_iter().map(Line::from).collect();
    frame.render_widget(
        List::new(rows).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Apps and network"),
        ),
        area,
    );
}

/// One line each: manager, zone, allowed, listening, the networks.
pub fn firewall_lines(model: &AppModel) -> Vec<String> {
    if model.firewall.is_empty() {
        return vec!["no firewall state read yet".into()];
    }
    model.firewall.clone()
}

fn draw_firewall(frame: &mut Frame, model: &AppModel, area: ratatui::layout::Rect) {
    let rows: Vec<Line> = firewall_lines(model).into_iter().map(Line::from).collect();
    frame.render_widget(
        List::new(rows).block(Block::default().borders(Borders::ALL).title("Firewall")),
        area,
    );
}

fn draw_plugins(frame: &mut Frame, model: &AppModel, area: ratatui::layout::Rect) {
    let rows: Vec<Line> = model
        .plugins
        .iter()
        .map(|plugin| {
            let state = if plugin.enabled { "on " } else { "off" };
            Line::from(vec![
                Span::styled(
                    format!("[{state}] "),
                    Style::default().fg(if plugin.enabled {
                        Color::Green
                    } else {
                        Color::DarkGray
                    }),
                ),
                Span::styled(plugin.id.clone(), Style::default().fg(Color::Cyan)),
                Span::raw(format!("  {} · {}", plugin.kind, plugin.origin)),
            ])
        })
        .collect();
    frame.render_widget(
        List::new(rows).block(Block::default().borders(Borders::ALL).title("Plugins")),
        area,
    );
}

fn draw_history(frame: &mut Frame, model: &AppModel, area: ratatui::layout::Rect) {
    let rows: Vec<Line> = model
        .history
        .iter()
        .map(|entry| {
            Line::from(format!(
                "{:12} {:10} {}",
                entry.plugin, entry.result, entry.actor
            ))
        })
        .collect();
    frame.render_widget(
        List::new(rows).block(Block::default().borders(Borders::ALL).title("History")),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AppRow;

    fn row(key: &str) -> AppRow {
        AppRow {
            key: key.into(),
            kind: "cli".into(),
            mode: "monitor".into(),
            connections: 3,
            destinations: 2,
            last_seen: "2026-11-03T10:00:00Z".into(),
        }
    }

    #[test]
    fn the_monitor_state_comes_first_and_explains_an_empty_list() {
        let mut model = AppModel::default();
        assert_eq!(apps_lines(&model)[0], "monitor: unknown");
        model.monitor = Some((false, "waiting for ibexwall-monitor".into()));
        let lines = apps_lines(&model);
        assert_eq!(lines[0], "monitor: off (waiting for ibexwall-monitor)");
        assert_eq!(lines[1], "no applications seen yet");
        model.monitor = Some((true, String::new()));
        model.apps = vec![row("cli:/usr/bin/curl")];
        let lines = apps_lines(&model);
        assert_eq!(lines[0], "monitor: running");
        assert!(lines[1].starts_with(">cli:/usr/bin/curl"));
        assert!(lines[1].contains("monitor"));
        assert!(lines[1].contains("3 conns"));
    }

    #[test]
    fn waiting_connections_come_first_and_the_cursor_marks_one_app() {
        use crate::model::PromptRow;
        let mut model = AppModel {
            monitor: Some((true, String::new())),
            apps: vec![row("cli:/usr/bin/curl"), row("cli:/usr/bin/wget")],
            prompts: vec![PromptRow {
                id: "7".into(),
                app: "cli:/usr/bin/curl".into(),
                destination: "example.com".into(),
                port: 443,
            }],
            ..AppModel::default()
        };
        model.move_selection(true);
        model.move_selection(true);
        assert_eq!(model.selected, 1, "the cursor stays inside the list");
        let lines = apps_lines(&model);
        assert!(lines[1].starts_with("WAITING #7: cli:/usr/bin/curl -> example.com:443"));
        assert!(lines[2].starts_with(' '));
        assert!(lines[3].starts_with(">cli:/usr/bin/wget"));
        model.move_selection(false);
        model.move_selection(false);
        assert_eq!(model.selected, 0);
        model.notice = Some("done".into());
        assert_eq!(apps_lines(&model).last().unwrap(), "done");
    }

    #[test]
    fn the_firewall_tab_shows_the_manager_and_honesty_when_empty() {
        let mut model = AppModel::default();
        assert_eq!(firewall_lines(&model), ["no firewall state read yet"]);
        model.firewall = vec![
            "manager: firewalld (on)".into(),
            "allowed ports:    8080/tcp".into(),
        ];
        assert_eq!(firewall_lines(&model).len(), 2);
    }
}
