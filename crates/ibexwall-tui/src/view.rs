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

    let titles = ["Overview (j/k)", "Plugins", "History"];
    let selected = match model.tab {
        crate::model::Tab::Overview => 0,
        crate::model::Tab::Plugins => 1,
        crate::model::Tab::History => 2,
    };
    frame.render_widget(
        Tabs::new(titles)
            .select(selected)
            .highlight_style(Style::default().fg(Color::Green)),
        chunks[0],
    );

    match model.tab {
        crate::model::Tab::Overview => draw_overview(frame, model, chunks[1]),
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
