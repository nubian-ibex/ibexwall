// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! TUI state. Kept separate from rendering so it can be unit tested.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Overview,
    Plugins,
    History,
}

impl Tab {
    pub fn next(self) -> Self {
        match self {
            Tab::Overview => Tab::Plugins,
            Tab::Plugins => Tab::History,
            Tab::History => Tab::Overview,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Tab::Overview => Tab::History,
            Tab::Plugins => Tab::Overview,
            Tab::History => Tab::Plugins,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Plugins => "Plugins",
            Tab::History => "History",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginRow {
    pub id: String,
    pub enabled: bool,
    pub kind: String,
    pub origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRow {
    pub plugin: String,
    pub result: String,
    pub actor: String,
}

#[derive(Debug, Clone, Default)]
pub struct AppModel {
    pub tab: Tab,
    pub loading: bool,
    pub error: Option<String>,
    pub score: Option<u16>,
    pub open_findings: u32,
    pub checked_at: String,
    pub plugins: Vec<PluginRow>,
    pub history: Vec<HistoryRow>,
}

impl AppModel {
    /// One line of the header: the score, or honesty about not having one.
    pub fn headline(&self) -> String {
        if self.loading {
            return "Loading…".into();
        }
        if let Some(err) = &self.error {
            return format!("Cannot reach ibexwalld: {err}");
        }
        match self.score {
            Some(score) => format!("Score {score}/100 · {} open finding(s)", self.open_findings),
            None => "No check has run yet".into(),
        }
    }
}
