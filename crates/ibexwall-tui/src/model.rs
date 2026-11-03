// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! TUI state. Kept separate from rendering so it can be unit tested.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Overview,
    Apps,
    Plugins,
    History,
}

impl Tab {
    pub fn next(self) -> Self {
        match self {
            Tab::Overview => Tab::Apps,
            Tab::Apps => Tab::Plugins,
            Tab::Plugins => Tab::History,
            Tab::History => Tab::Overview,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Tab::Overview => Tab::History,
            Tab::Apps => Tab::Overview,
            Tab::Plugins => Tab::Apps,
            Tab::History => Tab::Plugins,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Apps => "Apps",
            Tab::Plugins => "Plugins",
            Tab::History => "History",
        }
    }
}

/// Names, paths and domains come from other programs: control characters
/// (escape sequences) must never reach the terminal.
pub fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRow {
    pub key: String,
    pub kind: String,
    pub connections: u64,
    pub destinations: u64,
    pub last_seen: String,
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
    /// `None` until the daemon answered; then whether the monitor runs and why not.
    pub monitor: Option<(bool, String)>,
    pub apps: Vec<AppRow>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tabs_cycle_through_apps_in_both_directions() {
        let mut tab = Tab::Overview;
        let mut seen = vec![tab];
        for _ in 0..4 {
            tab = tab.next();
            seen.push(tab);
        }
        assert_eq!(
            seen,
            [
                Tab::Overview,
                Tab::Apps,
                Tab::Plugins,
                Tab::History,
                Tab::Overview
            ]
        );
        assert_eq!(Tab::Overview.prev(), Tab::History);
        assert_eq!(Tab::Apps.prev(), Tab::Overview);
        assert_eq!(Tab::Apps.title(), "Apps");
    }

    #[test]
    fn untrusted_text_loses_its_control_characters() {
        assert_eq!(sanitize("a\u{1b}[31mb\nc\u{7}"), "a?[31mb?c?");
        assert_eq!(sanitize("plain é"), "plain é");
    }
}
