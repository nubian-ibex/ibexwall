// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The parts of the daemon that are not the DNS server itself: building
//! the policy from settings plus stored lists, and refreshing the lists.

use std::sync::Arc;
use std::time::Duration;

use crate::config::Settings;
use crate::handler::Handler;
use crate::lists::{self, Fetcher, ListRef, Store};
use crate::policy::Policy;

/// Settings rules plus every stored list. Lists that were never fetched
/// are skipped, so a first boot without network still serves.
pub fn build_policy(settings: &Settings, store: &Store) -> Policy {
    let mut policy = settings.policy();
    for list in &settings.lists {
        if let Some(parsed) = store.load(&list.id) {
            policy.block(parsed.block);
            policy.allow(parsed.allow);
        }
    }
    if settings.block_doh
        && let Some(list) = &settings.doh_list
        && let Some(parsed) = store.load(&list.id)
    {
        policy.doh_endpoints(parsed.block);
    }
    policy
}

/// One refresh pass: update every list, then swap in the new policy if at
/// least one list changed. Returns how many lists updated successfully;
/// failures are reported through `on_error` and never stop the others.
pub fn refresh(
    settings: &Settings,
    store: &Store,
    fetcher: &dyn Fetcher,
    handler: &Handler,
    mut on_error: impl FnMut(&str, &lists::ListError),
) -> usize {
    let mut updated = 0;
    let mut targets: Vec<&ListRef> = settings.lists.iter().collect();
    if let Some(list) = &settings.doh_list {
        targets.push(list);
    }
    for list in targets {
        match lists::update(store, fetcher, list) {
            Ok(_) => updated += 1,
            Err(error) => on_error(&list.id, &error),
        }
    }
    if updated > 0 {
        handler.set_policy(build_policy(settings, store));
    }
    updated
}

/// Runs `refresh` forever on a blocking thread: first soon after start
/// (lists may be missing), then every interval plus jitter.
pub fn spawn_updater(
    settings: Arc<Settings>,
    store: Arc<Store>,
    fetcher: Arc<dyn Fetcher>,
    handler: Handler,
) {
    // Nothing to keep updated: neither block lists nor a DoH endpoints list.
    if settings.lists.is_empty() && settings.doh_list.is_none() {
        return;
    }
    tokio::spawn(async move {
        let interval = Duration::from_secs(settings.update_interval_hours.max(1) * 3600);
        let mut delay = Duration::from_secs(30);
        loop {
            tokio::time::sleep(delay).await;
            let (settings, store, fetcher, handler) = (
                Arc::clone(&settings),
                Arc::clone(&store),
                Arc::clone(&fetcher),
                handler.clone(),
            );
            let result = tokio::task::spawn_blocking(move || {
                refresh(&settings, &store, fetcher.as_ref(), &handler, |id, error| {
                    tracing::warn!(list = id, %error, "list update failed; keeping the stored copy");
                })
            })
            .await;
            if let Ok(updated) = result {
                tracing::info!(updated, "lists refreshed");
            }
            delay = lists::next_delay(interval, jitter_seed());
        }
    });
}

/// Cheap per-process entropy for jitter; it only spreads load, so it does
/// not need to be unpredictable.
fn jitter_seed() -> u64 {
    use std::hash::{BuildHasher, RandomState};
    RandomState::new().hash_one(std::time::SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::build_resolver;
    use crate::lists::{ListError, ListRef};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counting(AtomicUsize, &'static str);

    impl Fetcher for Counting {
        fn fetch(&self, url: &str, _max: usize) -> Result<Vec<u8>, ListError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            if url.contains("broken") {
                return Err(ListError::Fetch("boom".into()));
            }
            Ok(self.1.as_bytes().to_vec())
        }
    }

    fn settings(lists: &[(&str, &str)]) -> Settings {
        let lists: Vec<serde_json::Value> = lists
            .iter()
            .map(|(id, url)| serde_json::json!({ "id": id, "url": url }))
            .collect();
        serde_json::from_value(serde_json::json!({
            "servers": [{ "ip": "192.0.2.1", "server_name": "dns.example", "transport": "tls" }],
            "block": ["static.example"],
            "allow": ["fine.ads.example"],
            "lists": lists,
            "doh_list": { "id": "doh_endpoints", "url": "https://x.example/doh" },
        }))
        .unwrap()
    }

    fn temp_store(name: &str) -> Store {
        let dir =
            std::env::temp_dir().join(format!("ibexwall-daemon-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Store::new(dir)
    }

    #[tokio::test]
    async fn policy_merges_settings_and_stored_lists_and_skips_missing_ones() {
        let settings = settings(&[
            ("a", "https://x.example/a"),
            ("missing", "https://x.example/m"),
        ]);
        let store = temp_store("merge");
        lists::update(
            &store,
            &Counting(0.into(), "ads.example\n@@||ok.example^\n"),
            &ListRef {
                id: "a".into(),
                url: Some("https://x.example/a".into()),
            },
        )
        .unwrap();
        lists::update(
            &store,
            &Counting(0.into(), "doh1.example\n"),
            &ListRef {
                id: "doh_endpoints".into(),
                url: Some("https://x.example/doh".into()),
            },
        )
        .unwrap();
        let policy = build_policy(&settings, &store);
        use crate::policy::Category::{DohEndpoint, List};
        use crate::policy::Verdict::{Block, Forward};
        assert_eq!(policy.decide("ads.example"), Block(List));
        assert_eq!(policy.decide("static.example"), Block(List));
        assert_eq!(policy.decide("fine.ads.example"), Forward);
        assert_eq!(policy.decide("ok.example"), Forward);
        assert_eq!(policy.decide("doh1.example"), Block(DohEndpoint));
    }

    #[tokio::test]
    async fn refresh_swaps_the_policy_and_survives_one_failing_list() {
        let settings = settings(&[
            ("good", "https://x.example/good"),
            ("bad", "https://x.example/broken"),
        ]);
        let store = temp_store("refresh");
        let resolver = build_resolver(&settings.servers).unwrap();
        let handler = Handler::new(settings.policy(), resolver);
        let fetcher = Counting(0.into(), "newly-blocked.example\n");
        let mut errors = vec![];
        let updated = refresh(&settings, &store, &fetcher, &handler, |id, _| {
            errors.push(id.to_string());
        });
        // Two lists updated (good and the DoH endpoints list), one failed.
        assert_eq!(updated, 2);
        assert_eq!(errors, vec!["bad".to_string()]);
        assert_eq!(fetcher.0.load(Ordering::SeqCst), 3);
        // The swap is visible through the handler's policy.
        let none = settings.policy();
        assert_eq!(none.blocked_len(), 1);
        assert!(
            store
                .load("good")
                .unwrap()
                .block
                .contains("newly-blocked.example")
        );
    }
}
