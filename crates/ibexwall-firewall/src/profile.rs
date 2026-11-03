// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Network profiles (spec 4.7): how much of this computer a network may
//! see. They map to firewalld zones when those exist; the recommendation
//! for a network is conservative and always comes with its reason.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// Your own network: other devices at home may reach shared services.
    Home,
    /// A workplace network.
    Work,
    /// A network you do not control: only what you chose is open.
    Public,
    /// Open or unknown networks while away: nothing comes in.
    Travel,
}

impl Profile {
    pub const ALL: [Profile; 4] = [
        Profile::Home,
        Profile::Work,
        Profile::Public,
        Profile::Travel,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Profile::Home => "home",
            Profile::Work => "work",
            Profile::Public => "public",
            Profile::Travel => "travel",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == text)
    }

    /// The firewalld zone this profile stands for. `travel` is the `drop`
    /// zone: every unsolicited packet is discarded, SSH included.
    pub fn zone(self) -> &'static str {
        match self {
            Profile::Home => "home",
            Profile::Work => "work",
            Profile::Public => "public",
            Profile::Travel => "drop",
        }
    }
}

/// What kind of network a connection is, as NetworkManager reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    Wired,
    /// Wi-Fi with a password or enterprise login.
    WifiSecured,
    /// Wi-Fi anyone can join.
    WifiOpen,
    /// Mobile broadband, VPNs and anything not understood.
    Other,
}

/// The profile to suggest and, for the cautious ones, why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recommendation {
    pub profile: Profile,
    /// A warning to show with it (a Fluent key), when there is one.
    pub warning: Option<&'static str>,
}

/// Open and unknown networks get `travel` with a warning; a network the
/// user has not classified is otherwise `public`, never `home`: trust is
/// something the user grants.
pub fn recommend(kind: NetworkKind) -> Recommendation {
    match kind {
        NetworkKind::WifiOpen => Recommendation {
            profile: Profile::Travel,
            warning: Some("firewall-warning-open-network"),
        },
        NetworkKind::Other => Recommendation {
            profile: Profile::Travel,
            warning: Some("firewall-warning-unknown-network"),
        },
        NetworkKind::Wired | NetworkKind::WifiSecured => Recommendation {
            profile: Profile::Public,
            warning: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_round_trip_and_map_to_zones() {
        for profile in Profile::ALL {
            assert_eq!(Profile::parse(profile.name()), Some(profile));
        }
        assert_eq!(Profile::parse("Home"), None);
        assert_eq!(Profile::parse("../x"), None);
        assert_eq!(Profile::Home.zone(), "home");
        assert_eq!(Profile::Travel.zone(), "drop");
    }

    #[test]
    fn open_and_unknown_networks_get_travel_with_a_warning() {
        let open = recommend(NetworkKind::WifiOpen);
        assert_eq!(open.profile, Profile::Travel);
        assert_eq!(open.warning, Some("firewall-warning-open-network"));
        let other = recommend(NetworkKind::Other);
        assert_eq!(other.profile, Profile::Travel);
        assert!(other.warning.is_some());
    }

    #[test]
    fn known_networks_are_never_trusted_for_the_user() {
        for kind in [NetworkKind::Wired, NetworkKind::WifiSecured] {
            let recommendation = recommend(kind);
            assert_eq!(recommendation.profile, Profile::Public);
            assert_eq!(recommendation.warning, None);
        }
    }
}
