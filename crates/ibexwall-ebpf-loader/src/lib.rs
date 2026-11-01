// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! IbexWall eBPF loader (aya) (placeholder; lands with its phase, see docs/plans/).

/// Returns the crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_semver_like() {
        assert!(super::version().split('.').count() >= 2);
    }
}
