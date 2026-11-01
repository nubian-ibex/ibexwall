// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! IbexWall plugin SDK (placeholder; lands with its phase, see docs/plans/).

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
