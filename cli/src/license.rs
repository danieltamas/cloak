//! License tier management for Cloak features.
//!
//! In v0.1.0, all features are free. This module provides extension points
//! for future Pro tier features.

use anyhow::Result;

/// License tier for Cloak features.
#[derive(Debug, Clone, PartialEq)]
pub enum LicenseTier {
    /// Free tier — all v0.1.0 features.
    Free,
    /// Pro tier — future premium features.
    Pro,
}

/// Returns the current license tier. Always Free in v0.1.0.
pub fn current_tier() -> LicenseTier {
    LicenseTier::Free
}

/// Returns whether a feature requires Pro. Always false in v0.1.0.
pub fn requires_pro(_feature: &str) -> bool {
    false
}

/// Gate a feature behind Pro license. Always passes in v0.1.0.
pub fn gate_pro(feature: &str) -> Result<()> {
    if requires_pro(feature) && current_tier() != LicenseTier::Pro {
        anyhow::bail!("Cloak Pro required. https://cloak.dev/pro");
    }
    Ok(())
}
