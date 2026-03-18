//! Version constants for Cloak's binary formats and CLI version.
//!
//! These constants are the single source of truth for all format versioning.
//! Other modules reference these when writing or validating file headers.

#![allow(dead_code)]

/// The current Cloak CLI version, sourced from `Cargo.toml`.
pub const CLOAK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The vault file format version this build writes.
pub const VAULT_FORMAT_VERSION: u8 = 0x01;

/// The recovery file format version this build writes.
pub const RECOVERY_FORMAT_VERSION: u8 = 0x01;

/// The marker file format version this build writes.
pub const MARKER_FORMAT_VERSION: u32 = 1;

/// The oldest vault format version this build can read.
pub const MIN_SUPPORTED_VAULT_VERSION: u8 = 0x01;

/// The newest vault format version this build can read.
pub const MAX_SUPPORTED_VAULT_VERSION: u8 = 0x01;

/// The oldest recovery format version this build can read.
pub const MIN_SUPPORTED_RECOVERY_VERSION: u8 = 0x01;

/// The newest recovery format version this build can read.
pub const MAX_SUPPORTED_RECOVERY_VERSION: u8 = 0x01;

/// The oldest marker format version this build can read.
pub const MIN_SUPPORTED_MARKER_VERSION: u32 = 1;

/// The newest marker format version this build can read.
pub const MAX_SUPPORTED_MARKER_VERSION: u32 = 1;
