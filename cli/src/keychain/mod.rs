//! Platform-dispatched keychain access.
//!
//! On macOS, uses the data protection keychain with biometric (Touch ID) access control.
//! On all other platforms, uses the `keyring` crate (Windows Credential Manager / Linux secret-service).

use anyhow::Result;

#[cfg(target_os = "macos")]
mod macos;

// `default` is used on all non-macOS platforms, and also on macOS for legacy migration.
mod default;

/// Store a 32-byte key in the OS keychain for a project.
pub fn store_key(project_hash: &str, key: &[u8; 32]) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        // Try biometric keychain first; fall back to legacy if not yet available.
        if let Ok(()) = macos::store_key(project_hash, key) {
            return Ok(());
        }
        return default::store_key(project_hash, key);
    }

    #[cfg(not(target_os = "macos"))]
    return default::store_key(project_hash, key);
}

/// Retrieve a 32-byte key from the OS keychain for a project.
/// On macOS, tries biometric keychain first, then migrates from legacy if found.
pub fn get_key(project_hash: &str) -> Result<[u8; 32]> {
    #[cfg(target_os = "macos")]
    return get_key_macos(project_hash);

    #[cfg(not(target_os = "macos"))]
    return default::get_key(project_hash);
}

/// Delete a key from the OS keychain for a project.
pub fn delete_key(project_hash: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        // Delete from both to be thorough.
        let _ = macos::delete_key(project_hash);
        let _ = default::delete_key(project_hash);
        return Ok(());
    }

    #[cfg(not(target_os = "macos"))]
    return default::delete_key(project_hash);
}

/// Check if a key exists in the keychain for a project.
pub fn has_key(project_hash: &str) -> bool {
    get_key(project_hash).is_ok()
}

/// macOS: try biometric, then migrate from legacy if needed.
#[cfg(target_os = "macos")]
fn get_key_macos(project_hash: &str) -> Result<[u8; 32]> {
    // 1. Try biometric keychain first.
    if let Ok(key) = macos::get_key(project_hash) {
        return Ok(key);
    }

    // 2. Try legacy keychain (keyring crate).
    let legacy_key = default::get_key(project_hash)?;

    // 3. Migrate: store in biometric keychain.
    if let Err(e) = macos::store_key(project_hash, &legacy_key) {
        eprintln!("Warning: could not migrate key to biometric keychain: {}", e);
        return Ok(legacy_key);
    }

    // 4. Verify readback.
    match macos::get_key(project_hash) {
        Ok(readback) if readback == legacy_key => {
            // 5. Verified — delete legacy.
            let _ = default::delete_key(project_hash);
            Ok(legacy_key)
        }
        _ => {
            // Readback failed — keep legacy, remove potentially corrupt biometric entry.
            eprintln!("Warning: biometric keychain verification failed, keeping legacy key");
            let _ = macos::delete_key(project_hash);
            Ok(legacy_key)
        }
    }
}
