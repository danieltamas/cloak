//! File manager — orchestration layer for Cloak's protect/unprotect/read/save operations.
//!
//! This module ties together [`vault`], [`recovery`], [`envparser`], [`detector`],
//! [`sandbox`], and [`platform`] into file-level operations. It is the primary
//! entry point for the CLI commands.
//!
//! # Atomic writes
//!
//! All writes use a write-to-`.tmp`-then-rename strategy to avoid partial writes
//! corrupting files. On Unix the rename is atomic; on Windows the original is
//! removed first (best-available, not truly atomic).
//!
//! # Vault storage
//!
//! Vault and recovery files are stored outside the project directory in the
//! platform config dir (e.g. `~/Library/Application Support/cloak/vaults/`).
//! Only the sandbox `.env` is written inside the project directory.

use crate::{detector, envparser, platform, recovery, sandbox, vault, version};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// The `.cloak` marker file that records which files are protected.
///
/// Serialized as JSON and written to `<project_root>/.cloak`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloakMarker {
    /// Marker format version — always [`version::MARKER_FORMAT_VERSION`].
    pub version: u32,
    /// Relative paths of the files currently under Cloak protection.
    pub protected: Vec<String>,
    /// SHA-256-based project identifier (first 16 hex chars of the path hash).
    #[serde(rename = "projectHash")]
    pub project_hash: String,
    /// ISO 8601-style timestamp when protection was first applied.
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Result returned by [`protect_file`].
#[allow(dead_code)]
pub struct ProtectResult {
    /// Number of secret key-value pairs detected in the file.
    pub secret_count: usize,
    /// `true` when the file was already protected (vault already existed).
    pub already_protected: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Protect a `.env` file: detect secrets → encrypt vault → write recovery →
/// write sandbox to disk → update `.cloak` marker.
///
/// # Arguments
///
/// * `project_root` — absolute path to the project directory.
/// * `rel_path` — path to the `.env` file, relative to `project_root`.
/// * `key` — 32-byte AES-256-GCM encryption key.
/// * `recovery_key_bytes` — raw bytes of the recovery key used to encrypt the
///   recovery file (see [`recovery::create_recovery_file`]).
///
/// # Returns
///
/// A [`ProtectResult`] describing how many secrets were found and whether the
/// file was already protected.
///
/// # Errors
///
/// Returns an error if the `.env` file cannot be read, vault encryption fails,
/// or any file I/O operation fails.
pub fn protect_file(
    project_root: &Path,
    rel_path: &str,
    key: &[u8; 32],
    recovery_key_bytes: &[u8],
) -> Result<ProtectResult> {
    let env_path = project_root.join(rel_path);

    // 1. Read the .env file.
    let content = std::fs::read_to_string(&env_path)
        .with_context(|| format!("Failed to read {}", env_path.display()))?;

    // 2. Parse into EnvLine values.
    let lines = envparser::parse(&content);

    // 3. Count secrets.
    let secret_count = lines
        .iter()
        .filter(|line| {
            if let envparser::EnvLine::Assignment { key, value, .. } = line {
                detector::detect(key, value).is_secret
            } else {
                false
            }
        })
        .count();

    // 4. If no secrets, skip protection.
    if secret_count == 0 {
        return Ok(ProtectResult {
            secret_count: 0,
            already_protected: false,
        });
    }

    // 5. Get project hash.
    let hash = vault::project_hash(project_root)
        .map_err(|e| anyhow!("Failed to compute project hash: {e}"))?;

    // Check if already protected (vault already exists).
    let v_path = vault::vault_path(project_root)
        .map_err(|e| anyhow!("Failed to compute vault path: {e}"))?;

    let already_protected = v_path.exists();

    // 6. Generate sandbox content.
    let sandbox_content = sandbox::sandbox_env(&content, &hash);

    // 7. Encrypt original content.
    let vault_bytes =
        vault::encrypt(&content, key).map_err(|e| anyhow!("Vault encryption failed: {e}"))?;

    // 8. Create recovery file bytes.
    let recovery_bytes = recovery::create_recovery_file(key, recovery_key_bytes)
        .map_err(|e| anyhow!("Failed to create recovery file: {e}"))?;

    // 9. Write vault file atomically.
    atomic_write_bytes(&v_path, &vault_bytes)
        .with_context(|| format!("Failed to write vault to {}", v_path.display()))?;

    // 10. Write recovery file atomically.
    let r_path =
        recovery::recovery_path(project_root).context("Failed to compute recovery path")?;
    atomic_write_bytes(&r_path, &recovery_bytes)
        .with_context(|| format!("Failed to write recovery file to {}", r_path.display()))?;

    // 11. Set permissions 600 on vault and recovery files (Unix).
    platform::set_private_permissions(&v_path)
        .with_context(|| format!("Failed to set permissions on {}", v_path.display()))?;
    platform::set_private_permissions(&r_path)
        .with_context(|| format!("Failed to set permissions on {}", r_path.display()))?;

    // 12. Write sandbox content to the .env file on disk (atomic).
    atomic_write_str(&env_path, &sandbox_content)
        .with_context(|| format!("Failed to write sandbox to {}", env_path.display()))?;

    // 13. Update .cloak marker.
    let marker = build_or_update_marker(project_root, rel_path, &hash)?;
    write_marker(project_root, &marker).context("Failed to write .cloak marker")?;

    Ok(ProtectResult {
        secret_count,
        already_protected,
    })
}

/// Remove protection: decrypt vault → restore original `.env` → remove vault →
/// update `.cloak` marker.
///
/// # Errors
///
/// Returns an error if the vault cannot be decrypted, the original content
/// cannot be written to disk, or vault removal fails.
pub fn unprotect_file(project_root: &Path, rel_path: &str, key: &[u8; 32]) -> Result<()> {
    // Decrypt vault and get real content.
    let real_content = read_real(project_root, rel_path, key)?;

    // Restore the real .env to disk.
    let env_path = project_root.join(rel_path);
    atomic_write_str(&env_path, &real_content)
        .with_context(|| format!("Failed to restore {}", env_path.display()))?;

    // Remove vault file.
    let v_path = vault::vault_path(project_root)
        .map_err(|e| anyhow!("Failed to compute vault path: {e}"))?;
    if v_path.exists() {
        std::fs::remove_file(&v_path)
            .with_context(|| format!("Failed to remove vault {}", v_path.display()))?;
    }

    // Update marker — remove this file from the protected list.
    if let Some(mut marker) = read_marker(project_root)? {
        marker.protected.retain(|p| p != rel_path);
        write_marker(project_root, &marker).context("Failed to update .cloak marker")?;
    }

    Ok(())
}

/// Read the real (decrypted) content of a protected `.env` file from its vault.
///
/// # Errors
///
/// - If the vault file is missing, returns an error mentioning `cloak recover`.
/// - If decryption fails (wrong key or corruption), returns an error mentioning `cloak recover`.
/// - If the decrypted content does not contain at least one `=` (sanity check), returns
///   an error mentioning possible corruption.
pub fn read_real(project_root: &Path, rel_path: &str, key: &[u8; 32]) -> Result<String> {
    let v_path = vault::vault_path(project_root)
        .map_err(|e| anyhow!("Failed to compute vault path: {e}"))?;

    // Check for missing vault when a marker is present.
    if !v_path.exists() {
        if read_marker(project_root)?.is_some() {
            return Err(anyhow!(
                "Vault file missing. Run `cloak recover` to restore access."
            ));
        }
        return Err(anyhow!(
            "No vault found for {}. Has this file been protected?",
            rel_path
        ));
    }

    let vault_bytes = std::fs::read(&v_path)
        .with_context(|| format!("Failed to read vault from {}", v_path.display()))?;

    // Quick sanity check before attempting decryption.
    if !vault::is_vault(&vault_bytes) {
        return Err(anyhow!(
            "Vault corrupted. If you have your recovery key, run `cloak recover`."
        ));
    }

    let plaintext = vault::decrypt(&vault_bytes, key)
        .map_err(|e| anyhow!("Wrong key or corrupted vault. Try `cloak recover`. ({})", e))?;

    // Basic integrity check: a valid .env must contain at least one `=`.
    if !plaintext.contains('=') {
        return Err(anyhow!(
            "Vault corrupted: decrypted content does not look like a .env file. \
             If you have your recovery key, run `cloak recover`."
        ));
    }

    Ok(plaintext)
}

/// Save new real content: encrypt to vault and write sandbox version to disk.
///
/// Both the vault and the on-disk `.env` (sandbox) are written atomically.
///
/// # Errors
///
/// Returns an error if encryption fails or any file write fails.
pub fn save_real(project_root: &Path, rel_path: &str, content: &str, key: &[u8; 32]) -> Result<()> {
    // Compute paths.
    let v_path = vault::vault_path(project_root)
        .map_err(|e| anyhow!("Failed to compute vault path: {e}"))?;
    let hash = vault::project_hash(project_root)
        .map_err(|e| anyhow!("Failed to compute project hash: {e}"))?;
    let env_path = project_root.join(rel_path);

    // Encrypt new content.
    let vault_bytes =
        vault::encrypt(content, key).map_err(|e| anyhow!("Vault encryption failed: {e}"))?;

    // Generate sandbox content.
    let sandbox_content = sandbox::sandbox_env(content, &hash);

    // Write vault atomically.
    atomic_write_bytes(&v_path, &vault_bytes)
        .with_context(|| format!("Failed to write vault to {}", v_path.display()))?;

    // Write sandbox to disk atomically.
    atomic_write_str(&env_path, &sandbox_content)
        .with_context(|| format!("Failed to write sandbox to {}", env_path.display()))?;

    Ok(())
}

/// Read the `.cloak` marker file from `<project_root>/.cloak`.
///
/// Returns `Ok(None)` when the file does not exist.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be parsed as valid JSON.
pub fn read_marker(project_root: &Path) -> Result<Option<CloakMarker>> {
    let marker_path = marker_path(project_root);
    if !marker_path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&marker_path)
        .with_context(|| format!("Failed to read marker file {}", marker_path.display()))?;
    let marker: CloakMarker = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse marker file {}", marker_path.display()))?;
    Ok(Some(marker))
}

/// Write (or overwrite) the `.cloak` marker file at `<project_root>/.cloak`.
///
/// The file is written atomically (write-to-`.tmp`, then rename).
///
/// # Errors
///
/// Returns an error if serialization or the file write fails.
pub fn write_marker(project_root: &Path, marker: &CloakMarker) -> Result<()> {
    let marker_path = marker_path(project_root);
    let json = serde_json::to_string_pretty(marker).context("Failed to serialize marker")?;
    atomic_write_str(&marker_path, &json)
        .with_context(|| format!("Failed to write marker to {}", marker_path.display()))?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the path to the `.cloak` marker file for the given project root.
fn marker_path(project_root: &Path) -> PathBuf {
    project_root.join(".cloak")
}

/// Returns a simple ISO 8601-style timestamp string (UTC-assumed, no chrono dependency).
///
/// Format: `YYYY-MM-DDTHH:MM:SSZ` derived from [`std::time::SystemTime`].
fn iso8601_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Compute date/time components from Unix timestamp.
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;

    // Days since epoch.
    let days = secs / 86400;

    // Gregorian calendar calculation.
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Convert days since Unix epoch (1970-01-01) to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Build a new or update an existing [`CloakMarker`], adding `rel_path` to the
/// protected list if not already present.
fn build_or_update_marker(
    project_root: &Path,
    rel_path: &str,
    project_hash: &str,
) -> Result<CloakMarker> {
    let mut marker = match read_marker(project_root)? {
        Some(existing) => existing,
        None => CloakMarker {
            version: version::MARKER_FORMAT_VERSION,
            protected: Vec::new(),
            project_hash: project_hash.to_string(),
            created_at: iso8601_now(),
        },
    };

    if !marker.protected.contains(&rel_path.to_string()) {
        marker.protected.push(rel_path.to_string());
    }

    Ok(marker)
}

/// Atomically write `data` (bytes) to `path`.
///
/// Writes to `<path>.tmp` first, then renames. On Windows the original file
/// is removed before the rename (not atomic, but best-available).
fn atomic_write_bytes(path: &Path, data: &[u8]) -> Result<()> {
    let tmp_path = path.with_extension("tmp");

    std::fs::write(&tmp_path, data)
        .with_context(|| format!("Failed to write temp file {}", tmp_path.display()))?;

    #[cfg(windows)]
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("Failed to remove {} before rename", path.display()))?;
    }

    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "Failed to rename {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;

    Ok(())
}

/// Atomically write `text` (UTF-8) to `path`.
///
/// Convenience wrapper around [`atomic_write_bytes`].
fn atomic_write_str(path: &Path, text: &str) -> Result<()> {
    atomic_write_bytes(path, text.as_bytes())
}
