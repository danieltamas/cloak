//! Platform-specific paths, permissions, and secure file operations.
//!
//! This module abstracts OS differences for config directories,
//! file permissions, secure temporary storage, and secure deletion.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

/// Returns the Cloak configuration directory for the current platform.
///
/// - macOS: `~/Library/Application Support/cloak/`
/// - Linux: `~/.config/cloak/` (or `$XDG_CONFIG_HOME/cloak/`)
/// - Windows: `%APPDATA%\cloak\`
///
/// The directory is created if it does not already exist.
pub fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir()
        .ok_or_else(|| anyhow!("Could not determine config directory for the current user"))?;
    let dir = base.join("cloak");
    ensure_dir(&dir)?;
    Ok(dir)
}

/// Returns the vaults directory (`<config_dir>/vaults/`).
///
/// The directory is created if it does not already exist.
pub fn vaults_dir() -> Result<PathBuf> {
    let dir = config_dir()?.join("vaults");
    ensure_dir(&dir)?;
    Ok(dir)
}

/// Sets private (owner-read/write only) permissions on a file.
///
/// On Unix this applies `chmod 600`. On Windows this is a no-op because
/// NTFS ACL management is not required for the current scope.
pub fn set_private_permissions(path: &Path) -> Result<()> {
    _set_private_permissions_impl(path)
}

#[cfg(unix)]
fn _set_private_permissions_impl(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("Failed to set permissions on {}", path.display()))?;
    Ok(())
}

#[cfg(windows)]
fn _set_private_permissions_impl(_path: &Path) -> Result<()> {
    // Windows ACL management is out of scope for v0.1.0; no-op.
    Ok(())
}

/// Returns a secure temporary directory.
///
/// On Linux, `/dev/shm` is used when available (RAM-backed, never written to disk).
/// On all other platforms (macOS, Windows), the system temporary directory is used.
pub fn secure_temp_dir() -> Result<PathBuf> {
    _secure_temp_dir_impl()
}

#[cfg(target_os = "linux")]
fn _secure_temp_dir_impl() -> Result<PathBuf> {
    let shm = PathBuf::from("/dev/shm");
    if shm.exists() && shm.is_dir() {
        return Ok(shm);
    }
    Ok(std::env::temp_dir())
}

#[cfg(not(target_os = "linux"))]
fn _secure_temp_dir_impl() -> Result<PathBuf> {
    Ok(std::env::temp_dir())
}

/// Securely deletes a file by overwriting it with zeros before removing it.
///
/// This reduces the likelihood of data recovery from storage. Note that on
/// SSDs with wear-leveling, physical overwrite is not guaranteed.
pub fn secure_delete(path: &Path) -> Result<()> {
    use std::io::Write;

    if !path.exists() {
        return Ok(());
    }

    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to read metadata for {}", path.display()))?;
    let len = metadata.len() as usize;

    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("Failed to open {} for overwrite", path.display()))?;

        let zeros = vec![0u8; len.max(1)];
        file.write_all(&zeros)
            .with_context(|| format!("Failed to overwrite {} with zeros", path.display()))?;
        file.flush()
            .with_context(|| format!("Failed to flush {} after overwrite", path.display()))?;
    }

    std::fs::remove_file(path)
        .with_context(|| format!("Failed to remove {} after overwrite", path.display()))?;

    Ok(())
}

/// Creates a directory and all of its parents (equivalent to `mkdir -p`).
///
/// On Unix, newly created directories are given `0o700` permissions
/// (owner read/write/execute only). On Windows this is a no-op beyond
/// the standard directory creation.
pub fn ensure_dir(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(path)
        .with_context(|| format!("Failed to create directory {}", path.display()))?;
    _set_dir_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn _set_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("Failed to set permissions on directory {}", path.display()))?;
    Ok(())
}

#[cfg(windows)]
fn _set_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
