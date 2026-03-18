//! `cloak unprotect` command — remove Cloak protection and restore the original `.env`.
//!
//! This command:
//! 1. Verifies a `.cloak` marker exists.
//! 2. Retrieves the vault key from the OS keychain.
//! 3. For each protected file, calls `filemanager::unprotect_file` to decrypt
//!    the vault and restore the real content to disk.
//! 4. Deletes the `.cloak` marker file.
//! 5. Deletes the keychain entry for this project.
//! 6. Prints a confirmation message.

use crate::{filemanager, keychain};
use anyhow::{Context, Result};
use colored::Colorize;

/// Entry point for the `cloak unprotect` command.
///
/// Restores every protected file to its real (decrypted) content on disk,
/// removes the vault files, deletes the `.cloak` marker, and removes the
/// keychain entry. After this command the project is no longer protected.
///
/// # Errors
///
/// Returns an error if the `.cloak` marker is missing, the keychain key cannot be
/// retrieved, decryption fails, or any file I/O operation fails.
pub fn run() -> Result<()> {
    let project_root = std::env::current_dir().context("Failed to determine current directory")?;
    crate::auth::require_auth(&project_root)?;

    // 1. Read marker — must exist.
    let marker = filemanager::read_marker(&project_root)?
        .ok_or_else(|| anyhow::anyhow!("Not a Cloak project. Run `cloak init` first."))?;

    let project_hash = marker.project_hash.clone();

    // 2. Get key from keychain.
    let key = keychain::get_key(&project_hash)?;

    // 3. Unprotect each file.
    let protected = marker.protected.clone();
    for rel_path in &protected {
        filemanager::unprotect_file(&project_root, rel_path, &key)
            .with_context(|| format!("Failed to unprotect {}", rel_path))?;
        println!("  {} restored to real values.", rel_path.cyan());
    }

    // 4. Delete the .cloak marker file.
    let marker_path = project_root.join(".cloak");
    if marker_path.exists() {
        std::fs::remove_file(&marker_path)
            .with_context(|| format!("Failed to remove marker file {}", marker_path.display()))?;
    }

    // 5. Remove keychain entry.
    // Ignore errors here — the project is already unprotected on disk.
    let _ = keychain::delete_key(&project_hash);

    // 6. Print confirmation.
    println!();
    println!("{}", "Cloak protection removed.".green().bold());
    println!("  All files have been restored to their real values.");
    println!("  Run `cloak init` to re-protect this project.");

    Ok(())
}
