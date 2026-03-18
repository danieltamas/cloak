//! `cloak recover` command — restore the vault keychain key from a recovery key.
//!
//! This command:
//! 1. Reads the `.cloak` marker to get the project hash.
//! 2. Locates the `.recovery` file on disk.
//! 3. Prompts for the recovery key (hidden input via [`rpassword`]).
//! 4. Parses and validates the recovery key.
//! 5. Decrypts the recovery file to obtain the original vault key.
//! 6. Stores the vault key back in the OS keychain.

use crate::{filemanager, keychain, recovery};
use anyhow::{anyhow, Context, Result};
use colored::Colorize;

/// Entry point for the `cloak recover` command.
///
/// Restores the vault key into the OS keychain using the user-supplied recovery key.
///
/// # Errors
///
/// Returns an error if the `.cloak` marker is missing, the recovery file does not exist,
/// the recovery key is invalid, decryption fails, or keychain storage fails.
pub fn run() -> Result<()> {
    let project_root = std::env::current_dir().context("Failed to determine current directory")?;

    // Step 1: Read .cloak marker.
    let marker = filemanager::read_marker(&project_root)?.ok_or_else(|| {
        anyhow!(
            "No .cloak marker found in {}. Is this a Cloak-protected project?",
            project_root.display()
        )
    })?;

    let project_hash = &marker.project_hash;

    // Step 2: Locate the recovery file.
    let recovery_file_path =
        recovery::recovery_path(&project_root).context("Failed to compute recovery file path")?;

    if !recovery_file_path.exists() {
        return Err(anyhow!(
            "Recovery file not found at {}.\n\
             The recovery file may have been deleted or moved.\n\
             Without both the recovery key and the recovery file, the vault cannot be recovered.",
            recovery_file_path.display()
        ));
    }

    // Step 3: Prompt for recovery key (hidden input).
    let recovery_key_input = rpassword::prompt_password("Enter recovery key: ")
        .context("Failed to read recovery key")?;

    if recovery_key_input.trim().is_empty() {
        return Err(anyhow!("Recovery key cannot be empty."));
    }

    // Step 4: Parse the recovery key.
    let recovery_key_bytes =
        recovery::parse_recovery_key(recovery_key_input.trim()).map_err(|e| {
            anyhow!(
                "Invalid recovery key format: {}.\n\
                 Expected format: CLOAK-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX",
                e
            )
        })?;

    // Step 5: Read the recovery file.
    let recovery_file_bytes = std::fs::read(&recovery_file_path).with_context(|| {
        format!(
            "Failed to read recovery file at {}",
            recovery_file_path.display()
        )
    })?;

    // Step 6: Decrypt recovery file to get the vault key.
    let vault_key = recovery::recover_keychain_key(&recovery_file_bytes, &recovery_key_bytes)
        .map_err(|e| {
            anyhow!(
                "Recovery failed: {}.\n\
                 Double-check your recovery key and try again.",
                e
            )
        })?;

    // Step 7: Store the vault key back in the keychain.
    keychain::store_key(project_hash, &vault_key)
        .context("Failed to store recovered key in keychain")?;

    // Step 8: Success.
    println!();
    println!("{}", "Keychain restored successfully.".green().bold());
    println!("  You can now use `cloak run`, `cloak edit`, and other commands.");

    Ok(())
}
