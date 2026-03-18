//! `cloak set` command — add or update a single key-value pair in the vault.
//!
//! This command:
//! 1. Verifies a `.cloak` marker exists.
//! 2. Retrieves the vault key from the OS keychain.
//! 3. Decrypts the vault and parses the real content.
//! 4. Finds the key and updates its value, or appends a new assignment if missing.
//! 5. Serializes back and saves via `filemanager::save_real` (vault + sandbox).
//! 6. Prints a confirmation message.

use crate::{envparser, filemanager, keychain, vault};
use anyhow::{Context, Result};
use colored::Colorize;

/// Entry point for the `cloak set` command.
///
/// Sets `key` to `value` inside the encrypted vault. If the key already exists
/// its value is replaced in-place, preserving surrounding whitespace, comments,
/// and quote style. If the key does not exist it is appended as a plain
/// unquoted assignment at the end of the file. The sandbox `.env` on disk is
/// regenerated automatically.
///
/// # Arguments
///
/// * `key` — the environment variable name to set.
/// * `value` — the new value to assign.
///
/// # Errors
///
/// Returns an error if the `.cloak` marker is missing, the keychain key cannot be
/// retrieved, decryption fails, or any file I/O operation fails.
pub fn run(key: String, value: String) -> Result<()> {
    let project_root = std::env::current_dir().context("Failed to determine current directory")?;
    crate::auth::require_auth(&project_root)?;

    // 1. Read marker — must exist.
    let marker = filemanager::read_marker(&project_root)?
        .ok_or_else(|| anyhow::anyhow!("Not a Cloak project. Run `cloak init` first."))?;

    // 2. Get key from keychain.
    let hash = vault::project_hash(&project_root)
        .map_err(|e| anyhow::anyhow!("Failed to compute project hash: {}", e))?;
    let enc_key = keychain::get_key(&hash)?;

    // 3. Get first protected file.
    let rel_path = marker
        .protected
        .first()
        .ok_or_else(|| anyhow::anyhow!("No protected files found."))?
        .clone();

    // 4. Decrypt vault and parse.
    let real_content = filemanager::read_real(&project_root, &rel_path, &enc_key)?;
    let mut lines = envparser::parse(&real_content);

    // 5. Find and update the key, or append if not present.
    let mut found = false;
    for line in &mut lines {
        if let envparser::EnvLine::Assignment {
            key: ref line_key,
            value: ref mut line_value,
            quote_style,
            raw_line,
            export,
        } = line
        {
            if line_key == &key {
                // Update the value and rebuild raw_line preserving quote style.
                let export_prefix = if *export { "export " } else { "" };
                let new_raw = match quote_style {
                    envparser::QuoteStyle::Double => {
                        format!("{}{}=\"{}\"", export_prefix, line_key, value)
                    }
                    envparser::QuoteStyle::Single => {
                        format!("{}{}='{}'", export_prefix, line_key, value)
                    }
                    envparser::QuoteStyle::None => {
                        format!("{}{}={}", export_prefix, line_key, value)
                    }
                };
                *line_value = value.clone();
                *raw_line = new_raw;
                found = true;
                break;
            }
        }
    }

    if !found {
        // Append a new unquoted assignment.
        let raw = format!("{}={}", key, value);
        lines.push(envparser::EnvLine::Assignment {
            export: false,
            key: key.clone(),
            value: value.clone(),
            quote_style: envparser::QuoteStyle::None,
            raw_line: raw,
        });
    }

    // 6. Serialize back and save (vault + sandbox).
    let new_content = envparser::serialize(&lines);
    filemanager::save_real(&project_root, &rel_path, &new_content, &enc_key)?;

    // 7. Print confirmation.
    if found {
        println!("{} {} updated.", "".green(), key.cyan());
    } else {
        println!("{} {} added.", "".green(), key.cyan());
    }

    Ok(())
}
