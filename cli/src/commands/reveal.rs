//! `cloak reveal` command — temporarily replace a sandbox value with its real value.
//!
//! This command:
//! 1. Verifies a `.cloak` marker exists.
//! 2. Retrieves the vault key from the OS keychain.
//! 3. Decrypts the vault and finds the real value for the requested key.
//! 4. Reads the sandbox `.env` from disk and replaces that key's value with the real value.
//! 5. Registers a Ctrl+C handler to revert before exit.
//! 6. Sleeps for `duration` seconds.
//! 7. Reverts by writing the sandbox value back to disk.

use crate::{envparser, filemanager, keychain, vault};
use anyhow::{Context, Result};
use colored::Colorize;
use std::sync::{Arc, Mutex};

/// Entry point for the `cloak reveal` command.
///
/// Temporarily replaces the on-disk sandbox value for `key` with the real
/// (decrypted) value. After `duration` seconds (default 30) the sandbox value
/// is automatically restored. If the user presses Ctrl+C the revert also
/// happens before exit.
///
/// # Arguments
///
/// * `key` — the environment variable name whose real value should be revealed.
/// * `duration` — number of seconds to keep the real value on disk.
///
/// # Errors
///
/// Returns an error if the `.cloak` marker is missing, the keychain key cannot be
/// retrieved, decryption fails, the key is not found in the vault, or any file
/// I/O operation fails.
pub fn run(key: String, duration: u64) -> Result<()> {
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

    // 4. Decrypt vault and find the real value for the requested key.
    let real_content = filemanager::read_real(&project_root, &rel_path, &enc_key)?;
    let real_lines = envparser::parse(&real_content);
    let real_value = real_lines
        .iter()
        .find_map(|line| {
            if let envparser::EnvLine::Assignment {
                key: line_key,
                value,
                ..
            } = line
            {
                if line_key == &key {
                    Some(value.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow::anyhow!("Key '{}' not found in vault.", key))?;

    // 5. Read the sandbox .env from disk and locate the key.
    let sandbox_path = project_root.join(&rel_path);
    let sandbox_content = std::fs::read_to_string(&sandbox_path)
        .with_context(|| format!("Failed to read sandbox file {}", sandbox_path.display()))?;
    let sandbox_lines = envparser::parse(&sandbox_content);

    // Find the sandbox value for the key (we need to restore it later).
    let sandbox_value = sandbox_lines
        .iter()
        .find_map(|line| {
            if let envparser::EnvLine::Assignment {
                key: line_key,
                value,
                ..
            } = line
            {
                if line_key == &key {
                    Some(value.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .unwrap_or_default();

    // 6. Build the revealed content: replace the key's value with the real value.
    let revealed_content = replace_value_in_content(&sandbox_content, &key, &real_value);

    // 7. Write the revealed content to disk.
    std::fs::write(&sandbox_path, &revealed_content).with_context(|| {
        format!(
            "Failed to write revealed content to {}",
            sandbox_path.display()
        )
    })?;

    // 8. Build the reverted content (sandbox value back).
    let reverted_content = replace_value_in_content(&revealed_content, &key, &sandbox_value);

    // 9. Register Ctrl+C handler to revert before exit.
    // Use Arc<Mutex<bool>> to track whether revert has already happened.
    let already_reverted = Arc::new(Mutex::new(false));
    let already_reverted_clone = Arc::clone(&already_reverted);
    let sandbox_path_clone = sandbox_path.clone();
    let reverted_content_clone = reverted_content.clone();

    ctrlc::set_handler(move || {
        let mut reverted = already_reverted_clone
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if !*reverted {
            *reverted = true;
            let _ = std::fs::write(&sandbox_path_clone, &reverted_content_clone);
            eprintln!("\nReverted: sandbox values restored.");
        }
        std::process::exit(130);
    })
    .context("Failed to register Ctrl+C handler")?;

    // 10. Print instructions.
    println!(
        "{} Key {} is now revealed for {} second{}.",
        "".yellow(),
        key.cyan().bold(),
        duration,
        if duration == 1 { "" } else { "s" }
    );
    println!("  Real value is now in {} on disk.", sandbox_path.display());
    println!("  Press Ctrl+C to revert immediately.");

    // 11. Sleep for duration seconds.
    std::thread::sleep(std::time::Duration::from_secs(duration));

    // 12. Revert: write sandbox value back.
    {
        let mut reverted = already_reverted.lock().unwrap_or_else(|p| p.into_inner());
        if !*reverted {
            *reverted = true;
            std::fs::write(&sandbox_path, &reverted_content)
                .with_context(|| format!("Failed to revert {}", sandbox_path.display()))?;
        }
    }

    println!("{} Reverted: sandbox values restored.", "".green());

    Ok(())
}

/// Replace the value of `key` in the given `.env` content string.
///
/// Rebuilds the raw line for the key preserving its quote style and export prefix.
/// Returns the modified content. If the key is not found, the content is returned unchanged.
fn replace_value_in_content(content: &str, key: &str, new_value: &str) -> String {
    let mut lines = envparser::parse(content);
    for line in &mut lines {
        if let envparser::EnvLine::Assignment {
            key: ref line_key,
            value: ref mut line_value,
            quote_style,
            raw_line,
            export,
        } = line
        {
            if line_key == key {
                let export_prefix = if *export { "export " } else { "" };
                let new_raw = match quote_style {
                    envparser::QuoteStyle::Double => {
                        format!("{}{}=\"{}\"", export_prefix, line_key, new_value)
                    }
                    envparser::QuoteStyle::Single => {
                        format!("{}{}='{}'", export_prefix, line_key, new_value)
                    }
                    envparser::QuoteStyle::None => {
                        format!("{}{}={}", export_prefix, line_key, new_value)
                    }
                };
                *line_value = new_value.to_string();
                *raw_line = new_raw;
                break;
            }
        }
    }
    envparser::serialize(&lines)
}
