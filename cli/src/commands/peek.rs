//! `cloak peek` command — show a side-by-side comparison of sandbox vs real values.
//!
//! This command:
//! 1. Verifies a `.cloak` marker exists.
//! 2. Retrieves the vault key from the OS keychain.
//! 3. Decrypts the vault to get real values.
//! 4. Reads the sandbox `.env` from disk.
//! 5. Prints a formatted comparison table showing differences.

use crate::{envparser, filemanager, keychain, vault};
use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::HashMap;

/// Maximum display width for a value column before truncation.
const MAX_VALUE_WIDTH: usize = 40;

/// Entry point for the `cloak peek` command.
///
/// Decrypts the vault and displays a side-by-side comparison table of sandbox
/// values (on disk) versus real values (from the vault). Values that are the
/// same in both are labelled "(same)". Long values are truncated to 40 chars.
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

    // 2. Get key from keychain.
    let hash = vault::project_hash(&project_root)
        .map_err(|e| anyhow::anyhow!("Failed to compute project hash: {}", e))?;
    let key = keychain::get_key(&hash)?;

    // 3. Get first protected file.
    let rel_path = marker
        .protected
        .first()
        .ok_or_else(|| anyhow::anyhow!("No protected files found."))?;

    // 4. Decrypt vault → parse real values.
    let real_content = filemanager::read_real(&project_root, rel_path, &key)?;
    let real_lines = envparser::parse(&real_content);
    let real_map: HashMap<String, String> = real_lines
        .into_iter()
        .filter_map(|line| {
            if let envparser::EnvLine::Assignment { key, value, .. } = line {
                Some((key, value))
            } else {
                None
            }
        })
        .collect();

    // 5. Read sandbox .env from disk → parse.
    let sandbox_path = project_root.join(rel_path);
    let sandbox_content = std::fs::read_to_string(&sandbox_path)
        .with_context(|| format!("Failed to read sandbox file {}", sandbox_path.display()))?;
    let sandbox_lines = envparser::parse(&sandbox_content);
    let sandbox_map: HashMap<String, String> = sandbox_lines
        .into_iter()
        .filter_map(|line| {
            if let envparser::EnvLine::Assignment { key, value, .. } = line {
                Some((key, value))
            } else {
                None
            }
        })
        .collect();

    // 6. Build the union of keys in insertion order from real (vault is authoritative).
    // Parse again to preserve key order.
    let real_content2 = filemanager::read_real(&project_root, rel_path, &key)?;
    let ordered_keys: Vec<String> = envparser::parse(&real_content2)
        .into_iter()
        .filter_map(|line| {
            if let envparser::EnvLine::Assignment { key, .. } = line {
                Some(key)
            } else {
                None
            }
        })
        .collect();

    // 7. Determine column widths.
    let key_width = ordered_keys
        .iter()
        .map(|k| k.len())
        .max()
        .unwrap_or(3)
        .max(3);

    // 8. Print header.
    println!(
        "{:<key_width$}  {:<MAX_VALUE_WIDTH$}  {}",
        "KEY".bold(),
        "SANDBOX".bold(),
        "REAL".bold(),
        key_width = key_width,
    );
    println!(
        "{}",
        "─"
            .repeat(key_width + 2 + MAX_VALUE_WIDTH + 2 + MAX_VALUE_WIDTH)
            .dimmed()
    );

    // 9. Print rows.
    for key in &ordered_keys {
        let real_val = real_map.get(key).map(|s| s.as_str()).unwrap_or("");
        let sandbox_val = sandbox_map.get(key).map(|s| s.as_str()).unwrap_or("");

        let sandbox_display = truncate(sandbox_val, MAX_VALUE_WIDTH);
        let real_display = if real_val == sandbox_val {
            format!("{} (same)", truncate(real_val, MAX_VALUE_WIDTH - 7))
                .dimmed()
                .to_string()
        } else {
            truncate(real_val, MAX_VALUE_WIDTH).green().to_string()
        };

        println!(
            "{:<key_width$}  {:<MAX_VALUE_WIDTH$}  {}",
            key.cyan(),
            sandbox_display,
            real_display,
            key_width = key_width,
        );
    }

    // Show keys only in sandbox (shouldn't normally occur).
    for key in sandbox_map.keys() {
        if !real_map.contains_key(key) {
            let sandbox_val = sandbox_map.get(key).map(|s| s.as_str()).unwrap_or("");
            println!(
                "{:<key_width$}  {:<MAX_VALUE_WIDTH$}  {}",
                key.cyan(),
                truncate(sandbox_val, MAX_VALUE_WIDTH),
                "(not in vault)".yellow(),
                key_width = key_width,
            );
        }
    }

    Ok(())
}

/// Truncate `s` to at most `max` characters, appending `...` if truncated.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}
