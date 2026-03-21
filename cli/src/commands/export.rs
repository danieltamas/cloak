//! `cloak export` — output decrypted env vars as JSON for tool integration.
//!
//! This command:
//! 1. Verifies a `.cloak` marker exists in the current directory.
//! 2. Retrieves the vault key from the OS keychain.
//! 3. Decrypts the vault and parses the real key-value pairs.
//! 4. Outputs all assignments as a JSON object to stdout.
//!
//! All banners and messages go to stderr, so piping works: `cloak export | jq`

use crate::{envparser, filemanager, keychain, vault};
use anyhow::{Context, Result};

/// Entry point for the `cloak export` command.
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

    // 3. Get first protected file and decrypt.
    let rel_path = marker
        .protected
        .first()
        .ok_or_else(|| anyhow::anyhow!("No protected files found."))?;
    let real_content = filemanager::read_real(&project_root, rel_path, &key)?;

    // 4. Parse and collect into a JSON map.
    let lines = envparser::parse(&real_content);
    let mut map = serde_json::Map::new();
    for line in lines {
        if let envparser::EnvLine::Assignment { key, value, .. } = line {
            map.insert(key, serde_json::Value::String(value));
        }
    }

    // 5. Print JSON to stdout.
    println!("{}", serde_json::to_string(&map)?);

    Ok(())
}
