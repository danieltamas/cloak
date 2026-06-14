//! `cloak export` — output decrypted env vars as JSON for tool integration.
//!
//! This command:
//! 1. Verifies a `.cloak` marker exists in the current directory.
//! 2. Retrieves the vault key from the OS keychain.
//! 3. Decrypts every protected file and merges their real key-value pairs
//!    (later files override earlier ones on key conflict).
//! 4. Outputs all assignments as a JSON object to stdout.
//!
//! All banners and messages go to stderr, so piping works: `cloak export | jq`

use crate::{filemanager, keychain, vault};
use anyhow::{Context, Result};

/// Entry point for the `cloak export` command.
pub fn run() -> Result<()> {
    let cwd = std::env::current_dir().context("Failed to determine current directory")?;
    let project_root = filemanager::find_project_root(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Not a Cloak project. Run `cloak init` first."))?;
    crate::auth::require_auth(&project_root)?;

    // 1. Read marker — must exist.
    let marker = filemanager::read_marker(&project_root)?
        .ok_or_else(|| anyhow::anyhow!("Not a Cloak project. Run `cloak init` first."))?;

    // 2. Get key from keychain.
    let hash = vault::project_hash(&project_root)
        .map_err(|e| anyhow::anyhow!("Failed to compute project hash: {}", e))?;
    let key = keychain::get_key(&hash)?;

    // 3. Decrypt every protected file and merge their real env vars.
    if marker.protected.is_empty() {
        anyhow::bail!("No protected files found.");
    }
    let env_vars = filemanager::read_all_env_vars(&project_root, &marker.protected, &key)?;

    // 4. Collect into a JSON map (later files already overrode earlier ones).
    let mut map = serde_json::Map::new();
    for (key, value) in env_vars {
        map.insert(key, serde_json::Value::String(value));
    }

    // 5. Print JSON to stdout.
    println!("{}", serde_json::to_string(&map)?);

    Ok(())
}
