//! `cloak keychain-get` — retrieve a vault key from the keychain (for extension integration).
//!
//! Outputs the hex-encoded 32-byte key to stdout and exits.
//! On macOS, this triggers Touch ID / password prompt.
//! This is an internal command used by the VS Code extension.

use crate::keychain;
use anyhow::{anyhow, Result};

pub fn run(project_hash: String) -> Result<()> {
    if project_hash.is_empty() {
        return Err(anyhow!("Project hash cannot be empty"));
    }

    let key = keychain::get_key(&project_hash)?;
    // Output hex to stdout — no newline, no logging, no temp files.
    print!("{}", hex::encode(key));
    Ok(())
}
