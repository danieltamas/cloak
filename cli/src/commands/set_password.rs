//! `cloak set-password` command — set or change the CLI access password (auth gate).
//!
//! Creates the `<hash>.auth` file that gates `cloak run / peek / edit / …` behind
//! Touch ID (macOS) or a password. `cloak init` sets this up for fresh projects,
//! but a project protected from the editor — or any already-protected project —
//! may not have it. This command adds (or rotates) the gate without re-protecting
//! anything.
//!
//! If a gate already exists, the current credential is required before it can be
//! changed, so an AI agent can't silently reset it.

use crate::{auth, filemanager};
use anyhow::{anyhow, Result};

pub fn run() -> Result<()> {
    let cwd = std::env::current_dir().map_err(|e| anyhow!("Failed to read current dir: {e}"))?;
    let project_root = filemanager::find_project_root(&cwd)
        .ok_or_else(|| anyhow!("Not a Cloak project. Run `cloak init` first."))?;

    // Marker must exist — don't create a dangling gate for an unprotected dir.
    if filemanager::read_marker(&project_root)?.is_none() {
        return Err(anyhow!("Not a Cloak project. Run `cloak init` first."));
    }

    // Rotating an existing gate requires passing the current one first.
    if auth::auth_configured(&project_root) {
        eprintln!("A CLI password is already set — authenticate to change it.");
        auth::require_auth(&project_root)?;
    }

    auth::setup_auth(&project_root)?;
    Ok(())
}
