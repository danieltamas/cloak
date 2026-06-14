//! `cloak run` command — inject real environment variables and run a child process.
//!
//! This command:
//! 1. Verifies a `.cloak` marker exists in the current directory.
//! 2. Retrieves the vault key from the OS keychain.
//! 3. Decrypts every protected file and merges their real key-value pairs
//!    (later files override earlier ones on key conflict).
//! 4. Spawns the requested command with the real env vars injected (inheriting the
//!    parent's environment, overriding with real secret values).
//! 5. Waits for the child to exit and forwards its exit code.
//!
//! No files are modified by this command.

use crate::{filemanager, keychain, vault};
use anyhow::{Context, Result};

/// Entry point for the `cloak run` command.
///
/// Decrypts the vault, extracts real environment variable values, and spawns
/// `command[0]` with the remaining elements as arguments. The child process
/// inherits the parent's full environment, with real secret values overlaid.
/// Exits with the child process's exit code.
///
/// # Arguments
///
/// * `command` — the command to run followed by its arguments (must be non-empty).
///
/// # Errors
///
/// Returns an error if the `.cloak` marker is missing, the keychain key cannot be
/// retrieved, decryption fails, or the child process cannot be spawned.
pub fn run(command: Vec<String>) -> Result<()> {
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

    // 3. Decrypt every protected file and merge their real env vars (later
    //    files override earlier ones on key conflict).
    if marker.protected.is_empty() {
        anyhow::bail!("No protected files found.");
    }
    let env_vars = filemanager::read_all_env_vars(&project_root, &marker.protected, &key)?;

    // 4. Split command into program and arguments.
    let (cmd, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("No command specified"))?;

    // 5. Spawn child process with real env vars injected (inherits parent env).
    let status = std::process::Command::new(cmd)
        .args(args)
        .envs(env_vars)
        .status()
        .with_context(|| format!("Failed to execute: {}", cmd))?;

    // 6. Exit with the child's exit code.
    std::process::exit(status.code().unwrap_or(1));
}
