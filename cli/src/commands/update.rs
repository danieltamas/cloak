//! `cloak update` command — self-update to the latest GitHub release.
//!
//! This command:
//! 1. Uses the `self_update` crate to check the GitHub releases for `danieltamas/cloak`.
//! 2. Compares the current version with the latest available release.
//! 3. Downloads and replaces the binary if a newer version is available.
//! 4. Prints the result.

use anyhow::{Context, Result};
use colored::Colorize;

/// Entry point for the `cloak update` command.
///
/// Checks GitHub releases for `danieltamas/cloak` and updates the running binary
/// if a newer version is available. Shows download progress during the update.
/// Prints the current version and outcome when complete.
///
/// # Errors
///
/// Returns an error if the GitHub API cannot be reached, the release cannot be
/// downloaded, or the binary cannot be replaced (e.g. insufficient permissions).
pub fn run() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    println!("  Current version: {}", current.cyan());
    println!("  Checking for updates...");

    let status = self_update::backends::github::Update::configure()
        .repo_owner("danieltamas")
        .repo_name("cloak")
        .bin_name("cloak")
        .current_version(current)
        .show_download_progress(true)
        .build()
        .context("Failed to configure self-updater")?
        .update()
        .context("Failed to perform self-update")?;

    match status {
        self_update::Status::UpToDate(version) => {
            println!("{} Already up to date (v{}).", "".green(), version);
        }
        self_update::Status::Updated(version) => {
            println!("{} Updated to v{}.", "".green().bold(), version.cyan());
        }
    }

    Ok(())
}
