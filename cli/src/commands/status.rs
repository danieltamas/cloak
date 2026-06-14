//! `cloak status` command — show the current protection status of the project.
//!
//! This command:
//! 1. Checks whether a `.cloak` marker exists in the current directory.
//! 2. If not present: prints a "not protected" message.
//! 3. If present: shows protected files, secret counts, vault location,
//!    keychain status, and recovery file status.

use crate::{filemanager, keychain, recovery, vault};
use anyhow::{Context, Result};
use colored::Colorize;

/// Entry point for the `cloak status` command.
///
/// Displays protection status for the current project. When the project is not
/// protected under Cloak a short guidance message is shown. When it is protected
/// the command reports the list of protected files, vault location, keychain
/// availability, and recovery file presence.
///
/// # Errors
///
/// Returns an error if the current directory cannot be determined or file I/O fails.
pub fn run() -> Result<()> {
    let cwd = std::env::current_dir().context("Failed to determine current directory")?;
    let project_root = match filemanager::find_project_root(&cwd) {
        Some(root) => root,
        None => {
            println!("{}", "Not protected.".yellow().bold());
            println!("  Run {} to protect this project.", "`cloak init`".cyan());
            return Ok(());
        }
    };

    // 1. Check for .cloak marker.
    let marker = filemanager::read_marker(&project_root)?;

    if marker.is_none() {
        println!("{}", "Not protected.".yellow().bold());
        println!("  Run {} to protect this project.", "`cloak init`".cyan());
        return Ok(());
    }

    let marker = marker.unwrap();

    // 2. Header.
    println!("{}", "Cloak protection is active.".green().bold());
    println!();

    // 3. Project info.
    println!(
        "  {} {}",
        "Project hash:".bold(),
        marker.project_hash.dimmed()
    );
    println!(
        "  {} {}",
        "Protected since:".bold(),
        marker.created_at.dimmed()
    );
    println!();

    // 4. Protected files (each with its own vault).
    println!("  {}", "Protected files:".bold());
    let mut any_vault_missing = false;
    for rel_path in &marker.protected {
        let abs_path = project_root.join(rel_path);
        let exists_marker = if abs_path.exists() {
            "".green().to_string()
        } else {
            " (missing from disk)".red().to_string()
        };

        // Count secrets in sandbox (on-disk) file.
        let secret_info = if abs_path.exists() {
            match std::fs::read_to_string(&abs_path) {
                Ok(content) => {
                    let count = count_assignments(&content);
                    format!(" ({} assignments)", count)
                }
                Err(_) => String::new(),
            }
        } else {
            String::new()
        };

        // Per-file vault presence.
        let vault_present = vault::vault_path(&project_root, rel_path)
            .map(|p| p.exists())
            .unwrap_or(false);
        if !vault_present {
            any_vault_missing = true;
        }
        let vault_note = if vault_present {
            String::new()
        } else {
            " — vault MISSING".red().bold().to_string()
        };

        println!(
            "    {} {}{}{}{}",
            exists_marker,
            rel_path.cyan(),
            secret_info.dimmed(),
            if abs_path.exists() {
                String::new()
            } else {
                " (missing)".red().to_string()
            },
            vault_note,
        );
    }
    println!();

    // 5. Vault summary.
    let vaults_dir = vault::vault_path(&project_root, ".env")
        .map(|p| p.parent().map(|d| d.display().to_string()).unwrap_or_default())
        .unwrap_or_default();
    let vault_status = if any_vault_missing {
        "one or more MISSING — run `cloak recover`"
            .red()
            .bold()
            .to_string()
    } else {
        "all present".green().to_string()
    };
    println!("  {} {}", "Vaults:".bold(), vault_status);
    println!("    {}", vaults_dir.dimmed());
    println!();

    // 6. Keychain status.
    let keychain_ok = keychain::has_key(&marker.project_hash);
    let keychain_status = if keychain_ok {
        "available".green().to_string()
    } else {
        "NOT FOUND — run `cloak recover`".red().bold().to_string()
    };
    println!("  {} {}", "Keychain:".bold(), keychain_status);
    println!();

    // 7. Recovery file status.
    let recovery_path =
        recovery::recovery_path(&project_root).context("Failed to compute recovery file path")?;
    let recovery_status = if recovery_path.exists() {
        "present".green().to_string()
    } else {
        "missing".yellow().to_string()
    };
    println!("  {} {}", "Recovery file:".bold(), recovery_status);
    println!("    {}", recovery_path.display().to_string().dimmed());

    Ok(())
}

/// Count the number of `Assignment` lines in the given `.env` content.
fn count_assignments(content: &str) -> usize {
    use crate::envparser;
    envparser::parse(content)
        .into_iter()
        .filter(|line| matches!(line, envparser::EnvLine::Assignment { .. }))
        .count()
}
