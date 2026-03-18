//! `cloak init` command — detect secrets, generate keys, protect env files.
//!
//! This command:
//! 1. Resolves the project root (current directory).
//! 2. Checks if `.cloak` already exists (idempotent).
//! 3. Scans for `.env*` files and counts secrets using [`envparser`] + [`detector`].
//! 4. Prompts the user for confirmation.
//! 5. Generates a 32-byte vault key and a human-readable recovery key.
//! 6. Displays the recovery key (shown only once).
//! 7. Stores the vault key in the OS keychain.
//! 8. Protects each file via [`filemanager::protect_file`].
//! 9. Appends Cloak instructions to `CLAUDE.md` if that file exists.

use crate::{detector, envparser, filemanager, keychain, recovery};
use anyhow::{Context, Result};
use colored::Colorize;
use std::io::{self, BufRead, Write};
use std::path::Path;

/// Candidate `.env` files scanned during `cloak init`.
const ENV_FILES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.staging",
    ".env.test",
];

/// Text appended to `CLAUDE.md` when it exists in the project root.
const CLAUDE_MD_APPEND: &str = r#"
# Cloak Protection
This project uses Cloak to protect secrets. The .env file contains sandbox (fake) values.
- Do NOT modify sandbox values in .env directly
- Use `cloak run <command>` to run with real environment variables
- Use `cloak edit` to modify secrets
"#;

/// Entry point for the `cloak init` command.
///
/// Runs the full init lifecycle: scan → confirm → generate keys → protect files.
///
/// # Errors
///
/// Returns an error if key generation, keychain storage, or file protection fails.
pub fn run() -> Result<()> {
    let project_root = std::env::current_dir().context("Failed to determine current directory")?;

    // Step 1: Check idempotency — if .cloak marker already exists, bail out cleanly.
    let marker_path = project_root.join(".cloak");
    if marker_path.exists() {
        println!("{}", "Already protected".green());
        return Ok(());
    }

    // Step 2: Scan for env files and count secrets.
    let file_secret_counts = scan_env_files(&project_root);

    let total_secrets: usize = file_secret_counts.iter().map(|(_, c)| c).sum();

    if total_secrets == 0 {
        println!("{}", "No secrets found".yellow());
        return Ok(());
    }

    // Step 3: Print summary.
    let file_count = file_secret_counts.len();
    println!(
        "{}",
        format!(
            "Found {} secrets in {} file{}:",
            total_secrets,
            file_count,
            if file_count == 1 { "" } else { "s" }
        )
        .bold()
    );
    for (rel_path, count) in &file_secret_counts {
        println!(
            "  {} — {} secret{}",
            rel_path.cyan(),
            count,
            if *count == 1 { "" } else { "s" }
        );
    }
    println!();

    // Step 4: Ask confirmation (default yes).
    print!("Protect these files? [Y/n]: ");
    io::stdout().flush().context("Failed to flush stdout")?;

    let stdin = io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .context("Failed to read confirmation")?;
    let trimmed = line.trim();
    if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("y") {
        println!("Aborted.");
        return Ok(());
    }

    // Step 5: Generate keys.
    let key: [u8; 32] = rand::random();
    let (recovery_display, recovery_bytes) = recovery::generate_recovery_key();

    // Step 6: Display recovery key.
    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════╗"
            .yellow()
            .bold()
    );
    println!(
        "{}",
        "║  RECOVERY KEY — save this somewhere safe!        ║"
            .yellow()
            .bold()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════╝"
            .yellow()
            .bold()
    );
    println!();
    println!("  {}", recovery_display.bright_white().bold());
    println!();
    println!("  If your system keychain is lost, this is the ONLY way to recover.");
    println!("  Cloak will {} show this again.", "NEVER".red().bold());
    println!();
    println!("  Save it in your password manager, write it down, or take a screenshot.");
    println!();

    // Step 7: Confirm user has saved the recovery key.
    print!("I've saved my recovery key [Y/n]: ");
    io::stdout().flush().context("Failed to flush stdout")?;

    let mut confirm_line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut confirm_line)
        .context("Failed to read recovery key confirmation")?;
    let confirm_trimmed = confirm_line.trim();
    if !confirm_trimmed.is_empty() && !confirm_trimmed.eq_ignore_ascii_case("y") {
        println!("Aborted. Run `cloak init` again when you are ready.");
        return Ok(());
    }

    // Step 7.5: Set up CLI access password.
    crate::auth::setup_auth(&project_root)?;

    // Step 8: Store key in keychain.
    let project_hash = crate::vault::project_hash(&project_root)
        .map_err(|e| anyhow::anyhow!("Failed to compute project hash: {}", e))?;
    keychain::store_key(&project_hash, &key).context("Failed to store key in keychain")?;

    // Step 9: Protect each env file that has secrets.
    let mut protected_count = 0usize;
    for (rel_path, _) in &file_secret_counts {
        let result = filemanager::protect_file(&project_root, rel_path, &key, &recovery_bytes)
            .with_context(|| format!("Failed to protect {}", rel_path))?;
        if result.secret_count > 0 {
            protected_count += 1;
        }
    }

    // Step 10: Append to CLAUDE.md if it exists.
    let claude_md_path = project_root.join("CLAUDE.md");
    if claude_md_path.exists() {
        append_claude_md(&claude_md_path)?;
    }

    // Step 11: Print success.
    println!();
    println!(
        "{}",
        format!(
            "Protected {} file{} successfully.",
            protected_count,
            if protected_count == 1 { "" } else { "s" }
        )
        .green()
        .bold()
    );
    println!("  AI agents will now see sandbox values. Real values are encrypted in the vault.");
    println!("  Use `cloak run <cmd>` or `cloak edit` to work with real values.");

    Ok(())
}

/// Scans the candidate env file list and returns `(rel_path, secret_count)` pairs
/// for files that exist and contain at least one detected secret.
fn scan_env_files(project_root: &Path) -> Vec<(String, usize)> {
    let mut results = Vec::new();

    for &candidate in ENV_FILES {
        let full_path = project_root.join(candidate);
        if !full_path.exists() {
            continue;
        }

        let content = match std::fs::read_to_string(&full_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let count = count_secrets(&content);
        if count > 0 {
            results.push((candidate.to_string(), count));
        }
    }

    results
}

/// Parses a `.env` file content and returns the number of detected secrets.
fn count_secrets(content: &str) -> usize {
    let lines = envparser::parse(content);
    lines
        .iter()
        .filter(|line| {
            if let envparser::EnvLine::Assignment { key, value, .. } = line {
                detector::detect(key, value).is_secret
            } else {
                false
            }
        })
        .count()
}

/// Appends Cloak instructions to an existing `CLAUDE.md` file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or written.
fn append_claude_md(path: &Path) -> Result<()> {
    use std::fs::OpenOptions;
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .with_context(|| format!("Failed to open {} for appending", path.display()))?;
    file.write_all(CLAUDE_MD_APPEND.as_bytes())
        .with_context(|| format!("Failed to append to {}", path.display()))?;
    Ok(())
}
