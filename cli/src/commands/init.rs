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

use crate::{detector, envparser, filemanager, keychain, recovery, vault};
use anyhow::{Context, Result};
use colored::Colorize;
use std::io::{self, BufRead, Write};
use std::path::Path;

/// Candidate `.env` file names scanned during `cloak init`, in each directory.
const ENV_FILES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.staging",
    ".env.test",
];

/// Maximum directory depth to descend when scanning for nested `.env` files.
/// 0 = project root only. Mirrors the extension's project-discovery cap.
const MAX_SCAN_DEPTH: usize = 5;

/// Directory names skipped during the recursive scan. Dot-directories
/// (`.git`, `.venv`, …) are skipped separately via a `.`-prefix check.
const IGNORE_DIRS: &[&str] = &["node_modules", "dist", "build", "target", "vendor", "coverage"];

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

    // Step 1: Check idempotency — if .cloak marker exists, check vault health.
    let marker_path = project_root.join(".cloak");
    if marker_path.exists() {
        // Check if the vault is actually functional (keychain key + recovery file).
        let project_hash = vault::project_hash(&project_root)
            .unwrap_or_default();
        let keychain_ok = keychain::get_key(&project_hash).is_ok();
        let recovery_ok = recovery::recovery_path(&project_root)
            .map(|p| p.exists())
            .unwrap_or(false);

        if keychain_ok {
            println!("{}", "Already protected".green());
            return Ok(());
        }

        // Vault is broken — offer to re-initialize.
        if !keychain_ok && !recovery_ok {
            println!(
                "{}",
                "Vault is broken: keychain key missing and no recovery file."
                    .red()
                    .bold()
            );
        } else if !keychain_ok {
            println!(
                "{}",
                "Vault is broken: keychain key missing. Use `cloak recover` if you have the recovery key, or re-init below."
                    .yellow()
                    .bold()
            );
        }
        println!();
        print!("Re-initialize protection from current .env files? [Y/n]: ");
        io::stdout().flush().context("Failed to flush stdout")?;
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .context("Failed to read confirmation")?;
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
        // Remove the old marker so we can proceed with a fresh init.
        std::fs::remove_file(&marker_path).ok();
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

/// Recursively scans `project_root` (and subdirectories up to [`MAX_SCAN_DEPTH`])
/// for candidate env files and returns `(rel_path, secret_count)` pairs for files
/// that contain at least one detected secret.
///
/// Relative paths are forward-slash normalized so they match across platforms and
/// the TypeScript implementation. `node_modules`, build output, and dot-directories
/// are skipped to avoid encrypting vendored or example `.env` files. Symlinked
/// directories are not followed.
fn scan_env_files(project_root: &Path) -> Vec<(String, usize)> {
    let mut results = Vec::new();
    scan_dir(project_root, project_root, 0, &mut results);
    // Deterministic order: shallower/root first, then lexicographic.
    results.sort_by(|a, b| a.0.cmp(&b.0));
    results
}

/// Recursive worker for [`scan_env_files`].
fn scan_dir(project_root: &Path, dir: &Path, depth: usize, results: &mut Vec<(String, usize)>) {
    // Check candidate env files in this directory.
    for &candidate in ENV_FILES {
        let full_path = dir.join(candidate);
        if !full_path.is_file() {
            continue;
        }
        let content = match std::fs::read_to_string(&full_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let count = count_secrets(&content);
        if count > 0 {
            let rel = full_path
                .strip_prefix(project_root)
                .unwrap_or(&full_path)
                .to_string_lossy()
                .replace('\\', "/");
            results.push((rel, count));
        }
    }

    if depth >= MAX_SCAN_DEPTH {
        return;
    }

    // Recurse into subdirectories, skipping ignored and dot-directories.
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        // file_type() does not follow symlinks, so symlinked dirs are skipped.
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || IGNORE_DIRS.contains(&name.as_ref()) {
            continue;
        }
        scan_dir(project_root, &entry.path(), depth + 1, results);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A `.env` line the detector reliably flags as a secret.
    const SECRET_LINE: &str = "DATABASE_URL=postgres://user:password@localhost:5432/db\n";

    #[test]
    fn scan_finds_nested_env_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        std::fs::write(root.join(".env"), SECRET_LINE).unwrap();
        std::fs::create_dir_all(root.join("apps/api")).unwrap();
        std::fs::write(root.join("apps/api/.env"), SECRET_LINE).unwrap();

        let found: Vec<String> = scan_env_files(root).into_iter().map(|(p, _)| p).collect();
        assert!(found.contains(&".env".to_string()), "root .env found");
        assert!(
            found.contains(&"apps/api/.env".to_string()),
            "nested apps/api/.env found, got {found:?}"
        );
    }

    #[test]
    fn scan_skips_ignored_and_dot_directories() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        std::fs::write(root.join(".env"), SECRET_LINE).unwrap();
        for ignored in ["node_modules/pkg", "dist", ".hidden"] {
            std::fs::create_dir_all(root.join(ignored)).unwrap();
            std::fs::write(root.join(ignored).join(".env"), SECRET_LINE).unwrap();
        }

        let found: Vec<String> = scan_env_files(root).into_iter().map(|(p, _)| p).collect();
        assert_eq!(found, vec![".env".to_string()], "only root .env, got {found:?}");
    }

    #[test]
    fn scan_excludes_files_without_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        std::fs::write(root.join(".env"), SECRET_LINE).unwrap();
        std::fs::create_dir_all(root.join("config")).unwrap();
        std::fs::write(root.join("config/.env"), "PORT=3000\nNODE_ENV=production\n").unwrap();

        let found: Vec<String> = scan_env_files(root).into_iter().map(|(p, _)| p).collect();
        assert_eq!(found, vec![".env".to_string()], "no-secret file excluded");
    }

    #[test]
    fn scan_respects_max_depth() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Build a directory chain one level deeper than MAX_SCAN_DEPTH.
        let mut deep = root.to_path_buf();
        for _ in 0..(MAX_SCAN_DEPTH + 1) {
            deep = deep.join("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join(".env"), SECRET_LINE).unwrap();

        let found = scan_env_files(root);
        assert!(found.is_empty(), "file beyond depth cap must be skipped, got {found:?}");
    }
}
