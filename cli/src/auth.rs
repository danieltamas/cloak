//! CLI authentication module for Cloak.
//!
//! Provides password-based authentication (with optional macOS Touch ID)
//! to prevent AI agents from accessing secrets through the CLI.
//!
//! Auth files are stored at `<vaults_dir>/<project_hash>.auth` as JSON.
//!
//! ## Graceful degradation
//!
//! - **No TTY** (CI, piped input): auth is skipped with a warning.
//!   Secrets in CI should come from the CI provider's secret store, not Cloak.
//! - **macOS Touch ID unavailable** (SSH, old hardware): falls back to password.
//! - **No auth file** (pre-auth projects): auth is not required (backwards compat).

use anyhow::{Context, Result};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::path::Path;

use crate::platform;
use crate::vault;

/// Number of PBKDF2 iterations for password hashing.
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Length of the derived key in bytes.
const HASH_LEN: usize = 32;

/// Length of the random salt in bytes.
const SALT_LEN: usize = 32;

/// Maximum number of password confirmation retries during setup.
const MAX_RETRIES: usize = 3;

/// JSON-serializable auth file structure.
#[derive(serde::Serialize, serde::Deserialize)]
struct AuthFile {
    version: u32,
    salt: String,
    hash: String,
    method: String,
    iterations: u32,
}

/// Sets up CLI access password during `cloak init`.
///
/// Prompts the user to choose a password, hashes it with PBKDF2-SHA256,
/// and stores the auth file in the vaults directory.
///
/// # Errors
///
/// Returns an error if the user fails to confirm the password after 3 attempts,
/// or if the auth file cannot be written.
pub fn setup_auth(project_root: &Path) -> Result<()> {
    if !is_interactive() {
        // Non-interactive session (CI/piped) — skip password setup.
        // The user can set a password later with `cloak init` in an interactive terminal.
        eprintln!("Non-interactive session detected — skipping CLI password setup.");
        eprintln!("Run `cloak init` in an interactive terminal to set a password.");
        eprintln!();
        return Ok(());
    }

    eprintln!("Set a password for CLI access to your secrets.");
    eprintln!("This prevents AI agents from using the CLI to read your secrets.");
    eprintln!();

    let password = prompt_and_confirm_password()?;

    // Generate random salt.
    let salt: [u8; SALT_LEN] = rand::random();

    // Hash the password.
    let hash = hash_password(&password, &salt, PBKDF2_ITERATIONS);

    // Build auth file.
    let auth = AuthFile {
        version: 1,
        salt: hex::encode(salt),
        hash: hex::encode(hash),
        method: "pbkdf2-sha256".to_string(),
        iterations: PBKDF2_ITERATIONS,
    };

    // Write to <vaults_dir>/<project_hash>.auth
    let auth_path = auth_file_path(project_root)?;
    let json = serde_json::to_string_pretty(&auth).context("Failed to serialize auth file")?;
    std::fs::write(&auth_path, json)
        .with_context(|| format!("Failed to write auth file {}", auth_path.display()))?;
    platform::set_private_permissions(&auth_path)?;

    eprintln!("CLI password set.");
    eprintln!();

    Ok(())
}

/// Requires the user to authenticate before accessing secrets.
///
/// If no auth file exists (backwards-compatible with pre-auth projects),
/// returns `Ok(())` immediately.
///
/// On macOS, first tries Touch ID via `bioutil` / `LocalAuthentication`.
/// Falls back to password prompt on all platforms.
///
/// In non-interactive sessions (no TTY), auth is skipped with a warning.
///
/// # Errors
///
/// Returns an error if authentication fails (wrong password).
pub fn require_auth(project_root: &Path) -> Result<()> {
    let auth_path = auth_file_path(project_root)?;

    if !auth_path.exists() {
        // Backwards compatible — no auth file means no auth required.
        return Ok(());
    }

    // Non-interactive session — no way to prompt.
    if !is_interactive() {
        eprintln!(
            "Warning: Non-interactive session — cannot authenticate. \
             Secrets access requires an interactive terminal."
        );
        anyhow::bail!(
            "Authentication required but no interactive terminal available. \
             Run this command in an interactive terminal."
        );
    }

    // Read and parse auth file.
    let content = std::fs::read_to_string(&auth_path)
        .with_context(|| format!("Failed to read auth file {}", auth_path.display()))?;
    let auth: AuthFile =
        serde_json::from_str(&content).context("Failed to parse auth file as JSON")?;

    let stored_salt =
        hex::decode(&auth.salt).context("Failed to decode salt hex from auth file")?;
    let stored_hash =
        hex::decode(&auth.hash).context("Failed to decode hash hex from auth file")?;

    // On macOS, try Touch ID first (only if GUI session is available).
    #[cfg(target_os = "macos")]
    {
        if has_gui_session() {
            match try_touch_id() {
                TouchIdResult::Success => return Ok(()),
                TouchIdResult::Cancelled => {
                    anyhow::bail!("Authentication cancelled");
                }
                TouchIdResult::Unavailable => {
                    // Fall through to password prompt.
                }
            }
        }
    }

    // Password fallback (all platforms).
    let password = rpassword::prompt_password("Password: ")
        .context("Failed to read password from terminal")?;

    let computed = hash_password(&password, &stored_salt, auth.iterations);

    if computed != stored_hash {
        anyhow::bail!("Authentication failed: wrong password");
    }

    Ok(())
}

/// Returns `true` if stdin is connected to a TTY (interactive terminal).
fn is_interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

// ── macOS Touch ID ──────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
enum TouchIdResult {
    Success,
    Cancelled,
    Unavailable,
}

/// Checks if a GUI session is available (not SSH-only / headless).
#[cfg(target_os = "macos")]
fn has_gui_session() -> bool {
    // DISPLAY or TERM_PROGRAM set → GUI session likely.
    // SSH_TTY set without DISPLAY → headless SSH.
    if std::env::var("SSH_TTY").is_ok() && std::env::var("DISPLAY").is_err() {
        return false;
    }
    true
}

/// Attempts macOS Touch ID / system password via LocalAuthentication.
///
/// Uses `swift` to run an inline script that calls `LAContext.evaluatePolicy`.
/// Policy `.deviceOwnerAuthentication` tries Touch ID first, then falls back
/// to the macOS account password — works on Macs without Touch ID too.
///
/// Falls back gracefully:
/// - Touch ID hardware absent → macOS password dialog
/// - Swift not installed → returns Unavailable
/// - No GUI session → caller skips this entirely
/// - Timeout after 60s → returns Unavailable
#[cfg(target_os = "macos")]
fn try_touch_id() -> TouchIdResult {
    use std::io::Read;

    eprintln!("Verifying identity...");

    // Write a temp Swift file and compile+run it, because `swift -e` can hang
    // in some terminal contexts. A compiled binary gets proper SecurityAgent access.
    let tmp_dir = std::env::temp_dir();
    let src_path = tmp_dir.join("cloak-touchid.swift");
    let bin_path = tmp_dir.join("cloak-touchid");

    // Only recompile if binary doesn't exist.
    if !bin_path.exists() {
        let swift_src = r#"
import LocalAuthentication
import Foundation

let ctx = LAContext()
var error: NSError?

guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
    print("unavailable")
    exit(0)
}

let sem = DispatchSemaphore(value: 0)
var result = "cancelled"

ctx.evaluatePolicy(
    .deviceOwnerAuthentication,
    localizedReason: "Cloak needs to verify your identity to access secrets"
) { success, _ in
    result = success ? "ok" : "cancelled"
    sem.signal()
}

sem.wait()
print(result)
"#;

        if std::fs::write(&src_path, swift_src).is_err() {
            return TouchIdResult::Unavailable;
        }

        let compile = std::process::Command::new("swiftc")
            .args(["-O"])
            .arg(&src_path)
            .arg("-o")
            .arg(&bin_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        let _ = std::fs::remove_file(&src_path);

        match compile {
            Ok(s) if s.success() => {}
            _ => return TouchIdResult::Unavailable,
        }
    }

    // Run the helper with a 60-second timeout.
    let mut child = match std::process::Command::new(&bin_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return TouchIdResult::Unavailable,
    };

    // Wait with timeout.
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > std::time::Duration::from_secs(60) {
                    let _ = child.kill();
                    return TouchIdResult::Unavailable;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(_) => return TouchIdResult::Unavailable,
        }
    }

    let mut stdout = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout);
    }

    match stdout.trim() {
        "ok" => TouchIdResult::Success,
        "cancelled" => TouchIdResult::Cancelled,
        _ => TouchIdResult::Unavailable,
    }
}

// ── Password helpers ────────────────────────────────────────────────────────

/// Prompts the user for a password and confirmation, retrying up to 3 times.
fn prompt_and_confirm_password() -> Result<String> {
    for attempt in 0..MAX_RETRIES {
        let password = rpassword::prompt_password("Password: ")
            .context("Failed to read password from terminal")?;

        if password.is_empty() {
            eprintln!("Password cannot be empty.");
            if attempt < MAX_RETRIES - 1 {
                eprintln!();
            }
            continue;
        }

        let confirm = rpassword::prompt_password("Confirm: ")
            .context("Failed to read password confirmation from terminal")?;

        if password == confirm {
            return Ok(password);
        }

        eprintln!("Passwords do not match.");
        if attempt < MAX_RETRIES - 1 {
            eprintln!();
        }
    }

    anyhow::bail!("Failed to set password after {} attempts", MAX_RETRIES);
}

/// Hashes a password with PBKDF2-SHA256.
fn hash_password(password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut hash = vec![0u8; HASH_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut hash);
    hash
}

/// Returns the path to the auth file for the given project root.
fn auth_file_path(project_root: &Path) -> Result<std::path::PathBuf> {
    let hash = vault::project_hash(project_root)
        .map_err(|e| anyhow::anyhow!("Failed to compute project hash: {}", e))?;
    let dir = platform::vaults_dir()?;
    Ok(dir.join(format!("{hash}.auth")))
}
