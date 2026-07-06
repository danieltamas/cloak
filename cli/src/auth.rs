//! CLI authentication module for Cloak.
//!
//! Provides password-based authentication (with optional macOS Touch ID)
//! to prevent AI agents from accessing secrets through the CLI.
//!
//! Auth files are stored at `<vaults_dir>/<project_hash>.auth` as JSON.
//!
//! ## Graceful degradation
//!
//! - **macOS GUI session, no TTY** (run.dev, IDE task runners with piped stdin):
//!   Touch ID still fires — it's a GUI modal, not a terminal prompt.
//! - **No TTY and no Touch ID** (CI, headless piped input): auth is rejected.
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
/// On macOS with a GUI session, tries Touch ID first — the biometric prompt is
/// a GUI modal (LocalAuthentication), not a terminal read, so it works even when
/// stdin is piped. GUI supervisors (run.dev, IDE task runners) spawn children
/// with piped stdin/stdout, so this path must be attempted *before* the
/// non-interactive bail below, or those tools can never authenticate.
///
/// The password fallback still requires an interactive terminal; a
/// non-interactive session with no Touch ID available is rejected.
///
/// # Errors
///
/// Returns an error if authentication fails (wrong password, cancelled biometric,
/// or no way to prompt).
pub fn require_auth(project_root: &Path) -> Result<()> {
    let auth_path = auth_file_path(project_root)?;

    if !auth_path.exists() {
        // Backwards compatible — no auth file means no auth required.
        return Ok(());
    }

    for method in auth_methods(gui_session_available(), is_interactive()) {
        match method {
            // Biometric is tried first whenever a GUI session exists — see
            // `auth_methods`. On Unavailable we fall through to the next method.
            AuthMethod::Biometric =>
            {
                #[cfg(target_os = "macos")]
                match try_touch_id() {
                    TouchIdResult::Success => return Ok(()),
                    TouchIdResult::Cancelled => anyhow::bail!("Authentication cancelled"),
                    TouchIdResult::Unavailable => {}
                }
            }
            AuthMethod::Password => return verify_password(&auth_path),
        }
    }

    // No usable method: either no GUI + no TTY, or the only option was biometric
    // and its hardware/helper was unavailable with no interactive fallback.
    eprintln!(
        "Warning: Non-interactive session — cannot authenticate. \
         Secrets access requires an interactive terminal."
    );
    anyhow::bail!(
        "Authentication required but no interactive terminal available. \
         Run this command in an interactive terminal."
    );
}

/// An authentication method to attempt, in priority order.
#[derive(Debug, PartialEq, Eq)]
enum AuthMethod {
    /// macOS Touch ID / system-password GUI modal (LocalAuthentication).
    Biometric,
    /// Hidden password prompt on an interactive terminal.
    Password,
}

/// Decides which auth methods to attempt, in order, for the current session.
///
/// Biometric is planned FIRST whenever a GUI session is available, **regardless
/// of whether stdin is a TTY**. This is the fix for the run.dev / IDE-task-runner
/// case: those supervisors pipe stdin, so `is_interactive()` is false even though
/// the user is physically at their Mac — but Touch ID is a GUI modal that needs no
/// TTY. Gating biometric behind interactivity is what made it silently unreachable.
///
/// The password fallback requires an interactive terminal. An empty result means
/// there is no way to authenticate and the caller must reject.
fn auth_methods(gui_session: bool, interactive: bool) -> Vec<AuthMethod> {
    let mut methods = Vec::new();
    if gui_session {
        methods.push(AuthMethod::Biometric);
    }
    if interactive {
        methods.push(AuthMethod::Password);
    }
    methods
}

/// Whether a biometric-capable GUI session is available on this platform.
fn gui_session_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        has_gui_session()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Verifies the stored password against an interactive prompt.
fn verify_password(auth_path: &Path) -> Result<()> {
    let content = std::fs::read_to_string(auth_path)
        .with_context(|| format!("Failed to read auth file {}", auth_path.display()))?;
    let auth: AuthFile =
        serde_json::from_str(&content).context("Failed to parse auth file as JSON")?;

    let stored_salt =
        hex::decode(&auth.salt).context("Failed to decode salt hex from auth file")?;
    let stored_hash =
        hex::decode(&auth.hash).context("Failed to decode hash hex from auth file")?;

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

/// Returns `true` if a CLI auth gate (`.auth` file) is configured for this project.
pub fn auth_configured(project_root: &Path) -> bool {
    auth_file_path(project_root)
        .map(|p| p.exists())
        .unwrap_or(false)
}

/// Returns the path to the auth file for the given project root.
fn auth_file_path(project_root: &Path) -> Result<std::path::PathBuf> {
    let hash = vault::project_hash(project_root)
        .map_err(|e| anyhow::anyhow!("Failed to compute project hash: {}", e))?;
    let dir = platform::vaults_dir()?;
    Ok(dir.join(format!("{hash}.auth")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-compat known vector: the `.auth` PBKDF2 hash must be byte-identical
    /// to the extension (extension/src/auth.ts, same vector in its test). If this
    /// changes, the CLI and extension auth gates diverge — never edit one side only.
    #[test]
    fn auth_pbkdf2_known_vector_matches_extension() {
        let salt = hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
            .unwrap();
        let hash = hash_password("cloak-cross-compat-pw", &salt, PBKDF2_ITERATIONS);
        assert_eq!(
            hex::encode(hash),
            "4ba4cf0bf92ece95fd3026ef1bdf68577540f55854e8d0dda192fc50b71df1ee"
        );
        assert_eq!(PBKDF2_ITERATIONS, 100_000);
        assert_eq!(HASH_LEN, 32);
        assert_eq!(SALT_LEN, 32);
    }

    /// Regression: under run.dev (and any GUI task runner) stdin is piped, so
    /// `is_interactive()` is false — but the user is at their Mac and Touch ID
    /// must still fire. Biometric therefore has to be planned even without a TTY.
    /// Before the fix, the non-interactive check bailed before Touch ID was ever
    /// attempted. See `auth_methods`.
    #[test]
    fn gui_session_without_tty_still_plans_biometric() {
        assert_eq!(auth_methods(true, false), vec![AuthMethod::Biometric]);
    }

    /// Interactive GUI session (normal terminal on a Mac): Touch ID first, then
    /// the password prompt as a fallback.
    #[test]
    fn interactive_gui_session_tries_biometric_then_password() {
        assert_eq!(
            auth_methods(true, true),
            vec![AuthMethod::Biometric, AuthMethod::Password]
        );
    }

    /// No GUI (headless SSH, Linux/Windows) but an interactive TTY: password only.
    #[test]
    fn headless_interactive_session_uses_password_only() {
        assert_eq!(auth_methods(false, true), vec![AuthMethod::Password]);
    }

    /// No GUI and no TTY (CI, headless piped input): nothing to try — reject.
    #[test]
    fn headless_non_interactive_session_has_no_methods() {
        assert!(auth_methods(false, false).is_empty());
    }
}
