//! `cloak edit` command — open the protected `.env` file in the user's editor.
//!
//! This command:
//! 1. Verifies a `.cloak` marker exists in the current directory.
//! 2. Retrieves the vault key from the OS keychain.
//! 3. Decrypts the vault to a temporary file in a secure temp directory.
//! 4. Registers a Ctrl+C handler that securely deletes the temp file before exit.
//! 5. Opens the editor (`$VISUAL` → `$EDITOR` → `vi` / `notepad`) and waits for it to exit.
//! 6. Re-encrypts if the content changed; prints "No changes" otherwise.
//! 7. Securely deletes the temp file.

use crate::{filemanager, keychain, platform, vault};
use anyhow::{Context, Result};

/// Entry point for the `cloak edit` command.
///
/// Opens the first protected `.env` file in the user's preferred editor with real
/// (decrypted) content. If the user saves changes, the vault is re-encrypted and
/// the sandbox file on disk is updated. The plaintext temp file is always securely
/// deleted when the editor exits, even on Ctrl+C.
///
/// # Errors
///
/// Returns an error if the `.cloak` marker is missing, the keychain key cannot be
/// retrieved, decryption fails, the editor cannot be launched, or any file I/O
/// operation fails.
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

    // 3. Get first protected file.
    let rel_path = marker
        .protected
        .first()
        .ok_or_else(|| anyhow::anyhow!("No protected files found."))?;

    // 4. Decrypt vault to get real content.
    let real_content = filemanager::read_real(&project_root, rel_path, &key)?;

    // 5. Write to temp file in secure temp dir.
    let temp_dir = platform::secure_temp_dir()?;
    let temp_path = temp_dir.join(format!("cloak-edit-{}.env", hash));
    std::fs::write(&temp_path, &real_content)
        .with_context(|| format!("Failed to write temp file {}", temp_path.display()))?;

    // 6. Register Ctrl+C handler — securely delete temp and exit 130.
    let temp_path_clone = temp_path.clone();
    ctrlc::set_handler(move || {
        let _ = platform::secure_delete(&temp_path_clone);
        std::process::exit(130);
    })
    .context("Failed to register Ctrl+C handler")?;

    // 7. Determine editor: $VISUAL → $EDITOR → vi (Unix) / notepad (Windows).
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                "notepad".to_string()
            } else {
                "vi".to_string()
            }
        });

    // 8. Open editor and wait for it to exit.
    let status = std::process::Command::new(&editor)
        .arg(&temp_path)
        .status()
        .with_context(|| format!("Failed to launch editor: {}", editor))?;

    if !status.success() {
        let _ = platform::secure_delete(&temp_path);
        anyhow::bail!("Editor exited with non-zero status");
    }

    // 9. Read edited content.
    let edited = std::fs::read_to_string(&temp_path)
        .with_context(|| format!("Failed to read temp file {}", temp_path.display()))?;

    // 10. Compare and save if changed.
    if edited != real_content {
        filemanager::save_real(&project_root, rel_path, &edited, &key)?;
        println!("Saved and re-encrypted.");
    } else {
        println!("No changes.");
    }

    // 11. Secure delete temp file.
    platform::secure_delete(&temp_path)?;

    Ok(())
}
