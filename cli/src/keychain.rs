use anyhow::{anyhow, Result};

/// Store a 32-byte key in the OS keychain for a project.
///
/// The key is hex-encoded to a 64-character string before storage.
/// Service name is `"cloak"`, account name is `"vault-<project_hash>"`.
pub fn store_key(project_hash: &str, key: &[u8; 32]) -> Result<()> {
    let account = format!("vault-{}", project_hash);
    let entry = keyring::Entry::new("cloak", &account)
        .map_err(|e| anyhow!("Failed to create keychain entry: {}", e))?;
    let hex_key = hex::encode(key);
    entry
        .set_password(&hex_key)
        .map_err(|e| anyhow!("Failed to store key in keychain: {}", e))?;
    Ok(())
}

/// Retrieve a 32-byte key from the OS keychain for a project.
///
/// Returns an error if the key is not found, the stored data is invalid hex,
/// or the decoded length is not exactly 32 bytes.
pub fn get_key(project_hash: &str) -> Result<[u8; 32]> {
    let account = format!("vault-{}", project_hash);
    let entry = keyring::Entry::new("cloak", &account)
        .map_err(|e| anyhow!("Failed to create keychain entry: {}", e))?;
    let hex_key = entry.get_password().map_err(|e| {
        anyhow!(
            "Keychain key not found for this project. Run `cloak recover` to restore access. ({})",
            e
        )
    })?;
    let bytes = hex::decode(&hex_key)
        .map_err(|_| anyhow!("Keychain data corrupted: invalid hex encoding"))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "Keychain data corrupted: expected 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Delete a key from the OS keychain for a project.
///
/// Returns an error if the entry cannot be found or the deletion fails.
pub fn delete_key(project_hash: &str) -> Result<()> {
    let account = format!("vault-{}", project_hash);
    let entry = keyring::Entry::new("cloak", &account)
        .map_err(|e| anyhow!("Failed to create keychain entry: {}", e))?;
    entry
        .delete_credential()
        .map_err(|e| anyhow!("Failed to delete keychain key: {}", e))?;
    Ok(())
}

/// Check if a key exists in the keychain for a project.
///
/// Returns `true` if `get_key` succeeds, `false` otherwise.
pub fn has_key(project_hash: &str) -> bool {
    get_key(project_hash).is_ok()
}
