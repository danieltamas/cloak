//! macOS keychain access using the data protection keychain with biometric (Touch ID) ACL.
//!
//! Uses `security-framework` SecItem API with:
//! - Access control: BiometryAny | DevicePasscode | Or (Touch ID with password fallback)
//! - Protection: AccessibleWhenPasscodeSetThisDeviceOnly (strongest, no iCloud sync)
//! - Data protection keychain (not legacy file-based keychain)

use anyhow::{anyhow, Result};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::passwords::{
    delete_generic_password, generic_password, set_generic_password_options,
    AccessControlOptions, PasswordOptions,
};

const SERVICE: &str = "cloak-bio";

pub fn store_key(project_hash: &str, key: &[u8; 32]) -> Result<()> {
    let account = format!("vault-{}", project_hash);
    let hex_key = hex::encode(key);

    let mut opts = PasswordOptions::new_generic_password(SERVICE, &account);

    let ac = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        (AccessControlOptions::BIOMETRY_ANY
            | AccessControlOptions::DEVICE_PASSCODE
            | AccessControlOptions::OR)
            .bits(),
    )
    .map_err(|e| anyhow!("Failed to create access control: {}", e))?;

    opts.set_access_control(ac);
    opts.use_protected_keychain();

    set_generic_password_options(hex_key.as_bytes(), opts)
        .map_err(|e| anyhow!("Failed to store key in biometric keychain: {}", e))?;

    Ok(())
}

pub fn get_key(project_hash: &str) -> Result<[u8; 32]> {
    let account = format!("vault-{}", project_hash);

    let mut opts = PasswordOptions::new_generic_password(SERVICE, &account);
    opts.use_protected_keychain();

    let password_bytes = generic_password(opts)
        .map_err(|e| anyhow!("Biometric keychain key not found: {}", e))?;

    let hex_key = String::from_utf8(password_bytes)
        .map_err(|_| anyhow!("Biometric keychain data corrupted: invalid UTF-8"))?;

    let bytes = hex::decode(&hex_key)
        .map_err(|_| anyhow!("Biometric keychain data corrupted: invalid hex encoding"))?;

    if bytes.len() != 32 {
        return Err(anyhow!(
            "Biometric keychain data corrupted: expected 32 bytes, got {}",
            bytes.len()
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn delete_key(project_hash: &str) -> Result<()> {
    let account = format!("vault-{}", project_hash);
    delete_generic_password(SERVICE, &account)
        .map_err(|e| anyhow!("Failed to delete biometric keychain key: {}", e))?;
    Ok(())
}
