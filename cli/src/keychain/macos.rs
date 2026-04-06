use anyhow::{anyhow, Result};

pub fn store_key(_project_hash: &str, _key: &[u8; 32]) -> Result<()> {
    Err(anyhow!("Biometric keychain not yet implemented"))
}

pub fn get_key(_project_hash: &str) -> Result<[u8; 32]> {
    Err(anyhow!("Biometric keychain not yet implemented"))
}

pub fn delete_key(_project_hash: &str) -> Result<()> {
    Err(anyhow!("Biometric keychain not yet implemented"))
}
