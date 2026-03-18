//! Vault encrypt/decrypt module for Cloak.
//!
//! Implements the vault binary format (spec §6.2):
//! - Bytes 0–2:   Magic "CLK"
//! - Byte  3:     Version 0x01
//! - Bytes 4–15:  IV / nonce (12 bytes, random)
//! - Bytes 16–31: AES-256-GCM authentication tag (16 bytes)
//! - Bytes 32+:   Ciphertext
//!
//! Encryption: AES-256-GCM, 32-byte key, 12-byte random IV, no AAD.

use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::platform::vaults_dir;
use crate::version::{
    MAX_SUPPORTED_VAULT_VERSION, MIN_SUPPORTED_VAULT_VERSION, VAULT_FORMAT_VERSION,
};

/// The ASCII magic bytes that identify a Cloak vault file.
const MAGIC: &[u8; 3] = b"CLK";

/// Minimum valid vault byte length: magic(3) + version(1) + iv(12) + tag(16) = 32.
const MIN_VAULT_LEN: usize = 32;

/// Errors that can occur during vault operations.
#[derive(Error, Debug)]
pub enum VaultError {
    /// The data does not begin with the "CLK" magic bytes.
    #[error("Not a vault file: missing CLK magic")]
    InvalidMagic,

    /// The vault's version byte is outside the range this build supports.
    #[error("Vault version {found} not supported (supported: v{min}-v{max})")]
    UnsupportedVersion { found: u8, min: u8, max: u8 },

    /// AES-256-GCM authentication failed — wrong key or corrupted data.
    #[error("Decryption failed: wrong key or corrupted data")]
    DecryptionFailed,

    /// An underlying I/O error (e.g. reading/writing vault files).
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Encrypts `plaintext` with the given 32-byte `key` and returns vault bytes.
///
/// The output layout is: `magic(3) || version(1) || iv(12) || tag(16) || ciphertext(N)`.
/// A fresh random 12-byte IV is generated for every call, so two encryptions of the
/// same plaintext will always produce different outputs.
///
/// # Errors
/// Returns `VaultError::DecryptionFailed` (wrapping the aes-gcm error) if encryption
/// unexpectedly fails (this should not occur in normal operation).
pub fn encrypt(plaintext: &str, key: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
    // Generate a random 12-byte IV.
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&iv);

    // aes_gcm::encrypt() returns ciphertext || tag (tag is the last 16 bytes).
    let encrypted = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| VaultError::DecryptionFailed)?;

    let (ciphertext, tag) = encrypted.split_at(encrypted.len() - 16);

    // Layout: magic(3) + version(1) + iv(12) + tag(16) + ciphertext(N)
    let mut out = Vec::with_capacity(32 + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(VAULT_FORMAT_VERSION);
    out.extend_from_slice(&iv);
    out.extend_from_slice(tag);
    out.extend_from_slice(ciphertext);
    Ok(out)
}

/// Decrypts `vault_bytes` with the given 32-byte `key` and returns the plaintext string.
///
/// Validates the "CLK" magic, version byte, and AES-256-GCM authentication tag before
/// returning plaintext.
///
/// # Errors
/// - `VaultError::InvalidMagic` — data does not start with "CLK".
/// - `VaultError::UnsupportedVersion` — version byte is outside the supported range.
/// - `VaultError::DecryptionFailed` — wrong key, tampered ciphertext, or tampered tag.
pub fn decrypt(vault_bytes: &[u8], key: &[u8; 32]) -> Result<String, VaultError> {
    if vault_bytes.len() < MIN_VAULT_LEN {
        // Could be invalid magic, empty, or truncated — check magic first for best error.
        if vault_bytes.len() < 3 || &vault_bytes[0..3] != MAGIC {
            return Err(VaultError::InvalidMagic);
        }
        return Err(VaultError::InvalidMagic);
    }

    // Check magic bytes.
    if &vault_bytes[0..3] != MAGIC {
        return Err(VaultError::InvalidMagic);
    }

    // Check version.
    let version = vault_bytes[3];
    if version < MIN_SUPPORTED_VAULT_VERSION || version > MAX_SUPPORTED_VAULT_VERSION {
        return Err(VaultError::UnsupportedVersion {
            found: version,
            min: MIN_SUPPORTED_VAULT_VERSION,
            max: MAX_SUPPORTED_VAULT_VERSION,
        });
    }

    // Parse IV, tag, ciphertext.
    let iv = &vault_bytes[4..16];
    let tag = &vault_bytes[16..32];
    let ciphertext = &vault_bytes[32..];

    // Rejoin ciphertext || tag for aes_gcm::decrypt().
    let mut combined = Vec::with_capacity(ciphertext.len() + 16);
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(iv);

    let plaintext_bytes = cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|_| VaultError::DecryptionFailed)?;

    String::from_utf8(plaintext_bytes).map_err(|_| VaultError::DecryptionFailed)
}

/// Returns `true` if `data` begins with the "CLK" magic bytes.
///
/// Does not validate any other fields. Use this as a quick pre-check before calling
/// `decrypt`.
pub fn is_vault(data: &[u8]) -> bool {
    data.len() >= 3 && &data[0..3] == MAGIC
}

/// Returns the absolute path for the vault file of the given `project_root`.
///
/// The path is `<vaults_dir>/<project_hash>.vault`.
///
/// # Errors
/// Propagates errors from `vaults_dir()` or `project_hash()`.
pub fn vault_path(project_root: &Path) -> Result<PathBuf, VaultError> {
    let hash = project_hash(project_root)?;
    let dir = vaults_dir().map_err(|e| {
        // anyhow::Error → std::io::Error (Other) → VaultError::Io
        std::io::Error::other(e.to_string())
    })?;
    Ok(dir.join(format!("{hash}.vault")))
}

/// Returns a 16-character hex string derived from SHA-256 of the canonicalized,
/// backslash-normalized absolute path of `project_root`.
///
/// Normalization: all `\` characters are replaced with `/` before hashing, making the
/// hash consistent across platforms and with the TypeScript implementation.
///
/// Uses `dunce::canonicalize` to resolve symlinks and avoid UNC paths on Windows.
///
/// # Errors
/// Returns `VaultError::Io` if the path cannot be canonicalized (e.g. does not exist).
pub fn project_hash(project_root: &Path) -> Result<String, VaultError> {
    let canonical = dunce::canonicalize(project_root)?;
    let normalized = canonical.to_string_lossy().replace('\\', "/");
    let hash = Sha256::digest(normalized.as_bytes());
    Ok(hex::encode(&hash[..8])) // first 16 hex chars = 8 bytes
}
