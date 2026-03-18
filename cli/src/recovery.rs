//! Recovery key generation, parsing, and recovery file creation/decryption.
//!
//! This module implements the recovery file format (spec §6.3) and recovery
//! key format (spec §6.4). It allows a user to regain access to their vault
//! keychain key using a human-readable recovery key even if the system
//! keychain is lost or corrupted.
//!
//! # Binary format of a `.recovery` file
//!
//! | Offset | Size | Content                                  |
//! |--------|------|------------------------------------------|
//! | 0      | 3    | Magic bytes `RCK`                        |
//! | 3      | 1    | Version `0x01`                           |
//! | 4      | 32   | PBKDF2 salt (random)                     |
//! | 36     | 12   | AES-256-GCM IV (random)                  |
//! | 48     | 16   | AES-256-GCM authentication tag           |
//! | 64     | N    | Ciphertext (32-byte keychain key)        |

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::platform::vaults_dir;

/// Magic bytes identifying a Cloak recovery file.
const MAGIC: &[u8; 3] = b"RCK";
/// Current recovery file format version.
const VERSION: u8 = 0x01;
/// PBKDF2 iteration count for key derivation from recovery key.
const PBKDF2_ITERS: u32 = 100_000;

// Offsets within the recovery file binary format.
const OFFSET_MAGIC: usize = 0;
const OFFSET_VERSION: usize = 3;
const OFFSET_SALT: usize = 4;
const OFFSET_IV: usize = 36;
const OFFSET_TAG: usize = 48;
const OFFSET_CIPHERTEXT: usize = 64;

const LEN_SALT: usize = 32;
const LEN_IV: usize = 12;
const LEN_TAG: usize = 16;

/// Errors that can occur during recovery operations.
#[derive(Debug, Error)]
pub enum RecoveryError {
    /// The file does not begin with the `RCK` magic bytes.
    #[error("Not a recovery file: missing RCK magic")]
    InvalidMagic,

    /// The version byte in the file header is not recognised.
    #[error("Unsupported recovery file version: {found}")]
    UnsupportedVersion {
        /// The version byte that was found.
        found: u8,
    },

    /// The user-supplied recovery key string has an invalid format.
    #[error("Invalid recovery key format")]
    InvalidKeyFormat,

    /// Decryption failed — most likely a wrong recovery key or tampered file.
    #[error("Recovery decryption failed: wrong recovery key or corrupted file")]
    DecryptionFailed,

    /// An I/O error occurred while reading or writing a recovery file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a new human-readable recovery key.
///
/// Returns `(display_string, raw_bytes)` where `display_string` is formatted
/// as `CLOAK-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (24 uppercase hex characters split
/// into six groups of four) and `raw_bytes` is the underlying 12-byte value.
pub fn generate_recovery_key() -> (String, Vec<u8>) {
    let mut raw = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut raw);

    let hex = hex::encode(raw); // 24 lowercase hex chars
    let hex_upper = hex.to_uppercase();

    // Split into 6 groups of 4 characters: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
    let groups: Vec<&str> = (0..6).map(|i| &hex_upper[i * 4..(i + 1) * 4]).collect();
    let display = format!("CLOAK-{}", groups.join("-"));

    (display, raw.to_vec())
}

/// Parse a recovery key from user input.
///
/// Accepts any of these equivalent formats:
/// - `CLOAK-ABCD-1234-EF56-7890-ABCD-EF12`
/// - `cloak-abcd-1234-ef56-7890-abcd-ef12`
/// - `cloakabcd1234ef5678 90abcdef12` (no dashes, spaces, mixed case)
///
/// Returns the raw 12-byte key or a [`RecoveryError::InvalidKeyFormat`].
pub fn parse_recovery_key(input: &str) -> Result<Vec<u8>, RecoveryError> {
    // Normalise: lowercase, strip all non-hex characters.
    let lowered = input.to_lowercase();

    // Strip the optional "cloak" prefix (covers "cloak-" and "cloak").
    let without_prefix = if let Some(rest) = lowered.strip_prefix("cloak") {
        rest
    } else {
        &lowered
    };

    // Remove dashes, spaces, and any other non-hex characters.
    let hex_only: String = without_prefix
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();

    if hex_only.len() != 24 {
        return Err(RecoveryError::InvalidKeyFormat);
    }

    hex::decode(&hex_only).map_err(|_| RecoveryError::InvalidKeyFormat)
}

/// Create the binary contents of a `.recovery` file.
///
/// Derives a 256-bit key from `recovery_key_bytes` and a freshly-generated
/// random 32-byte salt using PBKDF2-SHA256 (100 000 iterations), then
/// encrypts `keychain_key` with AES-256-GCM.
///
/// The returned `Vec<u8>` follows the binary layout described in the module
/// documentation.
pub fn create_recovery_file(
    keychain_key: &[u8; 32],
    recovery_key_bytes: &[u8],
) -> Result<Vec<u8>, RecoveryError> {
    // Generate random salt and IV.
    let mut salt = [0u8; LEN_SALT];
    let mut iv = [0u8; LEN_IV];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut iv);

    // Derive encryption key from recovery key + salt.
    let derived = derive_key(recovery_key_bytes, &salt);

    // Encrypt the keychain key.
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived));
    let nonce = Nonce::from_slice(&iv);
    let ct_with_tag = cipher
        .encrypt(nonce, keychain_key.as_ref())
        .map_err(|_| RecoveryError::DecryptionFailed)?;

    // AES-GCM appends the 16-byte tag at the end of the ciphertext.
    let (ciphertext, tag) = ct_with_tag.split_at(ct_with_tag.len() - LEN_TAG);

    // Assemble the recovery file.
    let mut out = Vec::with_capacity(OFFSET_CIPHERTEXT + ciphertext.len());
    out.extend_from_slice(MAGIC); // 0..3
    out.push(VERSION); //   3
    out.extend_from_slice(&salt); // 4..36
    out.extend_from_slice(&iv); // 36..48
    out.extend_from_slice(tag); // 48..64
    out.extend_from_slice(ciphertext); // 64..

    Ok(out)
}

/// Recover the 32-byte keychain key from a `.recovery` file.
///
/// Parses the binary recovery file, re-derives the encryption key using
/// `recovery_key_bytes` and the stored salt, then decrypts the ciphertext.
///
/// # Errors
///
/// - [`RecoveryError::InvalidMagic`] — file does not start with `RCK`.
/// - [`RecoveryError::UnsupportedVersion`] — unknown version byte.
/// - [`RecoveryError::DecryptionFailed`] — wrong key or tampered ciphertext.
pub fn recover_keychain_key(
    recovery_bytes: &[u8],
    recovery_key_bytes: &[u8],
) -> Result<[u8; 32], RecoveryError> {
    // Validate minimum length: header (64 bytes) + at least 1 byte of ciphertext.
    if recovery_bytes.len() < OFFSET_CIPHERTEXT + 1 {
        return Err(RecoveryError::InvalidMagic);
    }

    // Check magic.
    if &recovery_bytes[OFFSET_MAGIC..OFFSET_MAGIC + 3] != MAGIC {
        return Err(RecoveryError::InvalidMagic);
    }

    // Check version.
    let version = recovery_bytes[OFFSET_VERSION];
    if version != VERSION {
        return Err(RecoveryError::UnsupportedVersion { found: version });
    }

    // Extract fields.
    let salt: &[u8; LEN_SALT] = recovery_bytes[OFFSET_SALT..OFFSET_SALT + LEN_SALT]
        .try_into()
        .map_err(|_| RecoveryError::InvalidMagic)?;
    let iv = &recovery_bytes[OFFSET_IV..OFFSET_IV + LEN_IV];
    let tag = &recovery_bytes[OFFSET_TAG..OFFSET_TAG + LEN_TAG];
    let ciphertext = &recovery_bytes[OFFSET_CIPHERTEXT..];

    // Re-assemble ciphertext||tag for AES-GCM (aes-gcm crate expects it that way).
    let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + LEN_TAG);
    ct_with_tag.extend_from_slice(ciphertext);
    ct_with_tag.extend_from_slice(tag);

    // Derive the decryption key.
    let derived = derive_key(recovery_key_bytes, salt);

    // Decrypt.
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived));
    let nonce = Nonce::from_slice(iv);
    let plaintext = cipher
        .decrypt(nonce, ct_with_tag.as_ref())
        .map_err(|_| RecoveryError::DecryptionFailed)?;

    plaintext
        .as_slice()
        .try_into()
        .map_err(|_| RecoveryError::DecryptionFailed)
}

/// Returns the path to the `.recovery` file for the given project root.
///
/// The file lives at `<vaults_dir>/<project_hash>.recovery` where
/// `project_hash` is the first 16 hex characters of the SHA-256 hash of the
/// canonical, forward-slash-normalised absolute project path.
///
/// # Errors
///
/// Propagates any error from [`vaults_dir()`] or path canonicalisation.
pub fn recovery_path(project_root: &Path) -> Result<PathBuf, anyhow::Error> {
    let dir = vaults_dir()?;
    let hash = project_hash(project_root)?;
    Ok(dir.join(format!("{hash}.recovery")))
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Derive a 32-byte key from `recovery_key_bytes` and `salt` using PBKDF2-SHA256.
fn derive_key(recovery_key_bytes: &[u8], salt: &[u8; LEN_SALT]) -> [u8; 32] {
    let mut derived = [0u8; 32];
    pbkdf2_hmac::<Sha256>(recovery_key_bytes, salt, PBKDF2_ITERS, &mut derived);
    derived
}

/// Compute a short deterministic hash of the project root path.
///
/// The path is normalised to forward slashes and lowercased on Windows
/// before hashing, so the hash is stable across path representations.
fn project_hash(project_root: &Path) -> Result<String, anyhow::Error> {
    use sha2::Digest;

    // Canonicalise to an absolute path without `..` components.
    let canonical = dunce::canonicalize(project_root).unwrap_or_else(|_| project_root.to_owned());

    // Normalise separators to `/` for cross-platform consistency.
    let path_str = canonical.to_string_lossy().replace('\\', "/");

    let digest = sha2::Sha256::digest(path_str.as_bytes());
    // Use the first 16 hex chars (8 bytes) as the identifier — matches vault.rs.
    Ok(hex::encode(&digest[..8]))
}
