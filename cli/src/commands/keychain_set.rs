//! `cloak keychain-set` — store a vault key into the OS keychain (for extension integration).
//!
//! Reads a 64-character hex (32-byte) key from **stdin** and stores it under the
//! given project hash. This lets the VS Code extension seed the OS keychain so the
//! `cloak` CLI can decrypt a project that was protected from the editor — keeping a
//! single canonical key store across both implementations.
//!
//! The key is read from stdin (never argv) so it never appears in the process list.
//! This is an internal command used by the VS Code extension; it is hidden from help.

use crate::keychain;
use anyhow::{anyhow, Result};
use std::io::Read;

/// Parse and validate a 64-character hex key into 32 raw bytes.
///
/// Trims surrounding whitespace. Rejects anything that is not exactly 64 hex digits.
fn parse_key_hex(input: &str) -> Result<[u8; 32]> {
    let hex = input.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("Expected a 64-character hex key on stdin"));
    }
    let bytes = hex::decode(hex).map_err(|e| anyhow!("Invalid hex key: {e}"))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Entry point for the `cloak keychain-set` command.
///
/// Reads the hex key from stdin, validates it, and stores it in the OS keychain
/// under `vault-<project_hash>`. No files are written; nothing is printed.
pub fn run(project_hash: String) -> Result<()> {
    if project_hash.is_empty() {
        return Err(anyhow!("Project hash cannot be empty"));
    }

    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| anyhow!("Failed to read key from stdin: {e}"))?;

    let key = parse_key_hex(&input)?;
    keychain::store_key(&project_hash, &key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_64_char_hex() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let key = parse_key_hex(hex).unwrap();
        assert_eq!(key[0], 0x00);
        assert_eq!(key[1], 0x11);
        assert_eq!(key[31], 0xff);
    }

    #[test]
    fn trims_surrounding_whitespace_and_newline() {
        let hex = "  00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";
        assert!(parse_key_hex(hex).is_ok());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(parse_key_hex("abcd").is_err());
        // 62 chars — one byte short.
        assert!(parse_key_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddee").is_err());
    }

    #[test]
    fn rejects_non_hex() {
        // 64 chars but contains 'g'/'z'.
        let bad = "g0112233445566778899aabbccddeeff00112233445566778899aabbccddeezz";
        assert!(parse_key_hex(bad).is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_key_hex("").is_err());
        assert!(parse_key_hex("   \n").is_err());
    }
}
