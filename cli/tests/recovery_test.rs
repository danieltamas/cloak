//! Integration tests for `recovery.rs`.
//!
//! Run with:
//! ```bash
//! cd cli && cargo test --test recovery_test -- --nocapture
//! ```

use cloak::recovery::{
    create_recovery_file, generate_recovery_key, parse_recovery_key, recover_keychain_key,
    RecoveryError,
};

// ─────────────────────────────────────────────────────────────────────────────
// 1. generate_format
// ─────────────────────────────────────────────────────────────────────────────

/// The generated display string must match `CLOAK-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`.
#[test]
fn test_generate_format() {
    let (display, raw) = generate_recovery_key();

    // Display string must start with "CLOAK-"
    assert!(
        display.starts_with("CLOAK-"),
        "display should start with CLOAK-, got: {display}"
    );

    // Must be exactly "CLOAK-" + 6 groups of 4 hex chars separated by "-"
    let parts: Vec<&str> = display.splitn(7, '-').collect();
    assert_eq!(
        parts.len(),
        7,
        "expected 7 dash-separated segments, got: {display}"
    );
    assert_eq!(parts[0], "CLOAK");
    for group in &parts[1..] {
        assert_eq!(group.len(), 4, "each group must be 4 chars, got '{group}'");
        assert!(
            group.chars().all(|c| c.is_ascii_hexdigit()),
            "each group must be hex digits, got '{group}'"
        );
    }

    // Raw bytes must be 12.
    assert_eq!(raw.len(), 12, "raw key must be 12 bytes");

    // The hex encoding of raw bytes must match the groups (case-insensitive).
    let hex_from_raw = hex::encode(&raw).to_uppercase();
    let hex_from_display: String = parts[1..].join("");
    assert_eq!(hex_from_raw, hex_from_display);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. parse_case_insensitive
// ─────────────────────────────────────────────────────────────────────────────

/// Upper-case and lower-case inputs must decode to identical bytes.
#[test]
fn test_parse_case_insensitive() {
    let upper = "CLOAK-ABCD-1234-EF56-7890-ABCD-EF12";
    let lower = "cloak-abcd-1234-ef56-7890-abcd-ef12";

    let bytes_upper = parse_recovery_key(upper).expect("upper-case parse failed");
    let bytes_lower = parse_recovery_key(lower).expect("lower-case parse failed");

    assert_eq!(
        bytes_upper, bytes_lower,
        "case-insensitive: both should decode to same bytes"
    );
    assert_eq!(bytes_upper.len(), 12);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. parse_no_dashes
// ─────────────────────────────────────────────────────────────────────────────

/// Input without any dashes (but with "cloak" prefix) must be accepted.
#[test]
fn test_parse_no_dashes() {
    // 24 hex chars after the "cloak" prefix, no dashes.
    let input = "cloakabcd1234ef5678 90abcdef12";
    // Remove the space — only hex chars are kept after stripping prefix.
    let input_no_space = "cloakabcd1234ef567890abcdef12";

    let result = parse_recovery_key(input_no_space);
    assert!(
        result.is_ok(),
        "no-dashes input should be accepted: {result:?}"
    );
    assert_eq!(result.unwrap().len(), 12);

    // Also works with mixed spacing (non-hex chars stripped).
    let result2 = parse_recovery_key(input);
    assert!(
        result2.is_ok(),
        "input with space should be accepted: {result2:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. parse_invalid
// ─────────────────────────────────────────────────────────────────────────────

/// Clearly invalid strings must return `Err` and must not panic.
#[test]
fn test_parse_invalid() {
    let cases = [
        "invalid",
        "",
        "CLOAK-ZZZZ-1234-EF56-7890-ABCD-EF12", // non-hex chars
        "CLOAK-1234-5678",                     // too short
        "CLOAK-1234-5678-9ABC-DEF0-1234-5678-EXTRA", // too long
    ];

    for input in &cases {
        let result = parse_recovery_key(input);
        assert!(
            result.is_err(),
            "expected Err for input {:?}, got Ok",
            input
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. roundtrip
// ─────────────────────────────────────────────────────────────────────────────

/// create_recovery_file → recover_keychain_key must return the original key.
#[test]
fn test_roundtrip() {
    let keychain_key: [u8; 32] = [0xAB; 32];
    let (_, raw_key) = generate_recovery_key();

    let recovery_bytes =
        create_recovery_file(&keychain_key, &raw_key).expect("create_recovery_file failed");

    let recovered =
        recover_keychain_key(&recovery_bytes, &raw_key).expect("recover_keychain_key failed");

    assert_eq!(
        keychain_key, recovered,
        "roundtrip: recovered key must match original"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. wrong_recovery_key
// ─────────────────────────────────────────────────────────────────────────────

/// Using the wrong recovery key must return `RecoveryError::DecryptionFailed`.
#[test]
fn test_wrong_recovery_key() {
    let keychain_key: [u8; 32] = [0x11; 32];
    let (_, correct_key) = generate_recovery_key();
    let (_, wrong_key) = generate_recovery_key();

    let recovery_bytes = create_recovery_file(&keychain_key, &correct_key).expect("create failed");

    let result = recover_keychain_key(&recovery_bytes, &wrong_key);
    assert!(
        matches!(result, Err(RecoveryError::DecryptionFailed)),
        "expected DecryptionFailed, got: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. tampered_file
// ─────────────────────────────────────────────────────────────────────────────

/// Flipping a byte in the ciphertext must cause an error (no panic).
#[test]
fn test_tampered_file() {
    let keychain_key: [u8; 32] = [0x22; 32];
    let (_, raw_key) = generate_recovery_key();

    let mut recovery_bytes = create_recovery_file(&keychain_key, &raw_key).expect("create failed");

    // Flip a byte in the ciphertext area.
    let last = recovery_bytes.len() - 1;
    recovery_bytes[last] ^= 0xFF;

    let result = recover_keychain_key(&recovery_bytes, &raw_key);
    assert!(result.is_err(), "expected Err for tampered file, got Ok");
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. magic_check
// ─────────────────────────────────────────────────────────────────────────────

/// Bytes that do not start with `RCK` must return `RecoveryError::InvalidMagic`.
#[test]
fn test_magic_check() {
    let bad: Vec<u8> = b"NOTARCK\x01"
        .iter()
        .copied()
        .chain(std::iter::repeat(0).take(60))
        .collect();

    let result = recover_keychain_key(&bad, b"anykey");
    assert!(
        matches!(result, Err(RecoveryError::InvalidMagic)),
        "expected InvalidMagic, got: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. version_check
// ─────────────────────────────────────────────────────────────────────────────

/// A file with version byte ≠ 0x01 must return `RecoveryError::UnsupportedVersion`.
#[test]
fn test_version_check() {
    let keychain_key: [u8; 32] = [0x33; 32];
    let (_, raw_key) = generate_recovery_key();

    let mut recovery_bytes = create_recovery_file(&keychain_key, &raw_key).expect("create failed");

    // Overwrite version byte (index 3).
    recovery_bytes[3] = 0xFF;

    let result = recover_keychain_key(&recovery_bytes, &raw_key);
    assert!(
        matches!(
            result,
            Err(RecoveryError::UnsupportedVersion { found: 0xFF })
        ),
        "expected UnsupportedVersion{{found: 0xFF}}, got: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. salt_randomness
// ─────────────────────────────────────────────────────────────────────────────

/// Two recovery files created for the same keychain key must differ (random salt/IV).
#[test]
fn test_salt_randomness() {
    let keychain_key: [u8; 32] = [0x44; 32];
    let (_, raw_key) = generate_recovery_key();

    let file1 = create_recovery_file(&keychain_key, &raw_key).expect("create 1 failed");
    let file2 = create_recovery_file(&keychain_key, &raw_key).expect("create 2 failed");

    assert_ne!(
        file1, file2,
        "two recovery files for the same key must differ"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. pbkdf2_determinism
// ─────────────────────────────────────────────────────────────────────────────

/// Given the same recovery key bytes and the same salt, PBKDF2 must produce
/// the same derived key — i.e. two recoveries of the same file must succeed.
#[test]
fn test_pbkdf2_determinism() {
    let keychain_key: [u8; 32] = [0x55; 32];
    let (_, raw_key) = generate_recovery_key();

    let recovery_bytes = create_recovery_file(&keychain_key, &raw_key).expect("create failed");

    // Recover twice from the same bytes with the same key.
    let r1 = recover_keychain_key(&recovery_bytes, &raw_key).expect("first recovery failed");
    let r2 = recover_keychain_key(&recovery_bytes, &raw_key).expect("second recovery failed");

    assert_eq!(
        r1, r2,
        "PBKDF2 must be deterministic: two recoveries must agree"
    );
    assert_eq!(r1, keychain_key);
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. empty_recovery_key
// ─────────────────────────────────────────────────────────────────────────────

/// An empty string must not panic and must return `Err`.
#[test]
fn test_empty_recovery_key() {
    let result = parse_recovery_key("");
    assert!(
        result.is_err(),
        "empty input must return Err, got: {result:?}"
    );
}
