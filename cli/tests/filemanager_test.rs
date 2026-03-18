//! Integration tests for `cli/src/filemanager.rs`.
//!
//! Run with: `cd cli && cargo test --test filemanager_test -- --nocapture`

use cloak::filemanager::{
    protect_file, read_marker, read_real, save_real, unprotect_file, write_marker, CloakMarker,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn test_key() -> [u8; 32] {
    [42u8; 32]
}

fn test_recovery_bytes() -> Vec<u8> {
    vec![0xABu8; 12]
}

/// Standard .env content with secrets.
fn env_with_secrets() -> &'static str {
    "DATABASE_URL=postgres://admin:secret@db:5432/app\nAPI_KEY=sk-abcdefghijklmnopqrstuvwxyz01234567890\nPORT=3000\n# this is a comment\n"
}

/// .env content with NO secrets (only non-secret values).
fn env_no_secrets() -> &'static str {
    "PORT=3000\nNODE_ENV=production\nHOST=localhost\n"
}

/// Create a temp directory, write a `.env` file inside it, and return the dir handle.
fn setup_project(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    std::fs::write(root.join(".env"), content).unwrap();
    (dir, root)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: protect_file creates sandbox on disk, vault, recovery, marker
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_protect_creates_artifacts() {
    let (_dir, root) = setup_project(env_with_secrets());
    let key = test_key();
    let rb = test_recovery_bytes();

    let result = protect_file(&root, ".env", &key, &rb).expect("protect_file should succeed");

    assert!(result.secret_count > 0, "should detect secrets");
    assert!(
        !result.already_protected,
        "first time — not already protected"
    );

    // .cloak marker exists
    assert!(
        root.join(".cloak").exists(),
        ".cloak marker must be written"
    );

    // sandbox .env is on disk
    let sandbox_content = std::fs::read_to_string(root.join(".env")).unwrap();
    assert!(
        !sandbox_content.contains("admin:secret@"),
        "sandbox must not contain real credentials"
    );

    // vault file exists in vaults dir
    let v_path = cloak::vault::vault_path(&root).unwrap();
    assert!(v_path.exists(), "vault file must exist");

    // recovery file exists
    let r_path = cloak::recovery::recovery_path(&root).unwrap();
    assert!(r_path.exists(), "recovery file must exist");

    println!(
        "test_protect_creates_artifacts OK (secrets={})",
        result.secret_count
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: protect_file with no secrets returns secret_count 0, no vault created
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_protect_no_secrets() {
    let (_dir, root) = setup_project(env_no_secrets());
    let key = test_key();
    let rb = test_recovery_bytes();

    let result = protect_file(&root, ".env", &key, &rb).expect("protect_file should succeed");

    assert_eq!(result.secret_count, 0, "should detect 0 secrets");

    // Vault must NOT have been created.
    let v_path = cloak::vault::vault_path(&root).unwrap();
    assert!(
        !v_path.exists(),
        "vault must NOT exist when no secrets found"
    );

    // .cloak marker should also not exist.
    assert!(
        !root.join(".cloak").exists(),
        ".cloak must NOT exist when no secrets"
    );

    println!("test_protect_no_secrets OK");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: protect_file twice is idempotent
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_protect_idempotent() {
    let (_dir, root) = setup_project(env_with_secrets());
    let key = test_key();
    let rb = test_recovery_bytes();

    let r1 = protect_file(&root, ".env", &key, &rb).expect("first protect");
    assert!(
        !r1.already_protected,
        "first time should not be already_protected"
    );

    let r2 = protect_file(&root, ".env", &key, &rb).expect("second protect");
    assert!(
        r2.already_protected,
        "second time must be already_protected"
    );

    // Marker protected list should contain exactly one entry for ".env".
    let marker = read_marker(&root).unwrap().expect("marker must exist");
    let count = marker
        .protected
        .iter()
        .filter(|p| p.as_str() == ".env")
        .count();
    assert_eq!(
        count, 1,
        "protected list should have exactly one '.env' entry"
    );

    println!("test_protect_idempotent OK");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: read_real returns original content
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_read_real_returns_original() {
    let original = env_with_secrets();
    let (_dir, root) = setup_project(original);
    let key = test_key();
    let rb = test_recovery_bytes();

    protect_file(&root, ".env", &key, &rb).expect("protect");

    let real = read_real(&root, ".env", &key).expect("read_real should succeed");
    assert_eq!(real, original, "read_real must return original plaintext");

    println!("test_read_real_returns_original OK");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: save_real updates vault AND sandbox atomically
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_save_real_updates_vault_and_sandbox() {
    let (_dir, root) = setup_project(env_with_secrets());
    let key = test_key();
    let rb = test_recovery_bytes();

    protect_file(&root, ".env", &key, &rb).expect("protect");

    let new_content = "DATABASE_URL=postgres://newuser:newpass@db:5432/newdb\nPORT=8080\n";
    save_real(&root, ".env", new_content, &key).expect("save_real should succeed");

    // Vault should decrypt to new content.
    let real = read_real(&root, ".env", &key).expect("read_real after save");
    assert_eq!(
        real, new_content,
        "vault must contain new content after save"
    );

    // Sandbox on disk must NOT contain the real DB password.
    let sandbox_on_disk = std::fs::read_to_string(root.join(".env")).unwrap();
    assert!(
        !sandbox_on_disk.contains("newuser:newpass@"),
        "sandbox must not contain real credentials after save"
    );

    println!("test_save_real_updates_vault_and_sandbox OK");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: unprotect_file restores original, removes vault, updates marker
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_unprotect_restores_original() {
    let original = env_with_secrets();
    let (_dir, root) = setup_project(original);
    let key = test_key();
    let rb = test_recovery_bytes();

    protect_file(&root, ".env", &key, &rb).expect("protect");

    // File on disk should now be sandbox.
    let sandbox = std::fs::read_to_string(root.join(".env")).unwrap();
    assert!(!sandbox.contains("admin:secret@"), "sandbox check");

    unprotect_file(&root, ".env", &key).expect("unprotect should succeed");

    // File on disk should now be the original.
    let restored = std::fs::read_to_string(root.join(".env")).unwrap();
    assert_eq!(
        restored, original,
        "unprotect must restore original content"
    );

    // Vault must be removed.
    let v_path = cloak::vault::vault_path(&root).unwrap();
    assert!(!v_path.exists(), "vault must be deleted after unprotect");

    // Marker protected list should be empty.
    let marker = read_marker(&root)
        .unwrap()
        .expect("marker should still exist");
    assert!(
        !marker.protected.contains(&".env".to_string()),
        "protected list must not contain '.env' after unprotect"
    );

    println!("test_unprotect_restores_original OK");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: vault and recovery file permissions are 600 on Unix
// ─────────────────────────────────────────────────────────────────────────────
#[test]
#[cfg(unix)]
fn test_file_permissions_600() {
    use std::os::unix::fs::PermissionsExt;

    let (_dir, root) = setup_project(env_with_secrets());
    let key = test_key();
    let rb = test_recovery_bytes();

    protect_file(&root, ".env", &key, &rb).expect("protect");

    let v_path = cloak::vault::vault_path(&root).unwrap();
    let r_path = cloak::recovery::recovery_path(&root).unwrap();

    let vault_mode = std::fs::metadata(&v_path).unwrap().permissions().mode() & 0o777;
    let recovery_mode = std::fs::metadata(&r_path).unwrap().permissions().mode() & 0o777;

    assert_eq!(vault_mode, 0o600, "vault must have 600 permissions");
    assert_eq!(
        recovery_mode, 0o600,
        "recovery file must have 600 permissions"
    );

    println!("test_file_permissions_600 OK (vault={vault_mode:o}, recovery={recovery_mode:o})");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: corrupted vault → clear error mentioning recovery
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_corrupted_vault_error() {
    let (_dir, root) = setup_project(env_with_secrets());
    let key = test_key();
    let rb = test_recovery_bytes();

    protect_file(&root, ".env", &key, &rb).expect("protect");

    // Corrupt the vault file.
    let v_path = cloak::vault::vault_path(&root).unwrap();
    std::fs::write(&v_path, b"not a valid vault at all").unwrap();

    let err = read_real(&root, ".env", &key).expect_err("should fail with corrupted vault");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("corrupt") || msg.contains("recover"),
        "error should mention corruption or recovery, got: {msg}"
    );

    println!("test_corrupted_vault_error OK: {err}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 9: missing vault with marker → clear error mentioning `cloak recover`
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_missing_vault_with_marker_error() {
    let (_dir, root) = setup_project(env_with_secrets());
    let key = test_key();
    let rb = test_recovery_bytes();

    protect_file(&root, ".env", &key, &rb).expect("protect");

    // Remove the vault file manually (simulates lost keychain scenario).
    let v_path = cloak::vault::vault_path(&root).unwrap();
    std::fs::remove_file(&v_path).unwrap();

    let err = read_real(&root, ".env", &key).expect_err("should fail with missing vault");
    let msg = err.to_string();
    assert!(
        msg.contains("cloak recover") || msg.contains("recover"),
        "error should mention 'cloak recover', got: {msg}"
    );

    println!("test_missing_vault_with_marker_error OK: {err}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 10: atomic write — .tmp file not left behind on success
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_no_tmp_file_left_behind() {
    let (_dir, root) = setup_project(env_with_secrets());
    let key = test_key();
    let rb = test_recovery_bytes();

    protect_file(&root, ".env", &key, &rb).expect("protect");

    // No .tmp files should be lingering in the project root.
    let tmp_files: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "tmp")
                .unwrap_or(false)
        })
        .collect();

    assert!(
        tmp_files.is_empty(),
        ".tmp files must not be left behind: {:?}",
        tmp_files.iter().map(|e| e.path()).collect::<Vec<_>>()
    );

    println!("test_no_tmp_file_left_behind OK");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 11: read_marker returns None when no .cloak file
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_read_marker_none_when_absent() {
    let (_dir, root) = setup_project(env_no_secrets());

    let result = read_marker(&root).expect("read_marker should not error");
    assert!(
        result.is_none(),
        "should return None when .cloak does not exist"
    );

    println!("test_read_marker_none_when_absent OK");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 12: write_marker + read_marker roundtrip
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_marker_roundtrip() {
    let (_dir, root) = setup_project(env_no_secrets());

    let marker = CloakMarker {
        version: 1,
        protected: vec![".env".to_string(), ".env.local".to_string()],
        project_hash: "abc123def456abcd".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
    };

    write_marker(&root, &marker).expect("write_marker should succeed");

    let loaded = read_marker(&root)
        .expect("read_marker should succeed")
        .expect("marker should exist after write");

    assert_eq!(loaded.version, marker.version);
    assert_eq!(loaded.protected, marker.protected);
    assert_eq!(loaded.project_hash, marker.project_hash);
    assert_eq!(loaded.created_at, marker.created_at);

    println!("test_marker_roundtrip OK");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 13: marker contains correct project hash and protected files list
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_marker_contains_correct_hash_and_protected() {
    let (_dir, root) = setup_project(env_with_secrets());
    let key = test_key();
    let rb = test_recovery_bytes();

    protect_file(&root, ".env", &key, &rb).expect("protect");

    let marker = read_marker(&root)
        .expect("read_marker should succeed")
        .expect("marker must exist");

    // Verify project hash matches what vault::project_hash computes.
    let expected_hash = cloak::vault::project_hash(&root).unwrap();
    assert_eq!(
        marker.project_hash, expected_hash,
        "marker project_hash must match vault::project_hash"
    );

    assert!(
        marker.protected.contains(&".env".to_string()),
        "marker protected list must contain '.env'"
    );

    assert_eq!(marker.version, 1, "marker version must be 1");

    println!(
        "test_marker_contains_correct_hash_and_protected OK (hash={})",
        marker.project_hash
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 14: protect_file preserves comments and non-secrets in sandbox
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn test_protect_preserves_comments_and_non_secrets() {
    let content =
        "# App configuration\nDATABASE_URL=postgres://admin:secret@db:5432/app\nPORT=3000\n# End of config\n";
    let (_dir, root) = setup_project(content);
    let key = test_key();
    let rb = test_recovery_bytes();

    protect_file(&root, ".env", &key, &rb).expect("protect");

    let sandbox = std::fs::read_to_string(root.join(".env")).unwrap();

    // Comments must be preserved.
    assert!(
        sandbox.contains("# App configuration"),
        "sandbox must preserve comments"
    );
    assert!(
        sandbox.contains("# End of config"),
        "sandbox must preserve trailing comments"
    );

    // Non-secret PORT=3000 must remain unchanged.
    assert!(
        sandbox.contains("PORT=3000"),
        "sandbox must preserve non-secret PORT=3000"
    );

    // Real DB credentials must be replaced.
    assert!(
        !sandbox.contains("admin:secret@"),
        "sandbox must NOT contain real DB credentials"
    );

    println!("test_protect_preserves_comments_and_non_secrets OK");
    println!("sandbox content:\n{sandbox}");
}
