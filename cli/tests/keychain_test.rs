use cloak::keychain;

// Use a unique test hash to avoid colliding with real vault keys.
const TEST_HASH: &str = "cloak_test_keychain_00";

/// Store a key and verify it can be retrieved with the same value.
#[test]
#[ignore]
fn store_and_retrieve() {
    let key: [u8; 32] = [42u8; 32];
    keychain::store_key(TEST_HASH, &key).expect("store should succeed");
    let retrieved = keychain::get_key(TEST_HASH).expect("get should succeed");
    assert_eq!(key, retrieved);
    // cleanup
    let _ = keychain::delete_key(TEST_HASH);
}

/// Storing the same key multiple times is idempotent — the last stored value is returned.
#[test]
#[ignore]
fn idempotent() {
    let key: [u8; 32] = [7u8; 32];
    for _ in 0..5 {
        keychain::store_key(TEST_HASH, &key).expect("repeated store should succeed");
    }
    let retrieved = keychain::get_key(TEST_HASH).expect("get after repeated store should succeed");
    assert_eq!(key, retrieved);
    // cleanup
    let _ = keychain::delete_key(TEST_HASH);
}

/// After deleting a key, has_key returns false.
#[test]
#[ignore]
fn delete_key() {
    let key: [u8; 32] = [99u8; 32];
    keychain::store_key(TEST_HASH, &key).expect("store should succeed");
    assert!(keychain::has_key(TEST_HASH), "key should exist after store");
    keychain::delete_key(TEST_HASH).expect("delete should succeed");
    assert!(
        !keychain::has_key(TEST_HASH),
        "key should not exist after delete"
    );
}

/// Retrieving a non-existent key returns an Err, not a panic.
#[test]
#[ignore]
fn missing_key() {
    // Ensure it is gone first
    let _ = keychain::delete_key(TEST_HASH);

    let result = keychain::get_key(TEST_HASH);
    assert!(
        result.is_err(),
        "get_key on non-existent key should return Err"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("cloak recover"),
        "error message should suggest `cloak recover`, got: {}",
        err_msg
    );
}

/// has_key returns true after storing and false after deleting.
#[test]
#[ignore]
fn has_key_check() {
    // Start clean
    let _ = keychain::delete_key(TEST_HASH);
    assert!(
        !keychain::has_key(TEST_HASH),
        "should be absent before store"
    );

    let key: [u8; 32] = [11u8; 32];
    keychain::store_key(TEST_HASH, &key).expect("store should succeed");
    assert!(
        keychain::has_key(TEST_HASH),
        "should be present after store"
    );

    keychain::delete_key(TEST_HASH).expect("delete should succeed");
    assert!(
        !keychain::has_key(TEST_HASH),
        "should be absent after delete"
    );
}
