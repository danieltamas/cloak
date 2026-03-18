//! Integration tests for the sandbox module.

use cloak::detector::SecretType;
use cloak::sandbox::{deterministic_hex, sandbox_env, sandbox_value};

const PROJ: &str = "testproject123";

// ── 1. sandbox_database_url_postgres ─────────────────────────────────────────

#[test]
fn sandbox_database_url_postgres() {
    let result = sandbox_value(
        "DATABASE_URL",
        "postgres://user:secret@db.example.com:5432/myapp",
        &SecretType::DatabaseUrl,
        PROJ,
    );
    assert_eq!(result, "postgres://dev:dev@localhost:5432/devdb");
    println!("postgres sandbox: {}", result);
}

// ── 2. sandbox_database_url_redis ────────────────────────────────────────────

#[test]
fn sandbox_database_url_redis() {
    let result = sandbox_value(
        "REDIS_URL",
        "redis://:password@redis.example.com:6379",
        &SecretType::DatabaseUrl,
        PROJ,
    );
    assert_eq!(result, "redis://localhost:6379");
    println!("redis sandbox: {}", result);
}

// ── 3. sandbox_stripe_live_key ───────────────────────────────────────────────

#[test]
fn sandbox_stripe_live_key() {
    let result = sandbox_value(
        "STRIPE_SECRET_KEY",
        "sk_test_FAKE23xyz456def789ghi012jkl345",
        &SecretType::StripeKey,
        PROJ,
    );
    assert_eq!(result, "sk_test_cloak_sandbox_000000000000");
    println!("stripe live sandbox: {}", result);

    // pk_live_ also replaced
    let pk = sandbox_value(
        "STRIPE_PK",
        "pk_test_FAKE23xyz456def789ghi012jkl345",
        &SecretType::StripeKey,
        PROJ,
    );
    assert_eq!(pk, "pk_test_cloak_sandbox_000000000000");
}

// ── 4. sandbox_stripe_test_key_passthrough ───────────────────────────────────

#[test]
fn sandbox_stripe_test_key_passthrough() {
    let sk_test = "sk_test_abc123xyz456def789ghi012jkl345";
    let result = sandbox_value("STRIPE_SECRET_KEY", sk_test, &SecretType::StripeKey, PROJ);
    assert_eq!(result, sk_test, "sk_test_ must pass through unchanged");

    let pk_test = "pk_test_abc123xyz456def789ghi012jkl345";
    let result_pk = sandbox_value("STRIPE_PK", pk_test, &SecretType::StripeKey, PROJ);
    assert_eq!(result_pk, pk_test, "pk_test_ must pass through unchanged");

    println!("stripe test passthrough OK");
}

// ── 5. sandbox_aws_keys ───────────────────────────────────────────────────────

#[test]
fn sandbox_aws_keys() {
    let access = sandbox_value(
        "AWS_ACCESS_KEY_ID",
        "AKIAREALKEY1234567890",
        &SecretType::AwsAccessKey,
        PROJ,
    );
    assert_eq!(access, "AKIAIOSFODNN7EXAMPLE");

    let secret = sandbox_value(
        "AWS_SECRET_ACCESS_KEY",
        "realSecretKeyHere",
        &SecretType::AwsSecretKey,
        PROJ,
    );
    assert_eq!(secret, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");

    println!("aws sandbox access: {}", access);
    println!("aws sandbox secret: {}", secret);
}

// ── 6. sandbox_jwt_secret ────────────────────────────────────────────────────

#[test]
fn sandbox_jwt_secret() {
    let result = sandbox_value(
        "JWT_SECRET",
        "my-super-secret-jwt-signing-key-very-long",
        &SecretType::JwtSecret,
        PROJ,
    );
    assert_eq!(result, "cloak-dev-jwt-secret-not-real-000000");
    println!("jwt sandbox: {}", result);
}

// ── 7. sandbox_api_key ───────────────────────────────────────────────────────

#[test]
fn sandbox_api_key() {
    // Generic API key (non sk- prefix)
    let result = sandbox_value(
        "SOME_API_KEY",
        "some-random-api-key-value-1234567890",
        &SecretType::ApiKey,
        PROJ,
    );
    assert!(
        result.starts_with("cloak_sandbox_api_key_"),
        "expected cloak_sandbox_api_key_ prefix, got: {}",
        result
    );

    // sk- prefixed API key
    let sk_result = sandbox_value(
        "OPENAI_API_KEY",
        "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234y",
        &SecretType::ApiKey,
        PROJ,
    );
    assert!(
        sk_result.starts_with("sk-cloak-sandbox-key-"),
        "expected sk-cloak-sandbox-key- prefix, got: {}",
        sk_result
    );

    println!("api key sandbox: {}", result);
    println!("openai api key sandbox: {}", sk_result);
}

// ── 8. sandbox_token_github ──────────────────────────────────────────────────

#[test]
fn sandbox_token_github() {
    let result = sandbox_value(
        "GITHUB_TOKEN",
        "ghp_FAKE0000000000000000000000000000000000",
        &SecretType::Token,
        PROJ,
    );
    assert!(
        result.starts_with("ghp_cloaksandbox"),
        "expected ghp_cloaksandbox prefix, got: {}",
        result
    );
    println!("github token sandbox: {}", result);

    // Slack token
    let slack = sandbox_value(
        "SLACK_BOT_TOKEN",
        "xoxb-0000-0000-FAKEefghijklmnop",
        &SecretType::Token,
        PROJ,
    );
    assert_eq!(slack, "xoxb-0000-0000-cloaksandboxtoken");

    // JWT token
    let jwt = sandbox_value(
        "ACCESS_TOKEN",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
        &SecretType::Token,
        PROJ,
    );
    assert_eq!(jwt, "eyJjbG9hayI6InNhbmRib3gifQ==");
}

// ── 9. sandbox_deterministic ─────────────────────────────────────────────────

#[test]
fn sandbox_deterministic() {
    let key = "MY_SECRET_KEY";
    let value = "some-high-entropy-secret-value-xyz";
    let secret_type = SecretType::Unknown;

    // Same inputs → same output (called twice)
    let r1 = sandbox_value(key, value, &secret_type, "hash_abc");
    let r2 = sandbox_value(key, value, &secret_type, "hash_abc");
    assert_eq!(r1, r2, "same inputs must produce same output");

    // Different project hash → different output
    let r3 = sandbox_value(key, value, &secret_type, "hash_xyz");
    assert_ne!(
        r1, r3,
        "different project hash must produce different output"
    );

    // deterministic_hex helper itself is deterministic
    let h1 = deterministic_hex("proj", "key", 32);
    let h2 = deterministic_hex("proj", "key", 32);
    assert_eq!(h1, h2);

    // deterministic_hex differs by project_hash
    let h3 = deterministic_hex("other", "key", 32);
    assert_ne!(h1, h3);

    println!("deterministic test passed: {} vs {}", r1, r3);
}

// ── 10. sandbox_env_preserves_structure ──────────────────────────────────────

#[test]
fn sandbox_env_preserves_structure() {
    let content = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/realistic.env"),
    )
    .expect("failed to read realistic.env");

    let result = sandbox_env(&content, PROJ);

    println!("=== sandbox_env output ===");
    println!("{}", result);
    println!("==========================");

    // Comments must be preserved
    assert!(
        result.contains("# Application configuration"),
        "comment '# Application configuration' must be preserved"
    );
    assert!(
        result.contains("# Database"),
        "comment '# Database' must be preserved"
    );
    assert!(
        result.contains("# Stripe"),
        "comment '# Stripe' must be preserved"
    );

    // Non-secrets must be unchanged
    assert!(
        result.contains("NODE_ENV=development"),
        "NODE_ENV=development must be unchanged"
    );
    assert!(result.contains("PORT=3000"), "PORT=3000 must be unchanged");
    assert!(
        result.contains("HOST=localhost"),
        "HOST=localhost must be unchanged"
    );
    assert!(
        result.contains("APP_NAME=MyApplication"),
        "APP_NAME=MyApplication must be unchanged"
    );
    assert!(
        result.contains("LOG_LEVEL=info"),
        "LOG_LEVEL=info must be unchanged"
    );
    assert!(
        result.contains("DEBUG=false"),
        "DEBUG=false must be unchanged"
    );

    // Real secrets must be replaced — original values must not appear
    assert!(
        !result.contains("postgres://user:secret@db.example.com"),
        "real postgres URL must not appear in output"
    );
    assert!(
        !result.contains("sk_live_abc123"),
        "real Stripe live key must not appear in output"
    );
    assert!(
        !result.contains("AKIAREALKEY"),
        // The test file uses AKIAIOSFODNN7EXAMPLE which is already the sandbox value
        "real AWS key must not appear"
    );

    // Sandbox replacements must be present
    assert!(
        result.contains("postgres://dev:dev@localhost:5432/devdb"),
        "postgres sandbox value must appear"
    );
    assert!(
        result.contains("sk_test_cloak_sandbox_000000000000"),
        "stripe sandbox value must appear"
    );

    // sk_test_ must pass through unchanged
    assert!(
        result.contains("STRIPE_TEST_KEY=sk_test_abc123xyz456def789ghi012jkl345"),
        "sk_test_ key must pass through unchanged"
    );

    // Structure: result should have roughly same number of lines
    let original_lines = content.lines().count();
    let result_lines = result.lines().count();
    assert_eq!(
        original_lines, result_lines,
        "line count must be preserved: original={}, result={}",
        original_lines, result_lines
    );
}
