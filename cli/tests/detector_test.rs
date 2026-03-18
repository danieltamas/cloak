//! Integration tests for `cli/src/detector.rs`.
//!
//! Run with: `cd cli && cargo test --test detector_test -- --nocapture`

use cloak::detector::{detect, SecretType};

// ──────────────────────────────────────────────────────────────────────────────
// 1. detect_database_url
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn detect_database_url() {
    let result = detect(
        "DATABASE_URL",
        "postgres://admin:s3cret@db.example.com:5432/myapp",
    );
    assert!(result.is_secret, "DATABASE_URL should be a secret");
    assert_eq!(result.secret_type, Some(SecretType::DatabaseUrl));
}

// ──────────────────────────────────────────────────────────────────────────────
// 2. detect_stripe_key
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn detect_stripe_key() {
    let result = detect("STRIPE_SECRET_KEY", "sk_test_FAKE4eC39HqLyjWDarjtT1zd");
    assert!(result.is_secret, "STRIPE_SECRET_KEY should be a secret");
    assert_eq!(result.secret_type, Some(SecretType::StripeKey));
}

// ──────────────────────────────────────────────────────────────────────────────
// 3. detect_aws_access_key
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn detect_aws_access_key() {
    let result = detect("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE");
    assert!(result.is_secret, "AWS_ACCESS_KEY_ID should be a secret");
    assert_eq!(result.secret_type, Some(SecretType::AwsAccessKey));
}

// ──────────────────────────────────────────────────────────────────────────────
// 4. detect_aws_secret_key
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn detect_aws_secret_key() {
    let result = detect(
        "AWS_SECRET_ACCESS_KEY",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    );
    assert!(result.is_secret, "AWS_SECRET_ACCESS_KEY should be a secret");
    assert_eq!(result.secret_type, Some(SecretType::AwsSecretKey));
}

// ──────────────────────────────────────────────────────────────────────────────
// 5. detect_jwt_secret
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn detect_jwt_secret() {
    let result = detect("JWT_SECRET", "my-super-secret-jwt-key-that-should-not-leak");
    assert!(result.is_secret, "JWT_SECRET should be a secret");
    assert_eq!(result.secret_type, Some(SecretType::JwtSecret));
}

// ──────────────────────────────────────────────────────────────────────────────
// 6. detect_api_key
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn detect_api_key() {
    let result = detect(
        "SENDGRID_API_KEY",
        "SG.xxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
    assert!(result.is_secret, "SENDGRID_API_KEY should be a secret");
    assert_eq!(result.secret_type, Some(SecretType::ApiKey));
}

// ──────────────────────────────────────────────────────────────────────────────
// 7. detect_private_key
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn detect_private_key() {
    let result = detect("PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----MIIE...");
    assert!(result.is_secret, "PRIVATE_KEY should be a secret");
    assert_eq!(result.secret_type, Some(SecretType::PrivateKey));
}

// ──────────────────────────────────────────────────────────────────────────────
// 8. detect_password
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn detect_password() {
    let result = detect("DB_PASSWORD", "s3cret_p4ssw0rd!");
    assert!(result.is_secret, "DB_PASSWORD should be a secret");
    assert_eq!(result.secret_type, Some(SecretType::Password));
}

// ──────────────────────────────────────────────────────────────────────────────
// 9. detect_token_by_key
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn detect_token_by_key() {
    // SESSION_TOKEN: key contains TOKEN, not in exclusion list
    let r1 = detect("SESSION_TOKEN", "abc123_not_a_known_prefix_but_key_matches");
    assert!(r1.is_secret, "SESSION_TOKEN should be a secret");
    assert_eq!(r1.secret_type, Some(SecretType::Token));

    // SLACK_BOT_TOKEN: key contains TOKEN
    let r2 = detect(
        "SLACK_BOT_TOKEN",
        "xoxb-0000000000-0000000000000-FAKE00000000000000000000",
    );
    assert!(r2.is_secret, "SLACK_BOT_TOKEN should be a secret");
    assert_eq!(r2.secret_type, Some(SecretType::Token));
}

// ──────────────────────────────────────────────────────────────────────────────
// 10. detect_non_secret
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn detect_non_secret() {
    let cases = vec![
        ("NODE_ENV", "production"),
        ("PORT", "3000"),
        ("HOST", "0.0.0.0"),
        ("DEBUG", "false"),
        ("API_BASE_URL", "https://api.example.com/v1"),
        ("FRONTEND_URL", "http://localhost:5173"),
    ];

    for (key, value) in cases {
        let result = detect(key, value);
        assert!(
            !result.is_secret,
            "Expected {} = {} to NOT be a secret, but it was detected as {:?}",
            key, value, result.secret_type
        );
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 11. detect_by_value_pattern
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn detect_by_value_pattern() {
    // sk_live_ → StripeKey
    let r1 = detect("PAYMENT_KEY", "sk_test_FAKE4eC39HqLyjWDarjtT1zd");
    assert!(r1.is_secret);
    assert_eq!(r1.secret_type, Some(SecretType::StripeKey));

    // ghp_ → Token
    let r2 = detect("MY_VAR", "ghp_FAKE0000000000000000000000000000000000");
    assert!(r2.is_secret);
    assert_eq!(r2.secret_type, Some(SecretType::Token));

    // AKIA + 16 uppercase alphanumeric → AwsAccessKey
    let r3 = detect("SOME_ID", "AKIAIOSFODNN7EXAMPLE");
    assert!(r3.is_secret);
    assert_eq!(r3.secret_type, Some(SecretType::AwsAccessKey));

    // eyJ → Token (JWT-like)
    let r4 = detect(
        "MY_TOKEN",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc",
    );
    assert!(r4.is_secret);
    assert_eq!(r4.secret_type, Some(SecretType::Token));

    // xoxb- → Token (Slack)
    let r5 = detect(
        "BOT_CREDENTIAL",
        "xoxb-0000000000-0000000000000-FAKE00000000000000000000",
    );
    assert!(r5.is_secret);
    assert_eq!(r5.secret_type, Some(SecretType::Token));
}

// ──────────────────────────────────────────────────────────────────────────────
// 12. detect_high_entropy_unknown
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn detect_high_entropy_unknown() {
    // Base64-like value with mixed case and special chars — high entropy (>4.5 bits),
    // length > 20, no known value prefix, and no specific key pattern.
    // This simulates a random secret that doesn't fit any known format.
    let result = detect("MY_CONFIG_VALUE", "aB3Xq7Zp9Km2Yw5Nv8Rj4Ts6Uh1Wf0");
    assert!(
        result.is_secret,
        "High-entropy value should be detected as a secret"
    );
    assert_eq!(result.secret_type, Some(SecretType::Unknown));
}

// ──────────────────────────────────────────────────────────────────────────────
// 13. detect_realistic_env
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn detect_realistic_env() {
    // Parse the realistic.env test fixture without depending on the envparser module.
    let env_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/realistic.env");
    let content = std::fs::read_to_string(env_path).expect("testdata/realistic.env should exist");

    let mut pairs: Vec<(String, String)> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        // Skip comments and blank lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().to_string();
            let value = trimmed[eq_pos + 1..].trim().to_string();
            pairs.push((key, value));
        }
    }

    // Expected secrets (11)
    let expected_secrets = vec![
        "DATABASE_URL",
        "STRIPE_SECRET_KEY",
        "STRIPE_PUBLISHABLE_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "JWT_SECRET",
        "SESSION_SECRET",
        "REDIS_URL",
        "SENDGRID_API_KEY",
        "GITHUB_TOKEN",
        "SLACK_BOT_TOKEN",
    ];

    // Expected non-secrets (6)
    let expected_non_secrets = vec![
        "NODE_ENV",
        "PORT",
        "HOST",
        "DEBUG",
        "API_BASE_URL",
        "FRONTEND_URL",
    ];

    println!("Parsed {} key-value pairs from realistic.env", pairs.len());

    for (key, value) in &pairs {
        let result = detect(key, value);
        println!(
            "  {} = {} ... is_secret={} type={:?}",
            key, value, result.is_secret, result.secret_type
        );

        if expected_secrets.contains(&key.as_str()) {
            assert!(
                result.is_secret,
                "Expected {} to be detected as a secret (value: {})",
                key, value
            );
        } else if expected_non_secrets.contains(&key.as_str()) {
            assert!(
                !result.is_secret,
                "Expected {} to NOT be detected as a secret (value: {}), but got type={:?}",
                key, value, result.secret_type
            );
        }
    }

    // Verify all expected keys were actually present in the file
    let present_keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
    for key in &expected_secrets {
        assert!(
            present_keys.contains(key),
            "Expected key {} was not found in realistic.env",
            key
        );
    }
    for key in &expected_non_secrets {
        assert!(
            present_keys.contains(key),
            "Expected key {} was not found in realistic.env",
            key
        );
    }
}
