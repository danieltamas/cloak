//! Sandbox value generation for Cloak.
//!
//! Generates fake but structurally valid replacement values for detected secrets.
//! Sandbox values are deterministic: the same (key, value, SecretType, project_hash)
//! inputs always produce the same output. This allows `.env` files on disk to contain
//! consistent fake credentials that look plausible but are never real.

use sha2::{Digest, Sha256};

use crate::detector::{self, SecretType};
use crate::envparser::{self, EnvLine, QuoteStyle};

/// Generate a deterministic hex string from `SHA-256("cloak-sandbox:<project_hash>:<key>")`,
/// truncated to `length` hex characters (each hex char = 4 bits).
///
/// Always returns at most 64 characters (the full SHA-256 hex output).
pub fn deterministic_hex(project_hash: &str, key: &str, length: usize) -> String {
    let input = format!("cloak-sandbox:{}:{}", project_hash, key);
    let hash = Sha256::digest(input.as_bytes());
    let hex = hex::encode(hash);
    hex[..length.min(hex.len())].to_string()
}

/// Generate a sandbox (fake) value for a detected secret.
///
/// The returned value is structurally valid for the given `secret_type` but
/// contains no real credentials. Stripe test keys (`sk_test_*`, `pk_test_*`)
/// are passed through unchanged so that test environments continue to work.
pub fn sandbox_value(
    key: &str,
    value: &str,
    secret_type: &SecretType,
    project_hash: &str,
) -> String {
    match secret_type {
        SecretType::DatabaseUrl => {
            if value.starts_with("postgres://") {
                "postgres://dev:dev@localhost:5432/devdb".to_string()
            } else if value.starts_with("mysql://") {
                "mysql://dev:dev@localhost:3306/devdb".to_string()
            } else if value.starts_with("mongodb://") {
                "mongodb://localhost:27017/devdb".to_string()
            } else if value.starts_with("redis://") {
                "redis://localhost:6379".to_string()
            } else {
                "postgres://dev:dev@localhost:5432/devdb".to_string()
            }
        }

        SecretType::StripeKey => {
            // Test keys pass through unchanged.
            if value.starts_with("sk_test_") || value.starts_with("pk_test_") {
                return value.to_string();
            }
            if value.starts_with("sk_live_") || value.starts_with("sk_") {
                "sk_test_cloak_sandbox_000000000000".to_string()
            } else if value.starts_with("pk_live_") || value.starts_with("pk_") {
                "pk_test_cloak_sandbox_000000000000".to_string()
            } else {
                format!(
                    "sk_test_cloak_sandbox_{}",
                    deterministic_hex(project_hash, key, 12)
                )
            }
        }

        SecretType::AwsAccessKey => "AKIAIOSFODNN7EXAMPLE".to_string(),

        SecretType::AwsSecretKey => "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),

        SecretType::JwtSecret => "cloak-dev-jwt-secret-not-real-000000".to_string(),

        SecretType::ApiKey => {
            if value.starts_with("sk-") {
                format!(
                    "sk-cloak-sandbox-key-{}",
                    deterministic_hex(project_hash, key, 20)
                )
            } else {
                format!(
                    "cloak_sandbox_api_key_{}",
                    deterministic_hex(project_hash, key, 20)
                )
            }
        }

        SecretType::PrivateKey => "cloak-sandbox-private-key-not-real".to_string(),

        SecretType::Password => "cloak_sandbox_password".to_string(),

        SecretType::Token => {
            if value.starts_with("ghp_") {
                format!(
                    "ghp_cloaksandbox{}",
                    deterministic_hex(project_hash, key, 20)
                )
            } else if value.starts_with("xoxb-") {
                "xoxb-0000-0000-cloaksandboxtoken".to_string()
            } else if value.starts_with("eyJ") {
                "eyJjbG9hayI6InNhbmRib3gifQ==".to_string()
            } else {
                format!(
                    "cloak_sandbox_token_{}",
                    deterministic_hex(project_hash, key, 20)
                )
            }
        }

        SecretType::GenericUrl => replace_url_credentials(value),

        SecretType::Unknown => {
            format!("cloak_sandbox_{}", deterministic_hex(project_hash, key, 20))
        }
    }
}

/// Replace credentials in a URL with `dev:dev@<host>`, preserving scheme,
/// host, port, path, query, and fragment.
///
/// If the value does not contain `://`, returns the value unchanged.
fn replace_url_credentials(value: &str) -> String {
    // Find scheme separator "://"
    let scheme_end = match value.find("://") {
        Some(pos) => pos,
        None => return value.to_string(),
    };
    let scheme = &value[..scheme_end];
    let after_scheme = &value[scheme_end + 3..];

    // Split authority from path (first '/')
    let (authority, path_and_rest) = match after_scheme.find('/') {
        Some(pos) => (&after_scheme[..pos], &after_scheme[pos..]),
        None => (after_scheme, ""),
    };

    // Strip any existing userinfo (everything up to and including the last '@')
    let host_port = match authority.rfind('@') {
        Some(at_pos) => &authority[at_pos + 1..],
        None => authority,
    };

    format!("{}://dev:dev@{}{}", scheme, host_port, path_and_rest)
}

/// Process a full `.env` file content: parse lines, detect secrets, replace
/// detected secret values with their sandbox equivalents, and serialize back.
///
/// Preserves all comments, blank lines, ordering, quote style, and `export`
/// prefix. Non-secret assignments are left completely unchanged (including
/// their original `raw_line`).
pub fn sandbox_env(content: &str, project_hash: &str) -> String {
    let mut lines = envparser::parse(content);

    for line in &mut lines {
        if let EnvLine::Assignment {
            export,
            key,
            value,
            quote_style,
            raw_line,
        } = line
        {
            let detection = detector::detect(key, value);
            if detection.is_secret {
                if let Some(secret_type) = &detection.secret_type {
                    let new_value = sandbox_value(key, value, secret_type, project_hash);
                    let export_prefix = if *export { "export " } else { "" };
                    let new_raw = match quote_style {
                        QuoteStyle::Double => {
                            format!("{}{}=\"{}\"", export_prefix, key, new_value)
                        }
                        QuoteStyle::Single => {
                            format!("{}{}='{}'", export_prefix, key, new_value)
                        }
                        QuoteStyle::None => {
                            format!("{}{}={}", export_prefix, key, new_value)
                        }
                    };
                    *value = new_value;
                    *raw_line = new_raw;
                }
            }
        }
    }

    envparser::serialize(&lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_hex_length() {
        let h = deterministic_hex("proj123", "MY_KEY", 20);
        assert_eq!(h.len(), 20);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn deterministic_hex_is_deterministic() {
        let h1 = deterministic_hex("proj", "key", 16);
        let h2 = deterministic_hex("proj", "key", 16);
        assert_eq!(h1, h2);
    }

    #[test]
    fn deterministic_hex_differs_by_hash() {
        let h1 = deterministic_hex("hash_a", "key", 16);
        let h2 = deterministic_hex("hash_b", "key", 16);
        assert_ne!(h1, h2);
    }
}
