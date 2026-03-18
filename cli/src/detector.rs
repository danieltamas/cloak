//! Secret detection module for Cloak.
//!
//! Detects whether an environment variable key-value pair contains a secret,
//! using key-name patterns, value patterns, and Shannon entropy analysis.

/// Classifies what type of secret was detected.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum SecretType {
    /// Database connection URL (postgres, mysql, mongodb, redis, etc.)
    DatabaseUrl,
    /// Stripe API key or secret
    StripeKey,
    /// AWS access key ID
    AwsAccessKey,
    /// AWS secret access key
    AwsSecretKey,
    /// JWT secret or signing key
    JwtSecret,
    /// Generic API key
    ApiKey,
    /// Private key (PEM, SSH, etc.)
    PrivateKey,
    /// Password or passphrase
    Password,
    /// Generic token or secret
    Token,
    /// Generic URL with credentials
    GenericUrl,
    /// High-entropy value with no specific pattern match
    Unknown,
}

/// The result of running the detector on a key-value pair.
pub struct DetectionResult {
    /// Whether the value is classified as a secret.
    pub is_secret: bool,
    /// The type of secret detected, if any.
    pub secret_type: Option<SecretType>,
}

impl DetectionResult {
    fn not_secret() -> Self {
        DetectionResult {
            is_secret: false,
            secret_type: None,
        }
    }

    fn secret(t: SecretType) -> Self {
        DetectionResult {
            is_secret: true,
            secret_type: Some(t),
        }
    }
}

/// List of exact key names that are never secrets.
const EXCLUDED_KEYS: &[&str] = &[
    "NODE_ENV",
    "PORT",
    "HOST",
    "DEBUG",
    "LOG_LEVEL",
    "TZ",
    "LANG",
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "EDITOR",
    "TERM",
];

/// Prefixes (uppercased) that mark a key as non-secret.
/// Note: GITHUB_* is handled specially — excluded only if the value also has no secret pattern.
const EXCLUDED_PREFIXES: &[&str] = &["NPM_", "CI", "VERCEL_", "NEXT_PUBLIC_"];

/// Values (lowercased) that are never secrets.
const EXCLUDED_VALUES: &[&str] = &["true", "false", "yes", "no", "on", "off", "null", "none"];

/// Returns `true` if the value is a trivially non-secret value (boolean, integer, localhost, plain
/// URL without credentials).
fn is_trivial_value(value: &str) -> bool {
    let lower = value.to_lowercase();

    // Boolean-like literals
    if EXCLUDED_VALUES.contains(&lower.as_str()) {
        return true;
    }

    // Plain integer
    if value.chars().all(|c| c.is_ascii_digit()) && !value.is_empty() {
        return true;
    }

    // Localhost addresses
    if lower == "localhost" || lower == "127.0.0.1" {
        return true;
    }

    // Plain URL without credentials (no `@` in authority part)
    if is_plain_url(value) {
        return true;
    }

    false
}

/// Returns `true` if the value is a URL without credentials embedded (no `@` in the userinfo
/// position).
fn is_plain_url(value: &str) -> bool {
    // Must contain a scheme (e.g. https://)
    if let Some(after_scheme) = value.find("://") {
        let authority = &value[after_scheme + 3..];
        // If there's an `@` in the authority section (before the first `/`), it has credentials.
        let authority_end = authority.find('/').unwrap_or(authority.len());
        let authority_part = &authority[..authority_end];
        return !authority_part.contains('@');
    }
    false
}

/// Returns `true` if the key (uppercased) is in the exclusion list by exact match or prefix.
/// GITHUB_* is NOT treated as excluded here — it is handled separately so that value patterns
/// can still override it.
fn is_excluded_key(upper_key: &str) -> bool {
    if EXCLUDED_KEYS.contains(&upper_key) {
        return true;
    }
    for prefix in EXCLUDED_PREFIXES {
        if upper_key.starts_with(prefix) {
            return true;
        }
    }
    false
}

/// Returns `true` if the key starts with `GITHUB_` (uppercased).
fn is_github_prefix(upper_key: &str) -> bool {
    upper_key.starts_with("GITHUB_")
}

/// Attempts to classify the secret type from the key name alone.
/// Returns `None` if the key doesn't match any known pattern.
fn detect_by_key(upper_key: &str) -> Option<SecretType> {
    // DatabaseUrl — check these substrings first (most specific)
    let db_substrings = [
        "DATABASE_URL",
        "DB_URL",
        "DB_URI",
        "DB_CONNECTION",
        "MONGO_URI",
        "MYSQL_URL",
        "POSTGRES_URL",
        "REDIS_URL",
        "REDIS_URI",
    ];
    for sub in &db_substrings {
        if upper_key.contains(sub) {
            return Some(SecretType::DatabaseUrl);
        }
    }

    // AwsAccessKey
    if upper_key.starts_with("AWS_ACCESS_KEY") {
        return Some(SecretType::AwsAccessKey);
    }

    // AwsSecretKey
    if upper_key.starts_with("AWS_SECRET") {
        return Some(SecretType::AwsSecretKey);
    }

    // StripeKey — must contain STRIPE and (KEY or SECRET or TOKEN)
    if upper_key.contains("STRIPE")
        && (upper_key.contains("KEY")
            || upper_key.contains("SECRET")
            || upper_key.contains("TOKEN"))
    {
        return Some(SecretType::StripeKey);
    }

    // JwtSecret — must contain JWT and (SECRET or KEY or PRIVATE)
    if upper_key.contains("JWT")
        && (upper_key.contains("SECRET")
            || upper_key.contains("KEY")
            || upper_key.contains("PRIVATE"))
    {
        return Some(SecretType::JwtSecret);
    }

    // ApiKey — API + KEY, APIKEY, or API + SECRET
    if (upper_key.contains("API") && upper_key.contains("KEY"))
        || upper_key.contains("APIKEY")
        || (upper_key.contains("API") && upper_key.contains("SECRET"))
    {
        return Some(SecretType::ApiKey);
    }

    // PrivateKey — PRIVATE + KEY but NOT PUBLIC + KEY
    if upper_key.contains("PRIVATE") && upper_key.contains("KEY") {
        return Some(SecretType::PrivateKey);
    }

    // Password
    if upper_key.contains("PASSWORD")
        || upper_key.contains("PASSWD")
        || upper_key.ends_with("_PW")
        || upper_key.ends_with("_PWD")
        || upper_key.ends_with("_PASS")
    {
        return Some(SecretType::Password);
    }

    // Token / generic secret / _KEY (but not PUBLIC_KEY)
    if upper_key.contains("TOKEN")
        || upper_key.contains("SECRET")
        || (upper_key.ends_with("_KEY") && !upper_key.contains("PUBLIC_KEY"))
    {
        return Some(SecretType::Token);
    }

    None
}

/// Attempts to classify the secret type from the value alone.
/// Returns `None` if the value doesn't match any known pattern.
fn detect_by_value(value: &str) -> Option<SecretType> {
    // Database URL schemes with credentials (@)
    for scheme in &["postgres://", "mysql://", "mongodb://", "redis://"] {
        if value.starts_with(scheme) && value.contains('@') {
            return Some(SecretType::DatabaseUrl);
        }
    }

    // Stripe live keys
    if value.starts_with("sk_live_")
        || value.starts_with("pk_live_")
        || value.starts_with("rk_live_")
    {
        return Some(SecretType::StripeKey);
    }

    // AWS Access Key ID pattern: AKIA followed by exactly 16 uppercase alphanumeric chars
    if is_aws_access_key(value) {
        return Some(SecretType::AwsAccessKey);
    }

    // GitHub tokens
    if value.starts_with("ghp_")
        || value.starts_with("gho_")
        || value.starts_with("ghs_")
        || value.starts_with("ghr_")
        || value.starts_with("github_pat_")
    {
        return Some(SecretType::Token);
    }

    // Slack tokens
    if value.starts_with("xoxb-")
        || value.starts_with("xoxp-")
        || value.starts_with("xoxs-")
        || value.starts_with("xoxa-")
    {
        return Some(SecretType::Token);
    }

    // OpenAI-style API key
    if value.starts_with("sk-") && value.len() >= 40 {
        return Some(SecretType::ApiKey);
    }

    // JWT (base64url encoded JSON starting with `eyJ`)
    if value.starts_with("eyJ") {
        return Some(SecretType::Token);
    }

    // High entropy catch-all (not a bare URL)
    if value.len() > 20 && !is_plain_url(value) && shannon_entropy(value) > 4.5 {
        return Some(SecretType::Unknown);
    }

    None
}

/// Returns `true` if the value matches the AWS Access Key ID format: `AKIA` followed by exactly
/// 16 uppercase alphanumeric characters (total 20 chars).
fn is_aws_access_key(value: &str) -> bool {
    if !value.starts_with("AKIA") {
        return false;
    }
    let rest = &value[4..];
    rest.len() == 16
        && rest
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// Computes the Shannon entropy of a string.
///
/// H(X) = -Σ p(x) * log2(p(x)) where p(x) is the frequency of each unique character divided
/// by the total length of the string.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut freq = [0usize; 256];
    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Detects whether the given environment variable key-value pair contains a secret.
///
/// Detection order:
/// 1. Value patterns are checked first for known prefixes (e.g. `ghp_`, `sk_live_`).
/// 2. Key name patterns are checked.
/// 3. If the key is in the exclusion list, return not-secret (unless value matched in step 1).
/// 4. Remaining value patterns and entropy are checked.
pub fn detect(key: &str, value: &str) -> DetectionResult {
    let upper_key = key.to_uppercase();

    // Skip trivial values early — these are never secrets regardless of key name.
    if is_trivial_value(value) {
        return DetectionResult::not_secret();
    }

    // Step 1: Check value patterns that override everything, including exclusions.
    // This ensures GITHUB_TOKEN with a ghp_ value is caught even though GITHUB_* is excluded.
    if let Some(t) = detect_by_value_override(value) {
        return DetectionResult::secret(t);
    }

    // Step 2: Check key name patterns.
    if let Some(t) = detect_by_key(&upper_key) {
        return DetectionResult::secret(t);
    }

    // Step 3: Check exclusion lists (after key patterns so specific keys still fire).
    if is_excluded_key(&upper_key) || is_github_prefix(&upper_key) {
        return DetectionResult::not_secret();
    }

    // Step 4: Check remaining value patterns and entropy.
    if let Some(t) = detect_by_value(value) {
        return DetectionResult::secret(t);
    }

    DetectionResult::not_secret()
}

/// Checks value patterns that should override the exclusion list.
/// These are patterns that are unambiguously secret regardless of key name.
fn detect_by_value_override(value: &str) -> Option<SecretType> {
    // Database URL schemes with credentials (@)
    for scheme in &["postgres://", "mysql://", "mongodb://", "redis://"] {
        if value.starts_with(scheme) && value.contains('@') {
            return Some(SecretType::DatabaseUrl);
        }
    }

    // Stripe live keys
    if value.starts_with("sk_live_")
        || value.starts_with("pk_live_")
        || value.starts_with("rk_live_")
    {
        return Some(SecretType::StripeKey);
    }

    // AWS Access Key ID pattern
    if is_aws_access_key(value) {
        return Some(SecretType::AwsAccessKey);
    }

    // GitHub tokens
    if value.starts_with("ghp_")
        || value.starts_with("gho_")
        || value.starts_with("ghs_")
        || value.starts_with("ghr_")
        || value.starts_with("github_pat_")
    {
        return Some(SecretType::Token);
    }

    // Slack tokens
    if value.starts_with("xoxb-")
        || value.starts_with("xoxp-")
        || value.starts_with("xoxs-")
        || value.starts_with("xoxa-")
    {
        return Some(SecretType::Token);
    }

    // JWT
    if value.starts_with("eyJ") {
        return Some(SecretType::Token);
    }

    // OpenAI-style API key
    if value.starts_with("sk-") && value.len() >= 40 {
        return Some(SecretType::ApiKey);
    }

    None
}
