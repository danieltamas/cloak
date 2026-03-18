/**
 * Secret detection module for Cloak.
 *
 * Detects whether an environment variable key-value pair contains a secret,
 * using key-name patterns, value patterns, and Shannon entropy analysis.
 */

/** Classifies what type of secret was detected. */
export type SecretType =
    | 'DatabaseUrl'
    | 'StripeKey'
    | 'AwsAccessKey'
    | 'AwsSecretKey'
    | 'JwtSecret'
    | 'ApiKey'
    | 'PrivateKey'
    | 'Password'
    | 'Token'
    | 'GenericUrl'
    | 'Unknown';

/** The result of running the detector on a key-value pair. */
export interface DetectionResult {
    /** Whether the value is classified as a secret. */
    isSecret: boolean;
    /** The type of secret detected, if any. */
    secretType: SecretType | null;
}

/** List of exact key names that are never secrets. */
const EXCLUDED_KEYS: string[] = [
    'NODE_ENV',
    'PORT',
    'HOST',
    'DEBUG',
    'LOG_LEVEL',
    'TZ',
    'LANG',
    'PATH',
    'HOME',
    'USER',
    'SHELL',
    'EDITOR',
    'TERM',
];

/** Prefixes (uppercased) that mark a key as non-secret.
 * Note: GITHUB_* is handled specially — excluded only if the value also has no secret pattern. */
const EXCLUDED_PREFIXES: string[] = ['NPM_', 'CI', 'VERCEL_', 'NEXT_PUBLIC_'];

/** Values (lowercased) that are never secrets. */
const EXCLUDED_VALUES: string[] = ['true', 'false', 'yes', 'no', 'on', 'off', 'null', 'none'];

/** Returns true if the value is a trivially non-secret value (boolean, integer, localhost, plain URL without credentials). */
function isTrivialValue(value: string): boolean {
    const lower = value.toLowerCase();

    // Boolean-like literals
    if (EXCLUDED_VALUES.includes(lower)) {
        return true;
    }

    // Plain integer
    if (value.length > 0 && /^\d+$/.test(value)) {
        return true;
    }

    // Localhost addresses
    if (lower === 'localhost' || lower === '127.0.0.1') {
        return true;
    }

    // Plain URL without credentials (no `@` in authority part)
    if (isPlainUrl(value)) {
        return true;
    }

    return false;
}

/** Returns true if the value is a URL without credentials embedded (no `@` in the userinfo position). */
function isPlainUrl(value: string): boolean {
    const schemeEnd = value.indexOf('://');
    if (schemeEnd !== -1) {
        const authority = value.slice(schemeEnd + 3);
        const authorityEnd = authority.indexOf('/');
        const authorityPart = authorityEnd === -1 ? authority : authority.slice(0, authorityEnd);
        return !authorityPart.includes('@');
    }
    return false;
}

/** Returns true if the key (uppercased) is in the exclusion list by exact match or prefix.
 * GITHUB_* is NOT treated as excluded here — it is handled separately so that value patterns
 * can still override it. */
function isExcludedKey(upperKey: string): boolean {
    if (EXCLUDED_KEYS.includes(upperKey)) {
        return true;
    }
    for (const prefix of EXCLUDED_PREFIXES) {
        if (upperKey.startsWith(prefix)) {
            return true;
        }
    }
    return false;
}

/** Returns true if the key starts with `GITHUB_` (uppercased). */
function isGithubPrefix(upperKey: string): boolean {
    return upperKey.startsWith('GITHUB_');
}

/** Attempts to classify the secret type from the key name alone.
 * Returns null if the key doesn't match any known pattern. */
function detectByKey(upperKey: string): SecretType | null {
    // DatabaseUrl — check these substrings first (most specific)
    const dbSubstrings = [
        'DATABASE_URL',
        'DB_URL',
        'DB_URI',
        'DB_CONNECTION',
        'MONGO_URI',
        'MYSQL_URL',
        'POSTGRES_URL',
        'REDIS_URL',
        'REDIS_URI',
    ];
    for (const sub of dbSubstrings) {
        if (upperKey.includes(sub)) {
            return 'DatabaseUrl';
        }
    }

    // AwsAccessKey
    if (upperKey.startsWith('AWS_ACCESS_KEY')) {
        return 'AwsAccessKey';
    }

    // AwsSecretKey
    if (upperKey.startsWith('AWS_SECRET')) {
        return 'AwsSecretKey';
    }

    // StripeKey — must contain STRIPE and (KEY or SECRET or TOKEN)
    if (
        upperKey.includes('STRIPE') &&
        (upperKey.includes('KEY') || upperKey.includes('SECRET') || upperKey.includes('TOKEN'))
    ) {
        return 'StripeKey';
    }

    // JwtSecret — must contain JWT and (SECRET or KEY or PRIVATE)
    if (
        upperKey.includes('JWT') &&
        (upperKey.includes('SECRET') || upperKey.includes('KEY') || upperKey.includes('PRIVATE'))
    ) {
        return 'JwtSecret';
    }

    // ApiKey — API + KEY, APIKEY, or API + SECRET
    if (
        (upperKey.includes('API') && upperKey.includes('KEY')) ||
        upperKey.includes('APIKEY') ||
        (upperKey.includes('API') && upperKey.includes('SECRET'))
    ) {
        return 'ApiKey';
    }

    // PrivateKey — PRIVATE + KEY but NOT PUBLIC + KEY
    if (upperKey.includes('PRIVATE') && upperKey.includes('KEY')) {
        return 'PrivateKey';
    }

    // Password
    if (
        upperKey.includes('PASSWORD') ||
        upperKey.includes('PASSWD') ||
        upperKey.endsWith('_PW') ||
        upperKey.endsWith('_PWD') ||
        upperKey.endsWith('_PASS')
    ) {
        return 'Password';
    }

    // Token / generic secret / _KEY (but not PUBLIC_KEY)
    if (
        upperKey.includes('TOKEN') ||
        upperKey.includes('SECRET') ||
        (upperKey.endsWith('_KEY') && !upperKey.includes('PUBLIC_KEY'))
    ) {
        return 'Token';
    }

    return null;
}

/** Attempts to classify the secret type from the value alone.
 * Returns null if the value doesn't match any known pattern. */
function detectByValue(value: string): SecretType | null {
    // Database URL schemes with credentials (@)
    for (const scheme of ['postgres://', 'mysql://', 'mongodb://', 'redis://']) {
        if (value.startsWith(scheme) && value.includes('@')) {
            return 'DatabaseUrl';
        }
    }

    // Stripe live keys
    if (value.startsWith('sk_live_') || value.startsWith('pk_live_') || value.startsWith('rk_live_')) {
        return 'StripeKey';
    }

    // AWS Access Key ID pattern: AKIA followed by exactly 16 uppercase alphanumeric chars
    if (isAwsAccessKey(value)) {
        return 'AwsAccessKey';
    }

    // GitHub tokens
    if (
        value.startsWith('ghp_') ||
        value.startsWith('gho_') ||
        value.startsWith('ghs_') ||
        value.startsWith('ghr_') ||
        value.startsWith('github_pat_')
    ) {
        return 'Token';
    }

    // Slack tokens
    if (
        value.startsWith('xoxb-') ||
        value.startsWith('xoxp-') ||
        value.startsWith('xoxs-') ||
        value.startsWith('xoxa-')
    ) {
        return 'Token';
    }

    // OpenAI-style API key
    if (value.startsWith('sk-') && value.length >= 40) {
        return 'ApiKey';
    }

    // JWT (base64url encoded JSON starting with `eyJ`)
    if (value.startsWith('eyJ')) {
        return 'Token';
    }

    // High entropy catch-all (not a bare URL)
    if (value.length > 20 && !isPlainUrl(value) && shannonEntropy(value) > 4.5) {
        return 'Unknown';
    }

    return null;
}

/** Checks value patterns that should override the exclusion list.
 * These are patterns that are unambiguously secret regardless of key name. */
function detectByValueOverride(value: string): SecretType | null {
    // Database URL schemes with credentials (@)
    for (const scheme of ['postgres://', 'mysql://', 'mongodb://', 'redis://']) {
        if (value.startsWith(scheme) && value.includes('@')) {
            return 'DatabaseUrl';
        }
    }

    // Stripe live keys
    if (value.startsWith('sk_live_') || value.startsWith('pk_live_') || value.startsWith('rk_live_')) {
        return 'StripeKey';
    }

    // AWS Access Key ID pattern
    if (isAwsAccessKey(value)) {
        return 'AwsAccessKey';
    }

    // GitHub tokens
    if (
        value.startsWith('ghp_') ||
        value.startsWith('gho_') ||
        value.startsWith('ghs_') ||
        value.startsWith('ghr_') ||
        value.startsWith('github_pat_')
    ) {
        return 'Token';
    }

    // Slack tokens
    if (
        value.startsWith('xoxb-') ||
        value.startsWith('xoxp-') ||
        value.startsWith('xoxs-') ||
        value.startsWith('xoxa-')
    ) {
        return 'Token';
    }

    // JWT
    if (value.startsWith('eyJ')) {
        return 'Token';
    }

    // OpenAI-style API key
    if (value.startsWith('sk-') && value.length >= 40) {
        return 'ApiKey';
    }

    return null;
}

/** Returns true if the value matches the AWS Access Key ID format: `AKIA` followed by exactly
 * 16 uppercase alphanumeric characters (total 20 chars). */
function isAwsAccessKey(value: string): boolean {
    if (!value.startsWith('AKIA')) {
        return false;
    }
    const rest = value.slice(4);
    return rest.length === 16 && /^[A-Z0-9]+$/.test(rest);
}

/**
 * Computes the Shannon entropy of a string.
 *
 * H(X) = -Σ p(x) * log2(p(x)) where p(x) is the frequency of each unique character divided
 * by the total length of the string.
 */
export function shannonEntropy(s: string): number {
    if (s.length === 0) return 0.0;
    const len = s.length;
    const freq = new Array<number>(256).fill(0);
    for (let i = 0; i < s.length; i++) {
        freq[s.charCodeAt(i)]++;
    }
    let entropy = 0.0;
    for (const c of freq) {
        if (c > 0) {
            const p = c / len;
            entropy += -p * Math.log2(p);
        }
    }
    return entropy;
}

/**
 * Detects whether the given environment variable key-value pair contains a secret.
 *
 * Detection order:
 * 1. Value patterns are checked first for known prefixes (e.g. `ghp_`, `sk_live_`).
 * 2. Key name patterns are checked.
 * 3. If the key is in the exclusion list, return not-secret (unless value matched in step 1).
 * 4. Remaining value patterns and entropy are checked.
 */
export function detect(key: string, value: string): DetectionResult {
    const upperKey = key.toUpperCase();

    // Skip trivial values early — these are never secrets regardless of key name
    if (isTrivialValue(value)) {
        return { isSecret: false, secretType: null };
    }

    // Step 1: Check value patterns that override everything, including exclusions.
    // This ensures GITHUB_TOKEN with a ghp_ value is caught even though GITHUB_* is excluded.
    const overrideType = detectByValueOverride(value);
    if (overrideType !== null) {
        return { isSecret: true, secretType: overrideType };
    }

    // Step 2: Check key name patterns.
    const keyType = detectByKey(upperKey);
    if (keyType !== null) {
        return { isSecret: true, secretType: keyType };
    }

    // Step 3: Check exclusion lists (after key patterns so specific keys still fire).
    if (isExcludedKey(upperKey) || isGithubPrefix(upperKey)) {
        return { isSecret: false, secretType: null };
    }

    // Step 4: Check remaining value patterns and entropy.
    const valueType = detectByValue(value);
    if (valueType !== null) {
        return { isSecret: true, secretType: valueType };
    }

    return { isSecret: false, secretType: null };
}
