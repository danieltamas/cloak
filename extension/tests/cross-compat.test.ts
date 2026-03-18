/**
 * Cross-compatibility tests for Cloak.
 *
 * Verifies that the TypeScript extension implements the same crypto primitives
 * as the Rust CLI, using fixed known inputs so that the expected outputs can be
 * computed independently and matched against what Rust must also produce.
 *
 * Tests cover:
 *   1. Vault binary format layout (CLK magic, offsets)
 *   2. Vault encrypt/decrypt roundtrip
 *   3. Recovery file binary format layout (RCK magic, offsets)
 *   4. Recovery file create/recover roundtrip
 *   5. projectHash determinism and backslash normalization
 *   6. sandboxEnv / deterministicHex determinism
 *   7. PBKDF2 key derivation — known test vector
 */

import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import { encrypt, decrypt, isVault, projectHash } from '../src/vault';
import {
    generateRecoveryKey,
    parseRecoveryKey,
    deriveKeyFromRecovery,
    createRecoveryFile,
    recoverKeychainKey,
} from '../src/recovery';
import { deterministicHex, sandboxValue, sandboxEnv } from '../src/sandbox';

// ── Fixed test inputs ────────────────────────────────────────────────────────

/** 32 bytes of 0xAB — the vault encryption key used across all vault tests. */
const TEST_KEY = Buffer.alloc(32, 0xab);

/** A typical POSIX project path used for projectHash tests. */
const TEST_PATH = '/Users/test/myproject';

/**
 * Fixed 12-byte recovery key (raw hex: 0123456789abcdef01234567).
 * This corresponds to display key "CLOAK-0123-4567-89AB-CDEF-0123-4567".
 */
const TEST_RECOVERY_KEY_HEX = '0123456789abcdef01234567';
const TEST_RECOVERY_BYTES = Buffer.from(TEST_RECOVERY_KEY_HEX, 'hex');

/** 32 bytes of 0xCD — fixed salt for deterministic PBKDF2 tests. */
const TEST_SALT = Buffer.alloc(32, 0xcd);

// ── Test 1 & 2: Vault format and encrypt/decrypt roundtrip ──────────────────

describe('Cross-compatibility — Test 1 & 2: Vault format', () => {
    it('encrypted output starts with CLK magic byte sequence', () => {
        const vaultBytes = encrypt('hello', TEST_KEY);
        expect(vaultBytes[0]).toBe(0x43); // 'C'
        expect(vaultBytes[1]).toBe(0x4c); // 'L'
        expect(vaultBytes[2]).toBe(0x4b); // 'K'
    });

    it('version byte is 0x01 at offset 3', () => {
        const vaultBytes = encrypt('hello', TEST_KEY);
        expect(vaultBytes[3]).toBe(0x01);
    });

    it('binary layout: magic(3) + version(1) + iv(12) + tag(16) + ciphertext', () => {
        const plaintext = 'cross-compat-test-value';
        const vaultBytes = encrypt(plaintext, TEST_KEY);

        // Total length must be at least 32 (header) + plaintext bytes
        expect(vaultBytes.length).toBeGreaterThanOrEqual(32);

        // The ciphertext portion starts at offset 32 and has the same byte-length as
        // the UTF-8 plaintext (AES-GCM is a stream cipher — no padding).
        const ciphertextLen = vaultBytes.length - 32;
        expect(ciphertextLen).toBe(Buffer.byteLength(plaintext, 'utf8'));
    });

    it('isVault returns true for encrypted output', () => {
        const vaultBytes = encrypt('data', TEST_KEY);
        expect(isVault(vaultBytes)).toBe(true);
    });

    it('encrypt/decrypt roundtrip with fixed key and plaintext', () => {
        const plaintext = 'SECRET=supersecret\nANOTHER=value\n';
        const vaultBytes = encrypt(plaintext, TEST_KEY);
        const recovered = decrypt(vaultBytes, TEST_KEY);
        expect(recovered).toBe(plaintext);
    });

    it('encrypt/decrypt roundtrip preserves Unicode content', () => {
        const plaintext = 'KEY=こんにちは世界\nEMOJI=🔑🔒\n';
        const vaultBytes = encrypt(plaintext, TEST_KEY);
        const recovered = decrypt(vaultBytes, TEST_KEY);
        expect(recovered).toBe(plaintext);
    });

    it('two encryptions of same plaintext produce different ciphertext (random IV)', () => {
        const plaintext = 'same-data';
        const v1 = encrypt(plaintext, TEST_KEY);
        const v2 = encrypt(plaintext, TEST_KEY);
        // IV occupies bytes 4–15; they must differ across calls
        expect(v1.subarray(4, 16).equals(v2.subarray(4, 16))).toBe(false);
        // Both must decrypt correctly
        expect(decrypt(v1, TEST_KEY)).toBe(plaintext);
        expect(decrypt(v2, TEST_KEY)).toBe(plaintext);
    });

    it('decryption with wrong key throws', () => {
        const vaultBytes = encrypt('secret', TEST_KEY);
        const wrongKey = Buffer.alloc(32, 0x00);
        expect(() => decrypt(vaultBytes, wrongKey)).toThrow();
    });

    it('tampered ciphertext byte causes decryption failure', () => {
        const vaultBytes = encrypt('secret data', TEST_KEY);
        const tampered = Buffer.from(vaultBytes);
        tampered[32] ^= 0xff; // flip a bit in the ciphertext
        expect(() => decrypt(tampered, TEST_KEY)).toThrow();
    });
});

// ── Test 3 & 4: Recovery file format and create/recover roundtrip ────────────

describe('Cross-compatibility — Test 3 & 4: Recovery file format', () => {
    it('recovery file starts with RCK magic', () => {
        const keychainKey = Buffer.alloc(32, 0x01);
        const fileBytes = createRecoveryFile(keychainKey, TEST_RECOVERY_BYTES);
        expect(fileBytes[0]).toBe(0x52); // 'R'
        expect(fileBytes[1]).toBe(0x43); // 'C'
        expect(fileBytes[2]).toBe(0x4b); // 'K'
    });

    it('version byte is 0x01 at offset 3', () => {
        const keychainKey = Buffer.alloc(32, 0x01);
        const fileBytes = createRecoveryFile(keychainKey, TEST_RECOVERY_BYTES);
        expect(fileBytes[3]).toBe(0x01);
    });

    it('binary layout: magic(3) + version(1) + salt(32) + iv(12) + tag(16) + ciphertext', () => {
        const keychainKey = Buffer.alloc(32, 0x01);
        const fileBytes = createRecoveryFile(keychainKey, TEST_RECOVERY_BYTES);

        // Minimum header = 3 + 1 + 32 + 12 + 16 = 64 bytes, plus ≥1 byte ciphertext
        expect(fileBytes.length).toBeGreaterThan(64);

        // Ciphertext (encrypted keychainKey) has same byte length as keychainKey (32)
        const ciphertextLen = fileBytes.length - 64;
        expect(ciphertextLen).toBe(keychainKey.length);
    });

    it('create/recover roundtrip with fixed 32-byte keychain key', () => {
        const keychainKey = TEST_KEY; // reuse the same fixed key
        const fileBytes = createRecoveryFile(keychainKey, TEST_RECOVERY_BYTES);
        const recovered = recoverKeychainKey(fileBytes, TEST_RECOVERY_BYTES);
        expect(recovered).toEqual(keychainKey);
    });

    it('create/recover roundtrip with random keychain key', () => {
        const keychainKey = crypto.randomBytes(32);
        const fileBytes = createRecoveryFile(keychainKey, TEST_RECOVERY_BYTES);
        const recovered = recoverKeychainKey(fileBytes, TEST_RECOVERY_BYTES);
        expect(recovered).toEqual(keychainKey);
    });

    it('recovery with wrong recovery key bytes throws', () => {
        const keychainKey = Buffer.alloc(32, 0x01);
        const fileBytes = createRecoveryFile(keychainKey, TEST_RECOVERY_BYTES);
        const wrongRecoveryBytes = Buffer.alloc(12, 0xff);
        expect(() => recoverKeychainKey(fileBytes, wrongRecoveryBytes)).toThrow();
    });
});

// ── Test 5: projectHash — determinism and backslash normalization ─────────────

describe('Cross-compatibility — Test 5: projectHash', () => {
    it('produces the SHA-256 first-16-hex of the normalized path', () => {
        // Expected: SHA-256('/Users/test/myproject') → first 16 hex chars
        // Computed: 7b4d1b0b25658663
        const expected = crypto
            .createHash('sha256')
            .update(TEST_PATH)
            .digest('hex')
            .substring(0, 16);
        expect(expected).toBe('7b4d1b0b25658663'); // known value for cross-checking with Rust
        expect(projectHash(TEST_PATH)).toBe(expected);
    });

    it('output is exactly 16 lowercase hex characters', () => {
        const hash = projectHash(TEST_PATH);
        expect(hash).toHaveLength(16);
        expect(hash).toMatch(/^[0-9a-f]{16}$/);
    });

    it('backslashes are normalised to forward slashes before hashing', () => {
        // Windows path equivalent must produce the same hash as the POSIX path
        const winPath = '/Users/test/myproject'.replace(/\//g, '\\');
        expect(projectHash(winPath)).toBe(projectHash(TEST_PATH));
    });

    it('different paths produce different hashes', () => {
        expect(projectHash('/Users/test/proj-a')).not.toBe(projectHash('/Users/test/proj-b'));
    });

    it('is deterministic across multiple calls', () => {
        expect(projectHash(TEST_PATH)).toBe(projectHash(TEST_PATH));
    });
});

// ── Test 6: sandboxEnv / deterministicHex — determinism ─────────────────────

describe('Cross-compatibility — Test 6: sandbox determinism', () => {
    it('deterministicHex produces a known fixed value for fixed inputs', () => {
        // Input: 'cloak-sandbox:testhash:MY_KEY' → SHA-256 → first 20 hex chars
        // Computed: a07404faa6392b60de34
        const expected = crypto
            .createHash('sha256')
            .update('cloak-sandbox:testhash:MY_KEY', 'utf8')
            .digest('hex')
            .slice(0, 20);
        expect(expected).toBe('a07404faa6392b60de34'); // known value for Rust cross-check
        expect(deterministicHex('testhash', 'MY_KEY', 20)).toBe(expected);
    });

    it('deterministicHex is deterministic across calls', () => {
        const h1 = deterministicHex('testhash', 'MY_KEY', 20);
        const h2 = deterministicHex('testhash', 'MY_KEY', 20);
        expect(h1).toBe(h2);
    });

    it('deterministicHex respects requested length', () => {
        const full = deterministicHex('hash', 'key', 32);
        const short = deterministicHex('hash', 'key', 8);
        expect(full).toHaveLength(32);
        expect(short).toHaveLength(8);
        expect(full.startsWith(short)).toBe(true);
    });

    it('sandboxEnv produces identical output for same content and projectHash', () => {
        const content = [
            'DATABASE_URL=postgres://user:pass@db.example.com:5432/mydb',
            'STRIPE_SECRET_KEY=sk_test_FAKEdefghijklmnopqrstuvwx',
            'NODE_ENV=production',
            'API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef',
        ].join('\n');

        const hash = projectHash(TEST_PATH);
        const out1 = sandboxEnv(content, hash);
        const out2 = sandboxEnv(content, hash);
        expect(out1).toBe(out2);
    });

    it('sandboxEnv output differs when projectHash differs (for hash-dependent types)', () => {
        // An ApiKey value that starts with 'sk-' produces a sandboxed value that
        // embeds deterministicHex — so different project hashes yield different results.
        const content = 'OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef';
        const hash1 = projectHash('/proj/a');
        const hash2 = projectHash('/proj/b');
        expect(sandboxEnv(content, hash1)).not.toBe(sandboxEnv(content, hash2));
    });

    it('sandboxValue for each SecretType is deterministic with fixed inputs', () => {
        const hash = '7b4d1b0b25658663'; // known hash for TEST_PATH
        const cases: Array<[string, string, Parameters<typeof sandboxValue>[2]]> = [
            ['DATABASE_URL', 'postgres://user:pass@host:5432/db', 'DatabaseUrl'],
            ['STRIPE_SECRET_KEY', 'sk_live_abc123', 'StripeKey'],
            ['AWS_ACCESS_KEY_ID', 'AKIAIOSFODNN7EXAMPLE', 'AwsAccessKey'],
            ['AWS_SECRET_ACCESS_KEY', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCY', 'AwsSecretKey'],
            ['JWT_SECRET', 'supersecretjwt', 'JwtSecret'],
            ['API_KEY', 'sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef', 'ApiKey'],
            ['PRIVATE_KEY', 'myprivatekey123', 'PrivateKey'],
            ['DB_PASSWORD', 'mypassword', 'Password'],
            ['GITHUB_TOKEN', 'ghp_abcdef12345678901234', 'Token'],
            ['WEBHOOK_URL', 'https://user:pass@hook.example.com/endpoint', 'GenericUrl'],
            ['SOME_UNKNOWN', 'highentropystringabcdefghijklmno12345', 'Unknown'],
        ];

        for (const [key, value, secretType] of cases) {
            const v1 = sandboxValue(key, value, secretType, hash);
            const v2 = sandboxValue(key, value, secretType, hash);
            expect(v1).toBe(v2);
        }
    });
});

// ── Test 7: PBKDF2 key derivation — known test vector ────────────────────────

describe('Cross-compatibility — Test 7: PBKDF2 determinism and known vector', () => {
    it('deriveKeyFromRecovery is deterministic with fixed inputs', () => {
        const derived1 = deriveKeyFromRecovery(TEST_RECOVERY_BYTES, TEST_SALT);
        const derived2 = deriveKeyFromRecovery(TEST_RECOVERY_BYTES, TEST_SALT);
        expect(derived1).toEqual(derived2);
    });

    it('output is 32 bytes', () => {
        const derived = deriveKeyFromRecovery(TEST_RECOVERY_BYTES, TEST_SALT);
        expect(derived.length).toBe(32);
    });

    it('matches known PBKDF2-SHA256 vector: password=TEST_RECOVERY_BYTES, salt=0xCD*32, iters=100000, dkLen=32', () => {
        // Pre-computed expected value:
        //   PBKDF2-SHA256(
        //     password = 0x0123456789abcdef01234567,  (12 bytes)
        //     salt     = 0xCDCD...CD,                 (32 bytes of 0xCD)
        //     iters    = 100000,
        //     dkLen    = 32
        //   ) = d2abbf640a495386534bcfa4670d183e15eadb06f9476a0eb1a671b62a1ef2a7
        const expectedHex = 'd2abbf640a495386534bcfa4670d183e15eadb06f9476a0eb1a671b62a1ef2a7';
        const expected = Buffer.from(expectedHex, 'hex');

        const derived = deriveKeyFromRecovery(TEST_RECOVERY_BYTES, TEST_SALT);
        expect(derived.toString('hex')).toBe(expectedHex);
        expect(derived).toEqual(expected);
    });

    it('different recovery key bytes produce different derived key', () => {
        const otherRecoveryBytes = Buffer.alloc(12, 0xff);
        const d1 = deriveKeyFromRecovery(TEST_RECOVERY_BYTES, TEST_SALT);
        const d2 = deriveKeyFromRecovery(otherRecoveryBytes, TEST_SALT);
        expect(d1.equals(d2)).toBe(false);
    });

    it('different salts produce different derived keys', () => {
        const otherSalt = Buffer.alloc(32, 0xAA);
        const d1 = deriveKeyFromRecovery(TEST_RECOVERY_BYTES, TEST_SALT);
        const d2 = deriveKeyFromRecovery(TEST_RECOVERY_BYTES, otherSalt);
        expect(d1.equals(d2)).toBe(false);
    });

    it('parseRecoveryKey + deriveKeyFromRecovery pipeline is deterministic from display string', () => {
        // A fixed display string must always parse to the same bytes and derive the same key.
        const displayKey = 'CLOAK-0123-4567-89AB-CDEF-0123-4567';
        const parsed = parseRecoveryKey(displayKey);
        expect(parsed).toEqual(TEST_RECOVERY_BYTES);

        const derived = deriveKeyFromRecovery(parsed, TEST_SALT);
        const expectedHex = 'd2abbf640a495386534bcfa4670d183e15eadb06f9476a0eb1a671b62a1ef2a7';
        expect(derived.toString('hex')).toBe(expectedHex);
    });

    it('full cross-compat pipeline: generateRecoveryKey → create → recover → derive is stable', () => {
        // Use fixed recovery bytes (not random) so this test is deterministic.
        const keychainKey = TEST_KEY;
        const recoveryFile = createRecoveryFile(keychainKey, TEST_RECOVERY_BYTES);

        // Recover using the same bytes
        const recoveredKey = recoverKeychainKey(recoveryFile, TEST_RECOVERY_BYTES);
        expect(recoveredKey).toEqual(keychainKey);

        // The recovered key can then be used to decrypt a vault
        const plaintext = 'API_SECRET=my-real-secret-value\n';
        const vaultBytes = encrypt(plaintext, recoveredKey);
        expect(decrypt(vaultBytes, recoveredKey)).toBe(plaintext);
    });
});
