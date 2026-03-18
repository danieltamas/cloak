import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import { encrypt, decrypt, isVault, projectHash } from '../src/vault';

function makeKey(): Buffer {
    return crypto.randomBytes(32);
}

describe('vault', () => {
    it('encrypt/decrypt roundtrip', () => {
        const key = makeKey();
        const plaintext = 'hello, world!';
        const vaultBytes = encrypt(plaintext, key);
        const result = decrypt(vaultBytes, key);
        expect(result).toBe(plaintext);
    });

    it('wrong key fails', () => {
        const key = makeKey();
        const wrongKey = makeKey();
        const vaultBytes = encrypt('secret', key);
        expect(() => decrypt(vaultBytes, wrongKey)).toThrow();
    });

    it('tampered data fails', () => {
        const key = makeKey();
        const vaultBytes = encrypt('secret data', key);
        // Flip a byte in the ciphertext portion (offset 32+)
        const tampered = Buffer.from(vaultBytes);
        tampered[32] ^= 0xff;
        expect(() => decrypt(tampered, key)).toThrow();
    });

    it('non-vault bytes: isVault returns false for random data', () => {
        const random = crypto.randomBytes(64);
        // Extremely unlikely to start with CLK, but ensure it doesn't
        random[0] = 0x00;
        expect(isVault(random)).toBe(false);
    });

    it('isVault returns true for valid vault bytes', () => {
        const key = makeKey();
        const vaultBytes = encrypt('test', key);
        expect(isVault(vaultBytes)).toBe(true);
    });

    it('empty bytes fail to decrypt', () => {
        const key = makeKey();
        expect(() => decrypt(Buffer.alloc(0), key)).toThrow('Not a vault file: missing CLK magic');
    });

    it('truncated bytes fail to decrypt', () => {
        const key = makeKey();
        const vaultBytes = encrypt('test', key);
        const truncated = vaultBytes.subarray(0, 10);
        expect(() => decrypt(truncated, key)).toThrow('Not a vault file: missing CLK magic');
    });

    it('two encryptions of same plaintext differ (random IV)', () => {
        const key = makeKey();
        const plaintext = 'same content';
        const v1 = encrypt(plaintext, key);
        const v2 = encrypt(plaintext, key);
        // They should not be byte-for-byte identical due to random IV
        expect(v1.equals(v2)).toBe(false);
        // But both decrypt to the same plaintext
        expect(decrypt(v1, key)).toBe(plaintext);
        expect(decrypt(v2, key)).toBe(plaintext);
    });

    it('unicode roundtrip', () => {
        const key = makeKey();
        const plaintext = 'こんにちは🌍';
        const vaultBytes = encrypt(plaintext, key);
        expect(decrypt(vaultBytes, key)).toBe(plaintext);
    });

    it('projectHash normalization: backslash treated as forward slash', () => {
        const pathForward = '/home/user/my-project';
        const pathBackslash = '\\home\\user\\my-project';
        expect(projectHash(pathForward)).toBe(projectHash(pathBackslash));
    });

    it('projectHash is deterministic', () => {
        const path = '/home/user/project';
        expect(projectHash(path)).toBe(projectHash(path));
    });

    it('projectHash produces 16 hex characters', () => {
        const hash = projectHash('/some/path');
        expect(hash).toMatch(/^[0-9a-f]{16}$/);
    });

    it('isVault returns false for empty buffer', () => {
        expect(isVault(Buffer.alloc(0))).toBe(false);
    });

    it('non-CLK magic returns false from isVault', () => {
        const buf = Buffer.from('RCK\x01somecontent');
        expect(isVault(buf)).toBe(false);
    });
});
