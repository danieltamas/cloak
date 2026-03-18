import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import {
    generateRecoveryKey,
    parseRecoveryKey,
    deriveKeyFromRecovery,
    createRecoveryFile,
    recoverKeychainKey,
} from '../src/recovery';

describe('recovery', () => {
    it('generateRecoveryKey format: starts with CLOAK-, has 6 groups of 4 hex chars', () => {
        const { display, bytes } = generateRecoveryKey();
        expect(display).toMatch(/^CLOAK-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/);
        expect(bytes.length).toBe(12);
    });

    it('generateRecoveryKey display encodes the same bytes', () => {
        const { display, bytes } = generateRecoveryKey();
        // Strip the CLOAK- prefix and dashes, parse hex, compare to bytes
        const hexPart = display.replace('CLOAK-', '').replace(/-/g, '').toLowerCase();
        expect(Buffer.from(hexPart, 'hex')).toEqual(bytes);
    });

    it('parseRecoveryKey is case-insensitive: uppercase and lowercase give same result', () => {
        const { display, bytes } = generateRecoveryKey();
        const upper = display; // already uppercase
        const lower = display.toLowerCase();
        expect(parseRecoveryKey(upper)).toEqual(bytes);
        expect(parseRecoveryKey(lower)).toEqual(bytes);
    });

    it('parseRecoveryKey accepts input without dashes', () => {
        const { display, bytes } = generateRecoveryKey();
        // Remove all dashes: "CLOAKXXXXXXXXXXXXXXXXXXXXXXXX"
        const noDashes = display.replace(/-/g, '');
        expect(parseRecoveryKey(noDashes)).toEqual(bytes);
    });

    it('parseRecoveryKey accepts just the hex part without CLOAK prefix', () => {
        const { display, bytes } = generateRecoveryKey();
        // Strip prefix and dashes entirely: raw 24 hex chars
        const hexOnly = display.replace('CLOAK-', '').replace(/-/g, '');
        expect(parseRecoveryKey(hexOnly)).toEqual(bytes);
    });

    it('parseRecoveryKey rejects wrong length', () => {
        expect(() => parseRecoveryKey('CLOAK-ABCD-1234')).toThrow('Invalid recovery key format');
        expect(() => parseRecoveryKey('')).toThrow('Invalid recovery key format');
        expect(() => parseRecoveryKey('CLOAK-ABCD-1234-EF56-7890-ABCD-EF12-XTRA')).toThrow('Invalid recovery key format');
    });

    it('create/recover roundtrip: recoverKeychainKey returns original key', () => {
        const keychainKey = crypto.randomBytes(32);
        const { bytes: recoveryKeyBytes } = generateRecoveryKey();
        const recoveryFile = createRecoveryFile(keychainKey, recoveryKeyBytes);
        const recovered = recoverKeychainKey(recoveryFile, recoveryKeyBytes);
        expect(recovered).toEqual(keychainKey);
    });

    it('wrong recovery key fails during recovery', () => {
        const keychainKey = crypto.randomBytes(32);
        const { bytes: correctKey } = generateRecoveryKey();
        const { bytes: wrongKey } = generateRecoveryKey();
        const recoveryFile = createRecoveryFile(keychainKey, correctKey);
        expect(() => recoverKeychainKey(recoveryFile, wrongKey)).toThrow();
    });

    it('PBKDF2 determinism: same inputs produce same derived key', () => {
        const recoveryKeyBytes = crypto.randomBytes(12);
        const salt = crypto.randomBytes(32);
        const derived1 = deriveKeyFromRecovery(recoveryKeyBytes, salt);
        const derived2 = deriveKeyFromRecovery(recoveryKeyBytes, salt);
        expect(derived1).toEqual(derived2);
        expect(derived1.length).toBe(32);
    });

    it('PBKDF2 different salts produce different keys', () => {
        const recoveryKeyBytes = crypto.randomBytes(12);
        const salt1 = crypto.randomBytes(32);
        const salt2 = crypto.randomBytes(32);
        const derived1 = deriveKeyFromRecovery(recoveryKeyBytes, salt1);
        const derived2 = deriveKeyFromRecovery(recoveryKeyBytes, salt2);
        expect(derived1.equals(derived2)).toBe(false);
    });

    it('recoverKeychainKey rejects too-short data', () => {
        const buf = Buffer.alloc(10);
        expect(() => recoverKeychainKey(buf, crypto.randomBytes(12))).toThrow();
    });

    it('recoverKeychainKey rejects wrong magic', () => {
        const buf = Buffer.alloc(65);
        buf.write('CLK', 0, 'ascii'); // wrong magic (should be RCK)
        buf[3] = 0x01;
        expect(() => recoverKeychainKey(buf, crypto.randomBytes(12))).toThrow('Not a recovery file: missing RCK magic');
    });
});
