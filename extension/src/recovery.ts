import crypto from 'crypto';

const MAGIC = Buffer.from('RCK');
const VERSION = 0x01;
const PBKDF2_ITERATIONS = 100_000;

// Offsets
const OFFSET_SALT = 4;
const OFFSET_IV = 36;
const OFFSET_TAG = 48;
const OFFSET_CIPHERTEXT = 64;
const LEN_SALT = 32;
const LEN_IV = 12;
const LEN_TAG = 16;

export function generateRecoveryKey(): { display: string; bytes: Buffer } {
    const bytes = crypto.randomBytes(12);
    const hex = bytes.toString('hex').toUpperCase();
    const display = `CLOAK-${hex.slice(0,4)}-${hex.slice(4,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20,24)}`;
    return { display, bytes };
}

export function parseRecoveryKey(input: string): Buffer {
    const lowered = input.toLowerCase();
    const withoutPrefix = lowered.startsWith('cloak') ? lowered.slice(5) : lowered;
    const hexOnly = withoutPrefix.replace(/[^0-9a-f]/g, '');
    if (hexOnly.length !== 24) throw new Error('Invalid recovery key format');
    return Buffer.from(hexOnly, 'hex');
}

export function deriveKeyFromRecovery(recoveryKeyBytes: Buffer, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(recoveryKeyBytes, salt, PBKDF2_ITERATIONS, 32, 'sha256');
}

export function createRecoveryFile(keychainKey: Buffer, recoveryKeyBytes: Buffer): Buffer {
    const salt = crypto.randomBytes(LEN_SALT);
    const iv = crypto.randomBytes(LEN_IV);
    const derived = deriveKeyFromRecovery(recoveryKeyBytes, salt);

    const cipher = crypto.createCipheriv('aes-256-gcm', derived, iv);
    const ciphertext = Buffer.concat([cipher.update(keychainKey), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Format: magic(3) + version(1) + salt(32) + iv(12) + tag(16) + ciphertext(N)
    return Buffer.concat([MAGIC, Buffer.from([VERSION]), salt, iv, tag, ciphertext]);
}

export function recoverKeychainKey(recoveryBytes: Buffer, recoveryKeyBytes: Buffer): Buffer {
    if (recoveryBytes.length < OFFSET_CIPHERTEXT + 1) {
        throw new Error('Not a recovery file: too short');
    }
    if (!recoveryBytes.subarray(0, 3).equals(MAGIC)) {
        throw new Error('Not a recovery file: missing RCK magic');
    }
    const version = recoveryBytes[3];
    if (version !== VERSION) {
        throw new Error(`Unsupported recovery file version: ${version}`);
    }

    const salt = recoveryBytes.subarray(OFFSET_SALT, OFFSET_SALT + LEN_SALT);
    const iv = recoveryBytes.subarray(OFFSET_IV, OFFSET_IV + LEN_IV);
    const tag = recoveryBytes.subarray(OFFSET_TAG, OFFSET_TAG + LEN_TAG);
    const ciphertext = recoveryBytes.subarray(OFFSET_CIPHERTEXT);

    const derived = deriveKeyFromRecovery(recoveryKeyBytes, salt);

    const decipher = crypto.createDecipheriv('aes-256-gcm', derived, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext;
}
