import crypto from 'crypto';

const MAGIC = Buffer.from('CLK');
const VERSION = 0x01;
const MIN_VAULT_LEN = 32; // magic(3) + version(1) + iv(12) + tag(16)

export function encrypt(plaintext: string, key: Buffer): Buffer {
    if (key.length !== 32) throw new Error('Key must be 32 bytes');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag(); // 16 bytes
    // Format: magic(3) + version(1) + iv(12) + tag(16) + ciphertext(N)
    return Buffer.concat([MAGIC, Buffer.from([VERSION]), iv, tag, ciphertext]);
}

export function decrypt(vaultBytes: Buffer, key: Buffer): string {
    if (key.length !== 32) throw new Error('Key must be 32 bytes');
    if (vaultBytes.length < MIN_VAULT_LEN) {
        if (vaultBytes.length < 3 || !vaultBytes.subarray(0, 3).equals(MAGIC)) {
            throw new Error('Not a vault file: missing CLK magic');
        }
        throw new Error('Not a vault file: missing CLK magic');
    }
    if (!vaultBytes.subarray(0, 3).equals(MAGIC)) {
        throw new Error('Not a vault file: missing CLK magic');
    }
    const version = vaultBytes[3];
    if (version < 0x01 || version > 0x01) {
        throw new Error(`Vault version ${version} not supported`);
    }
    const iv = vaultBytes.subarray(4, 16);
    const tag = vaultBytes.subarray(16, 32);
    const ciphertext = vaultBytes.subarray(32);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString('utf8');
}

export function isVault(data: Buffer): boolean {
    return data.length >= 3 && data.subarray(0, 3).equals(MAGIC);
}

export function projectHash(projectRoot: string): string {
    const normalized = projectRoot.replace(/\\/g, '/');
    return crypto.createHash('sha256').update(normalized).digest('hex').substring(0, 16);
}
