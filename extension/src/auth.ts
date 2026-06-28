import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as filemanager from './filemanager';

// Must stay identical to the CLI (cli/src/auth.rs): PBKDF2-HMAC-SHA256,
// 100_000 iterations, 32-byte salt, 32-byte derived hash.
const PBKDF2_ITERATIONS = 100_000;
const SALT_LEN = 32;
const HASH_LEN = 32;

/** Returns true if a CLI auth gate (`<hash>.auth`) already exists for this project. */
export async function authConfigured(projectRoot: string): Promise<boolean> {
    try {
        await fs.access(await filemanager.authFilePath(projectRoot));
        return true;
    } catch {
        return false;
    }
}

/**
 * Write the `<hash>.auth` gate so the `cloak` CLI requires Touch ID / password
 * before revealing secrets from the terminal. Cross-compatible with the CLI's
 * `cloak run/peek/...` auth check and `cloak set-password`.
 */
export async function writeAuthFile(projectRoot: string, password: string): Promise<void> {
    const salt = crypto.randomBytes(SALT_LEN);
    const hash = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, HASH_LEN, 'sha256');
    const auth = {
        version: 1,
        salt: salt.toString('hex'),
        hash: hash.toString('hex'),
        method: 'pbkdf2-sha256',
        iterations: PBKDF2_ITERATIONS,
    };
    const authPath = await filemanager.authFilePath(projectRoot);
    await fs.writeFile(authPath, JSON.stringify(auth, null, 2));
    if (process.platform !== 'win32') {
        await fs.chmod(authPath, 0o600).catch(() => { /* best-effort */ });
    }
}
