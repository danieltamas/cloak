import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import * as vault from './vault';
import * as recovery from './recovery';
import * as envparser from './envparser';
import * as detector from './detector';
import * as sandbox from './sandbox';
import { MARKER_FORMAT_VERSION } from './version';

export interface CloakMarker {
    version: number;
    protected: string[];
    projectHash: string;
    createdAt: string;
}

export interface ProtectResult {
    secretCount: number;
    alreadyProtected: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform paths
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns the platform-appropriate vaults directory, creating it if needed.
 * - macOS: ~/Library/Application Support/cloak/vaults/
 * - Linux: ~/.config/cloak/vaults/
 * - Windows: %APPDATA%\cloak\vaults\
 */
async function vaultsDir(): Promise<string> {
    let base: string;
    if (process.platform === 'darwin') {
        base = path.join(os.homedir(), 'Library', 'Application Support', 'cloak', 'vaults');
    } else if (process.platform === 'win32') {
        const appdata = process.env['APPDATA'];
        if (!appdata) throw new Error('APPDATA environment variable not set');
        base = path.join(appdata, 'cloak', 'vaults');
    } else {
        // Linux / other — prefer XDG_CONFIG_HOME
        const xdg = process.env['XDG_CONFIG_HOME'];
        base = xdg
            ? path.join(xdg, 'cloak', 'vaults')
            : path.join(os.homedir(), '.config', 'cloak', 'vaults');
    }
    await fs.mkdir(base, { recursive: true });
    return base;
}

/**
 * Returns the vault file path for the given project root.
 * Format: <vaultsDir>/<projectHash>.vault
 */
export async function vaultFilePath(projectRoot: string): Promise<string> {
    const hash = vault.projectHash(projectRoot);
    const dir = await vaultsDir();
    return path.join(dir, `${hash}.vault`);
}

/**
 * Returns the recovery file path for the given project root.
 * Format: <vaultsDir>/<projectHash>.recovery
 */
export async function recoveryFilePath(projectRoot: string): Promise<string> {
    const hash = vault.projectHash(projectRoot);
    const dir = await vaultsDir();
    return path.join(dir, `${hash}.recovery`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Atomic write helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Atomically write bytes to a file.
 * Writes to <path>.tmp, then renames. On Windows removes original first.
 */
async function atomicWriteBytes(filePath: string, data: Buffer): Promise<void> {
    const tmpPath = filePath + '.tmp';
    await fs.writeFile(tmpPath, data);
    if (process.platform === 'win32') {
        try { await fs.unlink(filePath); } catch { /* file may not exist */ }
    }
    await fs.rename(tmpPath, filePath);
}

/**
 * Atomically write a UTF-8 string to a file.
 */
async function atomicWriteStr(filePath: string, text: string): Promise<void> {
    await atomicWriteBytes(filePath, Buffer.from(text, 'utf8'));
}

// ─────────────────────────────────────────────────────────────────────────────
// Timestamp helper
// ─────────────────────────────────────────────────────────────────────────────

function iso8601Now(): string {
    return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Protect a .env file: detect secrets → encrypt vault → write recovery →
 * write sandbox to disk → update .cloak marker.
 */
export async function protectFile(
    projectRoot: string,
    relPath: string,
    key: Buffer,
    recoveryKeyBytes: Buffer,
): Promise<ProtectResult> {
    const envPath = path.join(projectRoot, relPath);

    // 1. Read the .env file.
    const content = await fs.readFile(envPath, 'utf8');

    // 2. Parse into EnvLine values.
    const lines = envparser.parse(content);

    // 3. Count secrets.
    const secretCount = lines.filter(line => {
        if (line.type === 'assignment') {
            return detector.detect(line.key, line.value).isSecret;
        }
        return false;
    }).length;

    // 4. If no secrets, skip protection.
    if (secretCount === 0) {
        return { secretCount: 0, alreadyProtected: false };
    }

    // 5. Get project hash.
    const hash = vault.projectHash(projectRoot);

    // Check if already protected (vault already exists).
    const vPath = await vaultFilePath(projectRoot);
    let alreadyProtected = false;
    try {
        await fs.access(vPath);
        alreadyProtected = true;
    } catch { /* vault doesn't exist */ }

    // 6. Generate sandbox content.
    const sandboxContent = sandbox.sandboxEnv(content, hash);

    // 7. Encrypt original content.
    const vaultBytes = vault.encrypt(content, key);

    // 8. Create recovery file bytes.
    const recoveryBytes = recovery.createRecoveryFile(key, recoveryKeyBytes);

    // 9. Write vault file atomically.
    await atomicWriteBytes(vPath, vaultBytes);

    // 10. Write recovery file atomically.
    const rPath = await recoveryFilePath(projectRoot);
    await atomicWriteBytes(rPath, recoveryBytes);

    // 11. Set permissions 600 on vault and recovery files (Unix).
    if (process.platform !== 'win32') {
        await fs.chmod(vPath, 0o600);
        await fs.chmod(rPath, 0o600);
    }

    // 12. Write sandbox content to the .env file on disk (atomic).
    await atomicWriteStr(envPath, sandboxContent);

    // 13. Update .cloak marker.
    const marker = await buildOrUpdateMarker(projectRoot, relPath, hash);
    await writeMarker(projectRoot, marker);

    return { secretCount, alreadyProtected };
}

/**
 * Remove protection: decrypt vault → restore original .env → remove vault →
 * update .cloak marker.
 */
export async function unprotectFile(
    projectRoot: string,
    relPath: string,
    key: Buffer,
): Promise<void> {
    // Decrypt vault and get real content.
    const realContent = await readReal(projectRoot, relPath, key);

    // Restore the real .env to disk.
    const envPath = path.join(projectRoot, relPath);
    await atomicWriteStr(envPath, realContent);

    // Remove vault file.
    const vPath = await vaultFilePath(projectRoot);
    try {
        await fs.unlink(vPath);
    } catch { /* vault may not exist */ }

    // Update marker — remove this file from the protected list.
    const marker = await readMarker(projectRoot);
    if (marker) {
        marker.protected = marker.protected.filter(p => p !== relPath);
        await writeMarker(projectRoot, marker);
    }
}

/**
 * Read the real (decrypted) content of a protected .env file from its vault.
 */
export async function readReal(
    projectRoot: string,
    relPath: string,
    key: Buffer,
): Promise<string> {
    const vPath = await vaultFilePath(projectRoot);

    // Check for missing vault.
    let vaultExists = false;
    try {
        await fs.access(vPath);
        vaultExists = true;
    } catch { /* vault missing */ }

    if (!vaultExists) {
        const marker = await readMarker(projectRoot);
        if (marker) {
            throw new Error('Vault file missing. Run cloak recover to restore access.');
        }
        throw new Error(`No vault found for ${relPath}. Has this file been protected?`);
    }

    const vaultBytes = await fs.readFile(vPath);

    // Sanity check.
    if (!vault.isVault(vaultBytes)) {
        throw new Error('Vault corrupted. If you have your recovery key, run cloak recover.');
    }

    const plaintext = vault.decrypt(vaultBytes, key);

    // Basic integrity check.
    if (!plaintext.includes('=')) {
        throw new Error(
            'Vault corrupted: decrypted content does not look like a .env file. ' +
            'If you have your recovery key, run cloak recover.'
        );
    }

    return plaintext;
}

/**
 * Save new real content: encrypt to vault and write sandbox version to disk.
 */
export async function saveReal(
    projectRoot: string,
    relPath: string,
    content: string,
    key: Buffer,
): Promise<void> {
    const vPath = await vaultFilePath(projectRoot);
    const hash = vault.projectHash(projectRoot);
    const envPath = path.join(projectRoot, relPath);

    // Encrypt new content.
    const vaultBytes = vault.encrypt(content, key);

    // Generate sandbox content.
    const sandboxContent = sandbox.sandboxEnv(content, hash);

    // Write vault atomically.
    await atomicWriteBytes(vPath, vaultBytes);

    // Write sandbox to disk atomically.
    await atomicWriteStr(envPath, sandboxContent);
}

/**
 * Read the .cloak marker file from <projectRoot>/.cloak.
 * Returns null if the file does not exist.
 */
export async function readMarker(projectRoot: string): Promise<CloakMarker | null> {
    const markerPath = path.join(projectRoot, '.cloak');
    try {
        const content = await fs.readFile(markerPath, 'utf8');
        return JSON.parse(content) as CloakMarker;
    } catch (err: unknown) {
        if (isNodeError(err) && err.code === 'ENOENT') return null;
        throw err;
    }
}

/**
 * Write (or overwrite) the .cloak marker file at <projectRoot>/.cloak.
 * Written atomically.
 */
export async function writeMarker(projectRoot: string, marker: CloakMarker): Promise<void> {
    const markerPath = path.join(projectRoot, '.cloak');
    const json = JSON.stringify(marker, null, 2);
    await atomicWriteStr(markerPath, json);
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

async function buildOrUpdateMarker(
    projectRoot: string,
    relPath: string,
    projectHash: string,
): Promise<CloakMarker> {
    const existing = await readMarker(projectRoot);
    const marker: CloakMarker = existing ?? {
        version: MARKER_FORMAT_VERSION,
        protected: [],
        projectHash,
        createdAt: iso8601Now(),
    };

    if (!marker.protected.includes(relPath)) {
        marker.protected.push(relPath);
    }

    return marker;
}

function isNodeError(err: unknown): err is NodeJS.ErrnoException {
    return typeof err === 'object' && err !== null && 'code' in err;
}
