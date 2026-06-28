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
 * Returns the vault file path for `relPath` within the given project root.
 * Format: <vaultsDir>/<vaultId>.vault — one vault per protected file so that
 * multiple `.env` files in a project never collide (see vault.vaultId).
 */
export async function vaultFilePath(projectRoot: string, relPath: string): Promise<string> {
    const hash = vault.projectHash(projectRoot);
    const id = vault.vaultId(hash, relPath);
    const dir = await vaultsDir();
    return path.join(dir, `${id}.vault`);
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

/**
 * Returns the auth file path for the given project root.
 * Format: <vaultsDir>/<projectHash>.auth — must match the CLI (auth.rs).
 */
export async function authFilePath(projectRoot: string): Promise<string> {
    const hash = vault.projectHash(projectRoot);
    const dir = await vaultsDir();
    return path.join(dir, `${hash}.auth`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Recursive .env discovery (mirrors the CLI's `scan_env_files`)
// ─────────────────────────────────────────────────────────────────────────────

/** Candidate env file names scanned in each directory. Matches the CLI. */
const ENV_FILE_NAMES = [
    '.env',
    '.env.local',
    '.env.development',
    '.env.production',
    '.env.staging',
    '.env.test',
];

/** Directory names skipped during the scan (dot-directories are skipped separately). */
const IGNORE_DIRS = new Set(['node_modules', 'dist', 'build', 'target', 'vendor', 'coverage']);

/** Maximum directory depth to descend (0 = project root only). */
const MAX_SCAN_DEPTH = 5;

/**
 * Recursively scan `rootDir` (subdirectories up to {@link MAX_SCAN_DEPTH}) for
 * candidate env files that contain at least one detected secret.
 *
 * Returns `{ relPath, secretCount }` for each, with forward-slash relative paths
 * sorted deterministically. `node_modules`, build output, and dot-directories are
 * skipped, and symlinked directories are not followed — same rules as `cloak init`.
 */
export async function findEnvFilesWithSecrets(
    rootDir: string,
): Promise<Array<{ relPath: string; secretCount: number }>> {
    const results: Array<{ relPath: string; secretCount: number }> = [];

    async function scan(dir: string, depth: number): Promise<void> {
        // Candidate env files in this directory.
        for (const name of ENV_FILE_NAMES) {
            const full = path.join(dir, name);
            let content: string;
            try {
                content = await fs.readFile(full, 'utf8');
            } catch {
                continue; // not a file / unreadable
            }
            const secretCount = envparser.parse(content).filter(
                line => line.type === 'assignment' && detector.detect(line.key, line.value).isSecret,
            ).length;
            if (secretCount > 0) {
                results.push({
                    relPath: path.relative(rootDir, full).replace(/\\/g, '/'),
                    secretCount,
                });
            }
        }

        if (depth >= MAX_SCAN_DEPTH) return;

        let entries: import('fs').Dirent[];
        try {
            entries = await fs.readdir(dir, { withFileTypes: true });
        } catch {
            return;
        }
        for (const entry of entries) {
            // isDirectory() is false for symlinks, so symlinked dirs are skipped.
            if (!entry.isDirectory()) continue;
            if (entry.name.startsWith('.') || IGNORE_DIRS.has(entry.name)) continue;
            const child = path.join(dir, entry.name);
            // Don't descend into an independently-protected sub-project — its own
            // .cloak owns those files.
            try {
                await fs.access(path.join(child, '.cloak'));
                continue;
            } catch { /* no marker here — keep scanning */ }
            await scan(child, depth + 1);
        }
    }

    await scan(rootDir, 0);
    results.sort((a, b) => a.relPath.localeCompare(b.relPath));
    return results;
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
    recoveryKeyBytes: Buffer | null,
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
    const vPath = await vaultFilePath(projectRoot, relPath);
    let alreadyProtected = false;
    try {
        await fs.access(vPath);
        alreadyProtected = true;
    } catch { /* vault doesn't exist */ }

    // 6. Generate sandbox content.
    const sandboxContent = sandbox.sandboxEnv(content, hash);

    // 7. Encrypt original content.
    const vaultBytes = vault.encrypt(content, key);

    // 8. Write vault file atomically.
    await atomicWriteBytes(vPath, vaultBytes);

    // 9. Write the per-project recovery file — only when seeding a fresh key.
    //    When adding a file to an already-protected project the key is reused and
    //    recoveryKeyBytes is null, so the existing recovery file is left untouched
    //    (rewriting it would invalidate the recovery key the user already saved).
    if (recoveryKeyBytes) {
        const recoveryBytes = recovery.createRecoveryFile(key, recoveryKeyBytes);
        const rPath = await recoveryFilePath(projectRoot);
        await atomicWriteBytes(rPath, recoveryBytes);
        if (process.platform !== 'win32') {
            await fs.chmod(rPath, 0o600);
        }
    }

    // 10. Set permissions 600 on the vault file (Unix).
    if (process.platform !== 'win32') {
        await fs.chmod(vPath, 0o600);
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
    const vPath = await vaultFilePath(projectRoot, relPath);
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
    const vPath = await vaultFilePath(projectRoot, relPath);

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
    const vPath = await vaultFilePath(projectRoot, relPath);
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
 * Walk up from `startDir` to find the nearest directory containing a `.cloak` marker.
 * Stops at `stopAt` (inclusive). Returns null if no marker is found.
 */
export async function findProjectRoot(startDir: string, stopAt: string): Promise<string | null> {
    let dir = startDir;
    while (dir.startsWith(stopAt)) {
        const markerPath = path.join(dir, '.cloak');
        try {
            await fs.access(markerPath);
            return dir;
        } catch { /* not found */ }
        const parent = path.dirname(dir);
        if (parent === dir) break;
        dir = parent;
    }
    return null;
}

/**
 * Recursively find all directories containing `.cloak` markers within `rootDir`.
 * Returns an array of directory paths.
 */
export async function findAllCloakProjects(rootDir: string): Promise<string[]> {
    const results: string[] = [];
    async function scan(dir: string, depth: number): Promise<void> {
        if (depth > 5) return; // limit depth to avoid scanning node_modules etc.
        const markerPath = path.join(dir, '.cloak');
        try {
            await fs.access(markerPath);
            results.push(dir);
        } catch { /* no marker here */ }
        try {
            const entries = await fs.readdir(dir, { withFileTypes: true });
            for (const entry of entries) {
                if (!entry.isDirectory()) continue;
                if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === 'dist' || entry.name === 'build') continue;
                await scan(path.join(dir, entry.name), depth + 1);
            }
        } catch { /* unreadable dir */ }
    }
    await scan(rootDir, 0);
    return results;
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
