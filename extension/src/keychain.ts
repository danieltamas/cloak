import * as vscode from 'vscode';
import { execFile } from 'child_process';

let secretStorage: vscode.SecretStorage;

export function init(storage: vscode.SecretStorage): void {
    secretStorage = storage;
}

export async function storeKey(projectHash: string, key: Buffer): Promise<void> {
    await secretStorage.store(`cloak-vault-${projectHash}`, key.toString('hex'));
    // Best-effort: also seed the OS keychain via the `cloak` CLI so terminal
    // commands (cloak run/peek/edit) can decrypt a project protected from the editor.
    // Without this, the CLI has no key for editor-protected projects. Failure is
    // non-fatal — the recovery key remains the backstop and "Cloak: Enable CLI
    // Access" can retry once the CLI is installed.
    await seedCliKeychain(projectHash, key);
}

/**
 * Push a key into the OS keychain via `cloak keychain-set` so the CLI can use it.
 * The key is piped over stdin (never argv, so it can't leak via the process list).
 * Resolves true on success, false if the CLI is missing or the write failed.
 */
export function seedCliKeychain(projectHash: string, key: Buffer): Promise<boolean> {
    return new Promise((resolve) => {
        try {
            const child = execFile('cloak', ['keychain-set', projectHash], { timeout: 30000 }, (err) => {
                resolve(!err);
            });
            child.stdin?.end(key.toString('hex'));
        } catch {
            resolve(false);
        }
    });
}

export async function getKey(projectHash: string): Promise<Buffer | null> {
    // 1. Try VS Code SecretStorage first (fast, no prompt).
    const hex = await secretStorage.get(`cloak-vault-${projectHash}`);
    if (hex) return Buffer.from(hex, 'hex');

    // 2. Fall back to cloak CLI (triggers Touch ID on macOS).
    try {
        const cliHex = await readViaCli(projectHash);
        if (cliHex) {
            // Cache in VS Code SecretStorage for next time.
            await secretStorage.store(`cloak-vault-${projectHash}`, cliHex);
            return Buffer.from(cliHex, 'hex');
        }
    } catch { /* cloak CLI not found or failed */ }

    return null;
}

export async function deleteKey(projectHash: string): Promise<void> {
    await secretStorage.delete(`cloak-vault-${projectHash}`);
}

/**
 * Retrieve key via `cloak keychain-get` CLI command.
 * On macOS this triggers Touch ID / password prompt.
 */
function readViaCli(projectHash: string): Promise<string | null> {
    return new Promise((resolve) => {
        execFile('cloak', ['keychain-get', projectHash], { timeout: 30000 }, (err, stdout) => {
            if (err) return resolve(null);
            const hex = stdout.trim();
            // Validate: must be exactly 64 hex characters (32 bytes).
            if (hex.length === 64 && /^[0-9a-f]+$/i.test(hex)) {
                return resolve(hex);
            }
            resolve(null);
        });
    });
}
