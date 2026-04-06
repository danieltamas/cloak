import * as vscode from 'vscode';
import { execFile } from 'child_process';

let secretStorage: vscode.SecretStorage;

export function init(storage: vscode.SecretStorage): void {
    secretStorage = storage;
}

export async function storeKey(projectHash: string, key: Buffer): Promise<void> {
    await secretStorage.store(`cloak-vault-${projectHash}`, key.toString('hex'));
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
