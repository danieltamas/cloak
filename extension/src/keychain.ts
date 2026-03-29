import * as vscode from 'vscode';
import keytar from 'keytar';

let secretStorage: vscode.SecretStorage;

export function init(storage: vscode.SecretStorage): void {
    secretStorage = storage;
}

export async function storeKey(projectHash: string, key: Buffer): Promise<void> {
    await secretStorage.store(`cloak-vault-${projectHash}`, key.toString('hex'));
}

export async function getKey(projectHash: string): Promise<Buffer | null> {
    // 1. Try VS Code SecretStorage first.
    const hex = await secretStorage.get(`cloak-vault-${projectHash}`);
    if (hex) return Buffer.from(hex, 'hex');

    // 2. Fall back to OS keychain (shared with CLI).
    try {
        const osHex = await keytar.getPassword('cloak', `vault-${projectHash}`);
        if (osHex) {
            // Cache it in VS Code SecretStorage for next time.
            await secretStorage.store(`cloak-vault-${projectHash}`, osHex);
            return Buffer.from(osHex, 'hex');
        }
    } catch { /* keytar not available or failed */ }

    return null;
}

export async function deleteKey(projectHash: string): Promise<void> {
    await secretStorage.delete(`cloak-vault-${projectHash}`);
}

export function hasKey(projectHash: string): Promise<boolean> {
    return getKey(projectHash).then(k => k !== null);
}
