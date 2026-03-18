import * as vscode from 'vscode';

let secretStorage: vscode.SecretStorage;

export function init(storage: vscode.SecretStorage): void {
    secretStorage = storage;
}

export async function storeKey(projectHash: string, key: Buffer): Promise<void> {
    await secretStorage.store(`cloak-vault-${projectHash}`, key.toString('hex'));
}

export async function getKey(projectHash: string): Promise<Buffer | null> {
    const hex = await secretStorage.get(`cloak-vault-${projectHash}`);
    if (!hex) return null;
    return Buffer.from(hex, 'hex');
}

export async function deleteKey(projectHash: string): Promise<void> {
    await secretStorage.delete(`cloak-vault-${projectHash}`);
}
