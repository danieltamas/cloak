import * as vscode from 'vscode';
import * as keychain from './keychain';
import * as filemanager from './filemanager';
import * as vault from './vault';
import * as detector from './detector';
import * as envparser from './envparser';
import * as sandbox from './sandbox';
import * as statusbar from './statusbar';
import * as watcher from './watcher';
import * as commands from './commands';
import * as onboarding from './onboarding';
import * as fs from 'fs/promises';
import * as path from 'path';

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * URIs of documents currently being updated programmatically.
 * Used to prevent infinite save loops.
 */
const programmaticEdits = new Set<string>();

/**
 * Returns true if the given document is a cloak-managed .env file.
 * A file is managed if it is listed in the .cloak marker's protected list.
 */
async function isCloakManaged(doc: vscode.TextDocument): Promise<{ managed: boolean; projectRoot: string; relPath: string; marker: filemanager.CloakMarker | null }> {
    const filePath = doc.uri.fsPath;
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) return { managed: false, projectRoot: '', relPath: '', marker: null };

    for (const folder of workspaceFolders) {
        const projectRoot = folder.uri.fsPath;
        if (!filePath.startsWith(projectRoot)) continue;

        const marker = await filemanager.readMarker(projectRoot);
        if (!marker) continue;

        const relPath = path.relative(projectRoot, filePath).replace(/\\/g, '/');
        if (marker.protected.includes(relPath)) {
            return { managed: true, projectRoot, relPath, marker };
        }
    }

    return { managed: false, projectRoot: '', relPath: '', marker: null };
}

/**
 * Get the workspace folder for a given file path.
 */
function getWorkspaceRoot(filePath: string): string | null {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders) return null;
    for (const folder of folders) {
        if (filePath.startsWith(folder.uri.fsPath)) return folder.uri.fsPath;
    }
    return null;
}

/**
 * Replace the entire document content via a WorkspaceEdit without triggering
 * the onWillSaveTextDocument handler.
 */
async function replaceDocumentContent(doc: vscode.TextDocument, newContent: string): Promise<void> {
    const uri = doc.uri.toString();
    programmaticEdits.add(uri);
    try {
        const edit = new vscode.WorkspaceEdit();
        const fullRange = new vscode.Range(
            doc.positionAt(0),
            doc.positionAt(doc.getText().length)
        );
        edit.replace(doc.uri, fullRange, newContent);
        await vscode.workspace.applyEdit(edit);
    } finally {
        programmaticEdits.delete(uri);
    }
}

/**
 * Re-process all open cloak-managed documents (e.g. after init or recover).
 */
export async function refreshDocuments(): Promise<void> {
    for (const doc of vscode.workspace.textDocuments) {
        void onDidOpenTextDocument(doc);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Activation
// ─────────────────────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
    // 1. Initialize keychain with VS Code's SecretStorage
    keychain.init(context.secrets);

    // 2. Create status bar
    statusbar.create(context);

    // 3. Create file watchers
    watcher.create(context, {
        onEnvChanged: () => void refreshStatus(),
        onCloakChanged: () => void refreshStatus(),
    });

    // 4. Initial status check
    void refreshStatus();

    // 5. Safety check on activation
    void runActivationCheck(context);

    // 6. Register document handlers
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(onDidOpenTextDocument),
        vscode.workspace.onWillSaveTextDocument(onWillSaveTextDocument),
        vscode.workspace.onDidSaveTextDocument(onDidSaveTextDocument),
    );

    // 7. Register commands via commands module
    const helpers: commands.CommandHelpers = {
        isCloakManaged,
        getWorkspaceRoot,
        refreshDocuments,
        refreshStatus,
    };
    commands.register(context, helpers);

    // 8. Check already-open documents
    for (const doc of vscode.workspace.textDocuments) {
        void onDidOpenTextDocument(doc);
    }
}

export function deactivate(): void {}

// ─────────────────────────────────────────────────────────────────────────────
// Status bar refresh
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Checks the current workspace state and updates the status bar accordingly.
 * - .cloak marker present → protected (shows secret count)
 * - No marker but .env exists → unprotected (warning)
 * - Neither → hidden
 */
async function refreshStatus(): Promise<void> {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders) {
        statusbar.update('hidden');
        return;
    }

    for (const folder of folders) {
        const projectRoot = folder.uri.fsPath;
        const marker = await filemanager.readMarker(projectRoot);

        if (marker) {
            // Count total secrets across all protected files
            const key = await keychain.getKey(marker.projectHash);
            let secretCount = 0;

            if (key) {
                for (const relPath of marker.protected) {
                    try {
                        const realContent = await filemanager.readReal(projectRoot, relPath, key);
                        const lines = envparser.parse(realContent);
                        secretCount += lines.filter(
                            line => line.type === 'assignment' && detector.detect(line.key, line.value).isSecret
                        ).length;
                    } catch { /* vault unreadable — skip */ }
                }
            } else {
                // Key missing — still show as protected but count from marker
                secretCount = marker.protected.length;
            }

            statusbar.update('protected', secretCount);
            return;
        }

        // No marker — check for .env files
        const envCandidates = ['.env', '.env.local', '.env.production'];
        for (const candidate of envCandidates) {
            const envPath = path.join(projectRoot, candidate);
            try {
                await fs.access(envPath);
                statusbar.update('unprotected');
                return;
            } catch { /* not found */ }
        }
    }

    statusbar.update('hidden');
}

// ─────────────────────────────────────────────────────────────────────────────
// Activation safety check
// ─────────────────────────────────────────────────────────────────────────────

async function runActivationCheck(context: vscode.ExtensionContext): Promise<void> {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders) return;

    for (const folder of folders) {
        const projectRoot = folder.uri.fsPath;
        const marker = await filemanager.readMarker(projectRoot);

        if (marker) {
            // .cloak marker exists → check vault and keychain
            try {
                const vPath = await filemanager.vaultFilePath(projectRoot);
                await fs.access(vPath);
            } catch {
                // Vault missing
                void vscode.window.showWarningMessage(
                    'Cloak: Vault file is missing. Your .env may be unprotected.',
                );
                continue;
            }

            // Vault exists → check keychain
            const key = await keychain.getKey(marker.projectHash);
            if (!key) {
                const choice = await vscode.window.showWarningMessage(
                    'Cloak: Keychain key is missing for this project.',
                    'Recover',
                    'Dismiss',
                );
                if (choice === 'Recover') {
                    void vscode.commands.executeCommand('cloak.recover');
                }
            }
            // Normal operation — all good
        } else {
            // No .cloak marker → scan for .env files and prompt onboarding
            await onboarding.promptIfNeeded(projectRoot, context.workspaceState);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Document event handlers
// ─────────────────────────────────────────────────────────────────────────────

async function onDidOpenTextDocument(doc: vscode.TextDocument): Promise<void> {
    if (programmaticEdits.has(doc.uri.toString())) return;

    const { managed, projectRoot, relPath, marker } = await isCloakManaged(doc);
    if (!managed || !marker) return;

    const key = await keychain.getKey(marker.projectHash);
    if (!key) {
        void vscode.window.showWarningMessage(
            'Cloak: Cannot decrypt vault — keychain key missing. Showing sandbox values.',
            'Recover',
        ).then(choice => {
            if (choice === 'Recover') {
                void vscode.commands.executeCommand('cloak.recover');
            }
        });
        return;
    }

    let realContent: string;
    try {
        realContent = await filemanager.readReal(projectRoot, relPath, key);
    } catch (err) {
        void vscode.window.showWarningMessage(
            `Cloak: Decryption failed — showing sandbox values. (${String(err)})`,
        );
        return;
    }

    await replaceDocumentContent(doc, realContent);
}

function onWillSaveTextDocument(event: vscode.TextDocumentWillSaveEvent): void {
    const uri = event.document.uri.toString();
    if (programmaticEdits.has(uri)) return;

    // Use waitUntil to encrypt the vault before VS Code writes to disk.
    // We let real values save to disk (so buffer = disk = not dirty),
    // then immediately overwrite with sandbox in onDidSaveTextDocument.
    event.waitUntil(handleWillSave(event.document));
}

async function handleWillSave(doc: vscode.TextDocument): Promise<vscode.TextEdit[]> {
    const { managed, projectRoot, relPath, marker } = await isCloakManaged(doc);
    if (!managed || !marker) return [];

    const key = await keychain.getKey(marker.projectHash);
    if (!key) {
        void vscode.window.showErrorMessage(
            'Cloak: Keychain key missing — real values will be written to disk!',
        );
        return [];
    }

    const realContent = doc.getText();

    try {
        // Encrypt to vault (before disk write, so vault is always up to date)
        const vaultBytes = vault.encrypt(realContent, key);
        const vPath = await filemanager.vaultFilePath(projectRoot);
        await fs.writeFile(vPath + '.tmp', vaultBytes);
        await fs.rename(vPath + '.tmp', vPath);
    } catch (err) {
        void vscode.window.showErrorMessage(
            `Cloak: Encryption failed — real values will be written to disk! (${String(err)})`,
        );
    }

    // Return NO edits — let VS Code write real values to disk.
    // This keeps buffer = disk, so no dirty indicator.
    // We overwrite with sandbox in onDidSaveTextDocument.
    return [];
}

async function onDidSaveTextDocument(doc: vscode.TextDocument): Promise<void> {
    if (programmaticEdits.has(doc.uri.toString())) return;

    const { managed, projectRoot, relPath, marker } = await isCloakManaged(doc);
    if (!managed || !marker) return;

    const key = await keychain.getKey(marker.projectHash);
    if (!key) return;

    // Generate sandbox and overwrite the file on disk (outside VS Code's awareness).
    // VS Code still thinks the file matches the buffer (real values) — no dirty dot.
    // External readers (AI agents, cat, etc.) see sandbox values.
    try {
        const realContent = doc.getText();
        const projectHash = vault.projectHash(projectRoot);
        const sandboxContent = sandbox.sandboxEnv(realContent, projectHash);
        const filePath = path.join(projectRoot, relPath);
        await fs.writeFile(filePath, sandboxContent);
    } catch (err) {
        void vscode.window.showErrorMessage(
            `Cloak: Failed to write sandbox values to disk. (${String(err)})`,
        );
    }
}
