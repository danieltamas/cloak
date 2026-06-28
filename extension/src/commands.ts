import * as vscode from 'vscode';
import * as keychain from './keychain';
import * as filemanager from './filemanager';
import * as vault from './vault';
import * as recovery from './recovery';
import * as envparser from './envparser';
import * as sandbox from './sandbox';
import * as fs from 'fs/promises';
import * as path from 'path';
import crypto from 'crypto';

// ─────────────────────────────────────────────────────────────────────────────
// Helpers interface
// ─────────────────────────────────────────────────────────────────────────────

export interface CommandHelpers {
    isCloakManaged: (doc: vscode.TextDocument) => Promise<{
        managed: boolean;
        projectRoot: string;
        relPath: string;
        marker: filemanager.CloakMarker | null;
    }>;
    getWorkspaceRoot: (filePath: string) => string | null;
    refreshDocuments: () => Promise<void>;
    refreshStatus: () => Promise<void>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Register all commands
// ─────────────────────────────────────────────────────────────────────────────

export function register(context: vscode.ExtensionContext, helpers: CommandHelpers): void {
    context.subscriptions.push(
        vscode.commands.registerCommand('cloak.init', (presetRoot?: string) => cmdInit(helpers, presetRoot)),
        vscode.commands.registerCommand('cloak.peek', () => cmdPeek(helpers)),
        vscode.commands.registerCommand('cloak.unprotect', () => cmdUnprotect(helpers)),
        vscode.commands.registerCommand('cloak.openCloakTerminal', () => cmdOpenCloakTerminal()),
        vscode.commands.registerCommand('cloak.recover', () => cmdRecover(helpers)),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Command implementations
// ─────────────────────────────────────────────────────────────────────────────

/**
 * cloak.init — Protect every `.env` file with secrets in the workspace folder,
 * including nested ones (e.g. `apps/api/.env`). Mirrors the CLI's recursive
 * `cloak init`: one project key + recovery key, one vault per file.
 *
 * When the project is already protected, the existing key is reused and the
 * recovery file is left untouched — only the newly-discovered files are added.
 *
 * `presetRoot` lets a caller (e.g. the onboarding prompt) pass the project root
 * it already resolved, so the user is never asked to pick a workspace folder.
 */
async function cmdInit(helpers: CommandHelpers, presetRoot?: string): Promise<void> {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
        void vscode.window.showErrorMessage('Cloak: No workspace folder open.');
        return;
    }

    // 1. Resolve the project root to scan (the workspace folder).
    let projectRoot: string;
    const editor = vscode.window.activeTextEditor;
    const activeFolder = editor && vscode.workspace.getWorkspaceFolder(editor.document.uri);
    if (presetRoot) {
        projectRoot = presetRoot;
    } else if (activeFolder) {
        projectRoot = activeFolder.uri.fsPath;
    } else if (folders.length === 1) {
        projectRoot = folders[0].uri.fsPath;
    } else {
        const picked = await vscode.window.showWorkspaceFolderPick({
            placeHolder: 'Select the project to protect',
        });
        if (!picked) return;
        projectRoot = picked.uri.fsPath;
    }

    // 2. Recursively scan for .env files containing secrets.
    const found = await filemanager.findEnvFilesWithSecrets(projectRoot);
    if (found.length === 0) {
        void vscode.window.showInformationMessage('Cloak: No unprotected secrets found in this project.');
        return;
    }

    // 3. Skip files already in the marker.
    const existingMarker = await filemanager.readMarker(projectRoot);
    const alreadyProtected = new Set(existingMarker?.protected ?? []);
    const toProtect = found.filter(f => !alreadyProtected.has(f.relPath));
    if (toProtect.length === 0) {
        void vscode.window.showInformationMessage('Cloak: All .env files with secrets are already protected.');
        return;
    }

    // 4. Confirm the file list with the user.
    const fileList = toProtect
        .map(f => `• ${f.relPath} — ${f.secretCount} secret${f.secretCount === 1 ? '' : 's'}`)
        .join('\n');
    const proceed = await vscode.window.showWarningMessage(
        `Cloak will protect ${toProtect.length} file${toProtect.length === 1 ? '' : 's'}:\n\n${fileList}`,
        { modal: true },
        'Protect',
    );
    if (proceed !== 'Protect') return;

    // 5. Determine the encryption key + whether to seed a recovery file.
    const projectHash = vault.projectHash(projectRoot);
    const existingKey = await keychain.getKey(projectHash);
    let key: Buffer;
    let recoveryBytes: Buffer | null;

    if (existingMarker && existingKey) {
        // Already protected — reuse the project key, leave the recovery file alone.
        key = existingKey;
        recoveryBytes = null;
    } else if (existingMarker && !existingKey) {
        void vscode.window.showErrorMessage(
            'Cloak: This project is protected but its keychain key is missing. Run "Cloak: Recover" first.',
        );
        return;
    } else {
        // Fresh protection — generate a key + recovery key and store the key.
        key = crypto.randomBytes(32);
        const { display: recoveryDisplay, bytes } = recovery.generateRecoveryKey();
        const confirmed = await vscode.window.showInformationMessage(
            `Cloak: Save your recovery key — it cannot be recovered if lost!\n\n${recoveryDisplay}`,
            { modal: true },
            'I have saved my recovery key',
        );
        if (confirmed !== 'I have saved my recovery key') return;
        await vscode.env.clipboard.writeText(recoveryDisplay);
        void vscode.window.showInformationMessage('Recovery key copied to clipboard.');
        await keychain.storeKey(projectHash, key);
        recoveryBytes = bytes;
    }

    // 6. Protect each file (each gets its own vault; the recovery file is written
    //    only on the first call when seeding a fresh key).
    let protectedCount = 0;
    let seededRecovery = recoveryBytes;
    for (const f of toProtect) {
        try {
            const result = await filemanager.protectFile(projectRoot, f.relPath, key, seededRecovery);
            if (result.secretCount > 0) {
                protectedCount++;
                seededRecovery = null; // recovery file is per-project — write it once
            }
        } catch (err) {
            void vscode.window.showErrorMessage(`Cloak: Failed to protect ${f.relPath}. ${String(err)}`);
        }
    }

    // 7. Refresh open editors and status.
    await helpers.refreshDocuments();
    await helpers.refreshStatus();

    void vscode.window.showInformationMessage(
        `Cloak: Protected ${protectedCount} file${protectedCount === 1 ? '' : 's'}.`,
    );
}

/**
 * cloak.peek — Show side-by-side real vs sandbox values.
 */
async function cmdPeek(helpers: CommandHelpers): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        void vscode.window.showErrorMessage('Cloak: No active editor.');
        return;
    }

    const { managed, projectRoot, relPath, marker } = await helpers.isCloakManaged(editor.document);
    if (!managed || !marker) {
        void vscode.window.showInformationMessage('Cloak: This file is not cloak-managed.');
        return;
    }

    const key = await keychain.getKey(marker.projectHash);
    if (!key) {
        void vscode.window.showErrorMessage('Cloak: Keychain key missing. Use Recover to restore.');
        return;
    }

    let realContent: string;
    try {
        realContent = await filemanager.readReal(projectRoot, relPath, key);
    } catch (err) {
        void vscode.window.showErrorMessage(`Cloak: Cannot read vault. ${String(err)}`);
        return;
    }

    // Generate sandbox content for comparison
    const projectHash = vault.projectHash(projectRoot);
    const sandboxContent = sandbox.sandboxEnv(realContent, projectHash);

    // Show real content in a new virtual document vs sandbox
    const realDoc = await vscode.workspace.openTextDocument({
        content: realContent,
        language: 'dotenv',
    });

    const sandboxDoc = await vscode.workspace.openTextDocument({
        content: sandboxContent,
        language: 'dotenv',
    });

    await vscode.commands.executeCommand('vscode.diff', sandboxDoc.uri, realDoc.uri, 'Cloak: Sandbox ↔ Real');
}

/**
 * cloak.unprotect — Remove Cloak protection from the active .env file.
 */
async function cmdUnprotect(helpers: CommandHelpers): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        void vscode.window.showErrorMessage('Cloak: No active editor.');
        return;
    }

    const { managed, projectRoot, relPath, marker } = await helpers.isCloakManaged(editor.document);
    if (!managed || !marker) {
        void vscode.window.showInformationMessage('Cloak: This file is not cloak-managed.');
        return;
    }

    const confirmed = await vscode.window.showWarningMessage(
        `Cloak: Remove protection from ${relPath}? Real values will be written to disk.`,
        { modal: true },
        'Remove Protection',
    );
    if (confirmed !== 'Remove Protection') return;

    const key = await keychain.getKey(marker.projectHash);
    if (!key) {
        void vscode.window.showErrorMessage(
            'Cloak: Keychain key missing. Use Recover before unprotecting.',
        );
        return;
    }

    try {
        await filemanager.unprotectFile(projectRoot, relPath, key);
        await keychain.deleteKey(marker.projectHash);
        void vscode.window.showInformationMessage(
            `Cloak: Protection removed from ${relPath}. Real values restored.`,
        );
        await helpers.refreshStatus();
    } catch (err) {
        void vscode.window.showErrorMessage(`Cloak: Failed to remove protection. ${String(err)}`);
    }
}

/**
 * cloak.openCloakTerminal — Open a terminal with real env vars injected.
 */
async function cmdOpenCloakTerminal(): Promise<void> {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders) {
        void vscode.window.showErrorMessage('Cloak: No workspace folder open.');
        return;
    }

    const confirmed = await vscode.window.showWarningMessage(
        'Cloak: This will open a terminal with real secret values in the environment. Continue?',
        { modal: true },
        'Open Terminal',
    );
    if (confirmed !== 'Open Terminal') return;

    // Find protected .env files in the workspace
    for (const folder of folders) {
        const projectRoot = folder.uri.fsPath;
        const marker = await filemanager.readMarker(projectRoot);
        if (!marker || marker.protected.length === 0) continue;

        const key = await keychain.getKey(marker.projectHash);
        if (!key) {
            void vscode.window.showErrorMessage(
                'Cloak: Keychain key missing. Use Recover to restore.',
            );
            return;
        }

        // Merge real env vars from every protected file. Later files in the
        // marker override earlier ones on key conflict (dotenv-style) — same
        // semantics as `cloak run`.
        const envVars: Record<string, string> = {};
        try {
            for (const relPath of marker.protected) {
                const realContent = await filemanager.readReal(projectRoot, relPath, key);
                for (const line of envparser.parse(realContent)) {
                    if (line.type === 'assignment') {
                        envVars[line.key] = line.value;
                    }
                }
            }
        } catch (err) {
            void vscode.window.showErrorMessage(`Cloak: Cannot read vault. ${String(err)}`);
            return;
        }

        // Open terminal with env vars
        const terminal = vscode.window.createTerminal({
            name: 'Cloak (real env)',
            env: envVars,
            cwd: projectRoot,
        });
        terminal.show();
        return;
    }

    void vscode.window.showInformationMessage('Cloak: No protected .env files found in workspace.');
}

/**
 * cloak.recover — Recover from a lost keychain key using the recovery key.
 */
async function cmdRecover(helpers: CommandHelpers): Promise<void> {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders) {
        void vscode.window.showErrorMessage('Cloak: No workspace folder open.');
        return;
    }

    // Find the project with a .cloak marker
    let projectRoot: string | null = null;
    let marker: filemanager.CloakMarker | null = null;

    for (const folder of folders) {
        const m = await filemanager.readMarker(folder.uri.fsPath);
        if (m) {
            projectRoot = folder.uri.fsPath;
            marker = m;
            break;
        }
    }

    if (!projectRoot || !marker) {
        void vscode.window.showErrorMessage('Cloak: No protected project found.');
        return;
    }

    // Ask for the recovery key
    const input = await vscode.window.showInputBox({
        prompt: 'Enter your Cloak recovery key (format: CLOAK-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX)',
        ignoreFocusOut: true,
        password: false,
        validateInput: value => {
            try {
                recovery.parseRecoveryKey(value);
                return null;
            } catch {
                return 'Invalid recovery key format. Expected: CLOAK-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX';
            }
        },
    });

    if (!input) return;

    let recoveryKeyBytes: Buffer;
    try {
        recoveryKeyBytes = recovery.parseRecoveryKey(input);
    } catch (err) {
        void vscode.window.showErrorMessage(`Cloak: Invalid recovery key. ${String(err)}`);
        return;
    }

    // Read the recovery file
    const rPath = await filemanager.recoveryFilePath(projectRoot);
    let recoveryBytes: Buffer;
    try {
        recoveryBytes = await fs.readFile(rPath);
    } catch {
        void vscode.window.showErrorMessage(
            'Cloak: Recovery file not found. Cannot recover without the recovery file.',
        );
        return;
    }

    // Recover the keychain key
    let restoredKey: Buffer;
    try {
        restoredKey = recovery.recoverKeychainKey(recoveryBytes, recoveryKeyBytes);
    } catch (err) {
        void vscode.window.showErrorMessage(`Cloak: Recovery failed — wrong key? (${String(err)})`);
        return;
    }

    // Store the recovered key in the keychain
    await keychain.storeKey(marker.projectHash, restoredKey);

    void vscode.window.showInformationMessage(
        'Cloak: Recovery successful! Keychain key has been restored.',
    );

    // Refresh any open cloak-managed documents and status
    await helpers.refreshDocuments();
    await helpers.refreshStatus();
}

// Export individual command implementations for testing if needed
export { cmdInit, cmdPeek, cmdUnprotect, cmdOpenCloakTerminal, cmdRecover };
