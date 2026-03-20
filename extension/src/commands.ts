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
        vscode.commands.registerCommand('cloak.init', () => cmdInit(helpers)),
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
 * cloak.init — Onboarding flow: generate key, recovery key, protect file.
 */
async function cmdInit(helpers: CommandHelpers): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    const folders = vscode.workspace.workspaceFolders;

    if (!folders) {
        void vscode.window.showErrorMessage('Cloak: No workspace folder open.');
        return;
    }

    // Determine the target file
    let targetUri: vscode.Uri | undefined;
    if (editor && editor.document.fileName.endsWith('.env')) {
        targetUri = editor.document.uri;
    } else {
        // Ask user to pick an .env file
        const picked = await vscode.window.showOpenDialog({
            canSelectFiles: true,
            canSelectFolders: false,
            canSelectMany: false,
            filters: { 'Env files': ['env'] },
            openLabel: 'Protect this file',
        });
        targetUri = picked?.[0];
    }

    if (!targetUri) {
        void vscode.window.showInformationMessage('Cloak: No file selected.');
        return;
    }

    const projectRoot = helpers.getWorkspaceRoot(targetUri.fsPath);
    if (!projectRoot) {
        void vscode.window.showErrorMessage('Cloak: File is not in any workspace folder.');
        return;
    }

    const relPath = path.relative(projectRoot, targetUri.fsPath).replace(/\\/g, '/');

    // Check if already protected
    const existingMarker = await filemanager.readMarker(projectRoot);
    if (existingMarker?.protected.includes(relPath)) {
        void vscode.window.showInformationMessage(`Cloak: ${relPath} is already protected.`);
        return;
    }

    // Generate encryption key
    const key = crypto.randomBytes(32);
    const projectHash = vault.projectHash(projectRoot);

    // Generate recovery key
    const { display: recoveryDisplay, bytes: recoveryBytes } = recovery.generateRecoveryKey();

    // Show recovery key to user — must be acknowledged
    const confirmed = await vscode.window.showInformationMessage(
        `Cloak: Save your recovery key — it cannot be recovered if lost!\n\n${recoveryDisplay}`,
        { modal: true },
        'I have saved my recovery key',
    );

    if (confirmed !== 'I have saved my recovery key') return;

    // Copy recovery key to clipboard after user confirms
    await vscode.env.clipboard.writeText(recoveryDisplay);
    vscode.window.showInformationMessage('Recovery key copied to clipboard.');

    try {
        const result = await filemanager.protectFile(projectRoot, relPath, key, recoveryBytes);

        if (result.secretCount === 0) {
            void vscode.window.showInformationMessage(
                `Cloak: No secrets detected in ${relPath}. Nothing to protect.`,
            );
            return;
        }

        // Store key in keychain
        await keychain.storeKey(projectHash, key);

        if (result.alreadyProtected) {
            void vscode.window.showInformationMessage(
                `Cloak: ${relPath} was already protected. Vault has been updated.`,
            );
        } else {
            void vscode.window.showInformationMessage(
                `Cloak: Protected ${result.secretCount} secret(s) in ${relPath}.`,
            );
        }

        // Refresh open editors and status
        await helpers.refreshDocuments();
        await helpers.refreshStatus();
    } catch (err) {
        void vscode.window.showErrorMessage(`Cloak: Failed to protect file. ${String(err)}`);
    }
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

    // Find the first protected .env file in the workspace
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

        const relPath = marker.protected[0];
        let realContent: string;
        try {
            realContent = await filemanager.readReal(projectRoot, relPath, key);
        } catch (err) {
            void vscode.window.showErrorMessage(`Cloak: Cannot read vault. ${String(err)}`);
            return;
        }

        // Parse real env vars
        const lines = envparser.parse(realContent);
        const envVars: Record<string, string> = {};
        for (const line of lines) {
            if (line.type === 'assignment') {
                envVars[line.key] = line.value;
            }
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
