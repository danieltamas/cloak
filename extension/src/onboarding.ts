import * as vscode from 'vscode';
import * as envparser from './envparser';
import * as detector from './detector';
import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * Check for unprotected .env files and prompt the user.
 * Respects "Don't Ask Again" via workspaceState.
 */
export async function promptIfNeeded(
    projectRoot: string,
    workspaceState: vscode.Memento,
): Promise<void> {
    // Check "Don't Ask Again" flag
    const dismissed = workspaceState.get<boolean>('cloak.onboardingDismissed', false);
    if (dismissed) return;

    const envCandidates = ['.env', '.env.local', '.env.production'];
    for (const candidate of envCandidates) {
        const envPath = path.join(projectRoot, candidate);
        try {
            const content = await fs.readFile(envPath, 'utf8');
            const lines = envparser.parse(content);
            const secretCount = lines.filter(
                line => line.type === 'assignment' && detector.detect(line.key, line.value).isSecret
            ).length;

            if (secretCount > 0) {
                const choice = await vscode.window.showInformationMessage(
                    `Cloak detected ${secretCount} secret${secretCount !== 1 ? 's' : ''} in ${candidate}. Protect them?`,
                    'Protect Now',
                    'Not Now',
                    "Don't Ask Again",
                );

                if (choice === 'Protect Now') {
                    void vscode.commands.executeCommand('cloak.init');
                } else if (choice === "Don't Ask Again") {
                    await workspaceState.update('cloak.onboardingDismissed', true);
                }
                return; // Only prompt once per workspace
            }
        } catch { /* file not found */ }
    }
}
