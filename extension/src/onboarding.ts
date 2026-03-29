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

    const envFiles = await findEnvFiles(projectRoot);

    for (const envPath of envFiles) {
        try {
            const content = await fs.readFile(envPath, 'utf8');
            const lines = envparser.parse(content);
            const secretCount = lines.filter(
                line => line.type === 'assignment' && detector.detect(line.key, line.value).isSecret
            ).length;

            if (secretCount > 0) {
                const relPath = path.relative(projectRoot, envPath);
                const choice = await vscode.window.showInformationMessage(
                    `Cloak detected ${secretCount} secret${secretCount !== 1 ? 's' : ''} in ${relPath}. Protect them?`,
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

const SKIP_DIRS = new Set(['.git', '.claude', 'node_modules', 'dist', 'build', '.next', '.nuxt', '__pycache__', 'target', 'vendor']);
const ENV_NAMES = new Set(['.env', '.env.local', '.env.production']);

async function findEnvFiles(rootDir: string, depth = 0): Promise<string[]> {
    if (depth > 5) return [];
    const results: string[] = [];
    try {
        const entries = await fs.readdir(rootDir, { withFileTypes: true });
        for (const entry of entries) {
            if (entry.isFile() && ENV_NAMES.has(entry.name)) {
                results.push(path.join(rootDir, entry.name));
            } else if (entry.isDirectory() && !SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
                results.push(...await findEnvFiles(path.join(rootDir, entry.name), depth + 1));
            }
        }
    } catch { /* unreadable dir */ }
    return results;
}
