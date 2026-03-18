import * as vscode from 'vscode';

export interface WatcherCallbacks {
    onEnvChanged: () => void;
    onCloakChanged: () => void;
}

export function create(context: vscode.ExtensionContext, callbacks: WatcherCallbacks): void {
    // Watch for .env file changes
    const envWatcher = vscode.workspace.createFileSystemWatcher('**/.env*');
    envWatcher.onDidCreate(() => callbacks.onEnvChanged());
    envWatcher.onDidDelete(() => callbacks.onEnvChanged());
    envWatcher.onDidChange(() => callbacks.onEnvChanged());

    // Watch for .cloak marker changes
    const cloakWatcher = vscode.workspace.createFileSystemWatcher('**/.cloak');
    cloakWatcher.onDidCreate(() => callbacks.onCloakChanged());
    cloakWatcher.onDidDelete(() => callbacks.onCloakChanged());
    cloakWatcher.onDidChange(() => callbacks.onCloakChanged());

    context.subscriptions.push(envWatcher, cloakWatcher);
}
