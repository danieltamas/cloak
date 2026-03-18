import * as vscode from 'vscode';

let statusBarItem: vscode.StatusBarItem;

// ── Sponsor rotation ────────────────────────────────────────────────────────

const SPONSOR_URL = 'https://dani.fkey.id';
const SPONSOR_INTERVAL_MS = 5 * 60 * 1000;   // every 5 minutes
const SPONSOR_DISPLAY_MS  = 8 * 1000;         // show for 8 seconds

const SPONSOR_MESSAGES = [
    'Buy me a mass spectrometer from 1987',
    'Buy me a used roomba with trust issues',
    'Buy me a nokia 3310 (emotional support)',
    'Buy me an industrial cheese wheel',
    'Buy me a bluetooth ouija board',
    'Buy me a fog machine for standup',
    'Buy me a vintage 56k modem',
    'Buy me a taxidermied squirrel in business casual',
    'Buy me a broken laptop from a philosopher',
    'Buy me a typewriter so I can feel things',
    'Buy me 1000 yards of bubble wrap (therapeutic)',
    'Buy me a decommissioned stop sign',
    'Buy me a bag of resistors I\'ll never use',
];

let sponsorTimer: ReturnType<typeof setInterval> | undefined;
let revertTimer: ReturnType<typeof setTimeout> | undefined;
let currentState: 'protected' | 'unprotected' | 'hidden' = 'hidden';
let currentSecretCount = 0;
let showingSponsor = false;

function startSponsorRotation(context: vscode.ExtensionContext): void {
    if (sponsorTimer) return;

    sponsorTimer = setInterval(() => {
        if (currentState !== 'protected' || !statusBarItem) return;

        const idx = Math.floor(Math.random() * SPONSOR_MESSAGES.length);
        const msg = SPONSOR_MESSAGES[idx];

        showingSponsor = true;
        statusBarItem.text = `$(heart) ${msg}`;
        statusBarItem.tooltip = 'Support Cloak development — click to sponsor';
        statusBarItem.command = 'cloak.openSponsor';

        revertTimer = setTimeout(() => {
            showingSponsor = false;
            update(currentState, currentSecretCount);
        }, SPONSOR_DISPLAY_MS);
    }, SPONSOR_INTERVAL_MS);

    context.subscriptions.push({ dispose: () => {
        if (sponsorTimer) clearInterval(sponsorTimer);
        if (revertTimer) clearTimeout(revertTimer);
    }});
}

// ── Public API ──────────────────────────────────────────────────────────────

export function create(context: vscode.ExtensionContext): vscode.StatusBarItem {
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'cloak.init';
    context.subscriptions.push(statusBarItem);

    // Register sponsor command
    context.subscriptions.push(
        vscode.commands.registerCommand('cloak.openSponsor', () => {
            vscode.env.openExternal(vscode.Uri.parse(SPONSOR_URL));
        })
    );

    startSponsorRotation(context);

    return statusBarItem;
}

export function update(state: 'protected' | 'unprotected' | 'hidden', secretCount?: number): void {
    if (!statusBarItem) return;

    currentState = state;
    currentSecretCount = secretCount ?? 0;

    // Don't interrupt sponsor message
    if (showingSponsor) return;

    switch (state) {
        case 'protected':
            statusBarItem.text = `$(lock) Cloak: ${currentSecretCount} secret${currentSecretCount !== 1 ? 's' : ''}`;
            statusBarItem.tooltip = 'Cloak is protecting your secrets';
            statusBarItem.command = 'cloak.init';
            statusBarItem.backgroundColor = undefined;
            statusBarItem.show();
            break;
        case 'unprotected':
            statusBarItem.text = '$(warning) .env unprotected';
            statusBarItem.tooltip = 'Click to protect your .env secrets';
            statusBarItem.command = 'cloak.init';
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
            statusBarItem.show();
            break;
        case 'hidden':
            statusBarItem.hide();
            break;
    }
}
