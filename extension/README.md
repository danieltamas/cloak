# Cloak — Protect .env from AI Agents

AI agents see sandbox credentials. You see the real ones. Your app runs with real credentials.

> **Early Software Notice:** Cloak is in active development (v0.3.1). Start with a non-critical project to verify it works for your setup. Please [report bugs](https://github.com/danieltamas/cloak/issues) — your feedback helps make Cloak rock-solid.

## The Problem

Claude Code, Cursor, Copilot, and Codex read your `.env` file — your Stripe keys, database passwords, JWT secrets — all sent to AI providers as context. `.gitignore` doesn't help. If an agent can read the file, it sees everything.

## How Cloak Works

Cloak encrypts your secrets and replaces them with structurally valid sandbox values **on disk**. The extension decrypts them in your editor buffer. You see real values. AI agents see fakes.

```
.env on disk (what AI reads)             Your editor (what you see)
────────────────────────────             ────────────────────────────
STRIPE_KEY=sk_test_cloak_sandbox_000     STRIPE_KEY=sk_live_4eC39HqLyjWDar...
DATABASE_URL=postgres://dev:dev@local    DATABASE_URL=postgres://admin:s3cret@prod
NODE_ENV=production                      NODE_ENV=production  (unchanged)
```

## Getting Started

1. Open a project with a `.env` file
2. Command Palette → **Cloak: Protect Secrets**
3. Save the recovery key when prompted
4. Done — your editor shows real values, disk has sandbox values

## Features

- **Auto-decrypt in editor** — open `.env`, see real values instantly. No extra steps.
- **Auto-encrypt on save** — save the file, sandbox goes to disk, vault is updated.
- **AES-256-GCM encryption** — secrets stored in an encrypted binary vault.
- **OS keychain integration** — encryption key stored in macOS Keychain, libsecret, or Windows Credential Manager.
- **Smart sandbox values** — structurally valid fakes: `sk_test_*` for Stripe, `postgres://dev:dev@localhost` for databases.
- **Recovery key** — human-readable key shown once during init. Restores access from any machine.
- **Terminal gate** — opening a terminal with real env vars requires clicking through a confirmation dialog (AI agents can't).
- **Zero network calls** — fully local, no cloud, no accounts, no telemetry.

## Commands

| Command | Description |
|---------|-------------|
| **Cloak: Protect Secrets** | Initialize protection for the current `.env` file |
| **Cloak: Peek at Real Values** | Side-by-side diff of sandbox vs real values |
| **Cloak: Open Terminal with Real Env** | Terminal with real env vars (confirmation required) |
| **Cloak: Remove Protection** | Restore real values to disk, delete vault |
| **Cloak: Recover from Lost Keychain** | Restore access using your recovery key |

## Status Bar

- 🔒 **Cloak: N secrets** — protected, N secrets encrypted
- ⚠️ **.env unprotected** — `.env` file found but not yet protected

## CLI Companion

For terminal-only workflows (Claude Code, SSH):

```bash
curl -fsSL https://getcloak.dev/install.sh | sh
```

The CLI and extension are fully compatible — protect with one, use with the other.

## Security

- AES-256-GCM authenticated encryption with random IVs
- Keys in OS keychain, never on disk as plaintext
- PBKDF2-SHA256 recovery (100k iterations)
- No temp files, no backups, no network calls
- Terminal with real env vars requires modal confirmation

## Requirements

- VS Code 1.85.0 or later (works in Cursor, Windsurf, any VS Code fork)
- No runtime dependencies

## Links

- [Documentation](https://getcloak.dev)
- [GitHub](https://github.com/danieltamas/cloak)
- [Report an Issue](https://github.com/danieltamas/cloak/issues)

## Support Cloak

Cloak is free and open source. If it saves your secrets (and your sanity), consider supporting development:

[Sponsor on fkey.id](https://dani.fkey.id)

## License

MIT — Copyright (c) 2026 Daniel Tamas
