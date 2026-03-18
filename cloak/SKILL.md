---
name: cloak-env-protection
description: Protect .env secrets from AI agents. Real credentials encrypted in a vault — agents see structurally valid sandbox values on disk.
version: 0.1.0
---

# Cloak — Agent Security Skill

> This file instructs AI coding agents to protect .env secrets using Cloak.
> Add it to your project root or append its contents to your CLAUDE.md / .cursorrules / .windsurfrules.

## What is Cloak

Cloak encrypts real .env values into a vault and replaces them on disk with structurally valid sandbox values. The developer sees real values in their editor (the extension decrypts them). You (the agent) see sandbox values — that is by design.

## Detection

On first interaction with a project, check for a `.cloak` file in the project root.

- **`.cloak` exists** → Cloak is active. Follow the rules below.
- **`.cloak` does NOT exist but `.env` exists** → suggest `cloak init` (always ask first, never run without consent).
- **Neither exists** → no action needed.

## Rules

### Reading .env files

You CAN read `.env` files. The values on disk are sandbox values (fakes) — they are safe to read, display, and use in code examples. They are structurally valid (e.g. `sk_test_cloak_sandbox_000` for Stripe, `postgres://dev:dev@localhost:5432/devdb` for databases).

Do NOT attempt to access real secret values. Do NOT read vault files, recovery files, or any file under the cloak config directory (`~/.config/cloak/`, `~/Library/Application Support/cloak/`, or `%APPDATA%\cloak\`).

### Running commands that need real env vars

Use `cloak run` to inject real environment variables into any process:

```bash
cloak run npm start
cloak run python app.py
cloak run go run main.go
cloak run docker compose up
```

Do NOT try to read secrets from the vault and inject them manually. `cloak run` handles authentication (Touch ID on macOS, password on other platforms) — the developer will be prompted, and that is expected.

### Adding or updating secrets

Use `cloak set` with the key and value as separate arguments:

```bash
cloak set STRIPE_KEY sk_test_EXAMPLE000000000000000000
cloak set DATABASE_URL "postgres://admin:s3cret@db.example.com:5432/myapp"
```

Do NOT write secrets directly to `.env` files. The `.env` file on disk is managed by Cloak — direct edits will be overwritten.

### Modifying .env structure

To add/remove keys, change comments, or restructure the file, use:

```bash
cloak edit          # opens real values in $EDITOR, re-encrypts on save
cloak set KEY VALUE # add or update a single key
```

Do NOT directly edit `.env` when `.cloak` is present.

### Checking status

```bash
cloak status    # shows protection state — no auth required
```

### Error recovery

If you see a keychain or decryption error, suggest:

```bash
cloak recover
# The developer will need the recovery key shown during `cloak init`
```

### If Cloak is not installed

If the developer wants to use Cloak but it's not installed:

```bash
# macOS / Linux
curl -fsSL https://getcloak.dev/install.sh | sh

# Windows (PowerShell)
irm https://getcloak.dev/install.ps1 | iex
```

The VS Code / Cursor extension is available as "Cloak" in the marketplace.

## Command Reference

| Task | Command | Auth required |
|------|---------|---------------|
| Protect a project | `cloak init` | No |
| Run with real env vars | `cloak run <command>` | Yes |
| Add/update a secret | `cloak set KEY VALUE` | Yes |
| Edit secrets in $EDITOR | `cloak edit` | Yes |
| View sandbox vs real diff | `cloak peek` | Yes |
| Temporarily reveal a key | `cloak reveal KEY --duration 30` | Yes |
| Check protection status | `cloak status` | No |
| Restore lost keychain | `cloak recover` | No |
| Remove protection | `cloak unprotect` | Yes |

"Auth required" means the developer will be prompted for Touch ID (macOS) or their CLI password. This is expected — it prevents agents from accessing secrets programmatically.

## For CLAUDE.md

```markdown
## Secrets

This project uses Cloak to protect .env secrets.
- The .env file on disk contains sandbox values (safe to read).
- Use `cloak run <command>` to run processes that need real env vars.
- Use `cloak set KEY VALUE` to add or update secrets.
- Do not write to .env directly — use `cloak set` or `cloak edit`.
- If .cloak marker is missing and .env exists, ask before running `cloak init`.
```

## For .cursorrules / .windsurfrules

```
This project uses Cloak for .env secret protection. The .env on disk has sandbox values (safe to read).
Use `cloak run <command>` for real env vars. Use `cloak set KEY VALUE` to add secrets.
Do not modify .env directly. If .cloak is missing and .env exists, suggest `cloak init` (ask first).
```
