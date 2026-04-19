<p align="center">
  <img src="https://img.shields.io/badge/rust-2021-orange?style=flat-square&logo=rust" alt="Rust 2021" />
  <img src="https://img.shields.io/badge/typescript-5.4-blue?style=flat-square&logo=typescript" alt="TypeScript" />
  <img src="https://img.shields.io/badge/version-0.3.1-blue?style=flat-square" alt="Version" />
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey?style=flat-square" alt="Platform" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License" />
  <img src="https://img.shields.io/badge/encryption-AES--256--GCM-blueviolet?style=flat-square" alt="AES-256-GCM" />
</p>

<h1 align="center">Cloak</h1>

<h3 align="center">Protect .env secrets from AI coding agents</h3>
<p align="center">
  <em>AI agents see sandbox values. You see the real ones. Your app runs with real credentials.</em>
</p>

---

> **Early Software Notice:** Cloak is in active development (v0.3.1). It works end-to-end on macOS and has been tested on Linux. Windows support is functional but less tested. Start with a non-critical project to verify it works for your setup before protecting production secrets. Please [report bugs](https://github.com/danieltamas/cloak/issues) — your feedback helps make Cloak rock-solid across all platforms.

---

## The Problem

You're using Claude Code, Cursor, Copilot, or Codex. These agents read your entire project to build context. That includes your `.env` file — with your Stripe live keys, database passwords, JWT secrets, private keys, and wallet mnemonics. All in plaintext. All on disk. All sent to AI providers as part of every API request.

`.gitignore` keeps secrets out of git. It does nothing for local file access. If an agent can `cat .env`, it can see everything.

**Cloak fixes this.**

## What Cloak Does

Cloak encrypts your real credentials and replaces them with structurally valid sandbox values on disk. The VS Code / Cursor / Windsurf extension decrypts and shows real values in your editor. Your app gets real values at runtime via environment variable injection.

```
  .env on disk (what agents read)        Your editor (what you see)
  ---------------------------------      ---------------------------------
  # Stripe                               # Stripe
  STRIPE_KEY=sk_test_cloak_sandbox_000   STRIPE_KEY=sk_live_4eC39HqLyjWDar...

  # Database                             # Database
  DATABASE_URL=postgres://dev:dev@       DATABASE_URL=postgres://admin:s3cret
    localhost:5432/devdb                    @db.example.com:5432/myapp_prod

  # WAM                                  # WAM
  WAM_API_KEY=cloak_sandbox_api_key_00   WAM_API_KEY=wam_live_k8xPq2mNvR7b...
  WAM_SECRET=cloak_sandbox_token_00      WAM_SECRET=wam_sec_Yx3kF7nQ2pR8m...

  # Non-secrets (unchanged)              # Non-secrets (unchanged)
  NODE_ENV=production                    NODE_ENV=production
  PORT=3000                              PORT=3000
```

- **Encrypted vault** — secrets stored in AES-256-GCM encrypted binary vault
- **OS keychain** — encryption keys in macOS Keychain, libsecret, or Windows Credential Manager
- **Authentication gate** — Touch ID on macOS, CLI password on all platforms. AI agents can't bypass.
- **Smart sandbox values** — structurally valid fakes (`sk_test_*` for Stripe, `postgres://dev:dev@localhost` for databases)
- **Recovery system** — human-readable recovery key, shown once, restores access from any machine
- **Zero network calls** — fully local, no cloud, no accounts, no telemetry

## Install

**VS Code / Cursor / Windsurf / any VS Code fork:**

Install "Cloak" from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=danieltamas.cloak). Same extension works in all VS Code forks.

**CLI (terminal-only / Claude Code users):**

macOS / Linux:
```bash
curl -fsSL https://getcloak.dev/install.sh | sh
```

Windows (PowerShell):
```powershell
irm https://getcloak.dev/install.ps1 | iex
```

**Build from source:**

```bash
git clone https://github.com/danieltamas/cloak.git
cd cloak/cli
cargo build --release
```

**Requirements:** Rust toolchain for CLI. Node.js for extension development. macOS: Xcode Command Line Tools for Touch ID (optional — falls back to password). No runtime dependencies.

## Quick Start

```bash
# Protect your project
cloak init

# Cloak scans .env, finds secrets, encrypts them, writes sandbox to disk
# Shows a recovery key — save it in your password manager
# Sets a CLI access password (prevents AI agents from reading secrets)

# Run your app with real env vars (Touch ID or password required)
cloak run npm start

# Edit secrets in your terminal editor
cloak edit

# Check protection status (no auth needed)
cloak status
```

In VS Code / Cursor: open a `.env` file — you see real values. Save — sandbox goes to disk, vault is updated. No workflow change, no prompts.

## Authentication

Cloak's security model has two layers: encryption (vault) and authentication (human proof). Without auth, an AI agent with terminal access could just run `cloak peek` and read your secrets.

### CLI Authentication Flow

```
cloak peek / run / edit / reveal / set / unprotect
  │
  ├─ macOS: Touch ID prompt (via LocalAuthentication framework)
  │    ├─ Fingerprint recognized → access granted
  │    ├─ Touch ID unavailable (SSH, old hardware) → password prompt
  │    └─ Cancelled → access denied
  │
  ├─ Linux / Windows: CLI password prompt
  │    ├─ Correct password → access granted
  │    └─ Wrong password → access denied
  │
  └─ No TTY (CI, piped input) → access denied with clear error
```

**Commands requiring auth:** `peek`, `run`, `edit`, `reveal`, `set`, `unprotect`

**Commands that skip auth:** `init`, `status`, `recover`, `update`

### VS Code Extension Flow

```
Open .env file in editor
  │
  └─ Extension decrypts vault automatically → real values in editor buffer
     (No prompt. Disk always has sandbox values. AI agents read from disk.)

Open Cloak Terminal (real env vars)
  │
  └─ Modal confirmation dialog → must click "Open Terminal"
     (AI agents cannot interact with VS Code modal dialogs.)
```

### Password Setup

During `cloak init`, after the recovery key step:

```
Set a password for CLI access to your secrets.
This prevents AI agents from using the CLI to read your secrets.

Password: ********
Confirm:  ********

CLI password set.
```

The password is hashed with PBKDF2-SHA256 (100k iterations) and stored in `~/.config/cloak/vaults/<hash>.auth`. The plaintext password is never stored.

### Touch ID on macOS

On macOS with Touch ID hardware, Cloak compiles a small Swift helper binary on first use (~4 seconds, cached at `/tmp/cloak-touchid`). Subsequent auth is instant — just touch the sensor.

If Touch ID is unavailable (SSH session, old Mac, no Xcode CLT), Cloak falls back to the CLI password.

## How It Works

```
Developer's editor                  Disk (.env file)              Vault (~/.config/cloak/)
       │                                  │                              │
       │  Open .env                       │                              │
       ├─────────────────────────────────>│  sandbox values              │
       │                                  │                              │
       │  Extension intercepts            │                              │
       │  Reads vault ──────────────────────────────────────────────────>│ AES-256-GCM
       │  Decrypts <────────────────────────────────────────────────────┤ decrypt
       │  Shows real values in buffer     │                              │
       │                                  │                              │
       │  Save                            │                              │
       │  Extension intercepts            │                              │
       │  Encrypts real values ─────────────────────────────────────────>│ encrypt
       │  Writes sandbox to disk ────────>│  sandbox values              │
       │                                  │                              │
       │                                  │                              │
  AI Agent reads ────────────────────────>│  sees sandbox only           │
       │                                  │                              │
  AI Agent runs `cloak peek` ────────────>│  Touch ID / password gate    │
                                          │  (cannot authenticate)       │
```

No plaintext secrets ever exist on disk outside the vault. No temp files, no backups, no recovery dumps.

## CLI Commands

```bash
cloak init                        # Detect secrets, encrypt, write sandbox, show recovery key, set password
cloak edit                        # Open real values in $EDITOR, re-encrypt on save (auth required)
cloak run <command>               # Run command with real env vars injected (auth required)
cloak peek                        # Compare sandbox vs real values side-by-side (auth required)
cloak set KEY VALUE               # Add or update a secret (auth required)
cloak reveal KEY --duration 30    # Temporarily show real value on disk, auto-revert (auth required)
cloak unprotect                   # Restore original .env, delete vault (auth required)
cloak status                      # Show protection state (no auth)
cloak recover                     # Restore keychain key from recovery key (no auth)
cloak update                      # Self-update from GitHub releases (no auth)
```

## Agent Skill File

Drop `SKILL.md` into your project to make your AI agent security-aware:

```bash
curl -fsSL https://getcloak.dev/SKILL.md > SKILL.md
```

The skill file instructs agents to:
- Check for `.cloak` marker before accessing `.env`
- Use `cloak run` instead of reading secrets directly
- Use `cloak set` to add secrets
- Suggest `cloak init` if unprotected (with consent)
- Never access vault or recovery files

Works with `CLAUDE.md`, `.cursorrules`, `.windsurfrules`, or any agent config.

## Secret Detection

Cloak detects secrets by key name and value pattern:

| Pattern | Examples |
|---------|----------|
| Database URLs | `DATABASE_URL`, `MONGO_URI`, `REDIS_URL` |
| Stripe keys | `STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY` |
| AWS credentials | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
| Auth secrets | `JWT_SECRET`, `SESSION_SECRET` |
| API keys | `SENDGRID_API_KEY`, `OPENAI_API_KEY` |
| Passwords | `DB_PASSWORD`, `ADMIN_PASS` |
| Tokens | `GITHUB_TOKEN`, `SLACK_BOT_TOKEN` |
| Private keys | `PRIVATE_KEY`, `WALLET_KEY` |
| High entropy | Shannon entropy > 4.5, length > 20 |

Non-secrets like `NODE_ENV`, `PORT`, `HOST`, `DEBUG`, `LOG_LEVEL` are left unchanged.

## Security Model

- **AES-256-GCM encryption** — vault files use authenticated encryption with random IVs
- **OS keychain storage** — encryption keys never written to disk as plaintext
- **Authentication gate** — Touch ID (macOS) or PBKDF2-hashed password before any secret-revealing CLI command
- **PBKDF2-SHA256 recovery** — 100,000 iterations, recovery key shown once during init
- **Non-interactive rejection** — CLI refuses to reveal secrets when no TTY is available (blocks piped/scripted access)
- **VS Code modal gate** — terminal with real env vars requires clicking through a modal dialog (AI agents can't)
- **Zero network calls** — no telemetry, no cloud, no analytics. Only `cloak update` optionally checks GitHub
- **Atomic writes** — write-to-temp-then-rename prevents corruption on interruption
- **Secure deletion** — temp files overwritten with zeros before removal, `/dev/shm` on Linux
- **Fail toward visibility** — decrypt failure shows sandbox with warning, encrypt failure saves real values. Temporary leak beats permanent data loss

### Threat Model

| Threat | Protection |
|--------|------------|
| AI agent reads `.env` from disk | Sees sandbox values only |
| AI agent runs `cloak peek` in terminal | Touch ID or password required (can't authenticate) |
| AI agent opens VS Code terminal with real env | Modal dialog required (can't click UI) |
| AI agent reads vault file directly | AES-256-GCM encrypted, key in OS keychain |
| Lost laptop / stolen disk | Vault encrypted, key in OS keychain (hardware-protected on macOS) |
| Lost keychain access | Recovery key restores access |
| Lost recovery key AND keychain | Re-enter credentials, run `cloak init` again |
| Compromised AI provider | Only sandbox values in context window |

## Supported Platforms

| Platform | CLI | Extension | Auth Method |
|----------|-----|-----------|-------------|
| macOS (Apple Silicon) | ok | ok | Touch ID + password fallback |
| macOS (Intel x86_64) | ok | ok | Touch ID + password fallback |
| Linux (x86_64, ARM64) | ok | ok | Password |
| Windows (x86_64) | ok | ok | Password |

### Platform Notes

- **macOS**: Touch ID requires Xcode Command Line Tools (`xcode-select --install`). If unavailable, falls back to password. The Touch ID helper is a compiled Swift binary cached at `/tmp/cloak-touchid`.
- **Linux**: Keychain uses D-Bus Secret Service (gnome-keyring or kwallet). Headless Linux without D-Bus needs `cloak recover` to restore keys.
- **Windows**: Keychain uses Windows Credential Manager. File permissions for vault/auth files use default NTFS ACLs (v0.1 limitation).

## Supported Editors

| Editor | Status |
|--------|--------|
| VS Code | ok (extension) |
| Cursor | ok (same extension) |
| Windsurf | ok (same extension) |
| Any VS Code fork | ok (same extension) |
| Terminal (Claude Code) | ok (CLI) |
| JetBrains IDEs | Planned (v0.3) |
| Neovim | Planned (v0.3) |

## Architecture

Two implementations, one contract:

- **CLI** — Rust single binary, cross-platform, ~3MB stripped
- **Extension** — TypeScript, VS Code API + Node crypto built-ins, zero runtime dependencies

Both implement identical encryption, sandbox generation, and env parsing logic independently. The **vault file format** and **recovery file format** are the binary contracts between them. A project protected by the CLI can be used by the extension and vice versa.

```
~/.config/cloak/                          (macOS: ~/Library/Application Support/cloak/)
  vaults/                                 (Windows: %APPDATA%\cloak\)
    <hash>.vault          AES-256-GCM encrypted secrets
    <hash>.recovery       Keychain key encrypted with recovery-derived key
    <hash>.auth           PBKDF2-SHA256 hashed CLI access password

project/
  .env                    Sandbox values (what AI agents read)
  .cloak                  JSON marker: project hash, protected file list
```

### Vault Binary Format

```
Bytes 0-2:    Magic "CLK"
Byte  3:      Version (0x01)
Bytes 4-15:   IV / nonce (12 bytes, random per encryption)
Bytes 16-31:  AES-256-GCM authentication tag (16 bytes)
Bytes 32+:    Ciphertext
```

### Cross-Compatibility

CLI and extension use identical algorithms with verified known-vector tests:
- `projectHash('/Users/test/myproject')` → `7b4d1b0b25658663` (both implementations)
- `PBKDF2-SHA256` with fixed salt → identical 32-byte output (both implementations)
- `deterministicHex('testhash', 'MY_KEY', 20)` → `a07404faa6392b60de34` (both implementations)

128 TypeScript tests + 94 Rust tests, including 33 cross-compatibility tests with fixed known vectors.

## FAQ

**How is this different from .gitignore?**
`.gitignore` prevents git commits. It does nothing for local file access. Agents read from disk, not from git.

**How is this different from Vault / Infisical / Doppler?**
Those are team secret managers for production. Cloak is workstation-level protection. No servers, no accounts. Use both.

**What if I lose my recovery key?**
If you lose both keychain access and recovery key, you can't decrypt the vault. But nothing is destroyed — re-enter credentials and run `cloak init` again. Save the recovery key in a password manager.

**What if I forget my CLI password?**
Delete the auth file (`~/.config/cloak/vaults/<hash>.auth`) and run `cloak init` again in the project to set a new password. Your vault and recovery key are unaffected.

**Does my app work with sandbox values?**
Sandbox values are structurally valid but won't authenticate. Use `cloak run npm start` for real env vars.

**Can AI agents bypass the auth gate?**
No. Touch ID requires biometric proof. The CLI password requires a TTY (interactive terminal) — piped input and scripted access are rejected. The VS Code terminal gate requires clicking a modal dialog that AI agents can't interact with.

**Does Cloak send my secrets anywhere?**
No. Zero network calls. Everything is local. No telemetry ever.

## Roadmap

```
v0.2.9 — Core: CLI + extension, .env protection, auth gate (Touch ID + password)
v0.2.9 — Audit logging, git pre-commit hook, Linux file-based keychain fallback
v0.3.0 — Non-.env protection (~/.ssh, ~/.aws, private keys)
v0.4.0 — Web dashboard
v0.5.0 — License system for pro features
v1.0.0 — Stable release
```

## License

MIT License — see [LICENSE](LICENSE) for details.

Copyright (c) 2026 Daniel Tamas <hello@danieltamas.com>

---

<p align="center">
  <strong>Built by <a href="mailto:hello@danieltamas.com">Daniel Tamas</a></strong>
  <br />
  <em>Because your Stripe key shouldn't be in an AI's context window</em>
</p>

<p align="center">
  <a href="https://getcloak.dev">getcloak.dev</a>
</p>
