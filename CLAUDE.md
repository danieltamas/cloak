# Cloak — Protect .env secrets from AI coding agents

Cloak encrypts real `.env` credentials into an AES-256-GCM vault and leaves structurally valid **sandbox values** on disk. Editors decrypt transparently; AI agents read only sandbox. Two independent implementations share one binary contract.

- **CLI** — Rust single binary (`cli/`), cross-platform, ~3 MB stripped
- **Extension** — TypeScript VS Code extension (`extension/`), zero runtime deps, same code works in Cursor / Windsurf / any VS Code fork
- **Static site** — `index.html`, `llms.txt`, `SKILL.md`, `install.sh`, `install.ps1` served from `getcloak.dev`

Current version: **0.3.0**. Early software — works end-to-end on macOS, tested on Linux, functional on Windows.

---

## Stack & Layout

| Layer | Technology | Location |
|-------|-----------|----------|
| CLI | Rust 2021, `clap`, `aes-gcm`, `keyring 3`, `pbkdf2`, `rpassword` | `cli/src/` |
| Extension | TypeScript 5.4, VS Code API, Node `crypto` built-ins | `extension/src/` |
| Biometric helper | Swift `LAContext.evaluatePolicy` (compiled on first use) | invoked from CLI, cached at `/tmp/cloak-touchid` |
| Installers | Bash + PowerShell | `install.sh`, `install.ps1` (served from site root) |
| CI | GitHub Actions, 5 build targets + `.vsix` | `.github/workflows/` |
| Docs / site | Plain HTML + Markdown | repo root (`index.html`, `ARCHITECTURE.md`, `SPECS.md`, `SKILL.md`, `llms.txt`) |

### Directory map

```
cli/              Rust crate (bin = cloak). Commands in src/commands/, core in src/{vault,envparser,detector,sandbox,recovery,filemanager,keychain,platform,auth,license}.rs
extension/        VS Code extension. Mirrors the CLI core in TS + commands in src/commands/
scripts/          install.sh, install.ps1
docs/             Superpowers plans/specs (e.g. biometric-keychain)
assets/, cover.png, og-image.jpg    Brand assets
SKILL.md          Agent skill file — shipped to users' projects
llms.txt, ARCHITECTURE.md, SPECS.md, README.md   Canonical docs (kept in sync)
testdata/         Cross-compat known-vector fixtures
```

---

## Core Architecture

Two implementations, one contract. They never share code; they share **two binary file formats** and a handful of algorithmic constants.

```
Editor buffer ─────────────────────────┐
   (real values, via extension)        │        ~/.config/cloak/   (Linux)
                                       │        ~/Library/Application Support/cloak/   (macOS)
   .env on disk ◄── sandbox values ────┤        %APPDATA%\cloak\   (Windows)
   (what AI agents read)               │          vaults/
                                       │            <hash>.vault     AES-256-GCM(secrets)
   cloak run / peek / edit / reveal ───┤            <hash>.recovery  AES-256-GCM(keychain_key) w/ PBKDF2 key
        │                              │            <hash>.auth      PBKDF2-SHA256(password)
        └── Touch ID or password gate ─┘
```

`<hash>` = first 16 hex chars of SHA-256 over the canonicalized forward-slash-normalized project root path. **Identical across CLI and extension** — this is the primary cross-compat anchor.

### Vault binary format (`CLK`)

```
Offset  Size  Field
0       3     Magic "CLK"
3       1     Version 0x01
4       12    IV (random per encryption)
16      16    AES-256-GCM tag
32      N     Ciphertext = UTF-8 .env content
```

### Recovery binary format (`CRK`)

```
0       3     Magic "CRK"
3       1     Version 0x01
4       32    PBKDF2 salt
36      16    IV
52      16    tag
68      32    Ciphertext = 32-byte keychain key
```

Recovery key shown **once** during `init`: `CLOAK-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (96 bits, base36). PBKDF2-SHA256, 100 000 iterations.

### Auth file (JSON)

```json
{ "version": 1, "salt": "<hex 32>", "hash": "<hex 32>", "method": "pbkdf2-sha256", "iterations": 100000 }
```

### Keychain backends

| Platform | Backend | Rust feature |
|----------|---------|--------------|
| macOS | Keychain Services | `apple-native` |
| Linux | D-Bus Secret Service (gnome-keyring / kwallet) | `sync-secret-service` |
| Windows | Credential Manager | `windows-native` |
| VS Code extension | `SecretStorage` API | — |

Service name `cloak`, account `vault-<project_hash>`, key stored as 64-char hex.

### Authentication flow

`peek / run / edit / reveal / set / unprotect` require auth. `init / status / recover / update` do not.

1. No `.auth` file → skip (backwards compat with pre-auth projects).
2. No TTY → reject.
3. macOS with GUI session → spawn `cloak-touchid` Swift helper (`LAContext.evaluatePolicy(.deviceOwnerAuthentication)`). Touch ID first, macOS password fallback. Cancelled → deny. Unavailable (SSH, no Xcode CLT) → fall through.
4. Prompt for CLI password via `rpassword` (hidden), hash with stored salt, compare.

Extension flow: `onDidOpenTextDocument` decrypts buffer-side; `onWillSaveTextDocument` re-encrypts and writes sandbox; `onDidSaveTextDocument` restores real values in the buffer. Opening a "Cloak Terminal" with real env requires a modal dialog — AI agents cannot click it.

---

## God Nodes (core abstractions — touch with care)

From the graphify knowledge graph:

1. `detect()` in `cli/src/detector.rs` — 16 edges. Shared key+value+entropy detector. Mirror is `detectByKey / detectByValue / detectByValueOverride` in `extension/src/detector.ts`.
2. `setup_project()` in filemanager tests — fixture helper used by every integration test.
3. `key_a()` / `key_b()` / `test_key()` / `test_recovery_bytes()` — known-vector fixtures for cross-compat tests.
4. `Architecture Overview` (ARCHITECTURE.md) — cross-community bridge. **Update it when core formats or flows change.**
5. `activateInternal()` in `extension/src/extension.ts` — main extension activation path.
6. `parse()` in `cli/src/envparser.rs` — env line parser (quoting, comments, line continuations). TS mirror: `parse()` in `extension/src/envparser.ts`.

---

## Critical Rules

- **The vault and recovery binary formats are a public contract.** Any change requires: bumped version byte, updated spec in `ARCHITECTURE.md` + `llms.txt` + `SPECS.md`, new cross-compat fixtures in `testdata/`, and matching implementations in both CLI and extension shipped in the same release. Never change one side only.
- **CLI and extension must stay algorithmically identical** for: `project_hash` / `projectHash`, `deterministic_hex` / `deterministicHex`, PBKDF2-SHA256 parameters, AES-256-GCM parameters, sandbox generation, secret detection rules. Cross-compat is enforced by **33 known-vector tests** (`testdata/`) — do not edit a fixture without regenerating it in both implementations.
- **Fail toward visibility.** Decrypt failure → show sandbox with warning. Encrypt failure → save real values. A temporary leak beats permanent data loss.
- **Zero network calls** other than `cloak update` (GitHub releases). No telemetry, no analytics, no cloud.
- **Non-interactive = deny.** If there is no TTY, any auth-requiring command must refuse. Piped input / scripted access is an AI-agent vector.
- **Atomic writes only.** Write-to-temp + rename. Never truncate and rewrite in place. Unix: POSIX rename. Windows: remove-then-rename (best available).
- **Secure deletion for temp files.** Overwrite with zeros before removal; prefer `/dev/shm` on Linux.
- **File permissions on Unix**: `chmod 600` on vault/recovery/auth files, `chmod 700` on directories. Windows uses default NTFS ACLs (v0.1 limitation).
- **Detector allowlist is load-bearing.** `NODE_ENV`, `PORT`, `HOST`, `DEBUG`, `LOG_LEVEL`, etc. must never be treated as secrets. Adding a new allowlisted key requires matching updates in both `cli/src/detector.rs` and `extension/src/detector.ts`, plus a cross-compat test.
- **Extension has zero runtime dependencies.** Use Node built-ins (`crypto`, `fs`, `path`) and the VS Code API only. Do not add npm packages without a very strong reason.
- **CLI binary stays small.** ~3 MB stripped. New heavy deps need justification; prefer feature flags.
- **Sensitive command surface is closed-by-default.** Adding a new command that can reveal or modify secrets means adding it to the auth-required list in `cli/src/auth.rs` and documenting it in `README.md` + `SKILL.md` + `llms.txt`.

---

## Version Bumps

When bumping version (e.g. 0.2.9 → 0.3.0), update **every** reference — `cli/Cargo.toml`, `cli/Cargo.lock`, `extension/package.json`, `extension/package-lock.json`, `README.md` badge, `llms.txt`, `SKILL.md` / `cloak/SKILL.md`, `install.sh`, `install.ps1`, any roadmap lines in `README.md`. Not just `Cargo.toml` and `package.json`.

## Doc Parity

Five documents describe the same system and must not drift:

- `README.md` — user-facing pitch + commands + FAQ
- `ARCHITECTURE.md` — internal design of record
- `SPECS.md` — format specs
- `llms.txt` — canonical summary for AI agents (served from the site)
- `SKILL.md` (and `cloak/SKILL.md`) — agent skill file shipped to users' projects

When you change a format, flow, or command: update all five (or consciously decide one doesn't apply, and say why in the commit).

## Testing

| Suite | Count | Location | Run |
|-------|-------|----------|-----|
| Rust unit + integration | ~94 | `cli/src/**/*.rs` and `cli/src/*_test.rs` | `cd cli && cargo test` |
| TypeScript | ~128 | `extension/src/**/*.test.ts` | `cd extension && npm test` |
| Cross-compat known-vector | 33 | `cli/src/cross_compat_test.rs` + TS mirror, fixtures in `testdata/` | both of the above |

**Every bugfix needs a regression test.** Every change to detector / parser / sandbox / vault / recovery needs matching tests in **both** languages.

Key fixtures — do not edit without regenerating on both sides:
- `projectHash('/Users/test/myproject') == 7b4d1b0b25658663`
- `deterministicHex('testhash', 'MY_KEY', 20) == a07404faa6392b60de34`

## Commands (user-facing)

```
cloak init        # scan .env, encrypt, write sandbox, show recovery key, set password
cloak status      # protection state (no auth)
cloak peek        # sandbox vs real, side-by-side (auth)
cloak run <cmd>   # run with real env vars injected (auth)
cloak edit        # $EDITOR on real values, re-encrypt on save (auth)
cloak set K V     # add/update a secret (auth)
cloak reveal K    # temporarily write real value on disk, auto-revert (auth)
cloak unprotect   # restore original .env, delete vault (auth)
cloak recover     # restore keychain key from recovery key (no auth)
cloak update      # self-update from GitHub releases (no auth)
cloak keychain-get <hash>   # hidden subcommand used by the extension for Touch ID fallback
```

The hidden `keychain-get` subcommand is the bridge that lets the extension trigger the Touch ID prompt via the CLI binary. Do not surface it in help text or user docs.

---

## Platforms & Build Targets

```
x86_64-apple-darwin         (codesigned, ad-hoc)
aarch64-apple-darwin        (codesigned, ad-hoc)
x86_64-unknown-linux-musl   (static, no glibc dep)
aarch64-unknown-linux-musl  (cross-compiled, static)
x86_64-pc-windows-msvc
extension .vsix             (platform-independent)
```

macOS release binaries are **ad-hoc codesigned** to prevent Keychain access prompts — don't remove this step.

### Known platform limitations (v0.1)

- Linux headless: no file-based keychain fallback yet (D-Bus Secret Service required).
- Windows: default NTFS ACLs, no per-user restriction, no Windows Hello.
- Single `.env` per project (multi-file planned).

---

## SOPs

### When you touch the detector (`detector.rs` / `detector.ts`)
1. Update both implementations in the same PR.
2. Add test cases to both `detector_test.rs` and `detector.test.ts`.
3. If adding a new secret pattern, add a sandbox generator for it in `sandbox.rs` + `sandbox.ts`.
4. If adding a new allowlist entry, add a `non_secret_allowed` test case in both suites.

### When you change a binary format
1. Bump the version byte.
2. Update `ARCHITECTURE.md`, `llms.txt`, `SPECS.md`, and `README.md` (if user-visible).
3. Add cross-compat fixture for the **new** format in `testdata/`.
4. Keep read-compat for the old version until explicitly dropped in a major.

### When you add a CLI command
1. Implement in `cli/src/commands/<name>.rs` and wire into `cli/src/main.rs` (`Commands` enum).
2. Decide auth class: if it reveals or modifies secrets → add to the auth-required list in `cli/src/auth.rs`.
3. If the extension needs parity, add TS equivalent under `extension/src/commands/`.
4. Update `README.md` commands table + `SKILL.md` + `llms.txt`.

### When you modify extension activation (`extension/src/extension.ts`)
1. Preserve the order: read workspace roots → detect cloak-managed projects → register document listeners → status bar → watcher. `activateInternal()` is the single place this ordering lives.
2. Test by reloading the extension host, not just unit tests — listener ordering bugs don't show up in unit tests.

### When you add a VS Code extension dependency
Default answer is **no**. Extension ships zero runtime deps. If unavoidable, justify in the PR and pin the version.

### Before every release
1. Bump version everywhere (see "Version Bumps" above).
2. `cd cli && cargo test && cargo build --release --all-features`.
3. `cd extension && npm test && npm run package` (produces `.vsix`).
4. Smoke-test `cloak init → run → edit → peek → unprotect` on a throwaway project with a real `.env`.
5. Verify ad-hoc codesign on macOS binaries.
6. Tag, push, let GitHub Actions build the 5 platform binaries + `.vsix`.

---

## Git

- Author: `Daniel Tamas <hello@danieltamas.com>`
- Main branch: `main`
- **NEVER add `Co-Authored-By` or any co-author trailer to commits.** All commits are authored solely by Daniel Tamas. Non-negotiable.
- Prefer conventional-style subjects (`feat:`, `fix:`, `refactor:`, `chore:`, `docs:`) — existing history uses this shape.
- Prefer creating new commits over `--amend`. Never force-push `main`.

---

## Knowledge Graph

`graphify-out/` contains a persistent knowledge graph (`graph.json`, `GRAPH_REPORT.md`, interactive `graph.html`). Use it to orient before exploring unfamiliar code:

- **Before grepping:** check `graphify-out/GRAPH_REPORT.md` god nodes and community hubs.
- **Architecture questions:** the graph is faster than reading individual files.
- **After code changes:** `/graphify --update` (or run the watcher) keeps it current.

Key bridge nodes (high betweenness): `Architecture Overview`, `Biometric Keychain Design Spec`, `Keychain Backends Table`. If a change touches any of these concepts, the graph will show every community affected — use it as a checklist for which docs to sync.
