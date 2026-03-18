# Cloak Architecture

## Overview

Cloak has two independent implementations sharing binary file format contracts:

```
cli/                    Rust CLI — single binary, cross-platform
extension/              TypeScript VS Code extension — zero runtime deps
scripts/                Installers (install.sh, install.ps1)
.github/workflows/      CI: 5 build targets + extension .vsix
```

## Two Implementations, One Contract

The CLI and extension never share code. They share two binary formats:

1. **Vault format** — AES-256-GCM encrypted secrets
2. **Recovery format** — keychain key encrypted with PBKDF2-derived recovery key

A project protected by the CLI works in the extension and vice versa. Cross-compatibility is enforced by 33 known-vector tests.

## File Layout

### Per-project files (in project root)

```
.env              Sandbox values on disk (what AI agents read)
.cloak            JSON marker: { version, projectHash, protected: [".env"] }
```

### Global files

```
macOS:   ~/Library/Application Support/cloak/
Linux:   ~/.config/cloak/
Windows: %APPDATA%\cloak\

  vaults/
    <hash>.vault          AES-256-GCM encrypted secret values
    <hash>.recovery       Keychain key encrypted with recovery-derived key
    <hash>.auth           PBKDF2-SHA256 hashed CLI access password (JSON)
```

`<hash>` = first 16 hex chars of SHA-256 of the canonicalized, forward-slash-normalized project root path. Identical across CLI and extension.

## Vault Binary Format

```
Offset  Size   Field
0       3      Magic: "CLK"
3       1      Version: 0x01
4       12     IV (random nonce)
16      16     AES-256-GCM authentication tag
32      N      Ciphertext (encrypted .env content as UTF-8)
```

Encryption: AES-256-GCM, 32-byte key, 12-byte random IV, no AAD. Fresh IV per encryption.

## Recovery Format

```
Offset  Size   Field
0       3      Magic: "CRK"
3       1      Version: 0x01
4       32     PBKDF2 salt (random)
36      16     AES-256-GCM IV (random)
52      16     AES-256-GCM tag
68      32     Ciphertext (encrypted 32-byte keychain key)
```

Recovery key: `CLOAK-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (96 bits entropy, base36 encoded).
PBKDF2-SHA256 with 100,000 iterations derives a 32-byte encryption key from the recovery key bytes + salt.

## Auth File Format

```json
{
  "version": 1,
  "salt": "<hex, 32 bytes>",
  "hash": "<hex, 32 bytes>",
  "method": "pbkdf2-sha256",
  "iterations": 100000
}
```

Password hashed with PBKDF2-SHA256 (100k iterations, 32-byte random salt). Plaintext password never stored.

## Authentication Flow

### CLI

```
User runs sensitive command (peek, run, edit, reveal, set, unprotect)
  |
  +-- No .auth file? --> skip auth (backwards compat with pre-auth projects)
  |
  +-- No TTY? --> reject ("run this in an interactive terminal")
  |
  +-- macOS with GUI session?
  |     |
  |     +-- Run cloak-touchid helper binary
  |     |     Uses LAContext.evaluatePolicy(.deviceOwnerAuthentication)
  |     |     Tries Touch ID first, falls back to macOS account password
  |     |
  |     +-- Success --> access granted (skip CLI password)
  |     +-- Cancelled --> access denied
  |     +-- Unavailable (SSH, no hardware, no Xcode CLT) --> fall through
  |
  +-- Prompt "Password: " via rpassword (hidden input)
  |     Hash with stored salt + iterations
  |     Compare to stored hash
  |
  +-- Match --> access granted
  +-- Mismatch --> "Authentication failed: wrong password"
```

Safe commands skip auth entirely: `init`, `status`, `recover`, `update`.

### macOS Touch ID Helper

A Swift binary compiled on first use, cached at `/tmp/cloak-touchid`:

```swift
LAContext().evaluatePolicy(.deviceOwnerAuthentication, ...)
```

- `.deviceOwnerAuthentication` = Touch ID first, macOS password fallback
- Compiled via `swiftc -O` (requires Xcode CLT)
- Compilation: ~4 seconds (one-time)
- Execution: instant (native binary, no interpreter)
- Falls back to CLI password if: no Xcode CLT, SSH without GUI, compilation fails

### VS Code Extension

```
Open .env in editor
  --> Extension intercepts onDidOpenTextDocument
  --> Reads vault, decrypts with keychain key
  --> Replaces editor buffer with real values
  --> Disk still has sandbox values
  --> No prompt (core UX: human sees real, disk has sandbox)

Save .env in editor
  --> Extension intercepts onWillSaveTextDocument
  --> Encrypts real values to vault
  --> Replaces buffer with sandbox
  --> VS Code writes sandbox to disk
  --> Extension restores real values in buffer via onDidSaveTextDocument

Open Cloak Terminal
  --> Modal warning dialog: "This will open a terminal with real secrets"
  --> User must click "Open Terminal" (AI agents can't interact with modals)
  --> Terminal created with real env vars injected
```

## Keychain Backends

| Platform | Backend | Crate Feature |
|----------|---------|---------------|
| macOS | Keychain Services (native) | `apple-native` |
| Linux | D-Bus Secret Service (gnome-keyring / kwallet) | `sync-secret-service` |
| Windows | Credential Manager (native) | `windows-native` |
| VS Code | SecretStorage API (built-in) | N/A |

Service name: `cloak`, account: `vault-<project_hash>`. Key stored as hex-encoded 64-char string.

## Secret Detection

Both CLI and extension use identical detection rules:

1. **Key name patterns** — regex matches for known secret key names (API_KEY, SECRET, TOKEN, PASSWORD, etc.)
2. **Value patterns** — structural regex for known formats (Stripe keys, AWS keys, JWTs, private keys, database URLs)
3. **Shannon entropy** — values with entropy > 4.5 and length > 20 are treated as secrets
4. **Non-secret allowlist** — PORT, HOST, NODE_ENV, DEBUG, LOG_LEVEL, etc. are never treated as secrets

## Sandbox Generation

Deterministic sandbox values via `SHA-256("cloak-sandbox:<project_hash>:<key>")`:

- Same project + same key = same sandbox value every time
- Different projects get different sandbox values
- Format-preserving: Stripe keys get `sk_test_*`, database URLs get `postgres://dev:dev@localhost`, etc.

## Platform-Specific Behavior

### File Permissions
- **Unix**: `chmod 600` on vault, recovery, and auth files. `chmod 700` on directories.
- **Windows**: Default NTFS ACLs (v0.1 limitation — files contain only encrypted data or password hashes).

### Secure Temp Directory
- **Linux**: `/dev/shm` (RAM-backed) if available, falls back to system temp.
- **macOS / Windows**: System temp directory.

### Atomic Writes
- **Unix**: Write to `.tmp`, then `rename()` (POSIX atomic).
- **Windows**: Write to `.tmp`, remove original, then `rename()` (not truly atomic, but best available).

### TTY Detection
- `std::io::IsTerminal` (Rust 1.70+) on all platforms.
- Non-interactive sessions: `setup_auth` skips password setup, `require_auth` rejects access.

## Build Targets

```
macOS x86_64:       x86_64-apple-darwin        (codesigned)
macOS ARM64:        aarch64-apple-darwin       (codesigned)
Linux x86_64:       x86_64-unknown-linux-musl  (static, no glibc dep)
Linux ARM64:        aarch64-unknown-linux-musl (cross-compiled, static)
Windows x86_64:     x86_64-pc-windows-msvc
Extension:          .vsix (platform-independent)
```

Release binaries are ad-hoc codesigned on macOS to prevent Keychain access prompts.

## Test Suite

```
CLI (Rust):       94 tests — vault, recovery, keychain, filemanager, detector, sandbox, envparser
Extension (TS):   128 tests — same modules + 33 cross-compatibility known-vector tests
```

Cross-compat tests verify that both implementations produce identical output for:
- `projectHash` given the same path
- `deterministicHex` given the same inputs
- PBKDF2-SHA256 given the same password, salt, iterations

## Known Limitations (v0.1)

- **Linux headless**: Keychain requires D-Bus Secret Service. No file-based fallback yet.
- **Windows file permissions**: Vault/auth files use default NTFS ACLs (no per-user restriction).
- **Windows biometric**: No Windows Hello support. Password-only auth.
- **Single .env per project**: Protects the first `.env` file found. Multi-file support planned.
- **Binary size**: ~3MB stripped. Could be smaller with feature flags.
