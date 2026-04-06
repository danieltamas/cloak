# Biometric Keychain (Touch ID) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace legacy keychain storage on macOS with biometric-protected (Touch ID) keychain using the data protection keychain, with safe auto-migration of existing keys.

**Architecture:** Platform-dispatched keychain directory module — `keychain/mod.rs` dispatches to `keychain/macos.rs` (security-framework SecItem API with biometric ACL) on macOS, or `keychain/default.rs` (existing keyring crate) on Windows/Linux. On macOS, `default.rs` is also used for legacy migration. Migration reads old → writes new → verifies → deletes old. Extension falls back to `cloak keychain-get` subcommand instead of `security find-generic-password`.

**Tech Stack:** Rust, `security-framework` 3.7 (with `OSX_10_15` feature), `keyring` 3 (Windows/Linux only), TypeScript (VS Code extension)

**Spec:** `docs/superpowers/specs/2026-04-04-biometric-keychain-design.md`

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Delete | `cli/src/keychain.rs` | Replaced by directory module |
| Create | `cli/src/keychain/mod.rs` | Platform dispatch + migration logic |
| Create | `cli/src/keychain/macos.rs` | macOS biometric keychain via security-framework SecItem API |
| Create | `cli/src/keychain/default.rs` | Windows/Linux keychain via keyring crate (extracted from old keychain.rs) |
| Modify | `cli/src/main.rs` | Add `KeychainGet` subcommand |
| Modify | `cli/src/commands/mod.rs` | Add `keychain_get` module |
| Create | `cli/src/commands/keychain_get.rs` | `cloak keychain-get <hash>` implementation |
| Modify | `cli/Cargo.toml` | Add `security-framework` dep with feature gate |
| Modify | `extension/src/keychain.ts` | Replace `security find-generic-password` with `cloak keychain-get` |
| Modify | `cli/tests/keychain_test.rs` | Update tests for new module structure |

---

### Task 1: Convert keychain to directory module with platform dispatch

Convert `cli/src/keychain.rs` into a directory module (`cli/src/keychain/mod.rs`) with submodules for platform-specific implementations. The `default` submodule gets the existing `keyring`-based code. The `mod.rs` handles dispatch and migration.

**Files:**
- Delete: `cli/src/keychain.rs`
- Create: `cli/src/keychain/mod.rs`
- Create: `cli/src/keychain/default.rs`
- Test: `cli/tests/keychain_test.rs` (existing tests must still pass)

- [ ] **Step 1: Create `cli/src/keychain/default.rs` with the existing keyring implementation**

```rust
// cli/src/keychain/default.rs
use anyhow::{anyhow, Result};

pub fn store_key(project_hash: &str, key: &[u8; 32]) -> Result<()> {
    let account = format!("vault-{}", project_hash);
    let entry = keyring::Entry::new("cloak", &account)
        .map_err(|e| anyhow!("Failed to create keychain entry: {}", e))?;
    let hex_key = hex::encode(key);
    entry
        .set_password(&hex_key)
        .map_err(|e| anyhow!("Failed to store key in keychain: {}", e))?;
    Ok(())
}

pub fn get_key(project_hash: &str) -> Result<[u8; 32]> {
    let account = format!("vault-{}", project_hash);
    let entry = keyring::Entry::new("cloak", &account)
        .map_err(|e| anyhow!("Failed to create keychain entry: {}", e))?;
    let hex_key = entry.get_password().map_err(|e| {
        anyhow!(
            "Keychain key not found for this project. Run `cloak recover` to restore access. ({})",
            e
        )
    })?;
    let bytes = hex::decode(&hex_key)
        .map_err(|_| anyhow!("Keychain data corrupted: invalid hex encoding"))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "Keychain data corrupted: expected 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn delete_key(project_hash: &str) -> Result<()> {
    let account = format!("vault-{}", project_hash);
    let entry = keyring::Entry::new("cloak", &account)
        .map_err(|e| anyhow!("Failed to create keychain entry: {}", e))?;
    entry
        .delete_credential()
        .map_err(|e| anyhow!("Failed to delete keychain key: {}", e))?;
    Ok(())
}
```

- [ ] **Step 2: Create `cli/src/keychain/mod.rs` as the platform dispatcher**

Delete `cli/src/keychain.rs` and create `cli/src/keychain/mod.rs`:

```rust
//! Platform-dispatched keychain access.
//!
//! On macOS, uses the data protection keychain with biometric (Touch ID) access control.
//! On all other platforms, uses the `keyring` crate (Windows Credential Manager / Linux secret-service).

use anyhow::Result;

#[cfg(target_os = "macos")]
mod macos;

// `default` is used on all non-macOS platforms, and also on macOS for legacy migration.
mod default;

/// Store a 32-byte key in the OS keychain for a project.
pub fn store_key(project_hash: &str, key: &[u8; 32]) -> Result<()> {
    #[cfg(target_os = "macos")]
    return macos::store_key(project_hash, key);

    #[cfg(not(target_os = "macos"))]
    return default::store_key(project_hash, key);
}

/// Retrieve a 32-byte key from the OS keychain for a project.
/// On macOS, tries biometric keychain first, then migrates from legacy if found.
pub fn get_key(project_hash: &str) -> Result<[u8; 32]> {
    #[cfg(target_os = "macos")]
    return get_key_macos(project_hash);

    #[cfg(not(target_os = "macos"))]
    return default::get_key(project_hash);
}

/// Delete a key from the OS keychain for a project.
pub fn delete_key(project_hash: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        // Delete from both to be thorough.
        let _ = macos::delete_key(project_hash);
        let _ = default::delete_key(project_hash);
        return Ok(());
    }

    #[cfg(not(target_os = "macos"))]
    return default::delete_key(project_hash);
}

/// Check if a key exists in the keychain for a project.
pub fn has_key(project_hash: &str) -> bool {
    get_key(project_hash).is_ok()
}

/// macOS: try biometric, then migrate from legacy if needed.
#[cfg(target_os = "macos")]
fn get_key_macos(project_hash: &str) -> Result<[u8; 32]> {
    // 1. Try biometric keychain first.
    if let Ok(key) = macos::get_key(project_hash) {
        return Ok(key);
    }

    // 2. Try legacy keychain (keyring crate).
    let legacy_key = default::get_key(project_hash)?;

    // 3. Migrate: store in biometric keychain.
    if let Err(e) = macos::store_key(project_hash, &legacy_key) {
        eprintln!("Warning: could not migrate key to biometric keychain: {}", e);
        return Ok(legacy_key);
    }

    // 4. Verify readback.
    match macos::get_key(project_hash) {
        Ok(readback) if readback == legacy_key => {
            // 5. Verified — delete legacy.
            let _ = default::delete_key(project_hash);
            Ok(legacy_key)
        }
        _ => {
            // Readback failed — keep legacy, remove potentially corrupt biometric entry.
            eprintln!("Warning: biometric keychain verification failed, keeping legacy key");
            let _ = macos::delete_key(project_hash);
            Ok(legacy_key)
        }
    }
}
```

- [ ] **Step 3: Verify it compiles and existing tests pass**

`lib.rs` already has `pub mod keychain;` — Rust will now resolve this to `cli/src/keychain/mod.rs` instead of `cli/src/keychain.rs`. No changes to `lib.rs` needed.

Run: `cd cli && cargo check 2>&1 | tail -10`

Expected: Compiles (on macOS, the `macos` module doesn't exist yet — that's Task 2. The `#[cfg(target_os = "macos")]` gate means compilation still succeeds only if we stub it or are on non-macOS. **On macOS, temporarily comment out the `mod macos;` line and the macos-gated code, or create an empty stub.**)

**macOS stub to unblock compilation** — create `cli/src/keychain/macos.rs` with:

```rust
// cli/src/keychain/macos.rs — stub, replaced in Task 2
use anyhow::{anyhow, Result};

pub fn store_key(_project_hash: &str, _key: &[u8; 32]) -> Result<()> {
    Err(anyhow!("Biometric keychain not yet implemented"))
}

pub fn get_key(_project_hash: &str) -> Result<[u8; 32]> {
    Err(anyhow!("Biometric keychain not yet implemented"))
}

pub fn delete_key(_project_hash: &str) -> Result<()> {
    Err(anyhow!("Biometric keychain not yet implemented"))
}
```

Now run: `cd cli && cargo check 2>&1 | tail -10`

Expected: Compiles on all platforms.

- [ ] **Step 4: Run existing keychain tests to verify nothing broke**

Run: `cd cli && cargo test --test keychain_test -- --ignored 2>&1 | tail -20`

Expected: All 5 tests pass. On macOS, `get_key_macos` will try biometric (stub fails) → fall back to legacy (keyring) → migration fails (stub) → returns legacy key. So existing behavior is preserved.

- [ ] **Step 5: Commit**

```bash
git add cli/src/keychain/ && git rm cli/src/keychain.rs
git commit -m "refactor: convert keychain to directory module with platform dispatch"
```

---

### Task 2: Implement macOS biometric keychain module

**Files:**
- Modify: `cli/src/keychain/macos.rs` (replace stub from Task 1)
- Modify: `cli/Cargo.toml`

- [ ] **Step 1: Add `security-framework` dependency to Cargo.toml**

Add to `[dependencies]` section in `cli/Cargo.toml`:

```toml
# macOS biometric keychain (Touch ID)
[target.'cfg(target_os = "macos")'.dependencies]
security-framework = { version = "3.7", features = ["OSX_10_15"] }
```

- [ ] **Step 2: Replace stub `macos.rs` with biometric SecItem API**

```rust
// cli/src/keychain/macos.rs
//! macOS keychain access using the data protection keychain with biometric (Touch ID) ACL.
//!
//! Uses `security-framework` SecItem API with:
//! - Access control: BiometryAny | DevicePasscode | Or (Touch ID with password fallback)
//! - Protection: AccessibleWhenPasscodeSetThisDeviceOnly (strongest, no iCloud sync)
//! - Data protection keychain (not legacy file-based keychain)

use anyhow::{anyhow, Result};
use security_framework::passwords::{
    delete_generic_password, generic_password, set_generic_password_options,
    AccessControlOptions, PasswordOptions,
};
use security_framework::access_control::{ProtectionMode, SecAccessControl};

const SERVICE: &str = "cloak-bio";

pub fn store_key(project_hash: &str, key: &[u8; 32]) -> Result<()> {
    let account = format!("vault-{}", project_hash);
    let hex_key = hex::encode(key);

    let mut opts = PasswordOptions::new_generic_password(SERVICE, &account);

    let ac = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        (AccessControlOptions::BIOMETRY_ANY
            | AccessControlOptions::DEVICE_PASSCODE
            | AccessControlOptions::OR)
            .bits(),
    )
    .map_err(|e| anyhow!("Failed to create access control: {}", e))?;

    opts.set_access_control(ac);
    opts.use_protected_keychain();

    set_generic_password_options(hex_key.as_bytes(), opts)
        .map_err(|e| anyhow!("Failed to store key in biometric keychain: {}", e))?;

    Ok(())
}

pub fn get_key(project_hash: &str) -> Result<[u8; 32]> {
    let account = format!("vault-{}", project_hash);

    let mut opts = PasswordOptions::new_generic_password(SERVICE, &account);
    opts.use_protected_keychain();

    let password_bytes = generic_password(opts)
        .map_err(|e| anyhow!("Biometric keychain key not found: {}", e))?;

    let hex_key = String::from_utf8(password_bytes)
        .map_err(|_| anyhow!("Biometric keychain data corrupted: invalid UTF-8"))?;

    let bytes = hex::decode(&hex_key)
        .map_err(|_| anyhow!("Biometric keychain data corrupted: invalid hex encoding"))?;

    if bytes.len() != 32 {
        return Err(anyhow!(
            "Biometric keychain data corrupted: expected 32 bytes, got {}",
            bytes.len()
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn delete_key(project_hash: &str) -> Result<()> {
    let account = format!("vault-{}", project_hash);
    delete_generic_password(SERVICE, &account)
        .map_err(|e| anyhow!("Failed to delete biometric keychain key: {}", e))?;
    Ok(())
}
```

- [ ] **Step 3: Verify it compiles on macOS**

Run: `cd cli && cargo check 2>&1 | tail -20`

Expected: No errors. On non-macOS, the `keychain_macos` module is not compiled (gated by `#[cfg(target_os = "macos")]`).

- [ ] **Step 4: Run keychain tests on macOS (will trigger Touch ID)**

Run: `cd cli && cargo test --test keychain_test -- --ignored 2>&1 | tail -20`

Expected: All tests pass. On macOS, `store_key` now writes to biometric keychain (Touch ID prompt or password fallback). The tests exercise store → get → delete cycle.

- [ ] **Step 5: Commit**

```bash
git add cli/src/keychain/macos.rs cli/Cargo.toml
git commit -m "feat: add macOS biometric keychain (Touch ID) via security-framework"
```

---

### Task 3: Add `cloak keychain-get` subcommand

**Files:**
- Create: `cli/src/commands/keychain_get.rs`
- Modify: `cli/src/commands/mod.rs`
- Modify: `cli/src/main.rs`

- [ ] **Step 1: Create `cli/src/commands/keychain_get.rs`**

```rust
//! `cloak keychain-get` — retrieve a vault key from the keychain (for extension integration).
//!
//! Outputs the hex-encoded 32-byte key to stdout and exits.
//! On macOS, this triggers Touch ID / password prompt.
//! This is an internal command used by the VS Code extension.

use crate::keychain;
use anyhow::{anyhow, Result};

pub fn run(project_hash: String) -> Result<()> {
    if project_hash.is_empty() {
        return Err(anyhow!("Project hash cannot be empty"));
    }

    let key = keychain::get_key(&project_hash)?;
    // Output hex to stdout — no newline, no logging, no temp files.
    print!("{}", hex::encode(key));
    Ok(())
}
```

- [ ] **Step 2: Add module declaration in `cli/src/commands/mod.rs`**

Add after the existing module declarations:

```rust
/// `cloak keychain-get` — retrieve a vault key for extension integration.
pub mod keychain_get;
```

- [ ] **Step 3: Add subcommand to CLI in `cli/src/main.rs`**

Add to the `Commands` enum:

```rust
    /// Retrieve vault key from keychain (internal, used by VS Code extension)
    #[command(name = "keychain-get", hide = true)]
    KeychainGet {
        /// The project hash to look up
        project_hash: String,
    },
```

Add to the `run` match block:

```rust
        Commands::KeychainGet { project_hash } => commands::keychain_get::run(project_hash),
```

- [ ] **Step 4: Verify it compiles and the hidden command works**

Run: `cd cli && cargo build 2>&1 | tail -5`

Then test: `cd cli && cargo run -- keychain-get test-nonexistent 2>&1`

Expected: Build succeeds. The test command should fail with "Keychain key not found" error (non-zero exit). The command should NOT appear in `cloak --help` output (hidden).

Verify hidden: `cd cli && cargo run -- --help 2>&1 | grep keychain`

Expected: No output (command is hidden).

- [ ] **Step 5: Commit**

```bash
git add cli/src/commands/keychain_get.rs cli/src/commands/mod.rs cli/src/main.rs
git commit -m "feat: add hidden keychain-get subcommand for extension integration"
```

---

### Task 4: Update VS Code extension to use `cloak keychain-get`

**Files:**
- Modify: `extension/src/keychain.ts`

- [ ] **Step 1: Replace `readFromMacKeychain` with `readViaCli` in `extension/src/keychain.ts`**

Replace the entire `readFromMacKeychain` function and update `getKey` to use it:

```typescript
import * as vscode from 'vscode';
import { execFile } from 'child_process';

let secretStorage: vscode.SecretStorage;

export function init(storage: vscode.SecretStorage): void {
    secretStorage = storage;
}

export async function storeKey(projectHash: string, key: Buffer): Promise<void> {
    await secretStorage.store(`cloak-vault-${projectHash}`, key.toString('hex'));
}

export async function getKey(projectHash: string): Promise<Buffer | null> {
    // 1. Try VS Code SecretStorage first (fast, no prompt).
    const hex = await secretStorage.get(`cloak-vault-${projectHash}`);
    if (hex) return Buffer.from(hex, 'hex');

    // 2. Fall back to cloak CLI (triggers Touch ID on macOS).
    try {
        const cliHex = await readViaCli(projectHash);
        if (cliHex) {
            // Cache in VS Code SecretStorage for next time.
            await secretStorage.store(`cloak-vault-${projectHash}`, cliHex);
            return Buffer.from(cliHex, 'hex');
        }
    } catch { /* cloak CLI not found or failed */ }

    return null;
}

export async function deleteKey(projectHash: string): Promise<void> {
    await secretStorage.delete(`cloak-vault-${projectHash}`);
}

/**
 * Retrieve key via `cloak keychain-get` CLI command.
 * On macOS this triggers Touch ID / password prompt.
 */
function readViaCli(projectHash: string): Promise<string | null> {
    return new Promise((resolve) => {
        execFile('cloak', ['keychain-get', projectHash], { timeout: 30000 }, (err, stdout) => {
            if (err) return resolve(null);
            const hex = stdout.trim();
            // Validate: must be exactly 64 hex characters (32 bytes).
            if (hex.length === 64 && /^[0-9a-f]+$/i.test(hex)) {
                return resolve(hex);
            }
            resolve(null);
        });
    });
}
```

- [ ] **Step 2: Build the extension to verify no TypeScript errors**

Run: `cd extension && npm run build 2>&1 | tail -10`

Expected: Build succeeds with no errors.

- [ ] **Step 3: Commit**

```bash
git add extension/src/keychain.ts
git commit -m "feat: extension uses cloak keychain-get for Touch ID fallback"
```

---

### Task 5: Update CI workflow for macOS codesigning

The data protection keychain requires the binary to be codesigned. The CI already does `codesign -s -` for macOS artifacts. Verify this is sufficient and that the `security-framework` feature gate doesn't break non-macOS builds.

**Files:**
- Modify: `cli/Cargo.toml` (if needed)

- [ ] **Step 1: Verify non-macOS builds exclude security-framework**

The `security-framework` dependency uses `[target.'cfg(target_os = "macos")'.dependencies]` so it won't be pulled in on Linux/Windows. Verify:

Run: `cd cli && cargo check --target x86_64-unknown-linux-gnu --no-default-features 2>&1 | tail -10` (if cross-compilation target available)

Or verify by reading `Cargo.toml` that the dep is target-gated.

- [ ] **Step 2: Verify `keyring` is still available for non-macOS**

The `keyring` dependency in `[dependencies]` (non-target-gated) is still needed for `keychain_default.rs` on all platforms, and for legacy migration on macOS. No changes needed.

- [ ] **Step 3: Verify macOS CI codesign step is present**

Check `.github/workflows/release.yml` line: `codesign -s - "${{ matrix.artifact }}"` — already present for macOS. Ad-hoc signing is sufficient for data protection keychain access.

- [ ] **Step 4: Commit (only if changes were needed)**

```bash
git commit -m "chore: verify CI handles biometric keychain deps correctly"
```

---

### Task 6: Manual testing and version bump

**Files:**
- Modify: `cli/Cargo.toml` (version bump)
- Modify: `extension/package.json` (version bump)
- Modify: `cli/src/version.rs` (version string)

- [ ] **Step 1: Manual test matrix on macOS**

Test each scenario:

1. **Fresh install:** `cloak init` on a new project → key stored in biometric keychain → Touch ID prompt on next `cloak peek`
2. **Migration:** Have an existing legacy key → run `cloak peek` → should migrate silently, Touch ID prompt
3. **Clamshell mode:** Close lid, use external monitor → should get password prompt instead of Touch ID
4. **Cancel biometric:** Click "Cancel" on Touch ID → should get error, not crash
5. **Extension fallback:** Open project in VS Code → extension should trigger Touch ID via `cloak keychain-get`
6. **Extension caching:** After first Touch ID, subsequent opens should NOT prompt (cached in SecretStorage)

- [ ] **Step 2: Manual test on Windows/Linux (if available)**

Verify `cloak init` and `cloak peek` still work without changes (using `keyring` crate as before).

- [ ] **Step 3: Bump versions**

Update `cli/Cargo.toml` version, `cli/src/version.rs`, and `extension/package.json` version as appropriate for this feature release.

- [ ] **Step 4: Commit**

```bash
git add cli/Cargo.toml cli/src/version.rs extension/package.json
git commit -m "feat: bump versions for biometric keychain release"
```
