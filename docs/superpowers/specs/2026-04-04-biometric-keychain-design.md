# Biometric Keychain (Touch ID) — Design Spec

**Date:** 2026-04-04
**Status:** Approved
**Scope:** CLI keychain module + extension keychain fallback

## Problem

Since the shared CLI/extension keychain change (commit 1a54cce), users are prompted for their keychain password instead of Touch ID when accessing vault keys. The Rust `keyring` crate stores items in the legacy file-based macOS keychain without biometric access control flags.

## Solution

Replace `keyring` on macOS with direct `security-framework` SecItem API calls using biometric access control. Add a `cloak keychain-get` subcommand so the VS Code extension can trigger Touch ID through the CLI binary.

## Platform Strategy

| Platform | Approach | Biometric |
|----------|----------|-----------|
| macOS | `security-framework` 3.7 SecItem API with `SecAccessControl` | Touch ID with password fallback |
| Windows | `keyring` crate with `windows-native` (unchanged) | No (future work) |
| Linux | `keyring` crate with `sync-secret-service` (unchanged) | No |

## Architecture

### CLI Module Structure

```
cli/src/keychain.rs          → platform dispatch (pub API unchanged)
cli/src/keychain_macos.rs    → security-framework SecItem API with biometric ACL
cli/src/keychain_default.rs  → existing keyring-based impl (Windows/Linux)
```

The public API of `keychain.rs` remains the same: `store_key`, `get_key`, `delete_key`, `has_key`. Internal dispatch uses `#[cfg(target_os = "macos")]`.

### macOS Keychain Details

**Crate:** `security-framework = { version = "3.7", features = ["OSX_10_15"] }`

**Keychain type:** Data protection keychain (required for biometric ACL, set via `use_protected_keychain()`)

**Access control flags:**
- `BiometryAny | DevicePasscode | Or` — Touch ID first, OS-managed fallback to device password
- Protection mode: `AccessibleWhenPasscodeSetThisDeviceOnly` — requires device passcode, no iCloud sync, this-device-only

**Keychain item identifiers:**
- Service: `cloak-bio` (distinct from legacy `cloak` to avoid conflicts during migration)
- Account: `vault-<project_hash>` (same pattern as before)

**Code signing:** Data protection keychain requires the binary to be codesigned. Distribution builds are already signed. Development builds need ad-hoc signing (`codesign --sign -`).

### New CLI Subcommand: `cloak keychain-get`

```
cloak keychain-get <project_hash>
```

- Outputs the hex-encoded key to stdout
- Exit code 0 on success, non-zero on failure
- No logging, no temp files — key only appears on stdout
- Triggers Touch ID prompt on macOS

### Extension Changes

In `extension/src/keychain.ts`, replace `readFromMacKeychain` (which uses `security find-generic-password`) with:

```typescript
function readViaCli(projectHash: string): Promise<string | null> {
    return new Promise((resolve) => {
        execFile('cloak', ['keychain-get', projectHash], (err, stdout) => {
            if (err) return resolve(null);
            resolve(stdout.trim() || null);
        });
    });
}
```

Flow remains: VS Code SecretStorage (primary, no prompt) → `cloak keychain-get` fallback (triggers Touch ID) → cache result back to SecretStorage.

## Migration

Safe migration from legacy `keyring` entries to biometric entries. Runs automatically on any CLI command that reads a key.

### Flow

1. Try biometric keychain (`cloak-bio` / `vault-<hash>`)
2. If found → return key, done
3. If not found → try legacy keychain (`cloak` / `vault-<hash>`) via `keyring` crate
4. If legacy found:
   a. Store key in biometric keychain
   b. Read back from biometric keychain
   c. Compare readback with original — must match exactly
   d. If match → delete legacy entry → return key
   e. If mismatch → log warning, keep legacy intact, return legacy key
5. If neither found → return error (key missing)

### Safety Guarantees

- Old key is never deleted before new key is verified
- If biometric store or readback fails, legacy key is preserved
- Migration is idempotent — running it twice has no effect
- No data loss path: every branch either succeeds fully or falls back to legacy

## Security Considerations

1. **AccessibleWhenPasscodeSetThisDeviceOnly** — strongest protection mode; key is inaccessible if device passcode is removed, no iCloud keychain sync
2. **BiometryAny with DevicePasscode fallback** — balances security with usability; pure BiometryAny would lock users out in clamshell mode
3. **Data protection keychain** — modern keychain, not the legacy file-based one; required for access control flags
4. **No key in logs or temp files** — `keychain-get` writes only to stdout, no intermediate storage
5. **Hex encoding** — consistent with existing approach; 64 printable chars for 32-byte key
6. **Separate service name** (`cloak-bio` vs `cloak`) — prevents migration from corrupting entries if the new format is somehow incompatible

## Testing

### Unit Tests
- Migration logic: mock keychain read/write/delete, verify correct sequence
- Platform dispatch: verify macOS path vs default path via cfg

### Integration Tests
- Store via legacy keyring → trigger migration → verify biometric entry exists and legacy is deleted
- Store via legacy → simulate biometric write failure → verify legacy preserved
- `keychain-get` subcommand returns correct hex and exit code

### Manual Test Matrix
| Scenario | Expected |
|----------|----------|
| Touch ID available | Touch ID prompt, key returned |
| Touch ID unavailable (clamshell) | Password prompt, key returned |
| User cancels biometric | Error, graceful failure |
| No device passcode set | Key inaccessible (AccessibleWhenPasscodeSetThisDeviceOnly) |
| First run after upgrade (migration) | Legacy key migrated, Touch ID works |
| Legacy key missing, biometric key missing | Error: "run cloak recover" |

## Out of Scope

- Windows Hello biometric support (no viable Rust ecosystem; future work)
- Linux biometric support
- LAContext reuse for batch operations (single key access per prompt is sufficient)
