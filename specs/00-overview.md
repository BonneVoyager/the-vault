# 00 — Overview

## Goal

A native macOS password manager, written in Rust, no webview. Single-user, local-first. Vault is one encrypted file the user can put anywhere — a local folder, iCloud Drive, or a Dropbox folder — and the app keeps it consistent across machines and keeps rotating backups.

Visual target: 1Password 8 level of polish. Three-column layout, keyboard-first, dark/light.

## Non-goals (v1)

- Browser extension / autofill
- Mobile
- Multi-user sharing, organisations
- Server-side sync, accounts, telemetry
- Windows/Linux (keep `vault-core` and `vault-sync` portable anyway; only `vault-macos` and `vault-app` are allowed macOS-only deps)

## Threat model

Protects against:

- Stolen or lost laptop (vault at rest)
- Compromised cloud storage account (attacker gets the file)
- Offline brute force of the master password (Argon2id, calibrated ≥ 500 ms on the user's machine)
- Tampering with the vault file: modified items, swapped items between vaults, deleted/rolled-back items (per-item AEAD with AAD + encrypted manifest)
- Casual clipboard snooping (concealed pasteboard type, auto-clear)

Does **not** protect against:

- Malware or a keylogger on an unlocked machine
- A user with a weak master password
- Someone with physical access to an unlocked session

Explicitly accepted leaks in the file format: number of items, item UUIDs, per-item last-modified timestamps, vault creation time. Everything else — titles, URLs, usernames, notes, tags, field names — is encrypted.

## Architecture

```
┌──────────────────────────────────────────────────┐
│ vault-app (gpui)                                 │
│   views · state · actions · keymap · theme       │
├────────────────────┬─────────────────────────────┤
│ vault-sync         │ vault-macos                 │
│  atomic write      │  Keychain / Secure Enclave  │
│  watcher + merge   │  Touch ID                   │
│  backup rotation   │  NSPasteboard               │
│  conflict copies   │  iCloud eviction            │
├────────────────────┴─────────────────────────────┤
│ vault-core (pure, no I/O)                        │
│  format · crypto · items · merge · totp · gen    │
└──────────────────────────────────────────────────┘
```

Rules of dependency: `vault-core` depends on nothing in the workspace. `vault-sync` and `vault-macos` depend on `vault-core`. `vault-app` and `vault-cli` depend on all three.

## Key decisions (do not relitigate without a spec change)

| Decision | Choice | Why |
|---|---|---|
| Vault format | Own binary format, CBOR payloads (`01-vault-format.md`) | Simpler than KDBX4, designed for field-level merge |
| KDF | Argon2id, params stored in header | Standard, memory-hard |
| AEAD | XChaCha20-Poly1305 | 24-byte random nonces, no nonce-counter state to get wrong |
| Serialization | CBOR via `ciborium` | Schema-tolerant, compact, no reflection |
| Granularity | Per-item encryption | Enables merge without re-encrypting whole file; swap detection via AAD |
| Sync model | File-based; cloud providers are just folders | iCloud / Dropbox / local folder are the same code path |
| Merge | Field-level last-write-wins + tombstones | Good enough for one user on 2–3 devices; no CRDT library |
| UI | gpui + gpui-component, pinned versions | GPU-rendered, own widgets, closest to 1Password look without a webview |
| Unlock factors | Master password (required). Touch ID convenience unlock via Secure Enclave (phase 4). Secret key and hardware keys deferred to v2. | Scope |

## Phases and acceptance criteria

### Phase 1 — core + CLI
- `vault-core` implements `01-vault-format.md` and `02-core-api.md`
- Round-trip test: create → add 100 items → serialize → parse → unlock → equal
- Tamper tests: flip a byte in header, in item ciphertext, in manifest, drop an item, swap an item into another vault — all must fail with the right error
- KDF calibration function works
- `vault-cli`: `init`, `add`, `get`, `list`, `rm`, `totp`, `gen`, `export`, `import --format csv`
- Format fixture `tests/fixtures/v1-basic.vault` committed with its password in the test

### Phase 2 — app skeleton
- Unlock screen, three-column layout, item list with search, item detail, edit, password generator, TOTP code with countdown
- Auto-lock on idle (default 5 min) and on screen lock/sleep
- Keyboard: `⌘F` search, `⌘N` new, `⌘E` edit, `⌘⇧C` copy password, `⌘L` lock, `↑↓` navigate, `⏎` open
- Light and dark theme

### Phase 3 — sync + backup
- `03-sync.md` fully implemented
- Test: two in-memory "devices" edit different fields of the same item, both write, both merge → both converge
- Test: conflicted-copy file is absorbed and moved to backups
- Backups rotate per policy

### Phase 4 — macOS integration
- Touch ID unlock via Secure Enclave wrapped key
- Pasteboard concealment and auto-clear
- iCloud eviction handling
- Signed and notarized `.app` produced by `scripts/package.sh`

### Phase 5 — polish
- Empty states, animations, drag-to-reorder, icons/favicons (bundled, no network), onboarding
