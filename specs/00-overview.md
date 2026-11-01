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
- macOS 14 or earlier. Minimum is macOS 15 (needed for passkey PRF).
- Hardware keys (YubiKey HMAC-SHA1, FIDO2 hmac-secret) and key files. Dropped from the roadmap; see `docs/research/2026-10-29-hardware-key-and-unlocked-state.md`.
- Network access of any kind, so no leaked-password ("compromised") checks.
- Backups of attachments. Snapshots cover the vault file only (`03` §1.1); attachments are capped at 100 MB each.

## Threat model

Protects against:

- Stolen or lost laptop (vault at rest)
- Compromised cloud storage account (attacker gets the file)
- Offline brute force of the master password (Argon2id, calibrated ≥ 500 ms on the user's machine)
- Tampering with the vault file: modified items, swapped items between vaults, deleted or rolled-back individual items, a replaced or re-stamped header (per-item AEAD with AAD + encrypted manifest + header digest). Replacing the WHOLE file with an older complete copy is NOT detected (no external freshness anchor); the old copy is itself authentic and opens. Accepted limit.
- Casual clipboard snooping (concealed pasteboard type, current-host-only so nothing reaches Universal Clipboard, auto-clear)
- Weak or reused item passwords (local audit: weak < 40 bits, reused across items; master password minimum 50 bits)

Does **not** protect against:

- Malware or a keylogger on an unlocked machine
- A user with a weak master password
- Someone with physical access to an unlocked session

Unlock factors (master password, Touch ID, passkey) protect the file at rest and in transit only. While the vault is unlocked the vault key and decrypted items are in process memory; the controls for that window are auto-lock (idle, sleep, screen lock, user switch), zeroize on lock, hardened runtime without debugging entitlements, clipboard hygiene, and best-effort screen-capture exclusion.

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
| Unlock factors | Master password (required). Touch ID convenience unlock via Secure Enclave (phase 4). Passkey unlock via the WebAuthn PRF extension (after phase 5, macOS 15). Hardware keys and key files: dropped. | Scope |
| Forward compatibility | Readers preserve unknown slot kinds, item kinds, field kinds, and map keys; every `FORMAT_VERSION` keeps its fixtures forever (`01` §9) | A newer app always opens an older file, and an older app opens a newer file that only added things |

## Phases and acceptance criteria

### Phase 1 — core + CLI
- `vault-core` implements `01-vault-format.md` and `02-core-api.md`
- Round-trip test: create → add 100 items → serialize → parse → unlock → equal
- Tamper tests: flip a byte in header, in item ciphertext, in manifest, drop an item, swap an item into another vault — all must fail with the right error
- KDF calibration function works
- `vault-cli`: `init`, `add`, `get`, `list`, `rm`, `totp`, `gen`, `export`, `import --format csv`; later dev-tool additions: `attach`, `upgrade` (01 §9), `edit` (title, favorite, tags, icon, set/add/remove fields; command-line values are visible in process listings, `--set-env` for secrets) and `sync` (start the watcher, poll once, absorb conflict copies, save), both added 2026-10-31 for the sync lab; `VAULT_DEVICE_ID` overrides the stored device id for one process
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

## Testing roadmap (future considerations, noted 2026-10-30, not scheduled)

Unit tests plus diff-based code and security review missed two cross-device defects that an independent spec-derived bug hunt found. Beyond the manual `bug-hunter` agent, the following would add independent lenses, in order of value:

1. **Continuous integration**: a macOS job on every push running `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, plus a nightly long job for the items below. Nothing runs today unless someone runs it.
2. **Property tests for the merge laws** — DONE 2026-11-01 (`vault-core/tests/merge_props.rs`, `proptest`): over random edit scripts on 2–3 devices: commutativity (content equal after one exchange with `modified_at` within 1 ms, fully equal after two: the 03 §5 "+1 bump" is one-sided by construction), idempotence, convergence of N devices within N rounds (N+1 when the `removed_fields` cap fires), `modified_at` never decreases and attribute/field stamps never decrease while an item stays live (a tombstone win replaces the item wholesale), guarantee 9 incl. resurrection. Both high-severity external findings were violations of these laws.
3. **Fuzzing the parsers** (`cargo-fuzz`): file format, KDBX outer header walk, CSV and 1PUX importers, TOTP URI; fixed time budget per wave, corpus checked in.
4. **Multi-device simulation** in vault-sync: randomised interleavings of edits, saves, locks and conflict copies of both shapes, compared against a reference model.
5. **Mutation testing** (`cargo-mutants`) on vault-core and vault-sync per wave, listing tests that do not bite.
6. **Spec traceability** — DONE 2026-11-01 (`docs/spec-traceability.md`, 220 rules, 4 uncovered as of 2026-11-01; refresh it when a spec section or test file changes): a table mapping every guarantee in 02 and 03 to a named test.
7. **Golden screenshots**: compare headless renders of each screen against stored images to catch visual regressions.
