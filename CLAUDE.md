# CLAUDE.md — project rules

Native macOS password manager in Rust. Codename: **vault**. Specs live in `specs/`; read `specs/00-overview.md` first, then the spec for the crate you are touching.

## Working rules

- **Never run `git commit`, `git push`, `git rebase`, or anything that rewrites history unless the user explicitly asks in that message.** Stage nothing without being asked. Show a diff summary and wait.
- Do not invent crypto. Use RustCrypto crates (`argon2`, `chacha20poly1305`, `hkdf`, `sha2`) and `rand` with `OsRng`. No custom primitives, no custom padding, no custom MACs.
- `unsafe` is allowed only in `vault-macos`. Any `unsafe` block gets a `// SAFETY:` comment.
- `vault-core` has **no** I/O, no `std::fs`, no platform crates, no `tokio`. Bytes in, bytes out.
- Every change to `vault-core` or `vault-sync` ships with tests. Format changes ship with a test fixture under `vault-core/tests/fixtures/` and a bump of `FORMAT_VERSION`.
- Secrets are `secrecy::SecretString` / `SecretVec` or wrapped in `zeroize::Zeroizing`. Never `String` for passwords, keys, or TOTP secrets. Never log them, never `Debug`-print them.
- Prefer small PR-sized changes. If a task needs more than ~400 lines of diff, stop and outline the split first.
- When a spec is ambiguous, pick the simplest interpretation, implement it, and note the choice in the PR summary. Do not silently expand scope.
- Do not add dependencies without listing them and why. Pin versions in `Cargo.toml` (`=x.y.z` for gpui and gpui-component; caret elsewhere).
- After each major wave and before the owner commits it, remind the owner to run the `bug-hunter` agent (`.claude/agents/bug-hunter.md`): an independent spec-derived hunt that writes its checks before reading the code and reports to `docs/qa/`. It is slow and costly, so it never runs automatically; the orchestrator's checkpoint must end with "Bug hunt: run / not yet run for this wave".

## Workspace

```
Cargo.toml            workspace
crates/vault-core     format, crypto, items, merge, TOTP, generator, import/export
crates/vault-sync     file watching, atomic write, backup rotation, conflict handling
crates/vault-macos    Keychain, Touch ID, Secure Enclave, pasteboard, iCloud eviction
crates/vault-cli      thin CLI over core+sync (dev/debug tool, also phase-1 deliverable)
crates/vault-app      gpui app
specs/                the specs
```

## Commands

```
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo run -p vault-cli -- --help
cargo run -p vault-app
```

Toolchain: Rust pinned in `rust-toolchain.toml` (gpui-pre needs it), edition 2024. macOS 15+ target. No CI yet; run the four checks above before declaring a task done.

## Phases (see 00-overview.md)

1. `vault-core` + `vault-cli` — format, crypto, CRUD, TOTP, round-trip tests
2. `vault-app` skeleton — unlock, list, detail, generator
3. `vault-sync` — watcher, atomic writes, merge, backups, iCloud
4. `vault-macos` — Touch ID, Keychain, pasteboard, signing
5. Polish

Do not start a phase-3 feature while phase-1 acceptance criteria are unmet.
