# spec-checks

Independent checks written from `specs/` and the README only, before reading the source. Outside
the workspace (own `[workspace]`). Every test names the spec sentence it checks. Keep every
existing check; add new ones. This is the regression ledger.

```sh
cargo build -p vault-cli                       # from the repo root, for the CLI checks
cd qa/spec-checks
cargo build --bins                             # child-process harnesses for hostile inputs
cargo test --no-fail-fast
./cli/run_all.sh                               # black-box CLI against target/debug/vault
```

- `src/lib.rs`: an independent decoder and independent crypto (Argon2id, HKDF, XChaCha20-Poly1305 with the spec AADs), sync helpers, and a child-process runner with time and RSS limits.
- `src/bin/`: `open_file`, `open_kdbx` and `open_1pux` harnesses, so aborts or OOM in hostile-input cases are observable.
- `tests/`: `format`, `corruption`, `keys`, `merge`, `sync`, `sync_edge`, `sync_cloud`, `attachments`, `retention`, `totp_gen`, `import`, `modes`, `cli_bridge`.
- Temp files go under `tmp/` (git-ignored) and are removed by each test.

A passing check shows the behaviour on those inputs only. It is not a proof.
