---
name: vault-app-session-guards
description: vault-app gotchas for lock/session staleness, secondary windows (backup viewer, item window), clipboard guard, capped reads, and gpui entity double-lease
metadata:
  type: project
---
- AppState staleness counters: `epoch` (vault closed/switched) and `lock_gen` (locked), private in state.rs; `AppState::session_gen()` (state/viewer.rs) exposes both for secondary windows. Child modules under `state/` can read the private fields directly.
- Backup viewer (screens/backup.rs) captures `session_gen()` when an unlock starts and installs the result only if it is unchanged and the vault is not locked. All vault reads go through `live_vault(cx)`, and `forget()` drops the vault in the lock observer and in render.
- Clipboard: `copy_value_for_window` (state/session.rs) refuses when `locked`. The viewer's `copy_value` also requires `main_active()` and returns `Option<u32>` (the number of seconds before the clear).
- Do NOT `entity.update` a secondary window from inside `AppState::lock`. gpui-pre 0.3.10 panics on a double lease ("already being updated"), and lock can run inside a window's own update. That is why window closing is deferred. Use gates and observers instead.
- App tests: in a `TestAppContext`, a background task does not run until `run_until_parked`. So "complete after lock" races are deterministic: call unlock, then lock, then park. Sparse files (`File::set_len`) give an oversize-file test that allocates nothing.
- `vault_sync::read_capped(path, cap)` is public: it follows symlinks, refuses non-regular files and returns an unwiped Vec. The app (`src/bounded_read.rs`, also used by kdbx.rs) and vault-cli (main.rs) each wrap it in `Zeroizing` and reword the too-large error as "file is larger than the N MiB limit".
- vault-cli has two sanitizers: `sanitize_for_terminal` keeps LF and is for values/notes; `sanitize_line` escapes `\n`/`\r` and is for titles, names, paths, sync events and errors.
- vault-app's full `cargo test` takes more than 10 minutes, so run it in the background.
- `cargo clippy -p X -- -D warnings` also lints workspace path deps. When another agent's WIP in vault-sync has dead code, use `--no-deps`.
- Autosave: `SaveLockTimeout` and `PrimaryChangedDuringSave` share the single retry (`sync.busy_retried`) in `autosave_finished`.

**Why:** these came out of the daybreak-03-10-2026 review fixes [4], [7] and [10] (2026-11-06).
**How to apply:** reuse these patterns for any new secondary window or async result, and for any new file-import path.
