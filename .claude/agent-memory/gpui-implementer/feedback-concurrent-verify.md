---
name: feedback-concurrent-verify
description: When parallel agents leave vault-sync/vault-core mid-edit and vault-app no longer compiles, verify own vault-app diff in a scratch detached worktree
metadata:
  type: feedback
---
When other agents edit vault-sync concurrently (e.g. adding a `SyncEvent` variant), `cargo test -p vault-app` in the main tree can fail on non-exhaustive matches that are not mine to fix.

**Why:** scope rules forbid touching their files or adding handling for their in-flight API; fixing it in place would collide with their work.
**How to apply:** `git worktree add --detach /tmp/<name> HEAD`, `git diff -- crates/vault-app/<my files> | (cd /tmp/<name> && git apply)`, run build/test/clippy/fmt there with a separate `CARGO_TARGET_DIR` (~2.5 min cold), then `git worktree remove --force` and delete the target dir. Report the main-tree breakage to the orchestrator. See [[feedback-fmt-scope]].
