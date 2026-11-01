---
name: workspace-fmt-concurrency
description: Never run `cargo fmt --all` (write mode) here; other agents edit other crates concurrently
metadata:
  type: feedback
---
Run `cargo fmt -p <my crate>` (or rustfmt on my files) to format, and only `cargo fmt --all -- --check` to verify.

**Why:** on 2026-11-01 other agents had uncommitted in-progress edits in vault-core/vault-sync while I worked in vault-macos; `cargo fmt --all` can rewrite their files, and `cargo build --workspace` failed from their half-done work (not mine).

**How to apply:** scope formatting to the task crate; when workspace checks fail, `git status` first to see whether the failures are in files someone else is editing, and report rather than fix.
