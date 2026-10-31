---
name: feedback-fmt-scope
description: Run rustfmt only on owned files, not `cargo fmt --all`, when other agents edit the workspace concurrently
metadata:
  type: feedback
---

Format with `rustfmt --edition 2024 <owned files>` and check with `cargo fmt --all -- --check`; do not run `cargo fmt --all` (it rewrites every crate).

**Why:** several agents edit vault-core / vault-sync / vault-app at the same time and only some files are mine; a workspace-wide rewrite can collide with their in-flight edits (2026-10-29, attachments UI: it happened to touch only my files, by luck).
**How to apply:** whenever the lead lists owned files; report fmt failures in others' files instead of fixing them. See [[gpui-version-pins]].
Careful: `rustfmt src/main.rs` (a crate root, or any file with out-of-line `mod x;`) formats every module it declares, i.e. the whole crate. Pass leaf files only, or confirm with `cargo fmt --all -- --check` that nothing else changed.

