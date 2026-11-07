---
name: recently-deleted-decisions
description: Recently Deleted (trash) in vault-core: is_trashed stamp rule (2026-11-06 L1), has_content, recover, delete_permanently, expire_deleted, deleted_items; error messages, record_extras, merge propagation outcomes and residuals
metadata:
  type: project
---

Recently Deleted (02 "Recently Deleted (2026-11-03)", 03 §5 "both tombstones" row). No format change, no FORMAT_VERSION bump (still true after the 2026-11-06 L1 fix).

Settled interpretations:
- `Item::has_content()` = any of the seven lists non-empty (fields, history, attachments, removed_fields, removed_attachments, removed_history, extras). Metadata alone (title/tags/favorite/icon/deleted_at) is not content. Kept as "what a strip removes".
- **`Item::is_trashed()` (2026-11-06, bug hunt L1)** = `deleted_at.is_some() && (has_content() || modified_at <= deleted_at)`. This is "in the trash"; `deleted_items`, `recover`, `expire_deleted` and the `delete`-on-stripped no-op all use it, so title-only items (vault add --title with card/identity template, title-only CSV/KDBX rows) are recoverable. Proof: `delete` ends with `item.deleted_at = Some(item.modified_at)` after the restamp (equality by construction, not via the writer invariant); a strip restamps `stamp(now, prev) > prev >= deleted_at` and never moves deleted_at; merges take tombstones whole. Hybrid (not pure stamp rule) because a content tombstone's modified_at legitimately moves past deleted_at (merge +1 bump, add_attachment_ref on a tombstone).
- Security review 2026-11-06: `strip_tombstone` AND `recover` floor the restamp at `stamp(now, modified_at.max(deleted_at))`, so a foreign file's shell with `deleted_at > modified_at` (parser does not enforce 01 §4) leaves the trash after one strip even when `now <= deleted_at`. Unit test lives in `src/vault.rs` `mod tests` (plants the shell on the private map; no public mutation can produce it and tests cannot re-seal files).
- Residuals of the stamp half (documented on `is_trashed`, pinned by tests): (1) equal-stamp tie (wording settled 2026-11-06, not "same-millisecond"): any merge that replaces ours with a peer tombstone at an equal `modified_at` applies the 03 §5 +1 bump, so a *title-only* tombstone reads stripped there and after convergence (content tombstones unaffected); (2) at u64::MAX a strip cannot restamp past deleted_at, so a stripped shell reads trashed and `recover` yields a live title-only item; (3) pre-2026-11-03 tombstones (fields emptied at delete, m == d) count as trashed until the first sweep restamps them. Owner was told; do not "fix" by touching merge_from's bump without a 03 §5 sentence.
- All precondition errors reuse `Malformed` with distinct messages: `"unknown item {id}"`, `"item {id} is not deleted"` (live item on recover/delete_permanently), `"item {id} is not in the trash"` (recover on a stripped tombstone; was "has no content" until 2026-11-06). Helper `not_deleted(id)` next to `unknown_item`.
- Strip (`strip_tombstone` helper, shared by `delete_permanently` and `expire_deleted`): replace each list with `Vec::new()` so secrets drop/zeroize in place; keep deleted_at + attribute stamps; `restamp(stamp(now, previous), device_id)`; ALSO drops `record_extras[id]`. Re-stripping an already stripped tombstone is allowed and only restamps. On a title-only tombstone a strip is a pure restamp, and that restamp is what takes it out of the trash.
- `expire_deleted(cutoff, now)`: strict `deleted_at < cutoff` AND `is_trashed()`; idempotent. Never drops records.
- `deleted_items()` = trashed tombstones, id order.
- `delete` keeps everything. `delete` on a non-trashed (stripped) tombstone is a no-op `Ok(())` with no restamp; a trashed tombstone (content or title-only) may be re-deleted (moves deleted_at forward).
- vault-app `state/trash.rs:54` still filters `is_deleted() && has_content()` itself (outside core scope); flagged to the owner on 2026-11-06 to switch to `is_trashed()`.

Merge outcomes verified (tests/recently_deleted.rs):
- Strip propagates via both-tombstone LWW (restamp is strictly newer). Expiry = same strip, propagates even against a peer re-delete with a smaller stamp. Same for title-only tombstones.
- Recovery wins the one-tombstone rule because the rule compares the tombstone's `deleted_at`, which a strip does NOT move: a peer strip stamped later than the recovery still loses. Only a fresh `delete` after the recovery removes it again. Same for title-only.
- Tie-break (equal modified_at): greater device_id wins regardless of which side is stripped, so content CAN come back into a stripped tombstone; next `expire_deleted` sweep strips it again (spec accepts this).

Fixture `tests/fixtures/v2-trash-legacy.vault` (2026-11-06): two pre-2026-11-03-shaped shells (lists empty, `deleted_at == modified_at`, ids 0x7A5A..01/02, tags ["legacy"]) + one live item; regenerator `regenerate_trash_legacy_fixture` (ignored) in tests/recently_deleted.rs builds the shape via `insert` of a tombstone at its own stamp. Registered in fixtures.rs `post_removal` list (stamped header, no legacy `kind`) and the >= 10 count.

Test gotchas: merge_from bumps modified_at by +1 when taking theirs at an equal stamp, so converge() needs two rounds (copy of tests/merge.rs::converge). add_attachment_ref/remove_attachment_ref each advance the item stamp (loaded_vault BASE = 1_003). sample_item already carries a history entry. `title_only()` helper = Item::new + tags + favorite.
