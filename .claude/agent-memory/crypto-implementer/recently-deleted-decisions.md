---
name: recently-deleted-decisions
description: 2026-11-03 Recently Deleted (trash) in vault-core: has_content, recover, delete_permanently, expire_deleted, deleted_items; error choices, record_extras, merge propagation outcomes
metadata:
  type: project
---

Recently Deleted (02 "Recently Deleted (2026-11-03)", 03 §5 "both tombstones" row). No format change, no FORMAT_VERSION bump.

Settled interpretations:
- `Item::has_content()` = any of the seven lists non-empty (fields, history, attachments, removed_fields, removed_attachments, removed_history, extras). Metadata alone (title/tags/favorite/icon/deleted_at) is not content.
- All precondition errors reuse `Malformed` with distinct messages (same convention as `unknown_item`, duplicate attachment, last slot): `"unknown item {id}"`, `"item {id} is not deleted"` (live item on recover/delete_permanently), `"item {id} has no content"` (recover on a stripped tombstone). Helper `not_deleted(id)` next to `unknown_item`.
- Strip (`strip_tombstone` helper, shared by `delete_permanently` and `expire_deleted`): replace each list with `Vec::new()` so secrets drop/zeroize in place; keep deleted_at + attribute stamps; `restamp(stamp(now, previous), device_id)`; ALSO drops `record_extras[id]` (mirrors purge_tombstones_older_than; record extras belong to the content record). Re-stripping an already stripped tombstone is allowed and only restamps.
- `expire_deleted(cutoff, now)`: strict `deleted_at < cutoff` AND `has_content()`; stripped tombstones are never restamped again, so it is idempotent. Never drops records.
- `deleted_items()` = tombstones with content, id order.
- `delete` keeps everything (tested with assert_item_eq against pre-delete clone). Security-review fix: `delete` on a STRIPPED tombstone is a no-op `Ok(())` with no restamp (moving deleted_at forward would re-arm the one-tombstone rule and kill a peer's recovery); a content tombstone may still be re-deleted. Saturation at u64::MAX tested.

Merge outcomes verified (tests/recently_deleted.rs):
- Strip propagates via both-tombstone LWW (restamp is strictly newer). Expiry = same strip, propagates even against a peer re-delete with a smaller stamp.
- Recovery wins the one-tombstone rule because the rule compares the tombstone's `deleted_at`, which a strip does NOT move: a peer strip stamped later than the recovery still loses (deleted_at 2000 < recovery 2500). Only a fresh `delete` after the recovery removes it again.
- Tie-break (equal modified_at): greater device_id wins regardless of which side is stripped, so content CAN come back into a stripped tombstone; next `expire_deleted` sweep strips it again (spec accepts this). Canonical-CBOR tie (same device) is content-dependent; both sides agree.

Test gotchas: merge_from bumps modified_at by +1 when taking theirs at an equal stamp, so converge() needs two rounds (copy of tests/merge.rs::converge). add_attachment_ref/remove_attachment_ref each advance the item stamp (loaded_vault BASE = 1_003). sample_item already carries a history entry.
