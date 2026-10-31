---
name: field-identity-decisions
description: 2026-10-31 FI-1 field identity in vault-core — Field.id (v4), FORMAT_VERSION 2 (new vaults only; a v1 file stays v1 on save, upgrade_format is explicit because slot AADs bind the prefix version), UUIDv5 migration formula, removed_fields tombstones + merge rule, set_field by id / set_field_named, FieldNotFound/AmbiguousField, HistoryEntry.field_id, v2-basic fixture, historical v1 regenerators
metadata:
  type: project
---

Owner decision 2026-10-31 (package FI-1): fields are identified by a UUID, duplicate and
empty names allowed, format bump acceptable while older files still open. Implemented in
`crates/vault-core`. Supersedes "fields keyed by name" everywhere in
[[mutation-merge-decisions]] and the "merges by name" line in [[created-at-section-decisions]].
See [[format-decisions]], [[attachment-decisions]], [[history-tombstone-decisions]].

**Model:** `Field.id: Uuid` (v4 from `Field::new`; `Debug` prints it). `Item::field(name)` is
now first NON-SECTION match, ASCII case-insensitive, and an EMPTY name never matches;
`Item::field_by_id(id)`. `FieldTombstone { id, removed_at }` (Copy/Debug/Eq) and
`Item.removed_fields` (newest first, one per id, cap `vault::FIELD_TOMBSTONE_CAP = 64`,
written only when non-empty, purged by `purge_tombstones_older_than`). `HistoryEntry.field_id:
Option<Uuid>` (optional CBOR `field_id` bytes(16), written only when Some; missing/null ->
None; bad -> Malformed). Importers push history with `field_id: None` (lead: "nothing else
changes"); `set_field` on a Password field records `Some(field.id)`. `uuid` gained the `v5`
feature (only `sha1_smol`, already in the lockfile).

**Format (01 §4/§9):** field map key `"id": bytes(16)` ALWAYS written (canonical order:
`id, kind, name, value, section, modified_at`); item key `removed_fields: [{id, removed_at}]`
sorts between `attachments` and `removed_history`. `FORMAT_VERSION = 2`, `MIN_FORMAT_VERSION
= 1`. `decode_item_plain(plain, id, modified_at, format_version)` (4th arg new): under v2 a
field without `id` is `Malformed("field: missing key \"id\"")`; under v1 a missing `id`
derives `Field::derived_id(item_id, name, ordinal)` = `Uuid::new_v5(&item_id, b"field:" ||
name || b":" || ordinal decimal)`, ordinal = count of EARLIER fields in the array with the
byte-equal name (explicit-id siblings count too). Present-but-bad `id` (null, wrong type,
not 16 bytes) and duplicate ids within an item are `Malformed` under both versions.

**Version rule (DEVIATION from the lead's "writer always writes v2", reported):** the prefix
version is bound into every slot AAD (01 §2), so relabelling a v1 file as v2 needs every slot
re-wrapped and the core holds only the KEK of the credential it was given (enclave slots
cannot be re-wrapped on the password path, password slots cannot on the kek path). Hence:
`create` -> v2; `serialize` keeps `header.format_version` (a v1-origin file stays v1 and just
gains explicit ids; older builds keep `id`/`removed_fields`/`field_id` as extras);
`UnlockedVault::upgrade_format(password, now)` is the explicit upgrade: verifies the password,
re-wraps password slots under the v2 AAD (fresh nonces, same vault_key), DROPS enclave/
recovery/opaque slots (same contract as `rotate_vault_key`), sets `format_version`, bumps the
header stamp; no-op (no KDF) when already current. The CLI/app should offer it when
`header().format_version < FORMAT_VERSION`.

**Merge (03 §5):** `merge_live` keys fields by id, whole-field LWW by `field.modified_at`
(name/kind/kind_raw/value/section/extras travel with the winner; tie -> owning item device
id -> ours); then union both `removed_fields` (normalised), drop any field with a marker
`removed_at >= field.modified_at`, and drop every marker whose field survived (strictly
newer edit resurrects AND clears the marker on both sides). Conflict losers of a dropped
field do not enter history. `normalize_history` sorts `(replaced_at desc, value asc,
Some(field_id) first)` and dedups on `(value, replaced_at)` only, so a v1 entry and its
id-carrying twin collapse to the one with the id; `item_eq` compares `field_id`,
`removed_fields` and field ids (`field_eq`), `field_content_eq` does not include the id.

**Mutations:** `update` diffs by id: rename = edit (bumped if stamp untouched); disappeared id
-> marker `removed_at = max(stamp(now, before.modified_at), prev.modified_at)` (floor lifted,
like `remove_attachment_ref`); changing a field's id = removal + new field (carried stamp ->
`stamp(carried, before.modified_at)`); a live field whose id has a marker is "re-added":
lifted to `stamp(now, removed_at)` if not already past it and the marker dropped
(`reconcile_field_tombstones`, also in `try_insert`); duplicate ids -> `Malformed("duplicate
field id ..")` and the item restored (`check_field_ids`, `insert` panics like for bad refs).
`set_field(item, field_id, value, now)` by id; `set_field_named(item, name, value, now)` ->
`FieldNotFound` (none, or empty name, or only a Section matches) / `AmbiguousField` (>1
non-section ASCII-ci match), unknown item still `Malformed("unknown item ..")` first.
`remove_field(item, field_id, now)` -> marker at `stamp(now, item).max(field.modified_at)`,
`FieldNotFound` if absent. New `VaultError::{FieldNotFound, AmbiguousField}` unit variants
(documented extensions to 01 §7, like `NoUsableSlot`).

**Fixtures:** `v2-basic.vault` (items 0x0F "Duplicate names": fields 0x21/0x22 both
`username`, 0x23 empty name, 0x24 password set to `hunter3` at V2_AT+1 (history `hunter2`
with field_id 0x24), 0x25 `pin` removed at V2_AT+2 -> marker; 0x10 "Plain note" field 0x26;
V2_AT = T0+80) by `regenerate_v2_basic_fixture`. Every `v1-*` regenerator now calls
`v1_regenerators_are_historical()` which panics unless `FORMAT_VERSION == 1` (so a v1 fixture
can never be overwritten by the v2 writer). `every_fixture_in_the_directory_opens` requires
>= 8 fixtures, one `v1-` and one `v2-`, name version == prefix version (also after a save),
unique field ids, and for v1 files the derived-id formula; `post_removal` includes
`v2-basic`. Test helper `common::field_named(item, name)` finds any field incl. sections
(production `Item::field` skips them); `assert_field_eq`/`assert_item_eq` compare ids,
`field_id`, `removed_fields`. Tests addressing a Section by name must use its id.

**Why:** names were the merge key, so a rename duplicated a field and a removal came back
from any peer (03 §5 accepted limit); the owner wants stable identity and free labels.
**How to apply:** never match fields by name in core logic again; new field-level state must
travel with the field id; keep `derived_id` byte-exact forever (it is what every v1 file's
ids ARE); never write a v2 prefix without re-wrapping slots; keep `upgrade_format` as the
only path that changes `format_version`.

**Bug-hunt fixes 2026-10-31 (docs/qa/bug-hunt-2026-10-31.md H1/M1/L1), tests/merge_hunt.rs:**
- H1: `merge_from` header winner is the tuple `(format_version, slots_stamp, slots_device_id)`
  and adoption copies `format_version` with slots/kdf/stamp/device/keys, so slots and the
  version they are wrapped under are one unit; a v2 header beats any v1 stamp (upgrade is
  never undone, a merge can never lower the version); a slot change made on the OLD version
  after an upgrade (password change, Touch ID enrolment) is DROPPED by the merge.
- M1: every tie ends symmetric: field pick = stamp, owning-item device id, then
  `format::field_canonical_bytes` (greater wins); `ours_wins_metadata` = modified_at,
  device_id, then `encode_item_plain` bytes. Never "tie -> ours" again.
- L1: `normalize_field_tombstones` no longer truncates; `cap_field_tombstones` runs only in
  `merge_live` and drops (oldest first) only markers whose field is absent on BOTH input
  sides, leaving the list over the cap otherwise. Residual limit: a third device that never
  saw a capped-away marker can resurrect that field. `removed_attachments` keeps its plain cap.
