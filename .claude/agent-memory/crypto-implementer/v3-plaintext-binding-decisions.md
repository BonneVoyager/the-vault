---
name: v3-plaintext-binding-decisions
description: 2026-11-27 I-04 FORMAT_VERSION 3 in vault-core — whole-header digest, manifest-record extras digest in the manifest AAD (86 bytes), per-item record-extras digest as optional 3rd manifest entry element, TamperKind mapping, v2/v1 unchanged + upgrade_format path, header extras now adopted in merge, v3-basic/v3-meta fixtures, test-splicing rules
metadata:
  type: project
---

Settled 2026-11-27 fixing security review 2026-11-26 **I-04** (header `created_at`, unknown
header keys and unknown record-level keys were preserved but bound to nothing). Supersedes
the "manifest AAD" line in [[format-decisions]] and the "header extras never change" line in
[[header-merge-decisions]]; the FORMAT_VERSION=2 statements in [[field-identity-decisions]]
are historical (now 3).

**Constants:** `FORMAT_VERSION = 3`, `MIN_FORMAT_VERSION = 1`, new
`format::PLAINTEXT_BINDING_VERSION = 3` (the only place the ">= 3" rule lives besides the
version-aware helpers), `DIGEST_LEN = 32` (`HEADER_DIGEST_LEN` kept as alias). No CBOR shape
changed in v3; only what the manifest vouches for.

**v3 binding (byte-exact):**
- `Header::digest()`: v>=3 -> ALWAYS `Some(SHA-256(header.to_bytes()))` = hash of the whole
  canonical header map (vault_id, created_at, kdf+kdf_extras, all slots incl. opaque,
  stamp keys when present, every unknown header key) = exactly the header bytes on disk
  for a canonical file. v<3 -> the v1.1 rule (only when stamped, over kdf/slots/stamp/device).
  Magic and format_version stay out of the digest (version is in every AAD).
- manifest AAD v3 = `vault_id(16) || item_count_be32(4) || version_be16(2) ||
  header_digest(32) || manifest_record_digest(32)` = 86 bytes fixed;
  `manifest_record_digest = extras_digest(ManifestRecord.extras)` (SHA-256 of canonical
  CBOR map of the extras; `SHA-256(0xa0)` when empty). v<3 AAD unchanged (22 / 54 bytes).
  `manifest_aad(version, vault_id, count, header_digest: Option, record_digest: Option)`.
- manifest entries v3 = `[id, modified_at]` when the ItemRecord has no extras, else
  `[id, modified_at, extras_digest(32)]` (absence == none, so ordinary items cost nothing).
  `format::ManifestEntry {id, modified_at, extras_digest: Option}`; `encode_manifest(pairs)`
  kept (fuzz seed uses it), `encode_manifest_entries`, `decode_manifest(plain) ->
  Vec<ManifestEntry>` (lenient on arity 2|3, 3rd must be bytes(32)). Helpers:
  `extras_digest`, `item_record_digest(version, extras)` (Some only v>=3 && non-empty),
  `manifest_record_digest(version, extras)` (Some for v>=3 always).
- item AAD UNCHANGED (deliberate: qa/spec-checks has an independent `item_aad`; the
  orchestrator's design put the record digest in the manifest, which also catches a record
  rolled back to an older copy with different extras at the same (id, modified_at)).

**Unlock order (vault.rs step 5):** items -> manifest tag (`Tampered(Manifest)`) -> pair
compare (`Manifest`) -> v3 only: per-entry digest vs `item_record_digest(record.extras)`,
first mismatch in id order -> `Tampered(Item(id))` (no new TamperKind: the record is the
tampered unit). v<3 with a 3-element entry -> `Malformed` (unreachable without the key,
untested). Tamper map for a v3 file: header `created_at`/unknown key/stamp strip/kdf/slot
edit -> `Manifest`; manifest-record unknown key -> `Manifest`; item-record unknown key
injected/altered/removed -> `Item(id)`; key path identical, except the empty-vault
`WrongPassword` residual (unchanged).

**Version rule unchanged (deviation from "writers always write 3", same reasoning as
FI-1):** `serialize` keeps `header.format_version` (slot AADs bind it; enclave KEK not held),
so a v1/v2 file keeps its weaker binding through plain saves (incl. the L-02 stamp-1 save);
`upgrade_format(password, now)` (-> 3, drops enclave/opaque slots) is the only path up, and
the app/CLI run it on password unlock. Writer recomputes every digest from memory; merge
never touches them. `merge_from` NOW ADOPTS `header.extras` with the winning header
(whole header = one authenticated unit; `vault_id`/`created_at` still never change).

**Fixtures:** `v3-basic.vault` (items 0x15 login username/password/totp 0x2D-0x2F, 0x16
note 0x30, V3_AT = T0+120, stamped at creation, no extras anywhere) by
`regenerate_v3_basic_fixture`; `v3-meta.vault` = `v1-forward.vault` unlocked, device 0x11,
`upgrade_format(pw, T0+130)`, saved -> unknown keys at 7 sites (header, kdf, password slot,
item record, item payload incl. legacy `kind`, field + unknown field kind, manifest
record), opaque slot gone, by `regenerate_v3_meta_fixture`. Every `v2-*` regenerator now
calls `v2_regenerators_are_historical()`. `every_fixture_in_the_directory_opens` requires
>= 13 fixtures incl. a `v3-`; `stamped(name)` = post_removal || v3-meta; digest-bound iff
stamped || version >= 3. Tests: `tests/v3_binding.rs` (12), format.rs unit tests
(`header_digest_v3_covers_the_whole_header`, `extras_digest_known_answers_and_version_gates`).

**Coordinator follow-ups (same day, SHIP WITH WARNINGS):** manifest-record digest in the AAD
approved. Digest doc wording: v3 digest = SHA-256 of the canonical RE-ENCODING of the parsed
header map (binds content, not byte layout; equals raw header bytes only for canonical files).
Prefix downgrade of a v3 file (relabel 2/1): password path `WrongPassword` (slot AAD binds the
version), key path ALSO `WrongPassword` (not `Tampered(Manifest)` as the coordinator expected:
first item fails -> probe manifest under the relabelled AAD fails -> L1 2026-11-21 rule) — tests
`prefix_downgrade_of_a_v3_file_opens_nothing` + key-path loop. Pinned hex vectors in format.rs
unit tests: v2 digest of the fixed `header_digest_known_answer` header
`5d9c9a97...f94f`, v3 digest in `header_digest_v3_covers_the_whole_header` `a8d81ca1...f73f`
(a canonicaliser/encoding change must fail these first). `tests/binding_props.rs` (3 laws,
default 256 cases, `VAULT_PROPTEST_CASES` override, no Argon2): manifest entry codec round
trip, extras_digest order-insensitive, digest equal iff canonical content equal.

**Test-splicing rule (extends the L-02 rule):** NO plaintext of a fresh (v3) vault can be
edited by hand after `serialize` — not even record/manifest extras (used to be the "only
sites left"). Tests that plant record-level extras must use `unstamped_vault()` (v1-empty,
stays v1) — `recently_deleted::delete_permanently_drops_record_extras` and
`roundtrip` do; header extras go through `header_extras_mut()` before serialize.
`parser::unsupported_version` uses `FORMAT_VERSION + 1`.

**Downstream (not fixed, reported):** qa/spec-checks ledger asserts version 2 in
cli_bridge/format/upgrade/field_ids/field_icon/exports_1119 and its independent opener
(`src/lib.rs` `manifest_aad`/`header_digest`) cannot open v3 manifests (54-byte AAD,
v1.1 digest); vault-cli status text says "format 1; run `vault upgrade`" for any older
version; fuzz crate compiles unchanged (`decode_manifest` result ignored, `encode_manifest`
kept). vault-sync/app/cli build and use `FORMAT_VERSION` generically.

**2026-11-27 later:** `upgrade_format` no longer carries record-level keys (dropped, see
[[record-extras-merge-decisions]]); `regenerate_v3_meta_fixture` is historical and
`v3_binding.rs` test rewritten. Later the same day the header-top-level and manifest-record
keys and the kdf/slot keys (stamped header or not) are dropped by the upgrade too; the
"v3-meta = v1-forward upgraded, 7 sites" provenance above is history, the fixture is frozen.

**Why:** an attacker could alter `created_at` and inject unknown keys that persisted across
saves; a version bump is the clean way to make the stricter digest unconditional.
**How to apply:** any new plaintext key anywhere in a v3 file is bound automatically
(header via `to_bytes`, records via extras digests); never add a plaintext site outside
those; keep `item_record_digest` absence semantics; v1/v2 files must keep opening exactly
as before (fixtures assert it); when the orchestrator aligns 01 §4, the wording above is
the source of truth.
