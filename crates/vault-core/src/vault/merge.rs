//! Three-way-free last-writer-wins merge (`03-sync.md` §5).
//!
//! `ours.merge_from(&theirs)` folds every item of `theirs` into `ours`, item by item, with no
//! common ancestor. The rules, in order:
//!
//! | ours | theirs | result |
//! |---|---|---|
//! | absent | present | take theirs (tombstones included) |
//! | present | absent | keep ours |
//! | one tombstone | — | tombstone wins iff `deleted_at >= other.modified_at`; else the live item (edit after delete resurrects) |
//! | both tombstones | — | the side with greater `(modified_at, device_id)`; tie -> greater canonical item bytes |
//! | both live | — | field-level merge, see [`merge_items`] |
//!
//! The result's `modified_at` is always `max(ours, theirs)`, and its `created_at` (v1.3) is
//! always the minimum of the two known values (see [`merge_created_at`]); a differing
//! `created_at` alone is not a change.
//!
//! Fields are matched **by [`Field::id`]** (FI-1, 2026-10-31), never by name: a field on one
//! side only is taken, a field on both sides is whole-field last-writer-wins by
//! `field.modified_at` (name, kind, value, section all travel with the winner), and a field
//! whose id has a `removed_fields` marker with `removed_at >= modified_at` is dropped,
//! which closes the "field deletion resurrection" limit of 03 §5. See [`merge_live`].
//!
//! The merge is idempotent (folding the same `theirs` twice changes nothing the second time)
//! and commutative in content. Field *order* follows the metadata winner, so it is
//! commutative in field order too: an exact `(modified_at, device_id)` tie is broken by the
//! canonical CBOR bytes of the two item payloads, so both sides pick the same winner.
//!
//! Every "tie" in this module ends in a symmetric comparison (canonical bytes), never in
//! "ours". `device_id` is compared as
//! raw bytes (`Uuid`'s `Ord`), which is what the spec means by "greater `device_id` bytes".
//!
//! **Header merge** (03 §5): the slot set and KDF parameters are last-writer-wins as a unit,
//! keyed by `header.slots_modified_at`; see [`UnlockedVault::merge_from`].

use std::cmp::Ordering;

use ciborium::Value;
use uuid::Uuid;

use secrecy::ExposeSecret;

use super::{ATTACHMENT_TOMBSTONE_CAP, FIELD_TOMBSTONE_CAP, HISTORY_CAP, UnlockedVault};
use crate::crypto::Keys;
use crate::error::VaultError;
use crate::format;
use crate::item::{
    AttachmentRef, AttachmentTombstone, Field, FieldKind, FieldTombstone, HistoryEntry, Item,
    Millis,
};

/// What `merge_from` did, per item id in `ours ∪ theirs`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Ids that were not in ours and were taken from theirs (live or tombstone).
    pub added: usize,
    /// Ids present on both sides whose merged result differs from ours and is live
    /// (includes resurrections).
    pub updated: usize,
    /// Ids that were live in ours and are a tombstone after the merge.
    pub deleted: usize,
    /// Ids whose merged result equals ours, including ids absent from theirs.
    pub unchanged: usize,
    /// The slot set and KDF parameters were taken from theirs (their
    /// `header.slots_modified_at` was greater; 03 §5 "Header merge").
    pub header_updated: bool,
}

impl MergeReport {
    /// `true` if the merge changed anything in ours (so a caller should save): an item moved
    /// or the header was taken from theirs.
    pub fn changed(&self) -> bool {
        self.added + self.updated + self.deleted > 0 || self.header_updated
    }
}

impl UnlockedVault {
    /// Fold every item of `other` into `self` per `03-sync.md` §5. See the module docs for the
    /// rules. `other` is only read.
    ///
    /// **Header merge** (03 §5). The header winner is chosen by the tuple
    /// `(format_version, slots_modified_at, slots_device_id)`: if theirs is greater (a
    /// missing stamp reads as 0, a missing device id sorts below any present one, greater
    /// device-id bytes win like item metadata), our **format version**, whole slot set (key
    /// slots *and* opaque slots, in their order), KDF parameters (with the unknown keys of
    /// the `kdf` map), stamp and device id are replaced by theirs and
    /// `report.header_updated` is set; otherwise ours stay. The version leads the tuple
    /// because every slot is wrapped under an AAD that binds it (01 §2): slots and version
    /// are one unit, a file written with one side's version and the other side's slots opens
    /// with no credential. Consequently a version 2 header always beats a version 1 header,
    /// however new the latter's stamp, so an [`UnlockedVault::upgrade_format`] is never
    /// undone and a merge can never lower the version; a slot change made on the old
    /// version after the upgrade (a password change, a Touch ID enrolment) is dropped by the
    /// merge and must be redone on the upgraded vault. Equal tuple (the same change seen
    /// twice, or two never-stamped headers) keeps ours, which is what makes the merge
    /// idempotent. The persisted id is used rather than the in-memory `device_id`:
    /// vault-sync opens the on-disk copy with the local device id, so the two
    /// `UnlockedVault`s always carry the same one. A password change, re-calibration, slot
    /// add/remove or key rotation on one device therefore survives the other device's next
    /// save instead of being reverted by it. Top-level header extras, `vault_id` and
    /// `created_at` are never touched. The next `serialize` seals every item and the
    /// manifest under the adopted version's AADs and binds the adopted header's digest
    /// (01 §4), so the manifest binding holds after adoption.
    ///
    /// **Key rotation.** Their slots wrap *their* `vault_key`, so whenever their header wins
    /// our in-memory keys are replaced by theirs too (a no-op when both sides hold the same
    /// key, which is every case except a rotation). The two always travel together: taking
    /// slots that wrap key X while still encrypting items under key Y would write a file no
    /// credential can open. The core cannot verify slots without a KEK and does not try;
    /// `other` is an [`UnlockedVault`], so it *has* the key its slots wrap. Consequences:
    /// after a merge that reports `header_updated`, any `VaultKeyHandle` exported earlier may
    /// be stale and items are re-encrypted under the adopted key on the next `serialize`.
    /// vault-sync reaches this path only after `unlock_with_key` failed on the rotated file
    /// (`KeyRotatedOnDisk`) and the user re-entered a credential; if our stamp is the greater
    /// one (a later local slot change), the rotation is undone by the merge and the other
    /// device will in turn see `KeyRotatedOnDisk`. That is the LWW rule applied to keys.
    ///
    /// **Record timestamp always moves with content.** If the merged item differs from ours but
    /// the rule's `max(ours, theirs)` leaves `modified_at` equal to ours (e.g. ours
    /// `{A@10, B@5, item@10}`, theirs `{A@3, B@8, item@8}` -> `{A@10, B@8}` at 10), the
    /// merged item is stamped `ours.modified_at + 1` instead. Otherwise the new file would
    /// carry the old `(id, modified_at)` pair with new content, and splicing the pre-merge
    /// record back in would pass the manifest check (02 guarantee 6 is unconditional). The
    /// peer takes the max on its next merge, so both sides still converge, at most one extra
    /// round trip later. The bump behaves exactly like a local edit stamped `prev + 1` by the
    /// merging device: it can win or lose an exact-millisecond tie with a genuine remote edit
    /// under the normal `(modified_at, device_id)` tie-break, and both sides converge on the
    /// same outcome either way.
    ///
    /// **Extras.** For an id present on both sides, ours' plaintext `record_extras` are kept
    /// and theirs ignored. Inside the item, the metadata loser's `ItemPlain` extras are
    /// dropped; only the winner's survive.
    ///
    /// **Attachments** (v1.1) of two live items are merged by union on `id`, sorted by
    /// `(added_at, id)`, after applying the union of both sides' removal markers: a
    /// reference whose id has a marker with `removed_at >= added_at` is dropped. A removal
    /// on one side therefore wins over the other side's untouched copy; see [`merge_live`].
    ///
    /// **Purged tombstones.** A peer that has been offline since before a delete still holds
    /// the live item; if the tombstone was purged here in the meantime, merging that peer
    /// resurrects the item (ours absent -> take theirs). See
    /// [`UnlockedVault::purge_tombstones_older_than`].
    ///
    /// # Errors
    ///
    /// `Malformed("vault_id mismatch")` if the two vaults are not the same vault. (The spec
    /// signature returns a bare `MergeReport` but says "same `vault_id` (else error)"; a
    /// `Result` is the only way to report that.)
    pub fn merge_from(&mut self, other: &UnlockedVault) -> Result<MergeReport, VaultError> {
        if self.header.vault_id != other.header.vault_id {
            return Err(VaultError::Malformed("vault_id mismatch".into()));
        }
        let mut report = MergeReport::default();
        // The format version is part of the slot unit: every slot is wrapped under an AAD
        // that binds it (01 §2), so slots and version must always be adopted together, and
        // a greater version always wins regardless of stamp (an upgrade is never undone;
        // a merge can never lower the version). `Option` ordering puts a missing device id
        // below every present one.
        let theirs_newer = (
            other.header.format_version,
            other.header.slots_stamp(),
            other.header.slots_device_id,
        ) > (
            self.header.format_version,
            self.header.slots_stamp(),
            self.header.slots_device_id,
        );
        if theirs_newer {
            self.header.format_version = other.header.format_version;
            self.header.slots = other.header.slots.clone();
            self.header.kdf = other.header.kdf.clone();
            self.header.kdf_extras = other.header.kdf_extras.clone();
            self.header.slots_modified_at = other.header.slots_modified_at;
            self.header.slots_device_id = other.header.slots_device_id;
            // Dropping the previous `Keys` zeroizes them. Same key in all but the rotation
            // case; see the docs above.
            self.keys = Keys::from_vault_key(other.keys.vault_key.clone(), self.header.vault_id);
            report.header_updated = true;
        }
        for (id, theirs) in &other.items {
            match self.items.get(id) {
                None => {
                    self.items.insert(*id, theirs.clone());
                    if let Some(extras) = other.record_extras.get(id) {
                        self.record_extras.insert(*id, extras.clone());
                    }
                    report.added += 1;
                }
                Some(ours) => {
                    let mut merged = merge_items(ours, theirs);
                    if item_eq(ours, &merged) {
                        // `created_at` is immutable metadata outside the "changed" decision
                        // (see `item_eq`): carry the merged minimum without a restamp, a
                        // report entry, or a `changed()` signal. It is persisted with the
                        // next save made for any other reason, and both sides re-derive the
                        // same minimum on every merge, so a copy that missed it converges.
                        if merged.created_at != ours.created_at {
                            // The borrow of `ours` ends here; re-fetch mutably.
                            if let Some(item) = self.items.get_mut(id) {
                                item.created_at = merged.created_at;
                            }
                        }
                        report.unchanged += 1;
                    } else {
                        if merged.modified_at == ours.modified_at {
                            merged.modified_at = ours.modified_at.saturating_add(1);
                        }
                        if merged.is_deleted() && !ours.is_deleted() {
                            report.deleted += 1;
                        } else {
                            report.updated += 1;
                        }
                        self.items.insert(*id, merged);
                    }
                }
            }
        }
        report.unchanged += self
            .items
            .keys()
            .filter(|id| !other.items.contains_key(id))
            .count();
        Ok(report)
    }
}

/// Merge two versions of the same item (same `id`). Pure; see the module docs for the rules.
pub fn merge_items(ours: &Item, theirs: &Item) -> Item {
    debug_assert_eq!(ours.id, theirs.id);
    let modified_at = ours.modified_at.max(theirs.modified_at);
    let mut result = match (ours.deleted_at, theirs.deleted_at) {
        (Some(d), None) => {
            if d >= theirs.modified_at {
                ours.clone()
            } else {
                theirs.clone()
            }
        }
        (None, Some(d)) => {
            if d >= ours.modified_at {
                theirs.clone()
            } else {
                ours.clone()
            }
        }
        (Some(_), Some(_)) => {
            if ours_wins_metadata(ours, theirs) {
                ours.clone()
            } else {
                theirs.clone()
            }
        }
        (None, None) => merge_live(ours, theirs),
    };
    result.modified_at = modified_at;
    result.created_at = merge_created_at(ours.created_at, theirs.created_at);
    result
}

/// `created_at` is immutable metadata (v1.3): the earliest known creation time wins. Both
/// `Some` -> the minimum; one `Some` -> that one; neither -> `None`. Applied to every merge
/// outcome (live, tombstone, both tombstones), independent of which side won the metadata.
pub(crate) fn merge_created_at(ours: Option<Millis>, theirs: Option<Millis>) -> Option<Millis> {
    match (ours, theirs) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, None) => a,
        (None, b) => b,
    }
}

/// `true` if ours supplies the metadata: greater `modified_at`, tie -> greater `device_id`
/// bytes, tie -> greater canonical CBOR bytes of the whole item payload (a symmetric total
/// order on content, so both devices pick the same side; equal bytes are the same item and
/// either choice is the same choice).
fn ours_wins_metadata(ours: &Item, theirs: &Item) -> bool {
    match ours
        .modified_at
        .cmp(&theirs.modified_at)
        .then_with(|| ours.device_id.cmp(&theirs.device_id))
    {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => {
            format::encode_item_plain(ours).as_slice()
                >= format::encode_item_plain(theirs).as_slice()
        }
    }
}

/// Both sides live. `title`, `favorite`, `tags` (as one set) and `icon` are each merged by
/// their own stamp ([`pick_attr`]); `extras` and `device_id` (and field order, below) come
/// from the item winner per [`ours_wins_metadata`]. Fields are keyed by **id**: a field on one side only is taken; a field on
/// both sides is taken whole (name, kind, kind_raw, value, section, extras) from the greater
/// field `modified_at`, tie -> greater owning-item `device_id`, tie -> greater canonical CBOR bytes of the
/// field (symmetric, so both devices pick the same one). Field order is
/// the winner's, followed by the loser's extra fields in the loser's order. Then the field
/// removal markers (`removed_fields`, union of both sides, one per id with the greatest
/// `removed_at`, newest first; capped at [`FIELD_TOMBSTONE_CAP`] only over markers whose field
/// is absent on both input sides, see [`cap_field_tombstones`]) are applied: a field whose
/// id has a marker with `removed_at >= field.modified_at` is dropped (a removal on one
/// side beats the other side's untouched copy), while a field stamped strictly after its
/// marker (edited after the removal) survives and the marker is dropped, so both sides
/// converge on the resurrected field. History is the union on `(value, replaced_at)` plus,
/// for every surviving [`FieldKind::Password`] field that lost a true conflict (both sides
/// present, different values), the losing value as `(value, replaced_at = loser field
/// modified_at, field_id)` so nothing is lost (03 §5). A losing value already present in the
/// union by value (the common "only one side edited" case, where the winner recorded it when
/// replacing it) is not pushed again, so merging an untouched copy never changes history.
/// `removed_history` is the union of both stamp lists (newest first, capped at
/// [`HISTORY_CAP`]); every history entry whose `replaced_at` is in that set is then dropped
/// (including a conflict loser that happens to carry such a stamp), so a deletion survives
/// a merge with a peer that still holds the entry. The rest is kept newest first, capped at
/// [`HISTORY_CAP`].
///
/// Attachment removal markers are the union by `id` with the greater `removed_at`, newest
/// first, capped at [`ATTACHMENT_TOMBSTONE_CAP`] with the same discipline as field markers
/// ([`cap_attachment_tombstones`]): only here, oldest first, and only markers whose reference
/// neither input side still holds. Attachment references are the union by `id`
/// (ours' copy kept when both carry an id; the blob and reference are immutable so the copies
/// can only differ if something is wrong) minus every reference whose id has a marker with
/// `removed_at >= added_at`, sorted by `(added_at, id)` so both sides produce the same order.
/// Ids are random and never reused, so a marker can only ever match the reference it was
/// written for.
fn merge_live<'a>(ours: &'a Item, theirs: &'a Item) -> Item {
    let ours_wins = ours_wins_metadata(ours, theirs);
    let (winner, loser) = if ours_wins {
        (ours, theirs)
    } else {
        (theirs, ours)
    };

    // Returns (kept, dropped). Greater field stamp; tie -> greater owning-item device id;
    // tie -> greater canonical CBOR bytes of the field. The last step is what makes the
    // choice symmetric: the owning items' device ids follow the metadata winner, so after
    // one merge both sides can carry the same id and a same-stamp edit would otherwise fall
    // to "ours" on each side forever (bug hunt 2026-10-31 M1).
    let pick = |o: &'a Field, t: &'a Field| -> (&'a Field, &'a Field) {
        let take_ours = match o
            .modified_at
            .cmp(&t.modified_at)
            .then_with(|| ours.device_id.cmp(&theirs.device_id))
        {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => {
                format::field_canonical_bytes(o).as_slice()
                    >= format::field_canonical_bytes(t).as_slice()
            }
        };
        if take_ours { (o, t) } else { (t, o) }
    };

    let mut conflict_losers: Vec<&Field> = Vec::new();
    let mut fields = Vec::with_capacity(winner.fields.len() + loser.fields.len());
    for w in &winner.fields {
        match loser.field_by_id(w.id) {
            None => fields.push(w.clone()),
            Some(l) => {
                let (o, t) = if ours_wins { (w, l) } else { (l, w) };
                let (kept, dropped) = pick(o, t);
                fields.push(kept.clone());
                if dropped.kind == FieldKind::Password
                    && dropped.value.expose_secret() != kept.value.expose_secret()
                {
                    conflict_losers.push(dropped);
                }
            }
        }
    }
    for l in &loser.fields {
        if winner.field_by_id(l.id).is_none() {
            fields.push(l.clone());
        }
    }
    // Removal markers: a marker at or past the field's stamp removes the field; a field
    // edited strictly after the marker survives and takes the marker with it.
    let mut removed_fields = ours.removed_fields.clone();
    removed_fields.extend_from_slice(&theirs.removed_fields);
    normalize_field_tombstones(&mut removed_fields);
    fields.retain(|f| {
        !removed_fields
            .iter()
            .any(|t| t.id == f.id && t.removed_at >= f.modified_at)
    });
    removed_fields.retain(|t| !fields.iter().any(|f| f.id == t.id));
    // The cap is enforced only here, where both sides are known: an overflowing marker may
    // go only once neither input side still carries its field (so the peer just merged
    // cannot bring it back), oldest first. Markers for fields that one side still held
    // are kept even past the cap; the next merge round, when both sides lack the field,
    // caps them. A third device that never saw the marker can still resurrect such a field
    // (03 §5 accepted limit).
    cap_field_tombstones(&mut removed_fields, |id| {
        ours.field_by_id(id).is_none() && theirs.field_by_id(id).is_none()
    });

    let mut history = ours.history.clone();
    history.extend(theirs.history.iter().cloned());
    for lost in conflict_losers {
        if !fields.iter().any(|f| f.id == lost.id) {
            continue; // the field itself was removed; its losing value is not history
        }
        let present = history
            .iter()
            .any(|h| h.value.expose_secret() == lost.value.expose_secret());
        if !present {
            history.push(HistoryEntry {
                value: lost.value.clone(),
                replaced_at: lost.modified_at,
                field_id: Some(lost.id),
            });
        }
    }
    let mut removed_history = ours.removed_history.clone();
    removed_history.extend_from_slice(&theirs.removed_history);
    normalize_removed_history(&mut removed_history);
    history.retain(|h| !removed_history.contains(&h.replaced_at));
    normalize_history(&mut history);

    let mut removed_attachments = ours.removed_attachments.clone();
    removed_attachments.extend_from_slice(&theirs.removed_attachments);
    normalize_attachment_tombstones(&mut removed_attachments);
    let removed = |a: &AttachmentRef| {
        removed_attachments
            .iter()
            .any(|t| t.id == a.id && t.removed_at >= a.added_at)
    };
    let mut attachments: Vec<AttachmentRef> = ours
        .attachments
        .iter()
        .filter(|a| !removed(a))
        .cloned()
        .collect();
    for a in &theirs.attachments {
        if ours.attachment(a.id).is_none() && !removed(a) {
            attachments.push(a.clone());
        }
    }
    attachments.sort_by(|a, b| a.added_at.cmp(&b.added_at).then_with(|| a.id.cmp(&b.id)));
    // Same discipline as `removed_fields`: a marker may fall off the cap only once neither
    // input side still carries its reference (so the peer just merged cannot bring it back
    // and its blob can be pruned), oldest first; otherwise the list stays over the cap until
    // a later merge, when both sides lack the reference, finishes the job.
    cap_attachment_tombstones(&mut removed_attachments, |id| {
        ours.attachment(id).is_none() && theirs.attachment(id).is_none()
    });

    // Per-attribute merge (03 §5, 01 §4 per-attribute stamps): each of title, favorite,
    // tags (as one set) and icon follows its own effective stamp; see `pick_attr`.
    let title = pick_attr(
        ours,
        theirs,
        |i| i.title_stamp(),
        |i| i.title_modified_at,
        |i| Value::Text(i.title.clone()),
    );
    let favorite = pick_attr(
        ours,
        theirs,
        |i| i.favorite_stamp(),
        |i| i.favorite_modified_at,
        |i| Value::Bool(i.favorite),
    );
    let tags = pick_attr(
        ours,
        theirs,
        |i| i.tags_stamp(),
        |i| i.tags_modified_at,
        |i| Value::Array(i.tags.iter().map(|t| Value::Text(t.clone())).collect()),
    );
    let icon = pick_attr(
        ours,
        theirs,
        |i| i.icon_stamp(),
        |i| i.icon_modified_at,
        |i| i.icon.as_ref().map_or(Value::Null, format::icon_to_value),
    );

    Item {
        id: ours.id,
        title: title.title.to_owned(),
        deleted_at: None,
        device_id: winner.device_id,
        favorite: favorite.favorite,
        tags: tags.tags.to_vec(),
        icon: icon.icon.clone(),
        created_at: merge_created_at(ours.created_at, theirs.created_at),
        title_modified_at: title.stamp,
        favorite_modified_at: favorite.stamp,
        tags_modified_at: tags.stamp,
        icon_modified_at: icon.stamp,
        fields,
        history,
        attachments,
        removed_attachments,
        removed_history,
        removed_fields,
        modified_at: ours.modified_at.max(theirs.modified_at),
        extras: winner.extras.clone(),
    }
}

/// The side an attribute is taken from, with the stamp the merged item records for it.
struct AttrPick<'a> {
    title: &'a str,
    favorite: bool,
    tags: &'a [String],
    icon: &'a Option<crate::item::ItemIcon>,
    stamp: Option<Millis>,
}

/// Per-attribute last-writer-wins (03 §5): the greater *effective* stamp (the stored stamp,
/// or the item's `modified_at` when the item has none) wins; tie -> greater owning-item
/// `device_id`; tie -> greater canonical CBOR bytes of the attribute value (symmetric). The
/// merged stamp is the winner's stored stamp; when the winner has none but the loser has
/// one, the winner's effective stamp is materialised so the merged item's later, larger
/// `modified_at` cannot inflate it; when neither side has one it stays `None`, so two
/// legacy items merge exactly as before.
fn pick_attr<'a>(
    ours: &'a Item,
    theirs: &'a Item,
    effective: impl Fn(&Item) -> Millis,
    stored: impl Fn(&Item) -> Option<Millis>,
    value: impl Fn(&Item) -> Value,
) -> AttrPick<'a> {
    let take_ours = match effective(ours)
        .cmp(&effective(theirs))
        .then_with(|| ours.device_id.cmp(&theirs.device_id))
    {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => {
            format::canonical_bytes(value(ours)) >= format::canonical_bytes(value(theirs))
        }
    };
    let (winner, loser) = if take_ours {
        (ours, theirs)
    } else {
        (theirs, ours)
    };
    let stamp = match (stored(winner), stored(loser)) {
        (Some(s), _) => Some(s),
        (None, Some(_)) => Some(effective(winner)),
        (None, None) => None,
    };
    AttrPick {
        title: &winner.title,
        favorite: winner.favorite,
        tags: &winner.tags,
        icon: &winner.icon,
        stamp,
    }
}

/// Sort field removal markers newest first (ties by id) and keep one marker per id (the
/// greatest `removed_at`). Shared with `remove_field`, `insert` and `update`. Deliberately
/// does **not** truncate: a marker dropped by count while a peer still holds the field
/// would let that field come back (bug hunt 2026-10-31 L1); the cap is applied by
/// [`cap_field_tombstones`] inside the merge, where both sides are known.
pub(crate) fn normalize_field_tombstones(tombstones: &mut Vec<FieldTombstone>) {
    tombstones.sort_by(|a, b| {
        b.removed_at
            .cmp(&a.removed_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut seen = std::collections::BTreeSet::new();
    tombstones.retain(|t| seen.insert(t.id));
}

/// Bring a normalised (newest-first) marker list down to [`FIELD_TOMBSTONE_CAP`] by dropping,
/// oldest first, only markers for which `droppable(id)` holds (in the merge: the field is
/// absent on both input sides). If fewer than needed are droppable the list stays over the
/// cap; a later merge finishes the job.
fn cap_field_tombstones(tombstones: &mut Vec<FieldTombstone>, droppable: impl Fn(Uuid) -> bool) {
    cap_tombstones(tombstones, FIELD_TOMBSTONE_CAP, |t| droppable(t.id));
}

/// [`cap_field_tombstones`] for attachment removal markers: down to
/// [`ATTACHMENT_TOMBSTONE_CAP`], oldest first, only markers for which `droppable(id)` holds
/// (in the merge: the reference is absent on both input sides).
fn cap_attachment_tombstones(
    tombstones: &mut Vec<AttachmentTombstone>,
    droppable: impl Fn(Uuid) -> bool,
) {
    cap_tombstones(tombstones, ATTACHMENT_TOMBSTONE_CAP, |t| droppable(t.id));
}

/// Drop, oldest (end of the newest-first list) first, droppable markers until the list is
/// at `cap` or no droppable marker is left.
fn cap_tombstones<T>(tombstones: &mut Vec<T>, cap: usize, droppable: impl Fn(&T) -> bool) {
    let mut excess = tombstones.len().saturating_sub(cap);
    if excess == 0 {
        return;
    }
    // Walk from the oldest (end) towards the newest.
    let mut i = tombstones.len();
    while excess > 0 && i > 0 {
        i -= 1;
        if droppable(&tombstones[i]) {
            tombstones.remove(i);
            excess -= 1;
        }
    }
}

/// Sort attachment removal markers newest first (ties by id) and keep one marker per id (the
/// greatest `removed_at`). Shared with `remove_attachment_ref`, `insert` and `update`.
/// Deliberately does **not** truncate (same reasoning as [`normalize_field_tombstones`]): a
/// marker dropped by count while a peer still holds the reference would let that reference,
/// and a blob vault-sync may already have pruned, come back; the cap is applied by
/// [`cap_attachment_tombstones`] inside the merge, where both sides are known.
pub(crate) fn normalize_attachment_tombstones(tombstones: &mut Vec<AttachmentTombstone>) {
    tombstones.sort_by(|a, b| {
        b.removed_at
            .cmp(&a.removed_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    // After the sort the first occurrence of an id is its greatest removed_at.
    let mut seen = std::collections::BTreeSet::new();
    tombstones.retain(|t| seen.insert(t.id));
}

/// Sort removed-history stamps newest first, drop duplicates, and cap at [`HISTORY_CAP`].
/// Shared with `remove_history_entry`, `clear_history`, `insert` and `update`.
pub(crate) fn normalize_removed_history(stamps: &mut Vec<Millis>) {
    stamps.sort_unstable_by(|a, b| b.cmp(a));
    stamps.dedup();
    stamps.truncate(HISTORY_CAP);
}

/// Sort history newest first (ties broken by value, then an entry that knows its `field_id`
/// before one that does not, so the order is deterministic on every device), drop
/// `(value, replaced_at)` duplicates (keeping the first, i.e. the one with a `field_id` when
/// a v1 entry meets its id-carrying twin), and keep at most [`HISTORY_CAP`] entries. Shared
/// with `set_field`.
pub(crate) fn normalize_history(history: &mut Vec<HistoryEntry>) {
    history.sort_by(|a, b| {
        b.replaced_at
            .cmp(&a.replaced_at)
            .then_with(|| a.value.expose_secret().cmp(b.value.expose_secret()))
            .then_with(|| b.field_id.is_some().cmp(&a.field_id.is_some()))
            .then_with(|| a.field_id.cmp(&b.field_id))
    });
    history.dedup_by(|a, b| history_key_eq(a, b));
    history.truncate(HISTORY_CAP);
}

/// The history union key: `(value, replaced_at)`, without `field_id`.
fn history_key_eq(a: &HistoryEntry, b: &HistoryEntry) -> bool {
    a.replaced_at == b.replaced_at && a.value.expose_secret() == b.value.expose_secret()
}

/// Full equality of a history entry, `field_id` included (used by [`item_eq`] so that a
/// merge that only supplies a missing `field_id` is persisted).
fn history_entry_eq(a: &HistoryEntry, b: &HistoryEntry) -> bool {
    history_key_eq(a, b) && a.field_id == b.field_id
}

/// Everything about a field except its id and timestamp. Used by `update` to detect edits
/// that forgot to bump `modified_at` (fields are matched by id first, so the id itself is
/// not part of the content).
pub(crate) fn field_content_eq(a: &Field, b: &Field) -> bool {
    a.name == b.name
        && a.kind == b.kind
        && a.kind_raw == b.kind_raw
        && a.section == b.section
        && a.extras == b.extras
        && a.value.expose_secret() == b.value.expose_secret()
}

fn field_eq(a: &Field, b: &Field) -> bool {
    a.id == b.id && a.modified_at == b.modified_at && field_content_eq(a, b)
}

fn attachment_eq(a: &AttachmentRef, b: &AttachmentRef) -> bool {
    a.id == b.id
        && a.name == b.name
        && a.size == b.size
        && a.added_at == b.added_at
        && a.chunk_nonces == b.chunk_nonces
        && a.extras == b.extras
        && a.key.as_ref() == b.key.as_ref()
}

/// Full structural equality including secrets and order. `Item` has no `PartialEq` (it holds
/// secrets), so merge decides "unchanged" here.
///
/// `created_at` is deliberately **not** compared: it is immutable metadata whose merged value
/// (the minimum) must never count as an update or bump `modified_at`. `merge_from` carries
/// the minimum separately. Test helpers that need exact equality compare it themselves.
pub fn item_eq(a: &Item, b: &Item) -> bool {
    a.id == b.id
        && a.title == b.title
        && a.deleted_at == b.deleted_at
        && a.device_id == b.device_id
        && a.favorite == b.favorite
        && a.tags == b.tags
        && a.icon == b.icon
        && a.title_modified_at == b.title_modified_at
        && a.favorite_modified_at == b.favorite_modified_at
        && a.tags_modified_at == b.tags_modified_at
        && a.icon_modified_at == b.icon_modified_at
        && a.modified_at == b.modified_at
        && a.extras == b.extras
        && a.fields.len() == b.fields.len()
        && a.fields.iter().zip(&b.fields).all(|(x, y)| field_eq(x, y))
        && a.history.len() == b.history.len()
        && a.history
            .iter()
            .zip(&b.history)
            .all(|(x, y)| history_entry_eq(x, y))
        && a.attachments.len() == b.attachments.len()
        && a.attachments
            .iter()
            .zip(&b.attachments)
            .all(|(x, y)| attachment_eq(x, y))
        && a.removed_attachments == b.removed_attachments
        && a.removed_history == b.removed_history
        && a.removed_fields == b.removed_fields
}
