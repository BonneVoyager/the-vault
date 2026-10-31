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
//! | both tombstones | — | the side with greater `(modified_at, device_id)`; tie -> ours |
//! | both live | — | field-level merge, see [`merge_items`] |
//!
//! The result's `modified_at` is always `max(ours, theirs)`, and its `created_at` (v1.3) is
//! always the minimum of the two known values (see [`merge_created_at`]); a differing
//! `created_at` alone is not a change.
//!
//! The merge is idempotent (folding the same `theirs` twice changes nothing the second time)
//! and commutative in content. Field *order* follows the metadata winner, so it is also
//! commutative whenever one side strictly wins on `(modified_at, device_id)`; an exact tie
//! (same millisecond, same device) keeps "ours" order on each side.
//!
//! Only the identical-pair tie is not resolved by timestamps. `device_id` is compared as
//! raw bytes (`Uuid`'s `Ord`), which is what the spec means by "greater `device_id` bytes".
//!
//! **Header merge** (03 §5): the slot set and KDF parameters are last-writer-wins as a unit,
//! keyed by `header.slots_modified_at`; see [`UnlockedVault::merge_from`].

use std::cmp::Ordering;

use secrecy::ExposeSecret;

use super::{ATTACHMENT_TOMBSTONE_CAP, HISTORY_CAP, UnlockedVault};
use crate::crypto::Keys;
use crate::error::VaultError;
use crate::item::{
    AttachmentRef, AttachmentTombstone, Field, FieldKind, HistoryEntry, Item, Millis,
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
    /// **Header merge** (03 §5). If `other.header.slots_modified_at` is greater than ours
    /// (a missing stamp reads as 0), or equal with a greater `slots_device_id` (the
    /// persisted device id of that change; greater bytes win, like item metadata, and a
    /// missing id sorts below any present one), our whole slot set (key slots *and* opaque slots, in their order), KDF
    /// parameters (with the unknown keys of the `kdf` map), stamp and device id are replaced by
    /// theirs and `report.header_updated` is set; otherwise ours stay. Equal stamp *and*
    /// device id (the same change seen twice, or two never-stamped headers) keeps ours, which
    /// is what makes the merge idempotent. The persisted id is used rather than the
    /// in-memory `device_id`: vault-sync opens the on-disk copy with the local device id, so
    /// the two `UnlockedVault`s always carry the same one. A password change, re-calibration, slot add/remove or key rotation on one
    /// device therefore survives the other device's next save instead of being reverted by
    /// it. Top-level header extras, `vault_id` and `created_at` are never touched.
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
        // `Option` ordering puts a missing id below every present one.
        let theirs_newer = (other.header.slots_stamp(), other.header.slots_device_id)
            > (self.header.slots_stamp(), self.header.slots_device_id);
        if theirs_newer {
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
/// bytes, tie -> ours.
fn ours_wins_metadata(ours: &Item, theirs: &Item) -> bool {
    match ours.modified_at.cmp(&theirs.modified_at) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => ours.device_id >= theirs.device_id,
    }
}

/// Both sides live. Metadata (`title`, `favorite`, `tags`, `icon`, `extras`, `device_id`)
/// comes from the winner per [`ours_wins_metadata`]; the icon (v1.2) is never merged at a
/// finer grain. Fields are keyed by `name`: a field on
/// one side only is taken; a field on both sides is taken from the greater field
/// `modified_at`, tie -> greater owning-item `device_id`, tie -> ours. Field order is the
/// winner's, followed by the loser's extra fields in the loser's order. History is the union
/// on `(value, replaced_at)` plus, for every [`FieldKind::Password`] field that lost a true
/// conflict (both sides present, different values), the losing value as
/// `(value, replaced_at = loser field modified_at)` so nothing is lost (03 §5). A losing
/// value already present in the union by value (the common "only one side edited" case,
/// where the winner recorded it when replacing it) is not pushed again, so merging an
/// untouched copy never changes history. `removed_history` is the union of both stamp
/// lists (newest first, capped at [`HISTORY_CAP`]); every history entry whose `replaced_at`
/// is in that set is then dropped (including a conflict loser that happens to carry such a
/// stamp), so a deletion survives a merge with a peer that still holds the entry. The rest
/// is kept newest first, capped at [`HISTORY_CAP`].
///
/// Attachment removal markers are the union by `id` with the greater `removed_at`, newest
/// first, capped at [`ATTACHMENT_TOMBSTONE_CAP`]. Attachment references are the union by `id`
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

    // Returns (kept, dropped).
    let pick = |o: &'a Field, t: &'a Field| -> (&'a Field, &'a Field) {
        let take_ours = match o.modified_at.cmp(&t.modified_at) {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => ours.device_id >= theirs.device_id,
        };
        if take_ours { (o, t) } else { (t, o) }
    };

    let mut conflict_losers: Vec<&Field> = Vec::new();
    let mut fields = Vec::with_capacity(winner.fields.len() + loser.fields.len());
    for w in &winner.fields {
        match loser.fields.iter().find(|l| l.name == w.name) {
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
        if !winner.fields.iter().any(|w| w.name == l.name) {
            fields.push(l.clone());
        }
    }

    let mut history = ours.history.clone();
    history.extend(theirs.history.iter().cloned());
    for lost in conflict_losers {
        let present = history
            .iter()
            .any(|h| h.value.expose_secret() == lost.value.expose_secret());
        if !present {
            history.push(HistoryEntry {
                value: lost.value.clone(),
                replaced_at: lost.modified_at,
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

    Item {
        id: ours.id,
        title: winner.title.clone(),
        deleted_at: None,
        device_id: winner.device_id,
        favorite: winner.favorite,
        tags: winner.tags.clone(),
        icon: winner.icon.clone(),
        created_at: merge_created_at(ours.created_at, theirs.created_at),
        fields,
        history,
        attachments,
        removed_attachments,
        removed_history,
        modified_at: ours.modified_at.max(theirs.modified_at),
        extras: winner.extras.clone(),
    }
}

/// Sort attachment removal markers newest first (ties by id), keep one marker per id (the
/// greatest `removed_at`), and cap at [`ATTACHMENT_TOMBSTONE_CAP`]. Shared with
/// `remove_attachment_ref`, `insert` and `update`.
pub(crate) fn normalize_attachment_tombstones(tombstones: &mut Vec<AttachmentTombstone>) {
    tombstones.sort_by(|a, b| {
        b.removed_at
            .cmp(&a.removed_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    // After the sort the first occurrence of an id is its greatest removed_at.
    let mut seen = std::collections::BTreeSet::new();
    tombstones.retain(|t| seen.insert(t.id));
    tombstones.truncate(ATTACHMENT_TOMBSTONE_CAP);
}

/// Sort removed-history stamps newest first, drop duplicates, and cap at [`HISTORY_CAP`].
/// Shared with `remove_history_entry`, `clear_history`, `insert` and `update`.
pub(crate) fn normalize_removed_history(stamps: &mut Vec<Millis>) {
    stamps.sort_unstable_by(|a, b| b.cmp(a));
    stamps.dedup();
    stamps.truncate(HISTORY_CAP);
}

/// Sort history newest first (ties broken by value so the order is deterministic on every
/// device), drop exact `(value, replaced_at)` duplicates, and keep at most [`HISTORY_CAP`]
/// entries. Shared with `set_field`.
pub(crate) fn normalize_history(history: &mut Vec<HistoryEntry>) {
    history.sort_by(|a, b| {
        b.replaced_at
            .cmp(&a.replaced_at)
            .then_with(|| a.value.expose_secret().cmp(b.value.expose_secret()))
    });
    history.dedup_by(|a, b| history_entry_eq(a, b));
    history.truncate(HISTORY_CAP);
}

fn history_entry_eq(a: &HistoryEntry, b: &HistoryEntry) -> bool {
    a.replaced_at == b.replaced_at && a.value.expose_secret() == b.value.expose_secret()
}

/// Everything about a field except its timestamp. Used by `update` to detect edits that
/// forgot to bump `modified_at`.
pub(crate) fn field_content_eq(a: &Field, b: &Field) -> bool {
    a.name == b.name
        && a.kind == b.kind
        && a.kind_raw == b.kind_raw
        && a.section == b.section
        && a.extras == b.extras
        && a.value.expose_secret() == b.value.expose_secret()
}

fn field_eq(a: &Field, b: &Field) -> bool {
    a.modified_at == b.modified_at && field_content_eq(a, b)
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
}
