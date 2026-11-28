//! Record-level unknown keys in a merge and an upgrade (bug hunt 2026-11-27 N10, its
//! security review, and the owner decision of the same day; 01 §4 and §9, 03 §5).
//!
//! The plaintext unknown keys of an `ItemRecord` carry no stamp. Between two version 3
//! vaults (the manifest vouches for them) they travel whole with the item winner, like the
//! unknown keys inside the item, and are part of the "equal to ours / equal to theirs"
//! comparison that decides the restamp (02 guarantee 6). Below version 3 nothing
//! authenticates them: a peer's are never merge input, and a vault's own are dropped when
//! it moves to version 3 (`upgrade_format`, or a merge that adopts a version 3 header), so
//! no version 3 manifest ever vouches for a key a pre-3 file carried.
//!
//! `with_record_keys` plants keys: a plain edit below version 3, the work of a newer
//! writer holding the vault key from 3 on.

mod common;

use common::*;
use vault_core::format::VaultFile;
use vault_core::{MergeReport, TamperKind, UnlockedVault, Uuid, VaultError};

const V3_META: &[u8] = include_bytes!("fixtures/v3-meta.vault");
const V2_BASIC: &[u8] = include_bytes!("fixtures/v2-basic.vault");
const V1_FORWARD: &[u8] = include_bytes!("fixtures/v1-forward.vault");

fn dev_o() -> Uuid {
    Uuid::from_u128(0x0A)
}

fn dev_t() -> Uuid {
    Uuid::from_u128(0x0B)
}

/// A version 1 vault written by device O with one login, and the login's id and stamp.
fn base() -> (UnlockedVault, Uuid, u64) {
    let mut v = unstamped_vault();
    v.set_device_id(dev_o());
    let id = v.insert(sample_item(1, 1_000), 1_000);
    let stamp = v.get(id).unwrap().modified_at;
    (v, id, stamp)
}

/// `base` opened as `device`, upgraded to version 3, then given `keys` on the record of `id`
/// by a (test-side) version 3 writer, so the manifest vouches for them.
fn v3(base: &UnlockedVault, id: Uuid, keys: &[(&str, u64)], device: Uuid) -> UnlockedVault {
    let mut v = with_record_keys(base, id, &[], device);
    v.upgrade_format(&pw(), 5_000).unwrap();
    with_record_keys(&v, id, keys, device)
}

/// `snapshot` (a file below version 3) opened as device O, with one more item only this
/// device holds and `evil` planted on every record. Returns the vault and the extra id.
fn planted_pre_v3(snapshot: &[u8]) -> (UnlockedVault, Uuid) {
    let mut v = unlock(snapshot).unwrap();
    v.set_device_id(dev_o());
    let mut ids: Vec<Uuid> = v.items_including_deleted().map(|i| i.id).collect();
    let extra = v.insert(sample_item(9, 1_500), 1_500);
    ids.push(extra);
    for id in ids {
        v = with_record_keys(&v, id, &[("evil", 9)], dev_o());
    }
    assert!(version(&v) < 3);
    (v, extra)
}

/// Every record-level key name in a written file.
fn key_names(bytes: &[u8]) -> Vec<String> {
    let file = VaultFile::parse(bytes).unwrap();
    let names = file.items.iter().flat_map(|r| r.extras.iter());
    names
        .map(|(k, _)| k.as_text().unwrap().to_owned())
        .collect()
}

/// The file opens with the password and, with the `sync` feature, with the vault key.
fn assert_opens_on_both_paths(bytes: &[u8], v: &UnlockedVault) {
    assert_vaults_eq(&unlock(bytes).unwrap(), v);
    #[cfg(feature = "sync")]
    vault_core::LockedVault::parse(bytes)
        .unwrap()
        .unlock_with_key(&v.export_vault_key(), dev_o())
        .unwrap();
}

/// The peer as vault-sync sees it: read back from its file.
fn on_disk(v: &UnlockedVault) -> UnlockedVault {
    unlock(&v.serialize()).unwrap()
}

fn keys(pairs: &[(&str, u64)]) -> Vec<(String, u64)> {
    pairs.iter().map(|(k, n)| ((*k).to_owned(), *n)).collect()
}

/// Item records the merge changed (independently upgraded devices differ in their header,
/// so `changed()` would also count the header adoption).
fn items_changed(report: &MergeReport) -> usize {
    report.added + report.updated + report.deleted
}

fn version(v: &UnlockedVault) -> u16 {
    v.header().format_version
}

/// Same items, same stamps, same record-level keys.
fn assert_converged(a: &UnlockedVault, b: &UnlockedVault, id: Uuid) {
    assert_vaults_eq(a, b);
    assert_eq!(record_keys(a, id), record_keys(b, id));
}

// ---------------------------------------------------------------------------------------
// Version 3 peer: the keys travel with the item winner
// ---------------------------------------------------------------------------------------

/// The N10 case: the peer's record wins and carries a key ours lacks. Both files are
/// version 3, so the adopted key is digest-bound in the file we save.
#[test]
fn a_winning_peer_record_brings_its_record_level_key() {
    let (base, id, _) = base();
    let mut o = v3(&base, id, &[], dev_o());
    let mut t = v3(&base, id, &[("zz_shared", 7)], dev_t());
    t.set_field_named(id, "username", secret("newer"), 2_000)
        .unwrap();
    let file_t = t.serialize();
    assert_eq!(&file_t[4..6], &[0, 3]);
    assert!(record_keys(&o, id).is_empty());

    let report = o.merge_from(&unlock(&file_t).unwrap()).unwrap();
    assert_eq!((report.updated, report.unchanged), (1, 0));
    assert_eq!(
        o.get(id).unwrap().modified_at,
        2_000,
        "theirs' record at a greater stamp is adopted verbatim"
    );
    let expected = keys(&[("zz_shared", 7)]);
    assert_eq!(record_keys(&o, id), expected);

    // The saved file binds the key (01 §4) and opens on both paths.
    let saved = o.serialize();
    let without = rewrite(&saved, |f| f.items[0].extras.clear());
    assert_eq!(
        unlock(&without).unwrap_err(),
        VaultError::Tampered(TamperKind::Item(id))
    );
    let by_password = unlock(&saved).unwrap();
    assert_vaults_eq(&by_password, &o);
    #[cfg(feature = "sync")]
    {
        let by_key = vault_core::LockedVault::parse(&saved)
            .unwrap()
            .unlock_with_key(&o.export_vault_key(), dev_o())
            .unwrap();
        assert_eq!(record_keys(&by_key, id), expected);
    }
    // ... and the key survives a second save.
    let again = unlock(&by_password.serialize()).unwrap();
    assert_eq!(record_keys(&again, id), expected);
    assert!(!o.merge_from(&again).unwrap().changed());
}

/// The mirror: ours wins, the peer holds a different key. Ours is kept, the peer's is
/// dropped with the losing record, and the peer converges on ours when it merges back.
#[test]
fn our_winning_record_keeps_its_key_and_the_peer_converges_on_it() {
    let (base, id, _) = base();
    let mut o = v3(&base, id, &[("x_ours", 1)], dev_o());
    let mut t = v3(&base, id, &[("x_theirs", 2)], dev_t());
    o.set_field_named(id, "username", secret("newer"), 3_000)
        .unwrap();

    let report = o.merge_from(&on_disk(&t)).unwrap();
    assert_eq!((items_changed(&report), report.unchanged), (0, 1));
    assert_eq!(record_keys(&o, id), keys(&[("x_ours", 1)]));

    let report = t.merge_from(&on_disk(&o)).unwrap();
    assert_eq!(report.updated, 1);
    assert_eq!(t.get(id).unwrap().modified_at, 3_000);
    assert_eq!(record_keys(&t, id), keys(&[("x_ours", 1)]));
    assert_converged(&o, &t, id);
    assert!(!o.merge_from(&on_disk(&t)).unwrap().changed());
    assert!(!t.merge_from(&on_disk(&o)).unwrap().changed());
}

/// Two copies of the same item that differ in nothing but the record-level keys.
#[test]
fn a_record_level_key_difference_alone_is_a_change_stamped_by_the_symmetric_rule() {
    let (base, id, stamp) = base();

    // Equal stamps: the items tie completely, the greater canonical bytes of the keys win
    // on both sides. The losing side takes theirs' record at a stamp its own record used,
    // so it restamps; the winning side is unchanged, then adopts the restamp verbatim.
    let mut o = v3(&base, id, &[("x", 1)], dev_o());
    let mut t = v3(&base, id, &[("x", 2)], dev_t());
    let (o_before, t_before) = (on_disk(&o), on_disk(&t));
    let report = t.merge_from(&o_before).unwrap();
    assert_eq!(items_changed(&report), 0);
    assert_eq!(t.get(id).unwrap().modified_at, stamp);
    let report = o.merge_from(&t_before).unwrap();
    assert_eq!((report.updated, report.unchanged), (1, 0));
    assert_eq!(o.get(id).unwrap().modified_at, stamp + 1);
    assert_eq!(record_keys(&o, id), keys(&[("x", 2)]));
    let report = t.merge_from(&on_disk(&o)).unwrap();
    assert_eq!(report.updated, 1);
    assert_converged(&o, &t, id);
    assert!(!o.merge_from(&on_disk(&t)).unwrap().changed());

    // Theirs at a strictly greater stamp (a content-free restamp): the stamp decides, not
    // the bytes, and theirs' record is adopted verbatim with its keys.
    let mut o = v3(&base, id, &[("x", 9)], dev_o());
    let mut t = v3(&base, id, &[("x", 2)], dev_t());
    t.update(id, 2_000, |_| {}).unwrap();
    let report = o.merge_from(&on_disk(&t)).unwrap();
    assert_eq!((report.updated, report.unchanged), (1, 0));
    assert_eq!(o.get(id).unwrap().modified_at, 2_000);
    assert_eq!(record_keys(&o, id), keys(&[("x", 2)]));
    assert_converged(&o, &t, id);

    // A true field-level merge: a record neither side wrote, stamped past both on both
    // sides, with the keys of the item winner (the later edit).
    let mut o = v3(&base, id, &[("a", 1)], dev_o());
    let mut t = v3(&base, id, &[("b", 2)], dev_t());
    o.set_field_named(id, "username", secret("o-user"), 2_000)
        .unwrap();
    t.set_field_named(id, "url", secret("https://t.example"), 3_000)
        .unwrap();
    let (o_before, t_before) = (on_disk(&o), on_disk(&t));
    assert_eq!(o.merge_from(&t_before).unwrap().updated, 1);
    assert_eq!(t.merge_from(&o_before).unwrap().updated, 1);
    assert_eq!(o.get(id).unwrap().modified_at, 3_001);
    assert_eq!(record_keys(&o, id), keys(&[("b", 2)]));
    assert_converged(&o, &t, id);
    assert!(!o.merge_from(&on_disk(&t)).unwrap().changed());
}

/// With a tombstone involved one whole item wins; the record-level keys are that side's. A
/// strip drops them (as before), and the stripped tombstone takes them off the peer too.
#[test]
fn record_level_keys_follow_the_tombstone_winner_and_a_strip_removes_them() {
    let (base, id, _) = base();
    let mut o = v3(&base, id, &[("a", 1)], dev_o());
    let mut t = v3(&base, id, &[("b", 2)], dev_t());
    o.delete(id, 5_000).unwrap();
    assert_eq!(record_keys(&o, id), keys(&[("a", 1)]), "delete keeps them");

    // Tombstone beats the older live copy, on both sides.
    assert_eq!(items_changed(&o.merge_from(&on_disk(&t)).unwrap()), 0);
    assert_eq!(record_keys(&o, id), keys(&[("a", 1)]));
    assert_eq!(t.merge_from(&on_disk(&o)).unwrap().deleted, 1);
    assert_eq!(t.get(id).unwrap().modified_at, 5_000);
    assert_converged(&o, &t, id);

    // Strip on O: its record-level keys go with the content, and T, merging the stripped
    // (newer) tombstone, drops its copy of them as well.
    o.delete_permanently(id, 7_000).unwrap();
    assert!(record_keys(&o, id).is_empty());
    assert_eq!(t.merge_from(&on_disk(&o)).unwrap().updated, 1);
    assert!(record_keys(&t, id).is_empty());
    assert_converged(&o, &t, id);
}

/// (c) Both sides are tombstones with different keys: the newer tombstone's keys win.
#[test]
fn two_tombstones_with_different_keys_converge_on_the_newer_one() {
    let (base, id, _) = base();
    let mut o = v3(&base, id, &[("a", 1)], dev_o());
    let mut t = v3(&base, id, &[("b", 2)], dev_t());
    o.delete(id, 2_000).unwrap();
    t.delete(id, 3_000).unwrap();
    let (o_before, t_before) = (on_disk(&o), on_disk(&t));
    assert_eq!(items_changed(&t.merge_from(&o_before).unwrap()), 0);
    let report = o.merge_from(&t_before).unwrap();
    assert_eq!((report.updated, report.deleted), (1, 0));
    assert_eq!(o.get(id).unwrap().modified_at, 3_000, "adopted verbatim");
    assert_eq!(record_keys(&o, id), keys(&[("b", 2)]));
    assert_converged(&o, &t, id);
}

/// (d) A later edit resurrects the item over the peer's stripped tombstone (which has a
/// higher stamp and no keys): the live side is the item winner, so its keys survive on
/// both sides, under a stamp past both inputs.
#[test]
fn resurrection_over_a_stripped_tombstone_keeps_the_live_side_keys() {
    let (base, id, _) = base();
    let mut o = v3(&base, id, &[("a", 1)], dev_o());
    let mut t = v3(&base, id, &[("b", 2)], dev_t());
    o.set_field_named(id, "username", secret("later"), 10_000)
        .unwrap();
    t.delete(id, 5_000).unwrap();
    t.delete_permanently(id, 20_000).unwrap();
    assert!(record_keys(&t, id).is_empty());
    let (o_before, t_before) = (on_disk(&o), on_disk(&t));
    assert_eq!(o.merge_from(&t_before).unwrap().updated, 1);
    assert_eq!(t.merge_from(&o_before).unwrap().updated, 1);
    for v in [&o, &t] {
        let item = v.get(id).unwrap();
        assert!(!item.is_deleted());
        assert_eq!(item.modified_at, 20_001);
        assert_eq!(record_keys(v, id), keys(&[("a", 1)]));
    }
    assert_converged(&o, &t, id);
}

/// (e) A `created_at` carry together with a keys difference: T's copy has the earlier
/// creation time and other keys at the base stamp, O's copy was restamped later. O is the
/// item winner, so O's keys stay; the minimum `created_at` is carried, which makes a
/// record neither side wrote and stamps it past both, identically on both sides.
#[test]
fn a_created_at_carry_with_a_keys_difference_converges_on_the_winner_keys() {
    let (base, id, stamp) = base();
    // T's copy: the base record re-inserted into an emptied twin with `created_at = 0`.
    let mut twin = with_record_keys(&base, id, &[], dev_o());
    let mut copy = twin.get(id).unwrap().clone();
    assert!(copy.created_at > Some(0));
    copy.created_at = Some(0);
    twin.delete(id, stamp).unwrap();
    twin.purge_tombstones_older_than(u64::MAX);
    twin.set_device_id(copy.device_id);
    twin.insert(copy, stamp);
    assert_eq!(twin.get(id).unwrap().modified_at, stamp);
    let mut t = v3(&twin, id, &[("x", 2)], dev_t());
    let mut o = v3(&base, id, &[("x", 9)], dev_o());
    o.update(id, 8_000, |_| {}).unwrap();

    let (o_before, t_before) = (on_disk(&o), on_disk(&t));
    assert_eq!(o.merge_from(&t_before).unwrap().updated, 1);
    assert_eq!(t.merge_from(&o_before).unwrap().updated, 1);
    for v in [&o, &t] {
        let item = v.get(id).unwrap();
        assert_eq!((item.created_at, item.modified_at), (Some(0), 8_001));
        assert_eq!(record_keys(v, id), keys(&[("x", 9)]));
    }
    assert_converged(&o, &t, id);
    assert_eq!(items_changed(&o.merge_from(&on_disk(&t)).unwrap()), 0);
}

/// (g) Two version 3 files that share `(id, stamp)` and differ only in the record-level
/// keys: the manifest entry's digest tells the two records apart, in both directions.
#[test]
fn splicing_a_record_with_other_keys_at_the_same_pair_is_tampered_item() {
    let (base, id, _) = base();
    let o = v3(&base, id, &[("x", 1)], dev_o());
    let t = v3(&base, id, &[("x", 2)], dev_t());
    let (file_o, file_t) = (o.serialize(), t.serialize());
    for (file, donor) in [(&file_o, &file_t), (&file_t, &file_o)] {
        assert_eq!(
            unlock(&splice(file, donor, id)).unwrap_err(),
            VaultError::Tampered(TamperKind::Item(id))
        );
    }
}

// ---------------------------------------------------------------------------------------
// Peer below version 3: its keys are not merge input (security review 2026-11-27)
// ---------------------------------------------------------------------------------------

/// (a) Laundering. Ours is version 3. An authentic pre-upgrade snapshot (version 1, and
/// the version 2 fixture) gets a key planted on every record by someone without the vault
/// key and is merged as a peer. The untouched items tie exactly, and the planted key must
/// not win that tie: nothing changes, nothing is restamped, no key is written.
#[test]
fn a_planted_key_in_a_pre_v3_copy_is_not_laundered_into_a_v3_vault() {
    let (base, _, _) = base();
    let v1_snapshot = base.serialize();
    for (name, snapshot) in [("v1", v1_snapshot.as_slice()), ("v2", V2_BASIC)] {
        let mut o = unlock(snapshot).unwrap();
        o.set_device_id(dev_o());
        o.upgrade_format(&pw(), 5_000).unwrap();
        let before = o.serialize();
        assert_eq!(&before[4..6], &[0, 3], "{name}");
        let before = VaultFile::parse(&before).unwrap();

        let mut peer = unlock(snapshot).unwrap();
        for rec in &before.items {
            peer = with_record_keys(&peer, rec.id, &[("evil", 1)], dev_t());
        }
        assert!(version(&peer) < 3, "{name}");
        assert_eq!(record_keys(&peer, before.items[0].id).len(), 1, "{name}");

        let report = o.merge_from(&peer).unwrap();
        assert!(!report.changed(), "{name}: {report:?}");
        let saved = o.serialize();
        let after = VaultFile::parse(&saved).unwrap();
        assert_eq!(after.items.len(), before.items.len());
        for (b, a) in before.items.iter().zip(&after.items) {
            assert_eq!((b.id, b.modified_at), (a.id, a.modified_at), "{name}");
            assert!(a.extras.is_empty(), "{name}: no planted key is written");
        }
        assert!(unlock(&saved).is_ok(), "{name}");
    }
}

/// (b) The stamp pump. Both sides below version 3: a key planted again and again (and a
/// key of ours removed) never counts as a change, so the authenticated `modified_at` does
/// not move and a peer's tombstone a few milliseconds later still wins.
#[test]
fn planted_keys_below_v3_never_move_a_stamp_and_a_later_tombstone_still_wins() {
    let (base, id, stamp) = base();
    let mut o = with_record_keys(&base, id, &[("mine", 1)], dev_o());
    let mut t = with_record_keys(&base, id, &[], dev_t());
    t.delete(id, stamp + 4).unwrap();
    assert_eq!(t.get(id).unwrap().deleted_at, Some(stamp + 4));

    let plants: [&[(&str, u64)]; 6] = [
        &[("x", 1)],
        &[("x", 2)],
        &[("x", 3)],
        &[("y", 1), ("z", 1)],
        &[("zzzz", u64::MAX)],
        &[],
    ];
    for plant in plants {
        let planted = with_record_keys(&o, id, plant, dev_o());
        let report = o.merge_from(&planted).unwrap();
        assert!(!report.changed(), "{plant:?}: {report:?}");
        assert_eq!(o.get(id).unwrap().modified_at, stamp, "{plant:?}");
        assert_eq!(record_keys(&o, id), keys(&[("mine", 1)]), "{plant:?}");
    }

    assert_eq!(o.merge_from(&on_disk(&t)).unwrap().deleted, 1);
    assert!(o.get(id).unwrap().is_deleted());
    assert_eq!(record_keys(&o, id), keys(&[("mine", 1)]), "ours are kept");
}

#[derive(Debug, Clone, Copy)]
enum Stamps {
    Tie,
    OursGreater,
    TheirsGreater,
}

/// (f) Ours below version 3, with `evil` planted on a shared item and on an item only ours
/// holds, against a version 3 peer (clean, or with a bound key of its own). Ours' keys are
/// never merge input: the merge runs as if ours had none, the header merge moves us to
/// version 3, and the file we save vouches only for the peer's key where the rule gives
/// it. The peer, merging back, converges without ever seeing `evil`.
#[test]
fn a_pre_v3_vault_never_carries_its_record_level_keys_into_version_3() {
    let (base, _, _) = base();
    let v1_snapshot = base.serialize();
    let none: &[(&str, u64)] = &[];
    for (name, snapshot) in [("v1", v1_snapshot.as_slice()), ("v2", V2_BASIC)] {
        let id = VaultFile::parse(snapshot).unwrap().items[0].id;
        for peer_keys in [none, &[("p", 5)]] {
            for stamps in [Stamps::Tie, Stamps::OursGreater, Stamps::TheirsGreater] {
                let ctx = format!("{name} {peer_keys:?} {stamps:?}");
                let (mut o, extra) = planted_pre_v3(snapshot);
                let mut t = unlock(snapshot).unwrap();
                t.set_device_id(dev_t());
                t.upgrade_format(&pw(), 5_000).unwrap();
                let stamp = o.get(id).unwrap().modified_at;
                match stamps {
                    Stamps::Tie => {}
                    Stamps::OursGreater => o.update(id, stamp + 50, |_| {}).unwrap(),
                    Stamps::TheirsGreater => t.update(id, stamp + 50, |_| {}).unwrap(),
                }
                let mut t = with_record_keys(&t, id, peer_keys, dev_t());

                // The version 3 side reads nothing from us while we are below 3.
                let mut early = on_disk(&t);
                early.merge_from(&on_disk(&o)).unwrap();
                assert_eq!(key_names(&early.serialize()), key_names(&t.serialize()));

                let report = o.merge_from(&on_disk(&t)).unwrap();
                assert!(report.header_updated, "{ctx}");
                let (want_keys, want_stamp) = match stamps {
                    Stamps::Tie => (peer_keys, stamp + u64::from(!peer_keys.is_empty())),
                    Stamps::OursGreater => (none, stamp + 50),
                    Stamps::TheirsGreater => (peer_keys, stamp + 50),
                };
                assert_eq!(record_keys(&o, id), keys(want_keys), "{ctx}");
                assert_eq!(o.get(id).unwrap().modified_at, want_stamp, "{ctx}");
                assert!(
                    o.get(extra).is_some(),
                    "{ctx}: the item only ours holds stays"
                );

                let saved = o.serialize();
                assert_eq!(&saved[4..6], &[0, 3], "{ctx}");
                assert!(!key_names(&saved).contains(&"evil".to_owned()), "{ctx}");
                for entry in manifest_entries(&manifest_key(&saved), &saved) {
                    let vouched = entry.id == id && !want_keys.is_empty();
                    assert_eq!(entry.extras_digest.is_some(), vouched, "{ctx}");
                }
                assert_opens_on_both_paths(&saved, &o);

                t.merge_from(&unlock(&saved).unwrap()).unwrap();
                assert!(
                    !key_names(&t.serialize()).contains(&"evil".to_owned()),
                    "{ctx}"
                );
                assert_converged(&o, &t, id);
                assert_eq!(
                    items_changed(&o.merge_from(&on_disk(&t)).unwrap()),
                    0,
                    "{ctx}"
                );
            }
        }
    }
}

/// `upgrade_format` from below version 3 drops every record-level key (live items and
/// tombstones) instead of letting the first version 3 save bind them; no item is
/// restamped, every manifest entry has two elements, and the pre-upgrade record cannot be
/// put back. Checked on a version 1 file and on the version 2 fixture.
#[test]
fn upgrade_format_drops_unbound_record_level_keys() {
    let (base, id, _) = base();
    let mut with_tombstone = with_record_keys(&base, id, &[], dev_o());
    let gone = with_tombstone.insert(sample_item(3, 1_200), 1_200);
    with_tombstone.delete(gone, 1_300).unwrap();
    let v1_snapshot = with_tombstone.serialize();
    for (name, snapshot) in [("v1", v1_snapshot.as_slice()), ("v2", V2_BASIC)] {
        let (mut v, _) = planted_pre_v3(snapshot);
        let before_bytes = v.serialize();
        let before = VaultFile::parse(&before_bytes).unwrap();
        assert!(before.items.iter().all(|r| r.extras.len() == 1), "{name}");

        v.upgrade_format(&pw(), 5_000).unwrap();
        let saved = v.serialize();
        assert_eq!(&saved[4..6], &[0, 3], "{name}");
        let after = VaultFile::parse(&saved).unwrap();
        assert_eq!(after.items.len(), before.items.len(), "{name}");
        for (b, a) in before.items.iter().zip(&after.items) {
            assert_eq!((b.id, b.modified_at), (a.id, a.modified_at), "{name}");
            assert!(a.extras.is_empty(), "{name}");
        }
        let entries = manifest_entries(&manifest_key(&saved), &saved);
        assert_eq!(entries.len(), after.items.len(), "{name}");
        assert!(entries.iter().all(|e| e.extras_digest.is_none()), "{name}");
        assert_opens_on_both_paths(&saved, &v);
        let spliced = splice(&saved, &before_bytes, after.items[0].id);
        assert!(
            matches!(unlock(&spliced).unwrap_err(), VaultError::Tampered(_)),
            "{name}"
        );
    }
}

/// A vault already at version 3 is untouched by `upgrade_format`: its keys are bound.
#[test]
fn a_no_op_upgrade_keeps_the_bound_keys_of_a_v3_vault() {
    let (base, id, _) = base();
    let mut v = v3(&base, id, &[("x", 1)], dev_o());
    let header = v.header().clone();
    v.upgrade_format(&pw(), 9_000).unwrap();
    assert_eq!(v.header(), &header);
    assert_eq!(record_keys(&v, id), keys(&[("x", 1)]));
    let saved = v.serialize();
    let entries = manifest_entries(&manifest_key(&saved), &saved);
    assert!(
        entries
            .iter()
            .all(|e| e.extras_digest.is_some() == (e.id == id))
    );
    assert_opens_on_both_paths(&saved, &v);
}

/// (h) An item only the peer holds. From a file below version 3 it enters a version 3
/// vault without its record-level keys (our manifest would bind them); a vault that is
/// below 3 itself takes them as before (unbound either way); from a version 3 peer they
/// are authenticated and come along.
#[test]
fn a_peer_only_item_from_a_pre_v3_file_enters_a_v3_vault_without_record_keys() {
    let (base, id, _) = base();
    let mut peer = with_record_keys(&base, id, &[], dev_t());
    let extra = peer.insert(sample_item(2, 1_500), 1_500);
    let mut peer = with_record_keys(&peer, extra, &[("evil", 1)], dev_t());
    assert!(version(&peer) < 3);

    let mut ours_v3 = v3(&base, id, &[], dev_o());
    assert_eq!(ours_v3.merge_from(&peer).unwrap().added, 1);
    assert!(ours_v3.get(extra).is_some());
    assert!(record_keys(&ours_v3, extra).is_empty());
    assert!(unlock(&ours_v3.serialize()).is_ok());

    let mut ours_v1 = with_record_keys(&base, id, &[], dev_o());
    assert_eq!(ours_v1.merge_from(&peer).unwrap().added, 1);
    assert_eq!(record_keys(&ours_v1, extra), keys(&[("evil", 1)]));

    // The peer's own upgrade drops the planted key; a key it holds as a version 3 vault
    // is bound and comes along.
    peer.upgrade_format(&pw(), 6_000).unwrap();
    assert!(record_keys(&peer, extra).is_empty());
    let peer = with_record_keys(&peer, extra, &[("bound", 1)], dev_t());
    let mut ours_v3 = v3(&base, id, &[], dev_o());
    assert_eq!(ours_v3.merge_from(&on_disk(&peer)).unwrap().added, 1);
    assert_eq!(record_keys(&ours_v3, extra), keys(&[("bound", 1)]));
    assert!(unlock(&ours_v3.serialize()).is_ok());
}

// ---------------------------------------------------------------------------------------
// Self-merge
// ---------------------------------------------------------------------------------------

/// Merging a vault with its own copy changes nothing, record-level keys included. The two
/// fixtures that carry such a key (version 3 and version 1) still open and still write it.
#[test]
fn self_merge_is_a_no_op_with_record_level_keys() {
    for (name, bytes) in [("v3-meta", V3_META), ("v1-forward", V1_FORWARD)] {
        let mut v = unlock(bytes).unwrap();
        v.set_device_id(device());
        let before = VaultFile::parse(&v.serialize()).unwrap();
        assert!(
            before.items.iter().any(|r| !r.extras.is_empty()),
            "{name}: the fixture carries a record-level key"
        );
        let report = v.merge_from(&unlock(bytes).unwrap()).unwrap();
        assert!(!report.changed(), "{name}");
        assert_eq!(report.unchanged, before.items.len(), "{name}");
        let saved = v.serialize();
        let after = VaultFile::parse(&saved).unwrap();
        for (b, a) in before.items.iter().zip(&after.items) {
            assert_eq!(
                (b.id, b.modified_at, &b.extras),
                (a.id, a.modified_at, &a.extras),
                "{name}"
            );
        }
        assert!(unlock(&saved).is_ok(), "{name}");
    }
}
