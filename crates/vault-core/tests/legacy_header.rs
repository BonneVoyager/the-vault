//! Security review 2026-11-26 L-02: a header without `slots_modified_at` (a v1.0-era file
//! that never had a slot change, e.g. `v1-basic.vault`) is not bound into the manifest, so a
//! key-less edit of its slots in a copy used to win the header merge's final byte tie-break
//! and be written back by the next save. Two rules close that: `merge_from` never adopts an
//! unstamped peer header, and `serialize` stamps a never-stamped header (with 1) on its
//! first save so the manifest covers the slots from then on. The `unlock_with_key` half of
//! the reproduction (Appendix B) lives in `sync_feature.rs`.

mod common;

use ciborium::Value;
use common::*;
use vault_core::{
    KdfParams, LockedVault, OpaqueSlot, Slot, TamperKind, UnlockedVault, Uuid, VaultError,
};

const BASIC: &[u8] = include_bytes!("fixtures/v1-basic.vault");
const T1: u64 = 1_700_000_000_000;

fn open_basic() -> UnlockedVault {
    let mut v = LockedVault::parse(BASIC).unwrap().unlock(&pw()).unwrap();
    assert_eq!(v.header().slots_modified_at, None, "fixture is unstamped");
    v.set_device_id(device());
    v
}

/// The fixture with the password slot's `created_at` (outside the slot AAD, so the file
/// still opens with the password) set to `created_at`; an edit a file-writing attacker can
/// make without any key.
fn with_slot_created_at(created_at: u64) -> UnlockedVault {
    let bytes = rewrite(BASIC, |f| {
        f.header.slots[0].as_key_mut().unwrap().created_at = created_at;
    });
    let mut v = unlock(&bytes).unwrap();
    v.set_device_id(Uuid::from_u128(0x5E5E));
    v
}

fn slot_created_at(v: &UnlockedVault) -> u64 {
    v.header().slots[0].as_key().unwrap().created_at
}

#[test]
fn legacy_file_is_stamped_by_its_first_save_and_the_manifest_then_covers_the_slots() {
    let v = open_basic();
    let saved = v.serialize();
    let header = LockedVault::parse(&saved).unwrap().header().clone();
    assert_eq!(header.slots_modified_at, Some(1), "smallest possible stamp");
    assert_eq!(header.slots_device_id, Some(device()));
    assert_eq!(header.slots, v.header().slots, "slots written as stored");
    assert_eq!(
        v.header().slots_modified_at,
        None,
        "in memory: still unstamped"
    );
    assert!(
        unlock(&saved).is_ok(),
        "the correct password opens the saved file"
    );
    // Deterministic: a second save writes the same header.
    assert_eq!(
        LockedVault::parse(&v.serialize()).unwrap().header(),
        &header
    );

    // Every key-less header edit of the saved file is now caught on the password path
    // (these are outside the slot AAD, so the slot still unwraps and the manifest fails).
    let manifest = VaultError::Tampered(TamperKind::Manifest);
    for (what, edit) in [
        (
            "slot created_at",
            (|f: &mut vault_core::format::VaultFile| {
                f.header.slots[0].as_key_mut().unwrap().created_at += 1;
            }) as fn(&mut vault_core::format::VaultFile),
        ),
        ("kdf extra", |f| {
            f.header
                .kdf_extras
                .push((Value::Text("x".into()), Value::Null))
        }),
        ("stamp stripped", |f| {
            f.header.slots_modified_at = None;
            f.header.slots_device_id = None;
        }),
    ] {
        assert_eq!(
            unlock(&rewrite(&saved, edit)).unwrap_err(),
            manifest,
            "{what}"
        );
    }
    // The same edits on the committed (unstamped) bytes are invisible: that is the gap.
    let planted = rewrite(BASIC, |f| {
        f.header.slots[0].as_key_mut().unwrap().created_at += 1
    });
    assert!(unlock(&planted).is_ok());
}

#[test]
fn unstamped_peer_header_is_never_adopted_whatever_the_byte_tie_break_says() {
    let genuine = slot_created_at(&open_basic());
    // Greatest and smallest canonical slot bytes: one of them beat the genuine header on
    // the old `(version, 0, None, bytes)` tie-break in each direction.
    for planted_at in [u64::MAX, 0] {
        let mut ours = open_basic();
        let theirs = with_slot_created_at(planted_at);
        let report = ours.merge_from(&theirs).unwrap();
        assert!(!report.header_updated, "planted {planted_at}: not adopted");
        assert!(!report.changed(), "same items, nothing to save");
        assert_eq!(slot_created_at(&ours), genuine);
        assert_eq!(ours.header().slots_modified_at, None);
        let saved = ours.serialize();
        assert_eq!(
            slot_created_at(&unlock(&saved).unwrap()),
            genuine,
            "planted {planted_at}: the saved file carries our slots"
        );
        // The other way round ours is the planted copy; it keeps its own header too (no
        // manifest vouches for either side), which is the "keep ours" of two unstamped
        // headers. Nothing in a merge can repair a locally opened planted copy.
        let mut planted = with_slot_created_at(planted_at);
        assert!(!planted.merge_from(&ours).unwrap().header_updated);
        assert_eq!(slot_created_at(&planted), planted_at);
    }
}

#[test]
fn genuine_stamped_peer_is_adopted_over_an_unstamped_header_and_both_ways_converge() {
    // A peer that merely saved the legacy file: its header carries the first-save stamp 1
    // and identical slots. Adopting it is harmless and makes ours stamped in memory.
    let mut ours = open_basic();
    let saved_peer = unlock(&ours.serialize()).unwrap();
    assert_eq!(saved_peer.header().slots_modified_at, Some(1));
    assert!(ours.merge_from(&saved_peer).unwrap().header_updated);
    assert_eq!(ours.header().slots_modified_at, Some(1));
    assert_eq!(ours.header(), saved_peer.header());
    assert!(unlock(&ours.serialize()).is_ok());

    // A peer with a real slot change (stamped from its clock). Its header passed the
    // peer's own manifest check at unlock, which is the only authentication there is.
    let mut ours = open_basic();
    let mut theirs = unlock(BASIC).unwrap();
    theirs.set_device_id(Uuid::from_u128(0x5E5E));
    theirs
        .change_password(
            &pw(),
            &secret("the new password"),
            KdfParams::for_tests(),
            T1,
        )
        .unwrap();
    let theirs = unlock_with(&theirs.serialize(), "the new password");
    let report = ours.merge_from(&theirs).unwrap();
    assert!(report.header_updated);
    assert_eq!(ours.header(), theirs.header());
    let saved = ours.serialize();
    assert!(unlock_with_result(&saved, "the new password").is_ok());
    assert_eq!(unlock(&saved).unwrap_err(), VaultError::WrongPassword);
    // The reverse direction keeps theirs (ours was unstamped): converged.
    let mut theirs = theirs;
    assert!(!theirs.merge_from(&open_basic()).unwrap().header_updated);
    assert_eq!(theirs.header(), ours.header());
}

fn unlock_with(bytes: &[u8], password: &str) -> UnlockedVault {
    unlock_with_result(bytes, password).unwrap()
}

fn unlock_with_result(bytes: &[u8], password: &str) -> Result<UnlockedVault, VaultError> {
    LockedVault::parse(bytes)?.unlock(&secret(password))
}

/// An unstamped device whose slot set differs from the fixture's: a `future-kind` opaque
/// slot spliced ahead of the password slot (what a newer build could have written), opened
/// with the password and given `device`.
fn with_opaque_slot(device: Uuid) -> UnlockedVault {
    let opaque = OpaqueSlot::new(Uuid::from_u128(0x77), "future-kind", vec![]).unwrap();
    let bytes = rewrite(BASIC, |f| f.header.slots.insert(0, Slot::Opaque(opaque)));
    let mut v = unlock(&bytes).unwrap();
    assert_eq!(v.header().slots_modified_at, None);
    v.set_device_id(device);
    v
}

#[test]
fn legacy_device_adopts_the_other_legacy_devices_saved_header_but_not_its_unsaved_one() {
    let mut a = open_basic();
    let b = with_opaque_slot(Uuid::from_u128(0xB));
    assert_ne!(a.header().slots, b.header().slots);
    // In memory B is unstamped: nothing vouches for its slots, A keeps its own.
    assert!(!a.merge_from(&b).unwrap().header_updated);
    assert_eq!(a.header().slots.len(), 1);
    // B saves (stamp 1, device B); A unlocks that file and merges it: 1 > none.
    let saved = b.serialize();
    let from_file = unlock(&saved).unwrap();
    assert_eq!(from_file.header().slots_modified_at, Some(1));
    assert!(a.merge_from(&from_file).unwrap().header_updated);
    assert_eq!(a.header(), from_file.header());
    assert_eq!(a.header().slots.len(), 2);
    assert!(unlock(&a.serialize()).is_ok());
}

#[test]
fn two_first_save_headers_with_different_slots_are_decided_by_device_id_both_ways() {
    let (lo, hi) = (Uuid::from_u128(0x1), Uuid::from_u128(0x2));
    // The opaque slot sits on the lower device id in one run and the higher in the other,
    // so the outcome follows the device id, not the slot bytes.
    for (plain_dev, opaque_dev) in [(lo, hi), (hi, lo)] {
        let mut plain = open_basic();
        plain.set_device_id(plain_dev);
        let opaque = with_opaque_slot(opaque_dev);
        let (file_p, file_o) = (plain.serialize(), opaque.serialize());
        let mut p = unlock(&file_p).unwrap();
        let mut o = unlock(&file_o).unwrap();
        assert_eq!(p.header().slots_modified_at, Some(1));
        assert_eq!(o.header().slots_modified_at, Some(1));
        let (p_before, o_before) = (p.header().clone(), o.header().clone());
        let p_adopted = p.merge_from(&o).unwrap().header_updated;
        let o_adopted = o.merge_from(&p).unwrap().header_updated;
        let winner = if opaque_dev == hi {
            &o_before
        } else {
            &p_before
        };
        assert_ne!(p_adopted, o_adopted, "exactly one side moves");
        assert_eq!(p.header(), winner);
        assert_eq!(o.header(), winner);
        assert_eq!(p.header().slots_device_id, Some(hi));
        assert!(unlock(&p.serialize()).is_ok() && unlock(&o.serialize()).is_ok());
    }
}
