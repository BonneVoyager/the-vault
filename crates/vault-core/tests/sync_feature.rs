//! `unlock_with_key` / `export_vault_key` behind the `sync` feature (03 §3 step 6a).

mod common;

use common::*;
use vault_core::format::VaultFile;
use vault_core::{LockedVault, TamperKind, Uuid, VaultError};

fn other_device() -> vault_core::Uuid {
    vault_core::Uuid::from_u128(0x5E5E_5E5E_5E5E_5E5E_5E5E_5E5E_5E5E_5E5E)
}

#[test]
fn unlock_with_key_matches_password_unlock_and_sets_device_id() {
    let mut v = new_vault();
    populate(&mut v, 4);
    let handle = v.export_vault_key();
    let bytes = v.serialize();
    let locked = LockedVault::parse(&bytes).unwrap();

    let by_password = locked.unlock(&pw()).unwrap();
    let by_key = locked.unlock_with_key(&handle, other_device()).unwrap();

    assert_vaults_eq(&by_password, &by_key);
    assert_vaults_eq(&v, &by_key);
    assert_eq!(by_key.device_id(), other_device());
    assert_eq!(by_key.header(), by_password.header());
}

#[test]
fn handle_from_different_vault_is_wrong_password() {
    let mut a = new_vault();
    populate(&mut a, 2);
    let other = new_vault();
    let foreign = other.export_vault_key();

    let locked = LockedVault::parse(&a.serialize()).unwrap();
    assert_eq!(
        locked.unlock_with_key(&foreign, device()).unwrap_err(),
        VaultError::WrongPassword
    );

    // Same for an empty target: the manifest is the first (and only) tag check.
    let empty = LockedVault::parse(&new_vault().serialize()).unwrap();
    assert_eq!(
        empty.unlock_with_key(&foreign, device()).unwrap_err(),
        VaultError::WrongPassword
    );
}

#[test]
fn tampered_second_item_is_still_reported_as_tampered() {
    let mut v = new_vault();
    populate(&mut v, 3);
    let handle = v.export_vault_key();
    let bytes = v.serialize();
    let file = VaultFile::parse(&bytes).unwrap();
    let second = file.items[1].id;
    let third = file.items[2].id;

    let t = rewrite(&bytes, |f| f.items[1].ct[0] ^= 0x01);
    assert_eq!(
        LockedVault::parse(&t)
            .unwrap()
            .unlock_with_key(&handle, device())
            .unwrap_err(),
        VaultError::Tampered(TamperKind::Item(second))
    );
    let t = rewrite(&bytes, |f| f.items[2].nonce[0] ^= 0x01);
    assert_eq!(
        LockedVault::parse(&t)
            .unwrap()
            .unlock_with_key(&handle, device())
            .unwrap_err(),
        VaultError::Tampered(TamperKind::Item(third))
    );
    // Manifest damage after at least one good item is `Tampered(Manifest)`, not a key error.
    let t = rewrite(&bytes, |f| f.manifest.ct[0] ^= 0x01);
    assert_eq!(
        LockedVault::parse(&t)
            .unwrap()
            .unlock_with_key(&handle, device())
            .unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
}

#[test]
fn tampered_first_item_is_conflated_with_wrong_key() {
    // Documented limitation of the heuristic: with the right key and a damaged *first*
    // record (or every record dropped, see below), `unlock_with_key` says WrongPassword while
    // `unlock` says Tampered. vault-sync must therefore treat WrongPassword from
    // `unlock_with_key` as "re-verify with the password", never as "adopt disk silently".
    let mut v = new_vault();
    populate(&mut v, 2);
    let handle = v.export_vault_key();
    let bytes = v.serialize();
    let first = VaultFile::parse(&bytes).unwrap().items[0].id;
    let t = rewrite(&bytes, |f| f.items[0].ct[0] ^= 0x01);
    let locked = LockedVault::parse(&t).unwrap();
    assert_eq!(
        locked.unlock_with_key(&handle, device()).unwrap_err(),
        VaultError::WrongPassword
    );
    assert_eq!(
        locked.unlock(&pw()).unwrap_err(),
        VaultError::Tampered(TamperKind::Item(first))
    );

    // Rollback to empty: all item records dropped, manifest left behind. The manifest is now
    // the first (and only) tag check, its AAD count no longer matches, so WrongPassword.
    let t = rewrite(&bytes, |f| f.items.clear());
    let locked = LockedVault::parse(&t).unwrap();
    assert_eq!(
        locked.unlock_with_key(&handle, device()).unwrap_err(),
        VaultError::WrongPassword
    );
    assert_eq!(
        locked.unlock(&pw()).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
}

#[test]
fn unlock_with_key_on_empty_vault_works() {
    let v = new_vault();
    let handle = v.export_vault_key();
    let locked = LockedVault::parse(&v.serialize()).unwrap();
    let opened = locked.unlock_with_key(&handle, device()).unwrap();
    assert_eq!(opened.items_including_deleted().count(), 0);
    assert_eq!(opened.vault_id(), v.vault_id());
    assert_eq!(opened.device_id(), device());
}

#[test]
fn duplicate_handle_unlocks_and_survives_original_drop() {
    let mut v = new_vault();
    populate(&mut v, 1);
    let handle = v.export_vault_key();
    let copy = handle.duplicate();
    drop(handle);
    let locked = LockedVault::parse(&v.serialize()).unwrap();
    let opened = locked.unlock_with_key(&copy, device()).unwrap();
    assert_vaults_eq(&v, &opened);
}

/// 01 §4 `header_digest` on the `unlock_with_key` path (reviewer W1): a vault-sync peer
/// opening a tampered file with its cached key gets `Tampered(Manifest)`, never a header to
/// merge. The KDF params are checked here too (no slot is unwrapped on this path).
#[test]
fn header_digest_is_checked_by_unlock_with_key() {
    let mut v = new_vault();
    populate(&mut v, 2);
    let handle = v.export_vault_key();
    v.change_password(
        &pw(),
        &secret("another password"),
        vault_core::KdfParams::for_tests(),
        5_000,
    )
    .unwrap();
    let cur = v.serialize();
    let open = |bytes: &[u8]| {
        LockedVault::parse(bytes)
            .unwrap()
            .unlock_with_key(&handle, device())
    };
    assert_vaults_eq(&v, &open(&cur).unwrap());
    let manifest = VaultError::Tampered(TamperKind::Manifest);
    for edit in [
        (|f: &mut VaultFile| f.header.slots_modified_at = Some(6_000)) as fn(&mut VaultFile),
        |f| f.header.slots_modified_at = Some(u64::MAX),
        |f| f.header.slots_modified_at = None,
        |f| f.header.slots_device_id = None,
        |f| f.header.kdf.t_cost = 2,
        |f| f.header.kdf.salt[0] ^= 1,
        |f| f.header.slots.clear(),
    ] {
        let tampered = rewrite(&cur, edit);
        match LockedVault::parse(&tampered) {
            Ok(locked) => assert_eq!(
                locked.unlock_with_key(&handle, device()).unwrap_err(),
                manifest
            ),
            Err(VaultError::Malformed(_)) => {} // e.g. no slots at all
            Err(e) => panic!("{e:?}"),
        }
    }
}

/// The reviewer's gap: a merge whose `theirs` was opened with the cached key (vault-sync's
/// normal path) adopts a legitimately newer header, and the result opens with the new
/// password while the cached key still works (the vault key did not change).
#[test]
fn merge_through_unlock_with_key_adopts_newer_header() {
    let mut a = new_vault();
    populate(&mut a, 2);
    let mut b = unlock(&a.serialize()).unwrap();
    b.set_device_id(Uuid::from_u128(0xB));
    let new_pw = secret("changed on B");
    // Later than the creation stamp (`new_vault` is created at 1_700_000_000 s), so the
    // change is stamped with this clock rather than `creation + 1`.
    let changed_at = 1_700_000_005_000;
    b.change_password(
        &pw(),
        &new_pw,
        vault_core::KdfParams::for_tests(),
        changed_at,
    )
    .unwrap();
    let handle = a.export_vault_key();
    let b_disk = LockedVault::parse(&b.serialize())
        .unwrap()
        .unlock_with_key(&handle, device())
        .unwrap();
    assert_eq!(b_disk.header().slots_modified_at, Some(changed_at));
    assert_eq!(b_disk.header().slots_device_id, Some(Uuid::from_u128(0xB)));

    let report = a.merge_from(&b_disk).unwrap();
    assert!(report.header_updated, "{report:?}");
    let bytes = a.serialize();
    let locked = LockedVault::parse(&bytes).unwrap();
    assert_eq!(locked.unlock(&pw()).unwrap_err(), VaultError::WrongPassword);
    assert_vaults_eq(&a, &locked.unlock(&new_pw).unwrap());
    assert_vaults_eq(&a, &locked.unlock_with_key(&handle, device()).unwrap());
    assert_eq!(locked.header().slots, b.header().slots);
}

/// A header merge that adopts a rotated vault key (03 §5) invalidates handles exported
/// before it, exactly like a local rotation; a handle exported afterwards opens the result.
#[test]
fn handle_is_stale_after_merge_adopts_a_rotated_key() {
    let mut a = new_vault();
    populate(&mut a, 2);
    let mut b = unlock(&a.serialize()).unwrap();
    let stale = a.export_vault_key();
    b.rotate_vault_key(&pw(), 7_000).unwrap();
    let b_disk = LockedVault::parse(&b.serialize()).unwrap();
    assert_eq!(
        b_disk.unlock_with_key(&stale, device()).unwrap_err(),
        VaultError::WrongPassword,
        "vault-sync sees KeyRotatedOnDisk here and re-asks for a credential"
    );
    let report = a.merge_from(&b_disk.unlock(&pw()).unwrap()).unwrap();
    assert!(report.header_updated);
    let merged = LockedVault::parse(&a.serialize()).unwrap();
    assert_eq!(
        merged.unlock_with_key(&stale, device()).unwrap_err(),
        VaultError::WrongPassword
    );
    let fresh = a.export_vault_key();
    assert_vaults_eq(&a, &merged.unlock_with_key(&fresh, device()).unwrap());
    assert_vaults_eq(&a, &merged.unlock(&pw()).unwrap());
}

#[test]
fn handle_survives_change_password_but_not_rotation() {
    let mut v = new_vault();
    populate(&mut v, 2);
    let handle = v.export_vault_key();

    v.change_password(
        &pw(),
        &secret("another password"),
        vault_core::KdfParams::for_tests(),
        5_000,
    )
    .unwrap();
    let after_change = LockedVault::parse(&v.serialize()).unwrap();
    assert_vaults_eq(
        &v,
        &after_change.unlock_with_key(&handle, device()).unwrap(),
    );

    v.rotate_vault_key(&secret("another password"), 5_001)
        .unwrap();
    let after_rotate = LockedVault::parse(&v.serialize()).unwrap();
    assert_eq!(
        after_rotate.unlock_with_key(&handle, device()).unwrap_err(),
        VaultError::WrongPassword
    );
    let fresh = v.export_vault_key();
    assert_vaults_eq(&v, &after_rotate.unlock_with_key(&fresh, device()).unwrap());
}

/// Why `create` stamps the header (01 §2): a device holding the cached vault key must not keep
/// opening a file whose password slot was edited by hand. On an unstamped (v1.0) header the
/// slot is bound into nothing this path checks, so the tampered file still opens; a fresh
/// vault is digest-bound (01 §4) and the same edit is `Tampered(Manifest)` at open.
#[test]
fn flipped_slot_nonce_on_a_fresh_vault_fails_unlock_with_key() {
    let flip = |bytes: &[u8]| {
        rewrite(bytes, |f| {
            f.header.slots[0].as_key_mut().unwrap().nonce[0] ^= 1;
        })
    };

    let mut v = new_vault();
    populate(&mut v, 2);
    let handle = v.export_vault_key();
    let bytes = v.serialize();
    assert!(
        LockedVault::parse(&bytes)
            .unwrap()
            .header()
            .slots_modified_at
            .is_some()
    );
    let tampered = flip(&bytes);
    let locked = LockedVault::parse(&tampered).unwrap();
    assert_eq!(
        locked.unlock_with_key(&handle, device()).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
    assert_eq!(locked.unlock(&pw()).unwrap_err(), VaultError::WrongPassword);

    // The same edit on a never-stamped file is invisible to the key path: this is the gap
    // that stamping at creation closes. (Existing v1.0 files stay this way until a slot
    // mutation stamps them.)
    let mut old = unstamped_vault();
    populate(&mut old, 2);
    let handle = old.export_vault_key();
    let locked = LockedVault::parse(&flip(&old.serialize())).unwrap();
    assert!(locked.unlock_with_key(&handle, device()).is_ok());
    assert_eq!(locked.unlock(&pw()).unwrap_err(), VaultError::WrongPassword);

    // Empty fresh vault: the manifest is the first tag check on this path, so the tamper is
    // reported as `WrongPassword` (first-failure rule) but still fails at open.
    let empty = new_vault();
    let handle = empty.export_vault_key();
    let locked = LockedVault::parse(&flip(&empty.serialize())).unwrap();
    assert_eq!(
        locked.unlock_with_key(&handle, device()).unwrap_err(),
        VaultError::WrongPassword
    );
}
