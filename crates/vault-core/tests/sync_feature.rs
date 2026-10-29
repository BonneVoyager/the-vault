//! `unlock_with_key` / `export_vault_key` behind the `sync` feature (03 §3 step 6a).

mod common;

use common::*;
use vault_core::format::VaultFile;
use vault_core::{LockedVault, TamperKind, VaultError};

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

#[test]
fn handle_survives_change_password_but_not_rotation() {
    let mut v = new_vault();
    populate(&mut v, 2);
    let handle = v.export_vault_key();

    v.change_password(
        &pw(),
        &secret("another password"),
        vault_core::KdfParams::for_tests(),
    )
    .unwrap();
    let after_change = LockedVault::parse(&v.serialize()).unwrap();
    assert_vaults_eq(
        &v,
        &after_change.unlock_with_key(&handle, device()).unwrap(),
    );

    v.rotate_vault_key(&secret("another password")).unwrap();
    let after_rotate = LockedVault::parse(&v.serialize()).unwrap();
    assert_eq!(
        after_rotate.unlock_with_key(&handle, device()).unwrap_err(),
        VaultError::WrongPassword
    );
    let fresh = v.export_vault_key();
    assert_vaults_eq(&v, &after_rotate.unlock_with_key(&fresh, device()).unwrap());
}
