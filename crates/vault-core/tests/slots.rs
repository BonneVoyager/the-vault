//! Key-slot management: guarantee 8, `unlock_with_kek`, `change_password`, `add_enclave_slot`,
//! `remove_slot`, `rotate_vault_key` (02 "keys").

mod common;

use common::*;
use rand::RngCore;
use rand::rngs::OsRng;
use vault_core::{
    KdfParams, LockedVault, SecretVec, SlotKind, TamperKind, UnlockedVault, Uuid, VaultError,
};

const NEW_PASSWORD: &str = "new password, same vault key";

fn new_pw() -> vault_core::SecretString {
    secret(NEW_PASSWORD)
}

fn random_kek() -> SecretVec<u8> {
    let mut bytes = vec![0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    SecretVec::new(bytes)
}

/// A populated vault with one password slot and one enclave slot.
fn vault_with_enclave() -> (UnlockedVault, Uuid, SecretVec<u8>) {
    let mut v = new_vault();
    populate(&mut v, 5);
    let kek = random_kek();
    let slot = v.add_enclave_slot(&kek);
    (v, slot, kek)
}

fn kinds(v: &UnlockedVault) -> Vec<SlotKind> {
    v.slots().map(|(_, k)| k).collect()
}

#[test]
fn guarantee_8_change_password_leaves_vault_key_unchanged() {
    let (mut v, slot, kek) = vault_with_enclave();
    assert_eq!(kinds(&v), [SlotKind::Password, SlotKind::Enclave]);

    v.change_password(&pw(), &new_pw(), KdfParams::for_tests())
        .unwrap();
    let bytes = v.serialize();
    let locked = LockedVault::parse(&bytes).unwrap();

    let with_new = locked.unlock(&new_pw()).unwrap();
    assert_vaults_eq(&v, &with_new);
    assert!(matches!(
        locked.unlock(&pw()),
        Err(VaultError::WrongPassword)
    ));

    // The enclave slot was added *before* the change and still unwraps the same vault_key,
    // which is the only way the items could decrypt.
    let with_kek = locked.unlock_with_kek(slot, &kek).unwrap();
    assert_vaults_eq(&v, &with_kek);
    assert_eq!(
        locked.slots().collect::<Vec<_>>(),
        v.slots().collect::<Vec<_>>()
    );
}

#[test]
fn unlock_with_kek_errors() {
    let (v, slot, kek) = vault_with_enclave();
    let locked = LockedVault::parse(&v.serialize()).unwrap();

    assert!(matches!(
        locked.unlock_with_kek(slot, &random_kek()),
        Err(VaultError::WrongPassword)
    ));
    assert!(matches!(
        locked.unlock_with_kek(Uuid::new_v4(), &kek),
        Err(VaultError::Malformed(_))
    ));
    let short = SecretVec::new(vec![0u8; 31]);
    assert!(matches!(
        locked.unlock_with_kek(slot, &short),
        Err(VaultError::Malformed(_))
    ));
    let long = SecretVec::new(vec![0u8; 33]);
    assert!(matches!(
        locked.unlock_with_kek(slot, &long),
        Err(VaultError::Malformed(_))
    ));
    // Any slot kind can be addressed by id; the password slot just needs the Argon2 KEK.
    let (password_slot, _) = locked
        .slots()
        .find(|(_, k)| *k == SlotKind::Password)
        .unwrap();
    assert!(matches!(
        locked.unlock_with_kek(password_slot, &kek),
        Err(VaultError::WrongPassword)
    ));
    // Still fine the right way round.
    assert_vaults_eq(&v, &locked.unlock_with_kek(slot, &kek).unwrap());
}

#[test]
fn remove_slot_refuses_last_password_slot_and_removes_enclave() {
    let (mut v, slot, kek) = vault_with_enclave();
    let (password_slot, _) = v.slots().find(|(_, k)| *k == SlotKind::Password).unwrap();

    let err = v.remove_slot(password_slot).unwrap_err();
    assert!(
        matches!(&err, VaultError::Malformed(m) if m.contains("last password slot")),
        "{err:?}"
    );
    assert!(matches!(
        v.remove_slot(Uuid::new_v4()),
        Err(VaultError::Malformed(_))
    ));
    assert_eq!(kinds(&v), [SlotKind::Password, SlotKind::Enclave]);

    v.remove_slot(slot).unwrap();
    assert_eq!(kinds(&v), [SlotKind::Password]);

    let locked = LockedVault::parse(&v.serialize()).unwrap();
    assert!(matches!(
        locked.unlock_with_kek(slot, &kek),
        Err(VaultError::Malformed(_))
    ));
    assert_vaults_eq(&v, &locked.unlock(&pw()).unwrap());
}

#[test]
fn rotate_vault_key_reencrypts_items_drops_enclave_and_keeps_old_file_valid() {
    let (mut v, slot, kek) = vault_with_enclave();
    let old_bytes = v.serialize();

    assert!(matches!(
        v.rotate_vault_key(&new_pw()),
        Err(VaultError::WrongPassword)
    ));
    assert_eq!(kinds(&v), [SlotKind::Password, SlotKind::Enclave]);

    let header_before = v.header().clone();
    v.rotate_vault_key(&pw()).unwrap();
    let header_after = v.header();
    assert_eq!(kinds(&v), [SlotKind::Password], "enclave slot dropped");
    assert_eq!(header_after.kdf, header_before.kdf, "kdf params unchanged");
    let (after0, before0) = (
        header_after.slots[0].as_key().unwrap(),
        header_before.slots[0].as_key().unwrap(),
    );
    assert_eq!(after0.id, before0.id);
    assert_eq!(after0.created_at, before0.created_at);
    assert_ne!(after0.nonce, before0.nonce);
    assert_ne!(after0.wrapped_key, before0.wrapped_key);

    let new_bytes = v.serialize();
    let locked = LockedVault::parse(&new_bytes).unwrap();
    assert_vaults_eq(&v, &locked.unlock(&pw()).unwrap());
    assert!(matches!(
        locked.unlock_with_kek(slot, &kek),
        Err(VaultError::Malformed(_))
    ));

    // Already-written bytes are an independent vault under the old key material.
    let old_locked = LockedVault::parse(&old_bytes).unwrap();
    assert_vaults_eq(&v, &old_locked.unlock(&pw()).unwrap());
    assert_vaults_eq(&v, &old_locked.unlock_with_kek(slot, &kek).unwrap());

    // Proof the key really changed: an item record from the old file has the same id and
    // modified_at (same AAD, same manifest pair) but was sealed under the old item key, so
    // transplanting it into the new file must fail at the item, not the manifest.
    let old_file = vault_core::format::VaultFile::parse(&old_bytes).unwrap();
    let victim = old_file.items[0].clone();
    let spliced = rewrite(&new_bytes, |file| {
        let pos = file.items.iter().position(|r| r.id == victim.id).unwrap();
        file.items[pos] = victim.clone();
    });
    assert!(matches!(
        unlock(&spliced),
        Err(VaultError::Tampered(TamperKind::Item(id))) if id == victim.id
    ));
}

#[test]
fn change_password_with_wrong_old_leaves_header_unchanged() {
    let (mut v, _, _) = vault_with_enclave();
    let before = v.header().clone();
    assert!(matches!(
        v.change_password(&new_pw(), &new_pw(), KdfParams::for_tests()),
        Err(VaultError::WrongPassword)
    ));
    assert_eq!(v.header(), &before);

    // Invalid new params are also rejected before anything is touched.
    let mut bad = KdfParams::for_tests();
    bad.t_cost = 0;
    assert!(matches!(
        v.change_password(&pw(), &new_pw(), bad),
        Err(VaultError::Malformed(_))
    ));
    assert_eq!(v.header(), &before);
    assert_vaults_eq(&v, &unlock(&v.serialize()).unwrap());
}

#[test]
fn change_password_replaces_slot_and_adopts_new_kdf_salt() {
    let (mut v, enclave, _) = vault_with_enclave();
    let before = v.header().clone();
    let old_slot = before.slots[0].as_key().unwrap();
    assert_eq!(old_slot.kind, SlotKind::Password);

    let mut params = KdfParams::for_tests();
    params.salt = [0x5a; 32];
    assert_ne!(params.salt, before.kdf.salt);
    v.change_password(&pw(), &new_pw(), params.clone()).unwrap();

    let after = v.header();
    let password_slots: Vec<_> = after
        .slots
        .iter()
        .filter_map(|s| s.as_key())
        .filter(|s| s.kind == SlotKind::Password)
        .collect();
    assert_eq!(password_slots.len(), 1);
    let new_slot = password_slots[0];
    assert_ne!(new_slot.id, old_slot.id);
    assert_ne!(new_slot.nonce, old_slot.nonce);
    assert_ne!(new_slot.wrapped_key, old_slot.wrapped_key);
    assert_eq!(new_slot.created_at, old_slot.created_at);
    assert_eq!(after.kdf, params);
    assert_eq!(after.vault_id, before.vault_id);
    assert_eq!(after.created_at, before.created_at);
    assert!(
        after.slots.iter().any(|s| s.id() == enclave),
        "enclave kept"
    );

    let locked = LockedVault::parse(&v.serialize()).unwrap();
    assert_eq!(locked.kdf_params().salt, params.salt);
    assert_eq!(locked.kdf_params(), &params);
    assert_vaults_eq(&v, &locked.unlock(&new_pw()).unwrap());
}

#[test]
fn add_enclave_slot_with_created_at_and_multiple_enclave_slots() {
    let mut v = new_vault();
    populate(&mut v, 2);
    let (k1, k2) = (random_kek(), random_kek());
    let s1 = v.add_enclave_slot_with_created_at(&k1, 1_700_000_123);
    let s2 = v.add_enclave_slot(&k2);
    assert_ne!(s1, s2);
    let header = v.header();
    assert_eq!(header.slots[1].as_key().unwrap().created_at, 1_700_000_123);
    assert_eq!(header.slots[2].as_key().unwrap().created_at, 0);

    let locked = LockedVault::parse(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &locked.unlock_with_kek(s1, &k1).unwrap());
    assert_vaults_eq(&v, &locked.unlock_with_kek(s2, &k2).unwrap());
    // KEKs are bound to their own slot id through the AAD.
    assert!(matches!(
        locked.unlock_with_kek(s1, &k2),
        Err(VaultError::WrongPassword)
    ));
}
