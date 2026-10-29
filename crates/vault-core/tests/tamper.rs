//! Guarantees 4-7 and header tampering.

mod common;

use common::*;
use vault_core::format::VaultFile;
use vault_core::{LockedVault, TamperKind, VaultError};

#[test]
fn guarantee_4_flip_byte_in_item_ct() {
    let mut v = new_vault();
    populate(&mut v, 3);
    let bytes = v.serialize();
    let file = VaultFile::parse(&bytes).unwrap();
    for (idx, rec) in file.items.iter().enumerate() {
        let len = rec.ct.len();
        // first byte, middle, last plaintext byte, and inside the tag
        for pos in [0, len / 2, len - 17, len - 1] {
            let tampered = rewrite(&bytes, |f| f.items[idx].ct[pos] ^= 0x01);
            assert_eq!(
                unlock(&tampered).unwrap_err(),
                VaultError::Tampered(TamperKind::Item(rec.id)),
                "item {idx} byte {pos}"
            );
        }
    }
}

#[test]
fn flip_nonce_or_modified_at_is_item_tamper() {
    let mut v = new_vault();
    populate(&mut v, 2);
    let bytes = v.serialize();
    let id = VaultFile::parse(&bytes).unwrap().items[1].id;
    let t = rewrite(&bytes, |f| f.items[1].nonce[3] ^= 0x80);
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Item(id))
    );
    let t = rewrite(&bytes, |f| f.items[1].modified_at += 1);
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Item(id))
    );
}

#[test]
fn guarantee_5_remove_item_record() {
    let mut v = new_vault();
    populate(&mut v, 4);
    let bytes = v.serialize();
    for idx in 0..4 {
        let t = rewrite(&bytes, |f| {
            f.items.remove(idx);
        });
        assert_eq!(
            unlock(&t).unwrap_err(),
            VaultError::Tampered(TamperKind::Manifest)
        );
    }
    let t = rewrite(&bytes, |f| {
        let dup = f.items[0].clone();
        f.items.push(dup);
    });
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
    // duplicate while dropping another keeps the count equal; still caught by pair comparison
    let t = rewrite(&bytes, |f| {
        f.items[1] = f.items[0].clone();
    });
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
}

#[test]
fn guarantee_6_rollback_item_record() {
    let mut v = new_vault();
    populate(&mut v, 3);
    let old = v.serialize();
    let id = VaultFile::parse(&old).unwrap().items[1].id;

    let mut item = v.get(id).unwrap().clone();
    item.title = "renamed".into();
    item.modified_at += 5;
    v.insert(item, 0);
    let new = v.serialize();

    let old_file = VaultFile::parse(&old).unwrap();
    let old_rec = old_file.items.iter().find(|r| r.id == id).unwrap().clone();
    let t = rewrite(&new, |f| {
        let slot = f.items.iter_mut().find(|r| r.id == id).unwrap();
        *slot = old_rec;
    });
    // The old record is genuine (its own AAD still verifies) so it decrypts; the manifest
    // cross-check is what catches the rollback.
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
}

#[test]
fn flip_manifest_ct() {
    let mut v = new_vault();
    populate(&mut v, 2);
    let bytes = v.serialize();
    let t = rewrite(&bytes, |f| f.manifest.ct[0] ^= 1);
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
    let t = rewrite(&bytes, |f| f.manifest.nonce[0] ^= 1);
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
}

#[test]
fn guarantee_7_item_moved_between_vaults() {
    let mut a = new_vault();
    populate(&mut a, 2);
    let mut b = new_vault();
    populate(&mut b, 2);
    let ab = a.serialize();
    let bb = b.serialize();
    let foreign = VaultFile::parse(&ab).unwrap().items[0].clone();
    let foreign_id = foreign.id;

    // Append the foreign record.
    let t = rewrite(&bb, |f| f.items.push(foreign.clone()));
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Item(foreign_id)),
        "item AAD binds vault_id; checked before the manifest"
    );
    // Replace one of B's records with it (count unchanged).
    let t = rewrite(&bb, |f| f.items[1] = foreign.clone());
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Item(foreign_id))
    );
}

fn slot0(f: &mut vault_core::format::VaultFile) -> &mut vault_core::KeySlot {
    f.header.slots[0].as_key_mut().unwrap()
}

#[test]
fn header_tamper_reports_wrong_password() {
    let mut v = new_vault();
    populate(&mut v, 1);
    let bytes = v.serialize();

    let t = rewrite(&bytes, |f| {
        let mut b = *f.header.vault_id.as_bytes();
        b[0] ^= 1;
        f.header.vault_id = vault_core::Uuid::from_bytes(b);
    });
    assert_eq!(unlock(&t).unwrap_err(), VaultError::WrongPassword);

    let t = rewrite(&bytes, |f| f.header.kdf.salt[0] ^= 1);
    assert_eq!(unlock(&t).unwrap_err(), VaultError::WrongPassword);

    let t = rewrite(&bytes, |f| f.header.kdf.t_cost += 1);
    assert_eq!(unlock(&t).unwrap_err(), VaultError::WrongPassword);

    let t = rewrite(&bytes, |f| slot0(f).wrapped_key[40] ^= 1);
    assert_eq!(unlock(&t).unwrap_err(), VaultError::WrongPassword);

    let t = rewrite(&bytes, |f| slot0(f).nonce[0] ^= 1);
    assert_eq!(unlock(&t).unwrap_err(), VaultError::WrongPassword);

    let t = rewrite(&bytes, |f| {
        slot0(f).id = vault_core::Uuid::from_u128(9);
    });
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::WrongPassword,
        "slot id is in the AAD"
    );

    // Relabelling the only password slot leaves no password slot at all: that is reported as
    // `NoUsableSlot` (not `WrongPassword`) so the app can explain it; see forward_compat.rs.
    let t = rewrite(&bytes, |f| slot0(f).kind = vault_core::SlotKind::Enclave);
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::NoUsableSlot,
        "no password slot left"
    );

    // Invalid Argon2 params are structural damage, not a wrong password.
    let t = rewrite(&bytes, |f| f.header.kdf.m_cost_kib = 1);
    assert!(matches!(unlock(&t).unwrap_err(), VaultError::Malformed(_)));
    assert!(
        LockedVault::parse(&t).is_ok(),
        "parse itself does not run the KDF"
    );
}
