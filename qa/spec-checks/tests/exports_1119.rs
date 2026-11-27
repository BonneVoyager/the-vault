//! 02 "Also exported (2026-11-19, verified against `lib.rs` and the modules; names only)": every
//! listed name resolves from outside the crate, and constants carry the values other spec
//! sentences give them. Kept in its own file so a missing name fails only this file's build.
use vault_core::*;

#[test]
fn ex01_also_exported_names_resolve() {
    // LockedVault / UnlockedVault methods (named, not called)
    let _ = LockedVault::header;
    let _ = LockedVault::slots;
    let _ = UnlockedVault::create_with_created_at;
    let _ = UnlockedVault::set_device_id;
    let _ = UnlockedVault::export_vault_key;
    let _ = UnlockedVault::header;
    let _ = UnlockedVault::header_extras_mut;
    let _ = UnlockedVault::try_insert;
    let _ = UnlockedVault::remove_history_entry;
    let _ = UnlockedVault::clear_history;
    let _ = UnlockedVault::add_enclave_slot_with_created_at;
    let _ = UnlockedVault::slots;
    let _ = VaultKeyHandle::duplicate;
    let _ = MergeReport::changed;
    let _ = vault_core::merge::merge_items;
    let _ = vault_core::merge::item_eq;
    let _ = vault_core::kdf::KdfParams::validate;
    let _ = vault_core::generator::PasswordSpec::min_length;
    let _ = vault_core::attachment::new_ref;
    let _ = vault_core::attachment::validate_ref;
    let _ = vault_core::attachment::chunk_count;
    let _ = vault_core::attachment::blob_file_name;
    let _: Option<vault_core::attachment::AttachmentError> = None;
    let _: Option<vault_core::format::Header> = None;
    let _: Option<vault_core::format::KeySlot> = None;
    let _: Option<vault_core::format::OpaqueSlot> = None;
    let _: Option<vault_core::format::Slot> = None;
    let _: Option<vault_core::format::SlotKind> = None;
}

#[test]
fn ex02_constants_match_other_spec_sentences() {
    let mut bad = vec![];
    let mut eq = |name: &str, got: u64, want: u64| {
        if got != want {
            bad.push(format!("{name} = {got}, spec {want}"));
        }
    };
    // 01 §2 KDF acceptance range
    eq("kdf::MAX_T_COST", vault_core::kdf::MAX_T_COST as u64, 16);
    eq("kdf::MAX_P_COST", vault_core::kdf::MAX_P_COST as u64, 64);
    eq(
        "kdf::MAX_M_COST_KIB",
        vault_core::kdf::MAX_M_COST_KIB as u64,
        1_048_576,
    );
    // 02 history cap 10; 01 §4 / 03 §5 marker caps 64
    eq(
        "vault::HISTORY_CAP",
        vault_core::vault::HISTORY_CAP as u64,
        10,
    );
    eq(
        "vault::FIELD_TOMBSTONE_CAP",
        vault_core::vault::FIELD_TOMBSTONE_CAP as u64,
        64,
    );
    eq(
        "vault::ATTACHMENT_TOMBSTONE_CAP",
        vault_core::vault::ATTACHMENT_TOMBSTONE_CAP as u64,
        64,
    );
    // 02 strength_bits "first 100 characters"
    eq(
        "generator::STRENGTH_SCORED_CHARS",
        vault_core::generator::STRENGTH_SCORED_CHARS as u64,
        100,
    );
    // 01 §4 attachments
    eq(
        "attachment::CHUNK_SIZE",
        vault_core::attachment::CHUNK_SIZE as u64,
        1_048_576,
    );
    eq(
        "attachment::MAX_ATTACHMENT_SIZE",
        vault_core::attachment::MAX_ATTACHMENT_SIZE,
        100_000_000,
    );
    eq(
        "attachment::ATTACHMENT_VERSION",
        vault_core::attachment::ATTACHMENT_VERSION as u64,
        1,
    );
    // 01 §1 magic; §9 current version 3 (I-04)
    eq(
        "format::MAGIC == RVLT",
        (vault_core::format::MAGIC[..] == b"RVLT"[..]) as u64,
        1,
    );
    eq(
        "format::FORMAT_VERSION",
        vault_core::format::FORMAT_VERSION as u64,
        3,
    );
    // 02 FieldKind: ALL has 10 entries; is_sensitive = Password | Pin | Totp | Other
    eq("FieldKind::ALL.len()", FieldKind::ALL.len() as u64, 10);
    for k in FieldKind::ALL.iter() {
        let want = matches!(k, FieldKind::Password | FieldKind::Pin | FieldKind::Totp);
        eq(
            &format!("{k:?}.is_sensitive()"),
            k.is_sensitive() as u64,
            want as u64,
        );
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
