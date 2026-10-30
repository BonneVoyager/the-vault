//! Shared helpers for the integration tests. Everything uses `KdfParams::for_tests()`.
#![allow(dead_code)]

use vault_core::format::VaultFile;
use vault_core::{
    ExposeSecret, Field, FieldKind, Item, KdfParams, LockedVault, SecretString, UnlockedVault, Uuid,
};

pub const PASSWORD: &str = "correct horse battery staple";

pub fn pw() -> SecretString {
    SecretString::new(PASSWORD.to_owned())
}

pub fn device() -> Uuid {
    Uuid::from_u128(0xD0D0_D0D0_D0D0_D0D0_D0D0_D0D0_D0D0_D0D0)
}

pub fn new_vault() -> UnlockedVault {
    UnlockedVault::create_with_created_at(&pw(), KdfParams::for_tests(), device(), 1_700_000_000)
}

pub fn secret(s: impl Into<String>) -> SecretString {
    SecretString::new(s.into())
}

/// An item with username, password, totp, url and notes fields. Every fourth item carries a
/// different template tag (the replacement for the removed item kinds).
pub fn sample_item(i: u64, now: u64) -> Item {
    let template = match i % 4 {
        0 => "login",
        1 => "note",
        2 => "card",
        _ => "identity",
    };
    let mut item = Item::new(format!("Item {i} \u{1F511} caf\u{e9}"), Uuid::nil(), now);
    item.favorite = i.is_multiple_of(3);
    item.tags = vec![template.into(), "work".into(), format!("tag{}", i % 5)];
    item.fields.push(Field::new(
        "username",
        FieldKind::Text,
        secret(format!("user{i}@example.com")),
        now,
    ));
    item.fields.push(Field::new(
        "password",
        FieldKind::Password,
        secret(format!("p\u{e4}ss-{i}-hunter2")),
        now.saturating_sub(1),
    ));
    item.fields.push(Field::new(
        "totp",
        FieldKind::Totp,
        secret(format!(
            "otpauth://totp/Example:user{i}%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30"
        )),
        now,
    ));
    let mut url = Field::new(
        "url",
        FieldKind::Url,
        secret(format!("https://site{i}.example")),
        now,
    );
    url.section = Some("web".into());
    item.fields.push(url);
    item.fields.push(Field::new(
        "notes",
        FieldKind::Notes,
        secret("multi\nline\nnotes"),
        now,
    ));
    if i.is_multiple_of(7) {
        item.history.push(vault_core::HistoryEntry {
            value: secret(format!("old-{i}")),
            replaced_at: now.saturating_sub(100),
        });
    }
    item
}

pub fn populate(vault: &mut UnlockedVault, n: u64) {
    for i in 0..n {
        let now = 1_700_000_000_000 + i * 1000;
        vault.insert(sample_item(i, now), now);
    }
}

pub fn unlock(bytes: &[u8]) -> Result<UnlockedVault, vault_core::VaultError> {
    LockedVault::parse(bytes)?.unlock(&pw())
}

pub fn assert_field_eq(a: &Field, b: &Field) {
    assert_eq!(a.name, b.name);
    assert_eq!(a.kind, b.kind);
    assert_eq!(
        a.value.expose_secret(),
        b.value.expose_secret(),
        "field {}",
        a.name
    );
    assert_eq!(a.modified_at, b.modified_at);
    assert_eq!(a.section, b.section);
    assert_eq!(a.extras, b.extras);
}

pub fn assert_item_eq(a: &Item, b: &Item) {
    assert_eq!(a.id, b.id);
    assert_eq!(a.title, b.title);
    assert_eq!(a.deleted_at, b.deleted_at);
    assert_eq!(a.device_id, b.device_id);
    assert_eq!(a.favorite, b.favorite);
    assert_eq!(a.tags, b.tags);
    assert_eq!(a.modified_at, b.modified_at);
    assert_eq!(a.extras, b.extras);
    assert_eq!(a.fields.len(), b.fields.len());
    for (x, y) in a.fields.iter().zip(&b.fields) {
        assert_field_eq(x, y);
    }
    assert_eq!(a.history.len(), b.history.len());
    for (x, y) in a.history.iter().zip(&b.history) {
        assert_eq!(x.value.expose_secret(), y.value.expose_secret());
        assert_eq!(x.replaced_at, y.replaced_at);
    }
    assert_eq!(a.removed_attachments, b.removed_attachments);
    assert_eq!(a.removed_history, b.removed_history);
}

pub fn assert_vaults_eq(a: &UnlockedVault, b: &UnlockedVault) {
    assert_eq!(a.vault_id(), b.vault_id());
    let xs: Vec<_> = a.items_including_deleted().collect();
    let ys: Vec<_> = b.items_including_deleted().collect();
    assert_eq!(xs.len(), ys.len());
    for (x, y) in xs.iter().zip(&ys) {
        assert_item_eq(x, y);
    }
}

/// Parse, let the caller edit the structure, re-encode. Locates records structurally, never
/// by byte search.
pub fn rewrite(bytes: &[u8], edit: impl FnOnce(&mut VaultFile)) -> Vec<u8> {
    let mut file = VaultFile::parse(bytes).expect("parse for rewrite");
    edit(&mut file);
    file.to_bytes()
}
