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

/// The committed, unstamped `v1-empty.vault` bytes (same password and KDF as `new_vault`).
/// The only unstamped file with this password: `create` stamps every new vault (01 §2) and
/// `serialize` stamps a never-stamped header on its first save (L-02, 2026-11-26), so a
/// test that splices slots or header keys into a file by hand must `rewrite` *these* bytes
/// and unlock the result; any by-hand header edit of a saved file is `Tampered(Manifest)`.
pub fn unstamped_bytes() -> &'static [u8] {
    include_bytes!("../fixtures/v1-empty.vault")
}

/// [`unstamped_bytes`] unlocked, with `device()` set. The in-memory header carries **no**
/// `slots_modified_at`; a `serialize` writes it stamped with 1.
pub fn unstamped_vault() -> UnlockedVault {
    let mut v = LockedVault::parse(unstamped_bytes())
        .expect("v1-empty fixture parses")
        .unlock(&pw())
        .expect("v1-empty fixture opens");
    assert_eq!(v.header().slots_modified_at, None, "fixture is unstamped");
    v.set_device_id(device());
    v
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
            field_id: None,
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
    assert_eq!(a.id, b.id, "field {}", a.name);
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
    assert_eq!(a.icon, b.icon, "field {}", a.name);
    assert_eq!(a.extras, b.extras);
}

pub fn assert_item_eq(a: &Item, b: &Item) {
    assert_eq!(a.id, b.id);
    assert_eq!(a.title, b.title);
    assert_eq!(a.deleted_at, b.deleted_at);
    assert_eq!(a.device_id, b.device_id);
    assert_eq!(a.favorite, b.favorite);
    assert_eq!(a.tags, b.tags);
    assert_eq!(a.icon, b.icon);
    assert_eq!(a.created_at, b.created_at, "created_at of {}", a.title);
    assert_eq!(
        a.title_modified_at, b.title_modified_at,
        "title stamp of {}",
        a.title
    );
    assert_eq!(a.favorite_modified_at, b.favorite_modified_at);
    assert_eq!(a.tags_modified_at, b.tags_modified_at);
    assert_eq!(a.icon_modified_at, b.icon_modified_at);
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
        assert_eq!(x.field_id, y.field_id);
    }
    assert_eq!(a.removed_attachments, b.removed_attachments);
    assert_eq!(a.removed_history, b.removed_history);
    assert_eq!(a.removed_fields, b.removed_fields);
}

/// The first field named `name` regardless of kind (so section headings are found too; the
/// production lookup [`Item::field`] skips them).
pub fn field_named<'a>(item: &'a Item, name: &str) -> Option<&'a Field> {
    item.fields.iter().find(|f| f.name == name)
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

/// `file` with the record for `id` replaced by the record for `id` in `donor`.
pub fn splice(file: &[u8], donor: &[u8], id: Uuid) -> Vec<u8> {
    let donor = VaultFile::parse(donor).unwrap();
    let record = donor.items.iter().find(|r| r.id == id).unwrap().clone();
    rewrite(file, |f| {
        let victim = f.items.iter_mut().find(|r| r.id == id).unwrap();
        *victim = record;
    })
}

/// `v` saved with `keys` as the record-level unknown keys of item `id` (01 §9), reopened as
/// `device`. Below format version 3 nothing authenticates these keys, so this is the
/// plaintext edit anyone can make to the file. From version 3 on the manifest vouches for
/// them (01 §4), so it is what a newer writer *holding the vault key* does
/// ([`rewrite_with_key`]). There is no API that sets these keys, and `upgrade_format` drops
/// unbound ones, so this is the only way a version 3 vault with record-level keys comes
/// about in the tests.
pub fn with_record_keys(
    v: &UnlockedVault,
    id: Uuid,
    keys: &[(&str, u64)],
    device: Uuid,
) -> UnlockedVault {
    let plant = |file: &mut VaultFile| {
        let rec = file.items.iter_mut().find(|r| r.id == id).expect("record");
        rec.extras = keys
            .iter()
            .map(|(k, n)| {
                (
                    ciborium::Value::Text((*k).to_owned()),
                    ciborium::Value::Integer((*n).into()),
                )
            })
            .collect();
    };
    let bytes = v.serialize();
    let bytes = if v.header().format_version >= vault_core::format::PLAINTEXT_BINDING_VERSION {
        rewrite_with_key(&bytes, plant)
    } else {
        rewrite(&bytes, plant)
    };
    let mut v = unlock(&bytes).expect("planted file opens");
    v.set_device_id(device);
    v
}

/// [`rewrite`] by a writer that holds the vault key: `edit` is applied to the parsed file
/// and the manifest is sealed again over the result, so whatever plaintext the file's
/// version binds through the manifest (01 §4: the header digest, from version 3 the digest
/// of each record's unknown keys and of the manifest record's own) is vouched for. Item
/// ciphertexts are untouched. This is how the tests obtain plaintext keys that are *bound*,
/// as opposed to planted by a plain [`rewrite`].
pub fn rewrite_with_key(bytes: &[u8], edit: impl FnOnce(&mut VaultFile)) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use vault_core::format::{self, ManifestEntry};

    let key = manifest_key(bytes);
    let mut file = VaultFile::parse(bytes).expect("parse for rewrite");
    edit(&mut file);
    let version = file.header.format_version;
    let mut entries: Vec<ManifestEntry> = file
        .items
        .iter()
        .map(|r| ManifestEntry {
            id: r.id,
            modified_at: r.modified_at,
            extras_digest: format::item_record_digest(version, &r.extras),
        })
        .collect();
    entries.sort_by_key(|e| e.id);
    let aad = format::manifest_aad(
        version,
        file.header.vault_id,
        u32::try_from(entries.len()).unwrap(),
        file.header.digest().as_ref(),
        format::manifest_record_digest(version, &file.manifest.extras).as_ref(),
    );
    let mut nonce = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    file.manifest.ct = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&*key)
        .unwrap()
        .encrypt(
            chacha20poly1305::XNonce::from_slice(&nonce),
            Payload {
                msg: &format::encode_manifest_entries(&entries),
                aad: &aad,
            },
        )
        .expect("manifest seals");
    file.manifest.nonce = nonce;
    file.to_bytes()
}

/// The `manifest_key` of the vault in `bytes` (01 §3: HKDF-SHA256 of the vault key, salt
/// `vault_id`, info `vault/manifest/v1`), for the test-side writer and reader of manifests.
/// The vault key comes out of an enclave slot added to a throwaway copy under a KEK chosen
/// here, which is the public API's own way for a KEK holder to reach it.
pub fn manifest_key(bytes: &[u8]) -> zeroize::Zeroizing<[u8; 32]> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};

    let kek = vault_core::SecretVec::new(vec![0x4B; 32]);
    let mut probe = unlock(bytes).expect("file opens");
    let slot_id = probe.add_enclave_slot(&kek, 1);
    let header = probe.header();
    let slot = header
        .slots
        .iter()
        .find(|s| s.id() == slot_id)
        .and_then(|s| s.as_key())
        .expect("the slot just added");
    let aad =
        vault_core::format::slot_aad(header.format_version, header.vault_id, slot.id, &slot.kind);
    let vault_key = zeroize::Zeroizing::new(
        chacha20poly1305::XChaCha20Poly1305::new_from_slice(kek.expose_secret())
            .unwrap()
            .decrypt(
                chacha20poly1305::XNonce::from_slice(&slot.nonce),
                Payload {
                    msg: &slot.wrapped_key,
                    aad: &aad,
                },
            )
            .expect("slot unwraps"),
    );
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(Some(header.vault_id.as_bytes()), &vault_key)
        .expand(b"vault/manifest/v1", key.as_mut())
        .expect("32 bytes");
    key
}

/// The decrypted manifest entries of the file in `bytes` (`key` from [`manifest_key`]): a
/// third element (`extras_digest`) is present iff the manifest vouches for record-level
/// unknown keys of that record (01 §4, version 3).
pub fn manifest_entries(key: &[u8; 32], bytes: &[u8]) -> Vec<vault_core::format::ManifestEntry> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use vault_core::format;

    let file = VaultFile::parse(bytes).expect("file parses");
    let version = file.header.format_version;
    let aad = format::manifest_aad(
        version,
        file.header.vault_id,
        u32::try_from(file.items.len()).unwrap(),
        file.header.digest().as_ref(),
        format::manifest_record_digest(version, &file.manifest.extras).as_ref(),
    );
    let plain = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
        .unwrap()
        .decrypt(
            chacha20poly1305::XNonce::from_slice(&file.manifest.nonce),
            Payload {
                msg: &file.manifest.ct,
                aad: &aad,
            },
        )
        .expect("manifest opens");
    format::decode_manifest(&plain).expect("manifest decodes")
}

/// The record-level unknown keys `v` writes for item `id`, as `(name, integer)` pairs in
/// file order (the inverse of [`with_record_keys`]).
pub fn record_keys(v: &UnlockedVault, id: Uuid) -> Vec<(String, u64)> {
    let file = VaultFile::parse(&v.serialize()).expect("own file parses");
    let rec = file.items.iter().find(|r| r.id == id).expect("record");
    rec.extras
        .iter()
        .map(|(k, n)| {
            let n = n.as_integer().expect("integer value");
            (
                k.as_text().expect("text key").to_owned(),
                u64::try_from(n).expect("u64 value"),
            )
        })
        .collect()
}
