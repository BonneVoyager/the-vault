//! Committed format fixtures (01 §8). `regenerate_fixtures` / `regenerate_forward_fixture`
//! rewrite them; the other tests parse, unlock and assert contents.
//!
//! # Fixture policy
//!
//! **Every `FORMAT_VERSION` keeps its fixtures forever; the current reader must open all of
//! them.** Fixtures are named `v<FORMAT_VERSION>-<name>.vault`, all use the password
//! `correct horse battery staple` and `KdfParams::for_tests()`, and are never deleted or
//! rewritten once a version has shipped (regenerating is only for an unreleased version).
//! [`every_fixture_in_the_directory_opens`] walks `tests/fixtures/` so a new fixture is
//! covered the moment it is committed and a reader regression on any old one fails loudly.
//!
//! `v1-forward.vault` exercises 01 §9 forward compatibility: it carries an opaque key slot
//! of an unknown kind, a field of an unknown kind, and an unknown key at every one of the
//! eight map levels a newer build could add one to: header, `header.kdf`, the opaque slot,
//! a known (password) key slot, an item record (plaintext), an item's encrypted payload, a
//! field, and the manifest record. It never carries `slots_modified_at` (v1.1 header merge):
//! a build that writes that key only does so after a slot mutation, so an untouched fixture
//! must stay byte-identical through unlock + serialize.
//!
//! Item categories (`ItemPlain.kind`) were removed on 2026-10-30 without a version bump.
//! Every fixture written before that still carries a `kind` entry per item; the reader keeps
//! it as an unknown key in `Item::extras` and re-emits it verbatim, so the committed bytes
//! are unchanged and the regenerators below add the entry to `extras` explicitly to stay
//! byte-identical with what they produced before the removal.
//!
//! `v1-stamped.vault` (01 §2 `slots_modified_at` / `slots_device_id`, 01 §4 `header_digest`)
//! is the one fixture whose header is stamped: one item, the password re-set at `T0 + 50`
//! by device `0x11..`, so its manifest AAD carries the header digest. It proves a stamped
//! file written today stays openable, and that the digest binding is checked on it.
//!
//! `v1-attach.vault` (01 §4 "Attachments (v1.1)") holds one item with two attachment
//! references, an empty file and a 3-chunk file (2 MiB + 7 bytes), whose sealed blobs live
//! under `v1-attach.vault.attachments/<id hex>.bin`. The blob contents are deterministic
//! (`attach_pattern`) so the test can verify the decrypted bytes.
//!
//! `v1-icon.vault` (01 §4 `ItemPlain.icon`, v1.2, no version bump) holds three items written
//! by a post-2026-10-31 build: a `symbol` icon with a colour, a `logo` icon without one, and
//! an item with no icon (so no `icon` key at all). Like `v1-stamped` it was created after
//! stamp-at-create, so its header carries `slots_modified_at`, and after the item-kind
//! removal, so its items carry no legacy `kind` extra. Password: `correct horse battery
//! staple` (`PASSWORD`), KDF `KdfParams::for_tests()`.
//!
//! `v1-meta.vault` (01 §4 `ItemPlain.created_at` and `Field.kind = "section"`, v1.3, no
//! version bump) holds two items written by a post-2026-10-31 build: one with `created_at`
//! and a `section` heading field followed by two text fields, and one with no `created_at`
//! key at all. Stamped header, no legacy `kind` extra (same vintage as `v1-icon`). Password
//! `correct horse battery staple` (`PASSWORD`), KDF `KdfParams::for_tests()`.
//!
//! # Format version 2 (field identity, FI-1, 2026-10-31)
//!
//! `FORMAT_VERSION` is 2: every field carries an `id`, items may carry `removed_fields`
//! markers and history entries a `field_id` (01 §4, §9). **Every `v1-*.vault` above is
//! frozen**: the reader opens them through the migration (each field gets
//! `Field::derived_id`, see `tests/field_id.rs`) and a save keeps them at version 1. Their
//! regenerators are kept as the record of how they were built but are *historical*: they
//! refuse to run (`v1_regenerators_are_historical`) because `new_vault()` now creates a
//! version 2 vault, so running one would silently replace a v1 fixture with a v2 file.
//!
//! `v2-basic.vault` is the first version 2 fixture: two items, one of which has two fields
//! named `username`, a field with an empty name, a `removed_fields` marker and a history
//! entry with `field_id`; the other is a plain note. Stamped header (created at version 2),
//! no legacy `kind` extra. Password `correct horse battery staple` (`PASSWORD`), KDF
//! `KdfParams::for_tests()`. Built by `regenerate_v2_basic_fixture`.

use std::io::Cursor;

use ciborium::Value;
use vault_core::attachment::{CHUNK_SIZE, blob_file_name, new_ref, open, seal};
use vault_core::format::VaultFile;
use vault_core::{
    ExposeSecret, FORMAT_VERSION, Field, FieldKind, Item, ItemIcon, KdfParams, LockedVault,
    OpaqueSlot, SecretString, Slot, SlotKind, TamperKind, UnlockedVault, Uuid, VaultError,
};

/// Parse, edit the structure, re-encode (same as `common::rewrite`, kept local because this
/// file does not pull in the shared helpers).
fn rewrite(bytes: &[u8], edit: impl FnOnce(&mut VaultFile)) -> Vec<u8> {
    let mut file = VaultFile::parse(bytes).unwrap();
    edit(&mut file);
    file.to_bytes()
}

const PASSWORD: &str = "correct horse battery staple";
const BASIC: &[u8] = include_bytes!("fixtures/v1-basic.vault");
const EMPTY: &[u8] = include_bytes!("fixtures/v1-empty.vault");
const FORWARD: &[u8] = include_bytes!("fixtures/v1-forward.vault");
const STAMPED: &[u8] = include_bytes!("fixtures/v1-stamped.vault");
/// `v1-stamped.vault`: the item and the stamp.
const STAMPED_ITEM_ID: [u8; 16] = [0x07; 16];
const STAMPED_AT: u64 = T0 + 50;
const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
const T0: u64 = 1_700_000_000_000;

/// What `v1-forward.vault` carries from "the future".
const FUTURE_SLOT_KIND: &str = "future-kind";
const FUTURE_ITEM_KIND: &str = "future-item-kind";
const FUTURE_FIELD_KIND: &str = "future-field-kind";
const FUTURE_SLOT_ID: [u8; 16] = [0x05; 16];
const FUTURE_ITEM_ID: [u8; 16] = [0x04; 16];

/// `v1-attach.vault`: the item and its two attachments.
const ATTACH_ITEM_ID: [u8; 16] = [0x06; 16];
const ATTACH_EMPTY_ID: [u8; 16] = [0x0A; 16];
const ATTACH_BIG_ID: [u8; 16] = [0x0B; 16];
const ATTACH_BIG_LEN: usize = 2 * CHUNK_SIZE + 7;
const ATTACH_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/v1-attach.vault.attachments"
);

/// `v1-icon.vault`: the three items, in insertion order.
const ICON_SYMBOL_ID: [u8; 16] = [0x08; 16];
const ICON_LOGO_ID: [u8; 16] = [0x09; 16];
const ICON_NONE_ID: [u8; 16] = [0x0C; 16];
const ICON_AT: u64 = T0 + 60;

/// `v1-meta.vault`: the two items, in insertion order.
const META_DATED_ID: [u8; 16] = [0x0D; 16];
const META_UNDATED_ID: [u8; 16] = [0x0E; 16];
const META_AT: u64 = T0 + 70;
/// The dated item's `created_at`: earlier than its stamp, as a real item's would be.
const META_CREATED_AT: u64 = T0 - 86_400_000;

/// `v2-basic.vault`: the two items and the field ids of the first one, in field order.
const V2_DUPES_ID: [u8; 16] = [0x0F; 16];
const V2_NOTE_ID: [u8; 16] = [0x10; 16];
const V2_USERNAME_1: [u8; 16] = [0x21; 16];
const V2_USERNAME_2: [u8; 16] = [0x22; 16];
const V2_UNNAMED: [u8; 16] = [0x23; 16];
const V2_PASSWORD: [u8; 16] = [0x24; 16];
/// Removed after insertion; only its `removed_fields` marker is in the file.
const V2_PIN: [u8; 16] = [0x25; 16];
const V2_NOTES: [u8; 16] = [0x26; 16];
const V2_AT: u64 = T0 + 80;

/// Every `v1-*.vault` is frozen (see the module docs): `new_vault()` creates a version 2
/// vault now, so a v1 regenerator must never run again. Each one calls this first.
fn v1_regenerators_are_historical() {
    if FORMAT_VERSION != 1 {
        panic!(
            "historical: this regenerator built a v1 fixture; FORMAT_VERSION is now {FORMAT_VERSION} and the v1 fixtures are frozen (01 §9)"
        );
    }
}

fn icon_symbol() -> ItemIcon {
    ItemIcon {
        kind: "symbol".into(),
        value: "key.fill".into(),
        color: Some("#3B82F6".into()),
        extras: Vec::new(),
    }
}

fn icon_logo() -> ItemIcon {
    ItemIcon::new("logo", "github.com")
}

fn attach_pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn t(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn header_extra() -> (Value, Value) {
    (t("x_header_future"), t("from a newer header"))
}

/// Unknown key inside `header.kdf` (e.g. a parameter of a future KDF variant).
fn kdf_extra() -> (Value, Value) {
    (t("x_kdf_future"), t("argon2id-next"))
}

/// Unknown key on the *known* password slot (not the opaque one).
fn key_slot_extra() -> (Value, Value) {
    (t("x_slot_known_future"), Value::Integer(9.into()))
}

/// Unknown plaintext key on the item record (outside the ciphertext, unauthenticated).
fn record_extra() -> (Value, Value) {
    (t("x_record_future"), Value::Bytes(vec![0xC0, 0xFF, 0xEE]))
}

/// Unknown plaintext key on the manifest record.
fn manifest_extra() -> (Value, Value) {
    (t("x_manifest_future"), Value::Bool(false))
}

/// The legacy per-item `kind` entry as pre-2026-10-30 writers emitted it; now an unknown key.
fn kind_extra(kind: &str) -> (Value, Value) {
    (t("kind"), t(kind))
}

fn item_extra() -> (Value, Value) {
    (t("x_item_future"), Value::Integer(42.into()))
}

fn field_extra() -> (Value, Value) {
    (t("x_field_future"), Value::Bool(true))
}

/// The opaque slot as a newer version would write it: no `nonce`/`wrapped_key` at all, a
/// different payload, plus an unknown key. Extras are listed in canonical key order (the
/// order the parser hands them back from the canonical file).
fn future_slot() -> OpaqueSlot {
    OpaqueSlot::new(
        Uuid::from_bytes(FUTURE_SLOT_ID),
        FUTURE_SLOT_KIND,
        vec![
            (t("blob"), Value::Bytes(vec![0xAB; 40])),
            (t("created_at"), Value::Integer(1_700_000_000.into())),
            (t("x_slot_future"), t("opaque")),
        ],
    )
    .unwrap()
}

fn pw() -> SecretString {
    SecretString::new(PASSWORD.to_owned())
}

fn device() -> Uuid {
    Uuid::from_bytes([0x11; 16])
}

fn secret(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

fn field(name: &str, kind: FieldKind, value: &str, now: u64) -> Field {
    Field::new(name, kind, secret(value), now)
}

fn new_vault() -> UnlockedVault {
    let kdf = KdfParams::for_tests();
    assert_eq!((kdf.m_cost_kib, kdf.t_cost, kdf.p_cost), (8192, 1, 1));
    UnlockedVault::create_with_created_at(&pw(), kdf, device(), 1_700_000_000)
}

#[test]
#[ignore]
fn regenerate_fixtures() {
    v1_regenerators_are_historical();
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    std::fs::create_dir_all(dir).unwrap();

    let mut vault = new_vault();

    let mut github = Item::new("GitHub", device(), T0);
    github.id = Uuid::from_bytes([0x01; 16]);
    github.extras.push(kind_extra("login"));
    github.tags = vec!["dev".into()];
    github.fields = vec![
        field("username", FieldKind::Text, "chris@example.com", T0),
        field(
            "password",
            FieldKind::Password,
            "hunter2-but-longer",
            T0 + 1,
        ),
        field("url", FieldKind::Url, "https://github.com", T0 + 2),
        field(
            "totp",
            FieldKind::Totp,
            "otpauth://totp/GitHub:chris?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
            T0 + 3,
        ),
    ];
    vault.insert(github, T0 + 3);

    let mut wifi = Item::new("Wifi", device(), T0 + 10);
    wifi.id = Uuid::from_bytes([0x02; 16]);
    wifi.extras.push(kind_extra("note"));
    wifi.fields = vec![field(
        "notes",
        FieldKind::Notes,
        "SSID: home-net\nPassphrase: lorem ipsum dolor",
        T0 + 10,
    )];
    vault.insert(wifi, T0 + 10);

    let mut visa = Item::new("Visa", device(), T0 + 20);
    visa.id = Uuid::from_bytes([0x03; 16]);
    visa.extras.push(kind_extra("card"));
    visa.fields = vec![
        field("number", FieldKind::Text, "4111111111111111", T0 + 20),
        field("expiry", FieldKind::MonthYear, "12/29", T0 + 21),
        field("cvv", FieldKind::Password, "123", T0 + 22),
    ];
    vault.insert(visa, T0 + 22);

    std::fs::write(format!("{dir}/v1-basic.vault"), vault.serialize()).unwrap();
    std::fs::write(format!("{dir}/v1-empty.vault"), new_vault().serialize()).unwrap();
}

/// Builds `v1-forward.vault` (see the module docs). Separate from [`regenerate_fixtures`] so
/// it can be regenerated without churning the other two files.
#[test]
#[ignore]
fn regenerate_forward_fixture() {
    v1_regenerators_are_historical();
    let mut vault = new_vault();
    vault.header_extras_mut().push(header_extra());

    let mut future = Item::new("Future thing", device(), T0 + 30);
    future.id = Uuid::from_bytes(FUTURE_ITEM_ID);
    future.extras.push(kind_extra(FUTURE_ITEM_KIND));
    future.tags = vec!["future".into()];
    let mut f = field("future", FieldKind::Other, "future-value", T0 + 30);
    f.kind_raw = Some(FUTURE_FIELD_KIND.to_owned());
    f.extras.push(field_extra());
    future.fields = vec![
        f,
        field("username", FieldKind::Text, "chris@example.com", T0 + 31),
    ];
    future.extras.push(item_extra());
    vault.insert(future, T0 + 31);

    // The remaining unknown-key sites are plaintext structure, so they are spliced in after
    // encryption. The opaque slot goes FIRST so the position test is meaningful.
    let mut file = VaultFile::parse(&vault.serialize()).unwrap();
    file.header.kdf_extras.push(kdf_extra());
    file.header.slots[0]
        .as_key_mut()
        .expect("the password slot")
        .extras
        .push(key_slot_extra());
    file.header.slots.insert(0, Slot::Opaque(future_slot()));
    assert_eq!(file.items.len(), 1);
    file.items[0].extras.push(record_extra());
    file.manifest.extras.push(manifest_extra());
    std::fs::write(format!("{FIXTURE_DIR}/v1-forward.vault"), file.to_bytes()).unwrap();
}

/// Builds `v1-stamped.vault` (see the module docs). Separate so the other fixtures' bytes
/// are not churned.
#[test]
#[ignore]
fn regenerate_stamped_fixture() {
    v1_regenerators_are_historical();
    let mut vault = new_vault();
    let mut item = Item::new("Stamped", device(), T0 + 45);
    item.id = Uuid::from_bytes(STAMPED_ITEM_ID);
    item.fields = vec![field(
        "password",
        FieldKind::Password,
        "still the same",
        T0 + 45,
    )];
    vault.insert(item, T0 + 45);
    // Same password, fresh KDF salt: the re-calibration path, which stamps the header.
    vault
        .change_password(&pw(), &pw(), KdfParams::for_tests(), STAMPED_AT)
        .unwrap();
    assert_eq!(vault.header().slots_modified_at, Some(STAMPED_AT));
    assert_eq!(vault.header().slots_device_id, Some(device()));
    std::fs::write(format!("{FIXTURE_DIR}/v1-stamped.vault"), vault.serialize()).unwrap();
}

#[test]
fn v1_stamped_opens_and_its_header_is_digest_bound() {
    let locked = LockedVault::parse(STAMPED).unwrap();
    check_kdf(&locked);
    let header = locked.header();
    assert_eq!(header.slots_modified_at, Some(STAMPED_AT));
    assert_eq!(header.slots_device_id, Some(device()));
    assert_eq!(header.slots_stamp(), STAMPED_AT);
    assert!(header.digest().is_some());
    let vault = locked.unlock(&pw()).unwrap();
    let item = vault.get(Uuid::from_bytes(STAMPED_ITEM_ID)).unwrap();
    assert_eq!(item.title, "Stamped");
    assert_eq!(
        item.field("password").unwrap().value.expose_secret(),
        "still the same"
    );
    assert_eq!(vault.items().count(), 1);

    // The stamp survives a save, and the digest is checked on the committed bytes.
    let again = vault.serialize();
    let reopened = LockedVault::parse(&again).unwrap();
    assert_eq!(reopened.header().slots_modified_at, Some(STAMPED_AT));
    assert_eq!(reopened.header().slots_device_id, Some(device()));
    assert!(reopened.unlock(&pw()).is_ok());
    let manifest = VaultError::Tampered(TamperKind::Manifest);
    let stripped = rewrite(STAMPED, |f| {
        f.header.slots_modified_at = None;
        f.header.slots_device_id = None;
    });
    assert_eq!(
        LockedVault::parse(&stripped)
            .unwrap()
            .unlock(&pw())
            .unwrap_err(),
        manifest
    );
    let raised = rewrite(STAMPED, |f| {
        f.header.slots_modified_at = Some(STAMPED_AT + 1)
    });
    assert_eq!(
        LockedVault::parse(&raised)
            .unwrap()
            .unlock(&pw())
            .unwrap_err(),
        manifest
    );
}

/// Builds `v1-attach.vault` and its two blobs (see the module docs). Separate from the other
/// regenerators so their bytes are not churned.
#[test]
#[ignore]
fn regenerate_attach_fixture() {
    v1_regenerators_are_historical();
    std::fs::create_dir_all(ATTACH_DIR).unwrap();
    let mut vault = new_vault();

    let mut item = Item::new("With attachments", device(), T0 + 40);
    item.id = Uuid::from_bytes(ATTACH_ITEM_ID);
    item.extras.push(kind_extra("note"));
    item.fields = vec![field("notes", FieldKind::Notes, "see attached", T0 + 40)];
    let id = vault.insert(item, T0 + 40);

    let mut empty = new_ref("empty.txt", 0, T0 + 41).unwrap();
    empty.id = Uuid::from_bytes(ATTACH_EMPTY_ID);
    let mut big = new_ref("three-chunks.bin", ATTACH_BIG_LEN as u64, T0 + 42).unwrap();
    big.id = Uuid::from_bytes(ATTACH_BIG_ID);

    for (r, plain) in [(empty, Vec::new()), (big, attach_pattern(ATTACH_BIG_LEN))] {
        let mut blob = Vec::new();
        let (r, _) = seal(vault.vault_id(), r, Cursor::new(plain), &mut blob).unwrap();
        std::fs::write(format!("{ATTACH_DIR}/{}", blob_file_name(r.id)), blob).unwrap();
        let added_at = r.added_at;
        vault.add_attachment_ref(id, r, added_at).unwrap();
    }
    std::fs::write(format!("{FIXTURE_DIR}/v1-attach.vault"), vault.serialize()).unwrap();
}

#[test]
fn v1_attach_refs_and_blobs_open() {
    let bytes = std::fs::read(format!("{FIXTURE_DIR}/v1-attach.vault")).unwrap();
    let locked = LockedVault::parse(&bytes).unwrap();
    check_kdf(&locked);
    let vault = locked.unlock(&pw()).unwrap();
    let item = vault.get(Uuid::from_bytes(ATTACH_ITEM_ID)).unwrap();
    assert_eq!(item.title, "With attachments");
    assert_eq!(item.extras, vec![kind_extra("note")], "legacy kind kept");
    assert_eq!(item.attachments.len(), 2);
    let mut ids: Vec<_> = vault.attachment_ids().collect();
    ids.sort();
    assert_eq!(
        ids,
        [
            Uuid::from_bytes(ATTACH_EMPTY_ID),
            Uuid::from_bytes(ATTACH_BIG_ID)
        ]
    );

    let expected = [
        (ATTACH_EMPTY_ID, "empty.txt", 0usize, 1usize, T0 + 41),
        (
            ATTACH_BIG_ID,
            "three-chunks.bin",
            ATTACH_BIG_LEN,
            3,
            T0 + 42,
        ),
    ];
    for (id, name, len, chunks, added_at) in expected {
        let r = item.attachment(Uuid::from_bytes(id)).unwrap();
        assert_eq!(r.name, name);
        assert_eq!(r.size, len as u64);
        assert_eq!(r.chunk_count(), chunks);
        assert_eq!(r.added_at, added_at);
        let blob = std::fs::read(format!("{ATTACH_DIR}/{}", blob_file_name(r.id))).unwrap();
        assert_eq!(blob.len(), len + 16 * chunks);
        let mut out = Vec::new();
        open(vault.vault_id(), r, Cursor::new(&blob), &mut out)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(out, attach_pattern(len), "{name}: contents");

        // The blob is bound to this vault: another vault id rejects it.
        let mut out = Vec::new();
        assert!(open(Uuid::nil(), r, Cursor::new(&blob), &mut out).is_err());
    }
}

/// Builds `v1-icon.vault` (see the module docs). Separate from the other regenerators so
/// their bytes are not churned.
#[test]
#[ignore]
fn regenerate_icon_fixture() {
    v1_regenerators_are_historical();
    let mut vault = new_vault();
    let specs: [([u8; 16], &str, Option<ItemIcon>); 3] = [
        (ICON_SYMBOL_ID, "Symbol icon", Some(icon_symbol())),
        (ICON_LOGO_ID, "Logo icon", Some(icon_logo())),
        (ICON_NONE_ID, "No icon", None),
    ];
    for (id, title, icon) in specs {
        let mut item = Item::new(title, device(), ICON_AT);
        item.id = Uuid::from_bytes(id);
        item.icon = icon;
        item.tags = vec!["login".into()];
        item.fields = vec![
            field("username", FieldKind::Text, "someone@example.com", ICON_AT),
            field("password", FieldKind::Password, "hunter2", ICON_AT),
        ];
        vault.insert(item, ICON_AT);
    }
    std::fs::write(format!("{FIXTURE_DIR}/v1-icon.vault"), vault.serialize()).unwrap();
}

#[test]
fn v1_icon_opens_with_all_three_shapes() {
    let bytes = std::fs::read(format!("{FIXTURE_DIR}/v1-icon.vault")).unwrap();
    let locked = LockedVault::parse(&bytes).unwrap();
    check_kdf(&locked);
    let vault = locked.unlock(&pw()).unwrap();
    assert_eq!(vault.items().count(), 3);
    let expected = [
        (ICON_SYMBOL_ID, "Symbol icon", Some(icon_symbol())),
        (ICON_LOGO_ID, "Logo icon", Some(icon_logo())),
        (ICON_NONE_ID, "No icon", None),
    ];
    for (id, title, icon) in expected {
        let item = vault.get(Uuid::from_bytes(id)).unwrap();
        assert_eq!(item.title, title);
        assert_eq!(item.icon, icon, "{title}");
        assert!(
            item.extras.is_empty(),
            "{title}: written after the kind removal"
        );
        assert_eq!(item.modified_at, ICON_AT);
        assert_fields(
            item,
            &[
                ("username", FieldKind::Text, "someone@example.com"),
                ("password", FieldKind::Password, "hunter2"),
            ],
        );
    }
    // A save by this build keeps every icon exactly.
    let again = LockedVault::parse(&vault.serialize())
        .unwrap()
        .unlock(&pw())
        .unwrap();
    for (id, _, icon) in [
        (ICON_SYMBOL_ID, "", Some(icon_symbol())),
        (ICON_LOGO_ID, "", Some(icon_logo())),
        (ICON_NONE_ID, "", None),
    ] {
        assert_eq!(again.get(Uuid::from_bytes(id)).unwrap().icon, icon);
    }
}

/// Builds `v1-meta.vault` (see the module docs). Separate from the other regenerators so
/// their bytes are not churned.
#[test]
#[ignore]
fn regenerate_meta_fixture() {
    v1_regenerators_are_historical();
    let mut vault = new_vault();

    let mut dated = Item::new("Dated with section", device(), META_AT);
    dated.id = Uuid::from_bytes(META_DATED_ID);
    dated.created_at = Some(META_CREATED_AT);
    dated.tags = vec!["login".into()];
    dated.fields = vec![
        field("Account", FieldKind::Section, "", META_AT),
        field("username", FieldKind::Text, "someone@example.com", META_AT),
        field("employee id", FieldKind::Text, "E-1234", META_AT),
    ];
    vault.insert(dated, META_AT);

    let mut undated = Item::new("Undated", device(), META_AT);
    undated.id = Uuid::from_bytes(META_UNDATED_ID);
    undated.created_at = None;
    undated.tags = vec!["note".into()];
    undated.fields = vec![field(
        "notes",
        FieldKind::Notes,
        "no created_at key",
        META_AT,
    )];
    vault.insert(undated, META_AT);

    std::fs::write(format!("{FIXTURE_DIR}/v1-meta.vault"), vault.serialize()).unwrap();
}

#[test]
fn v1_meta_opens_with_created_at_and_section_heading() {
    let bytes = std::fs::read(format!("{FIXTURE_DIR}/v1-meta.vault")).unwrap();
    let locked = LockedVault::parse(&bytes).unwrap();
    check_kdf(&locked);
    let vault = locked.unlock(&pw()).unwrap();
    assert_eq!(vault.items().count(), 2);

    let dated = vault.get(Uuid::from_bytes(META_DATED_ID)).unwrap();
    assert_eq!(dated.title, "Dated with section");
    assert_eq!(dated.created_at, Some(META_CREATED_AT));
    assert_eq!(dated.modified_at, META_AT);
    assert!(dated.extras.is_empty(), "written after the kind removal");
    assert_fields(
        dated,
        &[
            ("Account", FieldKind::Section, ""),
            ("username", FieldKind::Text, "someone@example.com"),
            ("employee id", FieldKind::Text, "E-1234"),
        ],
    );
    let heading = &dated.fields[0];
    assert_eq!(heading.kind, FieldKind::Section, "heading comes first");
    assert_eq!(heading.kind_raw, None, "a known kind carries no raw string");
    assert_eq!(heading.kind_str(), "section");
    assert!(!heading.kind.is_sensitive());

    let undated = vault.get(Uuid::from_bytes(META_UNDATED_ID)).unwrap();
    assert_eq!(undated.title, "Undated");
    assert_eq!(undated.created_at, None, "no key on disk reads as None");
    assert_eq!(undated.modified_at, META_AT);
    assert_fields(undated, &[("notes", FieldKind::Notes, "no created_at key")]);

    // A save by this build keeps both exactly: the dated stamp and the absent key.
    let again = LockedVault::parse(&vault.serialize())
        .unwrap()
        .unlock(&pw())
        .unwrap();
    assert_eq!(
        again
            .get(Uuid::from_bytes(META_DATED_ID))
            .unwrap()
            .created_at,
        Some(META_CREATED_AT)
    );
    assert_eq!(
        again
            .get(Uuid::from_bytes(META_UNDATED_ID))
            .unwrap()
            .created_at,
        None
    );
    assert_eq!(
        again.get(Uuid::from_bytes(META_DATED_ID)).unwrap().fields[0].kind,
        FieldKind::Section
    );
}

/// Builds `v2-basic.vault` (see the module docs). The first version 2 fixture; the only
/// regenerator that may still run.
#[test]
#[ignore]
fn regenerate_v2_basic_fixture() {
    let mut vault = new_vault();
    assert_eq!(vault.header().format_version, 2);

    let with_id = |id: [u8; 16], name: &str, kind: FieldKind, value: &str| -> Field {
        let mut f = field(name, kind, value, V2_AT);
        f.id = Uuid::from_bytes(id);
        f
    };
    let mut dupes = Item::new("Duplicate names", device(), V2_AT);
    dupes.id = Uuid::from_bytes(V2_DUPES_ID);
    dupes.tags = vec!["login".into()];
    dupes.fields = vec![
        with_id(
            V2_USERNAME_1,
            "username",
            FieldKind::Text,
            "first@example.com",
        ),
        with_id(
            V2_USERNAME_2,
            "username",
            FieldKind::Text,
            "second@example.com",
        ),
        with_id(V2_UNNAMED, "", FieldKind::Text, "unnamed value"),
        with_id(V2_PASSWORD, "password", FieldKind::Password, "hunter2"),
        with_id(V2_PIN, "pin", FieldKind::Text, "0000"),
    ];
    let id = vault.insert(dupes, V2_AT);
    // A password change records the field id in history; a removal leaves a marker.
    vault
        .set_field(
            id,
            Uuid::from_bytes(V2_PASSWORD),
            secret("hunter3"),
            V2_AT + 1,
        )
        .unwrap();
    vault
        .remove_field(id, Uuid::from_bytes(V2_PIN), V2_AT + 2)
        .unwrap();

    let mut note = Item::new("Plain note", device(), V2_AT);
    note.id = Uuid::from_bytes(V2_NOTE_ID);
    note.tags = vec!["note".into()];
    note.fields = vec![with_id(
        V2_NOTES,
        "notes",
        FieldKind::Notes,
        "nothing special",
    )];
    vault.insert(note, V2_AT);

    std::fs::write(format!("{FIXTURE_DIR}/v2-basic.vault"), vault.serialize()).unwrap();
}

#[test]
fn v2_basic_opens_with_ids_duplicates_empty_name_marker_and_history_id() {
    let bytes = std::fs::read(format!("{FIXTURE_DIR}/v2-basic.vault")).unwrap();
    assert_eq!(&bytes[4..6], &[0, 2], "prefix version 2");
    let locked = LockedVault::parse(&bytes).unwrap();
    check_kdf(&locked);
    assert_eq!(locked.header().format_version, 2);
    let vault = locked.unlock(&pw()).unwrap();
    assert_eq!(vault.items().count(), 2);

    let dupes = vault.get(Uuid::from_bytes(V2_DUPES_ID)).unwrap();
    assert_eq!(dupes.title, "Duplicate names");
    assert!(dupes.extras.is_empty());
    let ids: Vec<Uuid> = dupes.fields.iter().map(|f| f.id).collect();
    assert_eq!(
        ids,
        [V2_USERNAME_1, V2_USERNAME_2, V2_UNNAMED, V2_PASSWORD].map(Uuid::from_bytes),
        "explicit ids in field order; the pin is gone"
    );
    let names: Vec<&str> = dupes.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["username", "username", "", "password"]);
    assert_eq!(
        dupes.field("username").unwrap().id,
        Uuid::from_bytes(V2_USERNAME_1),
        "name lookup: first match"
    );
    assert_eq!(
        dupes
            .field_by_id(Uuid::from_bytes(V2_USERNAME_2))
            .unwrap()
            .value
            .expose_secret(),
        "second@example.com"
    );
    assert!(dupes.field("").is_none(), "an empty name never matches");
    assert_eq!(
        dupes
            .field_by_id(Uuid::from_bytes(V2_UNNAMED))
            .unwrap()
            .value
            .expose_secret(),
        "unnamed value"
    );
    let password = dupes.field_by_id(Uuid::from_bytes(V2_PASSWORD)).unwrap();
    assert_eq!(password.value.expose_secret(), "hunter3");
    assert_eq!(password.modified_at, V2_AT + 1);
    assert_eq!(dupes.history.len(), 1);
    assert_eq!(dupes.history[0].value.expose_secret(), "hunter2");
    assert_eq!(dupes.history[0].replaced_at, V2_AT + 1);
    assert_eq!(
        dupes.history[0].field_id,
        Some(Uuid::from_bytes(V2_PASSWORD)),
        "history carries the field id"
    );
    assert_eq!(
        dupes.removed_fields,
        vec![vault_core::FieldTombstone {
            id: Uuid::from_bytes(V2_PIN),
            removed_at: V2_AT + 2,
        }]
    );
    assert_eq!(dupes.modified_at, V2_AT + 2);

    let note = vault.get(Uuid::from_bytes(V2_NOTE_ID)).unwrap();
    assert_eq!(note.fields.len(), 1);
    assert_eq!(note.fields[0].id, Uuid::from_bytes(V2_NOTES));
    assert_eq!(note.fields[0].value.expose_secret(), "nothing special");
    assert!(note.removed_fields.is_empty());

    // A save by this build keeps everything exactly, at version 2.
    let again = vault.serialize();
    assert_eq!(&again[4..6], &[0, 2]);
    let reopened = LockedVault::parse(&again).unwrap().unlock(&pw()).unwrap();
    let d2 = reopened.get(Uuid::from_bytes(V2_DUPES_ID)).unwrap();
    assert_eq!(d2.fields.iter().map(|f| f.id).collect::<Vec<_>>(), ids);
    assert_eq!(d2.history[0].field_id, Some(Uuid::from_bytes(V2_PASSWORD)));
    assert_eq!(d2.removed_fields, dupes.removed_fields);
}

fn check_kdf(locked: &LockedVault) {
    let k = locked.kdf_params();
    assert_eq!((k.m_cost_kib, k.t_cost, k.p_cost), (8192, 1, 1));
}

fn assert_fields(item: &Item, expected: &[(&str, FieldKind, &str)]) {
    assert_eq!(
        item.fields.len(),
        expected.len(),
        "field count of {}",
        item.title
    );
    for (name, kind, value) in expected {
        // By name regardless of kind: `Item::field` skips section headings.
        let f = item
            .fields
            .iter()
            .find(|f| f.name == *name)
            .unwrap_or_else(|| panic!("missing field {name}"));
        assert_eq!(f.kind, *kind, "kind of {name}");
        assert_eq!(f.value.expose_secret(), value, "value of {name}");
    }
}

#[test]
fn v1_basic_unlocks_and_matches() {
    let locked = LockedVault::parse(BASIC).unwrap();
    check_kdf(&locked);
    let vault = locked.unlock(&pw()).unwrap();
    assert_eq!(vault.items().count(), 3);

    let by_title = |t: &str| {
        vault
            .items()
            .find(|i| i.title == t)
            .unwrap_or_else(|| panic!("missing item {t}"))
    };

    let github = by_title("GitHub");
    assert_eq!(github.extras, vec![kind_extra("login")], "legacy kind kept");
    assert_eq!(github.tags, vec!["dev".to_owned()]);
    assert_fields(
        github,
        &[
            ("username", FieldKind::Text, "chris@example.com"),
            ("password", FieldKind::Password, "hunter2-but-longer"),
            ("url", FieldKind::Url, "https://github.com"),
            (
                "totp",
                FieldKind::Totp,
                "otpauth://totp/GitHub:chris?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
            ),
        ],
    );

    let wifi = by_title("Wifi");
    assert_eq!(wifi.extras, vec![kind_extra("note")]);
    assert!(wifi.tags.is_empty());
    assert_eq!(wifi.fields.len(), 1);
    let notes = wifi.field("notes").unwrap();
    assert_eq!(notes.kind, FieldKind::Notes);
    assert_eq!(
        notes.value.expose_secret(),
        "SSID: home-net\nPassphrase: lorem ipsum dolor"
    );

    let visa = by_title("Visa");
    assert_eq!(visa.extras, vec![kind_extra("card")]);
    assert!(visa.tags.is_empty());
    assert_fields(
        visa,
        &[
            ("number", FieldKind::Text, "4111111111111111"),
            ("expiry", FieldKind::MonthYear, "12/29"),
            ("cvv", FieldKind::Password, "123"),
        ],
    );
}

#[test]
fn v1_empty_unlocks() {
    let locked = LockedVault::parse(EMPTY).unwrap();
    check_kdf(&locked);
    let vault = locked.unlock(&pw()).unwrap();
    assert_eq!(vault.items().count(), 0);
    assert_eq!(vault.items_including_deleted().count(), 0);
}

#[test]
fn v1_basic_wrong_password() {
    let locked = LockedVault::parse(BASIC).unwrap();
    match locked.unlock(&SecretString::new("incorrect horse".to_owned())) {
        Err(VaultError::WrongPassword) => {}
        Err(e) => panic!("expected WrongPassword, got {e:?}"),
        Ok(_) => panic!("wrong password unlocked the vault"),
    }
}

fn future_item(vault: &UnlockedVault) -> &Item {
    let items: Vec<_> = vault.items().collect();
    assert_eq!(items.len(), 1);
    let item = items[0];
    assert_eq!(item.id, Uuid::from_bytes(FUTURE_ITEM_ID));
    assert_eq!(item.title, "Future thing");
    // Extras come back in the file's canonical key order: "kind" (4 bytes) sorts before
    // "x_item_future" (13 bytes).
    assert_eq!(
        item.extras,
        vec![kind_extra(FUTURE_ITEM_KIND), item_extra()],
        "unknown item kind is just another unknown key"
    );
    let f = item.field("future").unwrap();
    assert_eq!(f.kind, FieldKind::Other);
    assert_eq!(f.kind_raw.as_deref(), Some(FUTURE_FIELD_KIND));
    assert_eq!(f.kind_str(), FUTURE_FIELD_KIND);
    assert!(f.kind.is_sensitive(), "unknown field kinds are masked");
    assert_eq!(f.value.expose_secret(), "future-value");
    assert_eq!(f.extras, vec![field_extra()]);
    let username = item.field("username").unwrap();
    assert_eq!(username.kind, FieldKind::Text);
    assert_eq!(username.kind_raw, None, "known kinds carry no raw string");
    item
}

fn assert_forward_header(locked: &LockedVault) {
    check_kdf(locked);
    let header = locked.header();
    assert_eq!(header.extras, vec![header_extra()]);
    assert_eq!(header.kdf_extras, vec![kdf_extra()]);
    assert_eq!(header.slots_modified_at, None, "untouched header: no stamp");
    assert_eq!(header.slots_device_id, None);
    assert_eq!(header.slots.len(), 2);
    assert_eq!(
        header.slots[0],
        Slot::Opaque(future_slot()),
        "opaque slot first"
    );
    assert!(header.slots[1].is_key_of(SlotKind::Password));
    assert_eq!(
        header.slots[1].as_key().unwrap().extras,
        vec![key_slot_extra()],
        "unknown key on the known slot"
    );
    assert_eq!(
        locked.slots().map(|(_, k)| k).collect::<Vec<_>>(),
        [
            SlotKind::Other(FUTURE_SLOT_KIND.to_owned()),
            SlotKind::Password
        ]
    );
}

#[test]
fn v1_forward_unlocks_with_unknown_kinds_intact() {
    let locked = LockedVault::parse(FORWARD).unwrap();
    assert_forward_header(&locked);
    let vault = locked.unlock(&pw()).unwrap();
    future_item(&vault);
    assert_eq!(vault.items_including_deleted().count(), 1);
}

/// The four plaintext unknown-key sites that live outside `Header`/`Item`: record, manifest
/// (and, via `assert_forward_header`, `kdf` and the known slot).
fn assert_forward_records(file: &VaultFile) {
    assert_eq!(file.items.len(), 1);
    assert_eq!(file.items[0].extras, vec![record_extra()], "item record");
    assert_eq!(
        file.manifest.extras,
        vec![manifest_extra()],
        "manifest record"
    );
}

#[test]
fn v1_forward_unknowns_survive_serialize_parse_roundtrip() {
    // The committed bytes are canonical, so a structural parse -> to_bytes is byte-identical;
    // this proves every one of the eight unknown-key sites (and the opaque slot) is re-emitted
    // verbatim, in position.
    let file = VaultFile::parse(FORWARD).unwrap();
    assert_eq!(file.to_bytes(), FORWARD);
    assert_forward_records(&file);

    let locked = LockedVault::parse(FORWARD).unwrap();
    assert_forward_header(&locked);
    let vault = locked.unlock(&pw()).unwrap();
    let again = vault.serialize();
    let relocked = LockedVault::parse(&again).unwrap();
    assert_forward_header(&relocked);
    assert_forward_records(&VaultFile::parse(&again).unwrap());
    let reopened = relocked.unlock(&pw()).unwrap();
    let a = future_item(&vault);
    let b = future_item(&reopened);
    assert_eq!(a.modified_at, b.modified_at);
    assert_eq!(a.tags, b.tags);
    // Byte-equal extras at every level (Value equality is structural; the encodings are
    // canonical so structural equality is byte equality). Sites 1-8: header, kdf, opaque
    // slot, known slot, record, item payload, field, manifest.
    assert_eq!(vault.header().extras, reopened.header().extras);
    assert_eq!(vault.header().extras, vec![header_extra()]);
    assert_eq!(reopened.header().kdf_extras, vec![kdf_extra()]);
    assert_eq!(reopened.header().slots[0], Slot::Opaque(future_slot()));
    assert_eq!(
        reopened.header().slots[1].as_key().unwrap().extras,
        vec![key_slot_extra()]
    );
    assert_eq!(a.extras, b.extras);
    assert_eq!(b.extras, vec![kind_extra(FUTURE_ITEM_KIND), item_extra()]);
    assert_eq!(a.fields[0].extras, b.fields[0].extras);
    assert_eq!(b.fields[0].extras, vec![field_extra()]);

    // A second save is canonical and still carries everything: the extras are not merely
    // tolerated once but preserved by this build's own writer.
    let twice = VaultFile::parse(&reopened.serialize()).unwrap();
    assert_forward_records(&twice);
    assert_eq!(twice.header.kdf_extras, vec![kdf_extra()]);
}

#[test]
fn v1_forward_opaque_slot_survives_change_password() {
    let mut vault = LockedVault::parse(FORWARD).unwrap().unlock(&pw()).unwrap();
    let new_pw = SecretString::new("a different passphrase".to_owned());
    vault
        .change_password(&pw(), &new_pw, KdfParams::for_tests(), T0)
        .unwrap();
    assert_eq!(vault.header().slots[0], Slot::Opaque(future_slot()));
    assert!(vault.header().slots[1].is_key_of(SlotKind::Password));

    let bytes = vault.serialize();
    let locked = LockedVault::parse(&bytes).unwrap();
    assert_eq!(locked.header().slots[0], Slot::Opaque(future_slot()));
    assert_eq!(locked.unlock(&pw()).unwrap_err(), VaultError::WrongPassword);
    let reopened = locked.unlock(&new_pw).unwrap();
    future_item(&reopened);
}

#[test]
fn v1_forward_items_yields_item_with_unknown_kind_in_extras() {
    let vault = LockedVault::parse(FORWARD).unwrap().unlock(&pw()).unwrap();
    let kinds: Vec<_> = vault
        .items()
        .map(|i| i.extras.iter().find(|(k, _)| k == &t("kind")).cloned())
        .collect();
    assert_eq!(kinds, [Some(kind_extra(FUTURE_ITEM_KIND))]);
}

/// The policy test: every committed fixture, of every version, must parse and unlock with the
/// shared password. Walks the directory so a new fixture is covered without a code change.
#[test]
fn every_fixture_in_the_directory_opens() {
    let mut names: Vec<String> = std::fs::read_dir(FIXTURE_DIR)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".vault"))
        .collect();
    names.sort();
    assert!(
        names.len() >= 8,
        "expected at least v1-attach, v1-basic, v1-empty, v1-forward, v1-icon, v1-meta, v1-stamped, v2-basic; found {names:?}"
    );
    assert!(names.iter().any(|n| n.starts_with("v1-")));
    assert!(names.iter().any(|n| n.starts_with("v2-")));
    // Written after the item-kind removal (no legacy `kind` extra) and after stamp-at-create
    // (header carries `slots_modified_at`).
    let post_removal = |name: &str| {
        matches!(
            name,
            "v1-stamped.vault" | "v1-icon.vault" | "v1-meta.vault" | "v2-basic.vault"
        )
    };
    for name in &names {
        let bytes = std::fs::read(format!("{FIXTURE_DIR}/{name}")).unwrap();
        // The name's version is the file's prefix version, and every version this build
        // reads has at least one fixture here (asserted above for 1 and 2).
        let named_version: u16 = name
            .strip_prefix('v')
            .and_then(|r| r.split_once('-'))
            .and_then(|(v, _)| v.parse().ok())
            .unwrap_or_else(|| panic!("{name}: fixtures are named v<FORMAT_VERSION>-<name>.vault"));
        // The committed bytes are canonical: a structural parse -> to_bytes is byte-identical.
        let file = VaultFile::parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(file.to_bytes(), bytes, "{name}: structural round trip");
        assert_eq!(
            file.header.format_version, named_version,
            "{name}: prefix version matches the name"
        );
        let locked = LockedVault::parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        check_kdf(&locked);
        let vault = locked
            .unlock(&pw())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        // Field identity (FI-1): a v1 file's fields get the documented derived ids (the
        // full migration test is in `tests/field_id.rs`); every file's ids are unique.
        for item in vault.items_including_deleted() {
            let mut seen = std::collections::BTreeSet::new();
            for (i, f) in item.fields.iter().enumerate() {
                assert!(
                    seen.insert(f.id),
                    "{name}: duplicate field id in {}",
                    item.title
                );
                if named_version == 1 {
                    let ordinal = item.fields[..i].iter().filter(|e| e.name == f.name).count();
                    assert_eq!(
                        f.id,
                        Field::derived_id(item.id, &f.name, ordinal),
                        "{name}: derived id of {}/{}",
                        item.title,
                        f.name
                    );
                }
            }
        }
        // Every pre-2026-10-30 item carries a legacy `kind` entry, now an unknown key: it is
        // never dropped and never resurfaces as anything else. (`v1-stamped` and `v1-icon`
        // were written after the removal and have none.)
        let legacy = !post_removal(name);
        for item in vault.items_including_deleted().filter(|_| legacy) {
            let kinds: Vec<_> = item
                .extras
                .iter()
                .filter(|(k, _)| k == &t("kind"))
                .collect();
            assert_eq!(kinds.len(), 1, "{name}: item {} legacy kind", item.title);
            assert!(
                matches!(kinds[0].1, Value::Text(_)),
                "{name}: legacy kind is text"
            );
        }
        // Only `v1-stamped` (slot mutation) and `v1-icon` (created after stamp-at-create)
        // carry the stamp. A save by this build must neither invent the v1.1 stamp (old bytes
        // would change on every round trip) nor lose it.
        let committed = (file.header.slots_modified_at, file.header.slots_device_id);
        assert_eq!(
            committed.0.is_some(),
            post_removal(name),
            "{name}: committed stamp"
        );
        // Whatever it holds, it must survive a save by this build, extras included. A save
        // never changes the prefix version (a v1 file stays v1; see `FORMAT_VERSION`).
        let again = vault.serialize();
        let again_header = VaultFile::parse(&again).unwrap().header;
        assert_eq!(
            (again_header.slots_modified_at, again_header.slots_device_id),
            committed,
            "{name}: a plain save keeps slots_modified_at / slots_device_id as committed"
        );
        assert_eq!(
            again_header.format_version, named_version,
            "{name}: a plain save keeps the format version"
        );
        let reopened = LockedVault::parse(&again)
            .unwrap_or_else(|e| panic!("{name}: re-parse: {e}"))
            .unlock(&pw())
            .unwrap_or_else(|e| panic!("{name}: re-unlock: {e}"));
        let before: Vec<_> = vault.items_including_deleted().collect();
        let after: Vec<_> = reopened.items_including_deleted().collect();
        assert_eq!(before.len(), after.len(), "{name}: item count after save");
        for (a, b) in before.iter().zip(&after) {
            assert_eq!(a.id, b.id);
            assert_eq!(
                a.extras, b.extras,
                "{name}: item {} extras after save",
                a.title
            );
            // Ids are stable across the save (explicit on disk now, derived before).
            assert_eq!(
                a.fields.iter().map(|f| f.id).collect::<Vec<_>>(),
                b.fields.iter().map(|f| f.id).collect::<Vec<_>>(),
                "{name}: field ids of {} after save",
                a.title
            );
        }
    }
}
