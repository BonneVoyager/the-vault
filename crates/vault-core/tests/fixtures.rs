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
//! of an unknown kind, an item and a field of unknown kinds, and unknown keys at header,
//! item and field level, as a newer build would write them.
//!
//! `v1-attach.vault` (01 §4 "Attachments (v1.1)") holds one item with two attachment
//! references, an empty file and a 3-chunk file (2 MiB + 7 bytes), whose sealed blobs live
//! under `v1-attach.vault.attachments/<id hex>.bin`. The blob contents are deterministic
//! (`attach_pattern`) so the test can verify the decrypted bytes.

use std::io::Cursor;

use ciborium::Value;
use vault_core::attachment::{CHUNK_SIZE, blob_file_name, new_ref, open, seal};
use vault_core::format::VaultFile;
use vault_core::{
    ExposeSecret, Field, FieldKind, Item, ItemKind, KdfParams, LockedVault, OpaqueSlot,
    SecretString, Slot, SlotKind, UnlockedVault, Uuid, VaultError,
};

const PASSWORD: &str = "correct horse battery staple";
const BASIC: &[u8] = include_bytes!("fixtures/v1-basic.vault");
const EMPTY: &[u8] = include_bytes!("fixtures/v1-empty.vault");
const FORWARD: &[u8] = include_bytes!("fixtures/v1-forward.vault");
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

fn attach_pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn t(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn header_extra() -> (Value, Value) {
    (t("x_header_future"), t("from a newer header"))
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
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    std::fs::create_dir_all(dir).unwrap();

    let mut vault = new_vault();

    let mut github = Item::new(ItemKind::Login, "GitHub", device(), T0);
    github.id = Uuid::from_bytes([0x01; 16]);
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

    let mut wifi = Item::new(ItemKind::Note, "Wifi", device(), T0 + 10);
    wifi.id = Uuid::from_bytes([0x02; 16]);
    wifi.fields = vec![field(
        "notes",
        FieldKind::Notes,
        "SSID: home-net\nPassphrase: lorem ipsum dolor",
        T0 + 10,
    )];
    vault.insert(wifi, T0 + 10);

    let mut visa = Item::new(ItemKind::Card, "Visa", device(), T0 + 20);
    visa.id = Uuid::from_bytes([0x03; 16]);
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
    let mut vault = new_vault();
    vault.header_extras_mut().push(header_extra());

    let mut future = Item::new(ItemKind::Other, "Future thing", device(), T0 + 30);
    future.kind_raw = Some(FUTURE_ITEM_KIND.to_owned());
    future.id = Uuid::from_bytes(FUTURE_ITEM_ID);
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

    // The opaque slot goes FIRST so the position test is meaningful.
    let mut file = VaultFile::parse(&vault.serialize()).unwrap();
    file.header.slots.insert(0, Slot::Opaque(future_slot()));
    std::fs::write(format!("{FIXTURE_DIR}/v1-forward.vault"), file.to_bytes()).unwrap();
}

/// Builds `v1-attach.vault` and its two blobs (see the module docs). Separate from the other
/// regenerators so their bytes are not churned.
#[test]
#[ignore]
fn regenerate_attach_fixture() {
    std::fs::create_dir_all(ATTACH_DIR).unwrap();
    let mut vault = new_vault();

    let mut item = Item::new(ItemKind::Note, "With attachments", device(), T0 + 40);
    item.id = Uuid::from_bytes(ATTACH_ITEM_ID);
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
        let f = item
            .field(name)
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
    assert_eq!(github.kind, ItemKind::Login);
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
    assert_eq!(wifi.kind, ItemKind::Note);
    assert!(wifi.tags.is_empty());
    assert_eq!(wifi.fields.len(), 1);
    let notes = wifi.field("notes").unwrap();
    assert_eq!(notes.kind, FieldKind::Notes);
    assert_eq!(
        notes.value.expose_secret(),
        "SSID: home-net\nPassphrase: lorem ipsum dolor"
    );

    let visa = by_title("Visa");
    assert_eq!(visa.kind, ItemKind::Card);
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
    assert_eq!(item.kind, ItemKind::Other);
    assert!(item.kind.is_other());
    assert_eq!(item.kind_raw.as_deref(), Some(FUTURE_ITEM_KIND));
    assert_eq!(item.kind_str(), FUTURE_ITEM_KIND);
    assert_eq!(item.title, "Future thing");
    assert_eq!(item.extras, vec![item_extra()]);
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
    assert_eq!(header.slots.len(), 2);
    assert_eq!(
        header.slots[0],
        Slot::Opaque(future_slot()),
        "opaque slot first"
    );
    assert!(header.slots[1].is_key_of(SlotKind::Password));
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

#[test]
fn v1_forward_unknowns_survive_serialize_parse_roundtrip() {
    // The committed bytes are canonical, so a structural parse -> to_bytes is byte-identical;
    // this proves the opaque slot (and every extra) is re-emitted verbatim, in position.
    let file = VaultFile::parse(FORWARD).unwrap();
    assert_eq!(file.to_bytes(), FORWARD);

    let vault = LockedVault::parse(FORWARD).unwrap().unlock(&pw()).unwrap();
    let again = vault.serialize();
    let relocked = LockedVault::parse(&again).unwrap();
    assert_forward_header(&relocked);
    let reopened = relocked.unlock(&pw()).unwrap();
    let a = future_item(&vault);
    let b = future_item(&reopened);
    assert_eq!(a.modified_at, b.modified_at);
    assert_eq!(a.tags, b.tags);
    // Byte-equal extras at all three levels (Value equality is structural; the encodings are
    // canonical so structural equality is byte equality).
    assert_eq!(a.extras, b.extras);
    assert_eq!(a.fields[0].extras, b.fields[0].extras);
    assert_eq!(vault.header().extras, reopened.header().extras);
}

#[test]
fn v1_forward_opaque_slot_survives_change_password() {
    let mut vault = LockedVault::parse(FORWARD).unwrap().unlock(&pw()).unwrap();
    let new_pw = SecretString::new("a different passphrase".to_owned());
    vault
        .change_password(&pw(), &new_pw, KdfParams::for_tests())
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
fn v1_forward_items_yields_unknown_kind_item() {
    let vault = LockedVault::parse(FORWARD).unwrap().unlock(&pw()).unwrap();
    let kinds: Vec<_> = vault.items().map(|i| (i.kind, i.kind_str())).collect();
    assert_eq!(kinds, [(ItemKind::Other, FUTURE_ITEM_KIND)]);
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
        names.len() >= 4,
        "expected at least v1-attach, v1-basic, v1-empty, v1-forward; found {names:?}"
    );
    for name in &names {
        let bytes = std::fs::read(format!("{FIXTURE_DIR}/{name}")).unwrap();
        assert!(
            name.starts_with('v') && name.contains('-'),
            "{name}: fixtures are named v<FORMAT_VERSION>-<name>.vault"
        );
        let locked = LockedVault::parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        check_kdf(&locked);
        let vault = locked
            .unlock(&pw())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        // Whatever it holds, it must survive a save by this build.
        let again = vault.serialize();
        LockedVault::parse(&again)
            .unwrap_or_else(|e| panic!("{name}: re-parse: {e}"))
            .unlock(&pw())
            .unwrap_or_else(|e| panic!("{name}: re-unlock: {e}"));
    }
}
