//! Committed format fixtures (01 §8). `regenerate_fixtures` rewrites them; the other tests parse,
//! unlock and assert contents.

use vault_core::{
    ExposeSecret, Field, FieldKind, Item, ItemKind, KdfParams, LockedVault, SecretString,
    UnlockedVault, Uuid, VaultError,
};

const PASSWORD: &str = "correct horse battery staple";
const BASIC: &[u8] = include_bytes!("fixtures/v1-basic.vault");
const EMPTY: &[u8] = include_bytes!("fixtures/v1-empty.vault");
const T0: u64 = 1_700_000_000_000;

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
