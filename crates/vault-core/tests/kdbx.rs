#![cfg(feature = "kdbx")]

use keepass::{
    Database, DatabaseKey,
    config::{KdfConfig, OuterCipherConfig},
};
use vault_core::{ExposeSecret as _, FieldKind, ImportError, SecretString, Uuid, import_kdbx};

const PASSWORD: &str = "kdbx-password";
const KEYFILE: &[u8] = b"0123456789abcdef0123456789abcdef";
const NOW: u64 = 42;

fn password(value: &str) -> SecretString {
    SecretString::new(value.into())
}

fn sample() -> Database {
    let mut db = Database::new();
    db.config.kdf_config = KdfConfig::Aes { rounds: 10 };
    {
        let mut root = db.root_mut();
        let mut work = root.add_group();
        work.name = "Work".into();
        let mut infra = work.add_group();
        infra.name = "Infra".into();
        let mut entry = infra.add_entry();
        entry.set_unprotected("Title", "GitHub");
        entry.set_unprotected("UserName", "chris");
        entry.set_protected("Password", "old-password");
        let previous = (*entry).clone();
        entry.history.as_mut().unwrap().add_entry(previous);
        entry.set_protected("Password", "new-password");
        entry.set_unprotected("URL", "https://github.com");
        entry.set_unprotected("Notes", "one\ntwo");
        entry.set_protected(
            "otp",
            "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&issuer=Test",
        );
        entry.set_protected("API token", "private-token");
        entry.set_unprotected("password", "custom collision");
        entry.tags = vec!["coding".into()];
    }
    db.root_mut()
        .add_entry()
        .set_unprotected("Title", "Reference");
    let bin = {
        let mut root = db.root_mut();
        let mut bin = root.add_group();
        bin.name = "Recycle Bin".into();
        bin.add_entry().set_unprotected("Title", "Deleted");
        bin.id().uuid()
    };
    db.meta.recyclebin_uuid = Some(bin);
    db
}

fn encoded(db: &Database, pw: Option<&str>, keyfile: Option<&[u8]>) -> Vec<u8> {
    let mut key = DatabaseKey::new();
    if let Some(pw) = pw {
        key = key.with_password(pw);
    }
    if let Some(mut keyfile) = keyfile {
        key = key.with_keyfile(&mut keyfile).unwrap();
    }
    let mut bytes = Vec::new();
    db.save(&mut bytes, key).unwrap();
    bytes
}

#[test]
fn maps_fields_groups_history_and_skips_recycle_bin() {
    let bytes = include_bytes!("fixtures/keepass-v4.kdbx");
    let device = Uuid::new_v4();
    let items = import_kdbx(bytes, &password(PASSWORD), None, device, NOW).unwrap();
    assert_eq!(items.len(), 2);
    let item = items.iter().find(|item| item.title == "GitHub").unwrap();
    assert_eq!(item.device_id, device);
    assert_eq!(item.modified_at, NOW);
    assert_eq!(item.tags, ["coding", "Work/Infra"]);
    for (name, kind, value) in [
        ("username", FieldKind::Text, "chris"),
        ("password", FieldKind::Password, "new-password"),
        ("website", FieldKind::Url, "https://github.com"),
        ("notes", FieldKind::Notes, "one\ntwo"),
        ("API token", FieldKind::Password, "private-token"),
        ("password (2)", FieldKind::Text, "custom collision"),
    ] {
        let field = item.fields.iter().find(|field| field.name == name).unwrap();
        assert_eq!(field.kind, kind);
        assert_eq!(field.value.expose_secret(), value);
        assert_eq!(field.modified_at, NOW);
    }
    assert_eq!(
        item.fields.iter().find(|f| f.name == "totp").unwrap().kind,
        FieldKind::Totp
    );
    assert_eq!(item.history[0].value.expose_secret(), "old-password");
    let again = import_kdbx(bytes, &password(PASSWORD), None, device, NOW).unwrap();
    assert!(
        items
            .iter()
            .all(|item| again.iter().all(|other| item.id != other.id))
    );
}

#[test]
fn imports_kdbx3_fixture_and_rejects_bad_inputs_without_leaking_values() {
    let bytes = include_bytes!("fixtures/keepass-v3.kdbx");
    assert!(
        !import_kdbx(bytes, &password("demopass"), None, Uuid::nil(), NOW)
            .unwrap()
            .is_empty()
    );
    let error = import_kdbx(
        bytes,
        &password("do-not-print-this"),
        None,
        Uuid::nil(),
        NOW,
    )
    .unwrap_err();
    assert!(matches!(error, ImportError::KdbxCredentials));
    assert!(!error.to_string().contains("do-not-print-this"));
    assert!(import_kdbx(b"junk", &password(PASSWORD), None, Uuid::nil(), NOW).is_err());
    let mut damaged = include_bytes!("fixtures/keepass-v4.kdbx").to_vec();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    assert!(import_kdbx(&damaged, &password(PASSWORD), None, Uuid::nil(), NOW).is_err());
}

#[test]
fn supports_password_plus_keyfile_and_keyfile_only() {
    for pw in [Some(PASSWORD), None] {
        let bytes = encoded(&sample(), pw, Some(KEYFILE));
        assert_eq!(
            import_kdbx(
                &bytes,
                &password(pw.unwrap_or("")),
                Some(KEYFILE),
                Uuid::nil(),
                NOW
            )
            .unwrap()
            .len(),
            2
        );
        assert!(import_kdbx(&bytes, &password(pw.unwrap_or("")), None, Uuid::nil(), NOW).is_err());
        assert!(
            import_kdbx(
                &bytes,
                &password(pw.unwrap_or("")),
                Some(b"wrong key"),
                Uuid::nil(),
                NOW
            )
            .is_err()
        );
    }
}

#[test]
fn supports_argon2_chacha_and_empty_database() {
    let mut db = Database::new();
    if let KdfConfig::Argon2 {
        iterations,
        memory,
        parallelism,
        ..
    } = &mut db.config.kdf_config
    {
        *iterations = 1;
        *memory = 64 * 1024;
        *parallelism = 1;
    }
    db.config.outer_cipher_config = OuterCipherConfig::ChaCha20;
    let bytes = encoded(&db, Some(PASSWORD), None);
    assert!(
        import_kdbx(&bytes, &password(PASSWORD), None, Uuid::nil(), NOW)
            .unwrap()
            .is_empty()
    );
}

#[test]
#[ignore = "regenerate the public encrypted KeePass test fixture"]
fn generate_fixture() {
    let bytes = encoded(&sample(), Some(PASSWORD), None);
    std::fs::write(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/keepass-v4.kdbx"
        ),
        bytes,
    )
    .unwrap();
}
