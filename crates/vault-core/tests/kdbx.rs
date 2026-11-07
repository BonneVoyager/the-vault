#![cfg(feature = "kdbx")]

use argon2::{Algorithm, Argon2, Params, Version};
use keepass::{
    Database, DatabaseKey,
    config::{CompressionConfig, KdfConfig, OuterCipherConfig},
};
use sha2::{Digest as _, Sha256, Sha512};
use vault_core::{
    ExposeSecret as _, FieldKind, ImportError, SecretString, Totp, Uuid, import_kdbx,
};

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
    assert_eq!(
        item.tags,
        ["login", "coding", "Work/Infra"],
        "template tag first, then entry tags, then the group path"
    );
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
    // The committed fixture's entries carry a real KeePass CreationTime, which is kept.
    assert!(
        item.created_at.is_some_and(|c| c != NOW),
        "created_at comes from CreationTime, not now: {:?}",
        item.created_at
    );
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
    // A flipped payload byte fails the HMAC block stream *after* the key passed: damaged, not
    // wrong credentials (owner decision 2026-11-06). The password still decides the rest.
    let mut damaged = include_bytes!("fixtures/keepass-v4.kdbx").to_vec();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    assert!(matches!(
        import_kdbx(&damaged, &password(PASSWORD), None, Uuid::nil(), NOW),
        Err(ImportError::KdbxMalformed)
    ));
    assert!(matches!(
        import_kdbx(&damaged, &password("wrong"), None, Uuid::nil(), NOW),
        Err(ImportError::KdbxCredentials)
    ));
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
fn created_at_comes_from_the_entry_creation_time_or_now() {
    use keepass::db::Times;
    let mut db = Database::new();
    db.config.kdf_config = KdfConfig::Aes { rounds: 10 };
    let dated_at = Times::now();
    {
        let mut root = db.root_mut();
        let mut dated = root.add_entry();
        dated.set_unprotected("Title", "Dated");
        dated.times.creation = Some(dated_at);
    }
    {
        let mut root = db.root_mut();
        let mut epoch = root.add_entry();
        epoch.set_unprotected("Title", "Epoch");
        epoch.times.creation = Some(Times::epoch());
    }
    {
        let mut root = db.root_mut();
        let mut undated = root.add_entry();
        undated.set_unprotected("Title", "Undated");
        undated.times.creation = None;
    }
    let bytes = encoded(&db, Some(PASSWORD), None);
    let items = import_kdbx(&bytes, &password(PASSWORD), None, Uuid::nil(), NOW).unwrap();
    let by_title = |t: &str| items.iter().find(|i| i.title == t).unwrap();
    let expected = u64::try_from(dated_at.and_utc().timestamp_millis()).unwrap();
    assert_eq!(by_title("Dated").created_at, Some(expected));
    assert_ne!(expected, NOW);
    assert_eq!(
        by_title("Epoch").created_at,
        Some(NOW),
        "a CreationTime at the Unix epoch is \"unknown\": now"
    );
    assert_eq!(
        by_title("Undated").created_at,
        Some(NOW),
        "no CreationTime: now"
    );
    for item in &items {
        assert_eq!(
            item.modified_at, NOW,
            "modified_at is always the import stamp"
        );
    }
}

fn small_db() -> Database {
    let mut db = Database::new();
    db.config.kdf_config = KdfConfig::Aes { rounds: 10 };
    db
}

fn import(bytes: &[u8], pw: &str) -> Result<Vec<vault_core::Item>, ImportError> {
    import_kdbx(bytes, &password(pw), None, Uuid::nil(), NOW)
}

fn is_limits_error(result: &Result<Vec<vault_core::Item>, ImportError>) -> bool {
    matches!(result, Err(ImportError::Malformed(m)) if m.contains("safe limits"))
}

/// `(type, value offset, value length)` of every outer-header entry including END.
/// KDBX3 entries are `type u8, len u16 LE`; KDBX4 entries are `type u8, len u32 LE`.
fn header_entries(bytes: &[u8]) -> Vec<(u8, usize, usize)> {
    let kdbx4 = bytes[10] == 4;
    let mut pos = 12;
    let mut out = Vec::new();
    loop {
        let kind = bytes[pos];
        let (len, start) = if kdbx4 {
            let len = u32::from_le_bytes(bytes[pos + 1..pos + 5].try_into().unwrap());
            (len as usize, pos + 5)
        } else {
            let len = u16::from_le_bytes(bytes[pos + 1..pos + 3].try_into().unwrap());
            (usize::from(len), pos + 3)
        };
        out.push((kind, start, len));
        pos = start + len;
        if kind == 0 {
            return out;
        }
    }
}

/// Offset just past the END entry (KDBX4: where the header SHA-256 starts).
fn header_end(bytes: &[u8]) -> usize {
    let (_, start, len) = *header_entries(bytes).last().unwrap();
    start + len
}

/// `(value offset, value length)` of `key` inside the KDBX4 KDF-parameters dictionary.
fn kdf_param(bytes: &[u8], key: &[u8]) -> (usize, usize) {
    let (_, start, len) = header_entries(bytes)
        .into_iter()
        .find(|entry| entry.0 == 11)
        .unwrap();
    let body = &bytes[start..start + len];
    let mut needle = (key.len() as u32).to_le_bytes().to_vec();
    needle.extend_from_slice(key);
    let at = body
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap()
        + needle.len();
    let value_len = u32::from_le_bytes(body[at..at + 4].try_into().unwrap()) as usize;
    (start + at + 4, value_len)
}

/// Overwrite one KDF parameter and recompute the (unauthenticated) header SHA-256, as an
/// attacker would, so keepass-rs would reach the KDF if the pre-walk did not stop it.
fn with_kdf_param(bytes: &[u8], key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let (at, len) = kdf_param(bytes, key);
    assert_eq!(len, value.len());
    out[at..at + len].copy_from_slice(value);
    let end = header_end(&out);
    let digest = Sha256::digest(&out[..end]);
    out[end..end + 32].copy_from_slice(&digest);
    out
}

fn argon2_db() -> Vec<u8> {
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
    encoded(&db, Some(PASSWORD), None)
}

#[test]
fn rejects_oversized_kdf_parameters_before_any_key_derivation() {
    // KDBX4 + Argon2d: `M` (bytes), `I`, `P` in the KDF-parameters dictionary.
    let argon2 = argon2_db();
    // The patch helper hits the live fields: rewriting `M` with its own value still opens.
    let (at, _) = kdf_param(&argon2, b"M");
    let same = argon2[at..at + 8].to_vec();
    assert!(import(&with_kdf_param(&argon2, b"M", &same), PASSWORD).is_ok());
    for (key, value) in [
        (&b"M"[..], ((1u64 << 30) + 1).to_le_bytes().to_vec()),
        (&b"M"[..], (1u64 << 40).to_le_bytes().to_vec()),
        (&b"I"[..], 65u64.to_le_bytes().to_vec()),
        (&b"P"[..], 17u32.to_le_bytes().to_vec()),
    ] {
        let result = import(&with_kdf_param(&argon2, key, &value), PASSWORD);
        assert!(is_limits_error(&result), "{key:?} = {value:?}");
    }
    // At the limit the walk passes and the (changed) parameters fail the key check instead.
    let at_limit = with_kdf_param(&argon2, b"I", &64u64.to_le_bytes());
    assert!(matches!(
        import(&at_limit, PASSWORD),
        Err(ImportError::KdbxCredentials)
    ));

    // KDBX4 + AES-KDF: `R` in the same dictionary (the committed fixture).
    let v4 = include_bytes!("fixtures/keepass-v4.kdbx");
    let (at, _) = kdf_param(v4, b"R");
    let same = v4[at..at + 8].to_vec();
    assert_eq!(
        import(&with_kdf_param(v4, b"R", &same), PASSWORD)
            .unwrap()
            .len(),
        2
    );
    let result = import(
        &with_kdf_param(v4, b"R", &((1u64 << 26) + 1).to_le_bytes()),
        PASSWORD,
    );
    assert!(is_limits_error(&result));

    // KDBX3: `transform_rounds` is outer-header entry 6, a bare u64.
    let v3 = include_bytes!("fixtures/keepass-v3.kdbx");
    let (_, at, len) = header_entries(v3)
        .into_iter()
        .find(|entry| entry.0 == 6)
        .unwrap();
    assert_eq!(len, 8);
    let mut huge = v3.to_vec();
    huge[at..at + 8].copy_from_slice(&((1u64 << 26) + 1).to_le_bytes());
    assert!(is_limits_error(&import(&huge, "demopass")));
    let mut truncated_rounds = v3.to_vec();
    truncated_rounds[at - 2] = 4; // keepass-rs would panic in `read_u64` on a 4-byte entry
    assert!(matches!(
        import(&truncated_rounds, "demopass"),
        Err(ImportError::Malformed(_))
    ));
}

#[test]
fn rejects_unknown_kdf_uuid() {
    let v4 = include_bytes!("fixtures/keepass-v4.kdbx");
    let result = import(&with_kdf_param(v4, b"$UUID", &[0xAB; 16]), PASSWORD);
    assert!(
        matches!(&result, Err(ImportError::Malformed(m)) if m.contains("unsupported")),
        "{:?}",
        result.err()
    );
}

#[test]
fn truncated_and_bit_flipped_headers_never_panic() {
    let v4 = include_bytes!("fixtures/keepass-v4.kdbx");
    let v3 = include_bytes!("fixtures/keepass-v3.kdbx");
    for (bytes, pw) in [(&v4[..], PASSWORD), (&v3[..], "demopass")] {
        // KDBX4 appends a 32-byte SHA-256 and a 32-byte HMAC to the header region.
        let region = header_end(bytes) + if bytes[10] == 4 { 64 } else { 0 };
        for n in 0..region {
            assert!(import(&bytes[..n], pw).is_err(), "prefix of {n} bytes");
        }
        for i in 0..region {
            let mut damaged = bytes.to_vec();
            damaged[i] ^= 1;
            // Any outcome is fine as long as nothing panics or allocates wildly.
            let _ = import(&damaged, pw);
        }
    }
}

#[test]
fn enforces_the_key_file_size_limit() {
    let key = vec![7u8; 1024 * 1024];
    let bytes = encoded(&sample(), Some(PASSWORD), Some(&key));
    assert_eq!(
        import_kdbx(&bytes, &password(PASSWORD), Some(&key), Uuid::nil(), NOW)
            .unwrap()
            .len(),
        2
    );
    let mut over = key.clone();
    over.push(7);
    let error =
        import_kdbx(&bytes, &password(PASSWORD), Some(&over), Uuid::nil(), NOW).unwrap_err();
    assert!(matches!(&error, ImportError::Malformed(m) if m.contains("size limit")));
}

#[test]
fn history_is_deduplicated_by_value_and_against_the_current_password() {
    let mut db = small_db();
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "Dup");
        // KeePass snapshots the entry on every edit, including edits of other fields, so
        // the same password shows up repeatedly.
        for i in 0..12 {
            let pw = format!("p{i}");
            entry.set_protected("Password", pw.as_str());
            for note in ["a", "b"] {
                entry.set_unprotected("Notes", note);
                let snapshot = (*entry).clone();
                entry.history.as_mut().unwrap().add_entry(snapshot);
            }
        }
        entry.set_protected("Password", "p11");
    }
    let items = import(&encoded(&db, Some(PASSWORD), None), PASSWORD).unwrap();
    let values: Vec<&str> = items[0]
        .history
        .iter()
        .map(|h| h.value.expose_secret().as_str())
        .collect();
    assert_eq!(values.len(), 10, "{values:?}");
    let mut unique = values.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), 10, "duplicates survived: {values:?}");
    assert!(
        !values.contains(&"p11"),
        "current password kept: {values:?}"
    );
}

#[test]
fn maps_native_keepass_and_keetraytotp_fields() {
    let mut db = small_db();
    {
        let mut root = db.root_mut();
        let mut native = root.add_entry();
        native.set_unprotected("Title", "Native: a/b");
        native.set_protected("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP");
        native.set_unprotected("TimeOtp-Length", "8");
        native.set_unprotected("TimeOtp-Period", "60");
        native.set_unprotected("TimeOtp-Algorithm", "HMAC-SHA-256");
        let mut tray = root.add_entry();
        tray.set_unprotected("Title", "Tray");
        tray.set_protected("TOTP Seed", "jbsw y3dp ehpk 3pxp");
        tray.set_unprotected("TOTP Settings", "30;6");
        let mut broken = root.add_entry();
        broken.set_unprotected("Title", "Broken");
        broken.set_protected("TimeOtp-Secret-Base32", "!!!");
        broken.set_unprotected("TimeOtp-Period", "60");
    }
    let items = import(&encoded(&db, Some(PASSWORD), None), PASSWORD).unwrap();
    let by_title = |title: &str| items.iter().find(|item| item.title == title).unwrap();
    for (title, period, digits) in [("Native: a/b", 60, 8), ("Tray", 30, 6)] {
        let item = by_title(title);
        let totp = item.fields.iter().find(|f| f.name == "totp").unwrap();
        assert_eq!(totp.kind, FieldKind::Totp);
        assert_eq!(item.fields.len(), 1, "raw TOTP fields were kept on {title}");
        let uri = totp.value.expose_secret();
        assert!(uri.starts_with("otpauth://totp/"), "{title}");
        let parsed = Totp::parse_uri(uri).unwrap();
        assert_eq!(parsed.period(), period);
        assert_eq!(parsed.code(1_700_000_000).len(), digits);
        let label = Totp::parse_uri(uri).unwrap().to_uri();
        assert_eq!(label.expose_secret(), uri, "to_uri round-trips");
    }
    let native = by_title("Native: a/b");
    let secret = Totp::from_secret_base32("JBSWY3DPEHPK3PXP").unwrap();
    assert_ne!(
        Totp::parse_uri(native.fields[0].value.expose_secret())
            .unwrap()
            .code(1_700_000_000),
        secret.code(1_700_000_000),
        "SHA-256 / 8 digits / 60 s must not collapse to the defaults"
    );
    let broken = by_title("Broken");
    assert!(broken.fields.iter().all(|f| f.name != "totp"));
    assert_eq!(broken.fields.len(), 2);
    assert_eq!(
        broken
            .fields
            .iter()
            .find(|f| f.name == "TimeOtp-Secret-Base32")
            .unwrap()
            .kind,
        FieldKind::Password
    );
}

/// HMAC-SHA256 (RFC 2104), built from `sha2` because no HMAC crate is a dependency. This is
/// test-fixture code that forges one KDBX4 HMAC block to craft an attack file; it is not a
/// primitive used by the crate under test.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(ih);
    outer.finalize().into()
}

/// `(value offset, length)` of a KDBX4 outer-header TLV by type.
fn outer_tlv(bytes: &[u8], kind: u8) -> (usize, usize) {
    let (_, start, len) = header_entries(bytes)
        .into_iter()
        .find(|e| e.0 == kind)
        .unwrap();
    (start, len)
}

/// [8] D-8 / finding [9 in the review's numbering]: keepass-rs 0.17.0 reads the KDBX4 inner
/// header `random-stream-id` with a fixed-width `read_u32` that panics when the field is
/// shorter than four bytes. That inner header is inside the encrypted, HMAC-protected payload,
/// so it cannot be pre-validated; the importer wraps `Database::parse` in `catch_unwind` and
/// maps the panic to `ImportError::KdbxMalformed`. Here we craft such a file.
///
/// A valid ChaCha20 + Argon2d + no-compression KDBX4 is saved, then one plaintext byte of the
/// first HMAC block is flipped via the ChaCha20 stream-cipher XOR property (ciphertext byte
/// XOR delta == plaintext byte XOR delta) to turn the inner header's `random-stream-id` length
/// field from 4 into 0, and the block HMAC is recomputed. Authentication therefore still
/// passes and the parse reaches the panicking read. The master key / HMAC key are reproduced
/// with RustCrypto `argon2` (same parameters keepass-rs's `rust-argon2` uses); asserting the
/// result is `KdbxMalformed` (not `KdbxCredentials`) also proves that reproduction is correct.
#[test]
fn crafted_kdbx4_inner_header_panic_is_caught_not_propagated() {
    let mut db = Database::new();
    db.config.outer_cipher_config = OuterCipherConfig::ChaCha20;
    db.config.compression_config = CompressionConfig::None;
    // Keep the default Argon2d config's `version` (keepass's own `argon2::Version`, which this
    // test crate cannot name since `argon2` resolves to RustCrypto here) and only shrink the
    // numeric parameters so the test is fast; version 0x13 is reproduced below.
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
    db.root_mut().add_entry().set_unprotected("Title", "Only");
    let valid = encoded(&db, Some(PASSWORD), None);
    // Sanity: the untampered file imports cleanly.
    assert_eq!(import(&valid, PASSWORD).unwrap().len(), 1);

    // Reproduce the KDBX4 HMAC key: composite = SHA256(SHA256(password)); transformed =
    // Argon2d(composite, salt S); hmac_key = SHA512(master_seed || transformed || 0x01).
    let (ms_off, ms_len) = outer_tlv(&valid, 4); // MASTERSEED
    assert_eq!(ms_len, 32);
    let master_seed = &valid[ms_off..ms_off + 32];
    let read = |key: &[u8]| {
        let (at, len) = kdf_param(&valid, key);
        &valid[at..at + len]
    };
    let salt = read(b"S");
    let memory = u64::from_le_bytes(read(b"M").try_into().unwrap());
    let iterations = u64::from_le_bytes(read(b"I").try_into().unwrap());
    let parallelism = u32::from_le_bytes(read(b"P").try_into().unwrap());

    let composite = Sha256::digest(Sha256::digest(PASSWORD.as_bytes()));
    let params = Params::new(
        (memory / 1024) as u32,
        iterations as u32,
        parallelism,
        Some(32),
    )
    .unwrap();
    let mut transformed = [0u8; 32];
    Argon2::new(Algorithm::Argon2d, Version::V0x13, params)
        .hash_password_into(&composite, salt, &mut transformed)
        .unwrap();
    let mut hmac_in = master_seed.to_vec();
    hmac_in.extend_from_slice(&transformed);
    hmac_in.push(0x01); // hmac_block_stream::HMAC_KEY_END
    let hmac_key = Sha512::digest(&hmac_in);

    // The HMAC block stream begins after the END entry + 32-byte header SHA-256 + 32-byte
    // header HMAC. Block 0 is `hmac(32) | size(u32 LE) | data`.
    let mut out = valid.clone();
    let bs = header_end(&out) + 64;
    let size = u32::from_le_bytes(out[bs + 32..bs + 36].try_into().unwrap()) as usize;
    let data = bs + 36;
    // Flip the inner-header `random-stream-id` length field (plaintext bytes 1..5, value 4)
    // to 0: one XOR on the stream ciphertext. `read_u32` on the now-empty field panics.
    out[data + 1] ^= 0x04;

    // Block 0 key: SHA512(block_index u64 LE || hmac_key). Message: index || size || data.
    let mut block_key_in = 0u64.to_le_bytes().to_vec();
    block_key_in.extend_from_slice(&hmac_key);
    let block_key = Sha512::digest(&block_key_in);
    let mut msg = 0u64.to_le_bytes().to_vec();
    msg.extend_from_slice(&out[bs + 32..bs + 36]);
    msg.extend_from_slice(&out[data..data + size]);
    let mac = hmac_sha256(&block_key, &msg);
    out[bs..bs + 32].copy_from_slice(&mac);

    // The parse panics on the short field; the importer catches it (no panic escapes) and
    // reports `KdbxMalformed` rather than the credential error, proving authentication passed.
    assert!(
        matches!(import(&out, PASSWORD), Err(ImportError::KdbxMalformed)),
        "expected KdbxMalformed, got {:?}",
        import(&out, PASSWORD).err()
    );
}

/// A valid database the importer cannot read must not be reported as a wrong password (bug
/// hunt 2026-11-06, L2; 05 §2.5 keeps the prompt open on `KdbxCredentials`). keepass-rs's XML
/// layer refuses more than 128 nested elements, so a 150-deep group tree authenticates with the
/// right password and then fails in the parser: that is `KdbxMalformed`. The same bytes with a
/// wrong password are still `KdbxCredentials`, and a 100-deep tree imports. Saving and parsing
/// the tree recurse, so the work runs on dedicated threads (8 MiB for the import, as the hunt
/// did: the default test stack overflows in debug builds around depth 200).
#[test]
fn rejected_content_after_a_correct_password_is_malformed_not_credentials() {
    fn nested(depth: usize) -> Vec<u8> {
        std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(move || {
                let mut db = small_db();
                let mut id = db.root_mut().id();
                for _ in 0..depth {
                    let mut group = db.group_mut(id).unwrap();
                    let mut child = group.add_group();
                    child.name = "g".into();
                    id = child.id();
                }
                let mut group = db.group_mut(id).unwrap();
                let mut entry = group.add_entry();
                entry.set_unprotected("Title", "deep");
                entry.set_protected("Password", "deep-secret");
                encoded(&db, Some(PASSWORD), None)
            })
            .unwrap()
            .join()
            .unwrap()
    }
    fn run(bytes: &[u8], pw: &'static str) -> Result<Vec<vault_core::Item>, ImportError> {
        let bytes = bytes.to_vec();
        std::thread::Builder::new()
            .stack_size(8 << 20)
            .spawn(move || import(&bytes, pw))
            .unwrap()
            .join()
            .unwrap()
    }

    let deep = nested(150);
    let right = run(&deep, PASSWORD);
    assert!(
        matches!(right, Err(ImportError::KdbxMalformed)),
        "correct password, parser-rejected content: {:?}",
        right.err()
    );
    let wrong = run(&deep, "not-the-password");
    assert!(
        matches!(wrong, Err(ImportError::KdbxCredentials)),
        "wrong password on the same bytes: {:?}",
        wrong.err()
    );
    assert!(!wrong.unwrap_err().to_string().contains("deep-secret"));

    let shallow = run(&nested(100), PASSWORD).unwrap();
    assert_eq!(shallow.len(), 1);
    assert!(shallow[0].tags.contains(&vec!["g"; 100].join("/")));
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
