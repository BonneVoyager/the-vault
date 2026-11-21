//! 2026-11-21 run: spec sentences that the 2026-11-19 realignment ("spec aligned to code
//! 2026-11-19") now asserts about vault-core and vault-sync, plus spec sentences dated
//! 2026-11-19/20/21 that are drivable from the library. Written from specs/ only.
use secrecy::ExposeSecret;
use spec_checks::dev::*;
use spec_checks::*;
use std::path::Path;
use std::time::{Duration, Instant};
use uuid::Uuid;
use vault_core::*;

fn kind(e: &VaultError) -> String {
    let s = format!("{e:?}");
    s.split('(').next().unwrap_or("").to_string()
}

fn new_vault() -> UnlockedVault {
    UnlockedVault::create(&pw(FIXTURE_PW), KdfParams::for_tests(), Uuid::new_v4())
}

fn login(v: &mut UnlockedVault, title: &str, now: u64) -> Uuid {
    let mut it = Item::new(title.to_string(), v.device_id(), now);
    it.fields
        .push(Field::new("username", FieldKind::Text, pw("u"), now));
    it.fields
        .push(Field::new("password", FieldKind::Password, pw("p0"), now));
    it.fields
        .push(Field::new("extra", FieldKind::Text, pw("x"), now));
    v.insert(it, now)
}

/// 01 §1 (aligned 2026-11-19): "`format_version` 0 (`UnsupportedVersion(0)`; the minimum is 1)".
#[test]
fn ra01_version_zero_is_unsupported_version_0() {
    for b in [new_vault().serialize(), fixture("v1-basic.vault")] {
        let mut m = b.clone();
        m[4..6].copy_from_slice(&0u16.to_be_bytes());
        let r = LockedVault::parse(&m);
        assert!(
            matches!(r, Err(VaultError::UnsupportedVersion(0))),
            "01 §1 version 0: {:?}",
            r.err()
        );
    }
}

/// 01 §1 (aligned 2026-11-19): "an empty body or a manifest that is not the last record
/// (`Malformed`)"; 01 §4 "Exactly one ManifestRecord per file; it is the last record."
#[test]
fn ra02_empty_body_and_manifest_position_malformed() {
    let mut v = new_vault();
    login(&mut v, "a", 1000);
    login(&mut v, "b", 1001);
    let raw = split(&v.serialize());
    assert_eq!(raw.body.len(), 3);
    let (it0, it1, man) = (
        raw.body[0].clone(),
        raw.body[1].clone(),
        raw.body[2].clone(),
    );
    let cases: Vec<(&str, Vec<Value>)> = vec![
        ("empty body", vec![]),
        (
            "manifest first",
            vec![man.clone(), it0.clone(), it1.clone()],
        ),
        (
            "manifest in the middle",
            vec![it0.clone(), man.clone(), it1.clone()],
        ),
        (
            "two manifests",
            vec![it0.clone(), it1.clone(), man.clone(), man.clone()],
        ),
        ("no manifest", vec![it0.clone(), it1.clone()]),
    ];
    let mut bad = vec![];
    for (name, body) in cases {
        let f = join(raw.version, &raw.header, &body);
        match LockedVault::parse(&f) {
            Err(VaultError::Malformed(_)) => {}
            Err(e) => bad.push(format!("{name}: parse -> {e:?} (spec: Malformed)")),
            Ok(l) => bad.push(format!(
                "{name}: parse accepted; unlock -> {:?}",
                l.unlock(&pw(FIXTURE_PW)).err()
            )),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 01 §2 (aligned 2026-11-19): "every parameter must be non-zero, `t_cost <= 16`, `p_cost <= 64`,
/// `m_cost <= 1_048_576` KiB (1 GiB). The parser rejects anything outside as `Malformed` before any
/// Argon2 run". Boundaries on both sides; parse only (in-range m_cost 1 GiB is never derived here).
#[test]
fn ra03_kdf_range_boundaries_at_parse() {
    let mut v = new_vault();
    login(&mut v, "a", 1000);
    let raw = split(&v.serialize());
    let cases: Vec<(&str, u64, bool)> = vec![
        ("t_cost", 16, true),
        ("t_cost", 17, false),
        ("t_cost", 0, false),
        ("p_cost", 64, true),
        ("p_cost", 65, false),
        ("p_cost", 0, false),
        ("m_cost", 1_048_576, true),
        ("m_cost", 1_048_577, false),
        ("m_cost", 0, false),
    ];
    let mut bad = vec![];
    for (k, val, ok) in cases {
        let mut h = raw.header.clone();
        set(get_mut(&mut h, "kdf").unwrap(), k, i(val));
        let f = join(raw.version, &h, &raw.body);
        let t = Instant::now();
        let r = LockedVault::parse(&f);
        let el = t.elapsed();
        match (ok, &r) {
            (true, Ok(_)) => {}
            (false, Err(VaultError::Malformed(_))) if el < Duration::from_millis(200) => {}
            _ => bad.push(format!(
                "{k}={val}: parse -> {:?} in {el:?} (spec: {})",
                r.as_ref().err(),
                if ok { "accepted" } else { "Malformed" }
            )),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 01 §2 (aligned 2026-11-19): "creation enforces the same range". `create` returns `Self`, so an
/// out-of-range request must not yield a vault whose own file the parser then refuses.
/// `change_password` and `SyncedVault::create` return Result and must refuse.
#[test]
fn ra04_creation_enforces_kdf_range() {
    let hostile = KdfParams {
        m_cost_kib: 8192,
        t_cost: 17,
        p_cost: 1,
        salt: [7; 32],
    };
    let mut bad = vec![];
    // UnlockedVault::create: panic (refusal) is acceptable; a silently created unopenable file is not.
    let h2 = hostile.clone();
    let r = std::panic::catch_unwind(move || {
        UnlockedVault::create(&pw(FIXTURE_PW), h2, Uuid::new_v4()).serialize()
    });
    match r {
        Err(_) => eprintln!("create(t_cost=17) panicked (refused)"),
        Ok(bytes) => match LockedVault::parse(&bytes).and_then(|l| l.unlock(&pw(FIXTURE_PW))) {
            Ok(_) => eprintln!(
                "create(t_cost=17) produced an openable vault (t_cost on disk {})",
                u64_of(get(get(&split(&bytes).header, "kdf").unwrap(), "t_cost").unwrap())
            ),
            Err(e) => bad.push(format!(
                "create(t_cost=17) wrote a vault its own parser refuses: {e:?}"
            )),
        },
    }
    // change_password
    let mut v = new_vault();
    let r = v.change_password(&pw(FIXTURE_PW), &pw("new pw 1"), hostile.clone(), 5000);
    if r.is_ok() {
        let b = v.serialize();
        let reopen = LockedVault::parse(&b).and_then(|l| l.unlock(&pw("new pw 1")));
        bad.push(format!(
            "change_password(t_cost=17) accepted; reopen -> {:?}",
            reopen.err()
        ));
    }
    // SyncedVault::create
    let d = tempdir();
    let pkg = d.path().join("k.vault");
    let r = vault_sync::SyncedVault::create(&pkg, &pw(PW), hostile, Uuid::new_v4(), hooks());
    if r.is_ok() {
        let reopen = std::fs::read(pkg.join("vault.bin"))
            .map_err(|e| e.to_string())
            .and_then(|b| LockedVault::parse(&b).map_err(|e| format!("{e:?}")));
        bad.push(format!(
            "SyncedVault::create(t_cost=17) accepted; reparse -> {:?}",
            reopen.err()
        ));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

fn passkey_slot() -> Value {
    canon(map(vec![
        ("id", Value::Bytes(vec![0xA5; 16])),
        ("kind", t("passkey")),
        ("nonce", Value::Bytes(vec![1; 24])),
        ("wrapped_key", Value::Bytes(vec![2; 48])),
        ("created_at", i(1_700_000_000)),
        ("credential_id", Value::Bytes(vec![3; 40])),
        ("prf_salt", Value::Bytes(vec![4; 32])),
        ("rp_id", t("vault.example")),
    ]))
}

/// 01 §2 (aligned 2026-11-19): "a `passkey` slot parses as an opaque slot of kind `Other` (kept
/// verbatim, skipped at unlock)"; 01 §7 `NoUsableSlot` "when there is no password slot at all".
#[test]
fn ra05_passkey_slot_is_opaque_and_kept() {
    let (ver, mut h, key) = empty_base(2);
    if let Some(Value::Array(s)) = get_mut(&mut h, "slots") {
        s.push(passkey_slot());
    }
    let f = build_file(ver, &h, &key, &[]);
    let v = LockedVault::parse(&f)
        .unwrap()
        .unlock(&pw(FIXTURE_PW))
        .expect("passkey slot must be skipped at unlock");
    let out = split(&v.serialize());
    let slots = get(&out.header, "slots")
        .unwrap()
        .as_array()
        .unwrap()
        .clone();
    assert!(
        slots.iter().any(|s| enc(s) == enc(&passkey_slot())),
        "passkey slot not re-emitted verbatim: {slots:?}"
    );
    // only the passkey slot: NoUsableSlot
    let mut h2 = h.clone();
    set(&mut h2, "slots", Value::Array(vec![passkey_slot()]));
    let f2 = build_file(ver, &h2, &key, &[]);
    let r = LockedVault::parse(&f2).and_then(|l| l.unlock(&pw(FIXTURE_PW)));
    assert!(
        matches!(r, Err(VaultError::NoUsableSlot)),
        "passkey-only header: {:?}",
        r.err()
    );
}

/// 01 §7 (aligned 2026-11-19): "`Tampered(Header)` is never produced"; "`TamperKind::ItemCount` is
/// never produced either"; "structural damage (including a short or garbled header) is
/// `Malformed`". Sweep: flip every header byte (password and key paths) and cut at every offset.
#[test]
fn ra06_tamper_header_and_itemcount_never_produced() {
    let mut v = new_vault();
    login(&mut v, "a", 1000);
    login(&mut v, "b", 1001);
    let b = v.serialize();
    let key = v.export_vault_key();
    let raw = split(&b);
    let hend = 10 + raw.header_len as usize;
    let mut seen = std::collections::BTreeMap::<String, usize>::new();
    let mut bad = vec![];
    let mut note = |label: String, r: Result<(), VaultError>, bad: &mut Vec<String>| {
        if let Err(e) = &r {
            *seen.entry(kind(e)).or_default() += 1;
            if matches!(
                e,
                VaultError::Tampered(TamperKind::Header)
                    | VaultError::Tampered(TamperKind::ItemCount)
            ) {
                bad.push(format!("{label}: {e:?}"));
            }
        }
    };
    for off in 0..hend {
        let mut m = b.clone();
        m[off] ^= 0x01;
        let r = LockedVault::parse(&m);
        let r2 = r
            .as_ref()
            .ok()
            .map(|l| l.unlock_with_key(&key, v.device_id()).map(|_| ()));
        note(
            format!("flip@{off} password"),
            r.and_then(|l| l.unlock(&pw(FIXTURE_PW))).map(|_| ()),
            &mut bad,
        );
        if let Some(r2) = r2 {
            note(format!("flip@{off} key"), r2, &mut bad);
        }
    }
    for cut in 0..b.len() {
        let r = LockedVault::parse(&b[..cut]).and_then(|l| l.unlock_with_key(&key, v.device_id()));
        match r {
            Ok(_) => bad.push(format!("cut@{cut} opened")),
            Err(e) => note(format!("cut@{cut}"), Err(e), &mut bad),
        }
    }
    // short header: header_len one less (header CBOR cut) -> Malformed per 01 §7
    let mut m = b.clone();
    m[6..10].copy_from_slice(&(raw.header_len - 1).to_be_bytes());
    let r = LockedVault::parse(&m);
    if !matches!(r, Err(VaultError::Malformed(_))) {
        bad.push(format!("header_len-1: {:?} (spec: Malformed)", r.err()));
    }
    eprintln!("error kinds seen: {seen:?}");
    bad.truncate(20);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 01 §9 (aligned 2026-11-19): extras are kept on each struct "except `HistoryEntry`,
/// `FieldTombstone` and `AttachmentTombstone`, which have no extras and drop unknown keys".
/// So unknown keys survive on the item, a field, the item icon and an `AttachmentRef`.
#[test]
fn ra07_unknown_keys_kept_or_dropped_per_struct() {
    let (ver, h, key) = empty_base(2);
    let item_id = *Uuid::new_v4().as_bytes();
    let fid = *Uuid::new_v4().as_bytes();
    let mut fld = field_v(Some(fid), "password", "password", "pw-now", 5000);
    set(&mut fld, "zz_field", t("keep-field"));
    let mut plain = item_plain("Extras", [9; 16], vec![fld]);
    set(&mut plain, "zz_item", t("keep-item"));
    set(
        &mut plain,
        "icon",
        map(vec![
            ("kind", t("symbol")),
            ("value", t("KeyRound")),
            ("zz_icon", t("keep-icon")),
        ]),
    );
    set(
        &mut plain,
        "history",
        Value::Array(vec![map(vec![
            ("value", t("pw-old")),
            ("replaced_at", i(4000)),
            ("field_id", Value::Bytes(fid.to_vec())),
            ("zz_hist", t("drop-hist")),
        ])]),
    );
    set(
        &mut plain,
        "removed_fields",
        Value::Array(vec![map(vec![
            ("id", Value::Bytes(vec![0xF1; 16])),
            ("removed_at", i(4500)),
            ("zz_rf", t("drop-rf")),
        ])]),
    );
    set(
        &mut plain,
        "removed_attachments",
        Value::Array(vec![map(vec![
            ("id", Value::Bytes(vec![0xF2; 16])),
            ("removed_at", i(4600)),
            ("zz_ra", t("drop-ra")),
        ])]),
    );
    set(
        &mut plain,
        "attachments",
        Value::Array(vec![map(vec![
            ("id", Value::Bytes(vec![0xF3; 16])),
            ("name", t("a.txt")),
            ("size", i(0)),
            ("key", Value::Bytes(vec![5; 32])),
            (
                "chunk_nonces",
                Value::Array(vec![Value::Bytes(vec![6; 24])]),
            ),
            ("added_at", i(4700)),
            ("zz_ref", t("keep-ref")),
        ])]),
    );
    let f = build_file(ver, &h, &key, &[(item_id, 5000, plain)]);
    let mut v = LockedVault::parse(&f)
        .unwrap()
        .unlock(&pw(FIXTURE_PW))
        .unwrap();
    let iid = Uuid::from_bytes(item_id);
    let mut report = vec![];
    for round in ["plain re-serialise", "after update(title)"] {
        if round.starts_with("after") {
            v.update(iid, 9000, |it| it.title = "Extras 2".into())
                .unwrap();
        }
        let o = indep::open_file(&v.serialize(), FIXTURE_PW);
        let (_, _, p) = o
            .items
            .iter()
            .find(|(id, _, _)| id.as_slice() == item_id)
            .unwrap();
        let text = format!("{p:?}");
        for (k, should_keep) in [
            ("keep-item", true),
            ("keep-field", true),
            ("keep-icon", true),
            ("keep-ref", true),
            ("drop-hist", false),
            ("drop-rf", false),
            ("drop-ra", false),
        ] {
            if text.contains(k) != should_keep {
                report.push(format!(
                    "{round}: {k} {}",
                    if should_keep {
                        "was dropped"
                    } else {
                        "was kept"
                    }
                ));
            }
        }
    }
    assert!(report.is_empty(), "{}", report.join("\n"));
}

/// 02 `unlock` (aligned 2026-11-19): "Argon2 runs once per unlock: the KEK is derived once and
/// tried against every `password` slot, so extra slots cost only an AEAD unwrap each."
#[test]
fn ra08_argon2_once_per_unlock_many_password_slots() {
    use rand::RngCore;
    let (ver, base_h, key) = empty_base(2);
    let vault_id = bytes_of(get(&base_h, "vault_id").unwrap());
    let (m, tc, p) = (8192u32, 6u32, 1u32);
    let salt = bytes_of(get(get(&base_h, "kdf").unwrap(), "salt").unwrap());
    let kek = indep::kek_password(FIXTURE_PW, &salt, m, tc, p);
    let mk_slot = |kek: &[u8]| {
        let mut sid = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut sid);
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let wrapped = indep::seal(
            kek,
            &nonce,
            &key,
            &indep::slot_aad(ver, &vault_id, &sid, "password"),
        );
        canon(map(vec![
            ("id", Value::Bytes(sid.to_vec())),
            ("kind", t("password")),
            ("nonce", Value::Bytes(nonce.to_vec())),
            ("wrapped_key", Value::Bytes(wrapped)),
            ("created_at", i(1_700_000_000)),
        ]))
    };
    let make = |n_wrong: usize| {
        let mut h = base_h.clone();
        let kdf = get_mut(&mut h, "kdf").unwrap();
        set(kdf, "m_cost", i(m as u64));
        set(kdf, "t_cost", i(tc as u64));
        set(kdf, "p_cost", i(p as u64));
        let mut slots = vec![];
        for _ in 0..n_wrong {
            let mut other = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut other);
            slots.push(mk_slot(&other));
        }
        slots.push(mk_slot(&kek)); // the right one last
        set(&mut h, "slots", Value::Array(slots));
        build_file(ver, &h, &key, &[])
    };
    let time = |f: &[u8], pass: &str| {
        let l = LockedVault::parse(f).unwrap();
        let mut best = Duration::MAX;
        for _ in 0..3 {
            let t = Instant::now();
            let _ = l.unlock(&pw(pass));
            best = best.min(t.elapsed());
        }
        best
    };
    let one = make(0);
    let many = make(7);
    assert!(
        LockedVault::parse(&many)
            .unwrap()
            .unlock(&pw(FIXTURE_PW))
            .is_ok(),
        "8 password slots, right one last: must unlock"
    );
    let t1 = time(&one, FIXTURE_PW);
    let t8 = time(&many, FIXTURE_PW);
    let w8 = time(&many, "wrong password");
    eprintln!("1 slot {t1:?}; 8 slots {t8:?}; 8 slots wrong pw {w8:?}");
    assert!(
        t8 < t1 * 2 && w8 < t1 * 2,
        "8 slots cost {t8:?} / wrong {w8:?} vs 1 slot {t1:?}: Argon2 runs per slot"
    );
}

/// 02 write (aligned 2026-11-19): every mutation stamps `max(now, previous + 1)`; "`recover` and a
/// strip use the same stamp floored past `deleted_at` as well as `modified_at`".
#[test]
fn ra09_mutations_stamp_past_previous_and_deleted_at() {
    let mut v = new_vault();
    let id = login(&mut v, "a", 10_000);
    let mut bad = vec![];
    let mut check = |label: &str, v: &UnlockedVault, before: u64| {
        let it = v.items_including_deleted().find(|x| x.id == id).unwrap();
        if it.modified_at != before + 1 || it.device_id != v.device_id() {
            bad.push(format!(
                "{label}: modified_at {} (want {}), device ok {}",
                it.modified_at,
                before + 1,
                it.device_id == v.device_id()
            ));
        }
        it.modified_at
    };
    let mut prev = v.get(id).unwrap().modified_at;
    v.update(id, 5, |it| it.title = "b".into()).unwrap();
    prev = check("update", &v, prev);
    let fid = v.get(id).unwrap().field("username").unwrap().id;
    v.set_field(id, fid, pw("u2"), 5).unwrap();
    prev = check("set_field(text)", &v, prev);
    v.set_field_named(id, "USERNAME", pw("u3"), 5).unwrap();
    prev = check("set_field_named", &v, prev);
    let xid = v.get(id).unwrap().field("extra").unwrap().id;
    v.remove_field(id, xid, 5).unwrap();
    prev = check("remove_field", &v, prev);
    v.delete(id, 5).unwrap();
    prev = check("delete", &v, prev);
    v.recover(id, 5).unwrap();
    prev = check("recover", &v, prev);
    v.delete(id, 5).unwrap();
    prev = check("delete again", &v, prev);
    v.delete_permanently(id, 5).unwrap();
    let _ = check("delete_permanently", &v, prev);

    // a peer-crafted tombstone with deleted_at ahead of modified_at
    let (ver, h, key) = empty_base(2);
    let iid = *Uuid::new_v4().as_bytes();
    let fid2 = *Uuid::new_v4().as_bytes();
    let mut plain = item_plain(
        "ahead",
        [3; 16],
        vec![field_v(Some(fid2), "n", "text", "v", 40_000)],
    );
    set(&mut plain, "deleted_at", i(50_000));
    let f = build_file(ver, &h, &key, &[(iid, 40_000, plain)]);
    for op in ["recover", "delete_permanently", "expire_deleted"] {
        let mut w = LockedVault::parse(&f)
            .unwrap()
            .unlock(&pw(FIXTURE_PW))
            .unwrap();
        let u = Uuid::from_bytes(iid);
        let r = match op {
            "recover" => w.recover(u, 1).map(|_| 1),
            "delete_permanently" => w.delete_permanently(u, 1).map(|_| 1),
            _ => Ok(w.expire_deleted(60_000, 1)),
        };
        let it = w.items_including_deleted().find(|x| x.id == u).unwrap();
        if r.is_err() || it.modified_at <= 50_000 {
            bad.push(format!(
                "{op} on deleted_at 50000 > modified_at 40000: {r:?}, modified_at {} (want > 50000)",
                it.modified_at
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 02 generator (2026-11-19): "`length` is clamped up to `PasswordSpec::min_length()` (the
/// enabled-class count), and with no class enabled it falls back to lowercase".
#[test]
fn ra10_generator_clamp_and_lowercase_fallback() {
    use vault_core::generator::*;
    let spec = |len, l, u, d, s, x| PasswordSpec {
        length: len,
        lower: l,
        upper: u,
        digits: d,
        symbols: s,
        exclude_ambiguous: x,
    };
    let mut bad = vec![];
    for (sp, want_min) in [
        (spec(0, true, true, true, true, false), 4),
        (spec(2, true, true, true, false, true), 3),
        (spec(1, false, true, false, true, false), 2),
        (spec(0, true, false, false, false, false), 1),
    ] {
        if sp.min_length() != want_min {
            bad.push(format!("min_length {} want {want_min}", sp.min_length()));
        }
        for _ in 0..200 {
            let p = password(&sp);
            let p = p.expose_secret();
            let n = p.chars().count();
            if n != want_min.max(sp.length) {
                bad.push(format!("len {} -> {n} chars (min {want_min})", sp.length));
                break;
            }
            let has = |f: fn(&char) -> bool| p.chars().any(|c| f(&c));
            if (sp.lower && !has(char::is_ascii_lowercase))
                || (sp.upper && !has(char::is_ascii_uppercase))
                || (sp.digits && !has(char::is_ascii_digit))
                || (sp.symbols && !has(|c: &char| c.is_ascii_punctuation()))
            {
                bad.push(format!("missing a class in {:?}-char output", n));
                break;
            }
        }
    }
    // no class enabled: lowercase only
    for x in [false, true] {
        let sp = spec(16, false, false, false, false, x);
        for _ in 0..100 {
            let p = password(&sp);
            let p = p.expose_secret();
            if p.chars().count() != 16 || !p.chars().all(|c| c.is_ascii_lowercase()) {
                bad.push(format!("no class (exclude_ambiguous {x}): {:?}", p.len()));
                break;
            }
        }
    }
    let sp0 = spec(0, false, false, false, false, false);
    let r = std::panic::catch_unwind(|| password(&sp0).expose_secret().chars().count());
    eprintln!(
        "no class, length 0: min_length {} -> {:?} chars",
        sp0.min_length(),
        r
    );
    if r.is_err() {
        bad.push("no class, length 0 panics".into());
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 05 §2.4: "83 symbols with exclude-ambiguous on, 88 off" (pool sizes) and the exact-entropy
/// formula `log2(pool) × length`; passphrase `log2(7776) × words (+ log2(10))` (02 generator).
/// Checked against the generator's observed output alphabet.
#[test]
fn ra11_generated_bits_pool_sizes_match_output() {
    use vault_core::generator::*;
    let mut bad = vec![];
    for (x, want_pool) in [(true, 83usize), (false, 88usize)] {
        let sp = PasswordSpec {
            length: 64,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: x,
        };
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..3000 {
            seen.extend(password(&sp).expose_secret().chars());
        }
        let bits = generated_bits(&sp);
        let want_bits = (want_pool as f64).log2() * 64.0;
        if seen.len() != want_pool || (bits - want_bits).abs() > 1e-6 {
            bad.push(format!(
                "exclude_ambiguous {x}: alphabet {} chars, generated_bits {bits:.3}, spec pool {want_pool} -> {want_bits:.3}",
                seen.len()
            ));
        }
    }
    let pp = |n| PassphraseSpec {
        words: 4,
        separator: '-',
        capitalize: true,
        number: n,
    };
    let w = 7776f64.log2() * 4.0;
    for (n, want) in [(false, w), (true, w + 10f64.log2())] {
        let got = generated_passphrase_bits(&pp(n));
        if (got - want).abs() > 1e-6 {
            bad.push(format!("passphrase number={n}: {got} want {want}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Spec self-consistency, 05 §2.1: buckets "Weak < 36, Fair < 50, Good < 56, Strong ≥ 56" and
/// "a 4-word passphrase is 55.0 bits exact and reads Good in the generator (corrected
/// 2026-11-21, bug hunt L2)". Encodes both sentences; fails again if they diverge.
#[test]
fn ra12_spec_passphrase_bucket_sentence_consistent() {
    use vault_core::generator::*;
    let bits = generated_passphrase_bits(&PassphraseSpec {
        words: 4,
        separator: '-',
        capitalize: true,
        number: true,
    });
    let bucket = |b: f64| {
        if b < 36.0 {
            "Weak"
        } else if b < 50.0 {
            "Fair"
        } else if b < 56.0 {
            "Good"
        } else {
            "Strong"
        }
    };
    assert!((bits - 55.0).abs() < 0.05, "55.0 bits exact: {bits}");
    assert_eq!(
        bucket(bits),
        "Good",
        "05 §2.1 says a 4-word passphrase ({bits:.2} bits) reads Good, but the spec's own buckets put it in {}",
        bucket(bits)
    );
}

/// 02 `strength_bits` and 05 §2.1 claims: 0 for empty, ≤ 64, first 100 characters only; "a
/// 12-character random password, about 39.8 bits under zxcvbn ... about 0.4 % ... score under
/// 36"; default length 20 "reads Strong"; a 4-word passphrase "zxcvbn scores it 64 in a field".
#[test]
fn ra13_strength_bits_claims() {
    use vault_core::generator::*;
    let mut bad = vec![];
    if strength_bits("") != 0.0 {
        bad.push(format!("empty -> {}", strength_bits("")));
    }
    let base = |len| PasswordSpec {
        length: len,
        lower: true,
        upper: true,
        digits: true,
        symbols: true,
        exclude_ambiguous: true,
    };
    let long = password(&base(64)).expose_secret().to_string();
    let s100: String = format!("{long}{long}").chars().take(100).collect();
    let a = strength_bits(&s100);
    let b = strength_bits(&format!(
        "{s100}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ));
    if a != b || a > 64.0 {
        bad.push(format!("first 100 chars only / cap 64: {a} vs {b}"));
    }
    let n = 3000;
    let mut s12: Vec<f64> = (0..n)
        .map(|_| strength_bits(password(&base(12)).expose_secret()))
        .collect();
    s12.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let under36 = s12.iter().filter(|b| **b < 36.0).count() as f64 / n as f64;
    let median = s12[n / 2];
    eprintln!(
        "12 chars: median {median:.2}, under 36: {:.2} %",
        under36 * 100.0
    );
    if !(39.0..=40.5).contains(&median) || under36 > 0.02 {
        bad.push(format!(
            "12 chars: median {median:.2} (spec ~39.8), under 36 {:.2} % (spec ~0.4 %)",
            under36 * 100.0
        ));
    }
    let strong20 = (0..1000)
        .filter(|_| strength_bits(password(&base(20)).expose_secret()) >= 56.0)
        .count();
    if strong20 < 990 {
        bad.push(format!("20 chars Strong in {strong20}/1000"));
    }
    let pp = PassphraseSpec {
        words: 4,
        separator: '-',
        capitalize: true,
        number: true,
    };
    let at64 = (0..500)
        .filter(|_| strength_bits(passphrase(&pp).expose_secret()) >= 64.0)
        .count();
    eprintln!("default passphrase scored 64 in {at64}/500");
    if at64 < 475 {
        bad.push(format!("4-word passphrase scored 64 in only {at64}/500"));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 02 export/import (aligned 2026-11-19): `export_csv` prefixes `'` to cells starting with `=`,
/// `+`, `-`, `@`, tab or CR, "a cell that is already a trigger behind quotes gets one more";
/// `import_csv` "strips exactly one leading `'` when a trigger follows it (behind zero or more
/// further quotes), so an export round-trips".
#[test]
fn ra14_csv_injection_guard_round_trips() {
    use vault_core::import::*;
    let vals = [
        "=1+1", "+x", "-5", "@sum", "\tTab", "\rCR", "'=x", "''@y", "'''+z", "'plain", "'", "''",
        "plain'", "=", "a=b", "' =x",
    ];
    let mut v = new_vault();
    for (n, val) in vals.iter().enumerate() {
        let mut it = Item::new(format!("t{n}"), v.device_id(), 1000);
        it.fields
            .push(Field::new("username", FieldKind::Text, pw(val), 1000));
        it.fields
            .push(Field::new("notes", FieldKind::Notes, pw(val), 1000));
        v.insert(it, 1000);
    }
    let out = export::export_csv(&v);
    let text = String::from_utf8_lossy(&out.0).to_string();
    let mut bad = vec![];
    // exported cells: every trigger cell (incl. behind quotes) is guarded
    for need in ["'=1+1", "'+x", "'-5", "'@sum", "''=x", "'''@y", "''''+z"] {
        if !text.contains(need) {
            bad.push(format!("export lacks guarded cell {need:?}"));
        }
    }
    let items = import_csv(&out.0, &CsvMapping::default(), Uuid::new_v4(), 2000).unwrap();
    for (n, val) in vals.iter().enumerate() {
        let Some(it) = items.iter().find(|x| x.title == format!("t{n}")) else {
            bad.push(format!("t{n} missing after import"));
            continue;
        };
        let got = it
            .field("username")
            .map(|f| f.value.expose_secret().to_string());
        if got.as_deref() != Some(*val) {
            bad.push(format!("username {val:?} -> {got:?}"));
        }
    }
    assert!(
        bad.is_empty(),
        "{}\n--- export ---\n{}",
        bad.join("\n"),
        text
    );
}

/// 02 import: "`created_at` is ... else now; CSV always now"; 1PUX "zero, negative or non-numeric
/// → now".
#[test]
fn ra15_import_created_at_rules() {
    use std::io::Write;
    use vault_core::import::*;
    let csv = b"title,url,username,password,notes,totp,tags\nA,https://a.example,u,p,n,,\n";
    let items = import_csv(csv, &CsvMapping::default(), Uuid::new_v4(), 123_456).unwrap();
    assert_eq!(items[0].created_at, Some(123_456), "CSV created_at = now");
    let mut bad = vec![];
    for (ca, want) in [
        ("1600000000", Some(1_600_000_000_000u64)),
        ("0", Some(777_000)),
        ("-5", Some(777_000)),
        ("\"abc\"", Some(777_000)),
    ] {
        let json = format!(
            r#"{{"accounts":[{{"vaults":[{{"items":[{{"uuid":"a1","createdAt":{ca},"updatedAt":1600000001,"state":"active","categoryUuid":"001","details":{{"loginFields":[],"notesPlain":"","sections":[],"passwordHistory":[]}},"overview":{{"title":"T","url":""}}}}]}}]}}]}}"#
        );
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let o: zip::write::SimpleFileOptions = Default::default();
            z.start_file("export.data", o).unwrap();
            z.write_all(json.as_bytes()).unwrap();
            z.start_file("export.attributes", o).unwrap();
            z.write_all(b"{}").unwrap();
            z.finish().unwrap();
        }
        match import_1pux(&buf.into_inner(), Uuid::new_v4(), 777_000) {
            Ok(v) if v.len() == 1 && v[0].created_at == want => {}
            Ok(v) => bad.push(format!(
                "createdAt {ca}: {:?} (want {want:?})",
                v.iter().map(|x| x.created_at).collect::<Vec<_>>()
            )),
            Err(e) => bad.push(format!("createdAt {ca}: error {e:?}")),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

fn make_kdbx(kdf: keepass::config::KdfConfig) -> Vec<u8> {
    let mut db = keepass::Database::new();
    db.config.kdf_config = kdf;
    {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected("Title", "Entry One");
        e.set_protected("Password", "kp-secret-1");
    }
    let mut out = vec![];
    db.save(
        &mut out,
        keepass::DatabaseKey::new().with_password("kdbx pass"),
    )
    .unwrap();
    out
}
fn argon(i: u64, m: u64, p: u32) -> keepass::config::KdfConfig {
    keepass::config::KdfConfig::Argon2 {
        iterations: i,
        memory: m,
        parallelism: p,
        version: argon2_rs::Version::Version13,
    }
}
/// Rewrites one KDF parameter in the KDBX 4 outer header and fixes the header SHA-256.
fn patch_kdf(db: &[u8], key: &str, val: Vec<u8>) -> Vec<u8> {
    use sha2::Digest;
    let mut pos = 12;
    let mut out = db[..12].to_vec();
    loop {
        let id = db[pos];
        let len = u32::from_le_bytes(db[pos + 1..pos + 5].try_into().unwrap()) as usize;
        let mut data = db[pos + 5..pos + 5 + len].to_vec();
        pos += 5 + len;
        if id == 11 {
            let mut nd = data[..2].to_vec();
            let mut q = 2;
            loop {
                let ty = data[q];
                if ty == 0 {
                    nd.push(0);
                    break;
                }
                let kl = u32::from_le_bytes(data[q + 1..q + 5].try_into().unwrap()) as usize;
                let k = String::from_utf8(data[q + 5..q + 5 + kl].to_vec()).unwrap();
                let vl =
                    u32::from_le_bytes(data[q + 5 + kl..q + 9 + kl].try_into().unwrap()) as usize;
                let mut v = data[q + 9 + kl..q + 9 + kl + vl].to_vec();
                q += 9 + kl + vl;
                if k == key {
                    v = val.clone();
                }
                nd.push(ty);
                nd.extend_from_slice(&(kl as u32).to_le_bytes());
                nd.extend_from_slice(k.as_bytes());
                nd.extend_from_slice(&(v.len() as u32).to_le_bytes());
                nd.extend_from_slice(&v);
            }
            data = nd;
        }
        out.push(id);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&data);
        if id == 0 {
            break;
        }
    }
    let hash = sha2::Sha256::digest(&out);
    out.extend_from_slice(&hash);
    out.extend_from_slice(&db[pos + 32..]);
    out
}

/// 02 KeePass (aligned 2026-11-19): "`check_outer_header` also bounds the KDBX KDF before any key
/// derivation: AES-KDF rounds at most 2^26, Argon2 memory at most 1 GiB, iterations at most 64,
/// parallelism at most 16; anything above is rejected." Exact boundaries, in a child process.
#[test]
fn ra16_kdbx_kdf_bounds_exact() {
    let d = tempdir();
    let run = |name: &str, bytes: &[u8], pass: &str| {
        let p = d.path().join(format!("{name}.kdbx"));
        std::fs::write(&p, bytes).unwrap();
        let t = Instant::now();
        let (out, st) = run_child("open_kdbx", &[p.to_str().unwrap(), pass], 120, 1500);
        (out, st, t.elapsed())
    };
    let base = make_kdbx(argon(1, 1 << 20, 1));
    let (wrong, _, _) = run("wrongpw", &base, "not it");
    let mut bad = vec![];
    // accepted side, built with the parameters at the limit
    for (name, kdf) in [
        ("argon I=64", argon(64, 1 << 20, 1)),
        ("argon P=16", argon(1, 1 << 20, 16)),
    ] {
        let (out, st, el) = run(name, &make_kdbx(kdf), "kdbx pass");
        eprintln!("{name}: {st} {out} {el:?}");
        if out != "OK 1" {
            bad.push(format!("{name} (at the limit) refused: {st} {out}"));
        }
    }
    // rejected side: patched header, must refuse fast with a non-credentials error
    let aes = make_kdbx(keepass::config::KdfConfig::Aes { rounds: 10 });
    for (name, src, key, val) in [
        ("argon I=65", &base, "I", 65u64.to_le_bytes().to_vec()),
        ("argon P=17", &base, "P", 17u32.to_le_bytes().to_vec()),
        (
            "argon M=1GiB+1KiB",
            &base,
            "M",
            ((1u64 << 30) + 1024).to_le_bytes().to_vec(),
        ),
        (
            "aes R=2^26+1",
            &aes,
            "R",
            ((1u64 << 26) + 1).to_le_bytes().to_vec(),
        ),
    ] {
        let (out, st, el) = run(name, &patch_kdf(src, key, val), "kdbx pass");
        eprintln!("{name}: {st} {out} {el:?}");
        if !out.starts_with("ERR") || out == wrong || el > Duration::from_secs(3) {
            bad.push(format!(
                "{name}: {st} {out:?} in {el:?} (wrong-password text {wrong:?})"
            ));
        }
    }
    // AES rounds exactly 2^26: must run (credentials then fail since the KEK changed)
    let (out, st, el) = run(
        "aes R=2^26",
        &patch_kdf(&aes, "R", (1u64 << 26).to_le_bytes().to_vec()),
        "kdbx pass",
    );
    eprintln!("aes R=2^26: {st} {out} {el:?}");
    if out != wrong {
        bad.push(format!(
            "aes R=2^26 (at the limit) did not reach the key check: {out:?} (wrong-password text {wrong:?})"
        ));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 02 `unlock_with_key`: "first tag failure → WrongPassword" (a key that is not this vault's);
/// guarantee 4 still holds on the key path: a flipped item ct is `Tampered(Item(id))`.
#[test]
fn ra17_unlock_with_key_error_mapping() {
    let mut v = new_vault();
    for n in 0..3 {
        login(&mut v, &format!("k{n}"), 1000 + n);
    }
    let b = v.serialize();
    let other = new_vault();
    let l = LockedVault::parse(&b).unwrap();
    let r = l.unlock_with_key(&other.export_vault_key(), v.device_id());
    assert!(
        matches!(r, Err(VaultError::WrongPassword)),
        "foreign key: {:?}",
        r.err()
    );
    let raw = split(&b);
    let mut bad = vec![];
    for rec in 0..raw.body.len() - 1 {
        let id = Uuid::from_slice(&bytes_of(get(&raw.body[rec], "id").unwrap())).unwrap();
        let mut body = raw.body.clone();
        let mut ct = bytes_of(get(&body[rec], "ct").unwrap());
        ct[3] ^= 0x10;
        set(&mut body[rec], "ct", Value::Bytes(ct));
        let m = join(raw.version, &raw.header, &body);
        let l = LockedVault::parse(&m).unwrap();
        let rk = l.unlock_with_key(&v.export_vault_key(), v.device_id());
        let rp = l.unlock(&pw(FIXTURE_PW));
        let ok_k = matches!(&rk, Err(VaultError::Tampered(TamperKind::Item(x))) if *x == id);
        let ok_p = matches!(&rp, Err(VaultError::Tampered(TamperKind::Item(x))) if *x == id);
        eprintln!(
            "record {rec}: key path {:?}; password path {:?}",
            rk.as_ref().err(),
            rp.as_ref().err()
        );
        if !ok_k || !ok_p {
            bad.push(format!(
                "record {rec} of {} flipped: key path {:?}, password path {:?} (02 guarantee 4: Tampered(Item(id)))",
                raw.body.len() - 1,
                rk.err(),
                rp.err()
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §2 (aligned 2026-11-19): "`open` takes a shared lock around its read of `vault.bin`", so an
/// `open` while another process holds the exclusive save lock waits for it.
#[test]
fn ra18_open_waits_for_exclusive_save_lock() {
    use std::io::{BufRead, BufReader};
    let d = tempdir();
    let pkg = d.path().join("l.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    drop(a);
    let mut perl = std::process::Command::new("perl")
        .args([
            "-e",
            r#"use Fcntl ":flock"; open(my $f, ">>", $ARGV[0]) or die; flock($f, LOCK_EX) or die; $|=1; print "L\n"; sleep 2;"#,
            pkg.join(".lock").to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(perl.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "L");
    let t = Instant::now();
    let r = vault_sync::SyncedVault::open(&pkg, Uuid::new_v4(), hooks());
    let el = t.elapsed();
    let _ = perl.wait();
    assert!(r.is_ok(), "open after the lock is released: {:?}", r.err());
    assert!(
        el >= Duration::from_millis(1500),
        "open returned after {el:?} while an exclusive save lock was held for 2 s"
    );
}

fn foreign_pkg(dir: &Path, name: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    let mut o = Dev::create(&p);
    o.add_login("foreign", now_ms());
    o.s.save().unwrap();
    p
}

/// 03 §6 step 1 (aligned 2026-11-19): "if vault_id != ours → emit SyncEvent::ForeignVault once per
/// sibling and ignore". Two foreign sibling packages, each rewritten three times.
#[test]
fn ra19_foreign_vault_event_once_per_sibling() {
    let d = tempdir();
    let pkg = d.path().join("f.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("base", now_ms());
    a.s.save().unwrap();
    let other = tempdir();
    let src = foreign_pkg(other.path(), "f.vault");
    a.s.start_watching().unwrap();
    std::thread::sleep(Duration::from_millis(700));
    let s2 = d.path().join("f 2.vault");
    let s3 = d.path().join("f 3.vault");
    copy_dir(&src, &s2);
    copy_dir(&src, &s3);
    a.wait_for(3, |_| false);
    for _ in 0..3 {
        for s in [&s2, &s3] {
            let b = std::fs::read(s.join("vault.bin")).unwrap();
            std::fs::write(s.join("vault.bin"), &b).unwrap();
        }
        a.wait_for(2, |_| false);
    }
    let n = a
        .seen
        .iter()
        .filter(|e| e.starts_with("ForeignVault"))
        .count();
    assert!(s2.join("vault.bin").exists() && s3.join("vault.bin").exists());
    assert_eq!(
        n, 2,
        "ForeignVault events {n} for 2 siblings; all: {:?}",
        a.seen
    );
}

fn civil(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let dd = doy - (153 * mp + 2) / 5 + 1;
    let mm = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mm <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{mm:02}-{dd:02}T{:02}-{:02}-{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// 03 §6 step 4 (aligned 2026-11-19): per-file copies move to
/// `backups/conflict-<timestamp>-<original name without .bin>.vault.bin` (`vault 2.bin` →
/// `conflict-…-vault 2.vault.bin`; "a same-second clash inserts `-N-` after the timestamp"); "Never
/// delete a conflict copy". 03 §1: every file in backups/ is independently openable.
#[test]
fn ra20_per_file_conflict_names_and_same_second_clash() {
    let d = tempdir();
    let pkg = d.path().join("c.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("base", now_ms());
    a.s.save().unwrap();
    let stage = tempdir();
    let copy = stage.path().join("stage.vault");
    copy_dir(&pkg, &copy);
    {
        let mut c = Dev::open(&copy);
        c.add_login("from-copy", now_ms());
        c.s.save().unwrap();
    }
    let cbytes = std::fs::read(copy.join("vault.bin")).unwrap();
    a.s.start_watching().unwrap();
    std::thread::sleep(Duration::from_millis(700));
    std::fs::write(pkg.join("vault 2.bin"), &cbytes).unwrap();
    assert!(a.wait_for(10, |e| e.iter().any(|x| x.starts_with("ConflictAbsorbed"))));
    let first: Vec<String> = ls(&pkg.join("backups"))
        .into_iter()
        .filter(|n| n.starts_with("conflict-"))
        .collect();
    assert_eq!(first.len(), 1, "{first:?}");
    let ts = first[0]
        .strip_prefix("conflict-")
        .and_then(|r| r.strip_suffix("-vault 2.vault.bin"))
        .unwrap_or_else(|| panic!("03 §6 naming `conflict-<ts>-vault 2.vault.bin`: {first:?}"))
        .to_string();
    // the spec timestamp shape (03 §4) is UTC ISO 8601 with '-' for ':'
    let now_s = now_ms() / 1000;
    let shape_ok = ts.len() == civil(now_s).len() && ts.ends_with('Z') && ts.contains('T');
    eprintln!("conflict timestamp {ts:?} (shape ok: {shape_ok})");
    // pre-seed the next 20 seconds' names so the next absorption must clash
    let seed = std::fs::read(pkg.join("vault.bin")).unwrap();
    let mut seeded = vec![];
    for s in now_s..now_s + 20 {
        let n = format!("conflict-{}-vault 2.vault.bin", civil(s));
        let p = pkg.join("backups").join(&n);
        if !p.exists() {
            std::fs::write(&p, &seed).unwrap();
            seeded.push(p);
        }
    }
    let before = a
        .seen
        .iter()
        .filter(|x| x.starts_with("ConflictAbsorbed"))
        .count();
    std::fs::write(pkg.join("vault 2.bin"), &cbytes).unwrap();
    let got = a.wait_for(10, move |e| {
        e.iter()
            .filter(|x| x.starts_with("ConflictAbsorbed"))
            .count()
            > before
    });
    let names: Vec<String> = ls(&pkg.join("backups"))
        .into_iter()
        .filter(|n| n.starts_with("conflict-"))
        .collect();
    let mut bad = vec![];
    if !got {
        bad.push(format!("clash: not absorbed; events {:?}", a.seen));
    }
    for p in &seeded {
        if std::fs::read(p).ok().as_deref() != Some(&seed[..]) {
            bad.push(format!("seeded clash target overwritten: {}", p.display()));
        }
    }
    let clash: Vec<&String> = names
        .iter()
        .filter(|n| {
            n.ends_with("-vault 2.vault.bin")
                && n.strip_prefix("conflict-")
                    .map(|r| {
                        let parts: Vec<&str> = r.splitn(2, "Z-").collect();
                        parts.len() == 2
                            && parts[1]
                                .split('-')
                                .next()
                                .map(|x| x.chars().all(|c| c.is_ascii_digit()) && !x.is_empty())
                                .unwrap_or(false)
                    })
                    .unwrap_or(false)
        })
        .collect();
    if got && clash.is_empty() {
        bad.push(format!(
            "no `conflict-<ts>-N-vault 2.vault.bin` among {names:?}"
        ));
    }
    if pkg.join("vault 2.bin").exists() && got {
        bad.push("absorbed copy still in the package".into());
    }
    // 03 §1: every file in backups/ opens; conflict packages are directories with vault.bin
    for n in ls(&pkg.join("backups")) {
        let p = pkg.join("backups").join(&n);
        let f = if p.is_dir() {
            p.join("vault.bin")
        } else {
            p.clone()
        };
        let r = std::fs::read(&f).map_err(|e| e.to_string()).and_then(|b| {
            LockedVault::parse(&b)
                .and_then(|l| l.unlock(&pw(PW)))
                .map_err(|e| format!("{e:?}"))
        });
        if let Err(e) = r {
            bad.push(format!("backups/{n} does not open: {e}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 01 §9 fixture list (aligned 2026-11-19) and 01 §4 "Fixture: `v1-stamped.vault` (header with
/// stamp, device id and digest-bound manifest)": every named fixture exists, opens with the
/// fixture password, and v1-stamped carries the stamp. Prints which fixtures are stamped, for the
/// "all committed fixtures" sentence in 01 §4.
#[test]
fn ra21_named_fixtures_present_and_stamps() {
    let names = [
        "v1-basic.vault",
        "v1-empty.vault",
        "v1-attach.vault",
        "v1-stamped.vault",
        "v1-forward.vault",
        "v1-icon.vault",
        "v1-meta.vault",
        "v2-basic.vault",
        "v2-field-icon.vault",
        "v2-meta.vault",
        "v2-trash-legacy.vault",
    ];
    let mut stamped = vec![];
    for n in names {
        let b = fixture(n);
        let raw = split(&b);
        if get(&raw.header, "slots_modified_at").is_some() {
            stamped.push(n);
        }
        LockedVault::parse(&b)
            .and_then(|l| l.unlock(&pw(FIXTURE_PW)))
            .unwrap_or_else(|e| panic!("{n}: {e:?}"));
    }
    eprintln!("stamped fixtures: {stamped:?}");
    assert!(stamped.contains(&"v1-stamped.vault"));
}

/// Impact of ra17 on vault-sync (03 §3 step 6a uses `unlock_with_key`; 03 §8 `KeyMismatch` means
/// "password changed elsewhere"). A file whose FIRST item ciphertext was altered on disk: records
/// the event, and checks nothing from it is merged and in-memory items stay intact.
#[test]
fn ra22_sync_first_item_tamper_event() {
    let d = tempdir();
    let pkg = d.path().join("t.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("one", now_ms());
    a.add_login("two", now_ms());
    a.s.save().unwrap();
    let before = snap_vault(a.v());
    a.s.start_watching().unwrap();
    std::thread::sleep(Duration::from_millis(700));
    let b = std::fs::read(primary(&pkg)).unwrap();
    let raw = split(&b);
    let mut events = vec![];
    for rec in [0usize, 1] {
        let mut body = raw.body.clone();
        let mut ct = bytes_of(get(&body[rec], "ct").unwrap());
        ct[5] ^= 0x01;
        set(&mut body[rec], "ct", Value::Bytes(ct));
        let tmp = pkg.join(format!("staged-{rec}"));
        std::fs::write(&tmp, join(raw.version, &raw.header, &body)).unwrap();
        std::fs::rename(&tmp, primary(&pkg)).unwrap();
        let n0 = a.seen.len();
        a.wait_for(3, |_| false);
        events.push(format!("record {rec}: {:?}", &a.seen[n0..]));
        assert_eq!(snap_vault(a.v()), before, "in-memory items changed");
    }
    eprintln!("{}", events.join("\n"));
    let rec0_keymismatch = events[0].contains("KeyMismatch");
    let rec1_keymismatch = events[1].contains("KeyMismatch");
    assert!(
        !rec0_keymismatch && !rec1_keymismatch,
        "a tampered item is reported as a password change elsewhere:\n{}",
        events.join("\n")
    );
}

/// 05 §2.2 (2026-11-19) shows the newer-version card for `UnsupportedVersion` *on open*. When a
/// peer writes a newer-version file while this handle is locked (with or without a pending
/// `ChangedWhileLocked`), record what each unlock path does, and check 03 §3: the save after it
/// is refused (`SaveBlocked{NewerVersion}`) and the newer file is never overwritten.
#[test]
fn ra23_newer_version_written_while_locked() {
    use secrecy::SecretVec;
    let mut out = vec![];
    let mut bad = vec![];
    for (path, peer_first) in [
        ("kek", false),
        ("password", false),
        ("kek", true),
        ("password", true),
    ] {
        let d = tempdir();
        let pkg = d.path().join("n.vault");
        let mut a = Dev::create(&pkg);
        a.add_login("x", now_ms());
        let k2 = SecretVec::new(vec![0x5A; 32]);
        let slot =
            a.s.edit(move |v| v.add_enclave_slot(&k2, now_ms()))
                .unwrap();
        a.s.save().unwrap();
        a.s.start_watching().unwrap();
        std::thread::sleep(Duration::from_millis(700));
        let _ = a.s.lock();
        if peer_first {
            let mut peer = Dev::open(&pkg);
            peer.add_login("peer", now_ms());
            peer.s.save().unwrap();
            a.wait_for(5, |e| e.iter().any(|x| x.starts_with("ChangedWhileLocked")));
        }
        let mut b = std::fs::read(primary(&pkg)).unwrap();
        b[4..6].copy_from_slice(&3u16.to_be_bytes());
        let tmp = pkg.join("staged");
        std::fs::write(&tmp, &b).unwrap();
        std::fs::rename(&tmp, primary(&pkg)).unwrap();
        a.wait_for(3, |_| false);
        let r = if path == "kek" {
            a.s.unlock_with_kek(slot, &SecretVec::new(vec![0x5A; 32]))
        } else {
            a.s.unlock(&pw(PW))
        };
        let mut save = None;
        if r.is_ok() {
            a.add_login("after", now_ms());
            save = Some(format!("{:?}", a.s.save().err()));
            a.wait_for(2, |_| false);
        }
        let same = std::fs::read(primary(&pkg)).unwrap() == b;
        let line = format!(
            "{path} (peer edit first: {peer_first}): unlock {:?}; save {:?}; newer file intact {same}; events {:?}",
            r.as_ref().err(),
            save,
            a.seen
                .iter()
                .filter(|e| !e.starts_with("BackupTaken"))
                .collect::<Vec<_>>()
        );
        if !same || save.as_deref().is_some_and(|s| s == "None") {
            bad.push(line.clone());
        }
        out.push(line);
    }
    eprintln!("{}", out.join("\n"));
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
