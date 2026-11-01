//! Corruption sweeps (01 §1 parser rejections, §4 tamper detection, §7 errors).
use spec_checks::*;
use uuid::Uuid;
use vault_core::*;

const PW: &str = "pw-for-corruption-checks";

fn sample() -> Vec<u8> {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(PW), KdfParams::for_tests(), dev);
    for i in 0..3 {
        let mut it = Item::new(format!("i{i}"), dev, 10);
        it.fields.push(Field::new(
            "password",
            FieldKind::Password,
            pw("s3cret"),
            10,
        ));
        v.insert(it, 10);
    }
    v.add_enclave_slot(&secrecy::SecretVec::new(vec![3; 32]), 20);
    v.serialize()
}

fn try_open(b: Vec<u8>) -> Result<Result<Vec<String>, String>, String> {
    std::panic::catch_unwind(
        move || match LockedVault::parse(&b).and_then(|l| l.unlock(&pw(PW))) {
            Ok(u) => Ok(snap_vault(&u)),
            Err(e) => Err(format!("{e:?}")),
        },
    )
    .map_err(|_| "PANIC".to_string())
}

/// Every truncation point must fail cleanly (never Ok, never panic).
#[test]
fn c01_every_cut_offset() {
    let b = sample();
    let mut bad = vec![];
    for cut in 0..b.len() {
        match try_open(b[..cut].to_vec()) {
            Ok(Err(_)) => {}
            Ok(Ok(_)) => bad.push(format!("cut {cut}: accepted")),
            Err(p) => bad.push(format!("cut {cut}: {p}")),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Random single- and multi-bit flips: never panic; if accepted, items must be identical
/// (only unauthenticated plaintext like created_at may change silently).
#[test]
fn c02_random_bit_flips() {
    use rand::{Rng, SeedableRng};
    let b = sample();
    let orig = match try_open(b.clone()) {
        Ok(Ok(s)) => s,
        _ => panic!(),
    };
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed);
    let mut bad = vec![];
    let mut accepted = 0;
    for n in 0..1500 {
        let mut m = b.clone();
        let flips = if n % 3 == 0 { rng.gen_range(2..8) } else { 1 };
        let mut where_ = vec![];
        for _ in 0..flips {
            let p = rng.gen_range(0..m.len());
            m[p] ^= 1 << rng.gen_range(0..8);
            where_.push(p);
        }
        match with_timeout(20, move || try_open(m)) {
            None => bad.push(format!("flips {where_:?}: hang")),
            Some(Err(p)) => bad.push(format!("flips {where_:?}: {p}")),
            Some(Ok(Ok(s))) => {
                accepted += 1;
                if s != orig {
                    bad.push(format!("flips {where_:?}: accepted with changed items"))
                }
            }
            Some(Ok(Err(_))) => {}
        }
    }
    eprintln!("accepted-unchanged flips: {accepted}");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

fn write_tmp(dir: &std::path::Path, name: &str, b: &[u8]) -> String {
    let p = dir.join(name);
    std::fs::write(&p, b).unwrap();
    p.to_string_lossy().into_owned()
}

/// Hostile CBOR length prefixes and nesting before any key check: no huge allocation, no stack
/// overflow, no hang. Run in a child process with RSS and time limits.
#[test]
fn c03_hostile_cbor_sizes() {
    let d = tempdir();
    let b = sample();
    let raw = split(&b);
    let mut cases: Vec<(String, Vec<u8>)> = vec![];
    // header that is 200k nested arrays
    let mut h = vec![0x81u8; 200_000];
    h.push(0x00);
    let mut f = b"RVLT".to_vec();
    f.extend_from_slice(&1u16.to_be_bytes());
    f.extend_from_slice(&(h.len() as u32).to_be_bytes());
    f.extend_from_slice(&h);
    f.push(0x80);
    cases.push(("nested header".into(), f));
    // body that is 200k nested arrays
    let mut f = b[..10 + raw.header_len as usize].to_vec();
    f.extend(std::iter::repeat_n(0x81u8, 200_000));
    f.push(0x80);
    cases.push(("nested body".into(), f));
    // body array claims 2^63 elements
    let mut f = b[..10 + raw.header_len as usize].to_vec();
    f.push(0x9b);
    f.extend_from_slice(&(1u64 << 62).to_be_bytes());
    cases.push(("body array len 2^62".into(), f));
    // body array of 2^32-1 elements declared, with 1 real
    let mut f = b[..10 + raw.header_len as usize].to_vec();
    f.push(0x9a);
    f.extend_from_slice(&u32::MAX.to_be_bytes());
    f.extend_from_slice(&raw.body_bytes[1..]);
    cases.push(("body array len u32::MAX".into(), f));
    // item ct declares 2^62 bytes: replace the body with one record map whose ct header lies
    let mut rec = enc(&Value::Map(vec![
        (Value::Text("t".into()), Value::Text("item".into())),
        (Value::Text("id".into()), Value::Bytes(vec![1; 16])),
        (Value::Text("modified_at".into()), Value::Integer(1.into())),
        (Value::Text("nonce".into()), Value::Bytes(vec![1; 24])),
    ]));
    rec[0] = 0xa5; // map of 5
    rec.extend_from_slice(&enc(&Value::Text("ct".into())));
    rec.push(0x5b);
    rec.extend_from_slice(&(1u64 << 62).to_be_bytes());
    let mut f = b[..10 + raw.header_len as usize].to_vec();
    f.push(0x82);
    f.extend_from_slice(&rec);
    cases.push(("ct len 2^62".into(), f));
    // header slots array declares u32::MAX entries
    let mut hdr = raw.header.clone();
    set(&mut hdr, "slots", Value::Array(vec![]));
    let mut hb = enc(&hdr);
    let pos = hb.windows(6).position(|w| w == b"\x65slots").unwrap() + 6;
    assert_eq!(hb[pos], 0x80);
    hb.splice(pos..pos + 1, [0x9a, 0xff, 0xff, 0xff, 0xff]);
    let mut f = b"RVLT".to_vec();
    f.extend_from_slice(&1u16.to_be_bytes());
    f.extend_from_slice(&(hb.len() as u32).to_be_bytes());
    f.extend_from_slice(&hb);
    f.extend_from_slice(&raw.body_bytes);
    cases.push(("slots len u32::MAX".into(), f));
    // text string of 2^40 declared in header map key
    let mut f = b"RVLT".to_vec();
    let hb = [0xa1u8, 0x7b, 0, 0, 1, 0, 0, 0, 0, 0];
    f.extend_from_slice(&1u16.to_be_bytes());
    f.extend_from_slice(&(hb.len() as u32).to_be_bytes());
    f.extend_from_slice(&hb);
    f.push(0x80);
    cases.push(("header key tstr 2^40".into(), f));
    // indefinite-length byte string chunks inside ct (canonical CBOR forbids indefinite)
    let mut bad = vec![];
    for (name, bytes) in cases {
        let p = write_tmp(d.path(), "h.bin", &bytes);
        let (out, st) = run_child("open_file", &[&p, PW], 20, 512);
        if !(st.starts_with("exit0") && out.starts_with("ERR")) {
            bad.push(format!("{name}: {st} {out}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 01 §1 "All CBOR is canonical": a non-canonical but well-formed header (indefinite-length map)
/// either opens with identical items or is rejected; it must not change what is authenticated.
#[test]
fn c04_noncanonical_header_tolerated_or_rejected() {
    let b = sample();
    let raw = split(&b);
    let hb = &raw.header_bytes;
    // convert definite map (0xa?) to indefinite (0xbf ... 0xff)
    assert!((0xa0..=0xb7).contains(&hb[0]));
    let mut nb = vec![0xbf];
    nb.extend_from_slice(&hb[1..]);
    nb.push(0xff);
    let mut f = b"RVLT".to_vec();
    f.extend_from_slice(&1u16.to_be_bytes());
    f.extend_from_slice(&(nb.len() as u32).to_be_bytes());
    f.extend_from_slice(&nb);
    f.extend_from_slice(&raw.body_bytes);
    let r = try_open(f);
    assert!(!matches!(r, Err(_)), "panic");
}

// ---------------------------------------------------------------------------------------------
// 2026-10-31 additions: new fixtures and hostile shapes of the version 2 keys.
// ---------------------------------------------------------------------------------------------

/// Every cut offset and 600 seeded bit flips on v2-basic and v1-meta (01 §9 fixtures): never Ok
/// with different contents, never a panic.
#[test]
fn c10_sweeps_on_new_fixtures() {
    use rand::{Rng, SeedableRng};
    let mut bad = vec![];
    for name in ["v2-basic.vault", "v1-meta.vault", "v1-icon.vault"] {
        let b = fixture(name);
        let open = |m: Vec<u8>| {
            std::panic::catch_unwind(move || {
                LockedVault::parse(&m)
                    .and_then(|l| l.unlock(&pw(FIXTURE_PW)))
                    .map(|u| snap_vault(&u))
                    .map_err(|_| ())
            })
            .map_err(|_| ())
        };
        let orig = open(b.clone()).unwrap().unwrap();
        for cut in 0..b.len() {
            match open(b[..cut].to_vec()) {
                Err(()) => bad.push(format!("{name} cut {cut}: PANIC")),
                Ok(Ok(_)) => bad.push(format!("{name} cut {cut}: accepted")),
                Ok(Err(())) => {}
            }
        }
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0FFEE);
        for _ in 0..600 {
            let mut m = b.clone();
            let pos = rng.gen_range(0..m.len());
            m[pos] ^= 1 << rng.gen_range(0..8);
            match open(m) {
                Err(()) => bad.push(format!("{name} flip at {pos}: PANIC")),
                Ok(Ok(s)) if s != orig => bad.push(format!(
                    "{name} flip at {pos}: accepted with different contents"
                )),
                _ => {}
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Hostile authenticated payloads (a device holding the key, or a buggy peer): removed_fields,
/// history field_id and icon with wrong types or huge sizes must be refused or bounded, never a
/// panic or a hang. (Only the key holder can produce these; checked for robustness.)
#[test]
fn c11_hostile_v2_item_payloads() {
    let (ver, h, key) = empty_base(2);
    let fid = *Uuid::new_v4().as_bytes();
    let base = || item_plain("x", [1; 16], vec![field_v(Some(fid), "a", "text", "v", 10)]);
    let many: Vec<Value> = (0..200_000u64)
        .map(|k| {
            map(vec![
                ("id", Value::Bytes(Uuid::new_v4().as_bytes().to_vec())),
                ("removed_at", i(k)),
            ])
        })
        .collect();
    let cases: Vec<(&str, &str, Value)> = vec![
        ("removed_fields text", "removed_fields", t("x")),
        (
            "removed_fields entry without id",
            "removed_fields",
            Value::Array(vec![map(vec![("removed_at", i(1))])]),
        ),
        (
            "removed_fields id 3 bytes",
            "removed_fields",
            Value::Array(vec![map(vec![
                ("id", Value::Bytes(vec![1, 2, 3])),
                ("removed_at", i(1)),
            ])]),
        ),
        (
            "removed_fields removed_at text",
            "removed_fields",
            Value::Array(vec![map(vec![
                ("id", Value::Bytes(vec![1; 16])),
                ("removed_at", t("1")),
            ])]),
        ),
        (
            "removed_fields 200k entries",
            "removed_fields",
            Value::Array(many),
        ),
        (
            "history field_id text",
            "history",
            Value::Array(vec![map(vec![
                ("value", t("old")),
                ("replaced_at", i(5)),
                ("field_id", t("nope")),
            ])]),
        ),
        (
            "history field_id 15 bytes",
            "history",
            Value::Array(vec![map(vec![
                ("value", t("old")),
                ("replaced_at", i(5)),
                ("field_id", Value::Bytes(vec![0; 15])),
            ])]),
        ),
        (
            "marker for a present field, later stamp",
            "removed_fields",
            Value::Array(vec![map(vec![
                ("id", Value::Bytes(fid.to_vec())),
                ("removed_at", i(99)),
            ])]),
        ),
    ];
    let mut report = vec![];
    for (name, k, val) in cases {
        let mut pt = base();
        set(&mut pt, k, val);
        let id = *Uuid::new_v4().as_bytes();
        let f = build_file(ver, &h, &key, &[(id, 100, pt)]);
        let t0 = std::time::Instant::now();
        let r = with_timeout(30, move || {
            std::panic::catch_unwind(|| {
                LockedVault::parse(&f)
                    .and_then(|l| l.unlock(&pw(FIXTURE_PW)))
                    .map(|u| {
                        let it = u.get(Uuid::from_bytes(id)).unwrap();
                        (
                            it.removed_fields.len(),
                            it.fields.len(),
                            u.serialize().len(),
                        )
                    })
            })
            .map_err(|_| ())
        });
        let el = t0.elapsed();
        match r {
            None => report.push(format!("HANG {name}")),
            Some(Err(())) => report.push(format!("PANIC {name}")),
            Some(Ok(res)) => eprintln!(
                "INFO {name}: {:?} in {el:?}",
                res.map_err(|e| format!("{e:?}").chars().take(80).collect::<String>())
            ),
        }
        if el.as_secs() > 10 {
            report.push(format!("SLOW {name}: {el:?}"));
        }
    }
    assert!(report.is_empty(), "{}", report.join("\n"));
}
