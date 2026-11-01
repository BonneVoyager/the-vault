//! 2026-11-01: corruption sweeps and hostile authenticated payloads for the keys added on
//! 2026-10-31 and 2026-11-01: per-attribute stamps (01 §4 `title_modified_at`, ...),
//! `removed_attachments` markers (01 §4, 03 §5), and extreme stamp values. Only a key holder can
//! produce authenticated payloads; these check robustness (refuse or bound, never panic or hang).
use secrecy::ExposeSecret;
use spec_checks::*;
use uuid::Uuid;
use vault_core::*;

const PW: &str = "pw-for-stamp-checks";

/// A file carrying every new key: attribute stamps, removed_attachments, removed_fields, refs,
/// history, icon, plus an enclave slot.
fn rich() -> Vec<u8> {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(PW), KdfParams::for_tests(), dev);
    let mut it = Item::new("rich", dev, 10);
    it.fields
        .push(Field::new("username", FieldKind::Text, pw("u"), 10));
    it.fields
        .push(Field::new("password", FieldKind::Password, pw("p"), 10));
    it.fields
        .push(Field::new("gone", FieldKind::Text, pw("g"), 10));
    let gone = it.fields[2].id;
    let id = v.insert(it, 10);
    v.update(id, 20, |it| {
        it.title = "rich2".into();
        it.favorite = true;
        it.tags = vec!["b".into(), "a".into()];
        it.icon = Some(ItemIcon::new("symbol", "key"));
    })
    .unwrap();
    v.set_field_named(id, "password", pw("p2"), 30).unwrap();
    v.remove_field(id, gone, 40).unwrap();
    let r = attachment::new_ref("x.txt", 5, 50).unwrap();
    let rid = r.id;
    v.add_attachment_ref(id, r, 50).unwrap();
    v.remove_attachment_ref(id, rid, 60).unwrap();
    let r2 = attachment::new_ref("y.txt", 7, 70).unwrap();
    v.add_attachment_ref(id, r2, 70).unwrap();
    v.add_enclave_slot(&secrecy::SecretVec::new(vec![9; 32]), 80);
    v.serialize()
}

fn plain_snapshot(u: &UnlockedVault) -> Vec<String> {
    let mut s = snap_vault(u);
    for it in u.items_including_deleted() {
        let mut ra: Vec<String> = it
            .removed_attachments
            .iter()
            .map(|t| format!("{}@{}", t.id, t.removed_at))
            .collect();
        ra.sort();
        let at: Vec<String> = it
            .attachments
            .iter()
            .map(|a| format!("{}:{}:{}", a.id, a.size, a.added_at))
            .collect();
        s.push(format!("{} ra={ra:?} at={at:?}", it.id));
    }
    s
}

/// Every cut offset and 800 seeded bit flips over a file carrying the new keys, on the password
/// path and on the sync path (`unlock_with_key`): never accepted with different contents (01 §4
/// tamper detection, 02 guarantees 4-7), never a panic.
#[test]
fn hs01_sweeps_over_file_with_new_keys() {
    use rand::{Rng, SeedableRng};
    let b = rich();
    let base = LockedVault::parse(&b).unwrap().unlock(&pw(PW)).unwrap();
    let key = base.export_vault_key();
    let dev = base.device_id();
    let orig = plain_snapshot(&base);
    let open_pw = |m: Vec<u8>| {
        std::panic::catch_unwind(move || {
            LockedVault::parse(&m)
                .and_then(|l| l.unlock(&pw(PW)))
                .map(|u| plain_snapshot(&u))
                .map_err(|_| ())
        })
        .map_err(|_| ())
    };
    let mut bad = vec![];
    for cut in 0..b.len() {
        match open_pw(b[..cut].to_vec()) {
            Err(()) => bad.push(format!("cut {cut}: PANIC")),
            Ok(Ok(_)) => bad.push(format!("cut {cut}: accepted")),
            Ok(Err(())) => {}
        }
    }
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x0B5E55ED);
    let mut accepted = 0;
    for n in 0..800 {
        let mut m = b.clone();
        let flips = if n % 4 == 0 { rng.gen_range(2..6) } else { 1 };
        let mut at = vec![];
        for _ in 0..flips {
            let p = rng.gen_range(0..m.len());
            m[p] ^= 1 << rng.gen_range(0..8);
            at.push(p);
        }
        let m2 = m.clone();
        match open_pw(m) {
            Err(()) => bad.push(format!("flips {at:?}: PANIC (password path)")),
            Ok(Ok(s)) if s != orig => {
                bad.push(format!("flips {at:?}: accepted with changed contents"))
            }
            Ok(Ok(_)) => accepted += 1,
            Ok(Err(())) => {}
        }
        let r = std::panic::catch_unwind(|| {
            LockedVault::parse(&m2)
                .and_then(|l| l.unlock_with_key(&key, dev))
                .map(|u| plain_snapshot(&u))
        });
        match r {
            Err(_) => bad.push(format!("flips {at:?}: PANIC (key path)")),
            Ok(Ok(s)) if s != orig => bad.push(format!(
                "flips {at:?}: key path accepted with changed contents"
            )),
            _ => {}
        }
    }
    eprintln!("INFO accepted-unchanged flips: {accepted}");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Hostile authenticated payloads for the 2026-10-31/11-01 keys: wrong types and huge sizes must
/// be refused (Malformed) or bounded; never a panic or a hang.
#[test]
fn hs02_hostile_attribute_stamps_and_attachment_markers() {
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
    let neg = Value::Integer((-5i64).into());
    let mut cases: Vec<(String, &str, Value)> = vec![];
    for k in [
        "title_modified_at",
        "favorite_modified_at",
        "tags_modified_at",
        "icon_modified_at",
    ] {
        cases.push((format!("{k} text"), k, t("12")));
        cases.push((format!("{k} negative"), k, neg.clone()));
        cases.push((format!("{k} float"), k, Value::Float(1.5)));
        cases.push((format!("{k} bytes"), k, Value::Bytes(vec![1; 8])));
        cases.push((format!("{k} map"), k, map(vec![])));
    }
    cases.push((
        "removed_attachments text".into(),
        "removed_attachments",
        t("x"),
    ));
    cases.push((
        "removed_attachments entry without id".into(),
        "removed_attachments",
        Value::Array(vec![map(vec![("removed_at", i(1))])]),
    ));
    cases.push((
        "removed_attachments id 3 bytes".into(),
        "removed_attachments",
        Value::Array(vec![map(vec![
            ("id", Value::Bytes(vec![1, 2, 3])),
            ("removed_at", i(1)),
        ])]),
    ));
    cases.push((
        "removed_attachments removed_at text".into(),
        "removed_attachments",
        Value::Array(vec![map(vec![
            ("id", Value::Bytes(vec![1; 16])),
            ("removed_at", t("1")),
        ])]),
    ));
    cases.push((
        "removed_attachments 200k entries".into(),
        "removed_attachments",
        Value::Array(many),
    ));
    let mut report = vec![];
    for (name, k, val) in cases {
        let mut pt = base();
        set(&mut pt, k, val);
        let id = *Uuid::new_v4().as_bytes();
        let f = build_file(ver, &h, &key, &[(id, 100, pt)]);
        let t0 = std::time::Instant::now();
        let r = with_timeout(60, move || {
            std::panic::catch_unwind(|| {
                LockedVault::parse(&f)
                    .and_then(|l| l.unlock(&pw(FIXTURE_PW)))
                    .map(|mut u| {
                        let iid = Uuid::from_bytes(id);
                        let _ = u.update(iid, 5_000, |it| it.title = "edited".into());
                        let other = LockedVault::parse(&u.serialize())
                            .unwrap()
                            .unlock(&pw(FIXTURE_PW))
                            .unwrap();
                        let _ = u.merge_from(&other);
                        u.get(iid).map(|it| it.removed_attachments.len())
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
                res.map_err(|e| format!("{e:?}").chars().take(60).collect::<String>())
            ),
        }
        if el.as_secs() > 15 {
            report.push(format!("SLOW {name}: {el:?}"));
        }
    }
    assert!(report.is_empty(), "{}", report.join("\n"));
}

/// 03 §5 "every write stamps max(now, previous + 1)" and "the merge bumps modified_at by one":
/// an authenticated item whose stamps sit at u64::MAX (a peer with a broken clock, or a key
/// holder) must not make an edit, a delete, a merge or a serialize panic (integer overflow).
#[test]
fn hs03_stamps_at_u64_max_do_not_panic() {
    let (ver, h, key) = empty_base(2);
    let max = u64::MAX;
    let fid = *Uuid::new_v4().as_bytes();
    let mut pt = item_plain(
        "max",
        [7; 16],
        vec![field_v(Some(fid), "password", "password", "v", max)],
    );
    for k in [
        "title_modified_at",
        "favorite_modified_at",
        "tags_modified_at",
        "icon_modified_at",
    ] {
        set(&mut pt, k, i(max));
    }
    let id = *Uuid::new_v4().as_bytes();
    let f = build_file(ver, &h, &key, &[(id, max, pt.clone())]);
    let iid = Uuid::from_bytes(id);
    let fuid = Uuid::from_bytes(fid);
    let mut report = vec![];
    type Op = Box<dyn Fn(&mut UnlockedVault) + std::panic::RefUnwindSafe>;
    let ops: Vec<(&str, Op)> = vec![
        (
            "update title",
            Box::new(move |u| {
                let _ = u.update(iid, 1_000, |it| it.title = "t".into());
            }),
        ),
        (
            "set_field (password, pushes history)",
            Box::new(move |u| {
                let _ = u.set_field(iid, fuid, pw("new"), 1_000);
            }),
        ),
        (
            "remove_field",
            Box::new(move |u| {
                let _ = u.remove_field(iid, fuid, 1_000);
            }),
        ),
        (
            "delete",
            Box::new(move |u| {
                let _ = u.delete(iid, 1_000);
            }),
        ),
        (
            "add_attachment_ref",
            Box::new(move |u| {
                let r = attachment::new_ref("a", 1, 1_000).unwrap();
                let _ = u.add_attachment_ref(iid, r, 1_000);
            }),
        ),
    ];
    for (name, op) in &ops {
        let f = f.clone();
        let r = std::panic::catch_unwind(|| {
            let mut u = LockedVault::parse(&f)
                .unwrap()
                .unlock(&pw(FIXTURE_PW))
                .unwrap();
            op(&mut u);
            let b = u.serialize();
            LockedVault::parse(&b)
                .and_then(|l| l.unlock(&pw(FIXTURE_PW)))
                .map(|_| ())
        });
        match r {
            Err(_) => report.push(format!("PANIC on {name} with stamps at u64::MAX")),
            Ok(Err(e)) => report.push(format!(
                "{name}: result no longer opens: {:?}",
                format!("{e:?}").chars().take(60).collect::<String>()
            )),
            Ok(Ok(())) => {}
        }
    }
    // merge: two copies at u64::MAX whose content differs at an equal stamp (the +1 bump case)
    let mut pt2 = pt.clone();
    set(
        &mut pt2,
        "fields",
        Value::Array(vec![field_v(Some(fid), "password", "password", "w", max)]),
    );
    let g = build_file(ver, &h, &key, &[(id, max, pt2)]);
    let r = std::panic::catch_unwind(|| {
        let mut a = LockedVault::parse(&f)
            .unwrap()
            .unlock(&pw(FIXTURE_PW))
            .unwrap();
        let b = LockedVault::parse(&g)
            .unwrap()
            .unlock(&pw(FIXTURE_PW))
            .unwrap();
        let _ = a.merge_from(&b);
        let out = a.serialize();
        LockedVault::parse(&out)
            .and_then(|l| l.unlock(&pw(FIXTURE_PW)))
            .map(|u| {
                u.get(iid)
                    .and_then(|it| it.fields.first())
                    .map(|f| f.value.expose_secret().clone())
            })
    });
    match r {
        Err(_) => report.push("PANIC on merge of equal u64::MAX stamps".into()),
        Ok(Err(e)) => report.push(format!(
            "merge at u64::MAX: result no longer opens: {:?}",
            format!("{e:?}").chars().take(60).collect::<String>()
        )),
        Ok(Ok(v)) => eprintln!("INFO merge at u64::MAX kept {v:?}"),
    }
    assert!(report.is_empty(), "{}", report.join("\n"));
}
