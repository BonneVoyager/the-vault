//! Field identity (01 §4 Field.id, §9 version 2 and v1 derivation; 02 set_field / set_field_named /
//! remove_field / update diff / Item::field). Added 2026-10-31.
use secrecy::ExposeSecret;
use spec_checks::*;
use uuid::Uuid;
use vault_core::*;

const PW: &str = FIXTURE_PW;

fn unlock(b: &[u8]) -> Result<UnlockedVault, VaultError> {
    LockedVault::parse(b)?.unlock(&pw(PW))
}
fn ids_of(v: &UnlockedVault, item: Uuid) -> Vec<(String, Uuid)> {
    v.get(item)
        .unwrap()
        .fields
        .iter()
        .map(|f| (f.name.clone(), f.id))
        .collect()
}
fn val_by_id(v: &UnlockedVault, item: Uuid, fid: Uuid) -> Option<String> {
    v.get(item)?
        .fields
        .iter()
        .find(|f| f.id == fid)
        .map(|f| f.value.expose_secret().clone())
}

/// A version 1 file with duplicate names, an empty name, a case variant, and one explicit id in
/// the middle of a same-name run.
fn v1_with_names() -> (Vec<u8>, [u8; 16], [u8; 16]) {
    let (ver, h, key) = empty_base(1);
    let item = *Uuid::new_v4().as_bytes();
    let explicit = *Uuid::new_v4().as_bytes();
    let fields = vec![
        field_v(None, "password", "password", "first", 10),
        field_v(Some(explicit), "password", "password", "explicit", 10),
        field_v(None, "password", "text", "third", 10),
        field_v(None, "", "text", "empty-a", 10),
        field_v(None, "", "notes", "empty-b", 10),
        field_v(None, "Password", "text", "case", 10),
        field_v(None, "url", "url", "https://e.example", 10),
        field_v(None, "ünï", "text", "unicode", 10),
    ];
    let b = build_file(
        ver,
        &h,
        &key,
        &[(item, 10, item_plain("v1 item", [7; 16], fields))],
    );
    (b, item, explicit)
}

/// 01 §9 "A version 1 file is read by deriving each field's id deterministically: UUIDv5 with the
/// item id as namespace over the bytes "field:" || name || ":" || ordinal, where ordinal is the
/// number of earlier fields in that item with the same name, as unpadded decimal; ids present in
/// a version 1 file are kept". Two reads agree; the ids match an independent UUIDv5.
#[test]
fn fi01_v1_derivation_matches_formula_and_is_deterministic() {
    let (b, item, explicit) = v1_with_names();
    let iid = Uuid::from_bytes(item);
    let a = unlock(&b).unwrap();
    let a2 = LockedVault::parse(&b).unwrap().unlock(&pw(PW)).unwrap();
    let a3 = LockedVault::parse(&b)
        .unwrap()
        .unlock_with_key(&a.export_vault_key(), Uuid::new_v4())
        .unwrap();
    assert_eq!(
        ids_of(&a, iid),
        ids_of(&a2, iid),
        "two password reads agree"
    );
    assert_eq!(
        ids_of(&a, iid),
        ids_of(&a3, iid),
        "password and key reads agree"
    );
    let want = vec![
        (
            "password".to_string(),
            derived_field_id(&item, "password", 0),
        ),
        ("password".to_string(), Uuid::from_bytes(explicit)),
        (
            "password".to_string(),
            derived_field_id(&item, "password", 2),
        ),
        ("".to_string(), derived_field_id(&item, "", 0)),
        ("".to_string(), derived_field_id(&item, "", 1)),
        (
            "Password".to_string(),
            derived_field_id(&item, "Password", 0),
        ),
        ("url".to_string(), derived_field_id(&item, "url", 0)),
        ("ünï".to_string(), derived_field_id(&item, "ünï", 0)),
    ];
    assert_eq!(
        ids_of(&a, iid),
        want,
        "ids follow 01 §9 literally (explicit id kept; ordinal counts every earlier same-name field)"
    );
    for f in &a.get(iid).unwrap().fields {
        if f.id != Uuid::from_bytes(explicit) {
            assert_eq!(f.id.get_version_num(), 5, "derived ids are UUIDv5");
        }
    }
}

/// 01 §9 "A save never changes a file's version ... a version 1 file stays version 1 and merely
/// gains explicit ids". Reopening the saved file yields the same ids; the independent decoder
/// still opens it with version-1 AADs; an edit by id keeps it version 1.
#[test]
fn fi02_v1_save_keeps_version_and_freezes_ids() {
    let (b, item, _) = v1_with_names();
    let iid = Uuid::from_bytes(item);
    let mut a = unlock(&b).unwrap();
    let before = ids_of(&a, iid);
    let out = a.serialize();
    assert_eq!(version_of(&out), 1, "save of a v1 file stays v1");
    let o = indep::open_file(&out, PW);
    let pt = &o.items[0].2;
    let written: Vec<Vec<u8>> = get(pt, "fields")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|f| bytes_of(get(f, "id").expect("explicit id written")))
        .collect();
    assert_eq!(
        written,
        before
            .iter()
            .map(|(_, id)| id.as_bytes().to_vec())
            .collect::<Vec<_>>()
    );
    assert_eq!(ids_of(&unlock(&out).unwrap(), iid), before, "reopen agrees");
    // edit by id, then a rename: ids stay, still v1
    let fid = before[2].1;
    a.set_field(iid, fid, pw("edited"), 50).unwrap();
    a.update(iid, 60, |it| it.fields[0].name = "renamed".into())
        .unwrap();
    let out2 = a.serialize();
    assert_eq!(version_of(&out2), 1);
    let r = unlock(&out2).unwrap();
    assert_eq!(val_by_id(&r, iid, fid).as_deref(), Some("edited"));
    assert_eq!(
        r.get(iid).unwrap().fields[0].id,
        before[0].1,
        "a rename keeps the (derived) id"
    );
}

/// 01 §9 "a duplicate id within an item is Malformed" — for explicit ids in a v1 file, and for an
/// explicit id that collides with another field's derived id.
#[test]
fn fi03_v1_duplicate_ids_malformed() {
    let (ver, h, key) = empty_base(1);
    let item = *Uuid::new_v4().as_bytes();
    let dup = *Uuid::new_v4().as_bytes();
    let f1 = vec![
        field_v(Some(dup), "a", "text", "1", 10),
        field_v(Some(dup), "b", "text", "2", 10),
    ];
    let b = build_file(ver, &h, &key, &[(item, 10, item_plain("x", [1; 16], f1))]);
    let r = unlock(&b);
    assert!(
        matches!(r, Err(VaultError::Malformed(_))),
        "two explicit equal ids: {:?}",
        r.err()
    );
    // explicit id equal to the derived id of an id-less field "a" at ordinal 0
    let collide = *derived_field_id(&item, "a", 0).as_bytes();
    let f2 = vec![
        field_v(None, "a", "text", "1", 10),
        field_v(Some(collide), "b", "text", "2", 10),
    ];
    let b = build_file(ver, &h, &key, &[(item, 10, item_plain("x", [1; 16], f2))]);
    match unlock(&b) {
        Err(VaultError::Malformed(_)) => {}
        Ok(u) => {
            let ids: Vec<Uuid> = u
                .get(Uuid::from_bytes(item))
                .unwrap()
                .fields
                .iter()
                .map(|f| f.id)
                .collect();
            let mut d = ids.clone();
            d.sort();
            d.dedup();
            assert_eq!(
                d.len(),
                ids.len(),
                "explicit id colliding with a derived id produced duplicate ids: {ids:?}"
            );
        }
        Err(e) => panic!("unexpected {e:?}"),
    }
}

/// 01 §4 Field.id "required in version 2": a v2 field without id, with a wrong-length id, a text
/// id, or a duplicated id is refused (Malformed), never a panic or a silent repair.
#[test]
fn fi04_v2_field_id_required_and_typed() {
    let (ver, h, key) = empty_base(2);
    let item = *Uuid::new_v4().as_bytes();
    let good = |n: &str| field_v(Some(*Uuid::new_v4().as_bytes()), n, "text", "v", 10);
    let mut cases: Vec<(&str, Vec<Value>)> = vec![
        (
            "missing id",
            vec![good("a"), field_v(None, "b", "text", "v", 10)],
        ),
        ("duplicate id", {
            let d = *Uuid::new_v4().as_bytes();
            vec![
                field_v(Some(d), "a", "text", "v", 10),
                field_v(Some(d), "b", "text", "v", 10),
            ]
        }),
    ];
    for (name, bad_id) in [
        ("15-byte id", Value::Bytes(vec![1; 15])),
        ("17-byte id", Value::Bytes(vec![1; 17])),
        ("text id", t("00000000-0000-4000-8000-000000000000")),
        ("int id", i(5)),
        ("null id", Value::Null),
        ("1 MB id", Value::Bytes(vec![9; 1 << 20])),
    ] {
        let mut f = good("x");
        set(&mut f, "id", bad_id);
        cases.push((name, vec![f]));
    }
    let mut bad = vec![];
    for (name, fields) in cases {
        let b = build_file(
            ver,
            &h,
            &key,
            &[(item, 10, item_plain("x", [1; 16], fields))],
        );
        let r = std::panic::catch_unwind(|| unlock(&b).map(|_| ()));
        match r {
            Err(_) => bad.push(format!("{name}: PANIC")),
            Ok(Ok(())) => bad.push(format!("{name}: accepted")),
            Ok(Err(VaultError::Malformed(_))) => {}
            Ok(Err(e)) => bad.push(format!("{name}: {e:?} (expected Malformed)")),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    // control: a well-formed hand-built v2 file opens (the builder is right)
    let b = build_file(
        ver,
        &h,
        &key,
        &[(
            item,
            10,
            item_plain("x", [1; 16], vec![good("a"), good("a")]),
        )],
    );
    assert_eq!(
        unlock(&b)
            .unwrap()
            .get(Uuid::from_bytes(item))
            .unwrap()
            .fields
            .len(),
        2
    );
}

/// 01 §4 "name ... NOT unique within an item and may be empty"; 02 Item::field "first non-Section
/// field whose name matches ASCII case-insensitively (an empty name never matches)"; set_field by
/// id edits exactly one field; history carries field_id (01 §4 HistoryEntry).
#[test]
fn fi05_duplicate_and_empty_names() {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(PW), KdfParams::for_tests(), dev);
    let mut it = Item::new("dups", dev, 100);
    it.fields
        .push(Field::new("Password", FieldKind::Section, pw(""), 100));
    it.fields
        .push(Field::new("password", FieldKind::Password, pw("one"), 100));
    it.fields
        .push(Field::new("PASSWORD", FieldKind::Password, pw("two"), 100));
    it.fields
        .push(Field::new("", FieldKind::Text, pw("nameless"), 100));
    let ids: Vec<Uuid> = it.fields.iter().map(|f| f.id).collect();
    let mut uniq = ids.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), 4, "Field::new gives distinct ids");
    let id = v.insert(it, 100);
    let r = unlock(&v.serialize()).unwrap();
    let got: Vec<(String, Uuid)> = ids_of(&r, id);
    assert_eq!(
        got.iter().map(|x| x.1).collect::<Vec<_>>(),
        ids,
        "round trip keeps every same-named and empty-named field, in order"
    );
    let item = r.get(id).unwrap();
    assert_eq!(
        item.field("password").map(|f| f.id),
        Some(ids[1]),
        "Item::field skips Section, first match"
    );
    assert_eq!(
        item.field("pAsSwOrD").map(|f| f.id),
        Some(ids[1]),
        "ASCII case-insensitive"
    );
    assert!(item.field("").is_none(), "empty name never matches");
    assert_eq!(
        item.field_by_id(ids[2])
            .map(|f| f.value.expose_secret().as_str()),
        Some("two")
    );
    // set_field by id on the second password: only it changes, history carries its field_id
    v.set_field(id, ids[2], pw("two-b"), 200).unwrap();
    let it = v.get(id).unwrap();
    assert_eq!(it.field_by_id(ids[1]).unwrap().value.expose_secret(), "one");
    assert_eq!(
        it.field_by_id(ids[2]).unwrap().value.expose_secret(),
        "two-b"
    );
    assert_eq!(
        it.field_by_id(ids[1]).unwrap().modified_at,
        100,
        "sibling untouched"
    );
    let h: Vec<_> = it
        .history
        .iter()
        .map(|e| (e.value.expose_secret().clone(), e.field_id))
        .collect();
    assert_eq!(
        h,
        vec![("two".to_string(), Some(ids[2]))],
        "history entry with field_id"
    );
    let o = indep::open_file(&v.serialize(), PW);
    let hist = get(&o.items[0].2, "history").unwrap().as_array().unwrap();
    assert_eq!(
        bytes_of(get(&hist[0], "field_id").expect("01 §4 HistoryEntry.field_id written")),
        ids[2].as_bytes().to_vec()
    );
    // set_field_named on an empty name / unknown name -> FieldNotFound; on duplicates either the first
    // (02 "first non-Section field matching") or AmbiguousField, but never the Section or the second.
    assert!(matches!(
        v.set_field_named(id, "", pw("x"), 300),
        Err(VaultError::FieldNotFound)
    ));
    assert!(matches!(
        v.set_field_named(id, "nope", pw("x"), 300),
        Err(VaultError::FieldNotFound)
    ));
    match v.set_field_named(id, "password", pw("named"), 300) {
        Ok(()) => {
            let it = v.get(id).unwrap();
            assert_eq!(
                it.field_by_id(ids[1]).unwrap().value.expose_secret(),
                "named"
            );
            assert_eq!(
                it.field_by_id(ids[2]).unwrap().value.expose_secret(),
                "two-b"
            );
            assert_eq!(
                it.field_by_id(ids[0]).unwrap().value.expose_secret(),
                "",
                "section untouched"
            );
            eprintln!("INFO set_field_named on two same-named fields: edits the first");
        }
        Err(VaultError::AmbiguousField) => {
            eprintln!("INFO set_field_named on two same-named fields: AmbiguousField");
            let it = v.get(id).unwrap();
            assert_eq!(it.field_by_id(ids[1]).unwrap().value.expose_secret(), "one");
        }
        Err(e) => panic!("{e:?}"),
    }
    // unknown field id / unknown item
    assert!(matches!(
        v.set_field(id, Uuid::new_v4(), pw("x"), 400),
        Err(VaultError::FieldNotFound)
    ));
    assert!(v.set_field(Uuid::new_v4(), ids[1], pw("x"), 400).is_err());
}

/// 02 update: "It diffs fields by id against the pre-call copy: a field whose name, kind, value or
/// section changed without a bumped modified_at is bumped to now (a rename is an edit, not a
/// delete + add); an id that vanished gets a removed_fields marker stamped now; a re-added id is
/// stamped past its marker and the marker dropped; a duplicate id within an item is rejected and
/// the item restored."
#[test]
fn fi06_update_diff_by_id() {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(PW), KdfParams::for_tests(), dev);
    let mut it = Item::new("u", dev, 100);
    for n in ["a", "b", "c"] {
        it.fields.push(Field::new(n, FieldKind::Text, pw(n), 100));
    }
    let ids: Vec<Uuid> = it.fields.iter().map(|f| f.id).collect();
    let id = v.insert(it, 100);
    // rename
    v.update(id, 1_000, |it| it.fields[0].name = "A2".into())
        .unwrap();
    let f = v.get(id).unwrap().field_by_id(ids[0]).unwrap();
    assert_eq!(
        (f.name.as_str(), f.modified_at),
        ("A2", 1_000),
        "rename keeps id and bumps stamp"
    );
    // kind change counts too
    v.update(id, 1_100, |it| it.fields[1].kind = FieldKind::Email)
        .unwrap();
    assert_eq!(
        v.get(id).unwrap().field_by_id(ids[1]).unwrap().modified_at,
        1_100,
        "kind change bumps"
    );
    // remove c
    let removed = v.get(id).unwrap().fields[2].clone();
    v.update(id, 2_000, |it| it.fields.retain(|f| f.id != ids[2]))
        .unwrap();
    let item = v.get(id).unwrap();
    assert_eq!(
        item.removed_fields
            .iter()
            .map(|t| (t.id, t.removed_at))
            .collect::<Vec<_>>(),
        vec![(ids[2], 2_000)],
        "removal marker stamped now"
    );
    assert_eq!(
        item.modified_at, 2_000,
        "item modified_at covers the removal"
    );
    // re-add the same id (e.g. undo) -> stamped past its marker, marker dropped
    v.update(id, 1_500, |it| it.fields.push(removed.clone()))
        .unwrap();
    let item = v.get(id).unwrap();
    let f = item.field_by_id(ids[2]).expect("re-added field present");
    assert!(
        f.modified_at > 2_000,
        "re-added field stamped past its marker: {}",
        f.modified_at
    );
    assert!(
        item.removed_fields.iter().all(|t| t.id != ids[2]),
        "marker dropped on re-add"
    );
    // duplicate id inside update -> rejected, item restored
    let snap = snap_item(v.get(id).unwrap());
    let r = v.update(id, 3_000, |it| {
        let d = it.fields[0].clone();
        it.title = "should not stick".into();
        it.fields.push(d);
    });
    assert!(r.is_err(), "duplicate id in update is rejected");
    assert_eq!(
        snap_item(v.get(id).unwrap()),
        snap,
        "item restored after rejected update"
    );
}

/// 02 remove_field "writes a removed_fields marker"; 01 §4 removed_fields "newest first, cap 64,
/// written only when non-empty"; 03 §5 (amended) the cap is applied by a merge, not a local removal.
#[test]
fn fi07_remove_field_markers_cap_and_order() {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(PW), KdfParams::for_tests(), dev);
    let mut it = Item::new("r", dev, 100);
    for n in 0..80 {
        it.fields
            .push(Field::new(format!("f{n}"), FieldKind::Text, pw("x"), 100));
    }
    let ids: Vec<Uuid> = it.fields.iter().map(|f| f.id).collect();
    let id = v.insert(it, 100);
    let o = indep::open_file(&v.serialize(), PW);
    assert!(
        get(&o.items[0].2, "removed_fields").is_none(),
        "removed_fields omitted while empty"
    );
    assert!(matches!(
        v.remove_field(id, Uuid::new_v4(), 150),
        Err(VaultError::FieldNotFound)
    ));
    for (n, fid) in ids.iter().enumerate() {
        v.remove_field(id, *fid, 1_000 + n as u64).unwrap();
    }
    // Ported 2026-10-31 to the amended 03 §5: "Markers are never dropped by a local removal; a
    // merge caps them at 64 by dropping, oldest first, only markers whose field neither side
    // still holds."
    let item = v.get(id).unwrap();
    assert!(item.fields.is_empty());
    let rf: Vec<(Uuid, u64)> = item
        .removed_fields
        .iter()
        .map(|t| (t.id, t.removed_at))
        .collect();
    let all: Vec<(Uuid, u64)> = (0..80).rev().map(|n| (ids[n], 1_000 + n as u64)).collect();
    assert_eq!(rf, all, "80 local removals keep 80 markers, newest first");
    let o = indep::open_file(&v.serialize(), PW);
    let w = get(&o.items[0].2, "removed_fields")
        .expect("written when non-empty")
        .as_array()
        .unwrap();
    assert_eq!(w.len(), 80, "all 80 markers written before any merge");
    assert_eq!(
        bytes_of(get(&w[0], "id").unwrap()),
        ids[79].as_bytes().to_vec()
    );
    assert_eq!(u64_of(get(&w[0], "removed_at").unwrap()), 1_079);
    // a merge where both sides lack every field: the cap fires, the 64 newest stay
    let other = LockedVault::parse(&v.serialize())
        .unwrap()
        .unlock_with_key(&v.export_vault_key(), Uuid::new_v4())
        .unwrap();
    v.merge_from(&other).unwrap();
    let rf: Vec<(Uuid, u64)> = v
        .get(id)
        .unwrap()
        .removed_fields
        .iter()
        .map(|t| (t.id, t.removed_at))
        .collect();
    let want: Vec<(Uuid, u64)> = (16..80).rev().map(|n| (ids[n], 1_000 + n as u64)).collect();
    assert_eq!(
        rf, want,
        "after a merge where neither side holds the fields: 64 newest, newest first"
    );
    let o = indep::open_file(&v.serialize(), PW);
    assert_eq!(
        get(&o.items[0].2, "removed_fields")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        64
    );
    // markers purged with item tombstones (01 §4): purge removes the whole tombstoned item
    v.delete(id, 5_000).unwrap();
    assert_eq!(v.purge_tombstones_older_than(6_000), 1);
}

/// 01 §4 Field kind "section": "a visual heading; name is the heading text, value is empty and
/// ignored (core stores it as given); never sensitive; skipped by CSV export and search; set_field
/// on it writes no history". 02 FieldKind ALL has 9 entries incl. Section; Other is sensitive.
#[test]
fn fi08_section_kind() {
    assert_eq!(FieldKind::ALL.len(), 9);
    assert!(FieldKind::ALL.contains(&FieldKind::Section));
    assert!(!FieldKind::Section.is_sensitive());
    assert!(FieldKind::Password.is_sensitive() && FieldKind::Totp.is_sensitive());
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(PW), KdfParams::for_tests(), dev);
    let mut it = Item::new("Sectioned", dev, 100);
    it.fields.push(Field::new(
        "Zebrahead",
        FieldKind::Section,
        pw("SECTIONVALUEQQ"),
        100,
    ));
    it.fields
        .push(Field::new("username", FieldKind::Text, pw("bob"), 100));
    let sid = it.fields[0].id;
    let id = v.insert(it, 100);
    let r = unlock(&v.serialize()).unwrap();
    assert_eq!(
        r.get(id)
            .unwrap()
            .field_by_id(sid)
            .unwrap()
            .value
            .expose_secret(),
        "SECTIONVALUEQQ",
        "core stores it as given"
    );
    let o = indep::open_file(&v.serialize(), PW);
    assert_eq!(
        get(
            &get(&o.items[0].2, "fields").unwrap().as_array().unwrap()[0],
            "kind"
        ),
        Some(&t("section"))
    );
    // set_field on a section -> no history
    v.set_field(id, sid, pw("other"), 200).unwrap();
    assert!(
        v.get(id).unwrap().history.is_empty(),
        "no history for Section"
    );
    // search skips sections (value and heading)
    let q = |s: &str| {
        search(
            &v,
            &Query {
                text: s,
                tag: None,
                favorites_only: false,
            },
        )
        .len()
    };
    assert_eq!(q("other"), 0, "section value not searched");
    assert_eq!(
        q("Zebrahead"),
        0,
        "section heading not searched (01 §4 'skipped by ... search')"
    );
    // CSV export skips sections
    let csv = String::from_utf8(export_csv(&v).0.clone()).unwrap();
    assert!(
        !csv.contains("other") && !csv.contains("SECTIONVALUEQQ"),
        "section value exported: {csv}"
    );
    assert!(
        !csv.contains("Zebrahead"),
        "section heading exported: {csv}"
    );
    assert!(csv.contains("bob"));
}

/// 01 §4 created_at (v1.3): "writers omit the key when unknown, readers treat missing or null as
/// unknown and any other non-integer as Malformed"; 02 "Item::new sets Some(now)".
#[test]
fn fi09_created_at_shape() {
    let dev = Uuid::new_v4();
    let it = Item::new("c", dev, 1_234);
    assert_eq!(it.created_at, Some(1_234));
    let mut v = UnlockedVault::create(&pw(PW), KdfParams::for_tests(), dev);
    let a = v.insert(it, 1_234);
    let mut it2 = Item::new("none", dev, 5);
    it2.created_at = None;
    let b = v.insert(it2, 5);
    let o = indep::open_file(&v.serialize(), PW);
    for (iid, _, pt) in &o.items {
        if iid == a.as_bytes() {
            assert_eq!(get(pt, "created_at").map(u64_of), Some(1_234));
        } else if iid == b.as_bytes() {
            assert!(
                get(pt, "created_at").is_none(),
                "writer omits created_at when unknown"
            );
        }
    }
    let (ver, h, key) = empty_base(2);
    let mut bad = vec![];
    for (name, val, ok) in [
        ("null", Value::Null, Some(None)),
        ("int", i(77), Some(Some(77u64))),
        ("text", t("77"), None),
        ("negative", Value::Integer((-1).into()), None),
        ("float", Value::Float(1.5), None),
        ("bytes", Value::Bytes(vec![1]), None),
    ] {
        let id = *Uuid::new_v4().as_bytes();
        let mut pt = item_plain(
            "x",
            [1; 16],
            vec![field_v(
                Some(*Uuid::new_v4().as_bytes()),
                "a",
                "text",
                "v",
                10,
            )],
        );
        set(&mut pt, "created_at", val);
        let f = build_file(ver, &h, &key, &[(id, 10, pt)]);
        let r = std::panic::catch_unwind(|| {
            unlock(&f).map(|u| u.get(Uuid::from_bytes(id)).unwrap().created_at)
        });
        match (r, ok) {
            (Err(_), _) => bad.push(format!("{name}: PANIC")),
            (Ok(Ok(got)), Some(want)) if got == want => {}
            (Ok(Err(VaultError::Malformed(_))), None) => {}
            (Ok(other), want) => bad.push(format!(
                "{name}: got {:?}, want {want:?}",
                other.map_err(|e| format!("{e:?}"))
            )),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 01 §4 icon (v1.2): "core validates types only; unknown keys inside the map are preserved;
/// writers omit the key when there is no icon, readers treat missing or null as none".
#[test]
fn fi10_icon_shape() {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(PW), KdfParams::for_tests(), dev);
    let mut it = Item::new("i", dev, 10);
    let mut icon = ItemIcon::new("symbol", "key.fill");
    icon.color = Some("#ff0000".into());
    it.icon = Some(icon);
    let a = v.insert(it, 10);
    let b = v.insert(Item::new("none", dev, 10), 10);
    let r = unlock(&v.serialize()).unwrap();
    let ic = r.get(a).unwrap().icon.clone().unwrap();
    assert_eq!(
        (ic.kind.as_str(), ic.value.as_str(), ic.color.as_deref()),
        ("symbol", "key.fill", Some("#ff0000"))
    );
    assert!(r.get(b).unwrap().icon.is_none());
    let o = indep::open_file(&v.serialize(), PW);
    for (iid, _, pt) in &o.items {
        if iid == b.as_bytes() {
            assert!(get(pt, "icon").is_none(), "writer omits icon when none");
        }
    }
    let (ver, h, key) = empty_base(2);
    let mut bad = vec![];
    let cases: Vec<(&str, Value, &str)> = vec![
        ("null", Value::Null, "none"),
        (
            "unknown inner key",
            map(vec![
                ("kind", t("logo")),
                ("value", t("github")),
                ("zz_future", Value::Array(vec![i(1)])),
            ]),
            "ok",
        ),
        (
            "no color",
            map(vec![("kind", t("logo")), ("value", t("github"))]),
            "ok",
        ),
        ("text", t("symbol"), "malformed"),
        (
            "kind int",
            map(vec![("kind", i(1)), ("value", t("x"))]),
            "malformed",
        ),
        (
            "value missing",
            map(vec![("kind", t("logo"))]),
            "malformed?",
        ),
        (
            "color int",
            map(vec![
                ("kind", t("logo")),
                ("value", t("x")),
                ("color", i(3)),
            ]),
            "malformed",
        ),
    ];
    for (name, val, want) in cases {
        let id = *Uuid::new_v4().as_bytes();
        let mut pt = item_plain("x", [1; 16], vec![]);
        set(&mut pt, "icon", val.clone());
        let f = build_file(ver, &h, &key, &[(id, 10, pt)]);
        let r = std::panic::catch_unwind(|| {
            unlock(&f).map(|u| {
                (
                    u.get(Uuid::from_bytes(id)).unwrap().icon.clone(),
                    u.serialize(),
                )
            })
        });
        match (r, want) {
            (Err(_), _) => bad.push(format!("{name}: PANIC")),
            (Ok(Ok((None, _))), "none") => {}
            (Ok(Ok((Some(_), out))), "ok") => {
                // unknown keys inside the map are preserved on re-serialize
                let oo = indep::open_file(&out, PW);
                let got = get(&oo.items[0].2, "icon").cloned();
                if got != Some(canon(val.clone())) {
                    bad.push(format!("{name}: icon map not preserved: {got:?}"));
                }
            }
            (Ok(Err(VaultError::Malformed(_))), "malformed" | "malformed?") => {}
            (Ok(Ok(_)), "malformed?") => eprintln!("INFO icon without value accepted"),
            (Ok(other), want) => bad.push(format!(
                "{name}: got {:?}, want {want}",
                other
                    .map(|(i, _)| i.is_some())
                    .map_err(|e| format!("{e:?}"))
            )),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 01 §9 fixtures: v2-basic "carries two same-named fields, an empty-named field, a removed_fields
/// marker and a history entry with field_id"; v1-icon and v1-meta as described; "a test opens every
/// fixture in that directory with the current reader".
#[test]
fn fi11_new_fixtures() {
    let b = fixture("v2-basic.vault");
    assert_eq!(version_of(&b), 2);
    let u = unlock(&b).expect("v2-basic opens");
    let o = indep::open_file(&b, PW);
    let mut same_name = false;
    let mut empty_name = false;
    let mut marker = false;
    let mut hist_fid = false;
    for it in u.items_including_deleted() {
        let mut names: Vec<&str> = it.fields.iter().map(|f| f.name.as_str()).collect();
        empty_name |= names.contains(&"");
        let n = names.len();
        names.sort();
        names.dedup();
        same_name |= names.len() < n;
        marker |= !it.removed_fields.is_empty();
        hist_fid |= it.history.iter().any(|h| h.field_id.is_some());
    }
    assert!(
        same_name && empty_name && marker && hist_fid,
        "v2-basic content: same={same_name} empty={empty_name} marker={marker} hist_fid={hist_fid}"
    );
    for (_, _, pt) in &o.items {
        for f in get(pt, "fields").unwrap().as_array().unwrap() {
            assert!(
                get(f, "id").is_some(),
                "v2 fixture fields carry explicit ids"
            );
        }
    }
    // v1-icon
    let u = unlock(&fixture("v1-icon.vault")).unwrap();
    let icons: Vec<Option<(String, Option<String>)>> = u
        .items()
        .map(|i| i.icon.as_ref().map(|c| (c.kind.clone(), c.color.clone())))
        .collect();
    assert!(
        icons
            .iter()
            .any(|c| matches!(c, Some((k, Some(_))) if k == "symbol")),
        "symbol icon with colour: {icons:?}"
    );
    assert!(
        icons
            .iter()
            .any(|c| matches!(c, Some((k, None)) if k == "logo")),
        "logo icon without colour"
    );
    assert!(icons.iter().any(|c| c.is_none()), "icon-less item");
    // v1-meta
    let u = unlock(&fixture("v1-meta.vault")).unwrap();
    assert!(
        u.items().any(|i| i.created_at.is_some()
            && i.fields.first().map(|f| f.kind) == Some(FieldKind::Section))
    );
    assert!(u.items().any(|i| i.created_at.is_none()));
    // every fixture in the directory opens
    let mut n = 0;
    for e in std::fs::read_dir(fixtures_dir()).unwrap() {
        let p = e.unwrap().path();
        if p.extension().and_then(|x| x.to_str()) == Some("vault") && p.is_file() {
            unlock(&std::fs::read(&p).unwrap())
                .unwrap_or_else(|e| panic!("{}: {e:?}", p.display()));
            n += 1;
        }
    }
    assert!(n >= 8, "fixtures opened: {n}");
}

/// 01 §2 slot AAD binds format_version: flipping the version bytes of a v2 file to 1 (or a v1 file
/// to 2) must never open on any path (downgrade/upgrade by an attacker who can write the file).
#[test]
fn fi12_version_flip_never_opens() {
    let (mut v, _) = {
        let dev = Uuid::new_v4();
        let mut v = UnlockedVault::create(&pw(PW), KdfParams::for_tests(), dev);
        let mut it = Item::new("x", dev, 10);
        it.fields
            .push(Field::new("a", FieldKind::Text, pw("b"), 10));
        v.insert(it, 10);
        (v, ())
    };
    let kek = secrecy::SecretVec::new(vec![5u8; 32]);
    let sid = v.add_enclave_slot(&kek, 20);
    let key = v.export_vault_key();
    let mut bad = vec![];
    for (label, mut b, to) in [
        ("v2->1", v.serialize(), 1u16),
        ("v1->2", fixture("v1-basic.vault"), 2u16),
        ("v1-stamped->2", fixture("v1-stamped.vault"), 2u16),
    ] {
        let fkey = if label == "v2->1" {
            Some(key.duplicate())
        } else {
            unlock(&b).ok().map(|u| u.export_vault_key())
        };
        b[4..6].copy_from_slice(&to.to_be_bytes());
        let l = match LockedVault::parse(&b) {
            Ok(l) => l,
            Err(_) => continue,
        };
        if let Ok(u) = l.unlock(&pw(PW)) {
            bad.push(format!(
                "{label}: password path opened ({} items)",
                u.items().count()
            ));
        }
        if label == "v2->1" && l.unlock_with_kek(sid, &kek).is_ok() {
            bad.push(format!("{label}: kek path opened"));
        }
        if let Some(k) = fkey {
            if l.unlock_with_key(&k, Uuid::new_v4()).is_ok() {
                bad.push(format!("{label}: key path opened"));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
