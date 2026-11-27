//! Field icons (2026-11-07): 01 §4 `Field.icon`, 01 §9 fixture `v2-field-icon.vault`, 02 `Field.icon`,
//! 03 §5 field merge, 05 §2.3 "Field icons" ("Not carried by CSV/1PUX/KDBX import or export; no CLI
//! flag"). Added 2026-11-08, written from the specs before reading the source.
use secrecy::ExposeSecret;
use spec_checks::dev::*;
use spec_checks::*;
use std::process::Command;
use uuid::Uuid;
use vault_core::import::*;
use vault_core::*;

fn fid() -> [u8; 16] {
    *Uuid::new_v4().as_bytes()
}
/// A text field map with an optional raw `icon` value (None = key absent).
fn fld(id: [u8; 16], name: &str, kind: &str, value: &str, ma: u64, icon: Option<Value>) -> Value {
    let mut f = field_v(Some(id), name, kind, value, ma);
    if let Some(ic) = icon {
        set(&mut f, "icon", ic);
    }
    f
}
/// Hand-built version 2 file (independent writer) with one item carrying `fields`.
fn file_with(fields: Vec<Value>) -> (Vec<u8>, [u8; 16]) {
    let (ver, h, key) = empty_base(2);
    let id = fid();
    let pt = item_plain("FI", [7u8; 16], fields);
    (build_file(ver, &h, &key, &[(id, 1000, pt)]), id)
}
fn unlock(b: &[u8]) -> Result<UnlockedVault, VaultError> {
    LockedVault::parse(b)?.unlock(&pw(FIXTURE_PW))
}
/// (field id bytes, raw icon entry: None = key absent) for every field of every item, decoded
/// with the independent decoder.
fn raw_icons(bytes: &[u8], password: &str) -> Vec<(Vec<u8>, Option<Value>)> {
    let o = indep::open_file(bytes, password);
    let mut out = vec![];
    for (_, _, pt) in &o.items {
        assert!(is_canonical(pt), "01: ItemPlain CBOR is canonical");
        if let Some(Value::Array(fs)) = get(pt, "fields") {
            for f in fs {
                out.push((bytes_of(get(f, "id").unwrap()), get(f, "icon").cloned()));
            }
        }
    }
    out
}
fn icon_of(v: &UnlockedVault, item: Uuid, field: Uuid) -> Option<String> {
    v.get(item)
        .or_else(|| v.items_including_deleted().find(|i| i.id == item))
        .unwrap()
        .field_by_id(field)
        .unwrap()
        .icon
        .clone()
}
/// Field-level snapshot including icons (lib `snap_item` predates field icons).
fn fsnap(v: &UnlockedVault) -> Vec<String> {
    let mut s: Vec<String> = v
        .items_including_deleted()
        .map(|i| {
            let f: Vec<String> = i
                .fields
                .iter()
                .map(|f| {
                    format!(
                        "{}|{}|{}|{}|{:?}",
                        f.id,
                        f.name,
                        f.value.expose_secret(),
                        f.modified_at,
                        f.icon
                    )
                })
                .collect();
            format!("{}|{}|{:?}|{:?}", i.id, i.title, i.deleted_at, f)
        })
        .collect();
    s.sort();
    s
}

/// 01 §9 "`v2-field-icon.vault` carries one item with a field whose `icon` is "key", a field
/// without the key and a field with `"icon": null`"; 01 §4 "no version bump"; "readers treat
/// missing, null or "" as none".
#[test]
fn fi01_fixture_shape_and_reader() {
    let b = fixture("v2-field-icon.vault");
    assert_eq!(version_of(&b), 2, "01 §4: field icon is no version bump");
    let o = indep::open_file(&b, FIXTURE_PW);
    let mut found = false;
    for (id, _, pt) in &o.items {
        let fs = get(pt, "fields").unwrap().as_array().unwrap();
        let key = fs
            .iter()
            .find(|f| get(f, "icon").and_then(|v| v.as_text()) == Some("key"));
        let absent = fs.iter().find(|f| get(f, "icon").is_none());
        let null = fs
            .iter()
            .find(|f| matches!(get(f, "icon"), Some(Value::Null)));
        if let (Some(k), Some(a), Some(n)) = (key, absent, null) {
            found = true;
            let v = unlock(&b).expect("fixture opens");
            let item = Uuid::from_slice(id).unwrap();
            let fid = |f: &Value| Uuid::from_slice(&bytes_of(get(f, "id").unwrap())).unwrap();
            assert_eq!(icon_of(&v, item, fid(k)).as_deref(), Some("key"));
            assert_eq!(icon_of(&v, item, fid(a)), None, "missing reads as none");
            assert_eq!(icon_of(&v, item, fid(n)), None, "null reads as none");
        }
    }
    assert!(
        found,
        "01 §9: fixture has key / absent / null fields in one item"
    );
}

/// 01 §4 "writers omit the key when there is no icon": a core round trip of the fixture keeps
/// "key" verbatim and writes neither `null` nor an empty icon; the version stays 2.
#[test]
fn fi02_core_writer_round_trip() {
    let v = unlock(&fixture("v2-field-icon.vault")).unwrap();
    let out = v.serialize();
    assert_eq!(version_of(&out), 2);
    let before = raw_icons(&fixture("v2-field-icon.vault"), FIXTURE_PW);
    let after = raw_icons(&out, FIXTURE_PW);
    for (id, ic) in &after {
        if let Some(x) = ic {
            assert!(
                matches!(x, Value::Text(s) if !s.is_empty()),
                "writer emitted icon {x:?} for field {id:?}"
            );
        }
    }
    for (id, ic) in &before {
        let a = after.iter().find(|(i, _)| i == id).unwrap();
        match ic {
            Some(Value::Text(s)) if !s.is_empty() => {
                assert_eq!(a.1, Some(Value::Text(s.clone())), "named icon kept")
            }
            _ => assert_eq!(a.1, None, "none written as an absent key"),
        }
    }
    let back = unlock(&out).unwrap();
    assert_eq!(fsnap(&back), fsnap(&v));
}

/// 01 §4 "readers treat missing, null or "" as none"; brief: `Some("")` = none. Reading "" and
/// writing `Some("")` must both end as an absent key.
#[test]
fn fi03_empty_string_is_none() {
    let (fa, fb) = (fid(), fid());
    let (b, item) = file_with(vec![
        fld(fa, "a", "text", "x", 1000, Some(t(""))),
        fld(fb, "b", "text", "y", 1000, None),
    ]);
    let mut v = unlock(&b).expect("\"\" icon opens");
    let item = Uuid::from_bytes(item);
    let read = icon_of(&v, item, Uuid::from_bytes(fa));
    eprintln!("INFO reader maps \"\" to {read:?}");
    assert!(
        read.as_deref().unwrap_or("").is_empty(),
        "\"\" reads as none, got {read:?}"
    );
    let out = v.serialize();
    for (id, ic) in raw_icons(&out, FIXTURE_PW) {
        assert_eq!(ic, None, "field {id:?}: \"\" re-written as {ic:?}");
    }
    // in memory: Some("") written by the app
    v.update(item, 5000, |it| {
        it.fields[1].icon = Some(String::new());
    })
    .unwrap();
    let out = v.serialize();
    for (id, ic) in raw_icons(&out, FIXTURE_PW) {
        assert_eq!(ic, None, "field {id:?}: Some(\"\") written as {ic:?}");
    }
}

/// 01 §4 "core validates the type only, a non-string non-null value is Malformed". No panic.
#[test]
fn fi04_hostile_icon_types() {
    let cases: Vec<(&str, Value)> = vec![
        ("int", i(7)),
        ("negint", Value::Integer((-1i64).into())),
        ("bytes", Value::Bytes(b"key".to_vec())),
        ("array", Value::Array(vec![t("key")])),
        ("map", map(vec![("kind", t("symbol"))])),
        ("bool", Value::Bool(true)),
        ("float", Value::Float(1.5)),
        ("tag", Value::Tag(32, Box::new(t("key")))),
    ];
    let mut bad = vec![];
    for (name, val) in cases {
        let (b, _) = file_with(vec![fld(fid(), "a", "text", "x", 1000, Some(val))]);
        let r = std::panic::catch_unwind(|| unlock(&b).map(|_| ()));
        match (r, name) {
            (Ok(Err(VaultError::Malformed(_))), _) => {}
            (Ok(Ok(())), "tag") => eprintln!("INFO tagged text accepted as an icon"),
            (r, _) => bad.push(format!(
                "{name}: {:?}",
                r.map(|x| x.map_err(|e| format!("{e:?}")))
            )),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 01 §4 "unknown names preserved" (05: "An unknown name (newer build) renders as no icon and is
/// preserved on save"): through edits of other parts, merge with a copy, change_password,
/// rotate_vault_key and delete/recover.
#[test]
fn fi05_unknown_names_preserved() {
    let long = "Z".repeat(10_000);
    let names = [
        "key",
        "FromTheFuture-ζ",
        long.as_str(),
        "\u{1b}[31mred\u{7}",
    ];
    let ids: Vec<[u8; 16]> = names.iter().map(|_| fid()).collect();
    let mut fields: Vec<Value> = names
        .iter()
        .zip(&ids)
        .map(|(n, id)| fld(*id, "f", "text", "v", 1000, Some(t(n))))
        .collect();
    let other = fid();
    fields.push(fld(other, "pw", "password", "old", 1000, None));
    let (b, item) = file_with(fields);
    let item = Uuid::from_bytes(item);
    let mut v = unlock(&b).unwrap();
    let check = |v: &UnlockedVault, step: &str| {
        for (n, id) in names.iter().zip(&ids) {
            assert_eq!(
                icon_of(v, item, Uuid::from_bytes(*id)).as_deref(),
                Some(*n),
                "{step}: icon lost or changed"
            );
        }
    };
    check(&v, "read");
    v.set_field(item, Uuid::from_bytes(other), pw("new"), 2000)
        .unwrap();
    v.update(item, 2001, |it| it.title = "Renamed".into())
        .unwrap();
    let mut v = unlock(&v.serialize()).unwrap();
    check(&v, "edit other field + title, round trip");
    let copy = unlock(&v.serialize()).unwrap();
    v.merge_from(&copy).unwrap();
    check(&v, "merge with own copy");
    v.change_password(
        &pw(FIXTURE_PW),
        &pw(FIXTURE_PW),
        KdfParams::for_tests(),
        3000,
    )
    .unwrap();
    v.rotate_vault_key(&pw(FIXTURE_PW), 3001).unwrap();
    let mut v = unlock(&v.serialize()).unwrap();
    check(&v, "change_password + rotate_vault_key");
    v.delete(item, 4000).unwrap();
    let mut v = unlock(&v.serialize()).unwrap();
    check(&v, "in the trash");
    v.recover(item, 5000).unwrap();
    check(&unlock(&v.serialize()).unwrap(), "recovered");
}

/// 01 §4 "a change to it alone restamps the field like a name or value change"; 02 `update`
/// recomputes item.modified_at. Removing the icon restamps too.
#[test]
fn fi06_icon_only_change_restamps() {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(FIXTURE_PW), KdfParams::for_tests(), dev);
    let mut it = Item::new("R", dev, 1000);
    it.fields
        .push(Field::new("user", FieldKind::Text, pw("u"), 1000));
    it.fields
        .push(Field::new("pass", FieldKind::Password, pw("p"), 1000));
    assert_eq!(it.fields[0].icon, None, "02: Field::new sets None");
    let (a, b) = (it.fields[0].id, it.fields[1].id);
    let id = v.insert(it, 1000);
    v.update(id, 5000, |it| it.fields[0].icon = Some("KeyRound".into()))
        .unwrap();
    let x = v.get(id).unwrap();
    assert_eq!(
        x.field_by_id(a).unwrap().modified_at,
        5000,
        "icon set restamps"
    );
    assert_eq!(
        x.field_by_id(b).unwrap().modified_at,
        1000,
        "other field untouched"
    );
    assert!(x.modified_at >= 5000);
    v.update(id, 6000, |it| it.fields[0].icon = None).unwrap();
    assert_eq!(
        v.get(id).unwrap().field_by_id(a).unwrap().modified_at,
        6000,
        "icon removal restamps"
    );
    for (_, ic) in raw_icons(&v.serialize(), FIXTURE_PW) {
        assert_eq!(ic, None);
    }
    // None -> Some("") is none -> none (01 §4); a restamp here is harmless but noted
    v.update(id, 7000, |it| it.fields[0].icon = Some(String::new()))
        .unwrap();
    let ma = v.get(id).unwrap().field_by_id(a).unwrap().modified_at;
    if ma == 7000 {
        eprintln!("INFO None -> Some(\"\") restamps the field (none -> none)");
    }
}

struct Net {
    devs: Vec<UnlockedVault>,
}
impl Net {
    fn new(n: usize) -> Net {
        let base = UnlockedVault::create(&pw("pw"), KdfParams::for_tests(), Uuid::new_v4());
        let l = LockedVault::parse(&base.serialize()).unwrap();
        let k = base.export_vault_key();
        Net {
            devs: (0..n)
                .map(|_| l.unlock_with_key(&k, Uuid::new_v4()).unwrap())
                .collect(),
        }
    }
    fn pull(&mut self, to: usize, from: usize) {
        let b = self.devs[from].serialize();
        let d = LockedVault::parse(&b)
            .unwrap()
            .unlock_with_key(&self.devs[to].export_vault_key(), self.devs[to].device_id())
            .unwrap();
        self.devs[to].merge_from(&d).unwrap();
    }
    fn all_pairs(&mut self, rounds: usize) {
        let n = self.devs.len();
        for _ in 0..rounds {
            for a in 0..n {
                for b in 0..n {
                    if a != b {
                        self.pull(a, b);
                    }
                }
            }
        }
    }
    fn converged(&self) -> bool {
        let s = fsnap(&self.devs[0]);
        self.devs.iter().all(|d| fsnap(d) == s)
    }
    /// Item with three text fields (icons: None, None, Some("Lock")) on every device.
    fn seed(&mut self, now: u64) -> (Uuid, [Uuid; 3]) {
        let d0 = self.devs[0].device_id();
        let mut it = Item::new("Seed", d0, now);
        for n in ["f", "g", "h"] {
            it.fields
                .push(Field::new(n, FieldKind::Text, pw(&format!("{n}0")), now));
        }
        it.fields[2].icon = Some("Lock".into());
        let f = [it.fields[0].id, it.fields[1].id, it.fields[2].id];
        let id = self.devs[0].insert(it, now);
        self.all_pairs(1);
        (id, f)
    }
}
fn fval(v: &UnlockedVault, item: Uuid, f: Uuid) -> String {
    v.get(item)
        .unwrap()
        .field_by_id(f)
        .unwrap()
        .value
        .expose_secret()
        .clone()
}

/// 03 §5 "name, kind, value, section and, since 2026-11-07, the field `icon` travel together with
/// no per-attribute stamp, so a rename or an icon change is an edit and a newer edit by a peer that
/// never saw the icon drops it"; tie → device id → canonical CBOR, converging in one round.
#[test]
fn fi07_merge_icon_travels_with_field() {
    // (a) icon at 2000, newer value edit at 3000 by a peer that never saw it: icon dropped
    let mut n = Net::new(2);
    let (id, [f, _, _]) = n.seed(1000);
    n.devs[0]
        .update(id, 2000, |it| it.fields[0].icon = Some("Star".into()))
        .unwrap();
    n.devs[1].set_field(id, f, pw("f-new"), 3000).unwrap();
    n.all_pairs(2);
    assert!(n.converged(), "(a) converged");
    assert_eq!(
        icon_of(&n.devs[0], id, f),
        None,
        "(a) newer edit drops icon"
    );
    assert_eq!(fval(&n.devs[0], id, f), "f-new");

    // (b) value edit at 2000, icon at 3000: whole field from the icon side (old value)
    let mut n = Net::new(2);
    let (id, [f, _, _]) = n.seed(1000);
    n.devs[1].set_field(id, f, pw("f-new"), 2000).unwrap();
    n.devs[0]
        .update(id, 3000, |it| it.fields[0].icon = Some("Star".into()))
        .unwrap();
    n.all_pairs(2);
    assert!(n.converged(), "(b) converged");
    assert_eq!(icon_of(&n.devs[1], id, f).as_deref(), Some("Star"));
    assert_eq!(fval(&n.devs[1], id, f), "f0", "(b) whole field wins");

    // (c) same-millisecond icon edits on two devices: one round converges
    let mut n = Net::new(2);
    let (id, [f, _, _]) = n.seed(1000);
    n.devs[0]
        .update(id, 2000, |it| it.fields[0].icon = Some("Mail".into()))
        .unwrap();
    n.devs[1]
        .update(id, 2000, |it| it.fields[0].icon = Some("Lock".into()))
        .unwrap();
    n.pull(0, 1);
    n.pull(1, 0);
    let (a, b) = (icon_of(&n.devs[0], id, f), icon_of(&n.devs[1], id, f));
    assert_eq!(a, b, "(c) tie converges in one round");
    assert!(matches!(a.as_deref(), Some("Mail") | Some("Lock")));

    // (d) three devices, different fields; removal of H's icon propagates
    let mut n = Net::new(3);
    let (id, [f, g, h]) = n.seed(1000);
    n.devs[0]
        .update(id, 2000, |it| it.fields[0].icon = Some("Globe".into()))
        .unwrap();
    n.devs[1]
        .update(id, 2100, |it| {
            it.fields[1].icon = Some("FromTheFuture".into())
        })
        .unwrap();
    n.devs[2]
        .update(id, 2200, |it| it.fields[2].icon = None)
        .unwrap();
    n.all_pairs(2);
    assert!(n.converged(), "(d) three devices converge");
    for d in &n.devs {
        assert_eq!(icon_of(d, id, f).as_deref(), Some("Globe"));
        assert_eq!(icon_of(d, id, g).as_deref(), Some("FromTheFuture"));
        assert_eq!(icon_of(d, id, h), None, "(d) removal propagates");
    }
    // (e) on-disk form after convergence: absent key for none, text otherwise
    for (_, ic) in raw_icons(&n.devs[2].serialize(), "pw") {
        assert!(matches!(ic, None | Some(Value::Text(_))), "{ic:?}");
    }
}

/// 01 §9: version 1 files read the key too, and `upgrade_format` keeps field icons.
#[test]
fn fi08_v1_file_and_upgrade() {
    let (ver, h, key) = empty_base(1);
    let id = fid();
    let mut f1 = field_v(None, "user", "text", "u", 1000);
    set(&mut f1, "icon", t("key"));
    let f2 = field_v(None, "pass", "password", "p", 1000);
    let b = build_file(
        ver,
        &h,
        &key,
        &[(id, 1000, item_plain("V1", [3; 16], vec![f1, f2]))],
    );
    let mut v = unlock(&b).expect("v1 with field icon opens");
    let item = Uuid::from_bytes(id);
    let icons = |v: &UnlockedVault| -> Vec<Option<String>> {
        v.get(item)
            .unwrap()
            .fields
            .iter()
            .map(|f| f.icon.clone())
            .collect()
    };
    assert_eq!(icons(&v), vec![Some("key".to_string()), None]);
    let kept = unlock(&v.serialize()).unwrap();
    assert_eq!(icons(&kept), vec![Some("key".to_string()), None], "v1 save");
    v.upgrade_format(&pw(FIXTURE_PW), 2000).unwrap();
    let out = v.serialize();
    assert_eq!(version_of(&out), 3);
    assert_eq!(
        icons(&unlock(&out).unwrap()),
        vec![Some("key".to_string()), None],
        "upgrade keeps field icons"
    );
}

fn kdbx_db() -> Vec<u8> {
    let mut db = keepass::Database::new();
    db.config.kdf_config = keepass::config::KdfConfig::Argon2 {
        iterations: 1,
        memory: 1 << 20,
        parallelism: 1,
        version: ::argon2_rs::Version::Version13,
    };
    {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected("Title", "Kp");
        e.set_unprotected("UserName", "alice");
        e.set_protected("Password", "kp-secret");
        e.set_protected("PIN", "1234");
    }
    let mut out = vec![];
    db.save(&mut out, keepass::DatabaseKey::new().with_password("k"))
        .unwrap();
    out
}
fn onepux() -> Vec<u8> {
    use std::io::Write;
    let data = br#"{"accounts":[{"attrs":{"name":"a"},"vaults":[{"attrs":{"name":"v"},"items":[
      {"uuid":"abc","favIndex":0,"createdAt":1600000000,"updatedAt":1600000001,"state":"active",
       "categoryUuid":"001",
       "details":{"loginFields":[
         {"value":"bob","name":"username","designation":"username","fieldType":"T"},
         {"value":"onepux-secret","name":"password","designation":"password","fieldType":"P"}],
         "notesPlain":"n","sections":[{"title":"S","name":"s","fields":[
           {"title":"PIN","id":"pin","value":{"concealed":"9999"}}]}]},
       "overview":{"title":"One","url":"https://one.example","tags":["t"]}}]}]}]}"#;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let opt = zip::write::SimpleFileOptions::default();
        z.start_file("export.data", opt).unwrap();
        z.write_all(data).unwrap();
        z.finish().unwrap();
    }
    buf.into_inner()
}

/// 05 §2.3 "Not carried by CSV/1PUX/KDBX import or export": CSV export holds no icon name; every
/// imported field has no icon.
#[test]
fn fi09_import_export_never_carry_icon() {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(FIXTURE_PW), KdfParams::for_tests(), dev);
    let mut it = Item::new("Exp", dev, 1000);
    it.fields
        .push(Field::new("username", FieldKind::Text, pw("u"), 1000));
    it.fields
        .push(Field::new("password", FieldKind::Password, pw("p"), 1000));
    it.fields.push(Field::new(
        "url",
        FieldKind::Url,
        pw("https://e.example"),
        1000,
    ));
    for f in &mut it.fields {
        f.icon = Some("ZqxIconNameQ".into());
    }
    v.insert(it, 1000);
    let exp = export::export_csv(&v);
    let csv = exp.0.clone();
    assert!(
        !String::from_utf8_lossy(&csv).contains("ZqxIconNameQ"),
        "CSV export carries a field icon"
    );
    let back = import_csv(&csv, &CsvMapping::default(), dev, 2000).unwrap();
    assert!(!back.is_empty());
    assert!(
        back.iter()
            .flat_map(|i| &i.fields)
            .all(|f| f.icon.is_none())
    );
    let kp = import_kdbx(&kdbx_db(), &pw("k"), None, dev, 2000).unwrap();
    assert!(!kp.is_empty());
    assert!(
        kp.iter().flat_map(|i| &i.fields).all(|f| f.icon.is_none()),
        "KDBX"
    );
    match import_1pux(&onepux(), dev, 2000) {
        Ok(items) => {
            assert!(!items.is_empty(), "1PUX produced no items");
            assert!(
                items
                    .iter()
                    .flat_map(|i| &i.fields)
                    .all(|f| f.icon.is_none()),
                "1PUX"
            );
        }
        Err(e) => panic!("hand-made 1PUX rejected: {e:?}"),
    }
}

/// 01 §4 icon is part of the field; 02 set_field pushes history for password fields. An icon
/// survives set_field and is not copied into history; a strip (02 Recently Deleted) removes the
/// fields and with them the icons.
#[test]
fn fi10_set_field_history_and_strip() {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(FIXTURE_PW), KdfParams::for_tests(), dev);
    let mut it = Item::new("H", dev, 1000);
    let mut f = Field::new("password", FieldKind::Password, pw("one"), 1000);
    f.icon = Some("KeyRound".into());
    let pf = f.id;
    it.fields.push(f);
    let id = v.insert(it, 1000);
    v.set_field(id, pf, pw("two"), 2000).unwrap();
    let v2 = unlock(&v.serialize()).unwrap();
    let x = v2.get(id).unwrap();
    assert_eq!(x.field_by_id(pf).unwrap().icon.as_deref(), Some("KeyRound"));
    assert_eq!(x.history.len(), 1);
    assert_eq!(x.history[0].value.expose_secret(), "one");
    v.delete(id, 3000).unwrap();
    v.delete_permanently(id, 4000).unwrap();
    let s = v.serialize();
    for (_, ic) in raw_icons(&s, FIXTURE_PW) {
        panic!("stripped tombstone still has a field (icon {ic:?})");
    }
}

/// Corruption sweep (every cut offset, 400 bit flips) over a file carrying field icons: clean
/// errors, never a panic, never a silent content change.
#[test]
fn fi11_corruption_sweep() {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(FIXTURE_PW), KdfParams::for_tests(), dev);
    for k in 0..3 {
        let mut it = Item::new(format!("C{k}"), dev, 1000);
        let mut f = Field::new("user", FieldKind::Text, pw("u"), 1000);
        f.icon = Some(format!("Icon{k}"));
        it.fields.push(f);
        it.fields
            .push(Field::new("pass", FieldKind::Password, pw("p"), 1000));
        v.insert(it, 1000);
    }
    let good = v.serialize();
    let want = fsnap(&v);
    for cut in 0..good.len() {
        let r = std::panic::catch_unwind(|| unlock(&good[..cut]).map(|_| ()));
        assert!(
            matches!(r, Ok(Err(_))),
            "cut at {cut}: {:?}",
            r.map(|x| x.is_ok())
        );
    }
    use rand::Rng;
    let mut rng = rand::thread_rng();
    for _ in 0..400 {
        let mut b = good.clone();
        let pos = rng.gen_range(0..b.len());
        b[pos] ^= 1 << rng.gen_range(0..8);
        let r = std::panic::catch_unwind(|| unlock(&b).map(|v| fsnap(&v)));
        match r {
            Ok(Err(_)) => {}
            Ok(Ok(s)) => assert_eq!(s, want, "flip at {pos} changed content silently"),
            Err(_) => panic!("panic on flip at {pos}"),
        }
    }
}

fn make_pkg_with_icons(d: &std::path::Path, name: &str) -> (std::path::PathBuf, Uuid, Uuid, Uuid) {
    let pkg = d.join(name);
    let mut a = Dev::create(&pkg);
    let dev = a.dev;
    let now = now_ms();
    let (id, uf, pf) =
        a.s.edit(move |v| {
            let mut it = Item::new("IconItem", dev, now);
            let mut u = Field::new("username", FieldKind::Text, pw("icon-user"), now);
            u.icon = Some("User".into());
            let mut p = Field::new(
                "password",
                FieldKind::Password,
                pw("Sekr3t-Field-Value-xyz"),
                now,
            );
            p.icon = Some("\u{1b}]0;pwn\u{7}Evil\u{1b}[2J".into());
            let (uf, pf) = (u.id, p.id);
            it.fields.push(u);
            it.fields.push(p);
            (v.insert(it, now), uf, pf)
        })
        .unwrap();
    a.s.save().unwrap();
    (pkg, id, uf, pf)
}

/// 03 §6 conflict copies of both shapes: a peer's later icon change arrives through a sibling
/// package (iCloud) and an in-package `vault*.bin` (Dropbox); both absorbed and moved to backups.
#[test]
fn fi12_conflict_copies_both_shapes_carry_icons() {
    let d = tempdir();
    let (pkg, id, uf, pf) = make_pkg_with_icons(d.path(), "fc.vault");
    let mut a = Dev::open(&pkg);
    a.s.start_watching().unwrap();
    // sibling package made by a "peer" in a staging dir, then moved next to ours
    let stage = d.path().join("stage");
    std::fs::create_dir_all(&stage).unwrap();
    copy_dir(&pkg, &stage.join("fc.vault"));
    {
        let mut p = Dev::open(&stage.join("fc.vault"));
        p.s.edit(|v| {
            v.update(id, now_ms() + 50, |it| {
                it.fields[0].icon = Some("Globe".into())
            })
        })
        .unwrap()
        .unwrap();
        p.s.save().unwrap();
    }
    std::fs::rename(stage.join("fc.vault"), d.path().join("fc 2.vault")).unwrap();
    assert!(
        a.wait_for(15, |e| e.iter().any(|x| x.contains("ConflictAbsorbed"))),
        "sibling package absorbed: {:?}",
        a.seen
    );
    assert_eq!(icon_of(a.v(), id, uf).as_deref(), Some("Globe"));
    // per-file copy
    copy_dir(&pkg, &stage.join("fc.vault"));
    {
        let mut p = Dev::open(&stage.join("fc.vault"));
        p.s.edit(|v| v.update(id, now_ms() + 50, |it| it.fields[1].icon = None))
            .unwrap()
            .unwrap();
        p.s.save().unwrap();
    }
    a.seen.clear();
    std::fs::copy(
        stage.join("fc.vault/vault.bin"),
        pkg.join("vault (Mac's conflicted copy 2026-11-08).bin"),
    )
    .unwrap();
    assert!(
        a.wait_for(15, |e| e.iter().any(|x| x.contains("ConflictAbsorbed"))),
        "per-file copy absorbed: {:?}",
        a.seen
    );
    assert_eq!(icon_of(a.v(), id, pf), None, "peer's icon removal merged");
    a.s.save().unwrap();
    let disk = read_vault(&pkg);
    assert_eq!(icon_of(&disk, id, uf).as_deref(), Some("Globe"));
    assert_eq!(icon_of(&disk, id, pf), None);
    assert!(!d.path().join("fc 2.vault").exists(), "sibling moved");
    assert!(
        !pkg.join("vault (Mac's conflicted copy 2026-11-08).bin")
            .exists()
    );
}

fn vault_bin() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/vault")
}
fn cli(pkg: &std::path::Path, password: &str, args: &[&str]) -> (i32, String) {
    let out = Command::new(vault_bin())
        .arg("--vault")
        .arg(pkg)
        .args(["--password-env", "QA_MPW"])
        .args(args)
        .env("QA_MPW", password)
        .env_remove("VAULT_FILE")
        .output()
        .unwrap();
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), s)
}
fn no_controls(s: &str) -> bool {
    !s.chars()
        .any(|c| (c.is_control() && c != '\n' && c != '\t') || ('\u{80}'..='\u{9f}').contains(&c))
}

/// CLI end to end on a vault with field icons (02 "CLI output never printing secrets", D-7
/// sanitising): get / get --reveal / edit --set / edit --title / export / rm keep icons, print no
/// secret without --reveal and no raw control characters; 05 "no CLI flag".
#[test]
fn fi13_cli_paths_keep_icons() {
    let d = tempdir();
    let (pkg, id, uf, pf) = make_pkg_with_icons(d.path(), "cl.vault");
    let (rc, o) = cli(&pkg, PW, &["get", "IconItem"]);
    assert_eq!(rc, 0, "{o}");
    assert!(
        !o.contains("Sekr3t-Field-Value-xyz"),
        "get prints the password"
    );
    assert!(no_controls(&o), "raw control chars in get: {o:?}");
    let (rc, o) = cli(&pkg, PW, &["get", "IconItem", "--reveal", "--ids"]);
    assert_eq!(rc, 0, "{o}");
    assert!(o.contains("Sekr3t-Field-Value-xyz"));
    assert!(no_controls(&o), "raw control chars in get --reveal: {o:?}");
    if o.contains("Evil") || o.contains("User\n") {
        eprintln!("INFO get prints field icon names");
    }
    let (rc, o) = cli(
        &pkg,
        PW,
        &["edit", "IconItem", "--set", "username=renamed-user"],
    );
    assert_eq!(rc, 0, "{o}");
    let (rc, o) = cli(
        &pkg,
        PW,
        &["edit", "IconItem", "--title", "IconItem2", "--tag", "x"],
    );
    assert_eq!(rc, 0, "{o}");
    let v = read_vault(&pkg);
    assert_eq!(fval(&v, id, uf), "renamed-user");
    assert_eq!(
        icon_of(&v, id, uf).as_deref(),
        Some("User"),
        "edit --set keeps icon"
    );
    assert_eq!(
        icon_of(&v, id, pf).as_deref(),
        Some("\u{1b}]0;pwn\u{7}Evil\u{1b}[2J"),
        "edit keeps other icons verbatim"
    );
    let out = d.path().join("e.csv");
    let (rc, o) = cli(
        &pkg,
        PW,
        &["export", "--out", out.to_str().unwrap(), "--yes"],
    );
    assert_eq!(rc, 0, "{o}");
    let csv = std::fs::read_to_string(&out).unwrap();
    assert!(
        !csv.contains("Evil") && !csv.contains(",User"),
        "export carries icons: {csv}"
    );
    std::fs::remove_file(&out).unwrap();
    let (rc, o) = cli(&pkg, PW, &["rm", "IconItem2"]);
    assert_eq!(rc, 0, "{o}");
    let v = read_vault(&pkg);
    assert_eq!(
        icon_of(&v, id, uf).as_deref(),
        Some("User"),
        "trash keeps icons"
    );
    let (_, help) = cli(&pkg, PW, &["add", "--help"]);
    assert!(
        !help.to_lowercase().contains("field-icon"),
        "05: no CLI flag"
    );
}

/// 01 §9 + CLI `upgrade` and `sync`: a version 1 package with a field icon upgrades with the icon,
/// and `vault sync` absorbs a per-file copy whose newer field carries a new icon.
#[test]
fn fi14_cli_upgrade_and_sync() {
    let d = tempdir();
    let (ver, h, key) = empty_base(1);
    let id = fid();
    let mut f1 = field_v(None, "user", "text", "u", 1000);
    set(&mut f1, "icon", t("FromTheFuture"));
    let b = build_file(
        ver,
        &h,
        &key,
        &[(id, 1000, item_plain("Up", [3; 16], vec![f1]))],
    );
    let pkg = d.path().join("up.vault");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(pkg.join("vault.bin"), &b).unwrap();
    let (rc, o) = cli(&pkg, FIXTURE_PW, &["upgrade"]);
    assert_eq!(rc, 0, "{o}");
    let nb = std::fs::read(pkg.join("vault.bin")).unwrap();
    assert_eq!(version_of(&nb), 3);
    let v = unlock(&nb).unwrap();
    let item = Uuid::from_bytes(id);
    assert_eq!(
        v.get(item).unwrap().fields[0].icon.as_deref(),
        Some("FromTheFuture"),
        "upgrade keeps field icon"
    );
    // sync: per-file copy with a newer icon
    let fid0 = v.get(item).unwrap().fields[0].id;
    let mut peer = unlock(&nb).unwrap();
    peer.update(item, now_ms(), |it| {
        it.fields[0].icon = Some("Globe".into())
    })
    .unwrap();
    std::fs::write(pkg.join("vault 2.bin"), peer.serialize()).unwrap();
    let (rc, o) = cli(&pkg, FIXTURE_PW, &["sync"]);
    assert_eq!(rc, 0, "{o}");
    let v = unlock(&std::fs::read(pkg.join("vault.bin")).unwrap()).unwrap();
    assert_eq!(
        icon_of(&v, item, fid0).as_deref(),
        Some("Globe"),
        "sync merged icon"
    );
    assert!(!pkg.join("vault 2.bin").exists(), "copy moved to backups");
}

/// 03 §5 field tie "tie → greater `device_id` of the owning item; tie → greater canonical CBOR
/// bytes of the field (symmetric, so both devices converge in one round)": with a cloned device id
/// and the same millisecond, only the icon differs, so the icon must be part of those bytes.
#[test]
fn fi15_cloned_device_icon_tie_converges() {
    let base = UnlockedVault::create(&pw("pw"), KdfParams::for_tests(), Uuid::new_v4());
    let l = LockedVault::parse(&base.serialize()).unwrap();
    let k = base.export_vault_key();
    let dev = Uuid::new_v4();
    let mut a = l.unlock_with_key(&k, dev).unwrap();
    let mut it = Item::new("T", dev, 1000);
    it.fields
        .push(Field::new("f", FieldKind::Text, pw("same"), 1000));
    let f = it.fields[0].id;
    let id = a.insert(it, 1000);
    let mut b = LockedVault::parse(&a.serialize())
        .unwrap()
        .unlock_with_key(&k, dev)
        .unwrap();
    a.update(id, 2000, |it| it.fields[0].icon = Some("Mail".into()))
        .unwrap();
    b.update(id, 2000, |it| it.fields[0].icon = Some("Lock".into()))
        .unwrap();
    for case in ["icon vs icon", "icon vs none"] {
        if case == "icon vs none" {
            a.update(id, 3000, |it| it.fields[0].icon = Some("Mail".into()))
                .unwrap();
            a.update(id, 3000, |it| it.fields[0].icon = Some("Star".into()))
                .unwrap();
            b.update(id, 3000, |it| it.fields[0].icon = None).unwrap();
        }
        let disk = |v: &UnlockedVault| {
            LockedVault::parse(&v.serialize())
                .unwrap()
                .unlock_with_key(&k, dev)
                .unwrap()
        };
        let (da, db) = (disk(&a), disk(&b));
        a.merge_from(&db).unwrap();
        b.merge_from(&da).unwrap();
        assert_eq!(
            icon_of(&a, id, f),
            icon_of(&b, id, f),
            "{case}: no convergence after one exchange"
        );
        let (da, db) = (disk(&a), disk(&b));
        a.merge_from(&db).unwrap();
        b.merge_from(&da).unwrap();
        assert_eq!(fsnap(&a), fsnap(&b), "{case}: not fully equal after two");
    }
}

/// 01 §4 `Some("")` = none and 03 §5 "Merge is idempotent": a side holding `Some("")` in memory
/// against a peer with `None` settles; merges stop reporting updates and stamps stop moving.
#[test]
fn fi16_empty_icon_in_memory_settles() {
    let mut n = Net::new(2);
    let (id, [f, _, _]) = n.seed(1000);
    n.devs[0]
        .update(id, 2000, |it| it.fields[0].icon = Some(String::new()))
        .unwrap();
    n.all_pairs(3);
    let ma: Vec<u64> = n
        .devs
        .iter()
        .map(|d| d.get(id).unwrap().modified_at)
        .collect();
    n.all_pairs(2);
    let ma2: Vec<u64> = n
        .devs
        .iter()
        .map(|d| d.get(id).unwrap().modified_at)
        .collect();
    assert_eq!(ma, ma2, "stamps keep moving: ping-pong");
    let b = n.devs[1].serialize();
    let d = LockedVault::parse(&b)
        .unwrap()
        .unlock_with_key(&n.devs[0].export_vault_key(), n.devs[0].device_id())
        .unwrap();
    let r = n.devs[0].merge_from(&d).unwrap();
    assert_eq!(r.updated, 0, "merge still reports an update: {r:?}");
    for d in &n.devs {
        assert!(icon_of(d, id, f).unwrap_or_default().is_empty());
    }
}

/// Added during the code read (still spec-derived). 05 §2.5 field drag-to-reorder; 03 §5 "unknown
/// extras and anything without a stamp follow whichever item has the greater `modified_at`"; 02
/// `update` restamps the item. A reorder alone must persist, reach a peer, and converge; icons
/// travel with their fields.
#[test]
fn fi17_reorder_propagates_and_converges() {
    let mut n = Net::new(3);
    let (id, [f, g, h]) = n.seed(1000);
    let order = |v: &UnlockedVault| -> Vec<Uuid> {
        v.get(id).unwrap().fields.iter().map(|x| x.id).collect()
    };
    n.devs[0]
        .update(id, 2000, |it| {
            let last = it.fields.pop().unwrap();
            it.fields.insert(0, last);
        })
        .unwrap();
    assert_eq!(order(&n.devs[0]), vec![h, f, g]);
    let back = LockedVault::parse(&n.devs[0].serialize())
        .unwrap()
        .unlock_with_key(&n.devs[0].export_vault_key(), n.devs[0].device_id())
        .unwrap();
    assert_eq!(order(&back), vec![h, f, g], "reorder persists");
    assert!(
        n.devs[0].get(id).unwrap().modified_at >= 2000,
        "reorder restamps the item"
    );
    n.all_pairs(2);
    for (k, d) in n.devs.iter().enumerate() {
        assert_eq!(order(d), vec![h, f, g], "device {k} order");
        assert_eq!(icon_of(d, id, h).as_deref(), Some("Lock"));
    }
    assert!(n.converged());
}
