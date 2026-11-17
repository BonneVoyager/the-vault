//! Icons after the 2026-11-16 catalog change, written from the specs before reading the source:
//! 01 §4 item `icon` ("app-interpreted icon choice ... core validates types only; unknown keys
//! inside the map are preserved"), 01 §4 `Field.icon` ("any identifier of the bundled Lucide
//! catalog since 2026-11-16 ... core validates the type only"), 05 §2.3 ("a stored icon of kind
//! "logo" is treated as no icon", "A stored colour outside the 8-swatch palette (the CLI accepts any
//! #RRGGBB)"), 03 §5 (icon merged by its own stamp; field icon travels with the field), 01 §9
//! ("a test opens every fixture in that directory with the current reader"), 03 §2 64 MiB cap.
use secrecy::ExposeSecret;
use spec_checks::dev::*;
use spec_checks::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;
use vault_core::*;

fn new_vault() -> UnlockedVault {
    UnlockedVault::create(&pw(FIXTURE_PW), KdfParams::for_tests(), Uuid::new_v4())
}
fn reopen(v: &UnlockedVault) -> UnlockedVault {
    LockedVault::parse(&v.serialize())
        .unwrap()
        .unlock(&pw(FIXTURE_PW))
        .unwrap()
}
fn odd_identifiers() -> Vec<String> {
    vec![
        "a-arrow-down".into(),
        "AArrowDown".into(),
        "KeyRound".into(),
        "key-round".into(),
        "Key Round".into(),
        " ".into(),
        "nul\0inside".into(),
        "\u{1b}[31mred\u{7}".into(),
        "line\nbreak\r".into(),
        "../../../etc/passwd".into(),
        "/absolute/path.svg".into(),
        "icons/star.svg".into(),
        "\u{202e}rtl".into(),
        "🔑".into(),
        "e\u{301}".into(),
        "symbol:Star:#123456".into(),
        "x".repeat(256 * 1024),
    ]
}
fn odd_colours() -> Vec<Option<String>> {
    vec![
        None,
        Some("#123456".into()),
        Some("#abcdef".into()),
        Some("#FFF".into()),
        Some("red".into()),
        Some("".into()),
        Some("#GGGGGG".into()),
        Some("javascript:alert(1)".into()),
        Some("#".repeat(10_000)),
    ]
}

/// ic01: 01 §4 "core validates types only": any string in kind, value and colour round-trips
/// exactly through serialize/parse/unlock, and the independent decoder sees the same strings in
/// canonical CBOR.
#[test]
fn ic01_item_icon_any_strings_round_trip() {
    let mut v = new_vault();
    let dev = v.device_id();
    let mut want = vec![];
    let kinds = ["symbol", "logo", "letter", "image", "", "future-kind"];
    let ids = odd_identifiers();
    let cols = odd_colours();
    let mut n = 0u64;
    for (k, kind) in kinds.iter().enumerate() {
        for (j, val) in ids.iter().enumerate() {
            let col = cols[(k + j) % cols.len()].clone();
            n += 1;
            let id = v.insert(Item::new(format!("I{n}"), dev, 1000 + n), 1000 + n);
            let mut icon = ItemIcon::new(*kind, val.clone());
            icon.color = col.clone();
            let ic = icon.clone();
            v.update(id, 2000 + n, move |it| it.icon = Some(ic))
                .unwrap();
            want.push((id, icon));
        }
    }
    let bytes = v.serialize();
    let r = LockedVault::parse(&bytes)
        .unwrap()
        .unlock(&pw(FIXTURE_PW))
        .unwrap();
    for (id, icon) in &want {
        assert_eq!(
            r.get(*id).unwrap().icon.as_ref(),
            Some(icon),
            "{}",
            icon.kind
        );
    }
    let o = indep::open_file(&bytes, FIXTURE_PW);
    let mut seen = 0;
    for (id, _, pt) in &o.items {
        assert!(is_canonical(pt));
        let (_, icon) = want
            .iter()
            .find(|(w, _)| w.as_bytes().as_slice() == id.as_slice())
            .unwrap();
        let m = get(pt, "icon").expect("icon key written");
        assert_eq!(get(m, "kind"), Some(&t(&icon.kind)));
        assert_eq!(get(m, "value"), Some(&t(&icon.value)));
        match &icon.color {
            Some(c) => assert_eq!(get(m, "color"), Some(&t(c))),
            None => assert!(
                matches!(get(m, "color"), None | Some(Value::Null)),
                "colour None written as {:?}",
                get(m, "color")
            ),
        }
        seen += 1;
    }
    assert_eq!(seen, want.len());
}

/// ic02: 03 §5 icon merged by its own stamp, two and three devices: an odd catalog identifier
/// with a non-palette colour set last wins over an older legacy logo, independently of a title
/// edit on a third device; all converge.
#[test]
fn ic02_item_icon_merge_three_devices() {
    let mut a = new_vault();
    let id = a.insert(Item::new("Base", a.device_id(), 1000), 1000);
    let base = a.serialize();
    let open = |b: &[u8]| {
        LockedVault::parse(b)
            .unwrap()
            .unlock(&pw(FIXTURE_PW))
            .unwrap()
    };
    let mut b = open(&base);
    let mut c = open(&base);
    let mut ic_new = ItemIcon::new("symbol", "a-arrow-down");
    ic_new.color = Some("#123456".into());
    let x = ic_new.clone();
    a.update(id, 3000, move |it| it.icon = Some(x)).unwrap();
    b.update(id, 2500, |it| it.title = "Renamed".into())
        .unwrap();
    c.update(id, 1500, |it| {
        it.icon = Some(ItemIcon::new("logo", "github"))
    })
    .unwrap();
    for _ in 0..3 {
        let (sa, sb, sc) = (reopen(&a), reopen(&b), reopen(&c));
        a.merge_from(&sb).unwrap();
        a.merge_from(&sc).unwrap();
        b.merge_from(&sa).unwrap();
        b.merge_from(&sc).unwrap();
        c.merge_from(&sa).unwrap();
        c.merge_from(&sb).unwrap();
    }
    for v in [&a, &b, &c] {
        let it = v.get(id).unwrap();
        assert_eq!(it.icon.as_ref(), Some(&ic_new));
        assert_eq!(it.title, "Renamed");
    }
    assert_eq!(snap_vault(&a), snap_vault(&b));
    assert_eq!(snap_vault(&a), snap_vault(&c));
    // idempotent
    let before = snap_vault(&a);
    let sa = reopen(&a);
    a.merge_from(&sa).unwrap();
    assert_eq!(snap_vault(&a), before);
}

/// ic03: cloned device, same millisecond, two different odd icons: converge within two rounds
/// (03 §5 "tie → greater canonical CBOR bytes of that attribute").
#[test]
fn ic03_item_icon_cloned_device_tie_converges() {
    for (x, y) in [
        ("a-arrow-down", "AArrowDown"),
        ("", "Star"),
        ("\u{1b}x", "x"),
        ("logo-like", "logo-like "),
    ] {
        let mut a = new_vault();
        let id = a.insert(Item::new("T", a.device_id(), 1000), 1000);
        let mut b = reopen(&a);
        a.update(id, 5000, |it| it.icon = Some(ItemIcon::new("symbol", x)))
            .unwrap();
        let mut ib = ItemIcon::new("logo", y);
        ib.color = Some("#010203".into());
        b.update(id, 5000, move |it| it.icon = Some(ib)).unwrap();
        for _ in 0..2 {
            let (sa, sb) = (reopen(&a), reopen(&b));
            a.merge_from(&sb).unwrap();
            b.merge_from(&sa).unwrap();
        }
        assert_eq!(
            a.get(id).unwrap().icon,
            b.get(id).unwrap().icon,
            "{x:?} vs {y:?}"
        );
        assert_eq!(snap_vault(&a), snap_vault(&b), "{x:?} vs {y:?}");
    }
}

fn logo_item(v: &UnlockedVault) -> Uuid {
    v.items()
        .find(|i| i.icon.as_ref().is_some_and(|c| c.kind == "logo"))
        .expect("v1-icon.vault carries a logo icon (01 §9)")
        .id
}

/// ic04: 05 §2.3 "a stored icon of kind "logo" is treated as no icon" is an app rule: core keeps
/// the legacy logo through an edit of another attribute, serialization and merge, and a peer's
/// newer symbol replaces it on both sides.
#[test]
fn ic04_legacy_logo_loads_keeps_and_merges() {
    let bytes = fixture("v1-icon.vault");
    let mut v = LockedVault::parse(&bytes)
        .unwrap()
        .unlock(&pw(FIXTURE_PW))
        .unwrap();
    let id = logo_item(&v);
    let logo = v.get(id).unwrap().icon.clone();
    let untouched = LockedVault::parse(&bytes)
        .unwrap()
        .unlock(&pw(FIXTURE_PW))
        .unwrap();
    let now = now_ms();
    v.update(id, now, |it| it.title = "Edited".into()).unwrap();
    let mut r = reopen(&v);
    assert_eq!(r.get(id).unwrap().icon, logo, "title edit keeps the logo");
    r.merge_from(&untouched).unwrap();
    assert_eq!(r.get(id).unwrap().icon, logo);
    assert_eq!(r.get(id).unwrap().title, "Edited");
    let mut u = reopen(&untouched);
    u.merge_from(&r).unwrap();
    assert_eq!(
        u.get(id).unwrap().icon,
        logo,
        "untouched side adopts title, keeps logo"
    );
    assert_eq!(u.get(id).unwrap().title, "Edited");
    // a peer replaces the logo with a catalog symbol later: wins on both sides
    let mut peer = reopen(&u);
    peer.update(id, now + 10, |it| {
        it.icon = Some(ItemIcon::new("symbol", "github"))
    })
    .unwrap();
    r.merge_from(&reopen(&peer)).unwrap();
    assert_eq!(r.get(id).unwrap().icon.as_ref().unwrap().kind, "symbol");
    let pr = reopen(&r);
    peer.merge_from(&pr).unwrap();
    assert_eq!(snap_vault(&peer), snap_vault(&r));
    // version 1 file stays version 1 on save
    assert_eq!(version_of(&v.serialize()), version_of(&bytes));
}

/// ic05: 01 §4 Field.icon "any identifier of the bundled Lucide catalog": catalog-style names in
/// both spellings and odd strings round-trip and travel with the field in a merge; a newer
/// icon-only change on one device wins on both.
#[test]
fn ic05_field_icon_any_identifier_round_trip_and_merge() {
    let mut a = new_vault();
    let dev = a.device_id();
    let mut it = Item::new("F", dev, 1000);
    let ids = odd_identifiers();
    for (k, name) in ids.iter().enumerate() {
        let mut f = Field::new(format!("f{k}"), FieldKind::Text, pw("v"), 1000);
        f.icon = Some(name.clone());
        it.fields.push(f);
    }
    let id = a.insert(it, 1000);
    let r = reopen(&a);
    let got: Vec<Option<String>> = r
        .get(id)
        .unwrap()
        .fields
        .iter()
        .map(|f| f.icon.clone())
        .collect();
    let want: Vec<Option<String>> = ids
        .iter()
        .map(|s| if s.is_empty() { None } else { Some(s.clone()) })
        .collect();
    assert_eq!(got, want);
    // merge: B changes only field 0's icon later; A changes field 1's value later
    let mut b = reopen(&a);
    let f0 = a.get(id).unwrap().fields[0].id;
    let f1 = a.get(id).unwrap().fields[1].id;
    b.update(id, 4000, |it| {
        it.fields.iter_mut().find(|f| f.id == f0).unwrap().icon = Some("circle-dashed".into())
    })
    .unwrap();
    a.set_field(id, f1, pw("new"), 4100).unwrap();
    for _ in 0..2 {
        let (sa, sb) = (reopen(&a), reopen(&b));
        a.merge_from(&sb).unwrap();
        b.merge_from(&sa).unwrap();
    }
    for v in [&a, &b] {
        let i = v.get(id).unwrap();
        assert_eq!(
            i.field_by_id(f0).unwrap().icon.as_deref(),
            Some("circle-dashed")
        );
        assert_eq!(i.field_by_id(f1).unwrap().value.expose_secret(), "new");
        assert_eq!(
            i.field_by_id(f1).unwrap().icon.as_deref(),
            Some("AArrowDown")
        );
    }
    assert_eq!(snap_vault(&a), snap_vault(&b));
}

/// ic06: 03 §2 "a save ... whose sealed bytes exceed 64 MiB is refused with `VaultTooLarge` ...
/// the file on disk is unchanged and the in-memory vault stays dirty": an icon string is not a
/// way around the cap, and a save succeeds again once the icon is replaced.
#[test]
fn ic06_huge_icon_hits_the_save_cap_cleanly() {
    let d = tempdir();
    let p = d.path().join("big.vault");
    let mut a = Dev::create(&p);
    let id = a.add_login("Big", now_ms());
    a.s.save().unwrap();
    let before = std::fs::read(p.join("vault.bin")).unwrap();
    let huge = "k".repeat(65 * 1024 * 1024);
    a.s.edit(move |v| {
        v.update(id, now_ms(), |it| {
            it.icon = Some(ItemIcon::new("symbol", huge))
        })
    })
    .unwrap()
    .unwrap();
    let e = a.s.save().expect_err("65 MiB icon must not save");
    assert!(format!("{e:?}").starts_with("VaultTooLarge"), "{e:?}");
    assert_eq!(std::fs::read(p.join("vault.bin")).unwrap(), before);
    assert!(a.s.is_dirty());
    assert!(!ls(&p).iter().any(|n| n.contains(".tmp")), "{:?}", ls(&p));
    a.s.edit(move |v| {
        v.update(id, now_ms(), |it| {
            it.icon = Some(ItemIcon::new("symbol", "Star"))
        })
    })
    .unwrap()
    .unwrap();
    a.s.save().unwrap();
    assert_eq!(
        read_vault(&p).get(id).unwrap().icon.as_ref().unwrap().value,
        "Star"
    );
}

/// ic07: 01 §9 "a test opens every fixture in that directory with the current reader": every
/// committed `.vault` fixture parses, unlocks with the fixture password, re-serialises and
/// re-opens to the same items, at its own version.
#[test]
fn ic07_every_fixture_opens_and_round_trips() {
    let mut n = 0;
    for e in std::fs::read_dir(fixtures_dir()).unwrap() {
        let p = e.unwrap().path();
        if p.extension().and_then(|x| x.to_str()) != Some("vault") || !p.is_file() {
            continue;
        }
        let b = std::fs::read(&p).unwrap();
        let v = LockedVault::parse(&b)
            .unwrap_or_else(|e| panic!("{p:?}: {e:?}"))
            .unlock(&pw(FIXTURE_PW))
            .unwrap_or_else(|e| panic!("{p:?}: {e:?}"));
        let b2 = v.serialize();
        assert_eq!(version_of(&b2), version_of(&b), "{p:?}");
        let v2 = LockedVault::parse(&b2)
            .unwrap()
            .unlock(&pw(FIXTURE_PW))
            .unwrap();
        assert_eq!(snap_vault(&v), snap_vault(&v2), "{p:?}");
        n += 1;
    }
    assert!(n >= 8, "only {n} fixtures");
}

// ---------------------------------------------------------------------------------------------
// CLI: `--icon symbol:<name>[:#RRGGBB]` (vault edit --help) with odd names; hostile icons from a
// peer file through get/list/export/sync/upgrade.
// ---------------------------------------------------------------------------------------------
fn vault_bin() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/vault")
}
fn cli(pkg: &Path, args: &[&str]) -> (i32, Vec<u8>) {
    let o = Command::new(vault_bin())
        .arg("--vault")
        .arg(pkg)
        .args(["--password-env", "QA_MPW"])
        .args(args)
        .env("QA_MPW", PW)
        .env_remove("VAULT_FILE")
        .env_remove("VAULT_DEVICE_ID")
        .output()
        .unwrap();
    let mut s = o.stdout.clone();
    s.extend_from_slice(&o.stderr);
    (o.status.code().unwrap_or(-1), s)
}
fn no_raw_controls(out: &[u8]) -> bool {
    !out.iter()
        .any(|&b| b == 0x1b || b == 0x07 || b == 0 || b == b'\r')
}

/// ic08: the CLI stores any non-empty `symbol:<name>` verbatim (05 §2.3 "`Field.icon` may hold any
/// Lucide identifier"; the item icon value is app-interpreted, 01 §4), lower- and upper-case
/// #RRGGBB both accepted ("the CLI accepts any #RRGGBB"), and `get` never prints raw control bytes.
#[test]
fn ic08_cli_symbol_identifiers_stored_verbatim() {
    let d = tempdir();
    let p = d.path().join("ic.vault");
    let mut a = Dev::create(&p);
    let id = a.add_login("Ico", now_ms());
    a.s.save().unwrap();
    drop(a);
    let ids = id.to_string();
    let cases: Vec<(String, String, Option<String>)> = vec![
        ("symbol:a-arrow-down".into(), "a-arrow-down".into(), None),
        (
            "symbol:AArrowDown:#abcdef".into(),
            "AArrowDown".into(),
            Some("#abcdef".into()),
        ),
        (
            "symbol:Star:#ABCDEF".into(),
            "Star".into(),
            Some("#ABCDEF".into()),
        ),
        ("symbol:NotInCatalog".into(), "NotInCatalog".into(), None),
        ("symbol:../../x".into(), "../../x".into(), None),
        (
            "symbol:\u{1b}[2Jboom\u{7}".into(),
            "\u{1b}[2Jboom\u{7}".into(),
            None,
        ),
        ("symbol:🔑".into(), "🔑".into(), None),
        (
            format!("symbol:{}", "y".repeat(100_000)),
            "y".repeat(100_000),
            None,
        ),
    ];
    for (arg, val, col) in &cases {
        let (rc, out) = cli(&p, &["edit", &ids, "--icon", arg]);
        let short: String = arg.chars().take(40).collect();
        assert_eq!(rc, 0, "{short:?}: {}", String::from_utf8_lossy(&out));
        let ic = read_vault(&p).get(id).unwrap().icon.clone().unwrap();
        assert_eq!(
            (ic.kind.as_str(), &ic.value, &ic.color),
            ("symbol", val, col),
            "{short:?}"
        );
        let (rc, out) = cli(&p, &["get", &ids]);
        assert_eq!(rc, 0);
        assert!(no_raw_controls(&out), "{short:?}: raw control bytes in get");
        let (rc, out) = cli(&p, &["list"]);
        assert_eq!(rc, 0);
        assert!(no_raw_controls(&out));
    }
    // refused shapes leave the stored icon alone
    let before = read_vault(&p).get(id).unwrap().icon.clone();
    for bad in [
        "symbol:",
        "symbol:Star:#12345",
        "symbol:Star:red",
        "logo:github",
        "image:x",
        "",
    ] {
        let (rc, _) = cli(&p, &["edit", &ids, "--icon", bad]);
        assert_ne!(rc, 0, "{bad:?} accepted");
        assert_eq!(read_vault(&p).get(id).unwrap().icon, before, "{bad:?}");
    }
    let (rc, _) = cli(&p, &["edit", &ids, "--icon", "auto"]);
    assert_eq!(rc, 0);
    assert!(
        read_vault(&p).get(id).unwrap().icon.is_none(),
        "auto clears"
    );
}

/// ic09: hostile icons arriving from a peer file (any kind/value/colour strings, 01 §4) through
/// the CLI: get, list, export, edit of another attribute (icon kept), sync of an in-package copy
/// and a sibling package, all exit 0 with no raw control bytes; legacy kind "logo" is kept.
#[test]
fn ic09_cli_with_hostile_icons_from_peer() {
    let d = tempdir();
    let p = d.path().join("hi.vault");
    let mut a = Dev::create(&p);
    let dev = a.dev;
    let mut ids = vec![];
    for (k, (kind, val, col)) in [
        ("logo", "\u{1b}]0;title\u{7}", Some("javascript:alert(1)")),
        ("symbol", "nul\0x", Some("#FFF")),
        ("image", "not-a-uuid", None),
        ("", "", Some("")),
        ("future", "../../../etc/passwd", Some("#GGGGGG")),
    ]
    .into_iter()
    .enumerate()
    {
        let now = now_ms() + k as u64;
        let mut icon = ItemIcon::new(kind, val);
        icon.color = col.map(String::from);
        let id =
            a.s.edit(move |v| {
                let id = v.insert(Item::new(format!("H{k}"), dev, now), now);
                v.update(id, now, |it| it.icon = Some(icon)).unwrap();
                id
            })
            .unwrap();
        ids.push(id);
    }
    a.s.save().unwrap();
    drop(a);
    let snap = |p: &Path| {
        let v = read_vault(p);
        ids.iter()
            .map(|i| v.get(*i).unwrap().icon.clone())
            .collect::<Vec<_>>()
    };
    let want = snap(&p);
    for args in [
        vec!["list"],
        vec!["get", "H0"],
        vec!["get", "H1", "--reveal"],
        vec!["get", "H4"],
    ] {
        let (rc, out) = cli(&p, &args);
        assert_eq!(rc, 0, "{args:?}: {}", String::from_utf8_lossy(&out));
        assert!(no_raw_controls(&out), "{args:?}: raw control bytes");
    }
    let csv = d.path().join("x.csv");
    let (rc, out) = cli(&p, &["export", "--out", csv.to_str().unwrap(), "--yes"]);
    assert_eq!(rc, 0, "{}", String::from_utf8_lossy(&out));
    let c = std::fs::read_to_string(&csv).unwrap();
    assert!(
        !c.contains("javascript:") && !c.contains("etc/passwd"),
        "icon in CSV: {c}"
    );
    let (rc, out) = cli(&p, &["edit", "H0", "--tag", "x"]);
    assert_eq!(rc, 0, "{}", String::from_utf8_lossy(&out));
    assert_eq!(snap(&p), want, "edit of another attribute keeps every icon");
    // conflict copies of both shapes carrying a newer odd icon
    let mut peer = read_vault(&p);
    let id0 = ids[0];
    peer.update(id0, now_ms() + 100, |it| {
        it.icon = Some(ItemIcon::new("symbol", "\u{1b}[31mpeer"))
    })
    .unwrap();
    std::fs::write(p.join("vault 2.bin"), peer.serialize()).unwrap();
    let (rc, out) = cli(&p, &["sync"]);
    assert_eq!(rc, 0, "{}", String::from_utf8_lossy(&out));
    assert!(no_raw_controls(&out));
    assert_eq!(
        read_vault(&p)
            .get(id0)
            .unwrap()
            .icon
            .as_ref()
            .unwrap()
            .value,
        "\u{1b}[31mpeer"
    );
    let sib = d.path().join("hi 2.vault");
    std::fs::create_dir_all(&sib).unwrap();
    let mut peer = read_vault(&p);
    peer.update(id0, now_ms() + 200, |it| {
        it.icon = Some(ItemIcon::new("logo", "back"))
    })
    .unwrap();
    std::fs::write(sib.join("vault.bin"), peer.serialize()).unwrap();
    let (rc, out) = cli(&p, &["sync"]);
    assert_eq!(rc, 0, "{}", String::from_utf8_lossy(&out));
    let ic = read_vault(&p).get(id0).unwrap().icon.clone().unwrap();
    assert_eq!((ic.kind.as_str(), ic.value.as_str()), ("logo", "back"));
    assert!(!sib.exists() && !p.join("vault 2.bin").exists());
}

/// ic10: the CLI on the committed v1-icon fixture (symbol with colour, logo without, icon-less):
/// get/list work; an edit of the logo item's title keeps the logo; `--icon auto` clears it;
/// `upgrade` keeps every remaining icon.
#[test]
fn ic10_cli_on_icon_fixture() {
    let d = tempdir();
    let p = d.path().join("fx.vault");
    std::fs::create_dir_all(&p).unwrap();
    std::fs::write(p.join("vault.bin"), fixture("v1-icon.vault")).unwrap();
    let run = |args: &[&str]| {
        let o = Command::new(vault_bin())
            .arg("--vault")
            .arg(&p)
            .args(["--password-env", "QA_FPW"])
            .args(args)
            .env("QA_FPW", FIXTURE_PW)
            .env_remove("VAULT_FILE")
            .output()
            .unwrap();
        (
            o.status.code().unwrap_or(-1),
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
        )
    };
    let open = || {
        LockedVault::parse(&std::fs::read(p.join("vault.bin")).unwrap())
            .unwrap()
            .unlock(&pw(FIXTURE_PW))
            .unwrap()
    };
    let v0 = open();
    let lid = logo_item(&v0);
    let icons0: Vec<(Uuid, Option<ItemIcon>)> =
        v0.items().map(|i| (i.id, i.icon.clone())).collect();
    let (rc, o) = run(&["list"]);
    assert_eq!(rc, 0, "{o}");
    let lids = lid.to_string();
    let (rc, o) = run(&["get", &lids]);
    assert_eq!(rc, 0, "{o}");
    let (rc, o) = run(&["edit", &lids, "--title", "Logo edited"]);
    assert_eq!(rc, 0, "{o}");
    let v1 = open();
    for (id, ic) in &icons0 {
        assert_eq!(&v1.get(*id).unwrap().icon, ic, "title edit changed an icon");
    }
    let (rc, o) = run(&["upgrade"]);
    assert_eq!(rc, 0, "{o}");
    let v2 = open();
    for (id, ic) in &icons0 {
        assert_eq!(&v2.get(*id).unwrap().icon, ic, "upgrade changed an icon");
    }
    let (rc, o) = run(&["edit", &lids, "--icon", "auto"]);
    assert_eq!(rc, 0, "{o}");
    assert!(open().get(lid).unwrap().icon.is_none());
}
