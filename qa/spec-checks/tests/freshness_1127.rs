//! Bug hunt 2026-11-27: 03 §8 `Freshness` (I-02) and `SyncEvent::Merged(MergeEvent { report,
//! peer })`, 03 §3 step 6d "`peer` is the external file's Freshness before the merge". Written
//! from the spec text before reading the source.
use spec_checks::dev::*;
use spec_checks::*;
use std::path::Path;
use vault_core::*;
use vault_sync::Freshness;

/// Independent computation from the plaintext: (max record modified_at, slots_modified_at, count).
fn indep_fresh(b: &[u8]) -> (Option<u64>, Option<u64>, usize) {
    let raw = split(b);
    let n = raw.body.len() - 1;
    let max = raw.body[..n]
        .iter()
        .map(|r| u64_of(get(r, "modified_at").unwrap()))
        .max();
    (max, get(&raw.header, "slots_modified_at").map(u64_of), n)
}
fn fr(b: &[u8]) -> Freshness {
    Freshness::of(&LockedVault::parse(b).unwrap())
}
fn same(f: &Freshness, b: &[u8]) -> bool {
    let (m, s, n) = indep_fresh(b);
    f.max_item_modified_at == m && f.slots_modified_at == s && f.item_count == n
}
fn deliver(stage: &Path, to: &Path, bytes: &[u8]) {
    let t = stage.join("staged.bin");
    std::fs::write(&t, bytes).unwrap();
    std::fs::rename(&t, to).unwrap();
}

/// 03 §8: "from a LockedVault's plaintext (id, modified_at) pairs (tombstones included) and header
/// stamp". Empty vault, live items, tombstones, stripped tombstones; and the committed fixtures.
#[test]
fn fr01_freshness_of_matches_plaintext() {
    let dev = uuid::Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw("p"), KdfParams::for_tests(), dev);
    let mut bad = vec![];
    let b = v.serialize();
    if !same(&fr(&b), &b) || fr(&b).max_item_modified_at.is_some() {
        bad.push(format!("empty vault: {:?}", fr(&b)));
    }
    let a = v.insert(Item::new("a", dev, 1_000), 1_000);
    let _b2 = v.insert(Item::new("b", dev, 2_000), 2_000);
    v.delete(a, 9_000).unwrap();
    let b = v.serialize();
    let f = fr(&b);
    if !same(&f, &b) || f.max_item_modified_at != Some(9_000) || f.item_count != 2 {
        bad.push(format!("tombstone included: {f:?}"));
    }
    v.delete_permanently(a, 9_500).unwrap();
    let b = v.serialize();
    if !same(&fr(&b), &b) {
        bad.push(format!("stripped tombstone: {:?}", fr(&b)));
    }
    for name in [
        "v1-basic.vault",
        "v1-empty.vault",
        "v2-basic.vault",
        "v3-basic.vault",
        "v3-meta.vault",
        "v2-trash-legacy.vault",
    ] {
        let b = fixture(name);
        if !same(&fr(&b), &b) {
            bad.push(format!("{name}: {:?} vs {:?}", fr(&b), indep_fresh(&b)));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §8 "`SyncedVault::on_disk_freshness()` = the file as last read or written (None only while
/// vault.bin is known missing)": after create, after save, on a freshly opened locked handle, after
/// the primary vanishes (`PrimaryMissing`) and after the save that recreates it.
#[test]
fn fr02_on_disk_freshness_tracks_the_file() {
    let d = tempdir();
    let pkg = d.path().join("f.vault");
    let mut a = Dev::create(&pkg);
    let mut bad = vec![];
    let chk = |label: &str, f: Option<Freshness>, pkg: &Path, bad: &mut Vec<String>| {
        let disk = std::fs::read(primary(pkg)).unwrap();
        match f {
            Some(f) if same(&f, &disk) => {}
            other => bad.push(format!(
                "{label}: {other:?} vs disk {:?}",
                indep_fresh(&disk)
            )),
        }
    };
    chk("after create", a.s.on_disk_freshness(), &pkg, &mut bad);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    chk("after save", a.s.on_disk_freshness(), &pkg, &mut bad);
    let locked = SyncedVault::open(&pkg, uuid::Uuid::new_v4(), hooks()).unwrap();
    chk(
        "fresh locked handle",
        locked.on_disk_freshness(),
        &pkg,
        &mut bad,
    );
    drop(locked);
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    std::fs::remove_file(primary(&pkg)).unwrap();
    let seen = a.wait_for(6, |e| e.iter().any(|x| x.starts_with("PrimaryMissing")));
    if !seen {
        bad.push(format!("no PrimaryMissing: {:?}", a.seen));
    } else if a.s.on_disk_freshness().is_some() {
        bad.push(format!(
            "missing primary: on_disk_freshness {:?}",
            a.s.on_disk_freshness()
        ));
    }
    a.add_login("y", now_ms());
    a.s.save().unwrap();
    chk("after recreate", a.s.on_disk_freshness(), &pkg, &mut bad);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §3 step 6d: "emit SyncEvent::Merged(MergeEvent { report, peer }) — `peer` is the external
/// file's Freshness before the merge". Two handles on one folder; B saves; A's event carries the
/// freshness of B's file. Then a stale authentic copy replaces the primary: A's event describes the
/// stale file, the report takes nothing in, and A writes its newer state back (05 §2.3 Freshness:
/// "the write-back of our newer state over the older file is kept").
#[test]
fn fr03_merged_event_peer_freshness() {
    let d = tempdir();
    let st = tempdir();
    let pkg = d.path().join("m.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("a1", now_ms());
    a.s.save().unwrap();
    let mut b = Dev::open(&pkg);
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    a.drain();
    b.add_login("from B", now_ms());
    b.s.save().unwrap();
    let b_bytes = std::fs::read(primary(&pkg)).unwrap();
    let want = format!("{:?}", fr(&b_bytes));
    let mut bad = vec![];
    if !a.wait_for(8, |e| e.iter().any(|x| x.starts_with("Merged"))) {
        bad.push(format!("no Merged event: {:?}", a.seen));
    } else {
        let ev = a
            .seen
            .iter()
            .find(|x| x.starts_with("Merged"))
            .unwrap()
            .clone();
        if !ev.contains(&want) {
            bad.push(format!(
                "Merged peer {ev} does not describe B's file {want}"
            ));
        }
    }
    // stale authentic copy
    let stale = std::fs::read(primary(&pkg)).unwrap();
    a.drain();
    a.seen.clear();
    a.add_login("newer on A", now_ms());
    a.s.save().unwrap();
    a.add_login("newer on A 2", now_ms());
    a.s.save().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    a.drain();
    a.seen.clear();
    deliver(st.path(), &primary(&pkg), &stale);
    let want = format!("{:?}", fr(&stale));
    if !a.wait_for(8, |e| e.iter().any(|x| x.starts_with("Merged"))) {
        bad.push(format!("stale copy: no Merged event: {:?}", a.seen));
    } else {
        let ev = a
            .seen
            .iter()
            .find(|x| x.starts_with("Merged"))
            .unwrap()
            .clone();
        if !ev.contains(&want) {
            bad.push(format!("stale Merged peer {ev} vs {want}"));
        }
        if !(ev.contains("added: 0") && ev.contains("updated: 0") && ev.contains("deleted: 0")) {
            bad.push(format!("stale merge took something in: {ev}"));
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(800));
    a.drain();
    let disk = std::fs::read(primary(&pkg)).unwrap();
    let u = LockedVault::parse(&disk).unwrap().unlock(&pw(PW)).unwrap();
    if !u.items().any(|i| i.title == "newer on A 2") {
        bad.push("newer state not written back over the stale file".into());
    }
    match a.s.on_disk_freshness() {
        Some(f) if same(&f, &disk) => {}
        other => bad.push(format!("on_disk_freshness after write-back {other:?}")),
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
