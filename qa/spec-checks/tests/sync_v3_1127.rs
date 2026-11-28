//! Bug hunt 2026-11-27: format 3 through merge and sync. 01 §9 "A merge never lowers a file's
//! version"; 01 §9 "writers preserve unknown keys they read"; 03 §6 conflict copies of both shapes
//! (sibling package and in-package `vault*.bin`); 03 §3 a relabelled or older primary. Written from
//! the spec text before reading the source.
use spec_checks::dev::*;
use spec_checks::w1127::*;
use spec_checks::*;
use std::path::Path;
use uuid::Uuid;
use vault_core::*;

fn deliver(stage: &Path, to: &Path, bytes: &[u8]) {
    let t = stage.join(format!("staged-{}", Uuid::new_v4().simple()));
    std::fs::write(&t, bytes).unwrap();
    std::fs::rename(&t, to).unwrap();
}
fn opens(b: &[u8]) -> Result<UnlockedVault, VaultError> {
    LockedVault::parse(b).and_then(|l| l.unlock(&pw(PW)))
}
/// Records of `b` as writer input, plus one new item `title` (with optional record extras).
fn plus_item(b: &[u8], key: &[u8], title: &str, extras: Vec<(Value, Value)>) -> (Vec<Rec>, Uuid) {
    let mut recs: Vec<Rec> = records(b, key)
        .into_iter()
        .map(|(id, (ma, _, p))| Rec {
            id,
            ma,
            plain: p,
            extras: vec![],
        })
        .collect();
    let id = Uuid::new_v4();
    let ma = now_ms();
    recs.push(Rec {
        id: id.as_bytes().to_vec(),
        ma,
        plain: item_plain(
            title,
            [9; 16],
            vec![field_v(Some([5; 16]), "n", "text", "v", ma)],
        ),
        extras,
    });
    (recs, id)
}

/// 01 §9 + 02 g6 "Record-level plaintext `extras` ...": a merge that takes a peer record carrying
/// record-level unknown keys must still produce a file that opens (a v3 entry digest has to match
/// whatever unknown keys the saved record carries), on both unlock paths.
#[test]
fn sv01_merge_of_records_with_unknown_keys_stays_openable() {
    let dev = Uuid::new_v4();
    let mut ours = UnlockedVault::create(&pw(PW), KdfParams::for_tests(), dev);
    let shared = ours.insert(Item::new("shared", dev, 1_000), 1_000);
    let b = ours.serialize();
    let raw = split(&b);
    let key = indep::open_file(&b, PW).vault_key;
    let (mut recs, new_id) = plus_item(&b, &key, "from newer writer", vec![(t("zz_new"), i(1))]);
    // the shared item, edited later by the newer writer, with its own unknown key
    for r in recs.iter_mut() {
        if r.id == shared.as_bytes().to_vec() {
            r.ma = 50_000;
            set(&mut r.plain, "title", t("edited by newer writer"));
            set(&mut r.plain, "title_modified_at", i(50_000));
            r.extras = vec![(t("zz_shared"), t("x"))];
        }
    }
    let theirs_b = seal_file(3, &raw.header, &key, &recs, &[(t("zz_m"), i(2))]);
    let theirs = opens(&theirs_b).expect("newer-writer file opens");
    let rep = ours.merge_from(&theirs).unwrap();
    let out = ours.serialize();
    let mut bad: Vec<String> = vec![];
    match opens(&out) {
        Ok(u) => {
            if !u.items().any(|i| i.id == new_id)
                || u.get(shared).map(|i| i.title.as_str()) != Some("edited by newer writer")
            {
                bad.push(format!("merged content wrong: {rep:?}"));
            }
        }
        Err(e) => bad.push(format!(
            "merged file does not open with the password: {e:?}"
        )),
    }
    let rk =
        LockedVault::parse(&out).and_then(|l| l.unlock_with_key(&ours.export_vault_key(), dev));
    if let Err(e) = rk {
        bad.push(format!("merged file does not open on the key path: {e:?}"));
    }
    if let Err(e) = indep::try_open_file(&out, PW) {
        bad.push(format!("merged file fails the spec binding: {e}"));
    }
    let raw_out = split(&out);
    let carried: Vec<String> = raw_out
        .body
        .iter()
        .filter_map(|r| match r {
            Value::Map(e) => Some(
                e.iter()
                    .filter_map(|(k, _)| {
                        k.as_text()
                            .filter(|k| k.starts_with("zz_"))
                            .map(String::from)
                    })
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            _ => None,
        })
        .filter(|s| !s.is_empty())
        .collect();
    eprintln!("INFO record unknown keys after merge: {carried:?}");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §6 per-file copy (`vault 2.bin`) written by an older build as version 2 (same vault, new
/// item): absorbed, item merged, primary stays version 3 (01 §9 "A merge never lowers a file's
/// version"), copy moved to backups.
#[test]
fn sv02_version2_per_file_copy_absorbed_primary_stays_3() {
    let d = tempdir();
    let st = tempdir();
    let pkg = d.path().join("c.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("a1", now_ms());
    a.s.save().unwrap();
    let disk = std::fs::read(primary(&pkg)).unwrap();
    let key = indep::open_file(&disk, PW).vault_key;
    let (recs, new_id) = plus_item(&disk, &key, "from v2 build", vec![]);
    let mut h2 = split(&disk).header;
    rewrap_password_slots(&mut h2, &key, 2, PW);
    let v2 = seal_file(2, &h2, &key, &recs, &[]);
    assert!(opens(&v2).is_ok(), "hand-built v2 copy opens");
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    deliver(st.path(), &pkg.join("vault 2.bin"), &v2);
    let got = a.wait_for(10, |e| e.iter().any(|x| x.starts_with("ConflictAbsorbed")));
    let disk = std::fs::read(primary(&pkg)).unwrap();
    let mut bad: Vec<String> = vec![];
    if !got {
        bad.push(format!("not absorbed: {:?}", a.seen));
    }
    if version_of(&disk) != 3 {
        bad.push(format!(
            "primary version {} after absorbing a v2 copy",
            version_of(&disk)
        ));
    }
    match opens(&disk) {
        Ok(u) if u.items().any(|i| i.id == new_id) => {}
        other => bad.push(format!(
            "merged primary: {:?}",
            other.map(|u| u.items().count()).err()
        )),
    }
    if pkg.join("vault 2.bin").exists() {
        bad.push("copy left in place".into());
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §6 sibling package (`<name> 2.vault/`) whose v3 header was edited (created_at) and that adds
/// an item: 01 §4 binds the header, so the copy does not authenticate; nothing from it may be merged
/// and it is never deleted.
#[test]
fn sv03_tampered_v3_sibling_not_merged_or_deleted() {
    let d = tempdir();
    let st = tempdir();
    let pkg = d.path().join("s.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("a1", now_ms());
    a.s.save().unwrap();
    let disk = std::fs::read(primary(&pkg)).unwrap();
    let key = indep::open_file(&disk, PW).vault_key;
    let (recs, new_id) = plus_item(&disk, &key, "smuggled", vec![]);
    let raw = split(&disk);
    let good = seal_file(3, &raw.header, &key, &recs, &[]);
    let r2 = split(&good);
    let mut h = r2.header.clone();
    let ca = u64_of(get(&h, "created_at").unwrap());
    set(&mut h, "created_at", i(ca + 1));
    let forged = join(3, &canon(h), &r2.body);
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    let sib_stage = st.path().join("s 2.vault");
    std::fs::create_dir_all(&sib_stage).unwrap();
    std::fs::write(sib_stage.join("vault.bin"), &forged).unwrap();
    std::fs::rename(&sib_stage, d.path().join("s 2.vault")).unwrap();
    a.wait_for(6, |e| e.len() > 1);
    std::thread::sleep(std::time::Duration::from_millis(800));
    a.drain();
    let mut bad: Vec<String> = vec![];
    if a.v().items().any(|i| i.id == new_id) {
        bad.push("item from a header-tampered copy was merged in memory".into());
    }
    let disk = std::fs::read(primary(&pkg)).unwrap();
    if opens(&disk)
        .map(|u| u.items().any(|i| i.id == new_id))
        .unwrap_or(false)
    {
        bad.push("item from a header-tampered copy reached vault.bin".into());
    }
    let still = d.path().join("s 2.vault/vault.bin").exists()
        || ls(&pkg.join("backups")).iter().any(|n| n.contains("s 2"));
    if !still {
        bad.push("tampered copy deleted".into());
    }
    eprintln!("INFO tampered sibling events: {:?}", a.seen);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §3 / 01 §9: an authentic older version 2 copy of the vault (from before the upgrade, e.g. a
/// provider's version history) replaces the version 3 primary while unlocked: the merge keeps the
/// greater version and writes the newer state back; the file ends version 3 and opens.
#[test]
fn sv04_older_version2_primary_rolled_back_under_an_unlocked_device() {
    let d = tempdir();
    let st = tempdir();
    let pkg = d.path().join("r.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("before", now_ms());
    a.s.save().unwrap();
    let disk = std::fs::read(primary(&pkg)).unwrap();
    let key = indep::open_file(&disk, PW).vault_key;
    let recs: Vec<Rec> = records(&disk, &key)
        .into_iter()
        .map(|(id, (ma, _, p))| Rec {
            id,
            ma,
            plain: p,
            extras: vec![],
        })
        .collect();
    let mut h2 = split(&disk).header;
    rewrap_password_slots(&mut h2, &key, 2, PW);
    let old_v2 = seal_file(2, &h2, &key, &recs, &[]);
    a.add_login("after", now_ms());
    a.s.save().unwrap();
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    a.drain();
    deliver(st.path(), &primary(&pkg), &old_v2);
    a.wait_for(8, |e| e.iter().any(|x| x.starts_with("Merged")));
    std::thread::sleep(std::time::Duration::from_millis(800));
    a.drain();
    let disk = std::fs::read(primary(&pkg)).unwrap();
    let mut bad: Vec<String> = vec![];
    if version_of(&disk) != 3 {
        bad.push(format!(
            "primary left at version {}; events {:?}",
            version_of(&disk),
            a.seen
        ));
    }
    match opens(&disk) {
        Ok(u) if u.items().any(|i| i.title == "after") => {}
        other => bad.push(format!("primary after rollback: {:?}", other.err())),
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 01 §4 v3 relabel: "A v3 file relabelled 2 or 1 opens nothing on either path". The primary
/// relabelled to 2 under an unlocked device: no merge of it, the device's state is kept and its next
/// save leaves an openable version 3 file (INFO: which event).
#[test]
fn sv05_relabelled_primary_under_an_unlocked_device() {
    let d = tempdir();
    let st = tempdir();
    let pkg = d.path().join("l.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("keep me", now_ms());
    a.s.save().unwrap();
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    a.drain();
    let mut b = std::fs::read(primary(&pkg)).unwrap();
    b[4..6].copy_from_slice(&2u16.to_be_bytes());
    a.seen.clear();
    deliver(st.path(), &primary(&pkg), &b);
    a.wait_for(6, |e| !e.is_empty());
    std::thread::sleep(std::time::Duration::from_millis(500));
    a.drain();
    eprintln!("INFO relabelled primary events: {:?}", a.seen);
    a.add_login("later", now_ms());
    let r = a.s.save();
    let disk = std::fs::read(primary(&pkg)).unwrap();
    eprintln!(
        "INFO save over relabelled primary: {r:?}; disk version {}",
        version_of(&disk)
    );
    let mut bad: Vec<String> = vec![];
    if !a.v().items().any(|i| i.title == "keep me") {
        bad.push("in-memory state lost".into());
    }
    if r.is_ok() && opens(&disk).is_err() {
        bad.push("save reported Ok but the file does not open".into());
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
