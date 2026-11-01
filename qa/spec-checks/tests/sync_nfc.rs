//! 2026-11-01 additions to 03-sync.md, checked with two handles on one folder:
//! - §3 "Names are compared normalisation-insensitively (each component folded to NFC on both
//!   sides, including the stored package and parent paths) ... nothing is renamed on disk, and
//!   filesystem operations always use the spelling the event or caller supplied."
//! - §6 conflict patterns are "case- and normalisation-insensitive".
//! - §8 `delete_backup`: "path must be inside backups/ (file or conflict package); refuses the
//!   primary; any kind incl. Unsaved/Conflict; name match is NFC-insensitive".
//! - §6 step 4 / §8 `SyncEvent::WaitingForBlobs(PathBuf)` semantics.
//!
//! The temp volume is APFS (normalisation-insensitive, normalisation-preserving), so an NFD and an
//! NFC spelling name the same directory entry, and read_dir/FSEvents report the stored spelling.
use spec_checks::dev::*;
use spec_checks::*;
use std::path::{Path, PathBuf};
use std::time::Duration;

const NFC: &str = "Caf\u{e9}";
const NFD: &str = "Cafe\u{301}";
const PARENT_NFC: &str = "R\u{e9}sum\u{e9}";
const PARENT_NFD: &str = "Re\u{301}sume\u{301}";

fn hex(id: uuid::Uuid) -> String {
    id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn to_nfd(s: &str) -> String {
    s.replace('\u{e9}', "e\u{301}")
        .replace('\u{eb}', "e\u{308}")
        .replace('\u{c9}', "E\u{301}")
}
fn path_nfd(p: &Path) -> PathBuf {
    PathBuf::from(to_nfd(&p.to_string_lossy()))
}
fn settle() {
    std::thread::sleep(Duration::from_millis(700));
}
fn count(seen: &[String], prefix: &str) -> usize {
    seen.iter().filter(|e| e.starts_with(prefix)).count()
}
fn has(seen: &[String], prefix: &str) -> bool {
    count(seen, prefix) > 0
}
/// Raw bytes of the names in `dir` (to show nothing was renamed).
fn raw_names(dir: &Path) -> Vec<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let mut v: Vec<Vec<u8>> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().as_bytes().to_vec())
        .collect();
    v.sort();
    v
}

/// 03 §3: a package stored on disk in NFD under an NFD parent, watched by a handle that was given
/// the NFC spelling (and the reverse): the primary's changes are recognised and merged both ways;
/// the on-disk names stay as created.
#[test]
fn sn01_primary_events_across_spellings() {
    for (disk_parent, disk_name, other_parent, other_name) in [
        (PARENT_NFD, NFD, PARENT_NFC, NFC),
        (PARENT_NFC, NFC, PARENT_NFD, NFD),
    ] {
        let d = tempdir();
        std::fs::create_dir(d.path().join(disk_parent)).unwrap();
        let pkg_disk = d
            .path()
            .join(disk_parent)
            .join(format!("{disk_name}.vault"));
        let pkg_other = d
            .path()
            .join(other_parent)
            .join(format!("{other_name}.vault"));
        let mut a = Dev::create(&pkg_disk);
        a.add_login("seed", now_ms());
        a.s.save().unwrap();
        let before = raw_names(&d.path().join(disk_parent));
        let mut b = Dev::open(&pkg_other);
        a.s.start_watching().unwrap();
        b.s.start_watching().unwrap();
        settle();
        let ia = a.add_login("from-a", now_ms());
        a.s.save().unwrap();
        let got_b = b.wait_for(8, |e| has(e, "Merged"));
        assert!(
            got_b && b.v().get(ia).is_some(),
            "handle with the other spelling ({}) missed the primary change; events {:?}",
            if other_name == NFC { "NFC" } else { "NFD" },
            b.seen
        );
        let ib = b.add_login("from-b", now_ms());
        b.s.save().unwrap();
        let got_a = a.wait_for(8, |e| has(e, "Merged"));
        assert!(
            got_a && a.v().get(ib).is_some(),
            "creator handle missed B's change; events {:?}",
            a.seen
        );
        assert!(
            !has(&a.seen, "ConflictAbsorbed") && !has(&b.seen, "ConflictAbsorbed"),
            "own package treated as a conflict copy: A {:?} B {:?}",
            a.seen,
            b.seen
        );
        assert_eq!(
            raw_names(&d.path().join(disk_parent)),
            before,
            "nothing is renamed on disk"
        );
        assert!(
            ls(&pkg_disk.join("backups"))
                .iter()
                .all(|n| !n.starts_with("conflict-")),
            "no conflict backups from our own writes"
        );
    }
}

/// 03 §3/§6: an in-package per-file conflict copy (`vault 2.bin`, and a Dropbox-style name with a
/// decomposed host name) inside a package whose stored name differs in normalisation from the
/// handle's path is absorbed and moved into backups/.
#[test]
fn sn02_in_package_copy_across_spellings() {
    let d = tempdir();
    let pkg_nfc = d.path().join(format!("{NFC}.vault"));
    let pkg_nfd = d.path().join(format!("{NFD}.vault"));
    {
        let mut c = Dev::create(&pkg_nfc);
        c.add_login("seed", now_ms());
        c.s.save().unwrap();
    }
    let mut a = Dev::open(&pkg_nfd);
    let st = tempdir();
    let staging = st.path().join("staging.vault");
    copy_dir(&pkg_nfc, &staging);
    let mut c = Dev::open(&staging);
    let c1 = c.add_login("copy-one", now_ms());
    c.s.save().unwrap();
    let one = std::fs::read(staging.join("vault.bin")).unwrap();
    let c2 = c.add_login("copy-two", now_ms());
    c.s.save().unwrap();
    let two = std::fs::read(staging.join("vault.bin")).unwrap();
    drop(c);
    a.s.start_watching().unwrap();
    settle();
    std::fs::write(pkg_nfc.join("vault 2.bin"), &one).unwrap();
    let dropbox = to_nfd("vault (Zo\u{eb}'s conflicted copy 2026-11-01).bin");
    std::fs::write(pkg_nfc.join(&dropbox), &two).unwrap();
    a.wait_for(10, |e| count(e, "ConflictAbsorbed") >= 2);
    assert!(
        a.v().get(c1).is_some() && a.v().get(c2).is_some(),
        "per-file copies not absorbed; events {:?}",
        a.seen
    );
    assert!(
        !pkg_nfc.join("vault 2.bin").exists() && !pkg_nfc.join(&dropbox).exists(),
        "copies not moved: {:?}",
        ls(&pkg_nfc)
    );
    let bk = ls(&pkg_nfc.join("backups"));
    assert!(
        bk.iter().filter(|n| n.starts_with("conflict-")).count() >= 2,
        "moved into backups/: {bk:?}"
    );
}

/// 03 §6 "Patterns to detect (case- and normalisation-insensitive, in <dir> only)": sibling
/// packages `CAFÉ 2.vault` (upper case, NFD) and `Café (Zoë's conflicted copy <date>).vault` (NFD)
/// of `Café.vault` (NFC) are absorbed; the package itself keeps its stored name.
#[test]
fn sn03_sibling_packages_case_and_normalisation() {
    let d = tempdir();
    let pkg = d.path().join(format!("{NFC}.vault"));
    let mut a = Dev::create(&pkg);
    a.add_login("seed", now_ms());
    a.s.save().unwrap();
    let names = [
        to_nfd("CAF\u{c9} 2.vault"),
        to_nfd("Caf\u{e9} (Zo\u{eb}'s conflicted copy 2026-11-01).vault"),
    ];
    let mut ids = vec![];
    let mut staged = vec![];
    for (k, _) in names.iter().enumerate() {
        let st = tempdir();
        let staging = st.path().join("staging.vault");
        copy_dir(&pkg, &staging);
        let mut c = Dev::open(&staging);
        ids.push(c.add_login(&format!("sib{k}"), now_ms()));
        c.s.save().unwrap();
        drop(c);
        staged.push((st, staging));
    }
    a.s.start_watching().unwrap();
    settle();
    for ((_, staging), name) in staged.iter().zip(&names) {
        std::fs::rename(staging, d.path().join(name)).unwrap();
    }
    a.wait_for(12, |e| count(e, "ConflictAbsorbed") >= 2);
    for (k, id) in ids.iter().enumerate() {
        assert!(
            a.v().get(*id).is_some(),
            "sibling {k} not absorbed; events {:?}",
            a.seen
        );
    }
    let left = ls(d.path());
    assert_eq!(
        raw_names(d.path()),
        vec![
            pkg.file_name()
                .unwrap()
                .to_string_lossy()
                .as_bytes()
                .to_vec()
        ],
        "only the package remains, with its stored name; left {left:?}"
    );
}

/// 03 §8 delete_backup: "path must be inside backups/ (file or conflict package); refuses the
/// primary; any kind incl. Unsaved/Conflict; name match is NFC-insensitive". Hostile spellings of
/// the primary, `..`, the backups dir itself, a symlink to the primary, and another package's
/// backups/ must all leave every non-backup file intact.
#[test]
fn sn04_delete_backup_paths() {
    let d = tempdir();
    let pkg = d.path().join(format!("{NFC}.vault"));
    let mut a = Dev::create(&pkg);
    a.add_login("seed", now_ms());
    a.s.save().unwrap();
    let snap = a.s.backup_now().unwrap();
    assert!(snap.exists());
    // NFD spelling of the whole backup path -> deleted, BackupDeleted emitted
    let r = a.s.delete_backup(&path_nfd(&snap));
    a.drain();
    assert!(
        r.is_ok(),
        "NFD spelling of a backup path refused: {:?}",
        r.err()
    );
    assert!(!snap.exists(), "backup still present");
    assert!(has(&a.seen, "BackupDeleted"), "events {:?}", a.seen);

    let primary_bytes = std::fs::read(primary(&pkg)).unwrap();
    let other = d.path().join("other.vault").join("backups");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("x.vault.bin"), b"keep").unwrap();
    std::fs::write(d.path().join("loose.vault.bin"), b"keep").unwrap();
    std::os::unix::fs::symlink("../vault.bin", pkg.join("backups").join("link.vault.bin")).unwrap();
    let hostile: Vec<(&str, PathBuf)> = vec![
        ("primary NFC", primary(&pkg)),
        ("primary NFD", path_nfd(&primary(&pkg))),
        (
            "backups/../vault.bin",
            pkg.join("backups").join("..").join("vault.bin"),
        ),
        (
            "NFD backups/../vault.bin",
            path_nfd(&pkg.join("backups").join("..").join("vault.bin")),
        ),
        ("the backups dir itself", pkg.join("backups")),
        ("the package dir", pkg.clone()),
        ("another package's backups", other.join("x.vault.bin")),
        (
            "backups/../../loose",
            pkg.join("backups")
                .join("..")
                .join("..")
                .join("loose.vault.bin"),
        ),
    ];
    let mut bad = vec![];
    for (name, p) in &hostile {
        let r = a.s.delete_backup(p);
        if r.is_ok() {
            bad.push(format!("{name}: accepted"));
        }
    }
    let _ =
        a.s.delete_backup(&pkg.join("backups").join("link.vault.bin"));
    if std::fs::read(primary(&pkg)).ok().as_deref() != Some(&primary_bytes[..]) {
        bad.push("primary changed or deleted".into());
    }
    if !pkg.join("backups").is_dir() {
        bad.push("backups dir deleted".into());
    }
    if !other.join("x.vault.bin").exists() || !d.path().join("loose.vault.bin").exists() {
        bad.push("a file outside our backups/ was deleted".into());
    }
    // a conflict package in backups/ (absorbed sibling) is deletable by an NFD path too
    let st = tempdir();
    let staging = st.path().join("staging.vault");
    copy_dir(&pkg, &staging);
    a.s.start_watching().unwrap();
    settle();
    std::fs::rename(&staging, d.path().join(format!("{NFD} 2.vault"))).unwrap();
    a.wait_for(8, |e| has(e, "ConflictAbsorbed"));
    let conflict_pkg = ls(&pkg.join("backups"))
        .into_iter()
        .find(|n| n.starts_with("conflict-") && !n.ends_with(".bin"));
    match conflict_pkg {
        None => bad.push(format!(
            "no conflict package in backups/ after absorb; events {:?}",
            a.seen
        )),
        Some(n) => {
            let p = path_nfd(&pkg.join("backups").join(&n));
            if let Err(e) = a.s.delete_backup(&p) {
                bad.push(format!("conflict package (NFD path) refused: {e:?}"));
            }
            if pkg.join("backups").join(&n).exists() {
                bad.push("conflict package still present".into());
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Builds a whole-package conflict copy of `pkg` that references an attachment whose blob is
/// missing from both sides. Returns (staging dir guard, staging path, item from copy, blob name,
/// blob bytes).
fn waiting_copy(
    pkg: &Path,
    item: uuid::Uuid,
) -> (tempfile::TempDir, PathBuf, uuid::Uuid, String, Vec<u8>) {
    let st = tempdir();
    let staging = st.path().join("staging.vault");
    copy_dir(pkg, &staging);
    let mut c = Dev::open(&staging);
    let aid =
        c.s.add_attachment(item, "late.txt", &b"late blob"[..], 9, now_ms())
            .unwrap();
    let extra = c.add_login("from-copy", now_ms());
    c.s.save().unwrap();
    drop(c);
    let blob = format!("{}.bin", hex(aid));
    let held = std::fs::read(staging.join("attachments").join(&blob)).unwrap();
    std::fs::remove_file(staging.join("attachments").join(&blob)).unwrap();
    (st, staging, extra, blob, held)
}

fn waiting_paths(seen: &[String]) -> usize {
    count(seen, "WaitingForBlobs")
}

/// 03 §6 step 4: WaitingForBlobs(conflict path) is emitted once per waiting package even when more
/// events arrive for it; the merge (step 3) already happened; ConflictAbsorbed follows the blob.
#[test]
fn sw01_waiting_for_blobs_once_then_absorbed() {
    let d = tempdir();
    let pkg = d.path().join("wb.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("host", now_ms());
    a.s.save().unwrap();
    let (_st, staging, extra, blob, held) = waiting_copy(&pkg, item);
    a.s.start_watching().unwrap();
    settle();
    let target = d.path().join("wb 2.vault");
    std::fs::rename(&staging, &target).unwrap();
    let got = a.wait_for(8, |e| has(e, "WaitingForBlobs"));
    assert!(got, "no WaitingForBlobs; events {:?}", a.seen);
    let w = a
        .seen
        .iter()
        .find(|e| e.starts_with("WaitingForBlobs"))
        .unwrap();
    assert!(
        w.contains("wb 2.vault"),
        "event names the conflict path: {w}"
    );
    assert!(
        a.v().get(extra).is_some(),
        "step 3 merge happens before the deferred move"
    );
    // more events on the waiting package: an unrelated blob, a rewrite of its vault.bin
    for k in 0..3 {
        std::fs::write(
            target
                .join("attachments")
                .join(format!("{:032x}.bin", 0xabc0 + k)),
            b"unrelated",
        )
        .unwrap();
        let vb = std::fs::read(target.join("vault.bin")).unwrap();
        std::fs::write(target.join("vault.bin"), vb).unwrap();
        std::thread::sleep(Duration::from_millis(800));
        a.drain();
    }
    a.wait_for(2, |_| false);
    assert_eq!(
        waiting_paths(&a.seen),
        1,
        "WaitingForBlobs must fire once per waiting package; events {:?}",
        a.seen
    );
    assert!(target.exists(), "not moved while the blob is missing");
    std::fs::write(target.join("attachments").join(&blob), &held).unwrap();
    let got = a.wait_for(8, |e| has(e, "ConflictAbsorbed"));
    assert!(
        got,
        "ConflictAbsorbed follows the blob; events {:?}",
        a.seen
    );
    assert!(!target.exists());
    assert_eq!(waiting_paths(&a.seen), 1, "events {:?}", a.seen);
}

/// 03 §6 step 4 "(never while locked ...)": a package that arrives while locked raises no
/// WaitingForBlobs until unlock; it is not moved; after unlock it waits (event) and is absorbed
/// when the blob arrives.
#[test]
fn sw02_never_while_locked() {
    let d = tempdir();
    let pkg = d.path().join("wl.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("host", now_ms());
    a.s.save().unwrap();
    let (_st, staging, extra, blob, held) = waiting_copy(&pkg, item);
    a.s.start_watching().unwrap();
    let _ = a.s.lock();
    settle();
    let target = d.path().join("wl 2.vault");
    std::fs::rename(&staging, &target).unwrap();
    a.wait_for(3, |_| false);
    assert_eq!(
        waiting_paths(&a.seen),
        0,
        "fired while locked: {:?}",
        a.seen
    );
    assert!(target.exists());
    a.s.unlock(&pw(PW)).unwrap();
    a.wait_for(5, |e| has(e, "WaitingForBlobs"));
    assert!(
        a.v().get(extra).is_some(),
        "deferred copy merged at unlock; events {:?}",
        a.seen
    );
    assert!(target.exists(), "not moved while the blob is missing");
    eprintln!(
        "INFO after unlock WaitingForBlobs count = {}",
        waiting_paths(&a.seen)
    );
    std::fs::write(target.join("attachments").join(&blob), &held).unwrap();
    let got = a.wait_for(8, |e| has(e, "ConflictAbsorbed"));
    assert!(got && !target.exists(), "events {:?}", a.seen);
}

/// 03 §6 step 4 "a package still waiting at lock is re-checked at the next unlock even if watching
/// was stopped meanwhile": wait -> lock -> stop watching -> blob arrives -> unlock -> absorbed.
#[test]
fn sw03_waiting_rechecked_at_unlock_without_watcher() {
    let d = tempdir();
    let pkg = d.path().join("wr.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("host", now_ms());
    a.s.save().unwrap();
    let (_st, staging, _extra, blob, held) = waiting_copy(&pkg, item);
    a.s.start_watching().unwrap();
    settle();
    let target = d.path().join("wr 2.vault");
    std::fs::rename(&staging, &target).unwrap();
    assert!(
        a.wait_for(8, |e| has(e, "WaitingForBlobs")),
        "events {:?}",
        a.seen
    );
    let _ = a.s.lock();
    a.s.stop_watching();
    std::fs::write(target.join("attachments").join(&blob), &held).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    a.s.unlock(&pw(PW)).unwrap();
    let got = a.wait_for(5, |e| has(e, "ConflictAbsorbed"));
    assert!(
        got && !target.exists(),
        "waiting package not re-checked at unlock without a watcher; events {:?}; exists={}",
        a.seen,
        target.exists()
    );
    assert!(pkg.join("attachments").join(&blob).exists(), "blob copied");
}

/// 03 §6 step 4 "it may fire again only after the package is absorbed or gone, or after
/// lock/stop_watching/start_watching reset the bookkeeping": a restart of watching while the
/// package still waits may fire again (allowed); a plain unrelated save does not.
#[test]
fn sw04_no_refire_on_own_saves() {
    let d = tempdir();
    let pkg = d.path().join("wf.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("host", now_ms());
    a.s.save().unwrap();
    let (_st, staging, _extra, _blob, _held) = waiting_copy(&pkg, item);
    a.s.start_watching().unwrap();
    settle();
    let target = d.path().join("wf 2.vault");
    std::fs::rename(&staging, &target).unwrap();
    assert!(a.wait_for(8, |e| has(e, "WaitingForBlobs")));
    for k in 0..3 {
        a.add_login(&format!("own{k}"), now_ms());
        a.s.save().unwrap();
        std::thread::sleep(Duration::from_millis(700));
        a.drain();
    }
    a.wait_for(2, |_| false);
    assert_eq!(
        waiting_paths(&a.seen),
        1,
        "own saves re-raised WaitingForBlobs; events {:?}",
        a.seen
    );
    a.s.stop_watching();
    a.s.start_watching().unwrap();
    std::fs::write(target.join("attachments").join("ffff.tmp"), b"x").unwrap();
    a.wait_for(4, |_| false);
    eprintln!(
        "INFO after stop/start watching: WaitingForBlobs count = {}",
        waiting_paths(&a.seen)
    );
    assert!(target.exists());
}

/// 03 §6 step 4 applies the blob deferral to whole packages only ("per-file: move the file"): an
/// in-package copy whose refs point to a blob nobody has is absorbed and moved at once.
#[test]
fn sw05_per_file_copy_never_waits() {
    let d = tempdir();
    let pkg = d.path().join("pf.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("host", now_ms());
    a.s.save().unwrap();
    let (_st, staging, extra, _blob, _held) = waiting_copy(&pkg, item);
    a.s.start_watching().unwrap();
    settle();
    std::fs::copy(staging.join("vault.bin"), pkg.join("vault 2.bin")).unwrap();
    let got = a.wait_for(8, |e| has(e, "ConflictAbsorbed"));
    assert!(got, "events {:?}", a.seen);
    assert_eq!(waiting_paths(&a.seen), 0, "events {:?}", a.seen);
    assert!(a.v().get(extra).is_some());
    assert!(!pkg.join("vault 2.bin").exists());
}

/// 03 §5 attachments paragraph through two handles: a removal made on A survives B's later
/// unrelated edit and save (B still held the ref), and the ref does not come back.
#[test]
fn sw06_attachment_removal_survives_other_handle() {
    let d = tempdir();
    let pkg = d.path().join("ar.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("host", now_ms());
    let aid =
        a.s.add_attachment(item, "f.txt", &b"data"[..], 4, now_ms())
            .unwrap();
    a.s.save().unwrap();
    let mut b = Dev::open(&pkg);
    a.s.remove_attachment(item, aid, now_ms()).unwrap();
    a.s.save().unwrap();
    std::thread::sleep(Duration::from_millis(5));
    b.s.edit(|v| v.set_field_named(item, "username", pw("b"), now_ms()))
        .unwrap()
        .unwrap();
    b.s.save().unwrap();
    let disk = read_vault(&pkg);
    let it = disk.get(item).unwrap();
    assert!(
        it.attachments.iter().all(|r| r.id != aid),
        "removed ref came back after the other handle's save"
    );
    assert!(it.removed_attachments.iter().any(|t| t.id == aid));
    assert!(
        it.fields
            .iter()
            .any(|f| f.name == "username" && secrecy::ExposeSecret::expose_secret(&f.value) == "b")
    );
}

/// 03 §3 "Merge is idempotent and commutative, so a ping-pong between two devices converges in one
/// round trip each": with two attachments added in the same millisecond (refs whose local order
/// differs from the merge order), two watching handles must go quiet; no endless write loop.
#[test]
fn sw07_no_ping_pong_after_same_millisecond_attachments() {
    let d = tempdir();
    let pkg = d.path().join("pp.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("host", now_ms());
    a.s.save().unwrap();
    let mut b = Dev::open(&pkg);
    a.s.start_watching().unwrap();
    b.s.start_watching().unwrap();
    settle();
    let t = now_ms();
    for k in 0..4 {
        a.s.add_attachment(item, &format!("f{k}"), &b"x"[..], 1, t)
            .unwrap();
    }
    a.s.save().unwrap();
    // let the handles exchange for a while, then require silence
    for _ in 0..6 {
        std::thread::sleep(Duration::from_millis(700));
        a.drain();
        b.drain();
    }
    let (ma, mb) = (count(&a.seen, "Merged"), count(&b.seen, "Merged"));
    let before = std::fs::read(primary(&pkg)).unwrap();
    for _ in 0..4 {
        std::thread::sleep(Duration::from_millis(700));
        a.drain();
        b.drain();
    }
    let after = std::fs::read(primary(&pkg)).unwrap();
    eprintln!("INFO Merged events during exchange: A {ma}, B {mb}");
    assert!(
        before == after,
        "the handles keep rewriting vault.bin; events A {:?} B {:?}",
        a.seen,
        b.seen
    );
    assert_eq!(snap_vault(a.v()), snap_vault(b.v()));
}

/// 03 §8 delete_backup "any kind incl. Unsaved/Conflict" and "name match is NFC-insensitive":
/// the Unsaved backup taken at lock (save blocked) of an NFC-named package is deleted through an
/// NFD spelling of its path, while locked; retention never prunes it otherwise (§8).
#[test]
fn sn05_delete_unsaved_backup_nfd_while_locked() {
    let d = tempdir();
    let pkg = d.path().join(format!("{NFC}.vault"));
    let mut a = Dev::create(&pkg);
    a.s.save().unwrap();
    a.add_login("unsaved", now_ms());
    let mut b = std::fs::read(primary(&pkg)).unwrap();
    b[4..6].copy_from_slice(&3u16.to_be_bytes());
    std::fs::write(primary(&pkg), &b).unwrap();
    let out = a.s.lock();
    eprintln!("INFO lock outcome {out:?}");
    let unsaved: Vec<String> = ls(&pkg.join("backups"))
        .into_iter()
        .filter(|n| n.contains("unsaved"))
        .collect();
    assert_eq!(unsaved.len(), 1, "one Unsaved backup: {unsaved:?}");
    let p = path_nfd(&pkg.join("backups").join(&unsaved[0]));
    let r = a.s.delete_backup(&p);
    a.drain();
    assert!(r.is_ok(), "Unsaved backup refused: {:?}", r.err());
    assert!(!pkg.join("backups").join(&unsaved[0]).exists());
    assert!(has(&a.seen, "BackupDeleted"), "events {:?}", a.seen);
    assert_eq!(
        std::fs::read(primary(&pkg)).unwrap(),
        b,
        "primary untouched"
    );
}
