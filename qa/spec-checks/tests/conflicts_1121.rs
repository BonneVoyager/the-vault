//! 2026-11-21 second run ("b"): unreadable conflict copies and the version-0 / newer-version split.
//! Written from specs/03-sync.md (§3, §6 step 1, §8 SyncEvent list and `restore_from`),
//! specs/05-ui.md (§2.2, §2.3, §5), specs/01-vault-format.md §4 and README only, before any source
//! under crates/ was read. Every check names the sentence it tests. A passing check shows the
//! behaviour on these inputs only.
use spec_checks::dev::*;
use spec_checks::*;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn settle() {
    std::thread::sleep(Duration::from_millis(700));
}
fn count(seen: &[String], prefix: &str) -> usize {
    seen.iter().filter(|e| e.starts_with(prefix)).count()
}
fn has(seen: &[String], prefix: &str) -> bool {
    count(seen, prefix) > 0
}
/// UnreadableConflict events whose path mentions `needle`.
fn unread(seen: &[String], needle: &str) -> usize {
    seen.iter()
        .filter(|e| e.starts_with("UnreadableConflict") && e.contains(needle))
        .count()
}
fn hex(id: uuid::Uuid) -> String {
    id.as_simple().to_string()
}
fn garbage(seed: u8, n: usize) -> Vec<u8> {
    // deterministic, not a vault (no RVLT magic)
    let mut x: u32 = 0x9E37_79B9 ^ seed as u32;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 8) as u8
        })
        .collect()
}
/// Deliver `bytes` at `path` the way a provider does: write elsewhere, then rename into place
/// (new inode, new mtime each time).
fn deliver(stage: &Path, path: &Path, bytes: &[u8]) {
    let tmp = stage.join(format!("stage-{}", uuid::Uuid::new_v4()));
    std::fs::write(&tmp, bytes).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}
fn with_version(b: &[u8], v: u16) -> Vec<u8> {
    let mut b = b.to_vec();
    b[4..6].copy_from_slice(&v.to_be_bytes());
    b
}
/// Our own vault package with one item, saved, watching.
fn setup(dir: &Path, name: &str) -> (PathBuf, Dev) {
    let pkg = dir.join(name);
    let mut a = Dev::create(&pkg);
    a.add_login("base", now_ms());
    a.s.save().unwrap();
    a.s.start_watching().unwrap();
    settle();
    (pkg, a)
}
/// A valid per-file conflict copy of `pkg` carrying one extra item; returns (bytes, item id).
fn valid_copy(pkg: &Path, title: &str) -> (Vec<u8>, uuid::Uuid) {
    let st = tempdir();
    let staging = st.path().join("staging.vault");
    copy_dir(pkg, &staging);
    let mut c = Dev::open(&staging);
    let id = c.add_login(title, now_ms());
    c.s.save().unwrap();
    drop(c);
    (std::fs::read(staging.join("vault.bin")).unwrap(), id)
}
fn others(seen: &[String]) -> Vec<&String> {
    seen.iter()
        .filter(|e| !e.starts_with("BackupTaken"))
        .collect()
}

/// 03 §6 step 1 (2026-11-21): "if the candidate does not parse … emit
/// SyncEvent::UnreadableConflict(path) once and leave it in place"; 03 §8: "emitted once per path
/// and content (re-emitted when the bytes change; the same bytes re-delivered under a new mtime
/// stay silent)". Also: an unreadable copy never changes the primary or the in-memory state.
#[test]
fn cf01_per_file_garbage_once_per_content() {
    let d = tempdir();
    let st = tempdir();
    let (pkg, mut a) = setup(d.path(), "u.vault");
    let before = std::fs::read(primary(&pkg)).unwrap();
    let snap = snap_vault(a.v());
    let p = pkg.join("vault 2.bin");
    let g1 = garbage(1, 3000);
    let g2 = garbage(2, 3000);
    deliver(st.path(), &p, &g1);
    assert!(
        a.wait_for(8, |e| unread(e, "vault 2.bin") >= 1),
        "no UnreadableConflict for a random-bytes `vault 2.bin`; events {:?}",
        a.seen
    );
    let ev = a
        .seen
        .iter()
        .find(|e| e.starts_with("UnreadableConflict"))
        .unwrap()
        .clone();
    eprintln!(
        "INFO event: {}",
        ev.replace(&*d.path().to_string_lossy(), "<tmp>")
    );
    for _ in 0..2 {
        deliver(st.path(), &p, &g1);
        a.wait_for(2, |_| false);
    }
    let after_same = unread(&a.seen, "vault 2.bin");
    deliver(st.path(), &p, &g2);
    a.wait_for(3, |e| unread(e, "vault 2.bin") >= 2);
    deliver(st.path(), &p, &g2);
    a.wait_for(2, |_| false);
    let after_change = unread(&a.seen, "vault 2.bin");
    deliver(st.path(), &p, &g1);
    a.wait_for(3, |_| false);
    eprintln!(
        "INFO A,A,A,B,B,A: counts after same={after_same} after change={after_change} after back-to-A={}",
        unread(&a.seen, "vault 2.bin")
    );
    let mut bad = vec![];
    if after_same != 1 {
        bad.push(format!(
            "same bytes re-delivered: {after_same} events, want 1"
        ));
    }
    if after_change != 2 {
        bad.push(format!(
            "changed bytes: {after_change} events in total, want 2"
        ));
    }
    if !p.exists() {
        bad.push("copy not left in place".into());
    }
    if std::fs::read(primary(&pkg)).unwrap() != before {
        bad.push("primary rewritten because of an unreadable copy".into());
    }
    if snap_vault(a.v()) != snap || a.s.is_dirty() {
        bad.push("in-memory state changed or dirty".into());
    }
    if has(&a.seen, "ConflictAbsorbed") || has(&a.seen, "Merged") || has(&a.seen, "Error") {
        bad.push("unexpected absorb/merge/error event".into());
    }
    assert!(bad.is_empty(), "{}\nevents {:?}", bad.join("\n"), a.seen);
}

/// 03 §6 step 1: "carries an unsupported format version → … UnreadableConflict"; 03 §8: "(any
/// value, 0 included)". Version 0, version 3 and 0xFFFF copies of our own file and a truncated
/// copy: each reported once, left in place, primary untouched, and a newer *copy* never blocks
/// saves (SaveBlocked is about the primary, §3).
#[test]
fn cf02_unsupported_version_and_truncated_copies() {
    let d = tempdir();
    let st = tempdir();
    let (pkg, mut a) = setup(d.path(), "v.vault");
    let ours = std::fs::read(primary(&pkg)).unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("vault 2.bin", with_version(&ours, 0)),
        ("vault 3.bin", with_version(&ours, 3)),
        ("vault 4.bin", with_version(&ours, 0xFFFF)),
        ("vault 5.bin", ours[..ours.len() / 2].to_vec()),
        (
            "vault (mbp's conflicted copy 2026-11-21).bin",
            with_version(&ours, 0),
        ),
        ("VAULT 6.BIN", garbage(6, 500)),
    ];
    for (n, b) in &cases {
        deliver(st.path(), &pkg.join(n), b);
    }
    a.wait_for(8, |e| count(e, "UnreadableConflict") >= cases.len());
    a.wait_for(2, |_| false);
    let mut bad = vec![];
    for (n, b) in &cases {
        let k = unread(&a.seen, n);
        if k != 1 {
            bad.push(format!("{n}: {k} UnreadableConflict events, want 1"));
        }
        if std::fs::read(pkg.join(n)).ok().as_deref() != Some(&b[..]) {
            bad.push(format!("{n}: not left in place unchanged"));
        }
    }
    if std::fs::read(primary(&pkg)).unwrap() != ours {
        bad.push("primary changed".into());
    }
    if has(&a.seen, "SaveBlocked") {
        bad.push("a newer conflict copy raised SaveBlocked".into());
    }
    a.add_login("after", now_ms());
    if let Err(e) = a.s.save() {
        bad.push(format!("save after unreadable copies failed: {e:?}"));
    }
    assert!(bad.is_empty(), "{}\nevents {:?}", bad.join("\n"), a.seen);
}

/// 03 §6 step 1 applies to "the candidate" of both shapes (03 §1: "Conflict copies come in two
/// shapes"): a whole sibling package whose vault.bin is garbage or version 3.
#[test]
fn cf03_sibling_package_unreadable() {
    let d = tempdir();
    let st = tempdir();
    let (pkg, mut a) = setup(d.path(), "w.vault");
    let ours = std::fs::read(primary(&pkg)).unwrap();
    for (n, b) in [
        ("w 2.vault", garbage(3, 4000)),
        ("w 3.vault", with_version(&ours, 3)),
    ] {
        let sp = st.path().join(format!("{n}-staging"));
        std::fs::create_dir_all(sp.join("attachments")).unwrap();
        std::fs::write(sp.join("vault.bin"), &b).unwrap();
        std::fs::rename(&sp, d.path().join(n)).unwrap();
    }
    a.wait_for(8, |e| count(e, "UnreadableConflict") >= 2);
    for n in ["w 2.vault", "w 3.vault"] {
        let vb = d.path().join(n).join("vault.bin");
        let b = std::fs::read(&vb).unwrap();
        deliver(st.path(), &vb, &b);
    }
    a.wait_for(3, |_| false);
    // 03 §3: "`X.vault/attachments/*` (a late blob re-triggers a deferred package move)": a blob
    // arriving in an unreadable sibling is a new event but not new content of the candidate.
    std::fs::create_dir_all(d.path().join("w 2.vault/attachments")).unwrap();
    std::fs::write(
        d.path()
            .join("w 2.vault/attachments/0000000000000000000000000000abcd.bin"),
        b"late",
    )
    .unwrap();
    a.wait_for(3, |_| false);
    let mut bad = vec![];
    for n in ["w 2.vault", "w 3.vault"] {
        let k = unread(&a.seen, n);
        if k != 1 {
            bad.push(format!("{n}: {k} UnreadableConflict events, want 1"));
        }
        if !d.path().join(n).join("vault.bin").exists() {
            bad.push(format!("{n}: not left in place"));
        }
    }
    assert!(bad.is_empty(), "{}\nevents {:?}", bad.join("\n"), a.seen);
}

/// 03 §8: "until it parses, is absorbed or disappears". A copy that becomes readable is absorbed
/// (§6 steps 3-5); afterwards the same garbage bytes at the same path are a new copy and are
/// reported again.
#[test]
fn cf04_unreadable_then_readable_absorbed_then_again() {
    let d = tempdir();
    let st = tempdir();
    let (pkg, mut a) = setup(d.path(), "r.vault");
    let p = pkg.join("vault 2.bin");
    let g = garbage(4, 2500);
    deliver(st.path(), &p, &g);
    assert!(
        a.wait_for(8, |e| unread(e, "vault 2.bin") == 1),
        "{:?}",
        a.seen
    );
    let (good, id) = valid_copy(&pkg, "from-copy");
    deliver(st.path(), &p, &good);
    let absorbed = a.wait_for(8, |e| has(e, "ConflictAbsorbed"));
    a.wait_for(1, |_| false);
    let mut bad = vec![];
    if !absorbed {
        bad.push("a copy that became readable was not absorbed".into());
    }
    if a.v().get(id).is_none() {
        bad.push("item from the now-readable copy not merged".into());
    }
    if p.exists() {
        bad.push("absorbed copy still in place".into());
    }
    let in_backups = ls(&pkg.join("backups"))
        .iter()
        .any(|n| n.contains("vault 2.vault.bin"));
    if !in_backups {
        bad.push(format!(
            "absorbed copy not in backups: {:?}",
            ls(&pkg.join("backups"))
        ));
    }
    if unread(&a.seen, "vault 2.bin") != 1 {
        bad.push("the readable copy was reported unreadable".into());
    }
    deliver(st.path(), &p, &g);
    a.wait_for(5, |e| unread(e, "vault 2.bin") >= 2);
    if unread(&a.seen, "vault 2.bin") != 2 {
        bad.push(format!(
            "same garbage after absorption: {} events in total, want 2 (absorbed resets the memory)",
            unread(&a.seen, "vault 2.bin")
        ));
    }
    assert!(
        bad.is_empty(),
        "{}\nevents {:?}",
        bad.join("\n"),
        others(&a.seen)
    );
}

/// 03 §8: "… until it parses, is absorbed or disappears": remove the copy, bring the same bytes
/// back, reported again; also for a sibling package.
#[test]
fn cf05_disappear_then_reappear() {
    let d = tempdir();
    let st = tempdir();
    let (pkg, mut a) = setup(d.path(), "g.vault");
    let p = pkg.join("vault 2.bin");
    let g = garbage(5, 2000);
    deliver(st.path(), &p, &g);
    assert!(
        a.wait_for(8, |e| unread(e, "vault 2.bin") == 1),
        "{:?}",
        a.seen
    );
    std::fs::remove_file(&p).unwrap();
    a.wait_for(3, |_| false);
    deliver(st.path(), &p, &g);
    a.wait_for(6, |e| unread(e, "vault 2.bin") >= 2);
    let per_file = unread(&a.seen, "vault 2.bin");
    // sibling package
    let sib = d.path().join("g 2.vault");
    let mk = |b: &[u8]| {
        let sp = st.path().join(format!("s-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&sp).unwrap();
        std::fs::write(sp.join("vault.bin"), b).unwrap();
        std::fs::rename(&sp, &sib).unwrap();
    };
    mk(&g);
    a.wait_for(8, |e| unread(e, "g 2.vault") >= 1);
    std::fs::remove_dir_all(&sib).unwrap();
    a.wait_for(3, |_| false);
    mk(&g);
    a.wait_for(6, |e| unread(e, "g 2.vault") >= 2);
    let sibling = unread(&a.seen, "g 2.vault");
    assert!(
        per_file == 2 && sibling == 2,
        "after disappear + same bytes: per-file {per_file}, sibling {sibling}, want 2 and 2; events {:?}",
        others(&a.seen)
    );
}

/// 03 §8: "and again after lock/unlock". Also a copy that arrives while locked is reported by the
/// end (03 §6 step 2 defers only the merge; nothing says an unreadable copy may go unreported).
#[test]
fn cf06_lock_unlock_resets() {
    let d = tempdir();
    let st = tempdir();
    let (pkg, mut a) = setup(d.path(), "l.vault");
    let p = pkg.join("vault 2.bin");
    let g = garbage(7, 2222);
    deliver(st.path(), &p, &g);
    assert!(
        a.wait_for(8, |e| unread(e, "vault 2.bin") == 1),
        "{:?}",
        a.seen
    );
    let _ = a.s.lock();
    a.wait_for(1, |_| false);
    // a second copy arrives while locked
    let p3 = pkg.join("vault 3.bin");
    deliver(st.path(), &p3, &garbage(8, 1111));
    a.wait_for(3, |_| false);
    let while_locked = unread(&a.seen, "vault 3.bin");
    a.s.unlock(&pw(PW)).unwrap();
    a.wait_for(3, |_| false);
    let at_unlock_2 = unread(&a.seen, "vault 2.bin");
    let at_unlock_3 = unread(&a.seen, "vault 3.bin");
    deliver(st.path(), &p, &g);
    a.wait_for(4, |e| unread(e, "vault 2.bin") >= 2);
    a.wait_for(1, |_| false);
    let total_2 = unread(&a.seen, "vault 2.bin");
    eprintln!(
        "INFO vault 3.bin while locked: {while_locked}; after unlock (no touch): vault 2.bin {at_unlock_2}, vault 3.bin {at_unlock_3}; vault 2.bin after same-bytes re-delivery: {total_2}"
    );
    let mut bad = vec![];
    if total_2 != 2 {
        bad.push(format!(
            "vault 2.bin: {total_2} events across lock/unlock + re-delivery, want exactly 2"
        ));
    }
    if at_unlock_3 == 0 {
        bad.push("a garbage copy that arrived while locked was never reported (none while locked, none after unlock)".into());
    }
    if !p.exists() || !p3.exists() {
        bad.push("copy not left in place".into());
    }
    assert!(
        bad.is_empty(),
        "{}\nevents {:?}",
        bad.join("\n"),
        others(&a.seen)
    );
}

/// 03 §8: "and again after … stop/start watching"; stop_watching "discards queued signals".
#[test]
fn cf07_stop_start_watching_resets() {
    let d = tempdir();
    let st = tempdir();
    let (pkg, mut a) = setup(d.path(), "s.vault");
    let p = pkg.join("vault 2.bin");
    let g = garbage(9, 1800);
    deliver(st.path(), &p, &g);
    assert!(
        a.wait_for(8, |e| unread(e, "vault 2.bin") == 1),
        "{:?}",
        a.seen
    );
    a.s.stop_watching();
    a.s.start_watching().unwrap();
    settle();
    a.wait_for(2, |_| false);
    let at_restart = unread(&a.seen, "vault 2.bin");
    deliver(st.path(), &p, &g);
    a.wait_for(5, |e| unread(e, "vault 2.bin") >= 2);
    a.wait_for(1, |_| false);
    let total = unread(&a.seen, "vault 2.bin");
    // a copy dropped while not watching (§3: no initial tree scan): record only
    a.s.stop_watching();
    let p4 = pkg.join("vault 4.bin");
    deliver(st.path(), &p4, &garbage(10, 900));
    a.s.start_watching().unwrap();
    settle();
    a.wait_for(3, |_| false);
    eprintln!(
        "INFO at restart without touch: {at_restart}; copy dropped while stopped reported after start: {}",
        unread(&a.seen, "vault 4.bin")
    );
    assert_eq!(
        total,
        2,
        "same bytes after stop/start: {total} events in total, want 2; events {:?}",
        others(&a.seen)
    );
}

/// 03 §8 "once per path and content": two paths with identical bytes are two copies.
#[test]
fn cf08_same_bytes_two_paths() {
    let d = tempdir();
    let st = tempdir();
    let (pkg, mut a) = setup(d.path(), "p.vault");
    let g = garbage(11, 1500);
    deliver(st.path(), &pkg.join("vault 2.bin"), &g);
    deliver(st.path(), &pkg.join("vault 3.bin"), &g);
    a.wait_for(8, |e| count(e, "UnreadableConflict") >= 2);
    a.wait_for(2, |_| false);
    let (x, y) = (
        unread(&a.seen, "vault 2.bin"),
        unread(&a.seen, "vault 3.bin"),
    );
    assert!(x == 1 && y == 1, "per path: {x}, {y}; events {:?}", a.seen);
}

/// 03 §3 classification: only `<name>.vault/vault*.bin` (other than vault.bin) and sibling
/// `X.vault/` packages are candidates; attachments/**, backups/**, tmp files and deeper paths are
/// ignored. Garbage in those places is never an UnreadableConflict.
#[test]
fn cf09_non_candidates_silent() {
    let d = tempdir();
    let st = tempdir();
    let (pkg, mut a) = setup(d.path(), "n.vault");
    let g = garbage(12, 700);
    std::fs::create_dir_all(pkg.join("attachments")).unwrap();
    std::fs::create_dir_all(pkg.join("deeper")).unwrap();
    for rel in [
        "notes.bin",
        "backups/n-2026-01-01T00-00-00Z.vault.bin",
        ".vault.bin.tmp-deadbeef",
        "attachments/00000000000000000000000000000abc.bin",
        "deeper/vault 2.bin",
        "vault.bin.bak",
    ] {
        deliver(st.path(), &pkg.join(rel), &g);
    }
    std::fs::create_dir_all(d.path().join("not-a-package")).unwrap();
    deliver(
        st.path(),
        &d.path().join("not-a-package").join("vault.bin"),
        &g,
    );
    a.wait_for(4, |_| false);
    assert_eq!(
        count(&a.seen, "UnreadableConflict"),
        0,
        "non-candidate paths reported; events {:?}",
        a.seen
    );
}

struct SlowCloud {
    fail_for: Mutex<Option<String>>,
}
impl vault_sync::CloudHooks for SlowCloud {
    fn is_evicted(&self, path: &Path) -> bool {
        let f = self.fail_for.lock().unwrap();
        f.as_ref()
            .is_some_and(|n| path.to_string_lossy().contains(n.as_str()))
    }
    fn ensure_downloaded(&self, path: &Path, _t: Duration) -> Result<(), vault_sync::CloudError> {
        if self.is_evicted(path) {
            Err(vault_sync::CloudError::Timeout)
        } else {
            Ok(())
        }
    }
    fn pin(&self, _path: &Path) {}
}

/// 03 §6 step 1: "a copy a provider is still downloading waits via §7 instead" (not reported as
/// unreadable); once downloadable and valid it is absorbed.
#[test]
fn cf10_downloading_copy_waits() {
    let d = tempdir();
    let st = tempdir();
    let pkg = d.path().join("c.vault");
    let hooks = Arc::new(SlowCloud {
        fail_for: Mutex::new(None),
    });
    let dev = uuid::Uuid::new_v4();
    let s = SyncedVault::create(
        &pkg,
        &pw(PW),
        vault_core::KdfParams::for_tests(),
        dev,
        hooks.clone(),
    )
    .unwrap();
    let rx = s.subscribe();
    let mut a = Dev {
        s,
        rx,
        seen: vec![],
        dev,
    };
    a.add_login("base", now_ms());
    a.s.save().unwrap();
    a.s.start_watching().unwrap();
    settle();
    *hooks.fail_for.lock().unwrap() = Some("vault 2.bin".into());
    let p = pkg.join("vault 2.bin");
    deliver(st.path(), &p, &garbage(13, 64)); // placeholder bytes
    a.wait_for(4, |_| false);
    let while_downloading = unread(&a.seen, "vault 2.bin");
    let cloud = count(&a.seen, "CloudUnavailable");
    *hooks.fail_for.lock().unwrap() = None;
    let (good, id) = valid_copy(&pkg, "downloaded");
    deliver(st.path(), &p, &good);
    let absorbed = a.wait_for(8, |e| has(e, "ConflictAbsorbed"));
    eprintln!("INFO while downloading: CloudUnavailable {cloud}");
    let mut bad = vec![];
    if while_downloading != 0 {
        bad.push(format!(
            "{while_downloading} UnreadableConflict while ensure_downloaded failed"
        ));
    }
    if !absorbed || a.v().get(id).is_none() {
        bad.push("not absorbed once downloaded".into());
    }
    assert!(
        bad.is_empty(),
        "{}\nevents {:?}",
        bad.join("\n"),
        others(&a.seen)
    );
}

/// Builds a whole-package copy of `pkg` that references a blob missing from both sides.
fn waiting_copy(pkg: &Path, item: uuid::Uuid) -> (tempfile::TempDir, PathBuf, String, Vec<u8>) {
    let st = tempdir();
    let staging = st.path().join("staging.vault");
    copy_dir(pkg, &staging);
    let mut c = Dev::open(&staging);
    let aid =
        c.s.add_attachment(item, "late.txt", &b"late blob"[..], 9, now_ms())
            .unwrap();
    c.s.save().unwrap();
    drop(c);
    let blob = format!("{}.bin", hex(aid));
    let held = std::fs::read(staging.join("attachments").join(&blob)).unwrap();
    std::fs::remove_file(staging.join("attachments").join(&blob)).unwrap();
    (st, staging, blob, held)
}

/// 03 §6 step 1/4 bookkeeping side by side: ForeignVault "once per sibling", WaitingForBlobs "once
/// per waiting package", UnreadableConflict once per path and content; none disturbs the others,
/// and ConflictAbsorbed follows the late blob.
#[test]
fn cf11_foreign_waiting_unreadable_together() {
    let d = tempdir();
    let st = tempdir();
    let pkg = d.path().join("m.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("host", now_ms());
    a.s.save().unwrap();
    let (_wst, waiting, blob, held) = waiting_copy(&pkg, item);
    let other = tempdir();
    let fpkg = other.path().join("m.vault");
    let mut f = Dev::create(&fpkg);
    f.add_login("foreign", now_ms());
    f.s.save().unwrap();
    drop(f);
    a.s.start_watching().unwrap();
    settle();
    copy_dir(&fpkg, &d.path().join("m 2.vault"));
    std::fs::rename(&waiting, d.path().join("m 3.vault")).unwrap();
    deliver(st.path(), &pkg.join("vault 2.bin"), &garbage(14, 1200));
    a.wait_for(8, |e| {
        has(e, "ForeignVault") && has(e, "WaitingForBlobs") && has(e, "UnreadableConflict")
    });
    for _ in 0..2 {
        for vb in [
            d.path().join("m 2.vault/vault.bin"),
            d.path().join("m 3.vault/vault.bin"),
            pkg.join("vault 2.bin"),
        ] {
            let b = std::fs::read(&vb).unwrap();
            deliver(st.path(), &vb, &b);
        }
        a.wait_for(2, |_| false);
    }
    let counts = (
        count(&a.seen, "ForeignVault"),
        count(&a.seen, "WaitingForBlobs"),
        count(&a.seen, "UnreadableConflict"),
    );
    std::fs::write(d.path().join("m 3.vault/attachments").join(&blob), &held).unwrap();
    let absorbed = a.wait_for(8, |e| has(e, "ConflictAbsorbed"));
    a.wait_for(1, |_| false);
    let mut bad = vec![];
    if counts != (1, 1, 1) {
        bad.push(format!(
            "(ForeignVault, WaitingForBlobs, UnreadableConflict) = {counts:?}, want (1, 1, 1)"
        ));
    }
    if !absorbed || d.path().join("m 3.vault").exists() {
        bad.push("waiting package not absorbed after its blob arrived".into());
    }
    if !d.path().join("m 2.vault/vault.bin").exists() || !pkg.join("vault 2.bin").exists() {
        bad.push("foreign sibling or unreadable copy moved".into());
    }
    if count(&a.seen, "UnreadableConflict") != 1 {
        bad.push("absorption of another package re-reported the unreadable copy".into());
    }
    assert!(
        bad.is_empty(),
        "{}\nevents {:?}",
        bad.join("\n"),
        others(&a.seen)
    );
}

/// A sibling package that is first unreadable, then readable but waiting for a blob, then complete:
/// one UnreadableConflict, one WaitingForBlobs, then ConflictAbsorbed (03 §6 step 1 and 4).
#[test]
fn cf12_sibling_unreadable_then_waiting_then_absorbed() {
    let d = tempdir();
    let st = tempdir();
    let pkg = d.path().join("k.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("host", now_ms());
    a.s.save().unwrap();
    let (_wst, waiting, blob, held) = waiting_copy(&pkg, item);
    let good = std::fs::read(waiting.join("vault.bin")).unwrap();
    std::fs::write(waiting.join("vault.bin"), garbage(15, 3000)).unwrap();
    a.s.start_watching().unwrap();
    settle();
    let sib = d.path().join("k 2.vault");
    std::fs::rename(&waiting, &sib).unwrap();
    a.wait_for(8, |e| has(e, "UnreadableConflict"));
    deliver(st.path(), &sib.join("vault.bin"), &good);
    a.wait_for(8, |e| has(e, "WaitingForBlobs"));
    std::fs::write(sib.join("attachments").join(&blob), &held).unwrap();
    let absorbed = a.wait_for(8, |e| has(e, "ConflictAbsorbed"));
    let c = (
        unread(&a.seen, "k 2.vault"),
        count(&a.seen, "WaitingForBlobs"),
        absorbed,
        sib.exists(),
    );
    assert_eq!(
        c,
        (1, 1, true, false),
        "(unreadable, waiting, absorbed, still in place); events {:?}",
        others(&a.seen)
    );
}

/// A provider creates the sibling directory before its vault.bin arrives (iCloud downloads files
/// one by one). 03 §2 allows a conflict package "with or without a `vault.bin`"; the final state
/// must be absorbed. Records whether the empty-directory moment was reported as unreadable.
#[test]
fn cf13_sibling_dir_before_its_vault_bin() {
    let d = tempdir();
    let st = tempdir();
    let (pkg, mut a) = setup(d.path(), "e.vault");
    let (good, id) = valid_copy(&pkg, "late file");
    let sib = d.path().join("e 2.vault");
    std::fs::create_dir_all(sib.join("attachments")).unwrap();
    a.wait_for(3, |_| false);
    let early = unread(&a.seen, "e 2.vault");
    let before_file = others(&a.seen).len();
    let moved_early = !sib.exists();
    if moved_early {
        std::fs::create_dir_all(&sib).unwrap();
    }
    deliver(st.path(), &sib.join("vault.bin"), &good);
    let absorbed = a.wait_for(8, |e| has(e, "ConflictAbsorbed"));
    eprintln!(
        "INFO empty sibling dir before vault.bin: UnreadableConflict {early}; events before file {before_file}; dir moved before its vault.bin arrived: {moved_early}; ConflictAbsorbed total {}",
        count(&a.seen, "ConflictAbsorbed")
    );
    assert!(
        absorbed && a.v().get(id).is_some(),
        "sibling whose vault.bin arrived late not absorbed; events {:?}",
        others(&a.seen)
    );
    assert_eq!(
        unread(&a.seen, "e 2.vault"),
        0,
        "a directory without vault.bin (yet) reported as an unreadable copy"
    );
}

/// 03 §8 restore_from "snapshots the current file first"; §6 "Never delete a conflict copy".
/// Restoring while an unreadable copy sits in the package leaves the copy alone.
#[test]
fn cf14_restore_with_unreadable_copy_present() {
    let d = tempdir();
    let st = tempdir();
    let (pkg, mut a) = setup(d.path(), "b.vault");
    let backup = a.s.backup_now().unwrap();
    a.add_login("later", now_ms());
    a.s.save().unwrap();
    let p = pkg.join("vault 2.bin");
    let g = garbage(16, 2600);
    deliver(st.path(), &p, &g);
    assert!(
        a.wait_for(8, |e| unread(e, "vault 2.bin") == 1),
        "{:?}",
        a.seen
    );
    let r = a.s.restore_from(&backup, &pw(PW));
    a.wait_for(3, |_| false);
    eprintln!(
        "INFO after restore: UnreadableConflict count {}",
        unread(&a.seen, "vault 2.bin")
    );
    let mut bad = vec![];
    if let Err(e) = &r {
        bad.push(format!("restore failed: {e:?}"));
    }
    if std::fs::read(&p).ok().as_deref() != Some(&g[..]) {
        bad.push("unreadable copy touched by restore".into());
    }
    if read_vault(&pkg).items().any(|i| i.title == "later") {
        bad.push("restore did not replace the vault".into());
    }
    if unread(&a.seen, "vault 2.bin") > 2 {
        bad.push("restore produced repeated reports".into());
    }
    assert!(
        bad.is_empty(),
        "{}\nevents {:?}",
        bad.join("\n"),
        others(&a.seen)
    );
}

/// 03 §3 (2026-11-21 L3): "If the on-disk file has a newer `FORMAT_VERSION` (strictly above
/// ours; version 0 or any other unsupported value is corruption and takes the step-3 corruption
/// path …)". 03 §9: "Corrupt the primary on disk → `CorruptOnDisk`, in-memory state intact, next
/// `save` rewrites a valid file." 05 §2.2: the locked-time card is raised by
/// `SaveBlocked(NewerVersion)`, so version 0 must never produce it, locked or unlocked.
#[test]
fn cf15_primary_version0_vs_newer_unlocked_and_locked() {
    let mut bad = vec![];
    let mut info = vec![];
    for (ver, locked) in [
        (0u16, false),
        (3, false),
        (0, true),
        (3, true),
        (0xFFFF, true),
    ] {
        let d = tempdir();
        let st = tempdir();
        let (pkg, mut a) = setup(d.path(), "z.vault");
        let snap = snap_vault(a.v());
        if locked {
            let _ = a.s.lock();
            a.wait_for(1, |_| false);
        }
        let n0 = a.seen.len();
        let ours = std::fs::read(primary(&pkg)).unwrap();
        let altered = with_version(&ours, ver);
        deliver(st.path(), &primary(&pkg), &altered);
        a.wait_for(4, |_| false);
        let ev: Vec<String> = a.seen[n0..]
            .iter()
            .filter(|e| !e.starts_with("BackupTaken"))
            .cloned()
            .collect();
        let newer = ev.iter().any(|e| e.contains("NewerVersion"));
        let corrupt = ev.iter().any(|e| e.starts_with("CorruptOnDisk"));
        info.push(format!("version {ver} locked={locked}: {ev:?}"));
        if ver == 0 && newer {
            bad.push(format!(
                "version 0 (locked={locked}) reported as NewerVersion: {ev:?}"
            ));
        }
        if ver != 0 && !newer {
            bad.push(format!(
                "version {ver} (locked={locked}) did not report SaveBlocked(NewerVersion): {ev:?}"
            ));
        }
        if !locked {
            if ver == 0 && !corrupt {
                bad.push(format!("version 0 unlocked: no CorruptOnDisk: {ev:?}"));
            }
            if snap_vault(a.v()) != snap {
                bad.push(format!("version {ver}: in-memory state changed"));
            }
            a.add_login("next", now_ms());
            let r = a.s.save();
            let disk = std::fs::read(primary(&pkg)).unwrap();
            if ver == 0 {
                if r.is_err() || version_of(&disk) != vault_core::FORMAT_VERSION {
                    bad.push(format!(
                        "version 0: next save should rewrite a valid file (03 §9): save {:?}, on-disk version {}",
                        r.err(),
                        version_of(&disk)
                    ));
                }
            } else if r.is_ok() || disk != altered {
                bad.push(format!(
                    "version {ver}: save not refused or newer file overwritten"
                ));
            }
        } else {
            let r = a.s.unlock(&pw(PW));
            info.push(format!("  unlock after: {:?}", r.as_ref().err()));
            if r.is_ok() {
                a.add_login("after", now_ms());
                let sv = a.s.save();
                let disk = std::fs::read(primary(&pkg)).unwrap();
                info.push(format!("  save after: {:?}", sv.as_ref().err()));
                if ver != 0 && (sv.is_ok() || disk != altered) {
                    bad.push(format!("version {ver} locked: newer file overwritten"));
                }
            }
        }
    }
    eprintln!("{}", info.join("\n"));
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §8: "`restore_from` … works even when the primary no longer parses (a version-0 primary
/// counts as unparseable and is kept as an `Unsaved` backup; only a version strictly above ours
/// refuses the restore as `NewerVersion`".
#[test]
fn cf16_restore_over_version0_and_newer_primary() {
    let mut bad = vec![];
    for ver in [0u16, 3] {
        let d = tempdir();
        let st = tempdir();
        let (pkg, mut a) = setup(d.path(), "q.vault");
        let backup = a.s.backup_now().unwrap();
        let ours = std::fs::read(primary(&pkg)).unwrap();
        let altered = with_version(&ours, ver);
        deliver(st.path(), &primary(&pkg), &altered);
        a.wait_for(3, |_| false);
        let before: Vec<String> = ls(&pkg.join("backups"));
        let r = a.s.restore_from(&backup, &pw(PW));
        let disk = std::fs::read(primary(&pkg)).unwrap();
        let new_backups: Vec<String> = ls(&pkg.join("backups"))
            .into_iter()
            .filter(|n| !before.contains(n))
            .collect();
        if ver == 0 {
            if let Err(e) = &r {
                bad.push(format!("version 0 primary: restore refused: {e:?}"));
            }
            if version_of(&disk) != vault_core::FORMAT_VERSION {
                bad.push("version 0 primary: not replaced".into());
            }
            let kept = new_backups.iter().any(|n| {
                n.contains("unsaved")
                    && std::fs::read(pkg.join("backups").join(n)).ok().as_deref()
                        == Some(&altered[..])
            });
            if !kept {
                bad.push(format!(
                    "version 0 primary not kept as an Unsaved backup; new: {new_backups:?}"
                ));
            }
        } else {
            if !format!("{:?}", r).contains("NewerVersion") {
                bad.push(format!(
                    "version 3 primary: restore result {:?}, want NewerVersion",
                    r.err()
                ));
            }
            if disk != altered {
                bad.push("version 3 primary overwritten by restore".into());
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §2: conflict-copy sources are opened `O_NOFOLLOW` and capped at 64 MiB ("refuse larger
/// files with a typed error before parsing"); §6 "Never delete a conflict copy". Records which event
/// an oversized or symlinked per-file copy produces (03 §6 step 1 names only "does not parse" and
/// "unsupported format version").
#[test]
fn cf17_oversize_and_symlink_copies() {
    let d = tempdir();
    let st = tempdir();
    let (pkg, mut a) = setup(d.path(), "o.vault");
    let big = pkg.join("vault 2.bin");
    let f = std::fs::File::create(st.path().join("big")).unwrap();
    f.set_len(65 * 1024 * 1024).unwrap();
    drop(f);
    std::fs::rename(st.path().join("big"), &big).unwrap();
    let target = st.path().join("target.bin");
    std::fs::write(&target, std::fs::read(primary(&pkg)).unwrap()).unwrap();
    let link = pkg.join("vault 3.bin");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    a.wait_for(5, |_| false);
    eprintln!(
        "INFO oversize: unreadable {}; symlink: unreadable {}; events {:?}",
        unread(&a.seen, "vault 2.bin"),
        unread(&a.seen, "vault 3.bin"),
        others(&a.seen)
            .iter()
            .map(|e| e.replace(&*d.path().to_string_lossy(), "<tmp>"))
            .collect::<Vec<_>>()
    );
    let errs0 = count(&a.seen, "Error");
    for _ in 0..2 {
        let f = std::fs::File::create(st.path().join("big")).unwrap();
        f.set_len(65 * 1024 * 1024).unwrap();
        drop(f);
        std::fs::rename(st.path().join("big"), &big).unwrap();
        a.wait_for(2, |_| false);
    }
    eprintln!(
        "INFO oversize copy re-delivered twice with the same (zero) bytes: Error events {errs0} -> {}",
        count(&a.seen, "Error")
    );
    assert!(
        big.exists() && std::fs::symlink_metadata(&link).is_ok(),
        "copy deleted"
    );
    assert!(target.exists(), "symlink target touched");
    assert!(!has(&a.seen, "ConflictAbsorbed"), "symlinked copy absorbed");
}

/// 03 §2 watcher bounds: "A poll processes at most 8 candidates … callers loop on `poll()` until it
/// returns 0". 40 unreadable copies: the loop terminates and each is reported exactly once.
#[test]
fn cf18_many_unreadable_copies_drain_terminates() {
    let d = tempdir();
    let st = tempdir();
    let (pkg, mut a) = setup(d.path(), "y.vault");
    for k in 0..40u8 {
        deliver(
            st.path(),
            &pkg.join(format!("vault {}.bin", k as u32 + 2)),
            &garbage(100 + k, 300),
        );
    }
    std::thread::sleep(Duration::from_millis(1500));
    let t = Instant::now();
    let mut polls = 0;
    loop {
        let n = a.s.poll();
        polls += 1;
        while let Ok(e) = a.rx.try_recv() {
            a.seen.push(format!("{e:?}"));
        }
        if n == 0 && count(&a.seen, "UnreadableConflict") >= 40 {
            break;
        }
        if t.elapsed() > Duration::from_secs(25) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    a.wait_for(2, |_| false);
    let c = count(&a.seen, "UnreadableConflict");
    eprintln!("INFO {polls} polls in {:?}", t.elapsed());
    assert_eq!(
        c,
        40,
        "40 unreadable copies -> {c} events in {:?}",
        t.elapsed()
    );
}

/// 05 §2.3 (owner decision 2026-11-21): the danger pill's "text contrast is at least 4.5:1 in both
/// appearances: in light mode the fill is darkened to #18181B under #E5484D text, in dark mode the
/// light fill stays and the text … #DE2026 (… because no lighter fill reaches 4.5:1)". 05 §5:
/// bg-elevated light #F7F7F8, danger #E5484D. WCAG 2 relative luminance, computed here.
#[test]
fn cf19_danger_pill_contrast_arithmetic() {
    fn lin(c: u8) -> f64 {
        let s = c as f64 / 255.0;
        if s <= 0.04045 {
            s / 12.92
        } else {
            ((s + 0.055) / 1.055).powf(2.4)
        }
    }
    fn lum(hex: u32) -> f64 {
        0.2126 * lin((hex >> 16) as u8) + 0.7152 * lin((hex >> 8) as u8) + 0.0722 * lin(hex as u8)
    }
    fn ratio(a: u32, b: u32) -> f64 {
        let (x, y) = (lum(a), lum(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }
    let light = ratio(0xE5484D, 0x18181B);
    let dark = ratio(0xDE2026, 0xF7F7F8);
    let white = ratio(0xE5484D, 0xFFFFFF);
    eprintln!(
        "INFO #E5484D/#18181B {light:.2}; #DE2026/#F7F7F8 {dark:.2}; #E5484D/#FFFFFF {white:.2}"
    );
    assert!(light >= 4.5, "light-mode danger pill {light:.2}:1");
    assert!(dark >= 4.5, "dark-mode danger pill {dark:.2}:1");
    assert!(
        white < 4.5,
        "spec claim 'no lighter fill reaches 4.5:1' for #E5484D: white gives {white:.2}"
    );
}

/// 01 §4 (aligned 2026-11-21): "Files without the stamp (every v1.0 file and the unstamped
/// fixtures, e.g. `v1-basic`, `v1-empty`; `v1-stamped`, `v1-icon`, `v1-meta`, `v2-basic`,
/// `v2-field-icon`, `v2-meta` and `v2-trash-legacy` carry it)".
#[test]
fn cf20_fixture_stamp_sentence() {
    let mut bad = vec![];
    for n in ["v1-basic", "v1-empty"] {
        let raw = split(&fixture(&format!("{n}.vault")));
        if get(&raw.header, "slots_modified_at").is_some() {
            bad.push(format!("{n} carries slots_modified_at"));
        }
    }
    for n in [
        "v1-stamped",
        "v1-icon",
        "v1-meta",
        "v2-basic",
        "v2-field-icon",
        "v2-meta",
        "v2-trash-legacy",
    ] {
        let raw = split(&fixture(&format!("{n}.vault")));
        if get(&raw.header, "slots_modified_at").is_none() {
            bad.push(format!("{n} lacks slots_modified_at"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §2 D-1: "every file the package opens (… conflict-copy sources) is opened with `O_NOFOLLOW`
/// and must be a regular file after `fstat`; a symlink or special file is `UnsafePackageEntry`,
/// never a silent fallback"; 03 §6 step 1 (2026-11-21) leaves no candidate unreported. A symlinked
/// or FIFO per-file copy must produce some event (and never be followed or absorbed).
#[test]
fn cf21_symlink_or_fifo_per_file_copy_not_silent() {
    let mut bad = vec![];
    for kind in ["symlink", "fifo", "symlinked sibling package"] {
        let d = tempdir();
        let st = tempdir();
        let (pkg, mut a) = setup(d.path(), "x.vault");
        let (good, id) = valid_copy(&pkg, "behind the link");
        let target = st.path().join("target.bin");
        std::fs::write(&target, &good).unwrap();
        let p = pkg.join("vault 2.bin");
        let sib = d.path().join("x 2.vault");
        if kind == "symlinked sibling package" {
            let real = st.path().join("real.vault");
            std::fs::create_dir_all(&real).unwrap();
            std::fs::write(real.join("vault.bin"), &good).unwrap();
            std::os::unix::fs::symlink(&real, &sib).unwrap();
            std::fs::write(&p, b"placeholder").unwrap();
            std::fs::remove_file(&p).unwrap();
        } else if kind == "symlink" {
            std::os::unix::fs::symlink(&target, &p).unwrap();
        } else {
            let st = std::process::Command::new("mkfifo")
                .arg(&p)
                .status()
                .unwrap();
            assert!(st.success());
        }
        a.wait_for(5, |e| !others(e).is_empty());
        let ev = others(&a.seen);
        if a.v().get(id).is_some() || has(&a.seen, "ConflictAbsorbed") {
            bad.push(format!("{kind}: followed and absorbed"));
        }
        if ev.is_empty() {
            bad.push(format!("{kind}: no event at all (silently skipped)"));
        }
        let kept = if kind == "symlinked sibling package" {
            std::fs::symlink_metadata(&sib).is_ok()
        } else {
            std::fs::symlink_metadata(&p).is_ok()
        };
        if !kept {
            bad.push(format!("{kind}: copy removed"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §8: `SaveBlocked` is "emitted once at first detection and once per refused save". A newer
/// file that arrives while *unlocked*, followed by lock and unlock: records which reports the app
/// can see while locked (05 §2.2 raises the card only on a report while locked) and checks the 03
/// counts: one at detection, none from lock/unlock themselves, one per refused save.
#[test]
fn cf22_newer_primary_arrives_unlocked_then_lock_unlock() {
    let d = tempdir();
    let st = tempdir();
    let (pkg, mut a) = setup(d.path(), "h.vault");
    let ours = std::fs::read(primary(&pkg)).unwrap();
    let newer = with_version(&ours, 3);
    deliver(st.path(), &primary(&pkg), &newer);
    a.wait_for(5, |e| has(e, "SaveBlocked"));
    let at_detection = count(&a.seen, "SaveBlocked");
    let outcome = a.s.lock();
    a.wait_for(2, |_| false);
    let while_locked = count(&a.seen, "SaveBlocked");
    let unlock = a.s.unlock(&pw(PW));
    a.wait_for(2, |_| false);
    let after_unlock = count(&a.seen, "SaveBlocked");
    let mut save = None;
    if unlock.is_ok() {
        a.add_login("edit", now_ms());
        save = Some(format!("{:?}", a.s.save().err()));
        a.wait_for(1, |_| false);
    }
    let after_save = count(&a.seen, "SaveBlocked");
    eprintln!(
        "INFO SaveBlocked counts: detection {at_detection}, after lock {while_locked} (lock outcome {}), after unlock {after_unlock} (unlock {:?}), after a refused save {after_save} ({save:?})",
        format!("{outcome:?}").split('(').next().unwrap_or(""),
        unlock.as_ref().err()
    );
    let mut bad = vec![];
    if at_detection != 1 {
        bad.push(format!(
            "{at_detection} SaveBlocked at first detection, want 1"
        ));
    }
    if after_unlock != at_detection {
        bad.push("lock/unlock emitted SaveBlocked although nothing new was detected".into());
    }
    if unlock.is_ok() && after_save != after_unlock + 1 {
        bad.push(format!(
            "refused save: SaveBlocked {after_unlock} -> {after_save}, want +1"
        ));
    }
    if std::fs::read(primary(&pkg)).unwrap() != newer {
        bad.push("newer file overwritten".into());
    }
    assert!(
        bad.is_empty(),
        "{}\nevents {:?}",
        bad.join("\n"),
        others(&a.seen)
    );
}
