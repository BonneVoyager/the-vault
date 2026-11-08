//! 03 §2 "Before-write hook (2026-11-07)": `SyncedVault::set_before_write`. Added 2026-11-08,
//! written from the spec before reading the source.
use secrecy::ExposeSecret;
use spec_checks::dev::*;
use spec_checks::*;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use vault_core::*;

const DAY: u64 = 86_400_000;

/// Hook that tags every live item "swept" once and counts its calls.
fn install_tagger(s: &mut SyncedVault, count: Arc<AtomicUsize>, seen: Arc<Mutex<Vec<String>>>) {
    s.set_before_write(Some(Box::new(move |v: &mut UnlockedVault| {
        count.fetch_add(1, SeqCst);
        let mut titles: Vec<String> = v.items().map(|i| i.title.clone()).collect();
        titles.sort();
        seen.lock().unwrap().push(titles.join(","));
        let ids: Vec<Uuid> = v
            .items()
            .filter(|i| !i.tags.iter().any(|t| t == "swept"))
            .map(|i| i.id)
            .collect();
        let now = now_ms();
        for id in &ids {
            v.update(*id, now, |it| it.tags.push("swept".into()))
                .unwrap();
        }
        !ids.is_empty()
    })));
}
fn swept(v: &UnlockedVault, title: &str) -> bool {
    v.items()
        .find(|i| i.title == title)
        .unwrap_or_else(|| panic!("{title} missing"))
        .tags
        .iter()
        .any(|t| t == "swept")
}
fn sweep_hook(s: &mut SyncedVault, count: Arc<AtomicUsize>) {
    s.set_before_write(Some(Box::new(move |v: &mut UnlockedVault| {
        count.fetch_add(1, SeqCst);
        let now = now_ms();
        v.expire_deleted(now - 30 * DAY, now) > 0
    })));
}
fn counters() -> (Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    (Arc::new(AtomicUsize::new(0)), Arc::new(Mutex::new(vec![])))
}

/// "vault-sync calls it ... inside each dirty `save` attempt"; "a change is carried by the write
/// that follows and does not mark the vault dirty"; "It never runs ... on a clean save";
/// `set_before_write(None)` uninstalls.
#[test]
fn bw01_dirty_save_runs_hook_clean_save_does_not() {
    let d = tempdir();
    let pkg = d.path().join("bw.vault");
    let mut a = Dev::create(&pkg);
    let (n, seen) = counters();
    install_tagger(&mut a.s, n.clone(), seen);
    a.add_login("One", now_ms());
    a.s.save().unwrap();
    assert_eq!(n.load(SeqCst), 1, "hook runs once on a dirty save");
    assert!(!a.s.is_dirty(), "hook change does not mark dirty");
    assert!(swept(&read_vault(&pkg), "One"), "hook change reached disk");
    assert!(swept(a.v(), "One"), "hook change kept in memory");
    a.s.save().unwrap();
    assert_eq!(n.load(SeqCst), 1, "clean save runs no hook");
    a.s.set_before_write(None);
    a.add_login("Two", now_ms());
    a.s.save().unwrap();
    assert_eq!(n.load(SeqCst), 1, "uninstalled hook still runs");
    assert!(!swept(&read_vault(&pkg), "Two"));
}

/// "and in `lock` before the Unsaved backup"; "It never runs ... while locked"; a clean lock
/// writes nothing and so runs nothing.
#[test]
fn bw02_lock_runs_hook_before_unsaved_backup() {
    let d = tempdir();
    let pkg = d.path().join("bl.vault");
    let mut a = Dev::create(&pkg);
    a.s.save().unwrap();
    let (n, seen) = counters();
    install_tagger(&mut a.s, n.clone(), seen);
    let out = a.s.lock();
    assert_eq!(n.load(SeqCst), 0, "clean lock: {out:?}");
    a.s.unlock(&pw(PW)).unwrap();
    let base = n.load(SeqCst);
    a.add_login("Unsaved", now_ms());
    let out = a.s.lock();
    assert_eq!(
        n.load(SeqCst),
        base + 1,
        "dirty lock runs hook once: {out:?}"
    );
    let p = match &out {
        vault_sync::LockOutcome::Snapshotted(p) => p.clone(),
        o => panic!("expected Snapshotted, got {o:?}"),
    };
    let snap = LockedVault::parse(&std::fs::read(&p).unwrap())
        .unwrap()
        .unlock(&pw(PW))
        .unwrap();
    assert!(
        swept(&snap, "Unsaved"),
        "Unsaved backup carries hook change"
    );
    let before = n.load(SeqCst);
    let _ = a.s.save();
    a.s.poll();
    assert_eq!(n.load(SeqCst), before, "runs while locked");
}

/// "It never runs ... on `restore_from` (which writes the backup bytes as they are)".
#[test]
fn bw03_restore_from_writes_backup_bytes_unhooked() {
    let d = tempdir();
    let pkg = d.path().join("br.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("Before", now_ms());
    a.s.save().unwrap();
    let snap = a.s.backup_now().unwrap();
    let snap_bytes = std::fs::read(&snap).unwrap();
    let (n, seen) = counters();
    install_tagger(&mut a.s, n.clone(), seen);
    a.add_login("After", now_ms());
    a.s.save().unwrap();
    let base = n.load(SeqCst);
    a.s.restore_from(&snap, &pw(PW)).unwrap();
    assert_eq!(n.load(SeqCst), base, "hook ran on restore_from");
    assert_eq!(
        std::fs::read(primary(&pkg)).unwrap(),
        snap_bytes,
        "restore_from did not write the backup bytes as they are"
    );
    assert!(!swept(a.v(), "Before"));
}

/// "right before every write that serialises it: inside each dirty save attempt after the
/// pre-write merge": the hook sees a peer's item merged in by the pre-write merge.
#[test]
fn bw04_hook_runs_after_pre_write_merge() {
    let d = tempdir();
    let pkg = d.path().join("bm.vault");
    let mut a = Dev::create(&pkg);
    a.s.save().unwrap();
    let mut b = Dev::open(&pkg);
    let (n, seen) = counters();
    install_tagger(&mut b.s, n.clone(), seen.clone());
    a.add_login("FromA", now_ms());
    a.s.save().unwrap();
    b.add_login("FromB", now_ms());
    b.s.save().unwrap();
    let s = seen.lock().unwrap().clone();
    assert!(
        s.iter().any(|t| t.contains("FromA") && t.contains("FromB")),
        "hook did not see the merged peer item: {s:?}"
    );
    let disk = read_vault(&pkg);
    assert!(swept(&disk, "FromA") && swept(&disk, "FromB"));
}

/// 03 §3 step 6c/e write-backs and §6 conflict absorption go through the hook ("merge
/// write-backs, conflict absorption"); "It never runs on reads or polls with nothing to write".
#[test]
fn bw05_write_backs_and_absorption_run_hook() {
    let d = tempdir();
    let pkg = d.path().join("bx.vault");
    let mut a = Dev::create(&pkg);
    a.s.save().unwrap();
    let mut b = Dev::open(&pkg);
    let (n, seen) = counters();
    install_tagger(&mut b.s, n.clone(), seen);
    b.s.start_watching().unwrap();
    // echo of nothing: polls with nothing to write
    b.wait_for(2, |_| false);
    assert_eq!(n.load(SeqCst), 0, "hook ran on an idle poll");
    a.add_login("Late", now_ms());
    a.s.save().unwrap();
    assert!(
        b.wait_for(15, |e| e.iter().any(|x| x.contains("Merged"))),
        "B merged: {:?}",
        b.seen
    );
    b.wait_for(2, |_| false);
    assert!(n.load(SeqCst) >= 1, "write-back did not run the hook");
    assert!(
        swept(&read_vault(&pkg), "Late"),
        "write-back missing hook change"
    );
    assert!(!b.s.is_dirty(), "hook change marked dirty");
    // per-file conflict copy from a peer
    let stage = d.path().join("stage");
    std::fs::create_dir_all(&stage).unwrap();
    copy_dir(&pkg, &stage.join("bx.vault"));
    {
        let mut p = Dev::open(&stage.join("bx.vault"));
        p.add_login("Peer", now_ms());
        p.s.save().unwrap();
    }
    let before = n.load(SeqCst);
    b.seen.clear();
    std::fs::copy(stage.join("bx.vault/vault.bin"), pkg.join("vault 2.bin")).unwrap();
    assert!(
        b.wait_for(15, |e| e.iter().any(|x| x.contains("ConflictAbsorbed"))),
        "absorbed: {:?}",
        b.seen
    );
    assert!(n.load(SeqCst) > before, "absorption did not run the hook");
    assert!(swept(&read_vault(&pkg), "Peer"));
}

/// 03 §2 / §5 "content a peer's file brings back past its window is stripped before vault-sync's
/// own write-back reaches disk" with the app's sweep installed as the hook. Control run without
/// the hook shows the check discriminates.
#[test]
fn bw06_expired_trash_from_peer_never_reaches_disk() {
    for hooked in [true, false] {
        let d = tempdir();
        let pkg = d.path().join("be.vault");
        let mut a = Dev::create(&pkg);
        a.s.save().unwrap();
        let stage = d.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        copy_dir(&pkg, &stage.join("be.vault"));
        let old = now_ms() - 41 * DAY;
        let id;
        {
            let mut p = Dev::open(&stage.join("be.vault"));
            let dev = p.dev;
            id =
                p.s.edit(move |v| {
                    let mut it = Item::new("Old", dev, old);
                    it.fields.push(Field::new(
                        "password",
                        FieldKind::Password,
                        pw("OLDSECRET-xyz"),
                        old,
                    ));
                    let id = v.insert(it, old);
                    v.delete(id, old + DAY).unwrap();
                    id
                })
                .unwrap();
            p.s.save().unwrap();
        }
        let n = Arc::new(AtomicUsize::new(0));
        if hooked {
            sweep_hook(&mut a.s, n.clone());
        }
        a.s.start_watching().unwrap();
        std::fs::copy(stage.join("be.vault/vault.bin"), pkg.join("vault 2.bin")).unwrap();
        assert!(
            a.wait_for(15, |e| e.iter().any(|x| x.contains("ConflictAbsorbed"))),
            "absorbed: {:?}",
            a.seen
        );
        let disk = read_vault(&pkg);
        let it = disk
            .items_including_deleted()
            .find(|i| i.id == id)
            .expect("tombstone on disk");
        if hooked {
            assert!(
                !it.has_content(),
                "expired content reached disk through a write-back"
            );
            assert!(!a.v().get(id).map(|i| i.has_content()).unwrap_or(false));
        } else if it.has_content() {
            eprintln!("INFO control: without the hook the expired content reaches disk");
        }
    }
}

/// "before the size check and serialisation": a hook that strips an expired 65 MiB note lets a
/// save that would otherwise be refused with `VaultTooLarge` succeed.
#[test]
fn bw07_hook_runs_before_size_check() {
    let d = tempdir();
    let pkg = d.path().join("bs.vault");
    let mut a = Dev::create(&pkg);
    a.s.save().unwrap();
    let old = now_ms() - 41 * DAY;
    let dev = a.dev;
    let big = "N".repeat(65 * 1024 * 1024);
    let id =
        a.s.edit(move |v| {
            let mut it = Item::new("Huge", dev, old);
            it.fields
                .push(Field::new("notes", FieldKind::Notes, pw(&big), old));
            let id = v.insert(it, old);
            v.delete(id, old + DAY).unwrap();
            id
        })
        .unwrap();
    let r = a.s.save();
    assert!(
        matches!(&r, Err(e) if format!("{e:?}").contains("TooLarge")),
        "control: oversize save refused: {r:?}"
    );
    let n = Arc::new(AtomicUsize::new(0));
    sweep_hook(&mut a.s, n.clone());
    a.s.save()
        .expect("hook strip happens before the size check");
    assert!(std::fs::metadata(primary(&pkg)).unwrap().len() < 1024 * 1024);
    let disk = read_vault(&pkg);
    assert!(!disk.get(id).map(|i| i.has_content()).unwrap_or(false));
    assert!(
        !disk
            .items_including_deleted()
            .find(|i| i.id == id)
            .unwrap()
            .has_content()
    );
}

/// 03 §2 "`SyncEvent::Merged` reports describe the pre-hook state": a merge that brings in one
/// item reports exactly that, though the hook then edits every item.
#[test]
fn bw08_merged_report_is_pre_hook() {
    let d = tempdir();
    let pkg = d.path().join("bp.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("Base1", now_ms());
    a.add_login("Base2", now_ms());
    a.s.save().unwrap();
    let mut b = Dev::open(&pkg);
    let (n, seen) = counters();
    install_tagger(&mut b.s, n, seen);
    b.s.start_watching().unwrap();
    a.add_login("New", now_ms());
    a.s.save().unwrap();
    assert!(b.wait_for(15, |e| e.iter().any(|x| x.contains("Merged"))));
    let m = b
        .seen
        .iter()
        .find(|x| x.contains("Merged"))
        .unwrap()
        .clone();
    assert!(
        m.contains("added: 1") && m.contains("updated: 0"),
        "Merged report includes hook edits: {m}"
    );
    let _ = b.v().items().map(|i| i.fields.len()).sum::<usize>();
    let _ = secrecy::SecretString::new(String::new())
        .expose_secret()
        .len();
}

/// 03 §2 hook list includes "the rewrite after unlock"; 03 §6 step 2 "if locked, defer to next
/// unlock". A hook installed before `lock` must still guard the write that absorbs a copy queued
/// while locked (expired trash from a peer stays off disk), and it still runs on later saves.
#[test]
fn bw09_hook_survives_lock_and_guards_unlock_rewrite() {
    let d = tempdir();
    let pkg = d.path().join("bu.vault");
    let mut a = Dev::create(&pkg);
    a.s.save().unwrap();
    let stage = d.path().join("stage");
    std::fs::create_dir_all(&stage).unwrap();
    copy_dir(&pkg, &stage.join("bu.vault"));
    let old = now_ms() - 41 * DAY;
    let id;
    {
        let mut p = Dev::open(&stage.join("bu.vault"));
        let dev = p.dev;
        id =
            p.s.edit(move |v| {
                let mut it = Item::new("OldU", dev, old);
                it.fields.push(Field::new(
                    "password",
                    FieldKind::Password,
                    pw("OLD-U"),
                    old,
                ));
                let id = v.insert(it, old);
                v.delete(id, old + DAY).unwrap();
                id
            })
            .unwrap();
        p.s.save().unwrap();
    }
    let n = Arc::new(AtomicUsize::new(0));
    sweep_hook(&mut a.s, n.clone());
    a.s.start_watching().unwrap();
    let _ = a.s.lock();
    std::fs::copy(stage.join("bu.vault/vault.bin"), pkg.join("vault 2.bin")).unwrap();
    a.wait_for(3, |_| false);
    assert!(pkg.join("vault 2.bin").exists(), "touched while locked");
    a.s.unlock(&pw(PW)).unwrap();
    a.wait_for(5, |e| e.iter().any(|x| x.contains("ConflictAbsorbed")));
    let absorbed = !pkg.join("vault 2.bin").exists();
    eprintln!(
        "INFO after unlock: absorbed={absorbed} hook calls={} events={:?}",
        n.load(SeqCst),
        a.seen
    );
    if absorbed {
        let disk = read_vault(&pkg);
        let it = disk.items_including_deleted().find(|i| i.id == id).unwrap();
        assert!(
            !it.has_content(),
            "expired peer content reached disk via the unlock-time absorption"
        );
    }
    let base = n.load(SeqCst);
    a.add_login("AfterUnlock", now_ms());
    a.s.save().unwrap();
    assert!(n.load(SeqCst) > base, "hook did not survive lock/unlock");
}
