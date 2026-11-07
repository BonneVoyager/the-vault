//! External security review fixes, 2026-11-06 (03 §2 step 4, §2 "Not following links", §2 "Blob
//! publication is authenticated", §2 "Watcher bounds", §2 "Reads of vault.bin are capped (64 MiB)",
//! §5 header tuple with canonical CBOR of the slot set). Written from the specs only.
//! A passing check shows the behaviour on these inputs, not a proof.
use spec_checks::dev::*;
use spec_checks::*;
use std::io::Read;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use uuid::Uuid;
use vault_core::*;

fn vault_bin() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/vault")
}

/// Runs the CLI with a wall-clock limit. Returns (exit code or None on timeout, output).
fn cli_t(pkg: &Path, args: &[&str], secs: u64) -> (Option<i32>, String) {
    let mut c = Command::new(vault_bin())
        .arg("--vault")
        .arg(pkg)
        .args(["--password-env", "QA_MPW"])
        .args(args)
        .env("QA_MPW", PW)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let t = Instant::now();
    loop {
        if let Some(st) = c.try_wait().unwrap() {
            let mut o = String::new();
            c.stdout.take().unwrap().read_to_string(&mut o).unwrap();
            c.stderr.take().unwrap().read_to_string(&mut o).unwrap();
            return (st.code(), o);
        }
        if t.elapsed() > Duration::from_secs(secs) {
            let _ = c.kill();
            let _ = c.wait();
            return (None, "TIMEOUT".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn mkfifo(p: &Path) {
    let st = Command::new("mkfifo").arg(p).status().unwrap();
    assert!(st.success());
}

fn hex(id: Uuid) -> String {
    id.simple().to_string()
}

fn base_pkg(dir: &Path, name: &str) -> (PathBuf, Dev, Uuid) {
    let pkg = dir.join(name);
    let mut a = Dev::create(&pkg);
    let id = a.add_login("Base", now_ms());
    a.s.save().unwrap();
    (pkg, a, id)
}

/// 03 §2 D-1: "a symlinked `.lock` must not degrade to the no-lock path" and "a symlink ... is
/// `UnsafePackageEntry`". Live target and dangling target: save fails, nothing is written through.
#[test]
fn rf01_symlinked_lock_refused() {
    for dangling in [false, true] {
        let d = tempdir();
        let (pkg, mut a, _) = base_pkg(d.path(), "lk.vault");
        let outside = d.path().join("outside-lock");
        if !dangling {
            std::fs::write(&outside, b"keep").unwrap();
        }
        let _ = std::fs::remove_file(pkg.join(".lock"));
        symlink(&outside, pkg.join(".lock")).unwrap();
        let before = std::fs::read(primary(&pkg)).unwrap();
        a.add_login("AfterLink", now_ms());
        let r = a.s.save();
        let after = std::fs::read(primary(&pkg)).unwrap();
        assert!(
            r.is_err(),
            "dangling={dangling}: save with a symlinked .lock succeeded (degraded lock?)"
        );
        let e = format!("{:?}", r.unwrap_err());
        assert!(e.contains("UnsafePackageEntry"), "dangling={dangling}: {e}");
        assert_eq!(before, after, "primary untouched");
        assert!(a.s.is_dirty(), "edits kept dirty");
        if dangling {
            assert!(!outside.exists(), "lock created through a dangling symlink");
        } else {
            assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
        }
    }
}

/// 03 §2 D-1: `vault.bin` opened with O_NOFOLLOW; a symlinked primary is refused at unlock/read and
/// a save never writes through it (rename replaces the link itself at most).
#[test]
fn rf02_symlinked_primary_refused() {
    let d = tempdir();
    let (pkg, a, _) = base_pkg(d.path(), "sp.vault");
    drop(a);
    let real = d.path().join("real.bin");
    std::fs::rename(primary(&pkg), &real).unwrap();
    symlink(&real, primary(&pkg)).unwrap();
    let mut s = SyncedVault::open(&pkg, Uuid::new_v4(), hooks());
    let r = match &mut s {
        Ok(s) => s.unlock(&pw(PW)).map(|_| ()),
        Err(_) => Ok(()),
    };
    let opened_err = s.as_ref().err().map(|e| format!("{e:?}"));
    let unlock_err = r.err().map(|e| format!("{e:?}"));
    let msg = opened_err.or(unlock_err);
    assert!(
        msg.as_deref()
            .is_some_and(|m| m.contains("UnsafePackageEntry")),
        "symlinked vault.bin: {msg:?}"
    );
    let (rc, out) = cli_t(&pkg, &["list"], 20);
    assert!(
        rc.is_some_and(|c| c != 0 && c != 101),
        "CLI list rc={rc:?} {out}"
    );
}

/// 03 §2 D-1 "or special file": a FIFO in place of vault.bin, .lock, a per-file conflict copy, a
/// sibling package's vault.bin, or a referenced blob must not hang the CLI (an O_RDONLY open of a
/// FIFO blocks until a writer appears unless the open is non-blocking).
#[test]
fn rf03_fifos_do_not_hang() {
    let mut bad = vec![];
    // primary FIFO
    {
        let d = tempdir();
        let (pkg, a, _) = base_pkg(d.path(), "ff.vault");
        drop(a);
        std::fs::remove_file(primary(&pkg)).unwrap();
        mkfifo(&primary(&pkg));
        let (rc, out) = cli_t(&pkg, &["list"], 15);
        if rc.is_none() || rc == Some(0) || rc == Some(101) {
            bad.push(format!("vault.bin FIFO: rc={rc:?} {out}"));
        }
    }
    // .lock FIFO
    {
        let d = tempdir();
        let (pkg, a, _) = base_pkg(d.path(), "fl.vault");
        drop(a);
        let _ = std::fs::remove_file(pkg.join(".lock"));
        mkfifo(&pkg.join(".lock"));
        let (rc, out) = cli_t(&pkg, &["add", "--title", "X"], 15);
        if rc.is_none() || rc == Some(0) || rc == Some(101) {
            bad.push(format!(".lock FIFO: rc={rc:?} {out}"));
        }
    }
    // per-file conflict copy FIFO and sibling package FIFO
    {
        let d = tempdir();
        let (pkg, a, _) = base_pkg(d.path(), "fc.vault");
        drop(a);
        mkfifo(&pkg.join("vault 2.bin"));
        std::fs::create_dir(d.path().join("fc 2.vault")).unwrap();
        mkfifo(&d.path().join("fc 2.vault").join("vault.bin"));
        let (rc, out) = cli_t(&pkg, &["sync"], 20);
        if rc.is_none() || rc == Some(101) {
            bad.push(format!("conflict-copy FIFOs: rc={rc:?} {out}"));
        }
        if !pkg.join("vault 2.bin").exists() && !pkg.join("backups").exists() {
            bad.push("FIFO conflict copy vanished".into());
        }
    }
    // blob FIFO
    {
        let d = tempdir();
        let (pkg, mut a, id) = base_pkg(d.path(), "fb.vault");
        let aid =
            a.s.add_attachment(id, "f.txt", &b"abc"[..], 3, now_ms())
                .unwrap();
        a.s.save().unwrap();
        drop(a);
        let blob = pkg.join("attachments").join(format!("{}.bin", hex(aid)));
        std::fs::remove_file(&blob).unwrap();
        mkfifo(&blob);
        let out_path = d.path().join("out.txt");
        let (rc, out) = cli_t(
            &pkg,
            &[
                "attach",
                "get",
                "Base",
                &aid.to_string(),
                out_path.to_str().unwrap(),
            ],
            15,
        );
        if rc.is_none() || rc == Some(101) {
            bad.push(format!("blob FIFO attach get: rc={rc:?} {out}"));
        }
        let (rc, out) = cli_t(&pkg, &["attach", "list", "Base"], 15);
        if rc.is_none() || rc == Some(101) {
            bad.push(format!("blob FIFO attach list: rc={rc:?} {out}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §2 D-1: "`backups/` and `attachments/` must not be symlinks." Nothing may be written through
/// them.
#[test]
fn rf04_symlinked_backups_and_attachments_dirs() {
    let d = tempdir();
    let (pkg, mut a, id) = base_pkg(d.path(), "sd.vault");
    let ob = d.path().join("outside-backups");
    let oa = d.path().join("outside-attachments");
    std::fs::create_dir(&ob).unwrap();
    std::fs::create_dir(&oa).unwrap();
    let _ = std::fs::remove_dir_all(pkg.join("backups"));
    let _ = std::fs::remove_dir_all(pkg.join("attachments"));
    symlink(&ob, pkg.join("backups")).unwrap();
    symlink(&oa, pkg.join("attachments")).unwrap();
    a.add_login("More", now_ms());
    let r1 = a.s.save().map(|_| ());
    let r2 = a.s.backup_now().map(|_| ());
    let r3 =
        a.s.add_attachment(id, "x.txt", &b"x"[..], 1, now_ms())
            .map(|_| ());
    a.drain();
    eprintln!(
        "INFO save={:?} backup_now={:?} add_attachment={:?}",
        r1.as_ref().err(),
        r2.as_ref().err(),
        r3.as_ref().err()
    );
    assert!(
        ls(&ob).is_empty(),
        "snapshot written through backups symlink: {:?}",
        ls(&ob)
    );
    assert!(
        ls(&oa).is_empty(),
        "blob written through attachments symlink: {:?}",
        ls(&oa)
    );
    assert!(
        r2.is_err() && r3.is_err(),
        "explicit operations report the refusal"
    );
}

/// 03 §2 D-1: a referenced blob that is a symlink is not followed.
#[test]
fn rf05_symlinked_blob_refused() {
    let d = tempdir();
    let (pkg, mut a, id) = base_pkg(d.path(), "sb.vault");
    let aid =
        a.s.add_attachment(id, "f.txt", &b"secret blob"[..], 11, now_ms())
            .unwrap();
    a.s.save().unwrap();
    let blob = pkg.join("attachments").join(format!("{}.bin", hex(aid)));
    let outside = d.path().join("elsewhere.bin");
    std::fs::rename(&blob, &outside).unwrap();
    symlink(&outside, &blob).unwrap();
    let r = a.s.open_attachment(id, aid);
    let ok = match r {
        Ok(mut rd) => {
            let mut v = vec![];
            rd.read_to_end(&mut v).is_err()
        }
        Err(e) => {
            let s = format!("{e:?}");
            eprintln!("INFO symlinked blob: {s}");
            true
        }
    };
    assert!(ok, "a symlinked blob was read through the link");
}

/// 03 §2: "Reads of vault.bin are capped (64 MiB) and refuse larger files with a typed error before
/// parsing." A 65 MiB primary and a 65 MiB per-file conflict copy are refused without harm.
#[test]
fn rf06_oversized_primary_and_copy() {
    let d = tempdir();
    let (pkg, a, _) = base_pkg(d.path(), "big.vault");
    drop(a);
    let good = std::fs::read(primary(&pkg)).unwrap();
    let mut big = good.clone();
    big.resize(65 * 1024 * 1024, 0);
    std::fs::write(pkg.join("vault 2.bin"), &big).unwrap();
    let (rc, out) = cli_t(&pkg, &["sync"], 60);
    assert!(
        rc.is_some() && rc != Some(101),
        "sync with 65 MiB copy: rc={rc:?} {out}"
    );
    assert_eq!(std::fs::read(primary(&pkg)).unwrap().len(), good.len());
    let still = pkg.join("vault 2.bin").exists()
        || ls(&pkg.join("backups"))
            .iter()
            .any(|n| n.starts_with("conflict-"));
    assert!(still, "03 §6 never delete a conflict copy");
    std::fs::write(primary(&pkg), &big).unwrap();
    let mut s = SyncedVault::open(&pkg, Uuid::new_v4(), hooks());
    let r = match &mut s {
        Ok(s) => s.unlock(&pw(PW)).map_err(|e| format!("{e:?}")),
        Err(e) => Err(format!("{e:?}")),
    };
    let e = r.expect_err("65 MiB primary refused");
    eprintln!("INFO 65 MiB primary: {e}");
    assert!(
        !e.contains("Malformed") && !e.contains("Trailing"),
        "typed size error, got {e}"
    );
}

/// 03 §2 cap vs write path: if reads refuse vault.bin over 64 MiB, a save must not produce a
/// vault.bin that this same code then refuses to open (otherwise a legitimate edit bricks the
/// vault: next unlock fails). Notes are free text with no size limit in 01/02.
#[test]
fn rf07_save_never_writes_an_unreadable_primary() {
    let d = tempdir();
    let (pkg, mut a, _) = base_pkg(d.path(), "huge.vault");
    let dev = a.dev;
    let big: String = (0..65 * 1024 * 1024 / 16)
        .map(|i| format!("{:015x}\n", i))
        .collect();
    a.s.edit(move |v| {
        let mut it = Item::new("Huge note", dev, now_ms());
        it.fields
            .push(Field::new("notes", FieldKind::Notes, pw(&big), now_ms()));
        v.insert(it, now_ms());
    })
    .unwrap();
    let r = a.s.save();
    let size = std::fs::metadata(primary(&pkg)).unwrap().len();
    a.add_login("after", now_ms());
    let r2 = a.s.save();
    drop(a);
    let reopened = SyncedVault::open(&pkg, Uuid::new_v4(), hooks())
        .map_err(|e| format!("{e:?}"))
        .and_then(|mut s| s.unlock(&pw(PW)).map_err(|e| format!("{e:?}")));
    assert!(
        r.is_err() || reopened.is_ok(),
        "save returned Ok and wrote a {size}-byte vault.bin; the next save on the same handle: \
         {:?}; open+unlock now: {:?}",
        r2.err(),
        reopened.err()
    );
}

/// 01 §4: attachments up to 100 MB; the 64 MiB read caps (D-10) must not reject a legitimate
/// 70 MB attachment on add, open, or blob publication from a whole-package conflict copy (D-6).
#[test]
fn rf08_seventy_megabyte_attachment_end_to_end() {
    let size = 70_000_000usize;
    let data: Vec<u8> = (0..size).map(|i| (i * 7 % 253) as u8).collect();
    let d = tempdir();
    let (pkg, mut a, id) = base_pkg(d.path(), "att.vault");
    // staging copy adds the big attachment, then arrives as a sibling package
    let st = d.path().join("stage.vault");
    copy_dir(&pkg, &st);
    let mut c = Dev::open(&st);
    let aid =
        c.s.add_attachment(id, "big.bin", &data[..], size as u64, now_ms())
            .expect("add 70 MB attachment");
    c.s.save().unwrap();
    {
        let mut rd = c.s.open_attachment(id, aid).expect("open 70 MB");
        let mut got = Vec::with_capacity(size);
        rd.read_to_end(&mut got).unwrap();
        assert!(got == data, "70 MB round trip in staging");
    }
    drop(c);
    std::fs::rename(&st, d.path().join("att 2.vault")).unwrap();
    a.s.start_watching().unwrap();
    let got = a.wait_for(60, |e| e.iter().any(|s| s.starts_with("ConflictAbsorbed")));
    assert!(got, "absorb with 70 MB blob; events {:?}", a.seen);
    let blob = pkg.join("attachments").join(format!("{}.bin", hex(aid)));
    assert!(blob.exists(), "70 MB blob published");
    let mut rd = a.s.open_attachment(id, aid).expect("open published 70 MB");
    let mut got = Vec::with_capacity(size);
    rd.read_to_end(&mut got).unwrap();
    assert!(got == data);
}

/// 03 §2 D-6: "a blob copied from a conflict package ... is published only if its length equals
/// the sealed size computed from the reference and every chunk authenticates under the reference's
/// key ...; a bad blob is skipped with a warning and nothing is written. An existing blob is never
/// replaced."
#[test]
fn rf09_blob_publication_authenticated() {
    let mut bad = vec![];
    for case in ["flip", "short", "long", "swap", "existing"] {
        let d = tempdir();
        let (pkg, mut a, id) = base_pkg(d.path(), "pub.vault");
        let st = d.path().join("stage.vault");
        copy_dir(&pkg, &st);
        let mut c = Dev::open(&st);
        let data: Vec<u8> = (0..1_048_576 + 100).map(|i| (i % 251) as u8).collect();
        let aid =
            c.s.add_attachment(id, "x.bin", &data[..], data.len() as u64, now_ms())
                .unwrap();
        let other =
            c.s.add_attachment(id, "y.bin", &b"other"[..], 5, now_ms())
                .unwrap();
        c.s.save().unwrap();
        drop(c);
        let sb = st.join("attachments").join(format!("{}.bin", hex(aid)));
        let ob = st.join("attachments").join(format!("{}.bin", hex(other)));
        let mut b = std::fs::read(&sb).unwrap();
        let ours = pkg.join("attachments").join(format!("{}.bin", hex(aid)));
        match case {
            "flip" => b[1_048_576 + 20] ^= 1,
            "short" => {
                b.pop();
            }
            "long" => b.push(0),
            "swap" => b = std::fs::read(&ob).unwrap(),
            "existing" => {
                std::fs::create_dir_all(ours.parent().unwrap()).unwrap();
                std::fs::write(&ours, b"pre-existing junk").unwrap();
            }
            _ => unreachable!(),
        }
        std::fs::write(&sb, &b).unwrap();
        std::fs::rename(&st, d.path().join("pub 2.vault")).unwrap();
        a.s.start_watching().unwrap();
        a.wait_for(8, |e| {
            e.iter()
                .any(|s| s.starts_with("ConflictAbsorbed") || s.starts_with("WaitingForBlobs"))
        });
        a.wait_for(2, |_| false);
        let published = std::fs::read(&ours).ok();
        match case {
            "existing" => {
                if published.as_deref() != Some(&b"pre-existing junk"[..]) {
                    bad.push("existing blob replaced".into());
                }
            }
            _ => {
                if let Some(p) = published {
                    bad.push(format!("{case}: bad blob published ({} bytes)", p.len()));
                }
                if !pkg
                    .join("attachments")
                    .join(format!("{}.bin", hex(other)))
                    .exists()
                {
                    bad.push(format!("{case}: the good sibling blob was not published"));
                }
            }
        }
        if ls(&pkg.join("attachments"))
            .iter()
            .any(|n| n.contains("tmp"))
        {
            bad.push(format!("{case}: tmp left in attachments/"));
        }
        if a.v().get(id).is_none() {
            bad.push(format!("{case}: merge lost the item"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

fn make_copies(pkg: &Path, n: usize, dir_for_staging: &Path) -> Vec<String> {
    let base = std::fs::read(primary(pkg)).unwrap();
    let l = LockedVault::parse(&base).unwrap();
    let u = l.unlock(&pw(PW)).unwrap();
    let k = u.export_vault_key();
    let mut titles = vec![];
    for i in 0..n {
        let mut v = l.unlock_with_key(&k, Uuid::new_v4()).unwrap();
        let dev = v.device_id();
        let t = format!("copy-{i:03}");
        v.insert(
            Item::new(t.clone(), dev, 1_000 + i as u64),
            1_000 + i as u64,
        );
        let stage = dir_for_staging.join(format!("s{i}"));
        std::fs::write(&stage, v.serialize()).unwrap();
        std::fs::rename(&stage, pkg.join(format!("vault {}.bin", i + 2))).unwrap();
        titles.push(t);
    }
    titles
}

/// 03 §2 D-11: "A poll processes at most 8 candidates; the rest wait for the next poll ... Directory
/// scans page, so every candidate is eventually seen." 20 per-file copies.
#[test]
fn rf10_watcher_eight_per_poll_all_eventually() {
    let d = tempdir();
    let (pkg, mut a, _) = base_pkg(d.path(), "w8.vault");
    a.s.start_watching().unwrap();
    std::thread::sleep(Duration::from_millis(800));
    let titles = make_copies(&pkg, 20, d.path());
    std::thread::sleep(Duration::from_millis(1_500));
    a.s.poll();
    let mut first = 0;
    while let Ok(e) = a.rx.try_recv() {
        let s = format!("{e:?}");
        if s.starts_with("ConflictAbsorbed") {
            first += 1;
        }
        a.seen.push(s);
    }
    assert!(first <= 8, "first poll absorbed {first} > 8");
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(30) {
        a.drain();
        if titles
            .iter()
            .all(|ti| a.v().items().any(|i| &i.title == ti))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let missing: Vec<&String> = titles
        .iter()
        .filter(|ti| !a.v().items().any(|i| &&i.title == ti))
        .collect();
    assert!(missing.is_empty(), "never absorbed: {missing:?}");
    let left: Vec<String> = ls(&pkg)
        .into_iter()
        .filter(|n| n.starts_with("vault ") && n.ends_with(".bin"))
        .collect();
    assert!(left.is_empty(), "copies not moved: {left:?}");
}

/// 03 §2 D-11: queue capped at 256 with a rescan flag on overflow; one-shot `vault sync` loops until
/// poll returns 0. 300 per-file copies created before `vault sync` all end up merged and moved.
#[test]
fn rf11_cli_sync_drains_three_hundred_copies() {
    let d = tempdir();
    let (pkg, a, _) = base_pkg(d.path(), "w300.vault");
    drop(a);
    let titles = make_copies(&pkg, 300, d.path());
    let (rc, out) = cli_t(&pkg, &["sync"], 300);
    assert_eq!(rc, Some(0), "{out}");
    let v = read_vault(&pkg);
    let missing = titles
        .iter()
        .filter(|ti| !v.items().any(|i| &&i.title == ti))
        .count();
    let left = ls(&pkg)
        .into_iter()
        .filter(|n| n.starts_with("vault ") && n.ends_with(".bin"))
        .count();
    assert!(
        missing == 0 && left == 0,
        "one `vault sync`: {missing} of 300 not merged, {left} copies left in the package"
    );
}

/// 03 §5 header tuple (D-9): "(format_version, slots_modified_at, slots_device_id, canonical CBOR of
/// the slot set) ... two authentic divergent header writes from a cloned device id in the same
/// millisecond otherwise never converge". Password change and key rotation variants.
#[test]
fn rf12_header_tie_break_converges() {
    for op in ["change_password", "rotate", "enclave"] {
        let same = Uuid::from_bytes([9; 16]);
        let base = UnlockedVault::create(&pw("old pw"), KdfParams::for_tests(), same);
        let bytes = base.serialize();
        let l = LockedVault::parse(&bytes).unwrap();
        let k = base.export_vault_key();
        let mut a = l.unlock_with_key(&k, same).unwrap();
        let mut b = l.unlock_with_key(&k, same).unwrap();
        a.insert(Item::new("A item", same, 50), 50);
        b.insert(Item::new("B item", same, 51), 51);
        let now = 1_000_000;
        match op {
            "change_password" => {
                a.change_password(&pw("old pw"), &pw("pw A"), KdfParams::for_tests(), now)
                    .unwrap();
                b.change_password(&pw("old pw"), &pw("pw B"), KdfParams::for_tests(), now)
                    .unwrap();
            }
            "rotate" => {
                a.rotate_vault_key(&pw("old pw"), now).unwrap();
                b.rotate_vault_key(&pw("old pw"), now).unwrap();
            }
            _ => {
                a.add_enclave_slot(&secrecy::SecretVec::new(vec![1; 32]), now);
                b.add_enclave_slot(&secrecy::SecretVec::new(vec![2; 32]), now);
            }
        }
        let fa = a.serialize();
        let fb = b.serialize();
        let la = LockedVault::parse(&fa).unwrap();
        let lb = LockedVault::parse(&fb).unwrap();
        // each side opens the other's file with the other's key (as sync would after a password
        // prompt) — use the exported keys
        let tb = lb.unlock_with_key(&b.export_vault_key(), same).unwrap();
        let ta = la.unlock_with_key(&a.export_vault_key(), same).unwrap();
        a.merge_from(&tb).unwrap();
        b.merge_from(&ta).unwrap();
        let ha = split(&a.serialize()).header;
        let hb = split(&b.serialize()).header;
        assert!(ha == hb, "{op}: headers differ after one exchange");
        // both files open with one and the same password, both items present
        let pass = match op {
            "change_password" => {
                if LockedVault::parse(&a.serialize())
                    .unwrap()
                    .unlock(&pw("pw A"))
                    .is_ok()
                {
                    "pw A"
                } else {
                    "pw B"
                }
            }
            _ => "old pw",
        };
        for (n, v) in [("a", &a), ("b", &b)] {
            let u = LockedVault::parse(&v.serialize())
                .unwrap()
                .unlock(&pw(pass))
                .unwrap_or_else(|e| panic!("{op}: {n} does not open with {pass}: {e:?}"));
            let titles: Vec<String> = u.items().map(|i| i.title.clone()).collect();
            assert!(
                titles.contains(&"A item".to_string()) && titles.contains(&"B item".to_string()),
                "{op}: {n} items {titles:?}"
            );
        }
    }
}

/// 03 §2 step 4: "when only (dev, ino) differ, a (size, blake3) match of the current bytes counts as
/// unchanged (SMB/FUSE mounts and iCloud same-bytes rewrites renumber inodes)". A same-bytes
/// rewrite with a new inode between edits never blocks a save.
#[test]
fn rf13_same_bytes_new_inode_does_not_block_save() {
    let d = tempdir();
    let (pkg, mut a, _) = base_pkg(d.path(), "ino.vault");
    for k in 0..5 {
        let b = std::fs::read(primary(&pkg)).unwrap();
        let t = pkg.join(format!("x{k}"));
        std::fs::write(&t, &b).unwrap();
        std::fs::rename(&t, primary(&pkg)).unwrap();
        a.add_login(&format!("after-rewrite-{k}"), now_ms());
        let r = a.s.save();
        assert!(r.is_ok(), "round {k}: {:?}", r.err());
    }
    let v = read_vault(&pkg);
    assert_eq!(
        v.items()
            .filter(|i| i.title.starts_with("after-rewrite"))
            .count(),
        5
    );
}

/// 03 §2 step 4 (D-2): two handles on one folder saving in a tight loop never lose an item and never
/// surface PrimaryChangedDuringSave while retries are available (the flock serialises them).
#[test]
fn rf14_two_handles_tight_save_loop() {
    let d = tempdir();
    let (pkg, a, _) = base_pkg(d.path(), "tl.vault");
    drop(a);
    let mut hs = vec![];
    for h in 0..2 {
        let pkg = pkg.clone();
        hs.push(std::thread::spawn(move || {
            let mut x = Dev::open(&pkg);
            let mut errs = vec![];
            for k in 0..25 {
                x.add_login(&format!("h{h}-{k}"), now_ms());
                if let Err(e) = x.s.save() {
                    errs.push(format!("{e:?}"));
                }
            }
            errs
        }));
    }
    let errs: Vec<String> = hs.into_iter().flat_map(|h| h.join().unwrap()).collect();
    let v = read_vault(&pkg);
    let n = v.items().filter(|i| i.title.starts_with('h')).count();
    assert!(errs.is_empty() && n == 50, "items {n}/50, errors {errs:?}");
}

/// Follow-up to rf07: a second device that holds the vault open while the other device tries
/// to save a vault over the 64 MiB cap. 03 §2: reads of vault.bin are capped, so a save must
/// never write what a read refuses (M1, fixed 2026-11-07): A's save is refused with
/// `VaultTooLarge`, vault.bin stays byte-identical, A keeps its edits (still dirty), and the
/// peer B, polling, sees no corruption and writes nothing.
#[test]
fn rf15_peer_after_oversize_save() {
    let d = tempdir();
    let (pkg, mut a, _) = base_pkg(d.path(), "peer.vault");
    let mut b = Dev::open(&pkg);
    b.s.start_watching().unwrap();
    std::thread::sleep(Duration::from_millis(700));
    b.drain();
    let before = std::fs::read(primary(&pkg)).unwrap();
    let dev = a.dev;
    let big: String = (0..65 * 1024 * 1024 / 16)
        .map(|i| format!("{:015x}\n", i))
        .collect();
    a.add_login("small-from-A", now_ms());
    a.s.edit(move |v| {
        let mut it = Item::new("Huge note", dev, now_ms());
        it.fields
            .push(Field::new("notes", FieldKind::Notes, pw(&big), now_ms()));
        v.insert(it, now_ms());
    })
    .unwrap();
    let r = a.s.save();
    assert!(
        matches!(
            r,
            Err(vault_sync::SyncError::VaultTooLarge { bytes, cap })
                if cap == 64 * 1024 * 1024 && bytes > cap
        ),
        "oversize save must be refused with VaultTooLarge: {r:?}"
    );
    assert!(
        std::fs::read(primary(&pkg)).unwrap() == before,
        "vault.bin changed although the save was refused"
    );
    assert!(a.s.is_dirty(), "A's edits must stay pending");
    assert!(a.v().items().any(|i| i.title == "small-from-A"));
    assert!(a.v().items().any(|i| i.title == "Huge note"));
    // The peer re-polls for a while: nothing to report, nothing to write.
    b.wait_for(3, |_| false);
    eprintln!("INFO B events {:?}", b.seen);
    assert!(
        !b.seen.iter().any(|e| e.contains("CorruptOnDisk")),
        "peer reported corruption: {:?}",
        b.seen
    );
    assert!(!b.s.is_dirty(), "peer scheduled a rewrite");
    assert!(
        std::fs::read(primary(&pkg)).unwrap() == before,
        "peer overwrote vault.bin"
    );
    // Recoverable: A shrinks the vault (a plain delete keeps the content in Recently Deleted)
    // and saves; B merges A's ordinary item that the refused save was carrying.
    let huge = a.v().items().find(|i| i.title == "Huge note").unwrap().id;
    a.s.edit(move |v| {
        v.delete(huge, now_ms())?;
        v.delete_permanently(huge, now_ms())
    })
    .unwrap()
    .unwrap();
    b.seen.clear();
    a.s.save().expect("save after shrinking");
    b.wait_for(20, |seen| seen.iter().any(|e| e.starts_with("Merged")));
    assert!(
        b.v().items().any(|i| i.title == "small-from-A"),
        "B did not merge small-from-A after A's save; B events {:?}",
        b.seen
    );
}

/// Added during the code-read pass (black-box, spec-derived): 03 §2 D-11 "A poll processes at most
/// 8 candidates ... one-shot callers (`vault sync`) loop on poll() until it returns 0" together
/// with 03 §6 step 4 (a whole-package copy whose blobs are missing waits). Ten waiting packages
/// plus one per-file copy: `vault sync` must terminate, merge all eleven and move the per-file
/// copy, and leave the waiting packages in place.
#[test]
fn rf16_cli_sync_with_many_waiting_packages() {
    let d = tempdir();
    let (pkg, a, id) = base_pkg(d.path(), "wt.vault");
    drop(a);
    let mut titles = vec![];
    for k in 0..10 {
        let st = d.path().join(format!("stage{k}.vault"));
        copy_dir(&pkg, &st);
        let _ = std::fs::remove_dir_all(st.join("backups"));
        let mut c = Dev::open(&st);
        let aid =
            c.s.add_attachment(id, "late.txt", &b"late"[..], 4, now_ms())
                .unwrap();
        let t = format!("waiting-{k}");
        c.add_login(&t, now_ms());
        c.s.save().unwrap();
        drop(c);
        std::fs::remove_file(st.join("attachments").join(format!("{}.bin", hex(aid)))).unwrap();
        std::fs::rename(&st, d.path().join(format!("wt {}.vault", k + 2))).unwrap();
        titles.push(t);
    }
    titles.extend(make_copies(&pkg, 1, d.path()));
    let (rc, out) = cli_t(&pkg, &["sync"], 180);
    assert!(rc.is_some(), "vault sync did not terminate within 180 s");
    let v = read_vault(&pkg);
    let missing: Vec<&String> = titles
        .iter()
        .filter(|t| !v.items().any(|i| &&i.title == t))
        .collect();
    assert!(
        missing.is_empty() && !pkg.join("vault 2.bin").exists(),
        "rc={rc:?} not merged {missing:?}; per-file copy left: {}; {out}",
        pkg.join("vault 2.bin").exists()
    );
}
