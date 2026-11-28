//! Bug hunt 2026-11-27: 03 §4 authenticated retention (L-04), the local fallback for Unsaved
//! copies (L-05, owner decision B), `repair_package`, and the 03 §8 `backups()` /
//! `restore_from` / `delete_backup` path rules for fallback copies. Written from the spec text
//! before reading the source.
use spec_checks::dev::*;
use spec_checks::*;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DAY: u64 = 86_400;

fn civil(s: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = s.div_euclid(86_400);
    let sod = s.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, sod / 3600, sod % 3600 / 60, sod % 60)
}
/// 03 §4 snapshot name `<name>-<UTC ISO8601 with - instead of :>.vault.bin`.
fn snap_name(prefix: &str, age_secs: u64) -> String {
    let t = SystemTime::now() - Duration::from_secs(age_secs);
    let s = t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let (y, m, d, hh, mm, ss) = civil(s);
    format!("{prefix}-{y:04}-{m:02}-{d:02}T{hh:02}-{mm:02}-{ss:02}Z.vault.bin")
}
fn events(a: &mut Dev) -> Vec<String> {
    a.drain();
    a.seen.clone()
}
fn clear_dir(p: &Path) {
    for f in ls(p) {
        let q = p.join(f);
        if std::fs::symlink_metadata(&q).unwrap().is_dir() {
            std::fs::remove_dir_all(&q).unwrap();
        } else {
            std::fs::remove_file(&q).unwrap();
        }
    }
}
fn setup(name: &str) -> (tempfile::TempDir, PathBuf, Dev) {
    let d = tempdir();
    let pkg = d.path().join(format!("{name}.vault"));
    let mut a = Dev::create(&pkg);
    a.add_login("first", now_ms());
    a.s.save().unwrap();
    (d, pkg, a)
}
fn plant_backups_file(pkg: &Path) {
    let b = pkg.join("backups");
    if b.is_dir() {
        std::fs::remove_dir_all(&b).unwrap();
    }
    std::fs::write(&b, b"planted plain file").unwrap();
}
fn opens_with(p: &Path, title: &str) -> bool {
    std::fs::read(p)
        .ok()
        .and_then(|b| vault_core::LockedVault::parse(&b).ok())
        .and_then(|l| l.unlock(&pw(PW)).ok())
        .is_some_and(|v| v.items().any(|i| i.title == title))
}

/// 03 §4 L-05: "When the Unsaved write at lock fails for any reason (a planted plain file ...
/// named `backups` ...), the sealed copy is written instead to
/// `<dir>/<vault_id>/<name>-<stamp>-unsaved.vault.bin` (folders 0700, ..., file 0600),
/// `BackupTaken` is emitted and the outcome is `Snapshotted(path)`". Then: "While `backups` is a
/// planted entry, `backups()` returns `UnsafePackageDir`"; `repair_package()` "renames a
/// non-directory `backups` ... to `<name>.quarantined-<unix seconds>` ... It returns the new
/// paths"; "`backups()` lists those copies with the package's (kind `Unsaved` ...)", "`restore_from`
/// and `delete_backup` accept them".
#[test]
fn fb01_fallback_copy_repair_list_restore_delete() {
    let (d, pkg, mut a) = setup("fb");
    let fb = d.path().join("local-fallback");
    a.s.set_fallback_dir(Some(fb.clone()));
    let vid = a.v().vault_id();
    plant_backups_file(&pkg);
    let primary_before = std::fs::read(primary(&pkg)).unwrap();
    a.add_login("unsaved edit", now_ms());
    let _ = events(&mut a);
    let out = a.s.lock();
    let mut bad = vec![];
    let p = match &out {
        vault_sync::LockOutcome::Snapshotted(p) => p.clone(),
        o => panic!("lock outcome {o:?}, want Snapshotted(fallback path)"),
    };
    let dir = fb.join(vid.to_string());
    if p.parent() != Some(dir.as_path()) {
        bad.push(format!(
            "fallback copy not in <dir>/<vault_id>/: {}",
            p.strip_prefix(d.path()).unwrap_or(&p).display()
        ));
    }
    let n = p.file_name().unwrap().to_string_lossy().into_owned();
    if !(n.starts_with("fb-") && n.ends_with("-unsaved.vault.bin")) {
        bad.push(format!("fallback name {n}"));
    }
    if mode(&p) != 0o600 {
        bad.push(format!("fallback file mode {:o}", mode(&p)));
    }
    for f in [&fb, &dir] {
        if f.exists() && mode(f) != 0o700 {
            bad.push(format!(
                "fallback folder {} mode {:o}",
                f.file_name().unwrap().to_string_lossy(),
                mode(f)
            ));
        }
    }
    if !opens_with(&p, "unsaved edit") {
        bad.push("fallback copy does not hold the unsaved edit".into());
    }
    let ev = events(&mut a);
    if !ev.iter().any(|e| e.starts_with("BackupTaken")) {
        bad.push(format!("no BackupTaken event: {ev:?}"));
    }
    if std::fs::read(primary(&pkg)).unwrap() != primary_before {
        bad.push("lock changed vault.bin".into());
    }
    a.s.unlock(&pw(PW)).unwrap();
    let l = a.s.backups();
    if !format!("{l:?}").contains("UnsafePackageDir") {
        bad.push(format!("backups() with a planted file: {l:?}"));
    }
    let moved = a.s.repair_package().expect("repair_package");
    if moved.len() != 1
        || !moved[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("backups.quarantined-")
    {
        bad.push(format!("repair returned {moved:?}"));
    } else if std::fs::read(&moved[0]).ok().as_deref() != Some(&b"planted plain file"[..]) {
        bad.push("repair did not keep the planted file's bytes".into());
    }
    if std::fs::read(primary(&pkg)).unwrap() != primary_before {
        bad.push("repair touched vault.bin".into());
    }
    match a.s.backups() {
        Ok(list) => {
            let e = list.iter().find(|b| b.path == p);
            match e {
                Some(b) if format!("{:?}", b.kind) == "Unsaved" => {}
                other => bad.push(format!("fallback copy listed as {other:?}")),
            }
        }
        Err(e) => bad.push(format!("backups() after repair: {e:?}")),
    }
    match a.s.restore_from(&p, &pw(PW)) {
        Ok(()) => {
            if !a.v().items().any(|i| i.title == "unsaved edit") {
                bad.push("restore from the fallback copy did not bring the edit back".into());
            }
        }
        Err(e) => bad.push(format!("restore_from(fallback copy): {e:?}")),
    }
    match a.s.delete_backup(&p) {
        Ok(()) => {
            if p.exists() {
                bad.push("delete_backup left the fallback copy".into());
            }
        }
        Err(e) => bad.push(format!("delete_backup(fallback copy): {e:?}")),
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §4: "only when that also fails is it `Unpreserved`"; the CLI and any caller that sets no
/// fallback get `Unpreserved` with a planted `backups`. "a symlinked vault-id folder refused".
#[test]
fn fb02_no_fallback_and_symlinked_vault_id_folder() {
    let mut bad = vec![];
    {
        let (_d, pkg, mut a) = setup("nf");
        plant_backups_file(&pkg);
        a.add_login("lost?", now_ms());
        let out = a.s.lock();
        if !matches!(out, vault_sync::LockOutcome::Unpreserved(_)) {
            bad.push(format!("no fallback dir: {out:?}"));
        }
    }
    {
        let (d, pkg, mut a) = setup("sl");
        let fb = d.path().join("fbdir");
        let elsewhere = d.path().join("elsewhere");
        std::fs::create_dir_all(&fb).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, fb.join(a.v().vault_id().to_string())).unwrap();
        a.s.set_fallback_dir(Some(fb.clone()));
        plant_backups_file(&pkg);
        a.add_login("edit", now_ms());
        let out = a.s.lock();
        if !ls(&elsewhere).is_empty() {
            bad.push(format!(
                "wrote through the symlinked vault-id folder: {:?}",
                ls(&elsewhere)
            ));
        }
        if !matches!(out, vault_sync::LockOutcome::Unpreserved(_)) {
            bad.push(format!("symlinked vault-id folder: outcome {out:?}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §4: "the path's parent must be exactly `backups/` or `<dir>/<vault_id>/` with no symlink on
/// the way; anything else is `NotABackup`" (for `restore_from` and `delete_backup`).
#[test]
fn fb03_fallback_path_rules() {
    let (d, pkg, mut a) = setup("pr");
    let fb = d.path().join("fb");
    a.s.set_fallback_dir(Some(fb.clone()));
    let vid = a.v().vault_id().to_string();
    let good = std::fs::read(primary(&pkg)).unwrap();
    let other = fb.join(uuid::Uuid::new_v4().to_string());
    let sub = fb.join(&vid).join("sub");
    let real = d.path().join("real");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::create_dir_all(&real).unwrap();
    let cand = vec![
        (
            "other vault-id folder",
            other.join("pr-2026-01-01T00-00-00Z-unsaved.vault.bin"),
        ),
        (
            "sub folder",
            sub.join("pr-2026-01-01T00-00-00Z-unsaved.vault.bin"),
        ),
        (
            "fallback root",
            fb.join("pr-2026-01-01T00-00-00Z-unsaved.vault.bin"),
        ),
        (
            "outside",
            real.join("pr-2026-01-01T00-00-00Z-unsaved.vault.bin"),
        ),
    ];
    let mut bad = vec![];
    for (label, p) in &cand {
        std::fs::write(p, &good).unwrap();
        let r = a.s.restore_from(p, &pw(PW));
        if !format!("{r:?}").contains("NotABackup") {
            bad.push(format!("restore_from {label}: {r:?}"));
        }
        let r = a.s.delete_backup(p);
        if !format!("{r:?}").contains("NotABackup") || !p.exists() {
            bad.push(format!(
                "delete_backup {label}: {r:?}, exists {}",
                p.exists()
            ));
        }
    }
    // a symlink on the way: <fb>/<vault_id> is a link to `real`
    std::fs::remove_dir_all(fb.join(&vid)).unwrap();
    std::os::unix::fs::symlink(&real, fb.join(&vid)).unwrap();
    let via = fb
        .join(&vid)
        .join("pr-2026-01-01T00-00-00Z-unsaved.vault.bin");
    let r = a.s.delete_backup(&via);
    // Refusal is the requirement; the spec names `NotABackup`, the variant is logged (Note).
    eprintln!("INFO delete_backup through a symlinked vault-id folder: {r:?}");
    if r.is_ok()
        || !real
            .join("pr-2026-01-01T00-00-00Z-unsaved.vault.bin")
            .exists()
    {
        bad.push(format!(
            "delete_backup through a symlinked vault-id folder: {r:?}"
        ));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §4 `repair_package`: "renames a non-directory `backups` or `attachments` entry (a plain file,
/// or a symlink of any kind, moved as the link itself) to `<name>.quarantined-<unix seconds>`
/// (`-2`, `-3` on collision) inside the package under the save lock, never deletes, never
/// replaces an existing entry and never touches `vault.bin` or anything else ... It returns the
/// new paths (empty when nothing needed moving)."
#[test]
fn rp01_repair_cases() {
    let mut bad = vec![];
    // nothing to do
    {
        let (_d, pkg, mut a) = setup("r0");
        let before = ls(&pkg);
        let r = a.s.repair_package();
        if !matches!(&r, Ok(v) if v.is_empty()) || ls(&pkg) != before {
            bad.push(format!("healthy package: {r:?}"));
        }
    }
    // plain file attachments + symlinked backups (to a directory with a file) + collisions
    {
        let (d, pkg, mut a) = setup("r1");
        let primary_before = std::fs::read(primary(&pkg)).unwrap();
        std::fs::remove_dir_all(pkg.join("backups")).unwrap();
        let target = d.path().join("target-dir");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("keep.txt"), b"keep").unwrap();
        std::os::unix::fs::symlink(&target, pkg.join("backups")).unwrap();
        let _ = std::fs::remove_dir_all(pkg.join("attachments"));
        std::fs::write(pkg.join("attachments"), b"att file").unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut pre = BTreeSet::new();
        for s in now.saturating_sub(2)..now + 30 {
            let n = format!("backups.quarantined-{s}");
            std::fs::write(pkg.join(&n), b"pre-existing").unwrap();
            pre.insert(n);
        }
        let r = a.s.repair_package();
        match &r {
            Ok(v) if v.len() == 2 => {
                for p in v {
                    let n = p.file_name().unwrap().to_string_lossy().into_owned();
                    if pre.contains(&n) {
                        bad.push(format!("repair reused an existing name {n}"));
                    }
                }
                let link = v.iter().find(|p| {
                    p.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("backups.")
                });
                match link {
                    Some(l) => {
                        if std::fs::read_link(l).ok().as_deref() != Some(target.as_path()) {
                            bad.push("symlinked backups not moved as the link itself".into());
                        }
                    }
                    None => bad.push(format!("no backups.* in {v:?}")),
                }
            }
            other => bad.push(format!("repair returned {other:?}")),
        }
        for n in &pre {
            if std::fs::read(pkg.join(n)).ok().as_deref() != Some(&b"pre-existing"[..]) {
                bad.push(format!("pre-existing {n} replaced or removed"));
            }
        }
        if ls(&target) != vec!["keep.txt".to_string()] {
            bad.push("repair touched the symlink target's contents".into());
        }
        if std::fs::read(primary(&pkg)).unwrap() != primary_before {
            bad.push("repair touched vault.bin".into());
        }
        // and saving works again
        a.add_login("after repair", now_ms());
        if let Err(e) = a.s.save() {
            bad.push(format!("save after repair: {e:?}"));
        }
    }
    // FIFO and dangling link
    {
        let (_d, pkg, mut a) = setup("r2");
        std::fs::remove_dir_all(pkg.join("backups")).unwrap();
        let st = std::process::Command::new("mkfifo")
            .arg(pkg.join("backups"))
            .status()
            .unwrap();
        assert!(st.success());
        let _ = std::fs::remove_dir_all(pkg.join("attachments"));
        std::os::unix::fs::symlink("/nonexistent/qa-dangling", pkg.join("attachments")).unwrap();
        let r = with_timeout(20, move || {
            let r = a.s.repair_package();
            (r, a)
        });
        match r {
            None => bad.push("repair hung on a FIFO backups entry".into()),
            Some((Ok(v), _)) if v.len() == 2 => {}
            Some((r, _)) => bad.push(format!("FIFO + dangling link: {r:?}")),
        }
    }
    // newer-version vault.bin stub left alone, saves keep refusing NewerVersion
    {
        let (_d, pkg, mut a) = setup("r3");
        let mut b = std::fs::read(primary(&pkg)).unwrap();
        b[4..6].copy_from_slice(&4u16.to_be_bytes());
        std::fs::write(primary(&pkg), &b).unwrap();
        plant_backups_file(&pkg);
        let r = a.s.repair_package();
        if std::fs::read(primary(&pkg)).unwrap() != b {
            bad.push("repair touched a newer-version vault.bin".into());
        }
        if !matches!(&r, Ok(v) if v.len() == 1) {
            bad.push(format!("repair with a newer stub: {r:?}"));
        }
        a.add_login("blocked", now_ms());
        let s = a.s.save();
        if !format!("{s:?}").contains("NewerVersion") {
            bad.push(format!("save after repair over a newer stub: {s:?}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §4: "an entry counts as a snapshot only if its prefix and plaintext header ... parse as a
/// supported vault with this vault's id ... Only validated snapshots take a retention slot or
/// satisfy the 1-hour rule ...; unvalidated entries are never deleted and are listed after every
/// validated one."
#[test]
fn ba01_unvalidated_entries_never_count_or_get_deleted() {
    let (d, pkg, mut a) = setup("ua");
    let bd = pkg.join("backups");
    let good = std::fs::read(primary(&pkg)).unwrap();
    // a foreign vault's file
    let fpkg = d.path().join("foreign.vault");
    let mut f = Dev::create(&fpkg);
    f.add_login("foreign", now_ms());
    f.s.save().unwrap();
    let foreign = std::fs::read(primary(&fpkg)).unwrap();
    clear_dir(&bd);
    let mut planted = vec![];
    // garbage and foreign entries named as fresh snapshots: they must not satisfy the 1 h rule
    for (k, bytes) in [(0u64, b"garbage".to_vec()), (60, foreign.clone())] {
        let n = snap_name("ua", k);
        std::fs::write(bd.join(&n), &bytes).unwrap();
        planted.push(n);
    }
    // and many old ones in one week, which retention would thin out if they were snapshots
    for k in 0..12u64 {
        let n = snap_name("ua", 40 * DAY + k * 3_600);
        let bytes = if k % 2 == 0 {
            b"junk".to_vec()
        } else {
            foreign.clone()
        };
        std::fs::write(bd.join(&n), &bytes).unwrap();
        planted.push(n);
    }
    a.add_login("second save", now_ms());
    a.s.save().unwrap();
    let after = ls(&bd);
    let mut bad = vec![];
    let fresh: Vec<&String> = after.iter().filter(|n| !planted.contains(n)).collect();
    let fresh_ok = fresh.iter().any(|n| opens_with(&bd.join(n), "second save"));
    if !fresh_ok {
        bad.push(format!(
            "no snapshot taken although only unvalidated entries are newer than 1 h: {fresh:?}"
        ));
    }
    for n in &planted {
        if !after.contains(n) {
            bad.push(format!("unvalidated entry deleted: {n}"));
        }
    }
    match a.s.backups() {
        Ok(list) => {
            let names: Vec<String> = list
                .iter()
                .map(|b| b.path.file_name().unwrap().to_string_lossy().into_owned())
                .collect();
            let last_valid = names.iter().rposition(|n| !planted.contains(n));
            let first_unvalid = names.iter().position(|n| planted.contains(n));
            if let (Some(v), Some(u)) = (last_valid, first_unvalid) {
                if u < v {
                    bad.push(format!(
                        "unvalidated entry listed before a validated one: {names:?}"
                    ));
                }
            }
        }
        Err(e) => bad.push(format!("backups(): {e:?}")),
    }
    let _ = good;
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Plants authentic snapshots at `ages` (bytes `auth`) and optional forged-body copies (the
/// authentic header with a garbage body) 10 minutes newer and older; returns the authentic names
/// kept after `backup_now`.
fn retention_with_forgeries(forge: bool) -> (BTreeSet<String>, usize, Vec<String>) {
    let (_d, pkg, mut a) = setup("fg");
    let bd = pkg.join("backups");
    let auth = std::fs::read(primary(&pkg)).unwrap();
    let hlen = u32::from_be_bytes([auth[6], auth[7], auth[8], auth[9]]) as usize;
    let mut forged = auth[..10 + hlen].to_vec();
    forged.extend_from_slice(&[0x81, 0x40]); // a body array with one empty byte string
    clear_dir(&bd);
    let mut names = BTreeSet::new();
    let mut forged_names = vec![];
    for k in 0..12u64 {
        let age = 35 * DAY + k * DAY;
        let n = snap_name("fg", age);
        std::fs::write(bd.join(&n), &auth).unwrap();
        names.insert(n);
        if forge {
            for delta in [age - 600, age + 600] {
                let n = snap_name("fg", delta);
                std::fs::write(bd.join(&n), &forged).unwrap();
                forged_names.push(n);
            }
        }
    }
    a.s.backup_now().unwrap();
    let after: BTreeSet<String> = ls(&bd).into_iter().collect();
    let kept: BTreeSet<String> = names.intersection(&after).cloned().collect();
    let forged_kept = forged_names.iter().filter(|n| after.contains(*n)).count();
    (kept, forged_kept, forged_names)
}

/// 03 §4: "Deleting a snapshot requires every snapshot that displaces it to authenticate fully
/// under the current vault key (...; a holder that fails ... means nothing is deleted this pass)
/// ... A copied header with a forged body lists as a backup and fails at restore." So forged-body
/// copies can never cost an authentic snapshot: the authentic set kept with forgeries present is a
/// superset of the set kept without them.
#[test]
fn ba02_forged_body_snapshots_never_displace_authentic_ones() {
    let (control, _, _) = retention_with_forgeries(false);
    let (with, forged_kept, forged) = retention_with_forgeries(true);
    eprintln!(
        "INFO authentic kept without forgeries {}/12, with forgeries {}/12; forged kept {forged_kept}/{}",
        control.len(),
        with.len(),
        forged.len()
    );
    assert!(
        control.len() < 12,
        "control run must prune something for the check to bite"
    );
    let lost: Vec<&String> = control.difference(&with).collect();
    assert!(
        lost.is_empty(),
        "authentic snapshots lost to forged-body copies: {lost:?}"
    );
}

/// 03 §4: "Snapshots sealed under a since-rotated key therefore stay listed and restorable with
/// the password but are never pruned".
#[test]
fn ba03_rotated_key_snapshots_never_pruned() {
    let run = |rotate: bool| {
        let (_d, pkg, mut a) = setup("rk");
        let bd = pkg.join("backups");
        let old = std::fs::read(primary(&pkg)).unwrap();
        clear_dir(&bd);
        let mut names = BTreeSet::new();
        for k in 0..20u64 {
            let n = snap_name("rk", 35 * DAY + k * DAY);
            std::fs::write(bd.join(&n), &old).unwrap();
            names.insert(n);
        }
        if rotate {
            a.s.edit(|v| v.rotate_vault_key(&pw(PW), now_ms()))
                .unwrap()
                .unwrap();
            a.s.save().unwrap();
        }
        a.s.backup_now().unwrap();
        let after: BTreeSet<String> = ls(&bd).into_iter().collect();
        let listed = a.s.backups().map(|l| l.len()).unwrap_or(0);
        (names.intersection(&after).count(), listed)
    };
    let (control, _) = run(false);
    let (rotated, listed) = run(true);
    eprintln!(
        "INFO old-key snapshots kept: control {control}/20, after rotation {rotated}/20; listed {listed}"
    );
    assert!(control < 20, "control run must prune");
    assert_eq!(
        rotated, 20,
        "a snapshot under a since-rotated key was pruned"
    );
}

/// 03 §4: "When `backups/` holds more than 10,000 entries, retention is skipped for that pass"
/// and 03 §2 "a partial listing never deletes more than a full one would": nothing is deleted;
/// the save itself still works in bounded time.
#[test]
fn ba04_more_than_10000_entries_skip_retention() {
    let (_d, pkg, mut a) = setup("tk");
    let bd = pkg.join("backups");
    let auth = std::fs::read(primary(&pkg)).unwrap();
    clear_dir(&bd);
    let mut names = vec![];
    for k in 0..20u64 {
        let n = snap_name("tk", 35 * DAY + k * DAY);
        std::fs::write(bd.join(&n), &auth).unwrap();
        names.push(n);
    }
    for k in 0..10_001 {
        std::fs::write(bd.join(format!("junk-{k:05}")), b"").unwrap();
    }
    let r = with_timeout(120, move || {
        let r = a.s.backup_now().map(|_| ());
        (r, a)
    });
    let (r, _a) = r.expect("backup_now hung with 10,021 entries");
    let after: BTreeSet<String> = ls(&bd).into_iter().collect();
    let gone: Vec<&String> = names.iter().filter(|n| !after.contains(*n)).collect();
    eprintln!("INFO backup_now with >10,000 entries: {r:?}");
    assert!(
        gone.is_empty(),
        "retention ran over a >10,000-entry backups/: deleted {}",
        gone.len()
    );
}

/// 03 §4 measurement for the report (INFO, asserts only the spec sentence): one forged-body file
/// in the monthly tier, authentic snapshots in the weekly tier that retention would thin out.
/// "a holder that fails ... means nothing is deleted this pass".
#[test]
fn ba05_one_forged_file_and_pruning() {
    let (_d, pkg, mut a) = setup("of");
    let bd = pkg.join("backups");
    let auth = std::fs::read(primary(&pkg)).unwrap();
    let hlen = u32::from_be_bytes([auth[6], auth[7], auth[8], auth[9]]) as usize;
    let mut forged = auth[..10 + hlen].to_vec();
    forged.extend_from_slice(&[0x81, 0x40]);
    clear_dir(&bd);
    let mut names = BTreeSet::new();
    for k in 0..12u64 {
        let n = snap_name("of", 35 * DAY + k * DAY);
        std::fs::write(bd.join(&n), &auth).unwrap();
        names.insert(n);
    }
    let fname = snap_name("of", 300 * DAY);
    std::fs::write(bd.join(&fname), &forged).unwrap();
    a.s.backup_now().unwrap();
    let after: BTreeSet<String> = ls(&bd).into_iter().collect();
    let kept = names.intersection(&after).count();
    eprintln!(
        "INFO one forged-body file 300 days old: authentic weekly-tier snapshots kept {kept}/12, forged kept {}",
        after.contains(&fname)
    );
    assert!(
        after.contains(&fname),
        "03 §4: the forged file is not deleted by a failing pass"
    );
}
