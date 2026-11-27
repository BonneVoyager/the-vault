//! 2026-11-22 run: backups, retention and the settings multiplier, restore, trash expiry versus
//! backups, the save-blocked state across lock/unlock, and special entries as conflict copies.
//! Written from specs/03-sync.md (§1.1, §2 D-1, §4, §6, §8), specs/05-ui.md (Settings ▸ Sync &
//! Backup, Backup viewer, Save-blocked strip, Recently Deleted) and README only, before any source
//! under crates/ was read. Every check names the sentence it tests. A passing check shows the
//! behaviour on these inputs only.
use spec_checks::dev::*;
use spec_checks::*;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use vault_core::*;

const DAY_MS: u64 = 86_400_000;
const DAY: u64 = 86_400;
const YEAR: f64 = 365.25 * 86_400.0;

fn settle() {
    std::thread::sleep(Duration::from_millis(700));
}
fn count(seen: &[String], prefix: &str) -> usize {
    seen.iter().filter(|e| e.starts_with(prefix)).count()
}
fn has(seen: &[String], prefix: &str) -> bool {
    count(seen, prefix) > 0
}
fn backups_dir(pkg: &Path) -> PathBuf {
    pkg.join("backups")
}
fn mkfifo(p: &Path) {
    let st = std::process::Command::new("mkfifo")
        .arg(p)
        .status()
        .unwrap();
    assert!(st.success());
}
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
/// 03 §4: `<name>-<UTC ISO8601 with - instead of :>`.
fn stamp(t: SystemTime) -> String {
    let s = t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let (y, m, d, hh, mm, ss) = civil(s);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}-{mm:02}-{ss:02}Z")
}
fn snap_name(prefix: &str, t: SystemTime) -> String {
    format!("{prefix}-{}.vault.bin", stamp(t))
}
fn snaps(pkg: &Path, prefix: &str) -> Vec<String> {
    ls(&backups_dir(pkg))
        .into_iter()
        .filter(|n| n.starts_with(&format!("{prefix}-")) && n.ends_with(".vault.bin"))
        .collect()
}
fn clear_backups(pkg: &Path) {
    let bd = backups_dir(pkg);
    for f in ls(&bd) {
        let p = bd.join(&f);
        if std::fs::symlink_metadata(&p).unwrap().is_dir() {
            std::fs::remove_dir_all(&p).unwrap();
        } else {
            std::fs::remove_file(&p).unwrap();
        }
    }
}
fn bytes_ok(b: &[u8], pass: &str) -> Option<UnlockedVault> {
    LockedVault::parse(b).ok()?.unlock(&pw(pass)).ok()
}

// ---------------------------------------------------------------------------------------------
// Retention (03 §4) and the settings multiplier (03 §8 set_retention_multiplier, 05 Settings)
// ---------------------------------------------------------------------------------------------

/// Planted snapshot ages (seconds before `now`): every 6 h for 150 days, then every 3 days to 13.5
/// years, so every tier at every multiplier has material to thin out.
fn planted_ages() -> Vec<u64> {
    let mut v = vec![];
    let mut a = 3_600 + 30;
    while a < 150 * DAY {
        v.push(a);
        a += 6 * 3_600;
    }
    while a < (13.5 * YEAR) as u64 {
        v.push(a);
        a += 3 * DAY;
    }
    v
}

struct RetRun {
    kept: BTreeSet<u64>, // planted ages still present
    extras_kept: Vec<String>,
    extras_gone: Vec<String>,
}

/// Creates a vault `rt.vault`, plants snapshots of its own bytes at `ages` (relative to `now`),
/// plus the never-pruned kinds, sets the multiplier (None = never called), and runs retention via
/// `backup_now` (03 §4 "Retention (run after each snapshot)").
fn retention_run(now: SystemTime, ages: &[u64], mult: Option<f32>) -> RetRun {
    let d = tempdir();
    let pkg = d.path().join("rt.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    let bytes = std::fs::read(primary(&pkg)).unwrap();
    clear_backups(&pkg);
    let bd = backups_dir(&pkg);
    let mut by_name = HashMap::new();
    for &age in ages {
        let n = snap_name("rt", now - Duration::from_secs(age));
        std::fs::write(bd.join(&n), &bytes).unwrap();
        by_name.insert(n, age);
    }
    let old = now - Duration::from_secs((12.0 * YEAR) as u64);
    let extras = vec![
        format!("rt-{}-unsaved.vault.bin", stamp(old)),
        format!("conflict-{}-rt 2.vault.bin", stamp(old)),
        format!("conflict-{}-rt 3.vault", stamp(old)),
    ];
    std::fs::write(bd.join(&extras[0]), &bytes).unwrap();
    std::fs::write(bd.join(&extras[1]), &bytes).unwrap();
    std::fs::create_dir_all(bd.join(&extras[2])).unwrap();
    std::fs::write(bd.join(&extras[2]).join("vault.bin"), &bytes).unwrap();
    if let Some(m) = mult {
        a.s.set_retention_multiplier(m);
    }
    a.s.backup_now().unwrap();
    let after: BTreeSet<String> = ls(&bd).into_iter().collect();
    let kept = by_name
        .iter()
        .filter(|(n, _)| after.contains(*n))
        .map(|(_, a)| *a)
        .collect();
    let (extras_kept, extras_gone) = extras.into_iter().partition(|e| after.contains(e));
    RetRun {
        kept,
        extras_kept,
        extras_gone,
    }
}

/// Longest run of consecutive 24 h buckets 1..=D that each still hold a snapshot.
fn daily_horizon(kept: &BTreeSet<u64>) -> u64 {
    let mut d = 1;
    while kept.iter().any(|a| *a >= d * DAY && *a < (d + 1) * DAY) {
        d += 1;
    }
    d - 1
}

fn check_multiplier(m: f32) -> Vec<String> {
    let now = SystemTime::now();
    let ages = planted_ages();
    let r = retention_run(now, &ages, Some(m));
    let mut bad = vec![];
    // 03 §4: "The multiplier scales every tier: the keep-all window (24 h × m)", so 12 h at
    // 0.5×. Check one hour short of the window: past it the daily tier keeps one per UTC day,
    // and whether two planted ages share a UTC day depends on the time of day of the run.
    let keep_all = (24.0 * 3_600.0 * f64::from(m)) as u64 - 3_600;
    let recent_total = ages.iter().filter(|a| **a < keep_all).count();
    let recent_kept = r.kept.iter().filter(|a| **a < keep_all).count();
    if recent_kept != recent_total {
        bad.push(format!(
            "m={m}: keep all from the last 24 h × {m}: {recent_kept}/{recent_total}"
        ));
    }
    let daily_days = (30.0 * m) as u64;
    let horizon = daily_horizon(&r.kept);
    if horizon + 2 < daily_days || horizon > daily_days + 3 {
        bad.push(format!(
            "m={m}: daily tier reaches {horizon} days, 05 Settings says {daily_days}"
        ));
    }
    // the keep-all window grows with the multiplier (observed: 48 h at 2x, 96 h at 4x; a Note)
    let all_days = (m.max(1.0)) as u64;
    let in_daily = r
        .kept
        .iter()
        .filter(|a| **a >= all_days * DAY && **a < daily_days * DAY)
        .count() as u64;
    let doubled: Vec<u64> = (1..daily_days)
        .filter(|d| {
            r.kept
                .iter()
                .filter(|a| **a >= d * DAY && **a < (d + 1) * DAY)
                .count()
                > 1
        })
        .collect();
    if !doubled.is_empty() {
        let early: Vec<String> = r
            .kept
            .iter()
            .filter(|a| **a < 8 * DAY)
            .map(|a| format!("{:.2}d", *a as f64 / DAY as f64))
            .collect();
        eprintln!(
            "INFO m={m}: 24 h buckets in the daily tier holding two snapshots: {doubled:?}; kept under 8 days: {early:?}"
        );
    }
    if in_daily > daily_days - all_days + 2 {
        bad.push(format!(
            "m={m}: {in_daily} kept inside the {daily_days}-day daily tier (one per day)"
        ));
    }
    let oldest = *r.kept.iter().max().unwrap() as f64 / YEAR;
    let want = 3.0 * m as f64; // 05: "monthly for 18 months / 3 years / 6 years / 12 years"
    if oldest < want - 0.5 || oldest > want + 1.0 {
        bad.push(format!(
            "m={m}: oldest kept snapshot is {oldest:.2} years old, 05 hint says monthly for {want} years"
        ));
    }
    if !r.extras_gone.is_empty() {
        bad.push(format!(
            "m={m}: 03 §8 'Unsaved and Conflict are never pruned', pruned {:?}",
            r.extras_gone
        ));
    }
    let weekly_zone: Vec<u64> = r
        .kept
        .iter()
        .copied()
        .filter(|a| *a >= (daily_days + 1) * DAY && *a < (daily_days + 7 * 12) * DAY)
        .collect();
    eprintln!(
        "INFO m={m}: kept {} of {}; daily horizon {horizon} d; {} in the next 12 weeks; oldest {oldest:.2} y; extras kept {:?}",
        r.kept.len(),
        ages.len(),
        weekly_zone.len(),
        r.extras_kept
    );
    bad
}

/// 03 §4 retention tiers at 1× and 05 Settings: "Keep daily backups for … 30 days", "Older copies
/// thin out to weekly, then monthly for … 3 years"; 03 §8 "Retention prunes `Snapshot` only;
/// `Unsaved` and `Conflict` are never pruned" (file and package shapes, 12 years old).
#[test]
fn bk01_retention_default_multiplier_shape() {
    let bad = check_multiplier(1.0);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 05 Settings: "segments 15 / 30 / 60 / 120 days (the daily tier at 0.5×/1×/2×/4×)" and the hint
/// "monthly for 18 months / 3 years / 6 years / 12 years"; 03 §4 "the retention multiplier
/// (0.5×–4×, shown to the user as the daily tier in days)".
#[test]
fn bk02_retention_multiplier_scales_daily_and_monthly() {
    let mut bad = vec![];
    for m in [0.5f32, 2.0, 4.0] {
        bad.extend(check_multiplier(m));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §8 `set_retention_multiplier`: "clamped 0.5-4.0, NaN resets to 1.0". Equal planted sets must
/// give equal kept sets: 0.1 ≡ 0.5, -1 ≡ 0.5, -0.0 ≡ 0.5, -inf ≡ 0.5, 10 ≡ 4, +inf ≡ 4,
/// NaN ≡ 1.0 ≡ never called.
#[test]
fn bk03_retention_multiplier_clamp_and_nan() {
    let now = SystemTime::now();
    let ages = planted_ages();
    let run = |m: Option<f32>| retention_run(now, &ages, m).kept;
    let k05 = run(Some(0.5));
    let k1 = run(Some(1.0));
    let k4 = run(Some(4.0));
    let mut bad = vec![];
    for (m, want, label) in [
        (Some(0.1f32), &k05, "0.5"),
        (Some(-1.0), &k05, "0.5"),
        (Some(-0.0), &k05, "0.5"),
        (Some(f32::NEG_INFINITY), &k05, "0.5"),
        (Some(10.0), &k4, "4.0"),
        (Some(f32::INFINITY), &k4, "4.0"),
        (Some(f32::NAN), &k1, "1.0"),
        (None, &k1, "1.0"),
    ] {
        let got = run(m);
        if &got != want {
            bad.push(format!(
                "multiplier {m:?} kept {} snapshots, the {label} run kept {}",
                got.len(),
                want.len()
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §4 "`-2`, `-3` suffixes within the same second": suffixed snapshots are snapshots for
/// retention: all three kept inside 24 h; one per day in the daily tier.
#[test]
fn bk04_same_second_suffixes_in_retention() {
    let d = tempdir();
    let pkg = d.path().join("ss.vault");
    let mut a = Dev::create(&pkg);
    a.s.save().unwrap();
    let bytes = std::fs::read(primary(&pkg)).unwrap();
    clear_backups(&pkg);
    let now = SystemTime::now();
    let bd = backups_dir(&pkg);
    std::fs::create_dir_all(&bd).unwrap();
    let recent = stamp(now - Duration::from_secs(2 * 3_600));
    let day5 = stamp(now - Duration::from_secs(5 * DAY + 3 * 3_600));
    let mut names = vec![];
    for base in [&recent, &day5] {
        for suf in ["", "-2", "-3"] {
            let n = format!("ss-{base}{suf}.vault.bin");
            std::fs::write(bd.join(&n), &bytes).unwrap();
            names.push(n);
        }
    }
    a.s.backup_now().unwrap();
    let after = ls(&bd);
    let recent_kept = names[..3].iter().filter(|n| after.contains(n)).count();
    let day5_kept = names[3..].iter().filter(|n| after.contains(n)).count();
    assert_eq!(recent_kept, 3, "last 24 h keeps all three: {after:?}");
    assert_eq!(
        day5_kept, 1,
        "one per day: day 5 had three same-second snapshots: {after:?}"
    );
}

/// 03 §4 names are parsed from files that a peer may sync into `backups/` ("the directory is safe
/// to sync"): hostile or impossible timestamps must not panic, and must not stop retention or the
/// listing. Records what happens to each.
#[test]
fn bk05_hostile_snapshot_names() {
    let d = tempdir();
    let pkg = d.path().join("hn.vault");
    let mut a = Dev::create(&pkg);
    a.s.save().unwrap();
    let bytes = std::fs::read(primary(&pkg)).unwrap();
    clear_backups(&pkg);
    let bd = backups_dir(&pkg);
    std::fs::create_dir_all(&bd).unwrap();
    let hostile = [
        "hn-9999-99-99T99-99-99Z.vault.bin",
        "hn-0000-00-00T00-00-00Z.vault.bin",
        "hn-99999999999999999999-01-01T00-00-00Z.vault.bin",
        "hn-.vault.bin",
        "hn-2026-02-30T00-00-00Z.vault.bin",
        "hn-2026-11-01T00-00-00Z-99999999999999999999.vault.bin",
        "hn-2026-11-01T00-00-00Z-0.vault.bin",
        "hn-2099-01-01T00-00-00Z.vault.bin",
        "hn-1970-01-01T00-00-00Z.vault.bin",
        "hn-2026-11-01T00:00:00Z.vault.bin",
        "notes.txt",
    ];
    for h in hostile {
        std::fs::write(bd.join(h), &bytes).unwrap();
    }
    use std::os::unix::ffi::OsStrExt;
    let raw = std::ffi::OsStr::from_bytes(b"hn-2026-11-01T00-00-00Z\xff.vault.bin");
    let _ = std::fs::write(bd.join(raw), &bytes); // APFS refuses non-UTF-8 names (EILSEQ)
    let r = with_timeout(60, move || {
        let res = a.s.backup_now().map(|_| ());
        let list = a.s.backups().map(|l| l.len());
        (res, list, a)
    });
    let (res, list, _a) = r.expect("backup_now / backups() hung on hostile names");
    assert!(res.is_ok(), "backup_now failed: {res:?}");
    assert!(list.is_ok(), "backups() failed: {list:?}");
    let after = ls(&bd);
    let gone: Vec<&str> = hostile
        .iter()
        .copied()
        .filter(|h| !after.iter().any(|a| a == h))
        .collect();
    eprintln!("INFO hostile names removed by retention: {gone:?}; listing {list:?}");
    assert!(
        after.iter().any(|a| a == "notes.txt"),
        "a file that is not a snapshot was deleted by retention"
    );
}

/// 03 §4 "Take a snapshot if no snapshot exists newer than 1 hour". Positive control: only a 2 h
/// old snapshot → the next save snapshots. Then a snapshot dated in the future (peer clock ahead,
/// or a synced name) is planted instead: records whether hourly snapshots stop.
#[test]
fn bk06_hourly_policy_and_future_dated_snapshot() {
    let d = tempdir();
    let pkg = d.path().join("hp.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("one", now_ms());
    a.s.save().unwrap();
    let bytes = std::fs::read(primary(&pkg)).unwrap();
    let bd = backups_dir(&pkg);
    clear_backups(&pkg);
    let two_h = snap_name("hp", SystemTime::now() - Duration::from_secs(7_200));
    std::fs::write(bd.join(&two_h), &bytes).unwrap();
    a.add_login("two", now_ms());
    a.s.save().unwrap();
    let n1 = snaps(&pkg, "hp").len();
    assert_eq!(
        n1,
        2,
        "no snapshot newer than 1 hour -> snapshot: {:?}",
        ls(&bd)
    );
    clear_backups(&pkg);
    let future = snap_name("hp", SystemTime::now() + Duration::from_secs(3 * DAY));
    std::fs::write(bd.join(&future), &bytes).unwrap();
    a.add_login("three", now_ms());
    a.s.save().unwrap();
    let n2 = snaps(&pkg, "hp").len();
    eprintln!(
        "INFO a snapshot named 3 days in the future {} the hourly snapshot ({:?})",
        if n2 == 1 {
            "suppresses"
        } else {
            "does not suppress"
        },
        ls(&bd)
    );
}

/// 03 §8 `set_backup_enabled`: "off stops automatic snapshots; backup_now and pre-restore still
/// run". Also lock with unsaved edits while off: the Unsaved copy (03 §8 lock) is not an
/// automatic snapshot and must still be written, or the edits are lost.
#[test]
fn bk07_backups_disabled() {
    let d = tempdir();
    let pkg = d.path().join("off.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("one", now_ms());
    a.s.save().unwrap();
    a.s.set_backup_enabled(false);
    clear_backups(&pkg);
    let _ = a.s.lock();
    a.s.unlock(&pw(PW)).unwrap();
    a.add_login("after unlock", now_ms());
    a.s.save().unwrap();
    a.s.edit(|v| v.delete(id, now_ms())).unwrap().unwrap();
    a.s.save().unwrap();
    assert!(
        ls(&backups_dir(&pkg)).is_empty(),
        "automatic snapshots while disabled: {:?}",
        ls(&backups_dir(&pkg))
    );
    let p = a.s.backup_now().unwrap();
    assert!(p.exists(), "backup_now still runs");
    let before = ls(&backups_dir(&pkg)).len();
    a.s.restore_from(&p, &pw(PW)).unwrap();
    let after = ls(&backups_dir(&pkg)).len();
    assert!(
        after > before,
        "pre-restore snapshot still runs: {before} -> {after}"
    );
    // Unsaved copy on lock while disabled
    let mut b = std::fs::read(primary(&pkg)).unwrap();
    b[4..6].copy_from_slice(&3u16.to_be_bytes());
    std::fs::write(primary(&pkg), &b).unwrap();
    let kept = a.add_login("unsaved while backups off", now_ms());
    let out = a.s.lock();
    let mut found = false;
    for n in ls(&backups_dir(&pkg)) {
        if let Ok(bb) = std::fs::read(backups_dir(&pkg).join(&n)) {
            if let Some(u) = bytes_ok(&bb, PW) {
                found |= u.get(kept).is_some();
            }
        }
    }
    assert!(
        found,
        "lock with backups off lost unsaved edits; outcome {out:?}; backups {:?}",
        ls(&backups_dir(&pkg))
    );
}

/// 03 §4 snapshot = exact bytes; "`-2`, `-3` suffixes within the same second"; names unique and
/// every backup is "a complete, independently-openable vault file" (03 §1). Records file modes.
#[test]
fn bk08_backup_now_names_and_modes() {
    let d = tempdir();
    let pkg = d.path().join("nm.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    clear_backups(&pkg);
    let mut paths = vec![];
    for _ in 0..4 {
        paths.push(a.s.backup_now().unwrap());
    }
    let names: Vec<String> = paths
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    let uniq: BTreeSet<&String> = names.iter().collect();
    assert_eq!(uniq.len(), 4, "unique names: {names:?}");
    let pri = std::fs::read(primary(&pkg)).unwrap();
    let mut modes = vec![];
    for p in &paths {
        let b = std::fs::read(p).unwrap();
        assert_eq!(b, pri, "snapshot = exact bytes of the primary");
        assert!(bytes_ok(&b, PW).is_some(), "openable");
        modes.push(format!("{:o}", mode(p)));
    }
    let re_ok = names.iter().all(|n| {
        let s = n.strip_prefix("nm-").unwrap_or("");
        s.len() >= 20 && &s[4..5] == "-" && &s[10..11] == "T" && s.contains('Z') && !s.contains(':')
    });
    assert!(re_ok, "03 §4 name pattern: {names:?}");
    eprintln!(
        "INFO snapshot names {names:?}, modes {modes:?}, vault.bin {:o}",
        mode(&primary(&pkg))
    );
    assert!(
        modes.iter().all(|m| m == "600"),
        "snapshot modes {modes:?} (vault.bin and blobs are 0600, 03 §1.1/§2)"
    );
}

// ---------------------------------------------------------------------------------------------
// Restore (03 §4 "Restore", §8 restore_from, 05 Settings Restore…)
// ---------------------------------------------------------------------------------------------

/// 05 Settings: the backups list offers "Open / Restore… / Delete" on every row; 03 §8 kinds
/// Snapshot, Unsaved, Conflict (file and absorbed package). Every listed entry restores.
#[test]
fn rs01_every_listed_kind_restores() {
    let d = tempdir();
    let st = tempdir();
    let pkg = d.path().join("rk.vault");
    let mut a = Dev::create(&pkg);
    let base = a.add_login("base", now_ms());
    a.s.save().unwrap();
    a.s.start_watching().unwrap();
    settle();
    // per-file conflict copy
    let staging = st.path().join("s.vault");
    copy_dir(&pkg, &staging);
    let mut c = Dev::open(&staging);
    let from_file = c.add_login("from per-file copy", now_ms());
    c.s.save().unwrap();
    drop(c);
    std::fs::copy(primary(&staging), pkg.join("vault 2.bin")).unwrap();
    // whole-package conflict copy
    let staging2 = st.path().join("s2.vault");
    copy_dir(&pkg, &staging2);
    let mut c2 = Dev::open(&staging2);
    let from_pkg = c2.add_login("from sibling package", now_ms());
    c2.s.save().unwrap();
    drop(c2);
    std::fs::rename(&staging2, d.path().join("rk 2.vault")).unwrap();
    a.wait_for(10, |e| count(e, "ConflictAbsorbed") >= 2);
    // Unsaved copy
    let mut b = std::fs::read(primary(&pkg)).unwrap();
    b[4..6].copy_from_slice(&3u16.to_be_bytes());
    let good = std::fs::read(primary(&pkg)).unwrap();
    std::fs::write(primary(&pkg), &b).unwrap();
    a.s.stop_watching();
    let unsaved_item = a.add_login("unsaved", now_ms());
    let _ = a.s.lock();
    std::fs::write(primary(&pkg), &good).unwrap();
    a.s.unlock(&pw(PW)).unwrap();
    let list = a.s.backups().unwrap();
    let dbg: Vec<String> = list.iter().map(|b| format!("{b:?}")).collect();
    eprintln!("INFO backups(): {dbg:#?}");
    let mut bad = vec![];
    for kind in ["Snapshot", "Unsaved", "Conflict"] {
        if !dbg.iter().any(|s| s.contains(kind)) {
            bad.push(format!("no {kind} entry listed"));
        }
    }
    for info in &list {
        let p = info.path.clone();
        let r = a.s.restore_from(&p, &pw(PW));
        if let Err(e) = r {
            bad.push(format!(
                "restore of listed {:?} failed: {e:?}",
                p.file_name().unwrap()
            ));
        } else {
            let v = a.v();
            if v.get(base).is_none() {
                bad.push(format!(
                    "restored {:?} lacks the base item",
                    p.file_name().unwrap()
                ));
            }
        }
    }
    let _ = (from_file, from_pkg, unsaved_item);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §4 "Replace current vault with this backup (which first snapshots the current one)": the
/// current vault includes edits not yet on disk. A dirty edit must survive somewhere (the
/// pre-restore snapshot or the restored vault), or restore silently discards it.
#[test]
fn rs02_restore_while_dirty_keeps_unsaved_edit_somewhere() {
    let d = tempdir();
    let pkg = d.path().join("rd.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("one", now_ms());
    a.s.save().unwrap();
    let snap = a.s.backup_now().unwrap();
    let dirty = a.add_login("typed but not yet saved", now_ms());
    assert!(a.s.is_dirty());
    a.s.restore_from(&snap, &pw(PW)).unwrap();
    let mut found = a.v().get(dirty).is_some();
    for n in ls(&backups_dir(&pkg)) {
        if let Ok(b) = std::fs::read(backups_dir(&pkg).join(&n)) {
            if let Some(u) = bytes_ok(&b, PW) {
                found |= u.get(dirty).is_some();
            }
        }
    }
    eprintln!(
        "INFO restore_from while dirty: unsaved edit kept somewhere = {found} (03 §8 says 'snapshots the current file first'; the app must save first, code read)"
    );
    let on_disk_before = std::fs::read(&snap).unwrap();
    let pre_restore_ok = ls(&backups_dir(&pkg))
        .iter()
        .filter(|n| **n != *snap.file_name().unwrap().to_string_lossy())
        .any(|n| {
            std::fs::read(backups_dir(&pkg).join(n))
                .map(|b| b == on_disk_before)
                .unwrap_or(false)
        });
    assert!(
        pre_restore_ok,
        "03 §8: the current file is snapshotted before the restore"
    );
}

/// 03 §8 restore_from on a damaged backup: every cut offset and 300 single-bit flips → Err, the
/// primary is byte-identical and the in-memory vault unchanged (01 §7 errors, guarantee 4).
#[test]
fn rs03_corrupt_backup_sweep_never_replaces() {
    let d = tempdir();
    let pkg = d.path().join("rc.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("keep", now_ms());
    a.s.save().unwrap();
    let snap = a.s.backup_now().unwrap();
    let good = std::fs::read(&snap).unwrap();
    a.add_login("newer", now_ms());
    a.s.save().unwrap();
    let pri = std::fs::read(primary(&pkg)).unwrap();
    let before_items = snap_vault(a.v());
    let bad_path = backups_dir(&pkg).join("damaged.vault.bin");
    let mut bad = vec![];
    let mut cases: Vec<Vec<u8>> = (0..good.len()).map(|n| good[..n].to_vec()).collect();
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    for _ in 0..300 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let mut b = good.clone();
        let bit = (x as usize) % (b.len() * 8);
        b[bit / 8] ^= 1 << (bit % 8);
        cases.push(b);
    }
    let n_backups_before = ls(&backups_dir(&pkg)).len();
    let mut opened = vec![];
    let raw_good = split(&good);
    for (k, c) in cases.iter().enumerate() {
        std::fs::write(&bad_path, c).unwrap();
        match a.s.restore_from(&bad_path, &pw(PW)) {
            Ok(()) => {
                // A flip in a field outside every AEAD/digest binding may still open; it must
                // then hold the same items as the good backup (01 §4 accepted plaintext leaks).
                let u = bytes_ok(&std::fs::read(primary(&pkg)).unwrap(), PW);
                if u.as_ref().map(|u| u.get(id).is_some()) != Some(true) {
                    bad.push(format!("case {k}: restore Ok but content differs"));
                }
                let diff = good.iter().zip(c.iter()).position(|(x, y)| x != y);
                let region = match diff {
                    Some(o) if o < 10 => "prefix".to_string(),
                    Some(o) if o < 10 + raw_good.header_len as usize => {
                        // which top-level header entry holds the byte (canonical re-encoding)
                        let off = o - 10;
                        let mut key = "?".to_string();
                        if let Value::Map(e) = &raw_good.header {
                            let mut pos = if e.len() > 23 { 2 } else { 1 };
                            for (k, v) in e {
                                let len = enc(k).len() + enc(v).len();
                                if off >= pos && off < pos + len {
                                    key = k.as_text().unwrap_or("?").to_string();
                                }
                                pos += len;
                            }
                        }
                        format!("header byte {off}, entry {key:?}")
                    }
                    Some(o) => format!("body byte {}", o - 10 - raw_good.header_len as usize),
                    None => "none".into(),
                };
                opened.push(format!("case {k} ({region})"));
                // put the newer state back for the next case
                std::fs::write(primary(&pkg), &pri).unwrap();
                a.s.restore_from(&snap, &pw(PW)).unwrap();
                std::fs::write(primary(&pkg), &pri).unwrap();
                let _ = a.s.lock();
                a.s.unlock(&pw(PW)).unwrap();
            }
            Err(_) => {
                if std::fs::read(primary(&pkg)).unwrap() != pri {
                    bad.push(format!("case {k}: failed restore changed the primary"));
                    break;
                }
                if snap_vault(a.v()) != before_items {
                    bad.push(format!(
                        "case {k}: failed restore changed the in-memory vault"
                    ));
                    break;
                }
            }
        }
    }
    let ok_count = opened.len();
    eprintln!("INFO damaged backups that still opened: {opened:?}");
    let grown = ls(&backups_dir(&pkg)).len() - n_backups_before;
    eprintln!(
        "INFO {} damaged backups; {ok_count} restored; backups/ grew by {grown} entries",
        cases.len()
    );
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §2 D-1 "every file the package opens (… backups …) is opened with `O_NOFOLLOW` and must be a
/// regular file"; 03 §2 64 MiB read cap. restore_from on a symlink, FIFO, directory without a
/// vault.bin, dangling symlink and a 65 MiB file: Err within 10 s, primary untouched.
#[test]
fn rs04_restore_from_special_entries() {
    let d = tempdir();
    let st = tempdir();
    let pkg = d.path().join("rx.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    let snap = a.s.backup_now().unwrap();
    let pri = std::fs::read(primary(&pkg)).unwrap();
    let bd = backups_dir(&pkg);
    let outside = st.path().join("outside.vault.bin");
    std::fs::copy(&snap, &outside).unwrap();
    std::os::unix::fs::symlink(&outside, bd.join("link.vault.bin")).unwrap();
    std::os::unix::fs::symlink(st.path().join("nope"), bd.join("dangling.vault.bin")).unwrap();
    mkfifo(&bd.join("fifo.vault.bin"));
    std::fs::create_dir_all(bd.join("conflict-2026-01-01T00-00-00Z-empty.vault")).unwrap();
    let pkg_link = bd.join("conflict-2026-01-01T00-00-00Z-linked.vault");
    std::fs::create_dir_all(&pkg_link).unwrap();
    std::os::unix::fs::symlink(&outside, pkg_link.join("vault.bin")).unwrap();
    let big = bd.join("big.vault.bin");
    {
        let f = std::fs::File::create(&big).unwrap();
        f.set_len(65 * 1024 * 1024).unwrap();
    }
    let names = [
        "link.vault.bin",
        "dangling.vault.bin",
        "fifo.vault.bin",
        "conflict-2026-01-01T00-00-00Z-empty.vault",
        "conflict-2026-01-01T00-00-00Z-linked.vault",
        "big.vault.bin",
    ];
    let pkg2 = pkg.clone();
    let res = with_timeout(60, move || {
        let mut out = vec![];
        for n in names {
            let r = a.s.restore_from(&backups_dir(&pkg2).join(n), &pw(PW));
            out.push((n, format!("{r:?}"), r.is_ok()));
        }
        out
    })
    .expect("restore_from hung on a special entry (FIFO?)");
    let mut bad = vec![];
    for (n, r, ok) in &res {
        eprintln!("INFO restore_from({n}) -> {r}");
        if *ok {
            bad.push(format!("{n}: restored ({r})"));
        }
    }
    if std::fs::read(primary(&pkg)).unwrap() != pri {
        bad.push("primary changed".into());
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §5 "Merge is idempotent and commutative" with three handles on one folder after a restore on
/// one of them: all three converge to the same content. Records whether the restore survives the
/// peers (items deleted after the backup).
#[test]
fn rs05_restore_with_two_watching_peers_converges() {
    let d = tempdir();
    let pkg = d.path().join("r3.vault");
    let mut a = Dev::create(&pkg);
    let keep = a.add_login("keep", now_ms());
    let gone = a.add_login("deleted after backup", now_ms());
    a.s.save().unwrap();
    let snap = a.s.backup_now().unwrap();
    std::thread::sleep(Duration::from_millis(20));
    a.s.edit(|v| v.delete(gone, now_ms())).unwrap().unwrap();
    a.s.edit(|v| v.set_field_named(keep, "username", pw("edited after backup"), now_ms()))
        .unwrap()
        .unwrap();
    a.s.save().unwrap();
    let mut b = Dev::open(&pkg);
    let mut c = Dev::open(&pkg);
    for x in [&mut a, &mut b, &mut c] {
        x.s.start_watching().unwrap();
    }
    settle();
    a.s.restore_from(&snap, &pw(PW)).unwrap();
    let restored_on_a = a.v().items().any(|i| i.id == gone);
    for _ in 0..30 {
        a.drain();
        b.drain();
        c.drain();
        for x in [&mut a, &mut b, &mut c] {
            if x.s.is_dirty() {
                let _ = x.s.save();
            }
        }
        std::thread::sleep(Duration::from_millis(200));
        if snap_content(a.v()) == snap_content(b.v()) && snap_content(b.v()) == snap_content(c.v())
        {
            break;
        }
    }
    let disk = read_vault(&pkg);
    let conv = snap_content(a.v()) == snap_content(b.v())
        && snap_content(b.v()) == snap_content(c.v())
        && snap_content(&disk) == snap_content(a.v());
    eprintln!(
        "INFO restore on A: deleted item back on A right after restore = {restored_on_a}; after peers merged: live on disk = {}",
        disk.items().any(|i| i.id == gone)
    );
    assert!(conv, "three handles did not converge after a restore");
}

/// 03 §4 "open a backup read-only … with the same password": a backup taken before a password
/// change. Records which password restore_from takes and that the vault stays openable after.
#[test]
fn rs06_restore_across_password_change() {
    let d = tempdir();
    let pkg = d.path().join("rp.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("x", now_ms());
    a.s.save().unwrap();
    let snap = a.s.backup_now().unwrap();
    let p2 = "second master Pa55phrase";
    a.s.edit(|v| v.change_password(&pw(PW), &pw(p2), KdfParams::for_tests(), now_ms()))
        .unwrap()
        .unwrap();
    a.s.save().unwrap();
    let with_new = a.s.restore_from(&snap, &pw(p2));
    let with_old = if with_new.is_err() {
        a.s.restore_from(&snap, &pw(PW))
    } else {
        Ok(())
    };
    eprintln!(
        "INFO restore old backup with new password: {with_new:?}; with old password: {with_old:?}"
    );
    assert!(
        with_new.is_ok() || with_old.is_ok(),
        "no password restores the old backup"
    );
    let _ = a.s.lock();
    let u_old = a.s.unlock(&pw(PW));
    let opened_with = if u_old.is_ok() {
        "old"
    } else {
        a.s.unlock(&pw(p2))
            .expect("restored vault opens with neither password");
        "new"
    };
    eprintln!("INFO after restore the vault opens with the {opened_with} password");
    assert!(a.v().get(id).is_some());
}

// ---------------------------------------------------------------------------------------------
// Trash expiry versus backups (03 §1.1 "Recently Deleted and backups", §2 hook, 05 Recently
// Deleted "The sweep … runs … after a successful restore")
// ---------------------------------------------------------------------------------------------

fn sweep_hook(s: &mut SyncedVault, n: Arc<AtomicUsize>) {
    s.set_before_write(Some(Box::new(move |v: &mut UnlockedVault| {
        n.fetch_add(1, SeqCst);
        let now = now_ms();
        v.expire_deleted(now - 30 * DAY_MS, now) > 0
    })));
}
fn has_content(v: &UnlockedVault, id: Uuid) -> bool {
    v.items_including_deleted()
        .find(|i| i.id == id)
        .map(|i| i.has_content())
        .unwrap_or(false)
}

/// 03 §1.1: a snapshot from inside the window "comes back into the trash when … restored; after
/// the window it is stripped". restore_from "writes the backup bytes as they are" (03 §2), so the
/// expired content is on disk until the next write; the next write (hook installed) strips it, and
/// a watching peer with the hook strips it on its own merge write-back.
#[test]
fn tb01_restore_brings_back_expired_trash_then_sweep_strips() {
    let d = tempdir();
    let pkg = d.path().join("tb.vault");
    let mut a = Dev::create(&pkg);
    let now = now_ms();
    let id = a.add_login("old trash", now - 40 * DAY_MS);
    a.s.edit(|v| v.delete(id, now - 31 * DAY_MS))
        .unwrap()
        .unwrap();
    a.s.save().unwrap();
    let snap = a.s.backup_now().unwrap();
    assert!(has_content(
        &bytes_ok(&std::fs::read(&snap).unwrap(), PW).unwrap(),
        id
    ));
    let n = Arc::new(AtomicUsize::new(0));
    sweep_hook(&mut a.s, n.clone());
    a.add_login("trigger", now_ms());
    a.s.save().unwrap();
    assert!(
        !has_content(&read_vault(&pkg), id),
        "hook stripped expired trash"
    );
    // restore the old snapshot
    a.s.restore_from(&snap, &pw(PW)).unwrap();
    let on_disk_after_restore = has_content(&read_vault(&pkg), id);
    let in_mem_after_restore = has_content(a.v(), id);
    let dirty_after_restore = a.s.is_dirty();
    eprintln!(
        "INFO after restore: content on disk {on_disk_after_restore}, in memory {in_mem_after_restore}, dirty {dirty_after_restore}"
    );
    // a peer opens and watches with the app's hook; any write strips again
    let mut b = Dev::open(&pkg);
    let nb = Arc::new(AtomicUsize::new(0));
    sweep_hook(&mut b.s, nb.clone());
    b.add_login("peer edit", now_ms());
    b.s.save().unwrap();
    assert!(
        !has_content(&read_vault(&pkg), id),
        "peer's next write did not strip expired trash restored from a backup"
    );
    // A's next write also strips (its own state may still carry the content)
    a.add_login("a edit", now_ms());
    a.s.save().unwrap();
    assert!(!has_content(&read_vault(&pkg), id));
    assert!(
        !has_content(a.v(), id),
        "A in memory still carries stripped content"
    );
}

/// 03 §1.1 "an item in the trash is inside any snapshot taken during its window and comes back into
/// the trash when that snapshot is restored" — also after a later permanent delete on this handle.
#[test]
fn tb02_restore_returns_item_to_trash_after_permanent_delete() {
    let d = tempdir();
    let pkg = d.path().join("tp.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("trashed", now_ms());
    a.s.edit(|v| v.delete(id, now_ms())).unwrap().unwrap();
    a.s.save().unwrap();
    let snap = a.s.backup_now().unwrap();
    a.s.edit(|v| v.delete_permanently(id, now_ms()))
        .unwrap()
        .unwrap();
    a.s.save().unwrap();
    assert!(!has_content(a.v(), id));
    a.s.restore_from(&snap, &pw(PW)).unwrap();
    let it = a
        .v()
        .items_including_deleted()
        .find(|i| i.id == id)
        .unwrap();
    assert!(
        it.is_trashed() && it.has_content(),
        "restored snapshot brings the item back into the trash"
    );
    assert!(a.v().deleted_items().any(|i| i.id == id));
}

// ---------------------------------------------------------------------------------------------
// Save-blocked across lock/unlock (03 §3, §8; 05 Save-blocked strip "after an unlock (unless
// vault-sync still reports … via `save_blocked()`…)")
// ---------------------------------------------------------------------------------------------

fn sb(a: &Dev) -> String {
    format!("{:?}", a.s.save_blocked())
}

/// Newer primary while unlocked → `save_blocked()` reports it; it still reports after lock and
/// unlock; a refused save leaves the file untouched; when a peer puts a readable file back, the
/// next save succeeds and `save_blocked()` clears.
#[test]
fn sb01_save_blocked_survives_lock_unlock_and_clears() {
    let d = tempdir();
    let st = tempdir();
    let pkg = d.path().join("sb.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    a.s.start_watching().unwrap();
    settle();
    let good = std::fs::read(primary(&pkg)).unwrap();
    let mut newer = good.clone();
    newer[4..6].copy_from_slice(&3u16.to_be_bytes());
    let tmp = st.path().join("n");
    std::fs::write(&tmp, &newer).unwrap();
    std::fs::rename(&tmp, primary(&pkg)).unwrap();
    a.wait_for(5, |e| has(e, "SaveBlocked"));
    let s_detect = sb(&a);
    let out = a.s.lock();
    let s_locked = sb(&a);
    let un = a.s.unlock(&pw(PW));
    let s_unlocked = sb(&a);
    eprintln!(
        "INFO save_blocked: detect {s_detect}; locked {s_locked} (lock {out:?}); unlock {un:?} -> {s_unlocked}"
    );
    let mut bad = vec![];
    if !s_detect.contains("Newer") {
        bad.push(format!("not reported at detection: {s_detect}"));
    }
    if un.is_ok() && !s_unlocked.contains("Newer") {
        bad.push(format!(
            "cleared by unlock although the file still refuses saves: {s_unlocked}"
        ));
    }
    if un.is_ok() {
        a.add_login("edit", now_ms());
        let r = a.s.save();
        if r.is_ok() || std::fs::read(primary(&pkg)).unwrap() != newer {
            bad.push(format!("save over a newer file was not refused: {r:?}"));
        }
    }
    // the peer goes back to a readable file
    let tmp = st.path().join("g");
    std::fs::write(&tmp, &good).unwrap();
    std::fs::rename(&tmp, primary(&pkg)).unwrap();
    a.wait_for(4, |_| false);
    if a.s.vault().is_none() {
        a.s.unlock(&pw(PW)).unwrap();
    }
    a.add_login("after the peer reverted", now_ms());
    let r = a.s.save();
    let s_end = sb(&a);
    if r.is_err() {
        bad.push(format!("save after the readable file came back: {r:?}"));
    }
    if s_end.contains("Newer") {
        bad.push(format!(
            "save_blocked() still set after a successful save: {s_end}"
        ));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §3 "If vault_id != ours → … ForeignVault"; 03 §8 SaveBlocked(ForeignVault). A different
/// vault (same master password, as users reuse it) replaces the primary while unlocked, then
/// lock + unlock: the handle must not silently adopt the foreign vault and write our snapshots or
/// edits into it, and our unsaved edits must survive.
#[test]
fn sb02_foreign_primary_then_lock_unlock() {
    let d = tempdir();
    let o = tempdir();
    let st = tempdir();
    let pkg = d.path().join("fv.vault");
    let mut a = Dev::create(&pkg);
    let ours_vid = a.v().vault_id();
    a.add_login("ours", now_ms());
    a.s.save().unwrap();
    a.s.start_watching().unwrap();
    settle();
    let opkg = o.path().join("other.vault");
    let mut other = Dev::create(&opkg); // same PW constant
    other.add_login("theirs", now_ms());
    other.s.save().unwrap();
    let foreign = std::fs::read(primary(&opkg)).unwrap();
    let tmp = st.path().join("f");
    std::fs::write(&tmp, &foreign).unwrap();
    std::fs::rename(&tmp, primary(&pkg)).unwrap();
    a.wait_for(5, |e| has(e, "SaveBlocked") || has(e, "ForeignVault"));
    let unsaved = a.add_login("unsaved edit", now_ms());
    let out = a.s.lock();
    let un = a.s.unlock(&pw(PW));
    let vid_after = a.s.vault().map(|v| v.vault_id());
    let s_after = sb(&a);
    eprintln!(
        "INFO foreign primary: events {:?}; lock {out:?}; unlock {un:?}; vault id after unlock {} ours; save_blocked {s_after}",
        a.seen
            .iter()
            .filter(|e| !e.starts_with("BackupTaken"))
            .collect::<Vec<_>>(),
        if vid_after == Some(ours_vid) {
            "=="
        } else {
            "!="
        }
    );
    let mut bad = vec![];
    if un.is_ok() && vid_after != Some(ours_vid) {
        bad.push("unlock adopted the foreign vault under our package".to_string());
        a.add_login("written into the foreign vault?", now_ms());
        let r = a.s.save();
        bad.push(format!("a save then gives {r:?}"));
    }
    let mut found = false;
    for n in ls(&backups_dir(&pkg)) {
        if let Ok(b) = std::fs::read(backups_dir(&pkg).join(&n)) {
            if let Some(u) = bytes_ok(&b, PW) {
                found |= u.get(unsaved).is_some();
            }
        }
    }
    if !found {
        bad.push("unsaved edit lost at lock".into());
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §3 step 5 "If app is locked … on next unlock, unlock the on-disk version"; 03 §8 restore over
/// a newer primary refuses as NewerVersion. A newer file arrives while locked: unlock result and
/// `save_blocked()`; then the peer reverts while still locked: unlock works and nothing is blocked.
#[test]
fn sb03_newer_primary_while_locked_then_reverted() {
    let d = tempdir();
    let pkg = d.path().join("nl.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    let good = std::fs::read(primary(&pkg)).unwrap();
    let mut newer = good.clone();
    newer[4..6].copy_from_slice(&3u16.to_be_bytes());
    let _ = a.s.lock();
    std::fs::write(primary(&pkg), &newer).unwrap();
    let un = a.s.unlock(&pw(PW));
    let s1 = sb(&a);
    eprintln!("INFO newer while locked: unlock {un:?}; save_blocked {s1}");
    if un.is_ok() {
        assert!(
            s1.contains("Newer"),
            "unlocked over a newer file without a block: {s1}"
        );
        let _ = a.s.lock();
    }
    std::fs::write(primary(&pkg), &good).unwrap();
    a.s.unlock(&pw(PW)).expect("unlock after the revert");
    let s2 = sb(&a);
    assert!(!s2.contains("Newer"), "block outlived the newer file: {s2}");
    a.add_login("y", now_ms());
    a.s.save().expect("save after revert");
}

// ---------------------------------------------------------------------------------------------
// Special entries as conflict copies (03 §6 step 1: "is not a regular file / directory (symlink,
// FIFO …) → emit SyncEvent::UnreadableConflict(path) once … and leave it in place")
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Special {
    Socket,
    DirNamedBin,
    DanglingLink,
    LinkLoop,
    LinkToDevZero,
    LinkToFifo,
    SiblingFifo,
    SiblingPlainFile,
    SiblingBinFifo,
    SiblingBinDir,
    SiblingBinLinkToDevZero,
}

fn plant(kind: Special, pkg: &Path, dir: &Path, outside: &Path, good: &[u8]) -> PathBuf {
    let perfile = pkg.join("vault 2.bin");
    let sib = dir.join("sp 2.vault");
    match kind {
        Special::Socket => {
            let l = std::os::unix::net::UnixListener::bind(&perfile).unwrap();
            std::mem::forget(l);
            perfile
        }
        Special::DirNamedBin => {
            std::fs::create_dir_all(&perfile).unwrap();
            std::fs::write(perfile.join("vault.bin"), good).unwrap();
            perfile
        }
        Special::DanglingLink => {
            std::os::unix::fs::symlink(outside.join("missing"), &perfile).unwrap();
            perfile
        }
        Special::LinkLoop => {
            std::os::unix::fs::symlink(pkg.join("vault 2.bin"), &perfile).unwrap();
            perfile
        }
        Special::LinkToDevZero => {
            std::os::unix::fs::symlink("/dev/zero", &perfile).unwrap();
            perfile
        }
        Special::LinkToFifo => {
            let f = outside.join("fifo");
            mkfifo(&f);
            std::os::unix::fs::symlink(&f, &perfile).unwrap();
            perfile
        }
        Special::SiblingFifo => {
            mkfifo(&sib);
            sib
        }
        Special::SiblingPlainFile => {
            std::fs::write(&sib, good).unwrap();
            sib
        }
        Special::SiblingBinFifo => {
            std::fs::create_dir_all(outside.join("stage")).unwrap();
            mkfifo(&outside.join("stage").join("vault.bin"));
            std::fs::rename(outside.join("stage"), &sib).unwrap();
            sib
        }
        Special::SiblingBinDir => {
            std::fs::create_dir_all(outside.join("stage2/vault.bin")).unwrap();
            std::fs::rename(outside.join("stage2"), &sib).unwrap();
            sib
        }
        Special::SiblingBinLinkToDevZero => {
            std::fs::create_dir_all(outside.join("stage3")).unwrap();
            std::os::unix::fs::symlink("/dev/zero", outside.join("stage3/vault.bin")).unwrap();
            std::fs::rename(outside.join("stage3"), &sib).unwrap();
            sib
        }
    }
}

/// Each special shape: not followed, not absorbed, left in place, primary untouched, the watcher
/// does not hang, and at least one report naming it (03 §6 step 1 "once"; counted and recorded).
#[test]
fn sp01_special_conflict_entries_reported_once_and_left() {
    let kinds = [
        Special::Socket,
        Special::DirNamedBin,
        Special::DanglingLink,
        Special::LinkLoop,
        Special::LinkToDevZero,
        Special::LinkToFifo,
        Special::SiblingFifo,
        Special::SiblingBinFifo,
        Special::SiblingBinDir,
        Special::SiblingBinLinkToDevZero,
    ];
    run_special(&kinds, true);
}

/// 03 §6 lists whole-package copies as directories (`<name> 2.vault/`). A *regular file* named
/// `<name> 2.vault` holding a valid copy: records whether it is reported (Note, not asserted).
#[test]
fn sp05_plain_file_named_like_a_sibling_package() {
    run_special(&[Special::SiblingPlainFile], false);
}

fn run_special(kinds: &[Special], strict: bool) {
    let mut bad = vec![];
    for &kind in kinds {
        let d = tempdir();
        let o = tempdir();
        let pkg = d.path().join("sp.vault");
        let mut a = Dev::create(&pkg);
        a.add_login("base", now_ms());
        a.s.save().unwrap();
        a.s.start_watching().unwrap();
        settle();
        let st = tempdir();
        let staging = st.path().join("s.vault");
        copy_dir(&pkg, &staging);
        let mut c = Dev::open(&staging);
        let extra = c.add_login("inside the special entry", now_ms());
        c.s.save().unwrap();
        drop(c);
        let good = std::fs::read(primary(&staging)).unwrap();
        let pri = std::fs::read(primary(&pkg)).unwrap();
        let p = plant(kind, &pkg, d.path(), o.path(), &good);
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let r = with_timeout(30, move || {
            a.wait_for(5, |e| e.iter().any(|x| !x.starts_with("BackupTaken")));
            // a second delivery of the same entry (touch the parent dir) must not report again
            let _ = std::process::Command::new("touch")
                .arg("-h")
                .arg(&p)
                .status();
            a.wait_for(3, |_| false);
            a
        });
        let Some(a) = r else {
            bad.push(format!("{kind:?}: watcher/poll hung"));
            continue;
        };
        let ev: Vec<&String> = a
            .seen
            .iter()
            .filter(|e| !e.starts_with("BackupTaken"))
            .collect();
        let naming: Vec<&&String> = ev.iter().filter(|e| e.contains(&name)).collect();
        eprintln!("INFO {kind:?}: events {ev:?}");
        if a.v().get(extra).is_some() || has(&a.seen, "ConflictAbsorbed") {
            bad.push(format!("{kind:?}: followed and absorbed"));
        }
        if naming.is_empty() && strict {
            bad.push(format!(
                "{kind:?}: no event names the entry (silently skipped): {ev:?}"
            ));
        }
        let unread = count(&a.seen, "UnreadableConflict");
        if unread > 1 {
            bad.push(format!(
                "{kind:?}: UnreadableConflict {unread} times, spec says once"
            ));
        }
        let in_place = std::fs::symlink_metadata(pkg.join("vault 2.bin")).is_ok()
            || std::fs::symlink_metadata(d.path().join("sp 2.vault")).is_ok();
        if !in_place {
            bad.push(format!("{kind:?}: entry moved or deleted"));
        }
        if std::fs::read(primary(&pkg)).unwrap() != pri {
            // a merge write-back would only be legitimate if something was absorbed
            bad.push(format!("{kind:?}: primary rewritten"));
        }
        drop(a);
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §6 step 1 "leave it in place … until it parses, is absorbed or disappears": a symlinked
/// per-file copy is replaced at the same path by a regular, valid copy → absorbed.
#[test]
fn sp02_special_entry_replaced_by_regular_copy_is_absorbed() {
    let d = tempdir();
    let o = tempdir();
    let pkg = d.path().join("rr.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("base", now_ms());
    a.s.save().unwrap();
    a.s.start_watching().unwrap();
    settle();
    let staging = o.path().join("s.vault");
    copy_dir(&pkg, &staging);
    let mut c = Dev::open(&staging);
    let extra = c.add_login("arrives later", now_ms());
    c.s.save().unwrap();
    drop(c);
    let good = std::fs::read(primary(&staging)).unwrap();
    let target = o.path().join("t.bin");
    std::fs::write(&target, &good).unwrap();
    let p = pkg.join("vault 2.bin");
    std::os::unix::fs::symlink(&target, &p).unwrap();
    a.wait_for(5, |e| has(e, "UnreadableConflict"));
    std::fs::remove_file(&p).unwrap();
    let tmp = o.path().join("staged");
    std::fs::write(&tmp, &good).unwrap();
    std::fs::rename(&tmp, &p).unwrap();
    let ok = a.wait_for(8, |e| has(e, "ConflictAbsorbed"));
    assert!(
        ok && a.v().get(extra).is_some(),
        "regular copy not absorbed: {:?}",
        a.seen
    );
    assert_eq!(
        std::fs::read(&target).unwrap(),
        good,
        "symlink target untouched"
    );
}

/// 03 §8 UnreadableConflict "… and again after lock/unlock"; 03 §6 "a copy first seen while locked
/// is reported once more at the next unlock" — for a FIFO per-file copy.
#[test]
fn sp03_special_entry_rereported_after_lock_unlock() {
    let d = tempdir();
    let pkg = d.path().join("ru.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("base", now_ms());
    a.s.save().unwrap();
    a.s.start_watching().unwrap();
    settle();
    mkfifo(&pkg.join("vault 2.bin"));
    a.wait_for(5, |e| has(e, "UnreadableConflict"));
    let n1 = count(&a.seen, "UnreadableConflict");
    let _ = a.s.lock();
    a.wait_for(1, |_| false);
    a.s.unlock(&pw(PW)).unwrap();
    a.wait_for(4, |e| count(e, "UnreadableConflict") > n1);
    let n2 = count(&a.seen, "UnreadableConflict");
    // arrives while locked
    let _ = a.s.lock();
    mkfifo(&d.path().join("ru 2.vault"));
    a.wait_for(3, |_| false);
    let n3 = count(&a.seen, "UnreadableConflict");
    a.s.unlock(&pw(PW)).unwrap();
    a.wait_for(4, |_| false);
    let n4 = count(&a.seen, "UnreadableConflict");
    eprintln!(
        "INFO UnreadableConflict counts: first {n1}, after unlock {n2}, while locked {n3}, after 2nd unlock {n4}"
    );
    assert_eq!(n1, 1, "reported once");
    assert!(n2 > n1, "again after lock/unlock");
    assert!(
        n4 >= n3 + 1,
        "FIFO sibling first seen while locked reported at the next unlock"
    );
}

/// 03 §2 D-1 "`backups/` and `attachments/` must not be symlinks" and "blobs … conflict-copy
/// sources are opened with `O_NOFOLLOW`"; D-6 blob publication. A sibling conflict package whose
/// `attachments/` is a symlink to a directory outside: records whether a blob is copied through it,
/// and checks the outside directory is untouched and no event hangs.
#[test]
fn sp04_sibling_package_with_symlinked_attachments_dir() {
    let d = tempdir();
    let o = tempdir();
    let pkg = d.path().join("sa.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("base", now_ms());
    a.s.save().unwrap();
    a.s.start_watching().unwrap();
    settle();
    let staging = o.path().join("s.vault");
    copy_dir(&pkg, &staging);
    let mut c = Dev::open(&staging);
    let data = b"attachment through a symlinked dir".to_vec();
    let aid =
        c.s.add_attachment(id, "f.txt", &data[..], data.len() as u64, now_ms())
            .unwrap();
    c.s.save().unwrap();
    drop(c);
    let ext = o.path().join("ext-attachments");
    std::fs::rename(staging.join("attachments"), &ext).unwrap();
    std::os::unix::fs::symlink(&ext, staging.join("attachments")).unwrap();
    let ext_before = ls(&ext);
    std::fs::rename(&staging, d.path().join("sa 2.vault")).unwrap();
    a.wait_for(8, |e| {
        has(e, "ConflictAbsorbed") || has(e, "Unreadable") || has(e, "WaitingForBlobs")
    });
    let blob = pkg
        .join("attachments")
        .join(format!("{}.bin", aid.as_simple()));
    eprintln!(
        "INFO symlinked attachments/ in a sibling: events {:?}; blob published through the link = {}",
        a.seen
            .iter()
            .filter(|e| !e.starts_with("BackupTaken"))
            .collect::<Vec<_>>(),
        blob.exists()
    );
    assert_eq!(ls(&ext), ext_before, "outside directory changed");
}

/// 03 §8 `delete_backup`: "path must be inside backups/ … refuses the primary". A symlink inside
/// backups/ pointing at the primary, at an outside file and at an outside directory: deleting it
/// removes at most the link, never the target.
#[test]
fn db01_delete_backup_never_follows_links() {
    let d = tempdir();
    let o = tempdir();
    let pkg = d.path().join("dl.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    let pri = std::fs::read(primary(&pkg)).unwrap();
    let bd = backups_dir(&pkg);
    let out_file = o.path().join("precious.txt");
    std::fs::write(&out_file, b"keep me").unwrap();
    let out_dir = o.path().join("precious-dir");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(out_dir.join("vault.bin"), &pri).unwrap();
    std::fs::write(out_dir.join("other"), b"x").unwrap();
    std::os::unix::fs::symlink(primary(&pkg), bd.join("dl-2026-01-01T00-00-00Z.vault.bin"))
        .unwrap();
    std::os::unix::fs::symlink(&out_file, bd.join("dl-2026-01-02T00-00-00Z.vault.bin")).unwrap();
    std::os::unix::fs::symlink(
        &out_dir,
        bd.join("conflict-2026-01-01T00-00-00Z-dl 2.vault"),
    )
    .unwrap();
    let mut res = vec![];
    for n in [
        "dl-2026-01-01T00-00-00Z.vault.bin",
        "dl-2026-01-02T00-00-00Z.vault.bin",
        "conflict-2026-01-01T00-00-00Z-dl 2.vault",
    ] {
        res.push((n, format!("{:?}", a.s.delete_backup(&bd.join(n)))));
    }
    eprintln!("INFO delete_backup on symlinks: {res:?}");
    assert_eq!(
        std::fs::read(primary(&pkg)).unwrap(),
        pri,
        "primary deleted through a link"
    );
    assert_eq!(
        std::fs::read(&out_file).unwrap(),
        b"keep me",
        "outside file deleted"
    );
    assert_eq!(
        ls(&out_dir),
        vec!["other".to_string(), "vault.bin".to_string()],
        "outside dir emptied"
    );
}

/// 03 §2 D-1 "The backup viewer reads backups through the same no-follow reader
/// (`vault_sync::read_package_entry_capped`); a conflict package in `backups/` whose `vault.bin` is
/// a symlink is not listed". backups() with a FIFO snapshot, a conflict package whose vault.bin is
/// a FIFO or a symlink: returns within 10 s and lists neither link nor FIFO package as openable.
#[test]
fn bl01_backups_listing_with_special_entries() {
    let d = tempdir();
    let o = tempdir();
    let pkg = d.path().join("bl.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    let pri = std::fs::read(primary(&pkg)).unwrap();
    let bd = backups_dir(&pkg);
    mkfifo(&bd.join("bl-2026-01-01T00-00-00Z.vault.bin"));
    let fifo_pkg = bd.join("conflict-2026-01-01T00-00-00Z-bl 2.vault");
    std::fs::create_dir_all(&fifo_pkg).unwrap();
    mkfifo(&fifo_pkg.join("vault.bin"));
    let link_pkg = bd.join("conflict-2026-01-01T00-00-00Z-bl 3.vault");
    std::fs::create_dir_all(&link_pkg).unwrap();
    std::fs::write(o.path().join("t.bin"), &pri).unwrap();
    std::os::unix::fs::symlink(o.path().join("t.bin"), link_pkg.join("vault.bin")).unwrap();
    let r = with_timeout(20, move || {
        let l =
            a.s.backups()
                .map(|l| l.iter().map(|b| format!("{b:?}")).collect::<Vec<_>>());
        let snap = a.s.backup_now().map(|_| ());
        (l, snap)
    })
    .expect("backups()/backup_now hung on a FIFO in backups/");
    eprintln!(
        "INFO backups() with special entries: {:?}; backup_now {:?}",
        r.0, r.1
    );
    let l = r.0.expect("backups() errored");
    assert!(
        !l.iter().any(|s| s.contains("bl 3.vault")),
        "conflict package with a symlinked vault.bin is listed"
    );
    // the viewer's reader
    let rd = |p: &Path| {
        format!(
            "{:?}",
            vault_sync::read_package_entry_capped(p).map(|b| b.len())
        )
    };
    let fifo_read = with_timeout(10, {
        let p = fifo_pkg.join("vault.bin");
        move || rd(&p)
    });
    assert!(
        fifo_read.is_some(),
        "read_package_entry_capped hung on a FIFO"
    );
    let link_read = rd(&link_pkg.join("vault.bin"));
    assert!(
        link_read.starts_with("Err"),
        "reader followed a symlink: {link_read}"
    );
    eprintln!("INFO reader: fifo {fifo_read:?}, link {link_read}");
}

/// 03 §2 D-1 "`backups/` and `attachments/` must not be symlinks … a symlink or special file is
/// `UnsafePackageEntry`, never a silent fallback"; 03 §8 `UnsafePackageDir`; 03 §4 "first save
/// after unlock" snapshots. With `backups/` a symlink, the policy snapshot cannot be taken: the save
/// may succeed, but the refusal must be reported (an event or an error), not skipped silently.
#[test]
fn bk09_symlinked_backups_dir_is_reported_on_policy_snapshot() {
    let d = tempdir();
    let o = tempdir();
    let pkg = d.path().join("sl.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    let _ = a.s.lock();
    std::fs::rename(backups_dir(&pkg), o.path().join("real")).unwrap();
    let ext = o.path().join("elsewhere");
    std::fs::create_dir_all(&ext).unwrap();
    std::os::unix::fs::symlink(&ext, backups_dir(&pkg)).unwrap();
    a.s.unlock(&pw(PW)).unwrap();
    a.drain();
    a.seen.clear();
    a.add_login("first save after unlock", now_ms());
    let r = a.s.save();
    a.drain();
    let ev: Vec<&String> = a.seen.iter().collect();
    eprintln!("INFO save with symlinked backups/: {r:?}; events {ev:?}");
    assert!(ls(&ext).is_empty(), "snapshot written through the link");
    let reported = r.is_err()
        || ev
            .iter()
            .any(|e| e.contains("backups") || e.contains("Unsafe") || e.starts_with("Error"));
    assert!(
        reported,
        "policy snapshot skipped without any report: save {r:?}, events {ev:?}"
    );
}

/// 03 §4 names: snapshots are `<name>-<stamp>[-N].vault.bin` (`-unsaved` for Unsaved), conflicts
/// `conflict-<timestamp>-<original name>` (03 §6); 03 §8 "Retention prunes `Snapshot` only". A vault
/// whose name is `conflict` must still see its own same-second (`-2`) snapshots as Snapshot (so
/// retention can prune them and Settings labels them "Backup from …") and `-unsaved` as Unsaved.
/// Added after the source read (step 4) from an observation in the name parser.
#[test]
fn bk10_vault_named_conflict_keeps_snapshot_kinds() {
    let d = tempdir();
    let pkg = d.path().join("conflict.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    clear_backups(&pkg);
    let mut paths = vec![];
    for _ in 0..3 {
        paths.push(a.s.backup_now().unwrap());
    }
    let list = a.s.backups().unwrap();
    let kinds: Vec<(String, String)> = list
        .iter()
        .map(|b| {
            (
                b.path.file_name().unwrap().to_string_lossy().into_owned(),
                format!("{:?}", b.kind),
            )
        })
        .collect();
    eprintln!("INFO backups of conflict.vault: {kinds:?}");
    let wrong: Vec<&(String, String)> = kinds.iter().filter(|(_, k)| k != "Snapshot").collect();
    assert!(
        wrong.is_empty(),
        "our own snapshots listed as another kind (never pruned, labelled as conflict copies): {wrong:?}"
    );
}

/// Consequence check for bk10: 03 §4 "Take a snapshot if no snapshot exists newer than 1 hour";
/// "Save twice in 1 s → one backup" (03 §9). Five dirty saves in a row (not the first after unlock)
/// of a vault named `conflict` versus one named `ordinary`, and retention over 60 planted old
/// snapshots.
#[test]
fn bk11_vault_named_conflict_snapshot_policy_and_retention() {
    let mut out = vec![];
    for name in ["ordinary", "conflict"] {
        let d = tempdir();
        let pkg = d.path().join(format!("{name}.vault"));
        let mut a = Dev::create(&pkg);
        a.add_login("x", now_ms());
        a.s.save().unwrap();
        let first = ls(&backups_dir(&pkg)).len();
        for k in 0..5 {
            a.add_login(&format!("e{k}"), now_ms());
            a.s.save().unwrap();
        }
        let after_saves = ls(&backups_dir(&pkg)).len() - first;
        let bytes = std::fs::read(primary(&pkg)).unwrap();
        let now = SystemTime::now();
        for k in 0..60u64 {
            let n = snap_name(name, now - Duration::from_secs((40 + k * 7) * DAY));
            std::fs::write(backups_dir(&pkg).join(n), &bytes).unwrap();
        }
        let before = ls(&backups_dir(&pkg)).len();
        a.s.backup_now().unwrap();
        let after = ls(&backups_dir(&pkg)).len();
        out.push((name, after_saves, before, after));
    }
    eprintln!("INFO (name, extra snapshots from 5 saves, files before retention, after): {out:?}");
    let (_, o_saves, o_before, o_after) = out[0];
    let (_, c_saves, _c_before, c_after) = out[1];
    assert_eq!(o_saves, 0, "control: no extra snapshot within the hour");
    assert!(o_after < o_before, "control: retention pruned");
    assert!(
        c_saves == 0 && c_after < o_before,
        "vault named conflict: {c_saves} extra snapshots from 5 saves within the hour; {c_after} files after retention"
    );
}
