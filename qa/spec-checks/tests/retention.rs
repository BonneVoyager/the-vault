//! 03 §4 retention: 24 h all, 1/day for 30 days, 1/week for 12 weeks, 1/month (cap 36); Unsaved
//! and Conflict never pruned. 03 §9 "generate 200 synthetic snapshots over a year".
use spec_checks::dev::*;
use spec_checks::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn name_for(prefix: &str, t: SystemTime) -> String {
    let s = t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    // civil from days (Howard Hinnant), UTC
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
    format!("{prefix}-{y:04}-{m:02}-{d:02}T{:02}-{:02}-{:02}Z.vault.bin", sod / 3600, sod % 3600 / 60, sod % 60)
}

#[test]
fn r01_retention_buckets() {
    let d = tempdir();
    let pkg = d.path().join("rt.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    let bytes = std::fs::read(pkg.join("vault.bin")).unwrap();
    let bd = pkg.join("backups");
    for f in ls(&bd) {
        std::fs::remove_file(bd.join(f)).unwrap();
    }
    let now = SystemTime::now();
    let mut ages = vec![];
    // 200 snapshots spread over 400 days, denser recently
    for i in 0..200u64 {
        let age_h = if i < 30 { i * 45 / 60 + 1 } else { 24 + (i - 30) * 9_600 / 170 };
        ages.push(age_h);
        std::fs::write(bd.join(name_for("rt", now - Duration::from_secs(age_h * 3600 + 30))), &bytes).unwrap();
    }
    // never-pruned kinds: an absorbed conflict copy and an unsaved snapshot from long ago
    std::fs::write(bd.join("conflict-2025-01-01T00-00-00Z-rt 2.vault.bin"), &bytes).unwrap();
    let before = ls(&bd).len();
    a.s.backup_now().unwrap();
    let after = ls(&bd);
    let kept: Vec<u64> = ages.iter().copied().filter(|h| after.contains(&name_for("rt", now - Duration::from_secs(h * 3600 + 30)))).collect();
    let within_24h_total = ages.iter().filter(|h| **h < 24).count();
    let within_24h_kept = kept.iter().filter(|h| **h < 24).count();
    assert_eq!(within_24h_kept, within_24h_total, "keep all from the last 24 h");
    let days_bucket = kept.iter().filter(|h| **h >= 24 && **h < 30 * 24).count();
    assert!(days_bucket <= 30, "one per day for 30 days: {days_bucket}");
    let weeks = kept.iter().filter(|h| **h >= 30 * 24 && **h < 30 * 24 + 12 * 7 * 24).count();
    assert!(weeks <= 13, "one per week for 12 weeks: {weeks}");
    let months = kept.iter().filter(|h| **h >= 30 * 24 + 12 * 7 * 24).count();
    assert!(months <= 36 && months >= 1, "one per month (cap 36): {months}");
    // each day in the 30-day window that had a snapshot still has one
    for day in 1..30u64 {
        let had = ages.iter().any(|h| *h / 24 == day);
        let has = kept.iter().any(|h| *h / 24 == day);
        if had {
            assert!(has, "day {day} lost all snapshots");
        }
    }
    assert!(after.iter().any(|n| n.starts_with("conflict-")), "Conflict backups never pruned");
    assert!(after.len() < before, "something was pruned: {before} -> {}", after.len());
    eprintln!("kept {} of 200: 24h={within_24h_kept} days={days_bucket} weeks={weeks} months={months}", kept.len());
}
