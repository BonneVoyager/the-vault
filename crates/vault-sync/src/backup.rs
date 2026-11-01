//! Snapshots and retention (03 §1, §4).
//!
//! Snapshots live in `<name>.vault/backups/` as `<name>-<YYYY-MM-DDTHH-MM-SSZ>.vault.bin`
//! (UTC), copies of the package's `vault.bin`. Two snapshots in the same second get `-2`,
//! `-3`, ... before `.vault.bin`. Conflict absorptions (03 §6) move the whole conflicted
//! package into the same directory as `conflict-<timestamp>-<original name>/`; they are listed
//! but never rotated. Any other entry there is ignored and never deleted.

use std::cmp::Reverse;
use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::atomic::{Mode, rename_no_replace, write_atomic_stat};
use crate::error::SyncError;
use crate::package::{self, backups_dir, ensure_dir, file_name, vault_name};

const HOUR: u64 = 3600;
const DAY: u64 = 24 * HOUR;
const WEEK: u64 = 7 * DAY;

/// A snapshot is taken on save when the newest existing one is older than this (03 §4).
pub(crate) const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(HOUR);

/// Retention multiplier bounds and default (03 §4 "Settings").
pub const RETENTION_MULTIPLIER_MIN: f32 = 0.5;
pub const RETENTION_MULTIPLIER_MAX: f32 = 4.0;
pub const RETENTION_MULTIPLIER_DEFAULT: f32 = 1.0;

/// Length of `YYYY-MM-DDTHH-MM-SSZ`.
const STAMP_LEN: usize = 20;
const CONFLICT_PREFIX: &str = "conflict-";
/// Extension of a snapshot file (a copy of the package's `vault.bin`).
const SNAPSHOT_EXT: &str = ".vault.bin";

/// One entry in the backups directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupInfo {
    /// A `.vault.bin` snapshot file, or the directory of an absorbed conflict package (pass
    /// either to `restore_from`).
    pub path: PathBuf,
    /// Parsed from the file name (second precision), not from filesystem metadata.
    pub taken_at: SystemTime,
    /// File size; for a conflict package, the size of its `vault.bin` (0 if absent).
    pub size: u64,
    /// Orders files that share a `taken_at` second: the `-N` file-name suffix for snapshots
    /// (1 when absent), 0 for conflict copies (03 §6).
    pub seq: u32,
    pub kind: BackupKind,
}

/// What a file in the backups directory holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupKind {
    /// `<name>-<timestamp>[-N].vault.bin`: bytes that were on disk (03 §4).
    Snapshot,
    /// `<name>-<timestamp>-unsaved[-N].vault.bin`: state that would otherwise be lost and is never
    /// pruned. Either the in-memory vault, preserved when it locked while saving was
    /// impossible (opens with that session's password), or the raw bytes of an unparseable
    /// primary, kept before `restore_from` replaced it (may not open at all).
    Unsaved,
    /// `conflict-<timestamp>-<original name>/`: an absorbed conflicted package (03 §6).
    Conflict,
}

impl BackupInfo {
    /// A `conflict-<timestamp>-<orig>` package rather than one of our own snapshots.
    pub fn is_conflict(&self) -> bool {
        self.kind == BackupKind::Conflict
    }

    fn order_key(&self) -> Reverse<(SystemTime, u32)> {
        Reverse((self.taken_at, self.seq))
    }
}

/// Clamp to `0.5..=4.0`; NaN becomes the default.
pub(crate) fn clamp_multiplier(m: f32) -> f32 {
    if m.is_nan() {
        RETENTION_MULTIPLIER_DEFAULT
    } else {
        m.clamp(RETENTION_MULTIPLIER_MIN, RETENTION_MULTIPLIER_MAX)
    }
}

// ---------------------------------------------------------------------------------------------
// Timestamps

/// Whole seconds since the epoch, floored (so pre-1970 instants stay monotonic).
fn unix_secs(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => {
            let d = e.duration();
            -(d.as_secs() as i64) - i64::from(d.subsec_nanos() > 0)
        }
    }
}

fn from_unix_secs(s: i64) -> SystemTime {
    if s >= 0 {
        UNIX_EPOCH + Duration::from_secs(s as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(s.unsigned_abs())
    }
}

/// Days since 1970-01-01 to proleptic Gregorian `(year, month, day)` (H. Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Inverse of [`civil_from_days`].
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYY-MM-DDTHH-MM-SSZ` in UTC, sub-seconds dropped. Lexicographic order equals time order
/// for years 0000-9999.
pub(crate) fn format_stamp(t: SystemTime) -> String {
    let secs = unix_secs(t);
    let (y, mo, d) = civil_from_days(secs.div_euclid(DAY as i64));
    let sod = secs.rem_euclid(DAY as i64);
    let (h, mi, s) = (sod / 3600, sod % 3600 / 60, sod % 60);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}-{mi:02}-{s:02}Z")
}

/// Inverse of [`format_stamp`]; `None` unless `s` is exactly a valid stamp.
pub(crate) fn parse_stamp(s: &str) -> Option<SystemTime> {
    let b = s.as_bytes();
    if b.len() != STAMP_LEN {
        return None;
    }
    for (i, &c) in b.iter().enumerate() {
        let ok = match i {
            4 | 7 | 13 | 16 => c == b'-',
            10 => c == b'T',
            19 => c == b'Z',
            _ => c.is_ascii_digit(),
        };
        if !ok {
            return None;
        }
    }
    let num = |r: std::ops::Range<usize>| s[r].parse::<u32>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || d == 0 || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    let days = days_from_civil(i64::from(y), mo, d);
    // Rejects day-of-month overflow such as 02-30, which days_from_civil silently normalises.
    if civil_from_days(days) != (i64::from(y), mo, d) {
        return None;
    }
    let secs = days * DAY as i64 + i64::from(h * 3600 + mi * 60 + sec);
    Some(from_unix_secs(secs))
}

// ---------------------------------------------------------------------------------------------
// Names and paths

const UNSAVED_TAG: &str = "-unsaved";

fn snapshot_file_name(name: &str, stamp: &str, kind: BackupKind, seq: u32) -> String {
    let tag = if kind == BackupKind::Unsaved {
        UNSAVED_TAG
    } else {
        ""
    };
    if seq <= 1 {
        format!("{name}-{stamp}{tag}{SNAPSHOT_EXT}")
    } else {
        format!("{name}-{stamp}{tag}-{seq}{SNAPSHOT_EXT}")
    }
}

/// `(taken_at, same-second sequence, kind)` for a file we manage, `None` for anything else.
/// `file` and `name` are compared in NFC: a provider may deliver either in NFD.
fn parse_file_name(file: &str, name: &str) -> Option<(SystemTime, u32, BackupKind)> {
    let (file, name) = (package::nfc(file), package::nfc(name));
    let (file, name) = (file.as_ref(), name.as_ref());
    if let Some(rest) = file.strip_prefix(CONFLICT_PREFIX) {
        let stamp = rest.get(..STAMP_LEN)?;
        let orig = rest.get(STAMP_LEN..)?.strip_prefix('-')?;
        if !orig.is_empty()
            && let Some(t) = parse_stamp(stamp)
        {
            return Some((t, 0, BackupKind::Conflict));
        }
    }
    let rest = file
        .strip_prefix(name)?
        .strip_prefix('-')?
        .strip_suffix(SNAPSHOT_EXT)?;
    let t = parse_stamp(rest.get(..STAMP_LEN)?)?;
    let tail = rest.get(STAMP_LEN..)?;
    let (kind, tail) = match tail.strip_prefix(UNSAVED_TAG) {
        Some(t) => (BackupKind::Unsaved, t),
        None => (BackupKind::Snapshot, tail),
    };
    let (t, seq) = parse_seq(t, tail)?;
    Some((t, seq, kind))
}

/// `""` is sequence 1; `-N` is N.
fn parse_seq(t: SystemTime, tail: &str) -> Option<(SystemTime, u32)> {
    match tail {
        "" => Some((t, 1)),
        tail => {
            let digits = tail.strip_prefix('-')?;
            if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            Some((t, digits.parse().ok()?))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Retention

/// Split `infos` into `(keep, delete)` per 03 §4, both newest first.
///
/// Tiers are by age (`now - taken_at`), each scaled by `multiplier` (clamped to 0.5-4.0):
/// everything younger than 24 h; the newest per UTC calendar day younger than 30 d; the
/// newest per Monday-based UTC week younger than 12 w; the newest per UTC calendar month
/// beyond that, for the newest `round(36 × multiplier)` months. Calendar buckets (rather than
/// buckets relative to `now`) keep the decision stable from one run to the next. Each tier
/// buckets only its own files. The newest snapshot is always kept. Future-dated files count
/// as age zero.
///
/// Only [`BackupKind::Snapshot`] files rotate. [`BackupKind::Unsaved`] files (possibly the only
/// copy of edits that could not be saved) and [`BackupKind::Conflict`] copies (03 §6: never
/// delete a conflict copy) are always kept; they are user-managed, with no automatic pruning
/// or cap.
pub fn retain(
    infos: &[BackupInfo],
    now: SystemTime,
    multiplier: f32,
) -> (Vec<BackupInfo>, Vec<BackupInfo>) {
    let m = f64::from(clamp_multiplier(multiplier));
    let recent = DAY as f64 * m;
    let daily = 30.0 * DAY as f64 * m;
    let weekly = 12.0 * WEEK as f64 * m;
    let month_cap = (36.0 * m).round() as usize;

    let mut sorted: Vec<&BackupInfo> = infos.iter().collect();
    sorted.sort_by_key(|a| a.order_key());

    let (mut days, mut weeks, mut months) = (HashSet::new(), HashSet::new(), HashSet::new());
    let (mut keep, mut delete) = (Vec::new(), Vec::new());
    let (user_managed, snapshots): (Vec<&BackupInfo>, Vec<&BackupInfo>) = sorted
        .into_iter()
        .partition(|i| i.kind != BackupKind::Snapshot);
    keep.extend(user_managed.into_iter().cloned());
    for (i, info) in snapshots.into_iter().enumerate() {
        let age = now
            .duration_since(info.taken_at)
            .map_or(0.0, |d| d.as_secs_f64());
        let day = unix_secs(info.taken_at).div_euclid(DAY as i64);
        let tier_keeps = if age < recent {
            true
        } else if age < daily {
            days.insert(day)
        } else if age < weekly {
            // 1970-01-01 was a Thursday; +3 makes buckets start on Monday.
            weeks.insert((day + 3).div_euclid(7))
        } else {
            let (y, mo, _) = civil_from_days(day);
            let month = y * 12 + i64::from(mo);
            !months.contains(&month) && months.len() < month_cap && months.insert(month)
        };
        if i == 0 || tier_keeps {
            keep.push(info.clone());
        } else {
            delete.push(info.clone());
        }
    }
    keep.sort_by_key(BackupInfo::order_key);
    (keep, delete)
}

// ---------------------------------------------------------------------------------------------
// Files

/// Every snapshot and conflict package of the vault package at `package`, newest first. A
/// missing backups directory is an empty list; a symlinked one is
/// [`SyncError::UnsafePackageDir`].
pub(crate) fn list_backups(package: &Path) -> Result<Vec<BackupInfo>, SyncError> {
    let dir = backups_dir(package);
    let name = vault_name(package);
    // Never list (and so never let retention delete in) a symlinked `backups/`.
    if !package::check_dir(&dir)? {
        return Ok(Vec::new());
    }
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(SyncError::io(&dir, e)),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| SyncError::io(&dir, e))?;
        let file = entry.file_name();
        let Some(file) = file.to_str() else { continue };
        let Some((taken_at, seq, kind)) = parse_file_name(file, &name) else {
            continue;
        };
        let meta = match entry.metadata() {
            Ok(m) => m,
            // Raced with a deletion (another device's retention, say).
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => return Err(SyncError::io(entry.path(), e)),
        };
        let size = if meta.is_file() {
            meta.len()
        } else if meta.is_dir() && kind == BackupKind::Conflict {
            fs::metadata(package::vault_file(&entry.path())).map_or(0, |m| m.len())
        } else {
            continue;
        };
        out.push(BackupInfo {
            path: entry.path(),
            taken_at,
            size,
            seq,
            kind,
        });
    }
    out.sort_by_key(BackupInfo::order_key);
    Ok(out)
}

/// Atomically write `bytes` as a new snapshot taken at `now`; never overwrites an existing
/// file (same-second collisions get the next `-N`). Returns the path and the directory fsync
/// outcome: an inner `Err` means the file IS there but not confirmed durable.
pub(crate) fn write_snapshot(
    package: &Path,
    bytes: &[u8],
    now: SystemTime,
    kind: BackupKind,
) -> Result<(PathBuf, Result<(), SyncError>), SyncError> {
    let dir = backups_dir(package);
    ensure_dir(&dir)?;
    let name = vault_name(package);
    let stamp = format_stamp(now);
    for seq in 1..=1000 {
        let path = dir.join(snapshot_file_name(&name, &stamp, kind, seq));
        match write_atomic_stat(&path, bytes, Mode::NoReplace) {
            Ok(written) => {
                tracing::info!(path = %path.display(), size = bytes.len(), "took backup");
                return Ok((path, written.dir_sync));
            }
            Err(SyncError::AlreadyExists(_)) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(SyncError::AlreadyExists(
        dir.join(snapshot_file_name(&name, &stamp, kind, 1)),
    ))
}

/// Run [`retain`] over the backups directory and delete what it rejects, except `protect`
/// (the snapshot just written). Individual delete failures are logged and skipped.
pub(crate) fn apply_retention(
    package: &Path,
    now: SystemTime,
    multiplier: f32,
    protect: &Path,
) -> Result<usize, SyncError> {
    let infos = list_backups(package)?;
    let (_, delete) = retain(&infos, now, multiplier);
    let mut deleted = 0;
    for info in delete.iter().filter(|i| i.path != protect) {
        match fs::remove_file(&info.path) {
            Ok(()) => deleted += 1,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(path = %info.path.display(), error = %e, "could not delete old backup");
            }
        }
    }
    if deleted > 0 {
        tracing::debug!(deleted, "backup retention");
    }
    Ok(deleted)
}

/// Move a whole conflicted package into the backups directory as `conflict-<timestamp>-<original
/// name>/` (03 §6 step 4); never deletes it. Returns the new path.
pub(crate) fn absorb_conflict_package(
    package: &Path,
    src: &Path,
    now: SystemTime,
) -> Result<PathBuf, SyncError> {
    move_conflict(package, src, &file_name(src), now)
}

/// Move a per-file conflicted copy of `vault.bin` (`<pkg>/vault 2.bin`, ...) into the backups
/// directory as `conflict-<timestamp>-<original stem>.vault.bin` (03 §6 step 4), so it lists
/// and restores like a snapshot file. Returns the new path.
pub(crate) fn absorb_conflict_file(
    package: &Path,
    src: &Path,
    now: SystemTime,
) -> Result<PathBuf, SyncError> {
    let orig = file_name(src);
    let stem = match orig.len().checked_sub(".bin".len()) {
        Some(i) if i > 0 && orig.is_char_boundary(i) && orig[i..].eq_ignore_ascii_case(".bin") => {
            &orig[..i]
        }
        _ => orig.as_str(),
    };
    move_conflict(package, src, &format!("{stem}{SNAPSHOT_EXT}"), now)
}

/// Rename `src` to `backups/conflict-<stamp>-<target>`; never deletes it. A name clash in the
/// same second inserts `-N-` after the timestamp.
fn move_conflict(
    package: &Path,
    src: &Path,
    target: &str,
    now: SystemTime,
) -> Result<PathBuf, SyncError> {
    let dir = backups_dir(package);
    ensure_dir(&dir)?;
    let stamp = format_stamp(now);
    for n in 1..=1000 {
        let dst = if n == 1 {
            dir.join(format!("{CONFLICT_PREFIX}{stamp}-{target}"))
        } else {
            dir.join(format!("{CONFLICT_PREFIX}{stamp}-{n}-{target}"))
        };
        // Same filesystem (a sibling of our package, or a file inside it). Atomic and never
        // replacing: a name taken meanwhile (another device absorbing too) moves on to `-N-`.
        match rename_no_replace(src, &dst) {
            Ok(()) => {}
            Err(SyncError::AlreadyExists(_)) => continue,
            Err(e) => return Err(e),
        }
        tracing::info!(from = %src.display(), to = %dst.display(), "absorbed conflicted copy");
        return Ok(dst);
    }
    Err(SyncError::AlreadyExists(
        dir.join(format!("{CONFLICT_PREFIX}{stamp}-{target}")),
    ))
}

/// 03 §4 snapshot policy.
pub(crate) fn should_snapshot(
    newest: Option<SystemTime>,
    now: SystemTime,
    item_count_decreased: bool,
    first_save_after_unlock: bool,
) -> bool {
    let stale = match newest {
        None => true,
        // A future-dated newest snapshot (clock skew across devices) does not suppress ours.
        Some(t) => now
            .duration_since(t)
            .map_or(true, |age| age >= SNAPSHOT_INTERVAL),
    };
    stale || item_count_decreased || first_save_after_unlock
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> SystemTime {
        from_unix_secs(secs)
    }

    #[test]
    fn stamp_known_instants_round_trip() {
        for (secs, s) in [
            (0, "1970-01-01T00-00-00Z"),
            (951_868_799, "2000-02-29T23-59-59Z"),
            (1_793_196_191, "2026-10-28T14-03-11Z"),
            (1_793_275_200, "2026-10-29T12-00-00Z"),
            (-1, "1969-12-31T23-59-59Z"),
        ] {
            assert_eq!(format_stamp(at(secs)), s);
            assert_eq!(parse_stamp(s), Some(at(secs)), "{s}");
        }
        // Sub-seconds are dropped.
        assert_eq!(
            format_stamp(at(1_793_196_191) + Duration::from_millis(999)),
            "2026-10-28T14-03-11Z"
        );
    }

    #[test]
    fn stamp_rejects_malformed() {
        for s in [
            "",
            "2026-10-28T14-03-11",
            "2026-10-28T14:03:11Z",
            "2026-13-01T00-00-00Z",
            "2026-02-29T00-00-00Z",
            "2026-04-31T00-00-00Z",
            "2026-10-28T24-00-00Z",
            "2026-10-28T14-60-00Z",
            "2026-10-28t14-03-11Z",
            "+026-10-28T14-03-11Z",
        ] {
            assert_eq!(parse_stamp(s), None, "{s}");
        }
    }

    #[test]
    fn stamp_order_is_time_order() {
        let mut times: Vec<i64> = (0..500)
            .map(|i: i64| (i * 7_919_993 + i * i * 104_729) % 4_000_000_000)
            .collect();
        let mut stamps: Vec<String> = times.iter().map(|&s| format_stamp(at(s))).collect();
        times.sort_unstable();
        stamps.sort();
        let expected: Vec<String> = times.iter().map(|&s| format_stamp(at(s))).collect();
        assert_eq!(stamps, expected);
    }

    #[test]
    fn civil_days_round_trip() {
        for z in (-800_000..800_000).step_by(37) {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
    }

    #[test]
    fn file_names_parse_in_either_normalisation_form() {
        let t = at(1_793_196_191);
        let (nfc, nfd) = ("\u{c4}rzte", "A\u{308}rzte");
        for (file_name, vault) in [(nfc, nfd), (nfd, nfc), (nfd, nfd)] {
            let f = format!("{file_name}-2026-10-28T14-03-11Z-unsaved-2.vault.bin");
            assert_eq!(
                parse_file_name(&f, vault),
                Some((t, 2, BackupKind::Unsaved)),
                "{f}"
            );
        }
        let conflict = format!("conflict-2026-10-28T14-03-11Z-{nfd} 2.vault");
        assert_eq!(
            parse_file_name(&conflict, nfc),
            Some((t, 0, BackupKind::Conflict))
        );
        // More than a normalisation difference: not ours.
        assert_eq!(
            parse_file_name("Arzte-2026-10-28T14-03-11Z.vault.bin", nfc),
            None
        );
    }

    #[test]
    fn file_names_parse() {
        let t = at(1_793_196_191);
        assert_eq!(
            parse_file_name("test-2026-10-28T14-03-11Z.vault.bin", "test"),
            Some((t, 1, BackupKind::Snapshot))
        );
        assert_eq!(
            parse_file_name("test-2026-10-28T14-03-11Z-3.vault.bin", "test"),
            Some((t, 3, BackupKind::Snapshot))
        );
        assert_eq!(
            parse_file_name("test-2026-10-28T14-03-11Z-unsaved.vault.bin", "test"),
            Some((t, 1, BackupKind::Unsaved))
        );
        assert_eq!(
            parse_file_name("test-2026-10-28T14-03-11Z-unsaved-2.vault.bin", "test"),
            Some((t, 2, BackupKind::Unsaved))
        );
        for kind in [BackupKind::Snapshot, BackupKind::Unsaved] {
            for seq in [1, 2, 13] {
                let f = snapshot_file_name("test", "2026-10-28T14-03-11Z", kind, seq);
                assert_eq!(parse_file_name(&f, "test"), Some((t, seq, kind)), "{f}");
            }
        }
        assert_eq!(
            parse_file_name(
                "conflict-2026-10-28T14-03-11Z-test (Mac's conflicted copy).vault",
                "test"
            ),
            Some((t, 0, BackupKind::Conflict))
        );
        assert_eq!(
            parse_file_name("my-vault-2026-10-28T14-03-11Z.vault.bin", "my-vault"),
            Some((t, 1, BackupKind::Snapshot))
        );
        for bad in [
            "other-2026-10-28T14-03-11Z.vault.bin",
            "test-2026-10-28T14-03-11Z.vault.bak",
            "test-2026-10-28T14-03-11Z.vault",
            "test-2026-10-28T14-03-11Z.vault.bin.bak",
            "test-2026-10-28T14-03-11Z-.vault.bin",
            "test-2026-10-28T14-03-11Z-x.vault.bin",
            "test-2026-10-28T14-03-11Z-unsaved-.vault.bin",
            "test-2026-10-28T14-03-11Z-unsavedx.vault.bin",
            ".test-2026-10-28T14-03-11Z.vault.bin.tmp-0011aabb",
            "conflict-2026-10-28T14-03-11Z-",
            "conflict-garbage-test.vault",
            "notes.txt",
        ] {
            assert_eq!(parse_file_name(bad, "test"), None, "{bad}");
        }
    }

    #[test]
    fn snapshot_policy() {
        let now = at(1_793_275_200);
        let hour = Duration::from_secs(HOUR);
        assert!(should_snapshot(None, now, false, false));
        assert!(!should_snapshot(Some(now - hour / 2), now, false, false));
        assert!(should_snapshot(Some(now - hour), now, false, false));
        assert!(should_snapshot(Some(now - hour / 2), now, true, false));
        assert!(should_snapshot(Some(now - hour / 2), now, false, true));
        assert!(should_snapshot(Some(now + hour), now, false, false));
    }

    // ---- retention ----

    /// 2026-10-29T12:00:00Z, a Thursday.
    const NOW: i64 = 1_793_275_200;
    const H: i64 = 3600;
    const D: i64 = 24 * H;

    fn info(age_secs: i64, kind: BackupKind) -> BackupInfo {
        let taken_at = at(NOW - age_secs);
        let stamp = format_stamp(taken_at);
        let (file, seq) = match kind {
            BackupKind::Conflict => (format!("conflict-{stamp}-test (conflicted copy).vault"), 0),
            _ => (snapshot_file_name("test", &stamp, kind, 1), 1),
        };
        BackupInfo {
            path: PathBuf::from("/b").join(file),
            taken_at,
            size: 1,
            seq,
            kind,
        }
    }

    /// 200 snapshots over a year:
    /// - 48 half-hourly in the last 24 h (ages 0:15 .. 23:45),
    /// - 2 a day (11:00 and 10:00 UTC) for days 1..=29 back (58),
    /// - 1 a day (11:00) for days 30..=83 back (54),
    /// - 1 a week (Thursdays 11:00) for days 84..=357 back (40).
    fn year_of_snapshots() -> Vec<BackupInfo> {
        let mut ages = Vec::new();
        ages.extend((0..48).map(|k| 15 * 60 + k * 30 * 60));
        for d in 1..=29 {
            ages.extend([d * D + H, d * D + 2 * H]);
        }
        ages.extend((30..=83).map(|d| d * D + H));
        ages.extend((0..40).map(|k| (84 + 7 * k) * D + H));
        assert_eq!(ages.len(), 200);
        ages.iter()
            .map(|&a| info(a, BackupKind::Snapshot))
            .collect()
    }

    fn age_of(i: &BackupInfo) -> i64 {
        NOW - unix_secs(i.taken_at)
    }

    /// Kept counts by age band `[< 24h, < 30d, < 12w, older]`, with the bands scaled by `m`.
    fn kept_by_band(keep: &[BackupInfo], m: i64) -> [usize; 4] {
        let mut out = [0; 4];
        for k in keep {
            let a = age_of(k);
            let band = if a < D * m {
                0
            } else if a < 30 * D * m {
                1
            } else if a < 84 * D * m {
                2
            } else {
                3
            };
            out[band] += 1;
        }
        out
    }

    #[test]
    fn retention_buckets_at_1x() {
        let infos = year_of_snapshots();
        let (keep, delete) = retain(&infos, at(NOW), 1.0);
        assert_eq!(keep.len() + delete.len(), 200);
        // 48 recent; 29 days; weeks Aug 3 .. Sep 28 = 9; months Nov 2025 .. Aug 2026 = 10.
        assert_eq!(kept_by_band(&keep, 1), [48, 29, 9, 10]);
        assert_eq!(keep.len(), 96);
        // In the daily band the kept one is the newer (11:00) of each pair.
        for k in keep.iter().filter(|k| (D..30 * D).contains(&age_of(k))) {
            assert_eq!(age_of(k) % D, H);
        }
        // Newest first, and the newest overall is kept.
        assert!(keep.windows(2).all(|w| w[0].taken_at >= w[1].taken_at));
        assert_eq!(keep[0], *infos.iter().max_by_key(|i| i.taken_at).unwrap());
    }

    #[test]
    fn unsaved_and_conflict_files_are_never_rotated() {
        let mut infos = year_of_snapshots();
        // Each shares a bucket with a newer snapshot, or lies beyond the monthly cap.
        let extras = [
            info(40 * D + 2 * H, BackupKind::Unsaved),
            info(40 * D + 3 * H, BackupKind::Conflict),
            info(2_000 * D, BackupKind::Unsaved),
            info(2_000 * D + H, BackupKind::Conflict),
            info(5 * D + 3 * H, BackupKind::Unsaved),
            info(5 * D + 4 * H, BackupKind::Unsaved),
        ];
        infos.extend(extras.iter().cloned());
        for m in [0.5, 1.0, 4.0] {
            let (keep, delete) = retain(&infos, at(NOW), m);
            for e in &extras {
                assert!(keep.contains(e), "{:?} dropped at {m}", e.path);
            }
            assert!(delete.iter().all(|d| d.kind == BackupKind::Snapshot));
            assert!(
                keep.windows(2)
                    .all(|w| w[0].order_key() <= w[1].order_key())
            );
        }
        // Snapshot rotation is unaffected by them.
        let (keep, _) = retain(&infos, at(NOW), 1.0);
        let snapshots: Vec<_> = keep
            .into_iter()
            .filter(|k| k.kind == BackupKind::Snapshot)
            .collect();
        assert_eq!(kept_by_band(&snapshots, 1), [48, 29, 9, 10]);
        // Alone, every unsaved file survives even when they share one day.
        let (keep, delete) = retain(&extras[4..], at(NOW), 1.0);
        assert_eq!(keep.len(), 2);
        assert!(delete.is_empty());
    }

    #[test]
    fn retention_buckets_at_2x_keep_more() {
        let infos = year_of_snapshots();
        let (keep, _) = retain(&infos, at(NOW), 2.0);
        // < 48 h: 48 + both of day 1 = 50.
        // < 60 d: days 2..=59, one each = 58.
        // < 24 w: weeks of Aug 3, 10, 17, 24 from the dailies + 11 earlier Thursdays = 15.
        // older: May 2026 back to Nov 2025 = 7 months (under the 72 cap).
        assert_eq!(kept_by_band(&keep, 2), [50, 58, 15, 7]);
        assert_eq!(keep.len(), 130);
        assert!(keep.len() > retain(&infos, at(NOW), 1.0).0.len());
    }

    #[test]
    fn monthly_cap_scales_and_newest_survives() {
        // 60 monthly snapshots, all beyond the weekly window.
        let infos: Vec<_> = (0..60)
            .map(|k| info((200 + 31 * k) * D, BackupKind::Snapshot))
            .collect();
        let (keep, _) = retain(&infos, at(NOW), 0.5);
        assert_eq!(keep.len(), 18);
        assert_eq!(keep[0].taken_at, at(NOW - 200 * D));
        assert_eq!(retain(&infos, at(NOW), 1.0).0.len(), 36);
        assert_eq!(retain(&infos, at(NOW), 4.0).0.len(), 60);
    }

    #[test]
    fn same_second_tie_breaks_on_suffix() {
        // Same-second pair: the `-2` one is newer and must win the day bucket.
        let mut a = info(40 * D, BackupKind::Snapshot);
        let mut b = a.clone();
        b.path = a
            .path
            .with_file_name(format!("test-{}-2.vault.bin", format_stamp(a.taken_at)));
        b.seq = 2;
        a.size = 2;
        let (keep, delete) = retain(&[a.clone(), b.clone()], at(NOW), 1.0);
        assert_eq!(keep, vec![b]);
        assert_eq!(delete, vec![a]);
        assert!(retain(&[], at(NOW), 1.0).0.is_empty());
    }

    #[test]
    fn multiplier_is_clamped() {
        assert_eq!(clamp_multiplier(0.1), 0.5);
        assert_eq!(clamp_multiplier(9.0), 4.0);
        assert_eq!(clamp_multiplier(f32::NAN), 1.0);
        assert_eq!(clamp_multiplier(1.5), 1.5);
    }
}
