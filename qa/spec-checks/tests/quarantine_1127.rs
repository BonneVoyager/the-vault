//! Bug hunt 2026-11-27: 03 §1.1 attachment quarantine (owner decision 2026-11-26, M-02), written
//! from the spec text before reading the source. The 24 h grace is measured from max(mtime,
//! ctime) and ctime cannot be set back from a test, so the move INTO quarantine is only checked for
//! the "not before the grace" half; the restore rules are checked in full.
use spec_checks::dev::*;
use spec_checks::*;
use std::path::{Path, PathBuf};

fn blob(pkg: &Path, id: uuid::Uuid) -> PathBuf {
    pkg.join("attachments").join(format!("{}.bin", id.simple()))
}
fn qdir(pkg: &Path) -> PathBuf {
    pkg.join("attachments").join("orphaned")
}
fn with_attachment(
    name: &str,
    data: &[u8],
) -> (tempfile::TempDir, PathBuf, Dev, uuid::Uuid, uuid::Uuid) {
    let d = tempdir();
    let pkg = d.path().join(format!("{name}.vault"));
    let mut a = Dev::create(&pkg);
    let item = a.add_login("with file", now_ms());
    let att =
        a.s.add_attachment(
            item,
            "file.txt",
            std::io::Cursor::new(data.to_vec()),
            data.len() as u64,
            now_ms(),
        )
        .unwrap();
    a.s.save().unwrap();
    (d, pkg, a, item, att)
}
fn read_att(a: &Dev, item: uuid::Uuid, att: uuid::Uuid) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut r = a.s.open_attachment(item, att).ok()?;
    let mut v = vec![];
    r.read_to_end(&mut v).ok()?;
    Some(v)
}
fn quarantine(pkg: &Path, att: uuid::Uuid, suffix: &str) -> Vec<u8> {
    let q = qdir(pkg);
    std::fs::create_dir_all(&q).unwrap();
    let bytes = std::fs::read(blob(pkg, att)).unwrap();
    std::fs::rename(
        blob(pkg, att),
        q.join(format!("{}.bin{suffix}", att.simple())),
    )
    .unwrap();
    bytes
}

/// 03 §1.1 Restore: "a quarantined blob whose id the unlocked vault references ... is moved back
/// ... after every unlock ..., and by `attachment_state` / `open_attachment` before they would
/// report the blob missing."
#[test]
fn qa01_restore_on_unlock_state_and_open() {
    let data = b"attachment payload 1127".repeat(1000);
    let mut bad = vec![];
    // after unlock
    {
        let (_d, pkg, mut a, item, att) = with_attachment("q1", &data);
        let sealed = quarantine(&pkg, att, "");
        let _ = a.s.lock();
        a.s.unlock(&pw(PW)).unwrap();
        if std::fs::read(blob(&pkg, att)).ok() != Some(sealed) {
            bad.push(format!(
                "not restored at unlock: attachments {:?} orphaned {:?}",
                ls(&pkg.join("attachments")),
                ls(&qdir(&pkg))
            ));
        }
        if read_att(&a, item, att).as_deref() != Some(&data[..]) {
            bad.push("content after unlock restore".into());
        }
    }
    // by attachment_state, without a lock cycle
    {
        let (_d, pkg, a, _item, att) = with_attachment("q2", &data);
        quarantine(&pkg, att, "");
        let s = a.s.attachment_state(att);
        if format!("{s:?}") != "Present" || !blob(&pkg, att).exists() {
            bad.push(format!("attachment_state did not restore: {s:?}"));
        }
    }
    // by open_attachment
    {
        let (_d, pkg, a, item, att) = with_attachment("q3", &data);
        quarantine(&pkg, att, "");
        if read_att(&a, item, att).as_deref() != Some(&data[..]) || !blob(&pkg, att).exists() {
            bad.push("open_attachment did not restore and stream the blob".into());
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §1.1: "Per id the lowest copy number whose size equals the sealed length implied by the
/// reference is taken; a wrong-sized copy is never restored"; "a blob already in `attachments/`
/// wins and the quarantined copy expires".
#[test]
fn qa02_copy_selection_and_existing_blob_wins() {
    let data = b"second payload".repeat(5000);
    let mut bad = vec![];
    {
        let (_d, pkg, a, item, att) = with_attachment("q4", &data);
        let sealed = quarantine(&pkg, att, ".2");
        let q = qdir(&pkg);
        let h = att.simple().to_string();
        std::fs::write(q.join(format!("{h}.bin")), &sealed[..sealed.len() - 1]).unwrap();
        let mut long = sealed.clone();
        long.push(0);
        std::fs::write(q.join(format!("{h}.bin.1")), &long).unwrap();
        let mut forged = sealed.clone();
        forged[100] ^= 1;
        std::fs::write(q.join(format!("{h}.bin.3")), &forged).unwrap();
        let s = a.s.attachment_state(att);
        let restored = std::fs::read(blob(&pkg, att)).ok();
        if restored.as_deref() != Some(&sealed[..]) {
            bad.push(format!(
                "selection: state {s:?}, restored {} (want the .2 copy); orphaned now {:?}",
                match &restored {
                    None => "nothing".to_string(),
                    Some(r) if r == &forged => ".3 (forged)".into(),
                    Some(r) => format!("{} bytes", r.len()),
                },
                ls(&q)
            ));
        }
        if read_att(&a, item, att).as_deref() != Some(&data[..]) {
            bad.push("content after selection".into());
        }
    }
    {
        let (_d, pkg, a, item, att) = with_attachment("q5", &data);
        let sealed = std::fs::read(blob(&pkg, att)).unwrap();
        let q = qdir(&pkg);
        std::fs::create_dir_all(&q).unwrap();
        let mut forged = sealed.clone();
        forged[100] ^= 1;
        std::fs::write(q.join(format!("{}.bin", att.simple())), &forged).unwrap();
        let _ = a.s.attachment_state(att);
        let _ = read_att(&a, item, att);
        if std::fs::read(blob(&pkg, att)).unwrap() != sealed {
            bad.push("a quarantined copy replaced the blob in attachments/".into());
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §1.1: "a symlinked `orphaned/` is refused and nothing is moved".
#[test]
fn qa03_symlinked_orphaned_dir() {
    let data = b"third".repeat(100);
    let (d, pkg, mut a, _item, att) = with_attachment("q6", &data);
    let elsewhere = d.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let sealed = std::fs::read(blob(&pkg, att)).unwrap();
    std::fs::remove_file(blob(&pkg, att)).unwrap();
    std::fs::write(elsewhere.join(format!("{}.bin", att.simple())), &sealed).unwrap();
    std::os::unix::fs::symlink(&elsewhere, qdir(&pkg)).unwrap();
    let s = a.s.attachment_state(att);
    let _ = a.s.lock();
    a.s.unlock(&pw(PW)).unwrap();
    let mut bad = vec![];
    if !elsewhere.join(format!("{}.bin", att.simple())).exists() {
        bad.push("a blob was moved out of the symlinked orphaned/ target".into());
    }
    if blob(&pkg, att).exists() {
        bad.push(format!(
            "restored through a symlinked orphaned/ (state {s:?})"
        ));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §1.1: an orphan "is moved into quarantine ... once it has been present locally for more
/// than 24 h": a just-written unreferenced blob stays in `attachments/` through saves and an
/// unlock-time pass. Also: "Cleanup never deletes a blob from `attachments/`".
#[test]
fn qa04_fresh_orphan_stays() {
    let data = b"orphan".repeat(10);
    let (_d, pkg, mut a, item, att) = with_attachment("q7", &data);
    a.s.remove_attachment(item, att, now_ms()).unwrap();
    a.s.save().unwrap();
    let _ = a.s.lock();
    a.s.unlock(&pw(PW)).unwrap();
    a.add_login("another", now_ms());
    a.s.save().unwrap();
    assert!(
        blob(&pkg, att).exists(),
        "fresh orphan moved or deleted; attachments {:?}",
        ls(&pkg.join("attachments"))
    );
}
