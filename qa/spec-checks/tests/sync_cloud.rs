//! 03 §2 step 6 / §3 step 1-2 (V-05) and 03 §7 CloudHooks.
use secrecy::ExposeSecret;
use spec_checks::dev::*;
use spec_checks::*;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use vault_core::*;

fn val(v: &UnlockedVault, id: uuid::Uuid, name: &str) -> Option<String> {
    v.get(id)?
        .fields
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.value.expose_secret().clone())
}
fn set_mtime(p: &Path, t: std::time::SystemTime) {
    let f = std::fs::File::options().write(true).open(p).unwrap();
    f.set_modified(t).unwrap();
}

/// V-05: an external write of the same size with the mtime forced back to ours must still be
/// noticed (03 §2 step 6 records mtime, ctime, inode, size, blake3).
#[test]
fn v01_same_size_forged_mtime_detected() {
    for in_place in [false, true] {
        let d = tempdir();
        let pkg = d.path().join("ss.vault");
        let mut a = Dev::create(&pkg);
        let id = a.add_login("x", now_ms());
        a.s.edit(|v| v.set_field_named(id, "username", pw("AAAA"), now_ms()))
            .unwrap()
            .unwrap();
        a.s.save().unwrap();
        let mtime = std::fs::metadata(primary(&pkg))
            .unwrap()
            .modified()
            .unwrap();
        let size = std::fs::metadata(primary(&pkg)).unwrap().len();
        a.s.start_watching().unwrap();
        std::thread::sleep(Duration::from_millis(700));
        // B writes a same-length value; the file length stays the same
        let mut b = Dev::open(&pkg);
        b.s.edit(|v| v.set_field_named(id, "username", pw("BBBB"), now_ms() + 5))
            .unwrap()
            .unwrap();
        let bytes = b.v().serialize();
        drop(b);
        assert_eq!(bytes.len() as u64, size, "test setup: same size");
        if in_place {
            std::fs::write(primary(&pkg), &bytes).unwrap(); // same inode, truncate+write
        } else {
            let tmp = pkg.join("ext.tmp");
            std::fs::write(&tmp, &bytes).unwrap();
            std::fs::rename(&tmp, primary(&pkg)).unwrap();
        }
        set_mtime(&primary(&pkg), mtime);
        a.wait_for(6, |e| e.iter().any(|x| x.starts_with("Merged")));
        assert_eq!(
            val(a.v(), id, "username").as_deref(),
            Some("BBBB"),
            "in_place={in_place}: external same-size write ignored; events {:?}",
            a.seen
        );
    }
}

struct Hooks {
    evicted: Mutex<Vec<PathBuf>>,
    fail: Mutex<bool>,
    calls: Mutex<Vec<String>>,
}
impl vault_sync::CloudHooks for Hooks {
    fn is_evicted(&self, path: &Path) -> bool {
        self.calls
            .lock()
            .unwrap()
            .push(format!("is_evicted {}", path.display()));
        self.evicted.lock().unwrap().iter().any(|p| p == path)
    }
    fn ensure_downloaded(&self, path: &Path, _t: Duration) -> Result<(), vault_sync::CloudError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("ensure {}", path.display()));
        if *self.fail.lock().unwrap() {
            Err(vault_sync::CloudError::Timeout)
        } else {
            Ok(())
        }
    }
    fn pin(&self, path: &Path) {
        self.calls
            .lock()
            .unwrap()
            .push(format!("pin {}", path.display()));
    }
}

/// 03 §7: ensure_downloaded before every read of the primary; pin after first open; timeout ->
/// CloudUnavailable, nothing overwritten; 03 §1.1 evicted blob -> NotDownloaded, not an error.
#[test]
fn v02_cloud_hooks() {
    let d = tempdir();
    let pkg = d.path().join("ic.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("x", now_ms());
    let aid =
        a.s.add_attachment(item, "f", &b"data"[..], 4, now_ms())
            .unwrap();
    a.s.save().unwrap();
    drop(a);
    let h = Arc::new(Hooks {
        evicted: Mutex::new(vec![]),
        fail: Mutex::new(false),
        calls: Mutex::new(vec![]),
    });
    let mut s = vault_sync::SyncedVault::open(&pkg, uuid::Uuid::new_v4(), h.clone()).unwrap();
    let rx = s.subscribe();
    s.unlock(&pw(PW)).unwrap();
    let calls = h.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("ensure") && c.ends_with("vault.bin")),
        "ensure_downloaded before reading primary: {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c.starts_with("pin")),
        "pin after first successful open: {calls:?}"
    );
    // evicted blob
    let hexid: String = aid.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let blob = pkg.join("attachments").join(format!("{hexid}.bin"));
    h.evicted.lock().unwrap().push(blob.clone());
    *h.fail.lock().unwrap() = true;
    let st = s.attachment_state(aid);
    assert!(
        matches!(st, vault_sync::AttachmentState::NotDownloaded),
        "evicted blob -> NotDownloaded, got {st:?}"
    );
    // primary download times out during save's pre-write merge -> no overwrite, CloudUnavailable
    let before = std::fs::read(primary(&pkg)).unwrap();
    s.edit(|v| v.set_field_named(item, "username", pw("new"), now_ms()))
        .unwrap()
        .unwrap();
    let r = s.save();
    let mut evs = vec![];
    s.poll();
    while let Ok(e) = rx.try_recv() {
        evs.push(format!("{e:?}"));
    }
    assert!(
        r.is_err() || evs.iter().any(|e| e.contains("CloudUnavailable")),
        "save with an undownloadable primary: {r:?} {evs:?}"
    );
    if r.is_err() {
        assert_eq!(
            std::fs::read(primary(&pkg)).unwrap(),
            before,
            "primary untouched"
        );
    }
}
