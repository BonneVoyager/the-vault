//! Attachment blobs (03 §1.1, §8 v1.1): add, stream, state, removal, orphan cleanup, peers.

use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use tempfile::TempDir;
use vault_core::attachment::{CHUNK_SIZE, MAX_ATTACHMENT_SIZE, blob_file_name};
use vault_core::{AttachmentError, Item, KdfParams, SecretString, Uuid};
use vault_sync::{
    AttachmentState, CloudError, CloudHooks, NoopHooks, SyncError, SyncEvent, SyncedVault,
};

const NOW: u64 = 1_700_000_000_000;
const DEV_A: Uuid = Uuid::from_u128(0xA);
const DEV_B: Uuid = Uuid::from_u128(0xB);
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

fn pw() -> SecretString {
    SecretString::new("correct horse battery staple".to_owned())
}

fn setup() -> (TempDir, PathBuf, SyncedVault, Uuid) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.vault");
    let mut v = SyncedVault::create(
        &path,
        &pw(),
        KdfParams::for_tests(),
        DEV_A,
        Arc::new(NoopHooks),
    )
    .unwrap();
    let item = v
        .edit(|vault| vault.insert(Item::new("mail", Uuid::nil(), NOW), NOW))
        .unwrap();
    v.save().unwrap();
    (dir, path, v, item)
}

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

fn three_chunks() -> Vec<u8> {
    data(2 * CHUNK_SIZE + 123)
}

fn add(v: &mut SyncedVault, item: Uuid, bytes: &[u8]) -> Uuid {
    v.add_attachment(item, "file.bin", bytes, bytes.len() as u64, NOW + 1)
        .unwrap()
}

fn read_all(v: &SyncedVault, item: Uuid, id: Uuid) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    v.open_attachment(item, id).unwrap().read_to_end(&mut out)?;
    Ok(out)
}

fn blob(v: &SyncedVault, id: Uuid) -> PathBuf {
    v.attachments_dir().join(blob_file_name(id))
}

fn names(dir: &Path) -> Vec<String> {
    let mut n: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    n.sort();
    n
}

fn tmp_leftovers(dir: &Path) -> Vec<String> {
    names(dir)
        .into_iter()
        .filter(|n| n.contains(".tmp-"))
        .collect()
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn age(p: &Path, by: Duration) {
    File::options()
        .write(true)
        .open(p)
        .unwrap()
        .set_modified(SystemTime::now() - by)
        .unwrap();
}

fn ref_ids(v: &SyncedVault, item: Uuid) -> Vec<Uuid> {
    v.vault()
        .unwrap()
        .get(item)
        .unwrap()
        .attachments
        .iter()
        .map(|a| a.id)
        .collect()
}

/// Make the vault dirty with an unrelated edit, so `save` writes.
fn touch(v: &mut SyncedVault, title: &str) {
    v.edit(|vault| vault.insert(Item::new(title, Uuid::nil(), NOW), NOW))
        .unwrap();
}

fn tampered_id(e: &io::Error) -> Option<Uuid> {
    match e.get_ref()?.downcast_ref::<SyncError>()? {
        SyncError::AttachmentTampered(id) => Some(*id),
        _ => None,
    }
}

/// Panics on any read: proves a refusal happened before touching the input.
struct PanicReader;
impl Read for PanicReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("input must not be read");
    }
}

/// The app opens on the main thread and decrypts on a background thread.
#[test]
fn reader_is_send_and_static() {
    fn assert_send_static<T: Read + Send + 'static>() {}
    assert_send_static::<vault_sync::AttachmentReader>();
}

#[test]
fn add_save_reopen_and_stream_identical_bytes() {
    let (dir, path, mut v, item) = setup();
    let empty = add(&mut v, item, &[]);
    let big = three_chunks();
    let three = add(&mut v, item, &big);

    assert!(v.is_dirty());
    assert_eq!(ref_ids(&v, item), vec![empty, three]);
    assert_eq!(mode(&v.attachments_dir()), 0o700);
    for id in [empty, three] {
        assert_eq!(mode(&blob(&v, id)), 0o600);
        assert_eq!(v.attachment_state(id), AttachmentState::Present);
    }
    // Blob = plaintext + one 16-byte tag per chunk.
    assert_eq!(fs::metadata(blob(&v, empty)).unwrap().len(), 16);
    assert_eq!(
        fs::metadata(blob(&v, three)).unwrap().len(),
        big.len() as u64 + 3 * 16
    );
    assert!(tmp_leftovers(&v.attachments_dir()).is_empty());

    v.save().unwrap();
    assert!(tmp_leftovers(dir.path()).is_empty());
    assert!(tmp_leftovers(&path).is_empty());

    let mut other = SyncedVault::open(&path, DEV_B, Arc::new(NoopHooks)).unwrap();
    other.unlock(&pw()).unwrap();
    assert_eq!(ref_ids(&other, item), vec![empty, three]);
    assert_eq!(read_all(&other, item, empty).unwrap(), Vec::<u8>::new());
    assert_eq!(read_all(&other, item, three).unwrap(), big);
    let reader = other.open_attachment(item, three).unwrap();
    assert_eq!((reader.id(), reader.size()), (three, big.len() as u64));

    // Small reads across chunk boundaries see the same bytes.
    let mut reader = other.open_attachment(item, three).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 7_777];
    loop {
        let n = reader.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    assert_eq!(out, big);
}

#[test]
fn size_cap_is_refused_before_reading() {
    let (_dir, _path, mut v, item) = setup();
    let err = v
        .add_attachment(item, "huge", PanicReader, MAX_ATTACHMENT_SIZE + 1, NOW)
        .unwrap_err();
    assert!(
        matches!(err, SyncError::Attachment(AttachmentError::TooLarge { .. })),
        "{err:?}"
    );
    assert!(!v.attachments_dir().exists());
    assert!(!v.is_dirty());
}

#[test]
fn unknown_item_is_refused_before_reading() {
    let (_dir, _path, mut v, _item) = setup();
    let err = v
        .add_attachment(Uuid::from_u128(99), "x", PanicReader, 3, NOW)
        .unwrap_err();
    assert!(matches!(err, SyncError::Vault(_)), "{err:?}");
    assert!(!v.attachments_dir().exists());
    assert!(!v.is_dirty());
}

#[test]
fn failed_seal_leaves_no_tmp_blob_or_ref() {
    let (_dir, _path, mut v, item) = setup();
    // Short input: 5 bytes where 10 were promised.
    let err = v
        .add_attachment(item, "short", &b"12345"[..], 10, NOW)
        .unwrap_err();
    assert!(
        matches!(
            err,
            SyncError::Attachment(AttachmentError::SizeMismatch { .. })
        ),
        "{err:?}"
    );
    // Long input fails after a full chunk was written.
    let long = data(CHUNK_SIZE + 1);
    let err = v
        .add_attachment(item, "long", &long[..], CHUNK_SIZE as u64, NOW)
        .unwrap_err();
    assert!(
        matches!(
            err,
            SyncError::Attachment(AttachmentError::SizeMismatch { .. })
        ),
        "{err:?}"
    );
    assert!(names(&v.attachments_dir()).is_empty());
    assert!(ref_ids(&v, item).is_empty());
    assert!(!v.is_dirty());
}

#[test]
fn tampered_blob_is_reported_by_the_reader() {
    let (_dir, _path, mut v, item) = setup();
    let big = three_chunks();
    let id = add(&mut v, item, &big);
    let path = blob(&v, id);
    let original = fs::read(&path).unwrap();

    // A flipped byte in the last chunk: the first two chunks stream, then the error.
    let mut bytes = original.clone();
    let last = bytes.len() - 20;
    bytes[last] ^= 1;
    fs::write(&path, &bytes).unwrap();
    let mut reader = v.open_attachment(item, id).unwrap();
    let mut out = Vec::new();
    let err = reader.read_to_end(&mut out).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(tampered_id(&err), Some(id));
    assert_eq!(out.len(), 2 * CHUNK_SIZE, "verified prefix only");
    // The error sticks.
    let again = reader.read(&mut [0u8; 16]).unwrap_err();
    assert_eq!(tampered_id(&again), Some(id));

    // First chunk flipped: nothing is handed out.
    let mut bytes = original.clone();
    bytes[0] ^= 1;
    fs::write(&path, &bytes).unwrap();
    let mut out = Vec::new();
    let err = v
        .open_attachment(item, id)
        .unwrap()
        .read_to_end(&mut out)
        .unwrap_err();
    assert_eq!(tampered_id(&err), Some(id));
    assert!(out.is_empty());

    // Truncated by one whole chunk.
    fs::write(&path, &original[..CHUNK_SIZE + 16]).unwrap();
    assert_eq!(tampered_id(&read_all(&v, item, id).unwrap_err()), Some(id));

    // Restored: reads again.
    fs::write(&path, &original).unwrap();
    assert_eq!(read_all(&v, item, id).unwrap(), big);
}

#[test]
fn missing_blob() {
    let (_dir, _path, mut v, item) = setup();
    let id = add(&mut v, item, b"hello");
    fs::remove_file(blob(&v, id)).unwrap();
    assert_eq!(v.attachment_state(id), AttachmentState::Missing);
    let err = v.open_attachment(item, id).unwrap_err();
    assert!(
        matches!(err, SyncError::AttachmentMissing(x) if x == id),
        "{err:?}"
    );
    // The item itself is unaffected.
    assert_eq!(ref_ids(&v, item), vec![id]);
}

#[test]
fn unknown_attachment_and_locked_are_errors() {
    let (_dir, _path, mut v, item) = setup();
    let id = add(&mut v, item, b"hello");
    let err = v.open_attachment(item, Uuid::from_u128(5)).unwrap_err();
    assert!(matches!(err, SyncError::Vault(_)), "{err:?}");
    v.save().unwrap();
    v.lock();
    assert!(matches!(
        v.open_attachment(item, id),
        Err(SyncError::Locked)
    ));
    assert!(matches!(
        v.add_attachment(item, "x", PanicReader, 1, NOW),
        Err(SyncError::Locked)
    ));
    assert!(matches!(
        v.remove_attachment(item, id, NOW),
        Err(SyncError::Locked)
    ));
    // State needs no key.
    assert_eq!(v.attachment_state(id), AttachmentState::Present);
}

/// Every blob is evicted and never downloads; the vault file itself is fine.
struct EvictedBlobs;
impl CloudHooks for EvictedBlobs {
    fn is_evicted(&self, path: &Path) -> bool {
        path.parent()
            .and_then(|p| p.file_name())
            .is_some_and(|n| n == "attachments")
    }
    fn ensure_downloaded(&self, path: &Path, _timeout: Duration) -> Result<(), CloudError> {
        if self.is_evicted(path) {
            Err(CloudError::Timeout)
        } else {
            Ok(())
        }
    }
    fn pin(&self, _path: &Path) {}
}

#[test]
fn evicted_blob_is_not_downloaded() {
    let (_dir, path, mut v, item) = setup();
    let id = add(&mut v, item, b"hello");
    v.save().unwrap();
    let mut other = SyncedVault::open(&path, DEV_B, Arc::new(EvictedBlobs)).unwrap();
    other.unlock(&pw()).unwrap();
    assert_eq!(other.attachment_state(id), AttachmentState::NotDownloaded);
    let err = other.open_attachment(item, id).unwrap_err();
    assert!(
        matches!(err, SyncError::AttachmentNotDownloaded(x) if x == id),
        "{err:?}"
    );
}

fn pruned_counts(events: &crossbeam_channel::Receiver<SyncEvent>) -> Vec<usize> {
    events
        .try_iter()
        .filter_map(|e| match e {
            SyncEvent::AttachmentsPruned(n) => Some(n),
            _ => None,
        })
        .collect()
}

/// Ages are simulated with the prune clock offset: they count from max(mtime, ctime), and
/// ctime cannot be set back. Backdated mtimes alone must not make anything old.
#[test]
fn orphan_cleanup_after_save() {
    let (_dir, _path, mut v, item) = setup();
    let events = v.subscribe();
    let kept_ref = add(&mut v, item, b"referenced");
    v.save().unwrap();
    let dir = v.attachments_dir();

    let orphan = dir.join(blob_file_name(Uuid::from_u128(1)));
    let tmp = dir.join(format!(
        ".{}.tmp-0000abcd",
        blob_file_name(Uuid::from_u128(3))
    ));
    let junk = dir.join("notes.txt");
    let upper = dir.join(blob_file_name(Uuid::from_u128(5)).to_uppercase());
    for p in [&orphan, &tmp, &junk, &upper] {
        fs::write(p, b"x").unwrap();
        age(p, 3 * DAY);
    }
    age(&blob(&v, kept_ref), 3 * DAY);

    // Now: everything is fresh by ctime, whatever the mtime says.
    touch(&mut v, "n0");
    v.save().unwrap();
    for p in [&orphan, &tmp] {
        assert!(p.exists(), "{} is fresh by ctime", p.display());
    }

    // Two hours on: the tmp is stale, the orphan still within its grace period.
    v.set_prune_clock_offset_for_tests(Duration::from_secs(2 * 60 * 60));
    touch(&mut v, "n1");
    v.save().unwrap();
    assert!(!tmp.exists());
    assert!(orphan.exists());
    assert!(
        pruned_counts(&events).is_empty(),
        "tmp files are not counted"
    );

    // A day on: the orphan goes; referenced blobs and foreign names stay.
    v.set_prune_clock_offset_for_tests(DAY + Duration::from_secs(60));
    touch(&mut v, "n2");
    v.save().unwrap();
    assert!(!orphan.exists());
    for p in [&junk, &upper, &blob(&v, kept_ref)] {
        assert!(p.exists(), "{} must be kept", p.display());
    }
    assert_eq!(pruned_counts(&events), vec![1]);
}

#[test]
fn prune_skips_clean_saves_and_locked_vaults() {
    let (_dir, _path, mut v, item) = setup();
    add(&mut v, item, b"x");
    v.save().unwrap();
    let orphan = v.attachments_dir().join(blob_file_name(Uuid::from_u128(1)));
    fs::write(&orphan, b"x").unwrap();
    v.set_prune_clock_offset_for_tests(2 * DAY);

    // Clean: nothing written, nothing pruned.
    assert!(!v.is_dirty());
    v.save().unwrap();
    assert!(orphan.exists());

    // Locked: save refuses and the directory is not touched.
    v.lock();
    assert!(matches!(v.save(), Err(SyncError::Locked)));
    assert!(orphan.exists());

    // Unlocking runs cleanup once (memory and disk agree).
    v.unlock(&pw()).unwrap();
    assert!(!orphan.exists());
}

#[test]
fn orphan_cleanup_runs_once_at_unlock() {
    let (_dir, path, mut v, item) = setup();
    let kept = add(&mut v, item, b"kept");
    v.save().unwrap();
    let orphan = v.attachments_dir().join(blob_file_name(Uuid::from_u128(1)));
    fs::write(&orphan, b"x").unwrap();
    v.set_prune_clock_offset_for_tests(2 * DAY);
    v.lock();
    assert!(orphan.exists(), "never while locked");

    let events = v.subscribe();
    v.unlock(&pw()).unwrap();
    assert!(!orphan.exists());
    assert!(blob(&v, kept).exists());
    assert_eq!(pruned_counts(&events), vec![1]);

    // Not when the unlocked state may not match disk: here the primary is now a newer format
    // (saving is blocked, its references are unknown).
    fs::write(&orphan, b"x").unwrap();
    v.lock();
    let file = path.join(vault_sync::VAULT_FILE_NAME);
    let mut newer = fs::read(&file).unwrap();
    newer[4..6].copy_from_slice(&0xFFFFu16.to_be_bytes());
    fs::write(&file, &newer).unwrap();
    v.unlock(&pw()).unwrap();
    assert!(orphan.exists());

    // Nor when the primary is missing: the unlock opens the copy held in memory, but what is
    // on disk (a peer's references) is unknown.
    v.lock();
    fs::remove_file(&file).unwrap();
    v.unlock(&pw()).unwrap();
    assert!(orphan.exists());
}

/// A peer's blob that lands before the vault file referencing it carries the peer's (old)
/// mtime but a fresh local ctime: it must survive saves until the grace period has run from
/// its arrival.
#[test]
fn freshly_arrived_peer_blob_with_old_mtime_is_kept() {
    let (_dir, _path, mut v, item) = setup();
    add(&mut v, item, b"ours");
    v.save().unwrap();
    let theirs = v
        .attachments_dir()
        .join(blob_file_name(Uuid::from_u128(0xFEED)));
    fs::write(&theirs, b"peer blob").unwrap();
    age(&theirs, 2 * DAY);

    touch(&mut v, "a");
    v.save().unwrap();
    assert!(theirs.exists());
    v.set_prune_clock_offset_for_tests(Duration::from_secs(23 * 60 * 60));
    touch(&mut v, "b");
    v.save().unwrap();
    assert!(theirs.exists(), "still within 24 h of arrival");
}

#[test]
fn dropping_reader_mid_stream_does_not_wedge_later_reads() {
    let (_dir, _path, mut v, item) = setup();
    let big = three_chunks();
    let first = add(&mut v, item, &big);
    let mut reader = v.open_attachment(item, first).unwrap();
    let mut buf = vec![0u8; CHUNK_SIZE];
    reader.read_exact(&mut buf).unwrap();
    assert_eq!(buf, big[..CHUNK_SIZE]);
    drop(reader);

    let second = add(&mut v, item, b"after the drop");
    assert_eq!(read_all(&v, item, second).unwrap(), b"after the drop");
    assert_eq!(read_all(&v, item, first).unwrap(), big);
}

/// Each device adds its own attachment and they save in turn: both references and both blobs
/// survive. A's first save runs while B's blob is still unreferenced on disk (B has not saved
/// yet), which the grace period covers; once both are saved, cleanup far past the grace period
/// keeps them because they are referenced.
#[test]
fn concurrent_adds_on_two_devices_both_survive() {
    let (_dir, path, mut a, item) = setup();
    let mut b = device_b(&path);

    let x = add(&mut a, item, b"from A");
    let y = add(&mut b, item, b"from B");
    a.save().unwrap();
    b.save().unwrap(); // reconciles A's file first
    touch(&mut a, "a");
    a.save().unwrap(); // reconciles B's file first

    a.set_prune_clock_offset_for_tests(2 * DAY);
    b.set_prune_clock_offset_for_tests(2 * DAY);
    touch(&mut b, "b");
    b.save().unwrap();
    touch(&mut a, "a2");
    a.save().unwrap();

    for v in [&a, &b] {
        assert!(has_ref(v, item, x) && has_ref(v, item, y));
        assert_eq!(v.attachment_state(x), AttachmentState::Present);
        assert_eq!(v.attachment_state(y), AttachmentState::Present);
    }
    assert_eq!(read_all(&a, item, y).unwrap(), b"from B");
    assert_eq!(read_all(&b, item, x).unwrap(), b"from A");
}

#[test]
fn removed_attachment_blob_goes_after_the_grace_period() {
    let (_dir, _path, mut v, item) = setup();
    let id = add(&mut v, item, b"bye");
    v.save().unwrap();
    v.remove_attachment(item, id, NOW + 2).unwrap();
    assert!(v.is_dirty());
    assert!(ref_ids(&v, item).is_empty());
    v.save().unwrap();
    assert!(blob(&v, id).exists(), "fresh blob survives the save");
    assert_eq!(v.attachment_state(id), AttachmentState::Present);

    v.set_prune_clock_offset_for_tests(DAY + Duration::from_secs(60));
    touch(&mut v, "later");
    v.save().unwrap();
    assert_eq!(v.attachment_state(id), AttachmentState::Missing);
}

#[test]
fn deleted_item_keeps_its_blob_while_tombstoned() {
    let (_dir, _path, mut v, item) = setup();
    let id = add(&mut v, item, b"keep");
    v.edit(|vault| vault.delete(item, NOW + 5))
        .unwrap()
        .unwrap();
    v.save().unwrap();
    v.set_prune_clock_offset_for_tests(2 * DAY);
    touch(&mut v, "later");
    v.save().unwrap();
    assert_eq!(v.attachment_state(id), AttachmentState::Present);
}

// --- two devices on one directory, B reacting to watcher events ---

const DEADLINE: Duration = Duration::from_secs(10);

fn wait_until(mut done: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < DEADLINE {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    done()
}

fn device_b(path: &Path) -> SyncedVault {
    let mut b = SyncedVault::open(path, DEV_B, Arc::new(NoopHooks)).unwrap();
    b.unlock(&pw()).unwrap();
    b
}

fn modified_at(v: &SyncedVault, item: Uuid) -> u64 {
    v.vault().unwrap().get(item).unwrap().modified_at
}

fn has_ref(v: &SyncedVault, item: Uuid, id: Uuid) -> bool {
    v.vault()
        .and_then(|vault| vault.get(item))
        .is_some_and(|i| i.attachment(id).is_some())
}

#[test]
fn peer_merges_new_attachment_and_opens_it() {
    let (_dir, path, mut a, item) = setup();
    let mut b = device_b(&path);
    b.start_watching().unwrap();

    let big = three_chunks();
    let id = add(&mut a, item, &big);
    a.save().unwrap();
    assert!(wait_until(|| {
        b.poll();
        has_ref(&b, item, id)
    }));
    assert_eq!(read_all(&b, item, id).unwrap(), big);
}

/// A removes a reference before B ever saw it: B merges the removal, and the unreferenced blob
/// is pruned on B's save only once it is older than 24 h.
#[test]
fn peer_prunes_unreferenced_blob_only_after_grace() {
    let (_dir, path, mut a, item) = setup();
    let mut b = device_b(&path);

    let id = add(&mut a, item, b"short-lived");
    a.save().unwrap();
    a.remove_attachment(item, id, NOW + 2).unwrap();
    a.save().unwrap();

    // B merges A's state through its save (dirty, so it reconciles the primary first).
    touch(&mut b, "b1");
    b.save().unwrap();
    assert!(!has_ref(&b, item, id));
    assert_eq!(b.attachment_state(id), AttachmentState::Present);

    b.set_prune_clock_offset_for_tests(DAY + Duration::from_secs(60));
    touch(&mut b, "b2");
    b.save().unwrap();
    assert_eq!(b.attachment_state(id), AttachmentState::Missing);
}

/// Once B holds a reference, A's removal still wins: core keeps an attachment tombstone, so
/// the merge drops the ref on B and nothing writes it back. The blob is kept while fresh and
/// pruned once older than 24 h, whichever device saves.
#[test]
fn removal_survives_merge_on_both_devices_and_blob_is_pruned() {
    let (_dir, path, mut a, item) = setup();
    let mut b = device_b(&path);
    b.start_watching().unwrap();
    a.start_watching().unwrap();

    let id = add(&mut a, item, b"short-lived");
    a.save().unwrap();
    assert!(wait_until(|| {
        b.poll();
        has_ref(&b, item, id)
    }));

    a.remove_attachment(item, id, NOW + 2).unwrap();
    a.save().unwrap();
    let removed_at = modified_at(&a, item);
    assert!(wait_until(|| {
        b.poll();
        modified_at(&b, item) >= removed_at && !b.is_dirty()
    }));
    assert!(!has_ref(&b, item, id), "removal survives the merge on B");
    // Anything B wrote meanwhile reaches A; A must not see the ref again either.
    for _ in 0..10 {
        a.poll();
        thread::sleep(Duration::from_millis(50));
    }
    assert!(!has_ref(&a, item, id), "removal stays on A");
    let mut c = SyncedVault::open(&path, Uuid::from_u128(0xC), Arc::new(NoopHooks)).unwrap();
    c.unlock(&pw()).unwrap();
    assert!(!has_ref(&c, item, id), "no reference on disk");

    // Fresh: both devices' saves keep the blob.
    touch(&mut b, "b1");
    b.save().unwrap();
    touch(&mut a, "a1");
    a.save().unwrap();
    assert_eq!(a.attachment_state(id), AttachmentState::Present);
    assert_eq!(b.attachment_state(id), AttachmentState::Present);

    // Past the grace period: pruned, seen as Missing by both.
    b.set_prune_clock_offset_for_tests(2 * DAY);
    let events = b.subscribe();
    touch(&mut b, "b2");
    b.save().unwrap();
    assert!(
        events
            .try_iter()
            .any(|e| e == SyncEvent::AttachmentsPruned(1))
    );
    assert_eq!(a.attachment_state(id), AttachmentState::Missing);
    assert_eq!(b.attachment_state(id), AttachmentState::Missing);
}

/// A conflicted package (03 §6) holding a blob we lack: the merge brings its reference, the
/// blob is copied into our `attachments/`, and the whole package moves into `backups/`.
#[test]
fn conflict_package_with_extra_blob_is_absorbed_whole() {
    let (dir, path, mut a, item) = setup();
    a.start_watching().unwrap();
    let events = a.subscribe();

    // B works on a copy of the package under a name that is not a candidate yet.
    let staging = dir.path().join("staging");
    fs::create_dir(&staging).unwrap();
    let file = vault_sync::VAULT_FILE_NAME;
    fs::copy(path.join(file), staging.join(file)).unwrap();
    let mut b = SyncedVault::open(&staging, DEV_B, Arc::new(NoopHooks)).unwrap();
    b.unlock(&pw()).unwrap();
    let big = three_chunks();
    let id = add(&mut b, item, &big);
    b.save().unwrap();
    drop(b);
    assert_eq!(a.attachment_state(id), AttachmentState::Missing);

    // The provider renames it into place as the loser of a conflict.
    let conflict = dir.path().join("test 2.vault");
    fs::rename(&staging, &conflict).unwrap();
    assert!(wait_until(|| {
        a.poll();
        !conflict.exists()
    }));

    assert!(has_ref(&a, item, id));
    assert_eq!(a.attachment_state(id), AttachmentState::Present);
    assert_eq!(mode(&blob(&a, id)), 0o600);
    assert_eq!(read_all(&a, item, id).unwrap(), big);
    assert!(tmp_leftovers(&a.attachments_dir()).is_empty());
    let absorbed = a
        .backups()
        .unwrap()
        .into_iter()
        .find(|b| b.is_conflict())
        .expect("conflict package listed");
    assert!(absorbed.path.starts_with(path.join("backups")));
    assert!(
        absorbed
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with("-test 2.vault")
    );
    // Moved whole: its vault file and its own copy of the blob are still inside.
    assert!(absorbed.path.join(file).is_file());
    assert!(
        absorbed
            .path
            .join("attachments")
            .join(blob_file_name(id))
            .is_file()
    );
    assert!(
        events
            .try_iter()
            .any(|e| e == SyncEvent::ConflictAbsorbed(absorbed.path.clone()))
    );
    // On disk too: a fresh open sees the reference.
    let mut c = SyncedVault::open(&path, Uuid::from_u128(0xC), Arc::new(NoopHooks)).unwrap();
    c.unlock(&pw()).unwrap();
    assert!(has_ref(&c, item, id));
}

/// A blob we already have is not replaced by the conflicted package's copy.
#[test]
fn conflict_package_does_not_replace_existing_blobs() {
    let (dir, path, mut a, item) = setup();
    let id = add(&mut a, item, b"ours");
    a.save().unwrap();
    let ours = fs::read(blob(&a, id)).unwrap();
    a.lock();

    let conflict = dir
        .path()
        .join("test (Mac's conflicted copy 2026-10-30).vault");
    fs::create_dir_all(conflict.join("attachments")).unwrap();
    let file = vault_sync::VAULT_FILE_NAME;
    fs::copy(path.join(file), conflict.join(file)).unwrap();
    fs::write(
        conflict.join("attachments").join(blob_file_name(id)),
        b"junk",
    )
    .unwrap();

    a.start_watching().unwrap();
    // Seen while locked: deferred, absorbed at unlock.
    assert!(wait_until(|| {
        a.poll();
        a.unlock(&pw()).unwrap();
        !conflict.exists()
    }));
    assert_eq!(fs::read(blob(&a, id)).unwrap(), ours);
}

/// A conflicted package whose items reference a blob that has not arrived inside it yet: it
/// is merged, but only moved once the blob arrives (and is copied).
#[test]
fn conflict_package_waits_for_a_late_blob() {
    let (dir, path, mut a, item) = setup();
    a.start_watching().unwrap();
    let staging = dir.path().join("staging");
    fs::create_dir(&staging).unwrap();
    let file = vault_sync::VAULT_FILE_NAME;
    fs::copy(path.join(file), staging.join(file)).unwrap();
    let mut b = SyncedVault::open(&staging, DEV_B, Arc::new(NoopHooks)).unwrap();
    b.unlock(&pw()).unwrap();
    let id = add(&mut b, item, b"late");
    b.save().unwrap();
    drop(b);
    // The blob is still in transit.
    let in_transit = dir.path().join("in-transit.bin");
    fs::rename(
        staging.join("attachments").join(blob_file_name(id)),
        &in_transit,
    )
    .unwrap();

    let conflict = dir.path().join("test 2.vault");
    fs::rename(&staging, &conflict).unwrap();
    assert!(wait_until(|| {
        a.poll();
        has_ref(&a, item, id)
    }));
    for _ in 0..20 {
        a.poll();
        thread::sleep(Duration::from_millis(50));
    }
    assert!(conflict.exists(), "moved before its blob arrived");
    assert_eq!(a.attachment_state(id), AttachmentState::Missing);

    fs::rename(
        &in_transit,
        conflict.join("attachments").join(blob_file_name(id)),
    )
    .unwrap();
    assert!(wait_until(|| {
        a.poll();
        !conflict.exists()
    }));
    assert_eq!(read_all(&a, item, id).unwrap(), b"late");
}

/// A conflicted package without `vault.bin` that only holds blobs (they arrived after the
/// package was absorbed): blobs we lack are copied in; the remnant stays in place.
#[test]
fn blob_only_conflict_package_contributes_its_blobs() {
    let (dir, _path, mut a, item) = setup();
    let id = add(&mut a, item, b"precious");
    a.save().unwrap();
    let blob_bytes = fs::read(blob(&a, id)).unwrap();
    fs::remove_file(blob(&a, id)).unwrap();
    assert_eq!(a.attachment_state(id), AttachmentState::Missing);
    a.start_watching().unwrap();

    let remnant = dir.path().join("test 2.vault");
    let staging = dir.path().join(".staging");
    fs::create_dir_all(staging.join("attachments")).unwrap();
    fs::write(
        staging.join("attachments").join(blob_file_name(id)),
        &blob_bytes,
    )
    .unwrap();
    fs::rename(&staging, &remnant).unwrap();
    assert!(wait_until(|| {
        a.poll();
        a.attachment_state(id) == AttachmentState::Present
    }));
    assert_eq!(read_all(&a, item, id).unwrap(), b"precious");
    assert!(remnant.exists());
}
