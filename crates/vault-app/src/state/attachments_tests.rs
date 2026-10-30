use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;

use gpui::{AppContext as _, Entity, TestAppContext};
use vault_core::{KdfParams, SecretString};
use vault_sync::NoopHooks;

use super::fake::FakeStore;
use super::*;
use crate::state::Screen;

const PW: &str = "pw";

/// An unlocked vault on disk with two notes, the fake store, and the first note selected.
fn setup(
    dir: &Path,
    store: Arc<dyn AttachmentStore>,
    cx: &mut TestAppContext,
) -> (Entity<AppState>, [Uuid; 2]) {
    let mut vault = SyncedVault::create(
        &dir.join("t.vault"),
        &SecretString::new(PW.into()),
        KdfParams::for_tests(),
        Uuid::new_v4(),
        Arc::new(NoopHooks),
    )
    .unwrap();
    let ids = vault
        .edit(|v| {
            let d = v.device_id();
            [
                v.insert(Item::new("Alpha", d, 1), 1),
                v.insert(Item::new("Beta", d, 1), 1),
            ]
        })
        .unwrap();
    vault.save().unwrap();
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, cx| {
        s.set_attachment_store(store);
        s.install_unlocked_for_tests(vault);
        s.select(ids[0], cx);
    });
    (state, ids)
}

fn file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn refs(state: &Entity<AppState>, item: Uuid, cx: &mut TestAppContext) -> Vec<(Uuid, String)> {
    state.read_with(cx, |s, _| {
        s.unlocked_vault()
            .and_then(|v| v.get(item))
            .map(|i| {
                i.attachments
                    .iter()
                    .map(|a| (a.id, a.name.clone()))
                    .collect()
            })
            .unwrap_or_default()
    })
}

fn add(state: &Entity<AppState>, paths: Vec<PathBuf>, cx: &mut TestAppContext) {
    state.update(cx, |s, cx| s.add_attachment_files(paths, cx));
    cx.run_until_parked();
}

#[test]
fn preview_only_for_listed_kinds() {
    let img = |f| Some(PreviewKind::Image(f));
    assert_eq!(preview_kind("a.png", 10), img(gpui::ImageFormat::Png));
    assert_eq!(preview_kind("A.JPG", 10), img(gpui::ImageFormat::Jpeg));
    assert_eq!(preview_kind("a.jpeg", 10), img(gpui::ImageFormat::Jpeg));
    assert_eq!(preview_kind("a.gif", 10), img(gpui::ImageFormat::Gif));
    assert_eq!(preview_kind("a.png", IMAGE_PREVIEW_MAX + 1), None);
    assert_eq!(preview_kind("notes.txt", 999_999), Some(PreviewKind::Text));
    assert_eq!(preview_kind("README", 10), Some(PreviewKind::Text));
    assert_eq!(
        preview_kind("notes.txt", TEXT_PREVIEW_MAX),
        None,
        "under 1 MB only"
    );
    for other in ["scan.heic", "a.pdf", "a.zip", "a.svg", "a.docx", "a.webp"] {
        assert_eq!(preview_kind(other, 10), None, "{other}");
    }
}

#[test]
fn text_preview_lines() {
    let t = TextPreview::new(Zeroizing::new("one\r\ntwo\n\nfour".to_owned()));
    assert_eq!(t.line_count(), 4);
    assert_eq!(
        [t.line(0), t.line(1), t.line(2), t.line(3)],
        ["one", "two", "", "four"]
    );
    let long = "é".repeat(PREVIEW_LINE_MAX);
    let t = TextPreview::new(Zeroizing::new(long));
    assert!(t.line(0).len() <= PREVIEW_LINE_MAX);
    assert_eq!(
        TextPreview::new(Zeroizing::new(String::new())).line_count(),
        1
    );
}

#[gpui::test]
fn add_files_then_remove_one(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let store = FakeStore::new();
    let (state, ids) = setup(dir.path(), store.clone(), cx);
    let a = file(dir.path(), "a.txt", b"hello");
    let b = file(dir.path(), "b.bin", &[1, 2, 3]);
    state.update(cx, |s, cx| {
        s.add_attachment_files(vec![a, b], cx);
        assert_eq!(s.busy, Some(Busy::Attaching));
        assert_eq!(s.attachments.pending.len(), 2, "rows with spinners");
        assert_eq!(
            s.shown_item().map(|i| i.id),
            Some(ids[0]),
            "held while sealing"
        );
    });
    cx.run_until_parked();
    let added = refs(&state, ids[0], cx);
    assert_eq!(
        added.iter().map(|(_, n)| n.as_str()).collect::<Vec<_>>(),
        ["a.txt", "b.bin"]
    );
    state.read_with(cx, |s, _| {
        assert!(s.busy.is_none() && s.attachments.pending.is_empty());
        assert!(!s.vault.as_ref().unwrap().is_dirty(), "the add saves");
        assert!(s.toast.is_none());
    });

    let gone = added[0].0;
    state.update(cx, |s, cx| {
        // Read mode: Remove is refused.
        s.request_remove_attachment(gone, cx);
        assert!(s.attachments.remove_confirm.is_none());
        s.confirm_remove_attachment(gone, cx);
        assert!(
            !s.vault.as_ref().unwrap().is_dirty(),
            "nothing removed in read mode"
        );
        s.begin_edit(cx);
        s.request_remove_attachment(gone, cx);
        assert_eq!(s.attachments.remove_confirm, Some(gone));
        s.confirm_remove_attachment(gone, cx);
        assert!(s.attachments.remove_confirm.is_none());
        assert!(s.vault.as_ref().unwrap().is_dirty(), "autosave pending");
    });
    assert_eq!(refs(&state, ids[0], cx), vec![added[1].clone()]);
    // Leaving edit mode drops a pending confirm.
    state.update(cx, |s, cx| {
        s.request_remove_attachment(added[1].0, cx);
        s.cancel_edit(cx);
        s.follow_attachment_selection(cx);
        assert!(s.attachments.remove_confirm.is_none());
    });
}

#[gpui::test]
fn add_over_cap_refused_with_toast(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids) = setup(dir.path(), FakeStore::new(), cx);
    let big = dir.path().join("big.iso");
    // Sparse: no 100 MB actually written.
    std::fs::File::create(&big)
        .unwrap()
        .set_len(MAX_ATTACHMENT_SIZE + 1)
        .unwrap();
    let ok = file(dir.path(), "ok.txt", b"x");
    add(&state, vec![big.clone()], cx);
    state.read_with(cx, |s, _| {
        assert_eq!(
            s.toast.as_ref().map(|t| t.message.as_ref()),
            Some(TOO_LARGE)
        );
        assert!(s.busy.is_none());
    });
    assert!(refs(&state, ids[0], cx).is_empty());
    // Mixed: the big one is skipped, the other is added.
    add(&state, vec![big, ok], cx);
    assert_eq!(refs(&state, ids[0], cx).len(), 1);
}

#[gpui::test]
fn lock_mid_add_discards_the_result(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let store = FakeStore::new();
    let (state, ids) = setup(dir.path(), store.clone(), cx);
    let a = file(dir.path(), "a.txt", b"hello");
    state.update(cx, |s, cx| {
        s.add_attachment_files(vec![a], cx);
        s.lock(cx);
    });
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert!(s.locked && s.busy.is_none());
        assert_eq!(s.screen, Screen::Unlock);
        assert!(s.toast.is_none(), "discarded silently");
        assert!(s.attachments.pending.is_empty());
        assert!(
            s.vault.as_ref().is_some_and(|v| v.vault().is_none()),
            "relocked"
        );
    });
    state.update(cx, |s, cx| s.unlock(SecretString::new(PW.into()), cx));
    cx.run_until_parked();
    assert!(!state.read_with(cx, |s, _| s.locked));
    assert!(
        refs(&state, ids[0], cx).is_empty(),
        "the reference was taken out again"
    );
}

#[gpui::test]
fn text_preview_is_wiped_on_selection_change_and_lock(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids) = setup(dir.path(), FakeStore::new(), cx);
    add(
        &state,
        vec![file(dir.path(), "notes.txt", b"line one\nline two")],
        cx,
    );
    let id = refs(&state, ids[0], cx)[0].0;
    let preview = |state: &Entity<AppState>, cx: &mut TestAppContext| {
        state.update(cx, |s, cx| s.toggle_attachment_preview(id, cx));
        cx.run_until_parked();
    };
    preview(&state, cx);
    state.read_with(cx, |s, _| {
        let p = s.attachments.preview.as_ref().expect("preview");
        let PreviewContent::Text(t) = &p.content else {
            panic!("not text")
        };
        assert_eq!((t.line(0), t.line(1)), ("line one", "line two"));
    });
    state.update(cx, |s, cx| {
        s.select(ids[1], cx);
        s.follow_attachment_selection(cx);
        assert!(s.attachments.preview.is_none(), "selection change wipes it");
        s.select(ids[0], cx);
    });
    preview(&state, cx);
    assert!(state.read_with(cx, |s, _| s.attachments.preview.is_some()));
    state.update(cx, |s, cx| s.lock(cx));
    assert!(state.read_with(cx, |s, _| s.attachments.preview.is_none()));
}

#[gpui::test]
fn binary_named_txt_is_not_previewed(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids) = setup(dir.path(), FakeStore::new(), cx);
    add(
        &state,
        vec![file(dir.path(), "x.txt", &[0xff, 0xfe, 0, 1])],
        cx,
    );
    let id = refs(&state, ids[0], cx)[0].0;
    state.update(cx, |s, cx| s.toggle_attachment_preview(id, cx));
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        let p = s.attachments.preview.as_ref().unwrap();
        assert!(matches!(p.content, PreviewContent::Unavailable(_)));
    });
}

#[gpui::test]
fn missing_blob_refuses_preview(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let store = FakeStore::new();
    let (state, ids) = setup(dir.path(), store.clone(), cx);
    add(&state, vec![file(dir.path(), "a.txt", b"hi")], cx);
    let id = refs(&state, ids[0], cx)[0].0;
    store.blobs.lock().unwrap().clear();
    state.update(cx, |s, cx| {
        assert_eq!(s.attachment_state(id), AttachmentState::Missing);
        s.toggle_attachment_preview(id, cx);
    });
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert!(s.attachments.preview.is_none());
        assert_eq!(s.toast.as_ref().map(|t| t.message.as_ref()), Some(MISSING));
    });
}

#[gpui::test]
fn save_copy_asks_first_and_writes_0600(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids) = setup(dir.path(), FakeStore::new(), cx);
    add(&state, vec![file(dir.path(), "a.txt", b"secret notes")], cx);
    let id = refs(&state, ids[0], cx)[0].0;
    let out = dir.path().join("out").join("a copy.txt");
    std::fs::create_dir(out.parent().unwrap()).unwrap();

    state.update(cx, |s, cx| s.save_attachment_to(id, out.clone(), cx));
    cx.run_until_parked();
    assert!(state.read_with(cx, |s, _| s.attachments.save_confirm.is_some()));
    assert!(!out.exists(), "nothing written before the confirm");

    state.update(cx, |s, cx| s.cancel_save_copy(cx));
    assert!(!out.exists());

    state.update(cx, |s, cx| {
        s.save_attachment_to(id, out.clone(), cx);
        s.confirm_save_copy(cx);
    });
    cx.run_until_parked();
    assert_eq!(std::fs::read(&out).unwrap(), b"secret notes");
    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let names: Vec<_> = std::fs::read_dir(out.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 1, "no temp file left: {names:?}");
    assert!(state.read_with(cx, |s, _| s.toast.is_some()));
}

#[gpui::test]
fn lock_cancels_a_running_save(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids) = setup(dir.path(), FakeStore::new(), cx);
    add(&state, vec![file(dir.path(), "a.txt", b"secret")], cx);
    let id = refs(&state, ids[0], cx)[0].0;
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let target = out.join("a.txt");
    state.update(cx, |s, cx| {
        s.save_attachment_to(id, target.clone(), cx);
        s.confirm_save_copy(cx);
        s.lock(cx);
    });
    cx.run_until_parked();
    assert_eq!(
        std::fs::read_dir(&out).unwrap().count(),
        0,
        "no plaintext left"
    );
    assert!(state.read_with(cx, |s, _| s.toast.is_none()));
}

/// A fresh state reading the vault from disk.
fn reopen(dir: &Path, cx: &mut TestAppContext) -> Entity<AppState> {
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    let path = dir.join("t.vault");
    state.update(cx, |s, cx| s.open_vault(path, cx));
    cx.run_until_parked();
    state.update(cx, |s, cx| s.unlock(SecretString::new(PW.into()), cx));
    cx.run_until_parked();
    state
}

/// Two saved attachments; the first is then removed (autosave pending, vault dirty) and
/// the second is evicted. Returns the ids `[removed, evicted]`.
fn dirty_with_evicted(
    state: &Entity<AppState>,
    store: &FakeStore,
    dir: &Path,
    item: Uuid,
    cx: &mut TestAppContext,
) -> [Uuid; 2] {
    add(
        state,
        vec![file(dir, "gone.txt", b"1"), file(dir, "cloud.txt", b"2")],
        cx,
    );
    let ids = refs(state, item, cx);
    let (gone, cloud) = (ids[0].0, ids[1].0);
    store.set_state(cloud, AttachmentState::NotDownloaded);
    state.update(cx, |s, cx| {
        s.begin_edit(cx);
        s.confirm_remove_attachment(gone, cx);
        s.cancel_edit(cx);
        assert!(s.vault.as_ref().unwrap().is_dirty());
    });
    [gone, cloud]
}

#[gpui::test]
fn lock_during_download_saves_pending_edits(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let store = FakeStore::new();
    let (state, ids) = setup(dir.path(), store.clone(), cx);
    let [_, cloud] = dirty_with_evicted(&state, &store, dir.path(), ids[0], cx);
    state.update(cx, |s, cx| {
        s.toggle_attachment_preview(cloud, cx);
        assert_eq!(
            s.busy,
            Some(Busy::ReadingAttachment),
            "vault moved for the download"
        );
        s.lock(cx);
    });
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert!(s.locked && s.attachments.preview.is_none());
        assert!(
            s.vault.as_ref().is_some_and(|v| !v.is_dirty()),
            "saved, then locked"
        );
    });
    let fresh = reopen(dir.path(), cx);
    let names: Vec<_> = refs(&fresh, ids[0], cx)
        .into_iter()
        .map(|(_, n)| n)
        .collect();
    assert_eq!(names, ["cloud.txt"], "the Remove reached the file");
}

#[gpui::test]
fn autosave_resumes_after_a_download(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let store = FakeStore::new();
    let (state, ids) = setup(dir.path(), store.clone(), cx);
    let [_, cloud] = dirty_with_evicted(&state, &store, dir.path(), ids[0], cx);
    state.update(cx, |s, cx| {
        s.toggle_attachment_preview(cloud, cx);
        // What a timer firing while the vault is in the task leaves behind.
        s.autosave = None;
        s.autosave_pending = false;
    });
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert!(s.attachments.preview.is_some());
        assert!(s.vault.as_ref().unwrap().is_dirty());
        assert!(s.autosave_pending, "autosave rescheduled");
    });
    cx.executor()
        .advance_clock(super::super::session::AUTOSAVE_DEBOUNCE * 2);
    cx.run_until_parked();
    assert!(state.read_with(cx, |s, _| !s.vault.as_ref().unwrap().is_dirty()));
}

#[test]
fn image_headers_give_pixel_counts() {
    use gpui::ImageFormat::{Gif, Jpeg, Png};
    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    png.extend_from_slice(&[0, 0, 0x27, 0x10, 0, 0, 0x13, 0x88]); // 10000 x 5000
    assert_eq!(image_pixels(Png, &png), Some(50_000_000));
    assert!(image_fits(Png, &png));
    png[19] = 0x11; // width 10001
    assert!(!image_fits(Png, &png));

    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0, 0];
    jpeg.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 8, 0x00, 0x04, 0x00, 0x05]);
    assert_eq!(image_pixels(Jpeg, &jpeg), Some(20));

    // 2x3 canvas, no colour table, one extension, two frames.
    let mut gif = b"GIF89a".to_vec();
    gif.extend_from_slice(&[2, 0, 3, 0, 0, 0, 0]);
    gif.extend_from_slice(&[0x21, 0xF9, 4, 0, 0, 0, 0, 0]);
    for _ in 0..2 {
        gif.extend_from_slice(&[0x2C, 0, 0, 0, 0, 2, 0, 3, 0, 0, 2, 1, 0x44, 0]);
    }
    gif.push(0x3B);
    assert_eq!(image_pixels(Gif, &gif), Some(12));

    assert_eq!(image_pixels(Png, b"not a png"), None);
    assert!(!image_fits(Gif, &gif[..20]), "truncated header is refused");
}

#[test]
fn one_toast_for_skipped_drops() {
    assert_eq!(skipped_message(0, 0), None);
    assert_eq!(skipped_message(1, 0).as_deref(), Some(TOO_LARGE));
    assert_eq!(
        skipped_message(0, 1).as_deref(),
        Some("Only files can be attached")
    );
    assert_eq!(
        skipped_message(2, 3).as_deref(),
        Some("Skipped: 2 files are larger than 100 MB; 3 items are not files")
    );
}

/// The real vault-sync store end to end: seal, state, preview, missing blob.
#[gpui::test]
fn real_store_round_trip(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids) = setup(dir.path(), sync_store(), cx);
    add(&state, vec![file(dir.path(), "real.txt", b"from disk")], cx);
    let id = refs(&state, ids[0], cx)[0].0;
    assert_eq!(
        state.read_with(cx, |s, _| s.attachment_state(id)),
        AttachmentState::Present
    );
    state.update(cx, |s, cx| s.toggle_attachment_preview(id, cx));
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        let Some(PreviewContent::Text(t)) = s.attachments.preview.as_ref().map(|p| &p.content)
        else {
            panic!("no text preview")
        };
        assert_eq!(t.line(0), "from disk");
    });
    let blob = dir
        .path()
        .join("t.vault")
        .join("attachments")
        .join(vault_core::attachment::blob_file_name(id));
    std::fs::remove_file(blob).unwrap();
    assert_eq!(
        state.read_with(cx, |s, _| s.attachment_state(id)),
        AttachmentState::Missing
    );
}

#[test]
fn attachment_not_found_has_its_own_toast() {
    let e = SyncError::AttachmentNotFound {
        item: Uuid::new_v4(),
        id: Uuid::new_v4(),
    };
    assert_eq!(read_error(&e), NOT_FOUND);
    assert_eq!(NOT_FOUND, "Attachment not found on this item.");
}
