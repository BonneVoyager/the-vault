//! Custom image icons through `AppState` with the fake attachment store: choosing,
//! replacing, giving up an image, cancel and lock, refusals, the decoded-image cache.

use std::path::Path;
use std::sync::Arc;

use gpui::{AppContext as _, Entity, TestAppContext};
use vault_core::{Item, KdfParams, SecretString};
use vault_sync::{NoopHooks, SyncedVault};

use super::*;
use crate::icon_image::test_images::{png, png_header_only};
use crate::state::AttachmentStore as _;
use crate::state::attachments::fake::FakeStore;

const PW: &str = "pw";

/// An unlocked vault on disk with one item ("Alpha"), selected, and the fake store.
fn setup(dir: &Path, cx: &mut TestAppContext) -> (Entity<AppState>, Uuid, Arc<FakeStore>) {
    let mut vault = SyncedVault::create(
        &dir.join("t.vault"),
        &SecretString::new(PW.into()),
        KdfParams::for_tests(),
        Uuid::new_v4(),
        Arc::new(NoopHooks),
    )
    .unwrap();
    let id = vault
        .edit(|v| {
            let d = v.device_id();
            v.insert(Item::new("Alpha", d, 1), 1)
        })
        .unwrap();
    vault.save().unwrap();
    let store = FakeStore::new();
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, cx| {
        s.set_attachment_store(store.clone());
        s.install_unlocked_for_tests(vault);
        s.select(id, cx);
    });
    (state, id, store)
}

fn image_file(dir: &Path, name: &str, rgba: [u8; 4]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, png(64, 32, rgba)).unwrap();
    path
}

fn stored(state: &Entity<AppState>, id: Uuid, cx: &mut TestAppContext) -> Item {
    state.read_with(cx, |s, _| {
        s.unlocked_vault().unwrap().get(id).unwrap().clone()
    })
}

fn ref_ids(item: &Item) -> Vec<Uuid> {
    item.attachments.iter().map(|a| a.id).collect()
}

/// Chooses `path` as the icon of the item being edited; returns the new attachment id.
fn choose(state: &Entity<AppState>, path: PathBuf, cx: &mut TestAppContext) -> Uuid {
    state.update(cx, |s, cx| s.set_icon_image_file(path, cx));
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        let b = s.edit_buffer().expect("still editing");
        assert!(!b.icon_loading);
        *b.icon_added.last().expect("image added")
    })
}

fn render_scan(state: &Entity<AppState>, cx: &mut TestAppContext) {
    state.update(cx, |s, cx| s.load_icon_images(cx));
    cx.run_until_parked();
}

/// Saves an image icon on `id` and returns its attachment id.
fn with_saved_image(
    state: &Entity<AppState>,
    id: Uuid,
    dir: &Path,
    cx: &mut TestAppContext,
) -> Uuid {
    state.update(cx, |s, cx| {
        s.select(id, cx);
        s.begin_edit(cx);
    });
    let a = choose(state, image_file(dir, "a.png", [200, 0, 0, 255]), cx);
    state.update(cx, |s, cx| s.save_edit(cx));
    assert!(!state.read_with(cx, |s, _| s.is_editing()));
    a
}

#[gpui::test]
fn choosing_an_image_stores_a_hidden_png_attachment(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, id, store) = setup(dir.path(), cx);
    state.update(cx, |s, cx| s.begin_edit(cx));
    let a = choose(
        &state,
        image_file(dir.path(), "logo.png", [0, 128, 255, 255]),
        cx,
    );

    // Before Save: the reference is on the stored item, the icon only in the buffer.
    let item = stored(&state, id, cx);
    assert_eq!(ref_ids(&item), vec![a]);
    assert_eq!(item.attachments[0].name, "icon.png");
    assert!(item.icon.is_none());
    state.read_with(cx, |s, _| {
        let b = s.edit_buffer().unwrap();
        assert_eq!(b.item.icon, Some(icon::image_icon(a)));
        assert_eq!(b.item.icon.as_ref().unwrap().value, a.to_string());
        assert!(b.item.icon.as_ref().unwrap().color.is_none());
        assert!(b.has_changes());
        // Hidden already: the pending add is not an attachment to the user.
        assert!(s.is_hidden_attachment(&item, &item.attachments[0]));
        assert_eq!(s.visible_attachments(&item).count(), 0);
        assert!(s.icon_image(a).is_some(), "the add fills the cache");
    });
    // The blob is the 128 px PNG, not the original.
    let blob = store.blobs.lock().unwrap().get(&a).cloned().unwrap();
    let decoded = image::load_from_memory(&blob).unwrap();
    assert_eq!((decoded.width(), decoded.height()), (128, 128));

    state.update(cx, |s, cx| s.save_edit(cx));
    let item = stored(&state, id, cx);
    assert_eq!(item.icon, Some(icon::image_icon(a)));
    assert_eq!(ref_ids(&item), vec![a]);
    assert!(icon::is_icon_attachment(&item, &item.attachments[0]));
    state.read_with(cx, |s, _| {
        assert_eq!(s.visible_attachments(&item).count(), 0);
    });
}

#[gpui::test]
fn replacing_an_image_removes_the_previous_reference(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, id, _) = setup(dir.path(), cx);
    let a = with_saved_image(&state, id, dir.path(), cx);

    // Two more in one edit: B is replaced by C before Save.
    state.update(cx, |s, cx| s.begin_edit(cx));
    let b = choose(
        &state,
        image_file(dir.path(), "b.png", [0, 200, 0, 255]),
        cx,
    );
    let c = choose(
        &state,
        image_file(dir.path(), "c.png", [0, 0, 200, 255]),
        cx,
    );
    // As a set: core orders by `(added_at, id)` and the three may share a millisecond.
    let mut refs = ref_ids(&stored(&state, id, cx));
    let mut want = vec![a, b, c];
    refs.sort();
    want.sort();
    assert_eq!(refs, want);
    state.read_with(cx, |s, _| {
        assert_eq!(
            s.edit_buffer().unwrap().icon_refs_dropped_on_save(),
            vec![a, b]
        );
    });
    state.update(cx, |s, cx| s.save_edit(cx));
    let item = stored(&state, id, cx);
    assert_eq!(item.icon, Some(icon::image_icon(c)));
    assert_eq!(ref_ids(&item), vec![c], "A and B are gone in the same save");
    let tombstoned: Vec<Uuid> = item.removed_attachments.iter().map(|t| t.id).collect();
    assert!(tombstoned.contains(&a) && tombstoned.contains(&b));
}

#[gpui::test]
fn automatic_symbol_or_colour_on_an_image_removes_its_reference(cx: &mut TestAppContext) {
    for cell in [
        PickerCell::Automatic,
        PickerCell::Symbol(3),
        PickerCell::Color(2),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (state, id, _) = setup(dir.path(), cx);
        let a = with_saved_image(&state, id, dir.path(), cx);
        state.update(cx, |s, cx| {
            s.begin_edit(cx);
            // A colour that is not the item's default (the default would mean no icon).
            let cell = match cell {
                PickerCell::Color(_) => {
                    let default = icon::palette_color(&s.edit_buffer().unwrap().item);
                    PickerCell::Color(icon::PALETTE.iter().position(|c| *c != default).unwrap())
                }
                other => other,
            };
            s.choose_icon(cell, cx);
        });
        // Not removed before Save: Cancel would keep the image.
        assert_eq!(ref_ids(&stored(&state, id, cx)), vec![a], "{cell:?}");
        state.update(cx, |s, cx| s.save_edit(cx));
        let item = stored(&state, id, cx);
        assert!(item.attachments.is_empty(), "{cell:?}");
        match cell {
            PickerCell::Automatic => assert!(item.icon.is_none()),
            PickerCell::Symbol(_) => {
                assert_eq!(item.icon.as_ref().unwrap().kind, icon::KIND_SYMBOL)
            }
            _ => assert_eq!(item.icon.as_ref().unwrap().kind, icon::KIND_LETTER),
        }
    }
}

#[gpui::test]
fn cancel_takes_the_new_reference_out_and_keeps_the_old_icon(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, id, store) = setup(dir.path(), cx);
    let a = with_saved_image(&state, id, dir.path(), cx);
    let before = stored(&state, id, cx);

    state.update(cx, |s, cx| s.begin_edit(cx));
    let b = choose(&state, image_file(dir.path(), "b.png", [1, 2, 3, 255]), cx);
    state.update(cx, |s, cx| s.cancel_edit(cx));
    let item = stored(&state, id, cx);
    assert_eq!(item.icon, before.icon, "the saved image stays the icon");
    assert_eq!(ref_ids(&item), vec![a], "only the cancelled add is removed");
    assert!(item.removed_attachments.iter().any(|t| t.id == b));
    // The sealed blob is left for vault-sync's orphan cleanup, like a cancelled add.
    assert!(store.blobs.lock().unwrap().contains_key(&b));

    // Adding then choosing Automatic again leaves no changes, yet the add is undone.
    let dir2 = tempfile::tempdir().unwrap();
    let (state, id, _) = setup(dir2.path(), cx);
    state.update(cx, |s, cx| s.begin_edit(cx));
    choose(&state, image_file(dir2.path(), "c.png", [9, 9, 9, 255]), cx);
    state.update(cx, |s, cx| {
        s.choose_icon(PickerCell::Automatic, cx);
        assert!(!s.edit_buffer().unwrap().has_changes());
        s.cancel_edit(cx);
    });
    assert!(stored(&state, id, cx).attachments.is_empty());
}

#[gpui::test]
fn lock_during_an_edit_drops_the_unsaved_image(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, id, _) = setup(dir.path(), cx);
    state.update(cx, |s, cx| s.begin_edit(cx));
    choose(&state, image_file(dir.path(), "a.png", [5, 5, 5, 255]), cx);
    state.update(cx, |s, cx| s.lock(cx));
    cx.run_until_parked();
    state.update(cx, |s, cx| s.unlock(SecretString::new(PW.into()), cx));
    cx.run_until_parked();
    let item = stored(&state, id, cx);
    assert!(
        item.attachments.is_empty(),
        "never saved with the reference"
    );
    assert!(item.icon.is_none());

    // Lock while the add itself runs: the result is discarded like a cancelled add.
    state.update(cx, |s, cx| {
        s.select(id, cx);
        s.begin_edit(cx);
        s.set_icon_image_file(image_file(dir.path(), "b.png", [6, 6, 6, 255]), cx);
        s.lock(cx);
    });
    cx.run_until_parked();
    state.update(cx, |s, cx| s.unlock(SecretString::new(PW.into()), cx));
    cx.run_until_parked();
    assert!(stored(&state, id, cx).attachments.is_empty());
}

#[gpui::test]
fn the_three_refusals_toast_and_add_nothing(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, id, _) = setup(dir.path(), cx);
    state.update(cx, |s, cx| s.begin_edit(cx));
    let big = dir.path().join("big.png");
    let mut bytes = png(4, 4, [0, 0, 0, 255]);
    bytes.resize(600 * 1024, 0);
    std::fs::write(&big, bytes).unwrap();
    let text = dir.path().join("notes.png");
    std::fs::write(&text, b"not an image").unwrap();
    let huge = dir.path().join("huge.png");
    std::fs::write(&huge, png_header_only(9000, 20)).unwrap();
    for (path, refusal) in [
        (big, Refusal::TooLarge),
        (text, Refusal::Unreadable),
        (huge, Refusal::TooManyPixels),
    ] {
        state.update(cx, |s, cx| {
            s.toast = None;
            s.set_icon_image_file(path, cx);
        });
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            let toast = s.toast.as_ref().expect("toast");
            assert_eq!(toast.message.as_ref(), refusal.message());
            let b = s.edit_buffer().unwrap();
            assert!(b.item.icon.is_none() && b.icon_added.is_empty());
        });
        assert!(stored(&state, id, cx).attachments.is_empty());
    }
}

#[gpui::test]
fn new_items_cannot_take_an_image_yet(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, _) = setup(dir.path(), cx);
    state.update(cx, |s, cx| {
        s.begin_new(crate::templates::Template::Login, String::new(), cx);
        assert!(!s.can_choose_icon_image());
        s.set_icon_image_file(image_file(dir.path(), "a.png", [1, 1, 1, 255]), cx);
        assert!(s.busy.is_none());
        assert!(s.edit_buffer().unwrap().item.icon.is_none());
    });
}

#[gpui::test]
fn undecodable_blob_is_rejected_not_cached(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, id, store) = setup(dir.path(), cx);
    // An image icon whose blob is not an image (another client, or damage).
    let bad = state.update(cx, |s, cx| {
        let vault = s.vault.as_mut().unwrap();
        let bad = store
            .add(vault, id, "icon.png", &mut &b"garbage!"[..], 8, 2)
            .unwrap();
        vault
            .edit(|v| v.update(id, 3, |it| it.icon = Some(icon::image_icon(bad))))
            .unwrap()
            .unwrap();
        s.vault_changed();
        cx.notify();
        bad
    });
    render_scan(&state, cx);
    state.read_with(cx, |s, _| {
        assert!(s.icon_images.is_rejected(bad), "tried once");
        assert!(!s.icon_images.is_cached(bad), "nothing kept");
        assert!(s.icon_image(bad).is_none(), "nothing to draw");
    });
    // A dangling reference (blob never arrived) is not cached and not fatal either.
    let gone = Uuid::new_v4();
    state.update(cx, |s, cx| {
        s.vault
            .as_mut()
            .unwrap()
            .edit(|v| v.update(id, 4, |it| it.icon = Some(icon::image_icon(gone))))
            .unwrap()
            .unwrap();
        s.vault_changed();
        s.load_icon_images(cx);
        assert!(!s.icon_images.is_cached(gone));
        assert!(
            !s.icon_images.is_rejected(bad),
            "pruned: no item uses it now"
        );
    });
}

#[gpui::test]
fn cache_decodes_once_per_unlock_and_clears_on_lock(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, id, _) = setup(dir.path(), cx);
    let a = with_saved_image(&state, id, dir.path(), cx);
    // The add put the image in the cache: no decode needed after Save.
    render_scan(&state, cx);
    state.read_with(cx, |s, _| {
        assert!(s.icon_image(a).is_some());
        assert_eq!(s.icon_images.decodes, 0);
    });

    state.update(cx, |s, cx| s.lock(cx));
    state.read_with(cx, |s, _| assert!(s.icon_images.is_empty(), "lock clears"));
    state.update(cx, |s, cx| s.unlock(SecretString::new(PW.into()), cx));
    cx.run_until_parked();
    render_scan(&state, cx);
    state.read_with(cx, |s, _| {
        assert!(s.icon_image(a).is_some(), "decoded again after unlock");
        assert_eq!(s.icon_images.decodes, 1);
    });
    // More vault changes and renders do not decode it again.
    for _ in 0..3 {
        state.update(cx, |s, _| s.vault_changed());
        render_scan(&state, cx);
    }
    assert_eq!(state.read_with(cx, |s, _| s.icon_images.decodes), 1);

    // The reference disappears (another device removed it): the entry goes.
    state.update(cx, |s, cx| {
        s.vault
            .as_mut()
            .unwrap()
            .edit(|v| v.remove_attachment_ref(id, a, 10))
            .unwrap()
            .unwrap();
        s.vault_changed();
        s.load_icon_images(cx);
        assert!(!s.icon_images.is_cached(a));
    });
}

#[test]
fn dropped_on_save_rules() {
    let d = Uuid::new_v4();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let mut item = Item::new("X", d, 1);
    item.icon = Some(icon::image_icon(a));
    // Unchanged image: nothing goes.
    let mut buf = super::super::EditBuffer::new(item.clone());
    assert!(buf.icon_refs_dropped_on_save().is_empty());
    // Replaced by B.
    buf.icon_added.push(b);
    buf.item.icon = Some(icon::image_icon(b));
    assert_eq!(buf.icon_refs_dropped_on_save(), vec![a]);
    // Back to A: B goes.
    buf.item.icon = Some(icon::image_icon(a));
    assert_eq!(buf.icon_refs_dropped_on_save(), vec![b]);
    // A symbol: both go.
    buf.item.icon = icon::choose_symbol(None, gpui_kit_assets::IconName::Mail);
    assert_eq!(buf.icon_refs_dropped_on_save(), vec![a, b]);
    // Unknown kinds and malformed image values never drop anything.
    item.icon = Some(vault_core::ItemIcon::new("image", "not-a-uuid"));
    let mut buf = super::super::EditBuffer::new(item);
    buf.item.icon = None;
    assert!(buf.icon_refs_dropped_on_save().is_empty());
}

#[gpui::test]
fn save_clears_an_image_icon_whose_reference_vanished(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, id, _) = setup(dir.path(), cx);
    state.update(cx, |s, cx| s.begin_edit(cx));
    let a = choose(&state, image_file(dir.path(), "a.png", [1, 2, 3, 255]), cx);
    // Another device removes the attachment (`attach rm`), merged in before Save.
    state.update(cx, |s, _| {
        s.vault
            .as_mut()
            .unwrap()
            .edit(|v| v.remove_attachment_ref(id, a, 5))
            .unwrap()
            .unwrap();
        s.vault_changed();
    });
    state.update(cx, |s, cx| {
        s.set_edit_title("Alpha 2".into(), cx);
        s.save_edit(cx);
    });
    let item = stored(&state, id, cx);
    assert_eq!(item.title, "Alpha 2", "the rest of the edit is saved");
    assert!(item.icon.is_none(), "no dangling image icon is written");
    assert!(item.attachments.is_empty());
}

#[gpui::test]
fn oversized_stored_blob_renders_automatic_and_is_not_cached(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, id, store) = setup(dir.path(), cx);
    // A foreign client stored a 1024 px icon (valid PNG, small file): over 256 px.
    let big = png(1024, 1024, [0, 0, 0, 255]);
    let header_bomb = png_header_only(8192, 8192);
    let mut ids = Vec::new();
    for bytes in [big, header_bomb] {
        let blob = state.update(cx, |s, cx| {
            let vault = s.vault.as_mut().unwrap();
            let len = bytes.len() as u64;
            let blob = store
                .add(vault, id, "icon.png", &mut &bytes[..], len, 2)
                .unwrap();
            vault
                .edit(|v| v.update(id, 3, |it| it.icon = Some(icon::image_icon(blob))))
                .unwrap()
                .unwrap();
            s.vault_changed();
            cx.notify();
            blob
        });
        render_scan(&state, cx);
        state.read_with(cx, |s, _| {
            assert!(s.icon_image(blob).is_none(), "drawn as the automatic icon");
            assert!(!s.icon_images.is_cached(blob), "nothing cached");
            assert!(s.icon_images.is_rejected(blob));
        });
        ids.push(blob);
    }
    // Rejected ids are not retried on later scans in this unlock.
    let decodes = state.read_with(cx, |s, _| s.icon_images.decodes);
    state.update(cx, |s, _| s.vault_changed());
    render_scan(&state, cx);
    assert_eq!(state.read_with(cx, |s, _| s.icon_images.decodes), decodes);
}

#[gpui::test]
fn cache_is_capped_and_evicts_the_least_recently_drawn(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, _) = setup(dir.path(), cx);
    let device = state.read_with(cx, |s, _| s.device_id());
    // Three items with saved image icons, cache capped at two.
    let items: Vec<Uuid> = state.update(cx, |s, _| {
        s.icon_images.cap = 2;
        (0..3)
            .map(|i| {
                s.vault
                    .as_mut()
                    .unwrap()
                    .edit(|v| v.insert(Item::new(format!("I{i}"), device, 1), 1))
                    .unwrap()
            })
            .collect()
    });
    let mut blobs = Vec::new();
    state.update(cx, |s, _| s.vault_changed());
    for item in &items {
        blobs.push(with_saved_image(&state, *item, dir.path(), cx));
    }
    state.read_with(cx, |s, _| {
        let cached = blobs
            .iter()
            .filter(|b| s.icon_images.is_cached(**b))
            .count();
        assert_eq!(cached, 2, "never more than the cap");
        assert!(s.icon_images.is_cached(blobs[2]), "newest kept");
        assert!(
            !s.icon_images.is_cached(blobs[0]),
            "least recently used went"
        );
    });
    // Drawing blob 1 makes blob 2 the least recently used; a fourth image evicts it.
    state.read_with(cx, |s, _| assert!(s.icon_image(blobs[1]).is_some()));
    let fourth = state.update(cx, |s, _| {
        s.vault
            .as_mut()
            .unwrap()
            .edit(|v| v.insert(Item::new("I3", device, 1), 1))
            .unwrap()
    });
    state.update(cx, |s, _| s.vault_changed());
    let d = with_saved_image(&state, fourth, dir.path(), cx);
    state.read_with(cx, |s, _| {
        assert!(s.icon_images.is_cached(d));
        assert!(s.icon_images.is_cached(blobs[1]), "recently drawn survives");
        assert!(!s.icon_images.is_cached(blobs[2]));
    });
    // A rescan does not decode into the full cache (no thrash).
    let decodes = state.read_with(cx, |s, _| s.icon_images.decodes);
    state.update(cx, |s, _| s.vault_changed());
    render_scan(&state, cx);
    state.read_with(cx, |s, _| {
        assert_eq!(s.icon_images.decodes, decodes);
        assert!(
            blobs
                .iter()
                .chain([&d])
                .filter(|b| s.icon_images.is_cached(**b))
                .count()
                <= 2
        );
    });
}

/// Each panel call's extensions and prompt.
type PanelCalls = std::rc::Rc<std::cell::RefCell<Vec<(Vec<String>, String)>>>;

/// A fake panel returning `answer`, recording each call's extensions and prompt.
fn fake_chooser(
    state: &Entity<AppState>,
    answer: Option<PathBuf>,
    cx: &mut TestAppContext,
) -> PanelCalls {
    let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let seen = calls.clone();
    state.update(cx, |s, _| {
        s.icon_images.chooser = std::rc::Rc::new(move |exts: &[&str], prompt: &str| {
            seen.borrow_mut().push((
                exts.iter().map(|e| (*e).to_owned()).collect(),
                prompt.to_owned(),
            ));
            answer.clone()
        });
    });
    calls
}

#[gpui::test]
fn one_panel_at_a_time_and_cancel_changes_nothing(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, id, _) = setup(dir.path(), cx);
    let calls = fake_chooser(&state, None, cx);
    state.update(cx, |s, cx| {
        s.begin_edit(cx);
        s.set_icon_picker(true, cx);
        // Two clicks before the panel returns: one panel.
        s.choose_icon(PickerCell::Image, cx);
        assert!(s.icon_images.choosing, "guard set while the panel is up");
        s.choose_icon(PickerCell::Image, cx);
    });
    cx.run_until_parked();
    assert_eq!(
        calls.borrow().len(),
        1,
        "a second click opened no second panel"
    );
    assert_eq!(
        calls.borrow()[0],
        (
            vec!["png".into(), "jpg".into(), "jpeg".into()],
            "Choose".into()
        )
    );
    state.read_with(cx, |s, _| {
        assert!(!s.icon_images.choosing, "guard cleared after the panel");
        let b = s.edit_buffer().expect("still editing");
        assert!(b.icon_picker.is_some(), "picker stays open");
        assert!(
            b.item.icon.is_none() && b.icon_added.is_empty(),
            "cancel: nothing"
        );
        assert!(s.busy.is_none() && s.toast.is_none());
    });
    assert!(stored(&state, id, cx).attachments.is_empty());
    // After it closed, a click opens the panel again.
    state.update(cx, |s, cx| s.choose_icon(PickerCell::Image, cx));
    cx.run_until_parked();
    assert_eq!(calls.borrow().len(), 2);
}

#[gpui::test]
fn chosen_file_takes_the_drop_path(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, id, _) = setup(dir.path(), cx);
    let path = image_file(dir.path(), "logo.png", [9, 9, 9, 255]);
    fake_chooser(&state, Some(path), cx);
    state.update(cx, |s, cx| {
        s.begin_edit(cx);
        s.pick_icon_image(cx);
    });
    cx.run_until_parked();
    let a = state.read_with(cx, |s, _| {
        *s.edit_buffer().unwrap().icon_added.first().unwrap()
    });
    assert_eq!(ref_ids(&stored(&state, id, cx)), vec![a]);
    // A non-image that gets through the panel is still refused by the magic bytes.
    let fake_png = dir.path().join("fake.png");
    std::fs::write(&fake_png, b"%PDF-1.7").unwrap();
    fake_chooser(&state, Some(fake_png), cx);
    state.update(cx, |s, cx| {
        s.toast = None;
        s.pick_icon_image(cx);
    });
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert_eq!(
            s.toast.as_ref().map(|t| t.message.to_string()).as_deref(),
            Some(Refusal::Unreadable.message())
        );
        assert_eq!(s.edit_buffer().unwrap().icon_added.len(), 1);
    });
}

#[gpui::test]
fn only_regular_files_are_read(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, id, _) = setup(dir.path(), cx);
    state.update(cx, |s, cx| s.begin_edit(cx));
    // A folder named like an image (a package to the panel), a symlink to a real PNG,
    // and an oversized file.
    let folder = dir.path().join("photo.png");
    std::fs::create_dir(&folder).unwrap();
    std::fs::write(folder.join("inner.png"), png(4, 4, [1, 1, 1, 255])).unwrap();
    let real = image_file(dir.path(), "real.png", [2, 2, 2, 255]);
    let link = dir.path().join("link.png");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let big = dir.path().join("big.jpg");
    std::fs::write(&big, vec![0xFF; 600 * 1024]).unwrap();
    for (path, refusal) in [
        (folder, Refusal::Unreadable),
        (link, Refusal::Unreadable),
        (dir.path().join("missing.png"), Refusal::Unreadable),
        (big, Refusal::TooLarge),
    ] {
        // Through the panel path (a fake panel answering this path).
        fake_chooser(&state, Some(path.clone()), cx);
        state.update(cx, |s, cx| {
            s.toast = None;
            s.pick_icon_image(cx);
        });
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert_eq!(
                s.toast.as_ref().map(|t| t.message.to_string()).as_deref(),
                Some(refusal.message()),
                "{path:?}"
            );
            assert!(s.busy.is_none(), "nothing read: {path:?}");
            assert!(s.edit_buffer().unwrap().icon_added.is_empty());
        });
    }
    assert!(stored(&state, id, cx).attachments.is_empty());
    // The real file itself is fine.
    state.update(cx, |s, cx| s.set_icon_image_file(real, cx));
    cx.run_until_parked();
    assert_eq!(stored(&state, id, cx).attachments.len(), 1);
}
