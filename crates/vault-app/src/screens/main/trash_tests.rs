//! Headless render tests for Recently Deleted (05 §2.3): sidebar row, list, read-only
//! detail with its expiry card, Recover, Delete permanently, the All Items confirm text.

use std::sync::Arc;

use gpui::{AppContext as _, Entity, OwnedMenuItem, TestAppContext, VisualTestContext};
use gpui_component::Root;
use vault_core::{Field, FieldKind, Item, KdfParams, SecretString, Uuid};
use vault_sync::{NoopHooks, SyncedVault};

use super::MainScreen;
use crate::actions::{self, DeleteItem};
use crate::clipboard::fake::FakePasteboard;
use crate::state::{AppState, Filter, NO_DELETED_ITEMS, TRASH_INFO};
use crate::text;

const DAY: u64 = 24 * 60 * 60 * 1000;
const TRASH_ROW: &str = "nav Recently Deleted icon=Trash";

fn login(title: &str, device: Uuid) -> Item {
    let mut item = Item::new(title, device, 1);
    item.fields.push(Field::new(
        "username",
        FieldKind::Text,
        SecretString::new("chris".into()),
        1,
    ));
    item.fields.push(Field::new(
        "password",
        FieldKind::Password,
        SecretString::new("hunter2-pw".into()),
        1,
    ));
    item
}

/// The main screen over logins `titles`; `deleted[i]` days ago (if `Some`) trashes the
/// i-th. Menus installed, a fake pasteboard in place.
fn open(
    dir: &std::path::Path,
    items: &[(&str, Option<u64>)],
    cx: &mut TestAppContext,
) -> (
    Entity<AppState>,
    Vec<Uuid>,
    FakePasteboard,
    VisualTestContext,
) {
    let mut vault = SyncedVault::create(
        &dir.join("t.vault"),
        &SecretString::new("pw".into()),
        KdfParams::for_tests(),
        Uuid::new_v4(),
        Arc::new(NoopHooks),
    )
    .unwrap();
    let now = text::now_millis();
    let ids = vault
        .edit(|v| {
            items
                .iter()
                .map(|(title, days)| {
                    let id = v.insert(login(title, v.device_id()), 1);
                    if let Some(days) = days {
                        v.delete(id, now - days * DAY).unwrap();
                    }
                    id
                })
                .collect::<Vec<_>>()
        })
        .unwrap();
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    cx.update(|cx| {
        gpui_component::init(cx);
        actions::bind_keys(cx);
        actions::register(&state, cx);
        actions::set_menus(Default::default(), true, cx);
    });
    state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
    let mut main = None;
    let window = cx.add_window(|window, cx| {
        crate::theme::apply(window, cx);
        let view = cx.new(|cx| MainScreen::new(state.clone(), None, window, cx));
        main = Some(view.clone());
        Root::new(view, window, cx)
    });
    let mut vcx = VisualTestContext::from_window(window.into(), cx);
    let main = main.unwrap();
    vcx.update(|window, cx| main.update(cx, |m, cx| m.appear(window, cx)));
    let board = FakePasteboard::default();
    vcx.update(|_, cx| state.update(cx, |s, _| s.set_pasteboard(Box::new(board.clone()))));
    vcx.run_until_parked();
    (state, ids, board, vcx)
}

fn show_trash(state: &Entity<AppState>, vcx: &mut VisualTestContext) {
    vcx.update(|_, cx| state.update(cx, |s, cx| s.set_filter(Filter::RecentlyDeleted, cx)));
    vcx.run_until_parked();
}

fn shown(key: &str, vcx: &mut VisualTestContext) -> bool {
    let key: &'static str = Box::leak(key.to_owned().into_boxed_str());
    vcx.debug_bounds(key).is_some()
}

fn click(key: &'static str, vcx: &mut VisualTestContext) {
    let at = vcx.debug_bounds(key).expect(key).center();
    vcx.simulate_click(at, gpui::Modifiers::none());
    vcx.run_until_parked();
}

fn item_menu(vcx: &mut VisualTestContext) -> Vec<String> {
    let menus = vcx.update(|_, cx| cx.get_menus()).expect("menus installed");
    let item = menus.into_iter().find(|m| m.name == "Item").unwrap();
    item.items
        .into_iter()
        .filter_map(|i| match i {
            OwnedMenuItem::Action { name, .. } => Some(name),
            _ => None,
        })
        .collect()
}

/// The row sits below Favorites while the trash has items, with their count; it is
/// absent for an empty trash, and emptying the trash while it shows falls back to All.
#[gpui::test]
fn sidebar_row_follows_the_trash_count(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, _, mut vcx) = open(dir.path(), &[("Live", None), ("Gone", Some(1))], cx);
    let fav = vcx.debug_bounds("nav Favorites icon=Star").unwrap();
    let row = vcx.debug_bounds(TRASH_ROW).expect("trash row");
    assert!(row.top() > fav.top());
    state.read_with(&vcx, |s, _| {
        assert_eq!((s.counts.all, s.counts.deleted), (1, 1))
    });

    show_trash(&state, &mut vcx);
    vcx.update(|_, cx| state.update(cx, |s, cx| s.select(ids[1], cx)));
    vcx.simulate_keystrokes("cmd-shift-z");
    vcx.run_until_parked();
    assert!(!shown(TRASH_ROW, &mut vcx), "hidden at 0");
    state.read_with(&vcx, |s, _| assert_eq!(s.filter, Filter::All));

    let dir = tempfile::tempdir().unwrap();
    let (_, _, _, mut vcx) = open(dir.path(), &[("Live", None)], cx);
    assert!(!shown(TRASH_ROW, &mut vcx));
}

/// Newest deletion first, the info card above the rows, search applies, the collapsed
/// heading names the filter; an empty search shows "No results" with nothing to create.
#[gpui::test]
fn trash_list_contents_and_order(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, _, mut vcx) = open(
        dir.path(),
        &[("Live", None), ("Older", Some(5)), ("Newer", Some(2))],
        cx,
    );
    assert!(!shown("trash-info", &mut vcx));
    show_trash(&state, &mut vcx);
    state.read_with(&vcx, |s, _| {
        assert_eq!(s.listing.items, [ids[2], ids[1]]);
        assert_eq!(s.selection, Some(ids[2]));
        assert_eq!(
            super::list::filter_heading(s),
            ("Recently Deleted".into(), 2)
        );
        assert_eq!(super::list_placeholder(s), None);
    });
    assert!(shown("trash-info", &mut vcx));
    vcx.update(|_, cx| state.update(cx, |s, cx| s.set_query("old".into(), cx)));
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| assert_eq!(s.listing.items, [ids[1]]));
    vcx.update(|_, cx| state.update(cx, |s, cx| s.set_query("zzz".into(), cx)));
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert_eq!(super::list_placeholder(s), Some(super::list::NO_RESULTS));
    });
    assert!(!shown("empty-create", &mut vcx));
}

/// The empty state (only reachable before the fallback to All Items applies): trash
/// glyph, "No Deleted Items" and the retention sentence.
#[gpui::test]
fn trash_empty_state(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, _, mut vcx) = open(dir.path(), &[("Live", None)], cx);
    vcx.update(|_, cx| {
        state.update(cx, |s, cx| {
            s.filter = Filter::RecentlyDeleted;
            s.refresh();
            cx.notify();
        })
    });
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert_eq!(super::list_placeholder(s), Some(NO_DELETED_ITEMS));
    });
    assert!(shown("trash-empty", &mut vcx));
    assert!(
        !shown("trash-info", &mut vcx),
        "the card sits above rows only"
    );
    assert_eq!(
        TRASH_INFO,
        "Deleted items are available here for 30 days before they are permanently deleted."
    );
}

/// The trashed item's detail: no header buttons, ⌘E / ⌘D do nothing (no toast), copy
/// on click still works, and the card counts down the days left.
#[gpui::test]
fn trashed_detail_is_read_only_with_the_expiry_card(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, board, mut vcx) = open(dir.path(), &[("Gone", Some(10))], cx);
    show_trash(&state, &mut vcx);
    assert!(shown("detail-title Gone", &mut vcx));
    assert!(!shown("detail-header-buttons", &mut vcx));
    assert!(shown(
        "trash-expiry This item will be permanently deleted in 20 days unless it is recovered.",
        &mut vcx
    ));
    assert!(shown("trash-delete", &mut vcx) && shown("trash-recover", &mut vcx));

    vcx.simulate_keystrokes("cmd-e cmd-d");
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert!(!s.is_editing());
        assert!(s.toast.is_none(), "no toast");
        let item = s.unlocked_vault().unwrap().get(ids[0]).unwrap();
        assert!(!item.favorite && item.is_deleted());
        assert!(!s.can_attach());
    });

    click("field-value 1", &mut vcx);
    assert_eq!(board.contents().as_deref(), Some("hunter2-pw"));
    assert!(shown("field-masked 1", &mut vcx), "copied, still masked");
}

/// 0 days left reads "today"; a `deleted_at` ahead of the clock reads 30 days.
#[gpui::test]
fn expiry_card_today_and_far_future(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, _, mut vcx) = open(
        dir.path(),
        &[("A", Some(1)), ("B", Some(2)), ("Due", None)],
        cx,
    );
    let now = text::now_millis();
    vcx.update(|_, cx| {
        state.update(cx, |s, _| {
            s.vault
                .as_mut()
                .unwrap()
                .edit(|v| {
                    // Re-deleting a trashed item moves `deleted_at` forward.
                    v.delete(ids[0], now + 400 * DAY).unwrap();
                    // Aged past 30 days during the session: due, not swept until a save.
                    v.delete(ids[2], now - 31 * DAY).unwrap();
                })
                .unwrap();
            s.vault_changed();
        })
    });
    show_trash(&state, &mut vcx);
    vcx.update(|_, cx| state.update(cx, |s, cx| s.select(ids[0], cx)));
    vcx.run_until_parked();
    assert!(shown(
        "trash-expiry This item will be permanently deleted in 30 days unless it is recovered.",
        &mut vcx
    ));
    vcx.update(|_, cx| state.update(cx, |s, cx| s.select(ids[2], cx)));
    vcx.run_until_parked();
    assert!(shown(
        "trash-expiry This item will be permanently deleted today unless it is recovered.",
        &mut vcx
    ));
}

/// Recover (button, ⌘⇧Z in the menu): back in All Items and selected; autosave queued.
#[gpui::test]
fn recover_round_trip(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, _, mut vcx) = open(
        dir.path(),
        &[("Live", None), ("Gone", Some(3)), ("Also", Some(4))],
        cx,
    );
    assert!(!item_menu(&mut vcx).contains(&"Recover".to_owned()));
    show_trash(&state, &mut vcx);
    let menu = item_menu(&mut vcx);
    assert!(menu.contains(&"Recover".to_owned()), "{menu:?}");
    assert!(menu.contains(&"Delete Permanently\u{2026}".to_owned()));
    assert!(!menu.contains(&"Delete\u{2026}".to_owned()));

    click("trash-recover", &mut vcx);
    state.read_with(&vcx, |s, _| {
        assert_eq!(s.filter, Filter::All);
        assert_eq!(s.selection, Some(ids[1]));
        assert!(s.listing.items.contains(&ids[1]));
        assert!(
            !s.unlocked_vault()
                .unwrap()
                .get(ids[1])
                .unwrap()
                .is_deleted()
        );
        assert_eq!((s.counts.all, s.counts.deleted), (2, 1));
        assert!(s.vault.as_ref().unwrap().is_dirty(), "autosave pending");
    });
    assert!(shown(TRASH_ROW, &mut vcx), "one left");
    let menu = item_menu(&mut vcx);
    assert!(!menu.contains(&"Recover".to_owned()), "{menu:?}");
    assert!(menu.contains(&"Delete\u{2026}".to_owned()));
}

/// Delete permanently (button, then the confirm): content gone, next row selected,
/// counts updated.
#[gpui::test]
fn delete_permanently_round_trip(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, _, mut vcx) = open(
        dir.path(),
        &[("Live", None), ("First", Some(1)), ("Second", Some(2))],
        cx,
    );
    show_trash(&state, &mut vcx);
    state.read_with(&vcx, |s, _| assert_eq!(s.selection, Some(ids[1])));
    click("trash-delete", &mut vcx);
    assert!(shown(
        "confirm-text Delete permanently? This cannot be undone.",
        &mut vcx
    ));
    click("delete-confirm", &mut vcx);
    state.read_with(&vcx, |s, _| {
        let v = s.unlocked_vault().unwrap();
        assert!(!v.get(ids[1]).unwrap().has_content());
        assert_eq!(s.listing.items, [ids[2]]);
        assert_eq!(s.selection, Some(ids[2]));
        assert_eq!((s.counts.all, s.counts.deleted), (1, 1));
        assert!(s.vault.as_ref().unwrap().is_dirty(), "autosave pending");
    });

    // ⌘⌫ (DeleteItem) is the same path; the last one empties the trash.
    vcx.dispatch_action(DeleteItem);
    vcx.run_until_parked();
    click("delete-confirm", &mut vcx);
    state.read_with(&vcx, |s, _| {
        assert!(
            !s.unlocked_vault()
                .unwrap()
                .get(ids[2])
                .unwrap()
                .has_content()
        );
        assert_eq!(s.counts.deleted, 0);
        assert_eq!(s.filter, Filter::All);
        // The emptied trash selects nothing, not some live item of All Items.
        assert_eq!(s.selection, None);
        assert!(
            !s.unlocked_vault()
                .unwrap()
                .get(ids[0])
                .unwrap()
                .is_deleted()
        );
    });
    assert!(!shown(TRASH_ROW, &mut vcx));
}

/// 05 §2.3: in the pinned header the order is title, expiry card, (after the card's
/// Delete) the red confirm, tags, rule; the fields scroll beneath.
#[gpui::test]
fn expiry_card_and_confirm_sit_between_title_and_tags(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, _, mut vcx) = open(dir.path(), &[("Gone", None)], cx);
    let now = text::now_millis();
    vcx.update(|_, cx| {
        state.update(cx, |s, _| {
            s.vault
                .as_mut()
                .unwrap()
                .edit(|v| {
                    v.update(ids[0], now, |item| item.tags = vec!["work".into()])
                        .unwrap();
                    v.delete(ids[0], now - DAY).unwrap();
                })
                .unwrap();
            s.vault_changed();
        })
    });
    show_trash(&state, &mut vcx);
    fn bounds(key: &'static str, vcx: &mut VisualTestContext) -> gpui::Bounds<gpui::Pixels> {
        vcx.debug_bounds(key).expect(key)
    }
    let title = bounds("detail-title Gone", &mut vcx);
    let card = bounds("trash-card", &mut vcx);
    let tags = bounds("detail-tags", &mut vcx);
    let rule = bounds("detail-fields-rule", &mut vcx);
    let pinned = bounds("detail-pinned", &mut vcx);
    assert!(title.bottom() <= card.top(), "{title:?} {card:?}");
    assert!(card.bottom() <= tags.top(), "{card:?} {tags:?}");
    assert!(tags.bottom() <= rule.top());
    assert!(pinned.top() <= card.top() && card.bottom() <= pinned.bottom());
    assert!(rule.bottom() <= bounds("field-value 1", &mut vcx).top());
    let confirm = "confirm-text Delete permanently? This cannot be undone.";
    assert!(!shown(confirm, &mut vcx));

    click("trash-delete", &mut vcx);
    let card = bounds("trash-card", &mut vcx);
    let text = bounds(confirm, &mut vcx);
    let button = bounds("delete-confirm", &mut vcx);
    let tags = bounds("detail-tags", &mut vcx);
    assert!(card.bottom() <= text.top(), "{card:?} {text:?}");
    assert!(text.bottom() <= tags.top() && button.bottom() <= tags.top());
    assert_eq!(
        bounds("detail-title Gone", &mut vcx),
        title,
        "title stays put"
    );
}

/// The All Items ⌘⌫ confirm says where the item goes.
#[gpui::test]
fn all_items_delete_confirm_mentions_recently_deleted(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, _, mut vcx) = open(dir.path(), &[("Live", None)], cx);
    vcx.dispatch_action(DeleteItem);
    vcx.run_until_parked();
    assert!(shown("confirm-text Delete \u{2018}Live\u{2019}?", &mut vcx));
    assert!(shown(
        "confirm-detail You can recover it from Recently Deleted for 30 days.",
        &mut vcx
    ));
    click("delete-confirm", &mut vcx);
    state.read_with(&vcx, |s, _| {
        let item = s.unlocked_vault().unwrap().get(ids[0]).unwrap();
        assert!(item.is_deleted() && item.has_content(), "in the trash");
        assert_eq!((s.counts.all, s.counts.deleted), (0, 1));
    });
    assert!(shown(TRASH_ROW, &mut vcx));
}

/// A trashed item keeps its custom image icon in the trash row and detail header; once
/// deleted permanently the image is no longer wanted and leaves the cache.
#[gpui::test]
fn trashed_item_keeps_its_image_icon_until_purged(cx: &mut TestAppContext) {
    use crate::state::AttachmentStore as _;
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, _, mut vcx) = open(dir.path(), &[("Live", None), ("Bank", None)], cx);
    let store = crate::state::attachments_fake();
    let bytes = crate::icon_image::test_images::png(40, 20, [0, 90, 200, 255]);
    let a = state.update(&mut vcx, |s, cx| {
        s.set_attachment_store(store.clone());
        let vault = s.vault.as_mut().unwrap();
        let a = store
            .add(
                vault,
                ids[1],
                "icon.png",
                &mut &bytes[..],
                bytes.len() as u64,
                11,
            )
            .unwrap();
        vault
            .edit(|v| {
                v.update(ids[1], 12, |it| it.icon = Some(crate::icon::image_icon(a)))?;
                v.delete(ids[1], text::now_millis() - DAY)
            })
            .unwrap()
            .unwrap();
        s.vault_changed();
        cx.notify();
        a
    });
    vcx.run_until_parked();
    show_trash(&state, &mut vcx);
    state.read_with(&vcx, |s, _| {
        assert_eq!(s.listing.items, [ids[1]]);
        assert!(s.icon_images.is_cached(a), "trashed icon decoded");
    });
    let tile: &'static str = Box::leak(format!("icon-tile image {a}").into_boxed_str());
    // Selected: the detail header (44 px, painted after the list) carries it.
    let header = vcx
        .debug_bounds(tile)
        .expect("trashed detail shows the image icon");
    assert_eq!(header.size.width, gpui::px(44.));
    // Nothing selected: only the trash row (32 px) draws it.
    state.update(&mut vcx, |s, cx| {
        s.selection = None;
        cx.notify();
    });
    vcx.run_until_parked();
    let row = vcx
        .debug_bounds(tile)
        .expect("trash row shows the image icon");
    assert_eq!(row.size.width, gpui::px(32.));
    state.update(&mut vcx, |s, cx| {
        s.selection = Some(ids[1]);
        cx.notify();
    });
    vcx.run_until_parked();

    click("trash-delete", &mut vcx);
    click("delete-confirm", &mut vcx);
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert!(!s.icon_images.is_cached(a), "purged icon no longer wanted");
    });
    assert!(vcx.debug_bounds(tile).is_none());
}
