//! Recently Deleted state: the 30-day sweep at unlock and before save, the expiry text.

use std::sync::Arc;

use gpui::{AppContext as _, Entity, TestAppContext};
use vault_core::{Item, KdfParams, SecretString, Uuid};
use vault_sync::{NoopHooks, SyncedVault};

use super::*;
use crate::state::Screen;

const DAY: u64 = 24 * 60 * 60 * 1000;

/// A saved vault file with a live item, an item deleted 31 days ago and one deleted 29
/// days ago (in that id order).
fn vault_file(dir: &std::path::Path) -> (std::path::PathBuf, [Uuid; 3]) {
    let path = dir.join("t.vault");
    let mut vault = SyncedVault::create(
        &path,
        &SecretString::new("pw".into()),
        KdfParams::for_tests(),
        Uuid::new_v4(),
        Arc::new(NoopHooks),
    )
    .unwrap();
    let now = text::now_millis();
    let ids = vault
        .edit(|v| {
            let device = v.device_id();
            let ids: Vec<Uuid> = ["Live", "Old", "Recent"]
                .into_iter()
                .map(|t| {
                    let mut item = Item::new(t, device, 1);
                    item.fields.push(vault_core::Field::new(
                        "username",
                        vault_core::FieldKind::Text,
                        SecretString::new("chris".into()),
                        1,
                    ));
                    v.insert(item, 1)
                })
                .collect();
            v.delete(ids[1], now - 31 * DAY).unwrap();
            v.delete(ids[2], now - 29 * DAY).unwrap();
            [ids[0], ids[1], ids[2]]
        })
        .unwrap();
    vault.save().unwrap();
    (vault.path().to_owned(), ids)
}

fn has_content(state: &Entity<AppState>, id: Uuid, cx: &mut TestAppContext) -> bool {
    state.read_with(cx, |s, _| {
        s.unlocked_vault().unwrap().get(id).unwrap().has_content()
    })
}

/// The 31-day-old item is stripped by the unlock itself (and saved), the 29-day-old one
/// stays in the trash.
#[gpui::test]
fn sweep_at_unlock_strips_31_days_and_keeps_29(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (path, [live, old, recent]) = vault_file(dir.path());
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, cx| s.open_vault(path.clone(), cx));
    cx.run_until_parked();
    state.update(cx, |s, cx| s.unlock(SecretString::new("pw".into()), cx));
    cx.run_until_parked();
    assert_eq!(state.read_with(cx, |s, _| s.screen), Screen::Main);
    assert!(!has_content(&state, old, cx));
    assert!(has_content(&state, recent, cx));
    assert!(has_content(&state, live, cx));
    state.read_with(cx, |s, _| {
        assert_eq!(s.counts.deleted, 1);
        assert!(
            s.vault.as_ref().unwrap().is_dirty(),
            "the strip must be saved"
        );
        assert!(s.autosave_pending, "the unlock scheduled the save");
    });

    // The scheduled autosave writes the stripped tombstone; nothing saves by hand.
    cx.executor().advance_clock(
        super::super::session::AUTOSAVE_DEBOUNCE + std::time::Duration::from_millis(50),
    );
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert!(!s.vault.as_ref().unwrap().is_dirty(), "autosaved");
    });
    let mut reopened = SyncedVault::open(&path, Uuid::new_v4(), Arc::new(NoopHooks)).unwrap();
    reopened.unlock(&SecretString::new("pw".into())).unwrap();
    let v = reopened.vault().unwrap();
    assert!(!v.get(old).unwrap().has_content());
    assert!(v.get(recent).unwrap().has_content());
}

/// Content past its 30 days that reaches memory after the unlock (a merge, here an edit
/// standing in for one) is stripped by the save, before it is written.
#[gpui::test]
fn sweep_runs_before_save(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (path, [live, _, recent]) = vault_file(dir.path());
    let mut vault = SyncedVault::open(&path, Uuid::new_v4(), Arc::new(NoopHooks)).unwrap();
    vault.unlock(&SecretString::new("pw".into())).unwrap();
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
    let now = text::now_millis();
    state.update(cx, |s, _| {
        s.vault
            .as_mut()
            .unwrap()
            .edit(|v| v.delete(live, now - 40 * DAY))
            .unwrap()
            .unwrap();
    });
    assert!(has_content(&state, live, cx));
    state.update(cx, |s, cx| s.save_now(cx));
    assert!(!has_content(&state, live, cx));
    assert!(has_content(&state, recent, cx));
    state.read_with(cx, |s, _| {
        assert!(!s.vault.as_ref().unwrap().is_dirty(), "saved");
    });
}

/// Bug hunt 2026-11-06: content past its 30 days that a peer's file brings back is
/// stripped by vault-sync's own merge write-back (the before-write hook), with no app save.
#[gpui::test]
fn expired_tombstone_from_a_peer_is_stripped_by_the_merge_write_back(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = vault_file(dir.path());
    let mut vault = SyncedVault::open(&path, Uuid::new_v4(), Arc::new(NoopHooks)).unwrap();
    vault.unlock(&SecretString::new("pw".into())).unwrap();
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, cx| {
        s.install_unlocked_for_tests(vault);
        s.save_now(cx);
    });
    let disk_has_content = |id| {
        let mut v = SyncedVault::open(&path, Uuid::new_v4(), Arc::new(NoopHooks)).unwrap();
        v.unlock(&SecretString::new("pw".into())).unwrap();
        v.vault().unwrap().get(id).unwrap().has_content()
    };
    // A peer without the sweep writes an item it deleted 40 days ago, content and all.
    let mut peer = SyncedVault::open(&path, Uuid::new_v4(), Arc::new(NoopHooks)).unwrap();
    peer.unlock(&SecretString::new("pw".into())).unwrap();
    let now = text::now_millis();
    let gone = peer
        .edit(|v| {
            let mut item = Item::new("Gone", v.device_id(), 1);
            item.fields.push(vault_core::Field::new(
                "password",
                vault_core::FieldKind::Password,
                SecretString::new("old".into()),
                1,
            ));
            let id = v.insert(item, 1);
            v.delete(id, now - 40 * DAY).unwrap();
            id
        })
        .unwrap();
    peer.save().unwrap();
    assert!(disk_has_content(gone));

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while state.read_with(cx, |s, _| s.unlocked_vault().unwrap().get(gone).is_none()) {
        assert!(
            std::time::Instant::now() < deadline,
            "peer write never merged"
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
        state.update(cx, |s, cx| s.poll_sync(cx));
    }
    assert!(!has_content(&state, gone, cx));
    state.read_with(cx, |s, _| {
        assert!(!s.autosave_pending, "no app save involved");
        assert!(!s.vault.as_ref().unwrap().is_dirty());
    });
    assert!(!disk_has_content(gone), "expired content stayed on disk");
}

/// Locked, the sweep does nothing (there is no vault to read, and it must not try).
#[gpui::test]
fn sweep_is_a_no_op_while_locked(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = vault_file(dir.path());
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, cx| s.open_vault(path, cx));
    cx.run_until_parked();
    state.update(cx, |s, _| {
        assert!(s.locked);
        assert_eq!(s.expire_trash(), 0);
        assert!(!s.vault.as_ref().unwrap().is_dirty());
    });
}

/// With nothing due the sweep changes nothing and does not mark a clean vault dirty.
#[gpui::test]
fn sweep_with_nothing_due_leaves_the_vault_clean(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = vault_file(dir.path());
    let mut vault = SyncedVault::open(&path, Uuid::new_v4(), Arc::new(NoopHooks)).unwrap();
    vault.unlock(&SecretString::new("pw".into())).unwrap();
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    // The install's unlock hook strips the 31-day item; save that.
    state.update(cx, |s, cx| {
        s.install_unlocked_for_tests(vault);
        s.save_now(cx);
    });
    state.update(cx, |s, _| {
        assert!(!s.vault.as_ref().unwrap().is_dirty());
        assert_eq!(s.expire_trash(), 0);
        assert!(!s.vault.as_ref().unwrap().is_dirty());
    });
}

#[test]
fn expiry_text_counts_whole_days_up() {
    let now = 1_000 * DAY;
    assert_eq!(
        expiry_text(now - 10 * DAY, now),
        "This item will be permanently deleted in 20 days unless it is recovered."
    );
    // 29 days and one hour left rounds up to 30.
    assert_eq!(days_left(now - DAY + 3_600_000, now), 30);
    assert_eq!(
        expiry_text(now - 29 * DAY - 1, now),
        "This item will be permanently deleted in 1 day unless it is recovered."
    );
    for due in [now - 30 * DAY, now - 45 * DAY, 0] {
        assert_eq!(
            expiry_text(due, now),
            "This item will be permanently deleted today unless it is recovered."
        );
    }
}

/// A `deleted_at` ahead of the clock (a peer's skewed clock) never panics or overflows,
/// and never promises more than 30 days.
#[test]
fn expiry_text_saturates_a_far_future_deleted_at() {
    let now = 1_000 * DAY;
    for at in [now + 400 * DAY, u64::MAX - 1, u64::MAX] {
        assert_eq!(days_left(at, now), 30);
        assert_eq!(
            expiry_text(at, now),
            "This item will be permanently deleted in 30 days unless it is recovered."
        );
    }
    assert_eq!(days_left(u64::MAX, 0), 30);
}

/// A title-only item (title and a tag, no fields) deleted in the app lands in Recently
/// Deleted, recovers with its title and tag, and a stripped tombstone is not listed.
#[gpui::test]
fn title_only_item_is_trashed_and_recovers_but_a_tombstone_is_not_listed(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.vault");
    let mut vault = SyncedVault::create(
        &path,
        &SecretString::new("pw".into()),
        KdfParams::for_tests(),
        Uuid::new_v4(),
        Arc::new(NoopHooks),
    )
    .unwrap();
    let [bare, gone] = vault
        .edit(|v| {
            let device = v.device_id();
            ["Bare", "Gone"].map(|t| {
                let mut item = Item::new(t, device, 1);
                item.tags.push("work".into());
                v.insert(item, 1)
            })
        })
        .unwrap();
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, _| s.install_unlocked_for_tests(vault));

    // Delete both from the app; the second is then purged to a stripped tombstone.
    for id in [bare, gone] {
        state.update(cx, |s, cx| {
            s.select(id, cx);
            s.request_delete(cx);
            s.confirm_delete(cx);
        });
    }
    state.update(cx, |s, cx| {
        s.set_filter(Filter::RecentlyDeleted, cx);
        s.select(gone, cx);
        s.request_delete(cx);
        s.confirm_delete(cx);
    });
    state.read_with(cx, |s, _| {
        assert_eq!(
            s.listing.items,
            [bare],
            "title-only item listed, tombstone not"
        );
        assert_eq!(s.counts.deleted, 1);
        let v = s.unlocked_vault().unwrap();
        assert!(v.get(bare).unwrap().is_trashed());
        assert!(!v.get(gone).unwrap().is_trashed());
    });
    state.update(cx, |s, cx| {
        s.select(bare, cx);
        assert_eq!(s.trashed_item().map(|i| i.id), Some(bare));
        s.recover_selected(cx);
    });
    state.read_with(cx, |s, _| {
        let item = s.unlocked_vault().unwrap().get(bare).unwrap();
        assert!(!item.is_deleted());
        assert_eq!(item.title, "Bare");
        assert_eq!(item.tags, ["work"]);
        assert_eq!(s.counts.deleted, 0);
    });
}
