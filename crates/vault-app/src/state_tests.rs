use super::*;
use gpui::{AppContext as _, TestAppContext};
use std::sync::Arc;
use vault_core::{Item, SecretString};
use vault_sync::NoopHooks;

fn create(dir: &Path) -> SyncedVault {
    SyncedVault::create(
        &dir.join("t.vault"),
        &SecretString::new(PW.into()),
        KdfParams::for_tests(),
        Uuid::new_v4(),
        Arc::new(NoopHooks),
    )
    .expect("create vault")
}

#[gpui::test]
fn lock_clears_session_state(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, _| {
        s.install(create(dir.path()), false);
        s.unlocked();
        s.selection = Some(Uuid::new_v4());
        let device = s.device_id();
        s.mode = Mode::Edit(EditBuffer::new(Item::new("x", device, 1)));
    });
    state.update(cx, |s, cx| s.lock(cx));
    state.read_with(cx, |s, _| {
        assert!(s.locked);
        assert_eq!(s.screen, Screen::Unlock);
        assert!(s.selection.is_none());
        assert!(matches!(s.mode, Mode::View));
        let vault = s.vault.as_ref().expect("vault kept, only locked");
        assert!(vault.vault().is_none(), "keys dropped");
    });
    // Rapid repeat and locking with no vault at all must be harmless.
    state.update(cx, |s, cx| {
        s.lock(cx);
        s.close_vault(cx);
        s.lock(cx);
    });
    state.read_with(cx, |s, _| {
        assert!(s.vault.is_none());
        assert_eq!(s.screen, Screen::Choose);
    });
}

#[gpui::test]
fn auto_lock_uses_shorter_idle(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, cx| {
        s.install(create(dir.path()), false);
        s.unlocked();
        s.settings.auto_lock_minutes = Some(1);
        // Recent in-app activity keeps it open even if the system says idle.
        s.tick(3600.0, cx);
        assert!(!s.locked);
        s.last_activity = Instant::now() - Duration::from_secs(120);
        s.tick(30.0, cx);
        assert!(!s.locked);
        s.tick(61.0, cx);
        assert!(s.locked);
    });
}

#[gpui::test]
fn lock_during_unlock_wins(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let path = create(dir.path()).path().to_owned();
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, cx| s.open_vault(path.clone(), cx));
    cx.run_until_parked();
    state.read_with(cx, |s, _| assert_eq!(s.screen, Screen::Unlock));

    state.update(cx, |s, cx| s.unlock(SecretString::new("nope".into()), cx));
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert!(s.locked);
        assert_eq!(s.unlock_failures, 1);
        assert!(s.error.is_some());
    });

    state.update(cx, |s, cx| {
        s.unlock(SecretString::new("correct horse".into()), cx);
        s.lock(cx);
    });
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert!(s.locked, "a lock issued mid-unlock must win");
        assert_eq!(s.screen, Screen::Unlock);
        assert!(s.vault.as_ref().is_some_and(|v| v.vault().is_none()));
        assert_eq!(s.vault_path.as_deref(), Some(path.as_path()));
    });

    state.update(cx, |s, cx| {
        s.unlock(SecretString::new("correct horse".into()), cx)
    });
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert!(!s.locked);
        assert_eq!(s.screen, Screen::Main);
        assert_eq!(s.item_count(), 0);
    });
}

const PW: &str = "correct horse";

fn new_state(cx: &mut TestAppContext) -> gpui::Entity<AppState> {
    cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false))
}

fn open_and_unlock(state: &gpui::Entity<AppState>, path: &Path, cx: &mut TestAppContext) {
    let path = path.to_owned();
    state.update(cx, |s, cx| s.open_vault(path, cx));
    cx.run_until_parked();
    state.update(cx, |s, cx| s.unlock(SecretString::new(PW.into()), cx));
    cx.run_until_parked();
    state.read_with(cx, |s, _| assert!(!s.locked));
}

#[gpui::test]
fn lock_during_create_wins(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new.vault");
    let state = new_state(cx);
    state.update(cx, |s, cx| {
        s.create_vault(path.clone(), SecretString::new(PW.into()), cx);
        assert_eq!(s.busy, Some(Busy::Calibrating));
        s.lock(cx);
    });
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert!(s.locked, "a lock issued mid-create must win");
        assert_eq!(s.screen, Screen::Unlock);
        assert!(s.busy.is_none());
        assert!(s.vault.as_ref().is_some_and(|v| v.vault().is_none()));
        assert_eq!(s.recent_vaults, vec![path.clone()]);
    });
    assert!(path.exists());
}

#[gpui::test]
fn lock_saves_dirty_edits(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let path = create(dir.path()).path().to_owned();
    let state = new_state(cx);
    open_and_unlock(&state, &path, cx);
    state.update(cx, |s, cx| {
        let vault = s.vault.as_mut().unwrap();
        let device = vault.device_id();
        vault
            .edit(|v| v.insert(Item::new("GitHub", device, 1), 1))
            .unwrap();
        assert!(vault.is_dirty());
        s.lock(cx);
    });
    // A fresh state reads the file from disk, so this proves the save happened.
    let reopened = new_state(cx);
    open_and_unlock(&reopened, &path, cx);
    reopened.read_with(cx, |s, _| {
        let titles: Vec<_> = s
            .vault
            .as_ref()
            .and_then(SyncedVault::vault)
            .unwrap()
            .items()
            .map(|i| i.title.clone())
            .collect();
        assert_eq!(titles, ["GitHub"]);
    });
}

#[gpui::test]
fn missing_vault_is_dropped_from_recents(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let gone = dir.path().join("gone.vault");
    let kept = dir.path().join("kept.vault");
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), vec![gone.clone(), kept.clone()], false));
    state.update(cx, |s, cx| s.open_vault(gone.clone(), cx));
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert_eq!(s.recent_vaults, vec![kept.clone()]);
        assert_eq!(s.screen, Screen::Choose);
        assert!(s.error.is_some());
        assert!(s.busy.is_none());
    });
}

/// The open panel allows folders; one without vault.bin is refused inline and kept
/// out of recents.
#[gpui::test]
fn folder_without_vault_bin_is_not_a_package(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("Photos.vault");
    std::fs::create_dir(&folder).unwrap();
    let state = new_state(cx);
    state.update(cx, |s, cx| s.open_vault(folder.clone(), cx));
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert_eq!(s.error.as_deref(), Some(NOT_A_PACKAGE));
        assert_eq!(s.screen, Screen::Choose);
        assert!(s.vault.is_none());
        assert!(s.recent_vaults.is_empty());
    });
}

/// A plain file picked in the open panel (not in recents) is "not a package", and is
/// neither flagged as a legacy recent nor remembered.
#[gpui::test]
fn picked_plain_file_is_not_a_package(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();
    let state = new_state(cx);
    state.update(cx, |s, cx| s.open_vault(file.clone(), cx));
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert_eq!(s.error.as_deref(), Some(NOT_A_PACKAGE));
        assert!(s.legacy_recents.is_empty());
        assert!(s.recent_vaults.is_empty());
        assert!(s.vault.is_none());
    });
}

/// A recent entry in the old single-file layout is flagged, refused, and kept listed.
#[gpui::test]
fn legacy_file_in_recents_is_refused(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("Old.vault");
    std::fs::write(&old, b"VLT1 pre-package vault").unwrap();
    let package = create(dir.path()).path().to_owned();
    let state =
        cx.new(|_| AppState::new(Uuid::new_v4(), vec![old.clone(), package.clone()], false));
    state.read_with(cx, |s, _| {
        assert!(s.legacy_recents.contains(&old));
        assert!(!s.legacy_recents.contains(&package));
    });
    state.update(cx, |s, cx| s.open_vault(old.clone(), cx));
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert_eq!(s.error.as_deref(), Some(LEGACY_LAYOUT));
        assert!(s.vault.is_none());
        assert_eq!(s.recent_vaults, vec![old.clone(), package.clone()]);
    });
}

#[gpui::test]
fn close_during_unlock_discards_result(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let path = create(dir.path()).path().to_owned();
    let state = new_state(cx);
    state.update(cx, |s, cx| s.open_vault(path.clone(), cx));
    cx.run_until_parked();
    state.update(cx, |s, cx| {
        s.unlock(SecretString::new(PW.into()), cx);
        s.switch_vault(ChooseIntent::Home, cx);
    });
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert!(s.vault.is_none(), "stale unlock result must be dropped");
        assert!(s.vault_path.is_none());
        assert!(s.locked);
        assert_eq!(s.screen, Screen::Choose);
        assert_eq!(s.choose_request, Some(ChooseIntent::Home));
    });
}

/// Opens a vault, adds an unsaved item and makes the package folder read-only, so the
/// save right before a lock fails. With `backups_too`, the Unsaved backup fails as well.
fn lock_with_failing_disk(backups_too: bool, cx: &mut TestAppContext) -> Option<Toast> {
    locked_with_failing_disk(backups_too, cx)
        .0
        .read_with(cx, |s, _| s.toast.clone())
}

/// [`lock_with_failing_disk`], returning the locked state (and its temp dir).
fn locked_with_failing_disk(
    backups_too: bool,
    cx: &mut TestAppContext,
) -> (gpui::Entity<AppState>, tempfile::TempDir) {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = create(dir.path()).path().to_owned();
    let backups = path.join("backups");
    std::fs::create_dir_all(&backups).unwrap();
    let state = new_state(cx);
    open_and_unlock(&state, &path, cx);
    let read_only = |p: &Path, mode| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    state.update(cx, |s, cx| {
        let vault = s.vault.as_mut().unwrap();
        let device = vault.device_id();
        vault
            .edit(|v| v.insert(Item::new("GitHub", device, 1), 1))
            .unwrap();
        read_only(&path, 0o500);
        if backups_too {
            read_only(&backups, 0o500);
        }
        s.lock(cx);
        // vault-sync's SyncEvent::Error fallback must not replace the lock toast.
        s.poll_sync(cx);
    });
    read_only(&backups, 0o700);
    read_only(&path, 0o700);
    state.read_with(cx, |s, _| assert!(s.locked));
    (state, dir)
}

#[gpui::test]
fn danger_toast_outlives_later_toasts_until_its_ttl(cx: &mut TestAppContext) {
    let (state, _dir) = locked_with_failing_disk(true, cx);
    state.update(cx, |s, cx| {
        // No window in this test: held until one opens, and later ordinary text is
        // dropped, not appended.
        assert!(s.toast_held);
        s.show_toast("Copied", cx);
        assert!(!s.toast.as_ref().unwrap().message.contains("Copied"));
        s.release_held_toast(cx);

        s.show_toast("Copied", cx);
        s.handle_sync_event(SyncEvent::ForeignVault, cx);
        s.handle_sync_event(SyncEvent::Error("boom".into()), cx);
        // A second lock (auto-lock while locked) keeps it too.
        s.lock(cx);
        let toast = s.toast.as_ref().expect("still up");
        assert!(toast.danger);
        assert!(toast.message.starts_with(LOCK_LOST), "{}", toast.message);
        assert!(
            toast.message.contains("Copied"),
            "shown: later text is appended"
        );
        assert_eq!(toast.ttl, Duration::from_secs(10));
        s.release_held_toast(cx);
        // Its 10 s run out: the tick removes it and ordinary toasts show again.
        s.toast.as_mut().unwrap().shown_at -= Duration::from_secs(11);
        s.tick(0.0, cx);
        assert!(s.toast.is_none());
        s.show_toast("Copied", cx);
        assert_eq!(s.toast.as_ref().unwrap().message.as_ref(), "Copied");
    });
}

#[gpui::test]
fn lock_toast_reports_a_kept_snapshot(cx: &mut TestAppContext) {
    let toast = lock_with_failing_disk(false, cx).expect("a toast");
    assert!(!toast.danger);
    assert!(
        toast.message.starts_with("Could not save before locking"),
        "{}",
        toast.message
    );
    assert!(toast.message.ends_with(LOCK_KEPT), "{}", toast.message);
}

#[gpui::test]
fn lock_toast_never_claims_unpreserved_edits_were_kept(cx: &mut TestAppContext) {
    let toast = lock_with_failing_disk(true, cx).expect("a toast");
    assert!(toast.danger);
    assert_eq!(toast.message.as_ref(), LOCK_LOST);
    assert!(!toast.message.contains("kept"));
}

#[test]
fn lock_toast_texts() {
    let path = PathBuf::from("b.vault");
    assert!(lock_toast(None, &LockOutcome::Clean).is_none());
    let kept = lock_toast(None, &LockOutcome::Snapshotted(path)).unwrap();
    assert_eq!((kept.message.as_ref(), kept.danger), (LOCK_KEPT, false));
    let failed = lock_toast(Some("disk full"), &LockOutcome::Clean).unwrap();
    assert_eq!(
        failed.message.as_ref(),
        "Could not save before locking (disk full)."
    );
}

/// ⌘1 … ⌘9 (05 §2.3): All Items, Favorites, Recently Deleted only while the trash is
/// not empty, then the tags only while the Tags section is open; nothing past the end.
#[test]
fn sidebar_row_filter_follows_display_order() {
    use crate::listing::Counts;
    let tag = |t: &str| Some(Filter::Tag(t.into()));
    let tags = vec![("Work".to_string(), 2), ("home".to_string(), 1)];
    // (trash count, tags open, n, expected)
    let table = [
        // No trash, tags open.
        (0, true, 1, Some(Filter::All)),
        (0, true, 2, Some(Filter::Favorites)),
        (0, true, 3, tag("Work")),
        (0, true, 4, tag("home")),
        (0, true, 5, None),
        // Trash present: Recently Deleted third, tags shift by one.
        (3, true, 3, Some(Filter::RecentlyDeleted)),
        (3, true, 4, tag("Work")),
        (3, true, 5, tag("home")),
        (3, true, 6, None),
        // Tags collapsed: nothing past Favorites / Recently Deleted.
        (0, false, 2, Some(Filter::Favorites)),
        (0, false, 3, None),
        (3, false, 3, Some(Filter::RecentlyDeleted)),
        (3, false, 4, None),
        // Out of range.
        (0, true, 0, None),
        (3, true, 9, None),
    ];
    let mut s = AppState::new(Uuid::new_v4(), Vec::new(), false);
    for (deleted, open, n, want) in table {
        s.counts = Counts {
            all: 5,
            favorites: 1,
            deleted,
            tags: tags.clone(),
        };
        s.tags_open = open;
        assert_eq!(
            s.sidebar_row_filter(n),
            want,
            "trash={deleted} open={open} n={n}"
        );
    }
}

/// Opens a main window (the `VaultRoot` every `open_main_window` caller builds).
fn open_main_window(state: &gpui::Entity<AppState>, cx: &mut TestAppContext) {
    cx.update(gpui_component::init);
    let state = state.clone();
    cx.add_window(|window, cx| {
        crate::theme::apply(window, cx);
        let view = cx.new(|cx| crate::root::VaultRoot::new(state, None, window, cx));
        gpui_component::Root::new(view, window, cx)
    });
    cx.run_until_parked();
}

/// 05 §3 "Toasts without a window": no main window, so the toast's clock does not run.
#[gpui::test]
fn toast_without_a_window_is_held(cx: &mut TestAppContext) {
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, cx| {
        s.show_toast("Hello", cx);
        assert!(
            s.toast_dismiss.is_none(),
            "no dismiss task for a held toast"
        );
    });
    cx.executor().advance_clock(TOAST_TTL * 3);
    cx.run_until_parked();
    state.update(cx, |s, cx| {
        assert!(s.toast_held);
        s.toast.as_mut().unwrap().shown_at -= TOAST_TTL * 3;
        s.tick(0.0, cx);
        assert_eq!(s.toast.as_ref().unwrap().message.as_ref(), "Hello");
        // The newest ordinary toast takes the one slot.
        s.show_toast("Newer", cx);
        assert_eq!(s.toast.as_ref().unwrap().message.as_ref(), "Newer");
        assert!(s.toast_held);
    });
}

/// The next main window shows a held toast for its full time, then it expires.
#[gpui::test]
fn opening_a_window_releases_the_held_toast(cx: &mut TestAppContext) {
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, cx| s.show_toast("Hello", cx));
    cx.executor().advance_clock(TOAST_TTL * 2);
    open_main_window(&state, cx);
    state.read_with(cx, |s, _| {
        assert!(!s.toast_held, "released");
        assert!(s.toast.as_ref().unwrap().shown_at.elapsed() < TOAST_TTL);
    });
    cx.executor()
        .advance_clock(TOAST_TTL - Duration::from_millis(1));
    cx.run_until_parked();
    assert!(state.read_with(cx, |s, _| s.toast.is_some()), "full TTL");
    cx.executor().advance_clock(Duration::from_millis(1));
    cx.run_until_parked();
    assert!(state.read_with(cx, |s, _| s.toast.is_none()), "expired");
    // With the window up, toasts are not held.
    state.update(cx, |s, cx| s.show_toast("Live", cx));
    assert!(state.read_with(cx, |s, _| !s.toast_held));
}

/// A held danger toast is never replaced by an ordinary one, however long it waits, and
/// the ordinary text is dropped, not appended (no window has shown the warning yet).
#[gpui::test]
fn held_danger_toast_is_not_replaced(cx: &mut TestAppContext) {
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, cx| {
        s.set_toast(Toast::danger(LOCK_LOST));
        s.hold_toast_if_windowless(cx);
        assert!(s.toast_held);
        s.toast.as_mut().unwrap().shown_at -= Duration::from_secs(60);
        s.show_toast("Copied", cx);
        let toast = s.toast.as_ref().unwrap();
        assert!(toast.danger);
        assert_eq!(toast.message.as_ref(), LOCK_LOST);
        assert!(s.toast_held);
    });
}

/// 05 §3 "Menus without a window": a lock with no window open removes Settings… at once.
#[gpui::test]
fn lock_without_a_window_rebuilds_the_menus(cx: &mut TestAppContext) {
    fn has_settings(cx: &mut TestAppContext) -> bool {
        cx.update(|cx| cx.get_menus()).unwrap()[0].items.iter().any(
            |item| matches!(item, gpui::OwnedMenuItem::Action { name, .. } if name == "Settings…"),
        )
    }
    let dir = tempfile::tempdir().unwrap();
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, _| s.install_unlocked_for_tests(create(dir.path())));
    // The launch menus (no Settings…) are stale for an already-unlocked state: the
    // follower's registration alone must bring Settings… in.
    cx.update(|cx| crate::actions::set_menus(Sort::default(), true, cx));
    assert!(!has_settings(cx), "launch menus");
    cx.update(|cx| crate::actions::follow_state_with_menus(&state, cx));
    assert!(has_settings(cx), "unlocked, at registration");
    assert!(cx.update(|cx| cx.windows().is_empty()));
    state.update(cx, |s, cx| s.lock(cx));
    cx.run_until_parked();
    assert!(!has_settings(cx), "locked with no window");
}

/// A vault whose format version is newer than this build: open shows the unlock screen
/// blocked instead of an error on the choose screen (05 §2.2).
#[gpui::test]
fn newer_version_vault_opens_blocked(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new.vault");
    drop(
        SyncedVault::create(
            &path,
            &SecretString::new("pw".into()),
            vault_core::KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap(),
    );
    let file = path.join(VAULT_FILE_NAME);
    let mut bytes = std::fs::read(&file).unwrap();
    bytes[4..6].copy_from_slice(&(vault_core::FORMAT_VERSION + 1).to_be_bytes());
    std::fs::write(&file, bytes).unwrap();

    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, cx| s.open_vault(path.clone(), cx));
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert_eq!(s.unlock_blocked, Some(UnlockBlocked::NewerVersion));
        assert_eq!(s.screen, Screen::Unlock);
        assert_eq!(s.vault_path.as_deref(), Some(path.as_path()));
        assert!(s.vault.is_none() && s.error.is_none());
    });
    state.update(cx, |s, cx| s.close_vault(cx));
    assert!(state.read_with(cx, |s, _| s.unlock_blocked.is_none()));

    for e in [
        VaultError::UnsupportedVersion(vault_core::FORMAT_VERSION + 1),
        VaultError::NoUsableSlot,
    ] {
        let e = SyncError::Vault(e);
        assert_eq!(error_message(&e), NEWER_VERSION);
        assert_eq!(unlock_blocked(&e), Some(UnlockBlocked::NewerVersion));
    }
    assert_eq!(
        unlock_blocked(&SyncError::Vault(VaultError::WrongPassword)),
        None
    );
}

/// A header with format version 0 is damage (01 §1), not a newer vault: opening it is not
/// blocked and reports the damaged-file text on the choose screen.
#[gpui::test]
fn version_zero_vault_is_damaged_not_newer(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let path = create(dir.path()).path().to_owned();
    let file = path.join(VAULT_FILE_NAME);
    let mut bytes = std::fs::read(&file).unwrap();
    bytes[4..6].copy_from_slice(&0u16.to_be_bytes());
    std::fs::write(&file, bytes).unwrap();

    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, cx| s.open_vault(path.clone(), cx));
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert_eq!(s.unlock_blocked, None);
        assert_eq!(s.error.as_deref(), Some(DAMAGED));
        assert_ne!(s.screen, Screen::Unlock);
    });

    for v in [0, vault_core::FORMAT_VERSION] {
        let e = SyncError::Vault(VaultError::UnsupportedVersion(v));
        assert_eq!(unlock_blocked(&e), None, "version {v}");
        assert_eq!(error_message(&e), DAMAGED, "version {v}");
    }
}

/// A password slot of a kind this build does not know (the header's only `password`
/// text renamed): a password unlock reports `NoUsableSlot`, which blocks the unlock
/// screen without counting a failed attempt. A later good unlock clears the flag.
#[gpui::test]
fn no_usable_slot_blocks_and_good_unlock_clears(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slot.vault");
    drop(
        SyncedVault::create(
            &path,
            &SecretString::new("pw".into()),
            vault_core::KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap(),
    );
    let file = path.join(VAULT_FILE_NAME);
    let good = std::fs::read(&file).unwrap();
    let at = good.windows(9).position(|w| w == b"hpassword").unwrap();
    let mut bad = good.clone();
    bad[at + 8] = b'X';
    std::fs::write(&file, bad).unwrap();

    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, cx| s.open_vault(path.clone(), cx));
    cx.run_until_parked();
    assert!(
        state.read_with(cx, |s, _| s.unlock_blocked.is_none()),
        "opens"
    );
    state.update(cx, |s, cx| s.unlock(SecretString::new("pw".into()), cx));
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert_eq!(s.unlock_blocked, Some(UnlockBlocked::NewerVersion));
        assert_eq!(s.unlock_failures, 0);
        assert!(s.error.is_none() && s.locked && s.vault.is_some());
    });
    // The file is fixed meanwhile; reopening and a good unlock clear the flag (and a
    // flag left over on the same session is cleared by `unlocked` too).
    std::fs::write(&file, good).unwrap();
    state.update(cx, |s, cx| s.open_vault(path.clone(), cx));
    cx.run_until_parked();
    state.update(cx, |s, cx| {
        s.unlock_blocked = Some(UnlockBlocked::NewerVersion);
        s.unlock(SecretString::new("pw".into()), cx);
    });
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert!(!s.locked && s.screen == Screen::Main);
        assert!(s.unlock_blocked.is_none());
    });
}
