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
