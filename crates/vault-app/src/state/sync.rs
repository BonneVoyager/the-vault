//! Sync events and the Sync & Backup tab (specs/05-ui.md §2.5, §3; specs/03-sync.md §3,
//! §4, §8).
//!
//! The watcher runs from `install` (open or create) until the vault is closed, including
//! while locked: vault-sync needs the locked-time signal to re-read the file at the next
//! unlock (`ChangedWhileLocked`), and its threads hold no key material. `tick` calls
//! `SyncedVault::poll` on the main thread once a second, then drains the event receiver.
//!
//! Saving stays on the main thread. `SyncedVault::save` is `&mut self` and does the atomic
//! write itself (serialize, encrypt, write, fsync, rename): milliseconds for a personal
//! vault. Moving it off-thread would mean sharing the vault behind a lock with every view.
//! The two Argon2 paths here (re-entering the password after a key change, restoring a
//! backup) do take long, so they move the vault into a background task like unlock does.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use gpui::{Context, SharedString};
use vault_core::{Item, SecretString};
use vault_sync::{BackupInfo, SyncError, SyncEvent, SyncedVault};

use super::{AppState, Busy, Mode, Navigation, Outcome, SyncStatus, TOAST_TTL, Toast, ToastPlace};
use crate::text;

/// Index of the Sync & Backup tab in the settings sheet.
pub const SYNC_TAB: usize = 2;
/// Index of the Import / Export tab.
pub const TRANSFER_TAB: usize = 3;

/// The two-step inline restore prompt in the Sync & Backup tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePrompt {
    pub backup: PathBuf,
    /// False: "Replace the current vault?" confirm. True: master password input.
    pub asking_password: bool,
    pub error: Option<SharedString>,
}

/// Sync-related UI state. Reset when the vault is closed.
#[derive(Debug, Default)]
pub struct SyncUi {
    /// "The vault file on disk is unreadable…" until the next successful save.
    pub corrupt: bool,
    /// "Waiting for iCloud…" until the next successful poll or save.
    pub waiting_for_cloud: bool,
    /// The on-disk vault was re-keyed elsewhere; the inline password prompt is up.
    pub key_mismatch: bool,
    pub key_mismatch_error: Option<SharedString>,
    /// Newest first, as `SyncedVault::backups` returns them.
    pub backups: Vec<BackupInfo>,
    pub backups_error: Option<SharedString>,
    pub restore: Option<RestorePrompt>,
    /// Last successful save by this app.
    pub last_saved: Option<SystemTime>,
    /// The red "Export unencrypted?" confirm in Import / Export.
    pub export_confirm: bool,
    /// The last save attempt failed; the tick does not retry until something changes.
    pub save_failing: bool,
    /// The re-key warning toast is up; the Merged right after it stays quiet.
    pub rekey_toast_shown: bool,
}

impl SyncUi {
    /// True when a banner or prompt sits at the top of the detail column.
    pub fn has_banner(&self) -> bool {
        self.corrupt || self.waiting_for_cloud || self.key_mismatch
    }
}

impl AppState {
    /// Starts the watcher and applies the backup settings to a freshly installed vault.
    pub(super) fn attach_vault(&mut self) {
        self.apply_backup_settings();
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        if let Err(e) = vault.start_watching() {
            // Not fatal: the vault still works, it just won't see other devices' changes.
            eprintln!("vault: file watcher failed: {e}");
            self.sync_status = SyncStatus::Error(e.to_string().into());
        }
    }

    pub(super) fn apply_backup_settings(&mut self) {
        if let Some(vault) = self.vault.as_mut() {
            vault.set_backup_enabled(self.settings.backup_enabled);
            vault.set_retention_multiplier(self.settings.retention_multiplier);
        }
    }

    pub fn is_watching(&self) -> bool {
        self.vault.as_ref().is_some_and(SyncedVault::is_watching)
    }

    /// Bookkeeping after any save attempt by the app. Returns the error message, if any.
    pub(super) fn record_save(&mut self, result: Result<(), SyncError>) -> Option<String> {
        match result {
            Ok(()) => {
                self.sync.save_failing = false;
                self.sync.corrupt = false;
                self.sync.waiting_for_cloud = false;
                self.sync.last_saved = Some(SystemTime::now());
                self.sync_status = SyncStatus::Idle;
                None
            }
            Err(e) => {
                self.sync.save_failing = true;
                Some(e.to_string())
            }
        }
    }

    /// Saves now if dirty, toasting a failure. Used by autosave.
    pub(super) fn save_now(&mut self, cx: &mut Context<Self>) {
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        if !vault.is_dirty() {
            return;
        }
        let result = vault.save();
        if let Some(e) = self.record_save(result) {
            self.show_toast(format!("Could not save: {e}"), cx);
        }
        cx.notify();
    }

    /// One tick of sync work: poll the watcher, then apply every queued event.
    pub(super) fn poll_sync(&mut self, cx: &mut Context<Self>) {
        // The vault is inside a background task: leave its events queued until it is back,
        // or a Merged would refresh against no vault and empty the listing mid-edit.
        if self.busy.is_some_and(Busy::holds_unlocked_vault) {
            return;
        }
        let drained = self.vault.as_mut().map_or(0, SyncedVault::poll);
        let events: Vec<SyncEvent> = self
            .sync_events
            .as_ref()
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default();
        let cloud_failed = events.contains(&SyncEvent::CloudUnavailable);
        for event in events {
            self.handle_sync_event(event, cx);
        }
        if drained > 0 && !cloud_failed && self.sync.waiting_for_cloud {
            self.sync.waiting_for_cloud = false;
            cx.notify();
        }
        // Dirty with nothing scheduled: a corrupt file to rewrite, or work deferred to
        // unlock. A save that keeps failing (key mismatch, blocked) is not retried here;
        // the next edit schedules one and shows its error.
        let needs_save = !self.locked
            && !self.autosave_pending
            && !self.sync.save_failing
            && !self.sync.key_mismatch
            && self.vault.as_ref().is_some_and(SyncedVault::is_dirty);
        if needs_save {
            self.schedule_autosave(cx);
        }
    }

    /// Applies one `SyncEvent` (05 §3). Safe in every state: locked, editing, choose screen.
    pub fn handle_sync_event(&mut self, event: SyncEvent, cx: &mut Context<Self>) {
        match event {
            SyncEvent::Merged(report) => {
                self.sync.key_mismatch = false;
                self.sync.key_mismatch_error = None;
                self.vault_changed();
                self.mark_remote_edits();
                // The Merged that follows KeyRotatedOnDisk must not cover its warning.
                let after_rekey = std::mem::take(&mut self.sync.rekey_toast_shown);
                if report.changed() && !after_rekey {
                    self.show_toast("Vault updated from another device", cx);
                }
                // vault-sync saves the merge itself; a clean vault means that save worked.
                if self.vault.as_ref().is_some_and(|v| !v.is_dirty()) {
                    self.sync.corrupt = false;
                    self.sync.waiting_for_cloud = false;
                    self.sync.save_failing = false;
                }
            }
            // vault-sync re-reads the file at the next unlock.
            SyncEvent::ChangedWhileLocked => {}
            SyncEvent::ConflictAbsorbed(path) => {
                self.vault_changed();
                self.refresh_backups();
                if !self.locked && self.vault.as_ref().is_some_and(SyncedVault::is_dirty) {
                    self.schedule_autosave(cx);
                }
                let name = text::file_name(&path);
                self.show_toast(format!("Merged a conflicted copy ({name})"), cx);
            }
            SyncEvent::CorruptOnDisk => {
                self.sync.corrupt = true;
                if !self.locked {
                    // vault-sync marked the vault dirty; the autosave rewrites the file.
                    self.schedule_autosave(cx);
                }
            }
            SyncEvent::ForeignVault => {
                self.show_toast("Ignored a different vault in this folder", cx);
            }
            SyncEvent::CloudUnavailable => self.sync.waiting_for_cloud = true,
            SyncEvent::BackupTaken(path) => {
                eprintln!("vault: backup taken: {}", path.display());
                self.refresh_backups();
            }
            SyncEvent::KeyMismatch => {
                if !self.locked {
                    self.sync.key_mismatch = true;
                    self.sync.key_mismatch_error = None;
                }
            }
            SyncEvent::KeyRotatedOnDisk => {
                self.sync.key_mismatch = false;
                self.sync.key_mismatch_error = None;
                self.sync.save_failing = false;
                self.sync.rekey_toast_shown = true;
                self.show_toast(
                    "Now using the vault's new key from disk. If no other device changed \
                     the password, the file may have been rolled back; check your backups.",
                    cx,
                );
            }
            SyncEvent::Error(message) => {
                self.sync_status = SyncStatus::Error(message.clone().into());
                self.show_toast(message, cx);
            }
        }
        cx.notify();
    }

    /// Marks edit-buffer rows (and the title) that the user touched and that changed
    /// remotely since editing began. The user's value still wins on save.
    fn mark_remote_edits(&mut self) {
        let Mode::Edit(buffer) = &self.mode else {
            return;
        };
        let stored: Option<Item> = self
            .unlocked_vault()
            .and_then(|v| v.get(buffer.item.id))
            .cloned();
        let Some(stored) = stored else {
            return;
        };
        if let Mode::Edit(buffer) = &mut self.mode {
            buffer.mark_remote(&stored);
        }
    }

    /// "Re-keyed on another device" prompt: verify the password on a background thread;
    /// vault-sync then adopts the on-disk vault and merges ours into it.
    pub fn resolve_key_mismatch(&mut self, password: SecretString, cx: &mut Context<Self>) {
        if self.busy.is_some() || self.locked || !self.sync.key_mismatch {
            return;
        }
        let Some(mut vault) = self.vault.take() else {
            return;
        };
        self.sync.key_mismatch_error = None;
        self.run_bg(
            Busy::Reverifying,
            cx,
            move || {
                let result = vault.unlock(&password);
                // The edits made during the mismatch could not be saved. Write them now,
                // on this thread, so a lock, close or quit during the Argon2 window cannot
                // drop them (vault-sync's `lock` only preserves them while mismatched).
                let saved = match result {
                    Ok(()) if vault.is_dirty() => Some(vault.save()),
                    _ => None,
                };
                (vault, result, saved)
            },
            |this, (mut vault, result, saved), outcome| match (outcome, result) {
                (Outcome::Closed, _) => {
                    if let Some(Err(e)) = saved {
                        eprintln!("vault: could not save after re-entering the password: {e}");
                    }
                    vault.lock();
                }
                (Outcome::Locked, _) => {
                    vault.lock();
                    this.vault = Some(vault);
                    if let Some(e) = saved.and_then(|r| this.record_save(r)) {
                        this.toast = Some(Toast::window(format!("Could not save: {e}")));
                    }
                }
                (Outcome::Fresh, Ok(())) => {
                    this.vault = Some(vault);
                    this.sync.key_mismatch = false;
                    if let Some(e) = saved.and_then(|r| this.record_save(r)) {
                        this.toast = Some(Toast::window(format!("Could not save: {e}")));
                    }
                    this.vault_changed();
                }
                (Outcome::Fresh, Err(e)) => {
                    this.vault = Some(vault);
                    this.sync.key_mismatch_error = Some(super::error_message(&e).into());
                }
            },
        );
    }

    /// Re-reads the backups directory for the Sync & Backup tab.
    pub fn refresh_backups(&mut self) {
        let Some(vault) = self.vault.as_ref() else {
            self.sync.backups.clear();
            self.sync.backups_error = None;
            return;
        };
        match vault.backups() {
            Ok(list) => {
                self.sync.backups = list;
                self.sync.backups_error = None;
            }
            Err(e) => {
                self.sync.backups.clear();
                self.sync.backups_error = Some(e.to_string().into());
            }
        }
    }

    /// "Back up now": snapshot the file on disk regardless of policy. Works while locked.
    pub fn backup_now(&mut self, cx: &mut Context<Self>) {
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        match vault.backup_now() {
            Ok(path) => {
                let name = text::file_name(&path);
                self.show_toast(format!("Backed up to {name}"), cx);
            }
            Err(e) => self.show_toast(format!("Backup failed: {e}"), cx),
        }
        self.refresh_backups();
        cx.notify();
    }

    /// "Restore…" on a backup row. Restoring discards the edit buffer, so it goes through
    /// the unsaved-changes guard first; the guard's prompt lives in the editor, so the
    /// sheet closes while it is up and reopens here after "Discard".
    pub fn request_restore(&mut self, backup: PathBuf, cx: &mut Context<Self>) {
        if self.locked {
            return;
        }
        if !self.guard(Navigation::Restore(backup.clone()), cx) {
            self.settings_open = false;
            cx.notify();
            return;
        }
        self.settings_tab = SYNC_TAB;
        self.settings_open = true;
        self.sync.restore = Some(RestorePrompt {
            backup,
            asking_password: false,
            error: None,
        });
        cx.notify();
    }

    /// "Replace…" in the confirm: ask for the backup's master password next.
    pub fn confirm_restore(&mut self, cx: &mut Context<Self>) {
        if let Some(r) = self.sync.restore.as_mut() {
            r.asking_password = true;
            r.error = None;
            cx.notify();
        }
    }

    pub fn cancel_restore(&mut self, cx: &mut Context<Self>) {
        if self.sync.restore.take().is_some() {
            cx.notify();
        }
    }

    /// Runs `restore_from` on a background thread (it unlocks the backup with Argon2).
    pub fn restore_backup(&mut self, password: SecretString, cx: &mut Context<Self>) {
        if self.busy.is_some() || self.locked {
            return;
        }
        let Some(backup) = self.sync.restore.as_ref().map(|r| r.backup.clone()) else {
            return;
        };
        // An edit may have started since the confirm (the sheet does not block ⌘E).
        if !self.guard(Navigation::Restore(backup.clone()), cx) {
            self.settings_open = false;
            cx.notify();
            return;
        }
        let Some(mut vault) = self.vault.take() else {
            return;
        };
        let task_backup = backup.clone();
        self.run_bg(
            Busy::Restoring,
            cx,
            move || {
                let result = vault.restore_from(&task_backup, &password);
                (vault, result)
            },
            move |this, (mut vault, result), outcome| match (outcome, result) {
                (Outcome::Closed, _) => vault.lock(),
                (Outcome::Locked, result) => {
                    vault.lock();
                    this.vault = Some(vault);
                    this.sync.restore = None;
                    if let Err(e) = result {
                        this.toast = Some(Toast::window(format!("Restore failed: {e}")));
                    }
                }
                (Outcome::Fresh, Ok(())) => {
                    this.vault = Some(vault);
                    this.restored(&backup);
                }
                (Outcome::Fresh, Err(e)) => {
                    this.vault = Some(vault);
                    if let Some(r) = this.sync.restore.as_mut() {
                        r.error = Some(super::error_message(&e).into());
                    }
                }
            },
        );
    }

    /// After a successful restore: the vault is unlocked and clean, everything derived
    /// from it is stale.
    fn restored(&mut self, backup: &Path) {
        let name = text::file_name(backup);
        self.mode = Mode::View;
        self.discard_prompt = None;
        self.delete_confirm = None;
        self.generator_target = None;
        self.sync = SyncUi {
            last_saved: Some(SystemTime::now()),
            ..SyncUi::default()
        };
        self.sync_status = SyncStatus::Idle;
        self.vault_changed();
        self.refresh_backups();
        self.toast = Some(Toast::window(format!("Restored from {name}")));
    }
}

impl Toast {
    /// A window toast built without a `Context` (background-task completions).
    /// The 1 s tick expires it.
    pub(super) fn window(message: impl Into<SharedString>) -> Self {
        Self {
            message: message.into(),
            shown_at: std::time::Instant::now(),
            place: ToastPlace::Window,
            ttl: TOAST_TTL,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Real `SyncedVault`s on a temp dir with the real watcher: device A is the app state,
    //! device B a second instance writing the same file. Waits are deadline loops around
    //! the app's tick, never bare sleeps for a positive assertion.

    use std::fs;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use gpui::{AppContext as _, Entity, TestAppContext};
    use vault_core::{ExposeSecret as _, Field, FieldKind, ItemKind, KdfParams, MergeReport, Uuid};
    use vault_sync::NoopHooks;

    use super::super::session::AUTOSAVE_DEBOUNCE;
    use super::*;

    const PW: &str = "correct horse";
    const DEADLINE: Duration = Duration::from_secs(20);

    fn secret(s: &str) -> SecretString {
        SecretString::new(s.into())
    }

    /// App state unlocked on a vault with one login (username, password, url), plus a
    /// second unlocked instance of the same file.
    fn two_devices(dir: &Path, cx: &mut TestAppContext) -> (Entity<AppState>, SyncedVault, Uuid) {
        let path = dir.join("t.vault");
        let mut vault = SyncedVault::create(
            &path,
            &secret(PW),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        let id = vault
            .edit(|v| {
                let mut gh = Item::new(ItemKind::Login, "GitHub", device, 10);
                gh.fields = vec![
                    Field::new("username", FieldKind::Text, secret("chris"), 10),
                    Field::new("password", FieldKind::Password, secret("old"), 10),
                    Field::new("url", FieldKind::Url, secret("https://github.com"), 10),
                ];
                v.insert(gh, 10)
            })
            .unwrap();
        vault.save().unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| {
            s.install(vault, false);
            s.unlocked();
            s.selection = Some(id);
        });
        let mut other = SyncedVault::open(&path, Uuid::new_v4(), Arc::new(NoopHooks)).unwrap();
        other.unlock(&secret(PW)).unwrap();
        (state, other, id)
    }

    /// Ticks the app (poll + events) until `done` holds or the deadline passes.
    fn wait_for(
        state: &Entity<AppState>,
        cx: &mut TestAppContext,
        done: impl Fn(&AppState) -> bool,
    ) -> bool {
        let start = Instant::now();
        while start.elapsed() < DEADLINE {
            state.update(cx, |s, cx| s.tick(0.0, cx));
            if state.read_with(cx, |s, _| done(s)) {
                return true;
            }
            thread::sleep(Duration::from_millis(25));
        }
        false
    }

    fn set_remote(other: &mut SyncedVault, id: Uuid, name: &str, value: &str) {
        other
            .edit(|v| {
                v.update(id, 20, |it| {
                    if let Some(f) = it.fields.iter_mut().find(|f| f.name == name) {
                        f.value = secret(value);
                    }
                })
            })
            .unwrap()
            .unwrap();
    }

    #[gpui::test]
    fn merged_during_edit_badges_only_touched_remote_fields(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, mut other, id) = two_devices(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.begin_edit(cx);
            // Rows 0..3 are username, password, url. Touch username and password here.
            s.set_edit_value(0, secret("chris2"), cx);
            s.set_edit_value(1, secret("mine"), cx);
        });
        // Elsewhere: password (touched here) and url (untouched here) change.
        set_remote(&mut other, id, "password", "theirs");
        set_remote(&mut other, id, "url", "https://github.com/login");
        other.save().unwrap();

        assert!(wait_for(&state, cx, |s| {
            s.edit_buffer().is_some_and(|b| !b.remote_fields.is_empty())
        }));
        state.read_with(cx, |s, _| {
            let b = s.edit_buffer().unwrap();
            assert_eq!(
                b.remote_fields,
                vec![1],
                "only the touched, remotely changed row"
            );
            assert!(!b.remote_title);
            // The edit buffer is kept; the stored item has the remote values.
            assert_eq!(b.item.fields[1].value.expose_secret(), "mine");
            let stored = s.unlocked_vault().unwrap().get(id).unwrap();
            assert_eq!(
                stored.field("url").unwrap().value.expose_secret(),
                "https://github.com/login"
            );
            assert_eq!(
                s.toast.as_ref().map(|t| t.message.to_string()).as_deref(),
                Some("Vault updated from another device")
            );
        });

        // The user's edit wins on save; the untouched remote change survives.
        state.update(cx, |s, cx| s.save_edit(cx));
        state.read_with(cx, |s, _| {
            let stored = s.unlocked_vault().unwrap().get(id).unwrap();
            assert_eq!(
                stored.field("password").unwrap().value.expose_secret(),
                "mine"
            );
            assert_eq!(
                stored.field("url").unwrap().value.expose_secret(),
                "https://github.com/login"
            );
        });
    }

    #[gpui::test]
    fn synthetic_merge_marks_title_and_new_mode_is_ignored(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, id) = two_devices(dir.path(), cx);
        let changed = MergeReport {
            updated: 1,
            ..MergeReport::default()
        };
        state.update(cx, |s, cx| {
            s.begin_edit(cx);
            s.set_edit_title("Mine".into(), cx);
            let vault = s.vault.as_mut().unwrap();
            vault
                .edit(|v| v.update(id, 30, |it| it.title = "Theirs".into()))
                .unwrap()
                .unwrap();
            s.handle_sync_event(SyncEvent::Merged(changed), cx);
            let b = s.edit_buffer().unwrap();
            assert!(b.remote_title);
            assert!(b.remote_fields.is_empty());

            // During New: nothing to compare, nothing marked, no panic.
            s.cancel_edit(cx);
            s.begin_new(ItemKind::Note, String::new(), cx);
            s.handle_sync_event(SyncEvent::Merged(changed), cx);
            assert!(s.edit_buffer().unwrap().remote_fields.is_empty());
        });
    }

    #[gpui::test]
    fn corrupt_banner_shows_and_clears_on_next_save(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, _) = two_devices(dir.path(), cx);
        let path = dir.path().join("t.vault");
        // Rename in, so the watcher never sees a half-written file.
        let tmp = dir.path().join(".garbage.tmp");
        fs::write(&tmp, b"definitely not a vault").unwrap();
        fs::rename(&tmp, &path).unwrap();

        assert!(wait_for(&state, cx, |s| s.sync.corrupt));
        state.read_with(cx, |s, _| assert!(s.sync.has_banner()));
        // The autosave scheduled by the event rewrites the file from memory.
        cx.executor().advance_clock(AUTOSAVE_DEBOUNCE);
        cx.run_until_parked();
        state.update(cx, |s, cx| s.tick(0.0, cx));
        state.read_with(cx, |s, _| {
            assert!(!s.sync.corrupt, "a successful save clears the banner");
            assert!(s.sync.last_saved.is_some());
        });
        let bytes = fs::read(&path).unwrap();
        assert!(vault_core::LockedVault::parse(&bytes).is_ok());
    }

    #[gpui::test]
    fn key_mismatch_prompt_resolves_via_unlock(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, mut other, _) = two_devices(dir.path(), cx);
        other
            .edit(|v| v.rotate_vault_key(&secret(PW)))
            .unwrap()
            .unwrap();
        other
            .edit(|v| v.insert(Item::new(ItemKind::Note, "from b", Uuid::nil(), 40), 40))
            .unwrap();
        other.save().unwrap();

        assert!(wait_for(&state, cx, |s| s.sync.key_mismatch));
        // Saves fail until resolved, and say so.
        state.update(cx, |s, cx| {
            s.toggle_favorite(cx);
            s.save_now(cx);
            assert!(s.sync.save_failing);
            let toast = s.toast.as_ref().unwrap().message.to_string();
            assert!(toast.starts_with("Could not save"), "{toast}");
        });

        state.update(cx, |s, cx| s.resolve_key_mismatch(secret("wrong"), cx));
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(s.sync.key_mismatch, "prompt stays up");
            assert_eq!(
                s.sync.key_mismatch_error.as_deref(),
                Some("Wrong password. Try again.")
            );
            assert!(s.vault.is_some() && !s.locked);
        });

        state.update(cx, |s, cx| s.resolve_key_mismatch(secret(PW), cx));
        cx.run_until_parked();
        state.update(cx, |s, cx| s.tick(0.0, cx));
        state.read_with(cx, |s, _| {
            assert!(!s.sync.key_mismatch);
            assert!(s.sync.key_mismatch_error.is_none());
            let titles: Vec<_> = s
                .unlocked_vault()
                .unwrap()
                .items()
                .map(|i| i.title.clone())
                .collect();
            assert!(titles.contains(&"from b".to_owned()), "{titles:?}");
        });
        state.update(cx, |s, cx| s.save_now(cx));
        state.read_with(cx, |s, _| assert!(!s.sync.save_failing));
    }

    /// Rotates the key from the second device and waits for the app's prompt.
    fn rotate_elsewhere(
        state: &Entity<AppState>,
        other: &mut SyncedVault,
        cx: &mut TestAppContext,
    ) {
        other
            .edit(|v| v.rotate_vault_key(&secret(PW)))
            .unwrap()
            .unwrap();
        other.save().unwrap();
        assert!(wait_for(state, cx, |s| s.sync.key_mismatch));
    }

    #[gpui::test]
    fn lock_during_reverify_keeps_the_mismatch_edits_on_disk(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, mut other, id) = two_devices(dir.path(), cx);
        rotate_elsewhere(&state, &mut other, cx);
        state.update(cx, |s, cx| {
            s.toggle_favorite(cx);
            s.save_now(cx);
            assert!(s.sync.save_failing, "saves fail during the mismatch");
            s.resolve_key_mismatch(secret(PW), cx);
            // ⌘L lands while Argon2 runs, with the vault inside the task.
            s.lock(cx);
        });
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(s.locked && s.vault.is_some() && s.busy.is_none());
        });
        let mut reopened = SyncedVault::open(
            &dir.path().join("t.vault"),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        reopened.unlock(&secret(PW)).unwrap();
        assert!(
            reopened.vault().unwrap().get(id).unwrap().favorite,
            "edit saved before lock"
        );
    }

    #[gpui::test]
    fn events_stay_queued_while_the_vault_is_in_a_task(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, id) = two_devices(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.begin_edit(cx);
            let mut vault = s.vault.take().unwrap();
            vault.backup_now().unwrap(); // emits BackupTaken
            s.busy = Some(Busy::Reverifying);
            s.tick(0.0, cx);
            assert_eq!(s.sync_events.as_ref().unwrap().len(), 1, "left queued");
            assert!(s.is_editing());
            assert_eq!(s.selection, Some(id));
            // Back from the task: the queue drains.
            s.vault = Some(vault);
            s.busy = None;
            s.tick(0.0, cx);
            assert!(s.sync_events.as_ref().unwrap().is_empty());
            assert!(!s.sync.backups.is_empty());
        });
    }

    #[gpui::test]
    fn save_failing_resets_and_conflicts_autosave(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, id) = two_devices(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.sync.save_failing = true;
            s.handle_sync_event(SyncEvent::Merged(MergeReport::default()), cx);
            assert!(
                !s.sync.save_failing,
                "a clean merge means saving works again"
            );

            s.sync.save_failing = true;
            s.unlocked();
            assert!(!s.sync.save_failing);

            // An absorbed conflict leaves the vault dirty: autosave it.
            s.vault
                .as_mut()
                .unwrap()
                .edit(|v| v.update(id, 50, |it| it.favorite = true))
                .unwrap()
                .unwrap();
            s.autosave_pending = false;
            s.handle_sync_event(SyncEvent::ConflictAbsorbed(dir.path().join("c.vault")), cx);
            assert!(s.autosave_pending);

            // The Merged right after a re-key keeps the re-key warning up.
            s.handle_sync_event(SyncEvent::KeyRotatedOnDisk, cx);
            let warning = s.toast.as_ref().unwrap().message.clone();
            let changed = MergeReport {
                added: 1,
                ..MergeReport::default()
            };
            s.handle_sync_event(SyncEvent::Merged(changed), cx);
            assert_eq!(s.toast.as_ref().unwrap().message, warning);
            s.handle_sync_event(SyncEvent::Merged(changed), cx);
            assert_eq!(
                s.toast.as_ref().unwrap().message.as_ref(),
                "Vault updated from another device"
            );
        });
        cx.executor().advance_clock(AUTOSAVE_DEBOUNCE);
        cx.run_until_parked();
        state.read_with(cx, |s, _| assert!(!s.vault.as_ref().unwrap().is_dirty()));
    }

    #[gpui::test]
    fn restore_rechecks_an_edit_started_after_the_confirm(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, _) = two_devices(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.backup_now(cx);
            let backup = s.sync.backups[0].path.clone();
            s.request_restore(backup, cx);
            s.confirm_restore(cx);
            s.begin_edit(cx);
            s.set_edit_title("changed".into(), cx);
            s.restore_backup(secret(PW), cx);
            assert!(s.busy.is_none(), "restore did not start");
            assert!(s.discard_prompt.is_some());
            assert!(!s.settings_open);
        });
    }

    #[gpui::test]
    fn events_are_harmless_locked_on_choose_and_during_new(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let every = |p: &Path| {
            vec![
                SyncEvent::Merged(MergeReport::default()),
                SyncEvent::ChangedWhileLocked,
                SyncEvent::ConflictAbsorbed(p.join("conflict-x.vault")),
                SyncEvent::CorruptOnDisk,
                SyncEvent::ForeignVault,
                SyncEvent::CloudUnavailable,
                SyncEvent::BackupTaken(p.join("b.vault")),
                SyncEvent::Error("boom".into()),
                SyncEvent::KeyMismatch,
                SyncEvent::KeyRotatedOnDisk,
            ]
        };
        // Choose screen: no vault at all.
        let empty = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        empty.update(cx, |s, cx| {
            for e in every(dir.path()) {
                s.handle_sync_event(e, cx);
            }
            s.tick(0.0, cx);
        });
        // Locked, then during New.
        let (state, _other, _) = two_devices(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.lock(cx);
            for e in every(dir.path()) {
                s.handle_sync_event(e, cx);
            }
            assert!(!s.sync.key_mismatch, "no prompt while locked");
            s.tick(0.0, cx);
        });
        let dir2 = tempfile::tempdir().unwrap();
        let (state, _other2, _) = two_devices(dir2.path(), cx);
        state.update(cx, |s, cx| {
            s.begin_new(ItemKind::Login, String::new(), cx);
            for e in every(dir.path()) {
                s.handle_sync_event(e, cx);
            }
            assert!(s.is_editing());
            assert!(s.sync.waiting_for_cloud && s.sync.corrupt);
        });
    }

    #[gpui::test]
    fn backup_now_and_restore_replace_the_vault(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, id) = two_devices(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.backup_now(cx);
            assert!(
                s.toast
                    .as_ref()
                    .unwrap()
                    .message
                    .starts_with("Backed up to ")
            );
            assert!(!s.sync.backups.is_empty());
            // Delete the item and save, then restore the backup taken before.
            s.request_delete(cx);
            s.confirm_delete(cx);
            s.save_now(cx);
            assert!(s.selected_item().is_none());
        });
        let backup = state.read_with(cx, |s, _| {
            s.sync
                .backups
                .iter()
                .find(|b| b.kind == vault_sync::BackupKind::Snapshot)
                .unwrap()
                .path
                .clone()
        });

        // Restore while editing with changes goes through the guard first.
        state.update(cx, |s, cx| {
            s.select(id, cx);
            s.begin_new(ItemKind::Note, "draft".into(), cx);
            s.set_edit_title("draft 2".into(), cx);
            s.settings_open = true;
            s.request_restore(backup.clone(), cx);
            assert!(s.discard_prompt.is_some());
            assert!(!s.settings_open, "sheet closes so the guard is visible");
            s.discard_changes(cx);
            assert!(s.settings_open && s.settings_tab == SYNC_TAB);
            assert!(s.sync.restore.is_some());
            s.confirm_restore(cx);
            s.restore_backup(secret("wrong"), cx);
        });
        cx.run_until_parked();
        state.update(cx, |s, cx| {
            let r = s.sync.restore.as_ref().unwrap();
            assert_eq!(r.error.as_deref(), Some("Wrong password. Try again."));
            s.restore_backup(secret(PW), cx);
        });
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(s.sync.restore.is_none());
            assert!(
                s.unlocked_vault()
                    .unwrap()
                    .get(id)
                    .is_some_and(|i| !i.is_deleted())
            );
            assert!(s.listing.items.contains(&id));
            assert!(
                s.toast
                    .as_ref()
                    .unwrap()
                    .message
                    .starts_with("Restored from ")
            );
        });
    }

    #[gpui::test]
    fn backup_settings_apply_to_the_vault_and_are_sanitized(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, _) = two_devices(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.update_settings(cx, |st| {
                st.backup_enabled = false;
                st.retention_multiplier = 2.0;
            });
            let v = s.vault.as_ref().unwrap();
            assert!(!v.backup_enabled());
            assert_eq!(v.retention_multiplier(), 2.0);
            // The live setter sanitizes too.
            s.update_settings(cx, |st| {
                st.retention_multiplier = 3.0;
                st.clipboard_clear_secs = 0;
            });
            assert_eq!(s.settings.retention_multiplier, 1.0);
            assert_eq!(s.settings.clipboard_clear_secs, 30);
            assert_eq!(s.vault.as_ref().unwrap().retention_multiplier(), 1.0);
        });
    }
}
