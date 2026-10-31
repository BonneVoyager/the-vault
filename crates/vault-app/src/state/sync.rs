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
use vault_sync::{BackupInfo, SaveBlocked, SyncError, SyncEvent, SyncedVault};

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
    /// The prompt is for a key rotated elsewhere (`KeyRotatedOnDisk`): its own wording, and
    /// the Merged after re-verifying says the new key is in use.
    pub key_rotated: bool,
    /// Newest first, as `SyncedVault::backups` returns them.
    pub backups: Vec<BackupInfo>,
    pub backups_error: Option<SharedString>,
    pub restore: Option<RestorePrompt>,
    /// The backup whose row shows the inline "Delete this backup?" confirm.
    pub delete_confirm: Option<PathBuf>,
    /// Last successful save by this app.
    pub last_saved: Option<SystemTime>,
    /// The red "Export unencrypted?" confirm in Import / Export.
    pub export_confirm: bool,
    /// The last save attempt failed; the tick does not retry until something changes.
    pub save_failing: bool,
    /// An autosave hit the save lock (`SaveLockTimeout`) and was retried once; the next
    /// failure is not retried. Reset by any other save outcome.
    pub busy_retried: bool,
}

/// Toast on the Merged that follows re-entering the password after a key rotation.
pub const KEY_ROTATED_RESOLVED: &str = "Now using the vault's new key";

/// Toast when another process held the vault's save lock for too long (03 §2).
pub const SAVE_BUSY: &str = "Another process is writing this vault. Try again in a moment.";

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
        self.autosave_finished(result, cx);
    }

    /// Bookkeeping and toast for one autosave attempt. A save that waited out another
    /// process's lock is retried once, `AUTOSAVE_DEBOUNCE` later.
    pub(super) fn autosave_finished(
        &mut self,
        result: Result<(), SyncError>,
        cx: &mut Context<Self>,
    ) {
        let busy = matches!(result, Err(SyncError::SaveLockTimeout(_)));
        if let Some(e) = self.record_save(result) {
            if busy {
                self.show_toast(SAVE_BUSY, cx);
            } else {
                self.show_toast(format!("Could not save: {e}"), cx);
            }
        }
        let retry = busy && !self.sync.busy_retried && !self.locked;
        self.sync.busy_retried = retry;
        if retry {
            self.schedule_autosave(cx);
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
                if std::mem::take(&mut self.sync.key_rotated) {
                    self.show_toast(KEY_ROTATED_RESOLVED, cx);
                } else if report.changed() {
                    self.show_toast("Vault updated from another device", cx);
                }
                if self.recheck_touch_slot() {
                    self.show_toast(super::touch_id::SLOT_GONE, cx);
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
                if self.recheck_touch_slot() {
                    self.show_toast(super::touch_id::SLOT_GONE, cx);
                }
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
            // vault.bin vanished while unlocked: vault-sync keeps the vault and marks it
            // dirty, so an autosave writes the file again (03 §8).
            SyncEvent::PrimaryMissing => {
                if !self.locked {
                    self.schedule_autosave(cx);
                }
                self.show_toast("The vault file went missing. It will be written again.", cx);
            }
            SyncEvent::CloudUnavailable => self.sync.waiting_for_cloud = true,
            // Orphan blobs deleted after a save: nothing the user needs to see.
            SyncEvent::AttachmentsPruned(_) => {}
            SyncEvent::BackupTaken(path) => {
                eprintln!("vault: backup taken: {}", path.display());
                self.refresh_backups();
            }
            SyncEvent::BackupDeleted(_) => self.refresh_backups(),
            // 03 §3: the file on disk must not be overwritten. vault-sync emits this when it
            // first sees such a file and on refused saves; a refused save already toasted
            // through `record_save`, so only the first sighting toasts. The status line
            // keeps the reason until a save succeeds, and autosave stops retrying.
            SyncEvent::SaveBlocked(blocked) => {
                let message = save_blocked_message(&blocked);
                self.sync_status = SyncStatus::Error(message.into());
                if !self.sync.save_failing {
                    self.show_toast(message, cx);
                }
                self.sync.save_failing = true;
            }
            // Both mean the cached key no longer opens the file on disk (a password change
            // or a key rotation elsewhere, or a rollback, which looks the same). vault-sync
            // keeps the in-memory edits and refuses to save; the inline prompt asks for the
            // password, and `unlock` merges our edits into the on-disk vault. Locked: the
            // next unlock re-reads the file anyway.
            SyncEvent::KeyMismatch | SyncEvent::KeyRotatedOnDisk => {
                if !self.locked {
                    self.sync.key_mismatch = true;
                    self.sync.key_mismatch_error = None;
                    self.sync.key_rotated = event == SyncEvent::KeyRotatedOnDisk;
                }
            }
            // Fallback for errors without a typed event (watcher failures, a failed backup).
            SyncEvent::Error(message) => {
                self.sync_status = SyncStatus::Error(message.clone().into());
                // A lock that lost unsaved edits already shows a danger toast; keep it.
                if !self.toast.as_ref().is_some_and(|t| t.danger) {
                    self.show_toast(message, cx);
                }
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
                    let save_error = saved.and_then(Result::err).map(|e| e.to_string());
                    if let Some(e) = &save_error {
                        eprintln!("vault: could not save after re-entering the password: {e}");
                    }
                    let lock = vault.lock();
                    this.report_lock(save_error.as_deref(), &lock);
                }
                (Outcome::Locked, _) => {
                    let save_error = saved.and_then(|r| this.record_save(r));
                    let lock = vault.lock();
                    this.vault = Some(vault);
                    this.report_lock(save_error.as_deref(), &lock);
                }
                (Outcome::Fresh, Ok(())) => {
                    this.vault = Some(vault);
                    this.sync.key_mismatch = false;
                    if let Some(e) = saved.and_then(|r| this.record_save(r)) {
                        this.set_toast(Toast::window(format!("Could not save: {e}")));
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
        self.sync.delete_confirm = None;
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
                (Outcome::Closed, _) => this.report_lock(None, &vault.lock()),
                (Outcome::Locked, result) => {
                    let lock = vault.lock();
                    this.vault = Some(vault);
                    this.sync.restore = None;
                    if let Err(e) = result {
                        this.set_toast(Toast::window(format!("Restore failed: {e}")));
                    }
                    this.report_lock(None, &lock);
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

    /// The trash button on a backup row: show the row's inline confirm. Works while
    /// locked (deleting a file needs no key); waits while the vault is in a task.
    pub fn request_delete_backup(&mut self, backup: PathBuf, cx: &mut Context<Self>) {
        if self.busy.is_some() || self.vault.is_none() {
            return;
        }
        self.sync.restore = None;
        self.sync.delete_confirm = Some(backup);
        cx.notify();
    }

    pub fn cancel_delete_backup(&mut self, cx: &mut Context<Self>) {
        if self.sync.delete_confirm.take().is_some() {
            cx.notify();
        }
    }

    /// "Delete" in the confirm: removes the snapshot file or conflict package (03 §8).
    /// No undo. Runs as a task like the other vault operations, so a lock or close while
    /// it runs discards the result.
    pub fn confirm_delete_backup(&mut self, cx: &mut Context<Self>) {
        if self.busy.is_some() {
            return;
        }
        let Some(backup) = self.sync.delete_confirm.take() else {
            return;
        };
        let Some(mut vault) = self.vault.take() else {
            cx.notify();
            return;
        };
        self.run_bg_cx(
            Busy::DeletingBackup,
            cx,
            move || {
                let result = vault.delete_backup(&backup);
                (vault, backup, result)
            },
            |this, (mut vault, backup, result), outcome, cx| match outcome {
                Outcome::Closed => this.report_lock(None, &vault.lock()),
                Outcome::Locked => {
                    this.report_lock(None, &vault.lock());
                    this.vault = Some(vault);
                    this.refresh_backups();
                }
                Outcome::Fresh => {
                    this.vault = Some(vault);
                    this.refresh_backups();
                    if let Err(e) = result {
                        let reason = delete_failure_reason(&e, &backup);
                        this.show_toast(format!("Could not delete backup: {reason}"), cx);
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
        self.set_toast(Toast::window(format!("Restored from {name}")));
    }
}

/// Status line and toast text for a refused save (03 §3).
fn save_blocked_message(blocked: &SaveBlocked) -> &'static str {
    match blocked {
        SaveBlocked::NewerVersion(_) => {
            "Not saving: a newer version of Vault wrote this vault. Update Vault to keep editing."
        }
        SaveBlocked::ForeignVault => {
            "Not saving: the vault file on disk now holds a different vault."
        }
    }
}

/// Why `delete_backup` failed, without the backup's path (05 §2.5).
fn delete_failure_reason(e: &SyncError, backup: &Path) -> String {
    match e {
        SyncError::Io { source, .. } => source.to_string(),
        SyncError::SaveLockTimeout(_) => SAVE_BUSY.into(),
        other => {
            let message = other.to_string();
            let mut scrubbed =
                message.replace(&backup.display().to_string(), &text::file_name(backup));
            if let Some(dir) = backup.parent().filter(|d| !d.as_os_str().is_empty()) {
                scrubbed = scrubbed.replace(&dir.display().to_string(), "backups");
            }
            scrubbed
        }
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
            danger: false,
        }
    }

    /// A window toast in the danger colour that stays up longer: unsaved edits were lost.
    pub(super) fn danger(message: impl Into<SharedString>) -> Self {
        Self {
            danger: true,
            ttl: DANGER_TOAST_TTL,
            ..Self::window(message)
        }
    }
}

/// Long enough to read a data-loss warning twice.
const DANGER_TOAST_TTL: std::time::Duration = std::time::Duration::from_secs(10);

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
    use vault_core::{ExposeSecret as _, Field, FieldKind, KdfParams, MergeReport, Uuid};
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
                let mut gh = Item::new("GitHub", device, 10);
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
            s.begin_new(crate::templates::Template::Note, String::new(), cx);
            s.handle_sync_event(SyncEvent::Merged(changed), cx);
            assert!(s.edit_buffer().unwrap().remote_fields.is_empty());
        });
    }

    #[gpui::test]
    fn missing_primary_is_written_again_by_autosave(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, _) = two_devices(dir.path(), cx);
        let path = dir.path().join("t.vault").join("vault.bin");
        fs::remove_file(&path).unwrap();
        assert!(wait_for(&state, cx, |s| s
            .toast
            .as_ref()
            .is_some_and(|t| t.message.contains("went missing"))));
        cx.executor().advance_clock(AUTOSAVE_DEBOUNCE);
        cx.run_until_parked();
        let bytes = fs::read(&path).expect("vault.bin recreated");
        assert!(vault_core::LockedVault::parse(&bytes).is_ok());
        state.read_with(cx, |s, _| assert!(!s.vault.as_ref().unwrap().is_dirty()));
    }

    #[gpui::test]
    fn corrupt_banner_shows_and_clears_on_next_save(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, _) = two_devices(dir.path(), cx);
        let path = dir.path().join("t.vault").join("vault.bin");
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
            .edit(|v| v.rotate_vault_key(&secret(PW), crate::text::now_millis()))
            .unwrap()
            .unwrap();
        other
            .edit(|v| v.insert(Item::new("from b", Uuid::nil(), 40), 40))
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
            .edit(|v| v.rotate_vault_key(&secret(PW), crate::text::now_millis()))
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

    /// The package's save lock held by "another process" (03 §2): the save waits out the
    /// 10 s timeout once, toasts, and the autosave retries once 2 s later.
    #[gpui::test]
    fn busy_save_toasts_and_autosave_retries_once(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, _) = two_devices(dir.path(), cx);
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.path().join("t.vault").join(".lock"))
            .unwrap();
        lock.lock().unwrap();
        state.update(cx, |s, cx| {
            s.toggle_favorite(cx);
            s.autosave = None;
            s.autosave_pending = false;
            s.save_now(cx);
            assert_eq!(s.toast.as_ref().unwrap().message.as_ref(), SAVE_BUSY);
            assert!(s.sync.save_failing && s.sync.busy_retried);
            assert!(s.autosave_pending, "one retry scheduled");
        });
        lock.unlock().unwrap();
        cx.executor().advance_clock(AUTOSAVE_DEBOUNCE);
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(!s.vault.as_ref().unwrap().is_dirty(), "the retry saved");
            assert!(!s.sync.save_failing && !s.sync.busy_retried);
        });

        // A retry that hits the lock again gives up until the next edit.
        let busy = || Err(SyncError::SaveLockTimeout(dir.path().join("t.vault")));
        state.update(cx, |s, cx| {
            s.autosave_finished(busy(), cx);
            assert!(s.sync.busy_retried && s.autosave_pending);
            s.autosave = None;
            s.autosave_pending = false;
            s.autosave_finished(busy(), cx);
            assert!(!s.autosave_pending, "no second retry");
            assert!(!s.sync.busy_retried, "the next edit's save may retry again");
            assert_eq!(s.toast.as_ref().unwrap().message.as_ref(), SAVE_BUSY);
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

            // A re-key raises the password prompt; the Merged after re-verifying clears it
            // and says the new key is in use. Later merges report changes as usual.
            s.handle_sync_event(SyncEvent::KeyRotatedOnDisk, cx);
            assert!(s.sync.key_mismatch);
            let changed = MergeReport {
                added: 1,
                ..MergeReport::default()
            };
            s.handle_sync_event(SyncEvent::Merged(changed), cx);
            assert!(!s.sync.key_mismatch);
            assert_eq!(
                s.toast.as_ref().unwrap().message.as_ref(),
                KEY_ROTATED_RESOLVED
            );
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
                SyncEvent::SaveBlocked(SaveBlocked::NewerVersion(99)),
                SyncEvent::SaveBlocked(SaveBlocked::ForeignVault),
                SyncEvent::BackupDeleted(p.join("b.vault")),
                SyncEvent::AttachmentsPruned(1),
                SyncEvent::PrimaryMissing,
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
            s.begin_new(crate::templates::Template::Login, String::new(), cx);
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
            s.begin_new(crate::templates::Template::Note, "draft".into(), cx);
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

    /// Takes a snapshot and returns its path, plus a conflict package of the same vault.
    fn backups_with_conflict(
        state: &Entity<AppState>,
        cx: &mut TestAppContext,
    ) -> (PathBuf, PathBuf) {
        state.update(cx, |s, cx| s.backup_now(cx));
        let snapshot = state.read_with(cx, |s, _| s.sync.backups[0].path.clone());
        let file = text::file_name(&snapshot);
        let stamp = &file["t-".len().."t-".len() + 20];
        let conflict = snapshot
            .parent()
            .unwrap()
            .join(format!("conflict-{stamp}-t (conflicted copy).vault"));
        fs::create_dir(&conflict).unwrap();
        fs::copy(&snapshot, conflict.join("vault.bin")).unwrap();
        state.update(cx, |s, _| s.refresh_backups());
        (snapshot, conflict)
    }

    fn listed(state: &Entity<AppState>, path: &Path, cx: &mut TestAppContext) -> bool {
        state.read_with(cx, |s, _| s.sync.backups.iter().any(|b| b.path == path))
    }

    #[gpui::test]
    fn delete_backup_removes_the_row_and_the_file_or_package(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, _) = two_devices(dir.path(), cx);
        let (snapshot, conflict) = backups_with_conflict(&state, cx);
        assert!(listed(&state, &conflict, cx), "conflict package listed");
        for path in [&snapshot, &conflict] {
            state.update(cx, |s, cx| {
                s.toast = None;
                s.request_delete_backup(path.clone(), cx);
                assert_eq!(s.sync.delete_confirm.as_ref(), Some(path));
                s.confirm_delete_backup(cx);
                assert_eq!(s.busy, Some(Busy::DeletingBackup));
            });
            cx.run_until_parked();
            state.read_with(cx, |s, _| {
                assert!(s.busy.is_none() && s.vault.is_some() && s.sync.delete_confirm.is_none());
                assert!(s.toast.is_none(), "no toast on success");
            });
            assert!(!path.exists(), "{} still on disk", path.display());
            assert!(!listed(&state, path, cx));
        }
    }

    #[gpui::test]
    fn cancel_keeps_the_backup(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, _) = two_devices(dir.path(), cx);
        let (snapshot, _) = backups_with_conflict(&state, cx);
        state.update(cx, |s, cx| {
            s.request_delete_backup(snapshot.clone(), cx);
            s.cancel_delete_backup(cx);
            assert!(s.sync.delete_confirm.is_none());
            // Delete without a confirm up does nothing.
            s.confirm_delete_backup(cx);
            assert!(s.busy.is_none());
        });
        cx.run_until_parked();
        assert!(snapshot.exists());
        assert!(listed(&state, &snapshot, cx));
    }

    #[gpui::test]
    fn delete_failure_toasts_without_the_path(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, _) = two_devices(dir.path(), cx);
        // vault-sync refuses anything outside backups/.
        let outside = dir.path().join("t-elsewhere.vault.bin");
        fs::write(&outside, b"x").unwrap();
        state.update(cx, |s, cx| {
            s.toast = None;
            s.request_delete_backup(outside.clone(), cx);
            s.confirm_delete_backup(cx);
        });
        cx.run_until_parked();
        let message = state.read_with(cx, |s, _| s.toast.as_ref().unwrap().message.to_string());
        assert!(
            message.starts_with("Could not delete backup: "),
            "{message}"
        );
        let dir_text = dir.path().display().to_string();
        assert!(!message.contains(&dir_text), "path leaked: {message}");
        assert!(outside.exists());
        state.read_with(cx, |s, _| assert!(s.vault.is_some() && s.busy.is_none()));
    }

    #[gpui::test]
    fn lock_mid_delete_discards_the_result(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, _) = two_devices(dir.path(), cx);
        let (snapshot, _) = backups_with_conflict(&state, cx);
        state.update(cx, |s, cx| {
            s.toast = None;
            s.request_delete_backup(snapshot.clone(), cx);
            s.confirm_delete_backup(cx);
            // ⌘L lands while the vault is inside the task.
            s.lock(cx);
        });
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(s.locked && s.vault.is_some() && s.busy.is_none());
            assert!(
                s.vault.as_ref().unwrap().vault().is_none(),
                "returned vault is locked"
            );
            assert!(s.sync.delete_confirm.is_none());
            assert!(s.toast.is_none(), "no toast after the lock");
        });
        // The list matches the disk, whatever the task finished doing.
        assert_eq!(listed(&state, &snapshot, cx), snapshot.exists());
    }

    #[gpui::test]
    fn backup_deleted_event_refreshes_the_list(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, _) = two_devices(dir.path(), cx);
        let (snapshot, _) = backups_with_conflict(&state, cx);
        fs::remove_file(&snapshot).unwrap();
        assert!(listed(&state, &snapshot, cx), "stale until the event");
        state.update(cx, |s, cx| {
            s.handle_sync_event(SyncEvent::BackupDeleted(snapshot.clone()), cx)
        });
        assert!(!listed(&state, &snapshot, cx));
    }

    /// The watcher reports a rotation elsewhere at detection time: the edit stays open, the
    /// password prompt comes up, and saving is refused until it is resolved.
    #[gpui::test]
    fn key_rotated_on_disk_keeps_the_edit_and_prompts(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, mut other, _) = two_devices(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.begin_edit(cx);
            s.toast = None;
        });
        rotate_elsewhere(&state, &mut other, cx);
        state.update(cx, |s, cx| {
            assert!(s.is_editing(), "edit buffer kept");
            assert!(s.sync.has_banner() && s.sync.key_mismatch_error.is_none());
            assert!(
                s.vault.as_mut().unwrap().save().is_err(),
                "cached key refused"
            );
            assert!(s.sync.key_rotated, "rotation wording");
            // A second report changes nothing and does not toast.
            s.handle_sync_event(SyncEvent::KeyRotatedOnDisk, cx);
            assert!(s.sync.key_mismatch && s.toast.is_none());
            s.resolve_key_mismatch(secret(PW), cx);
        });
        cx.run_until_parked();
        state.update(cx, |s, cx| s.tick(0.0, cx));
        state.read_with(cx, |s, _| {
            assert!(!s.sync.key_mismatch && !s.sync.key_rotated);
            assert!(s.is_editing(), "edit survives the re-verify");
            assert_eq!(
                s.toast.as_ref().unwrap().message.as_ref(),
                KEY_ROTATED_RESOLVED
            );
        });
        // A plain mismatch keeps the generic wording.
        state.update(cx, |s, cx| {
            s.handle_sync_event(SyncEvent::KeyMismatch, cx);
            assert!(s.sync.key_mismatch && !s.sync.key_rotated);
        });
    }

    #[gpui::test]
    fn save_blocked_shows_the_reason_once_and_stops_autosave(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _other, _) = two_devices(dir.path(), cx);
        for blocked in [SaveBlocked::NewerVersion(99), SaveBlocked::ForeignVault] {
            state.update(cx, |s, cx| {
                s.sync.save_failing = false;
                s.toast = None;
                s.handle_sync_event(SyncEvent::SaveBlocked(blocked), cx);
                let message = save_blocked_message(&blocked);
                assert_eq!(s.toast.as_ref().unwrap().message.as_ref(), message);
                assert_eq!(s.sync_status, SyncStatus::Error(message.into()));
                assert!(s.sync.save_failing);
                // Repeats (every refused save emits one) stay quiet.
                s.toast = None;
                s.handle_sync_event(SyncEvent::SaveBlocked(blocked), cx);
                assert!(s.toast.is_none());
                // Dirty, but a failing save is not retried by the tick.
                s.toggle_favorite(cx);
                s.autosave_pending = false;
                s.poll_sync(cx);
                assert!(!s.autosave_pending);
            });
        }
    }
}
