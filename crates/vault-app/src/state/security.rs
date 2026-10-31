//! Settings ▸ Security (specs/05-ui.md §2.5): change the master password, re-calibrate the
//! KDF, rotate the vault key. Turning Touch ID off also runs through [`AppState::security_task`];
//! enabling it and the policy live in `touch_id.rs`.
//!
//! Each operation does Argon2 work, so it moves the vault into a background task through
//! `run_bg` (like unlock and restore): `busy` is set, `poll_sync` leaves sync events queued,
//! and the vault is saved on that thread before it comes back, so a lock or quit during the
//! Argon2 window cannot lose the re-keyed header. Each goes through the unsaved-changes
//! guard first.

use std::time::{Duration, Instant};

use gpui::{Context, SharedString};
use vault_core::{ExposeSecret as _, KdfParams, SecretString, UnlockedVault, Uuid, VaultError};
use vault_sync::{SyncError, SyncedVault};

use super::{AppState, Busy, KDF_TARGET, Navigation, Outcome, Toast};

/// Index of the Security tab in the settings sheet.
pub const SECURITY_TAB: usize = 1;

/// The inline form open in the Security tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityForm {
    /// Current, new and confirm fields.
    ChangePassword,
    /// Master password prompt before re-calibrating.
    Recalibrate,
    /// Red confirm with a master password prompt.
    RotateKey,
    /// Master password prompt before turning Touch ID off.
    DisableTouchId,
}

/// Argon2 costs of a measurement (the salt does not affect timing).
pub type KdfCost = (u32, u32, u32);

fn cost(p: &KdfParams) -> KdfCost {
    (p.m_cost_kib, p.t_cost, p.p_cost)
}

#[derive(Debug)]
pub struct SecurityUi {
    pub form: Option<SecurityForm>,
    /// Inline error under the open form.
    pub error: Option<SharedString>,
    /// The "Advanced" disclosure holding "Rotate vault key". Collapsed by default.
    pub advanced_open: bool,
    /// One derivation with these costs took this long on this Mac. Per costs, not per
    /// vault, so it survives switching vaults and goes stale after a re-calibration.
    pub kdf_timing: Option<(KdfCost, Duration)>,
    pub measuring: bool,
    /// Target of "Re-calibrate" (01 §6). Tests lower it so calibration stops at once.
    pub calibration_target: Duration,
}

impl Default for SecurityUi {
    fn default() -> Self {
        Self {
            form: None,
            error: None,
            advanced_open: false,
            kdf_timing: None,
            measuring: false,
            calibration_target: KDF_TARGET,
        }
    }
}

/// Why a security operation failed.
pub(super) enum Failure {
    /// Refused before anything changed (wrong password, bad params): shown inline.
    Refused(String),
    /// The change was made in memory but not written.
    Save(SyncError),
}

impl Failure {
    /// A refusal from vault-sync, with the user-facing wrong-password text.
    pub(super) fn refused(e: SyncError) -> Self {
        match e {
            SyncError::Vault(v) => Self::Refused(vault_error_message(&v)),
            other => Self::Refused(other.to_string()),
        }
    }
}

fn vault_error_message(e: &VaultError) -> String {
    match e {
        VaultError::WrongPassword => "The master password is wrong.".into(),
        other => other.to_string(),
    }
}

impl AppState {
    /// KDF params in the unlocked vault's header.
    pub fn current_kdf(&self) -> Option<KdfParams> {
        self.unlocked_vault().map(|v| v.header().kdf.clone())
    }

    /// Seconds one derivation with the current params took, if measured.
    pub fn kdf_seconds(&self) -> Option<f64> {
        let now = self.current_kdf()?;
        self.security
            .kdf_timing
            .filter(|(c, _)| *c == cost(&now))
            .map(|(_, d)| d.as_secs_f64())
    }

    /// Times one derivation of the current params in the background, unless a fresh
    /// measurement is cached or one is running. Called while the Security tab is visible.
    pub fn measure_kdf(&mut self, cx: &mut Context<Self>) {
        if self.security.measuring || self.locked {
            return;
        }
        let Some(params) = self.current_kdf() else {
            return;
        };
        if self.kdf_seconds().is_some() {
            return;
        }
        self.security.measuring = true;
        let costs = cost(&params);
        let task = cx.background_executor().spawn(async move {
            // vault-core exposes no bare derivation; creating a throwaway vault runs
            // exactly one Argon2 derivation with these params (plus microseconds of AEAD).
            let probe = SecretString::new("vault-kdf-probe".to_owned());
            let started = Instant::now();
            drop(UnlockedVault::create(&probe, params, Uuid::nil()));
            started.elapsed()
        });
        cx.spawn(async move |this, cx| {
            let elapsed = task.await;
            this.update(cx, |this, cx| {
                this.security.measuring = false;
                this.security.kdf_timing = Some((costs, elapsed));
                cx.notify();
            })
            .ok();
        })
        .detach();
        cx.notify();
    }

    /// Opens one inline form (closing any other), or closes it with `None`.
    pub fn set_security_form(&mut self, form: Option<SecurityForm>, cx: &mut Context<Self>) {
        if self.busy.is_some() {
            return;
        }
        self.security.form = form;
        self.security.error = None;
        cx.notify();
    }

    pub fn toggle_security_advanced(&mut self, cx: &mut Context<Self>) {
        self.security.advanced_open = !self.security.advanced_open;
        if !self.security.advanced_open && self.security.form == Some(SecurityForm::RotateKey) {
            self.security.form = None;
            self.security.error = None;
        }
        cx.notify();
    }

    /// Closes the forms (sheet closed, vault locked).
    pub(super) fn reset_security_forms(&mut self) {
        self.security.form = None;
        self.security.error = None;
        self.security.advanced_open = false;
    }

    fn security_error(&mut self, message: &str, cx: &mut Context<Self>) {
        self.security.error = Some(SharedString::from(message.to_owned()));
        cx.notify();
    }

    /// "Change Password": the header's current Argon2 costs with a fresh salt.
    pub fn change_master_password(
        &mut self,
        current: SecretString,
        new: SecretString,
        confirm: SecretString,
        cx: &mut Context<Self>,
    ) {
        if new.expose_secret().is_empty() {
            return self.security_error("Choose a new master password.", cx);
        }
        if new.expose_secret() != confirm.expose_secret() {
            return self.security_error("The new passwords do not match.", cx);
        }
        drop(confirm);
        self.security_op(
            Busy::ChangingPassword,
            cx,
            move |v| {
                let kdf = KdfParams {
                    // `recommended` draws a fresh 32-byte salt from OsRng.
                    salt: KdfParams::recommended().salt,
                    ..v.header().kdf.clone()
                };
                v.change_password(&current, &new, kdf, crate::text::now_millis())
            },
            |_: &mut Self| "Master password changed".into(),
        );
    }

    /// "Re-calibrate": measure this Mac (01 §6), then re-wrap the vault key under the same
    /// password with the new params.
    pub fn recalibrate_kdf(&mut self, password: SecretString, cx: &mut Context<Self>) {
        let target = self.security.calibration_target;
        self.security_op(
            Busy::Recalibrating,
            cx,
            move |v| {
                let kdf = KdfParams::calibrate(target);
                v.change_password(&password, &password, kdf, crate::text::now_millis())
            },
            |_: &mut Self| "Encryption re-calibrated for this Mac".into(),
        );
    }

    /// "Rotate Key": a fresh vault key; core drops any Touch ID (enclave) slot.
    pub fn rotate_key(&mut self, password: SecretString, cx: &mut Context<Self>) {
        // Core drops every enclave slot; this Mac's Keychain item goes with it.
        let had_touch_id = self.touch_enabled()
            || self
                .vault_id
                .is_some_and(|id| self.settings.touch_id.contains_key(&id));
        let (bio, vault_id) = (self.biometrics.clone(), self.vault_id);
        self.security_op(
            Busy::RotatingKey,
            cx,
            move |v| {
                v.rotate_vault_key(&password, crate::text::now_millis())?;
                if let Some(id) = vault_id
                    && let Err(e) = bio.unenroll(id)
                {
                    eprintln!("vault: could not remove the Touch ID Keychain item: {e}");
                }
                Ok(())
            },
            move |this| {
                this.touch_rotated();
                if had_touch_id {
                    "Vault key rotated. Touch ID must be re-enrolled.".into()
                } else {
                    "Vault key rotated".into()
                }
            },
        );
    }

    /// Runs `op` on the vault in the background, then saves there. `done` builds the toast.
    fn security_op(
        &mut self,
        busy: Busy,
        cx: &mut Context<Self>,
        op: impl FnOnce(&mut UnlockedVault) -> Result<(), VaultError> + Send + 'static,
        done: impl FnOnce(&mut Self) -> String + 'static,
    ) {
        self.security_task(
            busy,
            cx,
            move |vault| {
                vault
                    .edit(op)
                    .map_err(Failure::Save)?
                    .map_err(|e| Failure::Refused(vault_error_message(&e)))?;
                vault.save().map_err(Failure::Save)
            },
            done,
        );
    }

    /// The single home of the guard, the vault hand-off and the Closed / Locked / Fresh
    /// handling for Security operations. `work` runs on the background executor with the
    /// unlocked vault and must save itself. `done` runs (and builds the toast) when `work`
    /// succeeded, unless the vault was closed meanwhile.
    pub(super) fn security_task(
        &mut self,
        busy: Busy,
        cx: &mut Context<Self>,
        work: impl FnOnce(&mut SyncedVault) -> Result<(), Failure> + Send + 'static,
        done: impl FnOnce(&mut Self) -> String + 'static,
    ) {
        if self.busy.is_some() || self.locked || self.vault.is_none() {
            return;
        }
        if !self.guard(Navigation::Security, cx) {
            // The guard's prompt lives in the editor; "Discard" reopens this tab.
            self.settings_open = false;
            cx.notify();
            return;
        }
        let Some(mut vault) = self.vault.take() else {
            return;
        };
        self.security.error = None;
        self.run_bg(
            busy,
            cx,
            move || {
                let result = work(&mut vault);
                (vault, result)
            },
            move |this, (mut vault, result), outcome| match (outcome, result) {
                (Outcome::Closed, _) => this.report_lock(None, &vault.lock()),
                (Outcome::Locked, result) => {
                    let lock = vault.lock();
                    this.vault = Some(vault);
                    let save_error = match result {
                        Ok(()) => {
                            let message = done(this);
                            this.set_toast(Toast::window(message));
                            None
                        }
                        Err(Failure::Save(e)) => Some(super::error_message(&e)),
                        Err(Failure::Refused(_)) => None,
                    };
                    // Last, so what happened to the unsaved change is what the user sees.
                    this.report_lock(save_error.as_deref(), &lock);
                }
                (Outcome::Fresh, Ok(())) => {
                    this.vault = Some(vault);
                    this.record_save(Ok(()));
                    this.security.form = None;
                    let message = done(this);
                    this.set_toast(Toast::window(message));
                }
                (Outcome::Fresh, Err(Failure::Refused(message))) => {
                    this.vault = Some(vault);
                    this.security.error = Some(message.into());
                }
                (Outcome::Fresh, Err(Failure::Save(e))) => {
                    this.vault = Some(vault);
                    this.security.form = None;
                    // Still dirty: the next edit's autosave retries.
                    if let Some(msg) = this.record_save(Err(e)) {
                        this.toast =
                            Some(Toast::window(format!("Changed, but not saved yet: {msg}")));
                    }
                }
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use gpui::{AppContext as _, Entity, TestAppContext};
    use vault_core::{Item, LockedVault};
    use vault_sync::{NoopHooks, SyncedVault};

    use super::*;
    use crate::state::{EditBuffer, Mode, Screen};

    const PW: &str = "correct horse";

    fn secret(s: &str) -> SecretString {
        SecretString::new(s.to_owned())
    }

    /// A vault on disk with two items, opened and unlocked in a fresh state.
    fn setup(dir: &Path, cx: &mut TestAppContext) -> (Entity<AppState>, PathBuf) {
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
        for title in ["GitHub", "Bank"] {
            vault
                .edit(|v| v.insert(Item::new(title, device, 1), 1))
                .unwrap();
        }
        vault.save().unwrap();
        drop(vault);
        let state = open(&path, PW, cx);
        state.read_with(cx, |s, _| assert!(!s.locked, "setup unlock"));
        (state, path)
    }

    /// Opens `path` in a new state and tries to unlock it with `pw`.
    fn open(path: &Path, pw: &str, cx: &mut TestAppContext) -> Entity<AppState> {
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        let p = path.to_owned();
        state.update(cx, |s, cx| s.open_vault(p, cx));
        cx.run_until_parked();
        state.update(cx, |s, cx| s.unlock(secret(pw), cx));
        cx.run_until_parked();
        state
    }

    fn unlocks(path: &Path, pw: &str, cx: &mut TestAppContext) -> bool {
        let state = open(path, pw, cx);
        state.read_with(cx, |s, _| !s.locked)
    }

    fn on_disk_kdf(path: &Path) -> KdfParams {
        LockedVault::parse(&std::fs::read(path.join("vault.bin")).unwrap())
            .unwrap()
            .kdf_params()
            .clone()
    }

    /// `header.slots_modified_at` of the file on disk (0 when absent).
    fn on_disk_slots_stamp(path: &Path) -> u64 {
        LockedVault::parse(&std::fs::read(path.join("vault.bin")).unwrap())
            .unwrap()
            .header()
            .slots_stamp()
    }

    fn titles(state: &Entity<AppState>, cx: &mut TestAppContext) -> Vec<String> {
        state.read_with(cx, |s, _| {
            let mut t: Vec<_> = s
                .unlocked_vault()
                .unwrap()
                .items()
                .map(|i| i.title.clone())
                .collect();
            t.sort();
            t
        })
    }

    #[gpui::test]
    fn change_password_round_trip(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, path) = setup(dir.path(), cx);
        let before = on_disk_kdf(&path);
        let stamp_before = on_disk_slots_stamp(&path);

        // Validation and a wrong current password leave everything as it was.
        state.update(cx, |s, cx| {
            s.set_security_form(Some(SecurityForm::ChangePassword), cx);
            s.change_master_password(secret(PW), secret("a"), secret("b"), cx);
            assert_eq!(
                s.security.error.as_deref(),
                Some("The new passwords do not match.")
            );
            assert!(s.busy.is_none());
            s.change_master_password(secret("wrong"), secret("new pw"), secret("new pw"), cx);
            assert_eq!(s.busy, Some(Busy::ChangingPassword));
            assert!(s.vault.is_none(), "vault moved into the task");
        });
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(s.busy.is_none());
            assert_eq!(
                s.security.error.as_deref(),
                Some("The master password is wrong.")
            );
            assert_eq!(s.security.form, Some(SecurityForm::ChangePassword));
        });
        assert!(unlocks(&path, PW, cx));
        assert_eq!(
            on_disk_slots_stamp(&path),
            stamp_before,
            "refused: header untouched"
        );

        state.update(cx, |s, cx| {
            s.change_master_password(secret(PW), secret("new pw"), secret("new pw"), cx)
        });
        cx.run_until_parked();
        // Saved at once with a newer stamp, so the header wins the merge elsewhere (03 §5).
        assert!(on_disk_slots_stamp(&path) > stamp_before);
        state.read_with(cx, |s, _| {
            assert!(s.security.error.is_none());
            assert!(s.security.form.is_none(), "form closes on success");
            assert!(!s.locked);
            assert!(s.toast.as_ref().unwrap().message.contains("changed"));
        });
        assert!(
            !unlocks(&path, PW, cx),
            "old password no longer opens the file"
        );
        let reopened = open(&path, "new pw", cx);
        assert_eq!(titles(&reopened, cx), ["Bank", "GitHub"]);
        let after = on_disk_kdf(&path);
        assert_eq!(cost(&after), cost(&before), "same Argon2 costs");
        assert_ne!(after.salt, before.salt, "fresh salt");
    }

    #[gpui::test]
    fn rotate_round_trip(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, path) = setup(dir.path(), cx);
        let bytes_before = std::fs::read(path.join("vault.bin")).unwrap();
        let stamp_before = on_disk_slots_stamp(&path);
        state.update(cx, |s, cx| s.rotate_key(secret("wrong"), cx));
        cx.run_until_parked();
        state.read_with(cx, |s, _| assert!(s.security.error.is_some()));

        state.update(cx, |s, cx| s.rotate_key(secret(PW), cx));
        cx.run_until_parked();
        assert!(
            on_disk_slots_stamp(&path) > stamp_before,
            "rotation saved with a newer stamp"
        );
        state.read_with(cx, |s, _| {
            assert!(s.security.error.is_none());
            assert_eq!(
                s.toast.as_ref().unwrap().message.as_ref(),
                "Vault key rotated",
                "no enclave slot, so no Touch ID note"
            );
        });
        assert_eq!(titles(&state, cx), ["Bank", "GitHub"]);
        let reopened = open(&path, PW, cx);
        assert_eq!(titles(&reopened, cx), ["Bank", "GitHub"]);
        // The pre-rotation key no longer opens the file: it really was re-keyed.
        let old = LockedVault::parse(&bytes_before)
            .unwrap()
            .unlock(&secret(PW))
            .unwrap();
        let now = LockedVault::parse(&std::fs::read(path.join("vault.bin")).unwrap()).unwrap();
        assert!(matches!(
            now.unlock_with_key(&old.export_vault_key(), Uuid::new_v4()),
            Err(VaultError::WrongPassword)
        ));
    }

    #[gpui::test]
    fn recalibrate_changes_on_disk_kdf(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, path) = setup(dir.path(), cx);
        let before = on_disk_kdf(&path);
        let stamp_before = on_disk_slots_stamp(&path);
        state.update(cx, |s, cx| {
            // Zero target: calibrate stops after one probe at the recommended params.
            s.security.calibration_target = Duration::ZERO;
            s.recalibrate_kdf(secret(PW), cx);
            assert_eq!(s.busy, Some(Busy::Recalibrating));
        });
        cx.run_until_parked();
        let after = on_disk_kdf(&path);
        assert!(
            on_disk_slots_stamp(&path) > stamp_before,
            "saved with a newer stamp"
        );
        assert_ne!(cost(&after), cost(&before));
        assert_eq!(cost(&after), cost(&KdfParams::recommended()));
        state.read_with(cx, |s, _| {
            assert!(s.security.error.is_none());
            assert_eq!(s.current_kdf().map(|k| cost(&k)), Some(cost(&after)));
            assert!(s.kdf_seconds().is_none(), "old measurement is stale");
        });
        state.update(cx, |s, cx| s.measure_kdf(cx));
        cx.run_until_parked();
        state.read_with(cx, |s, _| assert!(s.kdf_seconds().is_some()));
        assert!(unlocks(&path, PW, cx));
    }

    #[gpui::test]
    fn unsaved_edit_guards_security_ops(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, path) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.settings_open = true;
            s.settings_tab = SECURITY_TAB;
            let device = s.device_id();
            let mut buffer = EditBuffer::new(Item::new("x", device, 1));
            buffer.item.title = "changed".into();
            s.mode = Mode::Edit(buffer);
            s.rotate_key(secret(PW), cx);
            assert!(s.busy.is_none(), "blocked by the guard");
            assert!(!s.settings_open, "sheet closes so the editor prompt shows");
            assert!(s.discard_prompt.is_some());
            s.discard_changes(cx);
            assert!(s.settings_open);
            assert_eq!(s.settings_tab, SECURITY_TAB);
            assert!(matches!(s.mode, Mode::View));
            assert_eq!(s.screen, Screen::Main);
        });
        assert!(unlocks(&path, PW, cx));
    }

    #[gpui::test]
    fn lock_during_a_failed_save_shows_the_danger_toast(cx: &mut TestAppContext) {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let (state, path) = setup(dir.path(), cx);
        let backups = path.join("backups");
        std::fs::create_dir_all(&backups).unwrap();
        let mode = |p: &Path, m| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        };
        // Neither the save nor the Unsaved backup can be written.
        mode(&path, 0o500);
        mode(&backups, 0o500);
        state.update(cx, |s, cx| {
            s.security_task(
                Busy::ChangingPassword,
                cx,
                |vault| {
                    let device = vault.device_id();
                    vault
                        .edit(|v| v.insert(vault_core::Item::new("New", device, 5), 5))
                        .map_err(Failure::Save)?;
                    vault.save().map_err(Failure::Save)
                },
                |_| "done".into(),
            );
            // Locked while the task holds the vault: the Locked branch handles it.
            s.lock(cx);
        });
        cx.run_until_parked();
        mode(&backups, 0o700);
        mode(&path, 0o700);
        state.read_with(cx, |s, _| {
            assert!(s.locked);
            let toast = s.toast.as_ref().expect("a toast");
            assert!(toast.danger, "{}", toast.message);
            assert!(toast.message.starts_with(super::super::LOCK_LOST));
        });
    }
}
