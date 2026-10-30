//! Touch ID enrollment, unlock and policy (specs/04-macos.md §2; specs/05-ui.md §2.2, §2.5).
//!
//! Per vault, `settings.json` keeps a [`TouchIdPolicy`] (no secrets): the enclave slot id,
//! when Touch ID was enabled, the last master-password unlock and the failed Touch ID
//! attempts since. Touch ID is offered only while the policy allows it:
//! - the Mac has not restarted since the last master-password unlock (`boot_time`),
//! - that unlock is less than 7 days old,
//! - fewer than 5 Touch ID attempts failed since,
//! - the enrollment is not stale (fingerprints changed, slot gone).
//!
//! A stale enrollment is removed (Keychain item, Secure Enclave key, enclave slot) right
//! after the next successful master-password unlock, on the unlock's background thread.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gpui::{Context, SharedString};
use rand::RngCore as _;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use vault_core::{SecretString, SecretVec, SlotKind, Uuid, VaultError};
use vault_macos::MacError;
use vault_sync::{SyncError, SyncedVault};

use super::security::Failure;
use super::{AppState, Busy, Navigation, Outcome, Toast};
use crate::biometric::Biometrics;

/// Master password required again after this long.
pub const PASSWORD_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Master password required again after this many failed Touch ID attempts.
pub const MAX_TOUCH_FAILURES: u32 = 5;

/// Toast when a merge took away this Mac's enclave slot.
pub const SLOT_GONE: &str = "Another device changed this vault's keys, so Touch ID must be set up \
                             again in Settings \u{25b8} Security.";

/// Persisted per vault in `settings.json` under `touch_id.<vault_id>`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TouchIdPolicy {
    /// The enclave key slot this Mac added.
    pub slot_id: Uuid,
    /// Unix seconds.
    pub enrolled_at: u64,
    /// Unix seconds of the last successful master-password unlock.
    pub last_password_unlock_at: u64,
    pub failed_touch_attempts: u32,
    /// Fingerprints changed or the slot is gone: removed after the next password unlock.
    pub stale: bool,
}

/// Why Touch ID is not offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchDenied {
    NotEnrolled,
    Stale,
    Rebooted,
    Expired,
    TooManyFailures,
}

impl TouchDenied {
    /// Hint under the password field on the unlock screen.
    pub fn hint(self) -> Option<&'static str> {
        match self {
            Self::NotEnrolled => None,
            Self::Stale => Some(
                "Touch ID must be set up again. Enter your master password, then turn it on \
                 in Settings.",
            ),
            Self::Rebooted => Some("Enter your master password. It is required after a restart."),
            Self::Expired => Some("Enter your master password. It is required every 7 days."),
            Self::TooManyFailures => {
                Some("Enter your master password. It is required after 5 failed Touch ID attempts.")
            }
        }
    }
}

/// When the unlock screen should start Touch ID by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TouchAuto {
    #[default]
    Off,
    /// The vault was just opened: start when the unlock screen appears.
    OnAppear,
    /// The vault was locked: start when the window is next activated, not right away
    /// (a ⌘L or auto-lock must not pop the Touch ID sheet at once).
    OnActivation,
}

/// Session-only Touch ID state.
#[derive(Debug, Default)]
pub struct TouchUi {
    /// `Biometrics::available`, refreshed on open and when the settings sheet opens.
    pub available: bool,
    /// The Keychain item for this vault exists and a policy entry describes it.
    pub enrolled: bool,
    pub auto: TouchAuto,
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Unenrolls and removes `slot` from the unlocked `vault`, then saves.
fn remove_enrollment(
    vault: &mut SyncedVault,
    bio: &dyn Biometrics,
    vault_id: Uuid,
    slot: Uuid,
) -> Result<(), SyncError> {
    if let Err(e) = bio.unenroll(vault_id) {
        // The slot still goes: a leftover Keychain item can no longer open anything.
        eprintln!("vault: could not remove the Touch ID Keychain item: {e}");
    }
    let present = vault.vault().is_some_and(|v| {
        v.slots()
            .any(|(id, kind)| id == slot && kind == SlotKind::Enclave)
    });
    if !present {
        return Ok(());
    }
    vault.edit(|v| v.remove_slot(slot, crate::text::now_millis()))??;
    vault.save()
}

/// Whether an `unlock_with_kek` failure means the enrollment no longer fits this vault:
/// the KEK opens no slot (`WrongPassword`) or the slot is gone (`Malformed("no such
/// slot ..")`, e.g. the key was rotated on another Mac). Integrity and I/O errors are not
/// the enrollment's fault and leave it alone.
pub(super) fn kek_error_is_stale(e: &SyncError) -> bool {
    match e {
        SyncError::Vault(VaultError::WrongPassword) => true,
        SyncError::Vault(VaultError::Malformed(m)) => m.starts_with("no such slot"),
        _ => false,
    }
}

/// A stale enrollment to clean up after a password unlock: `(vault_id, slot_id)`.
pub(super) type StaleEnrollment = Option<(Uuid, Uuid)>;

/// Runs on the unlock thread after a successful password unlock.
pub(super) fn clean_stale(
    vault: &mut SyncedVault,
    bio: &dyn Biometrics,
    stale: StaleEnrollment,
) -> Option<Result<(), String>> {
    let (vault_id, slot) = stale?;
    Some(remove_enrollment(vault, bio, vault_id, slot).map_err(|e| e.to_string()))
}

impl AppState {
    fn policy(&self) -> Option<&TouchIdPolicy> {
        self.settings.touch_id.get(&self.vault_id?)
    }

    fn policy_mut(&mut self) -> Option<&mut TouchIdPolicy> {
        let id = self.vault_id?;
        self.settings.touch_id.get_mut(&id)
    }

    pub(super) fn save_policy(&self) {
        if self.persist_recent {
            crate::persist::save_settings(&self.settings);
        }
    }

    /// Re-reads availability and enrollment for the current vault. Cheap: no prompt.
    pub(super) fn refresh_touch(&mut self) {
        self.touch.available = self.biometrics.available();
        // `is_enrolled` reports any Keychain error as "not enrolled". That self-heals: the
        // policy entry then counts as stale and the next password unlock removes the slot,
        // after which Touch ID can be turned on again.
        self.touch.enrolled = match self.vault_id {
            Some(id) => self.policy().is_some() && self.biometrics.is_enrolled(id),
            None => false,
        };
    }

    /// Whether the unlock screen may offer Touch ID now.
    pub fn touch_policy(&self) -> Result<(), TouchDenied> {
        let policy = self.policy().ok_or(TouchDenied::NotEnrolled)?;
        if policy.stale {
            return Err(TouchDenied::Stale);
        }
        if !self.touch.enrolled {
            return Err(TouchDenied::NotEnrolled);
        }
        // `boot_time` is UNIX_EPOCH when sysctl failed: fail closed, as if rebooted.
        if self.boot_time == UNIX_EPOCH || policy.last_password_unlock_at < unix(self.boot_time) {
            return Err(TouchDenied::Rebooted);
        }
        let age = unix(SystemTime::now()).saturating_sub(policy.last_password_unlock_at);
        if age > PASSWORD_MAX_AGE.as_secs() {
            return Err(TouchDenied::Expired);
        }
        if policy.failed_touch_attempts >= MAX_TOUCH_FAILURES {
            return Err(TouchDenied::TooManyFailures);
        }
        Ok(())
    }

    /// Why "Use Touch ID" in Settings cannot be turned on, if it cannot.
    pub fn touch_enable_blocker(&self) -> Option<&'static str> {
        if !self.touch.available {
            Some("Touch ID is not available on this Mac")
        } else if self.locked {
            Some("Unlock the vault first")
        } else if self.unlocked_with_password_at.is_none() {
            Some("Lock and unlock once with your master password first")
        } else {
            None
        }
    }

    /// Touch ID is on for this vault (the Settings toggle).
    pub fn touch_enabled(&self) -> bool {
        self.touch.enrolled && self.policy().is_some_and(|p| !p.stale)
    }

    /// The stale enrollment a password unlock should clean up.
    pub(super) fn stale_enrollment(&self) -> StaleEnrollment {
        let policy = self.policy()?;
        (policy.stale || !self.touch.enrolled).then_some((self.vault_id?, policy.slot_id))
    }

    /// A master-password unlock (or create) succeeded. `session`: this session is now
    /// password-unlocked (false when a lock won the race).
    pub(super) fn password_unlocked(&mut self, session: bool) {
        if session {
            self.unlocked_with_password_at = Some(Instant::now());
        }
        let now = unix(SystemTime::now());
        if let Some(p) = self.policy_mut() {
            p.last_password_unlock_at = now;
            p.failed_touch_attempts = 0;
            self.save_policy();
        }
    }

    /// The stale enrollment was removed on the unlock thread.
    pub(super) fn stale_cleaned(&mut self, result: Option<Result<(), String>>) {
        match result {
            None => {}
            Some(Ok(())) => {
                if let Some(id) = self.vault_id {
                    self.settings.touch_id.remove(&id);
                    self.save_policy();
                }
                self.touch.enrolled = false;
                self.toast = Some(Toast::window(
                    "Touch ID was turned off for this vault. Turn it on again in Settings \u{25b8} Security.",
                ));
            }
            Some(Err(e)) => {
                self.toast = Some(Toast::window(format!(
                    "Could not remove the old Touch ID setup: {e}"
                )));
            }
        }
    }

    /// After a merge (watcher, pre-write, conflicted copy) or an unlock, which merges too:
    /// the header merge (03 §5) may have replaced our slot set with another device's, so the
    /// enclave slot this Mac enrolled can be gone (removed or rotated away over there).
    /// "Enrolled on this device" is re-derived from the live slot ids; a missing slot marks
    /// the policy stale, the same state a fingerprint change leads to. Another device's new
    /// enclave slot changes nothing here. True when the enrollment just went stale.
    pub(super) fn recheck_touch_slot(&mut self) -> bool {
        let Some(slot) = self.policy().filter(|p| !p.stale).map(|p| p.slot_id) else {
            return false;
        };
        let Some(vault) = self.unlocked_vault() else {
            return false;
        };
        if vault
            .slots()
            .any(|(id, kind)| id == slot && kind == SlotKind::Enclave)
        {
            return false;
        }
        self.mark_stale();
        true
    }

    fn mark_stale(&mut self) {
        if let Some(p) = self.policy_mut() {
            p.stale = true;
            self.save_policy();
        }
    }

    fn count_touch_failure(&mut self) {
        if let Some(p) = self.policy_mut() {
            p.failed_touch_attempts = p.failed_touch_attempts.saturating_add(1);
            self.save_policy();
        }
    }

    /// Unlock screen: starts Touch ID when `auto` says so. `activated`: called from a
    /// window activation rather than the screen appearing.
    pub fn auto_touch_unlock(&mut self, activated: bool, cx: &mut Context<Self>) {
        let go = match self.touch.auto {
            TouchAuto::Off => false,
            TouchAuto::OnAppear => true,
            TouchAuto::OnActivation => activated,
        };
        if go {
            self.touch.auto = TouchAuto::Off;
            self.touch_unlock(cx);
        }
    }

    /// "Unlock with Touch ID".
    pub fn touch_unlock(&mut self, cx: &mut Context<Self>) {
        if self.busy.is_some() || !self.locked || self.touch_policy().is_err() {
            return;
        }
        let Some(vault_id) = self.vault_id else {
            return;
        };
        let Some(mut vault) = self.vault.take() else {
            return;
        };
        let bio = self.biometrics.clone();
        let reason = format!("Unlock {}", self.vault_name());
        self.run_bg(
            Busy::TouchUnlocking,
            cx,
            move || {
                let result = bio
                    .unlock(vault_id, &reason)
                    .map(|(slot, kek)| vault.unlock_with_kek(slot, &kek));
                (vault, result)
            },
            move |this, (mut vault, result), outcome| {
                if outcome == Outcome::Closed {
                    vault.lock();
                    return;
                }
                let unlocked = matches!(result, Ok(Ok(())));
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(SyncError::KeyMismatch)) => {
                        this.error = Some(
                            "This vault's key changed on another Mac. Enter your master password."
                                .into(),
                        );
                    }
                    Ok(Err(e)) if kek_error_is_stale(&e) => {
                        this.mark_stale();
                        this.error = TouchDenied::Stale.hint().map(SharedString::from);
                    }
                    // Tampered, unreadable, ...: say so; the enrollment is fine.
                    Ok(Err(e)) => this.error = Some(super::error_message(&e).into()),
                    Err(MacError::UserCancelled) => {}
                    Err(MacError::BiometryChanged) => {
                        this.mark_stale();
                        this.toast = Some(Toast::window(
                            "Touch ID enrollment is no longer valid; enter your master password",
                        ));
                    }
                    Err(e) => {
                        this.count_touch_failure();
                        this.toast = Some(Toast::window(format!("Touch ID failed: {e}")));
                    }
                }
                match (outcome, unlocked) {
                    (Outcome::Fresh, true) => {
                        this.vault = Some(vault);
                        this.unlocked();
                    }
                    (_, true) => {
                        vault.lock();
                        this.vault = Some(vault);
                    }
                    (_, false) => this.vault = Some(vault),
                }
            },
        );
    }

    /// Settings toggle on: add an enclave slot, save, enroll the KEK; undo the slot if
    /// enrolling fails.
    pub fn enable_touch_id(&mut self, cx: &mut Context<Self>) {
        if self.busy.is_some() || self.touch_enable_blocker().is_some() {
            return;
        }
        let Some(vault_id) = self.vault_id else {
            return;
        };
        if !self.guard(Navigation::Security, cx) {
            self.settings_open = false;
            cx.notify();
            return;
        }
        let Some(mut vault) = self.vault.take() else {
            return;
        };
        let bio = self.biometrics.clone();
        let password_at = self
            .unlocked_with_password_at
            .and_then(|i| SystemTime::now().checked_sub(i.elapsed()))
            .unwrap_or_else(SystemTime::now);
        self.run_bg(
            Busy::EnablingTouchId,
            cx,
            move || {
                let result = enroll(&mut vault, &*bio, vault_id);
                (vault, result)
            },
            move |this, (mut vault, result), outcome| {
                // The slot is on disk and the Keychain item exists whatever happened
                // meanwhile, so the policy entry is written even if the vault was closed:
                // keyed by the captured id, it is found again when that vault reopens.
                if let Ok(slot_id) = &result {
                    let now = unix(SystemTime::now());
                    this.settings.touch_id.insert(
                        vault_id,
                        TouchIdPolicy {
                            slot_id: *slot_id,
                            enrolled_at: now,
                            last_password_unlock_at: unix(password_at),
                            failed_touch_attempts: 0,
                            stale: false,
                        },
                    );
                    this.save_policy();
                }
                if outcome == Outcome::Closed {
                    vault.lock();
                    return;
                }
                match result {
                    Ok(_) => {
                        this.touch.enrolled = true;
                        this.record_save(Ok(()));
                        this.toast = Some(Toast::window("Touch ID turned on"));
                    }
                    Err(EnrollError { message, unsaved }) => {
                        if let Some(e) = unsaved {
                            // The slot removal is only in memory; autosave retries it.
                            this.record_save(Err(e));
                        }
                        this.toast = Some(Toast::window(message));
                    }
                }
                if outcome == Outcome::Locked {
                    vault.lock();
                }
                this.vault = Some(vault);
            },
        );
    }

    /// Settings toggle off, after the master password prompt: unenroll, remove the slot,
    /// save.
    pub fn disable_touch_id(&mut self, password: SecretString, cx: &mut Context<Self>) {
        let (Some(vault_id), Some(slot)) = (self.vault_id, self.policy().map(|p| p.slot_id)) else {
            return;
        };
        let bio = self.biometrics.clone();
        self.security_task(
            Busy::DisablingTouchId,
            cx,
            move |vault| {
                // While unlocked, `unlock` checks the password against the LockedVault held
                // in memory (re-read first if the file changed) and keeps the in-memory
                // vault; if another Mac re-keyed the file it adopts that key and merges.
                vault.unlock(&password).map_err(Failure::refused)?;
                remove_enrollment(vault, &*bio, vault_id, slot).map_err(Failure::Save)
            },
            move |this| {
                this.settings.touch_id.remove(&vault_id);
                this.save_policy();
                if this.vault_id == Some(vault_id) {
                    this.touch.enrolled = false;
                }
                "Touch ID turned off".into()
            },
        );
    }

    /// The vault key was rotated: core dropped every enclave slot, so forget ours.
    pub(super) fn touch_rotated(&mut self) {
        if let Some(id) = self.vault_id
            && self.settings.touch_id.remove(&id).is_some()
        {
            self.save_policy();
        }
        self.touch.enrolled = false;
    }
}

/// Enabling failed. `unsaved`: the slot was taken out again but that could not be saved.
struct EnrollError {
    message: String,
    unsaved: Option<SyncError>,
}

/// Background half of enabling: fresh KEK, slot, save, Keychain.
fn enroll(
    vault: &mut SyncedVault,
    bio: &dyn Biometrics,
    vault_id: Uuid,
) -> Result<Uuid, EnrollError> {
    let mut bytes = vec![0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    // Zeroized when dropped at the end of this function.
    let kek = SecretVec::new(bytes);
    let slot = vault
        .edit(|v| v.add_enclave_slot(&kek, crate::text::now_millis()))
        .map_err(|e| EnrollError {
            message: e.to_string(),
            unsaved: None,
        })?;
    let fail = |vault: &mut SyncedVault, message: String| {
        let _ = vault.edit(|v| v.remove_slot(slot, crate::text::now_millis()));
        EnrollError {
            message,
            unsaved: vault.save().err(),
        }
    };
    if let Err(e) = vault.save() {
        return Err(fail(vault, format!("Could not save the vault: {e}")));
    }
    if let Err(e) = bio.enroll(vault_id, &kek, slot) {
        return Err(fail(vault, format!("Touch ID could not be turned on: {e}")));
    }
    Ok(slot)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use gpui::{AppContext as _, Entity, TestAppContext};
    use vault_core::{Item, KdfParams, LockedVault};
    use vault_sync::NoopHooks;

    use super::*;
    use crate::biometric::fake::{Call, FakeBiometrics};
    use crate::state::Screen;

    const PW: &str = "correct horse";

    fn secret(s: &str) -> SecretString {
        SecretString::new(s.to_owned())
    }

    fn make_vault(dir: &Path) -> PathBuf {
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
        vault
            .edit(|v| v.insert(Item::new("GitHub", device, 1), 1))
            .unwrap();
        vault.save().unwrap();
        path
    }

    /// A state with the fake, the vault opened and unlocked with the password.
    fn setup(
        dir: &Path,
        cx: &mut TestAppContext,
    ) -> (Entity<AppState>, Arc<FakeBiometrics>, PathBuf) {
        let path = make_vault(dir);
        let bio = FakeBiometrics::new();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        let (b, p) = (bio.clone(), path.clone());
        state.update(cx, |s, cx| {
            s.set_biometrics(b);
            s.open_vault(p, cx);
        });
        cx.run_until_parked();
        password_unlock(&state, PW, cx);
        state.read_with(cx, |s, _| assert!(!s.locked));
        (state, bio, path)
    }

    fn password_unlock(state: &Entity<AppState>, pw: &str, cx: &mut TestAppContext) {
        state.update(cx, |s, cx| s.unlock(secret(pw), cx));
        cx.run_until_parked();
    }

    fn enable(state: &Entity<AppState>, cx: &mut TestAppContext) {
        state.update(cx, |s, cx| s.enable_touch_id(cx));
        cx.run_until_parked();
        state.read_with(cx, |s, _| assert!(s.touch_enabled(), "{:?}", s.toast));
    }

    fn lock(state: &Entity<AppState>, cx: &mut TestAppContext) {
        state.update(cx, |s, cx| s.lock(cx));
    }

    fn enclave_slots_on_disk(path: &Path) -> Vec<Uuid> {
        LockedVault::parse(&std::fs::read(path.join("vault.bin")).unwrap())
            .unwrap()
            .slots()
            .filter(|(_, k)| *k == SlotKind::Enclave)
            .map(|(id, _)| id)
            .collect()
    }

    fn slots_stamp_on_disk(path: &Path) -> u64 {
        LockedVault::parse(&std::fs::read(path.join("vault.bin")).unwrap())
            .unwrap()
            .header()
            .slots_stamp()
    }

    fn policy(state: &Entity<AppState>, cx: &mut TestAppContext) -> Option<TouchIdPolicy> {
        state.read_with(cx, |s, _| s.policy().cloned())
    }

    #[gpui::test]
    fn enable_adds_slot_enrolls_and_records_policy(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, bio, path) = setup(dir.path(), cx);
        let vault_id = state.read_with(cx, |s, _| s.vault_id.unwrap());
        let stamp_before = slots_stamp_on_disk(&path);
        enable(&state, cx);
        let slots = enclave_slots_on_disk(&path);
        assert_eq!(slots.len(), 1, "slot saved to disk");
        assert!(
            slots_stamp_on_disk(&path) > stamp_before,
            "saved at once with a newer slots_modified_at (03 §5)"
        );
        assert_eq!(bio.calls(), vec![Call::Enroll(vault_id, slots[0])]);
        let p = policy(&state, cx).unwrap();
        assert_eq!(p.slot_id, slots[0]);
        assert!(p.enrolled_at > 0 && p.last_password_unlock_at > 0);
        assert_eq!(p.failed_touch_attempts, 0);
        // settings.json form: keyed by vault id, no secrets.
        let json = state.read_with(cx, |s, _| serde_json::to_string(&s.settings).unwrap());
        assert!(json.contains(&vault_id.to_string()), "{json}");
    }

    #[gpui::test]
    fn enroll_failure_removes_the_slot(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, bio, path) = setup(dir.path(), cx);
        bio.with(|i| i.next_enroll_error = Some(MacError::Keychain(-34018)));
        state.update(cx, |s, cx| s.enable_touch_id(cx));
        cx.run_until_parked();
        assert!(enclave_slots_on_disk(&path).is_empty());
        state.read_with(cx, |s, _| {
            assert!(!s.touch_enabled());
            assert!(s.policy().is_none());
            assert!(
                s.toast
                    .as_ref()
                    .unwrap()
                    .message
                    .contains("could not be turned on")
            );
        });
    }

    #[gpui::test]
    fn touch_unlock_uses_the_enclave_kek(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, bio, _) = setup(dir.path(), cx);
        enable(&state, cx);
        lock(&state, cx);
        state.update(cx, |s, cx| {
            assert_eq!(s.touch_policy(), Ok(()));
            assert_eq!(s.touch.auto, TouchAuto::OnActivation);
            // Appearing after a lock does not start Touch ID; activation does.
            s.auto_touch_unlock(false, cx);
            assert!(s.busy.is_none());
            s.auto_touch_unlock(true, cx);
            assert_eq!(s.busy, Some(Busy::TouchUnlocking));
        });
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(!s.locked);
            assert_eq!(s.screen, Screen::Main);
            assert_eq!(s.item_count(), 1);
            assert!(
                s.touch_enable_blocker().is_some(),
                "a Touch ID session cannot enable Touch ID"
            );
        });
        assert!(
            bio.calls()
                .iter()
                .any(|c| matches!(c, Call::Unlock(_, r) if r == "Unlock t"))
        );
    }

    #[gpui::test]
    fn touch_unlock_holds_the_minimum(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, _) = setup(dir.path(), cx);
        enable(&state, cx);
        lock(&state, cx);
        let ms = Duration::from_millis(1);
        state.update(cx, |s, _| s.unlock_hold = super::super::MIN_UNLOCK_HOLD);
        state.update(cx, |s, cx| s.touch_unlock(cx));
        // The fake Touch ID answers at once; the result waits for the hold.
        cx.executor()
            .advance_clock(super::super::MIN_UNLOCK_HOLD - ms);
        state.read_with(cx, |s, _| {
            assert_eq!(s.busy, Some(Busy::TouchUnlocking), "held");
            assert!(s.locked);
        });
        cx.executor().advance_clock(ms);
        state.read_with(cx, |s, _| {
            assert!(s.busy.is_none() && !s.locked);
            assert_eq!(s.screen, Screen::Main);
        });
    }

    #[gpui::test]
    fn policy_gates_deny(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, bio, _) = setup(dir.path(), cx);
        enable(&state, cx);
        lock(&state, cx);
        let now = unix(SystemTime::now());

        // Rebooted since the last password unlock.
        state.update(cx, |s, _| {
            s.boot_time = SystemTime::now() + Duration::from_secs(60);
            assert_eq!(s.touch_policy(), Err(TouchDenied::Rebooted));
            // Booted long ago, so only the age rule can deny below.
            s.boot_time = SystemTime::now() - Duration::from_secs(30 * 24 * 3600);
            assert_eq!(s.touch_policy(), Ok(()));
            // sysctl failed: fail closed.
            s.boot_time = UNIX_EPOCH;
            assert_eq!(s.touch_policy(), Err(TouchDenied::Rebooted));
            // Booted long ago, so only the age rule can deny below.
            s.boot_time = SystemTime::now() - Duration::from_secs(30 * 24 * 3600);
        });
        // Password unlock older than 7 days.
        state.update(cx, |s, _| {
            s.policy_mut().unwrap().last_password_unlock_at = now - 8 * 24 * 3600;
            assert_eq!(s.touch_policy(), Err(TouchDenied::Expired));
            s.policy_mut().unwrap().last_password_unlock_at = now - 6 * 24 * 3600;
            assert_eq!(s.touch_policy(), Ok(()));
        });
        // Five failed attempts, counted from real failures; a cancel is not one.
        bio.with(|i| i.next_unlock_error = Some(MacError::UserCancelled));
        state.update(cx, |s, cx| s.touch_unlock(cx));
        cx.run_until_parked();
        for _ in 0..MAX_TOUCH_FAILURES {
            bio.with(|i| i.next_unlock_error = Some(MacError::Other("no match".into())));
            state.update(cx, |s, cx| s.touch_unlock(cx));
            cx.run_until_parked();
        }
        state.read_with(cx, |s, _| {
            assert!(s.locked);
            assert_eq!(
                s.policy().unwrap().failed_touch_attempts,
                MAX_TOUCH_FAILURES
            );
            assert_eq!(s.touch_policy(), Err(TouchDenied::TooManyFailures));
        });
        let unlock_calls = || {
            bio.calls()
                .iter()
                .filter(|c| matches!(c, Call::Unlock(..)))
                .count()
        };
        let before = unlock_calls();
        state.update(cx, |s, cx| s.touch_unlock(cx));
        cx.run_until_parked();
        assert_eq!(unlock_calls(), before, "denied: no prompt");
        // The master password resets the counter.
        password_unlock(&state, PW, cx);
        state.read_with(cx, |s, _| {
            assert_eq!(s.policy().unwrap().failed_touch_attempts, 0);
            assert!(s.touch_enable_blocker().is_none());
        });
    }

    #[gpui::test]
    fn biometry_change_unenrolls_after_next_password_unlock(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, bio, path) = setup(dir.path(), cx);
        let vault_id = state.read_with(cx, |s, _| s.vault_id.unwrap());
        enable(&state, cx);
        lock(&state, cx);
        bio.with(|i| i.next_unlock_error = Some(MacError::BiometryChanged));
        state.update(cx, |s, cx| s.touch_unlock(cx));
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(s.locked);
            assert!(
                s.toast
                    .as_ref()
                    .unwrap()
                    .message
                    .contains("no longer valid")
            );
            assert_eq!(s.touch_policy(), Err(TouchDenied::Stale));
            assert!(s.policy().unwrap().stale);
        });
        assert_eq!(enclave_slots_on_disk(&path).len(), 1);

        password_unlock(&state, PW, cx);
        assert!(bio.calls().contains(&Call::Unenroll(vault_id)));
        assert!(enclave_slots_on_disk(&path).is_empty(), "slot removed");
        state.read_with(cx, |s, _| {
            assert!(!s.locked);
            assert!(s.policy().is_none());
            assert!(!s.touch_enabled());
            assert!(s.touch_enable_blocker().is_none(), "can be turned on again");
        });
    }

    #[gpui::test]
    fn disable_needs_the_password_and_removes_the_slot(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, bio, path) = setup(dir.path(), cx);
        let vault_id = state.read_with(cx, |s, _| s.vault_id.unwrap());
        enable(&state, cx);
        state.update(cx, |s, cx| s.disable_touch_id(secret("wrong"), cx));
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert_eq!(
                s.security.error.as_deref(),
                Some("The master password is wrong.")
            );
            assert!(s.touch_enabled());
        });
        assert_eq!(enclave_slots_on_disk(&path).len(), 1);

        state.update(cx, |s, cx| s.disable_touch_id(secret(PW), cx));
        cx.run_until_parked();
        assert!(enclave_slots_on_disk(&path).is_empty());
        assert!(bio.calls().contains(&Call::Unenroll(vault_id)));
        state.read_with(cx, |s, _| {
            assert!(!s.touch_enabled());
            assert!(s.policy().is_none());
            assert!(!s.locked);
        });
    }

    #[gpui::test]
    fn rotate_clears_the_enrollment(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, bio, path) = setup(dir.path(), cx);
        let vault_id = state.read_with(cx, |s, _| s.vault_id.unwrap());
        enable(&state, cx);
        state.update(cx, |s, cx| s.rotate_key(secret(PW), cx));
        cx.run_until_parked();
        assert!(enclave_slots_on_disk(&path).is_empty());
        assert!(bio.calls().contains(&Call::Unenroll(vault_id)));
        state.read_with(cx, |s, _| {
            assert!(s.policy().is_none());
            assert!(!s.touch_enabled());
            assert!(s.toast.as_ref().unwrap().message.contains("re-enrolled"));
        });
    }

    /// Ticks the app (watcher poll + events) until `done` holds; false after 20 s.
    fn wait_for(
        state: &Entity<AppState>,
        cx: &mut TestAppContext,
        done: impl Fn(&AppState) -> bool,
    ) -> bool {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(20) {
            state.update(cx, |s, cx| s.tick(0.0, cx));
            if state.read_with(cx, |s, _| done(s)) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        false
    }

    /// A second device on the same file, opened after this Mac's last slot change so its
    /// own slot changes carry the newer `slots_modified_at` and win the header merge.
    fn other_device(path: &Path) -> SyncedVault {
        let mut other = SyncedVault::open(path, Uuid::new_v4(), Arc::new(NoopHooks)).unwrap();
        other.unlock(&secret(PW)).unwrap();
        other
    }

    fn toast(state: &Entity<AppState>, cx: &mut TestAppContext) -> Option<String> {
        state.read_with(cx, |s, _| s.toast.as_ref().map(|t| t.message.to_string()))
    }

    #[gpui::test]
    fn merge_that_removes_our_slot_marks_the_enrollment_stale(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, bio, path) = setup(dir.path(), cx);
        let vault_id = state.read_with(cx, |s, _| s.vault_id.unwrap());
        enable(&state, cx);
        let ours = policy(&state, cx).unwrap().slot_id;
        let mut other = other_device(&path);

        // B enrolls its own Mac: a new enclave slot arrives; ours is still there.
        let kek = SecretVec::new(vec![7u8; 32]);
        let theirs = other
            .edit(|v| v.add_enclave_slot(&kek, crate::text::now_millis()))
            .unwrap();
        other.save().unwrap();
        assert!(wait_for(&state, cx, |s| {
            s.unlocked_vault()
                .is_some_and(|v| v.slots().any(|(id, _)| id == theirs))
        }));
        state.read_with(cx, |s, _| {
            assert!(s.touch_enabled(), "another Mac's slot leaves ours alone");
            assert!(!s.policy().unwrap().stale);
        });

        // B removes our slot (it turned this Mac's Touch ID off, or re-keyed).
        other
            .edit(|v| v.remove_slot(ours, crate::text::now_millis()))
            .unwrap()
            .unwrap();
        other.save().unwrap();
        assert!(wait_for(&state, cx, |s| s
            .policy()
            .is_some_and(|p| p.stale)));
        state.read_with(cx, |s, _| {
            assert!(!s.touch_enabled(), "Settings shows Touch ID off");
            assert_eq!(s.touch_policy(), Err(TouchDenied::Stale));
            assert!(
                !s.unlocked_vault()
                    .unwrap()
                    .slots()
                    .any(|(id, _)| id == ours),
                "B's slot set replaced ours"
            );
        });
        assert_eq!(toast(&state, cx).as_deref(), Some(SLOT_GONE));

        // Locked: the unlock screen shows the "set up again" hint; the next password unlock
        // removes the leftover Keychain item and forgets the policy.
        lock(&state, cx);
        state.read_with(cx, |s, _| {
            assert_eq!(s.touch_policy(), Err(TouchDenied::Stale));
        });
        password_unlock(&state, PW, cx);
        assert!(bio.calls().contains(&Call::Unenroll(vault_id)));
        state.read_with(cx, |s, _| {
            assert!(s.policy().is_none());
            assert!(!s.touch_enabled());
        });
        assert_eq!(enclave_slots_on_disk(&path), vec![theirs]);
    }

    #[gpui::test]
    fn unlock_that_merges_away_our_slot_marks_the_enrollment_stale(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _bio, path) = setup(dir.path(), cx);
        enable(&state, cx);
        let ours = policy(&state, cx).unwrap().slot_id;
        lock(&state, cx);
        let mut other = other_device(&path);
        other
            .edit(|v| v.remove_slot(ours, crate::text::now_millis()))
            .unwrap()
            .unwrap();
        other.save().unwrap();
        password_unlock(&state, PW, cx);
        state.read_with(cx, |s, _| {
            assert!(!s.locked);
            assert!(s.policy().unwrap().stale);
            assert!(!s.touch_enabled());
        });
        assert_eq!(toast(&state, cx).as_deref(), Some(SLOT_GONE));
    }

    #[gpui::test]
    fn conflict_absorbed_rechecks_the_slot(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _bio, _path) = setup(dir.path(), cx);
        enable(&state, cx);
        let ours = policy(&state, cx).unwrap().slot_id;
        // What absorbing a conflicted copy with a newer slot set does to the header.
        state.update(cx, |s, _| {
            s.vault
                .as_mut()
                .unwrap()
                .edit(|v| v.remove_slot(ours, crate::text::now_millis()))
                .unwrap()
                .unwrap();
        });
        let copy = dir.path().join("t (conflict).vault");
        state.update(cx, |s, cx| {
            s.handle_sync_event(vault_sync::SyncEvent::ConflictAbsorbed(copy), cx);
        });
        state.read_with(cx, |s, _| assert!(s.policy().unwrap().stale));
        assert_eq!(toast(&state, cx).as_deref(), Some(SLOT_GONE));
    }

    #[test]
    fn only_kek_mismatches_are_stale() {
        use vault_core::TamperKind;
        assert!(kek_error_is_stale(&SyncError::Vault(
            VaultError::WrongPassword
        )));
        assert!(kek_error_is_stale(&SyncError::Vault(
            VaultError::Malformed(format!("no such slot {}", Uuid::new_v4()))
        )));
        assert!(!kek_error_is_stale(&SyncError::Vault(
            VaultError::Malformed("bad header".into())
        )));
        let tampered = SyncError::Vault(VaultError::Tampered(TamperKind::Item(Uuid::nil())));
        assert!(!kek_error_is_stale(&tampered));
        assert!(!kek_error_is_stale(&SyncError::KeyMismatch));
    }

    /// Reopens `path` locked in a new state sharing `bio` and `settings`.
    fn reopen_locked(
        path: &Path,
        bio: &Arc<FakeBiometrics>,
        settings: crate::state::Settings,
        cx: &mut TestAppContext,
    ) -> Entity<AppState> {
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        let (b, p) = (bio.clone(), path.to_owned());
        state.update(cx, |s, cx| {
            s.settings = settings;
            s.set_biometrics(b);
            s.open_vault(p, cx);
            // Keep the automatic attempt out of the way; tests start Touch ID themselves.
            s.touch.auto = TouchAuto::Off;
        });
        cx.run_until_parked();
        state.update(cx, |s, _| s.touch.auto = TouchAuto::Off);
        state
    }

    #[gpui::test]
    fn tampered_file_is_reported_and_keeps_the_enrollment(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, bio, path) = setup(dir.path(), cx);
        enable(&state, cx);
        let settings = state.read_with(cx, |s, _| s.settings.clone());
        state.update(cx, |s, cx| s.close_vault(cx));
        // Flip the last byte (inside the final AEAD tag).
        let mut bytes = std::fs::read(path.join("vault.bin")).unwrap();
        *bytes.last_mut().unwrap() ^= 0x01;
        std::fs::write(path.join("vault.bin"), bytes).unwrap();

        let state = reopen_locked(&path, &bio, settings, cx);
        state.update(cx, |s, cx| s.touch_unlock(cx));
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(s.locked);
            let error = s.error.as_deref().unwrap_or_default();
            assert!(error.contains("integrity"), "{error}");
            let p = s.policy().unwrap();
            assert!(!p.stale, "a damaged file is not the enrollment's fault");
            assert_eq!(p.failed_touch_attempts, 0);
            assert_eq!(s.touch_policy(), Ok(()));
        });
    }

    #[gpui::test]
    fn wrong_kek_or_missing_slot_marks_stale(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, bio, path) = setup(dir.path(), cx);
        let vault_id = state.read_with(cx, |s, _| s.vault_id.unwrap());
        enable(&state, cx);
        let settings = state.read_with(cx, |s, _| s.settings.clone());
        state.update(cx, |s, cx| s.close_vault(cx));

        for corrupt in [
            |e: &mut (Uuid, Vec<u8>)| e.1[0] ^= 0xff,
            |e: &mut (Uuid, Vec<u8>)| e.0 = Uuid::new_v4(),
        ] {
            let saved = bio.with(|i| i.enrolled[&vault_id].clone());
            bio.with(|i| corrupt(i.enrolled.get_mut(&vault_id).unwrap()));
            let state = reopen_locked(&path, &bio, settings.clone(), cx);
            state.update(cx, |s, cx| s.touch_unlock(cx));
            cx.run_until_parked();
            state.read_with(cx, |s, _| {
                assert!(s.locked);
                assert_eq!(s.touch_policy(), Err(TouchDenied::Stale));
                assert_eq!(s.error.as_deref(), TouchDenied::Stale.hint());
            });
            bio.with(|i| i.enrolled.insert(vault_id, saved));
        }
    }

    #[gpui::test]
    fn enable_closed_midway_still_records_the_policy(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, bio, path) = setup(dir.path(), cx);
        let vault_id = state.read_with(cx, |s, _| s.vault_id.unwrap());
        state.update(cx, |s, cx| {
            s.enable_touch_id(cx);
            assert_eq!(s.busy, Some(Busy::EnablingTouchId));
            s.close_vault(cx);
        });
        cx.run_until_parked();
        let slots = enclave_slots_on_disk(&path);
        assert_eq!(slots.len(), 1);
        assert!(bio.calls().contains(&Call::Enroll(vault_id, slots[0])));
        let settings = state.read_with(cx, |s, _| {
            assert!(s.vault.is_none());
            assert_eq!(s.settings.touch_id[&vault_id].slot_id, slots[0]);
            s.settings.clone()
        });
        // Reopening finds the enrollment, so it can be used (or cleaned up) later.
        let state = reopen_locked(&path, &bio, settings, cx);
        state.read_with(cx, |s, _| {
            assert!(s.touch.enrolled);
            assert_eq!(s.touch_policy(), Ok(()));
        });
    }
}
