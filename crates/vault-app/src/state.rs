//! The single `AppState` entity (specs/05-ui.md §3).
//!
//! Slow work (opening, KDF calibration, unlocking) runs on gpui's background executor.
//! The `SyncedVault` is moved into that task and handed back, so the main thread never
//! blocks on Argon2. Two counters guard against results that arrive after the user moved
//! on: `epoch` changes whenever the open vault changes (switch, close) and `lock_gen`
//! whenever the vault locks. A stale unlock result is re-locked or dropped, never shown.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crossbeam_channel::Receiver;
use gpui::{Context, SharedString, Task};
use serde::{Deserialize, Serialize};
use vault_core::{ItemKind, KdfParams, SecretString, Uuid, VaultError};
use vault_sync::{SyncError, SyncEvent, SyncedVault};

use crate::biometric::{self, Biometrics};
use crate::clipboard::Clipboard;
#[cfg(not(test))]
use crate::clipboard::SystemPasteboard;
use crate::listing::{Counts, Listing};
use crate::{cloud, persist};

mod attachments;
mod edit;
mod generator;
mod prefs;
mod qr;
mod security;
mod session;
mod sync;
mod touch_id;
mod transfer;
mod viewer;

pub use attachments::{
    AttachmentStore, AttachmentsUi, PreviewContent, PreviewKind, preview_kind, state_label,
};
pub use edit::{EditBuffer, Navigation, kind_name};
pub use generator::{
    CharClass, GenTab, Generator, GeneratorTarget, LENGTH_RANGE, SEPARATORS, WORDS_RANGE,
};
pub use prefs::LoginRow;
pub use qr::QrScanner;
pub use security::{SECURITY_TAB, SecurityForm, SecurityUi};
pub use session::{CopyTarget, FocusTarget, parse_totp};
pub use sync::{RestorePrompt, SYNC_TAB, SyncUi, TRANSFER_TAB};
pub use touch_id::{TouchAuto, TouchDenied, TouchIdPolicy, TouchUi};

/// Target duration of one KDF derivation on this Mac (01 §6).
const KDF_TARGET: Duration = Duration::from_millis(500);
/// How long a window toast stays up.
const TOAST_TTL: Duration = Duration::from_secs(3);
/// Longest the quit hook waits for in-flight background work.
const BACKGROUND_QUIT_WAIT: Duration = Duration::from_secs(30);

/// Whether the world moved on while a background task ran (see `AppState::run_bg`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Fresh,
    /// The vault was locked meanwhile: install the result locked.
    Locked,
    /// The vault was closed or switched meanwhile: discard the result.
    Closed,
}

/// Which top-level screen the window shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Choose,
    Unlock,
    Main,
}

/// Background work in flight; the UI shows a spinner and refuses new requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Busy {
    Opening,
    /// KDF calibration plus the first write of a new vault.
    Calibrating,
    Unlocking,
    /// Re-entering the password after the vault was re-keyed on another device.
    Reverifying,
    /// Restoring a backup (unlocks it with Argon2).
    Restoring,
    /// Settings ▸ Security operations (each derives a key with Argon2, then saves).
    ChangingPassword,
    Recalibrating,
    RotatingKey,
    /// Touch ID prompt and `unlock_with_kek`.
    TouchUnlocking,
    EnablingTouchId,
    DisablingTouchId,
    /// Sealing dropped or picked files into the selected item.
    Attaching,
    /// Decrypting an attachment whose blob first has to download.
    ReadingAttachment,
}

impl Busy {
    /// The unlocked vault is inside the task: sync events must wait for it.
    pub fn holds_unlocked_vault(self) -> bool {
        matches!(
            self,
            Self::Reverifying
                | Self::Restoring
                | Self::ChangingPassword
                | Self::Recalibrating
                | Self::RotatingKey
                | Self::EnablingTouchId
                | Self::DisablingTouchId
                | Self::Attaching
                | Self::ReadingAttachment
        )
    }
}

/// Which step the choose-vault screen should show (File ▸ New Vault vs ⌘O).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChooseIntent {
    Home,
    Create,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Filter {
    #[default]
    All,
    Favorites,
    Kind(ItemKind),
    Tag(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sort {
    #[default]
    Alphabetical,
    RecentlyModified,
}

#[derive(Debug, Clone, Default)]
pub enum Mode {
    #[default]
    View,
    Edit(EditBuffer),
    New(ItemKind, EditBuffer),
}

/// Where a toast is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastPlace {
    /// Bottom centre of the window.
    Window,
    /// Bottom of the detail column ("Copied — clears in 30 s").
    Detail,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub message: SharedString,
    pub shown_at: Instant,
    pub place: ToastPlace,
    pub ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SyncStatus {
    #[default]
    Idle,
    Error(SharedString),
}

/// General and Sync & Backup settings (§2.5), persisted in `settings.json`. Missing keys
/// take defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// `None` = never.
    pub auto_lock_minutes: Option<u32>,
    /// Lock on sleep, screen lock or fast user switch (one setting, 05 §2.5).
    pub lock_on_sleep: bool,
    pub clipboard_clear_secs: u32,
    /// Automatic snapshots on save (03 §4).
    pub backup_enabled: bool,
    /// Retention multiplier (03 §4), one of [`Settings::RETENTION_CHOICES`].
    pub retention_multiplier: f32,
    /// Touch ID policy per vault id (04 §2). No secrets.
    pub touch_id: BTreeMap<Uuid, TouchIdPolicy>,
    /// Light / dark override (05 §5). An unknown value falls back to the default alone.
    #[serde(deserialize_with = "lenient")]
    pub appearance: Appearance,
    /// Text size step (05 §6). An unknown value falls back to the default alone.
    #[serde(deserialize_with = "lenient")]
    pub text_size: TextSize,
    /// The first-run tips card was dismissed.
    pub onboarding_dismissed: bool,
}

/// Deserializes `T`, or its default if the value does not parse: one bad key in a
/// hand-edited settings.json must not reset every other setting.
fn lenient<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned + Default,
{
    let value = serde_json::Value::deserialize(d)?;
    Ok(serde_json::from_value(value).unwrap_or_default())
}

/// Settings ▸ General ▸ Appearance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Appearance {
    #[default]
    System,
    Light,
    Dark,
}

impl Appearance {
    pub const ALL: [Self; 3] = [Self::System, Self::Light, Self::Dark];

    pub fn label(self) -> &'static str {
        match self {
            Self::System => "Follow system",
            Self::Light => "Light",
            Self::Dark => "Dark",
        }
    }
}

/// Settings ▸ General ▸ Text size: scales the base font, rem-based spacing and list rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TextSize {
    #[default]
    Default,
    Large,
    Larger,
}

impl TextSize {
    pub const ALL: [Self; 3] = [Self::Default, Self::Large, Self::Larger];

    pub fn scale(self) -> f32 {
        match self {
            Self::Default => 1.0,
            Self::Large => 1.15,
            Self::Larger => 1.3,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Default => "Default",
            Self::Large => "Large",
            Self::Larger => "Larger",
        }
    }
}

impl Settings {
    /// Choices offered in the General tab.
    pub const AUTO_LOCK_CHOICES: [Option<u32>; 5] = [Some(1), Some(5), Some(15), Some(60), None];
    pub const CLIPBOARD_CHOICES: [u32; 4] = [15, 30, 60, 90];
    /// Segments offered in the Sync & Backup tab, within vault-sync's 0.5-4.0 range.
    pub const RETENTION_CHOICES: [f32; 4] = [0.5, 1.0, 2.0, 4.0];

    /// Replaces values outside the offered choices (hand-edited or corrupt settings.json)
    /// with the defaults, so `0` can never mean "lock immediately" or "clear at once".
    pub fn sanitized(mut self) -> Self {
        let defaults = Self::default();
        if !Self::AUTO_LOCK_CHOICES.contains(&self.auto_lock_minutes) {
            self.auto_lock_minutes = defaults.auto_lock_minutes;
        }
        if !Self::CLIPBOARD_CHOICES.contains(&self.clipboard_clear_secs) {
            self.clipboard_clear_secs = defaults.clipboard_clear_secs;
        }
        if !Self::RETENTION_CHOICES.contains(&self.retention_multiplier) {
            self.retention_multiplier = defaults.retention_multiplier;
        }
        self
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: Some(5),
            lock_on_sleep: true,
            clipboard_clear_secs: 30,
            backup_enabled: true,
            retention_multiplier: vault_sync::RETENTION_MULTIPLIER_DEFAULT,
            touch_id: BTreeMap::new(),
            appearance: Appearance::System,
            text_size: TextSize::Default,
            onboarding_dismissed: false,
        }
    }
}

pub struct AppState {
    /// `None` = no vault chosen (or it is inside a background task, see `busy`).
    pub vault: Option<SyncedVault>,
    pub locked: bool,
    pub selection: Option<Uuid>,
    pub filter: Filter,
    pub query: String,
    pub sort: Sort,
    pub mode: Mode,
    pub toast: Option<Toast>,
    pub sync_status: SyncStatus,
    pub settings: Settings,
    pub last_activity: Instant,
    pub recent_vaults: Vec<PathBuf>,

    /// Derived from vault + query + filter + sort by `refresh`; never per frame.
    pub listing: Listing,
    pub counts: Counts,
    /// Bumped whenever `listing` is recomputed, so views know to reset their list state.
    pub listing_version: u64,
    /// Field names of the selected item whose values are revealed.
    pub revealed: HashSet<String>,
    /// Password history disclosure of the selected item.
    pub history_open: bool,
    pub sidebar_visible: bool,
    /// Bumped on every sidebar toggle; keys its slide-in.
    pub sidebar_toggles: usize,
    pub tags_open: bool,
    /// Focus move requested by a global action; the main screen applies and clears it.
    pub focus_request: Option<FocusTarget>,
    /// Set when the state cleared `query` itself; the main screen empties the search field.
    pub clear_search: bool,
    /// Bumped whenever an edit or new-item session starts; the editor rebuilds its inputs.
    pub edit_session: u64,
    /// Inline "Discard changes?" prompt and the navigation waiting behind it.
    pub discard_prompt: Option<Navigation>,
    /// Inline "Delete '<title>'?" confirm for this item.
    pub delete_confirm: Option<Uuid>,
    /// Open kind picker (⌘N) with the title to pre-fill ("Create '<query>'").
    pub kind_picker: Option<String>,
    pub generator: Generator,
    /// Open generator popover, if any.
    pub generator_target: Option<GeneratorTarget>,
    /// Settings sheet requested open; the root view opens and closes the dialog.
    pub settings_open: bool,
    /// Selected settings tab; File ▸ Export… and restore jump to theirs.
    pub settings_tab: usize,
    /// Banners, key-mismatch prompt, backups list, restore and export confirms.
    pub sync: SyncUi,
    /// Settings ▸ Security forms and the KDF timing.
    pub security: SecurityUi,
    pub touch: TouchUi,
    /// Header vault id of the open vault (known while locked).
    pub vault_id: Option<Uuid>,
    /// Set by a master-password unlock or create; cleared on lock. Touch ID can be
    /// turned on only while set (04 §2 policy).
    pub unlocked_with_password_at: Option<Instant>,
    /// When this Mac last booted; read once (it cannot change while we run).
    pub boot_time: SystemTime,
    biometrics: Arc<dyn Biometrics>,
    /// Login item status; `None` when not running from an app bundle.
    pub login_item: Option<vault_macos::LoginItemStatus>,
    /// A vault was created this session: show the tips card until dismissed.
    pub show_onboarding: bool,
    qr: Arc<dyn QrScanner>,
    /// A screen scan is running.
    pub qr_scanning: bool,
    /// The last scan lacked Screen Recording: the editor shows the settings button.
    pub screen_recording_hint: bool,
    /// Open read-only backup viewer windows; `lock` closes them (they hold decrypted data).
    pub backup_windows: Vec<gpui::AnyWindowHandle>,
    /// Detail ▸ Attachments: pending adds, preview, confirms.
    pub attachments: AttachmentsUi,
    attach_store: Arc<dyn AttachmentStore>,

    pub screen: Screen,
    pub busy: Option<Busy>,
    /// Pending request for the choose screen; the root view hands it over and clears it.
    /// Set even when the choose screen is already showing.
    pub choose_request: Option<ChooseIntent>,
    /// Path of the current vault; stays set while the vault is inside an unlock task.
    pub vault_path: Option<PathBuf>,
    /// Inline error for the current screen (wrong password, unreadable file, ...).
    pub error: Option<SharedString>,
    /// Bumped on every wrong password; keys the shake animation.
    pub unlock_failures: u32,
    /// Bumped on every unlock; keys the locked→unlocked crossfade.
    pub unlock_count: u32,
    /// macOS "Reduce motion": skip the unlock crossfade, the shake and the TOTP pulse.
    /// Refreshed by the 1 s tick.
    pub reduce_motion: bool,

    device_id: Uuid,
    sync_events: Option<Receiver<SyncEvent>>,
    epoch: u64,
    lock_gen: u64,
    /// False in tests so they never touch the user's recent.json or settings.json.
    persist_recent: bool,
    clipboard: Clipboard,
    clipboard_clear: Option<Task<()>>,
    /// Debounced autosave (03 §8); replacing it cancels the pending save.
    autosave: Option<Task<()>>,
    /// True from `schedule_autosave` until that save runs.
    autosave_pending: bool,
    /// Completion signal of the latest `run_bg` work, for the quit hook.
    background_done: Option<Receiver<()>>,
    toast_dismiss: Option<Task<()>>,
}

impl AppState {
    pub fn new(device_id: Uuid, recent_vaults: Vec<PathBuf>, persist_recent: bool) -> Self {
        Self {
            vault: None,
            locked: true,
            selection: None,
            filter: Filter::default(),
            query: String::new(),
            sort: Sort::default(),
            mode: Mode::default(),
            toast: None,
            sync_status: SyncStatus::default(),
            settings: Settings::default(),
            last_activity: Instant::now(),
            recent_vaults,
            listing: Listing::default(),
            counts: Counts::default(),
            listing_version: 0,
            revealed: HashSet::new(),
            history_open: false,
            sidebar_visible: true,
            sidebar_toggles: 0,
            tags_open: true,
            focus_request: None,
            clear_search: false,
            edit_session: 0,
            discard_prompt: None,
            delete_confirm: None,
            kind_picker: None,
            generator: Generator::default(),
            generator_target: None,
            settings_open: false,
            settings_tab: 0,
            sync: SyncUi::default(),
            security: SecurityUi::default(),
            touch: TouchUi::default(),
            vault_id: None,
            unlocked_with_password_at: None,
            boot_time: vault_macos::boot_time(),
            login_item: None,
            show_onboarding: false,
            #[cfg(not(test))]
            qr: qr::screen_scanner(),
            #[cfg(test)]
            qr: qr::fake::FakeScanner::returning(Ok(Vec::new())),
            qr_scanning: false,
            screen_recording_hint: false,
            backup_windows: Vec::new(),
            attachments: AttachmentsUi::default(),
            #[cfg(not(test))]
            attach_store: attachments::sync_store(),
            #[cfg(test)]
            attach_store: attachments::fake::FakeStore::new(),
            // Tests never reach the real Keychain or Touch ID sheet.
            #[cfg(not(test))]
            biometrics: biometric::system(),
            #[cfg(test)]
            biometrics: biometric::fake::FakeBiometrics::new(),
            screen: Screen::Choose,
            busy: None,
            choose_request: None,
            vault_path: None,
            error: None,
            unlock_failures: 0,
            unlock_count: 0,
            reduce_motion: false,
            device_id,
            sync_events: None,
            epoch: 0,
            lock_gen: 0,
            persist_recent,
            // Tests never touch the real pasteboard.
            #[cfg(not(test))]
            clipboard: Clipboard::new(Box::new(SystemPasteboard)),
            #[cfg(test)]
            clipboard: Clipboard::new(Box::new(crate::clipboard::fake::FakePasteboard::default())),
            clipboard_clear: None,
            autosave: None,
            autosave_pending: false,
            background_done: None,
            toast_dismiss: None,
        }
    }

    /// Starts with persisted settings (`main`); tests keep the defaults.
    pub fn with_settings(mut self, settings: Settings) -> Self {
        self.settings = settings;
        self
    }

    /// Settings sheet edits: applied live (auto-lock and clipboard read `self.settings`
    /// each time) and written to settings.json.
    pub fn update_settings(&mut self, cx: &mut Context<Self>, f: impl FnOnce(&mut Settings)) {
        let before = self.settings.clone();
        f(&mut self.settings);
        self.settings = self.settings.clone().sanitized();
        if self.settings != before {
            self.apply_backup_settings();
            if (self.settings.appearance, self.settings.text_size)
                != (before.appearance, before.text_size)
            {
                crate::theme::set_prefs(&self.settings, cx);
                crate::theme::reapply(cx);
            }
            if self.persist_recent {
                persist::save_settings(&self.settings);
            }
            cx.notify();
        }
    }

    /// ⌘, and the sidebar's Settings row.
    /// Always notifies on open, so the root re-checks the dialog even if the flag is stale.
    pub fn open_settings(&mut self, open: bool, cx: &mut Context<Self>) {
        if open && !self.settings_open {
            self.refresh_backups();
            self.refresh_touch();
            self.refresh_login_item();
        }
        if !open {
            self.sync.restore = None;
            self.sync.export_confirm = false;
            self.reset_security_forms();
        }
        if open || self.settings_open {
            self.settings_open = open;
            cx.notify();
        }
    }

    pub fn vault_name(&self) -> String {
        self.vault_path
            .as_deref()
            .map(persist::vault_name)
            .unwrap_or_default()
    }

    /// This Mac's device id (stamped on every edit).
    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    #[cfg(test)]
    pub fn set_qr_scanner(&mut self, scanner: Arc<dyn QrScanner>) {
        self.qr = scanner;
    }

    #[cfg(test)]
    pub fn set_biometrics(&mut self, bio: Arc<dyn Biometrics>) {
        self.biometrics = bio;
        self.refresh_touch();
    }

    /// Installs an already unlocked vault and shows the main screen (render tests).
    #[cfg(test)]
    pub fn install_unlocked_for_tests(&mut self, vault: SyncedVault) {
        self.install(vault, false);
        self.unlocked();
    }

    #[cfg(test)]
    pub fn item_count(&self) -> usize {
        self.vault
            .as_ref()
            .and_then(SyncedVault::vault)
            .map_or(0, |v| v.items().count())
    }

    pub fn touch_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn show_toast(&mut self, message: impl Into<SharedString>, cx: &mut Context<Self>) {
        self.toast_at(message, ToastPlace::Window, TOAST_TTL, cx);
    }

    /// Shows a toast and schedules its dismissal after `ttl`.
    pub fn toast_at(
        &mut self,
        message: impl Into<SharedString>,
        place: ToastPlace,
        ttl: Duration,
        cx: &mut Context<Self>,
    ) {
        let shown_at = Instant::now();
        self.toast = Some(Toast {
            message: message.into(),
            shown_at,
            place,
            ttl,
        });
        self.toast_dismiss = Some(cx.spawn(async move |this, cx| {
            cx.background_executor().timer(ttl).await;
            this.update(cx, |this, cx| {
                if this.toast.as_ref().is_some_and(|t| t.shown_at == shown_at) {
                    this.toast = None;
                    cx.notify();
                }
            })
            .ok();
        }));
        cx.notify();
    }

    /// Opens the vault file at `path` (locked) and shows the unlock screen.
    pub fn open_vault(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        if self.busy.is_some() {
            return;
        }
        self.close_vault(cx);
        let (device_id, task_path) = (self.device_id, path.clone());
        self.run_bg(
            Busy::Opening,
            cx,
            move || SyncedVault::open(&task_path, device_id, cloud::hooks()),
            move |this, result, outcome| {
                if outcome == Outcome::Closed {
                    return;
                }
                match result {
                    Ok(vault) => {
                        this.install(vault, true);
                        this.remember(&path);
                        this.touch.auto = TouchAuto::OnAppear;
                        this.screen = Screen::Unlock;
                    }
                    Err(e) => {
                        if matches!(e, SyncError::NoVault(_)) {
                            this.forget(&path);
                        }
                        this.error = Some(error_message(&e).into());
                    }
                }
            },
        );
    }

    /// Calibrates the KDF, creates a new vault at `path` and shows it unlocked.
    pub fn create_vault(&mut self, path: PathBuf, password: SecretString, cx: &mut Context<Self>) {
        if self.busy.is_some() {
            return;
        }
        self.close_vault(cx);
        let (device_id, task_path) = (self.device_id, path.clone());
        self.run_bg(
            Busy::Calibrating,
            cx,
            move || {
                let kdf = KdfParams::calibrate(KDF_TARGET);
                SyncedVault::create(&task_path, &password, kdf, device_id, cloud::hooks())
            },
            move |this, result, outcome| match result {
                Ok(mut vault) => {
                    // The file exists now whatever the user did meanwhile.
                    this.remember(&path);
                    match outcome {
                        Outcome::Fresh => {
                            this.install(vault, false);
                            this.unlocked();
                            this.password_unlocked(true);
                            this.show_onboarding = true;
                        }
                        Outcome::Locked => {
                            vault.lock();
                            this.install(vault, true);
                            this.screen = Screen::Unlock;
                        }
                        // Dropping zeroizes the keys.
                        Outcome::Closed => vault.lock(),
                    }
                }
                Err(e) if outcome != Outcome::Closed => {
                    this.error = Some(error_message(&e).into());
                }
                Err(_) => {}
            },
        );
    }

    /// Verifies `password` on a background thread and unlocks on success.
    pub fn unlock(&mut self, password: SecretString, cx: &mut Context<Self>) {
        if self.busy.is_some() || !self.locked {
            return;
        }
        let Some(mut vault) = self.vault.take() else {
            return;
        };
        let stale = self.stale_enrollment();
        let bio = self.biometrics.clone();
        self.run_bg(
            Busy::Unlocking,
            cx,
            move || {
                let result = vault.unlock(&password);
                // A stale Touch ID setup goes now, while the password is fresh (04 §2).
                let cleaned = match result {
                    Ok(()) => touch_id::clean_stale(&mut vault, &*bio, stale),
                    Err(_) => None,
                };
                (vault, result, cleaned)
            },
            |this, (mut vault, result, cleaned), outcome| match (outcome, result) {
                // The user switched or closed the vault meanwhile; dropping zeroizes it.
                (Outcome::Closed, _) => vault.lock(),
                (Outcome::Fresh, Ok(())) => {
                    this.vault = Some(vault);
                    this.unlocked();
                    this.password_unlocked(true);
                    this.stale_cleaned(cleaned);
                }
                (Outcome::Locked, Ok(())) => {
                    vault.lock();
                    this.vault = Some(vault);
                    this.password_unlocked(false);
                    this.stale_cleaned(cleaned);
                }
                (_, Err(e)) => {
                    this.vault = Some(vault);
                    this.unlock_failures = this.unlock_failures.wrapping_add(1);
                    this.error = Some(error_message(&e).into());
                }
            },
        );
    }

    /// Runs `work` on the background executor, then `finish` on the main thread.
    ///
    /// The single place that decides whether a result is stale: `finish` learns whether
    /// the vault was closed (`epoch` changed) or locked (`lock_gen` changed) meanwhile.
    /// `busy` is cleared unless the vault was closed, since a later request may own it.
    fn run_bg<R: Send + 'static>(
        &mut self,
        busy: Busy,
        cx: &mut Context<Self>,
        work: impl FnOnce() -> R + Send + 'static,
        finish: impl FnOnce(&mut Self, R, Outcome) + 'static,
    ) {
        self.run_bg_cx(busy, cx, work, move |this, result, outcome, _| {
            finish(this, result, outcome)
        });
    }

    /// [`Self::run_bg`] whose `finish` also gets the `Context` (to reschedule autosave).
    fn run_bg_cx<R: Send + 'static>(
        &mut self,
        busy: Busy,
        cx: &mut Context<Self>,
        work: impl FnOnce() -> R + Send + 'static,
        finish: impl FnOnce(&mut Self, R, Outcome, &mut Context<Self>) + 'static,
    ) {
        self.busy = Some(busy);
        self.error = None;
        cx.notify();
        let (epoch, lock_gen) = (self.epoch, self.lock_gen);
        // Signalled when `work` returns, so quit can wait for it (`wait_for_background`).
        let (done_tx, done_rx) = crossbeam_channel::bounded::<()>(1);
        self.background_done = Some(done_rx);
        // Known limitation: the vault is moved into `work`. If `work` panics, the task
        // drops it (zeroizing the keys), `finish` never runs, `busy` stays set and the
        // session must be reopened (⌘O). Unsaved edits in it are lost; vault-sync's
        // operations used here do not panic on I/O or crypto errors, they return them.
        let task = cx.background_executor().spawn(async move {
            let result = work();
            let _ = done_tx.send(());
            result
        });
        cx.spawn(async move |this, cx| {
            let result = task.await;
            this.update(cx, |this, cx| {
                let outcome = if epoch != this.epoch {
                    Outcome::Closed
                } else if lock_gen != this.lock_gen {
                    Outcome::Locked
                } else {
                    Outcome::Fresh
                };
                if outcome != Outcome::Closed {
                    this.busy = None;
                }
                finish(this, result, outcome, cx);
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn unlocked(&mut self) {
        self.apply_backup_settings();
        self.sync.save_failing = false;
        self.locked = false;
        self.error = None;
        self.vault_changed();
        self.screen = Screen::Main;
        self.unlock_count = self.unlock_count.wrapping_add(1);
        self.touch_activity();
    }

    /// Save if dirty, lock, clear selection and edit buffer, show the unlock screen.
    /// Safe to call at any time, including while locked or while an unlock is in flight.
    pub fn lock(&mut self, cx: &mut Context<Self>) {
        self.lock_gen = self.lock_gen.wrapping_add(1);
        // Overlays of the unlocked session go first, so a "could not save" toast set
        // below survives onto the unlock screen.
        self.toast = None;
        self.toast_dismiss = None;
        self.settings_open = false;
        self.screen_recording_hint = false;
        self.close_backup_windows(cx);
        self.clear_attachments(cx);
        let saved = match self.vault.as_mut() {
            Some(vault) if vault.is_dirty() => Some(vault.save()),
            _ => None,
        };
        let blocked = matches!(
            saved,
            Some(Err(SyncError::KeyMismatch | SyncError::SaveBlocked(_)))
        );
        if let Some(e) = saved.and_then(|r| self.record_save(r)) {
            // Locking wins over keeping unsaved edits: an auto-lock must not be vetoed
            // by a failing disk. The user sees why the edits are gone, or (when saving was
            // refused) where vault-sync preserved them.
            let message = if blocked {
                format!(
                    "Could not save before locking ({e}). Your changes were kept in the backups folder."
                )
            } else {
                format!("Could not save before locking: {e}")
            };
            self.toast = Some(Toast::window(message));
        }
        if let Some(vault) = self.vault.as_mut() {
            // The watcher keeps running: vault-sync needs it to see changes made while
            // locked, and it holds no key material.
            vault.lock();
        }
        if !self.locked {
            self.touch.auto = TouchAuto::OnActivation;
        }
        self.unlocked_with_password_at = None;
        self.locked = true;
        self.autosave = None;
        self.autosave_pending = false;
        self.sync.key_mismatch = false;
        self.sync.key_mismatch_error = None;
        self.sync.restore = None;
        self.sync.export_confirm = false;
        self.reset_security_forms();
        self.clear_session();
        self.clipboard_clear = None;
        self.clipboard.clear_if_ours();
        if self.screen == Screen::Main {
            self.screen = Screen::Unlock;
        }
        cx.notify();
    }

    /// Locks and forgets the current vault, then shows the choose-vault screen (⌘O).
    pub fn close_vault(&mut self, cx: &mut Context<Self>) {
        self.lock(cx);
        if let Some(vault) = self.vault.as_mut() {
            vault.stop_watching();
        }
        self.vault = None;
        self.sync_events = None;
        self.sync = SyncUi::default();
        self.sync_status = SyncStatus::Idle;
        self.vault_path = None;
        self.vault_id = None;
        self.touch.enrolled = false;
        self.touch.auto = TouchAuto::Off;
        self.epoch = self.epoch.wrapping_add(1);
        self.busy = None;
        self.error = None;
        self.screen = Screen::Choose;
        cx.notify();
    }

    /// ⌘O / File ▸ Open Vault, and File ▸ New Vault.
    /// Goes through the unsaved-changes guard; lock and quit do not.
    pub fn switch_vault(&mut self, intent: ChooseIntent, cx: &mut Context<Self>) {
        if !self.guard(Navigation::SwitchVault(intent), cx) {
            return;
        }
        self.close_vault(cx);
        self.choose_request = Some(intent);
        cx.notify();
    }

    /// Quit hook: block until in-flight background work (unlock, re-verify, restore) has
    /// returned, so its writes (re-verify saves the pending edits) reach the disk before
    /// the process exits. gpui gives async quit handlers only 200 ms, less than Argon2.
    pub fn wait_for_background(&mut self) {
        if self.busy.is_some()
            && let Some(rx) = self.background_done.take()
        {
            // Disconnected (task gone) returns at once.
            let _ = rx.recv_timeout(BACKGROUND_QUIT_WAIT);
        }
    }

    /// Called once a second: auto-lock, toast expiry, sync events.
    /// `system_idle_secs` is `vault_macos::seconds_since_user_input()`.
    pub fn tick(&mut self, system_idle_secs: f64, cx: &mut Context<Self>) {
        self.poll_sync(cx);
        if self
            .toast
            .as_ref()
            .is_some_and(|t| t.shown_at.elapsed() >= t.ttl)
        {
            self.toast = None;
            cx.notify();
        }
        if self.should_auto_lock(system_idle_secs) {
            self.lock(cx);
        }
    }

    /// Reduce-motion setting as read by the tick (`vault_macos::reduce_motion_enabled`).
    pub fn set_reduce_motion(&mut self, on: bool, cx: &mut Context<Self>) {
        if self.reduce_motion != on {
            self.reduce_motion = on;
            // gpui-component's own transitions (dialog, tabs) read gpui's flag.
            cx.set_reduce_motion(on);
            cx.notify();
        }
    }

    /// Idle = the shorter of system-wide idle and time since our last recorded activity.
    ///
    /// Every in-app event is also system-wide input, so `min(system idle, app idle)` is
    /// effectively system-idle driven: using another app keeps the vault unlocked.
    /// `last_activity` only matters right after unlock, before any input arrives.
    fn should_auto_lock(&self, system_idle_secs: f64) -> bool {
        if self.locked || self.vault.is_none() {
            return false;
        }
        let Some(minutes) = self.settings.auto_lock_minutes else {
            return false;
        };
        let app_idle = self.last_activity.elapsed().as_secs_f64();
        system_idle_secs.min(app_idle) >= f64::from(minutes) * 60.0
    }

    fn install(&mut self, vault: SyncedVault, locked: bool) {
        self.sync_events = Some(vault.subscribe());
        self.vault_path = Some(vault.path().to_owned());
        self.vault_id = Some(vault.locked_summary().vault_id);
        self.vault = Some(vault);
        self.locked = locked;
        self.clear_session();
        self.attach_vault();
        self.refresh_touch();
    }

    fn remember(&mut self, path: &Path) {
        persist::push_recent(&mut self.recent_vaults, path);
        if self.persist_recent {
            persist::save_recent(&self.recent_vaults);
        }
    }

    fn forget(&mut self, path: &Path) {
        self.recent_vaults.retain(|p| p != path);
        if self.persist_recent {
            persist::save_recent(&self.recent_vaults);
        }
    }
}

/// A fresh in-memory attachment store for render tests.
#[cfg(test)]
pub fn attachments_fake() -> Arc<attachments::fake::FakeStore> {
    attachments::fake::FakeStore::new()
}

/// User-facing text for a failed vault operation. Never contains secrets.
fn error_message(e: &SyncError) -> String {
    match e {
        SyncError::Vault(VaultError::WrongPassword) => "Wrong password. Try again.".into(),
        SyncError::Vault(VaultError::BadMagic) => "This file is not a vault.".into(),
        SyncError::Vault(VaultError::Tampered(_)) => {
            "This vault failed its integrity check and may have been tampered with.".into()
        }
        SyncError::NoVault(p) => format!("No vault at {}. Removed from recents.", p.display()),
        SyncError::AlreadyExists(p) => format!("{} already exists.", p.display()),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
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
            s.mode = Mode::Edit(EditBuffer::new(Item::new(ItemKind::Note, "x", device, 1)));
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
                .edit(|v| v.insert(Item::new(ItemKind::Login, "GitHub", device, 1), 1))
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
        let state =
            cx.new(|_| AppState::new(Uuid::new_v4(), vec![gone.clone(), kept.clone()], false));
        state.update(cx, |s, cx| s.open_vault(gone.clone(), cx));
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert_eq!(s.recent_vaults, vec![kept.clone()]);
            assert_eq!(s.screen, Screen::Choose);
            assert!(s.error.is_some());
            assert!(s.busy.is_none());
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
}
