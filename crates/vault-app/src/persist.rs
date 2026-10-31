//! Small JSON files in `~/Library/Application Support/<bundle id>/` (specs/05-ui.md §1, §2.1).
//!
//! Nothing here is secret: window geometry, vault paths and General settings only. Every failure is
//! non-fatal: a missing or corrupt file means "use defaults", a failed write is logged.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::state::Settings;

const WINDOW_FILE: &str = "window.json";
const RECENT_FILE: &str = "recent.json";
const SETTINGS_FILE: &str = "settings.json";
/// How many recent vaults the choose-vault screen lists.
pub const RECENT_MAX: usize = 8;

/// Persisted main-window geometry, in logical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct WindowState {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    /// Sidebar and item-list widths; `None` until the user drags a divider.
    #[serde(default)]
    pub columns: Option<[f32; 2]>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RecentFile {
    vaults: Vec<PathBuf>,
}

/// `~/Library/Application Support/dev.vault.app`, if the platform has one.
pub fn support_dir() -> Option<PathBuf> {
    Some(dirs::data_dir()?.join(vault_macos::BUNDLE_ID))
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let bytes = fs::read(path).ok()?;
    match serde_json::from_slice(&bytes) {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!("vault: ignoring unreadable {}: {e}", path.display());
            None
        }
    }
}

/// Write via a sibling temp file + rename so a crash never leaves half a JSON file.
fn write_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)
}

fn log_write(path: &Path, result: io::Result<()>) {
    if let Err(e) = result {
        eprintln!("vault: could not write {}: {e}", path.display());
    }
}

pub fn load_window_state() -> Option<WindowState> {
    let state: WindowState = read_json(&support_dir()?.join(WINDOW_FILE))?;
    let sane = [state.x, state.y, state.width, state.height]
        .iter()
        .all(|v| v.is_finite())
        && state.width > 0.
        && state.height > 0.;
    sane.then_some(state)
}

pub fn save_window_state(state: &WindowState) {
    if let Some(dir) = support_dir() {
        let path = dir.join(WINDOW_FILE);
        log_write(&path, write_json(&path, state));
    }
}

pub fn load_recent() -> Vec<PathBuf> {
    support_dir()
        .and_then(|dir| read_json::<RecentFile>(&dir.join(RECENT_FILE)))
        .map(|f| f.vaults)
        .unwrap_or_default()
}

pub fn save_recent(vaults: &[PathBuf]) {
    if let Some(dir) = support_dir() {
        let path = dir.join(RECENT_FILE);
        let file = RecentFile {
            vaults: vaults.to_vec(),
        };
        log_write(&path, write_json(&path, &file));
    }
}

/// Settings from `dir/settings.json`; defaults if missing or unreadable, and any value
/// outside the General tab's choices snapped back to its default.
pub fn load_settings_from(dir: &Path) -> Settings {
    read_json::<Settings>(&dir.join(SETTINGS_FILE))
        .unwrap_or_default()
        .sanitized()
}

pub fn save_settings_to(dir: &Path, settings: &Settings) {
    let path = dir.join(SETTINGS_FILE);
    log_write(&path, write_json(&path, settings));
}

/// Settings next to window.json, loaded once at launch.
pub fn load_settings() -> Settings {
    support_dir()
        .map(|dir| load_settings_from(&dir))
        .unwrap_or_default()
}

pub fn save_settings(settings: &Settings) {
    if let Some(dir) = support_dir() {
        save_settings_to(&dir, settings);
    }
}

/// Moves `path` to the front of `list`, dropping duplicates and trimming to [`RECENT_MAX`].
pub fn push_recent(list: &mut Vec<PathBuf>, path: &Path) {
    list.retain(|p| p != path);
    list.insert(0, path.to_owned());
    list.truncate(RECENT_MAX);
}

/// Display name of a vault: its file stem.
pub fn vault_name(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_recent_dedups_and_caps() {
        let mut list = Vec::new();
        for i in 0..RECENT_MAX + 3 {
            push_recent(&mut list, Path::new(&format!("/v/{i}.vault")));
        }
        push_recent(&mut list, Path::new("/v/9.vault"));
        assert_eq!(list.len(), RECENT_MAX);
        assert_eq!(list[0], Path::new("/v/9.vault"));
        assert_eq!(list.iter().filter(|p| p.ends_with("9.vault")).count(), 1);
    }

    #[test]
    fn settings_round_trip_through_settings_json() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_settings_from(dir.path()), Settings::default());
        let settings = Settings {
            auto_lock_minutes: None,
            lock_on_sleep: false,
            clipboard_clear_secs: 90,
            backup_enabled: false,
            retention_multiplier: 4.0,
            touch_id: [(
                vault_core::Uuid::new_v4(),
                crate::state::TouchIdPolicy {
                    slot_id: vault_core::Uuid::new_v4(),
                    enrolled_at: 1,
                    last_password_unlock_at: 2,
                    failed_touch_attempts: 3,
                    stale: true,
                },
            )]
            .into(),
            appearance: crate::state::Appearance::Dark,
            text_size: crate::state::TextSize::Larger,
            onboarding_dismissed: true,
            sidebar_hidden: true,
        };
        save_settings_to(dir.path(), &settings);
        assert_eq!(load_settings_from(dir.path()), settings);
        let json = fs::read_to_string(dir.path().join(SETTINGS_FILE)).unwrap();
        assert!(json.contains("\"backup_enabled\": false"), "{json}");
        assert!(json.contains("\"retention_multiplier\": 4.0"), "{json}");
        assert!(json.contains("\"sidebar_hidden\": true"), "{json}");

        // Older or hand-edited files: missing keys take defaults, garbage is ignored.
        fs::write(
            dir.path().join(SETTINGS_FILE),
            r#"{"lock_on_sleep": false}"#,
        )
        .unwrap();
        let partial = load_settings_from(dir.path());
        assert!(!partial.lock_on_sleep);
        // A bad appearance / text size falls back for that key only.
        fs::write(
            dir.path().join(SETTINGS_FILE),
            r#"{"lock_on_sleep": false, "appearance": "purple", "text_size": 5,
                "onboarding_dismissed": true}"#,
        )
        .unwrap();
        let lenient = load_settings_from(dir.path());
        assert!(!lenient.lock_on_sleep);
        assert!(lenient.onboarding_dismissed);
        assert_eq!(lenient.appearance, crate::state::Appearance::System);
        assert_eq!(lenient.text_size, crate::state::TextSize::Default);
        assert_eq!(partial.clipboard_clear_secs, 30);
        assert!(partial.backup_enabled);
        assert!(!partial.sidebar_hidden, "the sidebar defaults to expanded");
        assert_eq!(partial.retention_multiplier, 1.0);
        // A multiplier outside the offered segments snaps back to 1x.
        for m in ["3.0", "0.0", "-1", "100"] {
            let json = format!(r#"{{"retention_multiplier": {m}}}"#);
            fs::write(dir.path().join(SETTINGS_FILE), json).unwrap();
            assert_eq!(
                load_settings_from(dir.path()).retention_multiplier,
                1.0,
                "{m}"
            );
        }
        for (minutes, secs) in [(0, 0), (9999, 9999)] {
            let json =
                format!(r#"{{"auto_lock_minutes": {minutes}, "clipboard_clear_secs": {secs}}}"#);
            fs::write(dir.path().join(SETTINGS_FILE), json).unwrap();
            assert_eq!(
                load_settings_from(dir.path()),
                Settings::default(),
                "{minutes}/{secs}"
            );
        }
        // A malformed sidebar flag falls back alone; the other settings survive.
        fs::write(
            dir.path().join(SETTINGS_FILE),
            r#"{"lock_on_sleep": false, "sidebar_hidden": "yes", "onboarding_dismissed": true}"#,
        )
        .unwrap();
        let sidebar = load_settings_from(dir.path());
        assert!(!sidebar.sidebar_hidden);
        assert!(!sidebar.lock_on_sleep);
        assert!(sidebar.onboarding_dismissed);
        fs::write(dir.path().join(SETTINGS_FILE), "not json").unwrap();
        assert_eq!(load_settings_from(dir.path()), Settings::default());
    }
}
