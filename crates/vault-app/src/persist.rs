//! Small JSON files in `~/Library/Application Support/<bundle id>/` (specs/05-ui.md §1, §2.1).
//!
//! Nothing here is secret: window geometry, vault paths and General settings only. Every failure is
//! non-fatal: a missing or corrupt file means "use defaults", a failed write is logged.
//!
//! Not secret, but private (security review 2026-11-26 L-09): vault paths, vault and slot ids
//! and the lock settings. The folder is kept 0700 and every file is written 0600 through
//! [`write_private`] (random-suffix temp created exclusively, removed on failure, renamed
//! over the target), the export's own writer; files left 0644 by older builds are narrowed
//! on the first write.

use std::fs::{self, Permissions};
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::state::{Settings, write_private};

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

/// Write 0600 via a random sibling temp file + rename so a crash never leaves half a JSON
/// file, into a 0700 folder.
fn write_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        make_private_dir(dir)?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    write_private(path, &bytes)
}

/// Creates `dir` if needed and narrows it to 0700 and our files in it to 0600 (the
/// migration for files older builds wrote 0644). Narrowing is best effort: a failure is
/// logged and the write goes ahead.
fn make_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let narrow = |path: &Path, mode: u32| {
        let Ok(meta) = fs::symlink_metadata(path) else {
            return;
        };
        // Never chmod through a link; only a real file or folder of ours.
        let ours = meta.is_dir() || meta.is_file();
        if ours
            && meta.permissions().mode() & 0o777 != mode
            && let Err(e) = fs::set_permissions(path, Permissions::from_mode(mode))
        {
            eprintln!("vault: could not restrict {}: {e}", path.display());
        }
    };
    narrow(dir, 0o700);
    for name in [WINDOW_FILE, RECENT_FILE, SETTINGS_FILE] {
        narrow(&dir.join(name), 0o600);
    }
    Ok(())
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
            show_in_dock: false,
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

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// L-09: after a save the folder is 0700 and every file 0600, files an older build left
    /// 0644 included, and no temp file is left behind.
    #[test]
    fn saves_are_private_and_narrow_older_files() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("dev.vault.app");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, Permissions::from_mode(0o755)).unwrap();
        for name in [SETTINGS_FILE, RECENT_FILE, WINDOW_FILE] {
            let path = dir.join(name);
            fs::write(&path, "{}").unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        }
        save_settings_to(&dir, &Settings::default());
        assert_eq!(mode(&dir), 0o700);
        for name in [SETTINGS_FILE, RECENT_FILE, WINDOW_FILE] {
            assert_eq!(mode(&dir.join(name)), 0o600, "{name}");
        }
        assert_eq!(load_settings_from(&dir), Settings::default());

        // A fresh folder: created 0700, each file written 0600.
        let fresh = root.path().join("new").join("dev.vault.app");
        let window = WindowState {
            x: 1.,
            y: 2.,
            width: 3.,
            height: 4.,
            columns: None,
        };
        write_json(&fresh.join(WINDOW_FILE), &window).unwrap();
        write_json(&fresh.join(RECENT_FILE), &RecentFile::default()).unwrap();
        save_settings_to(&fresh, &Settings::default());
        assert_eq!(mode(&fresh), 0o700);
        for name in [SETTINGS_FILE, RECENT_FILE, WINDOW_FILE] {
            assert_eq!(mode(&fresh.join(name)), 0o600, "{name}");
        }
        assert_eq!(
            read_json::<WindowState>(&fresh.join(WINDOW_FILE)),
            Some(window)
        );
        let leftovers: Vec<_> = fs::read_dir(&fresh)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    /// A failed write (here: a symlink planted at the target) leaves no temp file and
    /// writes nothing through the link.
    #[test]
    fn a_failed_save_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere.json");
        fs::write(&elsewhere, "untouched").unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.path().join(SETTINGS_FILE)).unwrap();
        assert!(write_json(&dir.path().join(SETTINGS_FILE), &Settings::default()).is_err());
        assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "untouched");
        let tmp = fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(tmp, 0);
    }

    /// `show_in_dock` (05 §2.5): missing = true, `false` = false, garbage = true alone.
    #[test]
    fn show_in_dock_settings_json() {
        let dir = tempfile::tempdir().unwrap();
        let load = |json: &str| {
            fs::write(dir.path().join(SETTINGS_FILE), json).unwrap();
            load_settings_from(dir.path())
        };
        assert!(load(r#"{"lock_on_sleep": false}"#).show_in_dock);
        assert!(!load(r#"{"show_in_dock": false}"#).show_in_dock);
        let garbage =
            load(r#"{"show_in_dock": "no", "lock_on_sleep": false, "text_size": "large"}"#);
        assert!(garbage.show_in_dock);
        assert!(!garbage.lock_on_sleep);
        assert_eq!(garbage.text_size, crate::state::TextSize::Large);
        assert!(Settings::default().show_in_dock);
    }
}
