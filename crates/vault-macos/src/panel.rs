//! Modal open panel limited to given file extensions (spec 04 §3b).
//!
//! gpui's path prompt has no content-type filter, so `vault-app` uses this
//! for pickers that must only offer certain files (the item icon picker
//! offers PNG and JPEG). The filter uses `NSSavePanel.allowedFileTypes`,
//! which Apple deprecated in favour of `allowedContentTypes`; the latter
//! needs `UTType` bindings (a new crate), while the deprecated property still
//! works on macOS 15+ and accepts plain extensions.

use std::cell::Cell;
use std::path::PathBuf;

thread_local! {
    /// True while this thread is inside [`choose_file`]'s modal loop.
    static IN_PANEL: Cell<bool> = const { Cell::new(false) };
}

/// Marks this thread as showing a panel until dropped (also on unwind).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
struct PanelGuard;

impl Drop for PanelGuard {
    fn drop(&mut self) {
        IN_PANEL.with(|f| f.set(false));
    }
}

/// Claims the per-thread panel flag; `None` if a panel is already running on
/// this thread (a nested call from a timer or dispatch block during
/// `runModal`).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn enter_panel() -> Option<PanelGuard> {
    IN_PANEL.with(|f| {
        if f.get() {
            None
        } else {
            f.set(true);
            Some(PanelGuard)
        }
    })
}

/// Normalises `extensions` into the list handed to the panel's file-type
/// filter: surrounding whitespace and one leading `.` removed, lowercased,
/// empty entries dropped, duplicates removed (first occurrence keeps its
/// position).
pub fn normalize_extensions(extensions: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(extensions.len());
    for ext in extensions {
        let ext = ext.trim();
        let ext = ext.strip_prefix('.').unwrap_or(ext).to_lowercase();
        if !ext.is_empty() && !out.contains(&ext) {
            out.push(ext);
        }
    }
    out
}

/// Shows a modal `NSOpenPanel` for picking one existing file whose extension
/// is in `extensions` (see [`normalize_extensions`]); `prompt` is the
/// confirm button's title. Directories and multiple selection are off and
/// aliases are resolved. Blocks until the user closes the panel.
///
/// Returns the chosen file's path on OK. Returns `None` when the user
/// cancels, when not called on the main thread (AppKit is not touched), when
/// `extensions` normalises to an empty list (the panel is not shown, since it
/// could not be limited), and always off macOS.
///
/// Not re-entrant: while the modal loop runs, AppKit still fires timers and
/// main-queue blocks, and a nested call from one of them returns `None` at
/// once instead of stacking a second modal panel.
pub fn choose_file(extensions: &[&str], prompt: &str) -> Option<PathBuf> {
    imp::choose_file(extensions, prompt)
}

#[cfg(target_os = "macos")]
mod imp {
    use std::path::PathBuf;

    use objc2::MainThreadMarker;
    use objc2::rc::Retained;
    use objc2_app_kit::{NSModalResponseOK, NSOpenPanel};
    use objc2_foundation::{NSArray, NSString};

    pub fn choose_file(extensions: &[&str], prompt: &str) -> Option<PathBuf> {
        let mtm = MainThreadMarker::new()?;
        let _guard = super::enter_panel()?;
        let types = super::normalize_extensions(extensions);
        if types.is_empty() {
            return None;
        }
        let types: Vec<Retained<NSString>> = types.iter().map(|t| NSString::from_str(t)).collect();
        let types = NSArray::from_retained_slice(&types);

        let panel = NSOpenPanel::openPanel(mtm);
        panel.setCanChooseFiles(true);
        panel.setCanChooseDirectories(false);
        panel.setAllowsMultipleSelection(false);
        panel.setResolvesAliases(true);
        panel.setAllowsOtherFileTypes(false);
        panel.setPrompt(Some(&NSString::from_str(prompt)));
        // Deprecated in favour of allowedContentTypes (needs UTType bindings);
        // still honoured on macOS 15+. See the module docs.
        #[allow(deprecated)]
        panel.setAllowedFileTypes(Some(&types));

        if panel.runModal() != NSModalResponseOK {
            return None;
        }
        let path = panel.URL()?.path()?;
        Some(PathBuf::from(path.to_string()))
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use std::path::PathBuf;

    pub fn choose_file(_extensions: &[&str], _prompt: &str) -> Option<PathBuf> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_lowercases_and_dedupes() {
        assert_eq!(
            normalize_extensions(&["PNG", "jpg", "png", "JPEG", "Jpg"]),
            vec!["png", "jpg", "jpeg"]
        );
    }

    #[test]
    fn normalize_strips_dot_whitespace_and_empties() {
        assert_eq!(
            normalize_extensions(&[".png", " jpeg ", "", " ", "."]),
            vec!["png", "jpeg"]
        );
        assert!(normalize_extensions(&[]).is_empty());
    }

    #[test]
    fn normalize_keeps_order_of_first_occurrence() {
        assert_eq!(
            normalize_extensions(&["jpg", "PNG", "JPG"]),
            vec!["jpg", "png"]
        );
    }

    #[test]
    fn nested_call_is_refused_while_panel_runs() {
        let outer = enter_panel().expect("first entry");
        assert!(enter_panel().is_none(), "nested entry must be refused");
        drop(outer);
        let again = enter_panel().expect("flag cleared on drop");
        drop(again);
    }

    #[test]
    fn guard_clears_flag_on_panic() {
        let r = std::panic::catch_unwind(|| {
            let _g = enter_panel().expect("first entry");
            panic!("inside panel");
        });
        assert!(r.is_err());
        assert!(enter_panel().is_some(), "flag cleared during unwind");
    }

    #[test]
    fn flag_is_per_thread() {
        let _outer = enter_panel().expect("first entry");
        let other = std::thread::spawn(|| enter_panel().is_some());
        assert!(other.join().unwrap());
    }

    /// libtest runs tests on worker threads, never the process main thread,
    /// so this exercises the off-main-thread guard (no AppKit call is made:
    /// the check is the first thing `choose_file` does).
    #[test]
    fn off_main_thread_returns_none() {
        assert_eq!(choose_file(&["png", "jpg"], "Choose"), None);
        let handle = std::thread::spawn(|| choose_file(&["png"], "Choose"));
        assert_eq!(handle.join().unwrap(), None);
    }
}
