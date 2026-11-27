//! Open panel limited to given file extensions (spec 04 §3b).
//!
//! gpui's path prompt has no content-type filter, so `vault-app` uses this
//! for pickers that must only offer certain files (the item icon picker
//! offers PNG and JPEG). The filter uses `NSSavePanel.allowedFileTypes`,
//! which Apple deprecated in favour of `allowedContentTypes`; the latter
//! needs `UTType` bindings (a new crate), while the deprecated property still
//! works on macOS 15+ and accepts plain extensions.
//!
//! The panel is non-modal (`beginWithCompletionHandler`), never `runModal`:
//! gpui polls every foreground task from a main dispatch queue callback, and
//! the main queue is serial, so a modal loop entered from a task held every
//! other task (the auto-lock tick, the clipboard timer, redraws) until the
//! panel closed (security review 2026-11-26 M-04; `tests/modal_queue.rs`).

use std::cell::Cell;
use std::path::PathBuf;

thread_local! {
    /// True while a panel from [`choose_file_async`] is up on this thread.
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

/// Claims the per-thread panel flag; `None` if a panel is already up on this
/// thread.
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

/// Shows an `NSOpenPanel` (its own window, not a sheet) for picking one
/// existing file whose extension is in `extensions` (see
/// [`normalize_extensions`]); `prompt` is the confirm button's title.
/// Directories and multiple selection are off and aliases are resolved.
/// Returns at once; the run loop and the main dispatch queue keep running
/// while the panel is up.
///
/// When the panel closes, `done` runs on the main thread (AppKit delivers
/// the completion handler there; a handler call on any other thread is
/// ignored with a warning and `done` is not called) with the chosen
/// file's path on OK and `None` on cancel (including [`cancel_open_panel`]),
/// after the panel slot is free again, so `done` may open the next panel.
/// `done` may run synchronously inside [`cancel_open_panel`].
///
/// Returns `false` and never calls `done` when not on the main thread
/// (AppKit is not touched), when a panel from this function is already up,
/// when `extensions` normalises to an empty list (the panel could not be
/// limited), and always off macOS.
pub fn choose_file_async(
    extensions: &[&str],
    prompt: &str,
    done: impl FnOnce(Option<PathBuf>) + 'static,
) -> bool {
    imp::choose_file_async(extensions, prompt, Box::new(done))
}

/// Closes the panel from [`choose_file_async`] as if the user pressed
/// Cancel (its `done` gets `None`). Does nothing when no panel is up or when
/// not called on the main thread. `vault-app` calls it on lock, so a panel
/// opened for an unlocked session does not outlive it.
pub fn cancel_open_panel() {
    imp::cancel_open_panel();
}

#[cfg(target_os = "macos")]
mod imp {
    use std::cell::{Cell, RefCell};
    use std::path::PathBuf;

    use block2::RcBlock;
    use objc2::MainThreadMarker;
    use objc2::rc::Retained;
    use objc2_app_kit::{NSModalResponse, NSModalResponseOK, NSOpenPanel};
    use objc2_foundation::{NSArray, NSString};

    thread_local! {
        /// The panel that is up (at most one per thread, see `enter_panel`).
        static CURRENT: RefCell<Option<Retained<NSOpenPanel>>> = const { RefCell::new(None) };
    }

    type Done = Box<dyn FnOnce(Option<PathBuf>)>;

    pub fn choose_file_async(extensions: &[&str], prompt: &str, done: Done) -> bool {
        let Some(mtm) = MainThreadMarker::new() else {
            return false;
        };
        let types = super::normalize_extensions(extensions);
        if types.is_empty() {
            return false;
        }
        let Some(guard) = super::enter_panel() else {
            return false;
        };
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

        CURRENT.with(|c| *c.borrow_mut() = Some(panel.clone()));
        // The block type is `Fn`; the one-shot state is taken on the first
        // call, so a second call (AppKit never makes one) does nothing.
        // If AppKit released the block without ever calling it (it does so
        // only when the process exits with the panel up), `pending` would be
        // dropped with it: `done` never runs, and the guard's Drop clears
        // `IN_PANEL` of the dropping thread (at exit nothing reads it again).
        let pending: Cell<Option<(super::PanelGuard, Done)>> = Cell::new(Some((guard, done)));
        let handler = RcBlock::new(move |response: NSModalResponse| {
            // AppKit delivers the completion handler on the main thread. This
            // is a guard: the panel slot and the guard are main-thread
            // thread-locals and `done` expects the main thread, so on any
            // other thread nothing is touched and `done` is not called.
            if MainThreadMarker::new().is_none() {
                tracing::warn!("open panel completion handler ran off the main thread; ignored");
                return;
            }
            let Some((guard, done)) = pending.take() else {
                return;
            };
            let panel = CURRENT.with(|c| c.borrow_mut().take());
            drop(guard);
            let path = if response == NSModalResponseOK {
                panel
                    .and_then(|p| p.URL())
                    .and_then(|u| u.path())
                    .map(|p| PathBuf::from(p.to_string()))
            } else {
                None
            };
            done(path);
        });
        // The panel copies the block; `handler` may be dropped after this.
        panel.beginWithCompletionHandler(&handler);
        true
    }

    pub fn cancel_open_panel() {
        if MainThreadMarker::new().is_none() {
            return;
        }
        // Cloned out first: the completion handler (maybe run inside
        // `cancel:`) takes the slot itself.
        let panel = CURRENT.with(|c| c.borrow().clone());
        if let Some(panel) = panel {
            // SAFETY: `cancel:` is the panel's Cancel button action and takes
            // any sender, nil included. We are on the main thread (checked
            // above) and hold a retained reference to the panel, so it stays
            // alive through the call even when its completion handler runs
            // inside it and clears `CURRENT`.
            unsafe { panel.cancel(None) };
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use std::path::PathBuf;

    pub fn choose_file_async(
        _extensions: &[&str],
        _prompt: &str,
        _done: Box<dyn FnOnce(Option<PathBuf>)>,
    ) -> bool {
        false
    }

    pub fn cancel_open_panel() {}
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
    /// the check is the first thing `choose_file_async` does). `done` is
    /// never called, and the panel slot is not taken.
    #[test]
    fn off_main_thread_refuses_and_never_calls_done() {
        let called = std::rc::Rc::new(Cell::new(false));
        let c = called.clone();
        assert!(!choose_file_async(&["png", "jpg"], "Choose", move |_| c.set(true)));
        assert!(!called.get());
        assert!(enter_panel().is_some(), "slot not taken");
        let handle = std::thread::spawn(|| choose_file_async(&["png"], "Choose", |_| panic!()));
        assert!(!handle.join().unwrap());
        // Nothing to cancel, and off the main thread: a no-op.
        cancel_open_panel();
    }
}
