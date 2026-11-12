//! Menu bar status item while "Show Vault in Dock" is off (05 §2.5, 04 §5c). One
//! main-thread global owns it; one observer on `AppState` installs it, drops it and keeps
//! its glyph in step with the lock state ("no vault open" counts as locked).
//!
//! Like `autolock`, the AppKit callbacks never touch gpui state: they push a `Click` into
//! a channel that a task on gpui's main-thread executor drains.

use std::rc::Rc;

use futures::StreamExt as _;
use futures::channel::mpsc;
use gpui::{App, BorrowAppContext as _, Entity, Task};
use vault_macos::StatusItemCallbacks;

use crate::actions::{Lock, Quit};
use crate::state::AppState;

#[derive(Debug, Clone, Copy)]
enum Click {
    Open,
    LockOrUnlock,
    Quit,
}

/// An installed item, behind a trait so tests can record the calls.
pub trait Handle {
    fn set_locked(&self, locked: bool);
}

impl Handle for vault_macos::StatusItem {
    fn set_locked(&self, locked: bool) {
        vault_macos::StatusItem::set_locked(self, locked);
    }
}

/// Puts an item in the menu bar; `None` when there is none to show.
pub type Installer = Rc<dyn Fn(bool, StatusItemCallbacks) -> Option<Box<dyn Handle>>>;

/// The AppKit item. Any error, `NotAvailable` (headless, off the main thread) included,
/// is logged and means no item; `sync` then turns the Dock icon back on.
pub fn macos_installer() -> Installer {
    Rc::new(
        |locked, callbacks| match vault_macos::StatusItem::install(locked, callbacks) {
            Ok(item) => Some(Box::new(item)),
            Err(e) => {
                log::warn!("could not add the menu bar item: {e}");
                None
            }
        },
    )
}

struct MenuBarItem {
    installer: Installer,
    clicks: mpsc::UnboundedSender<Click>,
    /// `!show_in_dock` as last applied; install and drop happen only on a change.
    wanted: bool,
    item: Option<Box<dyn Handle>>,
    shown_locked: bool,
    _drain: Task<()>,
}

impl gpui::Global for MenuBarItem {}

/// Startup without a window or activation: a login-item launch (04 §5d) while the Dock
/// icon is off, so Vault starts as just the padlock (05 §2.5). Otherwise unchanged.
pub fn start_in_background(login_launch: bool, show_in_dock: bool) -> bool {
    login_launch && !show_in_dock
}

/// Shows the item now if the Dock icon is off and keeps it in step with `state`. `open`
/// is the Dock-reopen path (activates the app, raises or reopens the main window).
pub fn install(state: &Entity<AppState>, installer: Installer, open: fn(&mut App), cx: &mut App) {
    let (clicks, mut rx) = mpsc::unbounded();
    let weak = state.downgrade();
    let drain = cx.spawn(async move |cx| {
        while let Some(click) = rx.next().await {
            let Some(state) = weak.upgrade() else { break };
            cx.update(|cx| on_click(click, &state, open, cx));
        }
    });
    cx.set_global(MenuBarItem {
        installer,
        clicks,
        wanted: false,
        item: None,
        shown_locked: true,
        _drain: drain,
    });
    cx.observe(state, |state, cx| sync(&state, cx)).detach();
    sync(state, cx);
}

/// Lock and Quit go through their actions, as ⌘L and ⌘Q do (Quit runs `on_app_quit`).
/// "Unlock…" opens the window on the unlock screen, like Open Vault.
fn on_click(click: Click, state: &Entity<AppState>, open: fn(&mut App), cx: &mut App) {
    match click {
        Click::LockOrUnlock if !state.read(cx).locked => cx.dispatch_action(&Lock),
        Click::Open | Click::LockOrUnlock => open(cx),
        Click::Quit => cx.dispatch_action(&Quit),
    }
}

const NO_ITEM_TOAST: &str = "Could not add Vault to the menu bar. The Dock icon stays on.";

fn sync(state: &Entity<AppState>, cx: &mut App) {
    let s = state.read(cx);
    let (wanted, locked) = (!s.settings.show_in_dock, s.locked || s.vault_path.is_none());
    let bar = cx.global::<MenuBarItem>();
    let unchanged = wanted == bar.wanted && (bar.item.is_none() || bar.shown_locked == locked);
    if unchanged {
        return;
    }
    let installed = cx.update_global(|bar: &mut MenuBarItem, _| {
        if wanted == bar.wanted {
            if let Some(item) = &bar.item {
                item.set_locked(locked);
            }
            bar.shown_locked = locked;
            return true;
        }
        bar.wanted = wanted;
        bar.shown_locked = locked;
        // Dropping the old item removes it from the menu bar.
        bar.item = None;
        if !wanted {
            return true;
        }
        let send = |click| -> Box<dyn Fn()> {
            let tx = bar.clicks.clone();
            Box::new(move || {
                let _ = tx.unbounded_send(click);
            })
        };
        let callbacks = StatusItemCallbacks {
            open: send(Click::Open),
            lock_or_unlock: send(Click::LockOrUnlock),
            quit: send(Click::Quit),
        };
        bar.item = (bar.installer)(locked, callbacks);
        bar.item.is_some()
    });
    if !installed {
        // Never leave Vault with neither a Dock icon nor a menu bar item: turn the Dock
        // icon back on through the settings path (which restores it), outside this
        // observer and the global update.
        log::warn!("no menu bar item; turning the Dock icon back on");
        let state = state.clone();
        cx.defer(move |cx| {
            state.update(cx, |s, cx| {
                s.update_settings(cx, |st| st.show_in_dock = true);
                s.show_toast(NO_ITEM_TOAST, cx);
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::sync::Arc;

    use gpui::{AppContext as _, TestAppContext};
    use vault_core::{KdfParams, SecretString, Uuid};
    use vault_sync::{NoopHooks, SyncedVault};

    use super::*;
    use crate::state::ChooseIntent;

    #[derive(Debug, PartialEq)]
    enum Call {
        Install(bool),
        SetLocked(bool),
        Dropped,
    }

    type Log = Rc<RefCell<Vec<Call>>>;

    struct Fake(Log);

    impl Handle for Fake {
        fn set_locked(&self, locked: bool) {
            self.0.borrow_mut().push(Call::SetLocked(locked));
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            self.0.borrow_mut().push(Call::Dropped);
        }
    }

    thread_local! {
        static OPENS: Cell<usize> = const { Cell::new(0) };
    }

    fn record_open(_: &mut App) {
        OPENS.with(|n| n.set(n.get() + 1));
    }

    /// Installs with a recording fake; returns its log and the last callbacks handed over.
    fn fake(
        state: &Entity<AppState>,
        cx: &mut TestAppContext,
    ) -> (Log, Rc<RefCell<Option<StatusItemCallbacks>>>) {
        fake_opening(state, record_open, cx)
    }

    fn fake_opening(
        state: &Entity<AppState>,
        open: fn(&mut App),
        cx: &mut TestAppContext,
    ) -> (Log, Rc<RefCell<Option<StatusItemCallbacks>>>) {
        let (log, callbacks) = (Log::default(), Rc::new(RefCell::new(None)));
        let (l, c) = (log.clone(), callbacks.clone());
        let installer: Installer = Rc::new(move |locked, cb| {
            l.borrow_mut().push(Call::Install(locked));
            *c.borrow_mut() = Some(cb);
            Some(Box::new(Fake(l.clone())))
        });
        cx.update(|cx| install(state, installer, open, cx));
        (log, callbacks)
    }

    fn unlocked(dir: &std::path::Path, cx: &mut TestAppContext) -> Entity<AppState> {
        let vault = SyncedVault::create(
            &dir.join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
        state
    }

    fn set_dock(state: &Entity<AppState>, show: bool, cx: &mut TestAppContext) {
        state.update(cx, |s, cx| {
            s.update_settings(cx, |st| st.show_in_dock = show)
        });
        cx.run_until_parked();
    }

    /// Dock icon off installs exactly once (other notifies do not reinstall); on drops it.
    #[gpui::test]
    fn status_item_follows_show_in_dock(cx: &mut TestAppContext) {
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        let (log, _) = fake(&state, cx);
        assert!(log.borrow().is_empty(), "Dock icon on: no item at launch");
        set_dock(&state, false, cx);
        state.update(cx, |_, cx| cx.notify());
        set_dock(&state, false, cx);
        assert_eq!(
            *log.borrow(),
            [Call::Install(true)],
            "no vault open = locked"
        );
        set_dock(&state, true, cx);
        assert_eq!(*log.borrow(), [Call::Install(true), Call::Dropped]);
    }

    /// Lock, unlock and a vault switch each update the glyph once.
    #[gpui::test]
    fn status_item_tracks_lock_state(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let state = unlocked(dir.path(), cx);
        state.update(cx, |s, _| s.settings.show_in_dock = false);
        let (log, _) = fake(&state, cx);
        state.update(cx, |s, cx| s.lock(cx));
        cx.run_until_parked();
        state.update(cx, |s, cx| s.unlock(SecretString::new("pw".into()), cx));
        cx.run_until_parked();
        assert!(!state.read_with(cx, |s, _| s.locked), "unlocked again");
        state.update(cx, |s, cx| s.switch_vault(ChooseIntent::Home, cx));
        cx.run_until_parked();
        assert_eq!(
            *log.borrow(),
            [
                Call::Install(false),
                Call::SetLocked(true),
                Call::SetLocked(false),
                Call::SetLocked(true),
            ]
        );
    }

    /// Open → the reopen path; Lock/Unlock → the Lock action when unlocked, else the
    /// reopen path; Quit → the Quit action (whose real handler calls `cx.quit()`, which
    /// is a no-op on the test platform, so the action itself is what is asserted).
    #[gpui::test]
    fn status_item_callbacks_dispatch(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let state = unlocked(dir.path(), cx);
        state.update(cx, |s, _| s.settings.show_in_dock = false);
        let (locks, quits) = (Rc::new(Cell::new(0)), Rc::new(Cell::new(0)));
        let (l, q) = (locks.clone(), quits.clone());
        cx.update(|cx| {
            cx.on_action(move |_: &Lock, _| l.set(l.get() + 1));
            cx.on_action(move |_: &Quit, _| q.set(q.get() + 1));
        });
        let (_, callbacks) = fake(&state, cx);
        let click = |pick: fn(&StatusItemCallbacks) -> &Box<dyn Fn()>, cx: &mut TestAppContext| {
            pick(callbacks.borrow().as_ref().unwrap())();
            cx.run_until_parked();
        };
        let opens = || OPENS.with(Cell::get);

        click(|c| &c.lock_or_unlock, cx);
        assert_eq!((locks.get(), opens()), (1, 0), "unlocked: Lock");
        state.update(cx, |s, cx| s.lock(cx));
        click(|c| &c.lock_or_unlock, cx);
        assert_eq!((locks.get(), opens()), (1, 1), "locked: open the window");
        click(|c| &c.open, cx);
        assert_eq!(opens(), 2);
        click(|c| &c.quit, cx);
        assert_eq!((quits.get(), locks.get(), opens()), (1, 1, 2));
    }

    /// Startup with the Dock icon already off: one install, locked glyph for a locked
    /// vault, and later notifies neither reinstall nor update.
    #[gpui::test]
    fn status_item_installed_at_startup_when_dock_off(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let state = unlocked(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.lock(cx);
            s.settings.show_in_dock = false;
        });
        let (log, _) = fake(&state, cx);
        state.update(cx, |_, cx| cx.notify());
        cx.run_until_parked();
        assert_eq!(*log.borrow(), [Call::Install(true)]);
    }

    /// Only a login launch with the Dock icon off starts without a window.
    #[test]
    fn start_in_background_only_for_login_launch_with_dock_off() {
        assert!(start_in_background(true, false));
        assert!(!start_in_background(true, true));
        assert!(!start_in_background(false, false));
        assert!(!start_in_background(false, true));
    }

    /// Background startup (no window was ever opened, no `MainWindow` global): the
    /// padlock's Open runs the reopen path, which opens the main window on the unlock
    /// screen of the remembered vault.
    #[gpui::test]
    fn background_start_opens_the_window_from_the_padlock(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let state = unlocked(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.lock(cx);
            s.settings.show_in_dock = false;
        });
        cx.update(|cx| {
            gpui_component::init(cx);
            crate::actions::bind_keys(cx);
            crate::actions::register(&state, cx);
            cx.set_global(crate::RunningVault(state.clone()));
        });
        let (log, callbacks) = fake_opening(&state, crate::reopen_main_window, cx);
        assert_eq!(*log.borrow(), [Call::Install(true)], "locked padlock");
        assert!(cx.update(|cx| cx.windows().is_empty()));

        (callbacks.borrow().as_ref().unwrap().open)();
        cx.run_until_parked();
        assert_eq!(cx.update(|cx| cx.windows().len()), 1);
        state.read_with(cx, |s, _| {
            assert!(s.locked);
            assert_eq!(s.screen, crate::state::Screen::Unlock);
        });
    }

    /// Background start (no window) whose item fails: the setting reverts and still no
    /// window is opened. The activation guard itself is tested on `apply_dock_icon` in
    /// state/prefs.rs: test states run with `persist_recent` off, which skips the policy
    /// call in `update_settings`.
    #[gpui::test]
    fn status_item_failure_without_a_window_reverts_only(cx: &mut TestAppContext) {
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| s.settings.show_in_dock = false);
        let installer: Installer = Rc::new(|_, _| None);
        cx.update(|cx| install(&state, installer, record_open, cx));
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(s.settings.show_in_dock, "setting back on");
            assert_eq!(s.toast.as_ref().unwrap().message.as_ref(), NO_ITEM_TOAST);
        });
        assert!(cx.update(|cx| cx.windows().is_empty()), "no window opened");
        assert_eq!(OPENS.with(Cell::get), 0, "reopen path not taken");

        // No window: the toast waits past its TTL (05 §3 "Toasts without a window") and
        // shows for its full time once the window opens.
        let ttl = crate::state::TOAST_TTL;
        cx.executor().advance_clock(ttl * 2);
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert_eq!(s.toast.as_ref().unwrap().message.as_ref(), NO_ITEM_TOAST);
        });
        cx.update(|cx| {
            gpui_component::init(cx);
            crate::actions::bind_keys(cx);
            crate::actions::register(&state, cx);
            cx.set_global(crate::RunningVault(state.clone()));
            crate::reopen_main_window(cx);
        });
        cx.run_until_parked();
        assert_eq!(cx.update(|cx| cx.windows().len()), 1);
        cx.executor()
            .advance_clock(ttl - std::time::Duration::from_millis(1));
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert_eq!(s.toast.as_ref().unwrap().message.as_ref(), NO_ITEM_TOAST);
        });
        cx.executor()
            .advance_clock(std::time::Duration::from_millis(1));
        cx.run_until_parked();
        assert!(state.read_with(cx, |s, _| s.toast.is_none()), "expired");
    }

    /// An installer that fails (e.g. `NotAvailable`) turns the Dock icon back on, says
    /// so, and holds no item.
    #[gpui::test]
    fn status_item_failure_restores_the_dock_icon(cx: &mut TestAppContext) {
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        let tries = Rc::new(Cell::new(0));
        let t = tries.clone();
        let installer: Installer = Rc::new(move |_, _| {
            t.set(t.get() + 1);
            None
        });
        cx.update(|cx| install(&state, installer, record_open, cx));
        set_dock(&state, false, cx);
        state.read_with(cx, |s, _| {
            assert!(s.settings.show_in_dock, "setting back on");
            assert_eq!(s.toast.as_ref().unwrap().message.as_ref(), NO_ITEM_TOAST);
        });
        assert_eq!(tries.get(), 1);
        cx.update(|cx| {
            let bar = cx.global::<MenuBarItem>();
            assert!(bar.item.is_none() && !bar.wanted);
        });
    }
}
