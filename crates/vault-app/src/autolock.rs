//! Auto-lock triggers (specs/05-ui.md §3): a 1 s idle tick plus screen-lock, will-sleep
//! and user-switch notifications from `vault-macos`. The tick also refreshes the
//! "Reduce motion" flag (§5).
//!
//! The notification callbacks run inside AppKit's run loop. They never touch gpui
//! state: they push a `Signal` into an async channel, and a task on gpui's main-thread
//! executor drains it. The channel wakes that task immediately, so the vault locks
//! before the machine sleeps rather than at the next tick after wake.

use std::time::Duration;

use futures::StreamExt as _;
use futures::channel::mpsc;
use gpui::{App, Entity, InteractiveElement, Keystroke, Modifiers, Subscription, Task};

use crate::state::AppState;

const TICK: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy)]
enum Signal {
    ScreenLocked,
    WillSleep,
    /// Fast user switching moved the console to another account.
    UserSwitched,
}

/// Keeps the observers and tasks alive. Drop on the main thread.
pub struct LockTriggers {
    _screen_locked: vault_macos::Subscription,
    _will_sleep: vault_macos::Subscription,
    _user_switched: vault_macos::Subscription,
    _signals: Task<()>,
    _tick: Task<()>,
    _keys: Subscription,
}

pub fn install(state: &Entity<AppState>, cx: &mut App) -> LockTriggers {
    let (tx, rx) = mpsc::unbounded::<Signal>();
    let screen_tx = tx.clone();
    let screen_locked = vault_macos::on_screen_locked(move || {
        let _ = screen_tx.unbounded_send(Signal::ScreenLocked);
    });
    let switch_tx = tx.clone();
    let user_switched = vault_macos::on_user_switched(move || {
        let _ = switch_tx.unbounded_send(Signal::UserSwitched);
    });
    let will_sleep = vault_macos::on_will_sleep(move || {
        let _ = tx.unbounded_send(Signal::WillSleep);
    });
    let signals = drain_signals(state, rx, cx);
    let keys = gate_keys(state, cx);

    let reduce_motion = vault_macos::reduce_motion_enabled();
    state.update(cx, |s, cx| s.set_reduce_motion(reduce_motion, cx));
    let weak = state.downgrade();
    let tick = cx.spawn(async move |cx| {
        loop {
            cx.background_executor().timer(TICK).await;
            let idle = vault_macos::seconds_since_user_input();
            // Cheap (one NSWorkspace property read); a change takes effect within a second.
            let reduce_motion = vault_macos::reduce_motion_enabled();
            let alive = weak.update(cx, |state, cx| {
                state.set_reduce_motion(reduce_motion, cx);
                state.tick(idle, cx);
            });
            if alive.is_err() {
                break;
            }
        }
    });

    LockTriggers {
        _screen_locked: screen_locked,
        _will_sleep: will_sleep,
        _user_switched: user_switched,
        _signals: signals,
        _tick: tick,
        _keys: keys,
    }
}

/// Every keystroke in every window counts as activity, before gpui matches it to a key
/// binding or a menu key equivalent. When the Mac slept past the idle limit the vault
/// locks instead and the keystroke stops here, so a shortcut (⌘⇧C, ⌘⇧R…) cannot act on
/// the vault it found open (L-13). ⌘L and ⌘Q still go through.
pub fn gate_keys(state: &Entity<AppState>, cx: &mut App) -> Subscription {
    let state = state.downgrade();
    cx.intercept_keystrokes(move |event, _, cx| {
        let locked = state
            .update(cx, |s, cx| s.note_activity(cx))
            .unwrap_or(false);
        if locked && !passes_lock(&event.keystroke) {
            cx.stop_propagation();
        }
    })
}

/// ⌘L and ⌘Q: harmless on a locked vault, and the user expects them to work.
pub(crate) fn passes_lock(k: &Keystroke) -> bool {
    k.modifiers == Modifiers::command() && matches!(k.key.as_str(), "l" | "q")
}

/// Mouse-down anywhere in `el` (a window's root) counts as activity. When the Mac slept
/// past the idle limit the vault locks instead and the press stops in the capture phase,
/// so no click (copy, reveal) reaches the vault it found open (L-13).
pub fn gate_mouse<E: InteractiveElement>(el: E, state: &Entity<AppState>) -> E {
    let state = state.downgrade();
    el.capture_any_mouse_down(move |_, _, cx| {
        let locked = state
            .update(cx, |s, cx| s.note_activity(cx))
            .unwrap_or(false);
        if locked {
            cx.stop_propagation();
        }
    })
}

/// Locks on every signal while "Lock on sleep, screen lock or user switch" is on. Ends
/// when the state is dropped or every sender is gone.
fn drain_signals(
    state: &Entity<AppState>,
    mut rx: mpsc::UnboundedReceiver<Signal>,
    cx: &mut App,
) -> Task<()> {
    let weak = state.downgrade();
    cx.spawn(async move |cx| {
        while let Some(signal) = rx.next().await {
            let alive = weak.update(cx, |state, cx| match signal {
                // One setting covers all three triggers (05 §2.5 "lock on sleep/screen
                // lock"; user switch added under the same toggle).
                Signal::ScreenLocked | Signal::WillSleep | Signal::UserSwitched
                    if state.settings.lock_on_sleep =>
                {
                    state.lock(cx);
                }
                Signal::ScreenLocked | Signal::WillSleep | Signal::UserSwitched => {}
            });
            if alive.is_err() {
                break;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gpui::{AppContext as _, TestAppContext};
    use vault_core::{KdfParams, SecretString, Uuid};
    use vault_sync::{NoopHooks, SyncedVault};

    use super::*;

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
        state.read_with(cx, |s, _| assert!(!s.locked));
        state
    }

    /// Each notification locks through the same channel the AppKit observers feed.
    #[gpui::test]
    fn every_trigger_locks(cx: &mut TestAppContext) {
        for signal in [
            Signal::ScreenLocked,
            Signal::WillSleep,
            Signal::UserSwitched,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = unlocked(dir.path(), cx);
            let (tx, rx) = mpsc::unbounded();
            let _task = cx.update(|cx| drain_signals(&state, rx, cx));
            tx.unbounded_send(signal).unwrap();
            cx.run_until_parked();
            state.read_with(cx, |s, _| assert!(s.locked, "{signal:?} locks"));
        }
    }

    /// With the setting off, a user switch (or any trigger) leaves the vault open.
    #[gpui::test]
    fn triggers_respect_the_setting(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let state = unlocked(dir.path(), cx);
        state.update(cx, |s, _| s.settings.lock_on_sleep = false);
        let (tx, rx) = mpsc::unbounded();
        let _task = cx.update(|cx| drain_signals(&state, rx, cx));
        for signal in [
            Signal::UserSwitched,
            Signal::ScreenLocked,
            Signal::WillSleep,
        ] {
            tx.unbounded_send(signal).unwrap();
        }
        cx.run_until_parked();
        state.read_with(cx, |s, _| assert!(!s.locked));
    }
}
