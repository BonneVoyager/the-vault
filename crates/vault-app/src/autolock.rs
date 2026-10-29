//! Auto-lock triggers (specs/05-ui.md §3): a 1 s idle tick plus screen-lock and
//! will-sleep notifications from `vault-macos`. The tick also refreshes the
//! "Reduce motion" flag (§5).
//!
//! The notification callbacks run inside AppKit's run loop. They never touch gpui
//! state: they push a `Signal` into an async channel, and a task on gpui's main-thread
//! executor drains it. The channel wakes that task immediately, so the vault locks
//! before the machine sleeps rather than at the next tick after wake.

use std::time::Duration;

use futures::StreamExt as _;
use futures::channel::mpsc;
use gpui::{App, Entity, Task};

use crate::state::AppState;

const TICK: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy)]
enum Signal {
    ScreenLocked,
    WillSleep,
}

/// Keeps the observers and tasks alive. Drop on the main thread.
pub struct LockTriggers {
    _screen_locked: vault_macos::Subscription,
    _will_sleep: vault_macos::Subscription,
    _signals: Task<()>,
    _tick: Task<()>,
}

pub fn install(state: &Entity<AppState>, cx: &mut App) -> LockTriggers {
    let (tx, mut rx) = mpsc::unbounded::<Signal>();
    let screen_tx = tx.clone();
    let screen_locked = vault_macos::on_screen_locked(move || {
        let _ = screen_tx.unbounded_send(Signal::ScreenLocked);
    });
    let will_sleep = vault_macos::on_will_sleep(move || {
        let _ = tx.unbounded_send(Signal::WillSleep);
    });

    let weak = state.downgrade();
    let signals = cx.spawn(async move |cx| {
        while let Some(signal) = rx.next().await {
            let alive = weak.update(cx, |state, cx| match signal {
                // One setting covers both triggers (05 §2.5 "lock on sleep/screen lock").
                Signal::ScreenLocked | Signal::WillSleep if state.settings.lock_on_sleep => {
                    state.lock(cx);
                }
                Signal::ScreenLocked | Signal::WillSleep => {}
            });
            if alive.is_err() {
                break;
            }
        }
    });

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
        _signals: signals,
        _tick: tick,
    }
}
