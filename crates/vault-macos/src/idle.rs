//! Idle and lock triggers (spec 04 §5).

use std::time::SystemTime;

pub use imp::Subscription;
#[cfg(not(target_os = "macos"))]
pub(crate) use imp::noop_subscription;
#[cfg(target_os = "macos")]
pub(crate) use imp::on_center_notification;

/// Calls `cb` when the distributed notification `name` is posted, even while
/// the app is inactive. Building block for [`on_screen_locked`]; public so the
/// delivery test can use a private notification name.
#[doc(hidden)]
#[must_use = "dropping the Subscription unregisters the observer"]
pub fn on_distributed_notification(name: &str, cb: impl Fn() + Send + 'static) -> Subscription {
    imp::on_distributed_notification(name, cb)
}

/// Seconds since the last keyboard, mouse or trackpad event, system-wide.
pub fn seconds_since_user_input() -> f64 {
    imp::seconds_since_user_input()
}

/// Calls `cb` when the screen locks (`com.apple.screenIsLocked`).
///
/// Registered with `NSNotificationSuspensionBehaviorDeliverImmediately`, so it
/// fires even while the app is in the background. Delivered on the main
/// thread's run loop, so `cb` only fires while that run loop is running.
/// The observer stays registered until the returned [`Subscription`] is dropped.
#[must_use = "dropping the Subscription unregisters the observer"]
pub fn on_screen_locked(cb: impl Fn() + Send + 'static) -> Subscription {
    imp::on_screen_locked(cb)
}

/// Calls `cb` when the system is about to sleep (`NSWorkspaceWillSleepNotification`).
///
/// Delivered on the main thread's run loop. The observer stays registered
/// until the returned [`Subscription`] is dropped.
#[must_use = "dropping the Subscription unregisters the observer"]
pub fn on_will_sleep(cb: impl Fn() + Send + 'static) -> Subscription {
    imp::on_will_sleep(cb)
}

/// Calls `cb` when this login session stops being the active console
/// session, e.g. on fast user switching to another account
/// (`NSWorkspaceSessionDidResignActiveNotification`).
///
/// Delivered on the main thread's run loop. The observer stays registered
/// until the returned [`Subscription`] is dropped.
#[must_use = "dropping the Subscription unregisters the observer"]
pub fn on_user_switched(cb: impl Fn() + Send + 'static) -> Subscription {
    imp::on_user_switched(cb)
}

/// When the machine last booted (`sysctl kern.boottime`).
///
/// Returns `UNIX_EPOCH` if the value cannot be read.
pub fn boot_time() -> SystemTime {
    imp::boot_time()
}

/// True if the user enabled System Settings > Accessibility > Display >
/// Reduce motion (`NSWorkspace.accessibilityDisplayShouldReduceMotion`).
/// Always false off macOS.
pub fn reduce_motion_enabled() -> bool {
    imp::reduce_motion_enabled()
}

#[cfg(target_os = "macos")]
mod imp {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::ptr;
    use std::sync::{Mutex, TryLockError};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use objc2::rc::Retained;
    use objc2::runtime::{AnyObject, NSObject};
    use objc2::{AnyThread, DefinedClass, Message, define_class, msg_send, sel};
    use objc2_app_kit::{
        NSWorkspace, NSWorkspaceSessionDidResignActiveNotification,
        NSWorkspaceWillSleepNotification,
    };
    use objc2_core_graphics::{CGEventSource, CGEventSourceStateID, CGEventType};
    use objc2_foundation::{
        NSDistributedNotificationCenter, NSNotification, NSNotificationCenter, NSNotificationName,
        NSNotificationSuspensionBehavior, NSString,
    };

    /// `kCGAnyInputEventType` is `(CGEventType)(~0)` in CGEventTypes.h; the
    /// objc2 bindings do not export it.
    const ANY_INPUT_EVENT_TYPE: CGEventType = CGEventType(u32::MAX);

    const SCREEN_IS_LOCKED: &str = "com.apple.screenIsLocked";

    pub fn seconds_since_user_input() -> f64 {
        CGEventSource::seconds_since_last_event_type(
            CGEventSourceStateID::HIDSystemState,
            ANY_INPUT_EVENT_TYPE,
        )
    }

    type Callback = Box<dyn Fn() + Send>;

    /// Ivars of [`Observer`]. The mutex makes the class `Send + Sync` with a
    /// `Send`-only callback. Overlapping calls are skipped, not queued.
    struct ObserverIvars {
        cb: Mutex<Callback>,
    }

    define_class!(
        // SAFETY: NSObject has no subclassing requirements and `Observer`
        // does not implement `Drop`.
        #[unsafe(super(NSObject))]
        #[ivars = ObserverIvars]
        struct Observer;

        impl Observer {
            // SAFETY: the signature matches what NSNotificationCenter sends
            // to an observer selector: `- (void)handle:(NSNotification *)n`.
            #[unsafe(method(handle:))]
            fn handle(&self, _note: &NSNotification) {
                // Keep `self` alive even if the Subscription is dropped on
                // another thread while this call is running.
                let _keep = self.retain();
                // `try_lock`, not `lock`: if `cb` pumps a nested run loop and
                // this notification is re-delivered on the same thread,
                // blocking would deadlock. The nested delivery is skipped
                // instead; the outer call is already handling the event.
                // (An `Arc<dyn Fn + Sync>` would allow calling without the
                // lock but would force `Sync` on the spec §5 callback bound.)
                let cb = match self.ivars().cb.try_lock() {
                    Ok(guard) => guard,
                    Err(TryLockError::Poisoned(e)) => e.into_inner(),
                    Err(TryLockError::WouldBlock) => return,
                };
                // Unwinding into Objective-C frames is not allowed; contain
                // the panic here (the panic hook has already reported it).
                let _ = catch_unwind(AssertUnwindSafe(|| (*cb)()));
            }
        }
    );

    impl Observer {
        fn new(cb: Callback) -> Retained<Self> {
            let this = Self::alloc().set_ivars(ObserverIvars { cb: Mutex::new(cb) });
            // SAFETY: `init` is NSObject's designated initializer and the
            // ivars were set above, so the object is fully initialised.
            unsafe { msg_send![super(this), init] }
        }
    }

    /// Guard for a notification observer; removes it from its center on drop.
    ///
    /// Drop does not wait for a callback that is already running. All three
    /// notifications (screen lock, will sleep, user switch) are delivered on
    /// the main thread, so drop the guard on the main thread to be sure no
    /// callback is in flight.
    pub struct Subscription {
        center: Retained<NSNotificationCenter>,
        observer: Retained<Observer>,
    }

    impl Drop for Subscription {
        fn drop(&mut self) {
            let observer: &AnyObject = &self.observer;
            // SAFETY: `observer` is the object registered on this same center
            // in `on_*`; `removeObserver:` accepts any object.
            unsafe { self.center.removeObserver(observer) };
        }
    }

    impl std::fmt::Debug for Subscription {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Subscription").finish_non_exhaustive()
        }
    }

    /// Observes a distributed notification with
    /// `NSNotificationSuspensionBehaviorDeliverImmediately`, so it is delivered
    /// even while the app is inactive (the block API would coalesce it).
    pub fn on_distributed_notification(name: &str, cb: impl Fn() + Send + 'static) -> Subscription {
        let center = NSDistributedNotificationCenter::defaultCenter();
        let name = NSString::from_str(name);
        let observer = Observer::new(Box::new(cb));
        // SAFETY: `observer` is an `Observer`, which implements `handle:`
        // with the `(NSNotification *)` signature the center calls; `name` is
        // a valid NSString and a nil object means "any sender".
        unsafe {
            center.addObserver_selector_name_object_suspensionBehavior(
                &observer,
                sel!(handle:),
                Some(&name),
                None,
                NSNotificationSuspensionBehavior::DeliverImmediately,
            );
        }
        Subscription {
            center: Retained::into_super(center),
            observer,
        }
    }

    pub fn on_screen_locked(cb: impl Fn() + Send + 'static) -> Subscription {
        on_distributed_notification(SCREEN_IS_LOCKED, cb)
    }

    /// Observes `name` (any sender) on an in-process notification `center`.
    /// Shared with `appearance.rs`.
    pub(crate) fn on_center_notification(
        center: Retained<NSNotificationCenter>,
        name: &NSNotificationName,
        cb: impl Fn() + Send + 'static,
    ) -> Subscription {
        let observer = Observer::new(Box::new(cb));
        // SAFETY: as in `on_distributed_notification`: `observer` implements
        // `handle:` with the expected signature; nil object = any sender.
        unsafe {
            center.addObserver_selector_name_object(&observer, sel!(handle:), Some(name), None);
        }
        Subscription { center, observer }
    }

    /// Observes `name` on NSWorkspace's own notification center.
    fn on_workspace_notification(
        name: &NSNotificationName,
        cb: impl Fn() + Send + 'static,
    ) -> Subscription {
        on_center_notification(
            NSWorkspace::sharedWorkspace().notificationCenter(),
            name,
            cb,
        )
    }

    pub fn on_will_sleep(cb: impl Fn() + Send + 'static) -> Subscription {
        // SAFETY: AppKit initialises this extern constant at load time; it is
        // an immutable NSString that lives for the whole process.
        let name: &NSNotificationName = unsafe { NSWorkspaceWillSleepNotification };
        on_workspace_notification(name, cb)
    }

    pub fn on_user_switched(cb: impl Fn() + Send + 'static) -> Subscription {
        // SAFETY: as for `NSWorkspaceWillSleepNotification` above.
        let name: &NSNotificationName = unsafe { NSWorkspaceSessionDidResignActiveNotification };
        on_workspace_notification(name, cb)
    }

    pub fn boot_time() -> SystemTime {
        let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut len = size_of::<libc::timeval>();
        // SAFETY: `mib` points to 2 valid c_ints and its length is passed;
        // `tv` is a writable timeval and `len` holds its exact size, so the
        // kernel cannot write past it. No new value is set (null, 0).
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                (&raw mut tv).cast(),
                &mut len,
                ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || len != size_of::<libc::timeval>() || tv.tv_sec < 0 {
            return UNIX_EPOCH;
        }
        UNIX_EPOCH
            + Duration::from_secs(tv.tv_sec as u64)
            + Duration::from_micros(tv.tv_usec.max(0) as u64)
    }

    pub fn reduce_motion_enabled() -> bool {
        NSWorkspace::sharedWorkspace().accessibilityDisplayShouldReduceMotion()
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn seconds_since_user_input() -> f64 {
        0.0
    }

    /// No-op guard on non-macOS hosts.
    #[derive(Debug)]
    pub struct Subscription(());

    pub(crate) fn noop_subscription() -> Subscription {
        Subscription(())
    }

    pub fn on_screen_locked(_cb: impl Fn() + Send + 'static) -> Subscription {
        Subscription(())
    }

    pub fn on_will_sleep(_cb: impl Fn() + Send + 'static) -> Subscription {
        Subscription(())
    }

    pub fn on_user_switched(_cb: impl Fn() + Send + 'static) -> Subscription {
        Subscription(())
    }

    pub fn on_distributed_notification(
        _name: &str,
        _cb: impl Fn() + Send + 'static,
    ) -> Subscription {
        Subscription(())
    }

    pub fn boot_time() -> SystemTime {
        UNIX_EPOCH
    }

    pub fn reduce_motion_enabled() -> bool {
        false
    }
}
