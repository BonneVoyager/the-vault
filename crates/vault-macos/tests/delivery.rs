//! Delivery check for distributed notifications while the center is suspended
//! (which is what AppKit does when the app goes to the background).
//! Posting from a child process mirrors the system posting
//! `com.apple.screenIsLocked`. Verified 2026-10-29: with `Coalesce` or `Hold`
//! instead of `DeliverImmediately`, the first assertion fails.
//!
//! `harness = false` so this runs on the process main thread, which owns the
//! main run loop that delivers distributed notifications.

#[cfg(not(target_os = "macos"))]
fn main() {}

#[cfg(target_os = "macos")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let [_, flag, name] = args.as_slice()
        && flag == "--post"
    {
        macos::post(name);
        return;
    }
    macos::suspended_center_still_delivers();
    println!("delivery: ok");
    if std::env::args().any(|a| a == "--ignored" || a == "--include-ignored") {
        macos::manual_screen_lock();
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use objc2_foundation::{NSDate, NSDistributedNotificationCenter, NSRunLoop, NSString};
    use vault_macos::{on_distributed_notification, on_screen_locked};

    fn pump(for_: Duration, done: impl Fn() -> bool) {
        let deadline = Instant::now() + for_;
        let rl = NSRunLoop::currentRunLoop();
        while Instant::now() < deadline && !done() {
            rl.runUntilDate(&NSDate::dateWithTimeIntervalSinceNow(0.05));
        }
    }

    /// Child-process mode: post `name` from another process, as the system would.
    pub fn post(name: &str) {
        let center = NSDistributedNotificationCenter::defaultCenter();
        // SAFETY: valid NSString name, nil object.
        unsafe { center.postNotificationName_object(&NSString::from_str(name), None) };
    }

    fn post_from_child(name: &str) {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--post", name])
            .status()
            .unwrap();
        assert!(status.success());
    }

    pub fn suspended_center_still_delivers() {
        let name = format!("dev.vault.app.test.{}", std::process::id());
        let ours = Arc::new(AtomicUsize::new(0));
        let ours2 = ours.clone();
        let sub = on_distributed_notification(&name, move || {
            ours2.fetch_add(1, Ordering::SeqCst);
        });

        let center = NSDistributedNotificationCenter::defaultCenter();

        center.setSuspended(true);
        post_from_child(&name);
        pump(Duration::from_secs(3), || ours.load(Ordering::SeqCst) > 0);
        assert_eq!(
            ours.load(Ordering::SeqCst),
            1,
            "DeliverImmediately observer not called while suspended"
        );
        center.setSuspended(false);

        // After drop no further deliveries.
        drop(sub);
        post_from_child(&name);
        pump(Duration::from_millis(500), || false);
        assert_eq!(
            ours.load(Ordering::SeqCst),
            1,
            "callback ran after Subscription drop"
        );
    }

    /// Manual: run `cargo test -p vault-macos --test delivery -- --ignored`,
    /// switch to another app, lock the screen (ctrl-cmd-Q), unlock.
    pub fn manual_screen_lock() {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let _sub = on_screen_locked(move || {
            h.fetch_add(1, Ordering::SeqCst);
            println!("screen locked callback fired");
        });
        println!("lock the screen within 60 s...");
        pump(Duration::from_secs(60), || hits.load(Ordering::SeqCst) > 0);
        assert!(
            hits.load(Ordering::SeqCst) > 0,
            "no screen-lock notification within 60 s"
        );
    }
}
