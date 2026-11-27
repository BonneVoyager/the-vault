//! Experiment and regression test for security review M-04: which callbacks
//! run on the main thread while `NSOpenPanel::runModal` spins its nested run
//! loop (cases 1-3, the cause; printed as evidence, not asserted), and that `vault_macos::choose_file_async`
//! leaves the main queue running while its panel is up (case 4, the fix).
//!
//! gpui-pre resumes foreground tasks through the main dispatch queue and its
//! timers through `dispatch_after` on a global queue that then hops to the
//! main queue. This binary reproduces both paths (with the `_f` function
//! variants, so no block crate is needed) plus a run-loop source
//! (`performSelectorOnMainThread:` in the modal panel mode) as a watchdog,
//! and records for each callback whether `NSApp.modalWindow` was set when it
//! ran. `harness = false` because AppKit panels need the process main
//! thread. It needs a window server: it is skipped when there is no GUI
//! login session (`CGSessionCopyCurrentDictionary` returns NULL) or when
//! `VAULT_SKIP_GUI_TESTS` is set. A panel appears for up to two seconds per
//! case and closes itself (about five seconds in all).

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("test modal_queue ... ignored (macOS only)");
}

#[cfg(target_os = "macos")]
fn main() {
    imp::main();
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::c_void;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, Ordering};
    use std::time::{Duration, Instant};

    use objc2::rc::Retained;
    use objc2::runtime::NSObjectProtocol;
    use objc2::runtime::{AnyObject, Sel};
    use objc2::{ClassType, MainThreadMarker, msg_send, sel};
    use objc2_app_kit::{
        NSApplication, NSApplicationActivationPolicy, NSModalPanelRunLoopMode, NSOpenPanel,
    };
    use objc2_foundation::NSArray;

    type DispatchFn = extern "C" fn(*mut c_void);

    #[repr(C)]
    struct DispatchQueueS {
        _private: [u8; 0],
    }

    unsafe extern "C" {
        static _dispatch_main_q: DispatchQueueS;
        fn dispatch_get_global_queue(identifier: isize, flags: usize) -> *mut c_void;
        fn dispatch_time(when: u64, delta: i64) -> u64;
        fn dispatch_after_f(when: u64, queue: *mut c_void, ctx: *mut c_void, work: DispatchFn);
        fn dispatch_async_f(queue: *mut c_void, ctx: *mut c_void, work: DispatchFn);
        fn CGSessionCopyCurrentDictionary() -> *const c_void;
        fn CFRelease(cf: *const c_void);
    }

    const DISPATCH_TIME_NOW: u64 = 0;

    fn main_queue() -> *mut c_void {
        // Taking the address of libdispatch's main queue object is what the
        // `dispatch_get_main_queue()` macro does; nothing is read.
        (&raw const _dispatch_main_q).cast_mut().cast()
    }

    fn after(ms: i64, queue: *mut c_void, work: DispatchFn) {
        // SAFETY: valid queue, NULL context (the callbacks use statics), and
        // an `extern "C"` function that lives for the whole program.
        unsafe {
            let when = dispatch_time(DISPATCH_TIME_NOW, ms * 1_000_000);
            dispatch_after_f(when, queue, std::ptr::null_mut(), work);
        }
    }

    /// 0 = not run, 1 = ran with no modal window, 2 = ran while modal.
    static GLOBAL_HOP: AtomicU8 = AtomicU8::new(0);
    static MAIN_HOP: AtomicU8 = AtomicU8::new(0);
    static MAIN_DIRECT: AtomicU8 = AtomicU8::new(0);
    static MAIN_ASYNC_BEFORE: AtomicU8 = AtomicU8::new(0);
    static WATCHDOG_FIRED: AtomicBool = AtomicBool::new(false);
    /// Milliseconds after `runModal` was entered at which a callback ran
    /// (negative: before).
    static MAIN_HOP_AT: AtomicI64 = AtomicI64::new(0);
    static MAIN_DIRECT_AT: AtomicI64 = AtomicI64::new(0);
    static MODAL_START: OnceLock<std::sync::Mutex<Option<Instant>>> = OnceLock::new();

    fn modal_start() -> &'static std::sync::Mutex<Option<Instant>> {
        MODAL_START.get_or_init(|| std::sync::Mutex::new(None))
    }

    fn ms_since_modal_start() -> i64 {
        match *modal_start().lock().unwrap() {
            Some(t) => t.elapsed().as_millis() as i64,
            None => -1,
        }
    }

    fn record(slot: &AtomicU8, abort: bool) {
        let mtm = MainThreadMarker::new().expect("main-queue callback runs on the main thread");
        let app = NSApplication::sharedApplication(mtm);
        let modal = app.modalWindow().is_some();
        slot.store(if modal { 2 } else { 1 }, Ordering::SeqCst);
        if modal && abort {
            app.abortModal();
        }
    }

    extern "C" fn on_global(_: *mut c_void) {
        GLOBAL_HOP.store(1, Ordering::SeqCst);
        // SAFETY: as in `after`; the main queue is always valid.
        unsafe { dispatch_async_f(main_queue(), std::ptr::null_mut(), on_main_hop) };
    }

    extern "C" fn on_main_hop(_: *mut c_void) {
        MAIN_HOP_AT.store(ms_since_modal_start(), Ordering::SeqCst);
        record(&MAIN_HOP, true);
    }

    extern "C" fn on_main_direct(_: *mut c_void) {
        MAIN_DIRECT_AT.store(ms_since_modal_start(), Ordering::SeqCst);
        record(&MAIN_DIRECT, true);
    }

    extern "C" fn on_main_async_before(_: *mut c_void) {
        record(&MAIN_ASYNC_BEFORE, false);
    }

    /// Case 3 result: (runModal response, time in runModal, watchdog fired).
    static CASE3: std::sync::Mutex<Option<(isize, Duration, bool)>> = std::sync::Mutex::new(None);

    /// Case 3 body: runs the panel from INSIDE a main-queue callback, the way
    /// gpui-pre's trampoline polls a foreground task that calls `runModal`.
    extern "C" fn case3_block(_: *mut c_void) {
        let mtm = MainThreadMarker::new().expect("main queue runs on the main thread");
        // SAFETY: valid identifier (DEFAULT = 0) and flags 0.
        let global = unsafe { dispatch_get_global_queue(0, 0) };
        let (r, t) = run_panel_with(mtm, Duration::from_secs(2), || {
            after(500, global, on_global);
            after(1000, main_queue(), on_main_direct);
        });
        let wd = WATCHDOG_FIRED.swap(false, Ordering::SeqCst);
        *CASE3.lock().unwrap() = Some((r, t, wd));
    }

    /// Case 4 state: (choose_file_async shown, nested call refused).
    static CASE4_STARTED: std::sync::Mutex<Option<(bool, bool)>> = std::sync::Mutex::new(None);
    /// Case 4: `done` ran, with `None`.
    static CASE4_DONE_NONE: AtomicU8 = AtomicU8::new(0);
    /// Case 4: the main-queue callback saw a visible open panel.
    static CASE4_PANEL_VISIBLE: AtomicBool = AtomicBool::new(false);

    /// Case 4 body: the fixed path, again from inside a main-queue callback.
    extern "C" fn case4_block(_: *mut c_void) {
        let shown = vault_macos::choose_file_async(&["png"], "Choose", |path| {
            CASE4_DONE_NONE.store(if path.is_none() { 2 } else { 1 }, Ordering::SeqCst);
        });
        let refused = !vault_macos::choose_file_async(&["png"], "Choose", |_| {
            panic!("a refused call never calls done")
        });
        *CASE4_STARTED.lock().unwrap() = Some((shown, refused));
        *modal_start().lock().unwrap() = Some(Instant::now());
        // Returns now; this main-queue callback must run while the panel is up.
        after(500, main_queue(), on_case4_tick);
    }

    extern "C" fn on_case4_tick(_: *mut c_void) {
        MAIN_DIRECT_AT.store(ms_since_modal_start(), Ordering::SeqCst);
        let mtm = MainThreadMarker::new().expect("main queue runs on the main thread");
        let windows = NSApplication::sharedApplication(mtm).windows();
        let visible = (0..windows.count()).any(|i| {
            let w = windows.objectAtIndex(i);
            w.isVisible() && w.isKindOfClass(NSOpenPanel::class())
        });
        CASE4_PANEL_VISIBLE.store(visible, Ordering::SeqCst);
        MAIN_DIRECT.store(if visible { 2 } else { 1 }, Ordering::SeqCst);
        vault_macos::cancel_open_panel();
    }

    /// Pumps the main run loop until `cond` holds or `limit` passes.
    fn pump_until(limit: Duration, cond: impl Fn() -> bool) -> bool {
        use objc2_foundation::{NSDate, NSRunLoop};
        let start = Instant::now();
        while !cond() {
            if start.elapsed() > limit {
                return false;
            }
            NSRunLoop::currentRunLoop().runUntilDate(&NSDate::dateWithTimeIntervalSinceNow(0.05));
        }
        true
    }

    fn reset() {
        for s in [&GLOBAL_HOP, &MAIN_HOP, &MAIN_DIRECT] {
            s.store(0, Ordering::SeqCst);
        }
        MAIN_HOP_AT.store(0, Ordering::SeqCst);
        MAIN_DIRECT_AT.store(0, Ordering::SeqCst);
    }

    fn label(v: u8) -> &'static str {
        match v {
            0 => "did not run",
            1 => "ran after the modal loop ended",
            _ => "ran DURING runModal",
        }
    }

    /// Opens a panel and runs it modally; a watchdog thread aborts it via a
    /// run-loop source (`performSelectorOnMainThread:` in the modal mode)
    /// after `watchdog`, so the binary never hangs.
    /// `schedule` is called right before `runModal` (after the panel is
    /// built, which takes up to a second the first time).
    fn run_panel_with(
        mtm: MainThreadMarker,
        watchdog: Duration,
        schedule: impl FnOnce(),
    ) -> (isize, Duration) {
        let panel = NSOpenPanel::openPanel(mtm);
        panel.setCanChooseFiles(true);
        panel.setCanChooseDirectories(false);
        let app = NSApplication::sharedApplication(mtm);
        // NSApplication is MainThreadOnly; the address is only used for a
        // thread-safe performSelectorOnMainThread call.
        let app_addr = Retained::as_ptr(&app) as usize;
        let done = std::sync::Arc::new(AtomicBool::new(false));
        let done2 = done.clone();
        let wd = std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < watchdog {
                if done2.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            WATCHDOG_FIRED.store(true, Ordering::SeqCst);
            let app = app_addr as *const AnyObject;
            // SAFETY: NSApp lives for the whole process; NSModalPanelRunLoopMode
            // is an immutable extern NSString; performSelectorOnMainThread is
            // documented thread-safe and `abortModal` takes no argument.
            unsafe {
                let modes = NSArray::from_slice(&[NSModalPanelRunLoopMode]);
                let s: Sel = sel!(abortModal);
                let _: () = msg_send![app, performSelectorOnMainThread: s, withObject: std::ptr::null::<AnyObject>(), waitUntilDone: false, modes: &*modes];
            }
        });
        schedule();
        let start = Instant::now();
        *modal_start().lock().unwrap() = Some(start);
        let r = panel.runModal();
        *modal_start().lock().unwrap() = None;
        let took = start.elapsed();
        done.store(true, Ordering::SeqCst);
        wd.join().expect("watchdog thread");
        (r, took)
    }

    /// Spins the main run loop briefly in the default mode so callbacks that
    /// were held during the modal loop get a chance to run (and be labelled
    /// "after").
    fn drain(mtm: MainThreadMarker) {
        let _ = mtm;
        use objc2_foundation::{NSDate, NSRunLoop};
        let rl = NSRunLoop::currentRunLoop();
        rl.runUntilDate(&NSDate::dateWithTimeIntervalSinceNow(0.5));
    }

    pub fn main() {
        if std::env::var_os("VAULT_SKIP_GUI_TESTS").is_some() {
            println!("test modal_queue ... ignored (VAULT_SKIP_GUI_TESTS)");
            return;
        }
        // SAFETY: plain CoreGraphics query; a non-NULL result is a +1 CF
        // object released right away.
        let session = unsafe { CGSessionCopyCurrentDictionary() };
        if session.is_null() {
            println!("test modal_queue ... ignored (no window server session)");
            return;
        }
        // SAFETY: `session` is a non-NULL +1 reference from a Copy function.
        unsafe { CFRelease(session) };

        // Last resort if a modal loop cannot be ended: fail instead of hanging.
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(60));
            eprintln!("test modal_queue ... FAILED (hung in a modal loop)");
            std::process::exit(1);
        });
        let mtm = MainThreadMarker::new().expect("harness = false runs on the main thread");
        let app = NSApplication::sharedApplication(mtm);
        app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);

        // Case 1: gpui's timer path. dispatch_after 0.5 s on a global queue,
        // whose callback dispatch_asyncs onto the main queue; that one
        // aborts the modal loop. A dispatch_async queued just before
        // runModal shows whether pending main-queue work is drained too.
        // SAFETY: valid identifier (DEFAULT = 0) and flags 0.
        let global = unsafe { dispatch_get_global_queue(0, 0) };
        let (r1, t1) = run_panel_with(mtm, Duration::from_secs(3), || {
            after(500, global, on_global);
            // SAFETY: as in `after`.
            unsafe { dispatch_async_f(main_queue(), std::ptr::null_mut(), on_main_async_before) };
        });
        let wd1 = WATCHDOG_FIRED.swap(false, Ordering::SeqCst);
        drain(mtm);
        println!(
            "case 1 (global dispatch_after 0.5 s -> main dispatch_async): runModal returned {r1} after {:.2}s (watchdog fired: {wd1})",
            t1.as_secs_f64()
        );
        println!(
            "  global-queue callback: {}",
            if GLOBAL_HOP.load(Ordering::SeqCst) != 0 {
                "ran"
            } else {
                "did not run"
            }
        );
        println!(
            "  main-queue hop: {} ({} ms into runModal)",
            label(MAIN_HOP.load(Ordering::SeqCst)),
            MAIN_HOP_AT.load(Ordering::SeqCst)
        );
        println!(
            "  main dispatch_async queued before runModal: {}",
            label(MAIN_ASYNC_BEFORE.load(Ordering::SeqCst))
        );

        // Case 2: dispatch_after 3 s straight onto the main queue.
        let (r2, t2) = run_panel_with(mtm, Duration::from_secs(3), || {
            after(800, main_queue(), on_main_direct)
        });
        let wd2 = WATCHDOG_FIRED.swap(false, Ordering::SeqCst);
        drain(mtm);
        println!(
            "case 2 (main dispatch_after 0.8 s): runModal returned {r2} after {:.2}s (watchdog fired: {wd2})",
            t2.as_secs_f64()
        );
        println!(
            "  main-queue callback: {} ({} ms into runModal)",
            label(MAIN_DIRECT.load(Ordering::SeqCst)),
            MAIN_DIRECT_AT.load(Ordering::SeqCst)
        );

        // Case 3: the same two callbacks, but runModal is entered from inside
        // a main-queue callback (gpui-pre polls foreground tasks, including
        // the one that called the chooser, from main-queue blocks).
        reset();
        // SAFETY: as in `after`.
        unsafe { dispatch_async_f(main_queue(), std::ptr::null_mut(), case3_block) };
        let start = Instant::now();
        while CASE3.lock().unwrap().is_none() && start.elapsed() < Duration::from_secs(30) {
            use objc2_foundation::{NSDate, NSRunLoop};
            NSRunLoop::currentRunLoop().runUntilDate(&NSDate::dateWithTimeIntervalSinceNow(0.05));
        }
        let (r3, t3, wd3) = CASE3.lock().unwrap().expect("case 3 ran");
        drain(mtm);
        println!(
            "case 3 (runModal inside a main-queue callback; global hop 0.5 s, main dispatch_after 1 s): runModal returned {r3} after {:.2}s (watchdog fired: {wd3})",
            t3.as_secs_f64()
        );
        println!(
            "  global-queue callback: {}",
            if GLOBAL_HOP.load(Ordering::SeqCst) != 0 {
                "ran"
            } else {
                "did not run"
            }
        );
        println!(
            "  main-queue hop: {} ({} ms into runModal)",
            label(MAIN_HOP.load(Ordering::SeqCst)),
            MAIN_HOP_AT.load(Ordering::SeqCst)
        );
        println!(
            "  main dispatch_after: {} ({} ms into runModal)",
            label(MAIN_DIRECT.load(Ordering::SeqCst)),
            MAIN_DIRECT_AT.load(Ordering::SeqCst)
        );

        // Cases 1-3 describe AppKit and libdispatch behaviour and are printed
        // as evidence only (recorded 2026-11-27, macOS 27: the main-queue
        // callbacks ran during runModal in cases 1-2 and were held until it
        // returned in case 3, which only the watchdog ended). Only the fix
        // below is asserted.

        // Case 4 (the fix): choose_file_async from inside a main-queue
        // callback returns at once; a main-queue dispatch_after then runs
        // while the panel is visible and cancels it through cancel_open_panel.
        reset();
        // SAFETY: as in `after`.
        unsafe { dispatch_async_f(main_queue(), std::ptr::null_mut(), case4_block) };
        let finished = pump_until(Duration::from_secs(10), || {
            CASE4_DONE_NONE.load(Ordering::SeqCst) != 0
        });
        let (shown, refused) = CASE4_STARTED.lock().unwrap().expect("case 4 ran");
        println!(
            "case 4 (choose_file_async inside a main-queue callback; main dispatch_after 0.5 s calls cancel_open_panel): shown {shown}, nested call refused {refused}, done called {finished}"
        );
        println!(
            "  main dispatch_after: ran {} ms after the panel opened, panel visible then: {}",
            MAIN_DIRECT_AT.load(Ordering::SeqCst),
            CASE4_PANEL_VISIBLE.load(Ordering::SeqCst)
        );
        assert!(shown && refused, "case 4: one panel at a time");
        assert!(finished, "case 4: cancel_open_panel ended the panel");
        assert_eq!(
            CASE4_DONE_NONE.load(Ordering::SeqCst),
            2,
            "case 4: cancel gives None"
        );
        assert!(
            CASE4_PANEL_VISIBLE.load(Ordering::SeqCst),
            "case 4: main-queue work ran while the panel was up"
        );
        // The slot is free again after done: a new panel opens, and
        // cancel_open_panel closes it.
        let again = std::rc::Rc::new(std::cell::Cell::new(false));
        let a = again.clone();
        assert!(vault_macos::choose_file_async(
            &["png"],
            "Choose",
            move |p| {
                assert!(p.is_none());
                a.set(true);
            }
        ));
        pump_until(Duration::from_millis(200), || false);
        vault_macos::cancel_open_panel();
        println!(
            "  second panel: done ran inside cancel_open_panel: {}",
            again.get()
        );
        assert!(
            pump_until(Duration::from_secs(5), || again.get()),
            "second panel closed"
        );
        println!("test modal_queue ... ok");
    }
}
