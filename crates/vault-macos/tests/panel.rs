//! Manual test for `choose_file_async` (spec 04 §3b). An open panel can only
//! run on the process main thread and needs a person to click, so this
//! binary uses `harness = false` and behaves like an `#[ignore]`d test: it
//! only opens the panel when run with `--ignored` (or `--include-ignored`):
//!
//! ```text
//! cargo test -p vault-macos --test panel -- --ignored
//! ```
//!
//! Check by hand: only PNG/JPEG files are selectable, folders and other
//! files are greyed out, one file at most, the button reads "Use Icon".
//! The automatic checks (non-blocking, one panel at a time, cancel) are in
//! `tests/modal_queue.rs`.

fn main() {
    let manual = std::env::args().any(|a| a == "--ignored" || a == "--include-ignored");
    if !manual {
        println!("test choose_file_manual ... ignored (run with -- --ignored)");
        return;
    }
    #[cfg(target_os = "macos")]
    {
        use std::cell::RefCell;
        use std::rc::Rc;

        use objc2_foundation::{NSDate, NSRunLoop};

        let mtm = objc2::MainThreadMarker::new().expect("main thread");
        let app = objc2_app_kit::NSApplication::sharedApplication(mtm);
        app.setActivationPolicy(objc2_app_kit::NSApplicationActivationPolicy::Accessory);
        app.activate();
        let result: Rc<RefCell<Option<Option<std::path::PathBuf>>>> = Rc::default();
        let r = result.clone();
        let shown = vault_macos::choose_file_async(&["png", "JPG", "jpeg"], "Use Icon", move |p| {
            *r.borrow_mut() = Some(p);
        });
        assert!(shown, "panel shown");
        while result.borrow().is_none() {
            NSRunLoop::currentRunLoop().runUntilDate(&NSDate::dateWithTimeIntervalSinceNow(0.1));
        }
        println!(
            "test choose_file_manual ... chose {:?}",
            result.borrow().clone().unwrap()
        );
    }
}
