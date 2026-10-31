//! Manual test for `choose_file` (spec 04 §3b). An open panel can only run
//! on the process main thread and needs a person to click, so this binary
//! uses `harness = false` and behaves like an `#[ignore]`d test: it only
//! opens the panel when run with `--ignored` (or `--include-ignored`):
//!
//! ```text
//! cargo test -p vault-macos --test panel -- --ignored
//! ```
//!
//! Check by hand: only PNG/JPEG files are selectable, folders and other
//! files are greyed out, one file at most, the button reads "Use Icon".

fn main() {
    let manual = std::env::args().any(|a| a == "--ignored" || a == "--include-ignored");
    if !manual {
        println!("test choose_file_manual ... ignored (run with -- --ignored)");
        return;
    }
    #[cfg(target_os = "macos")]
    {
        let mtm = objc2::MainThreadMarker::new().expect("main thread");
        let _app = objc2_app_kit::NSApplication::sharedApplication(mtm);
    }
    let chosen = vault_macos::choose_file(&["png", "JPG", "jpeg"], "Use Icon");
    println!("test choose_file_manual ... chose {chosen:?}");
}
