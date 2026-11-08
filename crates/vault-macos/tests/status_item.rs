//! Menu bar status item (spec 04 §5c). `harness = false` because AppKit
//! only allows NSStatusItem buttons and NSMenu on the process main thread.
//! Installs a real item in the menu bar for a moment; no run loop is pumped,
//! so nothing is drawn interactively and no menu is shown.

use std::cell::RefCell;
use std::rc::Rc;

use vault_macos::{MacError, StatusItem, StatusItemCallbacks};

fn recorder() -> (Rc<RefCell<Vec<&'static str>>>, StatusItemCallbacks) {
    let log = Rc::new(RefCell::new(Vec::new()));
    let (a, b, c) = (log.clone(), log.clone(), log.clone());
    let cb = StatusItemCallbacks {
        open: Box::new(move || a.borrow_mut().push("open")),
        lock_or_unlock: Box::new(move || b.borrow_mut().push("lock_or_unlock")),
        quit: Box::new(move || c.borrow_mut().push("quit")),
    };
    (log, cb)
}

#[cfg(not(target_os = "macos"))]
fn main() {
    let (_log, cb) = recorder();
    assert!(matches!(
        StatusItem::install(true, cb),
        Err(MacError::NotAvailable)
    ));
    println!("status_item: ok (stub)");
}

#[cfg(target_os = "macos")]
fn main() {
    use objc2::MainThreadMarker;
    use objc2_app_kit::NSApplication;

    let mtm = MainThreadMarker::new().expect("harness = false runs on the main thread");
    let _app = NSApplication::sharedApplication(mtm);

    // Off the main thread: refused.
    let off = std::thread::spawn(|| {
        let (_log, cb) = recorder();
        matches!(StatusItem::install(false, cb), Err(MacError::NotAvailable))
    })
    .join()
    .unwrap();
    assert!(off, "install off the main thread must be NotAvailable");

    let (log, cb) = recorder();
    let item = StatusItem::install(true, cb).expect("install on the main thread");
    assert_eq!(
        item.test_menu_titles(),
        ["Open Vault", "Unlock\u{2026}", "-", "Quit Vault"]
    );
    assert_eq!(
        item.test_glyph(),
        Some(("Vault, locked".to_owned(), true)),
        "template padlock with the locked description"
    );

    item.set_locked(false);
    assert_eq!(
        item.test_menu_titles(),
        ["Open Vault", "Lock", "-", "Quit Vault"]
    );
    assert_eq!(
        item.test_glyph(),
        Some(("Vault, unlocked".to_owned(), true))
    );
    item.set_locked(true);
    assert_eq!(item.test_menu_titles()[1], "Unlock\u{2026}");

    // No current event: a button press takes the left-click path.
    item.test_click();
    item.test_menu_action(0);
    item.test_menu_action(1);
    item.test_menu_action(3);
    assert_eq!(*log.borrow(), ["open", "open", "lock_or_unlock", "quit"]);

    // A callback may call back into the item (vault-app's lock_or_unlock
    // will call set_locked) without a RefCell double borrow.
    let shared: Rc<RefCell<Option<StatusItem>>> = Rc::new(RefCell::new(None));
    let s = shared.clone();
    let reentrant = StatusItemCallbacks {
        open: Box::new(|| {}),
        lock_or_unlock: Box::new(move || {
            if let Some(it) = s.borrow().as_ref() {
                it.set_locked(false);
            }
        }),
        quit: Box::new(|| {}),
    };
    *shared.borrow_mut() = Some(StatusItem::install(true, reentrant).unwrap());
    shared.borrow().as_ref().unwrap().test_menu_action(1);
    assert_eq!(
        shared.borrow().as_ref().unwrap().test_menu_titles()[1],
        "Lock"
    );
    drop(shared.borrow_mut().take());

    // A callback may drop the item it was called from; the click finishes
    // and the item is gone afterwards.
    let holder: Rc<RefCell<Option<StatusItem>>> = Rc::new(RefCell::new(None));
    let dropped = Rc::new(std::cell::Cell::new(false));
    let (h, d) = (holder.clone(), dropped.clone());
    let self_dropping = StatusItemCallbacks {
        open: Box::new(|| {}),
        lock_or_unlock: Box::new(|| {}),
        quit: Box::new(move || {
            let it = h.borrow_mut().take();
            d.set(it.is_some());
            drop(it);
        }),
    };
    let it = StatusItem::install(false, self_dropping).unwrap();
    // Trigger through the menu alone, so no borrow of the item is held while
    // `quit` drops it (as when AppKit calls the target).
    let trigger = it.test_menu_trigger();
    *holder.borrow_mut() = Some(it);
    trigger(3);
    // The item is gone and its callbacks freed: further actions do nothing.
    trigger(3);
    trigger(0);
    assert!(dropped.get(), "quit dropped the item");
    assert!(holder.borrow().is_none());

    // A panicking callback does not propagate; later clicks still work.
    let (plog, mut pcb) = recorder();
    pcb.lock_or_unlock = Box::new(|| panic!("test panic in lock_or_unlock"));
    let pitem = StatusItem::install(false, pcb).unwrap();
    pitem.test_menu_action(1);
    pitem.test_menu_action(1);
    pitem.test_click();
    pitem.test_menu_action(3);
    assert_eq!(*plog.borrow(), ["open", "quit"]);
    // Out-of-range indices are ignored rather than raising NSRangeException.
    pitem.test_menu_action(-1);
    pitem.test_menu_action(4);
    pitem.test_menu_action(isize::MAX);
    assert_eq!(*plog.borrow(), ["open", "quit"]);
    drop(pitem);

    // Drop frees the callbacks (the recorder's Rc count falls back to 1).
    drop(item);
    assert_eq!(Rc::strong_count(&log), 1, "callbacks freed on drop");

    // The drawn fallback glyph is a square template image.
    assert_eq!(
        vault_macos::test_fallback_glyph_size(true),
        Some((18.0, 18.0))
    );
    assert_eq!(
        vault_macos::test_fallback_glyph_size(false),
        Some((18.0, 18.0))
    );

    println!("status_item: ok");
}
