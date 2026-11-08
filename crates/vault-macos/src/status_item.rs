//! Menu bar status item (spec 04 §5c): a template padlock in the system
//! status bar, shown while the Dock icon is hidden (§5b).
//!
//! Left click runs `open`. Right click or Control-click pops a native menu:
//! "Open Vault", "Lock" / "Unlock…", a separator, "Quit Vault". The menu is
//! attached to the status item only for the duration of that click, so the
//! left click keeps its action.
//!
//! Main thread only; callbacks run on the main thread. [`StatusItem`] is
//! `!Send`, so it is also dropped on the main thread.

use crate::MacError;

/// Actions the status item and its menu trigger. All run on the main thread.
pub struct StatusItemCallbacks {
    /// Left click and "Open Vault".
    pub open: Box<dyn Fn()>,
    /// "Lock" (while unlocked) and "Unlock…" (while locked).
    pub lock_or_unlock: Box<dyn Fn()>,
    /// "Quit Vault".
    pub quit: Box<dyn Fn()>,
}

/// An item in `NSStatusBar.systemStatusBar`, square length. Removed from the
/// status bar on drop; after drop no click reaches the callbacks.
pub struct StatusItem {
    inner: imp::Inner,
}

/// Point height of the padlock glyph.
const GLYPH_HEIGHT: f64 = 18.0;

const DESC_LOCKED: &str = "Vault, locked";
const DESC_UNLOCKED: &str = "Vault, unlocked";
const TITLE_OPEN: &str = "Open Vault";
const TITLE_LOCK: &str = "Lock";
const TITLE_UNLOCK: &str = "Unlock\u{2026}";
const TITLE_QUIT: &str = "Quit Vault";

fn accessibility_description(locked: bool) -> &'static str {
    if locked { DESC_LOCKED } else { DESC_UNLOCKED }
}

fn lock_title(locked: bool) -> &'static str {
    if locked { TITLE_UNLOCK } else { TITLE_LOCK }
}

impl StatusItem {
    /// Adds the item to the system status bar.
    ///
    /// Returns `Err(MacError::NotAvailable)` off the main thread or on
    /// non-macOS hosts; `Err(MacError::Other)` if AppKit gives the item no
    /// button.
    ///
    /// Each call adds another, independent item to the menu bar; keep a
    /// single `Option<StatusItem>` and drop the old one before reinstalling.
    pub fn install(locked: bool, cb: StatusItemCallbacks) -> Result<StatusItem, MacError> {
        imp::Inner::install(locked, cb).map(|inner| StatusItem { inner })
    }

    /// Swaps the glyph (closed / open padlock), its accessibility description
    /// and the "Lock" / "Unlock…" menu title.
    pub fn set_locked(&self, locked: bool) {
        self.inner.set_locked(locked);
    }

    /// Test support: the menu item titles in order (separator as `"-"`).
    #[doc(hidden)]
    pub fn test_menu_titles(&self) -> Vec<String> {
        self.inner.menu_titles()
    }

    /// Test support: the button image's accessibility description and
    /// whether it is a template image.
    #[doc(hidden)]
    pub fn test_glyph(&self) -> Option<(String, bool)> {
        self.inner.glyph()
    }

    /// Test support: `-[NSStatusBarButton performClick:]` with no current
    /// event, which takes the left-click path.
    #[doc(hidden)]
    pub fn test_click(&self) {
        self.inner.click();
    }

    /// Test support: `-[NSMenu performActionForItemAtIndex:]`; an index out
    /// of range is ignored.
    #[doc(hidden)]
    pub fn test_menu_action(&self, index: isize) {
        self.inner.menu_action(index);
    }

    /// Test support: like [`Self::test_menu_action`] but holding only the
    /// menu, so a callback may drop this `StatusItem` during the call.
    #[doc(hidden)]
    pub fn test_menu_trigger(&self) -> Box<dyn Fn(isize)> {
        self.inner.menu_trigger()
    }
}

/// Test support: size of the hand-drawn padlock used when the SF Symbol is
/// missing. `None` off the main thread or off macOS.
#[doc(hidden)]
pub fn test_fallback_glyph_size(locked: bool) -> Option<(f64, f64)> {
    imp::fallback_glyph_size(locked)
}

#[cfg(target_os = "macos")]
mod imp {
    use std::any::Any;
    use std::cell::{Cell, RefCell};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::rc::Rc;

    use objc2::rc::Retained;
    use objc2::runtime::{AnyObject, NSObject, Sel};
    use objc2::{
        AnyThread, DefinedClass, MainThreadMarker, MainThreadOnly, Message, define_class, msg_send,
        sel,
    };
    use objc2_app_kit::{
        NSApplication, NSBezierPath, NSColor, NSEventMask, NSEventModifierFlags, NSEventType,
        NSImage, NSMenu, NSMenuItem, NSSquareStatusItemLength, NSStatusBar, NSStatusBarButton,
        NSStatusItem,
    };
    use objc2_core_foundation::{CGPoint, CGRect, CGSize};
    use objc2_foundation::NSString;

    use super::{
        GLYPH_HEIGHT, StatusItemCallbacks, TITLE_OPEN, TITLE_QUIT, accessibility_description,
        lock_title,
    };
    use crate::MacError;

    /// Everything the target needs while installed. Taken out on drop, which
    /// frees the callbacks.
    struct Live {
        callbacks: Rc<StatusItemCallbacks>,
        item: Retained<NSStatusItem>,
        menu: Retained<NSMenu>,
    }

    struct TargetIvars {
        live: RefCell<Option<Live>>,
        /// True while `pop_menu` is tracking the menu; a nested pop is
        /// ignored.
        popping: Cell<bool>,
    }

    define_class!(
        // SAFETY: NSObject has no subclassing requirements and `Target` does
        // not implement `Drop`. Main-thread-only: it is AppKit's action
        // target and its ivars are `!Send`.
        #[unsafe(super(NSObject))]
        #[thread_kind = MainThreadOnly]
        #[ivars = TargetIvars]
        struct Target;

        impl Target {
            // SAFETY: NSControl / NSMenuItem action signature
            // `- (void)action:(id)sender`.
            #[unsafe(method(buttonClicked:))]
            fn button_clicked(&self, _sender: Option<&AnyObject>) {
                if is_menu_click(self.mtm()) {
                    self.pop_menu();
                } else {
                    self.run(|cb| &cb.open);
                }
            }

            // SAFETY: as above.
            #[unsafe(method(openClicked:))]
            fn open_clicked(&self, _sender: Option<&AnyObject>) {
                self.run(|cb| &cb.open);
            }

            // SAFETY: as above.
            #[unsafe(method(lockClicked:))]
            fn lock_clicked(&self, _sender: Option<&AnyObject>) {
                self.run(|cb| &cb.lock_or_unlock);
            }

            // SAFETY: as above.
            #[unsafe(method(quitClicked:))]
            fn quit_clicked(&self, _sender: Option<&AnyObject>) {
                self.run(|cb| &cb.quit);
            }
        }
    );

    impl Target {
        fn new(mtm: MainThreadMarker) -> Retained<Self> {
            let this = Self::alloc(mtm).set_ivars(TargetIvars {
                live: RefCell::new(None),
                popping: Cell::new(false),
            });
            // SAFETY: `init` is NSObject's designated initializer and the
            // ivars were set above.
            unsafe { msg_send![super(this), init] }
        }

        /// Runs one callback with no `RefCell` borrow held, so the callback
        /// may call `set_locked` or drop the `StatusItem`.
        fn run(&self, pick: impl Fn(&StatusItemCallbacks) -> &Box<dyn Fn()>) {
            let _keep = self.retain();
            let Some(callbacks) = self
                .ivars()
                .live
                .borrow()
                .as_ref()
                .map(|l| Rc::clone(&l.callbacks))
            else {
                return;
            };
            // Unwinding into Objective-C frames is not allowed. Report the
            // payload (vault-macos has no logger) and keep the item working.
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| (pick(&callbacks))())) {
                eprintln!(
                    "vault-macos: status item callback panicked: {}",
                    panic_message(payload.as_ref())
                );
            }
        }

        /// Attaches the menu, lets the button pop it, then detaches it.
        fn pop_menu(&self) {
            let _keep = self.retain();
            let popping = &self.ivars().popping;
            if popping.replace(true) {
                return;
            }
            self.pop_menu_once();
            popping.set(false);
        }

        fn pop_menu_once(&self) {
            let Some((item, menu)) = self
                .ivars()
                .live
                .borrow()
                .as_ref()
                .map(|l| (l.item.clone(), l.menu.clone()))
            else {
                return;
            };
            let Some(button) = item.button(self.mtm()) else {
                return;
            };
            item.setMenu(Some(&menu));
            // With a menu set the status bar button tracks the menu instead
            // of sending its action (observed, not documented); `popping`
            // makes a nested pop a no-op either way.
            // SAFETY: `performClick:` accepts a nil sender.
            unsafe { button.performClick(None) };
            item.setMenu(None);
        }
    }

    /// The `&str` / `String` payload of a panic, or a placeholder.
    fn panic_message(payload: &(dyn Any + Send)) -> &str {
        if let Some(s) = payload.downcast_ref::<&str>() {
            s
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s
        } else {
            "<non-string payload>"
        }
    }

    /// Right mouse up, or left mouse up with Control held.
    fn is_menu_click(mtm: MainThreadMarker) -> bool {
        let Some(event) = NSApplication::sharedApplication(mtm).currentEvent() else {
            return false;
        };
        match event.r#type() {
            NSEventType::RightMouseUp | NSEventType::RightMouseDown => true,
            NSEventType::LeftMouseUp | NSEventType::LeftMouseDown => event
                .modifierFlags()
                .contains(NSEventModifierFlags::Control),
            _ => false,
        }
    }

    pub struct Inner {
        mtm: MainThreadMarker,
        target: Retained<Target>,
        item: Retained<NSStatusItem>,
        button: Retained<NSStatusBarButton>,
        menu: Retained<NSMenu>,
        lock_item: Retained<NSMenuItem>,
    }

    fn menu_item(
        mtm: MainThreadMarker,
        title: &str,
        action: Sel,
        target: &Target,
    ) -> Retained<NSMenuItem> {
        // SAFETY: `action` is one of the selectors defined on `Target`, which
        // is the item's target.
        let item = unsafe {
            NSMenuItem::initWithTitle_action_keyEquivalent(
                NSMenuItem::alloc(mtm),
                &NSString::from_str(title),
                Some(action),
                &NSString::new(),
            )
        };
        // SAFETY: `target` implements `action`. NSMenuItem holds its target
        // weakly; `Inner::drop` clears it before `target` is released.
        unsafe { item.setTarget(Some(target)) };
        item
    }

    impl Inner {
        pub fn install(locked: bool, cb: StatusItemCallbacks) -> Result<Self, MacError> {
            let mtm = MainThreadMarker::new().ok_or(MacError::NotAvailable)?;
            let item =
                NSStatusBar::systemStatusBar().statusItemWithLength(NSSquareStatusItemLength);
            let Some(button) = item.button(mtm) else {
                NSStatusBar::systemStatusBar().removeStatusItem(&item);
                return Err(MacError::Other("status item has no button".into()));
            };
            let target = Target::new(mtm);

            let menu = NSMenu::new(mtm);
            menu.addItem(&menu_item(mtm, TITLE_OPEN, sel!(openClicked:), &target));
            let lock_item = menu_item(mtm, lock_title(locked), sel!(lockClicked:), &target);
            menu.addItem(&lock_item);
            menu.addItem(&NSMenuItem::separatorItem(mtm));
            menu.addItem(&menu_item(mtm, TITLE_QUIT, sel!(quitClicked:), &target));

            // SAFETY: `Target` implements `buttonClicked:`. NSControl holds
            // its target weakly; `Inner::drop` clears it first.
            unsafe {
                button.setTarget(Some(&target));
                button.setAction(Some(sel!(buttonClicked:)));
            }
            button.sendActionOn(NSEventMask::LeftMouseUp | NSEventMask::RightMouseUp);

            *target.ivars().live.borrow_mut() = Some(Live {
                callbacks: Rc::new(cb),
                item: item.clone(),
                menu: menu.clone(),
            });

            let inner = Inner {
                mtm,
                target,
                item,
                button,
                menu,
                lock_item,
            };
            inner.set_locked(locked);
            Ok(inner)
        }

        pub fn set_locked(&self, locked: bool) {
            let desc = NSString::from_str(accessibility_description(locked));
            self.button
                .setImage(Some(&padlock(self.mtm, locked, &desc)));
            self.lock_item
                .setTitle(&NSString::from_str(lock_title(locked)));
        }

        pub fn menu_titles(&self) -> Vec<String> {
            (0..self.menu.numberOfItems())
                .filter_map(|i| self.menu.itemAtIndex(i))
                .map(|it| {
                    if it.isSeparatorItem() {
                        "-".to_owned()
                    } else {
                        it.title().to_string()
                    }
                })
                .collect()
        }

        pub fn glyph(&self) -> Option<(String, bool)> {
            let image = self.button.image()?;
            let desc = image.accessibilityDescription()?.to_string();
            Some((desc, image.isTemplate()))
        }

        pub fn click(&self) {
            // SAFETY: `performClick:` accepts a nil sender.
            unsafe { self.button.performClick(None) };
        }

        pub fn menu_action(&self, index: isize) {
            perform_menu_action(&self.menu, index);
        }

        pub fn menu_trigger(&self) -> Box<dyn Fn(isize)> {
            let menu = self.menu.clone();
            Box::new(move |index| perform_menu_action(&menu, index))
        }
    }

    fn perform_menu_action(menu: &NSMenu, index: isize) {
        // Out of range raises NSRangeException, which must not unwind
        // through Rust.
        if index < 0 || index >= menu.numberOfItems() {
            return;
        }
        menu.performActionForItemAtIndex(index);
    }

    impl Drop for Inner {
        fn drop(&mut self) {
            // Free the callbacks; a click already in flight holds its own Rc
            // and finishes, later ones find `None`.
            let live = self.target.ivars().live.borrow_mut().take();
            // SAFETY: clearing target and action to nil is always valid.
            unsafe {
                self.button.setTarget(None);
                self.button.setAction(None);
            }
            for i in 0..self.menu.numberOfItems() {
                if let Some(it) = self.menu.itemAtIndex(i) {
                    // SAFETY: a nil target is always valid.
                    unsafe { it.setTarget(None) };
                }
            }
            self.item.setMenu(None);
            NSStatusBar::systemStatusBar().removeStatusItem(&self.item);
            drop(live);
        }
    }

    /// SF Symbol padlock scaled to [`GLYPH_HEIGHT`], or the drawn fallback.
    fn padlock(mtm: MainThreadMarker, locked: bool, desc: &NSString) -> Retained<NSImage> {
        let name = NSString::from_str(if locked {
            "lock.fill"
        } else {
            "lock.open.fill"
        });
        let image =
            match NSImage::imageWithSystemSymbolName_accessibilityDescription(&name, Some(desc)) {
                Some(image) => {
                    let size = image.size();
                    if size.height > 0.0 {
                        let scale = GLYPH_HEIGHT / size.height;
                        image.setSize(CGSize::new(size.width * scale, GLYPH_HEIGHT));
                    }
                    image
                }
                None => {
                    let image = drawn_padlock(mtm, locked);
                    image.setAccessibilityDescription(Some(desc));
                    image
                }
            };
        image.setTemplate(true);
        image
    }

    /// A simple padlock in black on clear (template), 18 x 18 pt: a rounded
    /// body and a stroked shackle, the open one raised on its right leg.
    fn drawn_padlock(_mtm: MainThreadMarker, locked: bool) -> Retained<NSImage> {
        let s = GLYPH_HEIGHT;
        let image = NSImage::initWithSize(NSImage::alloc(), CGSize::new(s, s));
        #[allow(deprecated)]
        image.lockFocus();
        NSColor::blackColor().set();
        let body = NSBezierPath::bezierPathWithRoundedRect_xRadius_yRadius(
            CGRect::new(CGPoint::new(3.0, 1.0), CGSize::new(12.0, 8.5)),
            2.0,
            2.0,
        );
        body.fill();
        let shackle = NSBezierPath::bezierPath();
        shackle.setLineWidth(2.0);
        let (left, right, r) = (5.5, 12.5, 3.5);
        if locked {
            shackle.moveToPoint(CGPoint::new(left, 9.0));
            shackle.lineToPoint(CGPoint::new(left, 12.5));
            shackle.appendBezierPathWithArcWithCenter_radius_startAngle_endAngle_clockwise(
                CGPoint::new(9.0, 12.5),
                r,
                180.0,
                0.0,
                true,
            );
            shackle.lineToPoint(CGPoint::new(right, 9.0));
        } else {
            shackle.moveToPoint(CGPoint::new(right, 9.0));
            shackle.lineToPoint(CGPoint::new(right, 13.0));
            shackle.appendBezierPathWithArcWithCenter_radius_startAngle_endAngle_clockwise(
                CGPoint::new(9.0, 13.0),
                r,
                0.0,
                180.0,
                false,
            );
            shackle.lineToPoint(CGPoint::new(left, 11.5));
        }
        shackle.stroke();
        #[allow(deprecated)]
        image.unlockFocus();
        image.setTemplate(true);
        image
    }

    pub fn fallback_glyph_size(locked: bool) -> Option<(f64, f64)> {
        let mtm = MainThreadMarker::new()?;
        let image = drawn_padlock(mtm, locked);
        image.isTemplate().then(|| {
            let s = image.size();
            (s.width, s.height)
        })
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use std::marker::PhantomData;

    use super::StatusItemCallbacks;
    use crate::MacError;

    /// `!Send` like the macOS item.
    pub struct Inner(PhantomData<*const ()>);

    impl Inner {
        pub fn install(_locked: bool, _cb: StatusItemCallbacks) -> Result<Self, MacError> {
            Err(MacError::NotAvailable)
        }
        pub fn set_locked(&self, _locked: bool) {}
        pub fn menu_titles(&self) -> Vec<String> {
            Vec::new()
        }
        pub fn glyph(&self) -> Option<(String, bool)> {
            None
        }
        pub fn click(&self) {}
        pub fn menu_action(&self, _index: isize) {}
        pub fn menu_trigger(&self) -> Box<dyn Fn(isize)> {
            Box::new(|_| {})
        }
    }

    pub fn fallback_glyph_size(_locked: bool) -> Option<(f64, f64)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    fn callbacks(hits: &Rc<Cell<u32>>) -> StatusItemCallbacks {
        let (a, b, c) = (hits.clone(), hits.clone(), hits.clone());
        StatusItemCallbacks {
            open: Box::new(move || a.set(a.get() + 1)),
            lock_or_unlock: Box::new(move || b.set(b.get() + 1)),
            quit: Box::new(move || c.set(c.get() + 1)),
        }
    }

    // libtest runs tests on worker threads, so on macOS this exercises the
    // off-main-thread guard and elsewhere the stub: both refuse.
    #[test]
    fn install_off_main_thread_is_not_available() {
        let hits = Rc::new(Cell::new(0));
        let r = StatusItem::install(true, callbacks(&hits));
        assert!(matches!(r, Err(MacError::NotAvailable)));
        assert_eq!(hits.get(), 0, "no callback ran");
        assert_eq!(test_fallback_glyph_size(true), None);
    }

    #[test]
    fn api_shape() {
        let _: fn(bool, StatusItemCallbacks) -> Result<StatusItem, MacError> = StatusItem::install;
        let _: fn(&StatusItem, bool) = StatusItem::set_locked;
    }

    #[test]
    fn titles_and_descriptions() {
        assert_eq!(lock_title(true), "Unlock\u{2026}");
        assert_eq!(lock_title(false), "Lock");
        assert_eq!(accessibility_description(true), "Vault, locked");
        assert_eq!(accessibility_description(false), "Vault, unlocked");
    }
}
