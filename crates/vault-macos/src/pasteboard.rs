//! Pasteboard with concealed writes and change-count-guarded clearing (spec 04 §3).

use secrecy::{ExposeSecret, SecretString};

/// `NSPasteboard.changeCount` right after one of our writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeCount(pub i64);

/// `public.utf8-plain-text` (`NSPasteboardTypeString`).
pub const PLAIN_TEXT_TYPE: &str = "public.utf8-plain-text";
/// Marker type that clipboard managers honour to skip an entry (nspasteboard.org).
pub const CONCEALED_TYPE: &str = "org.nspasteboard.ConcealedType";

/// The general pasteboard.
pub struct Clipboard;

impl Clipboard {
    /// Writes `text` as `public.utf8-plain-text` and marks the entry with
    /// `org.nspasteboard.ConcealedType` (empty value) so clipboard managers
    /// skip it. Returns the pasteboard's change count after the write, or
    /// `None` if AppKit refused to store a value (`setString:forType:` false).
    pub fn write_concealed(text: &SecretString) -> Option<ChangeCount> {
        imp::write_concealed(text.expose_secret()).map(ChangeCount)
    }

    /// Clears the pasteboard only if its change count is still `cc`, i.e.
    /// nobody has copied anything since our write.
    pub fn clear_if_unchanged(cc: ChangeCount) {
        imp::clear_if_unchanged(cc.0);
    }

    /// The pasteboard's current change count.
    pub fn change_count() -> ChangeCount {
        ChangeCount(imp::change_count())
    }

    /// Plain-text contents of the pasteboard. Test helper only.
    #[doc(hidden)]
    pub fn read_string() -> Option<String> {
        imp::read_string()
    }

    /// True if the pasteboard currently declares the concealed type. Test helper only.
    #[doc(hidden)]
    pub fn has_concealed_type() -> bool {
        imp::has_type(CONCEALED_TYPE)
    }

    /// Writes `text` as plain text without the concealed marker, as another
    /// app would. Test helper only.
    #[doc(hidden)]
    pub fn write_plain(text: &str) -> Option<ChangeCount> {
        imp::write_plain(text).map(ChangeCount)
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use objc2::rc::Retained;
    use objc2_app_kit::{NSPasteboard, NSPasteboardType};
    use objc2_foundation::{NSArray, NSString};

    use super::{CONCEALED_TYPE, PLAIN_TEXT_TYPE};

    fn general() -> Retained<NSPasteboard> {
        NSPasteboard::generalPasteboard()
    }

    fn pb_type(s: &str) -> Retained<NSPasteboardType> {
        NSString::from_str(s)
    }

    fn declare_and_set(pb: &NSPasteboard, values: &[(&str, &str)]) -> Option<i64> {
        let types: Vec<Retained<NSString>> = values.iter().map(|(t, _)| pb_type(t)).collect();
        let types = NSArray::from_retained_slice(&types);
        // SAFETY: `declareTypes:owner:` with a nil owner is always valid; the
        // array holds NSStrings, which is what NSPasteboardType is.
        unsafe { pb.declareTypes_owner(&types, None) };
        let mut ok = true;
        for (t, v) in values {
            // The NSString copy of the secret is not zeroized; AppKit owns it
            // from here and the pasteboard server holds its own copy anyway.
            ok &= pb.setString_forType(&NSString::from_str(v), &pb_type(t));
        }
        ok.then(|| pb.changeCount() as i64)
    }

    pub fn write_concealed(text: &str) -> Option<i64> {
        declare_and_set(&general(), &[(PLAIN_TEXT_TYPE, text), (CONCEALED_TYPE, "")])
    }

    pub fn write_plain(text: &str) -> Option<i64> {
        declare_and_set(&general(), &[(PLAIN_TEXT_TYPE, text)])
    }

    pub fn clear_if_unchanged(cc: i64) {
        let pb = general();
        if pb.changeCount() as i64 == cc {
            pb.clearContents();
        }
    }

    pub fn change_count() -> i64 {
        general().changeCount() as i64
    }

    pub fn read_string() -> Option<String> {
        general()
            .stringForType(&pb_type(PLAIN_TEXT_TYPE))
            .map(|s| s.to_string())
    }

    pub fn has_type(t: &str) -> bool {
        let want = pb_type(t);
        general()
            .types()
            .is_some_and(|types| types.containsObject(&want))
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    //! In-memory fake pasteboard for non-macOS hosts.
    use std::sync::Mutex;

    use super::{CONCEALED_TYPE, PLAIN_TEXT_TYPE};
    use secrecy::zeroize::Zeroizing;

    struct Fake {
        change_count: i64,
        text: Option<Zeroizing<String>>,
        types: Vec<&'static str>,
    }

    static FAKE: Mutex<Fake> = Mutex::new(Fake {
        change_count: 0,
        text: None,
        types: Vec::new(),
    });

    fn with<R>(f: impl FnOnce(&mut Fake) -> R) -> R {
        let mut g = FAKE.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut g)
    }

    fn set(text: &str, types: Vec<&'static str>) -> i64 {
        with(|p| {
            p.change_count += 1;
            p.text = Some(Zeroizing::new(text.to_owned()));
            p.types = types;
            p.change_count
        })
    }

    pub fn write_concealed(text: &str) -> Option<i64> {
        Some(set(text, vec![PLAIN_TEXT_TYPE, CONCEALED_TYPE]))
    }

    pub fn write_plain(text: &str) -> Option<i64> {
        Some(set(text, vec![PLAIN_TEXT_TYPE]))
    }

    pub fn clear_if_unchanged(cc: i64) {
        with(|p| {
            if p.change_count == cc {
                p.change_count += 1;
                p.text = None;
                p.types.clear();
            }
        });
    }

    pub fn change_count() -> i64 {
        with(|p| p.change_count)
    }

    pub fn read_string() -> Option<String> {
        with(|p| p.text.as_ref().map(|s| s.to_string()))
    }

    pub fn has_type(t: &str) -> bool {
        with(|p| p.types.iter().any(|x| *x == t))
    }
}
