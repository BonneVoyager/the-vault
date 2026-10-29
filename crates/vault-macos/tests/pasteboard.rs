//! Clipboard round-trip (spec 04 §8). Uses the real general pasteboard on
//! macOS; restores its previous plain-text contents afterwards (best effort).

use std::sync::Mutex;

use secrecy::SecretString;
use vault_macos::{CONCEALED_TYPE, Clipboard, PLAIN_TEXT_TYPE};

/// Serializes tests that touch the shared pasteboard.
static PASTEBOARD: Mutex<()> = Mutex::new(());

/// Restores the plain-text contents (and the concealed marker, if it was
/// set) that were on the pasteboard at creation. Empty before: clears.
struct Restore {
    text: Option<String>,
    concealed: bool,
}

impl Restore {
    fn save() -> Self {
        Restore {
            text: Clipboard::read_string(),
            concealed: Clipboard::has_concealed_type(),
        }
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        match self.text.take() {
            None => Clipboard::clear_if_unchanged(Clipboard::change_count()),
            Some(s) if self.concealed => {
                let _ = Clipboard::write_concealed(&SecretString::new(s));
            }
            Some(s) => {
                let _ = Clipboard::write_plain(&s);
            }
        }
    }
}

#[test]
fn write_read_clear_round_trip() {
    let _g = PASTEBOARD.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = Restore::save();

    let secret = SecretString::new("vault-test-secret-\u{1F511}".to_owned());
    let cc = Clipboard::write_concealed(&secret).expect("write accepted");
    assert_eq!(Clipboard::change_count(), cc);
    assert_eq!(
        Clipboard::read_string().as_deref(),
        Some("vault-test-secret-\u{1F511}")
    );
    assert!(Clipboard::has_concealed_type());

    // Both types present, marker declared before the text (it is written
    // first, so no observer can see the text without it).
    let types = Clipboard::types();
    let pos = |t: &str| types.iter().position(|x| x == t);
    let (marker, plain) = (pos(CONCEALED_TYPE), pos(PLAIN_TEXT_TYPE));
    assert!(marker.is_some() && plain.is_some(), "{types:?}");
    assert!(marker < plain, "marker must precede text: {types:?}");

    Clipboard::clear_if_unchanged(cc);
    assert_eq!(Clipboard::read_string(), None);
    assert!(!Clipboard::has_concealed_type());
}

#[test]
fn external_change_is_not_cleared() {
    let _g = PASTEBOARD.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = Restore::save();

    let cc =
        Clipboard::write_concealed(&SecretString::new("ours".to_owned())).expect("write accepted");
    let other = Clipboard::write_plain("someone else's copy").expect("write accepted");
    assert_ne!(other, cc);

    Clipboard::clear_if_unchanged(cc);
    assert_eq!(
        Clipboard::read_string().as_deref(),
        Some("someone else's copy")
    );
    assert!(!Clipboard::has_concealed_type());
}
