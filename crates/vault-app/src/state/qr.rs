//! Edit mode ▸ TOTP field ▸ "Scan QR from screen" (specs/05-ui.md §2.3).
//!
//! The capture runs on the background executor behind [`QrScanner`] (tests use a fake).
//! Only `otpauth://totp` payloads that `Totp::parse_uri` accepts are used; the first one
//! fills the field. Payloads are secrets and never reach a toast or a log.

use std::sync::Arc;

use gpui::Context;
use vault_core::{ExposeSecret as _, FieldKind, SecretString, Totp};
use vault_macos::MacError;

use super::{AppState, Mode};

/// System Settings ▸ Privacy & Security ▸ Screen Recording.
const SCREEN_RECORDING_SETTINGS: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture";

/// Captures the screen and decodes every QR code on it.
pub trait QrScanner: Send + Sync {
    fn scan(&self) -> Result<Vec<SecretString>, MacError>;
}

/// The real scanner (Screen Recording permission required).
#[cfg_attr(test, allow(dead_code))]
pub struct ScreenScanner;

impl QrScanner for ScreenScanner {
    fn scan(&self) -> Result<Vec<SecretString>, MacError> {
        vault_macos::scan_qr_from_screen()
    }
}

#[cfg_attr(test, allow(dead_code))]
pub fn screen_scanner() -> Arc<dyn QrScanner> {
    Arc::new(ScreenScanner)
}

/// The field a scan was started for.
#[derive(Debug, Clone, Copy)]
struct ScanTarget {
    session: u64,
    item: Option<vault_core::Uuid>,
    key: u64,
}

/// The first payload that is a valid `otpauth://totp` URI.
pub fn totp_payload(payloads: Vec<SecretString>) -> Option<SecretString> {
    payloads.into_iter().find(|p| {
        let uri = p.expose_secret().trim();
        uri.get(..14)
            .is_some_and(|s| s.eq_ignore_ascii_case("otpauth://totp"))
            && Totp::parse_uri(uri).is_ok()
    })
}

impl AppState {
    /// "Scan QR from screen" on the TOTP field `key` of the edit buffer.
    pub fn scan_totp_qr(&mut self, key: u64, cx: &mut Context<Self>) {
        if !self.is_editing() || self.qr_scanning {
            return;
        }
        // Row keys restart with every edit session: remember which session and item the
        // scan was for, so a late result can never land in another item's field.
        let target = ScanTarget {
            session: self.edit_session,
            item: self.edit_buffer().map(|b| b.item.id),
            key,
        };
        self.qr_scanning = true;
        cx.notify();
        let scanner = self.qr.clone();
        let task = cx
            .background_executor()
            .spawn(async move { scanner.scan() });
        cx.spawn(async move |this, cx| {
            let result = task.await;
            this.update(cx, |this, cx| {
                this.qr_scanning = false;
                this.qr_scanned(target, result, cx);
            })
            .ok();
        })
        .detach();
    }

    fn qr_scanned(
        &mut self,
        target: ScanTarget,
        result: Result<Vec<SecretString>, MacError>,
        cx: &mut Context<Self>,
    ) {
        match result {
            Ok(payloads) => match totp_payload(payloads) {
                Some(uri) => {
                    let same_session = self.edit_session == target.session;
                    let filled = match &mut self.mode {
                        Mode::Edit(b) | Mode::New(_, b)
                            if same_session && Some(b.item.id) == target.item =>
                        {
                            match b.index(target.key) {
                                Some(i) if b.item.fields[i].kind == FieldKind::Totp => {
                                    b.item.fields[i].value = uri;
                                    b.pushed.push(target.key);
                                    true
                                }
                                _ => false,
                            }
                        }
                        _ => false,
                    };
                    if filled {
                        self.screen_recording_hint = false;
                        self.show_toast("One-time code added from the screen", cx);
                    } else {
                        // `uri` is dropped (zeroized) here; nothing was written.
                        self.show_toast("Scan result discarded: field changed", cx);
                    }
                }
                None => self.show_toast("No TOTP QR code found on screen", cx),
            },
            Err(MacError::NotAvailable) => {
                self.screen_recording_hint = true;
                self.show_toast(
                    "Allow vault under Screen Recording in System Settings, then restart vault",
                    cx,
                );
            }
            Err(e) => self.show_toast(format!("Could not scan the screen: {e}"), cx),
        }
        cx.notify();
    }

    /// The hint's button. The only place a non-web URL is opened (not via
    /// `text::browser_url`): a fixed System Settings deep link.
    pub fn open_screen_recording_settings(&mut self, cx: &mut Context<Self>) {
        cx.open_url(SCREEN_RECORDING_SETTINGS);
    }
}

#[cfg(test)]
pub mod fake {
    use std::sync::Mutex;

    use super::*;

    /// Returns the queued result once, then an empty scan.
    pub struct FakeScanner(pub Mutex<Option<Result<Vec<SecretString>, MacError>>>);

    impl FakeScanner {
        pub fn returning(result: Result<Vec<SecretString>, MacError>) -> Arc<Self> {
            Arc::new(Self(Mutex::new(Some(result))))
        }
    }

    impl QrScanner for FakeScanner {
        fn scan(&self) -> Result<Vec<SecretString>, MacError> {
            self.0
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Ok(Vec::new()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use gpui::{AppContext as _, Entity, TestAppContext};
    use vault_core::{Field, FieldKind, Item, ItemKind, KdfParams, Uuid};
    use vault_sync::{NoopHooks, SyncedVault};

    use super::fake::FakeScanner;
    use super::*;
    use crate::state::EditBuffer;

    const VALID: &str = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example";

    fn s(v: &str) -> SecretString {
        SecretString::new(v.to_owned())
    }

    /// An unlocked state editing an item with one empty TOTP field; returns its row key.
    fn editing(dir: &Path, cx: &mut TestAppContext) -> (Entity<AppState>, u64) {
        let vault = SyncedVault::create(
            &dir.join("t.vault"),
            &s("pw"),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        let key = state.update(cx, |st, _| {
            st.install_unlocked_for_tests(vault);
            let mut item = Item::new(ItemKind::Login, "Example", st.device_id(), 1);
            item.fields = vec![Field::new("one-time code", FieldKind::Totp, s(""), 1)];
            st.mode = Mode::Edit(EditBuffer::new(item));
            st.edit_buffer().unwrap().keys[0]
        });
        (state, key)
    }

    fn field_value(state: &Entity<AppState>, cx: &mut TestAppContext) -> String {
        state.read_with(cx, |st, _| {
            st.edit_buffer().unwrap().item.fields[0]
                .value
                .expose_secret()
                .clone()
        })
    }

    #[test]
    fn picks_the_first_valid_totp_uri() {
        let got = totp_payload(vec![
            s("https://example.com"),
            s("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1"),
            s("otpauth://totp/broken"),
            s(VALID),
        ]);
        assert_eq!(got.unwrap().expose_secret(), VALID);
        assert!(totp_payload(vec![s("hello")]).is_none());
    }

    #[gpui::test]
    fn scan_fills_the_totp_field(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, key) = editing(dir.path(), cx);
        state.update(cx, |st, cx| {
            st.set_qr_scanner(FakeScanner::returning(Ok(vec![
                s("https://not-a-code.example"),
                s(VALID),
            ])));
            st.scan_totp_qr(key, cx);
            assert!(st.qr_scanning);
        });
        cx.run_until_parked();
        assert_eq!(field_value(&state, cx), VALID);
        state.read_with(cx, |st, _| {
            assert!(!st.qr_scanning);
            assert_eq!(
                st.edit_buffer().unwrap().pushed,
                vec![key],
                "editor input refreshed"
            );
            let toast = st.toast.as_ref().unwrap().message.to_string();
            assert!(!toast.contains("JBSW"), "the secret never reaches a toast");
        });
    }

    #[gpui::test]
    fn no_code_and_no_permission(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, key) = editing(dir.path(), cx);
        state.update(cx, |st, cx| {
            st.set_qr_scanner(FakeScanner::returning(Ok(vec![s("https://x.example")])));
            st.scan_totp_qr(key, cx);
        });
        cx.run_until_parked();
        state.read_with(cx, |st, _| {
            assert_eq!(
                st.toast.as_ref().unwrap().message.as_ref(),
                "No TOTP QR code found on screen"
            );
        });
        assert_eq!(field_value(&state, cx), "");

        state.update(cx, |st, cx| {
            st.set_qr_scanner(FakeScanner::returning(Err(MacError::NotAvailable)));
            st.scan_totp_qr(key, cx);
        });
        cx.run_until_parked();
        state.read_with(cx, |st, _| {
            assert!(st.screen_recording_hint);
            assert!(
                st.toast
                    .as_ref()
                    .unwrap()
                    .message
                    .contains("Screen Recording")
            );
        });
    }

    #[gpui::test]
    fn late_result_never_lands_in_another_edit(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, key) = editing(dir.path(), cx);
        state.update(cx, |st, cx| {
            st.set_qr_scanner(FakeScanner::returning(Ok(vec![s(VALID)])));
            st.scan_totp_qr(key, cx);
            // Cancel, then edit another item whose TOTP field has the same row key.
            st.mode = Mode::View;
            let mut other = Item::new(ItemKind::Login, "Other", st.device_id(), 1);
            other.fields = vec![Field::new("one-time code", FieldKind::Totp, s(""), 1)];
            st.mode = Mode::Edit(EditBuffer::new(other));
            st.edit_session = st.edit_session.wrapping_add(1);
            assert_eq!(st.edit_buffer().unwrap().keys[0], key, "keys restart");
        });
        cx.run_until_parked();
        assert_eq!(field_value(&state, cx), "", "nothing written");
        state.read_with(cx, |st, _| {
            assert!(st.edit_buffer().unwrap().pushed.is_empty());
            assert_eq!(
                st.toast.as_ref().unwrap().message.as_ref(),
                "Scan result discarded: field changed"
            );
        });
    }
}
