//! Edit mode ▸ TOTP field ▸ "Scan QR from image…" (specs/05-ui.md §2.3).
//!
//! The image decode runs on the background executor behind [`QrScanner`]
//! (tests use a fake).
//! Only `otpauth://totp` payloads that `Totp::parse_uri` accepts are used; the first one
//! fills the field. Payloads are secrets and never reach a toast or a log.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use gpui::Context;
use vault_core::{ExposeSecret as _, FieldKind, SecretString, Totp};
use vault_macos::MacError;

use super::{AppState, Mode};
use crate::ui;

/// Decodes every QR code in an image file.
pub trait QrScanner: Send + Sync {
    /// Reads the image at `path` (no permission needed).
    fn scan_file(&self, path: &Path) -> Result<Vec<SecretString>, MacError>;
}

/// The real scanner (Vision on the image file).
#[cfg_attr(test, allow(dead_code))]
pub struct ImageScanner;

impl QrScanner for ImageScanner {
    fn scan_file(&self, path: &Path) -> Result<Vec<SecretString>, MacError> {
        vault_macos::scan_qr_from_image_file(path)
    }
}

#[cfg_attr(test, allow(dead_code))]
pub fn image_scanner() -> Arc<dyn QrScanner> {
    Arc::new(ImageScanner)
}

/// The field a scan was started for.
#[derive(Debug, Clone, Copy)]
struct ScanTarget {
    session: u64,
    item: Option<vault_core::Uuid>,
    key: u64,
    /// `AppState::lock_gen` / `epoch` at the start: a lock or vault switch meanwhile
    /// makes the result void.
    lock_gen: u64,
    epoch: u64,
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
    /// "Scan QR from image…" on the TOTP field `key`: the open panel, then the decode.
    pub fn scan_totp_qr_file(&mut self, key: u64, cx: &mut Context<Self>) {
        if !self.is_editing() || self.qr_scanning {
            return;
        }
        // Taken before the panel opens: the user may cancel the edit meanwhile.
        let target = self.scan_target(key);
        let pick = ui::pick_path(false, "Choose", cx);
        cx.spawn(async move |this, cx| {
            let path = pick.await;
            this.update(cx, |this, cx| this.image_picked(target, path, cx))
                .ok();
        })
        .detach();
    }

    /// The open panel closed: decode the chosen file, unless it was cancelled, another
    /// scan is running, or the session ended while the panel was open.
    fn image_picked(&mut self, target: ScanTarget, path: Option<PathBuf>, cx: &mut Context<Self>) {
        if let Some(path) = path
            && !self.qr_scanning
            && !self.scan_outlived(&target)
        {
            self.run_scan(target, path, cx);
        }
    }

    /// Decodes the image at `path` into the TOTP field `key`: what the open panel's
    /// result does, minus the panel (tests).
    #[cfg(test)]
    pub fn scan_totp_qr_image(&mut self, key: u64, path: PathBuf, cx: &mut Context<Self>) {
        if !self.is_editing() || self.qr_scanning {
            return;
        }
        let target = self.scan_target(key);
        self.run_scan(target, path, cx);
    }

    /// Row keys restart with every edit session: remember which session and item the
    /// scan was for, so a late result can never land in another item's field.
    fn scan_target(&self, key: u64) -> ScanTarget {
        ScanTarget {
            session: self.edit_session,
            item: self.edit_buffer().map(|b| b.item.id),
            key,
            lock_gen: self.lock_gen,
            epoch: self.epoch,
        }
    }

    /// True when the session the scan started in is gone (locked, re-locked or another
    /// vault opened): the result is then dropped without a toast or hint.
    fn scan_outlived(&self, target: &ScanTarget) -> bool {
        self.locked || self.lock_gen != target.lock_gen || self.epoch != target.epoch
    }

    /// Decodes the image file off the main thread.
    fn run_scan(&mut self, target: ScanTarget, path: PathBuf, cx: &mut Context<Self>) {
        self.qr_scanning = true;
        cx.notify();
        let scanner = self.qr.clone();
        let task = cx
            .background_executor()
            .spawn(async move { scanner.scan_file(&path) });
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
        if self.scan_outlived(&target) {
            // Locked meanwhile: `result` (payloads are secrets) is dropped unread.
            return;
        }
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
                    if !filled {
                        // `uri` is dropped (zeroized) here; nothing was written.
                        self.show_toast("Scan result discarded: field changed", cx);
                    } else {
                        self.show_toast("One-time code added from the image", cx);
                    }
                }
                None => self.show_toast("No TOTP QR code found in the image", cx),
            },
            // The error text names the file at most, never a payload; keep it out anyway.
            Err(_) => self.show_toast("Could not read the image", cx),
        }
        cx.notify();
    }
}

#[cfg(test)]
pub mod fake {
    use std::sync::Mutex;

    use super::*;

    /// Returns the queued result once, then an empty scan. Records the last file path
    /// it was asked to read.
    pub struct FakeScanner {
        pub result: Mutex<Option<Result<Vec<SecretString>, MacError>>>,
        pub last_file: Mutex<Option<PathBuf>>,
    }

    impl FakeScanner {
        pub fn returning(result: Result<Vec<SecretString>, MacError>) -> Arc<Self> {
            Arc::new(Self {
                result: Mutex::new(Some(result)),
                last_file: Mutex::new(None),
            })
        }
    }

    impl QrScanner for FakeScanner {
        fn scan_file(&self, path: &Path) -> Result<Vec<SecretString>, MacError> {
            *self.last_file.lock().unwrap() = Some(path.to_owned());
            self.result
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
    fn late_result_never_lands_in_another_edit(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, key) = editing(dir.path(), cx);
        state.update(cx, |st, cx| {
            st.set_qr_scanner(FakeScanner::returning(Ok(vec![s(VALID)])));
            st.scan_totp_qr_image(key, PathBuf::from("/tmp/qr.png"), cx);
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

    fn toast(state: &Entity<AppState>, cx: &mut TestAppContext) -> String {
        state.read_with(cx, |st, _| st.toast.as_ref().unwrap().message.to_string())
    }

    #[gpui::test]
    fn image_scan_fills_the_field_it_was_started_for(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, key) = editing(dir.path(), cx);
        // A second TOTP row that must stay untouched.
        let other = state.update(cx, |st, cx| {
            let mut k = 0;
            st.edit(cx, |b| k = b.add_field(FieldKind::Totp));
            k
        });
        let fake = FakeScanner::returning(Ok(vec![s("hello"), s(VALID)]));
        let path = PathBuf::from("/tmp/qr.png");
        state.update(cx, |st, cx| {
            st.set_qr_scanner(fake.clone());
            st.scan_totp_qr_image(key, path.clone(), cx);
            assert!(st.qr_scanning);
        });
        cx.run_until_parked();
        assert_eq!(
            fake.last_file.lock().unwrap().as_deref(),
            Some(path.as_path())
        );
        assert_eq!(field_value(&state, cx), VALID);
        state.read_with(cx, |st, _| {
            let b = st.edit_buffer().unwrap();
            assert_eq!(b.field(other).unwrap().value.expose_secret(), "");
            assert_eq!(b.pushed, vec![key]);
            assert!(!st.qr_scanning);
        });
        let toast = toast(&state, cx);
        assert_eq!(toast, "One-time code added from the image");
        assert!(!toast.contains("JBSW"), "the secret never reaches a toast");
    }

    #[gpui::test]
    fn image_scan_none_found_unreadable_and_stale(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, key) = editing(dir.path(), cx);
        let path = PathBuf::from("/tmp/qr.png");

        state.update(cx, |st, cx| {
            st.set_qr_scanner(FakeScanner::returning(Ok(vec![s("https://x.example")])));
            st.scan_totp_qr_image(key, path.clone(), cx);
        });
        cx.run_until_parked();
        assert_eq!(toast(&state, cx), "No TOTP QR code found in the image");

        state.update(cx, |st, cx| {
            st.set_qr_scanner(FakeScanner::returning(Err(MacError::Other(
                "could not read image: /tmp/qr.png".into(),
            ))));
            st.scan_totp_qr_image(key, path.clone(), cx);
        });
        cx.run_until_parked();
        assert_eq!(toast(&state, cx), "Could not read the image");

        // Stale: the edit is replaced while the image is decoded.
        state.update(cx, |st, cx| {
            st.set_qr_scanner(FakeScanner::returning(Ok(vec![s(VALID)])));
            st.scan_totp_qr_image(key, path.clone(), cx);
            let mut other = Item::new(ItemKind::Login, "Other", st.device_id(), 1);
            other.fields = vec![Field::new("one-time code", FieldKind::Totp, s(""), 1)];
            st.mode = Mode::Edit(EditBuffer::new(other));
            st.edit_session = st.edit_session.wrapping_add(1);
        });
        cx.run_until_parked();
        assert_eq!(field_value(&state, cx), "", "nothing written");
        assert_eq!(toast(&state, cx), "Scan result discarded: field changed");
        assert_eq!(field_value(&state, cx), "");
    }

    #[gpui::test]
    fn scan_finishing_after_lock_is_dropped_silently(cx: &mut TestAppContext) {
        for found in [true, false] {
            {
                let dir = tempfile::tempdir().unwrap();
                let (state, key) = editing(dir.path(), cx);
                state.update(cx, |st, cx| {
                    st.set_qr_scanner(FakeScanner::returning(if found {
                        Ok(vec![s(VALID)])
                    } else {
                        Err(MacError::NotAvailable)
                    }));
                    st.scan_totp_qr_image(key, PathBuf::from("/tmp/qr.png"), cx);
                    // Lock before the background scan delivers. Put a same-keyed edit
                    // back afterwards so a write would be observable.
                    st.lock(cx);
                    assert!(st.locked);
                    let mut item = Item::new(ItemKind::Login, "Example", st.device_id(), 1);
                    item.fields = vec![Field::new("one-time code", FieldKind::Totp, s(""), 1)];
                    st.mode = Mode::Edit(EditBuffer::new(item));
                    st.toast = None;
                });
                cx.run_until_parked();
                state.read_with(cx, |st, _| {
                    assert!(!st.qr_scanning, "spinner cleared");
                    assert!(st.toast.is_none(), "no toast over the unlock screen");
                    assert!(st.edit_buffer().unwrap().pushed.is_empty());
                });
                assert_eq!(field_value(&state, cx), "", "nothing written");
            }
        }
    }

    #[gpui::test]
    fn lock_while_the_open_panel_is_up_starts_no_decode(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, key) = editing(dir.path(), cx);
        let fake = FakeScanner::returning(Ok(vec![s(VALID)]));
        state.update(cx, |st, cx| {
            st.set_qr_scanner(fake.clone());
            // Cancelled panel: nothing happens.
            let target = st.scan_target(key);
            st.image_picked(target, None, cx);
            assert!(!st.qr_scanning);
            // Panel resolves after a lock.
            let target = st.scan_target(key);
            st.lock(cx);
            st.image_picked(target, Some(PathBuf::from("/tmp/qr.png")), cx);
            assert!(!st.qr_scanning, "no decode started");
        });
        cx.run_until_parked();
        assert!(fake.last_file.lock().unwrap().is_none(), "file never read");
        state.read_with(cx, |st, _| assert!(st.toast.is_none()));

        // Control: the same call while unlocked does decode.
        let dir = tempfile::tempdir().unwrap();
        let (state, key) = editing(dir.path(), cx);
        let fake = FakeScanner::returning(Ok(vec![s(VALID)]));
        state.update(cx, |st, cx| {
            st.set_qr_scanner(fake.clone());
            let target = st.scan_target(key);
            st.image_picked(target, Some(PathBuf::from("/tmp/qr.png")), cx);
        });
        cx.run_until_parked();
        assert_eq!(field_value(&state, cx), VALID);
    }
}
