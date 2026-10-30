//! KeePass import credentials stay in the view; decrypted entries arrive from a
//! background task and are discarded if the session was locked or switched.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use gpui::{Context, SharedString};
use vault_core::{ImportError, SecretString, Uuid};
use zeroize::Zeroizing;

use super::{AppState, Busy, Outcome, TRANSFER_TAB};
use crate::{text, ui};

pub struct KdbxImportUi {
    pub id: Uuid,
    pub path: PathBuf,
    pub keyfile: Option<PathBuf>,
    pub error: Option<SharedString>,
}

fn read_bounded(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(path)
        .and_then(|file| file.take(limit + 1).read_to_end(&mut bytes))
        .map_err(|_| ImportError::Malformed("could not read the selected file".into()))?;
    if bytes.len() as u64 > limit {
        return Err(ImportError::Malformed("selected file is too large".into()));
    }
    Ok(bytes)
}

impl AppState {
    pub fn choose_import_kdbx(&mut self, cx: &mut Context<Self>) {
        if !self.main_active() || self.busy.is_some() {
            return;
        }
        let (epoch, generation) = (self.epoch, self.lock_gen);
        let picker = ui::pick_path(false, "Import KeePass database", cx);
        cx.spawn(async move |this, cx| {
            if let Some(path) = picker.await {
                this.update(cx, |s, cx| {
                    if s.main_active()
                        && s.busy.is_none()
                        && s.epoch == epoch
                        && s.lock_gen == generation
                    {
                        s.request_kdbx_import(path, cx);
                    }
                })
                .ok();
            }
        })
        .detach();
    }

    pub fn request_kdbx_import(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        if !self.main_active() || self.busy.is_some() {
            return;
        }
        self.kdbx_import = Some(KdbxImportUi {
            id: Uuid::new_v4(),
            path,
            keyfile: None,
            error: None,
        });
        self.settings_tab = TRANSFER_TAB;
        self.settings_open = true;
        cx.notify();
    }

    pub fn cancel_kdbx_import(&mut self, cx: &mut Context<Self>) {
        self.kdbx_import = None;
        cx.notify();
    }

    pub fn choose_kdbx_keyfile(&mut self, cx: &mut Context<Self>) {
        let Some(request) = &self.kdbx_import else {
            return;
        };
        if self.busy.is_some() {
            return;
        }
        let id = request.id;
        let picker = ui::pick_path(false, "Choose KeePass key file", cx);
        cx.spawn(async move |this, cx| {
            if let Some(path) = picker.await {
                this.update(cx, |s, cx| {
                    if let Some(request) = &mut s.kdbx_import
                        && request.id == id
                        && s.busy.is_none()
                    {
                        request.keyfile = Some(path);
                        cx.notify();
                    }
                })
                .ok();
            }
        })
        .detach();
    }

    pub fn clear_kdbx_keyfile(&mut self, cx: &mut Context<Self>) {
        if let Some(request) = &mut self.kdbx_import
            && self.busy.is_none()
        {
            request.keyfile = None;
            cx.notify();
        }
    }

    pub fn import_kdbx(&mut self, password: SecretString, cx: &mut Context<Self>) {
        if !self.main_active() || self.busy.is_some() {
            return;
        }
        let Some(request) = &mut self.kdbx_import else {
            return;
        };
        request.error = None;
        let (id, path, keyfile) = (request.id, request.path.clone(), request.keyfile.clone());
        let (device, now) = (self.device_id, text::now_millis());
        self.run_bg_cx(
            Busy::Importing,
            cx,
            move || {
                let bytes = read_bounded(&path, 100 * 1024 * 1024)?;
                let key = keyfile
                    .as_deref()
                    .map(|path| read_bounded(path, 1024 * 1024))
                    .transpose()?;
                vault_core::import_kdbx(
                    &bytes,
                    &password,
                    key.as_deref().map(|b| b.as_slice()),
                    device,
                    now,
                )
            },
            move |s, result, outcome, cx| {
                if outcome != Outcome::Fresh
                    || !s.main_active()
                    || !s
                        .kdbx_import
                        .as_ref()
                        .is_some_and(|request| request.id == id)
                {
                    return;
                }
                match result {
                    Ok(items) => {
                        s.kdbx_import = None;
                        s.insert_imported(items, now, cx);
                    }
                    Err(error) => {
                        if let Some(request) = &mut s.kdbx_import {
                            request.error = Some(error.to_string().into());
                        }
                    }
                }
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::{AppContext as _, TestAppContext};
    use std::sync::Arc;
    use vault_core::KdfParams;
    use vault_sync::{NoopHooks, SyncedVault};

    const FIXTURE: &[u8] = include_bytes!("../../../vault-core/tests/fixtures/keepass-v4.kdbx");

    fn setup(dir: &Path, cx: &mut TestAppContext) -> (gpui::Entity<AppState>, PathBuf) {
        let vault = SyncedVault::create(
            &dir.join("target.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
        let path = dir.join("source.kdbx");
        std::fs::write(&path, FIXTURE).unwrap();
        (state, path)
    }

    #[gpui::test]
    fn bad_credentials_retry_and_success_leave_source_unchanged(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, path) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.request_kdbx_import(path.clone(), cx);
            s.import_kdbx(SecretString::new("wrong".into()), cx);
            assert_eq!(s.busy, Some(Busy::Importing));
        });
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert_eq!(s.counts.all, 0);
            assert!(s.kdbx_import.as_ref().unwrap().error.is_some());
        });
        state.update(cx, |s, cx| {
            s.import_kdbx(SecretString::new("kdbx-password".into()), cx)
        });
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert_eq!(s.counts.all, 2);
            assert!(s.kdbx_import.is_none());
            assert!(s.busy.is_none());
        });
        assert_eq!(std::fs::read(&path).unwrap(), FIXTURE);
        state.update(cx, |s, cx| s.lock(cx));
        state.update(cx, |s, cx| s.unlock(SecretString::new("pw".into()), cx));
        cx.run_until_parked();
        assert_eq!(
            state.read_with(cx, |s, _| s.counts.all),
            2,
            "import persisted"
        );
    }

    #[gpui::test]
    fn lock_close_or_cancel_during_decryption_discards_results(cx: &mut TestAppContext) {
        for mode in [0, 1, 2] {
            let dir = tempfile::tempdir().unwrap();
            let (state, path) = setup(dir.path(), cx);
            state.update(cx, |s, cx| {
                s.request_kdbx_import(path, cx);
                s.import_kdbx(SecretString::new("kdbx-password".into()), cx);
                match mode {
                    1 => s.lock(cx),
                    2 => s.close_vault(cx),
                    _ => s.cancel_kdbx_import(cx),
                }
            });
            cx.run_until_parked();
            if mode == 1 {
                state.update(cx, |s, cx| s.unlock(SecretString::new("pw".into()), cx));
                cx.run_until_parked();
            }
            state.read_with(cx, |s, _| {
                assert_eq!(s.counts.all, 0);
                assert!(s.kdbx_import.is_none());
                assert!(s.busy.is_none());
            });
        }
    }
}
