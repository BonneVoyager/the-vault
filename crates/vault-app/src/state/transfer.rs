//! Settings ▸ Import / Export and File ▸ Import…/Export… (specs/05-ui.md §2.5).
//!
//! CSV export writes `vault_core::export_csv` bytes to a file created with mode 0600,
//! behind a red confirm. CSV import maps columns with `CsvMapping::default()` and inserts
//! every row as a new login. 1PUX import inserts every item of a 1Password export. The
//! plaintext bytes stay in zeroizing wrappers.

use std::fs::{OpenOptions, Permissions};
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use gpui::Context;
use vault_core::import::import_1pux;
use vault_core::{CsvMapping, ExposeSecret as _, SecretVec, export_csv, import_csv};

use super::AppState;
use super::edit::edit_result;
use super::sync::TRANSFER_TAB;
use crate::{text, ui};

/// Creates (or truncates) `path` owner-read/write only, then writes `bytes`.
///
/// An existing file keeps its inode, so its permissions are tightened before any
/// plaintext lands in it.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()
}

impl AppState {
    /// File ▸ Export…: open the Import / Export tab with the red confirm showing.
    pub fn request_export(&mut self, cx: &mut Context<Self>) {
        if !self.main_active() {
            return self.show_toast("Unlock the vault to export it", cx);
        }
        self.settings_tab = TRANSFER_TAB;
        self.settings_open = true;
        self.sync.export_confirm = true;
        cx.notify();
    }

    pub fn set_export_confirm(&mut self, show: bool, cx: &mut Context<Self>) {
        self.sync.export_confirm = show && self.main_active();
        cx.notify();
    }

    /// "Export" in the red confirm: native save panel, then [`Self::export_csv_to`].
    pub fn choose_export_path(&mut self, cx: &mut Context<Self>) {
        self.sync.export_confirm = false;
        cx.notify();
        if !self.main_active() {
            return;
        }
        let dir = dirs::document_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| PathBuf::from("/"));
        let name = format!("{}.csv", self.vault_name());
        let task = ui::pick_new_path(&dir, &name, cx);
        cx.spawn(async move |this, cx| {
            if let Some(path) = task.await {
                this.update(cx, |s, cx| s.export_csv_to(&path, cx)).ok();
            }
        })
        .detach();
    }

    /// Writes every live item as CSV to `path` (mode 0600). Returns whether it worked.
    pub fn export_csv_to(&mut self, path: &Path, cx: &mut Context<Self>) -> bool {
        let Some(vault) = self.unlocked_vault() else {
            self.show_toast("Unlock the vault to export it", cx);
            return false;
        };
        let count = vault.items().count();
        let bytes = export_csv(vault);
        match write_private(path, &bytes.0) {
            Ok(()) => {
                self.show_toast(
                    format!("Exported {count} items to {}", text::file_name(path)),
                    cx,
                );
                true
            }
            Err(e) => {
                self.show_toast(format!("Export failed: {e}"), cx);
                false
            }
        }
    }

    /// File ▸ Import… and "Import CSV…": native open panel, then [`Self::import_csv_from`].
    pub fn choose_import_path(&mut self, cx: &mut Context<Self>) {
        if !self.main_active() {
            return self.show_toast("Unlock the vault to import into it", cx);
        }
        let task = ui::pick_path(false, "Import", cx);
        cx.spawn(async move |this, cx| {
            if let Some(path) = task.await {
                this.update(cx, |s, cx| s.import_csv_from(&path, cx)).ok();
            }
        })
        .detach();
    }

    /// Inserts every row of the CSV at `path` as a new item. Returns how many.
    pub fn import_csv_from(&mut self, path: &Path, cx: &mut Context<Self>) -> usize {
        if !self.main_active() {
            self.show_toast("Unlock the vault to import into it", cx);
            return 0;
        }
        let bytes = match std::fs::read(path) {
            Ok(b) => SecretVec::new(b),
            Err(e) => {
                self.show_toast(format!("Could not read {}: {e}", text::file_name(path)), cx);
                return 0;
            }
        };
        let now = text::now_millis();
        let items = match import_csv(
            bytes.expose_secret(),
            &CsvMapping::default(),
            self.device_id,
            now,
        ) {
            Ok(items) => items,
            Err(e) => {
                self.show_toast(format!("Import failed: {e}"), cx);
                return 0;
            }
        };
        self.insert_imported(items, now, cx)
    }

    /// File ▸ Import 1Password (1PUX)… and the Import / Export row: open panel, then
    /// [`Self::import_1pux_bytes`].
    pub fn choose_import_1pux(&mut self, cx: &mut Context<Self>) {
        if !self.main_active() {
            return self.show_toast("Unlock the vault to import into it", cx);
        }
        let task = ui::pick_path(false, "Import", cx);
        cx.spawn(async move |this, cx| {
            if let Some(path) = task.await {
                this.update(cx, |s, cx| {
                    match std::fs::read(&path) {
                        Ok(bytes) => {
                            s.import_1pux_bytes(&SecretVec::new(bytes), cx);
                        }
                        Err(e) => s.show_toast(
                            format!("Could not read {}: {e}", text::file_name(&path)),
                            cx,
                        ),
                    };
                })
                .ok();
            }
        })
        .detach();
    }

    /// Inserts every item of a 1Password export (`.1pux`). Returns how many. Errors are
    /// `ImportError::Malformed` texts, which never contain values.
    pub fn import_1pux_bytes(&mut self, bytes: &SecretVec<u8>, cx: &mut Context<Self>) -> usize {
        if !self.main_active() {
            self.show_toast("Unlock the vault to import into it", cx);
            return 0;
        }
        let now = text::now_millis();
        match import_1pux(bytes.expose_secret(), self.device_id, now) {
            Ok(items) => self.insert_imported(items, now, cx),
            Err(e) => {
                self.show_toast(format!("Import failed: {e}"), cx);
                0
            }
        }
    }

    /// Inserts imported items as new items, autosaves and toasts the count.
    pub(super) fn insert_imported(
        &mut self,
        items: Vec<vault_core::Item>,
        now: vault_core::Millis,
        cx: &mut Context<Self>,
    ) -> usize {
        let count = items.len();
        if count == 0 {
            self.show_toast("No items found in that file", cx);
            return 0;
        }
        let Some(vault) = self.vault.as_mut() else {
            return 0;
        };
        let result = vault.edit(|v| {
            for item in items {
                v.insert(item, now);
            }
            Ok(())
        });
        if let Err(e) = edit_result(result) {
            self.show_toast(format!("Import failed: {e}"), cx);
            return 0;
        }
        self.vault_changed();
        self.schedule_autosave(cx);
        let noun = if count == 1 { "item" } else { "items" };
        self.show_toast(format!("{count} {noun} imported"), cx);
        count
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gpui::{AppContext as _, Entity, TestAppContext};
    use vault_core::{Field, FieldKind, Item, KdfParams, SecretString, Uuid};
    use vault_sync::{NoopHooks, SyncedVault};

    use super::*;

    fn unlocked_state(path: &Path, titles: &[&str], cx: &mut TestAppContext) -> Entity<AppState> {
        let mut vault = SyncedVault::create(
            path,
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        vault
            .edit(|v| {
                for t in titles {
                    let mut item = Item::new(*t, device, 10);
                    item.fields = vec![Field::new(
                        "password",
                        FieldKind::Password,
                        SecretString::new(format!("{t}-pw")),
                        10,
                    )];
                    v.insert(item, 10);
                }
            })
            .unwrap();
        vault.save().unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| {
            s.install(vault, false);
            s.unlocked();
        });
        state
    }

    #[gpui::test]
    fn export_is_private_and_import_reads_it_back(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let source = unlocked_state(&dir.path().join("a.vault"), &["Known Title", "Other"], cx);
        let csv = dir.path().join("out.csv");
        // A pre-existing world-readable file is tightened before plaintext lands in it.
        std::fs::write(&csv, "old").unwrap();
        std::fs::set_permissions(&csv, Permissions::from_mode(0o644)).unwrap();
        assert!(source.update(cx, |s, cx| s.export_csv_to(&csv, cx)));
        let mode = std::fs::metadata(&csv).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let text = std::fs::read_to_string(&csv).unwrap();
        assert!(text.contains("Known Title"), "{text}");
        assert!(text.contains("Known Title-pw"));

        let target = unlocked_state(&dir.path().join("b.vault"), &["Existing"], cx);
        let n = target.update(cx, |s, cx| s.import_csv_from(&csv, cx));
        assert_eq!(n, 2);
        target.read_with(cx, |s, _| {
            assert_eq!(s.item_count(), 3);
            assert_eq!(s.counts.all, 3);
            assert_eq!(
                s.toast.as_ref().unwrap().message.as_ref(),
                "2 items imported"
            );
            assert!(s.vault.as_ref().unwrap().is_dirty(), "autosave pending");
        });
    }

    #[gpui::test]
    fn transfer_needs_an_unlocked_vault(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let state = unlocked_state(&dir.path().join("a.vault"), &["x"], cx);
        let csv = dir.path().join("out.csv");
        state.update(cx, |s, cx| {
            s.lock(cx);
            assert!(!s.export_csv_to(&csv, cx));
            assert_eq!(s.import_csv_from(&csv, cx), 0);
            s.request_export(cx);
            assert!(!s.settings_open);
        });
        assert!(!csv.exists());
    }

    fn onepux(items: serde_json::Value) -> Vec<u8> {
        use std::io::Write as _;
        let data = serde_json::json!({"accounts": [{"vaults": [{"attrs": {}, "items": items}]}]});
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        w.start_file("export.attributes", opts).unwrap();
        w.write_all(b"{}").unwrap();
        w.start_file("export.data", opts).unwrap();
        w.write_all(data.to_string().as_bytes()).unwrap();
        w.finish().unwrap().into_inner()
    }

    #[gpui::test]
    fn onepux_import_inserts_items(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.vault");
        let state = unlocked_state(&path, &["Existing"], cx);
        let bytes = onepux(serde_json::json!([
            {"uuid": "a", "state": "active", "categoryUuid": "001",
             "details": {"loginFields": [
                 {"value": "alice", "name": "u", "fieldType": "T", "designation": "username"},
                 {"value": "s3cret", "name": "p", "fieldType": "P", "designation": "password"}]},
             "overview": {"title": "GitHub"}},
            {"uuid": "b", "state": "active", "categoryUuid": "003",
             "details": {"notesPlain": "note body"}, "overview": {"title": "My note"}}
        ]));
        state.update(cx, |s, cx| {
            assert_eq!(s.import_1pux_bytes(&SecretVec::new(bytes), cx), 2);
            assert_eq!(s.item_count(), 3);
            assert!(
                s.toast
                    .as_ref()
                    .unwrap()
                    .message
                    .contains("2 items imported")
            );
            assert!(s.vault.as_ref().unwrap().is_dirty(), "autosave scheduled");

            // A broken archive toasts the Malformed text and changes nothing.
            let junk = SecretVec::new(b"not a zip".to_vec());
            assert_eq!(s.import_1pux_bytes(&junk, cx), 0);
            let message = s.toast.as_ref().unwrap().message.to_string();
            assert!(message.contains("not a valid zip archive"), "{message}");
            assert_eq!(s.item_count(), 3);
        });
    }
}
