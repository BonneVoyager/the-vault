//! The read-only backup viewer's hooks into the live vault (specs/03-sync.md §4):
//! opening the window, copying a value, copying an item across.

use std::path::PathBuf;

use gpui::Context;
use vault_core::{Item, SecretString, Uuid};

use super::AppState;
use super::edit::edit_result;
use crate::text;

impl AppState {
    /// "Open" on a backup row: a second, read-only window that asks for the backup's
    /// password. Only while the live vault is unlocked; the window closes when it locks.
    pub fn open_backup(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        if self.locked || self.vault.is_none() {
            return self.show_toast("Unlock the vault to open a backup", cx);
        }
        let state = cx.entity();
        if let Err(e) = crate::screens::open_backup_window(state, path, cx) {
            self.show_toast(format!("Could not open the backup: {e}"), cx);
        }
    }

    /// Copies a value shown in the backup window, with the usual clear timer.
    pub fn copy_value(&mut self, value: SecretString, cx: &mut Context<Self>) {
        self.copy_secret(value, cx);
    }

    /// "Copy to current vault": inserts a clone of `item` under a fresh id (so it never
    /// overwrites the live item it came from) and autosaves. Returns the new id.
    pub fn copy_item_into_vault(&mut self, item: &Item, cx: &mut Context<Self>) -> Option<Uuid> {
        if !self.main_active() {
            self.show_toast("Unlock the vault to copy items into it", cx);
            return None;
        }
        let mut copy = item.clone();
        copy.id = Uuid::new_v4();
        copy.deleted_at = None;
        let now = text::now_millis();
        let title = copy.title.clone();
        let result = self.vault.as_mut()?.edit(|v| Ok(v.insert(copy, now)));
        match edit_result(result) {
            Ok(id) => {
                self.vault_changed();
                self.schedule_autosave(cx);
                self.show_toast(
                    format!("Copied \u{2018}{title}\u{2019} into this vault"),
                    cx,
                );
                Some(id)
            }
            Err(e) => {
                self.show_toast(format!("Could not copy the item: {e}"), cx);
                None
            }
        }
    }
}
