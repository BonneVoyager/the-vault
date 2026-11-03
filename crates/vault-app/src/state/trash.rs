//! Recently Deleted (specs/05-ui.md §2.3, 02 "Recently Deleted"): the trashed item shown
//! read-only, Recover, Delete permanently, and the 30-day sweep.

use gpui::Context;
use vault_core::{Item, Millis, Uuid};

use super::edit::edit_result;
use super::{AppState, Filter, Mode};
use crate::text;

/// How long a deleted item stays recoverable.
pub const TRASH_DAYS: u64 = 30;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const TRASH_MS: u64 = TRASH_DAYS * DAY_MS;

pub const TRASH_INFO: &str =
    "Deleted items are available here for 30 days before they are permanently deleted.";
pub const NO_DELETED_ITEMS: &str = "No Deleted Items";
pub const PURGE_CONFIRM: &str = "Delete permanently? This cannot be undone.";
pub const DELETE_RECOVERABLE: &str = "You can recover it from Recently Deleted for 30 days.";

/// Whole days (rounded up) until an item deleted at `deleted_at` is swept, at `now`.
/// 0 once due. A `deleted_at` ahead of the clock never yields more than [`TRASH_DAYS`].
pub fn days_left(deleted_at: Millis, now: Millis) -> u64 {
    let left = deleted_at.saturating_add(TRASH_MS).saturating_sub(now);
    left.div_ceil(DAY_MS).min(TRASH_DAYS)
}

/// The card under a trashed item's fields.
pub fn expiry_text(deleted_at: Millis, now: Millis) -> String {
    let when = match days_left(deleted_at, now) {
        0 => "today".to_owned(),
        1 => "in 1 day".to_owned(),
        n => format!("in {n} days"),
    };
    format!("This item will be permanently deleted {when} unless it is recovered.")
}

impl AppState {
    /// The Recently Deleted filter is showing on an unlocked main screen.
    pub fn viewing_trash(&self) -> bool {
        self.main_active() && self.filter == Filter::RecentlyDeleted
    }

    /// The selected item when it is in the trash and the trash is showing. Never a live
    /// item, never a stripped tombstone.
    pub fn trashed_item(&self) -> Option<&Item> {
        if self.filter != Filter::RecentlyDeleted {
            return None;
        }
        let id = self.selection?;
        self.unlocked_vault()?
            .get(id)
            .filter(|i| i.is_deleted() && i.has_content())
    }

    /// The item the detail column reads from: the selected live item, else the selected
    /// trashed one. Read-only paths (copy, reveal, open URL) use this; every mutating path
    /// keeps using [`Self::selected_item`], which never returns a tombstone.
    pub fn viewed_item(&self) -> Option<&Item> {
        self.selected_item().or_else(|| self.trashed_item())
    }

    /// ⌘⇧Z / "Recover": take the trashed item back, then show it in All Items.
    pub fn recover_selected(&mut self, cx: &mut Context<Self>) {
        if !self.viewing_trash() {
            return;
        }
        let Some(id) = self.trashed_item().map(|i| i.id) else {
            return;
        };
        let now = text::now_millis();
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        if let Err(e) = edit_result(vault.edit(|v| v.recover(id, now))) {
            return self.show_toast(format!("Could not recover: {e}"), cx);
        }
        self.delete_confirm = None;
        self.mode = Mode::View;
        self.filter = Filter::All;
        self.vault_changed();
        self.reveal_new(id);
        self.schedule_autosave(cx);
        cx.notify();
    }

    /// The confirmed "Delete permanently": strip the tombstone, select the next row of the
    /// trash; nothing once the trash is empty (the filter then falls back to All Items).
    pub(super) fn purge(&mut self, id: Uuid, cx: &mut Context<Self>) {
        // The row that slides into the purged one's place, else the one before it. Taken
        // from the trash list now: `vault_changed` may switch the listing to All Items.
        let items = &self.listing.items;
        let next = items.iter().position(|i| *i == id).and_then(|at| {
            items
                .get(at + 1)
                .or_else(|| at.checked_sub(1).and_then(|b| items.get(b)))
                .copied()
        });
        let now = text::now_millis();
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        if let Err(e) = edit_result(vault.edit(|v| v.delete_permanently(id, now))) {
            return self.show_toast(format!("Could not delete: {e}"), cx);
        }
        self.vault_changed();
        let next = next.filter(|_| self.filter == Filter::RecentlyDeleted);
        self.set_selection(next);
        self.schedule_autosave(cx);
        cx.notify();
    }

    /// The sweep: strips every trashed item deleted more than [`TRASH_DAYS`] ago. Runs
    /// after an unlock and before a save. Returns how many it stripped; the vault is then
    /// dirty and the listing refreshed. A no-op while locked, and when nothing is due (so
    /// it never marks a clean vault dirty).
    pub(super) fn expire_trash(&mut self) -> usize {
        if self.locked {
            return 0;
        }
        let now = text::now_millis();
        let cutoff = now.saturating_sub(TRASH_MS);
        let Some(vault) = self.vault.as_mut() else {
            return 0;
        };
        let due = vault.vault().is_some_and(|v| {
            v.deleted_items()
                .any(|i| i.deleted_at.is_some_and(|d| d < cutoff))
        });
        if !due {
            return 0;
        }
        let stripped = vault
            .edit(|v| v.expire_deleted(cutoff, now))
            .unwrap_or_default();
        if stripped > 0 {
            self.vault_changed();
        }
        stripped
    }
}

#[cfg(test)]
#[path = "trash_tests.rs"]
mod tests;
