//! Main-screen session logic on `AppState` (specs/05-ui.md §2.3, §3, §4): the cached
//! listing, selection, favourites with debounced autosave, copy with auto-clear,
//! reveal, and focus requests. Views only render this state and call these methods.

use std::rc::Rc;
use std::time::Duration;

use gpui::Context;
use vault_core::totp::Totp;
use vault_core::{ExposeSecret, Field, FieldKind, Item, SecretString, UnlockedVault, Uuid};
use vault_sync::SyncedVault;

use super::edit::edit_result;
use super::{AppState, Filter, Mode, Navigation, Screen, Sort, ToastPlace};
use crate::listing::{self, username_field};
use crate::text;

/// 03 §8: save this long after the last edit.
pub const AUTOSAVE_DEBOUNCE: Duration = Duration::from_secs(2);
/// The "Copied" pill.
const COPIED_TTL: Duration = Duration::from_secs(2);

/// Focus moves requested by global actions (⌘F, ⌘1, ⌘2, ⏎).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusTarget {
    Search,
    List,
    Detail,
}

/// What a copy action copies from the selected item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyTarget {
    Username,
    Password,
    Totp,
    /// `item.fields[i]`; a TOTP field copies its current code.
    Field(usize),
    /// `item.history[i]`.
    History(usize),
}

/// Parses a TOTP field value: an `otpauth://` URI, or a bare base32 secret.
pub fn parse_totp(value: &SecretString) -> Option<Totp> {
    let raw = value.expose_secret();
    Totp::parse_uri(raw)
        .or_else(|_| Totp::from_secret_base32(raw))
        .ok()
}

fn first_of(item: &Item, kind: FieldKind) -> Option<&Field> {
    item.fields.iter().find(|f| f.kind == kind)
}

fn totp_code(field: &Field) -> Option<SecretString> {
    let totp = parse_totp(&field.value)?;
    Some(SecretString::new(totp.code(text::now_millis() / 1000)))
}

impl AppState {
    /// Resets everything tied to the unlocked session (lock, vault switch).
    pub(super) fn clear_session(&mut self) {
        self.kdbx_import = None;
        self.selection = None;
        self.mode = Mode::View;
        self.revealed.clear();
        self.history_open = false;
        self.query.clear();
        self.listing = listing::Listing::default();
        self.counts = listing::Counts::default();
        self.listing_version = self.listing_version.wrapping_add(1);
        self.focus_request = None;
        self.discard_prompt = None;
        self.delete_confirm = None;
        self.template_picker = None;
        self.generator_target = None;
    }

    /// The decrypted vault, only while the session is unlocked.
    pub fn unlocked_vault(&self) -> Option<&UnlockedVault> {
        if self.locked {
            return None;
        }
        self.vault.as_ref().and_then(SyncedVault::vault)
    }

    /// The selected live item. Tombstones are never returned.
    pub fn selected_item(&self) -> Option<&Item> {
        let id = self.selection?;
        self.unlocked_vault()?
            .get(id)
            .filter(|item| !item.is_deleted())
    }

    /// True when the main screen is up and item actions apply.
    pub fn main_active(&self) -> bool {
        self.screen == Screen::Main && !self.locked
    }

    /// The vault's contents changed (unlock, edit): recompute the sidebar counts and the
    /// listing. Query, filter and sort changes only need [`Self::refresh`].
    pub fn vault_changed(&mut self) {
        self.icon_images.invalidate();
        self.counts = self
            .unlocked_vault()
            .map(listing::counts)
            .unwrap_or_default();
        // Password warnings depend only on the contents, so audit here, not per refresh.
        self.listing.issues = Rc::new(
            self.unlocked_vault()
                .map(crate::audit::audit)
                .unwrap_or_default(),
        );
        self.refresh();
    }

    /// Recomputes the listing. Keeps the selection if it is still visible (or being
    /// edited, so a search never yanks the editor away), else selects the first visible item.
    pub fn refresh(&mut self) {
        let Some(vault) = self.unlocked_vault() else {
            self.listing = listing::Listing::default();
            self.listing_version = self.listing_version.wrapping_add(1);
            self.set_selection(None);
            return;
        };
        let issues = self.listing.issues.clone();
        let new_listing = listing::compute(vault, &self.query, &self.filter, self.sort, issues);
        self.listing = new_listing;
        self.listing_version = self.listing_version.wrapping_add(1);
        let keep = self
            .selection
            .is_some_and(|id| self.listing.items.contains(&id) || self.is_editing());
        if !keep {
            self.set_selection(self.listing.items.first().copied());
        }
    }

    pub(super) fn set_selection(&mut self, id: Option<Uuid>) {
        if self.selection != id {
            self.selection = id;
            self.revealed.clear();
            self.history_open = false;
            self.delete_confirm = None;
        }
    }

    pub fn set_query(&mut self, query: String, cx: &mut Context<Self>) {
        if self.query != query {
            self.query = query;
            self.refresh();
            cx.notify();
        }
    }

    pub fn set_filter(&mut self, filter: Filter, cx: &mut Context<Self>) {
        if self.filter != filter && self.guard(Navigation::Filter(filter.clone()), cx) {
            self.filter = filter;
            self.refresh();
            cx.notify();
        }
    }

    pub fn set_sort(&mut self, sort: Sort, cx: &mut Context<Self>) {
        if self.sort != sort {
            self.sort = sort;
            self.refresh();
            cx.notify();
        }
    }

    pub fn select(&mut self, id: Uuid, cx: &mut Context<Self>) {
        // Re-clicking the item being edited is not navigation. In New mode the highlighted
        // row is someone else's item, so it goes through the guard like any other.
        if self.selection == Some(id) && matches!(self.mode, Mode::Edit(_)) {
            return;
        }
        if self.listing.items.contains(&id) && self.guard(Navigation::Select(id), cx) {
            self.set_selection(Some(id));
            cx.notify();
        }
    }

    /// ↓ / ↑: move the selection by `delta` within the visible items, clamped.
    pub fn select_offset(&mut self, delta: isize, cx: &mut Context<Self>) {
        if self.listing.items.is_empty() || !self.guard(Navigation::Offset(delta), cx) {
            return;
        }
        let items = &self.listing.items;
        let next = match self
            .selection
            .and_then(|id| items.iter().position(|i| *i == id))
        {
            Some(ix) => ix.saturating_add_signed(delta).min(items.len() - 1),
            None => 0,
        };
        self.set_selection(Some(items[next]));
        cx.notify();
    }

    /// ⌘D: flips `favorite` on the selected item, then autosaves after the debounce.
    pub fn toggle_favorite(&mut self, cx: &mut Context<Self>) {
        if !self.main_active() {
            return;
        }
        let Some(id) = self.selected_item().map(|i| i.id) else {
            return;
        };
        let now = text::now_millis();
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        match edit_result(vault.edit(|v| v.update(id, now, |it| it.favorite = !it.favorite))) {
            Ok(()) => {
                self.vault_changed();
                self.schedule_autosave(cx);
            }
            Err(e) => self.show_toast(format!("Could not update item: {e}"), cx),
        }
        cx.notify();
    }

    /// Restarts the autosave timer; the save runs `AUTOSAVE_DEBOUNCE` after the last edit.
    pub fn schedule_autosave(&mut self, cx: &mut Context<Self>) {
        self.autosave_pending = true;
        self.autosave = Some(cx.spawn(async move |this, cx| {
            cx.background_executor().timer(AUTOSAVE_DEBOUNCE).await;
            this.update(cx, |this, cx| this.save_if_dirty(cx)).ok();
        }));
    }

    fn save_if_dirty(&mut self, cx: &mut Context<Self>) {
        self.autosave_pending = false;
        if !self.locked {
            self.save_now(cx);
        }
    }

    /// Copies a value of the selected item and schedules the clipboard clear.
    pub fn copy(&mut self, target: CopyTarget, cx: &mut Context<Self>) {
        if !self.main_active() {
            return;
        }
        let Some(item) = self.selected_item() else {
            return;
        };
        let (value, what) = match target {
            CopyTarget::Username => (username_field(item).map(|f| f.value.clone()), "username"),
            CopyTarget::Password => (
                first_of(item, FieldKind::Password).map(|f| f.value.clone()),
                "password",
            ),
            CopyTarget::Totp => (
                first_of(item, FieldKind::Totp).and_then(totp_code),
                "one-time code",
            ),
            CopyTarget::Field(i) => (
                item.fields.get(i).and_then(|f| match f.kind {
                    FieldKind::Totp => totp_code(f),
                    _ => Some(f.value.clone()),
                }),
                "value",
            ),
            CopyTarget::History(i) => (item.history.get(i).map(|h| h.value.clone()), "value"),
        };
        match value {
            Some(value) => self.copy_secret(value, cx),
            None => self.show_toast(format!("This item has no {what}"), cx),
        }
    }

    pub(super) fn copy_secret(&mut self, value: SecretString, cx: &mut Context<Self>) {
        let Some(secs) = self.copy_value_for_window(value, cx) else {
            return;
        };
        self.toast_at(
            format!("Copied — clears in {secs} s"),
            ToastPlace::Detail,
            COPIED_TTL,
            cx,
        );
    }

    /// Shared clipboard and expiry behavior; the calling window supplies its feedback.
    pub fn copy_value_for_window(
        &mut self,
        value: SecretString,
        cx: &mut Context<Self>,
    ) -> Option<u32> {
        let generation = self.clipboard.copy(&value);
        drop(value);
        let Some(generation) = generation else {
            self.show_toast("Could not copy to the clipboard", cx);
            return None;
        };
        let secs = self.settings.clipboard_clear_secs;
        self.clipboard_clear = Some(cx.spawn(async move |this, cx| {
            cx.background_executor()
                .timer(Duration::from_secs(u64::from(secs)))
                .await;
            this.update(cx, |this, _| this.clipboard.expire(generation))
                .ok();
        }));
        Some(secs)
    }

    /// Opens a URL field of the selected item in the default browser: `fields[ix]`, or
    /// the first URL field for ⌘⇧O. Only http/https are opened (see `text::browser_url`).
    pub fn open_url(&mut self, ix: Option<usize>, cx: &mut Context<Self>) {
        if !self.main_active() {
            return;
        }
        let raw = self.selected_item().and_then(|item| match ix {
            Some(i) => item.fields.get(i).filter(|f| f.kind == FieldKind::Url),
            None => first_of(item, FieldKind::Url),
        });
        let Some(raw) = raw.map(|f| f.value.expose_secret().to_string()) else {
            self.show_toast("This item has no website", cx);
            return;
        };
        match text::browser_url(&raw) {
            Some(url) => cx.open_url(&url),
            None => self.show_toast("Can't open this link", cx),
        }
    }

    /// Reveal toggle for one field (password, card number).
    pub fn toggle_reveal(&mut self, name: &str, cx: &mut Context<Self>) {
        if !self.revealed.remove(name) {
            self.revealed.insert(name.to_owned());
        }
        cx.notify();
    }

    /// ⌘⇧R: toggles the first password field of the selected item.
    pub fn toggle_reveal_password(&mut self, cx: &mut Context<Self>) {
        if !self.main_active() {
            return;
        }
        let name = self
            .selected_item()
            .and_then(|item| first_of(item, FieldKind::Password))
            .map(|f| f.name.clone());
        if let Some(name) = name {
            self.toggle_reveal(&name, cx);
        }
    }

    pub fn toggle_history(&mut self, cx: &mut Context<Self>) {
        self.history_open = !self.history_open;
        cx.notify();
    }

    pub fn toggle_tags(&mut self, cx: &mut Context<Self>) {
        self.tags_open = !self.tags_open;
        cx.notify();
    }

    /// Whether the main window shows its sidebar (persisted in `settings.json`).
    pub fn sidebar_visible(&self) -> bool {
        !self.settings.sidebar_hidden
    }

    /// ⌃⌘S, View ▸ Hide/Show Sidebar and the list's sidebar button. Keeps the filter,
    /// selection and focus; persists through `update_settings`; updates the window
    /// minimum (narrower while collapsed).
    pub fn toggle_sidebar(&mut self, cx: &mut Context<Self>) {
        self.sidebar_toggles = self.sidebar_toggles.wrapping_add(1);
        self.update_settings(cx, |s| s.sidebar_hidden = !s.sidebar_hidden);
        crate::ui::apply_main_min_size(self.sidebar_visible());
    }

    pub fn request_focus(&mut self, target: FocusTarget, cx: &mut Context<Self>) {
        if self.main_active() {
            self.focus_request = Some(target);
            cx.notify();
        }
    }

    #[cfg(test)]
    pub fn set_pasteboard(&mut self, board: Box<dyn crate::clipboard::Pasteboard>) {
        self.clipboard = crate::clipboard::Clipboard::new(board);
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use gpui::{AppContext as _, Entity, TestAppContext};
    use vault_core::KdfParams;
    use vault_sync::NoopHooks;

    use super::*;
    use crate::clipboard::fake::FakePasteboard;

    /// An unlocked state over a fresh vault with three items.
    fn state_with_items(dir: &Path, cx: &mut TestAppContext) -> (Entity<AppState>, [Uuid; 3]) {
        let mut vault = SyncedVault::create(
            &dir.join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        let ids = vault
            .edit(|v| {
                let mut gh = crate::templates::tagged(
                    crate::templates::Template::Login,
                    "GitHub",
                    device,
                    10,
                );
                gh.fields.push(Field::new(
                    "username",
                    FieldKind::Text,
                    SecretString::new("chris".into()),
                    10,
                ));
                gh.fields.push(Field::new(
                    "password",
                    FieldKind::Password,
                    SecretString::new("hunter2".into()),
                    10,
                ));
                gh.fields.push(Field::new(
                    "totp",
                    FieldKind::Totp,
                    SecretString::new(TOTP_URI.into()),
                    10,
                ));
                let note = Item::new("Alarm code", device, 30);
                let card =
                    crate::templates::tagged(crate::templates::Template::Card, "Visa", device, 20);
                [v.insert(gh, 10), v.insert(note, 30), v.insert(card, 20)]
            })
            .unwrap();
        vault.save().unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| {
            s.install(vault, false);
            s.unlocked();
        });
        (state, ids)
    }

    const TOTP_SECRET: &str = "JBSWY3DPEHPK3PXP";
    const TOTP_URI: &str = "otpauth://totp/GitHub:chris?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";

    #[gpui::test]
    fn totp_copy_puts_only_the_code_on_the_pasteboard(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, [gh, ..]) = state_with_items(dir.path(), cx);
        let board = FakePasteboard::default();
        let totp_ix = state.update(cx, |s, cx| {
            s.set_pasteboard(Box::new(board.clone()));
            s.select(gh, cx);
            s.selected_item()
                .unwrap()
                .fields
                .iter()
                .position(|f| f.kind == FieldKind::Totp)
                .unwrap()
        });
        let expected = parse_totp(&SecretString::new(TOTP_URI.into())).unwrap();
        for target in [CopyTarget::Totp, CopyTarget::Field(totp_ix)] {
            board.set("");
            state.update(cx, |s, cx| s.copy(target, cx));
            let copied = board.contents().unwrap();
            assert_eq!(copied.len(), 6, "{target:?}");
            assert!(copied.chars().all(|c| c.is_ascii_digit()), "{target:?}");
            assert!(!copied.contains("otpauth") && !copied.contains(TOTP_SECRET));
            // The code for now (or the step that just started, if the test straddled one).
            let now = text::now_millis() / 1000;
            assert!(
                copied == expected.code(now) || copied == expected.code(now.saturating_sub(1)),
                "{target:?}"
            );
        }
    }

    #[gpui::test]
    fn reveal_resets_on_selection_change_and_lock(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, [gh, note, _]) = state_with_items(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.select(gh, cx);
            s.toggle_reveal_password(cx);
            s.toggle_history(cx);
            assert!(s.revealed.contains("password"));
            assert!(s.history_open);
            s.select(note, cx);
            assert!(s.revealed.is_empty(), "selection change hides secrets");
            assert!(!s.history_open);

            s.select(gh, cx);
            s.toggle_reveal_password(cx);
            assert!(s.revealed.contains("password"));
            s.lock(cx);
            assert!(s.revealed.is_empty(), "lock hides secrets");
        });
        // After unlocking again nothing is revealed.
        state.update(cx, |s, cx| s.unlock(SecretString::new("pw".into()), cx));
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(!s.locked);
            assert!(s.revealed.is_empty());
        });
    }

    #[gpui::test]
    fn non_web_links_are_not_opened(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, [gh, ..]) = state_with_items(dir.path(), cx);
        state.update(cx, |s, cx| {
            let now = text::now_millis();
            let vault = s.vault.as_mut().unwrap();
            vault
                .edit(|v| {
                    v.update(gh, now, |it| {
                        it.fields.push(Field::new(
                            "website",
                            FieldKind::Url,
                            SecretString::new("file:///etc/passwd".into()),
                            0,
                        ));
                    })
                })
                .unwrap()
                .unwrap();
            s.vault_changed();
            s.select(gh, cx);
            s.open_url(None, cx);
            assert_eq!(
                s.toast.as_ref().unwrap().message.as_ref(),
                "Can't open this link"
            );
        });
    }

    #[gpui::test]
    fn listing_follows_query_filter_and_sort(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, [gh, note, card]) = state_with_items(dir.path(), cx);
        state.update(cx, |s, cx| {
            assert_eq!(s.listing.items, [note, gh, card], "A–Z by default");
            assert_eq!(s.selection, Some(note), "first item selected on unlock");
            assert_eq!(s.counts.all, 3);

            let v0 = s.listing_version;
            s.set_sort(Sort::RecentlyModified, cx);
            assert_eq!(s.listing.items, [note, card, gh]);
            assert_ne!(s.listing_version, v0);

            s.select(gh, cx);
            s.set_query("git".into(), cx);
            assert_eq!(s.listing.items, [gh]);
            assert_eq!(s.selection, Some(gh));

            s.set_query("visa".into(), cx);
            assert_eq!(
                s.selection,
                Some(card),
                "hidden selection moves to first hit"
            );
            s.set_query("nothing matches".into(), cx);
            assert!(s.listing.items.is_empty());
            assert_eq!(s.selection, None);

            s.set_query(String::new(), cx);
            s.set_filter(Filter::Tag("login".into()), cx);
            assert_eq!(s.listing.items, [gh]);
            s.set_filter(Filter::Favorites, cx);
            assert!(s.listing.items.is_empty());
        });
    }

    #[gpui::test]
    fn arrows_clamp_at_the_ends(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, [gh, note, card]) = state_with_items(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.select_offset(-1, cx);
            assert_eq!(s.selection, Some(note));
            s.select_offset(1, cx);
            assert_eq!(s.selection, Some(gh));
            s.select_offset(5, cx);
            assert_eq!(s.selection, Some(card));
        });
    }

    #[gpui::test]
    fn favorite_marks_dirty_and_autosaves_after_debounce(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, [gh, ..]) = state_with_items(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.select(gh, cx);
            s.toggle_favorite(cx);
            assert!(s.vault.as_ref().unwrap().is_dirty());
            assert_eq!(s.counts.favorites, 1);
            assert!(s.selected_item().unwrap().favorite);
        });
        cx.executor().advance_clock(Duration::from_millis(1500));
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(s.vault.as_ref().unwrap().is_dirty(), "not before 2 s");
        });
        // A second edit restarts the debounce.
        state.update(cx, |s, cx| s.toggle_favorite(cx));
        cx.executor().advance_clock(Duration::from_millis(1500));
        cx.run_until_parked();
        state.read_with(cx, |s, _| assert!(s.vault.as_ref().unwrap().is_dirty()));
        cx.executor().advance_clock(Duration::from_millis(600));
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(
                !s.vault.as_ref().unwrap().is_dirty(),
                "saved after debounce"
            );
            assert!(!s.selected_item().unwrap().favorite);
        });
    }

    /// ⌘⇧U and the list subtitle find the username in any case: an imported or
    /// CLI-created lowercase "username" and a template's "Username" behave the same.
    #[gpui::test]
    fn copy_username_ignores_the_name_case(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _) = state_with_items(dir.path(), cx);
        let board = FakePasteboard::default();
        let ids = state.update(cx, |s, cx| {
            s.set_pasteboard(Box::new(board.clone()));
            let device = s.device_id();
            let ids = s
                .vault
                .as_mut()
                .unwrap()
                .edit(|v| {
                    let mut imported = Item::new("Imported", device, 40);
                    imported.fields = vec![Field::new(
                        "username",
                        FieldKind::Text,
                        SecretString::new("lower".into()),
                        40,
                    )];
                    let mut templ = crate::templates::Template::Login.new_item("Templ", device, 40);
                    templ.fields[0].value = SecretString::new("upper".into());
                    [v.insert(imported, 40), v.insert(templ, 40)]
                })
                .unwrap();
            s.vault_changed();
            cx.notify();
            ids
        });
        for (id, want) in ids.into_iter().zip(["lower", "upper"]) {
            state.update(cx, |s, cx| {
                s.select(id, cx);
                let item = s.selected_item().unwrap();
                assert_eq!(crate::listing::subtitle(item), want, "subtitle");
                s.copy(CopyTarget::Username, cx);
            });
            assert_eq!(board.contents().as_deref(), Some(want), "⌘⇧U");
        }
    }

    #[gpui::test]
    fn clipboard_clears_only_when_unchanged(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, [gh, ..]) = state_with_items(dir.path(), cx);
        let board = FakePasteboard::default();
        state.update(cx, |s, cx| {
            s.set_pasteboard(Box::new(board.clone()));
            s.settings.clipboard_clear_secs = 30;
            s.select(gh, cx);
            s.copy(CopyTarget::Password, cx);
            assert!(s.toast.as_ref().unwrap().message.contains("clears in 30 s"));
        });
        assert_eq!(board.contents().as_deref(), Some("hunter2"));
        cx.executor().advance_clock(Duration::from_secs(31));
        cx.run_until_parked();
        assert_eq!(board.contents(), None, "cleared after the timeout");
        state.read_with(cx, |s, _| assert!(s.toast.is_none(), "pill dismissed"));

        // The user copies something else meanwhile: leave it alone.
        state.update(cx, |s, cx| s.copy(CopyTarget::Username, cx));
        assert_eq!(board.contents().as_deref(), Some("chris"));
        board.set("from another app");
        cx.executor().advance_clock(Duration::from_secs(31));
        cx.run_until_parked();
        assert_eq!(board.contents().as_deref(), Some("from another app"));

        // Lock clears our copy immediately, guarded by the change count of our write.
        state.update(cx, |s, cx| s.copy(CopyTarget::Password, cx));
        let ours = board.change_count();
        state.update(cx, |s, cx| s.lock(cx));
        assert_eq!(board.clear_calls().last(), Some(&ours));
        assert_eq!(board.contents(), None);
        state.read_with(cx, |s, _| {
            assert!(s.listing.items.is_empty());
            assert!(s.selected_item().is_none());
        });
    }

    #[gpui::test]
    fn lock_leaves_a_later_copy_from_another_app(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, [gh, ..]) = state_with_items(dir.path(), cx);
        let board = FakePasteboard::default();
        state.update(cx, |s, cx| {
            s.set_pasteboard(Box::new(board.clone()));
            s.select(gh, cx);
            s.copy(CopyTarget::Password, cx);
        });
        let ours = board.change_count();
        board.set("from another app");
        state.update(cx, |s, cx| s.lock(cx));
        assert_eq!(
            board.clear_calls(),
            vec![ours],
            "cleared with our count, once"
        );
        assert_eq!(board.contents().as_deref(), Some("from another app"));
        // A second lock has nothing of ours left to clear.
        state.update(cx, |s, cx| s.lock(cx));
        assert_eq!(board.clear_calls().len(), 1);
    }

    #[gpui::test]
    fn actions_are_inert_while_locked(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _) = state_with_items(dir.path(), cx);
        let board = FakePasteboard::default();
        state.update(cx, |s, cx| {
            s.set_pasteboard(Box::new(board.clone()));
            s.lock(cx);
            s.copy(CopyTarget::Password, cx);
            s.toggle_favorite(cx);
            s.select_offset(1, cx);
            s.toggle_reveal_password(cx);
            s.request_focus(FocusTarget::Search, cx);
            assert!(s.focus_request.is_none());
            assert!(s.selection.is_none());
        });
        assert_eq!(board.contents(), None);
    }
}
