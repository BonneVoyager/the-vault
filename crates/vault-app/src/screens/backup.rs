//! Read-only backup viewer (specs/03-sync.md §4 "Restore"): a second window that opens a
//! backup file with its master password and shows its items in a list and a detail pane.
//!
//! The backup is parsed and unlocked directly (`LockedVault::parse` + `unlock`) on the
//! background executor: no `SyncedVault`, no watcher, nothing is ever written to the backup.
//! The only ways out are copying a value (concealed clipboard, usual clear timer), "Copy to
//! current vault" (a clone with a fresh id) and "Replace current vault with this backup"
//! (the existing restore flow). It looks like the main window in read mode (owner
//! 2026-11-22): the main list's rows and search field (`list::item_row`, `search_field`)
//! and the shared read-mode detail (`ReadDetail` with `ItemSource::Backup`), with the main
//! sidebar column (`sidebar_column`) at its left, under one strip in the title-bar band. It closes, dropping the decrypted backup, as soon as the
//! live vault locks.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use gpui::{
    AnyElement, App, AppContext as _, Context, Entity, FocusHandle, FontWeight,
    InteractiveElement as _, IntoElement, ListAlignment, ListState, ParentElement as _, Render,
    SharedString, Styled as _, Subscription, Task, Window, div, list, prelude::FluentBuilder as _,
    px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{InputEvent, InputState, MoveDown};
use gpui_component::{ActiveTheme as _, Disableable as _, Root, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{
    ExposeSecret as _, FieldKind, Item, LockedVault, SecretString, UnlockedVault, Uuid,
};
use vault_sync::{BackupInfo, BackupKind, SyncError};
use zeroize::Zeroizing;

use super::main::detail::{DetailAction, DetailActions, ItemSource, ReadDetail, rows_width};
use super::main::list::{group_header, item_row, item_row_height, search_field, sort_menu};
use super::main::sidebar::{SidebarColumn, sidebar_column};
use super::main::{LIST, SIDEBAR, fit_widths};
use crate::actions::{CopyUsername, FocusDetail, LIST_CONTEXT, NextItem, PrevItem, Search};
use crate::listing::{self, Counts, Listing, Row};
use crate::state::{AppState, COPIED_TTL, CopyTarget, Filter, Sort, disk_name, parse_totp};
use crate::ui::Clickable as _;
use crate::{audit, text, theme, ui};

pub struct BackupWindow {
    state: Entity<AppState>,
    /// The password card's name and second line (see [`open_backup_window`]).
    vault_name: SharedString,
    subtitle: SharedString,
    path: PathBuf,
    password: Entity<InputState>,
    /// The decrypted backup. Dropped (zeroized) with the window, or as soon as the live
    /// vault locks. Read only through [`Self::live_vault`].
    vault: Option<UnlockedVault>,
    /// `AppState::session_gen` when the backup was unlocked: the vault is usable only while
    /// the live session is still that one and unlocked.
    session: Option<(u64, u64)>,
    /// The list as shown: the backup's items matching the search query, in `sort` order
    /// (relevance while searching; group headers only for Name order without a query),
    /// through the main list's `listing::compute`; and the backup's password notices
    /// judged against its own items.
    listing: Listing,
    list_state: ListState,
    /// The list's search field; its query is local to this window.
    search: Entity<InputState>,
    /// The list order, local to this window: the main window's order when the backup
    /// was unlocked (not read in `new`: `AppState::open_backup` opens this window from
    /// inside its own update, where reading the state panics).
    sort: Sort,
    sort_menu_open: bool,
    /// The sidebar's filter and Tags state, local to this window (Tags starts as the main
    /// window's when the backup is unlocked, read then for the reason `sort` is).
    filter: Filter,
    tags_open: bool,
    /// The sidebar's counts over the backup's items, computed once when it opens.
    counts: Counts,
    sort_focus: FocusHandle,
    selection: Option<Uuid>,
    /// Field ids of the selected item whose values are revealed.
    revealed: HashSet<Uuid>,
    history_open: bool,
    /// Why the backup could not be opened, other than a wrong password (unreadable,
    /// refused, newer format): shown as text under the field.
    error: Option<SharedString>,
    /// Wrong passwords so far: each one shakes the field (keyed on this counter), with no
    /// error line, so the card never changes height (as the main unlock screen).
    failures: u32,
    /// `AppState::reduce_motion`, cached: the first frame is drawn while
    /// `AppState::open_backup` still updates the state, where reading it panics. Taken
    /// when an unlock finishes and on every state change.
    reduce_motion: bool,
    /// The copy pill pinned at the bottom of the detail column, and its clear timer.
    status: Option<SharedString>,
    status_clear: Option<Task<()>>,
    busy: bool,
    /// Hold ⌥ to reveal, for this window only (05 §2.3), as in item windows.
    option_reveal: bool,
    /// Tracked on the window's root: ⌥ and ⌘F follow the focus path.
    focus: FocusHandle,
    /// The list column: a focused list draws its selection active.
    list_focus: FocusHandle,
    /// The detail column: ⏎ in the list moves here, as in the main window.
    detail_focus: FocusHandle,
    /// Set when the backup opens: the next render moves focus from the (gone) password
    /// field to the list, so ⌥ and ⌘F reach this window.
    focus_list: bool,
    /// Redraws once a second while open so a TOTP code stays current.
    _ticker: Task<()>,
    _subscriptions: Vec<Subscription>,
}

/// The vault file to read for a backup entry: a snapshot is a `.vault.bin` file, an
/// absorbed conflict copy is a whole package directory (03 §6). Decided without following a
/// link: a symlinked entry is passed on as itself, and [`read_backup`] refuses it.
fn backup_file(path: &Path) -> PathBuf {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => path.join(vault_sync::VAULT_FILE_NAME),
        _ => path.to_owned(),
    }
}

/// Reads the backup at `path` like the package reads its own files (03 §2): capped, never
/// through a link (D-1), only a regular file. Errors are worded for the viewer, without the
/// path (the window title already names the backup).
fn read_backup(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    vault_sync::read_package_entry_capped(&backup_file(path))
        .map(Zeroizing::new)
        .map_err(|e| match e {
            SyncError::UnsafePackageEntry(_) => "This backup is a link or not a regular file. \
                 Vault does not open links in the backups folder; move it out of the folder to \
                 open it."
                .to_owned(),
            SyncError::PrimaryTooLarge(_) => format!(
                "This backup is larger than the {} MiB limit for a vault file.",
                vault_sync::MAX_VAULT_FILE_SIZE / (1024 * 1024)
            ),
            SyncError::Io { source, .. } => format!("Could not read the backup: {source}"),
            other => other.to_string(),
        })
}

/// Left padding of the strip: past the traffic lights with a 24 px gap (owner eye check
/// 2026-11-22: the list header's 12 px gap read as cramped next to the name).
const STRIP_PAD_LEFT: f32 = ui::TRAFFIC_LIGHTS_RIGHT + 24.;

/// The prompt card's second line (05 §2.3 "Backup viewer"): the backup's kind and the
/// time in its file name, worded and formatted like the Settings backups list; the file
/// name when it is not one of ours (no timestamp parsed).
fn backup_subtitle(info: Option<&BackupInfo>, path: &Path) -> String {
    let Some(info) = info else {
        return disk_name(path);
    };
    let kind = match info.kind {
        BackupKind::Snapshot => "Backup",
        BackupKind::Conflict => "Conflict copy",
        BackupKind::Unsaved => "Unsaved copy",
    };
    format!(
        "{kind} from {} \u{b7} read-only",
        text::date_time(info.taken_at)
    )
}

/// The password card's button (05 §2.3 "Backup viewer").
const OPEN_LABEL: &str = "Open read-only";

/// "Backup — <file name>": the strip's title and the window title (Dock, Window menu).
fn backup_title(path: &Path) -> String {
    format!("Backup \u{2014} {}", disk_name(path))
}

/// Opens the viewer for `path` in a new window: the main window's chrome (transparent
/// title bar, traffic lights inline, moved only from the band).
///
/// `info` is the backups-list entry for `path` (its kind and time, `None` when unknown)
/// and `vault_name` the open vault's name, both shown on the password card; passed in
/// because `AppState` cannot be read while it opens this window.
pub fn open_backup_window(
    state: Entity<AppState>,
    path: PathBuf,
    info: Option<BackupInfo>,
    vault_name: String,
    cx: &mut App,
) -> gpui::Result<gpui::AnyWindowHandle> {
    let title = backup_title(&path);
    let options = ui::main_window_options(None, cx);
    let handle = cx.open_window(options, |window, cx| {
        window.set_window_title(&title);
        theme::apply(window, cx);
        let view =
            cx.new(|cx| BackupWindow::new(state, path, info.as_ref(), vault_name, window, cx));
        cx.new(|cx| Root::new(view, window, cx))
    })?;
    Ok(handle.into())
}

impl BackupWindow {
    pub fn new(
        state: Entity<AppState>,
        path: PathBuf,
        info: Option<&BackupInfo>,
        vault_name: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        // The main unlock screen's placeholder (05 §2.2).
        let password = ui::password_input(ui::MASTER_PASSWORD_PLACEHOLDER, window, cx);
        let subtitle = backup_subtitle(info, &path).into();
        let vault_name = if vault_name.is_empty() {
            disk_name(&path)
        } else {
            vault_name
        }
        .into();
        let search = ui::text_input("Search", window, cx);
        // Esc in the search field clears it (and refilters through its Change event).
        search.update(cx, |s, _| s.set_clean_on_escape(true));
        ui::focus_input(&password, window, cx);
        let focus = cx.focus_handle();
        let subscriptions = vec![
            cx.subscribe_in(&password, window, |this, _, ev: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = ev {
                    this.submit(window, cx);
                }
            }),
            cx.subscribe_in(
                &search,
                window,
                |this, _, ev: &InputEvent, window, cx| match ev {
                    InputEvent::Change => this.refilter(cx),
                    // As the main list: ⏎ in the search field moves to the list.
                    InputEvent::PressEnter { .. } => window.focus(&this.list_focus, cx),
                    _ => {}
                },
            ),
            // Never outlive the live session: drop the keys and close when it locks.
            cx.observe_in(&state, window, |this, state, window, cx| {
                this.reduce_motion = state.read(cx).reduce_motion;
                if state.read(cx).locked {
                    this.forget();
                    window.remove_window();
                }
            }),
            // A key-up while another window is key never reaches this one.
            cx.observe_window_activation(window, |this, window, cx| {
                if !window.is_window_active() {
                    this.set_option_reveal(false, cx);
                }
            }),
            cx.on_focus_out(&focus, window, |this: &mut Self, _, _, cx| {
                this.set_option_reveal(false, cx);
            }),
        ];
        Self {
            state,
            vault_name,
            subtitle,
            path,
            password,
            vault: None,
            session: None,
            listing: Listing::default(),
            list_state: ListState::new(0, ListAlignment::Top, px(200.)),
            search,
            sort: Sort::Alphabetical,
            sort_menu_open: false,
            filter: Filter::All,
            tags_open: true,
            counts: Counts::default(),
            sort_focus: cx.focus_handle(),
            selection: None,
            revealed: HashSet::new(),
            history_open: false,
            error: None,
            failures: 0,
            reduce_motion: false,
            status: None,
            status_clear: None,
            busy: false,
            option_reveal: false,
            focus,
            list_focus: cx.focus_handle().tab_stop(true),
            detail_focus: cx.focus_handle(),
            focus_list: false,
            _ticker: cx.spawn(async move |this, cx| {
                loop {
                    cx.background_executor().timer(Duration::from_secs(1)).await;
                    let alive = this.update(cx, |this, cx| {
                        if this.vault.is_some() {
                            cx.notify();
                        }
                    });
                    if alive.is_err() {
                        break;
                    }
                }
            }),
            _subscriptions: subscriptions,
        }
    }

    #[cfg(test)]
    pub fn is_open(&self) -> bool {
        self.vault.is_some()
    }

    /// The listed item ids, in list order.
    #[cfg(test)]
    pub fn item_ids(&self) -> &[Uuid] {
        &self.listing.items
    }

    /// True while the live vault is still the unlocked session this backup was opened in.
    fn session_live(&self, cx: &App) -> bool {
        let state = self.state.read(cx);
        !state.locked && self.session == Some(state.session_gen())
    }

    /// The decrypted backup, only while [`Self::session_live`]: between a lock and the
    /// window's (deferred) removal nothing can read or copy from it.
    fn live_vault(&self, cx: &App) -> Option<&UnlockedVault> {
        self.vault.as_ref().filter(|_| self.session_live(cx))
    }

    fn item(&self, id: Uuid, cx: &App) -> Option<&Item> {
        self.live_vault(cx)?.get(id)
    }

    fn selected_item(&self, cx: &App) -> Option<&Item> {
        self.item(self.selection?, cx)
    }

    /// Drops (zeroizes) the decrypted backup and everything derived from it.
    fn forget(&mut self) {
        self.vault = None;
        self.session = None;
        self.listing = Listing::default();
        self.counts = Counts::default();
        self.list_state.reset(0);
        self.selection = None;
        self.revealed.clear();
        self.option_reveal = false;
    }

    /// Reads and unlocks the backup on the background executor.
    fn submit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy || ui::input_is_empty(&self.password, cx) {
            return;
        }
        let password = ui::input_secret(&self.password, cx);
        // The rope (and its undo history) must not keep the password.
        ui::clear_input(&self.password, window, cx);
        self.unlock(password, cx);
    }

    pub fn unlock(&mut self, password: SecretString, cx: &mut Context<Self>) {
        self.busy = true;
        self.error = None;
        cx.notify();
        let path = self.path.clone();
        let started = self.state.read(cx).session_gen();
        // `Err(None)`: wrong password (a shake); `Err(Some(text))`: any other failure.
        let task = cx.background_executor().spawn(async move {
            // Capped and never through a link, like every vault-file read (03 §2).
            let bytes = read_backup(&path).map_err(Some)?;
            let locked = LockedVault::parse(&bytes).map_err(|e| Some(e.to_string()))?;
            locked.unlock(&password).map_err(|e| match e {
                vault_core::VaultError::WrongPassword => None,
                other => Some(other.to_string()),
            })
        });
        cx.spawn(async move |this, cx| {
            let result = task.await;
            this.update(cx, |this, cx| {
                this.busy = false;
                let state = this.state.read(cx);
                let fresh = !state.locked && state.session_gen() == started;
                this.reduce_motion = state.reduce_motion;
                match result {
                    Ok(vault) if fresh => this.opened(vault, started, cx),
                    // The live vault locked (or closed) meanwhile: drop the keys unseen.
                    Ok(vault) => drop(vault),
                    Err(None) => this.failures = this.failures.wrapping_add(1),
                    Err(Some(e)) => this.error = Some(e.into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn opened(&mut self, vault: UnlockedVault, session: (u64, u64), cx: &mut Context<Self>) {
        // Notices against the backup's own items (05 §2.3), once per open.
        let issues = Rc::new(audit::audit(&vault));
        self.counts = listing::counts(&vault);
        self.vault = Some(vault);
        self.session = Some(session);
        let state = self.state.read(cx);
        (self.sort, self.tags_open) = (state.sort, state.tags_open);
        self.listing.issues = issues;
        self.refilter(cx);
        self.selection = self.listing.items.first().copied();
        self.focus_list = true;
    }

    /// A sidebar row: shows `filter` (selection rules as for a query).
    fn set_filter(&mut self, filter: Filter, cx: &mut Context<Self>) {
        self.filter = filter;
        self.refilter(cx);
    }

    /// Recomputes the list for the current query, filter and `sort` with the main list's matcher
    /// and ordering. A selection the query hides moves to the first hit.
    fn refilter(&mut self, cx: &mut Context<Self>) {
        let Some(vault) = self.vault.as_ref() else {
            return;
        };
        let query = self.search.read(cx).value().to_string();
        self.listing = listing::compute(
            vault,
            &query,
            &self.filter,
            self.sort,
            self.listing.issues.clone(),
        );
        self.list_state.reset(self.listing.rows.len());
        if self
            .selection
            .is_some_and(|id| !self.listing.items.contains(&id))
        {
            self.selection = self.listing.items.first().copied();
            self.revealed.clear();
            self.history_open = false;
            self.option_reveal = false;
        }
        cx.notify();
    }

    /// Selects `id`. Like the main window's selection, a different item starts with
    /// nothing revealed, history closed and no ⌥ peek carried over.
    fn select(&mut self, id: Uuid, cx: &mut Context<Self>) {
        if self.selection != Some(id) {
            self.selection = Some(id);
            self.revealed.clear();
            self.history_open = false;
            self.option_reveal = false;
        }
        cx.notify();
    }

    /// Follows ⌥ in this window; re-renders only when the flag flips.
    fn set_option_reveal(&mut self, held: bool, cx: &mut Context<Self>) {
        if self.option_reveal != held {
            self.option_reveal = held;
            cx.notify();
        }
    }

    /// The shared detail's callbacks, routed to this window's backup item.
    fn act(&mut self, action: DetailAction, cx: &mut Context<Self>) {
        match action {
            DetailAction::Reveal(field) => {
                if !self.revealed.remove(&field) {
                    self.revealed.insert(field);
                }
                cx.notify();
            }
            DetailAction::ToggleHistory => {
                self.history_open = !self.history_open;
                cx.notify();
            }
            DetailAction::Copy(target) => self.copy(target, cx),
            DetailAction::CopyHistory(stamp, field) => {
                let ix = self.selected_item(cx).and_then(|item| {
                    item.history
                        .iter()
                        .position(|h| h.replaced_at == stamp && h.field_id == field)
                });
                if let Some(ix) = ix {
                    self.copy(CopyTarget::History(ix), cx);
                }
            }
            DetailAction::OpenUrl(ix) => {
                let url = self
                    .selected_item(cx)
                    .and_then(|item| item.fields.get(ix))
                    .filter(|f| f.kind == FieldKind::Url)
                    .and_then(|field| text::browser_url(field.value.expose_secret()));
                if let Some(url) = url {
                    cx.open_url(&url);
                }
            }
        }
    }

    /// Copies field `ix` of the selected item (a TOTP field copies the current code).
    #[cfg(test)]
    pub fn copy_field(&mut self, ix: usize, cx: &mut Context<Self>) {
        let field = self
            .selected_item(cx)
            .and_then(|i| i.fields.get(ix))
            .map(|f| f.id);
        if let Some(field) = field {
            self.copy(CopyTarget::Field(field), cx);
        }
    }

    fn copy(&mut self, target: CopyTarget, cx: &mut Context<Self>) {
        let value = self.selected_item(cx).and_then(|item| match target {
            CopyTarget::Field(id) => item.field_by_id(id).and_then(|field| match field.kind {
                FieldKind::Totp => parse_totp(&field.value)
                    .map(|totp| SecretString::new(totp.code(text::now_millis() / 1000))),
                // A heading has nothing to copy; its stored value never leaves the vault.
                FieldKind::Section => None,
                _ => Some(field.value.clone()),
            }),
            CopyTarget::History(ix) => item.history.get(ix).map(|h| h.value.clone()),
            // ⌘C in the list, as in the main window.
            CopyTarget::Username => listing::username_field(item).map(|f| f.value.clone()),
            _ => None,
        });
        let Some(value) = value else {
            return;
        };
        let Some(secs) = self.state.update(cx, |s, cx| s.copy_value(value, cx)) else {
            return;
        };
        self.show_status(format!("Copied \u{2014} clears in {secs} s"), cx);
    }

    /// Shows `message` in the pinned copy pill until [`COPIED_TTL`] passes.
    fn show_status(&mut self, message: impl Into<SharedString>, cx: &mut Context<Self>) {
        self.status = Some(message.into());
        self.status_clear = Some(cx.spawn(async move |this, cx| {
            cx.background_executor().timer(COPIED_TTL).await;
            this.update(cx, |this, cx| {
                this.status = None;
                cx.notify();
            })
            .ok();
        }));
        cx.notify();
    }

    /// "Copy to current vault". Returns the new item's id in the live vault.
    pub fn copy_to_current(&mut self, cx: &mut Context<Self>) -> Option<Uuid> {
        let item = self.selected_item(cx)?.clone();
        let id = self
            .state
            .update(cx, |s, cx| s.copy_item_into_vault(&item, cx));
        let message = match id {
            Some(_) => format!(
                "Copied \u{2018}{}\u{2019} into the current vault",
                item.title
            ),
            None => "Could not copy the item".to_owned(),
        };
        self.show_status(message, cx);
        id
    }

    /// "Replace current vault with this backup": the restore confirm in Settings.
    fn replace_current(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let path = self.path.clone();
        self.state.update(cx, |s, cx| s.request_restore(path, cx));
        window.remove_window();
    }
}

impl BackupWindow {
    /// The password card: the main unlock screen's card (05 §2.3 "Backup viewer"), the
    /// app icon with a read-only eye badge, the vault name and the backup's kind and time.
    /// It behaves like the unlock screen: a wrong password shakes the field; while
    /// verifying, the controls are hidden under "Unlocking…".
    fn render_prompt(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme();
        let field = div()
            .w_full()
            .debug_selector(|| "backup-password".into())
            // No reveal toggle, as on the main unlock screen.
            .child(ui::input(&self.password));
        let controls = ui::v_flex()
            .child(ui::shake_field(
                field,
                self.failures,
                self.reduce_motion,
                "backup-input-shake",
            ))
            .when_some(self.error.clone(), |col, e| {
                col.child(div().text_sm().text_color(theme.danger).child(e))
            })
            .child(
                Button::new("backup-open")
                    .debug_selector(|| format!("backup-open {OPEN_LABEL}"))
                    .primary()
                    .w_full()
                    .label(OPEN_LABEL)
                    .clickable_when(!self.busy)
                    .on_click(cx.listener(|this, _, window, cx| this.submit(window, cx))),
            );
        let card = ui::unlock_card(
            ui::UnlockCard {
                prefix: "backup",
                icon: gpui::img(crate::assets::APP_ICON)
                    .size_full()
                    .into_any_element(),
                icon_size: ui::UNLOCK_ICON_SIZE,
                badge: Some(IconName::Eye),
                name: self.vault_name.clone(),
                title: false,
                subtitle: Some(self.subtitle.clone()),
                controls,
                unlocking: self.busy.then_some("backup-unlocking"),
            },
            cx,
        );
        // The password is the card's only input: a revealed one is never copied out.
        ui::centered(cx)
            .child(ui::refuse_plain_copy(card))
            .into_any_element()
    }

    /// The strip in the title-bar band: past the traffic lights, the backup's name, the
    /// Read-only tag and, pinned right, the danger Replace button.
    fn render_strip(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme();
        let font = theme.font_size;
        ui::h_flex()
            .debug_selector(|| "backup-strip".into())
            .flex_none()
            .w_full()
            .h(super::main::header_height(cx))
            .pl(px(STRIP_PAD_LEFT))
            .pr(px(ui::COLUMN_PAD_X))
            .gap(px(8.))
            .border_b_1()
            .border_color(theme.border)
            .child(
                div()
                    .debug_selector(|| "backup-strip-title".into())
                    .min_w_0()
                    .truncate()
                    .text_size(font)
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(backup_title(&self.path)),
            )
            .child(
                div()
                    .debug_selector(|| "backup-read-only".into())
                    .flex_none()
                    .flex()
                    .items_center()
                    .child(ui::info_label("Read-only", cx)),
            )
            .child(div().flex_1())
            .child(
                ui::no_window_drag(div())
                    .debug_selector(|| "backup-replace".into())
                    .flex_none()
                    .child(
                        Button::new("backup-replace")
                            .small()
                            .danger()
                            .label("Replace current vault with this backup\u{2026}")
                            .clickable()
                            .on_click(
                                cx.listener(|this, _, window, cx| this.replace_current(window, cx)),
                            ),
                    ),
            )
            .into_any_element()
    }

    /// ↓ / ↑ in the list (`delta` rows of items, headers skipped), as the main list's
    /// `AppState::select_offset`: no selection picks the first item; the row scrolls
    /// into view.
    fn select_offset(&mut self, delta: isize, cx: &mut Context<Self>) {
        let items = &self.listing.items;
        if items.is_empty() {
            return;
        }
        let next = match self
            .selection
            .and_then(|id| items.iter().position(|i| *i == id))
        {
            Some(ix) => ix.saturating_add_signed(delta).min(items.len() - 1),
            None => 0,
        };
        let id = items[next];
        self.select(id, cx);
        if let Some(row) = self.listing.row_of(id) {
            self.list_state.scroll_to_reveal_item(row);
        }
    }

    /// Picks the list order from the sort menu.
    fn set_sort(&mut self, sort: Sort, cx: &mut Context<Self>) {
        self.sort_menu_open = false;
        if self.sort != sort {
            self.sort = sort;
            self.refilter(cx);
        }
        cx.notify();
    }

    /// `[sidebar, list]` widths: the defaults, fitted as the main window's so the detail
    /// keeps `DETAIL_MIN` in a narrow window.
    fn widths(window: &Window) -> [f32; 2] {
        fit_widths(
            [SIDEBAR.0, LIST.0],
            window.viewport_size().width.as_f32(),
            true,
        )
    }

    /// The main window's sidebar column over the backup's counts, at the sidebar's default
    /// width: no divider, no collapse. Its filter and Tags state are this window's own.
    fn render_sidebar(&self, window: &Window, cx: &mut Context<Self>) -> AnyElement {
        let (pick, toggle) = (cx.entity().downgrade(), cx.entity().downgrade());
        div()
            .flex_none()
            .w(px(Self::widths(window)[0]))
            .h_full()
            .child(sidebar_column(
                SidebarColumn {
                    name: self.vault_name.clone(),
                    counts: &self.counts,
                    filter: &self.filter,
                    tags_open: self.tags_open,
                    on_pick: Rc::new(move |filter, _, cx| {
                        pick.update(cx, |this, cx| this.set_filter(filter, cx)).ok();
                    }),
                    on_toggle_tags: Rc::new(move |_, cx| {
                        toggle
                            .update(cx, |this, cx| {
                                this.tags_open = !this.tags_open;
                                cx.notify();
                            })
                            .ok();
                    }),
                    // The strip above already fills the title-bar band.
                    top_pad: px(0.),
                    focus: None,
                },
                cx,
            ))
            .into_any_element()
    }

    /// The list column: the main list's search field, sort menu and rows over the
    /// backup's items.
    fn render_list(&self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let sort_button = {
            let toggle = cx.entity().downgrade();
            let select = toggle.clone();
            sort_menu(
                &self.sort_focus,
                self.sort_menu_open,
                self.sort,
                move |open, _, cx| {
                    toggle
                        .update(cx, |this, cx| {
                            this.sort_menu_open = open;
                            cx.notify();
                        })
                        .ok();
                },
                Rc::new(move |sort, _, cx| {
                    select.update(cx, |this, cx| this.set_sort(sort, cx)).ok();
                }),
                window,
                cx,
            )
        };
        let theme = cx.theme();
        let active = self.list_focus.contains_focused(window, cx);
        let body = if self.listing.rows.is_empty() {
            let message = if !self.search.read(cx).value().trim().is_empty() {
                crate::screens::main::list::NO_RESULTS
            } else if self.filter == Filter::All {
                "This backup has no items"
            } else {
                crate::screens::main::list::NO_ITEMS_HERE
            };
            ui::v_flex()
                .size_full()
                .items_center()
                .justify_center()
                .child(ui::muted(message, cx))
                .into_any_element()
        } else {
            let rows = self.listing.rows.clone();
            let selection = self.selection;
            let view = cx.entity();
            let focus = self.list_focus.clone();
            list(self.list_state.clone(), move |ix, _, cx| {
                match rows.get(ix) {
                    Some(Row::Header(label)) => group_header(label.clone(), cx),
                    Some(Row::Item(id)) => {
                        let this = view.read(cx);
                        let Some(item) = this.item(*id, cx) else {
                            return div().h(item_row_height(cx)).into_any_element();
                        };
                        let id = *id;
                        let (view, focus) = (view.clone(), focus.clone());
                        item_row(
                            ix,
                            item,
                            None,
                            this.listing.issues(id),
                            selection == Some(id),
                            active,
                            move |_, window, cx| {
                                window.focus(&focus, cx);
                                view.update(cx, |this, cx| this.select(id, cx));
                            },
                            cx,
                        )
                    }
                    None => div().into_any_element(),
                }
            })
            .size_full()
            .into_any_element()
        };
        ui::v_flex()
            .id("backup-list")
            .w(px(Self::widths(window)[1]))
            .flex_none()
            .h_full()
            .border_r_1()
            .border_color(theme.border)
            .child(
                ui::h_flex()
                    .flex_none()
                    .h(super::main::header_height(cx))
                    .px(px(ui::COLUMN_PAD_X))
                    // As the main list's search row with the sidebar shown.
                    .pl(px(ui::list_header_pad_left(Self::widths(window)[0])))
                    .gap(px(4.))
                    .child(
                        div()
                            .flex_1()
                            .debug_selector(|| "list-search".into())
                            // ↓ leaves the field for the list and moves the selection,
                            // as ↓ in the list does (the input would swallow it).
                            .capture_action(cx.listener(|this, _: &MoveDown, window, cx| {
                                cx.stop_propagation();
                                window.focus(&this.list_focus, cx);
                                this.select_offset(1, cx);
                            }))
                            .child(search_field(&self.search, cx)),
                    )
                    .child(div().flex_none().child(sort_button)),
            )
            .child(
                ui::v_flex()
                    .id("item-list")
                    .debug_selector(|| "item-list".into())
                    .track_focus(&self.list_focus)
                    // The main list's key context and actions (↑ ↓ ⏎ ⌘C), handled here on
                    // the backup's own selection; their global handlers serve only the
                    // main window (`actions::on_main`).
                    .key_context(LIST_CONTEXT)
                    .on_action(cx.listener(|this, _: &NextItem, _, cx| this.select_offset(1, cx)))
                    .on_action(cx.listener(|this, _: &PrevItem, _, cx| this.select_offset(-1, cx)))
                    .on_action(cx.listener(|this, _: &FocusDetail, window, cx| {
                        window.focus(&this.detail_focus, cx);
                    }))
                    .on_action(cx.listener(|this, _: &CopyUsername, _, cx| {
                        this.copy(CopyTarget::Username, cx);
                    }))
                    .flex_1()
                    .min_h_0()
                    .mx(px(2.))
                    .rounded(theme.radius)
                    .map(|el| ui::focus_ring(el, cx))
                    .child(body),
            )
            .into_any_element()
    }

    /// The detail column: the shared read-mode detail with "Copy to current vault" as its
    /// only header button, and the copy pill pinned at the bottom.
    fn render_detail(&self, window: &Window, cx: &mut Context<Self>) -> AnyElement {
        let live = self.state.read(cx).main_active();
        let copy_across = Button::new("backup-copy-item")
            .debug_selector(|| "backup-copy-item".into())
            .small()
            .label("Copy to current vault")
            .disabled(!live)
            .clickable_when(live)
            .on_click(cx.listener(|this, _, _, cx| {
                this.copy_to_current(cx);
            }))
            .into_any_element();
        let weak = cx.entity().downgrade();
        let actions = DetailActions(Rc::new(move |action, cx| {
            weak.update(cx, |this, cx| this.act(action, cx)).ok();
        }));
        // Also checked against the live modifiers, key status and focus, so a key-up
        // that went elsewhere cannot leave values revealed.
        let peek = self.option_reveal
            && ui::option_alone(&window.modifiers())
            && window.is_window_active()
            && self.focus.contains_focused(window, cx);
        let [side, list] = Self::widths(window);
        let column = window.viewport_size().width.as_f32() - side - list;
        let content = match self.selected_item(cx) {
            Some(item) => ReadDetail {
                state: &self.state,
                revealed: &self.revealed,
                history_open: self.history_open,
                actions,
                standalone: true,
                rows_width: rows_width(column),
                peek,
                source: ItemSource::Backup(&self.listing.issues),
                header_buttons: Some(copy_across),
            }
            .render_item(item, self.state.read(cx), window, cx)
            .into_any_element(),
            None => ui::v_flex()
                .size_full()
                .items_center()
                .justify_center()
                .child(ui::muted("Select an item", cx))
                .into_any_element(),
        };
        ui::v_flex()
            .id("backup-detail")
            .debug_selector(|| "backup-detail".into())
            .track_focus(&self.detail_focus)
            .flex_1()
            .min_w_0()
            .h_full()
            .relative()
            .child(content)
            .when_some(self.status.clone(), |col, status| {
                col.child(ui::detail_copy_feedback(status, cx))
            })
            .into_any_element()
    }
}

impl Render for BackupWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let rem = theme::rem_size(cx);
        if window.rem_size() != rem {
            window.set_rem_size(rem);
        }
        ui::update_focus_ring(window, cx);
        if self.vault.is_some() && !self.session_live(cx) {
            self.forget();
        }
        // ⌥ and ⌘F follow the focus path: focus left on the password field (no longer
        // drawn) or pointing at nothing would silence both.
        if self.vault.is_some() && std::mem::take(&mut self.focus_list) {
            window.focus(&self.list_focus, cx);
        } else if self.vault.is_some() && window.is_window_active() && window.focused(cx).is_none()
        {
            window.focus(&self.focus, cx);
        }
        let theme = cx.theme();
        let (bg, fg, font) = (theme.background, theme.foreground, theme.font_size);
        let body = if self.vault.is_some() {
            ui::v_flex()
                .size_full()
                .child(self.render_strip(cx))
                .child(
                    ui::h_flex()
                        .flex_1()
                        .min_h_0()
                        .child(self.render_sidebar(window, cx))
                        .child(self.render_list(window, cx))
                        .child(self.render_detail(window, cx)),
                )
                .into_any_element()
        } else {
            self.render_prompt(cx)
        };
        ui::clear_focus_ring_on_click(div())
            .id("backup-window")
            // Activity gate (L-13): a click after a long sleep locks, never copies.
            .map(|el| crate::autolock::gate_mouse(el, &self.state))
            .track_focus(&self.focus)
            .on_modifiers_changed(
                cx.listener(|this, ev: &gpui::ModifiersChangedEvent, _, cx| {
                    this.set_option_reveal(ui::option_alone(&ev.modifiers), cx);
                }),
            )
            // ⌘F focuses this window's search (the global handler serves the main window).
            .on_action(cx.listener(|this, _: &Search, window, cx| {
                if this.vault.is_some() {
                    ui::focus_input(&this.search, window, cx);
                }
            }))
            .size_full()
            .relative()
            .bg(bg)
            .text_color(fg)
            .text_size(font)
            // Under the content: the window moves only from the band's empty parts.
            .child(ui::window_drag_band())
            .child(body)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gpui::{TestAppContext, VisualTestContext};
    use vault_core::{Field, KdfParams};
    use vault_sync::{NoopHooks, SyncedVault};

    use super::*;

    const PW: &str = "correct horse";

    /// A live vault with two items and a snapshot of it; returns the state and backup path.
    fn setup(dir: &std::path::Path, cx: &mut TestAppContext) -> (Entity<AppState>, PathBuf) {
        let mut vault = SyncedVault::create(
            &dir.join("t.vault"),
            &SecretString::new(PW.into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        vault
            .edit(|v| {
                let mut gh = Item::new("GitHub", device, 1);
                gh.tags = vec!["work".into()];
                gh.fields = vec![Field::new(
                    "password",
                    FieldKind::Password,
                    SecretString::new("hunter2".into()),
                    1,
                )];
                v.insert(gh, 1);
                v.insert(Item::new("Alarm code", device, 1), 1);
            })
            .unwrap();
        vault.save().unwrap();
        let backup = vault.backup_now().unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| {
            s.install_unlocked_for_tests(vault);
            // Settings lists it: only listed, validated entries open or restore (L-04).
            s.refresh_backups();
        });
        (state, backup)
    }

    /// The viewer for `backup`, with its entry from the live vault's backups list (as
    /// Settings passes it) and the vault name "Personal".
    fn window(
        state: &Entity<AppState>,
        backup: &std::path::Path,
        cx: &mut TestAppContext,
    ) -> (Entity<BackupWindow>, VisualTestContext) {
        let info = state.read_with(cx, |s, _| {
            s.vault
                .as_ref()
                .and_then(|v| v.backups().ok())
                .and_then(|list| list.into_iter().find(|b| b.path == backup))
        });
        window_with(state, backup, info, cx)
    }

    fn window_with(
        state: &Entity<AppState>,
        backup: &std::path::Path,
        info: Option<BackupInfo>,
        cx: &mut TestAppContext,
    ) -> (Entity<BackupWindow>, VisualTestContext) {
        cx.update(gpui_component::init);
        let mut view = None;
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let v = cx.new(|cx| {
                BackupWindow::new(
                    state.clone(),
                    backup.to_owned(),
                    info.as_ref(),
                    "Personal".into(),
                    window,
                    cx,
                )
            });
            view = Some(v.clone());
            Root::new(v, window, cx)
        });
        let vcx = VisualTestContext::from_window(window.into(), cx);
        (view.unwrap(), vcx)
    }

    /// 03 §2 D-1 (bug hunt 2026-11-06 L3): a symlink planted in `backups/` that points at a
    /// valid vault file (here, a real snapshot moved outside) is refused with a readable
    /// message and never parsed or unlocked; so is a conflict package that is itself a link.
    #[gpui::test]
    fn symlinked_backup_is_refused_not_followed(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("real.vault.bin");
        std::fs::rename(&backup, &target).unwrap();
        std::os::unix::fs::symlink(&target, &backup).unwrap();
        let pkg_target = outside.path().join("pkg.vault");
        std::fs::create_dir(&pkg_target).unwrap();
        std::fs::copy(&target, pkg_target.join(vault_sync::VAULT_FILE_NAME)).unwrap();
        let linked_pkg = backup
            .parent()
            .unwrap()
            .join("conflict-2026-10-28T14-03-11Z-t 2.vault");
        std::os::unix::fs::symlink(&pkg_target, &linked_pkg).unwrap();
        for path in [&backup, &linked_pkg] {
            let err = read_backup(path).unwrap_err();
            assert!(err.contains("is a link"), "{err}");
            assert!(!err.contains(&*outside.path().to_string_lossy()), "{err}");
            let (view, mut vcx) = window(&state, path, cx);
            view.update(&mut vcx, |w, cx| w.unlock(SecretString::new(PW.into()), cx));
            vcx.run_until_parked();
            view.read_with(&vcx, |w, _| {
                assert!(!w.is_open(), "not unlocked through the link");
                let error = w.error.as_ref().expect("an error is shown").to_string();
                assert!(error.contains("is a link"), "{error}");
            });
        }
        // The real file still opens where it is read directly.
        std::fs::remove_file(&backup).unwrap();
        std::fs::rename(&target, &backup).unwrap();
        assert!(read_backup(&backup).is_ok());
    }

    #[test]
    fn oversized_backup_is_refused_with_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t-2026-01-01T00-00-00Z.vault.bin");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(vault_sync::MAX_VAULT_FILE_SIZE + 1)
            .unwrap();
        let err = read_backup(&path).unwrap_err();
        assert!(err.contains("larger than the 64 MiB limit"), "{err}");
    }

    /// A field kind from a newer app version is concealed like a password until revealed.
    #[gpui::test]
    fn unknown_field_kind_is_masked(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new(PW.into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        vault
            .edit(|v| {
                let mut item = Item::new("Gadget", device, 1);
                let mut pin =
                    Field::new("pin", FieldKind::Other, SecretString::new("4711".into()), 1);
                pin.kind_raw = Some("x-future-pin".into());
                let mut user =
                    Field::new("user", FieldKind::Text, SecretString::new("al".into()), 1);
                user.icon = Some("KeyRound".into());
                item.fields = vec![
                    user,
                    pin,
                    // A crafted value on a heading: never shown or copied.
                    Field::new(
                        "Extras",
                        FieldKind::Section,
                        SecretString::new("SHOULD-NOT-SHOW".into()),
                        1,
                    ),
                ];
                v.insert(item, 1);
            })
            .unwrap();
        vault.save().unwrap();
        let backup = vault.backup_now().unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
        let (view, mut vcx) = window(&state, &backup, cx);
        view.update(&mut vcx, |w, cx| w.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        assert!(view.read_with(&vcx, |w, _| w.is_open()));
        assert!(vcx.debug_bounds("field-value 0").is_some(), "text field");
        assert!(vcx.debug_bounds("field-masked 1").is_some(), "Other field");
        assert!(vcx.debug_bounds("field-plain 1").is_none());
        // The shared renderer's Reveal, routed to this window (keyed by field id).
        view.update(&mut vcx, |w, cx| {
            let pin = w.selected_item(cx).unwrap().fields[1].id;
            w.act(DetailAction::Reveal(pin), cx);
        });
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("field-plain 1").is_some(), "Reveal works");
        // The shared field row: label beside the value, 7 px padding like the detail.
        let row = vcx.debug_bounds("field-row 0").expect("shared row");
        let label = vcx.debug_bounds("field-label 0").unwrap();
        let content = vcx.debug_bounds("field-content 0").unwrap();
        assert_eq!(
            content.top() - row.top(),
            px(crate::screens::main::detail::FIELD_ROW_PAD_Y)
        );
        assert!(label.right() < content.left(), "label beside its value");
        // Stored "user" and "pin": shown as stored, like the main detail.
        assert!(vcx.debug_bounds("field-label-text 0 user").is_some());
        assert!(vcx.debug_bounds("field-label-text 1 pin").is_some());
        // The field icon comes with the shared row (05 "Field icons").
        assert!(vcx.debug_bounds("field-row-icon 0 KeyRound").is_some());
        // A section heading renders through the shared heading row, without actions.
        assert!(vcx.debug_bounds("section-row 2 EXTRAS").is_some());
        assert!(vcx.debug_bounds("field-value 2").is_none());
        assert!(vcx.debug_bounds("field-masked 2").is_none());
        let board = crate::clipboard::fake::FakePasteboard::default();
        state.update(&mut vcx, |s, _| s.set_pasteboard(Box::new(board.clone())));
        view.update(&mut vcx, |w, cx| w.copy_field(2, cx));
        assert_eq!(board.contents(), None, "a heading copies nothing");
    }

    #[gpui::test]
    fn opens_read_only_and_copies_across(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        let backup_bytes = std::fs::read(&backup).unwrap();
        let (view, mut vcx) = window(&state, &backup, cx);
        vcx.run_until_parked();

        view.update(&mut vcx, |w, cx| {
            w.unlock(SecretString::new("nope".into()), cx)
        });
        vcx.run_until_parked();
        view.read_with(&vcx, |w, _| {
            assert!(!w.is_open());
            assert_eq!(w.error, None, "a wrong password shakes, no text");
            assert_eq!(w.failures, 1);
        });
        // Revealed, the password never reaches the pasteboard; typing below replaces it.
        let password = view.read_with(&vcx, |w, _| w.password.clone());
        ui::assert_revealed_copy_refused(&password, &mut vcx);

        // Typed and submitted like a user: the field is emptied as soon as it is read.
        vcx.simulate_input(PW);
        assert!(view.read_with(&vcx, |w, cx| !ui::input_is_empty(&w.password, cx)));
        vcx.simulate_keystrokes("enter");
        assert!(view.read_with(&vcx, |w, cx| ui::input_is_empty(&w.password, cx)));
        vcx.run_until_parked();
        let first = view.read_with(&vcx, |w, _| {
            assert!(w.is_open());
            assert_eq!(w.item_ids().len(), 2);
            w.selection.unwrap()
        });
        // Sorted by title: "Alarm code" first. Select GitHub and copy its password.
        let github = view.read_with(&vcx, |w, _| w.item_ids()[1]);
        assert_ne!(first, github);
        view.update(&mut vcx, |w, cx| {
            w.select(github, cx);
            w.copy_field(0, cx);
            assert!(w.status.as_ref().unwrap().contains("clears in"));
        });
        vcx.run_until_parked();
        // "hunter2" is weak: the shared row draws its notice under the field (05 §2.3).
        let field = view.read_with(&vcx, |w, _| {
            w.vault.as_ref().unwrap().get(github).unwrap().fields[0].id
        });
        let key = format!("issue-strip {field} Weak Password");
        assert!(vcx.debug_bounds(Box::leak(key.into_boxed_str())).is_some());

        // Copy to current vault: a clone under a fresh id.
        let new_id = view
            .update(&mut vcx, |w, cx| w.copy_to_current(cx))
            .expect("copied");
        state.read_with(&vcx, |s, _| {
            assert_ne!(new_id, github, "fresh id");
            assert_eq!(s.item_count(), 3);
            let v = s.unlocked_vault().unwrap();
            assert_eq!(v.get(new_id).unwrap().title, "GitHub");
            assert_eq!(v.get(github).unwrap().title, "GitHub", "original untouched");
        });

        // Nothing was ever written to the backup.
        assert_eq!(std::fs::read(&backup).unwrap(), backup_bytes);
    }

    /// 05 §2.3 "Password notices": the backup viewer audits against the backup's own items.
    /// Two backup items share a password the open vault no longer holds anywhere: the
    /// viewer still flags it as reused, and the open vault flags nothing.
    #[gpui::test]
    fn backup_reuse_is_judged_against_the_backups_own_items(cx: &mut TestAppContext) {
        const SHARED: &str = "Shared-backup-passphrase-91";
        let dir = tempfile::tempdir().unwrap();
        let mut vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new(PW.into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        let login = |title: &str, pw: &str| {
            let mut item = Item::new(title, device, 1);
            item.fields = vec![Field::new(
                "password",
                FieldKind::Password,
                SecretString::new(pw.into()),
                1,
            )];
            item
        };
        let (alpha, beta) = vault
            .edit(|v| {
                (
                    v.insert(login("Alpha", SHARED), 1),
                    v.insert(login("Beta", SHARED), 1),
                )
            })
            .unwrap();
        vault.save().unwrap();
        let backup = vault.backup_now().unwrap();
        // The open vault moves on: distinct passwords, plus an unrelated item.
        let unrelated = vault
            .edit(|v| {
                for (id, pw) in [
                    (alpha, "Alpha-new-passphrase-38"),
                    (beta, "Beta-new-passphrase-52"),
                ] {
                    v.update(id, 2, |item| {
                        item.fields[0].value = SecretString::new(pw.into());
                    })
                    .unwrap();
                }
                v.insert(login("Unrelated", "Unrelated-passphrase-64"), 2)
            })
            .unwrap();
        vault.save().unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
        state.read_with(cx, |s, _| {
            let v = s.unlocked_vault().unwrap();
            assert!(
                v.items()
                    .all(|i| i.fields.iter().all(|f| f.value.expose_secret() != SHARED))
            );
            assert!(
                s.listing.issues(unrelated).is_empty(),
                "open vault: no notices"
            );
            assert!(s.listing.issues(alpha).is_empty() && s.listing.issues(beta).is_empty());
        });

        let (view, mut vcx) = window(&state, &backup, cx);
        view.update(&mut vcx, |w, cx| w.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        assert!(view.read_with(&vcx, |w, _| w.is_open()));
        view.update(&mut vcx, |w, cx| w.select(alpha, cx));
        vcx.run_until_parked();
        let field = view.read_with(&vcx, |w, _| {
            w.vault.as_ref().unwrap().get(alpha).unwrap().fields[0].id
        });
        let key = format!("issue-strip {field} Reused Password");
        assert!(vcx.debug_bounds(Box::leak(key.into_boxed_str())).is_some());
        let weak = format!("issue-strip {field} Weak Password");
        assert!(vcx.debug_bounds(Box::leak(weak.into_boxed_str())).is_none());
    }

    /// Attachments are not backed up: the viewer lists them as Missing, with no actions.
    #[gpui::test]
    fn attachments_show_as_missing(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new(PW.into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        vault
            .edit(|v| {
                let mut item = Item::new("Passport", device, 1);
                item.attachments
                    .push(vault_core::attachment::new_ref("scan.pdf", 2_500_000, 1).unwrap());
                // A custom image icon: its blob is hidden, and the tile is automatic.
                let icon = vault_core::attachment::new_ref("icon.png", 900, 1).unwrap();
                item.icon = Some(crate::icon::image_icon(icon.id));
                item.attachments.push(icon);
                v.insert(item, 1);
            })
            .unwrap();
        vault.save().unwrap();
        let backup = vault.backup_now().unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
        let (view, mut vcx) = window(&state, &backup, cx);
        view.update(&mut vcx, |w, cx| w.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        assert!(
            vcx.debug_bounds("backup-attachment scan.pdf Missing")
                .is_some()
        );
        assert!(vcx.debug_bounds("attachment-preview scan.pdf").is_none());
        assert!(
            vcx.debug_bounds("backup-attachment icon.png Missing")
                .is_none(),
            "icon blob hidden"
        );
        // The backup has no blobs: the tile is the automatic letter, never an image.
        let item = state.read_with(&vcx, |s, _| {
            s.unlocked_vault().unwrap().items().next().unwrap().clone()
        });
        let auto: &'static str = Box::leak(
            format!(
                "icon-tile {} fill white",
                crate::icon::automatic(&item).describe()
            )
            .into_boxed_str(),
        );
        assert!(vcx.debug_bounds(auto).is_some(), "{auto}");
    }

    #[gpui::test]
    fn open_from_state_and_close_on_lock(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        cx.update(gpui_component::init);
        let before = cx.update(|cx| cx.windows().len());
        // Opened from inside `state.update`: also pins that `BackupWindow::new` never
        // reads `AppState` (reading an entity mid-update panics).
        state.update(cx, |s, cx| s.open_backup(backup.clone(), cx));
        cx.run_until_parked();
        assert_eq!(cx.update(|cx| cx.windows().len()), before + 1);
        assert_eq!(state.read_with(cx, |s, _| s.backup_windows.len()), 1);

        // Closed by the user (red button), then reopened: the dead handle is pruned.
        let first = state.read_with(cx, |s, _| s.backup_windows[0]);
        cx.update_window(first, |_, window, _| window.remove_window())
            .unwrap();
        cx.run_until_parked();
        state.update(cx, |s, cx| s.open_backup(backup.clone(), cx));
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert_eq!(s.backup_windows.len(), 1);
            assert_ne!(s.backup_windows[0], first);
        });

        state.update(cx, |s, cx| s.lock(cx));
        cx.run_until_parked();
        assert!(
            state.read_with(cx, |s, _| s.backup_windows.is_empty()),
            "lock forgets the viewer handle"
        );
        assert_eq!(
            cx.update(|cx| cx.windows().len()),
            before,
            "the viewer closes when the vault locks"
        );
        // Locked: opening is refused.
        state.update(cx, |s, cx| s.open_backup(backup.clone(), cx));
        cx.run_until_parked();
        assert_eq!(cx.update(|cx| cx.windows().len()), before);
    }

    /// A backup over vault-sync's 64 MiB vault-file cap is refused before it is read (a
    /// sparse file, so nothing is allocated).
    #[gpui::test]
    fn oversized_backup_is_refused(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _) = setup(dir.path(), cx);
        let big = dir.path().join("big.vault.bin");
        std::fs::File::create(&big)
            .unwrap()
            .set_len(vault_sync::MAX_VAULT_FILE_SIZE + 1)
            .unwrap();
        let (view, mut vcx) = window(&state, &big, cx);
        view.update(&mut vcx, |w, cx| w.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        view.read_with(&vcx, |w, _| {
            assert!(!w.is_open());
            let error = w.error.as_deref().unwrap_or_default();
            assert!(error.contains("larger than the 64 MiB limit"), "{error}");
        });
    }

    /// An unlock that finishes after the live vault locked installs nothing: the decrypted
    /// backup is dropped unseen, even though the (test-held) viewer entity is still alive.
    #[gpui::test]
    fn unlock_finishing_after_lock_installs_nothing(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        let (view, mut vcx) = window(&state, &backup, cx);
        view.update(&mut vcx, |w, cx| w.unlock(SecretString::new(PW.into()), cx));
        // The background unlock has not run yet: lock first.
        state.update(&mut vcx, |s, cx| s.lock(cx));
        vcx.run_until_parked();
        view.read_with(&vcx, |w, _| {
            assert!(!w.is_open(), "stale backup vault installed");
            assert!(w.item_ids().is_empty());
            assert!(!w.busy);
        });
    }

    /// Once the live vault locks, nothing copied from a backup viewer reaches the clipboard:
    /// neither the viewer's own copy nor `AppState::copy_value` called directly (the window's
    /// removal is deferred, so it may still receive an event).
    #[gpui::test]
    fn copy_after_lock_leaves_the_clipboard_alone(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        let board = crate::clipboard::fake::FakePasteboard::default();
        state.update(cx, |s, _| s.set_pasteboard(Box::new(board.clone())));
        let (view, mut vcx) = window(&state, &backup, cx);
        view.update(&mut vcx, |w, cx| w.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        let github = view.read_with(&vcx, |w, _| w.item_ids()[1]);
        view.update(&mut vcx, |w, cx| {
            w.select(github, cx);
            w.copy_field(0, cx);
        });
        assert_eq!(
            board.contents().as_deref(),
            Some("hunter2"),
            "copies while unlocked"
        );

        // Lock, then copy inside the same turn, before any deferred close can run.
        view.update(&mut vcx, |w, cx| {
            w.state.update(cx, |s, cx| s.lock(cx));
            w.status = None;
            w.copy_field(0, cx);
            assert!(w.status.is_none(), "no 'Copied' status after lock");
            assert!(w.live_vault(cx).is_none(), "backup unreachable once locked");
        });
        assert_eq!(
            board.contents(),
            None,
            "lock cleared ours; nothing new copied"
        );
        let secs = state.update(&mut vcx, |s, cx| {
            s.copy_value(SecretString::new("leak".into()), cx)
        });
        assert_eq!(secs, None);
        assert_eq!(board.contents(), None);
        vcx.run_until_parked();
        assert!(
            !view.read_with(&vcx, |w, _| w.is_open()),
            "keys dropped on lock"
        );
    }

    /// An absorbed iCloud conflict copy is a whole package directory: the viewer reads its
    /// vault.bin. `open_backup` opens only listed, validated entries, and this one (another
    /// vault, outside `backups/`) is not listed.
    #[gpui::test]
    fn opens_a_conflict_package_dir(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _) = setup(dir.path(), cx);
        let conflict = dir.path().join("conflict-x.vault");
        let mut other = SyncedVault::create(
            &conflict,
            &SecretString::new(PW.into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = other.device_id();
        other
            .edit(|v| v.insert(Item::new("From the other Mac", device, 1), 1))
            .unwrap();
        other.save().unwrap();
        drop(other);
        assert!(conflict.is_dir());

        let (view, mut vcx) = window(&state, &conflict, cx);
        view.update(&mut vcx, |w, cx| w.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        view.read_with(&vcx, |w, _| {
            assert!(w.is_open(), "{:?}", w.error);
            assert_eq!(w.item_ids().len(), 1);
        });

        // From the app it is refused: not in this vault's backups list (L-04).
        let before = vcx.update(|_, cx| cx.windows().len());
        state.update(&mut vcx, |s, cx| s.open_backup(conflict.clone(), cx));
        vcx.run_until_parked();
        assert_eq!(vcx.update(|_, cx| cx.windows().len()), before);
    }

    /// `window` with the backup at `backup` opened, GitHub selected.
    fn opened(
        state: &Entity<AppState>,
        backup: &std::path::Path,
        cx: &mut TestAppContext,
    ) -> (Entity<BackupWindow>, VisualTestContext, Uuid) {
        let (view, mut vcx) = window(state, backup, cx);
        view.update(&mut vcx, |w, cx| w.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        let github = view.read_with(&vcx, |w, _| w.item_ids()[1]);
        view.update(&mut vcx, |w, cx| w.select(github, cx));
        vcx.run_until_parked();
        (view, vcx, github)
    }

    fn bounds(key: &'static str, vcx: &mut VisualTestContext) -> gpui::Bounds<gpui::Pixels> {
        vcx.debug_bounds(key)
            .unwrap_or_else(|| panic!("{key} not drawn"))
    }

    /// Owner 2026-11-22: one strip in the title-bar band holds, left to right past the
    /// traffic lights, the name, the Read-only tag and the Replace button pinned right;
    /// Replace stays inside the window when it narrows. The window title names the backup.
    #[gpui::test]
    fn strip_holds_name_tag_and_replace_in_order(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        let (_view, mut vcx, _) = opened(&state, &backup, cx);
        for width in [None, Some(820.), Some(600.)] {
            if let Some(width) = width {
                vcx.simulate_resize(gpui::size(px(width), px(600.)));
                vcx.run_until_parked();
            }
            let window = vcx.update(|window, _| window.viewport_size().width);
            let strip = bounds("backup-strip", &mut vcx);
            let band = bounds("window-drag-band", &mut vcx);
            let title = bounds("backup-strip-title", &mut vcx);
            let tag = bounds("backup-read-only", &mut vcx);
            let replace = bounds("backup-replace", &mut vcx);
            assert_eq!(strip.top(), px(0.), "{width:?}");
            assert_eq!(strip.size.width, window, "full width");
            assert_eq!(strip.size.height, px(ui::TOP_BAND_HEIGHT), "the band");
            assert_eq!(band.size.height, strip.size.height);
            for (name, el) in [("title", title), ("tag", tag), ("replace", replace)] {
                assert!(
                    el.top() >= strip.top() && el.bottom() <= strip.bottom(),
                    "{name} inside the strip at {width:?}"
                );
            }
            assert_eq!(
                title.left(),
                px(ui::TRAFFIC_LIGHTS_RIGHT + 24.),
                "24 px past the lights"
            );
            assert!(
                (tag.center().y - title.center().y).abs() < px(1.),
                "tag centred on the name at {width:?}"
            );
            assert!(title.right() <= tag.left(), "name, then tag at {width:?}");
            assert!(
                tag.right() < replace.left(),
                "tag, then Replace at {width:?}"
            );
            // Above the window's minimum the columns fit like the main window's.
            if width != Some(600.) {
                let detail = bounds("backup-detail", &mut vcx);
                assert!(
                    detail.size.width >= px(super::super::main::DETAIL_MIN),
                    "detail keeps its minimum at {width:?}"
                );
            }
            assert!(replace.right() <= window, "Replace inside at {width:?}");
            assert_eq!(
                replace.right(),
                window - px(ui::COLUMN_PAD_X),
                "pinned right at {width:?}"
            );
        }
        // The list and detail sit under the strip.
        let strip = bounds("backup-strip", &mut vcx);
        assert!(bounds("item-list", &mut vcx).top() >= strip.bottom());
        assert!(bounds("backup-detail", &mut vcx).top() >= strip.bottom());

        // Opened for real: the main window's chrome, titled after the backup.
        let handle = cx
            .update(|cx| open_backup_window(state.clone(), backup.clone(), None, String::new(), cx))
            .unwrap();
        let title = VisualTestContext::from_window(handle, cx).window_title();
        let name = text::file_name(&backup);
        assert_eq!(title, Some(format!("Backup \u{2014} {name}")));
    }

    /// The detail is the main window's read-mode renderer: its title, tags, header and
    /// the copy-across button in the header buttons, which still copies.
    #[gpui::test]
    fn detail_is_the_shared_read_view(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        let (_view, mut vcx, _) = opened(&state, &backup, cx);
        assert!(vcx.debug_bounds("detail-title GitHub").is_some());
        assert!(vcx.debug_bounds("detail-tags").is_some(), "#work");
        assert!(vcx.debug_bounds("detail-footer").is_some());
        let buttons = bounds("detail-header-buttons", &mut vcx);
        let copy = bounds("backup-copy-item", &mut vcx);
        assert!(buttons.contains(&copy.center()), "in the header");
        // No Favorite / Delete / Edit here.
        assert!(vcx.debug_bounds("favorite").is_none());
        assert_eq!(state.read_with(&vcx, |s, _| s.item_count()), 2);
        vcx.simulate_click(copy.center(), gpui::Modifiers::default());
        vcx.run_until_parked();
        assert_eq!(state.read_with(&vcx, |s, _| s.item_count()), 3);
        assert!(vcx.debug_bounds("detail-copy-feedback").is_some());
    }

    /// Copying a value shows the pinned pill at the bottom of the detail column, which
    /// clears after the copied-pill time, as in item windows.
    #[gpui::test]
    fn copy_shows_the_pinned_pill_until_it_clears(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        let board = crate::clipboard::fake::FakePasteboard::default();
        state.update(cx, |s, _| s.set_pasteboard(Box::new(board.clone())));
        let (view, mut vcx, _) = opened(&state, &backup, cx);
        assert!(vcx.debug_bounds("detail-copy-feedback").is_none());
        let value = bounds("field-value 0", &mut vcx).center();
        vcx.simulate_click(value, gpui::Modifiers::default());
        assert_eq!(board.contents().as_deref(), Some("hunter2"));
        assert!(
            vcx.debug_bounds("field-masked 0").is_some(),
            "never revealed"
        );
        vcx.run_until_parked();
        let pill = bounds("detail-copy-feedback", &mut vcx);
        let detail = bounds("backup-detail", &mut vcx);
        assert_eq!(
            pill.bottom(),
            detail.bottom() - px(20.),
            "pinned at the bottom"
        );
        assert!(
            view.read_with(&vcx, |w, _| w.status.clone())
                .is_some_and(|s| s.contains("clears in"))
        );
        vcx.executor()
            .advance_clock(COPIED_TTL + Duration::from_millis(100));
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("detail-copy-feedback").is_none());
    }

    /// ⌘F focuses this window's search; the query filters the backup's items with the
    /// main list's matcher and leaves the open vault's search alone.
    #[gpui::test]
    fn search_filters_the_list(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        cx.update(|cx| cx.bind_keys([gpui::KeyBinding::new("cmd-f", Search, None)]));
        let (view, mut vcx, github) = opened(&state, &backup, cx);
        // A–Z with group headers, like the main list: "A", Alarm code, "G", GitHub.
        assert!(vcx.debug_bounds("item-row 1").is_some());
        assert!(vcx.debug_bounds("item-row 3").is_some());
        vcx.simulate_keystrokes("cmd-f");
        assert!(vcx.update(|window, cx| {
            use gpui::Focusable as _;
            view.read(cx).search.focus_handle(cx).is_focused(window)
        }));
        vcx.simulate_input("git");
        vcx.run_until_parked();
        view.read_with(&vcx, |w, _| {
            assert_eq!(w.item_ids(), &[github]);
            assert_eq!(w.selection, Some(github));
        });
        // Search results: no headers, the hit is row 0.
        assert!(vcx.debug_bounds("item-row 0").is_some());
        assert!(vcx.debug_bounds("item-row 1").is_none());
        // "Alarm code" matches "alarm"; the selection follows the only hit.
        view.update_in(&mut vcx, |w, window, cx| {
            w.search
                .update(cx, |s, cx| s.set_value("alarm", window, cx));
            w.refilter(cx);
        });
        vcx.run_until_parked();
        view.read_with(&vcx, |w, _| {
            assert_eq!(w.item_ids().len(), 1);
            assert_ne!(w.item_ids()[0], github);
            assert_eq!(w.selection, Some(w.item_ids()[0]));
        });
        assert!(
            state.read_with(&vcx, |s, _| s.query.is_empty()),
            "local query"
        );
        view.update_in(&mut vcx, |w, window, cx| {
            w.search.update(cx, |s, cx| s.set_value("", window, cx));
            w.refilter(cx);
        });
        assert_eq!(view.read_with(&vcx, |w, _| w.item_ids().len()), 2);
    }

    const TOTP_URI: &str = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";

    /// A backup holding "Rich" (password with one history entry, TOTP, website) and
    /// "Other"; the viewer opened on it with Rich selected.
    fn rich(
        dir: &std::path::Path,
        cx: &mut TestAppContext,
    ) -> (
        Entity<AppState>,
        Entity<BackupWindow>,
        VisualTestContext,
        Uuid,
        Uuid,
    ) {
        let mut vault = SyncedVault::create(
            &dir.join("t.vault"),
            &SecretString::new(PW.into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        let (rich, other) = vault
            .edit(|v| {
                let mut item = Item::new("Rich", device, 1);
                let pw = Field::new(
                    "password",
                    FieldKind::Password,
                    SecretString::new("Current-passphrase-17".into()),
                    1,
                );
                item.history.push(vault_core::HistoryEntry {
                    value: SecretString::new("Old-passphrase-42".into()),
                    replaced_at: 5,
                    field_id: Some(pw.id),
                });
                item.fields = vec![
                    pw,
                    Field::new(
                        "totp",
                        FieldKind::Totp,
                        SecretString::new(TOTP_URI.into()),
                        1,
                    ),
                    Field::new(
                        "website",
                        FieldKind::Url,
                        SecretString::new("https://example.com/login".into()),
                        1,
                    ),
                ];
                (
                    v.insert(item, 1),
                    v.insert(Item::new("Other", device, 1), 1),
                )
            })
            .unwrap();
        vault.save().unwrap();
        let backup = vault.backup_now().unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
        let (view, mut vcx) = window(&state, &backup, cx);
        view.update(&mut vcx, |w, cx| {
            w.unlock(SecretString::new(PW.into()), cx);
        });
        vcx.run_until_parked();
        view.update(&mut vcx, |w, cx| w.select(rich, cx));
        vcx.run_until_parked();
        (state, view, vcx, rich, other)
    }

    /// Review 2026-11-22: a new selection starts closed and unrevealed, like the main
    /// window's `set_selection`; re-selecting the same item keeps its state.
    #[gpui::test]
    fn selecting_another_item_resets_history_reveal_and_peek(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (_, view, mut vcx, rich, other) = rich(dir.path(), cx);
        view.update(&mut vcx, |w, cx| {
            let pw = w.selected_item(cx).unwrap().fields[0].id;
            w.act(DetailAction::ToggleHistory, cx);
            w.act(DetailAction::Reveal(pw), cx);
            w.option_reveal = true;
            w.select(rich, cx);
            assert!(w.history_open && w.option_reveal && !w.revealed.is_empty());
            w.select(other, cx);
            assert!(!w.history_open, "history closed");
            assert!(!w.option_reveal, "no peek carried over");
            assert!(w.revealed.is_empty());
        });
    }

    /// Mouse-driven: a row click selects, the shared Reveal button reveals.
    #[gpui::test]
    fn clicks_select_rows_and_reveal(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        let (view, mut vcx, github) = opened(&state, &backup, cx);
        // Rows: "A", Alarm code, "G", GitHub.
        let alarm = view.read_with(&vcx, |w, _| w.item_ids()[0]);
        let row = bounds("item-row 1", &mut vcx).center();
        vcx.simulate_click(row, gpui::Modifiers::default());
        vcx.run_until_parked();
        assert_eq!(view.read_with(&vcx, |w, _| w.selection), Some(alarm));
        assert!(vcx.debug_bounds("detail-title Alarm code").is_some());
        let row = bounds("item-row 3", &mut vcx).center();
        vcx.simulate_click(row, gpui::Modifiers::default());
        vcx.run_until_parked();
        assert_eq!(view.read_with(&vcx, |w, _| w.selection), Some(github));

        assert!(vcx.debug_bounds("field-masked 0").is_some());
        let reveal = bounds("field-reveal 0", &mut vcx).center();
        vcx.simulate_click(reveal, gpui::Modifiers::default());
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("field-plain 0").is_some(), "revealed");
        let reveal = bounds("field-reveal 0", &mut vcx).center();
        vcx.simulate_click(reveal, gpui::Modifiers::default());
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("field-masked 0").is_some(), "hidden again");
    }

    /// Replace sits in the band but never drags the window (the name does); a click asks
    /// for the restore confirm in Settings and closes the viewer.
    #[gpui::test]
    fn replace_click_hands_over_to_restore_without_dragging(cx: &mut TestAppContext) {
        use gpui::{Modifiers, MouseButton, point};
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        let (_view, mut vcx, _) = opened(&state, &backup, cx);
        vcx.update(|window, _| window.activate_window());
        let press_and_move = |at: gpui::Point<gpui::Pixels>, vcx: &mut VisualTestContext| {
            let before = ui::window_moves();
            let to = at + point(px(6.), px(0.));
            vcx.simulate_mouse_down(at, MouseButton::Left, Modifiers::default());
            vcx.simulate_mouse_move(to, MouseButton::Left, Modifiers::default());
            // Released away from where it was pressed, so nothing is clicked.
            let away = point(px(400.), px(400.));
            vcx.simulate_mouse_move(away, MouseButton::Left, Modifiers::default());
            vcx.simulate_mouse_up(away, MouseButton::Left, Modifiers::default());
            vcx.run_until_parked();
            ui::window_moves() - before
        };
        let title = bounds("backup-strip-title", &mut vcx).center();
        assert_eq!(press_and_move(title, &mut vcx), 1, "the band drags");
        let replace = bounds("backup-replace", &mut vcx);
        assert_eq!(
            press_and_move(replace.center(), &mut vcx),
            0,
            "Replace never drags"
        );
        assert!(state.read_with(&vcx, |s, _| s.sync.restore.is_none()));

        let windows = vcx.cx.update(|cx| cx.windows().len());
        vcx.simulate_click(replace.center(), Modifiers::default());
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            let prompt = s.sync.restore.as_ref().expect("restore confirm asked for");
            assert_eq!(prompt.backup, backup);
            assert!(s.settings_open, "the confirm lives in Settings");
        });
        assert_eq!(
            vcx.cx.update(|cx| cx.windows().len()),
            windows - 1,
            "viewer closed"
        );
    }

    /// The shared detail's actions in this window: a history entry copies its old value,
    /// Open URL opens the website, and a TOTP field copies the current code, never the
    /// secret.
    #[gpui::test]
    fn history_url_and_totp_actions_use_the_backup_item(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, view, mut vcx, _, _) = rich(dir.path(), cx);
        let board = crate::clipboard::fake::FakePasteboard::default();
        state.update(&mut vcx, |s, _| s.set_pasteboard(Box::new(board.clone())));
        // The history disclosure renders under the password and its copy button works.
        let toggle = bounds("history-toggle", &mut vcx).center();
        vcx.simulate_click(toggle, gpui::Modifiers::default());
        vcx.run_until_parked();
        assert!(view.read_with(&vcx, |w, _| w.history_open));
        let copy = bounds("history-copy 0", &mut vcx).center();
        vcx.simulate_click(copy, gpui::Modifiers::default());
        assert_eq!(board.contents().as_deref(), Some("Old-passphrase-42"));
        let pw = view.read_with(&vcx, |w, _| {
            w.vault
                .as_ref()
                .unwrap()
                .items()
                .find(|i| i.title == "Rich")
                .unwrap()
                .fields[0]
                .id
        });
        board.set("x");
        view.update(&mut vcx, |w, cx| {
            w.act(DetailAction::CopyHistory(5, Some(pw)), cx);
            // No such entry: nothing copied.
            w.act(DetailAction::CopyHistory(6, Some(pw)), cx);
        });
        assert_eq!(board.contents().as_deref(), Some("Old-passphrase-42"));

        view.update(&mut vcx, |w, cx| w.act(DetailAction::OpenUrl(2), cx));
        let url = vcx.opened_url().expect("opened");
        assert!(url.starts_with("https://example.com/login"), "{url}");
        // Not a URL field: nothing opens.
        vcx.update(|_, cx| cx.open_url("about:blank"));
        view.update(&mut vcx, |w, cx| w.act(DetailAction::OpenUrl(0), cx));
        assert_eq!(vcx.opened_url().as_deref(), Some("about:blank"));

        view.update(&mut vcx, |w, cx| w.copy_field(1, cx));
        let code = board.contents().unwrap();
        assert_eq!(code.len(), 6, "{code}");
        assert!(
            code.bytes().all(|b| b.is_ascii_digit()),
            "a code, not the secret"
        );
        let expected = vault_core::Totp::parse_uri(TOTP_URI)
            .unwrap()
            .code(text::now_millis() / 1000);
        assert_eq!(code, expected);
    }

    /// The main list's Sort menu, with a window-local order: Recently Modified reorders
    /// the backup's rows (no group headers) and leaves the main window's order alone.
    #[gpui::test]
    fn sort_menu_reorders_the_backup_only(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new(PW.into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        let (alpha, beta) = vault
            .edit(|v| {
                let alpha = v.insert(Item::new("Alpha", device, 1), 1);
                let beta = v.insert(Item::new("Beta", device, 1), 1);
                v.update(beta, 5, |it| it.favorite = true).unwrap();
                (alpha, beta)
            })
            .unwrap();
        vault.save().unwrap();
        let backup = vault.backup_now().unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
        let (view, mut vcx) = window(&state, &backup, cx);
        view.update(&mut vcx, |w, cx| w.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        assert_eq!(
            view.read_with(&vcx, |w, _| w.item_ids().to_vec()),
            [alpha, beta]
        );
        // A–Z: "A", Alpha, "B", Beta.
        assert!(vcx.debug_bounds("item-row 3").is_some());

        let sort = bounds("sort", &mut vcx).center();
        vcx.simulate_click(sort, gpui::Modifiers::default());
        vcx.run_until_parked();
        assert!(view.read_with(&vcx, |w, _| w.sort_menu_open));
        assert!(vcx.debug_bounds("sort-name-checked").is_some());
        let modified = bounds("sort-modified", &mut vcx).center();
        vcx.simulate_click(modified, gpui::Modifiers::default());
        vcx.run_until_parked();
        view.read_with(&vcx, |w, _| {
            assert_eq!(w.sort, Sort::RecentlyModified);
            assert!(!w.sort_menu_open, "a pick closes the menu");
            assert_eq!(w.item_ids(), &[beta, alpha], "newest first");
        });
        assert!(vcx.debug_bounds("sort-modified").is_none(), "menu gone");
        // No group headers: two item rows only.
        assert!(vcx.debug_bounds("item-row 1").is_some());
        assert!(vcx.debug_bounds("item-row 2").is_none());
        assert_eq!(
            state.read_with(&vcx, |s, _| s.sort),
            Sort::Alphabetical,
            "main window's order untouched"
        );
        // Reopened: the check mark moved.
        vcx.simulate_click(sort, gpui::Modifiers::default());
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("sort-modified-checked").is_some());
    }

    /// The viewer starts in the main window's order as of the unlock, not as of the
    /// window's construction: changed in between, the new order applies, without headers.
    #[gpui::test]
    fn viewer_starts_in_the_main_windows_order(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new(PW.into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        // Created in the opposite order to A–Z: Recently Created lists Zulu first.
        let (alpha, zulu) = vault
            .edit(|v| {
                (
                    v.insert(Item::new("Alpha", device, 10), 10),
                    v.insert(Item::new("Zulu", device, 20), 20),
                )
            })
            .unwrap();
        vault.save().unwrap();
        let backup = vault.backup_now().unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
        let (view, mut vcx) = window(&state, &backup, cx);
        state.update(&mut vcx, |s, cx| s.set_sort(Sort::RecentlyCreated, cx));
        view.update(&mut vcx, |w, cx| w.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        view.read_with(&vcx, |w, _| {
            assert_eq!(w.sort, Sort::RecentlyCreated);
            assert_eq!(w.item_ids(), &[zulu, alpha], "newest first, not A–Z");
            assert_eq!(w.listing.rows.len(), 2, "no group headers");
        });
        assert!(vcx.debug_bounds("item-row 1").is_some());
        assert!(vcx.debug_bounds("item-row 2").is_none());
    }

    /// Wrong password, as on the main unlock screen (05 §2.2): the field shakes, keyed on
    /// the failure count so each failure replays it, with no error line, so the card keeps
    /// its height.
    #[gpui::test]
    fn wrong_password_shakes_without_resizing_the_card(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        let (view, mut vcx) = window(&state, &backup, cx);
        vcx.run_until_parked();
        let card = bounds("backup-card", &mut vcx);
        assert!(
            vcx.debug_bounds("backup-input-shake").is_none(),
            "no early shake"
        );
        for n in 1..=2 {
            view.update(&mut vcx, |w, cx| {
                w.unlock(SecretString::new(format!("nope{n}")), cx)
            });
            vcx.run_until_parked();
            view.read_with(&vcx, |w, _| {
                assert!(!w.is_open());
                assert_eq!(w.failures, n, "counter keys the shake");
                assert!(w.error.is_none(), "no error line");
            });
            assert!(
                vcx.debug_bounds("backup-input-shake").is_some(),
                "shake {n}"
            );
            assert_eq!(bounds("backup-card", &mut vcx), card, "card unchanged");
        }
        // The right password still opens it.
        view.update(&mut vcx, |w, cx| w.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        assert!(view.read_with(&vcx, |w, _| w.is_open()));
    }

    /// Under Reduce Motion a wrong password does not shake (no wrapper is drawn).
    #[gpui::test]
    fn reduce_motion_skips_the_shake(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        state.update(cx, |s, _| s.reduce_motion = true);
        let (view, mut vcx) = window(&state, &backup, cx);
        view.update(&mut vcx, |w, cx| {
            w.unlock(SecretString::new("nope".into()), cx)
        });
        vcx.run_until_parked();
        assert_eq!(view.read_with(&vcx, |w, _| w.failures), 1);
        assert!(vcx.debug_bounds("backup-input-shake").is_none());
        assert!(vcx.debug_bounds("backup-password").is_some());
    }

    /// While the backup is being verified the controls are hidden, not greyed, under the
    /// shared "Unlocking…" overlay, and the card keeps its size.
    #[gpui::test]
    fn verifying_hides_the_controls_under_the_overlay(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        let (view, mut vcx) = window(&state, &backup, cx);
        vcx.run_until_parked();
        let card = bounds("backup-card", &mut vcx);
        let field = bounds("backup-password", &mut vcx);
        assert!(vcx.debug_bounds("backup-unlocking").is_none());
        // Busy as during a background unlock (no task, so the state holds).
        view.update(&mut vcx, |w, cx| {
            w.busy = true;
            cx.notify();
        });
        vcx.run_until_parked();
        let overlay = bounds("backup-unlocking", &mut vcx);
        assert_eq!(bounds("backup-card", &mut vcx), card, "card unchanged");
        assert!(overlay.contains(&field.center()), "over the controls");
        // Hidden, not drawn disabled: the invisible controls paint nothing.
        assert!(vcx.debug_bounds("backup-password").is_none());
        view.update(&mut vcx, |w, cx| {
            w.busy = false;
            cx.notify();
        });
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("backup-unlocking").is_none());
        assert_eq!(bounds("backup-password", &mut vcx), field, "back in place");
    }

    /// Owner 2026-11-22: the viewer's list takes the main list's keys. ↓ ↓ walks to the
    /// third item (the detail follows), ↑ goes back, ⏎ moves to the detail; ⌘F then ↓
    /// leaves the search for the list and moves on; Esc clears a query. The main
    /// window's selection never moves.
    #[gpui::test]
    fn keyboard_navigates_the_backup_list(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new(PW.into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        let ids: Vec<Uuid> = vault
            .edit(|v| {
                ["Alpha", "Bravo", "Charlie"]
                    .map(|t| {
                        let mut item = Item::new(t, device, 1);
                        item.fields.push(Field::new(
                            "username",
                            FieldKind::Text,
                            SecretString::new(format!("{}-user", t.to_lowercase())),
                            1,
                        ));
                        v.insert(item, 1)
                    })
                    .to_vec()
            })
            .unwrap();
        vault.save().unwrap();
        let backup = vault.backup_now().unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
        // The main window's handlers too: in tests they would serve any window, so an
        // unhandled ↓ here would move the main selection.
        cx.update(|cx| {
            crate::actions::bind_keys(cx);
            crate::actions::register(&state, cx);
        });
        state.update(cx, |s, cx| s.select(ids[0], cx));
        let main_selection = state.read_with(cx, |s, _| s.selection);
        assert_eq!(main_selection, Some(ids[0]));
        let (view, mut vcx) = window(&state, &backup, cx);
        view.update(&mut vcx, |w, cx| w.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        let selected = |vcx: &mut VisualTestContext| view.read_with(vcx, |w, _| w.selection);
        let list_focused = |vcx: &mut VisualTestContext| {
            vcx.update(|window, cx| view.read(cx).list_focus.is_focused(window))
        };
        assert!(list_focused(&mut vcx), "the list has focus after unlock");
        assert_eq!(selected(&mut vcx), Some(ids[0]));

        vcx.simulate_keystrokes("down down");
        vcx.run_until_parked();
        assert_eq!(selected(&mut vcx), Some(ids[2]));
        assert!(vcx.debug_bounds("detail-title Charlie").is_some());
        vcx.simulate_keystrokes("down");
        assert_eq!(selected(&mut vcx), Some(ids[2]), "stops at the last item");
        vcx.simulate_keystrokes("up");
        vcx.run_until_parked();
        assert_eq!(selected(&mut vcx), Some(ids[1]));
        assert!(vcx.debug_bounds("detail-title Bravo").is_some());
        assert_eq!(state.read_with(&vcx, |s, _| s.selection), main_selection);

        // ⌘C in the list copies the backup item's username, with this window's pill;
        // the main window (Alpha selected there) copies nothing of its own.
        let board = crate::clipboard::fake::FakePasteboard::default();
        state.update(&mut vcx, |s, _| s.set_pasteboard(Box::new(board.clone())));
        vcx.simulate_keystrokes("cmd-c");
        vcx.run_until_parked();
        assert_eq!(board.contents().as_deref(), Some("bravo-user"));
        assert!(vcx.debug_bounds("detail-copy-feedback").is_some());
        assert_eq!(state.read_with(&vcx, |s, _| s.selection), main_selection);

        // ⏎ moves to the detail column, as in the main window.
        vcx.simulate_keystrokes("enter");
        assert!(vcx.update(|window, cx| view.read(cx).detail_focus.is_focused(window)));

        // ⌘F, then ↓: focus back in the list, one item further.
        vcx.simulate_keystrokes("cmd-f");
        assert!(!list_focused(&mut vcx));
        vcx.simulate_keystrokes("down");
        vcx.run_until_parked();
        assert!(list_focused(&mut vcx), "↓ leaves the search");
        assert_eq!(selected(&mut vcx), Some(ids[2]));

        // Esc clears a query in the search field.
        vcx.simulate_keystrokes("cmd-f");
        vcx.simulate_input("zz");
        vcx.run_until_parked();
        assert!(view.read_with(&vcx, |w, _| w.item_ids().is_empty()));
        vcx.simulate_keystrokes("escape");
        vcx.run_until_parked();
        view.read_with(&vcx, |w, cx| {
            assert!(ui::input_is_empty(&w.search, cx));
            assert_eq!(w.item_ids().len(), 3);
        });
        assert_eq!(state.read_with(&vcx, |s, _| s.selection), main_selection);

        // Locked: ⌘C through the list's key context copies nothing (the window's close
        // is deferred, so the action can still arrive).
        view.update(&mut vcx, |w, cx| {
            w.select(ids[1], cx);
            w.status = None;
        });
        board.set("from another app");
        vcx.update(|window, cx| {
            let list = view.read(cx).list_focus.clone();
            window.focus(&list, cx);
            state.update(cx, |s, cx| s.lock(cx));
            list.dispatch_action(&CopyUsername, window, cx);
            assert!(view.read(cx).status.is_none(), "no pill after lock");
        });
        assert_ne!(board.contents().as_deref(), Some("bravo-user"));
    }

    /// The password card is the unlock screen's (05 §2.3 "Backup viewer"): the app icon
    /// with the eye badge at its lower right, the vault name, "Backup from <time> ·
    /// read-only" from the backups list, the unlock placeholder, "Open read-only".
    #[gpui::test]
    fn prompt_is_the_unlock_card_with_badge_and_backup_line(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        let (view, mut vcx) = window(&state, &backup, cx);
        vcx.run_until_parked();
        let icon = bounds("backup-icon", &mut vcx);
        let badge = bounds("backup-badge", &mut vcx);
        assert!(icon.contains(&badge.center()), "on the icon");
        assert!(
            badge.center().x > icon.center().x && badge.center().y > icon.center().y,
            "lower right"
        );
        assert_eq!(icon.size.width, px(ui::UNLOCK_ICON_SIZE));
        // Owner decision 2026-11-22: 32 px, centre 6 px inside the box's corner.
        assert_eq!(badge.size.width, px(32.));
        assert_eq!(badge.size.height, px(32.));
        let name = bounds("backup-vault-name", &mut vcx);
        assert!(name.top() > icon.bottom());
        assert_eq!(
            view.read_with(&vcx, |w, _| w.vault_name.clone()),
            "Personal"
        );
        let line = view.read_with(&vcx, |w, _| w.subtitle.to_string());
        assert!(line.starts_with("Backup from "), "{line}");
        assert!(line.ends_with(" UTC \u{b7} read-only"), "{line}");
        let key: &'static str = Box::leak(format!("backup-subtitle {line}").into_boxed_str());
        let sub = bounds(key, &mut vcx);
        assert!(
            sub.top() >= name.bottom() && sub.bottom() < bounds("backup-password", &mut vcx).top()
        );
        assert!(vcx.debug_bounds("backup-open Open read-only").is_some());
        // The main unlock card's frame: same width.
        assert_eq!(bounds("backup-card", &mut vcx).size.width, px(360.));
    }

    /// The kind and time line: "Conflict copy from …" / "Unsaved copy from …" for those
    /// kinds, the bare file name when no timestamp parsed (not in the backups list).
    #[gpui::test]
    fn prompt_line_names_the_kind_or_falls_back_to_the_file_name(cx: &mut TestAppContext) {
        let path = std::path::Path::new("/x/backups/conflict-2023-11-14T22-13-20Z-t 2.vault");
        let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let info = |kind| BackupInfo {
            path: path.to_owned(),
            taken_at: at,
            size: 0,
            seq: 0,
            kind,
            validated: true,
        };
        assert_eq!(
            backup_subtitle(Some(&info(BackupKind::Conflict)), path),
            "Conflict copy from 2023-11-14 22:13 UTC \u{b7} read-only"
        );
        assert_eq!(
            backup_subtitle(Some(&info(BackupKind::Unsaved)), path),
            "Unsaved copy from 2023-11-14 22:13 UTC \u{b7} read-only"
        );
        assert_eq!(
            backup_subtitle(Some(&info(BackupKind::Snapshot)), path),
            "Backup from 2023-11-14 22:13 UTC \u{b7} read-only"
        );

        // Not in the list (a file outside `backups/`): its name, drawn on the card.
        let dir = tempfile::tempdir().unwrap();
        let (state, _) = setup(dir.path(), cx);
        let odd = dir.path().join("odd name.vault.bin");
        std::fs::write(&odd, b"x").unwrap();
        let (view, mut vcx) = window_with(&state, &odd, None, cx);
        vcx.run_until_parked();
        assert_eq!(
            view.read_with(&vcx, |w, _| w.subtitle.clone()),
            "odd name.vault.bin"
        );
        assert!(
            vcx.debug_bounds("backup-subtitle odd name.vault.bin")
                .is_some()
        );
        // A conflict entry passed in from the list words it as a conflict copy.
        let (view, vcx) = window_with(&state, &odd, Some(info(BackupKind::Conflict)), cx);
        vcx.run_until_parked();
        assert!(view.read_with(&vcx, |w, _| w.subtitle.starts_with("Conflict copy from ")));
    }

    /// L-11: a file named with a bidi override and an ESC is drawn sanitised in the strip
    /// title, the window title and the card's fallback name and line.
    #[gpui::test]
    fn hostile_file_name_is_sanitised_in_the_titles(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _) = setup(dir.path(), cx);
        let hostile = dir.path().join("evil\u{202e}gpj.\u{1b}[2Jvault");
        std::fs::write(&hostile, b"x").unwrap();
        let clean = "evil\u{fffd}gpj.\u{fffd}[2Jvault";
        let expected = format!("Backup \u{2014} {clean}");
        assert_eq!(backup_title(&hostile), expected);
        let (view, vcx) = window_with(&state, &hostile, None, cx);
        vcx.run_until_parked();
        let line = view.read_with(&vcx, |w, _| w.subtitle.clone());
        assert_eq!(
            line, clean,
            "the card's line when the file is not in the list"
        );
        let handle = cx
            .update(|cx| {
                open_backup_window(state.clone(), hostile.clone(), None, String::new(), cx)
            })
            .unwrap();
        let title = VisualTestContext::from_window(handle, cx).window_title();
        assert_eq!(title, Some(expected));
        let root = handle.downcast::<Root>().unwrap();
        let card_name = cx.update(|cx| {
            let view = root.read(cx).unwrap().view().clone();
            view.downcast::<BackupWindow>()
                .unwrap()
                .read(cx)
                .vault_name
                .to_string()
        });
        assert_eq!(card_name, clean, "the card's fallback name");
    }

    /// Opened from Settings (`AppState::open_backup`): the card's line comes from the
    /// backups list entry and its name is the open vault's.
    #[gpui::test]
    fn open_backup_passes_the_list_entry_and_vault_name(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        cx.update(gpui_component::init);
        state.update(cx, |s, _| {
            s.sync.backups = s.vault.as_ref().unwrap().backups().unwrap();
            // `install_unlocked_for_tests` sets no path: give the vault a known name.
            s.vault_path = Some(dir.path().join("Family.vault"));
        });
        let name = state.read_with(cx, |s, _| s.vault_name());
        assert!(!name.is_empty());
        state.update(cx, |s, cx| s.open_backup(backup.clone(), cx));
        cx.run_until_parked();
        let handle = state.read_with(cx, |s, _| s.backup_windows[0]);
        let root = handle.downcast::<Root>().unwrap();
        let (vault_name, line) = cx.update(|cx| {
            let view = root.read(cx).unwrap().view().clone();
            let w = view.downcast::<BackupWindow>().unwrap().read(cx);
            (w.vault_name.to_string(), w.subtitle.to_string())
        });
        assert!(line.starts_with("Backup from "), "{line}");
        assert_eq!(vault_name, name, "the open vault's name");
        assert_ne!(vault_name, text::file_name(&backup), "not the fallback");
    }

    fn click(key: &'static str, vcx: &mut VisualTestContext) {
        let at = bounds(key, vcx).center();
        vcx.simulate_click(at, gpui::Modifiers::default());
        vcx.run_until_parked();
    }

    /// Owner 2026-11-22: the main sidebar column, left of the list at the sidebar's
    /// default width, with the backup's counts and the Tags section.
    #[gpui::test]
    fn sidebar_shows_the_backups_counts_and_tags(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        let (_view, mut vcx, _) = opened(&state, &backup, cx);
        let column = bounds("sidebar-column", &mut vcx);
        assert_eq!(column.size.width, px(SIDEBAR.0));
        assert!(column.right() <= bounds("list-search", &mut vcx).left());
        assert!(column.top() >= bounds("backup-strip", &mut vcx).bottom());
        bounds("nav All Items icon=LayoutList", &mut vcx);
        bounds("nav-count All Items 2", &mut vcx);
        bounds("nav-count Favorites 0", &mut vcx);
        bounds("nav Tags icon=ChevronDown", &mut vcx);
        bounds("nav-count #work 1", &mut vcx);
        bounds("sidebar-name Personal", &mut vcx);
        assert!(
            vcx.debug_bounds("nav Recently Deleted icon=Trash")
                .is_none(),
            "hidden with an empty trash"
        );
    }

    /// A tag row filters the backup's list; the selection moves to the first hit and the
    /// main window's filter is untouched.
    #[gpui::test]
    fn tag_row_filters_the_backup_only(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        let (view, mut vcx, github) = opened(&state, &backup, cx);
        let alarm = view.read_with(&vcx, |w, _| w.item_ids()[0]);
        view.update(&mut vcx, |w, cx| w.select(alarm, cx));
        click("nav #work icon=Tag", &mut vcx);
        view.read_with(&vcx, |w, _| {
            assert_eq!(w.filter, Filter::Tag("work".into()));
            assert_eq!(w.item_ids(), &[github]);
            assert_eq!(w.selection, Some(github));
        });
        assert_eq!(state.read_with(&vcx, |s, _| s.filter.clone()), Filter::All);
        click("nav All Items icon=LayoutList", &mut vcx);
        assert_eq!(view.read_with(&vcx, |w, _| w.item_ids().len()), 2);
    }

    /// Recently Deleted lists the backup's own trash, with its count; the trashed item
    /// renders in the shared read view without the live trash's actions.
    #[gpui::test]
    fn recently_deleted_lists_the_backups_trash(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new(PW.into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        let gone = vault
            .edit(|v| {
                let mut kept = Item::new("Kept", device, 1);
                kept.favorite = true;
                v.insert(kept, 1);
                let gone = v.insert(Item::new("Gone", device, 1), 1);
                v.delete(gone, text::now_millis()).unwrap();
                gone
            })
            .unwrap();
        vault.save().unwrap();
        let backup = vault.backup_now().unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
        let (view, mut vcx) = window(&state, &backup, cx);
        view.update(&mut vcx, |w, cx| w.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        assert_eq!(view.read_with(&vcx, |w, _| w.item_ids().len()), 1);
        bounds("nav-count All Items 1", &mut vcx);
        bounds("nav-count Recently Deleted 1", &mut vcx);
        click("nav Recently Deleted icon=Trash", &mut vcx);
        view.read_with(&vcx, |w, _| {
            assert_eq!(w.item_ids(), &[gone]);
            assert_eq!(w.selection, Some(gone));
        });
        bounds("detail-title Gone", &mut vcx);
        bounds("backup-copy-item", &mut vcx);
        // Copied across, the trashed item arrives live: under All Items, not in the trash.
        let copy = view
            .update(&mut vcx, |w, cx| w.copy_to_current(cx))
            .expect("copied");
        state.read_with(&vcx, |s, _| {
            let v = s.unlocked_vault().unwrap();
            assert_eq!(v.get(copy).unwrap().deleted_at, None);
            assert!(v.items().any(|i| i.id == copy));
            assert!(v.deleted_items().all(|i| i.id != copy));
        });
        assert_eq!(state.read_with(&vcx, |s, _| s.filter.clone()), Filter::All);
        click("nav Favorites icon=Star", &mut vcx);
        let kept = view.read_with(&vcx, |w, _| {
            assert_eq!(w.item_ids().len(), 1);
            w.item_ids()[0]
        });
        assert_eq!(
            view.read_with(&vcx, |w, cx| w.item(kept, cx).unwrap().title.clone()),
            "Kept"
        );
    }

    /// Tags starts as the main window's at unlock time and toggles in this window only.
    #[gpui::test]
    fn tags_toggle_is_local_and_starts_as_main(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, backup) = setup(dir.path(), cx);
        let (view, mut vcx) = window(&state, &backup, cx);
        state.update(&mut vcx, |s, cx| s.toggle_tags(cx));
        view.update(&mut vcx, |w, cx| w.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("nav #work icon=Tag").is_none());
        click("nav Tags icon=ChevronRight", &mut vcx);
        bounds("nav #work icon=Tag", &mut vcx);
        click("nav Tags icon=ChevronDown", &mut vcx);
        assert!(vcx.debug_bounds("nav #work icon=Tag").is_none());
        assert!(!view.read_with(&vcx, |w, _| w.tags_open));
        click("nav Tags icon=ChevronRight", &mut vcx);
        assert!(view.read_with(&vcx, |w, _| w.tags_open));
        assert!(!state.read_with(&vcx, |s, _| s.tags_open), "main untouched");
    }
}
