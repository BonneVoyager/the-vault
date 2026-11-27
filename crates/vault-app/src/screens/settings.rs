//! Settings sheet (specs/05-ui.md §2.5): a dialog with tabs. The Security tab (Touch ID,
//! master password, encryption strength, key rotation) is its own view (`security.rs`).
//!
//! Every preference writes through `AppState::update_settings`, which sanitizes, persists
//! settings.json and takes effect immediately. The selected tab lives in `AppState` so
//! File ▸ Export… and the restore flow can jump to theirs.

use gpui::{
    App, AppContext as _, Context, Entity, InteractiveElement as _, IntoElement,
    ParentElement as _, Render, SharedString, StatefulInteractiveElement as _, Styled as _,
    Subscription, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::menu::DropdownMenu as _;
use gpui_component::switch::Switch;
use gpui_component::tab::{Tab, TabBar};
use gpui_component::tag::Tag;
use gpui_component::tooltip::Tooltip;
use gpui_component::{ActiveTheme as _, Disableable as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;
use vault_sync::{BackupInfo, BackupKind};

use super::security::SecurityView;
use crate::state::{
    AppState, Appearance, Busy, LoginRow, NOT_THIS_VAULT, RestorePrompt, SECURITY_TAB, SYNC_TAB,
    Settings, SyncStatus, TRANSFER_TAB, TextSize,
};
use crate::ui::Clickable as _;
use crate::{cloud, text, ui};

const TABS: [&str; 5] = [
    "General",
    "Security",
    "Sync & Backup",
    "Import / Export",
    "About",
];

/// Text of the red export confirm.
pub const EXPORT_WARNING: &str = "The CSV file contains every password in plain text. \
     Anyone who can read the file can read your passwords.";

/// Tag shown instead of the kind on a backups-list row vault-sync could not validate
/// (L-04).
pub const UNKNOWN_FILE: &str = "Unknown file";

pub struct SettingsView {
    state: Entity<AppState>,
    /// Master password for restoring a backup.
    restore_input: Entity<InputState>,
    security: Entity<SecurityView>,
    kdbx: Entity<super::kdbx_import::KdbxImportView>,
    _subscriptions: Vec<Subscription>,
}

impl SettingsView {
    pub fn new(state: Entity<AppState>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let restore_input = ui::password_input("Master password of the backup", window, cx);
        let security = cx.new(|cx| SecurityView::new(state.clone(), window, cx));
        let kdbx = cx.new(|cx| super::kdbx_import::KdbxImportView::new(state.clone(), window, cx));
        let subscriptions = vec![
            cx.subscribe_in(
                &restore_input,
                window,
                |this, _, ev: &InputEvent, window, cx| {
                    if let InputEvent::PressEnter { .. } = ev {
                        this.submit_restore(window, cx);
                    }
                },
            ),
            // Clear the password field whenever the restore prompt goes away.
            cx.observe_in(&state, window, |this, state, window, cx| {
                let asking = state
                    .read(cx)
                    .sync
                    .restore
                    .as_ref()
                    .is_some_and(|r| r.asking_password);
                if !asking && !ui::input_is_empty(&this.restore_input, cx) {
                    ui::clear_input(&this.restore_input, window, cx);
                }
                cx.notify();
            }),
        ];
        Self {
            state,
            restore_input,
            security,
            kdbx,
            _subscriptions: subscriptions,
        }
    }

    fn submit_restore(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if ui::input_is_empty(&self.restore_input, cx) {
            return;
        }
        let password = ui::input_secret(&self.restore_input, cx);
        ui::clear_input(&self.restore_input, window, cx);
        self.state
            .update(cx, |s, cx| s.restore_backup(password, cx));
    }
}

const DOCK_HINT: &str = "Also hides the menu bar. A padlock in the menu bar opens Vault instead.";
const LOGIN_HINT: &str = "Starts in the menu bar when the Dock icon is off.";

fn auto_lock_label(minutes: Option<u32>) -> SharedString {
    match minutes {
        None => "Never".into(),
        Some(1) => "1 minute".into(),
        Some(m) => format!("{m} minutes").into(),
    }
}

const BACKUP_HINT: &str = "Copies the vault into the package after changes, about once an hour.";

/// A retention tab: the daily tier's length, `round(30 × m)` days (03 §4, vault-sync `retain`).
fn retention_label(m: f32) -> String {
    format!("{} days", (30.0 * m).round() as u32)
}

/// The retention hint for multiplier `m`: the monthly tier keeps `round(36 × m)` months,
/// shown as months below two years and as whole years from there.
fn retention_hint(m: f32) -> String {
    let months = (36.0 * m).round() as u32;
    let span = if months < 24 {
        format!("{months} months")
    } else {
        format!("{} years", months / 12)
    };
    format!("Older copies thin out to weekly, then monthly for {span}.")
}

/// One labelled settings row: label left, control right. Its divider comes from
/// [`section`]. The label column may shrink below its text width (`min_w_0`) and the
/// control never shrinks, so a wide control wraps the label instead of running past the
/// pane's right edge.
fn row(label: &'static str, control: impl IntoElement) -> gpui::Div {
    ui::h_flex()
        .py(px(10.))
        .gap(px(12.))
        .child(div().flex_1().min_w_0().text_sm().child(label))
        .child(div().flex_none().child(control))
}

/// A [`row`] with a muted hint under it: the label shares the first line with the
/// control, the hint runs under both at the full row width. `tag` names the hint's test
/// selector `settings-{tag}-hint: {hint}` (gpui exposes no painted text to tests: the
/// selector carries the string this element renders), the label `settings-{tag}-label`
/// and the control wrapper `settings-{tag}-control`.
fn hinted_row(
    label: &'static str,
    hint: impl Into<SharedString>,
    tag: &'static str,
    control: impl IntoElement,
    cx: &App,
) -> gpui::Div {
    let hint = hint.into();
    let selector = format!("settings-{tag}-hint: {hint}");
    ui::v_flex()
        .py(px(10.))
        .gap(px(2.))
        .child(
            ui::h_flex()
                .gap(px(12.))
                .items_center()
                .child(
                    div()
                        .debug_selector(move || format!("settings-{tag}-label"))
                        .flex_1()
                        .min_w_0()
                        .text_sm()
                        .child(label),
                )
                .child(
                    div()
                        .flex_none()
                        .debug_selector(move || format!("settings-{tag}-control"))
                        .child(control),
                ),
        )
        .child(
            ui::muted(hint, cx)
                .text_xs()
                .debug_selector(move || selector.clone()),
        )
}

/// A settings row plus whatever hangs under it (an inline form), which sits below the
/// row's divider.
pub(super) type SectionRow = (gpui::Div, Option<gpui::AnyElement>);

/// A group of rows separated by hairlines: every row except the last gets a bottom
/// border. Settings has no footer for a last line to close against, so nothing trails
/// the final row. Each row is tagged `settings-row {name} {index}` for tests.
pub(super) fn section(name: &'static str, rows: Vec<SectionRow>, cx: &App) -> gpui::Div {
    let border = cx.theme().border;
    let last = rows.len().saturating_sub(1);
    ui::v_flex().children(rows.into_iter().enumerate().flat_map(|(ix, (row, below))| {
        let row = row
            .debug_selector(move || format!("settings-row {name} {ix}"))
            .when(ix < last, |r| r.border_b_1().border_color(border))
            .into_any_element();
        std::iter::once(row).chain(below)
    }))
}

/// A tinted inline confirm strip (restore, export).
fn confirm_strip(danger: bool, cx: &App) -> gpui::Div {
    let theme = cx.theme();
    let tint = if danger { theme.danger } else { theme.warning };
    ui::v_flex()
        .gap(px(8.))
        .px(px(12.))
        .py(px(10.))
        .rounded(theme.radius)
        .bg(tint.opacity(0.10))
        .border_1()
        .border_color(tint.opacity(0.35))
}

/// A dropdown button listing `choices`, with the current one checked.
fn choice<T: Copy + PartialEq + 'static>(
    id: &'static str,
    current: T,
    choices: &'static [T],
    label: fn(T) -> SharedString,
    state: &Entity<AppState>,
    apply: fn(&mut Settings, T),
) -> impl IntoElement {
    let state = state.clone();
    Button::new(id)
        .small()
        .label(label(current))
        .icon(Icon::new(IconName::ChevronsUpDown))
        .clickable()
        .dropdown_menu(move |menu, _, _| {
            choices.iter().fold(menu, |menu, value| {
                let (value, state) = (*value, state.clone());
                menu.item(ui::menu_item(
                    label(value),
                    value == current,
                    move |_, _, cx| {
                        state.update(cx, |s, cx| s.update_settings(cx, |st| apply(st, value)));
                    },
                ))
            })
        })
}

/// A segmented control writing the chosen index into the settings.
fn segmented(
    id: &'static str,
    labels: &[&'static str],
    selected: usize,
    state: &Entity<AppState>,
    apply: fn(&mut Settings, usize),
) -> ui::Segmented {
    let state = state.clone();
    ui::segmented(id, labels.iter().copied(), selected).on_select(move |ix, _, cx| {
        state.update(cx, |s, cx| s.update_settings(cx, |st| apply(st, ix)));
    })
}

/// A button that calls `f` on the app state.
fn state_button(
    id: impl Into<gpui::ElementId>,
    label: &'static str,
    state: &Entity<AppState>,
    f: impl Fn(&mut AppState, &mut Context<AppState>) + 'static,
) -> Button {
    let state = state.clone();
    Button::new(id)
        .small()
        .label(label)
        .clickable()
        .on_click(move |_, _, cx| state.update(cx, |s, cx| f(s, cx)))
}

impl SettingsView {
    fn general(&self, cx: &App) -> gpui::Div {
        let settings = self.state.read(cx).settings.clone();
        let state = self.state.clone();
        let rows = vec![
            row(
                "Auto-lock after",
                choice(
                    "auto-lock",
                    settings.auto_lock_minutes,
                    &Settings::AUTO_LOCK_CHOICES,
                    auto_lock_label,
                    &self.state,
                    |s, v| s.auto_lock_minutes = v,
                ),
            ),
            row(
                "Lock on sleep, screen lock or user switch",
                Switch::new("lock-on-sleep")
                    .checked(settings.lock_on_sleep)
                    .accessibility_label("Lock on sleep, screen lock or user switch")
                    .clickable()
                    .on_click(move |on, _, cx| {
                        let on = *on;
                        state.update(cx, |s, cx| {
                            s.update_settings(cx, |st| st.lock_on_sleep = on)
                        });
                    }),
            ),
            row(
                "Clear clipboard after",
                choice(
                    "clipboard-clear",
                    settings.clipboard_clear_secs,
                    &Settings::CLIPBOARD_CHOICES,
                    |secs| format!("{secs} seconds").into(),
                    &self.state,
                    |s, v| s.clipboard_clear_secs = v,
                ),
            ),
            row(
                "Appearance",
                segmented(
                    "appearance",
                    &Appearance::ALL.map(Appearance::label),
                    Appearance::ALL
                        .iter()
                        .position(|a| *a == settings.appearance)
                        .unwrap_or(0),
                    &self.state,
                    |st, ix| st.appearance = Appearance::ALL[ix],
                )
                .aria_label("Appearance"),
            ),
            row(
                "Text size",
                segmented(
                    "text-size",
                    &TextSize::ALL.map(TextSize::label),
                    TextSize::ALL
                        .iter()
                        .position(|t| *t == settings.text_size)
                        .unwrap_or(0),
                    &self.state,
                    |st, ix| st.text_size = TextSize::ALL[ix],
                )
                .aria_label("Text size"),
            ),
        ];
        let rows = rows
            .into_iter()
            .chain([self.dock_row(cx)])
            .chain(self.login_item_row(cx))
            .map(|r| (r, None))
            .collect();
        section("general", rows, cx)
    }

    /// "Show Vault in Dock" (04 §5b), always shown, with its hint under the label.
    fn dock_row(&self, cx: &App) -> gpui::Div {
        let state = self.state.clone();
        let switch = Switch::new("show-in-dock")
            .checked(self.state.read(cx).settings.show_in_dock)
            .accessibility_label("Show Vault in Dock")
            .clickable()
            .on_click(move |on, _, cx| {
                let on = *on;
                state.update(cx, |s, cx| s.update_settings(cx, |st| st.show_in_dock = on));
            });
        let control = div()
            .debug_selector(|| "settings-dock-switch".into())
            .child(switch);
        hinted_row("Show Vault in Dock", DOCK_HINT, "dock", control, cx)
    }

    /// "Launch at login" (hidden outside an .app bundle), with its hint under the label.
    fn login_item_row(&self, cx: &App) -> Option<gpui::Div> {
        let control = match self.state.read(cx).login_row() {
            LoginRow::Hidden => return None,
            LoginRow::Toggle(on) => {
                let state = self.state.clone();
                Switch::new("launch-at-login")
                    .checked(on)
                    .accessibility_label("Launch at login")
                    .clickable()
                    .on_click(move |on, _, cx| {
                        let on = *on;
                        state.update(cx, |s, cx| s.set_launch_at_login(on, cx));
                    })
                    .into_any_element()
            }
            LoginRow::NeedsApproval => Button::new("login-items")
                .small()
                .label("Allow in System Settings\u{2026}")
                .clickable()
                .on_click(|_, _, _| vault_macos::open_login_items_settings())
                .into_any_element(),
        };
        Some(hinted_row(
            "Launch at login",
            LOGIN_HINT,
            "login",
            control,
            cx,
        ))
    }

    /// Sync & Backup (§2.5, 03 §4). The path shown and revealed is the `.vault` package.
    fn sync(&self, cx: &App) -> gpui::Div {
        let s = self.state.read(cx);
        let theme = cx.theme();
        let Some(path) = s.vault_path.clone() else {
            return ui::v_flex().py(px(10.)).child(ui::muted(
                "Open a vault to see its sync and backup settings.",
                cx,
            ));
        };
        let settings = &s.settings;
        let provider = cloud::provider_label(&path).unwrap_or_else(|| "Local folder".to_owned());
        let saved = s
            .sync
            .last_saved
            .map_or("Not saved this session".to_owned(), |t| {
                format!("Last saved {}", text::date_time(t))
            });
        let watching = if s.is_watching() {
            "watching for changes"
        } else {
            "not watching for changes"
        };
        let status = format!("{saved} \u{b7} {provider} \u{b7} {watching}");
        let sync_error = match &s.sync_status {
            SyncStatus::Error(e) => Some(e.clone()),
            SyncStatus::Idle => None,
        };

        let reveal_path = path.clone();
        // Heading and button share the first line; path, status and error run under
        // them at the full row width, like the other rows' hints.
        let location = ui::v_flex()
            .py(px(10.))
            .gap(px(6.))
            .child(
                ui::h_flex()
                    .gap(px(12.))
                    .items_center()
                    .child(div().flex_1().min_w_0().text_sm().child("Vault package"))
                    .child(
                        div()
                            .flex_none()
                            .debug_selector(|| "settings-reveal-vault".into())
                            .child(
                                Button::new("reveal-vault")
                                    .small()
                                    .label("Reveal in Finder")
                                    .clickable()
                                    .on_click(move |_, _, cx| cx.reveal_path(&reveal_path)),
                            ),
                    ),
            )
            .child(
                div()
                    .debug_selector(|| "settings-vault-path".into())
                    .text_xs()
                    .font_family(theme.mono_font_family.clone())
                    .text_color(theme.muted_foreground)
                    .truncate()
                    .child(path.display().to_string()),
            )
            .child(ui::muted(status, cx))
            .when_some(sync_error, |col, e| {
                col.child(div().text_sm().text_color(theme.danger).child(e))
            });

        let enabled_state = self.state.clone();
        let retention_state = self.state.clone();
        let current = Settings::RETENTION_CHOICES
            .iter()
            .position(|m| *m == settings.retention_multiplier)
            .unwrap_or(1);
        let retention = ui::segmented(
            "retention",
            Settings::RETENTION_CHOICES.map(retention_label),
            current,
        )
        .selector("settings-retention-tab")
        .aria_label("Keep daily backups for")
        .on_select(move |ix, _, cx| {
            if let Some(m) = Settings::RETENTION_CHOICES.get(ix).copied() {
                retention_state.update(cx, |s, cx| {
                    s.update_settings(cx, |st| st.retention_multiplier = m)
                });
            }
        });

        let rows = vec![
            location,
            hinted_row(
                "Automatic backups",
                BACKUP_HINT,
                "backup-enabled",
                Switch::new("backup-enabled")
                    .checked(settings.backup_enabled)
                    .accessibility_label("Automatic backups")
                    .clickable()
                    .on_click(move |on, _, cx| {
                        let on = *on;
                        enabled_state.update(cx, |s, cx| {
                            s.update_settings(cx, |st| st.backup_enabled = on)
                        });
                    }),
                cx,
            ),
            hinted_row(
                "Keep daily backups for",
                retention_hint(Settings::RETENTION_CHOICES[current]),
                "retention",
                retention,
                cx,
            ),
            row(
                "Backups",
                state_button("backup-now", "Back up now", &self.state, |s, cx| {
                    s.backup_now(cx)
                }),
            ),
        ];
        ui::v_flex()
            .child(section(
                "sync",
                rows.into_iter().map(|r| (r, None)).collect(),
                cx,
            ))
            .child(self.backups(s, cx))
    }

    fn backups(&self, s: &AppState, cx: &App) -> gpui::AnyElement {
        if let Some(e) = s.sync.backups_error.clone() {
            // L-05: the state already reworded it; the Repair strip carries the action.
            if s.sync.backups_unsafe {
                return ui::muted(e, cx).into_any_element();
            }
            return div()
                .text_sm()
                .text_color(cx.theme().danger)
                .child(e)
                .into_any_element();
        }
        if s.sync.backups.is_empty() {
            return ui::muted("No backups yet.", cx).into_any_element();
        }
        let rows = s
            .sync
            .backups
            .iter()
            .enumerate()
            .map(|(ix, b)| (self.backup_row(ix, b, s, cx), None))
            .collect();
        section("backups", rows, cx)
            .id("backups")
            .max_h(px(220.))
            .overflow_y_scroll()
            .into_any_element()
    }

    fn backup_row(&self, ix: usize, b: &BackupInfo, s: &AppState, cx: &App) -> gpui::Div {
        let restore = s.sync.restore.as_ref().filter(|r| r.backup == b.path);
        let confirming = s.sync.delete_confirm.as_ref() == Some(&b.path);
        let date = text::date_time(b.taken_at);
        if !b.validated {
            return self.unknown_backup_row(ix, b, date, confirming, s, cx);
        }
        let line = ui::h_flex()
            .w_full()
            .min_w_0()
            .py(px(6.))
            .gap(px(8.))
            .child(div().text_sm().child(date.clone()))
            .map(|row| match b.kind {
                BackupKind::Snapshot => row,
                BackupKind::Conflict => row.child(Tag::warning().small().child("Conflict copy")),
                BackupKind::Unsaved => row.child(Tag::info().small().child("Unsaved edits")),
            })
            .child(div().flex_1());
        // While confirming, the size gives way to the question so the buttons fit.
        let line = if confirming {
            self.delete_confirm(line, cx)
        } else {
            let line = line.child(ui::muted(text::file_size(b.size), cx));
            self.backup_actions(line, ix, b, date, s)
        };
        ui::v_flex()
            .child(line)
            .children(restore.map(|r| self.restore_prompt(r, s, cx)))
    }

    /// A file in `backups/` that vault-sync could not tie to this vault (L-04): a muted
    /// "Unknown file" tag instead of the kind, no Open or Restore, the tooltip
    /// [`NOT_THIS_VAULT`] over the row. It can still be deleted.
    fn unknown_backup_row(
        &self,
        ix: usize,
        b: &BackupInfo,
        date: String,
        confirming: bool,
        s: &AppState,
        cx: &App,
    ) -> gpui::Div {
        let info = ui::h_flex()
            .id(("backup-unknown", ix))
            .debug_selector(move || format!("backup-unknown {ix}"))
            .gap(px(8.))
            .child(div().text_sm().child(date.clone()))
            .child(Tag::secondary().small().child(UNKNOWN_FILE))
            .tooltip(|window, cx| Tooltip::new(NOT_THIS_VAULT).build(window, cx));
        let line = ui::h_flex()
            .w_full()
            .min_w_0()
            .py(px(6.))
            .gap(px(8.))
            .child(info)
            .child(div().flex_1());
        if confirming {
            self.delete_confirm(line, cx)
        } else {
            line.child(ui::muted(text::file_size(b.size), cx))
                .child(self.delete_backup_button(ix, b, date, s.busy.is_some()))
        }
    }

    /// The trash button at the right of a backup row.
    fn delete_backup_button(
        &self,
        ix: usize,
        b: &BackupInfo,
        date: impl std::fmt::Display,
        busy: bool,
    ) -> Button {
        let state = self.state.clone();
        let path = b.path.clone();
        ui::icon_button(("delete-backup", ix), IconName::Trash, "Delete backup")
            .accessibility_label(format!("Delete backup from {date}"))
            .disabled(busy)
            .clickable_when(!busy)
            .on_click(move |_, _, cx| {
                state.update(cx, |s, cx| s.request_delete_backup(path.clone(), cx))
            })
    }

    /// Open, Restore… and the trash button at the right of a backup row.
    fn backup_actions(
        &self,
        line: gpui::Div,
        ix: usize,
        b: &BackupInfo,
        date: impl std::fmt::Display,
        s: &AppState,
    ) -> gpui::Div {
        let busy = s.busy.is_some();
        line.child(state_button(("open-backup", ix), "Open", &self.state, {
            let path = b.path.clone();
            move |s, cx| s.open_backup(path.clone(), cx)
        }))
        .child(
            state_button(("restore-backup", ix), "Restore\u{2026}", &self.state, {
                let path = b.path.clone();
                move |s, cx| s.request_restore(path.clone(), cx)
            })
            .disabled(s.locked || busy)
            .clickable_when(!s.locked && !busy)
            .when(s.locked, |b| b.tooltip("Unlock the vault to restore")),
        )
        .child(self.delete_backup_button(ix, b, date, busy))
    }

    /// The row's size and actions replaced by "Delete this backup?" with Cancel / Delete.
    /// The question truncates first at narrow widths; the buttons never shrink.
    fn delete_confirm(&self, line: gpui::Div, cx: &App) -> gpui::Div {
        line.debug_selector(|| "backup-delete-confirm".into())
            .child(
                ui::muted("Delete this backup?", cx)
                    .min_w_0()
                    .flex_shrink(1.)
                    .truncate(),
            )
            .child(
                state_button("backup-delete-cancel", "Cancel", &self.state, |s, cx| {
                    s.cancel_delete_backup(cx)
                })
                .ghost()
                .flex_none(),
            )
            .child(
                state_button("backup-delete-ok", "Delete", &self.state, |s, cx| {
                    s.confirm_delete_backup(cx)
                })
                .danger()
                .flex_none(),
            )
    }

    fn restore_prompt(&self, r: &RestorePrompt, s: &AppState, cx: &App) -> gpui::Div {
        let theme = cx.theme();
        let cancel = state_button("restore-cancel", "Cancel", &self.state, |s, cx| {
            s.cancel_restore(cx)
        })
        .ghost();
        let strip = confirm_strip(true, cx).mb(px(8.));
        if !r.asking_password {
            return strip
                .child(div().text_sm().child(
                    "Replace the current vault with this backup? The current vault is \
                     backed up first.",
                ))
                .child(
                    ui::h_flex().gap(px(8.)).justify_end().child(cancel).child(
                        state_button(
                            "restore-confirm",
                            "Replace\u{2026}",
                            &self.state,
                            |s, cx| s.confirm_restore(cx),
                        )
                        .danger(),
                    ),
                );
        }
        let busy = s.busy == Some(Busy::Restoring);
        // The master password is the strip's only input: a revealed one is never copied out.
        ui::refuse_plain_copy(strip)
            .child(
                div()
                    .text_sm()
                    .child("Enter the master password this backup was saved with."),
            )
            .child(ui::input(&self.restore_input).small().mask_toggle())
            .when_some(r.error.clone(), |col, e| {
                col.child(div().text_sm().text_color(theme.danger).child(e))
            })
            .child(
                ui::h_flex().gap(px(8.)).justify_end().child(cancel).child(
                    Button::new("restore-submit")
                        .danger()
                        .small()
                        .label("Restore")
                        .loading(busy)
                        .clickable_when(!busy)
                        .on_click({
                            let input = self.restore_input.clone();
                            let state = self.state.clone();
                            move |_, window, cx| {
                                if ui::input_is_empty(&input, cx) {
                                    return;
                                }
                                let password = ui::input_secret(&input, cx);
                                ui::clear_input(&input, window, cx);
                                state.update(cx, |s, cx| s.restore_backup(password, cx));
                            }
                        }),
                ),
            )
    }

    /// Import / Export (§2.5).
    fn transfer(&self, cx: &App) -> gpui::Div {
        let s = self.state.read(cx);
        if !s.main_active() {
            return ui::v_flex()
                .py(px(10.))
                .child(ui::muted("Unlock the vault to import or export items.", cx));
        }
        let export = if s.sync.export_confirm {
            // A pick in a cloud folder (L-12): the confirm names the provider and its
            // button writes that pick instead of opening the panel again.
            let cloud = s.sync.export_cloud.as_ref().map(|c| c.provider.clone());
            let cloud_pick = cloud.is_some();
            confirm_strip(true, cx)
                .mt(px(10.))
                .child(div().text_sm().child(EXPORT_WARNING))
                .when_some(cloud, |strip, provider| {
                    strip.child(
                        div()
                            .debug_selector(|| "export-cloud-hint".into())
                            .text_sm()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(crate::state::export_cloud_hint(&provider)),
                    )
                })
                .child(
                    ui::h_flex()
                        .gap(px(8.))
                        .justify_end()
                        .child(
                            state_button("export-cancel", "Cancel", &self.state, |s, cx| {
                                s.set_export_confirm(false, cx)
                            })
                            .ghost(),
                        )
                        .child(
                            if cloud_pick {
                                state_button(
                                    "export-confirm",
                                    "Export Anyway",
                                    &self.state,
                                    |s, cx| {
                                        s.confirm_cloud_export(cx);
                                    },
                                )
                            } else {
                                state_button(
                                    "export-confirm",
                                    "Export\u{2026}",
                                    &self.state,
                                    |s, cx| s.choose_export_path(cx),
                                )
                            }
                            .danger(),
                        ),
                )
        } else {
            div()
        };
        let rows = vec![
            row(
                "Import from CSV",
                state_button("import-csv", "Import CSV\u{2026}", &self.state, |s, cx| {
                    s.choose_import_path(cx)
                }),
            ),
            row(
                "Import from 1Password (1PUX)",
                state_button(
                    "import-1pux",
                    "Import 1PUX\u{2026}",
                    &self.state,
                    |s, cx| s.choose_import_1pux(cx),
                ),
            ),
            row(
                "Import from KeePass (KDBX)",
                state_button("import-kdbx", "Import KDBX…", &self.state, |s, cx| {
                    s.choose_import_kdbx(cx)
                })
                .disabled(s.busy.is_some())
                .clickable_when(s.busy.is_none()),
            ),
            row(
                "Export to CSV (unencrypted)",
                state_button("export-csv", "Export CSV\u{2026}", &self.state, |s, cx| {
                    s.set_export_confirm(true, cx)
                }),
            ),
        ];
        section(
            "transfer",
            rows.into_iter().map(|r| (r, None)).collect(),
            cx,
        )
        .child(export)
        .child(self.kdbx.clone())
    }

    fn about(&self, cx: &App) -> gpui::Div {
        ui::v_flex().py(px(10.)).child(ui::muted(
            format!("Vault {}", env!("CARGO_PKG_VERSION")),
            cx,
        ))
    }
}

impl Render for SettingsView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tab = self.state.read(cx).settings_tab.min(TABS.len() - 1);
        let state = self.state.clone();
        let tabs = TabBar::new("settings-tabs")
            .underline()
            .small()
            .selected_index(tab)
            .children(TABS.map(|t| Tab::new().label(t).clickable()))
            .on_click(move |ix: &usize, _, cx| {
                let ix = *ix;
                state.update(cx, |s, cx| {
                    s.settings_tab = ix;
                    if ix == SYNC_TAB {
                        s.refresh_backups();
                    }
                    cx.notify();
                });
            });
        let body = match tab {
            0 => self.general(cx),
            SYNC_TAB => self.sync(cx),
            SECURITY_TAB => div().child(self.security.clone()),
            TRANSFER_TAB => self.transfer(cx),
            _ => self.about(cx),
        };
        ui::v_flex()
            .gap(px(8.))
            .min_h(px(220.))
            .debug_selector(|| "settings-pane".into())
            .child(tabs)
            .child(body)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gpui::{TestAppContext, VisualTestContext};
    use gpui_component::Root;
    use vault_core::{Item, KdfParams, SecretString, Uuid};
    use vault_sync::{NoopHooks, SyncedVault};

    use super::*;
    use crate::state::SecurityForm;
    use crate::theme;

    const SECTIONS: [&str; 6] = [
        "general",
        "security",
        "security-advanced",
        "sync",
        "backups",
        "transfer",
    ];

    /// Bounds of `settings-row {name} {ix}`, if rendered.
    fn row_bounds(
        name: &str,
        ix: usize,
        vcx: &mut VisualTestContext,
    ) -> Option<gpui::Bounds<gpui::Pixels>> {
        let key: &'static str = Box::leak(format!("settings-row {name} {ix}").into_boxed_str());
        vcx.debug_bounds(key)
    }

    /// Whether a quad with a bottom border is painted exactly over `bounds`.
    fn has_bottom_border(bounds: gpui::Bounds<gpui::Pixels>, vcx: &mut VisualTestContext) -> bool {
        vcx.update(|window, _| {
            let b = bounds.scale(window.scale_factor());
            let near = |a: gpui::ScaledPixels, c: gpui::ScaledPixels| (a.0 - c.0).abs() < 0.5;
            window.painted_quads().iter().any(|q| {
                near(q.bounds.origin.x, b.origin.x)
                    && near(q.bounds.origin.y, b.origin.y)
                    && near(q.bounds.size.width, b.size.width)
                    && near(q.bounds.size.height, b.size.height)
                    && q.border_widths.bottom.0 > 0.
            })
        })
    }

    /// For every section shown: a divider under each row but the last. Returns the
    /// sections found with their row counts.
    fn check_dividers(vcx: &mut VisualTestContext) -> Vec<(&'static str, usize)> {
        let mut found = Vec::new();
        for name in SECTIONS {
            let rows: Vec<_> = (0..).map_while(|ix| row_bounds(name, ix, vcx)).collect();
            if rows.is_empty() {
                continue;
            }
            let dividers: Vec<bool> = rows.iter().map(|b| has_bottom_border(*b, vcx)).collect();
            let last = rows.len() - 1;
            for (ix, divided) in dividers.iter().enumerate() {
                assert_eq!(
                    *divided,
                    ix < last,
                    "{name} row {ix} of {}: divider {divided}",
                    rows.len()
                );
            }
            found.push((name, rows.len()));
        }
        found
    }

    fn show_tab(tab: usize, state: &Entity<AppState>, vcx: &mut VisualTestContext) {
        state.update(vcx, |s, cx| {
            s.settings_tab = tab;
            cx.notify();
        });
        vcx.run_until_parked();
    }

    /// The owner's screenshot showed a line under the last row of every tab: rows are
    /// separated only between each other, nothing trails the final row of a section.
    #[gpui::test]
    fn no_divider_after_the_last_row(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        for (n, title) in ["GitHub", "GitLab", "Codeberg"].into_iter().enumerate() {
            let at = n as u64 + 1;
            vault
                .edit(|v| v.insert(Item::new(title, device, at), at))
                .unwrap();
            vault.save().unwrap();
            vault.backup_now().unwrap();
        }

        cx.update(gpui_component::init);
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        let mut settings = None;
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| SettingsView::new(state.clone(), window, cx));
            settings = Some(view.clone());
            Root::new(view, window, cx)
        });
        let settings = settings.unwrap();
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        state.update(&mut vcx, |s, cx| {
            s.install_unlocked_for_tests(vault);
            s.refresh_backups();
            s.open_settings(true, cx);
        });
        vcx.run_until_parked();

        show_tab(0, &state, &mut vcx);
        let general = check_dividers(&mut vcx);
        assert!(
            matches!(general[..], [("general", n)] if n >= 5),
            "{general:?}"
        );

        // Security with an inline form open (it hangs below its row's divider) and the
        // Advanced section expanded.
        show_tab(SECURITY_TAB, &state, &mut vcx);
        state.update(&mut vcx, |s, cx| {
            s.toggle_security_advanced(cx);
            s.set_security_form(Some(SecurityForm::ChangePassword), cx);
        });
        vcx.run_until_parked();
        assert_eq!(
            check_dividers(&mut vcx),
            [("security", 3), ("security-advanced", 1)]
        );

        show_tab(SYNC_TAB, &state, &mut vcx);
        let sync = check_dividers(&mut vcx);
        assert!(
            matches!(sync[..], [("sync", 4), ("backups", n)] if n >= 2),
            "{sync:?}"
        );
        // Restore's backup password: revealed, it never reaches the pasteboard.
        state.update(&mut vcx, |s, cx| {
            let backup = s.sync.backups[0].path.clone();
            s.request_restore(backup, cx);
            s.confirm_restore(cx);
        });
        vcx.run_until_parked();
        let restore = settings.read_with(&vcx, |v, _| v.restore_input.clone());
        ui::assert_revealed_copy_refused(&restore, &mut vcx);
        state.update(&mut vcx, |s, cx| s.cancel_restore(cx));
        vcx.run_until_parked();

        show_tab(TRANSFER_TAB, &state, &mut vcx);
        assert_eq!(check_dividers(&mut vcx), [("transfer", 4)]);

        show_tab(TABS.len() - 1, &state, &mut vcx);
        assert!(check_dividers(&mut vcx).is_empty(), "About has no rows");

        // Locked: lock closes the sheet and it cannot be reopened until unlocked.
        state.update(&mut vcx, |s, cx| {
            s.lock(cx);
            s.open_settings(true, cx);
        });
        vcx.run_until_parked();
        assert!(!state.read_with(&vcx, |s, _| s.settings_open));
    }

    /// "Show Vault in Dock" sits directly above "Launch at login", carries its hint, and
    /// toggling it flips and persists `show_in_dock`.
    #[gpui::test]
    fn settings_dock_row_above_login_and_toggles(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        cx.update(gpui_component::init);
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| SettingsView::new(state.clone(), window, cx));
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        state.update(&mut vcx, |s, cx| {
            s.install_unlocked_for_tests(vault);
            s.open_settings(true, cx);
            // Pretend to run from an .app bundle so the login row shows.
            s.login_item = Some(vault_macos::LoginItemStatus::Disabled);
        });
        show_tab(0, &state, &mut vcx);

        let rows: Vec<_> = (0..)
            .map_while(|ix| row_bounds("general", ix, &mut vcx))
            .collect();
        let hint = vcx
            .debug_bounds(
                "settings-dock-hint: Also hides the menu bar. \
                 A padlock in the menu bar opens Vault instead.",
            )
            .expect("General tab renders the hint text");
        let dock = rows
            .iter()
            .position(|r| r.contains(&hint.center()))
            .unwrap();
        assert_eq!(
            dock,
            rows.len() - 2,
            "Dock row directly above the login row"
        );
        assert!(rows[dock].bottom() <= rows[dock + 1].top());
        let login_hint = vcx
            .debug_bounds("settings-login-hint: Starts in the menu bar when the Dock icon is off.")
            .expect("login row renders its hint");
        assert!(
            rows[dock + 1].contains(&login_hint.center()),
            "hint sits in the login row"
        );

        assert!(state.read_with(&vcx, |s, _| s.settings.show_in_dock));
        let switch = vcx.debug_bounds("settings-dock-switch").unwrap();
        vcx.simulate_click(switch.center(), gpui::Modifiers::none());
        vcx.run_until_parked();
        let settings = state.read_with(&vcx, |s, _| s.settings.clone());
        assert!(!settings.show_in_dock);
        // Tests never write the real support dir; persist through the same functions.
        crate::persist::save_settings_to(dir.path(), &settings);
        assert!(!crate::persist::load_settings_from(dir.path()).show_in_dock);

        // The hint follows the row: still there as "Allow in System Settings…", gone
        // with the row outside an .app bundle.
        let login_hint = "settings-login-hint: Starts in the menu bar when the Dock icon is off.";
        let set_login = |status, vcx: &mut VisualTestContext| {
            state.update(vcx, |s, cx| {
                s.login_item = status;
                cx.notify();
            });
            vcx.run_until_parked();
            vcx.debug_bounds(login_hint).is_some()
        };
        assert!(set_login(
            Some(vault_macos::LoginItemStatus::RequiresApproval),
            &mut vcx
        ));
        assert!(!set_login(None, &mut vcx), "no row, no hint");
    }

    /// Sync & Backup: "Automatic backups" carries its hint; the retention tabs name the
    /// daily tier in days and the hint under the row follows the selection.
    #[gpui::test]
    fn sync_backup_rows_show_days_and_hints(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        cx.update(gpui_component::init);
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| SettingsView::new(state.clone(), window, cx));
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        state.update(&mut vcx, |s, cx| {
            s.install_unlocked_for_tests(vault);
            s.open_settings(true, cx);
        });
        show_tab(SYNC_TAB, &state, &mut vcx);

        assert!(
            vcx.debug_bounds(
                "settings-backup-enabled-hint: Copies the vault into the package \
                 after changes, about once an hour."
            )
            .is_some()
        );
        let tabs: Vec<_> = [
            "settings-retention-tab: 15 days",
            "settings-retention-tab: 30 days",
            "settings-retention-tab: 60 days",
            "settings-retention-tab: 120 days",
        ]
        .into_iter()
        .map(|sel| vcx.debug_bounds(sel).unwrap_or_else(|| panic!("{sel}")))
        .collect();
        assert!(
            tabs.windows(2).all(|w| w[0].right() <= w[1].left()),
            "tabs in order, left to right"
        );

        const THREE_YEARS: &str =
            "settings-retention-hint: Older copies thin out to weekly, then monthly for 3 years.";
        const EIGHTEEN_MONTHS: &str =
            "settings-retention-hint: Older copies thin out to weekly, then monthly for 18 months.";
        let hint = |vcx: &mut VisualTestContext, sel: &'static str| vcx.debug_bounds(sel).is_some();
        assert_eq!(
            state.read_with(&vcx, |s, _| s.settings.retention_multiplier),
            1.0
        );
        assert!(hint(&mut vcx, THREE_YEARS));
        vcx.simulate_click(tabs[0].center(), gpui::Modifiers::none());
        vcx.run_until_parked();
        assert_eq!(
            state.read_with(&vcx, |s, _| s.settings.retention_multiplier),
            0.5
        );
        assert!(hint(&mut vcx, EIGHTEEN_MONTHS));
        assert!(!hint(&mut vcx, THREE_YEARS));
    }

    /// A backups-list entry vault-sync could not validate (L-04) shows the "Unknown
    /// file" tag, and neither a click on its row nor a direct request opens or restores it.
    #[gpui::test]
    fn unvalidated_backup_shows_unknown_and_does_not_open(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        vault.backup_now().unwrap();
        cx.update(gpui_component::init);
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| SettingsView::new(state.clone(), window, cx));
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        state.update(&mut vcx, |s, cx| {
            s.install_unlocked_for_tests(vault);
            s.refresh_backups();
            assert_eq!(s.sync.backups.len(), 1);
            assert!(s.sync.backups[0].validated, "a real snapshot validates");
            s.open_settings(true, cx);
        });
        show_tab(SYNC_TAB, &state, &mut vcx);
        assert!(
            vcx.debug_bounds("backup-unknown 0").is_none(),
            "validated row"
        );

        let path = state.update(&mut vcx, |s, cx| {
            s.sync.backups[0].validated = false;
            cx.notify();
            s.sync.backups[0].path.clone()
        });
        vcx.run_until_parked();
        let row = vcx.debug_bounds("backup-unknown 0").expect("unknown row");
        let windows = vcx.update(|_, cx| cx.windows().len());
        vcx.simulate_click(row.center(), gpui::Modifiers::none());
        vcx.run_until_parked();
        assert_eq!(vcx.update(|_, cx| cx.windows().len()), windows, "no viewer");
        state.update(&mut vcx, |s, cx| {
            assert!(s.sync.restore.is_none());
            s.request_restore(path.clone(), cx);
            assert!(s.sync.restore.is_none(), "no restore prompt");
            s.open_backup(path.clone(), cx);
            assert_eq!(
                s.toast.as_ref().map(|t| t.message.as_ref()),
                Some(crate::state::NOT_THIS_VAULT)
            );
        });
        vcx.run_until_parked();
        assert_eq!(vcx.update(|_, cx| cx.windows().len()), windows, "no viewer");

        // A path that is not in the list at all is refused the same way.
        let unlisted = dir.path().join("elsewhere.vault.bin");
        std::fs::copy(&path, &unlisted).unwrap();
        state.update(&mut vcx, |s, cx| {
            s.toast = None;
            s.request_restore(unlisted.clone(), cx);
            assert!(s.sync.restore.is_none(), "no restore prompt");
            s.open_backup(unlisted.clone(), cx);
            assert_eq!(
                s.toast.as_ref().map(|t| t.message.as_ref()),
                Some(crate::state::NOT_THIS_VAULT)
            );
        });
        vcx.run_until_parked();
        assert_eq!(vcx.update(|_, cx| cx.windows().len()), windows, "no viewer");
    }

    #[test]
    fn retention_labels_and_hints_per_choice() {
        let labels = Settings::RETENTION_CHOICES.map(retention_label);
        assert_eq!(labels, ["15 days", "30 days", "60 days", "120 days"]);
        let spans = Settings::RETENTION_CHOICES.map(retention_hint);
        let want = ["18 months", "3 years", "6 years", "12 years"]
            .map(|s| format!("Older copies thin out to weekly, then monthly for {s}."));
        assert_eq!(spans, want);
    }

    /// The owner saw the retention tabs run past the sheet's right edge: in the real
    /// 560 px Settings sheet, at the default and the largest text size, every retention
    /// tab and the Dock switch lie inside the settings pane.
    #[gpui::test]
    fn sync_rows_fit_the_settings_sheet(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        // A long path, so the Vault package row must truncate it beside its button.
        let long = dir
            .path()
            .join("a-folder-name-long-enough-to-overflow-the-settings-sheet-on-its-own")
            .join("and-another-one-just-as-long-to-be-sure-it-never-fits-on-one-line");
        std::fs::create_dir_all(&long).unwrap();
        let vault = SyncedVault::create(
            &long.join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(|cx| {
            gpui_component::init(cx);
            crate::actions::bind_keys(cx);
            crate::actions::register(&state, cx);
        });
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| crate::root::VaultRoot::new(state.clone(), None, window, cx));
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        state.update(&mut vcx, |s, _| s.install_unlocked_for_tests(vault));
        vcx.run_until_parked();

        for size in [TextSize::Default, TextSize::Larger] {
            state.update(&mut vcx, |s, cx| {
                s.update_settings(cx, |st| st.text_size = size);
                s.settings_tab = SYNC_TAB;
                s.open_settings(true, cx);
            });
            vcx.run_until_parked();
            let pane = vcx
                .debug_bounds("settings-pane")
                .expect("Settings sheet open");
            for sel in [
                "settings-retention-tab: 15 days",
                "settings-retention-tab: 30 days",
                "settings-retention-tab: 60 days",
                "settings-retention-tab: 120 days",
            ] {
                let tab = vcx.debug_bounds(sel).unwrap_or_else(|| panic!("{sel}"));
                assert!(
                    tab.left() >= pane.left() && tab.right() <= pane.right() + px(0.5),
                    "{size:?}: {sel} {tab:?} outside the pane {pane:?}"
                );
            }
            // The tabs sit on the heading line at the controls' edge; the hint runs
            // under them at the full pane width.
            let hint = vcx
                .debug_bounds(
                    "settings-retention-hint: Older copies thin out to weekly, \
                     then monthly for 3 years.",
                )
                .expect("retention hint");
            let bar = vcx.debug_bounds("settings-retention-control").unwrap();
            let row = vcx
                .debug_bounds("settings-row sync 2")
                .expect("retention row");
            assert!(
                (hint.left() - pane.left()).abs() < px(1.),
                "{size:?}: hint {hint:?} does not start at the pane's left {pane:?}"
            );
            assert!(
                hint.top() >= bar.bottom(),
                "{size:?}: hint {hint:?} not under the tabs {bar:?}"
            );
            // The label wraps beside the 4-segment bar; the bar is centred on it and
            // starts no higher than the row's 10 px top padding.
            let label = vcx.debug_bounds("settings-retention-label").unwrap();
            assert!(
                (bar.center().y - label.center().y).abs() < px(1.5)
                    && bar.top() >= row.top() + px(9.5),
                "{size:?}: tabs {bar:?} not on the heading line {label:?} of {row:?}"
            );
            assert!(
                (pane.right() - bar.right()).abs() < px(1.),
                "{size:?}: tab bar ends at {:?}, pane at {:?}",
                bar.right(),
                pane.right()
            );
            // The long path truncates at the full row width; Reveal in Finder stays on
            // the heading line.
            let path = vcx.debug_bounds("settings-vault-path").unwrap();
            assert!(
                (pane.right() - path.right()).abs() < px(1.),
                "{size:?}: path ends at {:?}, pane at {:?}",
                path.right(),
                pane.right()
            );
            let reveal = vcx.debug_bounds("settings-reveal-vault").unwrap();
            let package = vcx
                .debug_bounds("settings-row sync 0")
                .expect("package row");
            assert!(
                reveal.left() >= pane.left() && reveal.right() <= pane.right() + px(0.5),
                "{size:?}: Reveal in Finder {reveal:?} outside the pane {pane:?}"
            );
            assert!(
                (reveal.top() - package.top() - px(10.)).abs() < px(3.),
                "{size:?}: Reveal in Finder {reveal:?} not on the heading line of {package:?}"
            );
            state.update(&mut vcx, |s, cx| {
                s.settings_tab = 0;
                cx.notify();
            });
            vcx.run_until_parked();
            let switch = vcx.debug_bounds("settings-dock-switch").unwrap();
            assert!(
                switch.right() <= pane.right() + px(0.5),
                "{size:?}: Dock switch {switch:?} outside the pane {pane:?}"
            );
        }
    }
}
