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
use gpui_component::menu::{DropdownMenu as _, PopupMenuItem};
use gpui_component::switch::Switch;
use gpui_component::tab::{Tab, TabBar};
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Disableable as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;
use vault_sync::{BackupInfo, BackupKind};

use super::security::SecurityView;
use crate::state::{
    AppState, Appearance, Busy, LoginRow, RestorePrompt, SECURITY_TAB, SYNC_TAB, Settings,
    SyncStatus, TRANSFER_TAB, TextSize,
};
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

pub struct SettingsView {
    state: Entity<AppState>,
    /// Master password for restoring a backup.
    restore_input: Entity<InputState>,
    security: Entity<SecurityView>,
    _subscriptions: Vec<Subscription>,
}

impl SettingsView {
    pub fn new(state: Entity<AppState>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let restore_input = ui::password_input("Master password of the backup", window, cx);
        let security = cx.new(|cx| SecurityView::new(state.clone(), window, cx));
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

fn auto_lock_label(minutes: Option<u32>) -> SharedString {
    match minutes {
        None => "Never".into(),
        Some(1) => "1 minute".into(),
        Some(m) => format!("{m} minutes").into(),
    }
}

fn retention_label(m: f32) -> String {
    if m < 1.0 {
        format!("{m}\u{d7}")
    } else {
        format!("{m:.0}\u{d7}")
    }
}

/// One labelled settings row: label left, control right.
fn row(label: &'static str, control: impl IntoElement, cx: &App) -> gpui::Div {
    ui::h_flex()
        .py(px(10.))
        .gap(px(12.))
        .border_b_1()
        .border_color(cx.theme().border)
        .child(div().flex_1().text_sm().child(label))
        .child(control)
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
        .dropdown_menu(move |menu, _, _| {
            choices.iter().fold(menu, |menu, value| {
                let (value, state) = (*value, state.clone());
                menu.item(
                    PopupMenuItem::new(label(value))
                        .checked(value == current)
                        .on_click(move |_, _, cx| {
                            state.update(cx, |s, cx| s.update_settings(cx, |st| apply(st, value)));
                        }),
                )
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
) -> impl IntoElement {
    let state = state.clone();
    TabBar::new(id)
        .segmented()
        .small()
        .selected_index(selected)
        .children(labels.iter().map(|l| Tab::new().label(*l)))
        .on_click(move |ix: &usize, _, cx| {
            let ix = *ix;
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
        .on_click(move |_, _, cx| state.update(cx, |s, cx| f(s, cx)))
}

impl SettingsView {
    fn general(&self, cx: &App) -> gpui::Div {
        let settings = self.state.read(cx).settings.clone();
        let state = self.state.clone();
        ui::v_flex()
            .child(row(
                "Auto-lock after",
                choice(
                    "auto-lock",
                    settings.auto_lock_minutes,
                    &Settings::AUTO_LOCK_CHOICES,
                    auto_lock_label,
                    &self.state,
                    |s, v| s.auto_lock_minutes = v,
                ),
                cx,
            ))
            .child(row(
                "Lock on sleep, screen lock or user switch",
                Switch::new("lock-on-sleep")
                    .checked(settings.lock_on_sleep)
                    .accessibility_label("Lock on sleep, screen lock or user switch")
                    .on_click(move |on, _, cx| {
                        let on = *on;
                        state.update(cx, |s, cx| {
                            s.update_settings(cx, |st| st.lock_on_sleep = on)
                        });
                    }),
                cx,
            ))
            .child(row(
                "Clear clipboard after",
                choice(
                    "clipboard-clear",
                    settings.clipboard_clear_secs,
                    &Settings::CLIPBOARD_CHOICES,
                    |secs| format!("{secs} seconds").into(),
                    &self.state,
                    |s, v| s.clipboard_clear_secs = v,
                ),
                cx,
            ))
            .child(row(
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
                ),
                cx,
            ))
            .child(row(
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
                ),
                cx,
            ))
            .children(self.login_item_row(cx))
    }

    /// "Launch at login" (hidden outside an .app bundle).
    fn login_item_row(&self, cx: &App) -> Option<gpui::Div> {
        let control = match self.state.read(cx).login_row() {
            LoginRow::Hidden => return None,
            LoginRow::Toggle(on) => {
                let state = self.state.clone();
                Switch::new("launch-at-login")
                    .checked(on)
                    .accessibility_label("Launch at login")
                    .on_click(move |on, _, cx| {
                        let on = *on;
                        state.update(cx, |s, cx| s.set_launch_at_login(on, cx));
                    })
                    .into_any_element()
            }
            LoginRow::NeedsApproval => Button::new("login-items")
                .small()
                .label("Allow in System Settings\u{2026}")
                .on_click(|_, _, _| vault_macos::open_login_items_settings())
                .into_any_element(),
        };
        Some(row("Launch at login", control, cx))
    }

    /// Sync & Backup (§2.5, 03 §4).
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
        let provider = cloud::provider_label(&path).unwrap_or("Local folder");
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
        let location = ui::v_flex()
            .py(px(10.))
            .gap(px(6.))
            .border_b_1()
            .border_color(theme.border)
            .child(div().text_sm().child("Vault file"))
            .child(
                div()
                    .text_xs()
                    .font_family(theme.mono_font_family.clone())
                    .text_color(theme.muted_foreground)
                    .truncate()
                    .child(path.display().to_string()),
            )
            .child(
                ui::h_flex()
                    .gap(px(8.))
                    .child(state_button(
                        "move-vault",
                        "Move\u{2026}",
                        &self.state,
                        |s, cx| s.show_toast("Moving the vault is coming later", cx),
                    ))
                    .child(
                        Button::new("reveal-vault")
                            .small()
                            .label("Reveal in Finder")
                            .on_click(move |_, _, cx| cx.reveal_path(&reveal_path)),
                    ),
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
        let retention = TabBar::new("retention")
            .segmented()
            .small()
            .selected_index(current)
            .children(Settings::RETENTION_CHOICES.map(|m| Tab::new().label(retention_label(m))))
            .on_click(move |ix: &usize, _, cx| {
                if let Some(m) = Settings::RETENTION_CHOICES.get(*ix).copied() {
                    retention_state.update(cx, |s, cx| {
                        s.update_settings(cx, |st| st.retention_multiplier = m)
                    });
                }
            });

        ui::v_flex()
            .child(location)
            .child(row(
                "Automatic backups",
                Switch::new("backup-enabled")
                    .checked(settings.backup_enabled)
                    .accessibility_label("Automatic backups")
                    .on_click(move |on, _, cx| {
                        let on = *on;
                        enabled_state.update(cx, |s, cx| {
                            s.update_settings(cx, |st| st.backup_enabled = on)
                        });
                    }),
                cx,
            ))
            .child(row("Keep backups longer", retention, cx))
            .child(
                ui::h_flex()
                    .py(px(10.))
                    .gap(px(12.))
                    .child(div().flex_1().text_sm().child("Backups"))
                    .child(state_button(
                        "backup-now",
                        "Back up now",
                        &self.state,
                        |s, cx| s.backup_now(cx),
                    )),
            )
            .child(self.backups(s, cx))
    }

    fn backups(&self, s: &AppState, cx: &App) -> gpui::AnyElement {
        if let Some(e) = s.sync.backups_error.clone() {
            return div()
                .text_sm()
                .text_color(cx.theme().danger)
                .child(e)
                .into_any_element();
        }
        if s.sync.backups.is_empty() {
            return ui::muted("No backups yet.", cx).into_any_element();
        }
        let rows: Vec<gpui::AnyElement> = s
            .sync
            .backups
            .iter()
            .enumerate()
            .map(|(ix, b)| self.backup_row(ix, b, s, cx))
            .collect();
        ui::v_flex()
            .id("backups")
            .max_h(px(220.))
            .overflow_y_scroll()
            .children(rows)
            .into_any_element()
    }

    fn backup_row(&self, ix: usize, b: &BackupInfo, s: &AppState, cx: &App) -> gpui::AnyElement {
        let theme = cx.theme();
        let restore = s.sync.restore.as_ref().filter(|r| r.backup == b.path);
        let path = b.path.clone();
        let line = ui::h_flex()
            .py(px(6.))
            .gap(px(8.))
            .child(div().text_sm().child(text::date_time(b.taken_at)))
            .map(|row| match b.kind {
                BackupKind::Snapshot => row,
                BackupKind::Conflict => row.child(Tag::warning().small().child("Conflict copy")),
                BackupKind::Unsaved => row.child(Tag::info().small().child("Unsaved edits")),
            })
            .child(div().flex_1())
            .child(ui::muted(text::file_size(b.size), cx))
            .child(state_button(("open-backup", ix), "Open", &self.state, {
                let path = b.path.clone();
                move |s, cx| s.open_backup(path.clone(), cx)
            }))
            .child(
                state_button(
                    ("restore-backup", ix),
                    "Restore\u{2026}",
                    &self.state,
                    move |s, cx| s.request_restore(path.clone(), cx),
                )
                .disabled(s.locked || s.busy.is_some())
                .when(s.locked, |b| b.tooltip("Unlock the vault to restore")),
            );
        ui::v_flex()
            .border_b_1()
            .border_color(theme.border)
            .child(line)
            .children(restore.map(|r| self.restore_prompt(r, s, cx)))
            .into_any_element()
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
        strip
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
        let not_yet = |id: &'static str| {
            state_button(id, "Import\u{2026}", &self.state, |s, cx| {
                s.show_toast("This import format is not supported yet", cx)
            })
        };
        let export = if s.sync.export_confirm {
            confirm_strip(true, cx)
                .mt(px(10.))
                .child(div().text_sm().child(EXPORT_WARNING))
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
                            state_button(
                                "export-confirm",
                                "Export\u{2026}",
                                &self.state,
                                |s, cx| s.choose_export_path(cx),
                            )
                            .danger(),
                        ),
                )
        } else {
            div()
        };
        ui::v_flex()
            .child(row(
                "Import from CSV",
                state_button("import-csv", "Import CSV\u{2026}", &self.state, |s, cx| {
                    s.choose_import_path(cx)
                }),
                cx,
            ))
            .child(row(
                "Import from 1Password (1PUX)",
                state_button(
                    "import-1pux",
                    "Import 1PUX\u{2026}",
                    &self.state,
                    |s, cx| s.choose_import_1pux(cx),
                ),
                cx,
            ))
            .child(row(
                "Import from KeePass (KDBX)",
                not_yet("import-kdbx"),
                cx,
            ))
            .child(row(
                "Export to CSV (unencrypted)",
                state_button("export-csv", "Export CSV\u{2026}", &self.state, |s, cx| {
                    s.set_export_confirm(true, cx)
                })
                .danger(),
                cx,
            ))
            .child(export)
    }

    fn about(&self, cx: &App) -> gpui::Div {
        ui::v_flex().py(px(10.)).child(ui::muted(
            format!("vault {}", env!("CARGO_PKG_VERSION")),
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
            .children(TABS.map(|t| Tab::new().label(t)))
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
            .child(tabs)
            .child(body)
    }
}
