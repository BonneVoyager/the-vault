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
use gpui_component::{ActiveTheme as _, Disableable as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;
use vault_sync::{BackupInfo, BackupKind};

use super::security::SecurityView;
use crate::state::{
    AppState, Appearance, Busy, LoginRow, RestorePrompt, SECURITY_TAB, SYNC_TAB, Settings,
    SyncStatus, TRANSFER_TAB, TextSize,
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

/// One labelled settings row: label left, control right. Its divider comes from
/// [`section`].
fn row(label: &'static str, control: impl IntoElement) -> gpui::Div {
    ui::h_flex()
        .py(px(10.))
        .gap(px(12.))
        .child(div().flex_1().text_sm().child(label))
        .child(control)
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
) -> impl IntoElement {
    let state = state.clone();
    TabBar::new(id)
        .segmented()
        .small()
        .selected_index(selected)
        .children(labels.iter().map(|l| Tab::new().label(*l).clickable()))
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
                ),
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
                ),
            ),
        ];
        let rows = rows
            .into_iter()
            .chain(self.login_item_row(cx))
            .map(|r| (r, None))
            .collect();
        section("general", rows, cx)
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
        Some(row("Launch at login", control))
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
                            .clickable()
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
            .children(
                Settings::RETENTION_CHOICES
                    .map(|m| Tab::new().label(retention_label(m)).clickable()),
            )
            .on_click(move |ix: &usize, _, cx| {
                if let Some(m) = Settings::RETENTION_CHOICES.get(*ix).copied() {
                    retention_state.update(cx, |s, cx| {
                        s.update_settings(cx, |st| st.retention_multiplier = m)
                    });
                }
            });

        let rows = vec![
            location,
            row(
                "Automatic backups",
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
            ),
            row("Keep backups longer", retention),
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
                .clickable_when(!s.locked && s.busy.is_none())
                .when(s.locked, |b| b.tooltip("Unlock the vault to restore")),
            );
        ui::v_flex()
            .child(line)
            .children(restore.map(|r| self.restore_prompt(r, s, cx)))
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
            .child(tabs)
            .child(body)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gpui::{TestAppContext, VisualTestContext};
    use gpui_component::Root;
    use vault_core::{Item, ItemKind, KdfParams, SecretString, Uuid};
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
                .edit(|v| v.insert(Item::new(ItemKind::Login, title, device, at), at))
                .unwrap();
            vault.save().unwrap();
            vault.backup_now().unwrap();
        }

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

        show_tab(TRANSFER_TAB, &state, &mut vcx);
        assert_eq!(check_dividers(&mut vcx), [("transfer", 4)]);

        show_tab(TABS.len() - 1, &state, &mut vcx);
        assert!(check_dividers(&mut vcx).is_empty(), "About has no rows");

        // Locked: Security shows only the Touch ID row, without a trailing line.
        state.update(&mut vcx, |s, cx| {
            s.lock(cx);
            s.open_settings(true, cx);
            s.settings_tab = SECURITY_TAB;
            cx.notify();
        });
        vcx.run_until_parked();
        assert_eq!(check_dividers(&mut vcx), [("security", 1)]);
    }
}
