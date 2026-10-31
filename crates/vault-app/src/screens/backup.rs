//! Read-only backup viewer (specs/03-sync.md §4 "Restore"): a second window that opens a
//! backup file with its master password and shows its items in a list and a detail pane.
//!
//! The backup is parsed and unlocked directly (`LockedVault::parse` + `unlock`) on the
//! background executor: no `SyncedVault`, no watcher, nothing is ever written to the backup.
//! The only ways out are copying a value (concealed clipboard, usual clear timer), "Copy to
//! current vault" (a clone with a fresh id) and "Replace current vault with this backup"
//! (the existing restore flow). MainScreen's renderers are bound to `AppState`'s listing,
//! selection and edit buffer, so this window has its own minimal list and detail instead.
//! It closes, dropping the decrypted backup, as soon as the live vault locks.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use gpui::{
    AnyElement, App, AppContext as _, Context, Entity, FontWeight, InteractiveElement as _,
    IntoElement, ParentElement as _, Render, SharedString, StatefulInteractiveElement as _,
    Styled as _, Subscription, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::{ActiveTheme as _, Disableable as _, Root, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{
    ExposeSecret as _, FieldKind, Item, LockedVault, SecretString, UnlockedVault, Uuid,
};

use super::main::item_tile;
use crate::state::{AppState, parse_totp};
use crate::ui::Clickable as _;
use crate::{listing, text, theme, ui};

pub struct BackupWindow {
    state: Entity<AppState>,
    path: PathBuf,
    password: Entity<InputState>,
    /// The decrypted backup. Dropped (zeroized) with the window.
    vault: Option<UnlockedVault>,
    /// Live items, by title.
    items: Vec<Uuid>,
    selection: Option<Uuid>,
    /// Field indexes of the selected item whose values are revealed.
    revealed: HashSet<usize>,
    error: Option<SharedString>,
    status: Option<SharedString>,
    busy: bool,
    /// Redraws once a second while open so a TOTP code stays current.
    _ticker: gpui::Task<()>,
    _subscriptions: Vec<Subscription>,
}

/// The vault file to read for a backup entry: a snapshot is a `.vault.bin` file, an
/// absorbed conflict copy is a whole package directory (03 §6).
fn backup_file(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.join(vault_sync::VAULT_FILE_NAME)
    } else {
        path.to_owned()
    }
}

/// Opens the viewer for `path` in a new window.
pub fn open_backup_window(
    state: Entity<AppState>,
    path: PathBuf,
    cx: &mut App,
) -> gpui::Result<gpui::AnyWindowHandle> {
    let title = format!("Backup \u{2014} {}", text::file_name(&path));
    let mut options = ui::main_window_options(None, cx);
    options.titlebar = Some(gpui::TitlebarOptions {
        title: Some(title.into()),
        ..Default::default()
    });
    let handle = cx.open_window(options, |window, cx| {
        theme::apply(window, cx);
        let view = cx.new(|cx| BackupWindow::new(state, path, window, cx));
        cx.new(|cx| Root::new(view, window, cx))
    })?;
    Ok(handle.into())
}

impl BackupWindow {
    pub fn new(
        state: Entity<AppState>,
        path: PathBuf,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let password = ui::password_input("Master password of this backup", window, cx);
        ui::focus_input(&password, window, cx);
        let subscriptions = vec![
            cx.subscribe_in(&password, window, |this, _, ev: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = ev {
                    this.submit(window, cx);
                }
            }),
            // Never outlive the live session: close (and drop the keys) when it locks.
            cx.observe_in(&state, window, |_, state, window, cx| {
                if state.read(cx).locked {
                    window.remove_window();
                }
            }),
        ];
        Self {
            state,
            path,
            password,
            vault: None,
            items: Vec::new(),
            selection: None,
            revealed: HashSet::new(),
            error: None,
            status: None,
            busy: false,
            _ticker: cx.spawn(async move |this, cx| {
                loop {
                    cx.background_executor()
                        .timer(std::time::Duration::from_secs(1))
                        .await;
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

    #[cfg(test)]
    pub fn item_ids(&self) -> &[Uuid] {
        &self.items
    }

    fn item(&self, id: Uuid) -> Option<&Item> {
        self.vault.as_ref()?.get(id)
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
        let task = cx.background_executor().spawn(async move {
            let bytes = std::fs::read(backup_file(&path)).map_err(|e| e.to_string())?;
            let locked = LockedVault::parse(&bytes).map_err(|e| e.to_string())?;
            locked.unlock(&password).map_err(|e| match e {
                vault_core::VaultError::WrongPassword => "Wrong password. Try again.".to_owned(),
                other => other.to_string(),
            })
        });
        cx.spawn(async move |this, cx| {
            let result = task.await;
            this.update(cx, |this, cx| {
                this.busy = false;
                match result {
                    Ok(vault) => this.opened(vault),
                    Err(e) => this.error = Some(e.into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn opened(&mut self, vault: UnlockedVault) {
        let mut items: Vec<&Item> = vault.items().collect();
        items.sort_by_key(|i| i.title.to_lowercase());
        self.items = items.iter().map(|i| i.id).collect();
        self.selection = self.items.first().copied();
        self.vault = Some(vault);
    }

    fn select(&mut self, id: Uuid, cx: &mut Context<Self>) {
        self.selection = Some(id);
        self.revealed.clear();
        self.status = None;
        cx.notify();
    }

    /// Copies field `ix` of the selected item (a TOTP field copies the current code).
    pub fn copy_field(&mut self, ix: usize, cx: &mut Context<Self>) {
        let Some(field) = self
            .selection
            .and_then(|id| self.item(id))
            .and_then(|i| i.fields.get(ix))
        else {
            return;
        };
        let value = if field.kind == FieldKind::Totp {
            match parse_totp(&field.value) {
                Some(totp) => SecretString::new(totp.code(text::now_millis() / 1000)),
                None => return,
            }
        } else {
            field.value.clone()
        };
        let secs = self.state.read(cx).settings.clipboard_clear_secs;
        self.state.update(cx, |s, cx| s.copy_value(value, cx));
        self.status = Some(format!("Copied \u{2014} clears in {secs} s").into());
        cx.notify();
    }

    /// "Copy to current vault". Returns the new item's id in the live vault.
    pub fn copy_to_current(&mut self, cx: &mut Context<Self>) -> Option<Uuid> {
        let item = self.selection.and_then(|id| self.item(id))?.clone();
        let id = self
            .state
            .update(cx, |s, cx| s.copy_item_into_vault(&item, cx));
        self.status = Some(match id {
            Some(_) => format!(
                "Copied \u{2018}{}\u{2019} into the current vault",
                item.title
            )
            .into(),
            None => "Could not copy the item".into(),
        });
        cx.notify();
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
    fn render_prompt(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme();
        ui::centered(cx)
            .child(
                ui::card(cx)
                    .w(px(380.))
                    .gap(px(10.))
                    .child(ui::illustration(IconName::Inbox, Some(IconName::Eye), cx))
                    .child(
                        div()
                            .text_lg()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child("Open backup read-only"),
                    )
                    .child(ui::muted(text::file_name(&self.path), cx).text_xs())
                    .child(ui::input(&self.password).mask_toggle().disabled(self.busy))
                    .when_some(self.error.clone(), |col, e| {
                        col.child(div().text_sm().text_color(theme.danger).child(e))
                    })
                    .child(
                        Button::new("backup-open")
                            .primary()
                            .w_full()
                            .label("Open")
                            .loading(self.busy)
                            .clickable_when(!self.busy)
                            .on_click(cx.listener(|this, _, window, cx| this.submit(window, cx))),
                    ),
            )
            .into_any_element()
    }

    fn render_list(&self, vault: &UnlockedVault, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme();
        let rows = self
            .items
            .iter()
            .filter_map(|id| vault.get(*id))
            .map(|item| {
                let id = item.id;
                let selected = self.selection == Some(id);
                ui::h_flex()
                    .id(("backup-row", id.as_u128() as usize))
                    .tab_index(0)
                    .clickable()
                    .h(theme::scaled(48., cx))
                    .px(px(12.))
                    .gap(px(10.))
                    .when(selected, |r| r.bg(theme.accent))
                    .hover(|r| r.bg(theme.accent.opacity(0.6)))
                    .child(item_tile(item, None, 28., cx))
                    .child(
                        ui::v_flex()
                            .min_w_0()
                            .child(div().text_sm().truncate().child(item.title.clone()))
                            .child(ui::muted(listing::subtitle(item), cx).text_xs().truncate()),
                    )
                    .on_click(cx.listener(move |this, _, _, cx| this.select(id, cx)))
            });
        ui::v_flex()
            .id("backup-list")
            .w(px(280.))
            .h_full()
            .border_r_1()
            .border_color(theme.border)
            .overflow_y_scroll()
            .children(rows)
            .into_any_element()
    }

    fn render_detail(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme();
        let Some(item) = self.selection.and_then(|id| self.item(id)) else {
            return ui::v_flex()
                .flex_1()
                .items_center()
                .justify_center()
                .child(ui::muted("This backup has no items", cx))
                .into_any_element();
        };
        let fields = item.fields.iter().enumerate().map(|(ix, field)| {
            // Passwords, unknown kinds from newer versions and card numbers start hidden.
            // TOTP has its own rendering below (the code, never the secret).
            let concealed = (field.kind.is_sensitive() && field.kind != FieldKind::Totp)
                || listing::is_card_number(item, field);
            let masked = concealed && !self.revealed.contains(&ix);
            let shown = if field.kind == FieldKind::Totp {
                // The current code, like the main detail (the secret itself never shows).
                parse_totp(&field.value).map_or_else(
                    || "Invalid one-time code setup".to_owned(),
                    |t| text::group_code(&t.code(text::now_millis() / 1000)),
                )
            } else if masked {
                "\u{2022}".repeat(10)
            } else {
                field.value.expose_secret().clone()
            };
            let reveal = concealed.then(|| {
                let revealed = self.revealed.contains(&ix);
                ui::icon_button(
                    ("backup-reveal", ix),
                    if revealed {
                        IconName::EyeOff
                    } else {
                        IconName::Eye
                    },
                    if revealed { "Hide" } else { "Reveal" },
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    if !this.revealed.remove(&ix) {
                        this.revealed.insert(ix);
                    }
                    cx.notify();
                }))
            });
            let value = div()
                // Records only whether the value is hidden, never the value.
                .debug_selector(move || {
                    format!(
                        "backup-value {ix} {}",
                        if masked { "masked" } else { "shown" }
                    )
                })
                .flex_1()
                .min_w_0()
                .pt(px(3.))
                .font_family(theme.mono_font_family.clone())
                .text_sm()
                .whitespace_normal()
                .child(shown);
            let mut buttons: Vec<AnyElement> =
                reveal.into_iter().map(|b| b.into_any_element()).collect();
            buttons.push(
                ui::icon_button(("backup-copy", ix), IconName::Copy, "Copy")
                    .on_click(cx.listener(move |this, _, _, cx| this.copy_field(ix, cx)))
                    .into_any_element(),
            );
            // The same row as the main detail and item windows.
            super::main::detail::field_row(ix, field.name.clone().into(), value, buttons, cx)
        });
        let live = self.state.read(cx).main_active();
        ui::v_flex()
            .id("backup-detail")
            .flex_1()
            .min_w_0()
            .h_full()
            .p(px(20.))
            .gap(px(8.))
            .overflow_y_scroll()
            .child(
                ui::h_flex()
                    .gap(px(12.))
                    .child(item_tile(item, None, 40., cx))
                    .child(
                        div()
                            .flex_1()
                            .text_xl()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(item.title.clone()),
                    )
                    .child(
                        Button::new("backup-copy-item")
                            .small()
                            .label("Copy to current vault")
                            .disabled(!live)
                            .clickable_when(live)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.copy_to_current(cx);
                            })),
                    ),
            )
            .children(fields)
            .children(super::main::attachments::backup_section(item, cx))
            .when_some(self.status.clone(), |col, s| col.child(ui::muted(s, cx)))
            .into_any_element()
    }
}

impl Render for BackupWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let rem = theme::rem_size(cx);
        if window.rem_size() != rem {
            window.set_rem_size(rem);
        }
        let theme = cx.theme();
        let (bg, fg, border, font) = (
            theme.background,
            theme.foreground,
            theme.border,
            theme.font_size,
        );
        let body = match self.vault.take() {
            None => self.render_prompt(cx),
            Some(vault) => {
                let list = self.render_list(&vault, cx);
                self.vault = Some(vault);
                let detail = self.render_detail(cx);
                ui::h_flex()
                    .size_full()
                    .child(list)
                    .child(detail)
                    .into_any_element()
            }
        };
        let header = self.vault.is_some().then(|| {
            ui::h_flex()
                .px(px(16.))
                .py(px(8.))
                .gap(px(8.))
                .border_b_1()
                .border_color(border)
                .child(gpui_component::tag::Tag::info().small().child("Read-only"))
                .child(
                    ui::muted(text::file_name(&self.path), cx)
                        .flex_1()
                        .truncate(),
                )
                .child(
                    Button::new("backup-replace")
                        .small()
                        .danger()
                        .label("Replace current vault with this backup\u{2026}")
                        .clickable()
                        .on_click(
                            cx.listener(|this, _, window, cx| this.replace_current(window, cx)),
                        ),
                )
        });
        ui::v_flex()
            .size_full()
            .bg(bg)
            .text_color(fg)
            .text_size(font)
            .children(header)
            .child(div().flex_1().min_h_0().child(body))
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
        state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
        (state, backup)
    }

    fn window(
        state: &Entity<AppState>,
        backup: &std::path::Path,
        cx: &mut TestAppContext,
    ) -> (Entity<BackupWindow>, VisualTestContext) {
        cx.update(gpui_component::init);
        let mut view = None;
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let v = cx.new(|cx| BackupWindow::new(state.clone(), backup.to_owned(), window, cx));
            view = Some(v.clone());
            Root::new(v, window, cx)
        });
        let vcx = VisualTestContext::from_window(window.into(), cx);
        (view.unwrap(), vcx)
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
                item.fields = vec![
                    Field::new("user", FieldKind::Text, SecretString::new("al".into()), 1),
                    pin,
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
        assert!(
            vcx.debug_bounds("backup-value 0 shown").is_some(),
            "text field"
        );
        assert!(
            vcx.debug_bounds("backup-value 1 masked").is_some(),
            "Other field"
        );
        assert!(vcx.debug_bounds("backup-value 1 shown").is_none());
        view.update(&mut vcx, |w, cx| {
            w.revealed.insert(1);
            cx.notify();
        });
        vcx.run_until_parked();
        assert!(
            vcx.debug_bounds("backup-value 1 shown").is_some(),
            "Reveal works"
        );
        // The shared field row: label beside the value, 7 px padding like the detail.
        let row = vcx.debug_bounds("field-row 0").expect("shared row");
        let label = vcx.debug_bounds("field-label 0").unwrap();
        let content = vcx.debug_bounds("field-content 0").unwrap();
        assert_eq!(
            content.top() - row.top(),
            px(crate::screens::main::detail::FIELD_ROW_PAD_Y)
        );
        assert!(label.right() < content.left(), "label beside its value");
        // Stored "user" and "pin": shown with a capital, like the main detail.
        assert!(vcx.debug_bounds("field-label-text 0 User").is_some());
        assert!(vcx.debug_bounds("field-label-text 1 Pin").is_some());
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
            assert_eq!(w.error.as_deref(), Some("Wrong password. Try again."));
        });

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
            w.revealed.insert(0);
            w.copy_field(0, cx);
            assert!(w.status.as_ref().unwrap().contains("clears in"));
        });
        vcx.run_until_parked();

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

    /// An absorbed iCloud conflict copy is a whole package directory: the viewer reads its
    /// vault.bin, and `open_backup` opens a window for it.
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

        let before = vcx.update(|_, cx| cx.windows().len());
        state.update(&mut vcx, |s, cx| s.open_backup(conflict.clone(), cx));
        vcx.run_until_parked();
        assert_eq!(vcx.update(|_, cx| cx.windows().len()), before + 1);
    }
}
