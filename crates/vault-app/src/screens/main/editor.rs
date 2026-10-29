//! Detail column in edit mode (specs/05-ui.md §2.3 "Edit mode", "New item").
//!
//! Owns one input per editable value and mirrors every change into the `EditBuffer` in
//! `AppState` as a `SecretString`. Rows are keyed by the buffer's stable row keys, so
//! adding, removing or reordering fields keeps the other inputs (and their cursors).

use std::cell::Cell;
use std::rc::Rc;

use gpui::{
    Anchor, AnyElement, App, AppContext as _, Context, Entity, FontWeight, InteractiveElement as _,
    IntoElement, ParentElement as _, Render, SharedString, StatefulInteractiveElement as _,
    Styled as _, Subscription, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{InputEvent, InputState, Textarea, TextareaState};
use gpui_component::menu::{DropdownMenu as _, PopupMenuItem};
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Disableable as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{ExposeSecret as _, FieldKind, strength_bits};

use super::generator::GeneratorView;
use super::prompts;
use super::sidebar::kind_singular;
use crate::actions::{CancelEdit, SaveItem};
use crate::state::{AppState, EditBuffer, GeneratorTarget, Mode, kind_name};
use crate::ui;

enum ValueInput {
    Line(Entity<InputState>),
    Area(Entity<TextareaState>),
}

struct Row {
    key: u64,
    name: Entity<InputState>,
    value: ValueInput,
    _subscriptions: Vec<Subscription>,
}

/// What is dragged when a row's grip is pulled.
#[derive(Clone)]
struct DraggedRow {
    key: u64,
    /// Index when the drag started: decides whether the drop line is above or below.
    ix: usize,
    name: SharedString,
    kind: &'static str,
}

/// The ghost row under the pointer while dragging: grip, name and kind, like the row.
struct DragPreview(DraggedRow);

impl Render for DragPreview {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let name = if self.0.name.is_empty() {
            SharedString::from("Untitled field")
        } else {
            self.0.name.clone()
        };
        ui::h_flex()
            .w(px(280.))
            .gap(px(6.))
            .px(px(8.))
            .py(px(6.))
            .rounded(theme.radius)
            .bg(theme.popover)
            .border_1()
            .border_color(theme.primary.opacity(0.6))
            .shadow_md()
            .opacity(0.92)
            .child(
                Icon::new(IconName::GripVertical)
                    .size_4()
                    .text_color(theme.muted_foreground),
            )
            .child(div().flex_1().truncate().text_sm().child(name))
            .child(Tag::secondary().small().child(self.0.kind))
    }
}

/// Where a row being dragged over would land relative to the dragged row's start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropLine {
    Above,
    Below,
    None,
}

/// Moving up inserts before the target (line above it); moving down, after it.
fn drop_line(from: usize, target: usize) -> DropLine {
    match from.cmp(&target) {
        std::cmp::Ordering::Greater => DropLine::Above,
        std::cmp::Ordering::Less => DropLine::Below,
        std::cmp::Ordering::Equal => DropLine::None,
    }
}

pub struct Editor {
    state: Entity<AppState>,
    generator: Entity<GeneratorView>,
    /// `AppState::edit_session` the inputs were built for.
    session: u64,
    title: Entity<InputState>,
    rows: Vec<Row>,
    /// Row key whose grip started the current drag (dimmed while a drag is active).
    dragging: Rc<Cell<Option<u64>>>,
    _subscriptions: Vec<Subscription>,
}

impl Editor {
    pub fn new(
        state: Entity<AppState>,
        generator: Entity<GeneratorView>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let title = ui::text_input("Title", window, cx);
        let subscriptions =
            vec![
                cx.subscribe_in(&title, window, |this, input, ev: &InputEvent, _, cx| {
                    if let InputEvent::Change = ev {
                        let text = ui::input_text(input, cx);
                        this.state.update(cx, |s, cx| s.set_edit_title(text, cx));
                    }
                }),
            ];
        Self {
            state,
            generator,
            session: u64::MAX,
            title,
            rows: Vec::new(),
            dragging: Rc::default(),
            _subscriptions: subscriptions,
        }
    }

    /// Brings the inputs in line with the edit buffer. Called by the main screen whenever
    /// `AppState` changes.
    pub fn sync(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let s = self.state.read(cx);
        let session = s.edit_session;
        let Some(buffer) = s.edit_buffer().cloned() else {
            if !self.rows.is_empty() {
                // Drop the inputs (and the text they hold) as soon as editing ends.
                self.rows.clear();
                ui::clear_input(&self.title, window, cx);
            }
            self.session = u64::MAX;
            return;
        };
        if session != self.session {
            self.session = session;
            self.rows.clear();
            ui::set_input(&self.title, &buffer.item.title, window, cx);
            ui::focus_input(&self.title, window, cx);
        }
        self.reconcile(&buffer, window, cx);
        if !buffer.pushed.is_empty() {
            for key in &buffer.pushed {
                if let (Some(row), Some(field)) =
                    (self.rows.iter().find(|r| r.key == *key), buffer.field(*key))
                {
                    let value = field.value.expose_secret();
                    match &row.value {
                        ValueInput::Line(i) => ui::set_input(i, value, window, cx),
                        ValueInput::Area(a) => ui::set_textarea(a, value, window, cx),
                    }
                }
            }
            self.state.update(cx, |s, _| {
                if let Some(b) = s.edit_buffer_mut() {
                    b.pushed.clear();
                }
            });
        }
        cx.notify();
    }

    /// Creates rows for new keys, drops rows for removed keys, and orders rows like the buffer.
    fn reconcile(&mut self, buffer: &EditBuffer, window: &mut Window, cx: &mut Context<Self>) {
        let mut old = std::mem::take(&mut self.rows);
        for (key, field) in buffer.keys.iter().zip(&buffer.item.fields) {
            let row = match old.iter().position(|r| r.key == *key) {
                Some(i) => old.swap_remove(i),
                None => self.new_row(*key, field, window, cx),
            };
            self.rows.push(row);
        }
    }

    fn new_row(
        &self,
        key: u64,
        field: &vault_core::Field,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Row {
        let name = ui::text_input("Field name", window, cx);
        ui::set_input(&name, &field.name, window, cx);
        let mut subs =
            vec![
                cx.subscribe_in(&name, window, move |this, input, ev: &InputEvent, _, cx| {
                    if let InputEvent::Change = ev {
                        let text = ui::input_text(input, cx);
                        this.state
                            .update(cx, |s, cx| s.set_edit_name(key, text, cx));
                    }
                }),
            ];
        let current = field.value.expose_secret();
        let value = match field.kind {
            FieldKind::Notes => {
                let area = ui::textarea(window, cx);
                ui::set_textarea(&area, current, window, cx);
                subs.push(cx.subscribe_in(
                    &area,
                    window,
                    move |this, input, ev: &InputEvent, _, cx| {
                        if let InputEvent::Change = ev {
                            let v = ui::textarea_secret(input, cx);
                            this.state.update(cx, |s, cx| s.set_edit_value(key, v, cx));
                        }
                    },
                ));
                ValueInput::Area(area)
            }
            kind => {
                let input = if matches!(kind, FieldKind::Password | FieldKind::Totp) {
                    ui::password_input(value_placeholder(kind), window, cx)
                } else {
                    ui::text_input(value_placeholder(kind), window, cx)
                };
                ui::set_input(&input, current, window, cx);
                subs.push(cx.subscribe_in(
                    &input,
                    window,
                    move |this, input, ev: &InputEvent, _, cx| {
                        if let InputEvent::Change = ev {
                            let v = ui::input_secret(input, cx);
                            this.state.update(cx, |s, cx| s.set_edit_value(key, v, cx));
                        }
                    },
                ));
                ValueInput::Line(input)
            }
        };
        Row {
            key,
            name,
            value,
            _subscriptions: subs,
        }
    }

    fn render_row(
        &self,
        ix: usize,
        row: &Row,
        buffer: &EditBuffer,
        s: &AppState,
        cx: &App,
    ) -> AnyElement {
        let theme = cx.theme();
        let Some(field) = buffer.field(row.key) else {
            return div().into_any_element();
        };
        let key = row.key;
        let count = buffer.keys.len();

        let mover = |id: &'static str, icon: IconName, label: &str, to: Option<usize>| {
            let state = self.state.clone();
            ui::icon_button((id, key), icon, label)
                .disabled(to.is_none())
                .on_click(move |_, _, cx| {
                    if let Some(to) = to {
                        state.update(cx, |s, cx| s.edit(cx, |b| b.move_field(key, to)));
                    }
                })
        };
        let remove = {
            let state = self.state.clone();
            ui::icon_button(("remove-field", key), IconName::Delete, "Remove field").on_click(
                move |_, _, cx| {
                    state.update(cx, |s, cx| s.edit(cx, |b| b.remove_field(key)));
                },
            )
        };

        let dragging = self.dragging.clone();
        let is_ghost = cx.has_active_drag() && self.dragging.get() == Some(key);
        let grip = div()
            .id(("grip", key))
            .cursor_grab()
            .text_color(theme.muted_foreground)
            .child(Icon::new(IconName::GripVertical).size_4())
            .on_drag(
                DraggedRow {
                    key,
                    ix,
                    name: field.name.clone().into(),
                    kind: kind_name(field.kind),
                },
                move |dragged, _, _, cx| {
                    dragging.set(Some(dragged.key));
                    cx.new(|_| DragPreview(dragged.clone()))
                },
            );

        let value: AnyElement = match &row.value {
            ValueInput::Line(input) => {
                let masked = matches!(field.kind, FieldKind::Password | FieldKind::Totp);
                ui::input(input)
                    .small()
                    .when(masked, |i| i.mask_toggle())
                    .into_any_element()
            }
            ValueInput::Area(area) => Textarea::new(area).into_any_element(),
        };
        let scan = (field.kind == FieldKind::Totp).then(|| {
            let state = self.state.clone();
            ui::icon_button(
                ("scan-qr", key),
                IconName::ScanQrCode,
                "Scan QR from screen",
            )
            .loading(s.qr_scanning)
            .on_click(move |_, _, cx| state.update(cx, |s, cx| s.scan_totp_qr(key, cx)))
        });
        let recording_hint =
            (field.kind == FieldKind::Totp && s.screen_recording_hint).then(|| {
                let state = self.state.clone();
                ui::h_flex()
                    .pl(px(22.))
                    .gap(px(8.))
                    .child(
                        div()
                            .flex_1()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child("Scanning needs Screen Recording permission for vault."),
                    )
                    .child(
                        Button::new(("screen-recording", key))
                            .small()
                            .label("Open System Settings")
                            .on_click(move |_, _, cx| {
                                state.update(cx, |s, cx| s.open_screen_recording_settings(cx))
                            }),
                    )
            });
        let generate = (field.kind == FieldKind::Password).then(|| {
            let open = s.generator_target == Some(GeneratorTarget::Field(key));
            let state = self.state.clone();
            let generator = self.generator.clone();
            ui::popover(
                ("generate", key),
                ui::icon_button(
                    ("generate-btn", key),
                    IconName::WandSparkles,
                    "Generate password  ⌘G",
                ),
                Anchor::TopRight,
                open,
                move |open, _, cx| {
                    state.update(cx, |s, cx| {
                        if open {
                            s.open_generator(GeneratorTarget::Field(key), cx);
                        } else {
                            s.close_generator(cx);
                        }
                    });
                },
                move |_, _| generator.clone().into_any_element(),
            )
        });

        ui::v_flex()
            .id(("edit-row", key))
            .py(px(8.))
            .gap(px(6.))
            .px(px(4.))
            .rounded(theme.radius)
            .border_b_1()
            .border_color(theme.border)
            // The row being dragged stays in place as a dimmed ghost.
            .when(is_ghost, |row| row.opacity(0.4))
            // Drop indicator: a 2 px accent line where the row would land.
            .drag_over::<DraggedRow>(move |style, dragged, _, cx| {
                let primary = cx.theme().primary;
                match drop_line(dragged.ix, ix) {
                    DropLine::Above => style.border_t_2().border_color(primary),
                    DropLine::Below => style.border_b_2().border_color(primary),
                    DropLine::None => style,
                }
            })
            .on_drop({
                let state = self.state.clone();
                let dragging = self.dragging.clone();
                move |dragged: &DraggedRow, _, cx| {
                    dragging.set(None);
                    let from = dragged.key;
                    state.update(cx, |s, cx| s.edit(cx, |b| b.move_field(from, ix)));
                }
            })
            .child(
                ui::h_flex()
                    .gap(px(6.))
                    .child(grip)
                    .child(div().w(px(180.)).child(ui::input(&row.name).small()))
                    .child(Tag::secondary().small().child(kind_name(field.kind)))
                    .when(buffer.remote_fields.contains(&key), |row| {
                        row.child(remote_badge(("remote", key)))
                    })
                    .child(div().flex_1())
                    .child(mover(
                        "move-up",
                        IconName::ArrowUp,
                        "Move field up",
                        ix.checked_sub(1),
                    ))
                    .child(mover(
                        "move-down",
                        IconName::ArrowDown,
                        "Move field down",
                        (ix + 1 < count).then_some(ix + 1),
                    ))
                    .child(remove),
            )
            .child(
                ui::h_flex()
                    .gap(px(4.))
                    .pl(px(22.))
                    .child(div().flex_1().min_w_0().child(value))
                    .children(generate)
                    .children(scan),
            )
            .children(recording_hint)
            .when(field.kind == FieldKind::Password, |col| {
                col.child(div().pl(px(22.)).child(ui::strength_meter(
                    strength_bits(field.value.expose_secret()),
                    cx,
                )))
            })
            .into_any_element()
    }
}

/// Text of the "changed remotely" badge (05 §3).
pub const REMOTE_BADGE: &str = "changed remotely \u{2014} your edit will win on save";

/// Small amber badge on a row the user edited that another device also changed.
fn remote_badge(id: impl Into<gpui::ElementId>) -> impl IntoElement {
    div()
        .id(id)
        .child(Tag::warning().small().child(REMOTE_BADGE))
}

fn value_placeholder(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Password => "Password",
        FieldKind::Totp => "otpauth:// URI or secret",
        FieldKind::Url => "https://",
        FieldKind::Email => "name@example.com",
        FieldKind::Date => "YYYY-MM-DD",
        FieldKind::MonthYear => "MM/YY",
        FieldKind::Number => "Number",
        FieldKind::Text | FieldKind::Notes => "Value",
    }
}

impl Render for Editor {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let s = self.state.read(cx);
        let Some(buffer) = s.edit_buffer() else {
            return div().into_any_element();
        };
        let theme = cx.theme();
        let new_kind = match s.mode {
            Mode::New(kind, _) => Some(kind),
            _ => None,
        };
        let rows: Vec<AnyElement> = self
            .rows
            .iter()
            .enumerate()
            .map(|(ix, row)| self.render_row(ix, row, buffer, s, cx))
            .collect();

        let add_field = {
            let state = self.state.clone();
            Button::new("add-field")
                .ghost()
                .small()
                .icon(Icon::new(IconName::Plus))
                .label("Add field")
                .dropdown_menu(move |menu, _, _| {
                    FieldKind::ALL.into_iter().fold(menu, |menu, kind| {
                        let state = state.clone();
                        menu.item(
                            PopupMenuItem::new(kind_name(kind)).on_click(move |_, _, cx| {
                                state.update(cx, |s, cx| {
                                    s.edit(cx, |b| {
                                        b.add_field(kind);
                                    });
                                });
                            }),
                        )
                    })
                })
        };

        let header = ui::h_flex()
            .gap(px(8.))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .text_lg()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(ui::input(&self.title)),
            )
            .child(
                Button::new("cancel-edit")
                    .ghost()
                    .small()
                    .label("Cancel")
                    .tooltip("Cancel  Esc")
                    .on_click(|_, window, cx| window.dispatch_action(Box::new(CancelEdit), cx)),
            )
            .child(
                Button::new("save-edit")
                    .primary()
                    .small()
                    .label(if new_kind.is_some() { "Create" } else { "Save" })
                    .tooltip("Save  ⌘S")
                    .on_click(|_, window, cx| window.dispatch_action(Box::new(SaveItem), cx)),
            );

        ui::v_flex()
            .id("editor-scroll")
            .size_full()
            .overflow_y_scroll()
            .pt(px(ui::content_top(s)))
            .px(px(28.))
            .pb(px(64.))
            .gap(px(10.))
            .when_some(new_kind, |col, kind| {
                col.child(ui::muted(format!("New {}", kind_singular(kind)), cx))
            })
            .child(header)
            .when(buffer.remote_title, |col| {
                col.child(remote_badge("remote-title"))
            })
            .children(prompts::discard(s, &self.state, cx))
            .when_some(buffer.error.clone(), |col, error| {
                col.child(div().text_sm().text_color(theme.danger).child(error))
            })
            .child(ui::divider(cx))
            .when(rows.is_empty(), |col| {
                col.child(ui::muted("No fields. Add one below.", cx))
            })
            .child(ui::v_flex().children(rows))
            .child(ui::h_flex().child(add_field))
            .into_any_element()
    }
}

#[cfg(test)]
mod drag_tests {
    use super::*;

    #[test]
    fn drop_line_follows_direction() {
        assert_eq!(drop_line(3, 1), DropLine::Above);
        assert_eq!(drop_line(0, 2), DropLine::Below);
        assert_eq!(drop_line(2, 2), DropLine::None);
    }
}
