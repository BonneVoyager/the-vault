//! Detail column in edit mode (specs/05-ui.md §2.3 "Edit mode", "New item").
//!
//! Owns one input per editable value and mirrors every change into the `EditBuffer` in
//! `AppState` as a `SecretString`. Rows are keyed by the buffer's stable row keys, so
//! adding, removing or reordering fields keeps the other inputs (and their cursors).

use std::cell::Cell;
use std::rc::Rc;

use gpui::{
    Anchor, AnyElement, App, AppContext as _, Context, Entity, FontWeight, InteractiveElement as _,
    IntoElement, ParentElement as _, Pixels, Render, ScrollHandle, SharedString,
    StatefulInteractiveElement as _, Styled as _, Subscription, Window, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{Backspace, InputEvent, InputState, Textarea, TextareaState};
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Disableable as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{ExposeSecret as _, FieldKind, strength_bits};

use super::detail::history_disclosure;
use super::generator::GeneratorView;
use super::prompts;
use crate::actions::{CancelEdit, SaveItem};
use crate::state::{ADDABLE_KINDS, AppState, EditBuffer, GeneratorTarget, Mode, kind_name};
use crate::text;
use crate::ui::{self, Clickable as _};

enum ValueInput {
    Line(Entity<InputState>),
    Area(Entity<TextareaState>),
    /// A section heading: a name only, no value input (01 §4 `"section"`).
    None,
}

// `capitalize_first`: shared with the read-only field labels.
use crate::text::capitalize_first;

struct Row {
    key: u64,
    name: Entity<InputState>,
    value: ValueInput,
    /// Focus of this row's field icon picker (05 "Field icons").
    icon_focus: super::icon_view::FieldIconFocus,
    _subscriptions: Vec<Subscription>,
}

/// What is dragged when a row's grip is pulled.
#[derive(Clone)]
struct DraggedRow {
    key: u64,
    name: SharedString,
    /// The name input's placeholder, shown by the ghost when the name is empty.
    placeholder: &'static str,
    icon: Option<IconName>,
    kind: &'static str,
    /// Row width at the last paint: the ghost is drawn at the row's width.
    width: Pixels,
}

/// The ghost under the pointer while dragging: the row's header line at the row's width.
struct DragPreview(DraggedRow);

impl Render for DragPreview {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let row = &self.0;
        let muted = theme.muted_foreground;
        let name = if row.name.is_empty() {
            div().text_color(muted).child(row.placeholder)
        } else {
            div().child(row.name.clone())
        };
        ui::h_flex()
            .w(row.width)
            .gap(px(6.))
            .px(px(4.))
            .py(px(6.))
            .rounded(theme.radius)
            .bg(theme.popover)
            .border_1()
            .border_color(theme.border)
            .shadow_md()
            .opacity(0.95)
            .child(Icon::new(IconName::GripVertical).size_4().text_color(muted))
            .when_some(row.icon, |r, icon| {
                r.child(Icon::new(icon).size_4().text_color(muted))
            })
            .child(name.min_w_0().truncate().text_sm())
            .child(Tag::secondary().small().child(row.kind))
    }
}

/// Field drag in progress, shared with the element listeners. Only meaningful while
/// `row` is set: it is set when a grip drag starts and cleared on every mouse-up, Esc
/// and when editing ends, so another kind of drag (a column resize) never reads it.
#[derive(Default)]
struct FieldDrag {
    /// Key of the row being dragged.
    row: Cell<Option<u64>>,
    /// Row under the pointer and whether the pointer is in its lower half. Kept while
    /// the pointer is between rows; cleared when it leaves the rows.
    target: Cell<Option<(usize, bool)>>,
}

impl FieldDrag {
    fn clear(&self) {
        self.row.set(None);
        self.target.set(None);
    }
}

/// Offset of the drop line from a row's top or bottom edge: centred on the 1 px separator.
const LINE_INSET: f32 = -1.5;

/// Mouse-up listener clearing the field drag once the event (and any drop) is handled.
fn defer_clear(drag: Rc<FieldDrag>) -> impl Fn(&gpui::MouseUpEvent, &mut Window, &mut App) {
    move |_, _, cx| {
        let drag = drag.clone();
        cx.defer(move |_| drag.clear());
    }
}

/// `move_field` destination for a row dragged from `from` and dropped on the upper
/// (`lower == false`) or lower half of row `target`; `None` when it would land where it
/// already is (no line, no move). `move_field` removes first, then inserts at the index.
fn drop_index(from: usize, target: usize, lower: bool) -> Option<usize> {
    let gap = target + usize::from(lower);
    (gap != from && gap != from + 1).then(|| if gap > from { gap - 1 } else { gap })
}

/// Icon tile in the edit header: the read-mode header's size, so it does not jump.
const HEADER_TILE: f32 = 44.;

pub struct Editor {
    state: Entity<AppState>,
    generator: Entity<GeneratorView>,
    /// `AppState::edit_session` the inputs were built for.
    session: u64,
    title: Entity<InputState>,
    /// "Add tag" input; Enter or a comma commits its text as a tag chip.
    tags: Entity<InputState>,
    /// Sideways scroll of the chip strip; moved to the newest chip after an add.
    tags_scroll: ScrollHandle,
    /// Tag count last seen by `sync`, to notice an add.
    tag_count: usize,
    rows: Vec<Row>,
    /// The field drag in progress, if any.
    drag: Rc<FieldDrag>,
    /// Width of the field rows at the last paint, for the drag ghost.
    row_width: Rc<Cell<Pixels>>,
    /// Focus of the open icon picker (arrow keys and Enter move and choose).
    icon_focus: gpui::FocusHandle,
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
        let tags = ui::text_input("Add tag", window, cx);
        let subscriptions = vec![
            cx.subscribe_in(
                &title,
                window,
                |this, input, ev: &InputEvent, window, cx| {
                    if let InputEvent::Change = ev {
                        let text = ui::input_text(input, cx);
                        // Over the field limit: the input keeps only what the buffer kept.
                        if let Some(kept) =
                            this.state.update(cx, |s, cx| s.set_edit_title(text, cx))
                        {
                            ui::set_input(input, &kept, window, cx);
                        }
                    }
                },
            ),
            cx.subscribe_in(
                &tags,
                window,
                |this, input, ev: &InputEvent, window, cx| match ev {
                    InputEvent::Change => {
                        let text = ui::input_text(input, cx);
                        let mut rest = None;
                        this.state
                            .update(cx, |s, cx| s.edit(cx, |b| rest = b.type_tags(&text)));
                        if let Some(rest) = rest {
                            ui::set_input(input, &rest, window, cx);
                        }
                    }
                    InputEvent::PressEnter { .. } => {
                        this.state
                            .update(cx, |s, cx| s.edit(cx, |b| b.commit_tag_draft()));
                        ui::clear_input(input, window, cx);
                    }
                    _ => {}
                },
            ),
        ];
        Self {
            state,
            generator,
            session: u64::MAX,
            title,
            tags,
            tags_scroll: ScrollHandle::new(),
            tag_count: 0,
            rows: Vec::new(),
            drag: Rc::default(),
            row_width: Rc::new(Cell::new(px(280.))),
            icon_focus: cx.focus_handle(),
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
                self.drag.clear();
                ui::clear_input(&self.title, window, cx);
                ui::clear_input(&self.tags, window, cx);
            }
            self.session = u64::MAX;
            return;
        };
        // Rows built when a session starts hold the item's own (or template) fields;
        // rows built later are fields added in this edit.
        let starting = session != self.session;
        if starting {
            self.session = session;
            self.rows.clear();
            self.drag.clear();
            ui::set_input(&self.title, &buffer.item.title, window, cx);
            ui::clear_input(&self.tags, window, cx);
            ui::focus_input(&self.title, window, cx);
            self.tag_count = buffer.item.tags.len();
        }
        let tag_count = buffer.item.tags.len();
        if tag_count > self.tag_count {
            // A new chip lands at the end of the strip: bring it into view.
            self.tags_scroll.scroll_to_item(tag_count - 1);
        }
        self.tag_count = tag_count;
        self.reconcile(&buffer, !starting, window, cx);
        if !buffer.pushed.is_empty() {
            for key in &buffer.pushed {
                if let (Some(row), Some(field)) =
                    (self.rows.iter().find(|r| r.key == *key), buffer.field(*key))
                {
                    let value = field.value.expose_secret();
                    match &row.value {
                        ValueInput::Line(i) => ui::set_input(i, value, window, cx),
                        ValueInput::Area(a) => ui::set_textarea(a, value, window, cx),
                        ValueInput::None => {}
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
    /// `added`: rows created now are fields the user just added.
    fn reconcile(
        &mut self,
        buffer: &EditBuffer,
        added: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let mut old = std::mem::take(&mut self.rows);
        for (key, field) in buffer.keys.iter().zip(&buffer.item.fields) {
            let row = match old.iter().position(|r| r.key == *key) {
                Some(i) => old.swap_remove(i),
                None => self.new_row(*key, field, added, window, cx),
            };
            self.rows.push(row);
        }
    }

    /// `added`: a field added in this edit, whose name gets [`capitalize_first`].
    fn new_row(
        &self,
        key: u64,
        field: &vault_core::Field,
        added: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Row {
        let section = field.kind == FieldKind::Section;
        let name = ui::text_input(
            // A name may be left empty (01 §4): the value then stands alone.
            if section { "Section name" } else { "Name" },
            window,
            cx,
        );
        ui::set_input(&name, &field.name, window, cx);
        // New fields only: the first time the name's first character is typed, it is
        // capitalised; after that the user's edits stand (they can lowercase it again).
        let mut auto_cap = added;
        let mut previous = field.name.clone();
        let mut subs = vec![cx.subscribe_in(
            &name,
            window,
            move |this, input, ev: &InputEvent, window, cx| {
                if let InputEvent::Change = ev {
                    let mut text = ui::input_text(input, cx);
                    // Only once a character is typed: clearing the name leaves the
                    // rule armed for the next first character.
                    if auto_cap
                        && !text.is_empty()
                        && text.chars().next() != previous.chars().next()
                    {
                        auto_cap = false;
                        let capitalized = capitalize_first(&text);
                        if capitalized != text {
                            // `set_input` emits no Change, so the buffer takes it below.
                            ui::set_input(input, &capitalized, window, cx);
                            text = capitalized;
                        }
                    }
                    previous.clone_from(&text);
                    if let Some(kept) = this
                        .state
                        .update(cx, |s, cx| s.set_edit_name(key, text, cx))
                    {
                        ui::set_input(input, &kept, window, cx);
                    }
                }
            },
        )];
        let current = field.value.expose_secret();
        let value = match field.kind {
            // A heading: no value input; its (empty) value is written as it is.
            FieldKind::Section => ValueInput::None,
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
                let input = if kind.is_sensitive() {
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
            icon_focus: super::icon_view::FieldIconFocus {
                panel: cx.focus_handle(),
                // A Tab stop: the row's `tab_index` does not apply to a tracked handle.
                none: cx.focus_handle().tab_stop(true),
            },
            _subscriptions: subs,
        }
    }

    /// The field rows: the one drop target for field drags, so a release between rows
    /// (or over the history block) lands where the line showed.
    fn rows_container(&self, rows: Vec<AnyElement>) -> impl IntoElement {
        let width = self.row_width.clone();
        let (leave, drag, state) = (self.drag.clone(), self.drag.clone(), self.state.clone());
        ui::v_flex()
            .on_children_prepainted(move |bounds, _, _| {
                if let Some(b) = bounds.first() {
                    width.set(b.size.width);
                }
            })
            .on_drag_move::<DraggedRow>(move |ev, _, _| {
                if !ev.bounds.contains(&ev.event.position) {
                    leave.target.set(None);
                }
            })
            .on_drop(move |dragged: &DraggedRow, _, cx| {
                let target = drag.target.take();
                drag.clear();
                // From the row's index now, as the line used, not the index at drag start.
                let key = dragged.key;
                let from = state.read(cx).edit_buffer().and_then(|b| b.index(key));
                let to = from
                    .zip(target)
                    .and_then(|(from, (t, lower))| drop_index(from, t, lower));
                if let Some(to) = to {
                    state.update(cx, |s, cx| s.edit(cx, |b| b.move_field(key, to)));
                }
            })
            .children(rows)
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
                .clickable_when(to.is_some())
                .on_click(move |_, _, cx| {
                    if let Some(to) = to {
                        state.update(cx, |s, cx| s.edit(cx, |b| b.move_field(key, to)));
                    }
                })
        };
        let remove = {
            let state = self.state.clone();
            ui::icon_button(("remove-field", key), IconName::Trash, "Remove field").on_click(
                move |_, _, cx| {
                    state.update(cx, |s, cx| s.edit(cx, |b| b.remove_field(key)));
                },
            )
        };

        let drag = self.drag.clone();
        let dragged_ix = cx
            .has_active_drag()
            .then(|| self.drag.row.get())
            .flatten()
            .and_then(|k| self.rows.iter().position(|r| r.key == k));
        let is_ghost = dragged_ix == Some(ix);
        // The accent line between rows: at this row's top (insert before) or bottom.
        let line = match (dragged_ix, self.drag.target.get()) {
            (Some(from), Some((target, lower))) if target == ix => {
                drop_index(from, ix, lower).map(|_| lower)
            }
            _ => None,
        };
        let section = field.kind == FieldKind::Section;
        let name_input = row.name.clone();
        let grip = div()
            .debug_selector(move || format!("grip {key}"))
            .id(("grip", key))
            .cursor_grab()
            .text_color(theme.muted_foreground)
            .child(Icon::new(IconName::GripVertical).size_4())
            // Pressing the grip focuses the row's name input rather than letting the
            // detail column take focus: the input stays drawn while the row is collapsed
            // and Esc then reaches the editor's drag cancel (not the edit cancel).
            .on_mouse_down(gpui::MouseButton::Left, move |_, window, cx| {
                window.prevent_default();
                ui::focus_input(&name_input, window, cx);
            })
            .on_drag(
                DraggedRow {
                    key,
                    name: field.name.clone().into(),
                    placeholder: if section { "Section name" } else { "Name" },
                    icon: field
                        .icon_name()
                        .filter(|_| !section)
                        .and_then(crate::icon::symbol),
                    kind: kind_name(field.kind),
                    width: self.row_width.get(),
                },
                move |dragged, _, _, cx| {
                    drag.row.set(Some(dragged.key));
                    drag.target.set(None);
                    cx.new(|_| DragPreview(dragged.clone()))
                },
            );

        let value: Option<AnyElement> = match &row.value {
            ValueInput::Line(input) => {
                let masked = matches!(field.kind, FieldKind::Password | FieldKind::Totp);
                Some(
                    ui::input(input)
                        .small()
                        .when(masked, |i| i.mask_toggle())
                        .into_any_element(),
                )
            }
            ValueInput::Area(area) => Some(Textarea::new(area).into_any_element()),
            ValueInput::None => None,
        }
        // The dragged row collapses to its header line.
        .filter(|_| !is_ghost);
        let scan_file = (field.kind == FieldKind::Totp).then(|| {
            let state = self.state.clone();
            ui::icon_button(
                ("scan-qr-file", key),
                IconName::ScanQrCode,
                "Scan QR from image\u{2026}",
            )
            .loading(s.qr_scanning)
            .clickable_when(!s.qr_scanning)
            .on_click(move |_, _, cx| state.update(cx, |s, cx| s.scan_totp_qr_file(key, cx)))
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
            .debug_selector(move || format!("edit-row {key}"))
            .relative()
            .py(px(8.))
            .gap(px(6.))
            .px(px(4.))
            .rounded(theme.radius)
            .border_b_1()
            .border_color(theme.border)
            // The row being dragged collapses to its header line at 40 % opacity.
            .when(is_ghost, |row| row.opacity(0.4))
            // Which half of this row the pointer is over (the line follows the pointer).
            .on_drag_move::<DraggedRow>({
                let drag = self.drag.clone();
                move |ev, _, _| {
                    let pos = ev.event.position;
                    if ev.bounds.contains(&pos) {
                        drag.target.set(Some((ix, pos.y >= ev.bounds.center().y)));
                    }
                }
            })
            // Drop indicator: one 2 px accent line over the separator, no layout shift.
            .when_some(line, |row, lower| {
                let bar = div()
                    .debug_selector(|| "drop-line".into())
                    .absolute()
                    .left_0()
                    .right_0()
                    .h(px(2.))
                    .bg(theme.primary);
                row.child(if lower {
                    bar.bottom(px(LINE_INSET))
                } else {
                    bar.top(px(LINE_INSET))
                })
            })
            .child(
                ui::h_flex()
                    .gap(px(6.))
                    .child(grip)
                    // Sections carry no icon (05 "Field icons").
                    .when(field.kind != FieldKind::Section, |r| {
                        r.child(super::icon_view::field_icon_button(
                            &self.state,
                            key,
                            &row.icon_focus,
                            &gpui::Focusable::focus_handle(&row.name, cx),
                            cx,
                        ))
                    })
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
            .when_some(value, |row, value| {
                row.child(
                    ui::h_flex()
                        .gap(px(4.))
                        .pl(px(22.))
                        .child(div().flex_1().min_w_0().child(value))
                        .children(generate)
                        .children(scan_file),
                )
            })
            .when(!is_ghost && buffer.row_limited(key), |col| {
                col.child(
                    limit_note(("field-limit", key), format!("field-limit {key}"), cx).pl(px(22.)),
                )
            })
            .children(totp_hint(key, buffer, cx).filter(|_| !is_ghost))
            .when(!is_ghost && field.kind == FieldKind::Password, |col| {
                col.child(div().pl(px(22.)).child(ui::strength_meter(
                    strength_bits(field.value.expose_secret()),
                    cx,
                )))
            })
            .into_any_element()
    }
}

/// "Field limited to 1 MiB": muted, under a field whose input was cut to the limit. Save
/// stays enabled; the kept text is what is saved.
/// `selector` names it for tests ("field-limit <key>", "field-limit-title", …).
fn limit_note(
    id: impl Into<gpui::ElementId>,
    selector: String,
    cx: &App,
) -> gpui::Stateful<gpui::Div> {
    ui::muted(EditBuffer::FIELD_LIMIT_MESSAGE, cx)
        .id(id)
        .debug_selector(move || selector.clone())
        .text_xs()
}

/// Parse status under a one-time-code row: icon plus text, so not colour alone (§6).
fn totp_hint(key: u64, buffer: &EditBuffer, cx: &App) -> Option<AnyElement> {
    let (valid, message) = buffer.totp_hint(key)?;
    let theme = cx.theme();
    let (icon, color) = if valid {
        (IconName::CircleCheck, theme.success)
    } else {
        (IconName::CircleX, theme.danger)
    };
    Some(
        ui::h_flex()
            .id(("totp-hint", key))
            .debug_selector(move || format!("totp-hint {message}"))
            .pl(px(22.))
            .gap(px(4.))
            .text_xs()
            .text_color(color)
            .child(Icon::new(icon).size_3())
            .child(message)
            .into_any_element(),
    )
}

/// The tag chips with their remove buttons, then the "Add tag" input (§2.3 edit mode).
/// Height of the edit-mode tags row at the default text size: fits a removable chip
/// and the small input.
const TAGS_ROW_HEIGHT: f32 = 28.;

fn tags_row(
    tags: &[String],
    input: &Entity<InputState>,
    scroll: &ScrollHandle,
    state: &Entity<AppState>,
    cx: &App,
) -> impl IntoElement {
    let theme = cx.theme();
    let chips = tags.iter().enumerate().map(|(ix, tag)| {
        let state = state.clone();
        div()
            .flex_none()
            .debug_selector(move || format!("edit-tag-chip {ix}"))
            .child(
                Tag::secondary().small().flex_none().child(
                    ui::h_flex().gap(px(2.)).child(format!("#{tag}")).child(
                        ui::icon_button(
                            ("remove-tag", ix),
                            IconName::Close,
                            &format!("Remove tag {tag}"),
                        )
                        .xsmall()
                        .on_click(move |_, _, cx| {
                            state.update(cx, |s, cx| s.edit(cx, |b| b.remove_tag(ix)));
                        }),
                    ),
                ),
            )
    });
    let (state, empty_check) = (state.clone(), input.clone());
    // Fixed height, one line: adding the first chip (taller than the bare input) or many
    // chips never moves the fields below (owner-reported jump). Only the chips scroll
    // sideways; the input stays outside the strip so it is always visible, and `sync`
    // scrolls the strip to the newest chip after an add.
    ui::h_flex()
        .id("edit-tags")
        .debug_selector(|| "edit-tags".into())
        .flex_none()
        .h(crate::theme::scaled(TAGS_ROW_HEIGHT, cx))
        .w_full()
        .items_center()
        .gap(px(6.))
        .child(
            Icon::new(IconName::Tag)
                .flex_none()
                .size_4()
                .text_color(theme.muted_foreground),
        )
        .child(
            ui::h_flex()
                .id("edit-tag-chips")
                .debug_selector(|| "edit-tag-chips".into())
                .flex_1()
                .min_w_0()
                .items_center()
                .gap(px(6.))
                .overflow_x_scroll()
                .track_scroll(scroll)
                .children(chips),
        )
        .child(
            div()
                .flex_none()
                .w(px(160.))
                .debug_selector(|| "edit-tag-input".into())
                // Backspace at the start of the input propagates here; in an empty input
                // it removes the last chip.
                .on_action(move |_: &Backspace, _, cx| {
                    if ui::input_is_empty(&empty_check, cx) {
                        state.update(cx, |s, cx| {
                            s.edit(cx, |b| {
                                b.item.tags.pop();
                            })
                        });
                    }
                })
                .child(ui::input(input).small()),
        )
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
        FieldKind::Text | FieldKind::Notes => "Value",
        // A heading has no value input; never shown.
        FieldKind::Section => "",
        // Unknown kind from a newer app version: treated as secret.
        FieldKind::Other => "Value",
    }
}

impl Render for Editor {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // Built first: the menu keeps its focus handles in element state (`&mut App`).
        let add_field_open = self.state.read(cx).add_field_menu_open;
        let add_field = {
            let state = self.state.clone();
            let rows_state = self.state.clone();
            ui::menu_popover(
                "add-field-menu",
                Button::new("add-field")
                    .debug_selector(|| "add-field".into())
                    .ghost()
                    .small()
                    .icon(Icon::new(IconName::Plus))
                    .label("Add field")
                    .clickable(),
                Anchor::TopLeft,
                add_field_open,
                move |open, _, cx| {
                    state.update(cx, |s, cx| {
                        if open {
                            s.open_add_field_menu(cx);
                        } else {
                            s.close_add_field_menu(cx);
                        }
                    });
                },
                move |_, _| add_field_rows(&rows_state),
                window,
                cx,
            )
        };
        let s = self.state.read(cx);
        let Some(buffer) = s.edit_buffer() else {
            return div().into_any_element();
        };
        let theme = cx.theme();
        let new_kind = match s.mode {
            Mode::New(kind, _) => Some(kind),
            _ => None,
        };
        // Password history sits under the first password row, as in read mode, with
        // per-entry remove buttons (edit mode only; a new item has no history).
        let history_after = (new_kind.is_none() && !buffer.item.history.is_empty())
            .then(|| {
                buffer
                    .item
                    .fields
                    .iter()
                    .position(|f| f.kind == FieldKind::Password)
            })
            .flatten()
            .and_then(|i| buffer.keys.get(i).copied());
        let mut rows: Vec<AnyElement> = Vec::with_capacity(self.rows.len() + 1);
        for (ix, row) in self.rows.iter().enumerate() {
            rows.push(self.render_row(ix, row, buffer, s, cx));
            if history_after == Some(row.key) {
                let history: Vec<_> = buffer.history().collect();
                rows.push(history_disclosure(
                    super::detail::History {
                        entries: &history,
                        fields: &buffer.item.fields,
                    },
                    Some(buffer.removed_history.len()),
                    s,
                    &self.state,
                    text::now_millis(),
                    cx,
                ));
            }
        }

        let header = ui::h_flex()
            .debug_selector(|| "editor-header".into())
            .gap(px(8.))
            .child(super::icon_view::picker_trigger(
                &self.state,
                &self.icon_focus,
                &gpui::Focusable::focus_handle(&self.title, cx),
                HEADER_TILE,
                cx,
            ))
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
                    .clickable()
                    .on_click(|_, window, cx| window.dispatch_action(Box::new(CancelEdit), cx)),
            )
            .child(
                Button::new("save-edit")
                    .primary()
                    .small()
                    .label(if new_kind.is_some() { "Create" } else { "Save" })
                    .tooltip("Save  ⌘S")
                    .clickable()
                    .on_click(|_, window, cx| window.dispatch_action(Box::new(SaveItem), cx)),
            );

        ui::v_flex()
            .id("editor-scroll")
            // Esc during a field drag cancels the drag, not the edit.
            .capture_action({
                let drag = self.drag.clone();
                move |_: &CancelEdit, window, cx| {
                    if drag.row.get().is_some() && cx.has_active_drag() {
                        drag.clear();
                        cx.stop_active_drag(window);
                        cx.stop_propagation();
                    }
                }
            })
            // Any release ends a field drag; after the drop listener has run.
            .capture_any_mouse_up(defer_clear(self.drag.clone()))
            .on_mouse_up_out(gpui::MouseButton::Left, defer_clear(self.drag.clone()))
            .size_full()
            .overflow_y_scroll()
            .pt(px(ui::content_top(s)))
            .px(px(ui::COLUMN_PAD_X - ui::FOCUS_RING_WIDTH))
            .pb(px(64.))
            .gap(px(10.))
            .when_some(new_kind, |col, kind| {
                col.child(ui::muted(format!("New {}", kind.label()), cx))
            })
            .child(header)
            .when(buffer.remote_title, |col| {
                col.child(remote_badge("remote-title"))
            })
            .when(buffer.limited_title, |col| {
                col.child(limit_note(
                    "field-limit-title",
                    "field-limit-title".into(),
                    cx,
                ))
            })
            .child(tags_row(
                &buffer.item.tags,
                &self.tags,
                &self.tags_scroll,
                &self.state,
                cx,
            ))
            .when(buffer.limited_tag, |col| {
                col.child(limit_note("field-limit-tag", "field-limit-tag".into(), cx))
            })
            .children(prompts::discard(s, &self.state, cx))
            .when_some(buffer.error.clone(), |col, error| {
                col.child(div().text_sm().text_color(theme.danger).child(error))
            })
            .child(ui::divider(cx))
            .when(rows.is_empty(), |col| {
                col.child(ui::muted("No fields. Add one below.", cx))
            })
            .child(self.rows_container(rows))
            .child(ui::h_flex().child(add_field))
            .into_any_element()
    }
}

/// Add field menu rows: one per addable kind, no icons (the editor has no per-kind icon).
fn add_field_rows(state: &Entity<AppState>) -> Vec<ui::MenuRow> {
    ADDABLE_KINDS
        .into_iter()
        .map(|kind| {
            let state = state.clone();
            ui::menu_row(format!("add-field-{}", kind.as_str()), kind_name(kind)).on_click(
                move |_, _, cx| {
                    state.update(cx, |s, cx| {
                        s.close_add_field_menu(cx);
                        s.edit(cx, |b| {
                            b.add_field(kind);
                        });
                    });
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod drag_tests {
    use gpui::{Bounds, Modifiers, MouseButton, TestAppContext, VisualTestContext, point};
    use vault_core::SecretString;

    use super::*;

    /// Every (from, target, half) for up to 5 rows: the line shows exactly when the drop
    /// changes the order, and `move_field`'s remove-then-insert lands the row in the gap
    /// the line marked (the gap before `target`, or after it for the lower half).
    #[test]
    fn drop_index_matches_remove_then_insert() {
        for n in 1..=5 {
            for from in 0..n {
                for target in 0..n {
                    for lower in [false, true] {
                        let gap = target + usize::from(lower);
                        let mut want: Vec<usize> = (0..n).collect();
                        want.insert(gap, usize::MAX);
                        want.retain(|&r| r != from);
                        let at = want.iter().position(|&r| r == usize::MAX).unwrap();
                        want[at] = from;
                        let unchanged = want == (0..n).collect::<Vec<_>>();
                        let got = drop_index(from, target, lower);
                        assert_eq!(got.is_none(), unchanged, "n={n} {from}->{target} {lower}");
                        if let Some(to) = got {
                            let mut v: Vec<usize> = (0..n).collect();
                            let x = v.remove(from);
                            v.insert(to.min(n - 1), x);
                            assert_eq!(v, want, "n={n} {from}->{target} {lower}");
                        }
                    }
                }
            }
        }
    }

    fn bounds(vcx: &mut VisualTestContext, selector: String) -> Option<Bounds<Pixels>> {
        vcx.debug_bounds(Box::leak(selector.into_boxed_str()))
    }

    /// Real drag through the editor: the line follows the pointer half and marks one
    /// gap from either side, Esc ends the drag but not the edit, a release drops.
    #[gpui::test]
    fn field_drag_line_esc_and_drop(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, main, mut vcx) = super::tests::open(dir.path(), cx);
        state.update(&mut vcx, |s, cx| {
            let device = s.device_id();
            let mut it = vault_core::Item::new("Drag", device, 10);
            it.fields = ["a", "b", "c"]
                .map(|n| {
                    vault_core::Field::new(n, FieldKind::Text, SecretString::new("v".into()), 10)
                })
                .to_vec();
            let id = s
                .vault
                .as_mut()
                .unwrap()
                .edit(|v| v.insert(it, 10))
                .unwrap();
            s.vault_changed();
            s.select(id, cx);
            s.begin_edit(cx);
        });
        vcx.run_until_parked();
        let keys = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
        let names = |vcx: &mut VisualTestContext| {
            state.read_with(vcx, |s, _| {
                let b = s.edit_buffer().unwrap();
                b.item
                    .fields
                    .iter()
                    .map(|f| f.name.clone())
                    .collect::<Vec<_>>()
            })
        };
        let row = |vcx: &mut VisualTestContext, i: usize| {
            bounds(vcx, format!("edit-row {}", keys[i])).unwrap()
        };
        let none = Modifiers::none();
        let start_drag = |vcx: &mut VisualTestContext| {
            let grip = bounds(vcx, format!("grip {}", keys[0])).unwrap().center();
            vcx.simulate_mouse_down(grip, MouseButton::Left, none);
            vcx.simulate_mouse_move(grip + point(px(0.), px(6.)), MouseButton::Left, none);
            vcx.run_until_parked();
        };
        let hover = |vcx: &mut VisualTestContext, i: usize, frac: f32| {
            let b = row(vcx, i);
            let p = point(b.center().x, b.top() + b.size.height * frac);
            vcx.simulate_mouse_move(p, MouseButton::Left, none);
            vcx.run_until_parked();
            bounds(vcx, "drop-line".into())
        };

        // Pressing the grip moves focus from the value input (hidden while dragged) to
        // the row's name input, not to the detail column.
        let value = super::tests::value_input(&main, keys[0], &mut vcx);
        vcx.update(|window, cx| ui::focus_input(&value, window, cx));
        let full = row(&mut vcx, 0).size.height;
        start_drag(&mut vcx);
        assert!(row(&mut vcx, 0).size.height < full, "dragged row collapses");
        vcx.update(|window, cx| {
            let editor = main.read(cx).editor.read(cx);
            let name = gpui::Focusable::focus_handle(&editor.rows[0].name, cx);
            assert!(name.is_focused(window), "focus kept in the row");
        });
        assert_eq!(hover(&mut vcx, 0, 0.75), None, "own row");
        assert_eq!(hover(&mut vcx, 1, 0.25), None, "own slot");
        let below_b = hover(&mut vcx, 1, 0.75).expect("line under b");
        let above_c = hover(&mut vcx, 2, 0.25).expect("line over c");
        assert_eq!(below_b, above_c, "one gap, one line position");
        assert!((below_b.size.height - px(2.)).abs() < px(0.01));

        vcx.simulate_keystrokes("escape");
        assert!(
            state.read_with(&vcx, |s, _| s.is_editing()),
            "still editing"
        );
        assert!(main.read_with(&vcx, |m, cx| m.editor.read(cx).drag.row.get().is_none()));
        assert!(bounds(&mut vcx, "drop-line".into()).is_none());
        assert_eq!(row(&mut vcx, 0).size.height, full, "row restored");
        let at = row(&mut vcx, 2).center();
        vcx.simulate_mouse_up(at, MouseButton::Left, none);
        assert_eq!(names(&mut vcx), ["a", "b", "c"], "Esc dropped nothing");

        start_drag(&mut vcx);
        hover(&mut vcx, 2, 0.75).expect("line under c");
        let at = row(&mut vcx, 2).center();
        vcx.simulate_mouse_up(at + point(px(0.), px(1.)), MouseButton::Left, none);
        vcx.run_until_parked();
        assert_eq!(names(&mut vcx), ["b", "c", "a"]);
        assert!(main.read_with(&vcx, |m, cx| m.editor.read(cx).drag.target.get().is_none()));

        // A release outside the rows (over the title) moves nothing and leaves no state.
        start_drag(&mut vcx);
        hover(&mut vcx, 1, 0.25).expect("line over b");
        let header = vcx.debug_bounds("editor-header").unwrap().center();
        vcx.simulate_mouse_move(header, MouseButton::Left, none);
        vcx.simulate_mouse_up(header, MouseButton::Left, none);
        vcx.run_until_parked();
        assert_eq!(names(&mut vcx), ["b", "c", "a"]);
        main.read_with(&vcx, |m, cx| {
            let drag = &m.editor.read(cx).drag;
            assert!(drag.row.get().is_none() && drag.target.get().is_none());
        });
    }
}

#[cfg(test)]
#[path = "editor_tests.rs"]
mod tests;
