//! Detail column in edit mode (specs/05-ui.md §2.3 "Edit mode", "New item").
//!
//! Owns one input per editable value and mirrors every change into the `EditBuffer` in
//! `AppState` as a `SecretString`. Rows are keyed by the buffer's stable row keys, so
//! adding, removing or reordering fields keeps the other inputs (and their cursors).

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use gpui::{
    Anchor, AnimationExt as _, AnyElement, App, AppContext as _, Bounds, Context, Entity,
    FocusHandle, FontWeight, InteractiveElement as _, IntoElement, ParentElement as _, Pixels,
    Render, ScrollHandle, SharedString, StatefulInteractiveElement as _, Styled as _, Subscription,
    WeakEntity, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{Backspace, Input, InputEvent, InputState, Textarea, TextareaState};
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Disableable as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{ExposeSecret as _, FieldKind, HistoryEntry, SecretString, Uuid};

use super::detail::{FIELD_LINE_MIN_H, FIELD_ROW_GAP, FIELD_ROW_PAD_Y, history_disclosure};
use super::generator::GeneratorView;
use super::prompts;
use crate::actions::{CancelEdit, SaveItem};
use crate::audit::{self, FieldIssue, Issue, strength_bits};
use crate::state::{ADDABLE_KINDS, AppState, EditBuffer, GeneratorTarget, Mode, kind_name};
use crate::text;
use crate::ui::{self, Clickable as _};

enum ValueInput {
    Line(Entity<InputState>),
    Area(Entity<TextareaState>),
    /// A section heading: a name only, no value input (01 §4 `"section"`).
    None,
}

// `capitalize_first`: only for a new field's first typed character (read-mode labels
// show the stored name as typed since 2026-11-22).
use crate::text::capitalize_first;

struct Row {
    key: u64,
    name: Entity<InputState>,
    value: ValueInput,
    /// Focus of this row's field icon picker (05 "Field icons").
    icon_focus: super::icon_view::FieldIconFocus,
    /// The ↑/↓ and trash buttons' focus: owned here so keyboard focus on ↑/↓ shows them
    /// (and their hidden slots keep the Tab stops), and focus stays on the button when
    /// the row moves.
    up: FocusHandle,
    down: FocusHandle,
    trash: FocusHandle,
    _subscriptions: Vec<Subscription>,
}

impl Row {
    /// The value input's focus handle (a section has none).
    fn value_focus(&self, cx: &App) -> Option<FocusHandle> {
        match &self.value {
            ValueInput::Line(i) => Some(gpui::Focusable::focus_handle(i, cx)),
            ValueInput::Area(a) => Some(gpui::Focusable::focus_handle(a, cx)),
            ValueInput::None => None,
        }
    }
}

/// What is dragged when a row's grip is pulled; also the ghost's content.
#[derive(Clone)]
struct DraggedRow {
    key: u64,
    name: SharedString,
    /// The name input's placeholder, shown by the ghost when the name is empty.
    placeholder: &'static str,
    icon: Option<IconName>,
    kind: &'static str,
    /// Extra space above the row's header line (a section's gap), so the ghost keeps
    /// the grip under the pointer.
    header_dy: Pixels,
}

/// gpui's drag preview, drawn at the pointer: nothing. The ghost is drawn inside the
/// rows container instead, clamped to it (05 §2.3, owner 2026-11-23).
struct NoPreview;

impl Render for NoPreview {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        gpui::Empty
    }
}

/// Height of the ghost and of the gap opened for it: the collapsed row's header line.
const GHOST_H: Pixels = px(2. * FIELD_ROW_PAD_Y + FIELD_LINE_MIN_H + 1.);
/// Edge auto-scroll during a field drag (05 §2.3 "Edit mode", owner 2026-11-23): the
/// band at either edge of the editor's viewport, and the speed in px/s from its inner
/// side to the edge (and beyond); one constant speed under Reduce Motion. Time-based,
/// so 60 and 120 Hz displays scroll alike; a frame's time is capped at 1/30 s.
const SCROLL_BAND: f32 = 24.;
const SCROLL_RATE_MIN: f32 = 120.;
const SCROLL_RATE_MAX: f32 = 720.;
const SCROLL_RATE_REDUCED: f32 = 360.;
const SCROLL_DT_MAX: f32 = 1. / 30.;

/// Scroll step for `dt` seconds with the pointer at `y` over a viewport from `top` to
/// `bottom`: negative towards the top, positive towards the bottom, zero outside the
/// bands. Beyond the viewport (above or below it) counts as the edge itself.
fn auto_scroll_step(y: Pixels, top: Pixels, bottom: Pixels, reduce_motion: bool, dt: f32) -> f32 {
    let band = SCROLL_BAND.min((bottom - top).as_f32() / 2.);
    let (depth, sign) = if y < top + px(band) {
        ((top + px(band) - y).as_f32(), -1.)
    } else if y > bottom - px(band) {
        ((y - (bottom - px(band))).as_f32(), 1.)
    } else {
        return 0.;
    };
    let rate = if reduce_motion {
        SCROLL_RATE_REDUCED
    } else {
        let t = (depth / band).min(1.);
        SCROLL_RATE_MIN + (SCROLL_RATE_MAX - SCROLL_RATE_MIN) * t
    };
    sign * rate * dt.min(SCROLL_DT_MAX)
}

/// The gap's open/close motion (05 §2.3 "Edit mode").
const GAP_MOTION: Duration = Duration::from_millis(150);

/// The ghost: the row's header line at the rows' width, in the row's geometry (label
/// column with grip, icon and name; kind chip trailing). The value is never drawn (it
/// may be a secret; the dragged row hides it too).
fn drag_ghost(row: &DraggedRow, label_w: Option<Pixels>, cx: &App) -> gpui::Div {
    let theme = cx.theme();
    let muted = theme.muted_foreground;
    let name = if row.name.is_empty() {
        div().text_color(muted).child(row.placeholder)
    } else {
        div()
            .font_weight(FontWeight::MEDIUM)
            .child(row.name.clone())
    };
    ui::h_flex()
        .debug_selector(|| "drag-ghost".into())
        .absolute()
        .left_0()
        .w_full()
        .h(GHOST_H)
        .gap(px(FIELD_ROW_GAP))
        .rounded(theme.radius)
        .bg(theme.popover)
        .border_1()
        .border_color(theme.border)
        .shadow_md()
        .opacity(0.95)
        .child(
            super::detail::label_column(ui::h_flex(), label_w)
                .min_h(px(FIELD_LINE_MIN_H))
                .gap(px(EDIT_LABEL_GAP))
                .child(Icon::new(IconName::GripVertical).size_4().text_color(muted))
                .when_some(row.icon, |r, icon| {
                    r.child(Icon::new(icon).size_4().text_color(muted))
                })
                .child(name.min_w_0().truncate().text_sm()),
        )
        .child(div().flex_1())
        .child(Tag::secondary().small().child(row.kind))
        .pr(px(4.))
}

/// Move flash (05 "Edit-mode field rows", owner 2026-11-16): the accent at 18 % under a
/// row that a click on ↑/↓ or a drop just moved, fading to clear.
const FLASH_ALPHA: f32 = 0.18;
const FLASH_FADE: Duration = Duration::from_millis(900);
/// Under Reduce Motion: a solid fill this long, then none.
const FLASH_SOLID: Duration = Duration::from_millis(300);

/// The flash in progress. Its fade is a `with_animation` keyed by `generation`, so other
/// re-renders do not replay it; a timer drops it at the end, so nothing keeps drawing
/// frames after (a finished `with_animation` would otherwise stay in the tree).
#[derive(Clone, Copy)]
struct Flash {
    key: u64,
    generation: u64,
    reduce_motion: bool,
}

/// A child of the rows container, as recorded at prepaint for the drag geometry.
#[derive(Clone, Copy, PartialEq)]
enum Child {
    Row(u64),
    /// A history block, by the key of the row it belongs to.
    History(u64),
    /// The gaps, the ghost and the dragged row: outside the projected flow.
    Other,
}

/// A gap closing after the ghost left its slot.
struct ClosingGap {
    slot: usize,
    /// Open fraction when it started closing.
    from: f32,
    started: Instant,
}

/// Eased open fraction of a gap that started opening at `started` (`None`: instant).
fn opened(started: Option<Instant>, now: Instant) -> f32 {
    started.map_or(1., |t| {
        let p = now.saturating_duration_since(t).as_secs_f32() / GAP_MOTION.as_secs_f32();
        gpui::ease_out_quint()(p.min(1.))
    })
}

/// Field drag in progress, shared with the element listeners. Only meaningful while
/// `row` is set: it is set when a grip drag starts and cleared on every mouse-up, Esc
/// and when editing ends, so another kind of drag (a column resize) never reads it.
#[derive(Default)]
struct FieldDrag {
    /// Key of the row being dragged.
    row: Cell<Option<u64>>,
    /// The ghost's content.
    ghost: RefCell<Option<DraggedRow>>,
    /// Pointer y at the grip press; then the pointer's offset from the ghost's top.
    press_y: Cell<Pixels>,
    grab_dy: Cell<Pixels>,
    /// The gap's slot: index among the rows other than the dragged one.
    slot: Cell<usize>,
    /// When the gap at `slot` started opening (`None`: open).
    opening: Cell<Option<Instant>>,
    closing: RefCell<Vec<ClosingGap>>,
    /// The rows' top the last frame was computed with; a prepaint finding them moved
    /// (a scroll during the drag) asks for another frame.
    used_top: Cell<Pixels>,
    /// When the last auto-scroll step ran (`None`: not scrolling).
    last_scroll: Cell<Option<Instant>>,
    /// Tests: the frame time auto-scroll uses, in place of the measured one.
    #[cfg(test)]
    test_dt: Cell<Option<f32>>,
    /// The rows container's children at the last prepaint (kept across drags).
    layout: RefCell<Vec<(Child, Bounds<Pixels>)>>,
}

impl FieldDrag {
    fn clear(&self) {
        self.row.set(None);
        self.ghost.take();
        self.opening.set(None);
        self.closing.borrow_mut().clear();
    }

    /// Starts a drag of `row`: the gap opens at once at the row's own slot.
    fn start(&self, row: &DraggedRow, from: usize) {
        let top = self
            .layout
            .borrow()
            .iter()
            .find(|(c, _)| *c == Child::Row(row.key))
            .map(|(_, b)| b.top());
        let dy = top.map_or(px(0.), |top| self.press_y.get() - top - row.header_dy);
        self.grab_dy.set(dy.clamp(px(0.), GHOST_H));
        self.row.set(Some(row.key));
        self.ghost.replace(Some(row.clone()));
        self.slot.set(from);
        self.last_scroll.set(None);
        self.opening.set(None);
        self.closing.borrow_mut().clear();
    }

    /// One drag frame for the pointer at `pointer_y`: moves the gap to the ghost's
    /// projected slot and returns the ghost's top relative to the rows container.
    fn frame(&self, pointer_y: Pixels, reduce_motion: bool, now: Instant) -> Pixels {
        let Some(key) = self.row.get() else {
            return px(0.);
        };
        let layout = self.layout.borrow();
        let group_top = layout.first().map_or(px(0.), |(_, b)| b.top());
        self.used_top.set(group_top);
        let flow: Vec<(bool, Pixels)> = layout
            .iter()
            .filter_map(|&(c, b)| match c {
                Child::Row(k) if k != key => Some((true, b.size.height)),
                Child::History(k) if k != key => Some((false, b.size.height)),
                _ => None,
            })
            .collect();
        let total: Pixels = flow.iter().map(|f| f.1).sum::<Pixels>() + GHOST_H;
        let top = (pointer_y - group_top - self.grab_dy.get()).clamp(px(0.), total - GHOST_H);
        let slot = self.slot.get();
        let to = project_slot(&flow, top + GHOST_H / 2.);
        if to != slot {
            let mut closing = self.closing.borrow_mut();
            closing.retain(|g| opened(Some(g.started), now) < 1.);
            if !reduce_motion {
                closing.push(ClosingGap {
                    slot,
                    from: opened(self.opening.get(), now),
                    started: now,
                });
            }
            self.slot.set(to);
            self.opening.set((!reduce_motion).then_some(now));
        }
        top
    }

    /// The gaps to draw before row slot `slot` (or at the end): (height, selector).
    fn gaps_at(&self, slot: usize, now: Instant) -> Vec<(Pixels, &'static str)> {
        let mut gaps: Vec<_> = self
            .closing
            .borrow()
            .iter()
            .filter(|g| g.slot == slot)
            .map(|g| {
                let h = GHOST_H * (g.from * (1. - opened(Some(g.started), now)));
                (h, "drop-gap-closing")
            })
            .collect();
        if self.slot.get() == slot {
            gaps.push((GHOST_H * opened(self.opening.get(), now), "drop-gap"));
        }
        gaps
    }

    /// Whether a gap is still moving (the editor asks for another frame).
    fn animating(&self, now: Instant) -> bool {
        opened(self.opening.get(), now) < 1.
            || self
                .closing
                .borrow()
                .iter()
                .any(|g| opened(Some(g.started), now) < 1.)
    }
}

/// The gap's slot for a ghost centred at `centre` (from the rows' top): the slot before
/// the first other row whose centre is below the ghost's, each row's centre taken
/// midway between its two places (gap above it, gap below it). Against the rows as
/// shifted, a ghost clamped at an end sits exactly on an equal-height end row's centre
/// (an end slot unreachable); against the rows closed up, a drag would swap with its
/// neighbour on the first pixel. The midway centres avoid both and do not depend on
/// where the gap is now, so the gap cannot flicker. `flow`: the other rows and history
/// blocks in order, as (is a row, height).
fn project_slot(flow: &[(bool, Pixels)], centre: Pixels) -> usize {
    let (mut y, mut r) = (px(0.), 0);
    for &(row, h) in flow {
        if row {
            if y + (GHOST_H + h) / 2. > centre {
                return r;
            }
            r += 1;
        }
        y += h;
    }
    r
}

/// A gap in the rows: blank, with one hairline at its bottom like a row's rule, so the
/// slot reads as an empty row (the rule above it is the previous row's).
fn drop_gap(h: Pixels, selector: &'static str, cx: &App) -> AnyElement {
    ui::v_flex()
        .debug_selector(move || selector.into())
        .flex_none()
        .w_full()
        .h(h)
        .overflow_hidden()
        .justify_end()
        .child(div().flex_none().h(px(1.)).bg(cx.theme().border))
        .into_any_element()
}

/// Ends a field drag on a release anywhere: the row lands in the gap's slot.
fn finish_drag(
    drag: &FieldDrag,
    state: &Entity<AppState>,
    this: &WeakEntity<Editor>,
    window: &mut Window,
    cx: &mut App,
) {
    let Some(key) = drag.row.get() else { return };
    let slot = drag.slot.get();
    drag.clear();
    this.update(cx, |e, cx| e.refocus_row(key, window, cx)).ok();
    let from = state.read(cx).edit_buffer().and_then(|b| b.index(key));
    if let Some(to) = from.and_then(|from| drop_index(from, slot)) {
        state.update(cx, |s, cx| s.edit(cx, |b| b.move_field(key, to)));
        this.update(cx, |e, cx| e.start_flash(key, cx)).ok();
    } else {
        this.update(cx, |_, cx| cx.notify()).ok();
    }
}

/// `move_field` destination for a row dragged from `from` and dropped in the gap at
/// `slot` (an index among the other rows); `None` at its own place (no edit). As
/// `move_field` removes first and then inserts, the destination is the slot itself.
fn drop_index(from: usize, slot: usize) -> Option<usize> {
    (slot != from).then_some(slot)
}

/// Strength and live notices of one password row (05 §2.3 "Password notices").
struct ScoredValue {
    /// The value they were computed for.
    value: SecretString,
    bits: f64,
    issues: Vec<Issue>,
}

/// Per-row [`ScoredValue`]s, kept until the row's value or the saved vault changes, so a
/// frame (a scroll, a drag move, typing in another row) scores nothing again: one
/// `strength_bits` and one reuse scan per value change.
#[derive(Default)]
struct IssueCache {
    /// The edited item: reuse is counted among the saved items other than it.
    item: Option<Uuid>,
    /// The listing's audit when the entries were computed. `vault_changed` replaces it,
    /// which is when the reuse counts can change.
    audit: Option<Rc<audit::Issues>>,
    rows: HashMap<u64, ScoredValue>,
}

impl IssueCache {
    /// Rescores the password rows whose value changed (all of them after a vault change)
    /// and drops the entries of rows that are gone or no longer passwords.
    fn update(&mut self, buffer: &EditBuffer, s: &AppState) {
        let audit = &s.listing.issues;
        let item = Some(buffer.item.id);
        if self.item != item || !self.audit.as_ref().is_some_and(|a| Rc::ptr_eq(a, audit)) {
            self.item = item;
            self.audit = Some(audit.clone());
            self.rows.clear();
        }
        let passwords = || {
            buffer
                .keys
                .iter()
                .zip(&buffer.item.fields)
                .filter(|(_, f)| f.kind == FieldKind::Password)
        };
        self.rows
            .retain(|key, _| passwords().any(|(k, _)| k == key));
        let vault = s.unlocked_vault();
        for (key, field) in passwords() {
            let value = field.value.expose_secret();
            if self
                .rows
                .get(key)
                .is_some_and(|c| c.value.expose_secret() == value)
            {
                continue;
            }
            let bits = strength_bits(value);
            let issues = vault
                .map(|v| audit::scored_value_issues(v, value, bits, buffer.item.id))
                .unwrap_or_default();
            let value = field.value.clone();
            self.rows.insert(
                *key,
                ScoredValue {
                    value,
                    bits,
                    issues,
                },
            );
        }
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
thread_local! {
    static ALL_ARROWS: Cell<bool> = const { Cell::new(false) };
}

/// Tests only: while alive, ↑/↓ are drawn on every row, as the cursor audit's scan moves
/// no hover. Dropping it restores hover/focus-only arrows.
#[cfg(test)]
#[must_use]
pub(crate) struct AllArrowsForTests(());

#[cfg(test)]
impl AllArrowsForTests {
    pub(crate) fn on() -> Self {
        ALL_ARROWS.with(|a| a.set(true));
        Self(())
    }
}

#[cfg(test)]
impl Drop for AllArrowsForTests {
    fn drop(&mut self) {
        ALL_ARROWS.with(|a| a.set(false));
    }
}

fn all_arrows() -> bool {
    #[cfg(test)]
    return ALL_ARROWS.with(Cell::get);
    #[cfg(not(test))]
    false
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
    /// The editor column's scroll; moved to the bottom to reveal an added field.
    scroll: ScrollHandle,
    rows: Vec<Row>,
    /// The field drag in progress, if any.
    drag: Rc<FieldDrag>,
    /// Focus during a field drag (the dragged row, and its inputs, are not drawn).
    drag_focus: FocusHandle,
    /// Width of the field rows at the last paint, for the drag ghost.
    row_width: Rc<Cell<Pixels>>,
    /// This render's label column width ([`edit_label_width`]; `None` = the base
    /// rule), shared by every row.
    label_w: Cell<Option<Pixels>>,
    /// Focus of the open icon picker (arrow keys and Enter move and choose).
    icon_focus: gpui::FocusHandle,
    /// The icon pickers' search field (05 "Icon search"), shared by the item picker and
    /// the field pickers (one is open at a time); its text mirrors `AppState::icon_search`.
    icon_search: Entity<InputState>,
    /// The icon picker's grid scroll, moved to keep the keyboard cursor in view.
    icon_scroll: ScrollHandle,
    /// Live password notices, rescored only when a value changes.
    scores: IssueCache,
    /// Key of the row under the pointer: it shows its ↑/↓ buttons.
    hovered: Option<u64>,
    /// The move flash showing, if any, and its timer (dropping the task cancels it).
    flash: Option<Flash>,
    flash_generation: u64,
    flash_end: Option<gpui::Task<()>>,
    /// Editor renders, for the tests that no frame keeps running after a flash.
    #[cfg(test)]
    renders: usize,
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
        let icon_search = ui::text_input("Search icons", window, cx);
        let subscriptions = vec![
            cx.subscribe_in(
                &icon_search,
                window,
                |this, input, ev: &InputEvent, _, cx| {
                    if matches!(ev, InputEvent::Change) {
                        let query = ui::input_text(input, cx);
                        this.state.update(cx, |s, cx| s.set_icon_query(query, cx));
                        // New results start at the top.
                        this.icon_scroll.set_offset(gpui::Point::default());
                    }
                },
            ),
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
            scroll: ScrollHandle::new(),
            rows: Vec::new(),
            drag: Rc::default(),
            drag_focus: cx.focus_handle(),
            row_width: Rc::new(Cell::new(px(280.))),
            label_w: Cell::new(None),
            icon_focus: cx.focus_handle(),
            icon_search,
            icon_scroll: ScrollHandle::new(),
            scores: IssueCache::default(),
            hovered: None,
            flash: None,
            flash_generation: 0,
            flash_end: None,
            #[cfg(test)]
            renders: 0,
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
                self.scores.clear();
                self.hovered = None;
                self.flash = None;
                self.flash_end = None;
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
            self.scores.clear();
            // Row keys restart per session: a stale key would light another row.
            self.hovered = None;
            self.flash = None;
            self.flash_end = None;
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
        if buffer.focus_row.is_some() {
            self.focus_added(window, cx);
        }
        cx.notify();
    }

    /// Focuses the row just added from "Add field" (its value input, or the name of a
    /// section) and scrolls it into view (05 §2.5, owner 2026-11-12).
    fn focus_added(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let key = self.state.update(cx, |s, _| {
            s.edit_buffer_mut().and_then(EditBuffer::take_focus_row)
        });
        let Some(row) = key.and_then(|k| self.rows.iter().find(|r| r.key == k)) else {
            return;
        };
        match &row.value {
            ValueInput::Line(input) => ui::focus_input(input, window, cx),
            ValueInput::Area(area) => area.update(cx, |a, cx| a.focus(window, cx)),
            ValueInput::None => ui::focus_input(&row.name, window, cx),
        }
        // Added fields are appended: the last row, just above "Add field".
        self.scroll.scroll_to_bottom();
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
            // Tab stops by the handle itself: a tracked handle ignores `tab_index`.
            up: cx.focus_handle().tab_stop(true),
            down: cx.focus_handle().tab_stop(true),
            trash: cx.focus_handle(),
            _subscriptions: subs,
        }
    }

    /// Focus back to row `key`'s name input after its drag ends (the grip put it there).
    fn refocus_row(&self, key: u64, window: &mut Window, cx: &mut App) {
        if let Some(row) = self.rows.iter().find(|r| r.key == key) {
            ui::focus_input(&row.name, window, cx);
        }
    }

    /// Flashes row `key` after a click-move or drop, replacing any flash (05 "Move flash").
    fn start_flash(&mut self, key: u64, cx: &mut Context<Self>) {
        self.flash_generation += 1;
        let generation = self.flash_generation;
        let reduce_motion = self.state.read(cx).reduce_motion;
        self.flash = Some(Flash {
            key,
            generation,
            reduce_motion,
        });
        let length = if reduce_motion {
            FLASH_SOLID
        } else {
            FLASH_FADE
        };
        self.flash_end = Some(cx.spawn(async move |this, cx| {
            cx.background_executor().timer(length).await;
            this.update(cx, |e, cx| {
                if e.flash.is_some_and(|f| f.generation == generation) {
                    e.flash = None;
                    cx.notify();
                }
            })
            .ok();
        }));
        cx.notify();
    }

    /// The field rows. `kinds` names each child, recorded with its bounds at prepaint
    /// for the drag geometry (and the ghost's width). Relative: the ghost and the
    /// dragged row are placed inside it.
    /// `drawn`: a dragged row is drawn this frame (its key still in the buffer).
    fn rows_container(
        &self,
        rows: Vec<AnyElement>,
        kinds: Vec<Child>,
        drawn: bool,
    ) -> impl IntoElement {
        let width = self.row_width.clone();
        let drag = self.drag.clone();
        let dragging = drag.row.get().is_some();
        ui::v_flex()
            .relative()
            // While dragging, focus sits here (the dragged row is not drawn), so Esc and
            // ⌘S still reach the editor and nothing types into the dragged row.
            .when(dragging, |rows| {
                rows.key_context(crate::actions::FIELD_DRAG_CONTEXT)
                    .track_focus(&self.drag_focus)
            })
            .on_children_prepainted(move |bounds, window, _| {
                if let Some(b) = bounds.first() {
                    width.set(b.size.width);
                    if drawn && b.top() != drag.used_top.get() {
                        window.request_animation_frame();
                    }
                }
                *drag.layout.borrow_mut() = kinds.iter().copied().zip(bounds).collect();
            })
            .children(rows)
    }

    /// One editable field row (05 §2.3 "Edit-mode field rows", owner 2026-11-15): read
    /// mode's `detail::field_row` geometry (label column, value column, 7 px padding,
    /// hairline rule) with borderless inputs in place of the text, the kind chip, ↑/↓
    /// and trash at the trailing edge, and the row's extras under the value line.
    /// `dragged_ix`: index of the row being dragged, if a field drag is in progress.
    #[allow(clippy::too_many_arguments)]
    fn render_row(
        &self,
        ix: usize,
        row: &Row,
        dragged_ix: Option<usize>,
        buffer: &EditBuffer,
        s: &AppState,
        this: &WeakEntity<Self>,
        window: &Window,
        cx: &App,
    ) -> AnyElement {
        let theme = cx.theme();
        let Some(field) = buffer.field(row.key) else {
            return div().into_any_element();
        };
        let key = row.key;
        let count = buffer.keys.len();
        let section = field.kind == FieldKind::Section;
        let name_focus = gpui::Focusable::focus_handle(&row.name, cx);
        let value_focus = row.value_focus(cx);
        let value_focused = value_focus.as_ref().is_some_and(|h| h.is_focused(window));
        // ↑/↓ (owner 2026-11-16): only while the pointer is over the row, or while one of
        // them has keyboard focus (`focus_ring_allowed`: focus arrived by keyboard and no
        // click since; a click on a gpui-component Button never takes focus). Never
        // because the row's inputs are focused, which follow the row when it moves (the
        // old rule lit a moved row away from the pointer); none during a field drag.
        let arrow_focused =
            (row.up.is_focused(window) || row.down.is_focused(window)) && ui::focus_ring_allowed();
        let show_arrows =
            all_arrows() || (dragged_ix.is_none() && self.hovered == Some(key)) || arrow_focused;

        let mover = |id: &'static str, icon: IconName, label: &str, to: Option<usize>, focus| {
            let state = self.state.clone();
            let this = this.clone();
            // The row that takes this row's place, i.e. the one under the pointer after
            // a click-move (for rows of equal height; the paint-time hover check corrects
            // it otherwise).
            let swapped = to.and_then(|to| buffer.keys.get(to).copied());
            ui::icon_button((id, key), icon, label)
                .track_focus(focus)
                .debug_selector(move || format!("{id} {key}"))
                .disabled(to.is_none())
                .clickable_when(to.is_some())
                .on_click(move |ev, _, cx| {
                    let Some(to) = to else { return };
                    // A click moves the row out from under the pointer: hand the hover
                    // to the row now there before the frame, so the moved row does not
                    // blink its arrows. By keyboard, focus (and the arrows) follow it.
                    let by_mouse = !matches!(ev, gpui::ClickEvent::Keyboard(_));
                    if by_mouse {
                        this.update(cx, |e, _| e.hovered = swapped).ok();
                    }
                    state.update(cx, |s, cx| s.edit(cx, |b| b.move_field(key, to)));
                    // Only a click flashes: by keyboard, focus already marks the row.
                    if by_mouse {
                        this.update(cx, |e, cx| e.start_flash(key, cx)).ok();
                    }
                })
        };
        // Hidden arrows keep their space and their Tab stops: two empty divs holding the
        // buttons' focus handles (`invisible()` would drop the Tab stops). Tab onto one
        // focuses the handle, which shows the real button in its place.
        let slot = |id: &'static str, focus: &FocusHandle| {
            div()
                .id((id, key))
                .flex_none()
                .size_6()
                .track_focus(focus)
                .tab_index(0)
        };
        let arrows = if show_arrows {
            ui::h_flex()
                .flex_none()
                .gap(px(4.))
                .child(mover(
                    "move-up",
                    IconName::ArrowUp,
                    "Move field up",
                    ix.checked_sub(1),
                    &row.up,
                ))
                .child(mover(
                    "move-down",
                    IconName::ArrowDown,
                    "Move field down",
                    (ix + 1 < count).then_some(ix + 1),
                    &row.down,
                ))
        } else {
            // Their space stays reserved, so the value input does not resize on hover.
            ui::h_flex()
                .flex_none()
                .gap(px(4.))
                .child(slot("move-up-slot", &row.up))
                .child(slot("move-down-slot", &row.down))
        };
        let remove = {
            let state = self.state.clone();
            ui::icon_button(("remove-field", key), IconName::Trash, "Remove field")
                .track_focus(&row.trash)
                .debug_selector(move || format!("remove-field {key}"))
                .on_click(move |_, _, cx| {
                    state.update(cx, |s, cx| s.edit(cx, |b| b.remove_field(key)));
                })
        };
        let trailing = ui::h_flex()
            .debug_selector(move || format!("edit-trailing {key}"))
            .flex_none()
            .gap(px(4.))
            .child(Tag::secondary().small().child(kind_name(field.kind)))
            .child(arrows)
            .child(remove);

        let drag = self.drag.clone();
        let drag_focus = self.drag_focus.clone();
        let grip_focus = row.name.clone();
        let grip = div()
            .flex_none()
            .debug_selector(move || format!("grip {key}"))
            .id(("grip", key))
            .cursor_grab()
            .text_color(theme.muted_foreground)
            .child(Icon::new(IconName::GripVertical).size_4())
            // Pressing the grip focuses the row's name input rather than letting the
            // detail column take focus: the input stays drawn while the row is collapsed
            // and Esc then reaches the editor's drag cancel (not the edit cancel).
            .on_mouse_down(gpui::MouseButton::Left, {
                let drag = drag.clone();
                move |ev, window, cx| {
                    window.prevent_default();
                    drag.press_y.set(ev.position.y);
                    ui::focus_input(&grip_focus, window, cx);
                }
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
                    header_dy: if section && ix > 0 {
                        px(super::detail::SECTION_GAP)
                    } else {
                        px(0.)
                    },
                },
                move |dragged, _, window, cx| {
                    drag.start(dragged, ix);
                    window.focus(&drag_focus, cx);
                    cx.new(|_| NoPreview)
                },
            );
        let name = div()
            .debug_selector(move || format!("edit-name {key}"))
            .flex_1()
            .min_w_0()
            .child(
                field_input(&row.name)
                    .text_color(theme.foreground)
                    .font_weight(FontWeight::MEDIUM),
            );

        let row_el = ui::h_flex()
            .id(("edit-row", key))
            .debug_selector(move || format!("edit-row {key}"))
            .relative()
            .w_full()
            .border_color(theme.border)
            // First child: painted under the row's content, inside its border, so the
            // inputs' text and the hairline rule are untouched.
            .children(
                self.flash
                    .filter(|f| f.key == key)
                    .map(|f| move_flash(f, theme.primary)),
            )
            .on_hover({
                let this = this.clone();
                move |hovered, _, cx| {
                    // A drag crossing rows does not hover them (and redraws nothing).
                    let hovered = *hovered && !cx.has_active_drag();
                    this.update(cx, |e, cx| {
                        let now = if hovered {
                            Some(key)
                        } else {
                            e.hovered.filter(|k| *k != key)
                        };
                        if now != e.hovered {
                            e.hovered = now;
                            cx.notify();
                        }
                    })
                    .ok();
                }
            });

        // A section: read mode's heading geometry (extra space above unless first, 2 px
        // rule), one name input spanning the row.
        if section {
            let top = if ix == 0 {
                FIELD_ROW_PAD_Y
            } else {
                FIELD_ROW_PAD_Y + super::detail::SECTION_GAP
            };
            return row_el
                .pt(px(top))
                .pb(px(FIELD_ROW_PAD_Y))
                .gap(px(4.))
                .border_b_2()
                .child(grip)
                .child(name)
                .child(trailing)
                .into_any_element();
        }

        let value: Option<AnyElement> = match &row.value {
            ValueInput::Line(input) => {
                let masked = matches!(
                    field.kind,
                    FieldKind::Password | FieldKind::Pin | FieldKind::Totp
                );
                Some(
                    field_input(input)
                        // Muted like read mode's values until focused.
                        .text_color(if value_focused {
                            theme.foreground
                        } else {
                            theme.muted_foreground
                        })
                        .when(masked, |i| {
                            i.font_family(theme.mono_font_family.clone()).mask_toggle()
                        })
                        .into_any_element(),
                )
            }
            ValueInput::Area(area) => Some(
                Textarea::new(area)
                    .bg(gpui::transparent_black())
                    .border_color(gpui::transparent_black())
                    .text_color(if value_focused {
                        theme.foreground
                    } else {
                        theme.muted_foreground
                    })
                    .into_any_element(),
            ),
            ValueInput::None => None,
        };
        let notes = matches!(row.value, ValueInput::Area(_));
        // A revealed secret copies through the concealed, auto-clearing pasteboard path.
        let sensitive_input = match &row.value {
            ValueInput::Line(input) if field.kind.is_sensitive() => Some(input.clone()),
            _ => None,
        };
        let content = ui::h_flex()
            .debug_selector(move || format!("edit-content {key}"))
            .w_full()
            .min_w_0()
            .when(notes, |line| line.items_start())
            .gap(px(4.))
            .min_h(px(FIELD_LINE_MIN_H))
            .child(
                div()
                    .debug_selector(move || format!("edit-value {key}"))
                    .flex_1()
                    .min_w_0()
                    .when_some(sensitive_input, |d, input| {
                        let state = self.state.clone();
                        ui::route_input_copy(d, &input, move |value, _, cx| {
                            state.update(cx, |s, cx| s.copy_secret(value, cx));
                        })
                    })
                    .children(value),
            )
            .child(trailing);

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
                )
                .debug_selector(move || format!("generate-btn {key}")),
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
        let scored = self.scores.rows.get(&key);
        // Under the value line, inside the value column: the strength meter with
        // Generate, the TOTP validity line with Scan, the notices (05 §2.3).
        let meter_line = generate.map(|generate| {
            ui::h_flex()
                .gap(px(8.))
                .child(div().flex_1().min_w_0().when_some(scored, |d, scored| {
                    d.debug_selector(move || format!("strength-meter {key}"))
                        .child(ui::strength_meter(scored.bits, cx))
                }))
                .child(generate)
        });
        let totp_line = scan_file.map(|scan| {
            ui::h_flex()
                .gap(px(8.))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .children(totp_hint(key, buffer, cx)),
                )
                .child(scan)
        });
        let issues = scored.map_or(&[][..], |scored| &scored.issues[..]);
        let column = ui::v_flex()
            .flex_1()
            .min_w_0()
            .gap(px(super::detail::ISSUE_STRIP_GAP))
            .child(content)
            .when(buffer.remote_fields.contains(&key), |col| {
                col.child(remote_badge(("remote", key)))
            })
            .when(buffer.row_limited(key), |col| {
                col.child(limit_note(
                    ("field-limit", key),
                    format!("field-limit {key}"),
                    cx,
                ))
            })
            .children(totp_line)
            .children(meter_line)
            // Password notices follow the typed value; reuse is checked against the
            // saved items other than this one (05 §2.3 "Password notices").
            .children(issues.iter().map(|&issue| {
                super::detail::issue_strip(
                    &FieldIssue {
                        field: field.id,
                        issue,
                    },
                    cx,
                )
            }));

        row_el
            .items_start()
            .py(px(FIELD_ROW_PAD_Y))
            .gap(px(FIELD_ROW_GAP))
            .border_b_1()
            .child(
                super::detail::label_column(ui::h_flex(), self.label_w.get())
                    .debug_selector(move || format!("edit-label {key}"))
                    .min_h(px(FIELD_LINE_MIN_H))
                    .gap(px(EDIT_LABEL_GAP))
                    .child(grip)
                    // Sections carry no icon (05 "Field icons").
                    .child(super::icon_view::field_icon_button(
                        &self.state,
                        key,
                        &row.icon_focus,
                        (&self.icon_search, &self.icon_scroll),
                        &name_focus,
                        cx,
                    ))
                    .child(name),
            )
            .child(column)
            .into_any_element()
    }
}

/// The edit-mode label column (owner decisions 2026-11-21). On rows at least
/// [`EDIT_WIDE_ROW`] px plus the chrome wide, the field-name input is a fixed
/// [`EDIT_NAME_W`] px box and the column is that plus [`edit_name_chrome`] (grip, gap,
/// field-icon button, gap); rows may shift on Edit. On narrower rows it is read mode's
/// rule (`detail::label_width` of `fit`, the read-mode fit), so a narrow pane keeps its
/// value input room. `None` = the base rule. `rem` is the window's rem size.
pub(crate) fn edit_label_width(
    row: Pixels,
    rem: Pixels,
    fit: impl FnOnce() -> Option<Pixels>,
) -> Option<Pixels> {
    let chrome = edit_name_chrome(rem);
    if row >= px(EDIT_WIDE_ROW) + chrome {
        Some(px(EDIT_NAME_W) + chrome)
    } else {
        super::detail::label_width(fit(), row)
    }
}

/// The editor label column's chrome left of the name input: the grip (`size_4`,
/// 1 rem), a gap, the field-icon button (small icon-only `Button`, `size_6`, 1.5 rem)
/// and a gap.
pub(crate) fn edit_name_chrome(rem: Pixels) -> Pixels {
    rem * 2.5 + px(2. * EDIT_LABEL_GAP)
}

/// The field-name input's fixed width on wide rows (padding and border included).
const EDIT_NAME_W: f32 = 140.;
/// Gap between the editor label column's grip, icon button and name input.
const EDIT_LABEL_GAP: f32 = 4.;
/// With the chrome added, the narrowest row that gets the fixed name width: the value
/// input then keeps the width it had at 420 px rows with a 140 px column (~114 px).
const EDIT_WIDE_ROW: f32 = 420.;

/// A borderless, transparent field input (05 §2.3 "Edit-mode field rows"): it reads
/// like read mode's text until focused, when gpui-component's accent ring is drawn on
/// the input itself (its border stays 1 px transparent at rest, so nothing moves).
fn field_input(state: &Entity<InputState>) -> Input {
    ui::input(state)
        .small()
        .bg(gpui::transparent_black())
        .border_color(gpui::transparent_black())
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
/// and the small input. Read mode's tags row has it as its minimum, so the field rows
/// of a tagged item sit at the same height in both modes.
pub(super) const TAGS_ROW_HEIGHT: f32 = 28.;

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
        FieldKind::Pin => "PIN",
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

/// The flash fill of row `flash.key` (05 "Move flash"): the accent at 18 % fading to
/// clear with an ease-out, or solid under Reduce Motion (its timer removes it).
fn move_flash(flash: Flash, accent: gpui::Hsla) -> AnyElement {
    let fill = div()
        .debug_selector(move || format!("move-flash {}", flash.key))
        .absolute()
        .inset_0();
    if flash.reduce_motion {
        return fill.bg(accent.opacity(FLASH_ALPHA)).into_any_element();
    }
    fill.with_animation(
        ("move-flash", flash.generation),
        gpui::Animation::new(FLASH_FADE).with_easing(gpui::ease_out_quint()),
        move |el, t| el.bg(accent.opacity(FLASH_ALPHA * (1. - t))),
    )
    .into_any_element()
}

impl Editor {
    /// The rows' width this frame, from the detail column (`detail::rows_width`), so
    /// the label column cap matches read mode's on the first edit frame (prepaint
    /// updates it too, one frame late).
    pub(super) fn set_rows_width(&self, width: Pixels) {
        self.row_width.set(width);
    }
}

impl Render for Editor {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        #[cfg(test)]
        {
            self.renders += 1;
        }
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
        self.scores.update(buffer, s);
        let theme = cx.theme();
        let new_kind = match s.mode {
            Mode::New(kind, _) => Some(kind),
            _ => None,
        };
        // History sits under its row as in read mode (under its own password or PIN row;
        // a removed field's under the first password, else the first PIN), with per-entry
        // remove buttons (edit mode only; a new item has no history).
        let mut rows: Vec<AnyElement> = Vec::with_capacity(self.rows.len() + 1);
        let fields = &buffer.item.fields;
        // Each stored entry's row, in one pass: field index -> its entries, in item order.
        let mut owned_by_row: Vec<Vec<&HistoryEntry>> = vec![Vec::new(); fields.len()];
        if new_kind.is_none() {
            for h in &buffer.item.history {
                if let Some(at) = super::detail::history_row(fields, h) {
                    owned_by_row[at].push(h);
                }
            }
        }
        let dragged_ix = cx
            .has_active_drag()
            .then(|| self.drag.row.get())
            .flatten()
            .and_then(|k| self.rows.iter().position(|r| r.key == k));
        // Below the wide threshold, read mode's fit from the buffer's live names (so
        // the column grows as a name is typed); shaped only when it is needed.
        let row_w = self.row_width.get();
        let live = buffer.keys.iter().filter_map(|&k| buffer.field(k));
        self.label_w
            .set(edit_label_width(row_w, window.rem_size(), || {
                super::detail::label_fit(live, window, cx)
            }));
        let this = cx.entity().downgrade();
        // A field drag: the ghost's top this frame; the gap follows its projected slot.
        let now = Instant::now();
        let ghost_top = dragged_ix.map(|_| {
            let pointer = window.mouse_position().y;
            // Edge auto-scroll first, so the ghost and the slot below use the rows'
            // positions after this frame's scroll (the layout is the last prepaint's).
            let drag = &self.drag;
            let dt = drag
                .last_scroll
                .get()
                .map_or(1. / 60., |t| now.saturating_duration_since(t).as_secs_f32());
            #[cfg(test)]
            let dt = drag.test_dt.get().unwrap_or(dt);
            let view = self.scroll.bounds();
            let step = auto_scroll_step(pointer, view.top(), view.bottom(), s.reduce_motion, dt);
            drag.last_scroll.set((step != 0.).then_some(now));
            let offset = self.scroll.offset();
            let max = self.scroll.max_offset().y.max(px(0.));
            let y = (offset.y - px(step)).clamp(-max, px(0.));
            if y != offset.y {
                self.scroll.set_offset(gpui::point(offset.x, y));
            }
            // The rows move by `y - offset.y`: the pointer, relative to them, the other way.
            let top = drag.frame(pointer - (y - offset.y), s.reduce_motion, now);
            if step != 0. || drag.animating(now) {
                window.request_animation_frame();
            }
            top
        });
        let mut kinds: Vec<Child> = Vec::with_capacity(self.rows.len() + 4);
        let mut slot = 0;
        for (ix, row) in self.rows.iter().enumerate() {
            let dragged = dragged_ix == Some(ix);
            if dragged_ix.is_some() && !dragged {
                for (h, selector) in self.drag.gaps_at(slot, now) {
                    rows.push(drop_gap(h, selector, cx));
                    kinds.push(Child::Other);
                }
                slot += 1;
            }
            // The dragged row leaves the flow, with its history; the ghost stands in.
            if dragged {
                continue;
            }
            rows.push(self.render_row(ix, row, dragged_ix, buffer, s, &this, window, cx));
            kinds.push(Child::Row(row.key));
            // The row's field index, by key (not by assuming row order).
            let at = if buffer.keys.get(ix) == Some(&row.key) {
                Some(ix)
            } else {
                buffer.keys.iter().position(|k| *k == row.key)
            };
            // Shown while the row owns any stored entry, so "(0) · N removed on save" stays
            // after the last one is trashed or cleared.
            let Some((at, owned)) = at.and_then(|at| Some((at, owned_by_row.get(at)?))) else {
                continue;
            };
            if owned.is_empty() {
                continue;
            }
            let history: Vec<_> = owned
                .iter()
                .copied()
                .filter(|h| !buffer.removed_history.contains(&h.replaced_at))
                .collect();
            // Pending removals of this row's entries.
            let removed = buffer
                .removed_history
                .iter()
                .filter(|t| owned.iter().any(|h| h.replaced_at == **t))
                .count();
            kinds.push(Child::History(row.key));
            rows.push(history_disclosure(
                super::detail::History {
                    entries: &history,
                    fields,
                    row: at,
                },
                Some(removed),
                s,
                &self.state,
                text::now_millis(),
                cx,
            ));
        }

        if let Some(top) = ghost_top {
            for (h, selector) in self.drag.gaps_at(slot, now) {
                rows.push(drop_gap(h, selector, cx));
                kinds.push(Child::Other);
            }
            if let Some(ghost) = self.drag.ghost.borrow().as_ref() {
                let ghost = drag_ghost(ghost, self.label_w.get(), cx).top(top);
                rows.push(ghost.into_any_element());
                kinds.push(Child::Other);
            }
        }

        let header = ui::h_flex()
            .debug_selector(|| "editor-header".into())
            .gap(px(8.))
            .child(super::icon_view::picker_trigger(
                &self.state,
                &self.icon_focus,
                &self.icon_search,
                &self.icon_scroll,
                &gpui::Focusable::focus_handle(&self.title, cx),
                HEADER_TILE,
                cx,
            ))
            .child(
                div()
                    .debug_selector(|| "editor-title".into())
                    .flex_1()
                    .min_w_0()
                    // Read mode's title size and weight, on the input itself (an Input
                    // sets its own text size, so a wrapper's would not reach it).
                    .child(super::detail::title_text(ui::input(&self.title))),
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

        let pad_x = px(ui::COLUMN_PAD_X - ui::FOCUS_RING_WIDTH);
        // Pinned (05 §2.3 "Detail header is pinned", edit mode): the header, the tags
        // row and the rule under them stay put, with read mode's top and side padding.
        let pinned = ui::v_flex()
            .debug_selector(|| "editor-pinned".into())
            .flex_none()
            .pt(px(ui::content_top(s)))
            .px(pad_x)
            // Read mode's gap: with the tags row's height, the rows stay put on Edit.
            .gap(px(12.))
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
            .child(ui::divider(cx));

        // Only the field rows and "Add field" scroll. No top padding: as in read mode the
        // first row sits under the rule by its own 7 px padding (05 "Edit-mode field rows").
        let scroll = ui::v_flex()
            .id("editor-scroll")
            .debug_selector(|| "editor-scroll".into())
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .track_scroll(&self.scroll)
            .px(pad_x)
            .pb(px(64.))
            .gap(px(10.))
            .when(rows.is_empty(), |col| {
                col.child(ui::muted("No fields. Add one below.", cx))
            })
            .child(self.rows_container(rows, kinds, dragged_ix.is_some()))
            .child(ui::h_flex().child(add_field));

        ui::v_flex()
            // Esc during a field drag cancels the drag, not the edit.
            .capture_action({
                let (drag, this) = (self.drag.clone(), this.clone());
                move |_: &CancelEdit, window, cx| {
                    if let Some(key) = drag.row.get().filter(|_| cx.has_active_drag()) {
                        drag.clear();
                        this.update(cx, |e, cx| e.refocus_row(key, window, cx)).ok();
                        cx.stop_active_drag(window);
                        cx.stop_propagation();
                    }
                }
            })
            // A release anywhere (in or out of the editor) drops at the gap's slot.
            .capture_any_mouse_up({
                let (drag, state, this) = (self.drag.clone(), self.state.clone(), this.clone());
                move |ev, window, cx| {
                    if ev.button == gpui::MouseButton::Left {
                        finish_drag(&drag, &state, &this, window, cx);
                    }
                }
            })
            .on_mouse_up_out(gpui::MouseButton::Left, {
                let (drag, state) = (self.drag.clone(), self.state.clone());
                move |_, window, cx| finish_drag(&drag, &state, &this, window, cx)
            })
            .size_full()
            .child(pinned)
            .child(scroll)
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
                        s.edit(cx, |b| b.focus_row = Some(b.add_field(kind)));
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

    /// Every (from, slot) for up to 5 rows: no move exactly when the drop leaves the
    /// order as it was, and `move_field`'s remove-then-insert lands the row in the gap,
    /// i.e. at `slot` among the other rows.
    #[test]
    fn drop_index_matches_remove_then_insert() {
        for n in 1..=5 {
            for from in 0..n {
                for slot in 0..n {
                    let mut want: Vec<usize> = (0..n).filter(|&r| r != from).collect();
                    want.insert(slot, from);
                    let unchanged = want == (0..n).collect::<Vec<_>>();
                    let got = drop_index(from, slot);
                    assert_eq!(got.is_none(), unchanged, "n={n} {from}->{slot}");
                    if let Some(to) = got {
                        let mut v: Vec<usize> = (0..n).collect();
                        let x = v.remove(from);
                        v.insert(to, x);
                        assert_eq!(v, want, "n={n} {from}->{slot}");
                    }
                }
            }
        }
    }

    fn bounds(vcx: &mut VisualTestContext, selector: String) -> Option<Bounds<Pixels>> {
        vcx.debug_bounds(Box::leak(selector.into_boxed_str()))
    }

    fn near(a: Pixels, b: Pixels) -> bool {
        (a - b).abs() < px(0.5)
    }

    struct Rig {
        state: Entity<AppState>,
        main: Entity<crate::screens::main::MainScreen>,
        vcx: VisualTestContext,
        keys: Vec<u64>,
        /// The rows' top before any drag (the group's top).
        top: Pixels,
        _dir: tempfile::TempDir,
    }

    /// An item with text fields a, b, c in edit mode; `reduce` sets Reduce Motion.
    fn rig(cx: &mut TestAppContext, reduce: bool) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let (state, main, mut vcx) = super::tests::open(dir.path(), cx);
        state.update(&mut vcx, |s, cx| {
            s.set_reduce_motion(reduce, cx);
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
        let top = bounds(&mut vcx, format!("edit-row {}", keys[0]))
            .unwrap()
            .top();
        Rig {
            state,
            main,
            vcx,
            keys,
            top,
            _dir: dir,
        }
    }

    impl Rig {
        fn names(&mut self) -> Vec<String> {
            self.state.read_with(&self.vcx, |s, _| {
                let b = s.edit_buffer().unwrap();
                b.item.fields.iter().map(|f| f.name.clone()).collect()
            })
        }
        fn row(&mut self, i: usize) -> Bounds<Pixels> {
            bounds(&mut self.vcx, format!("edit-row {}", self.keys[i])).unwrap()
        }
        fn get(&mut self, selector: &str) -> Option<Bounds<Pixels>> {
            bounds(&mut self.vcx, selector.into())
        }
        /// Presses row 0's grip and pulls it 6 px down: the drag starts.
        fn start(&mut self) {
            let grip = bounds(&mut self.vcx, format!("grip {}", self.keys[0]))
                .unwrap()
                .center();
            let none = Modifiers::none();
            self.vcx.simulate_mouse_down(grip, MouseButton::Left, none);
            let to = grip + point(px(0.), px(6.));
            self.vcx.simulate_mouse_move(to, MouseButton::Left, none);
            self.vcx.run_until_parked();
        }
        fn to(&mut self, p: gpui::Point<Pixels>) {
            self.vcx
                .simulate_mouse_move(p, MouseButton::Left, Modifiers::none());
            self.vcx.run_until_parked();
        }
        /// Moves the pointer so the ghost's centre lands at `y`.
        fn centre_at(&mut self, y: Pixels) {
            let ghost = self.get("drag-ghost").unwrap();
            let p = self.vcx.update(|w, _| w.mouse_position());
            self.to(point(p.x, p.y + y - ghost.center().y));
        }
        fn release(&mut self, p: gpui::Point<Pixels>) {
            self.vcx
                .simulate_mouse_up(p, MouseButton::Left, Modifiers::none());
            self.vcx.run_until_parked();
        }
        fn dragging(&mut self) -> bool {
            self.main.read_with(&self.vcx, |m, cx| {
                m.editor.read(cx).drag.row.get().is_some()
            })
        }
        /// (rows container's drag focus, row 0's name input) focused.
        fn focus(&mut self) -> (bool, bool) {
            let (main, key) = (self.main.clone(), self.keys[0]);
            self.vcx.update(|window, cx| {
                let editor = main.read(cx).editor.read(cx);
                let row = editor.rows.iter().find(|r| r.key == key).unwrap();
                let name = gpui::Focusable::focus_handle(&row.name, cx);
                (
                    editor.drag_focus.is_focused(window),
                    name.is_focused(window),
                )
            })
        }
        fn idle(&mut self) -> bool {
            !self.dragging() && self.get("drop-gap").is_none() && self.get("drag-ghost").is_none()
        }
        fn changed(&mut self) -> bool {
            self.state
                .read_with(&self.vcx, |s, _| s.edit_buffer().unwrap().has_changes())
        }
    }

    /// The ghost moves only vertically and never leaves the rows group, wherever the
    /// pointer goes; the dragged row leaves the flow, its gap holds its slot, the value
    /// is never drawn and focus stays in the row (05 §2.3, owner 2026-11-23).
    #[gpui::test]
    fn ghost_is_clamped_to_the_rows_and_vertical_only(cx: &mut TestAppContext) {
        let mut r = rig(cx, true);
        let value = super::tests::value_input(&r.main, r.keys[0], &mut r.vcx);
        r.vcx
            .update(|window, cx| ui::focus_input(&value, window, cx));
        let bottom = r.row(2).bottom();
        r.start();
        assert!(r.get("drop-line").is_none());
        let ghost = r.get("drag-ghost").expect("ghost drawn");
        let gap = r.get("drop-gap").expect("gap at the row's slot");
        assert!(near(gap.top(), r.top) && near(gap.size.height, GHOST_H));
        assert!(near(ghost.size.height, GHOST_H));
        assert!(near(r.row(1).top(), gap.bottom()), "b under the gap");
        let dragged = format!("edit-row {}", r.keys[0]);
        assert!(
            bounds(&mut r.vcx, dragged).is_none(),
            "dragged row not drawn"
        );
        assert!(
            r.focus() == (true, false),
            "focus on the rows while dragging"
        );

        let header = r.vcx.debug_bounds("editor-header").unwrap();
        r.to(point(ghost.center().x, header.top() - px(200.)));
        let up = r.get("drag-ghost").unwrap();
        assert!(near(up.top(), r.top), "clamped at the top: {up:?}");
        r.to(point(ghost.center().x, bottom + px(2000.)));
        let down = r.get("drag-ghost").unwrap();
        assert!(
            near(down.bottom(), bottom),
            "clamped at the bottom: {down:?}"
        );
        let gap = r.get("drop-gap").unwrap();
        assert!(near(gap.bottom(), bottom) && near(r.row(2).bottom(), gap.top()));
        let y = down.center().y;
        for x in [px(-500.), px(5000.)] {
            r.to(point(x, y + px(30.)));
            let side = r.get("drag-ghost").unwrap();
            assert_eq!(
                (side.left(), side.size.width),
                (ghost.left(), ghost.size.width)
            );
        }
    }

    /// The gap follows the ghost's centre against the other rows' midway centres, and
    /// the rows shift around it; Reduce Motion shows the final gap on the first frame.
    #[gpui::test]
    fn gap_follows_the_ghost_centre(cx: &mut TestAppContext) {
        let mut r = rig(cx, true);
        r.start();
        assert!(
            near(r.get("drop-gap").unwrap().top(), r.top),
            "own slot after 6 px"
        );
        // b's midway centre: half a gap plus half of b below the rows' top.
        let (hb, hc) = (r.row(1).size.height, r.row(2).size.height);
        let mid_b = r.top + (GHOST_H + hb) / 2.;
        r.centre_at(mid_b - px(2.));
        assert!(
            near(r.get("drop-gap").unwrap().top(), r.top),
            "still before b"
        );
        r.centre_at(mid_b + px(2.));
        let (gap, b, c) = (r.get("drop-gap").unwrap(), r.row(1), r.row(2));
        assert!(near(b.top(), r.top), "b slid up");
        assert!(near(gap.top(), b.bottom()) && near(c.top(), gap.bottom()));
        assert!(
            near(gap.size.height, GHOST_H),
            "full gap on the first frame"
        );
        assert!(r.get("drop-gap-closing").is_none(), "no closing gap");
        let mid_c = r.top + hb + (GHOST_H + hc) / 2.;
        r.centre_at(mid_c + px(2.));
        let (gap, c) = (r.get("drop-gap").unwrap(), r.row(2));
        assert!(
            near(c.top(), r.top + hb) && near(gap.top(), c.bottom()),
            "after c"
        );
        r.centre_at(mid_c - px(2.));
        let (gap, c) = (r.get("drop-gap").unwrap(), r.row(2));
        assert!(
            near(gap.top(), r.top + hb) && near(c.top(), gap.bottom()),
            "back"
        );
        r.centre_at(mid_b - px(2.));
        let gap = r.get("drop-gap").unwrap();
        assert!(
            near(gap.top(), r.top) && near(r.row(1).top(), gap.bottom()),
            "top"
        );
    }

    /// With motion the old gap closes while the new one opens, then settles.
    #[gpui::test]
    fn gap_moves_with_motion(cx: &mut TestAppContext) {
        let mut r = rig(cx, false);
        r.start();
        let hb = r.row(1).size.height;
        r.centre_at(r.top + (GHOST_H + hb) / 2. + px(2.));
        assert!(r.get("drop-gap-closing").is_some(), "old slot closing");
        std::thread::sleep(GAP_MOTION + Duration::from_millis(30));
        r.vcx.update(|w, _| w.refresh());
        r.vcx.run_until_parked();
        let gap = r.get("drop-gap").unwrap();
        assert!(near(gap.size.height, GHOST_H), "settled: {gap:?}");
        assert!(near(gap.top(), r.row(1).bottom()));
    }

    /// A release anywhere drops at the gap; at the row's own slot nothing changes; Esc
    /// cancels the drag (not the edit) and restores the rows.
    #[gpui::test]
    fn release_anywhere_drops_at_the_gap(cx: &mut TestAppContext) {
        let mut r = rig(cx, true);
        let full = r.row(0);
        let header = r.vcx.debug_bounds("editor-header").unwrap().center();

        r.start();
        let hb = r.row(1).size.height;
        r.centre_at(r.top + (GHOST_H + hb) / 2. - px(2.));
        r.release(point(px(-300.), header.y));
        assert_eq!(r.names(), ["a", "b", "c"]);
        assert!(!r.changed(), "own slot: no edit");
        assert!(!r.dragging() && r.get("drop-gap").is_none());

        r.start();
        let y = r.row(2).center().y;
        r.centre_at(y + px(2.));
        r.vcx.simulate_keystrokes("escape");
        r.vcx.run_until_parked();
        assert!(
            r.state.read_with(&r.vcx, |s, _| s.is_editing()),
            "still editing"
        );
        assert!(r.idle());
        assert_eq!(r.row(0), full, "row restored");
        assert_eq!(r.focus(), (false, true), "focus back in the row");
        let at = r.row(2).center();
        r.release(at);
        assert_eq!(r.names(), ["a", "b", "c"], "Esc dropped nothing");
        assert!(!r.changed());

        // Released far below the window, sideways: lands in the gap after c.
        r.start();
        let below = r.row(2).bottom() + px(2000.);
        r.to(point(px(5000.), below));
        r.release(point(px(5000.), below));
        assert_eq!(r.names(), ["b", "c", "a"]);
        assert!(r.changed());
        assert!(r.idle());
        assert_eq!(r.focus(), (false, true), "focus back in the dropped row");
    }

    /// Keys typed during a drag reach no input of the dragged row.
    #[gpui::test]
    fn typing_during_a_drag_edits_nothing(cx: &mut TestAppContext) {
        let mut r = rig(cx, true);
        r.start();
        r.vcx.simulate_input("xyz");
        r.vcx.simulate_keystrokes("tab x shift-tab y");
        r.vcx.run_until_parked();
        assert_eq!(r.focus(), (true, false), "Tab keeps focus on the drag");
        assert!(r.dragging());
        let at = r.vcx.update(|w, _| w.mouse_position());
        r.release(at);
        assert_eq!(r.names(), ["a", "b", "c"]);
        assert!(!r.changed(), "no edit");
    }

    /// ⌘S or leaving edit mode during a drag ends it with no gap or ghost left.
    #[gpui::test]
    fn save_or_cancel_during_a_drag_clears_it(cx: &mut TestAppContext) {
        for save in [true, false] {
            let mut r = rig(cx, true);
            r.start();
            let hb = r.row(1).size.height;
            r.centre_at(r.top + (GHOST_H + hb) / 2. + px(2.));
            if save {
                r.vcx.simulate_keystrokes("cmd-s");
            } else {
                r.state.update(&mut r.vcx, |s, cx| s.cancel_edit(cx));
            }
            r.vcx.run_until_parked();
            assert!(
                !r.state.read_with(&r.vcx, |s, _| s.is_editing()),
                "save={save}"
            );
            assert!(r.idle(), "save={save}");
            let at = r.vcx.update(|w, _| w.mouse_position());
            r.release(at);
            assert!(r.idle(), "save={save}");
        }
    }

    /// A scroll during a drag (pointer still) keeps the ghost under the pointer.
    #[gpui::test]
    fn scroll_during_a_drag_keeps_the_ghost_under_the_pointer(cx: &mut TestAppContext) {
        let mut r = rig(cx, true);
        let (state, vcx) = (r.state.clone(), &mut r.vcx);
        state.update(vcx, |s, cx| {
            s.edit(cx, |b| {
                for _ in 0..12 {
                    b.add_field(FieldKind::Text);
                }
            })
        });
        vcx.simulate_resize(gpui::size(px(1000.), px(420.)));
        vcx.run_until_parked();
        r.start();
        let ghost = r.get("drag-ghost").unwrap();
        let b = r.row(1);
        let at = r.vcx.update(|w, _| w.mouse_position());
        r.vcx.simulate_event(gpui::ScrollEvent {
            position: at,
            delta: gpui::ScrollDelta::Pixels(point(px(0.), px(-30.))),
            ..Default::default()
        });
        r.vcx.run_until_parked();
        assert!(near(r.row(1).top(), b.top() - px(30.)), "rows scrolled");
        // The scroll frame drew the ghost from the old rows' top; it asked for the next
        // frame (tests have no frame loop, so deliver it).
        let next = r.vcx.update(|w, cx| w.simulate_next_frame(cx));
        assert!(next > 0, "another frame requested");
        r.vcx.run_until_parked();
        assert!(
            near(r.get("drag-ghost").unwrap().top(), ghost.top()),
            "ghost stayed"
        );
    }

    /// A section's ghost keeps the grip under the pointer: the section's extra space
    /// above its header line does not shift it.
    #[gpui::test]
    fn section_ghost_keeps_the_grip_under_the_pointer(cx: &mut TestAppContext) {
        let mut r = rig(cx, true);
        let (state, vcx) = (r.state.clone(), &mut r.vcx);
        let key = state.update(vcx, |s, cx| {
            let mut key = 0;
            s.edit(cx, |b| {
                key = b.add_field(FieldKind::Section);
                b.move_field(key, 1);
            });
            key
        });
        vcx.run_until_parked();
        let grip = bounds(vcx, format!("grip {key}")).unwrap().center();
        let none = Modifiers::none();
        vcx.simulate_mouse_down(grip, MouseButton::Left, none);
        vcx.simulate_mouse_move(grip + point(px(0.), px(6.)), MouseButton::Left, none);
        vcx.run_until_parked();
        let ghost = r.get("drag-ghost").unwrap();
        // Its header line stays under the pointer (within the section's 24 px name
        // line against the ghost's 28 px one; 12 px off before the section offset).
        let off = ghost.center().y - (grip.y + px(6.));
        assert!(off.abs() <= px(3.), "{ghost:?} vs {grip:?}");
    }

    /// Speed: zero at the band's inner side, growing from 120 to 720 px/s at the edge
    /// and beyond it; a constant 360 px/s under Reduce Motion (steps for 1/60 s); a
    /// frame's time is capped at 1/30 s.
    #[test]
    fn auto_scroll_step_values() {
        let (top, bottom) = (px(100.), px(500.));
        let step = |y: f32, rm| auto_scroll_step(px(y), top, bottom, rm, 1. / 60.);
        let long = |y: f32, rm| auto_scroll_step(px(y), top, bottom, rm, 1.);
        let eq = |a: f32, b: f32| assert!((a - b).abs() < 1e-3, "{a} vs {b}");
        eq(long(100., false), -24.);
        eq(long(500., true), 12.);
        eq(step(300., false), 0.);
        eq(step(124., false), 0.);
        eq(step(476., false), 0.);
        eq(step(112., false), -7.);
        eq(step(100., false), -12.);
        eq(step(-400., false), -12.);
        eq(step(488., false), 7.);
        eq(step(2000., false), 12.);
        eq(step(120., true), -6.);
        eq(step(90., true), -6.);
        eq(step(480., true), 6.);
        eq(step(900., true), 6.);
    }

    /// A long item in a small window: auto-scroll at the edge bands, none in the middle,
    /// constant under Reduce Motion, stopping at the bounds and when the drag ends.
    #[gpui::test]
    fn drag_auto_scrolls_at_the_edges(cx: &mut TestAppContext) {
        for reduce in [false, true] {
            let mut r = rig(cx, reduce);
            let (state, vcx) = (r.state.clone(), &mut r.vcx);
            state.update(vcx, |s, cx| {
                s.edit(cx, |b| {
                    for _ in 0..16 {
                        b.add_field(FieldKind::Text);
                    }
                })
            });
            vcx.simulate_resize(gpui::size(px(1000.), px(420.)));
            vcx.run_until_parked();
            let main = r.main.clone();
            let offset = move |vcx: &mut VisualTestContext| {
                main.read_with(vcx, |m, cx| m.editor.read(cx).scroll.offset().y)
            };
            let frame = |vcx: &mut VisualTestContext| {
                vcx.update(|w, cx| w.simulate_next_frame(cx));
                vcx.run_until_parked();
            };
            let view = r.get("editor-scroll").unwrap();
            // A fixed frame time (1/60 s): steps independent of the test machine's pace.
            r.main.read_with(&r.vcx, |m, cx| {
                m.editor.read(cx).drag.test_dt.set(Some(1. / 60.))
            });
            r.start();
            let x = view.center().x;
            assert_eq!(offset(&mut r.vcx), px(0.));

            // Middle: no scroll.
            r.to(point(x, view.center().y));
            frame(&mut r.vcx);
            assert_eq!(offset(&mut r.vcx), px(0.), "middle, reduce={reduce}");

            // Bottom band, 20 px deep: (120 + 600 * 20/24) / 60 px per frame (360 / 60
            // under Reduce Motion).
            r.to(point(x, view.bottom() - px(4.)));
            let want = if reduce { 6. } else { 2. + 10. * 20. / 24. };
            let before = offset(&mut r.vcx);
            frame(&mut r.vcx);
            let d = (before - offset(&mut r.vcx)).as_f32();
            assert!((d - want).abs() < 0.01, "step {d}, reduce={reduce}");
            let max = r
                .main
                .read_with(&r.vcx, |m, cx| m.editor.read(cx).scroll.max_offset().y);
            assert!(max > px(100.), "long item scrolls: {max:?}");
            // The ghost stays under the still pointer across an auto-scroll frame.
            let (ghost, before) = (r.get("drag-ghost").unwrap(), offset(&mut r.vcx));
            frame(&mut r.vcx);
            assert!(offset(&mut r.vcx) < before, "scrolled");
            let now = r.get("drag-ghost").unwrap();
            // Within one device pixel (layout snaps a fractional scroll to 0.5 px).
            let lag = (now.top() - ghost.top()).abs();
            assert!(lag <= px(0.5), "{now:?} vs {ghost:?}");
            for _ in 0..400 {
                frame(&mut r.vcx);
            }
            // Gaps settled (frames here outrun their 150 ms), then two frames so the
            // clamp uses the settled bound.
            std::thread::sleep(GAP_MOTION + Duration::from_millis(20));
            let editor =
                |vcx: &mut VisualTestContext| r.main.read_with(vcx, |m, _| m.editor.clone());
            let editor = editor(&mut r.vcx);
            for _ in 0..20 {
                let busy = editor.read_with(&r.vcx, |e, _| e.drag.animating(Instant::now()));
                if !busy {
                    break;
                }
                frame(&mut r.vcx);
            }
            frame(&mut r.vcx);
            frame(&mut r.vcx);
            let max = r
                .main
                .read_with(&r.vcx, |m, cx| m.editor.read(cx).scroll.max_offset().y);
            assert_eq!(offset(&mut r.vcx), -max, "stops at the bottom");

            // Above the viewport (beyond the top band): back up to the top.
            r.to(point(x, view.top() - px(50.)));
            for _ in 0..400 {
                frame(&mut r.vcx);
            }
            assert_eq!(offset(&mut r.vcx), px(0.), "stops at the top");

            // The drag ends in the bottom band: no more scrolling.
            r.to(point(x, view.bottom() - px(2.)));
            let at = r.vcx.update(|w, _| w.mouse_position());
            r.release(at);
            let after = offset(&mut r.vcx);
            for _ in 0..5 {
                frame(&mut r.vcx);
            }
            assert_eq!(offset(&mut r.vcx), after, "stopped with the drag");
        }
    }

    /// `project_slot` over mixed heights: a section row (12 px gap, 2 px rule), a tall
    /// password row with a history block under it, a notes row, a plain row; and a
    /// single row. Each slot flips across the row's midway centre, ends included.
    #[test]
    fn project_slot_over_mixed_heights() {
        let h = GHOST_H.as_f32(); // 43
        // (is a row, height): section 56, password 90 + history 30, notes 120, text 43.
        let flow = [
            (true, 56.),
            (true, 90.),
            (false, 30.),
            (true, 120.),
            (true, 43.),
        ]
        .map(|(row, ht)| (row, px(ht)));
        // Row tops closed up: 0, 56, (history 146), 176, 296; total 339.
        // Midway centres: top + (43 + h) / 2.
        let mids = [
            (0. + (h + 56.) / 2.),
            56. + (h + 90.) / 2.,
            176. + (h + 120.) / 2.,
            296. + (h + 43.) / 2.,
        ];
        assert_eq!(mids, [49.5, 122.5, 257.5, 339.]);
        assert_eq!(project_slot(&flow, px(h / 2.)), 0, "top end");
        assert_eq!(project_slot(&flow, px(339. + h / 2.)), 4, "bottom end");
        for (r, m) in mids.into_iter().enumerate() {
            assert_eq!(project_slot(&flow, px(m - 1.)), r, "above row {r}");
            assert_eq!(project_slot(&flow, px(m + 1.)), r + 1, "below row {r}");
        }
        let one = [(true, px(43.))];
        assert_eq!(project_slot(&one, px(h / 2.)), 0, "single row, top");
        assert_eq!(
            project_slot(&one, px(43. + h / 2.)),
            1,
            "single row, bottom"
        );
    }
}

#[cfg(test)]
#[path = "editor_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "editor_perf_tests.rs"]
mod perf_tests;

#[cfg(test)]
#[path = "editor_row_tests.rs"]
mod row_tests;
