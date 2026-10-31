//! Unlocked main window: sidebar, item list, detail (specs/05-ui.md §1, §2.3).
//!
//! Renders `AppState` only. Global actions mutate the state; this view applies the
//! focus requests they leave behind and keeps the virtual list in step with the
//! cached listing.

pub(crate) mod attachments;
pub(crate) mod detail;
mod editor;
mod generator;
pub mod icon_view;
mod list;
pub use icon_view::item_tile;
#[cfg(test)]
pub use {detail::detail_placeholder, list::list_placeholder};
#[cfg(test)]
#[path = "main/collapse_tests.rs"]
mod collapse_tests;
mod prompts;
mod sidebar;
mod sync_banners;

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use gpui::{
    App, AppContext as _, Axis, Context, DragMoveEvent, Entity, EventEmitter, FocusHandle,
    InteractiveElement as _, IntoElement, ListAlignment, ListState, ParentElement as _, Render,
    Styled as _, Subscription, Task, Window, prelude::FluentBuilder as _, px,
};
use gpui_component::ActiveTheme as _;
use gpui_component::input::{InputEvent, InputState};
use vault_core::Uuid;

use self::editor::Editor;
use self::generator::GeneratorView;
use crate::state::{AppState, FocusTarget};
use crate::{text, ui};

/// Default widths and ranges for the sidebar and item list (§1).
const SIDEBAR: (f32, f32, f32) = (220., 180., 320.);
const LIST: (f32, f32, f32) = (300., 240., 420.);
/// The detail column never gets narrower than this (dragging, or restored widths in a
/// narrower window).
const DETAIL_MIN: f32 = 320.;

/// `[sidebar, list]` widths that leave the detail column at least `DETAIL_MIN` in a
/// window `window` px wide: the list gives way first, then the sidebar, neither below
/// its own minimum. `sidebar` says whether the sidebar takes room.
fn fit_widths([side, list]: [f32; 2], window: f32, sidebar: bool) -> [f32; 2] {
    let room = window - DETAIL_MIN;
    let taken = if sidebar { side } else { 0. };
    let list = list.min(room - taken).max(LIST.1);
    let side = if sidebar {
        side.min(room - list).max(SIDEBAR.1)
    } else {
        side
    };
    [side, list]
}

/// A column footer: fixed height, full-width 1 px top divider, contents centred
/// vertically. Only the item list has one (the sidebar has no bottom bar).
fn column_footer(border: gpui::Hsla, cx: &App) -> gpui::Div {
    ui::h_flex()
        .flex_none()
        .h(crate::theme::scaled(ui::FOOTER_HEIGHT, cx))
        .px(px(8.))
        .border_t_1()
        .border_color(border)
        .items_center()
}

/// Emitted after the user drags a column divider: `[sidebar, list]` widths.
pub struct ColumnsResized(pub [f32; 2]);

/// The column divider being dragged; also the (empty) drag preview.
#[derive(Clone, Copy, Debug, PartialEq)]
enum ColumnDrag {
    /// Between the sidebar and the list.
    Sidebar,
    /// Between the list and the detail.
    List,
}

impl Render for ColumnDrag {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        gpui::Empty
    }
}

/// The sidebar's width state (05 §5 panel motion). There is always one: at rest it is a
/// finished slide, so the columns use the same layout, and keep the same element
/// identity, before, during and after a toggle. The sidebar's width animates between 0
/// and its column width while the list and detail reflow beside it.
#[derive(Clone, Debug)]
struct Slide {
    /// Sliding in (expanding) rather than out; at rest, whether the sidebar shows.
    showing: bool,
    /// `AppState::sidebar_toggles` when it started; keys the animation.
    key: usize,
    /// Visible fraction it starts from: 0 or 1, or wherever a reversed slide was.
    from: f32,
    started: std::time::Instant,
    /// The full motion scaled by the distance left to travel.
    duration: Duration,
    /// Set by the animation itself on its last frame (t = 1): the slide's end comes
    /// from the animation, not from a timer that could run ahead of it.
    done: Rc<Cell<bool>>,
}

impl Slide {
    fn new(showing: bool, key: usize, from: f32) -> Self {
        let to = if showing { 1. } else { 0. };
        let distance = (to - from).abs().clamp(0.05, 1.);
        Self {
            showing,
            key,
            from,
            started: std::time::Instant::now(),
            duration: ui::SIDEBAR_MOTION.mul_f32(distance),
            done: Rc::new(Cell::new(false)),
        }
    }

    /// At rest (launch, Reduce Motion): already at its end.
    fn settled(showing: bool, key: usize) -> Self {
        let slide = Self::new(showing, key, if showing { 1. } else { 0. });
        slide.done.set(true);
        slide
    }

    fn is_done(&self) -> bool {
        self.done.get()
    }

    /// Visible fraction of the sidebar at (eased) animation progress `t`.
    fn visible(&self, t: f32) -> f32 {
        let to = if self.showing { 1. } else { 0. };
        self.from + (to - self.from) * t
    }

    /// Visible fraction at `now`, so a toggle mid-slide reverses from there.
    fn current_at(&self, now: std::time::Instant) -> f32 {
        if self.is_done() {
            return self.visible(1.);
        }
        let elapsed = now.saturating_duration_since(self.started);
        let p = elapsed.as_secs_f32() / self.duration.as_secs_f32();
        self.visible(gpui::ease_out_quint()(p.min(1.)))
    }

    fn animation(&self) -> gpui::Animation {
        gpui::Animation::new(self.duration).with_easing(gpui::ease_out_quint())
    }
}

pub struct MainScreen {
    state: Entity<AppState>,
    /// Sidebar and list column widths as chosen (dragged or restored).
    widths: [f32; 2],
    /// `widths` fitted to the current window by `fit_widths`, as laid out.
    fitted: [f32; 2],
    /// A divider drag is in progress; its end saves the widths.
    column_drag: bool,
    search: Entity<InputState>,
    /// Master password for the "re-keyed on another device" prompt.
    key_input: Entity<InputState>,
    editor: Entity<Editor>,
    generator: Entity<GeneratorView>,
    list_focus: FocusHandle,
    /// Tracks focus inside the sidebar, so collapsing it can move that focus on.
    sidebar_focus: FocusHandle,
    detail_focus: FocusHandle,
    list_state: ListState,
    seen_listing: u64,
    seen_selection: Option<Uuid>,
    seen_locked: bool,
    /// Sidebar visibility the layout last applied.
    seen_sidebar: bool,
    /// The sidebar's slide; finished at rest.
    slide: Slide,
    /// Tests pin the slide clock here instead of reading real time.
    #[cfg(test)]
    slide_now: Option<std::time::Instant>,
    _ticker: Task<()>,
    _subscriptions: Vec<Subscription>,
}

impl EventEmitter<ColumnsResized> for MainScreen {}

impl MainScreen {
    pub fn new(
        state: Entity<AppState>,
        columns: Option<[f32; 2]>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let widths = columns.unwrap_or([SIDEBAR.0, LIST.0]);
        let widths = [
            widths[0].clamp(SIDEBAR.1, SIDEBAR.2),
            widths[1].clamp(LIST.1, LIST.2),
        ];
        let search = ui::text_input("Search", window, cx);
        let key_input = ui::password_input("Master password", window, cx);
        let generator = cx.new(|cx| GeneratorView::new(state.clone(), window, cx));
        let editor = cx.new(|cx| Editor::new(state.clone(), generator.clone(), window, cx));
        let list_focus = cx.focus_handle();
        let subscriptions = vec![
            cx.observe_in(&state, window, |this, _, window, cx| this.sync(window, cx)),
            cx.subscribe_in(
                &search,
                window,
                |this, input, ev: &InputEvent, window, cx| match ev {
                    InputEvent::Change => {
                        let query = ui::input_text(input, cx);
                        this.state.update(cx, |s, cx| s.set_query(query, cx));
                    }
                    InputEvent::PressEnter { .. } => window.focus(&this.list_focus, cx),
                    _ => {}
                },
            ),
            cx.subscribe_in(
                &key_input,
                window,
                |this, input, ev: &InputEvent, window, cx| {
                    if let InputEvent::PressEnter { .. } = ev {
                        sync_banners::submit_key(&this.state, input, window, cx);
                    }
                },
            ),
        ];
        Self {
            seen_locked: state.read(cx).locked,
            seen_sidebar: state.read(cx).sidebar_visible(),
            slide: Slide::settled(
                state.read(cx).sidebar_visible(),
                state.read(cx).sidebar_toggles,
            ),
            #[cfg(test)]
            slide_now: None,
            state,
            widths,
            fitted: widths,
            column_drag: false,
            search,
            key_input,
            editor,
            generator,
            list_focus,
            sidebar_focus: cx.focus_handle(),
            detail_focus: cx.focus_handle(),
            list_state: ListState::new(0, ListAlignment::Top, px(200.)),
            seen_listing: u64::MAX,
            seen_selection: None,
            _ticker: Self::ticker(cx),
            _subscriptions: subscriptions,
        }
    }

    /// Re-renders on every wall-clock second while a TOTP code is on screen.
    fn ticker(cx: &mut Context<Self>) -> Task<()> {
        cx.spawn(async move |this, cx| {
            loop {
                let to_next_second = 1000 - text::now_millis() % 1000;
                cx.background_executor()
                    .timer(Duration::from_millis(to_next_second + 5))
                    .await;
                let alive = this.update(cx, |this, cx| {
                    if detail::shows_totp(this.state.read(cx)) {
                        cx.notify();
                    }
                });
                if alive.is_err() {
                    break;
                }
            }
        })
    }

    /// Called by the root view whenever the main screen becomes visible.
    pub fn appear(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        window.focus(&self.list_focus, cx);
    }

    pub fn focus_search(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        ui::focus_input(&self.search, window, cx);
    }

    #[cfg(test)]
    pub(crate) fn search_focused(&self, window: &Window, cx: &App) -> bool {
        use gpui::Focusable as _;
        self.search.read(cx).focus_handle(cx).is_focused(window)
    }

    fn focus(&mut self, target: FocusTarget, window: &mut Window, cx: &mut Context<Self>) {
        match target {
            FocusTarget::Search => ui::focus_input(&self.search, window, cx),
            FocusTarget::List => window.focus(&self.list_focus, cx),
            FocusTarget::Detail => window.focus(&self.detail_focus, cx),
        }
    }

    /// Applies state changes that need the window: list resets, scrolling, focus.
    fn sync(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (version, selection, request, locked, rows, selected_row, clear_search) = {
            let s = self.state.read(cx);
            (
                s.listing_version,
                s.selection,
                s.focus_request,
                s.locked,
                s.listing.rows.len(),
                s.selection.and_then(|id| s.listing.row_of(id)),
                s.clear_search,
            )
        };
        self.sync_sidebar(window, cx);
        if clear_search {
            self.state.update(cx, |s, _| s.clear_search = false);
            ui::clear_input(&self.search, window, cx);
        }
        self.editor.update(cx, |e, cx| e.sync(window, cx));
        if version != self.seen_listing {
            self.seen_listing = version;
            let same_shape = self.list_state.item_count() == rows;
            let top = self.list_state.logical_scroll_top();
            self.list_state.reset(rows);
            if same_shape {
                // A favourite toggle or a re-sort must not jump the list to the top.
                self.list_state.scroll_to(top);
            }
        }
        if selection != self.seen_selection {
            self.seen_selection = selection;
            if let Some(ix) = selected_row {
                self.list_state.scroll_to_reveal_item(ix);
            }
        }
        if let Some(target) = request {
            self.state.update(cx, |s, _| s.focus_request = None);
            self.focus(target, window, cx);
        }
        if locked && !self.seen_locked {
            ui::clear_input(&self.search, window, cx);
            ui::clear_input(&self.key_input, window, cx);
        }
        self.seen_locked = locked;
        cx.notify();
    }

    /// Starts the slide when the sidebar was toggled. Focus is left alone: the focused
    /// search field, list or editor input stays rendered in both layouts.
    fn sync_sidebar(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (visible, key, reduce_motion) = {
            let s = self.state.read(cx);
            (s.sidebar_visible(), s.sidebar_toggles, s.reduce_motion)
        };
        if visible == self.seen_sidebar {
            return;
        }
        self.seen_sidebar = visible;
        // Focus inside a sidebar that is going away moves to the search field (as in
        // Finder); focus anywhere else stays exactly where it is.
        if !visible && self.sidebar_focus.contains_focused(window, cx) {
            ui::focus_input(&self.search, window, cx);
        }
        if reduce_motion {
            self.slide = Slide::settled(visible, key);
            return;
        }
        // Toggled again mid-slide: reverse from the current width, not the far end.
        let from = self.slide.current_at(self.slide_clock());
        self.slide = Slide::new(visible, key, from);
    }

    /// The time a reversed slide is measured at: real time, or the test's pinned time.
    fn slide_clock(&self) -> std::time::Instant {
        #[cfg(test)]
        if let Some(now) = self.slide_now {
            return now;
        }
        std::time::Instant::now()
    }

    /// Whether the sidebar is out of the layout (collapsed, or sliding out).
    pub(super) fn sidebar_collapsed(&self) -> bool {
        !self.seen_sidebar
    }

    /// Follows a divider drag: the dragged column's width from the pointer's x,
    /// clamped to its range and to what leaves the detail `DETAIL_MIN`.
    fn on_column_drag(
        &mut self,
        event: &DragMoveEvent<ColumnDrag>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let x = (event.event.position.x - event.bounds.left()).as_f32();
        let room = window.viewport_size().width.as_f32() - DETAIL_MIN;
        let [side, list] = self.fitted;
        self.widths = match *event.drag(cx) {
            ColumnDrag::Sidebar => [
                x.clamp(SIDEBAR.1, SIDEBAR.2)
                    .min(room - list)
                    .max(SIDEBAR.1),
                list,
            ],
            ColumnDrag::List => {
                let taken = if self.seen_sidebar { side } else { 0. };
                [
                    side,
                    (x - taken)
                        .clamp(LIST.1, LIST.2)
                        .min(room - taken)
                        .max(LIST.1),
                ]
            }
        };
        self.column_drag = true;
        cx.notify();
    }

    /// Any mouse-up that ends a divider drag, wherever it happens (over a handle, a
    /// column or outside the window), saves the widths.
    fn end_column_drag(&mut self, cx: &mut Context<Self>) {
        if std::mem::take(&mut self.column_drag) {
            cx.emit(ColumnsResized(self.widths));
        }
    }
}

/// A column divider: gpui-component's resize handle on the leading edge of the column
/// to its right (which must be `relative`).
fn column_handle(drag: ColumnDrag) -> impl IntoElement {
    gpui_component::resizable::resize_handle::<ColumnDrag, ColumnDrag>(
        ("resizable-handle", drag as usize),
        Axis::Horizontal,
    )
    .debug_selector(move || format!("column-handle {drag:?}"))
    .on_drag(drag, |drag, _, _, cx| {
        cx.stop_propagation();
        cx.new(|_| *drag)
    })
}

impl Render for MainScreen {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // Keep typography consistent when this screen is hosted independently of VaultRoot.
        let rem = crate::theme::rem_size(cx);
        if window.rem_size() != rem {
            window.set_rem_size(rem);
        }
        // Focus rings in this window (sidebar, list, detail, editor) follow keyboard focus
        // moves only; see `ui::update_focus_ring`.
        ui::update_focus_ring(window, cx);
        let slide = self.slide.clone();
        // Fit before rendering the list: its header follows the fitted sidebar width.
        // The sidebar takes room while it shows or slides.
        self.fitted = fit_widths(
            self.widths,
            window.viewport_size().width.as_f32(),
            self.seen_sidebar || !slide.is_done(),
        );
        let list = self.render_list(window, cx);
        let detail = self.render_detail(window, cx);
        // `done` is set while laying out the slide's last frame, after this render. In
        // the app a next-frame callback re-renders then; otherwise the next render does.
        let settled = slide.is_done();
        if !settled {
            let this = cx.entity().downgrade();
            window.on_next_frame(move |_, cx| {
                this.update(cx, |_, cx| cx.notify()).ok();
            });
        }

        // One layout for every state, so the list and detail columns keep their element
        // identity (and the detail's fade-in state) across a toggle. Collapsed and at
        // rest, the sidebar is not in the tree at all; the list keeps its width.
        let sidebar = (self.seen_sidebar || !settled).then(|| {
            use gpui::AnimationExt as _;
            let width = self.fitted[0];
            let done = slide.done.clone();
            let at = slide.clone();
            let at_rest = settled;
            gpui::div()
                .id("sidebar-slot")
                .flex_none()
                .h_full()
                .relative()
                .overflow_hidden()
                .when(!settled, |el| el.debug_selector(|| "sidebar-slide".into()))
                .child(
                    gpui::div()
                        .absolute()
                        .top_0()
                        .bottom_0()
                        .right_0()
                        .w(px(width))
                        .child(self.render_sidebar(cx)),
                )
                // Anchored right, so the sidebar slides rather than squeezes.
                .with_animation(
                    ("sidebar-slide", slide.key),
                    slide.animation(),
                    move |el, t| {
                        // A finished slide stays at its end: a remount (after unlock,
                        // the root's crossfade) restarts animation state at t = 0.
                        let t = if at_rest { 1. } else { t };
                        if t >= 1. {
                            done.set(true);
                        }
                        el.w(px(width * at.visible(t)))
                    },
                )
        });
        // While a divider drag runs, any mouse-up (even outside the window, which keeps
        // receiving the mouse during a drag) ends it and saves the widths.
        let drag_end = self.column_drag.then(|| {
            let this = cx.entity().downgrade();
            gpui::canvas(
                |_, _, _| {},
                move |_, _, window, _| {
                    window.on_mouse_event(move |_: &gpui::MouseUpEvent, phase, _, cx| {
                        if phase.bubble() {
                            this.update(cx, |this, cx| this.end_column_drag(cx)).ok();
                        }
                    });
                },
            )
        });
        let list_column = gpui::div()
            .id("list-slot")
            .flex_none()
            .h_full()
            .w(px(self.fitted[1]))
            .relative()
            .child(list)
            .children(ui::test_probe("list-probe"))
            // No divider to drag while the sidebar moves.
            .when(self.seen_sidebar && settled, |el| {
                el.child(column_handle(ColumnDrag::Sidebar))
            });
        let detail_column = gpui::div()
            .id("detail-slot")
            .flex_1()
            .min_w_0()
            .h_full()
            .relative()
            .child(detail)
            .children(ui::test_probe("detail-probe"))
            .child(column_handle(ColumnDrag::List));

        // The window claims its titlebar, so it moves only by this band; it paints first
        // (underneath), and the controls in it opt out with `ui::no_window_drag`.
        ui::clear_focus_ring_on_click(gpui::div())
            .size_full()
            .text_size(cx.theme().font_size)
            .relative()
            .child(ui::window_drag_band())
            .children(drag_end)
            .child(
                ui::h_flex()
                    .id("main-columns")
                    .size_full()
                    .on_drag_move(cx.listener(Self::on_column_drag))
                    .children(sidebar)
                    .child(list_column)
                    .child(detail_column),
            )
    }
}

impl MainScreen {
    /// Wraps the list's search row so its left inset follows the sidebar slide.
    pub(super) fn slide_header(&self, header: gpui::Div) -> gpui::AnyElement {
        use gpui::AnimationExt as _;
        let slide = self.slide.clone();
        let width = self.fitted[0];
        // Finished: the end inset from the first frame, also after a remount.
        let at_rest = slide.is_done();
        header
            .with_animation(
                ("list-header-slide", slide.key),
                slide.animation(),
                move |el, t| {
                    let t = if at_rest { 1. } else { t };
                    el.pl(px(ui::list_header_pad_left(width * slide.visible(t))))
                },
            )
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    //! Headless render tests: build the real main screen in a gpui test window and
    //! drive it through the keymap, checking it renders without panicking.

    use std::sync::Arc;

    use gpui::{Entity, Pixels, TestAppContext, VisualTestContext, size};
    use gpui_component::Root;
    use vault_core::{ExposeSecret as _, Field, FieldKind, Item, KdfParams, SecretString};
    use vault_sync::{NoopHooks, SyncedVault};

    use super::*;
    use crate::actions;
    use crate::state::{Filter, GeneratorTarget};

    pub(super) const PW: &str = "pw";

    fn field(name: &str, kind: FieldKind, value: &str) -> Field {
        Field::new(name, kind, SecretString::new(value.into()), 1)
    }

    /// A vault on disk with one item of each rendering path, or none.
    fn vault(dir: &std::path::Path, populated: bool) -> SyncedVault {
        let mut v = SyncedVault::create(
            &dir.join("t.vault"),
            &SecretString::new(PW.into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        if populated {
            let device = v.device_id();
            v.edit(|v| {
                let mut gh = Item::new("GitHub", device, 1);
                gh.tags = vec!["infra".into()];
                gh.fields = vec![
                    field("username", FieldKind::Text, "chris"),
                    field("password", FieldKind::Password, "old"),
                    field(
                        "totp",
                        FieldKind::Totp,
                        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
                    ),
                    field("website", FieldKind::Url, "github.com"),
                    field("notes", FieldKind::Notes, "line one\nline two"),
                ];
                let id = v.insert(gh, 1);
                v.set_field(id, "password", SecretString::new("new".into()), 2)
                    .unwrap();
                let mut card =
                    crate::templates::tagged(crate::templates::Template::Card, "Visa", device, 3);
                card.fields = vec![
                    field("number", FieldKind::Text, "4242424242424242"),
                    field("expiry", FieldKind::MonthYear, "12/29"),
                ];
                v.insert(card, 3);
                v.insert(Item::new("", device, 4), 4);
            })
            .unwrap();
        }
        v.save().unwrap();
        v
    }

    pub(super) fn open(
        populated: bool,
        dir: &std::path::Path,
        cx: &mut TestAppContext,
    ) -> (Entity<AppState>, Entity<MainScreen>, VisualTestContext) {
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        let path = vault(dir, populated).path().to_owned();
        cx.update(|cx| {
            gpui_component::init(cx);
            actions::bind_keys(cx);
            actions::register(&state, cx);
        });
        state.update(cx, |s, cx| s.open_vault(path, cx));
        cx.run_until_parked();
        state.update(cx, |s, cx| s.unlock(SecretString::new(PW.into()), cx));
        cx.run_until_parked();

        let mut main = None;
        let window = cx.add_window(|window, cx| {
            crate::theme::apply(window, cx);
            let view = cx.new(|cx| MainScreen::new(state.clone(), None, window, cx));
            main = Some(view.clone());
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        let main = main.unwrap();
        vcx.update(|window, cx| {
            main.update(cx, |m, cx| {
                m.sync(window, cx);
                m.appear(window, cx);
            })
        });
        vcx.run_until_parked();
        (state, main, vcx)
    }

    #[gpui::test]
    fn double_click_opens_pinned_detail_window_that_closes_on_lock(cx: &mut TestAppContext) {
        use gpui::{Modifiers, MouseButton, MouseDownEvent, MouseUpEvent};

        let dir = tempfile::tempdir().unwrap();
        let (state, main, mut vcx) = open(true, dir.path(), cx);
        let board = crate::clipboard::fake::FakePasteboard::default();
        state.update(&mut vcx, |s, _| s.set_pasteboard(Box::new(board.clone())));
        let main_window = vcx.cx.update(|cx| cx.windows()[0]);
        // A–Z rows: # header, untitled item, G header, GitHub item.
        main.read_with(&vcx, |m, _| m.list_state.scroll_to_reveal_item(3));
        vcx.run_until_parked();
        let row = main.read_with(&vcx, |m, _| m.list_state.bounds_for_item(3).unwrap());
        let at = row.center();
        vcx.simulate_click(at, Modifiers::default());
        assert_eq!(vcx.cx.update(|cx| cx.windows().len()), 1);
        vcx.simulate_event(MouseDownEvent {
            position: at,
            button: MouseButton::Left,
            modifiers: Modifiers::default(),
            click_count: 2,
            first_mouse: false,
        });
        vcx.simulate_event(MouseUpEvent {
            position: at,
            button: MouseButton::Left,
            modifiers: Modifiers::default(),
            click_count: 2,
        });
        assert_eq!(
            state.read_with(&vcx, |s, _| s.selected_item().map(|i| i.title.clone())),
            Some("GitHub".into())
        );
        let detail_window = vcx
            .cx
            .update(|cx| cx.windows())
            .into_iter()
            .find(|window| window.window_id() != main_window.window_id())
            .expect("second window");
        let mut detail = VisualTestContext::from_window(detail_window, &vcx.cx);
        detail.run_until_parked();
        assert_eq!(
            detail.window_title().as_deref(),
            Some("GitHub"),
            "the item's name"
        );
        assert!(detail.debug_bounds("detail-title GitHub").is_some());
        for selector in [
            "detail-header",
            "field-row 1",
            "field-row 4",
            "detail-footer",
        ] {
            assert_eq!(
                detail.debug_bounds(selector).unwrap().size.height,
                vcx.debug_bounds(selector).unwrap().size.height,
                "same detail layout for {selector}"
            );
        }

        let visa = state.read_with(&vcx, |s, _| {
            s.listing
                .items
                .iter()
                .copied()
                .find(|id| s.unlocked_vault().unwrap().get(*id).unwrap().title == "Visa")
                .unwrap()
        });
        state.update(&mut vcx, |s, cx| s.select(visa, cx));
        detail.run_until_parked();
        assert_eq!(
            detail.window_title().as_deref(),
            Some("GitHub"),
            "pinned: the main window's selection does not retitle it"
        );
        assert!(detail.debug_bounds("detail-title GitHub").is_some());

        // Value clicks copy from the pinned item, even with Visa selected in the main window.
        let username = detail.debug_bounds("field-value 0").unwrap().center();
        detail.simulate_click(username, Modifiers::default());
        assert_eq!(board.contents().as_deref(), Some("chris"));
        let password = detail.debug_bounds("field-value 1").unwrap().center();
        detail.simulate_click(password, Modifiers::default());
        assert_eq!(board.contents().as_deref(), Some("new"));
        assert!(detail.debug_bounds("field-masked 1").is_some());
        for key in ["enter", "space"] {
            board.set("another value");
            detail.simulate_keystrokes(key);
            detail.simulate_event(gpui::KeyUpEvent {
                keystroke: gpui::Keystroke::parse(key).unwrap(),
            });
            assert_eq!(board.contents().as_deref(), Some("new"));
        }
        let totp = detail.debug_bounds("field-value 2").unwrap().center();
        detail.simulate_click(totp, Modifiers::default());
        let code = board.contents().unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
        assert!(detail.debug_bounds("detail-copy-feedback").is_some());
        assert!(
            state.read_with(&vcx, |s, _| s.toast.is_none()),
            "copy feedback stays in the item window"
        );
        detail.executor().advance_clock(Duration::from_secs(3));
        detail.run_until_parked();
        assert!(detail.debug_bounds("detail-copy-feedback").is_none());

        let history = detail.debug_bounds("history-toggle").unwrap().center();
        detail.simulate_click(history, Modifiers::default());
        let old_password = detail.debug_bounds("history-copy 0").unwrap().center();
        detail.simulate_click(old_password, Modifiers::default());
        assert_eq!(board.contents().as_deref(), Some("old"));
        assert!(!state.read_with(&vcx, |s, _| s.history_open));

        state.update(&mut vcx, |s, cx| s.lock(cx));
        vcx.run_until_parked();
        assert_eq!(vcx.cx.update(|cx| cx.windows().len()), 1);
    }

    #[gpui::test]
    fn keyboard_drives_the_populated_screen(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(true, dir.path(), cx);
        let first = state.read_with(&vcx, |s, _| {
            assert_eq!(s.listing.items.len(), 3);
            s.selection
        });
        assert!(first.is_some());

        // ↓ in the focused list moves the selection; ↑ moves it back.
        vcx.simulate_keystrokes("down");
        let second = state.read_with(&vcx, |s, _| s.selection);
        assert_ne!(first, second);
        vcx.simulate_keystrokes("up");
        assert_eq!(state.read_with(&vcx, |s, _| s.selection), first);

        // Select GitHub (A–Z: "#" untitled, GitHub, Visa), reveal, favourite, history.
        vcx.simulate_keystrokes("down");
        state.read_with(&vcx, |s, _| {
            assert_eq!(s.selected_item().unwrap().title, "GitHub");
        });
        vcx.simulate_keystrokes("cmd-shift-r cmd-d");
        state.update(&mut vcx, |s, cx| s.toggle_history(cx));
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert!(s.revealed.contains("password"));
            assert!(s.selected_item().unwrap().favorite);
            assert_eq!(s.counts.favorites, 1);
        });

        // ⌘F then typing filters the list.
        vcx.simulate_keystrokes("cmd-f");
        vcx.simulate_input("visa");
        state.read_with(&vcx, |s, _| {
            assert_eq!(s.query, "visa");
            assert_eq!(s.listing.items.len(), 1);
        });
        vcx.simulate_input("zzz");
        state.read_with(&vcx, |s, _| assert!(s.listing.items.is_empty()));

        // Sidebar toggle, filters, resizing to the minimum.
        vcx.simulate_keystrokes("ctrl-cmd-s");
        assert!(!state.read_with(&vcx, |s, _| s.sidebar_visible()));
        vcx.simulate_resize(size(px(820.), px(520.)));
        vcx.simulate_keystrokes("ctrl-cmd-s");
        state.update(&mut vcx, |s, cx| {
            s.set_query(String::new(), cx);
            s.set_filter(Filter::Tag("INFRA".into()), cx);
        });
        vcx.run_until_parked();
        assert_eq!(state.read_with(&vcx, |s, _| s.listing.items.len()), 1);

        // Lock with a selection, then rapid unlock/lock cycles.
        vcx.simulate_keystrokes("cmd-l");
        state.read_with(&vcx, |s, _| {
            assert!(s.locked);
            assert!(s.selection.is_none());
        });
        for _ in 0..3 {
            // A lock issued mid-unlock wins; a clean unlock then succeeds.
            state.update(&mut vcx, |s, cx| {
                s.unlock(SecretString::new(PW.into()), cx);
                s.lock(cx);
            });
            vcx.run_until_parked();
            assert!(state.read_with(&vcx, |s, _| s.locked));
            state.update(&mut vcx, |s, cx| s.unlock(SecretString::new(PW.into()), cx));
            vcx.run_until_parked();
            assert!(!state.read_with(&vcx, |s, _| s.locked));
        }
        vcx.simulate_keystrokes("down cmd-shift-c cmd-l");
        assert!(state.read_with(&vcx, |s, _| s.locked));
    }

    /// The y (window pixels) of the painted top divider of the element at `area`. gpui
    /// paints a border as one quad per edge, each clipped by its content mask, so the
    /// divider is the quad covering `area` whose mask is a thin strip at its top.
    fn top_divider_y(area: gpui::Bounds<Pixels>, vcx: &mut VisualTestContext) -> Option<Pixels> {
        vcx.update(|window, _| {
            let sf = window.scale_factor();
            let scaled = area.scale(sf);
            let near = |a: gpui::ScaledPixels, b: gpui::ScaledPixels| (a.0 - b.0).abs() < 0.5;
            window
                .painted_quads()
                .iter()
                .find(|q| {
                    let mask = q.content_mask.bounds;
                    near(q.bounds.origin.y, scaled.origin.y)
                        && near(q.bounds.origin.x, scaled.origin.x)
                        && near(q.bounds.size.width, scaled.size.width)
                        && near(q.bounds.size.height, scaled.size.height)
                        && q.border_widths.top.0 > 0.
                        && near(mask.origin.y, q.bounds.origin.y)
                        && mask.size.height.0 <= q.border_widths.top.0 + 1.
                })
                .map(|q| px(q.bounds.origin.y.0 / sf))
        })
    }

    /// Window drags started by pressing at `at` and moving 6 px with the button held.
    fn drags_from(at: gpui::Point<Pixels>, vcx: &mut VisualTestContext) -> usize {
        use gpui::{Modifiers, MouseButton, point};
        let before = ui::window_moves();
        let to = at + point(px(6.), px(0.));
        vcx.simulate_mouse_down(at, MouseButton::Left, Modifiers::default());
        vcx.simulate_mouse_move(to, MouseButton::Left, Modifiers::default());
        vcx.simulate_mouse_up(to, MouseButton::Left, Modifiers::default());
        vcx.run_until_parked();
        ui::window_moves() - before
    }

    #[gpui::test]
    fn title_band_moves_the_window_only_from_empty_space(cx: &mut TestAppContext) {
        use gpui::point;
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(true, dir.path(), cx);
        assert!(state.read_with(&vcx, |s, _| s.selection.is_some()));
        let bounds = |key: &'static str, vcx: &mut VisualTestContext| {
            vcx.debug_bounds(key)
                .unwrap_or_else(|| panic!("{key} not rendered"))
        };
        let band = bounds("window-drag-band", &mut vcx);
        let search = bounds("list-search", &mut vcx);
        let toggle = bounds("sidebar-toggle Hide Sidebar", &mut vcx);
        let header = bounds("detail-header", &mut vcx);
        let buttons = bounds("detail-header-buttons", &mut vcx);
        // The controls really sit in the band; otherwise this test proves nothing.
        assert!(band.contains(&search.center()));
        assert!(band.contains(&buttons.center()));

        // Controls in the band never move the window, and the search field still
        // takes focus and text.
        assert_eq!(drags_from(search.center(), &mut vcx), 0, "search field");
        vcx.simulate_input("visa");
        assert_eq!(state.read_with(&vcx, |s, _| s.query.clone()), "visa");
        assert_eq!(drags_from(buttons.center(), &mut vcx), 0, "header buttons");

        // Empty parts of the band do: above the sidebar, the list row's left padding,
        // and the detail header's avatar.
        assert_eq!(
            drags_from(point(px(120.), px(20.)), &mut vcx),
            1,
            "sidebar band"
        );
        let pad = point(toggle.left() - px(ui::COLUMN_PAD_X / 2.), search.center().y);
        assert_eq!(drags_from(pad, &mut vcx), 1, "list padding");
        let avatar = point(header.left() + px(20.), header.top() + px(20.));
        assert!(band.contains(&avatar));
        assert_eq!(drags_from(avatar, &mut vcx), 1, "detail avatar");

        // A press without movement is a plain click, not a drag.
        let before = ui::window_moves();
        vcx.simulate_click(pad, gpui::Modifiers::default());
        assert_eq!(ui::window_moves(), before);

        // The sidebar toggle is a control too (pressing it toggles, never drags).
        assert!(band.contains(&toggle.center()));
        assert_eq!(drags_from(toggle.center(), &mut vcx), 0, "sidebar toggle");
    }

    #[gpui::test]
    fn columns_share_the_top_band_and_footer_grid(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(true, dir.path(), cx);
        assert!(state.read_with(&vcx, |s, _| s.selection.is_some()));
        let bounds = |key: &'static str, vcx: &mut VisualTestContext| {
            vcx.debug_bounds(key)
                .unwrap_or_else(|| panic!("{key} not rendered"))
        };
        let near = |a: Pixels, b: Pixels| (a.as_f32() - b.as_f32()).abs() < 0.5;

        // Search field inside the title-bar band, centred on the traffic lights, and the
        // detail header's top level with it.
        let search = bounds("list-search", &mut vcx);
        let header = bounds("detail-header", &mut vcx);
        assert_eq!(search.top(), px(ui::SEARCH_TOP));
        assert!(search.bottom() <= px(ui::TOP_BAND_HEIGHT));
        assert!(near(search.center().y, px(ui::TOP_BAND_HEIGHT / 2.)));
        assert_eq!(header.top(), search.top());

        // Same left inset in the list (its first control, the sidebar toggle) and the
        // detail column.
        let list_x = bounds("list-footer", &mut vcx).left();
        let toggle = bounds("sidebar-toggle Hide Sidebar", &mut vcx);
        assert_eq!(toggle.left() - list_x, px(ui::COLUMN_PAD_X));
        assert!(near(toggle.center().y, search.center().y));
        let detail_x = bounds("detail-column", &mut vcx).left();
        assert_eq!(header.left() - detail_x, px(ui::COLUMN_PAD_X));

        // The list footer (the only bottom bar): fixed height, a top divider, and
        // "+ New" and the count centred alike; no Lock button. The sidebar runs to the
        // bottom.
        let list = bounds("list-footer", &mut vcx);
        assert_eq!(list.size.height, px(ui::FOOTER_HEIGHT));
        let divider = top_divider_y(list, &mut vcx).expect("list footer divider");
        assert_eq!(divider, list.top());
        assert!(vcx.debug_bounds("sidebar-footer").is_none());
        let sidebar = bounds("sidebar-column", &mut vcx);
        assert!(sidebar.bottom() > list.bottom() - px(1.));
        // Content centres sit half a divider below the box centre (1 px top border).
        let centre = list.top() + px(0.5) + list.size.height / 2.;
        assert!(vcx.debug_bounds("list-lock").is_none());
        for key in ["new-item", "list-footer-count"] {
            assert!(near(bounds(key, &mut vcx).center().y, centre), "{key}");
        }
    }

    #[gpui::test]
    fn editor_and_sync_banner_share_the_detail_left_edge(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(true, dir.path(), cx);
        let edge = |key: &'static str, vcx: &mut VisualTestContext| {
            vcx.debug_bounds(key)
                .unwrap_or_else(|| panic!("{key} not rendered"))
                .left()
        };
        let column = edge("detail-column", &mut vcx);
        let read = edge("detail-header", &mut vcx);
        assert_eq!(read - column, px(ui::COLUMN_PAD_X));

        // Edit mode: the editor header starts where the read header did.
        state.update(&mut vcx, |s, cx| s.begin_edit(cx));
        vcx.run_until_parked();
        assert_eq!(edge("editor-header", &mut vcx), read);

        // A sync banner above the editor sits on the same edge.
        state.update(&mut vcx, |s, cx| {
            s.sync.waiting_for_cloud = true;
            cx.notify();
        });
        vcx.run_until_parked();
        assert_eq!(edge("banner-cloud", &mut vcx), read);
        assert_eq!(edge("editor-header", &mut vcx), read);
    }

    #[gpui::test]
    fn empty_vault_renders(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(false, dir.path(), cx);
        // Every action on an empty vault is a harmless no-op.
        vcx.simulate_keystrokes("down up enter cmd-d cmd-shift-c cmd-shift-t cmd-shift-r");
        vcx.simulate_keystrokes("cmd-1 cmd-2 cmd-e cmd-backspace cmd-s cmd-n");
        state.read_with(&vcx, |s, _| {
            assert!(s.selection.is_none());
            assert_eq!(s.counts.all, 0);
            assert!(!s.is_editing());
            assert!(s.delete_confirm.is_none());
            assert_eq!(
                s.template_picker.as_deref(),
                Some(""),
                "⌘N opens the kind picker"
            );
        });
        // Pick Login, name it, save: the first item exists and is selected.
        state.update(&mut vcx, |s, cx| {
            s.begin_new(crate::templates::Template::Login, String::new(), cx)
        });
        vcx.run_until_parked();
        vcx.simulate_input("Hetzner");
        vcx.simulate_keystrokes("cmd-s");
        state.read_with(&vcx, |s, _| {
            assert!(!s.is_editing());
            assert_eq!(s.counts.all, 1);
            let item = s.selected_item().expect("new item selected");
            assert_eq!(item.title, "Hetzner");
            assert_eq!(item.fields.len(), 4);
        });
        // Delete it again: back to the empty state without a selection.
        vcx.simulate_keystrokes("cmd-1 cmd-backspace");
        state.update(&mut vcx, |s, cx| s.confirm_delete(cx));
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert_eq!(s.counts.all, 0);
            assert!(s.selection.is_none());
        });
    }

    #[gpui::test]
    fn edit_new_delete_and_generator_flows(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(true, dir.path(), cx);
        vcx.simulate_keystrokes("down");
        let gh = state.read_with(&vcx, |s, _| s.selection.unwrap());

        // ⌘E focuses the title; typing edits the buffer; ⌘S saves.
        vcx.simulate_keystrokes("cmd-e");
        assert!(state.read_with(&vcx, |s, _| s.is_editing()));
        vcx.simulate_input(" Enterprise");
        vcx.simulate_keystrokes("cmd-s");
        state.read_with(&vcx, |s, _| {
            assert!(!s.is_editing());
            assert!(s.selected_item().unwrap().title.contains("Enterprise"));
            assert!(s.vault.as_ref().unwrap().is_dirty());
        });

        // Generator "Use" fills the password row; its input is updated; save keeps history.
        vcx.simulate_keystrokes("cmd-e");
        let key = state.read_with(&vcx, |s, _| {
            let b = s.edit_buffer().unwrap();
            b.keys[b
                .item
                .fields
                .iter()
                .position(|f| f.kind == FieldKind::Password)
                .unwrap()]
        });
        state.update(&mut vcx, |s, cx| {
            s.open_generator(GeneratorTarget::Field(key), cx)
        });
        vcx.run_until_parked();
        let generated = state.read_with(&vcx, |s, _| {
            s.generator.preview().expose_secret().to_owned()
        });
        state.update(&mut vcx, |s, cx| s.use_generated(cx));
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert!(s.generator_target.is_none());
            assert!(
                s.edit_buffer().unwrap().pushed.is_empty(),
                "applied to the input"
            );
        });
        vcx.simulate_keystrokes("cmd-s");
        state.read_with(&vcx, |s, _| {
            let item = s.selected_item().unwrap();
            let pw = item.field("password").unwrap();
            assert_eq!(pw.value.expose_secret(), &generated);
            assert_eq!(item.history.len(), 2);
        });

        // Remove every field and save: no panic, item has no fields.
        vcx.simulate_keystrokes("cmd-e");
        state.update(&mut vcx, |s, cx| {
            let keys = s.edit_buffer().unwrap().keys.clone();
            s.edit(cx, |b| keys.iter().for_each(|k| b.remove_field(*k)));
        });
        vcx.run_until_parked();
        vcx.simulate_keystrokes("cmd-s");
        assert!(state.read_with(&vcx, |s, _| s.selected_item().unwrap().fields.is_empty()));

        // ⌘N + Esc mid-new cancels; an empty title is rejected inline.
        state.update(&mut vcx, |s, cx| {
            s.begin_new(crate::templates::Template::Note, String::new(), cx)
        });
        vcx.run_until_parked();
        vcx.simulate_keystrokes("cmd-s");
        state.read_with(&vcx, |s, _| {
            let b = s.edit_buffer().expect("still editing");
            assert_eq!(b.error.as_deref(), Some("Title required"));
        });
        vcx.simulate_keystrokes("escape");
        state.read_with(&vcx, |s, _| {
            assert!(!s.is_editing());
            assert_eq!(s.counts.all, 3);
        });

        // Unsaved changes + navigation shows the prompt; Esc keeps editing.
        vcx.simulate_keystrokes("cmd-e");
        vcx.simulate_input("x");
        state.update(&mut vcx, |s, cx| s.select_offset(1, cx));
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert!(s.discard_prompt.is_some());
            assert_eq!(s.selection, Some(gh));
        });
        vcx.simulate_keystrokes("escape");
        state.read_with(&vcx, |s, _| {
            assert!(s.discard_prompt.is_none());
            assert!(s.is_editing());
        });
        // Lock mid-edit always wins and discards the buffer.
        vcx.simulate_keystrokes("cmd-l");
        state.read_with(&vcx, |s, _| {
            assert!(s.locked);
            assert!(!s.is_editing());
        });
        state.update(&mut vcx, |s, cx| s.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();

        // ⌘G opens the global generator; Esc inside the popover closes it.
        vcx.simulate_keystrokes("cmd-g");
        assert_eq!(
            state.read_with(&vcx, |s, _| s.generator_target),
            Some(GeneratorTarget::Global)
        );
        vcx.simulate_keystrokes("escape");
        assert!(state.read_with(&vcx, |s, _| s.generator_target.is_none()));

        // ⌘⌫ asks first; Delete tombstones and moves the selection.
        vcx.simulate_keystrokes("cmd-1 cmd-backspace");
        let doomed = state.read_with(&vcx, |s, _| {
            assert_eq!(s.delete_confirm, s.selection);
            s.selection.unwrap()
        });
        state.update(&mut vcx, |s, cx| s.confirm_delete(cx));
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert_eq!(s.counts.all, 2);
            assert!(s.selection.is_some_and(|id| id != doomed));
        });
    }
}
