//! Item icon tile, the edit-mode icon picker (specs/05-ui.md §2.3) and the field icon
//! picker (05 "Field icons"), which share the symbol grid. What to show is decided by
//! `crate::icon`; this module only draws it.

use std::rc::Rc;
use std::sync::Arc;

use gpui::{
    Anchor, AnyElement, App, Entity, ExternalPaths, FocusHandle, FontWeight,
    InteractiveElement as _, IntoElement, KeyBinding, ParentElement as _, RenderImage,
    ScrollHandle, SharedString, StatefulInteractiveElement as _, Styled as _, actions, div, img,
    prelude::FluentBuilder, px, rgb,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{Input, InputState, MoveDown, MoveLeft, MoveRight, MoveUp};
use gpui_component::spinner::Spinner;
use gpui_component::{ActiveTheme as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{Item, Uuid};

use crate::icon::{self, GRID_COLS, IconSpec, Move, PALETTE, PALETTE_NAMES, PickerCell, SYMBOLS};
use crate::state::AppState;
use crate::ui::{self, Clickable as _};

/// Key context of the open picker (arrows, Enter). Nested inside gpui-component's
/// `PopoverContent`, so these bindings win over its `enter` → `NoAction`.
pub const PICKER_CONTEXT: &str = "IconPicker";

actions!(
    icon_picker,
    [
        /// ↑ in the icon picker.
        PickerUp,
        /// ↓ in the icon picker.
        PickerDown,
        /// ← in the icon picker.
        PickerLeft,
        /// → in the icon picker.
        PickerRight,
        /// ⏎ in the icon picker: choose the cell under the cursor.
        PickerChoose,
        /// ⎋ in the icon picker: close it and return focus to the title field.
        PickerClose,
    ]
);

pub fn bind_keys(cx: &mut App) {
    let ctx = Some(PICKER_CONTEXT);
    cx.bind_keys([
        KeyBinding::new("up", PickerUp, ctx),
        KeyBinding::new("down", PickerDown, ctx),
        KeyBinding::new("left", PickerLeft, ctx),
        KeyBinding::new("right", PickerRight, ctx),
        KeyBinding::new("enter", PickerChoose, ctx),
        // Not while the search field has the focus: there Space types.
        KeyBinding::new("space", PickerChoose, Some("IconPicker && !Input")),
        KeyBinding::new("escape", PickerClose, ctx),
    ]);
}

/// The tile of `item` at `size` px. A custom image comes from `images` (the app state's
/// decoded icons) when it is ready; otherwise, and when `images` is `None` (the backup
/// viewer, whose backups hold no blobs), the automatic icon is drawn instead.
pub fn item_tile(item: &Item, images: Option<&AppState>, size: f32, cx: &App) -> gpui::Div {
    match icon::resolve(item) {
        IconSpec::Image { attachment } => match images.and_then(|s| s.icon_image(attachment)) {
            Some(image) => image_tile(attachment, image, size),
            None => icon_tile(&icon::automatic(item), size, cx),
        },
        spec => icon_tile(&spec, size, cx),
    }
}

/// A decoded custom image in the tile's rounded mask. Tests find it as
/// `icon-tile image <attachment id>`.
fn image_tile(attachment: Uuid, image: Arc<RenderImage>, size: f32) -> gpui::Div {
    let radius = px(size / 4.);
    div()
        .debug_selector(move || format!("icon-tile image {attachment}"))
        .flex_shrink_0()
        .size(px(size))
        .rounded(radius)
        .child(img(image).size(px(size)).rounded(radius))
}

/// The rounded tile for `spec` at `size` px: list rows (32), detail header (44), backup
/// viewer (28/40) and the picker. A filled tile with a white glyph in both appearances
/// (the palette colours all read with white). Tests find it as
/// `icon-tile <spec> fill white`.
pub fn icon_tile(spec: &IconSpec, size: f32, cx: &App) -> gpui::Div {
    let theme = cx.theme();
    let color = match spec {
        IconSpec::Letter { color, .. }
        | IconSpec::Symbol { color, .. }
        | IconSpec::Unsupported { color, .. } => Some(*color),
        // Only reached without the item at hand (see `item_tile`): a neutral tile.
        IconSpec::Image { .. } => None,
    };
    let selector = match color {
        Some(_) => format!("icon-tile {} fill white", spec.describe()),
        None => format!("icon-tile {} surface", spec.describe()),
    };
    let tile = div()
        .debug_selector(move || selector.clone())
        .flex_shrink_0()
        .size(px(size))
        .rounded(px(size / 4.))
        .map(|d| match color {
            Some(c) => d.bg(rgb(c)),
            // The neutral tile keeps a hairline so it does not melt into the row.
            None => d.bg(theme.secondary).border_1().border_color(theme.border),
        })
        .flex()
        .items_center()
        .justify_center()
        .text_color(gpui::white());
    match spec {
        IconSpec::Letter { letter, .. } | IconSpec::Unsupported { letter, .. } => tile
            .font_weight(FontWeight::SEMIBOLD)
            .when(size > 36., |d| d.text_lg())
            .when(size < 26., |d| d.text_xs())
            .child(letter.clone()),
        IconSpec::Symbol { name, .. } => tile.child(
            Icon::new(*name)
                .size(px((size * 0.56).round()))
                .text_color(gpui::white()),
        ),
        IconSpec::Image { .. } => tile.child(
            Icon::new(IconName::Image)
                .size(px((size * 0.56).round()))
                .text_color(theme.muted_foreground),
        ),
    }
}

/// Side of a symbol cell and gap between cells in the picker.
const CELL: f32 = 30.;
const CELL_GAP: f32 = 4.;
const SWATCH: f32 = 22.;
/// Height of the picker's grid box: the 40 symbols exactly; search results scroll in it.
const GRID_H: f32 = SYMBOLS.len().div_ceil(GRID_COLS) as f32 * (CELL + CELL_GAP) - CELL_GAP;

/// The edit-mode tile in the editor header: a button that opens the picker, and a drop
/// target for an image file. `title` gets the focus back when Esc closes the picker.
pub fn picker_trigger(
    state: &Entity<AppState>,
    focus: &FocusHandle,
    search: &Entity<InputState>,
    scroll: &ScrollHandle,
    title: &FocusHandle,
    size: f32,
    cx: &App,
) -> AnyElement {
    let s = state.read(cx);
    let Some(buffer) = s.edit_buffer() else {
        return div().into_any_element();
    };
    let spec = icon::resolve(&buffer.item);
    let open = buffer.icon_picker.is_some();
    let droppable = s.can_choose_icon_image();
    let trigger = Button::new("edit-icon")
        .debug_selector(|| "edit-icon".into())
        .ghost()
        .p_0()
        .w(px(size))
        .h(px(size))
        .child(item_tile(&buffer.item, Some(s), size, cx))
        .tooltip("Change icon")
        .accessibility_label(format!("Icon: {}. Change icon", spec.label()))
        .clickable();
    let (toggle_state, content_state, content_focus, title) =
        (state.clone(), state.clone(), focus.clone(), title.clone());
    let (toggle_search, content_search, scroll) = (search.clone(), search.clone(), scroll.clone());
    let popover = ui::popover(
        "edit-icon-picker",
        trigger,
        Anchor::TopLeft,
        open,
        move |open, window, cx| {
            // The query is not kept between openings.
            ui::clear_input(&toggle_search, window, cx);
            toggle_state.update(cx, |s, cx| s.set_icon_picker(open, cx))
        },
        move |_, cx| {
            let handles = (&content_focus, &content_search, &scroll, &title);
            picker(&content_state, handles, cx)
        },
    )
    // Opening focuses the search field (05 "Icon search").
    .track_focus(&gpui::Focusable::focus_handle(search, cx));
    icon_drop_target(
        div()
            .debug_selector(|| "edit-icon-drop".into())
            .rounded(px(size / 4.)),
        state,
        droppable,
        cx,
    )
    .child(popover)
    .into_any_element()
}

/// Makes `el` take an image file dropped from Finder as the icon: the edit tile and the
/// picker's "Drop or choose image…" row share it, so both run `set_icon_image_file` (the same
/// 512 KB / 8192 px / PNG-or-JPEG checks and toasts). The drop is always taken here, so
/// the detail column's handler (which adds ordinary attachments) never sees it; while
/// `enabled` is false there is no highlight and `set_icon_image_file` refuses it just as
/// it refuses a click (silently for a new item, "Wait…" while a task runs).
fn icon_drop_target<E: gpui::InteractiveElement + gpui::Styled + FluentBuilder>(
    el: E,
    state: &Entity<AppState>,
    enabled: bool,
    cx: &App,
) -> E {
    let (state, tint) = (state.clone(), cx.theme().primary.opacity(0.18));
    el.when(enabled, |d| {
        d.drag_over::<ExternalPaths>(move |style, _, _, _| style.bg(tint))
    })
    .on_drop(move |paths: &ExternalPaths, _, cx| {
        if let Some(path) = paths.paths().first().cloned() {
            state.update(cx, |s, cx| s.set_icon_image_file(path, cx));
        }
    })
}

/// Popover body: Automatic, the search field, the symbol grid (or the search results), the
/// colour swatches and "Drop or choose image…".
fn picker(
    state: &Entity<AppState>,
    (focus, search, scroll, title): (
        &FocusHandle,
        &Entity<InputState>,
        &ScrollHandle,
        &FocusHandle,
    ),
    cx: &App,
) -> AnyElement {
    let s = state.read(cx);
    let Some(buffer) = s.edit_buffer() else {
        return div().into_any_element();
    };
    let theme = cx.theme();
    let cursor = buffer.icon_picker.map(|c| c.cell());
    // Shape and colour are independent (see `icon::Shape`): the Automatic row is
    // selected whenever no symbol (or image) is, and the colour row always shows the
    // effective colour, the item's own palette colour being marked as the default.
    let shape = icon::shape(buffer.item.icon.as_ref());
    let auto_selected = shape == icon::Shape::Automatic;
    let chosen_symbol = match shape {
        icon::Shape::Symbol(name) => Some(name),
        _ => None,
    };
    let chosen_color = Some(icon::effective_color(&buffer.item));
    let default_color = icon::palette_color(&buffer.item);
    let auto = icon::automatic_preview(&buffer.item);
    let ring = theme.ring;

    let choose = |cell: PickerCell| {
        let state = state.clone();
        move |_: &gpui::ClickEvent, _: &mut gpui::Window, cx: &mut App| {
            state.update(cx, |s, cx| s.choose_icon(cell, cx))
        }
    };
    // Keyboard cursor: an accent ring; the current choice: a tinted fill.
    let cursor_ring = move |d: gpui::Stateful<gpui::Div>, cell: PickerCell| {
        d.border_2().border_color(if cursor == Some(cell) {
            ring
        } else {
            gpui::transparent_black()
        })
    };

    let automatic = ui::h_flex()
        .id("icon-auto")
        .debug_selector(|| "icon-picker-automatic".into())
        .aria_label(SharedString::from(format!("Automatic: {}", auto.label())))
        .gap(px(8.))
        .px(px(6.))
        .py(px(4.))
        .rounded(theme.radius)
        .clickable()
        .hover(|d| d.bg(theme.accent))
        .when(auto_selected, |d| d.bg(theme.primary.opacity(0.12)))
        .map(|d| cursor_ring(d, PickerCell::Automatic))
        .on_click(choose(PickerCell::Automatic))
        // What Automatic means right now, in the effective colour (updates live).
        .child({
            let preview = format!("icon-auto-preview {}", auto.describe());
            div()
                .debug_selector(move || preview.clone())
                .child(icon_tile(&auto, 24., cx))
        })
        .child(
            ui::v_flex()
                .flex_1()
                .min_w_0()
                .child(div().text_sm().child("Automatic"))
                .child(ui::muted(auto.label(), cx).text_xs().truncate()),
        )
        .when(auto_selected, |d| {
            d.child(
                div().debug_selector(|| "icon-auto-selected".into()).child(
                    Icon::new(IconName::Check)
                        .size_4()
                        .text_color(theme.primary),
                ),
            )
        });

    let grid = search_grid(
        state,
        (search, scroll),
        GridKind {
            prefix: "icon-symbol",
            hit_prefix: "icon-hit",
        },
        chosen_symbol,
        match cursor {
            Some(PickerCell::Symbol(ix)) => Some(ix),
            _ => None,
        },
        {
            let state = state.clone();
            move |cell, _, cx| state.update(cx, |s, cx| s.choose_icon(cell, cx))
        },
        cx,
    );
    let searching = s.icon_search.active();

    let swatches = ui::h_flex()
        .gap(px(CELL_GAP + (CELL - SWATCH)))
        .px(px((CELL - SWATCH) / 2.))
        .children(PALETTE.iter().enumerate().map(|(ix, c)| {
            let cell = PickerCell::Color(ix);
            let chosen = chosen_color == Some(*c);
            let default = *c == default_color;
            let label = if default {
                format!("{} (default)", PALETTE_NAMES[ix])
            } else {
                PALETTE_NAMES[ix].to_owned()
            };
            div()
                .id(("icon-color", ix))
                .debug_selector(move || format!("icon-color {ix}"))
                .aria_label(SharedString::from(label))
                .size(px(SWATCH))
                .rounded_full()
                .bg(rgb(*c))
                .clickable()
                .flex()
                .items_center()
                .justify_center()
                .map(|d| cursor_ring(d, cell))
                .when(chosen, |d| {
                    d.child(
                        div()
                            .debug_selector(move || format!("icon-color-chosen {ix}"))
                            .child(
                                Icon::new(IconName::Check)
                                    .size_3()
                                    .text_color(gpui::white()),
                            ),
                    )
                })
                .on_click(choose(cell))
        }));

    let image_row = image_row(s, state, cursor == Some(PickerCell::Image), &choose, cx);

    ui::v_flex()
        .track_focus(focus)
        .key_context(PICKER_CONTEXT)
        .debug_selector(|| "icon-picker".into())
        // The search field keeps ↑/↓ (and ←/→ while it is empty) for itself; the grid
        // takes them first.
        .map(|d| arrow_handlers(d, state, scroll, ITEM_MOVE))
        .on_action({
            let state = state.clone();
            move |_: &PickerChoose, _, cx| state.update(cx, |s, cx| s.icon_picker_choose(cx))
        })
        .on_action({
            let (state, title) = (state.clone(), title.clone());
            move |_: &PickerClose, window, cx| {
                state.update(cx, |s, cx| s.set_icon_picker(false, cx));
                window.focus(&title, cx);
            }
        })
        .w(px(GRID_COLS as f32 * (CELL + CELL_GAP)))
        .gap(px(8.))
        .child(automatic)
        .child(grid.search_field)
        // Same height in both states, so the grid does not move while typing.
        .child(ui::muted(if searching { "Results" } else { "Symbol" }, cx).text_xs())
        .child(grid.grid)
        .child(ui::muted("Colour", cx).text_xs())
        .child(swatches)
        .child(image_row)
        .into_any_element()
}

/// "Drop or choose image…" (PNG or JPEG, open panel, or a file dropped on the row). A new item
/// has nowhere to keep the image until it is saved, so the row is disabled there and
/// says why.
fn image_row<H>(
    s: &AppState,
    state: &Entity<AppState>,
    under_cursor: bool,
    choose: &impl Fn(PickerCell) -> H,
    cx: &App,
) -> AnyElement
where
    H: Fn(&gpui::ClickEvent, &mut gpui::Window, &mut App) + 'static,
{
    let theme = cx.theme();
    let loading = s.edit_buffer().is_some_and(|b| b.icon_loading);
    let enabled = s.can_choose_icon_image();
    let chosen = s
        .edit_buffer()
        .and_then(|b| b.item.icon.as_ref())
        .and_then(icon::image_attachment)
        .is_some();
    let hint = if loading {
        "Preparing image\u{2026}"
    } else if matches!(s.mode, crate::state::Mode::New(..)) {
        "Save the item first to use an image"
    } else {
        "PNG or JPEG, up to 512 KB"
    };
    ui::h_flex()
        .id("icon-image")
        .debug_selector(|| "icon-picker-image".into())
        .aria_label(SharedString::from("Drop or choose image"))
        .gap(px(8.))
        .px(px(6.))
        .py(px(4.))
        .rounded(theme.radius)
        .border_2()
        .border_color(if under_cursor {
            theme.ring
        } else {
            gpui::transparent_black()
        })
        .when(chosen, |d| d.bg(theme.primary.opacity(0.12)))
        .clickable_when(enabled)
        .when(enabled, |d| {
            d.hover(|d| d.bg(theme.accent))
                .on_click(choose(PickerCell::Image))
        })
        .when(!enabled, |d| d.opacity(0.6))
        .map(|d| icon_drop_target(d, state, enabled, cx))
        .child(
            div()
                .size(px(24.))
                .flex()
                .items_center()
                .justify_center()
                .child(if loading {
                    Spinner::new().small().into_any_element()
                } else {
                    Icon::new(IconName::Image)
                        .size_4()
                        .text_color(theme.foreground)
                        .into_any_element()
                }),
        )
        .child(
            ui::v_flex()
                .flex_1()
                .min_w_0()
                .child(div().text_sm().child("Drop or choose image\u{2026}"))
                .child(ui::muted(hint, cx).text_xs().truncate()),
        )
        .when(chosen, |d| {
            d.child(
                Icon::new(IconName::Check)
                    .size_4()
                    .text_color(theme.primary),
            )
        })
        .into_any_element()
}

/// Which picker a [`search_grid`] belongs to: its cells are `(<prefix>, ix)` without a
/// query and `(<hit_prefix>, ix)` with one.
struct GridKind {
    prefix: &'static str,
    hit_prefix: &'static str,
}

/// The search field and the grid under it, shared by both pickers.
struct SearchGrid {
    search_field: gpui::Div,
    grid: gpui::Stateful<gpui::Div>,
}

/// The search field (05 "Icon search") and the grid: the curated symbols without a query,
/// else `AppState::icon_search`'s results (computed once per query change). The grid has a
/// fixed height and scrolls; `scroll` keeps the keyboard cursor in view (see
/// [`arrow_handlers`]) and is reset to the top by the editor on each query change.
#[allow(clippy::too_many_arguments)]
fn search_grid(
    state: &Entity<AppState>,
    (search, scroll): (&Entity<InputState>, &ScrollHandle),
    kind: GridKind,
    chosen: Option<IconName>,
    cursor: Option<usize>,
    on_pick: impl Fn(PickerCell, &mut gpui::Window, &mut App) + 'static,
    cx: &App,
) -> SearchGrid {
    let theme = cx.theme();
    let found = &state.read(cx).icon_search;
    let grid = if found.active() {
        hit_grid(
            found.hits(),
            kind.hit_prefix,
            chosen,
            found.hit(),
            on_pick,
            cx,
        )
    } else {
        symbol_grid(
            kind.prefix,
            chosen,
            cursor,
            move |ix, window, cx| on_pick(PickerCell::Symbol(ix), window, cx),
            cx,
        )
    };
    // The rows are the scroll element's own children, so `scroll_to_item(row)` reveals
    // the keyboard cursor's row.
    let grid = grid
        .id("icon-grid")
        .debug_selector(|| "icon-grid".into())
        .h(px(GRID_H))
        .flex_none()
        .overflow_y_scroll()
        .track_scroll(scroll)
        // A cell click leaves the focus where it was (the search field keeps typing).
        .on_mouse_down(gpui::MouseButton::Left, |_, window, _| {
            window.prevent_default()
        });
    let search_field = div().debug_selector(|| "icon-search".into()).child(
        Input::new(search).small().prefix(
            Icon::new(IconName::Search)
                .size_4()
                .text_color(theme.muted_foreground),
        ),
    );
    SearchGrid { search_field, grid }
}

/// Arrow handling of a picker root: ↑/↓ always, and ←/→ while the query is empty, are
/// taken from the focused search field first (capture phase); the picker's own arrow
/// actions too. Each moves the cursor with `f` and scrolls the grid to keep it in view.
fn arrow_handlers(
    d: gpui::Div,
    state: &Entity<AppState>,
    scroll: &ScrollHandle,
    f: MoveFn,
) -> gpui::Div {
    d.capture_action(arrow::<MoveUp>(state, scroll, Move::Up, true, f))
        .capture_action(arrow::<MoveDown>(state, scroll, Move::Down, true, f))
        .capture_action(arrow::<MoveLeft>(state, scroll, Move::Left, false, f))
        .capture_action(arrow::<MoveRight>(state, scroll, Move::Right, false, f))
        .on_action(arrow::<PickerUp>(state, scroll, Move::Up, true, f))
        .on_action(arrow::<PickerDown>(state, scroll, Move::Down, true, f))
        .on_action(arrow::<PickerLeft>(state, scroll, Move::Left, true, f))
        .on_action(arrow::<PickerRight>(state, scroll, Move::Right, true, f))
}

/// One arrow of [`arrow_handlers`]; `always` false leaves it to the field's caret while
/// there is a query.
fn arrow<A: gpui::Action>(
    state: &Entity<AppState>,
    scroll: &ScrollHandle,
    m: Move,
    always: bool,
    f: MoveFn,
) -> impl Fn(&A, &mut gpui::Window, &mut App) + 'static {
    let (state, scroll) = (state.clone(), scroll.clone());
    move |_, _, cx| {
        if always || !state.read(cx).icon_search.active() {
            state.update(cx, |s, cx| f(s, m, cx));
            if let Some(ix) = state.read(cx).icon_picker_cursor_index() {
                scroll.scroll_to_item(ix / GRID_COLS);
            }
            cx.stop_propagation();
        }
    }
}

/// The search results: curated symbols, then catalog icons. Cells are found in tests as
/// `<prefix> <ix> <IconName>`, the chosen one as `<prefix>-chosen <ix> <IconName>`.
fn hit_grid(
    hits: &[PickerCell],
    prefix: &'static str,
    chosen: Option<IconName>,
    cursor: Option<usize>,
    on_pick: impl Fn(PickerCell, &mut gpui::Window, &mut App) + 'static,
    cx: &App,
) -> gpui::Div {
    if hits.is_empty() {
        return ui::v_flex().items_center().justify_center().child(
            ui::muted("No icons match", cx)
                .text_sm()
                .debug_selector(|| "icon-no-match".into()),
        );
    }
    let theme = cx.theme();
    let on_pick = Rc::new(on_pick);
    let rows = hits.chunks(GRID_COLS).enumerate().map(|(r, row)| {
        ui::h_flex()
            .gap(px(CELL_GAP))
            .children(row.iter().enumerate().filter_map(|(c, cell)| {
                let ix = r * GRID_COLS + c;
                let name = icon::cell_icon(*cell)?;
                let is_chosen = chosen == Some(name);
                let selector = if is_chosen {
                    format!("{prefix}-chosen {ix} {name:?}")
                } else {
                    format!("{prefix} {ix} {name:?}")
                };
                let (on_pick, cell) = (on_pick.clone(), *cell);
                let color = if is_chosen {
                    theme.primary
                } else {
                    theme.foreground
                };
                Some(
                    grid_cell(
                        (prefix, ix),
                        selector,
                        icon::symbol_label(name),
                        is_chosen,
                        cursor == Some(ix),
                        cx,
                    )
                    .on_click(move |_, window, cx| on_pick(cell, window, cx))
                    .child(Icon::new(name).size_4().text_color(color)),
                )
            }))
    });
    ui::v_flex().gap(px(CELL_GAP)).children(rows)
}

/// One cell of a picker grid: `label` as tooltip and VoiceOver name, a tinted fill when
/// `chosen`, the keyboard cursor's ring when `under_cursor`.
fn grid_cell(
    id: (&'static str, usize),
    selector: String,
    label: String,
    chosen: bool,
    under_cursor: bool,
    cx: &App,
) -> gpui::Stateful<gpui::Div> {
    let theme = cx.theme();
    let tip = SharedString::from(label);
    div()
        .id(id)
        .debug_selector(move || selector)
        .aria_label(tip.clone())
        .tooltip(move |window, cx| {
            gpui_component::tooltip::Tooltip::new(tip.clone()).build(window, cx)
        })
        .size(px(CELL))
        .flex()
        .items_center()
        .justify_center()
        .rounded(theme.radius)
        .clickable()
        .hover(|d| d.bg(theme.accent))
        .when(chosen, |d| d.bg(theme.primary.opacity(0.18)))
        // Keyboard cursor: an accent ring; the current choice: a tinted fill.
        .border_2()
        .border_color(if under_cursor {
            theme.ring
        } else {
            gpui::transparent_black()
        })
}

type MoveFn = fn(&mut AppState, Move, &mut gpui::Context<AppState>);
const ITEM_MOVE: MoveFn = AppState::icon_picker_move;
const FIELD_MOVE: MoveFn = AppState::field_icon_picker_move;

/// The symbol grid of both pickers (`icon::SYMBOLS`, `GRID_COLS` per row). Cells are
/// `(<prefix>, ix)` elements, found in tests as `<prefix> <ix>` and the selected one as
/// `<prefix>-chosen <ix>`; `cursor` (a cell index) draws the keyboard cursor's ring and
/// `on_pick` runs with the clicked cell's index.
pub fn symbol_grid(
    prefix: &'static str,
    chosen: Option<IconName>,
    cursor: Option<usize>,
    on_pick: impl Fn(usize, &mut gpui::Window, &mut App) + 'static,
    cx: &App,
) -> gpui::Div {
    let theme = cx.theme();
    let on_pick = Rc::new(on_pick);
    let rows = SYMBOLS.chunks(GRID_COLS).enumerate().map(|(r, row)| {
        ui::h_flex()
            .gap(px(CELL_GAP))
            .children(row.iter().enumerate().map(|(c, (_, name, label))| {
                let ix = r * GRID_COLS + c;
                let is_chosen = chosen == Some(*name);
                let on_pick = on_pick.clone();
                let selector = if is_chosen {
                    format!("{prefix}-chosen {ix}")
                } else {
                    format!("{prefix} {ix}")
                };
                let label = (*label).to_owned();
                grid_cell(
                    (prefix, ix),
                    selector,
                    label,
                    is_chosen,
                    cursor == Some(ix),
                    cx,
                )
                .on_click(move |_, window, cx| on_pick(ix, window, cx))
                .child(Icon::new(*name).size_4().text_color(if is_chosen {
                    theme.primary
                } else {
                    theme.foreground
                }))
            }))
    });
    ui::v_flex().gap(px(CELL_GAP)).children(rows)
}

/// Focus handles of one field row's icon picker: the open panel and its "No icon" row.
pub struct FieldIconFocus {
    pub panel: FocusHandle,
    pub none: FocusHandle,
}

/// Edit mode: the ghost button left of field `key`'s name input, showing its symbol or
/// a faint placeholder, and the picker it opens: "No icon", then the symbol grid. A
/// pick, Enter and Esc close it and give the focus back to `name` (the name input).
pub fn field_icon_button(
    state: &Entity<AppState>,
    key: u64,
    focus: &FieldIconFocus,
    (search, scroll): (&Entity<InputState>, &ScrollHandle),
    name: &FocusHandle,
    cx: &App,
) -> AnyElement {
    let s = state.read(cx);
    let current = s
        .edit_buffer()
        .and_then(|b| b.field(key))
        .and_then(|f| f.icon_name());
    let symbol = current.and_then(icon::symbol);
    let open = s.field_icon_picker().is_some_and(|(k, _)| k == key);
    let muted = cx.theme().muted_foreground;
    let glyph = match symbol {
        Some(symbol) => Icon::new(symbol).text_color(muted),
        None => Icon::new(IconName::CircleDashed).text_color(muted.opacity(0.5)),
    };
    let shown = symbol.map_or("none".to_owned(), |s| format!("{s:?}"));
    let trigger = Button::new(("field-icon", key))
        .debug_selector(move || format!("field-icon-button {key} {shown}"))
        .ghost()
        .small()
        .icon(glyph)
        .tooltip("Field icon")
        .accessibility_label("Field icon")
        .clickable();
    let (toggle, toggle_search) = (state.clone(), search.clone());
    let (state, panel, none, name) = (
        state.clone(),
        focus.panel.clone(),
        focus.none.clone(),
        name.clone(),
    );
    let (search_state, scroll) = (search.clone(), scroll.clone());
    ui::popover(
        ("field-icon-picker", key),
        trigger,
        Anchor::TopLeft,
        open,
        move |open, window, cx| {
            // The query is not kept between openings.
            ui::clear_input(&toggle_search, window, cx);
            toggle.update(cx, |s, cx| s.set_field_icon_picker(key, open, cx))
        },
        move |_, cx| {
            let handles = (&panel, &none, &search_state, &scroll, &name);
            field_picker(&state, key, handles, cx)
        },
    )
    // Opening focuses the search field, as in the item picker.
    .track_focus(&gpui::Focusable::focus_handle(search, cx))
    .into_any_element()
}

/// The field icon picker's body. Uses the item picker's key context and actions.
fn field_picker(
    state: &Entity<AppState>,
    key: u64,
    (panel, none, search, scroll, name): (
        &FocusHandle,
        &FocusHandle,
        &Entity<InputState>,
        &ScrollHandle,
        &FocusHandle,
    ),
    cx: &App,
) -> AnyElement {
    let s = state.read(cx);
    let Some((_, cursor)) = s.field_icon_picker().filter(|(k, _)| *k == key) else {
        return div().into_any_element();
    };
    let current = s
        .edit_buffer()
        .and_then(|b| b.field(key))
        .and_then(|f| f.icon_name());
    let cell = cursor.cell();
    // Picks and closes, then the name input has the focus again.
    let pick = {
        let (state, name) = (state.clone(), name.clone());
        move |cell: PickerCell, window: &mut gpui::Window, cx: &mut App| {
            state.update(cx, |s, cx| s.choose_field_icon(key, cell, cx));
            window.focus(&name, cx);
        }
    };
    let none_row = {
        let pick = pick.clone();
        ui::menu_row(format!("field-icon-none {key}"), "No icon")
            .checked(current.is_none())
            .on_click(move |_, window, cx| pick(PickerCell::Automatic, window, cx))
            .render_alone(none, cell == PickerCell::Automatic, cx)
    };
    let grid = search_grid(
        state,
        (search, scroll),
        GridKind {
            prefix: "field-icon-symbol",
            hit_prefix: "field-icon-hit",
        },
        current.and_then(icon::symbol),
        match cell {
            PickerCell::Symbol(ix) => Some(ix),
            _ => None,
        },
        move |cell, window, cx| pick(cell, window, cx),
        cx,
    );
    ui::v_flex()
        .track_focus(panel)
        .key_context(PICKER_CONTEXT)
        .debug_selector(move || format!("field-icon-picker {key}"))
        .map(|d| arrow_handlers(d, state, scroll, FIELD_MOVE))
        .on_action({
            // Enter/Space reach this binding before a focused row's own key-up click, so
            // a Tab-focused "No icon" row clears here; otherwise the cursor's cell wins.
            let (state, name, none) = (state.clone(), name.clone(), none.clone());
            move |_: &PickerChoose, window, cx| {
                if none.is_focused(window) {
                    state.update(cx, |s, cx| {
                        s.choose_field_icon(key, PickerCell::Automatic, cx)
                    });
                } else {
                    state.update(cx, |s, cx| s.field_icon_picker_choose(cx));
                }
                window.focus(&name, cx);
            }
        })
        .on_action({
            let (state, name) = (state.clone(), name.clone());
            move |_: &PickerClose, window, cx| {
                state.update(cx, |s, cx| s.set_field_icon_picker(key, false, cx));
                window.focus(&name, cx);
            }
        })
        .w(px(GRID_COLS as f32 * (CELL + CELL_GAP)))
        .gap(px(8.))
        .child(none_row)
        .child(grid.search_field)
        .child(grid.grid)
        .into_any_element()
}
