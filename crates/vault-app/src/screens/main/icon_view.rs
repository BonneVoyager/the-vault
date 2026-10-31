//! Item icon tile and the edit-mode icon picker (specs/05-ui.md §2.3). What to show is
//! decided by `crate::icon`; this module only draws it.

use std::sync::Arc;

use gpui::{
    Anchor, AnyElement, App, Entity, ExternalPaths, FocusHandle, FontWeight, Hsla,
    InteractiveElement as _, IntoElement, KeyBinding, ParentElement as _, RenderImage,
    SharedString, StatefulInteractiveElement as _, Styled as _, actions, div, img,
    prelude::FluentBuilder, px, rgb, svg,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::spinner::Spinner;
use gpui_component::{ActiveTheme as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{Item, Uuid};

use crate::icon::{
    self, GRID_COLS, Glyph, IconSpec, Move, PALETTE, PALETTE_NAMES, PickerCell, SYMBOLS, TileBg,
};
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
        KeyBinding::new("space", PickerChoose, ctx),
        KeyBinding::new("escape", PickerClose, ctx),
    ]);
}

/// `0xRRGGBB` of a theme colour, for the contrast decision.
fn rgb_u32(c: Hsla) -> u32 {
    let c = c.to_rgb();
    let ch = |v: f32| (v.clamp(0., 1.) * 255.).round() as u32;
    (ch(c.r) << 16) | (ch(c.g) << 8) | ch(c.b)
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
/// viewer (28/40) and the picker. Tests find it as `icon-tile <spec> <bg> <glyph>`.
pub fn icon_tile(spec: &IconSpec, size: f32, cx: &App) -> gpui::Div {
    let theme = cx.theme();
    let surface = theme.secondary;
    let color = match spec {
        IconSpec::Letter { color, .. }
        | IconSpec::Symbol { color, .. }
        | IconSpec::Unsupported { color, .. } => *color,
        IconSpec::Logo { hex, .. } => *hex,
        // Only reached without the item at hand (see `item_tile`): a neutral tile.
        IconSpec::Image { .. } => rgb_u32(surface),
    };
    let (bg, glyph) = icon::tile_look(color, theme.is_dark(), rgb_u32(surface));
    let glyph_color: Hsla = match glyph {
        Glyph::White => gpui::white(),
        Glyph::Own(c) => rgb(c).into(),
        Glyph::Foreground => theme.foreground,
    };
    let selector = format!(
        "icon-tile {} {} {}",
        spec.describe(),
        match bg {
            TileBg::Fill(_) => "fill",
            TileBg::Surface => "surface",
        },
        match glyph {
            Glyph::White => "white",
            Glyph::Own(_) => "own",
            Glyph::Foreground => "foreground",
        }
    );
    let tile = div()
        .debug_selector(move || selector.clone())
        .flex_shrink_0()
        .size(px(size))
        .rounded(px(size / 4.))
        .map(|d| match bg {
            TileBg::Fill(c) => d.bg(rgb(c)),
            // The neutral tile keeps a hairline so it does not melt into the row.
            TileBg::Surface => d.bg(surface).border_1().border_color(theme.border),
        })
        .flex()
        .items_center()
        .justify_center()
        .text_color(glyph_color);
    match spec {
        IconSpec::Letter { letter, .. } | IconSpec::Unsupported { letter, .. } => tile
            .font_weight(FontWeight::SEMIBOLD)
            .when(size > 36., |d| d.text_lg())
            .when(size < 26., |d| d.text_xs())
            .child(letter.clone()),
        IconSpec::Logo { slug, .. } => tile.child(
            svg()
                .path(icon::brand_asset_path(slug))
                .size(px((size * 0.58).round()))
                .text_color(glyph_color),
        ),
        IconSpec::Symbol { name, .. } => tile.child(
            Icon::new(*name)
                .size(px((size * 0.56).round()))
                .text_color(glyph_color),
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

/// The edit-mode tile in the editor header: a button that opens the picker, and a drop
/// target for an image file. `title` gets the focus back when Esc closes the picker.
pub fn picker_trigger(
    state: &Entity<AppState>,
    focus: &FocusHandle,
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
    let popover = ui::popover(
        "edit-icon-picker",
        trigger,
        Anchor::TopLeft,
        open,
        move |open, _, cx| toggle_state.update(cx, |s, cx| s.set_icon_picker(open, cx)),
        move |_, cx| picker(&content_state, &content_focus, &title, cx),
    )
    .track_focus(focus);
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

/// Popover body: Automatic, the symbol grid, the colour swatches and "Drop or choose image…".
fn picker(
    state: &Entity<AppState>,
    focus: &FocusHandle,
    title: &FocusHandle,
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
    let color_disabled = icon::color_disabled_reason(&buffer.item);
    let chosen_color = color_disabled
        .is_none()
        .then(|| icon::effective_color(&buffer.item));
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

    let symbols = SYMBOLS.chunks(GRID_COLS).enumerate().map(|(r, row)| {
        ui::h_flex()
            .gap(px(CELL_GAP))
            .children(row.iter().enumerate().map(|(c, (_, name, label))| {
                let ix = r * GRID_COLS + c;
                let cell = PickerCell::Symbol(ix);
                let chosen = chosen_symbol == Some(*name);
                div()
                    .id(("icon-symbol", ix))
                    .debug_selector(move || format!("icon-symbol {ix}"))
                    .aria_label(SharedString::from(*label))
                    .tooltip(move |window, cx| {
                        gpui_component::tooltip::Tooltip::new(*label).build(window, cx)
                    })
                    .size(px(CELL))
                    .flex()
                    .items_center()
                    .justify_center()
                    .rounded(theme.radius)
                    .clickable()
                    .hover(|d| d.bg(theme.accent))
                    .when(chosen, |d| {
                        d.bg(theme.primary.opacity(0.18))
                            .debug_selector(move || format!("icon-symbol-chosen {ix}"))
                    })
                    .map(|d| cursor_ring(d, cell))
                    .on_click(choose(cell))
                    .child(Icon::new(*name).size_4().text_color(if chosen {
                        theme.primary
                    } else {
                        theme.foreground
                    }))
            }))
    });

    let enabled = color_disabled.is_none();
    let swatches = ui::h_flex()
        .gap(px(CELL_GAP + (CELL - SWATCH)))
        .px(px((CELL - SWATCH) / 2.))
        .when(!enabled, |d| d.opacity(0.4))
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
                .clickable_when(enabled)
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
                .when(enabled, |d| d.on_click(choose(cell)))
        }));
    let color_hint = color_disabled.map(|why| {
        ui::muted(why, cx)
            .debug_selector(|| "icon-color-disabled".into())
            .text_xs()
    });

    let image_row = image_row(s, state, cursor == Some(PickerCell::Image), &choose, cx);

    ui::v_flex()
        .track_focus(focus)
        .key_context(PICKER_CONTEXT)
        .debug_selector(|| "icon-picker".into())
        .on_action(move_handler(state, Move::Up, PickerUp))
        .on_action(move_handler(state, Move::Down, PickerDown))
        .on_action(move_handler(state, Move::Left, PickerLeft))
        .on_action(move_handler(state, Move::Right, PickerRight))
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
        .child(ui::muted("Symbol", cx).text_xs())
        .child(ui::v_flex().gap(px(CELL_GAP)).children(symbols))
        .child(ui::muted("Colour", cx).text_xs())
        .child(swatches)
        .children(color_hint)
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

/// Arrow-key handler moving the picker cursor.
fn move_handler<A: gpui::Action>(
    state: &Entity<AppState>,
    m: Move,
    _: A,
) -> impl Fn(&A, &mut gpui::Window, &mut App) + 'static {
    let state = state.clone();
    move |_, _, cx| state.update(cx, |s, cx| s.icon_picker_move(m, cx))
}
