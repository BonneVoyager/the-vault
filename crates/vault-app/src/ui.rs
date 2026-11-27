//! Thin wrappers over gpui / gpui-component calls used across the app.
//!
//! gpui is pre-1.0. Keep every upstream call that more than two views need in here,
//! so an upstream rename is a one-file fix.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use gpui::{
    Anchor, AnyElement, App, AppContext as _, Bounds, ClickEvent, Context, Div, Entity,
    FocusHandle, InteractiveElement as _, IntoElement, MouseButton, ParentElement as _,
    PathPromptOptions, Pixels, Point, Render, Result, SharedString, Stateful,
    StatefulInteractiveElement as _, Styled as _, Task, TitlebarOptions, Window, WindowBounds,
    WindowHandle, WindowOptions, point, prelude::FluentBuilder as _, px, relative, size,
};
use gpui_component::button::{Button, ButtonCustomVariant, ButtonVariants as _};
use gpui_component::input::{Input, InputState, TextareaState};
use gpui_component::popover::Popover;
use gpui_component::tooltip::Tooltip;
use gpui_component::{ActiveTheme as _, Disableable as _, Icon, Root, Selectable, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{ExposeSecret as _, PassphraseSpec, SecretString, passphrase, strength_bits};

pub use gpui_component::{h_flex, v_flex};

use crate::persist::WindowState;

/// Default and minimum main window size (specs/05-ui.md §1).
const MAIN_DEFAULT: (f32, f32) = (1100., 720.);
const MAIN_MIN: (f32, f32) = (820., 520.);
/// How much narrower the main window may get while the sidebar is collapsed: the
/// sidebar's default width (05 §1).
const SIDEBAR_MIN_DROP: f32 = 220.;

/// Main window minimum size for a sidebar state: 820 x 520 expanded, 600 x 520
/// collapsed.
pub fn main_min_size(sidebar_visible: bool) -> (f32, f32) {
    if sidebar_visible {
        MAIN_MIN
    } else {
        (MAIN_MIN.0 - SIDEBAR_MIN_DROP, MAIN_MIN.1)
    }
}

#[cfg(test)]
thread_local! {
    /// The last size `apply_main_min_size` asked for, on this thread (tests only).
    static LAST_MIN_SIZE: Cell<Option<(f32, f32)>> = const { Cell::new(None) };
}

/// The minimum size the last `apply_main_min_size` on this thread asked for.
#[cfg(test)]
pub fn last_main_min_size() -> Option<(f32, f32)> {
    LAST_MIN_SIZE.get()
}

/// The single hook for the main window's minimum size: called on every sidebar toggle
/// and once at launch when the persisted sidebar state is collapsed. gpui only sets a
/// window's minimum at creation, so this goes through AppKit.
///
/// Uses vault-macos's key-window variant: the per-view variant is an `unsafe fn`, and
/// vault-app has no `unsafe`. The toggle only runs while the main window is active
/// (`actions::on_main`), so the key window is the main window. Off the main thread, with
/// no key window, or in tests nothing is updated, which is harmless.
pub fn apply_main_min_size(sidebar_visible: bool) {
    let (width, height) = main_min_size(sidebar_visible);
    #[cfg(test)]
    LAST_MIN_SIZE.set(Some((width, height)));
    if !vault_macos::set_key_window_min_content_size(f64::from(width), f64::from(height)) {
        log::debug!("main window minimum size {width}x{height}: no key window updated");
    }
}
/// Traffic-light inset from the window's top-left corner.
const TRAFFIC_LIGHTS: (f32, f32) = (16., 16.);
/// Height of one macOS traffic-light button.
const TRAFFIC_LIGHT_SIZE: f32 = 14.;
/// Height of the transparent titlebar strip that content must keep clear of. The
/// sidebar's vault-name row starts below it because the traffic lights sit there.
pub const TITLEBAR_HEIGHT: f32 = 44.;
/// Height of the title-bar band: gpui sizes AppKit's titlebar container to the button
/// height plus the traffic-light inset above and below, so the lights sit centred in it.
/// The list's search row fills this band in the list column.
pub const TOP_BAND_HEIGHT: f32 = 2. * TRAFFIC_LIGHTS.1 + TRAFFIC_LIGHT_SIZE;
/// Height of the search field at the default text size. Set explicitly (scaled with the
/// text size) because gpui-component's small input is `1.5 rem` and the rem differs
/// between gpui-component's `Root` and ours.
pub const SEARCH_HEIGHT: f32 = 24.;
/// Top edge of the search field and of the detail header: centres the search field on
/// the traffic lights at the default text size.
pub const SEARCH_TOP: f32 = (TOP_BAND_HEIGHT - SEARCH_HEIGHT) / 2.;
/// Left and right padding of the list's search row and the detail column, so the
/// columns' content starts on the same inset.
pub const COLUMN_PAD_X: f32 = 16.;
/// Right edge of the traffic lights: three buttons on AppKit's 20 px pitch
/// (14 px button, 6 px gap) from the inset.
pub const TRAFFIC_LIGHTS_RIGHT: f32 = TRAFFIC_LIGHTS.0 + 2. * 20. + TRAFFIC_LIGHT_SIZE;
/// Left padding of the list's search row while the sidebar is collapsed: past the
/// traffic lights with the gap Finder leaves before its first toolbar button.
pub const COLLAPSED_PAD_X: f32 = TRAFFIC_LIGHTS_RIGHT + 12.;

/// Left padding of the list's search row with `sidebar_width` px of sidebar to its
/// left: the column inset, or more while the traffic lights would overlap the row.
pub fn list_header_pad_left(sidebar_width: f32) -> f32 {
    (COLLAPSED_PAD_X - sidebar_width).max(COLUMN_PAD_X)
}

/// Sidebar slide on ⌃⌘S (05 §5: 120-180 ms ease-out panel motion).
pub const SIDEBAR_MOTION: std::time::Duration = std::time::Duration::from_millis(180);

/// Height of the sidebar and list footers, including their 1 px top divider. Scaled with
/// the text size (`theme::scaled`) in both columns so they always match.
pub const FOOTER_HEIGHT: f32 = 44.;
/// Width of the transparent border `focus_ring` adds; content inside a focus-ringed
/// column is inset by it.
pub const FOCUS_RING_WIDTH: f32 = 1.;

/// ⌥ held with no other modifier: the hold-to-reveal chord (05 §2.3). ⌥ as part of a
/// shortcut (⌘⌥S, ⇧⌥…) does not reveal.
pub fn option_alone(m: &gpui::Modifiers) -> bool {
    m.alt && !m.platform && !m.control && !m.shift && !m.function
}

/// Top padding of the detail column's content: level with the search field in the
/// title-bar band, or just below the sync banners when they occupy it.
pub fn content_top(s: &crate::state::AppState) -> f32 {
    if s.sync.has_banner() {
        12.
    } else {
        // The detail column carries a focus ring, which already insets its content.
        SEARCH_TOP - FOCUS_RING_WIDTH
    }
}

/// Window options for the main window: restored or centred, hidden title, transparent titlebar.
pub fn main_window_options(restore: Option<WindowState>, cx: &App) -> WindowOptions {
    window_options(restore, MAIN_MIN, cx)
}

/// [`main_window_options`] with minimum size `min`, which also clamps restored bounds.
fn window_options(restore: Option<WindowState>, min: (f32, f32), cx: &App) -> WindowOptions {
    let bounds = match restore {
        Some(s) => Bounds::new(
            point(px(s.x), px(s.y)),
            size(px(s.width.max(min.0)), px(s.height.max(min.1))),
        ),
        None => Bounds::centered(None, size(px(MAIN_DEFAULT.0), px(MAIN_DEFAULT.1)), cx),
    };
    WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        window_min_size: Some(size(px(min.0), px(min.1))),
        titlebar: Some(TitlebarOptions {
            title: None,
            appears_transparent: true,
            traffic_light_position: Some(point(px(TRAFFIC_LIGHTS.0), px(TRAFFIC_LIGHTS.1))),
        }),
        // AppKit would otherwise move the window from anywhere in the titlebar band,
        // including from the search field and buttons placed there. The window moves
        // only from `window_drag_band` instead.
        app_owns_titlebar_drag: true,
        ..Default::default()
    }
}

thread_local! {
    /// The band saw a left mouse-down that may turn into a window drag.
    static DRAG_ARMED: Cell<bool> = const { Cell::new(false) };
    /// Position of the mouse-down a control in the band claimed (see `no_window_drag`).
    static DRAG_CLAIM: Cell<Option<Point<Pixels>>> = const { Cell::new(None) };
    #[cfg(test)]
    static DRAG_MOVES: Cell<usize> = const { Cell::new(0) };
}

/// Transparent strip across the top of a window that claims its titlebar
/// (`app_owns_titlebar_drag`): dragging it moves the window, double-clicking it applies
/// the system titlebar double-click action. Put it before the content so it paints
/// underneath, and wrap every control that reaches into the band in `no_window_drag`.
pub fn window_drag_band() -> Div {
    gpui::div()
        .absolute()
        .top_0()
        .left_0()
        .right_0()
        .h(px(TOP_BAND_HEIGHT))
        .debug_selector(|| "window-drag-band".into())
        .on_mouse_down(MouseButton::Left, |event, window, _| {
            // Controls paint above the band, so their listeners ran first.
            let claimed = DRAG_CLAIM.take() == Some(event.position);
            DRAG_ARMED.set(false);
            if claimed {
                return;
            }
            if event.click_count == 2 {
                window.titlebar_double_click();
            } else {
                DRAG_ARMED.set(true);
            }
        })
        .on_mouse_up(MouseButton::Left, |_, _, _| DRAG_ARMED.set(false))
        .on_mouse_move(|event, window, _| {
            if DRAG_ARMED.replace(false) && event.pressed_button == Some(MouseButton::Left) {
                // gpui's test window does not implement window moves; count them instead.
                #[cfg(test)]
                {
                    let _ = window;
                    DRAG_MOVES.set(DRAG_MOVES.get() + 1);
                }
                #[cfg(not(test))]
                window.start_window_move();
            }
        })
}

/// Marks `el` as a control: a mouse-down on it never starts a window drag from a
/// `window_drag_band` underneath. Does not stop propagation, so focus-on-click of the
/// enclosing column keeps working.
pub fn no_window_drag<E: gpui::InteractiveElement>(el: E) -> E {
    el.on_mouse_down(MouseButton::Left, |event, _, _| {
        DRAG_CLAIM.set(Some(event.position));
    })
}

/// Window drags started by `window_drag_band` on this thread (tests only).
#[cfg(test)]
pub fn window_moves() -> usize {
    DRAG_MOVES.get()
}

/// Opens the main window with `build` as content, wrapped in gpui-component's `Root`.
///
/// `Root` hosts dialogs, sheets and notifications, so every window needs it on top.
/// The minimum size (and the clamp on restored bounds) follows the persisted sidebar
/// state, so a narrow window saved while collapsed is not widened at launch.
pub fn open_main_window<V: Render>(
    restore: Option<WindowState>,
    sidebar_visible: bool,
    cx: &mut App,
    build: impl FnOnce(&mut Window, &mut App) -> Entity<V>,
) -> Result<WindowHandle<Root>> {
    let options = main_options(restore, sidebar_visible, cx);
    cx.open_window(options, |window, cx| {
        let view = build(window, cx);
        cx.new(|cx| main_root(view, window, cx))
    })
}

/// The main window's options: [`window_options`], blurred in both appearances so the
/// translucent sidebar shows the desktop behind (05 §5). Backup and item windows built
/// from [`window_options`] stay opaque.
fn main_options(restore: Option<WindowState>, sidebar_visible: bool, cx: &App) -> WindowOptions {
    WindowOptions {
        window_background: gpui::WindowBackgroundAppearance::Blurred,
        ..window_options(restore, main_min_size(sidebar_visible), cx)
    }
}

/// The main window's `Root`. gpui-component fills the whole root surface with the
/// theme background; an instance style wins over that, so clear it here and let our
/// screens paint their own fills (sidebar vibrancy, 05 §5).
pub fn main_root(
    view: impl Into<gpui::AnyView>,
    window: &mut Window,
    cx: &mut Context<Root>,
) -> Root {
    Root::new(view, window, cx).bg(gpui::transparent_black())
}

/// Current restore bounds of `window` (also valid while fullscreen or zoomed).
pub fn window_geometry(window: &Window, columns: Option<[f32; 2]>) -> WindowState {
    let b = window.window_bounds().get_bounds();
    WindowState {
        x: b.origin.x.as_f32(),
        y: b.origin.y.as_f32(),
        width: b.size.width.as_f32(),
        height: b.size.height.as_f32(),
        columns,
    }
}

/// A single-line text input state.
pub fn text_input<T>(
    placeholder: &str,
    window: &mut Window,
    cx: &mut Context<T>,
) -> Entity<InputState> {
    let placeholder = SharedString::from(placeholder.to_owned());
    cx.new(|cx| InputState::new(window, cx).placeholder(placeholder))
}

/// The unlock card's password placeholder (main unlock screen and backup viewer).
pub const MASTER_PASSWORD_PLACEHOLDER: &str = "Enter master password";

/// A masked password input state.
pub fn password_input<T>(
    placeholder: &str,
    window: &mut Window,
    cx: &mut Context<T>,
) -> Entity<InputState> {
    let placeholder = SharedString::from(placeholder.to_owned());
    cx.new(|cx| {
        InputState::new(window, cx)
            .masked(true)
            .placeholder(placeholder)
    })
}

/// Copy and Cut out of a sensitive input never take the toolkit's path.
///
/// gpui-component refuses them only while the input is masked; once revealed, ⌘C/⌘X go
/// straight to `cx.write_to_clipboard`: a plain, syncable entry with no auto-clear. Put
/// this on a container whose focusable descendants are all sensitive inputs: both actions
/// are captured on the way down and dropped. See [`route_input_copy`] to copy instead.
pub fn refuse_plain_copy<E: gpui::InteractiveElement>(el: E) -> E {
    el.capture_action(|_: &gpui_component::input::Copy, _, cx| cx.stop_propagation())
        .capture_action(|_: &gpui_component::input::Cut, _, cx| cx.stop_propagation())
}

/// Like [`refuse_plain_copy`] for one input, but a revealed value is handed to `copy`
/// (the concealed, host-only, auto-clearing path) instead of being dropped: the selection,
/// or the whole value when nothing is selected. Cut needs a selection; it hands it over
/// and then deletes it as the toolkit would (one undo step, emits Change). A masked input
/// copies nothing, as in the toolkit.
pub fn route_input_copy<E: gpui::InteractiveElement>(
    el: E,
    input: &Entity<InputState>,
    copy: impl Fn(SecretString, &mut Window, &mut App) + 'static,
) -> E {
    let copy = Rc::new(copy);
    let (copy_input, cut_input, cut_copy) = (input.clone(), input.clone(), copy.clone());
    el.capture_action(move |_: &gpui_component::input::Copy, window, cx| {
        cx.stop_propagation();
        if input_is_masked(&copy_input, cx) {
            return;
        }
        let state = copy_input.read(cx);
        let selected = state.selected_text();
        let value = if selected.len() > 0 {
            SecretString::new(selected.to_string())
        } else {
            SecretString::new(state.text().to_string())
        };
        if !value.expose_secret().is_empty() {
            copy(value, window, cx);
        }
    })
    .capture_action(move |_: &gpui_component::input::Cut, window, cx| {
        cx.stop_propagation();
        let state = cut_input.read(cx);
        if state.presentation().is_masked() || !state.is_editable() {
            return;
        }
        let selected = state.selected_text();
        if selected.len() == 0 {
            return;
        }
        let value = SecretString::new(selected.to_string());
        cut_copy(value, window, cx);
        // `replace` swaps the selection, like the toolkit's own Cut.
        cut_input.update(cx, |s, cx| s.replace("", window, cx));
    })
}

/// Test check for [`refuse_plain_copy`]: reveals `input` (typing a value if empty), then
/// ⌘A ⌘C must select everything (proof the keys reached the rendered input) yet leave the
/// toolkit clipboard untouched, and ⌘X must leave both the clipboard and the text
/// untouched (Cut refused, not just Copy). The input is masked again afterwards.
#[cfg(test)]
pub fn assert_revealed_copy_refused(input: &Entity<InputState>, vcx: &mut gpui::VisualTestContext) {
    vcx.update(|window, cx| {
        cx.write_to_clipboard(gpui::ClipboardItem::new_string("before".into()));
        input.update(cx, |s, cx| s.set_masked(false, window, cx));
        focus_input(input, window, cx);
    });
    if vcx.update(|_, cx| input_is_empty(input, cx)) {
        vcx.simulate_input("typed-secret");
    }
    vcx.simulate_keystrokes("cmd-a cmd-c");
    vcx.run_until_parked();
    vcx.update(|_, cx| {
        let state = input.read(cx);
        assert_eq!(
            state.selected_range(),
            0..state.text().len(),
            "⌘A reached the input"
        );
        let board = cx.read_from_clipboard().and_then(|c| c.text());
        assert_eq!(board.as_deref(), Some("before"), "revealed password copied");
    });
    let text_before = vcx.update(|_, cx| input.read(cx).text().to_string());
    vcx.simulate_keystrokes("cmd-x");
    vcx.run_until_parked();
    vcx.update(|window, cx| {
        let state = input.read(cx);
        assert_eq!(
            state.text().to_string(),
            text_before,
            "⌘X left the text intact"
        );
        let board = cx.read_from_clipboard().and_then(|c| c.text());
        assert_eq!(board.as_deref(), Some("before"), "revealed password cut");
        input.update(cx, |s, cx| s.set_masked(true, window, cx));
    });
}

/// The styled gpui-component input element for `state`.
pub fn input(state: &Entity<InputState>) -> Input {
    Input::new(state)
}

/// Copies an input's text straight into a `SecretString`.
///
/// The input's own rope (and undo history) still holds the text until [`clear_input`].
pub fn input_secret(state: &Entity<InputState>, cx: &App) -> SecretString {
    SecretString::new(state.read(cx).text().to_string())
}

/// A multi-line text area state that grows from 3 to 10 rows (notes fields).
pub fn textarea<T>(window: &mut Window, cx: &mut Context<T>) -> Entity<TextareaState> {
    cx.new(|cx| TextareaState::new(window, cx).auto_grow(3, 10))
}

pub fn textarea_secret(state: &Entity<TextareaState>, cx: &App) -> SecretString {
    SecretString::new(state.read(cx).text().to_string())
}

pub fn set_textarea(state: &Entity<TextareaState>, value: &str, window: &mut Window, cx: &mut App) {
    let value = value.to_owned();
    state.update(cx, |s, cx| s.set_value(value, window, cx));
}

pub fn input_text(state: &Entity<InputState>, cx: &App) -> String {
    state.read(cx).text().to_string()
}

/// Whether a password input currently hides its text.
pub fn input_is_masked(state: &Entity<InputState>, cx: &App) -> bool {
    state.read(cx).presentation().is_masked()
}

pub fn input_is_empty(state: &Entity<InputState>, cx: &App) -> bool {
    state.read(cx).text().len() == 0
}

pub fn clear_input(state: &Entity<InputState>, window: &mut Window, cx: &mut App) {
    state.update(cx, |s, cx| s.set_value("", window, cx));
}

pub fn set_input(state: &Entity<InputState>, value: &str, window: &mut Window, cx: &mut App) {
    let value = value.to_owned();
    state.update(cx, |s, cx| s.set_value(value, window, cx));
}

pub fn focus_input(state: &Entity<InputState>, window: &mut Window, cx: &mut App) {
    state.update(cx, |s, cx| s.focus(window, cx));
}

/// The centred card the choose-vault and unlock screens sit in.
pub fn card(cx: &App) -> Div {
    let theme = cx.theme();
    v_flex()
        .w(px(400.))
        .p(px(28.))
        .gap(px(14.))
        .bg(theme.popover)
        .border_1()
        .border_color(theme.border)
        .rounded(theme.radius_lg)
        .shadow_lg()
}

/// Full-window centring wrapper.
pub fn centered(cx: &App) -> Div {
    v_flex()
        .size_full()
        .items_center()
        .justify_center()
        .bg(cx.theme().background)
}

/// Muted secondary text.
pub fn muted(text: impl Into<SharedString>, cx: &App) -> Div {
    gpui::div()
        .text_sm()
        .text_color(cx.theme().muted_foreground)
        .child(text.into())
}

/// Shows the native open panel and resolves to the single chosen path, or `None`.
pub fn pick_path(directories: bool, prompt: &str, cx: &App) -> Task<Option<PathBuf>> {
    pick_one(!directories, directories, prompt, cx)
}

/// Open panel for a `<name>.vault` package. gpui 0.3.10 has no content-type filter, so
/// both files and folders are selectable: a bundled app with the `dev.vault.app` UTI
/// shows packages as single items, an unbundled run shows them as folders. The caller
/// validates the pick (`SyncedVault::open` refuses non-packages).
pub fn pick_vault_package(cx: &App) -> Task<Option<PathBuf>> {
    pick_one(true, true, "Open Vault", cx)
}

fn pick_one(files: bool, directories: bool, prompt: &str, cx: &App) -> Task<Option<PathBuf>> {
    let rx = cx.prompt_for_paths(PathPromptOptions {
        files,
        directories,
        multiple: false,
        prompt: Some(SharedString::from(prompt.to_owned())),
    });
    cx.background_executor().spawn(async move {
        match rx.await {
            Ok(Ok(Some(mut paths))) => paths.pop(),
            Ok(Err(e)) => {
                eprintln!("vault: file panel failed: {e:#}");
                None
            }
            _ => None,
        }
    })
}

/// Shows the native save panel in `dir` with `name` suggested; resolves to the chosen
/// path, or `None` if cancelled.
pub fn pick_new_path(dir: &Path, name: &str, cx: &App) -> Task<Option<PathBuf>> {
    let rx = cx.prompt_for_new_path(dir, Some(name));
    cx.background_executor().spawn(async move {
        match rx.await {
            Ok(Ok(path)) => path,
            Ok(Err(e)) => {
                eprintln!("vault: save panel failed: {e:#}");
                None
            }
            Err(_) => None,
        }
    })
}

/// Pointer (hand) cursor for everything the user can click: buttons, rows, links,
/// toggles, tabs and menu rows. The one place that decides how a clickable element looks
/// under the mouse; text inputs keep the I-beam and plain content keeps the arrow.
///
/// gpui-component 0.8.1 sets the pointer only on link and text buttons; Button (it
/// forces the arrow, then re-applies the caller's style, so this wins), Switch, Checkbox,
/// Tab and menu rows keep the arrow. Apply it after the builder's other calls.
pub trait Clickable: gpui::Styled + Sized {
    fn clickable(self) -> Self {
        self.cursor_pointer()
    }

    /// `clickable` while `enabled`; otherwise the arrow, also overriding an earlier
    /// `clickable` (such as `icon_button`'s), so a disabled or busy control never shows
    /// the hand.
    fn clickable_when(self, enabled: bool) -> Self {
        if enabled {
            self.clickable()
        } else {
            self.cursor_default()
        }
    }
}

impl<T: gpui::Styled> Clickable for T {}

/// Horizontal padding gpui-component 0.8.1 gives a dropdown-menu row (`INNER_PADDING` in
/// `menu/popup_menu.rs`, private there).
const MENU_ROW_PAD_X: f32 = 8.;

/// A dropdown-menu row with the pointer over its whole area and an optional trailing
/// check mark. gpui-component's menu rows keep the arrow and take no style, so the row's
/// content stretches to the row height and carries a pointer overlay that also covers the
/// row's side padding. Do not mix with `.checked()` / icon items in the same menu: those
/// add a slot this overlay does not cover.
pub fn menu_item(
    label: impl Into<SharedString>,
    checked: bool,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> gpui_component::menu::PopupMenuItem {
    let label = label.into();
    gpui_component::menu::PopupMenuItem::element(move |_, _| {
        h_flex()
            .relative()
            .flex_1()
            .self_stretch()
            .gap(px(12.))
            .justify_between()
            .child(label.clone())
            .when(checked, |row| {
                row.child(Icon::new(IconName::Check).xsmall())
            })
            .child(
                gpui::div()
                    .absolute()
                    .top_0()
                    .bottom_0()
                    .left(px(-MENU_ROW_PAD_X))
                    .right(px(-MENU_ROW_PAD_X))
                    .clickable(),
            )
    })
    .on_click(on_click)
}

/// An icon-only ghost button. `label` is both the tooltip and the VoiceOver label (§6).
/// Shows the pointer; a call site that disables it adds `.clickable_when(enabled)`.
pub fn icon_button(id: impl Into<gpui::ElementId>, icon: IconName, label: &str) -> Button {
    let label = SharedString::from(label.to_owned());
    Button::new(id)
        .ghost()
        .small()
        .icon(Icon::new(icon))
        .tooltip(label.clone())
        .accessibility_label(label)
        .clickable()
}

/// A 1 px horizontal rule.
pub fn divider(cx: &App) -> Div {
    gpui::div().h(px(1.)).w_full().bg(cx.theme().border)
}

/// The rounded "toast" pill. Drawn in the opposite appearance's elevated palette so it
/// stands out (owner decision 2026-11-21, option A): dark pill in light mode and vice versa.
pub fn pill(message: impl Into<SharedString>, cx: &App) -> Div {
    let inverse = crate::theme::VaultTheme::for_appearance(!cx.theme().is_dark());
    gpui::div()
        .px(px(14.))
        .py(px(6.))
        .rounded_full()
        .bg(inverse.bg_elevated)
        .border_1()
        .border_color(inverse.border)
        .text_color(inverse.text)
        .shadow_md()
        .text_sm()
        .child(message.into())
}

/// The danger pill's fill in light mode: the dark palette's elevated fill (#2A2A2D)
/// darkened by the smallest uniform step that lifts the #E5484D text to WCAG 4.5:1
/// (4.53:1; #2A2A2D gave 3.66:1; bug hunt 2026-11-21 N6, owner option A).
pub const DANGER_PILL_FILL_IN_LIGHT: u32 = 0x18181B;

/// The danger pill's text in dark mode, on the light palette's elevated fill (#F7F7F8):
/// #E5484D's hue and saturation at the highest lightness that reaches WCAG 4.5:1
/// (4.52:1). No light fill can lift #E5484D itself there (white tops out at 3.91:1), so
/// the text darkens instead (N6, orchestrator decision 2026-11-21, flagged to the owner).
pub const DANGER_PILL_TEXT_IN_DARK: u32 = 0xDE2026;

/// [`pill`] in the danger colour, for toasts about edits that could not be kept: danger
/// border on the inverted fill. Light mode: [`DANGER_PILL_FILL_IN_LIGHT`] fill, danger
/// text. Dark mode: the light palette's fill, [`DANGER_PILL_TEXT_IN_DARK`] text.
pub fn danger_pill(message: impl Into<SharedString>, cx: &App) -> Div {
    let danger = cx.theme().danger;
    let dark = cx.theme().is_dark();
    pill(message, cx)
        .when(!dark, |p| p.bg(gpui::rgb(DANGER_PILL_FILL_IN_LIGHT)))
        .border_color(danger)
        .text_color(if dark {
            gpui::rgb(DANGER_PILL_TEXT_IN_DARK).into()
        } else {
            danger
        })
}

/// Bits at which the strength bar is full: `strength_bits` (zxcvbn) never exceeds 64.
pub const STRENGTH_FULL_BITS: f64 = 64.;

/// Label and level (0 weak, 1 fair, 2 good, 3 strong) for a strength in bits, shared by
/// typed values (`strength_bits`, zxcvbn, at most 64) and the generator preview
/// (`generated_bits`, exact entropy, may exceed 64). Owner decision 2026-11-17, option B
/// (05 §2.1; Weak eased from 40 to 36 on 2026-11-17): Weak < 36, Fair < 50, Good < 56, Strong ≥ 56; 0 bits is "Empty".
pub fn strength_label(bits: f64) -> (&'static str, u8) {
    match bits {
        b if b <= 0. => ("Empty", 0),
        b if b < crate::audit::WEAK_BELOW_BITS => ("Weak", 0),
        b if b < 50. => ("Fair", 1),
        b if b < 56. => ("Good", 2),
        _ => ("Strong", 3),
    }
}

/// Fraction of the strength bar filled for `bits`: full at [`STRENGTH_FULL_BITS`].
pub fn strength_fill(bits: f64) -> f32 {
    (bits / STRENGTH_FULL_BITS).clamp(0., 1.) as f32
}

/// Strength bar plus a text label (§6: not colour alone).
pub fn strength_meter(bits: f64, cx: &App) -> Div {
    let theme = cx.theme();
    let (label, level) = strength_label(bits);
    let color = match level {
        0 => theme.danger,
        1 => theme.warning,
        _ => theme.success,
    };
    h_flex()
        .gap(px(8.))
        .child(
            gpui::div()
                .flex_1()
                .h(px(4.))
                .rounded(px(2.))
                .bg(theme.border)
                .child(
                    gpui::div()
                        .h_full()
                        .rounded(px(2.))
                        .bg(color)
                        .w(relative(strength_fill(bits))),
                ),
        )
        .child(
            gpui::div()
                .text_xs()
                .text_color(theme.muted_foreground)
                .child(format!("{label} · {bits:.0} bits")),
        )
}

/// Minimum estimated strength of a new master password (create vault, change password).
/// `strength_bits` is log2 of zxcvbn's guess estimate (at most 64); 50 bits is our
/// reading of "stronger than a short dictionary word", and a 4-word passphrase clears it.
pub const MIN_MASTER_BITS: f64 = 50.;
pub const WEAK_MASTER_PASSWORD: &str =
    "Choose a stronger master password (at least 50 bits). Try a 4-word passphrase.";
pub const WRITE_IT_DOWN: &str = "Write it down. There is no recovery without it.";
pub const PASSWORDS_DIFFER: &str = "The passwords do not match.";

/// Live checks on a new master password and its confirmation. Holds no secret text,
/// only derived numbers and flags.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct MasterPasswordCheck {
    pub bits: f64,
    filled: bool,
    matches: bool,
    /// The confirmation is at least as long as the password and still differs, so the
    /// user has finished typing it wrong (not merely not finished yet).
    mismatch: bool,
    /// The password field shows a suggested passphrase in clear text.
    pub suggested: bool,
}

impl MasterPasswordCheck {
    /// Recomputes everything from the two inputs.
    pub fn refresh(
        &mut self,
        password: &Entity<InputState>,
        confirm: &Entity<InputState>,
        cx: &App,
    ) {
        let pw = input_secret(password, cx);
        let again = input_secret(confirm, cx);
        let (pw, again) = (pw.expose_secret(), again.expose_secret());
        self.bits = strength_bits(pw);
        self.filled = !pw.is_empty();
        self.matches = pw == again;
        self.mismatch =
            !again.is_empty() && !self.matches && again.chars().count() >= pw.chars().count();
    }

    pub fn is_empty(&self) -> bool {
        !self.filled
    }

    /// Filled in and below the minimum.
    pub fn too_weak(&self) -> bool {
        self.filled && self.bits < MIN_MASTER_BITS
    }

    /// Strong enough and confirmed: the primary button may be enabled.
    pub fn ready(&self) -> bool {
        self.filled && !self.too_weak() && self.matches
    }

    /// The inline message under the meter, if any.
    pub fn problem(&self) -> Option<&'static str> {
        if self.too_weak() {
            Some(WEAK_MASTER_PASSWORD)
        } else if self.mismatch {
            Some(PASSWORDS_DIFFER)
        } else {
            None
        }
    }

    /// Fills both fields with a fresh 4-word passphrase and shows it in the password field
    /// so the user can read it once. The next edit of that field masks it again.
    pub fn suggest(
        &mut self,
        password: &Entity<InputState>,
        confirm: &Entity<InputState>,
        window: &mut Window,
        cx: &mut App,
    ) {
        let phrase = passphrase(&PassphraseSpec::default());
        for input in [password, confirm] {
            input.update(cx, |s, cx| s.set_value(phrase.expose_secret(), window, cx));
        }
        password.update(cx, |s, cx| s.set_masked(false, window, cx));
        self.suggested = true;
        self.refresh(password, confirm, cx);
    }

    /// The user typed in the password field: hide a revealed suggestion again.
    pub fn edited(&mut self, password: &Entity<InputState>, window: &mut Window, cx: &mut App) {
        if self.suggested {
            self.suggested = false;
            password.update(cx, |s, cx| s.set_masked(true, window, cx));
        }
    }

    /// The form closed or was cleared: masked again, nothing measured.
    pub fn reset(&mut self, password: &Entity<InputState>, window: &mut Window, cx: &mut App) {
        if !input_is_masked(password, cx) {
            password.update(cx, |s, cx| s.set_masked(true, window, cx));
        }
        *self = Self::default();
    }
}

/// Meter, inline problem, "Suggest passphrase" link and the write-it-down note shown under
/// a new master password field.
pub fn master_password_feedback(
    check: &MasterPasswordCheck,
    suggest_id: &'static str,
    on_suggest: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    cx: &App,
) -> Div {
    let theme = cx.theme();
    let problem = check.problem();
    v_flex()
        .gap(px(6.))
        .child(strength_meter(check.bits, cx))
        .child(
            h_flex()
                .gap(px(8.))
                .items_start()
                .child(
                    gpui::div()
                        .flex_1()
                        .min_w_0()
                        .text_xs()
                        .text_color(theme.danger)
                        .when_some(problem, |d, p| {
                            d.debug_selector(move || format!("master-problem {p}"))
                                .child(p)
                        }),
                )
                .child(
                    Button::new(suggest_id)
                        .debug_selector(move || suggest_id.into())
                        .link()
                        .small()
                        .label("Suggest passphrase")
                        .on_click(on_suggest),
                ),
        )
        .when(check.suggested, |col| {
            col.child(
                gpui::div()
                    .debug_selector(|| "master-write-it-down".into())
                    .text_xs()
                    .text_color(theme.warning)
                    .child(WRITE_IT_DOWN),
            )
        })
}

/// The unlock card's quiet secondary action ("Open another vault…  ⌘O"): small, no
/// background, foreground at 80 %, with a muted shortcut `hint`. The caller centres it
/// and adds `on_click`. `label` is what VoiceOver reads.
pub fn quiet_link(
    id: &'static str,
    text: &'static str,
    label: &'static str,
    hint: &'static str,
    enabled: bool,
    cx: &App,
) -> Button {
    let theme = cx.theme();
    Button::new(id)
        .custom(ButtonCustomVariant::new(cx).foreground(theme.foreground.opacity(0.8)))
        .small()
        .accessibility_label(label)
        .child(text)
        .child(gpui::div().text_color(theme.muted_foreground).child(hint))
        .disabled(!enabled)
        .clickable_when(enabled)
}

/// Wraps a form's primary button so headless tests can see whether it is enabled
/// (`"<name> ready"` or `"<name> blocked"`).
pub fn submit_gate(name: &'static str, ready: bool, button: impl IntoElement) -> Div {
    gpui::div()
        .debug_selector(move || format!("{name} {}", if ready { "ready" } else { "blocked" }))
        .child(button)
}

/// A popover whose open state lives in `AppState`: drawn open while `open`. The trigger
/// (click, Enter, Space), Esc and a click outside report the requested state through
/// `on_toggle`, which must write it back to `AppState`.
pub fn popover<T: Selectable + IntoElement + 'static>(
    id: impl Into<gpui::ElementId>,
    trigger: T,
    anchor: Anchor,
    open: bool,
    on_toggle: impl Fn(bool, &mut Window, &mut App) + 'static,
    content: impl Fn(&mut Window, &mut App) -> AnyElement + 'static,
) -> Popover {
    Popover::new(id)
        .anchor(anchor)
        .trigger(trigger)
        .open(open)
        .on_open_change(move |open, window, cx| on_toggle(*open, window, cx))
        .content(move |_, window, cx| content(window, cx))
}

/// Key context of an open `menu_popover` panel (↑/↓). Nested inside gpui-component's
/// `PopoverContent`, whose `escape` → Cancel still closes the menu.
pub const MENU_CONTEXT: &str = "VaultMenu";

gpui::actions!(
    vault_menu,
    [
        /// ↑ in a menu popover: focus the row above.
        MenuUp,
        /// ↓ in a menu popover: focus the row below.
        MenuDown,
    ]
);

pub fn bind_menu_keys(cx: &mut App) {
    cx.bind_keys([
        gpui::KeyBinding::new("up", MenuUp, Some(MENU_CONTEXT)),
        gpui::KeyBinding::new("down", MenuDown, Some(MENU_CONTEXT)),
    ]);
}

/// Width of the icon slot in menu rows, so every label starts at the same x. Reserved
/// on every row of a menu where at least one row has an icon, on none otherwise.
pub const MENU_ICON_SLOT: f32 = 20.;
/// A menu row's side padding.
const MENU_ROW_PAD: f32 = 8.;
/// Space between a row's icon slot and its label.
const MENU_ICON_GAP: f32 = 8.;
/// Space between a label and the hint / check-mark column after it.
const MENU_TRAIL_GAP: f32 = 24.;
/// Width of the check-mark column (a `size_4` icon).
const MENU_CHECK_COL: f32 = 16.;
/// Space after the label of a row without a check-mark column.
const MENU_TRAIL_PAD: f32 = 16.;
/// Widest a menu panel grows; longer labels truncate.
const MENU_MAX_W: f32 = 320.;

type MenuClick = Rc<dyn Fn(&ClickEvent, &mut Window, &mut App)>;

/// One row of a `menu_popover`: icon slot, label, optional trailing shortcut hint and
/// check mark. Built with `menu_row`.
pub struct MenuRow {
    id: SharedString,
    label: SharedString,
    icon: Option<IconName>,
    /// `None`: not checkable. A menu with any checkable row gives every row the
    /// check-mark column.
    checked: Option<bool>,
    hint: Option<SharedString>,
    on_click: Option<MenuClick>,
}

/// A menu row; `id` is its element id and debug selector.
pub fn menu_row(id: impl Into<SharedString>, label: impl Into<SharedString>) -> MenuRow {
    MenuRow {
        id: id.into(),
        label: label.into(),
        icon: None,
        checked: None,
        hint: None,
        on_click: None,
    }
}

impl MenuRow {
    pub fn icon(mut self, icon: IconName) -> Self {
        self.icon = Some(icon);
        self
    }

    /// Makes the row checkable (so its menu reserves the check-mark column, even
    /// when no row is checked) and shows the mark when `checked`.
    pub fn checked(mut self, checked: bool) -> Self {
        self.checked = Some(checked);
        self
    }

    // No library menu shows a shortcut yet; kept for the spec's menu row (tests use it).
    #[allow(dead_code)]
    pub fn hint(mut self, hint: impl Into<SharedString>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Runs on click, Enter and Space (focusable divs click on both keys).
    pub fn on_click(mut self, f: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static) -> Self {
        self.on_click = Some(Rc::new(f));
        self
    }

    /// The row on its own, outside a `menu_popover` (the field icon picker's "No icon"
    /// row): `cursor` draws a picker's keyboard-cursor ring on it.
    pub fn render_alone(self, focus: &FocusHandle, cursor: bool, cx: &App) -> Stateful<Div> {
        let (icons, checkable, ring) =
            (self.icon.is_some(), self.checked.is_some(), cx.theme().ring);
        self.render(focus, icons, checkable, cx)
            .when(cursor, |row| row.border_color(ring))
    }

    /// `icons` / `checkable`: some row of the menu has an icon / is checkable.
    fn render(self, focus: &FocusHandle, icons: bool, checkable: bool, cx: &App) -> Stateful<Div> {
        let theme = cx.theme();
        let (id, muted) = (self.id.clone(), theme.muted_foreground);
        let label_id = format!("{}-label", self.id);
        let checked_id = format!("{}-checked", self.id);
        // Rows stretch to the panel, which is as wide as its widest row.
        h_flex()
            .id(self.id)
            .debug_selector(move || id.to_string())
            .track_focus(focus)
            .tab_index(0)
            .h(crate::theme::scaled(28., cx))
            // Insets count from the row's edge: the focus ring's border is part of them.
            .pl(px(MENU_ROW_PAD - FOCUS_RING_WIDTH))
            .pr(px(if checkable {
                MENU_ROW_PAD
            } else {
                MENU_TRAIL_PAD
            } - FOCUS_RING_WIDTH))
            .rounded(theme.radius)
            .text_sm()
            .clickable()
            .hover(|style| style.bg(theme.accent))
            .active(|style| style.bg(theme.primary.opacity(0.16)))
            .map(|row| focus_ring(row, cx))
            .when(icons, |row| {
                row.child(
                    h_flex()
                        .flex_none()
                        .w(px(MENU_ICON_SLOT))
                        .mr(px(MENU_ICON_GAP))
                        .justify_center()
                        .children(
                            self.icon
                                .map(|icon| Icon::new(icon).size_4().text_color(muted)),
                        ),
                )
            })
            .child(
                gpui::div()
                    .debug_selector(move || label_id)
                    .flex_1()
                    .min_w_0()
                    .truncate()
                    .child(self.label),
            )
            .when_some(self.hint, |row, hint| {
                row.child(
                    gpui::div()
                        .flex_none()
                        .ml(px(MENU_TRAIL_GAP))
                        .text_xs()
                        .text_color(muted)
                        .child(hint),
                )
            })
            .when(checkable, |row| {
                row.child(
                    h_flex()
                        .flex_none()
                        .w(px(MENU_CHECK_COL))
                        .ml(px(MENU_TRAIL_GAP))
                        .when(self.checked == Some(true), |col| {
                            col.child(
                                gpui::div()
                                    .debug_selector(move || checked_id)
                                    .child(Icon::new(IconName::Check).size_4()),
                            )
                        }),
                )
            })
            .when_some(self.on_click, |row, f| {
                row.on_click(move |event, window, cx| f(event, window, cx))
            })
    }
}

/// Focus handles of one menu popover: the panel and one per row, kept across frames.
struct MenuFocus {
    panel: FocusHandle,
    rows: Vec<FocusHandle>,
}

impl MenuFocus {
    fn row(&mut self, ix: usize, cx: &mut App) -> FocusHandle {
        while self.rows.len() <= ix {
            self.rows.push(cx.focus_handle().tab_stop(true));
        }
        self.rows[ix].clone()
    }
}

/// The row to focus after ↑ (`down` false) or ↓ from the focused one; the first or
/// last row while no row has focus. Stops at the ends.
fn menu_step(rows: &[FocusHandle], down: bool, window: &mut Window, cx: &mut App) {
    let Some(last) = rows.len().checked_sub(1) else {
        return;
    };
    let at = rows.iter().position(|h| h.is_focused(window));
    let next = match (at, down) {
        (None, true) => 0,
        (None, false) => last,
        (Some(i), true) => (i + 1).min(last),
        (Some(i), false) => i.saturating_sub(1),
    };
    window.focus(&rows[next], cx);
}

/// A `popover` whose content is a menu panel of `rows` (state-driven like `popover`).
/// Opened from the keyboard (trigger Enter/Space, or app state such as ⌘N) the first
/// row has focus; opened by a click the panel has it and ↓ reaches the first row.
/// ↑/↓ move between rows, Enter/Space activate, Esc reports `on_toggle(false)`.
/// Call during render: the focus handles live in element state keyed by `id`.
#[allow(clippy::too_many_arguments)]
pub fn menu_popover<T: Selectable + IntoElement + 'static>(
    id: impl Into<SharedString>,
    trigger: T,
    anchor: Anchor,
    open: bool,
    on_toggle: impl Fn(bool, &mut Window, &mut App) + 'static,
    rows: impl Fn(&mut Window, &mut App) -> Vec<MenuRow> + 'static,
    window: &mut Window,
    cx: &mut App,
) -> Popover {
    let id: SharedString = id.into();
    let focus = window.use_keyed_state(SharedString::from(format!("{id}-focus")), cx, |_, cx| {
        MenuFocus {
            panel: cx.focus_handle(),
            rows: Vec::new(),
        }
    });
    let first = focus.update(cx, |f, cx| f.row(0, cx));
    let panel = focus.read(cx).panel.clone();
    let panel_id = SharedString::from(format!("{id}-panel"));
    popover(
        id,
        trigger,
        anchor,
        open,
        move |open, window, cx| {
            // The popover has just focused the first row; a click leaves no row focused.
            if open && !window.last_input_was_keyboard() {
                window.focus(&panel, cx);
            }
            on_toggle(open, window, cx);
        },
        move |window, cx| {
            let rows = rows(window, cx);
            let handles: Vec<FocusHandle> = focus.update(cx, |f, cx| {
                (0..rows.len()).map(|ix| f.row(ix, cx)).collect()
            });
            let handles = Rc::new(handles);
            let (up, down) = (handles.clone(), handles.clone());
            let icons = rows.iter().any(|row| row.icon.is_some());
            let checkable = rows.iter().any(|row| row.checked.is_some());
            let panel_id = panel_id.clone();
            // No width: the panel takes its widest row's natural width, like a native menu.
            v_flex()
                .debug_selector(move || panel_id.to_string())
                .track_focus(&focus.read(cx).panel)
                .key_context(MENU_CONTEXT)
                .max_w(px(MENU_MAX_W))
                .gap(px(1.))
                .on_action(move |_: &MenuUp, window, cx| menu_step(&up, false, window, cx))
                .on_action(move |_: &MenuDown, window, cx| menu_step(&down, true, window, cx))
                .children(
                    rows.into_iter()
                        .zip(handles.iter())
                        .map(|(row, handle)| row.render(handle, icons, checkable, cx)),
                )
                .into_any_element()
        },
    )
    .track_focus(&first)
    // gpui-component pads popover content with `p_3`; the caller's style is applied
    // after it, so this replaces it.
    .p(px(4.))
}

thread_local! {
    /// Per window: the focus seen at its last render and whether that focus may draw
    /// a ring (it arrived from the keyboard, and no click since).
    /// Weak, so a removed element's focus is not kept alive (`focused()` would keep
    /// returning it); entries go when their window closes (`forget_closed_windows`).
    static FOCUS_RINGS: std::cell::RefCell<
        std::collections::HashMap<gpui::WindowId, (Option<gpui::WeakFocusHandle>, bool)>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
    /// The window-closed observer is registered (once per app thread).
    static WATCHING_CLOSES: Cell<bool> = const { Cell::new(false) };
    /// `FOCUS_RINGS` for the window being rendered, read by `focus_ring`.
    static RING_ALLOWED: Cell<bool> = const { Cell::new(false) };
}

/// Call at the top of a window's root render, before any `focus_ring`. When focus has
/// moved since the last render, the new focus may draw a ring only if the keyboard
/// moved it (Tab, ⌘1/⌘2, Enter). gpui's own `focus_visible` instead turns on whenever
/// the last input was any key press, so a click-focused column showed a ring after
/// any shortcut (⌃⌘S, ⌘⇧C, a window-tiling key).
pub fn update_focus_ring(window: &Window, cx: &App) {
    let focused = window.focused(cx);
    let id = window.window_handle().window_id();
    let allowed = FOCUS_RINGS.with_borrow_mut(|rings| {
        let entry = rings.entry(id).or_insert((None, false));
        let same = match (&entry.0, &focused) {
            (Some(seen), Some(now)) => seen == now,
            (None, None) => true,
            _ => false,
        };
        if !same {
            entry.1 = focused.is_some() && window.last_input_was_keyboard();
            entry.0 = focused.as_ref().map(gpui::FocusHandle::downgrade);
        }
        entry.1
    });
    RING_ALLOWED.set(allowed);
}

/// Drops a window's ring entry when it closes (item windows on close, lock, vault switch
/// or item deletion). Registers one app-wide observer; later calls do nothing.
pub fn forget_closed_windows(cx: &mut App) {
    if WATCHING_CLOSES.replace(true) {
        return;
    }
    cx.on_window_closed(|_, id| {
        FOCUS_RINGS.with_borrow_mut(|rings| rings.remove(&id));
    })
    .detach();
}

/// Windows that have a ring entry (tests only).
#[cfg(test)]
pub fn focus_ring_windows() -> Vec<gpui::WindowId> {
    FOCUS_RINGS.with_borrow(|rings| rings.keys().copied().collect())
}

/// A click anywhere in the window hides the ring until focus next moves by keyboard.
/// Put on the window's root element (capture phase, so no control can swallow it).
pub fn clear_focus_ring_on_click<E: gpui::InteractiveElement>(el: E) -> E {
    el.capture_any_mouse_down(|_, window, _| {
        let id = window.window_handle().window_id();
        let changed = FOCUS_RINGS.with_borrow_mut(|rings| {
            rings
                .get_mut(&id)
                .is_some_and(|entry| std::mem::replace(&mut entry.1, false))
        });
        if changed {
            window.refresh();
        }
    })
}

/// Whether the focused element of the window last rendered may draw its ring, i.e. focus
/// reached it from the keyboard and no click came since (`update_focus_ring`). The
/// editor's ↑/↓ use it to tell keyboard focus from click focus.
pub fn focus_ring_allowed() -> bool {
    RING_ALLOWED.get()
}

/// Keyboard focus ring (§6): a transparent 1 px border that takes the ring colour while
/// the element is focused, if focus reached it from the keyboard (`update_focus_ring`).
/// Layout does not shift. The element must be focusable.
pub fn focus_ring<E: gpui::InteractiveElement + gpui::Styled>(el: E, cx: &App) -> E {
    let ring = cx.theme().ring;
    let el = el.border_1().border_color(gpui::transparent_black());
    if RING_ALLOWED.get() {
        el.focus(move |style| style.border_color(ring))
    } else {
        el
    }
}

/// Segmented track height at text scale 1 (a `.small()` Button's `h_6` at rem 16).
pub const SEGMENT_TRACK_H: f32 = 24.;
/// Selected pill height at text scale 1.
pub const SEGMENT_PILL_H: f32 = 18.;

/// The selected segment's lift: gpui-component's `raised_shadow` (pub(crate) there).
fn segment_shadow() -> Vec<gpui::BoxShadow> {
    let ink = gpui::hsla(0., 0., 0., 0.1);
    vec![
        gpui::BoxShadow::new(px(0.), px(1.), ink).blur_radius(px(1.5)),
        gpui::BoxShadow::new(px(0.), px(1.), ink)
            .blur_radius(px(1.))
            .spread_radius(px(-1.)),
    ]
}

/// Our segmented control (settings Appearance / Text size / retention, generator
/// tabs). gpui-component's segmented `TabBar` paints its track and selected pill from
/// library defaults that vanish on vault's dark window, so this draws its own: a
/// `bg_elevated` track with a 1 px border and a lighter raised pill for the selection,
/// the height of a `.small()` Button.
///
/// The track is one Tab stop; ←/→ move the selection while it has focus. A click
/// selects without taking focus (like a Button). Re-clicking the selected segment does
/// nothing.
pub fn segmented<L: Into<SharedString>>(
    id: impl Into<SharedString>,
    labels: impl IntoIterator<Item = L>,
    selected: usize,
) -> Segmented {
    Segmented {
        id: id.into(),
        labels: labels.into_iter().map(Into::into).collect(),
        selected,
        on_select: None,
        selector: None,
        name: None,
    }
}

/// [`Segmented::on_select`]'s callback.
type OnSelect = dyn Fn(usize, &mut Window, &mut App);

/// Builder returned by [`segmented`].
#[derive(gpui::IntoElement)]
pub struct Segmented {
    id: SharedString,
    labels: Vec<SharedString>,
    selected: usize,
    on_select: Option<Rc<OnSelect>>,
    selector: Option<&'static str>,
    name: Option<SharedString>,
}

impl Segmented {
    /// Called with the newly chosen index (click or ←/→).
    pub fn on_select(mut self, f: impl Fn(usize, &mut Window, &mut App) + 'static) -> Self {
        self.on_select = Some(Rc::new(f));
        self
    }

    /// Gives each segment the debug selector `"{prefix}: {label}"` and the track
    /// `"{prefix}-track"` (tests).
    pub fn selector(mut self, prefix: &'static str) -> Self {
        self.selector = Some(prefix);
        self
    }

    /// The control's VoiceOver name (usually its row label).
    pub fn aria_label(mut self, name: impl Into<SharedString>) -> Self {
        self.name = Some(name.into());
        self
    }
}

impl gpui::RenderOnce for Segmented {
    fn render(self, _: &mut Window, cx: &mut App) -> impl IntoElement {
        let theme = cx.theme();
        let (normal, strong) = (theme.muted_foreground, theme.foreground);
        let pill = crate::theme::VaultTheme::for_appearance(theme.is_dark()).segment_selected;
        let ring = theme.ring;
        // Every size follows the text size, like the small Button beside it (24 px).
        let size = |v: f32| crate::theme::scaled(v, cx);
        let count = self.labels.len();
        let selected = self.selected.min(count.saturating_sub(1));
        let on_select = self.on_select;

        let keys = on_select.clone();
        let track = h_flex()
            .id("segmented")
            .tab_index(0)
            .when_some(self.name, |el, name| el.aria_label(name))
            .when_some(self.selector, |el, p| {
                el.debug_selector(move || format!("{p}-track"))
            })
            .h(size(SEGMENT_TRACK_H))
            .px(size(3.))
            .gap(size(2.))
            .items_center()
            .bg(theme.secondary)
            .border_1()
            .border_color(theme.border)
            .rounded(theme.radius)
            .when(RING_ALLOWED.get(), |el| {
                el.focus(move |s| s.border_color(ring))
            })
            // A click (segment, padding or gap) leaves focus where it was, like a Button.
            .capture_any_mouse_down(|_, window, _| window.prevent_default())
            .on_key_down(move |ev: &gpui::KeyDownEvent, window, cx| {
                if ev.keystroke.modifiers.modified() || count == 0 {
                    return;
                }
                let next = match ev.keystroke.key.as_str() {
                    "left" => selected.checked_sub(1),
                    "right" => Some(selected + 1).filter(|n| *n < count),
                    _ => return,
                };
                cx.stop_propagation();
                if let (Some(next), Some(f)) = (next, keys.as_ref()) {
                    f(next, window, cx);
                }
            });

        let segments = self.labels.into_iter().enumerate().map(|(ix, label)| {
            let on = ix == selected;
            let click = on_select.clone();
            let selector = self.selector.map(|p| format!("{p}: {label}"));
            gpui::div()
                .id((SharedString::new_static("segment"), ix))
                .aria_label(label.clone())
                .aria_selected(on)
                .h(size(SEGMENT_PILL_H))
                .px(size(9.))
                .flex()
                .items_center()
                .rounded(size(4.))
                .text_sm()
                .when_some(selector, |el, s| el.debug_selector(move || s.clone()))
                // Every segment shows the pointer, like the TabBar it replaced.
                .clickable()
                .when(on, |el| {
                    el.bg(pill).shadow(segment_shadow()).text_color(strong)
                })
                .when(!on, |el| {
                    el.text_color(normal).hover(move |s| s.text_color(strong))
                })
                .on_click(move |_, window, cx| {
                    if let (false, Some(f)) = (on, click.as_ref()) {
                        f(ix, window, cx);
                    }
                })
                .child(label)
        });

        gpui::div()
            .id(gpui::ElementId::Name(self.id))
            .flex_none()
            .child(track.children(segments))
    }
}

/// Shared copyable value area for the main detail view and item windows.
/// Callers supply the value and copy handler; Tab, Enter and Space work like a button.
pub fn copy_value_area(id: impl Into<gpui::ElementId>, what: &str, cx: &App) -> Stateful<Div> {
    let theme = cx.theme();
    let hover = theme.accent.opacity(0.6);
    gpui::div()
        .id(id)
        .tab_index(0)
        .aria_label(SharedString::from(format!("{what}. Click to copy")))
        .flex_1()
        .min_w_0()
        .ml(px(-(4. + FOCUS_RING_WIDTH)))
        .px(px(4.))
        .py(px(2.))
        .rounded(theme.radius)
        .map(|el| focus_ring(el, cx))
        .clickable()
        .hover(move |style| style.bg(hover))
        .tooltip(|window, cx| Tooltip::new("Click to copy").build(window, cx))
}

/// Wrong-password shake of an unlock field (05 §2.2): main unlock screen and backup
/// viewer.
pub const SHAKE: std::time::Duration = std::time::Duration::from_millis(300);
/// Peak horizontal displacement of the shake.
pub const SHAKE_PX: f32 = 4.;

/// Damped sine: two small swings that settle back to 0 at `t = 1`.
pub fn shake_offset(t: f32) -> f32 {
    (t * std::f32::consts::PI * 4.).sin() * SHAKE_PX * (1. - t)
}

/// `field` shaken once per wrong password: keyed on the `failures` counter, so each new
/// failure replays it. Without a failure, or under Reduce Motion, `field` as it is (no
/// wrapper). Tests find the wrapper as `selector`. Only the field moves; the card and
/// buttons keep their positions.
pub fn shake_field(
    field: Div,
    failures: u32,
    reduce_motion: bool,
    selector: &'static str,
) -> AnyElement {
    use gpui::AnimationExt as _;
    if failures == 0 || reduce_motion {
        return field.into_any_element();
    }
    gpui::div()
        .w_full()
        .debug_selector(move || selector.into())
        .child(field.relative().with_animation(
            ("shake", failures as usize),
            gpui::Animation::new(SHAKE),
            |field, t| field.left(px(shake_offset(t))),
        ))
        .into_any_element()
}

/// "Unlocking…" centred over an unlock card's hidden controls (05 §2.2). Put it in a
/// `relative` container with the controls kept `invisible`, so the card keeps its size.
/// `id` is its element id and test selector.
pub fn unlocking_overlay(id: &'static str, cx: &App) -> gpui::Stateful<Div> {
    busy_overlay(id, "Unlocking…", Cover::Hide, cx)
}

/// How a [`busy_overlay`] covers the controls under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cover {
    /// The controls are `invisible` (kept in the layout): the label alone (the unlock
    /// card while verifying).
    Hide,
    /// The controls stay drawn at [`DIMMED_OPACITY`] under a spinner and the label (the
    /// create form while calibrating; owner decision 2026-11-27, option A). The overlay
    /// occludes them, so they take no pointer; the caller keeps focus out of them.
    Dim,
}

/// Opacity of controls under a [`Cover::Dim`] overlay.
pub const DIMMED_OPACITY: f32 = 0.4;

/// Applies `cover` to the controls under a [`busy_overlay`].
pub fn covered<E: gpui::Styled>(controls: E, cover: Cover) -> E {
    match cover {
        Cover::Hide => controls.invisible(),
        Cover::Dim => controls.opacity(DIMMED_OPACITY),
    }
}

/// [`unlocking_overlay`] with another `label`, e.g. the create form's "Calibrating
/// encryption for this Mac…" (05 §2.1). VoiceOver reads the label without the ellipsis.
/// Put the controls through [`covered`] with the same `cover`.
pub fn busy_overlay(
    id: &'static str,
    label: &'static str,
    cover: Cover,
    cx: &App,
) -> gpui::Stateful<Div> {
    let text = gpui::div()
        .text_sm()
        .text_color(cx.theme().muted_foreground)
        .child(label);
    v_flex()
        .absolute()
        .inset_0()
        .items_center()
        .justify_center()
        .id(id)
        .debug_selector(move || id.into())
        .aria_label(label.trim_end_matches('…'))
        .map(|overlay| match cover {
            Cover::Hide => overlay.child(text),
            // Drawn controls stay visible: block the pointer from them and set the
            // line on the card's fill so it reads over the dimmed fields.
            Cover::Dim => overlay.occlude().child(
                h_flex()
                    .gap(px(8.))
                    .px(px(10.))
                    .py(px(4.))
                    .rounded(cx.theme().radius)
                    .bg(cx.theme().popover)
                    .child(gpui_component::spinner::Spinner::new())
                    .child(text),
            ),
        })
}

/// Transient copy feedback, positioned consistently over either detail host.
pub fn detail_copy_feedback(message: impl Into<SharedString>, cx: &App) -> Div {
    h_flex()
        .debug_selector(|| "detail-copy-feedback".into())
        .absolute()
        .bottom(px(20.))
        .left_0()
        .right_0()
        .justify_center()
        .child(pill(message, cx))
}

/// Empty-state art (05 §2.3): a tinted disc holding `icon`, with an optional `badge` icon
/// in a small bubble at its lower right. Decorative only; the caption carries the meaning.
pub fn illustration(icon: IconName, badge: Option<IconName>, cx: &App) -> Div {
    let theme = cx.theme();
    let disc = gpui::div()
        .size_full()
        .rounded_full()
        .bg(theme.primary.opacity(0.10))
        .border_1()
        .border_color(theme.primary.opacity(0.25))
        .flex()
        .items_center()
        .justify_center()
        .child(
            Icon::new(icon)
                .size(px(40.))
                .text_color(theme.primary.opacity(0.85)),
        );
    let mut art = gpui::div().relative().size(px(88.)).child(disc);
    if let Some(badge) = badge {
        art = art.child(badge_bubble(badge, 32., cx).right(px(-2.)).bottom(px(-2.)));
    }
    art
}

/// The round badge of [`illustration`] and the unlock card (05 §2.3 "Backup viewer"),
/// both 32 px today: `icon` at half the bubble's `side`, in a 2 px ring of the
/// background colour. Absolute; the caller places it.
fn badge_bubble(icon: IconName, side: f32, cx: &App) -> Div {
    let theme = cx.theme();
    gpui::div()
        .absolute()
        .size(px(side))
        .rounded_full()
        .bg(theme.muted)
        .border_2()
        .border_color(theme.background)
        .flex()
        .items_center()
        .justify_center()
        .child(
            Icon::new(icon)
                .size(px(side / 2.))
                .text_color(theme.muted_foreground),
        )
}

/// A static info-coloured tag with no hover, for labels that are not buttons; black text
/// in dark mode (owner decision 2026-11-22). Matches `Tag::info()` at the default size,
/// whose render adds an opacity hover that `refine_style` cannot remove.
pub fn info_label(text: impl Into<SharedString>, cx: &App) -> Div {
    let theme = cx.theme();
    let fg = if theme.mode.is_dark() {
        gpui::black()
    } else {
        theme.info_foreground
    };
    gpui::div()
        .flex()
        .items_center()
        .border_1()
        .line_height(relative(1.25))
        .text_xs()
        .px_2p5()
        .py_1()
        .bg(theme.info)
        .border_color(theme.info)
        .rounded(theme.radius)
        .text_color(fg)
        .child(text.into())
}

/// Side of the app icon on the unlock card, in points (the raster is 2x this).
pub const UNLOCK_ICON_SIZE: f32 = 128.;

/// Side of the unlock card's badge bubble (the backup viewer's read-only eye), in points.
pub const UNLOCK_BADGE_SIZE: f32 = 32.;

/// The unlock screen's card (05 §2.2), shared by the main unlock screen, the backup
/// viewer's password prompt (05 §2.3 "Backup viewer") and the welcome card (05 §2.1).
pub struct UnlockCard {
    /// Test selector prefix: `<prefix>-card`, `-icon`, `-badge`, `-vault-name`,
    /// `-subtitle`.
    pub prefix: &'static str,
    /// What fills the icon box (the main screen's animated wheel, or the still app
    /// icon). The fixed box keeps the card size before the image decodes.
    pub icon: AnyElement,
    /// Side of the icon box: [`UNLOCK_ICON_SIZE`], or 64 on the create form.
    pub icon_size: f32,
    /// A badge at the icon's lower right (the viewer's read-only eye), 32 px.
    pub badge: Option<IconName>,
    pub name: SharedString,
    /// Draw the name as a semibold title in the foreground colour (the welcome card)
    /// instead of the small muted vault name.
    pub title: bool,
    /// A second, smaller muted line under the name.
    pub subtitle: Option<SharedString>,
    /// The field, buttons and links, top to bottom (12 px apart).
    pub controls: Div,
    /// `Some(overlay id)` while verifying: the controls are hidden (kept in the layout,
    /// so the card does not change size) under [`unlocking_overlay`].
    pub unlocking: Option<&'static str>,
}

pub fn unlock_card(parts: UnlockCard, cx: &App) -> Div {
    let UnlockCard {
        prefix,
        icon,
        icon_size,
        badge,
        name,
        title,
        subtitle,
        controls,
        unlocking,
    } = parts;
    let theme = cx.theme();
    let name_color = if title {
        theme.foreground
    } else if theme.mode.is_dark() {
        gpui::rgb(0xb8b8be).into()
    } else {
        theme.muted_foreground
    };
    let icon_box = gpui::div()
        .size(px(icon_size))
        .relative()
        .flex_shrink_0()
        .debug_selector(move || format!("{prefix}-icon"))
        .child(icon)
        .children(badge.map(|badge| {
            // Over the squircle's lower-right corner (the PNG has a transparent margin of
            // about 12 pt): 10 pt past the icon box, so the centre sits 6 pt inside it.
            badge_bubble(badge, UNLOCK_BADGE_SIZE, cx)
                .right(px(-10.))
                .bottom(px(-10.))
                .debug_selector(move || format!("{prefix}-badge"))
        }));
    let names = v_flex()
        .items_center()
        .gap(px(2.))
        .max_w_full()
        .child(
            gpui::div()
                .map(|line| {
                    if title {
                        line.text_lg().font_weight(gpui::FontWeight::SEMIBOLD)
                    } else {
                        line.text_sm()
                    }
                })
                .text_color(name_color)
                .overflow_hidden()
                .text_ellipsis()
                .debug_selector(move || format!("{prefix}-vault-name"))
                .child(name),
        )
        .children(subtitle.map(|line| {
            let text = line.clone();
            gpui::div()
                .text_xs()
                .text_color(theme.muted_foreground)
                .overflow_hidden()
                .text_ellipsis()
                // Tests read the line from its key (no painted-text API).
                .debug_selector(move || format!("{prefix}-subtitle {text}"))
                .child(line)
        }));
    let controls = controls
        .w_full()
        .gap(px(12.))
        // Hidden, not removed: the card keeps its size and nothing jumps. A hidden div
        // paints none of its children, so the field takes no clicks or keys.
        .when(unlocking.is_some(), |controls| controls.invisible());
    card(cx)
        .w(px(360.))
        .gap(px(20.))
        .items_center()
        .debug_selector(move || format!("{prefix}-card"))
        .child(
            v_flex()
                .items_center()
                .gap(px(10.))
                .child(icon_box)
                .child(names),
        )
        .child(
            gpui::div()
                .relative()
                .w_full()
                .child(controls)
                .children(unlocking.map(|id| unlocking_overlay(id, cx))),
        )
}

/// A zero-sized [`probe::Probe`] in test builds; nothing otherwise.
pub fn test_probe(name: &'static str) -> Option<AnyElement> {
    #[cfg(test)]
    {
        Some(probe::Probe(name).into_any_element())
    }
    #[cfg(not(test))]
    {
        let _ = name;
        None
    }
}

/// Test-only element that records, on every frame, its element-id path, whether its
/// element state was fresh (a remount), and its x position. Placed in the list and
/// detail columns to prove they keep their identity and do not jump across a sidebar
/// slide. Zero-sized; not compiled outside tests.
#[cfg(test)]
pub mod probe {
    use std::cell::RefCell;

    use gpui::{
        App, Bounds, Element, ElementId, GlobalElementId, InspectorElementId, IntoElement,
        LayoutId, Pixels, Style, Window,
    };

    /// One frame's record of one probe.
    #[derive(Clone, Debug, PartialEq)]
    pub struct Seen {
        pub name: &'static str,
        pub path: String,
        /// No element state from the previous frame: the element was (re)mounted.
        pub fresh: bool,
        pub x: Option<Pixels>,
    }

    thread_local! {
        static LOG: RefCell<Vec<Seen>> = const { RefCell::new(Vec::new()) };
    }

    /// Takes everything recorded on this thread so far.
    pub fn take() -> Vec<Seen> {
        LOG.with_borrow_mut(std::mem::take)
    }

    pub struct Probe(pub &'static str);

    impl IntoElement for Probe {
        type Element = Self;
        fn into_element(self) -> Self {
            self
        }
    }

    impl Element for Probe {
        type RequestLayoutState = ();
        type PrepaintState = ();

        fn id(&self) -> Option<ElementId> {
            Some(self.0.into())
        }

        fn source_location(&self) -> Option<&'static std::panic::Location<'static>> {
            None
        }

        fn request_layout(
            &mut self,
            id: Option<&GlobalElementId>,
            _: Option<&InspectorElementId>,
            window: &mut Window,
            cx: &mut App,
        ) -> (LayoutId, ()) {
            let id = id.expect("probe has an id");
            let fresh = window.with_element_state(id, |state: Option<()>, _| (state.is_none(), ()));
            LOG.with_borrow_mut(|log| {
                log.push(Seen {
                    name: self.0,
                    path: id.to_string(),
                    fresh,
                    x: None,
                })
            });
            (window.request_layout(Style::default(), [], cx), ())
        }

        fn prepaint(
            &mut self,
            _: Option<&GlobalElementId>,
            _: Option<&InspectorElementId>,
            bounds: Bounds<Pixels>,
            _: &mut (),
            _: &mut Window,
            _: &mut App,
        ) {
            let name = self.0;
            LOG.with_borrow_mut(|log| {
                if let Some(seen) = log.iter_mut().rev().find(|s| s.name == name) {
                    seen.x = Some(bounds.origin.x);
                }
            });
        }

        fn paint(
            &mut self,
            _: Option<&GlobalElementId>,
            _: Option<&InspectorElementId>,
            _: Bounds<Pixels>,
            _: &mut (),
            _: &mut (),
            _: &mut Window,
            _: &mut App,
        ) {
        }
    }
}

#[cfg(test)]
#[path = "ui_menu_tests.rs"]
mod menu_tests;

#[cfg(test)]
#[path = "ui_segmented_tests.rs"]
mod segmented_tests;

/// Only the main window is blurred (05 §5); the backup viewer's options stay opaque.
#[cfg(test)]
#[gpui::test]
fn only_the_main_window_is_blurred(cx: &mut gpui::TestAppContext) {
    use gpui::WindowBackgroundAppearance::{Blurred, Opaque};
    cx.update(|cx| {
        assert_eq!(main_options(None, true, cx).window_background, Blurred);
        assert_eq!(main_window_options(None, cx).window_background, Opaque);
    });
}

#[cfg(test)]
mod pill_tests {
    use gpui::{Hsla, Styled as _, TestAppContext};
    use gpui_component::{ActiveTheme as _, Theme, ThemeMode};

    use super::{danger_pill, pill};
    use crate::theme::VaultTheme;

    /// (fill, border, text) as set on the built pill's style.
    fn colours(mut el: gpui::Div) -> (Hsla, Hsla, Hsla) {
        let style = el.style();
        let fill = style
            .background
            .as_ref()
            .and_then(|f| f.color())
            .and_then(|b| b.as_solid())
            .expect("solid fill");
        let border = style.border_color.expect("border colour");
        let text = style.text.color.expect("text colour");
        (fill, border, text)
    }

    fn hex(value: u32) -> Hsla {
        gpui::rgb(value).into()
    }

    /// The library theme in `mode` with our danger token (the pills read `theme.danger`).
    fn set_mode(mode: ThemeMode, cx: &mut TestAppContext) {
        cx.update(gpui_component::init);
        cx.update(|cx| {
            Theme::change(mode, None, cx);
            Theme::global_mut(cx).danger = VaultTheme::for_appearance(mode.is_dark()).danger;
        });
    }

    /// Owner decision 2026-11-21, option A: light mode draws the dark palette's pill.
    #[gpui::test]
    fn pill_uses_dark_palette_in_light_mode(cx: &mut TestAppContext) {
        set_mode(ThemeMode::Light, cx);
        let dark = VaultTheme::for_appearance(true);
        cx.update(|cx| {
            assert!(!cx.theme().is_dark());
            let (fill, border, text) = colours(pill("Copied", cx));
            assert_eq!(fill, dark.bg_elevated);
            assert_eq!(border, dark.border);
            assert_eq!(text, dark.text);
            assert_eq!(
                (fill, text, border),
                (hex(0x2A2A2D), hex(0xF2F2F7), hex(0x38383B))
            );
        });
    }

    /// Dark mode draws the light palette's pill.
    #[gpui::test]
    fn pill_uses_light_palette_in_dark_mode(cx: &mut TestAppContext) {
        set_mode(ThemeMode::Dark, cx);
        let light = VaultTheme::for_appearance(false);
        cx.update(|cx| {
            assert!(cx.theme().is_dark());
            let (fill, border, text) = colours(pill("Copied", cx));
            assert_eq!(fill, light.bg_elevated);
            assert_eq!(border, light.border);
            assert_eq!(text, light.text);
            assert_eq!(
                (fill, text, border),
                (hex(0xF7F7F8), hex(0x1D1D1F), hex(0xE5E5EA))
            );
        });
    }

    /// The danger pill keeps the inverted fill (light mode darkened past the dark
    /// palette's) and the danger border; its text is danger in light mode and the
    /// darker same-hue shade in dark mode (N6).
    #[gpui::test]
    fn danger_pill_inverts_fill_only(cx: &mut TestAppContext) {
        for (mode, dark) in [(ThemeMode::Light, false), (ThemeMode::Dark, true)] {
            set_mode(mode, cx);
            cx.update(|cx| {
                let danger = cx.theme().danger;
                assert_eq!(danger, hex(0xE5484D));
                let (fill, border, text) = colours(danger_pill("Not saved", cx));
                let (expected_fill, expected_text) = if dark {
                    (
                        VaultTheme::for_appearance(false).bg_elevated,
                        hex(super::DANGER_PILL_TEXT_IN_DARK),
                    )
                } else {
                    (hex(super::DANGER_PILL_FILL_IN_LIGHT), danger)
                };
                assert_eq!(fill, expected_fill);
                assert_ne!(fill, cx.theme().background, "{mode:?}: still inverted");
                assert_eq!(border, danger);
                assert_eq!(text, expected_text);
                // Same hue and saturation as danger (to 8-bit rounding), only darker.
                assert!((text.h - danger.h).abs() < 0.005, "{mode:?} hue");
                assert!((text.s - danger.s).abs() < 0.01, "{mode:?} saturation");
                assert!(text.l <= danger.l, "{mode:?} lightness");
            });
        }
    }

    /// WCAG 2 relative luminance of an sRGB colour.
    fn luminance(c: Hsla) -> f32 {
        let c = c.to_rgb();
        let lin = |v: f32| {
            if v <= 0.04045 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b)
    }

    /// WCAG 2 contrast ratio of two colours.
    fn contrast(a: Hsla, b: Hsla) -> f32 {
        let (a, b) = (luminance(a), luminance(b));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    /// Bug hunt 2026-11-21 N6: the danger pill's text reaches WCAG 4.5:1 on its fill
    /// in both appearances.
    #[gpui::test]
    fn danger_pill_text_contrast(cx: &mut TestAppContext) {
        for mode in [ThemeMode::Light, ThemeMode::Dark] {
            set_mode(mode, cx);
            cx.update(|cx| {
                let (fill, _, text) = colours(danger_pill("Not saved", cx));
                let ratio = contrast(text, fill);
                assert!(ratio >= 4.5, "{mode:?}: {ratio}");
            });
        }
    }
}

#[cfg(test)]
mod strength_tests {
    use super::{STRENGTH_FULL_BITS, strength_fill, strength_label};

    /// 05 §2.1, option B (Weak eased to 36 on 2026-11-17): Weak < 36, Fair < 50, Good < 56, Strong ≥ 56, bar full at 64.
    #[test]
    fn strength_buckets_follow_option_b() {
        assert_eq!(strength_label(0.), ("Empty", 0));
        assert_eq!(strength_label(0.5), ("Weak", 0));
        assert_eq!(strength_label(35.9), ("Weak", 0));
        assert_eq!(strength_label(36.), ("Fair", 1));
        assert_eq!(strength_label(39.9), ("Fair", 1));
        assert_eq!(strength_label(40.), ("Fair", 1));
        assert_eq!(strength_label(49.9), ("Fair", 1));
        assert_eq!(strength_label(50.), ("Good", 2));
        assert_eq!(strength_label(55.9), ("Good", 2));
        assert_eq!(strength_label(56.), ("Strong", 3));
        assert_eq!(strength_label(64.), ("Strong", 3));
        assert_eq!(strength_label(127.5), ("Strong", 3));

        assert_eq!(STRENGTH_FULL_BITS, 64.);
        assert_eq!(strength_fill(0.), 0.);
        assert_eq!(strength_fill(32.), 0.5);
        assert_eq!(strength_fill(64.), 1.);
        assert_eq!(strength_fill(127.5), 1.);
    }
}
