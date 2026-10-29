//! Thin wrappers over gpui / gpui-component calls used across the app.
//!
//! gpui is pre-1.0. Keep every upstream call that more than two views need in here,
//! so an upstream rename is a one-file fix.

use std::cell::Cell;
use std::path::{Path, PathBuf};

use gpui::{
    Anchor, AnyElement, App, AppContext as _, Bounds, ClickEvent, Context, Div, Entity,
    InteractiveElement as _, IntoElement, MouseButton, ParentElement as _, PathPromptOptions,
    Pixels, Point, Render, Result, SharedString, Styled as _, Task, TitlebarOptions, Window,
    WindowBounds, WindowHandle, WindowOptions, point, prelude::FluentBuilder as _, px, relative,
    size,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{Input, InputState, TextareaState};
use gpui_component::popover::Popover;
use gpui_component::{ActiveTheme as _, Icon, Root, Selectable, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{ExposeSecret as _, PassphraseSpec, SecretString, passphrase, strength_bits};

pub use gpui_component::{h_flex, v_flex};

use crate::persist::WindowState;

/// Default and minimum main window size (specs/05-ui.md §1).
const MAIN_DEFAULT: (f32, f32) = (1100., 720.);
const MAIN_MIN: (f32, f32) = (820., 520.);
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
/// Height of the sidebar and list footers, including their 1 px top divider. Scaled with
/// the text size (`theme::scaled`) in both columns so they always match.
pub const FOOTER_HEIGHT: f32 = 44.;
/// Width of the transparent border `focus_ring` adds; content inside a focus-ringed
/// column is inset by it.
pub const FOCUS_RING_WIDTH: f32 = 1.;

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
    let bounds = match restore {
        Some(s) => Bounds::new(
            point(px(s.x), px(s.y)),
            size(px(s.width.max(MAIN_MIN.0)), px(s.height.max(MAIN_MIN.1))),
        ),
        None => Bounds::centered(None, size(px(MAIN_DEFAULT.0), px(MAIN_DEFAULT.1)), cx),
    };
    WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        window_min_size: Some(size(px(MAIN_MIN.0), px(MAIN_MIN.1))),
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
pub fn open_main_window<V: Render>(
    restore: Option<WindowState>,
    cx: &mut App,
    build: impl FnOnce(&mut Window, &mut App) -> Entity<V>,
) -> Result<WindowHandle<Root>> {
    let options = main_window_options(restore, cx);
    cx.open_window(options, |window, cx| {
        let view = build(window, cx);
        cx.new(|cx| Root::new(view, window, cx))
    })
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
    let rx = cx.prompt_for_paths(PathPromptOptions {
        files: !directories,
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

/// The rounded "toast" pill.
pub fn pill(message: impl Into<SharedString>, cx: &App) -> Div {
    let theme = cx.theme();
    gpui::div()
        .px(px(14.))
        .py(px(6.))
        .rounded_full()
        .bg(theme.popover)
        .border_1()
        .border_color(theme.border)
        .shadow_md()
        .text_sm()
        .child(message.into())
}

/// Label and level (0 weak, 1 fair, 2 good, 3 strong) for an entropy estimate.
pub fn strength_label(bits: f64) -> (&'static str, u8) {
    match bits {
        b if b <= 0. => ("Empty", 0),
        b if b < 40. => ("Weak", 0),
        b if b < 60. => ("Fair", 1),
        b if b < 80. => ("Good", 2),
        _ => ("Strong", 3),
    }
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
                        .w(relative((bits / 100.).clamp(0., 1.) as f32)),
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
/// `strength_bits` is the generator's naive length x log2(pool) estimate; 50 bits is our
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

/// Keyboard focus ring (§6): a transparent 1 px border that takes the ring colour on
/// `:focus-visible`, so layout does not shift. The element must be focusable.
pub fn focus_ring<E: gpui::InteractiveElement + gpui::Styled>(el: E, cx: &App) -> E {
    let ring = cx.theme().ring;
    el.border_1()
        .border_color(gpui::transparent_black())
        .focus_visible(move |style| style.border_color(ring))
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
        art = art.child(
            gpui::div()
                .absolute()
                .right(px(-2.))
                .bottom(px(-2.))
                .size(px(32.))
                .rounded_full()
                .bg(theme.muted)
                .border_2()
                .border_color(theme.background)
                .flex()
                .items_center()
                .justify_center()
                .child(Icon::new(badge).size_4().text_color(theme.muted_foreground)),
        );
    }
    art
}

/// Panel transitions (05 §5): 120-180 ms ease-out. Never used on list scrolling.
pub const PANEL_MOTION: std::time::Duration = std::time::Duration::from_millis(150);

/// Fades `el` in while sliding it `slide` px from the left, keyed by `id` (change the id
/// to replay). With Reduce Motion the element appears at once.
pub fn panel_in<E>(
    el: E,
    id: impl Into<gpui::ElementId>,
    slide: f32,
    reduce_motion: bool,
) -> AnyElement
where
    E: IntoElement + gpui::Styled + 'static,
{
    use gpui::AnimationExt as _;
    if reduce_motion {
        return el.into_any_element();
    }
    el.relative()
        .with_animation(
            id,
            gpui::Animation::new(PANEL_MOTION).with_easing(gpui::ease_out_quint()),
            move |el, t| el.opacity(t).left(px(-slide * (1. - t))),
        )
        .into_any_element()
}
