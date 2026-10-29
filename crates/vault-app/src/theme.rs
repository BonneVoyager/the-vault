//! Vault design tokens (specs/05-ui.md §5) layered on top of gpui-component's theme.
//!
//! gpui-component keeps one global `Theme`. `Theme::change` reloads the registered
//! light/dark config and wipes any field edits. So we always go through [`apply`]:
//! sync the mode with the window appearance first, then overwrite our tokens via
//! `Theme::update`.

use gpui::{App, Global, Hsla, Pixels, SharedString, Window, WindowAppearance, px, rgb};
use gpui_component::{Colorize as _, Theme, ThemeMode};

use crate::state::{Appearance, Settings};

/// gpui's default rem (16 px); scaled by the text size step.
const BASE_REM: f32 = 16.;

/// The user's appearance override and text scale (05 §5, §6), read by [`apply`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThemePrefs {
    pub appearance: Appearance,
    pub scale: f32,
}

impl Default for ThemePrefs {
    fn default() -> Self {
        Self {
            appearance: Appearance::System,
            scale: 1.0,
        }
    }
}

impl Global for ThemePrefs {}

/// Stores the prefs from `settings`; takes effect at the next [`apply`] / [`reapply`].
pub fn set_prefs(settings: &Settings, cx: &mut App) {
    cx.set_global(ThemePrefs {
        appearance: settings.appearance,
        scale: settings.text_size.scale(),
    });
}

fn prefs(cx: &App) -> ThemePrefs {
    cx.try_global::<ThemePrefs>().copied().unwrap_or_default()
}

/// Text scale factor (1.0, 1.15, 1.3).
pub fn scale(cx: &App) -> f32 {
    prefs(cx).scale
}

/// `value` px times the text scale: row heights and other fixed sizes that track text.
pub fn scaled(value: f32, cx: &App) -> Pixels {
    px(value * scale(cx))
}

/// The rem size for the current text scale. Each window root sets it in `render`, so
/// every rem-based size (text_sm, spacing) follows the step.
pub fn rem_size(cx: &App) -> Pixels {
    px(BASE_REM * scale(cx))
}

fn mode(appearance: Appearance, system: WindowAppearance) -> ThemeMode {
    match appearance {
        Appearance::System => system.into(),
        Appearance::Light => ThemeMode::Light,
        Appearance::Dark => ThemeMode::Dark,
    }
}

/// Preferred monospace family, used when installed.
const MONO_PREFERRED: &str = "SF Mono";
/// Fallback monospace family, always present on macOS.
const MONO_FALLBACK: &str = "Menlo";

/// The vault colour and shape tokens for one appearance.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VaultTheme {
    pub accent: Hsla,
    /// Text on an accent fill (primary buttons).
    pub accent_text: Hsla,
    pub bg: Hsla,
    /// Opaque stand-in for the sidebar. See `sidebar_vibrancy`.
    pub bg_sidebar: Hsla,
    /// The spec asks for vibrancy behind the sidebar in light mode. Not wired yet:
    /// it needs a blurred window background plus a translucent sidebar.
    pub sidebar_vibrancy: bool,
    pub bg_elevated: Hsla,
    pub border: Hsla,
    pub text: Hsla,
    pub text_muted: Hsla,
    pub danger: Hsla,
    pub warning: Hsla,
    pub success: Hsla,
    /// Panels, dialogs, popovers.
    pub radius_panel: Pixels,
    /// Inputs and buttons.
    pub radius_control: Pixels,
    /// Base UI font size (13 pt per spec, times the text scale).
    pub font_size: Pixels,
}

fn hex(value: u32) -> Hsla {
    rgb(value).into()
}

impl VaultTheme {
    pub fn for_appearance(dark: bool) -> Self {
        let shared =
            |accent, bg, bg_sidebar, sidebar_vibrancy, bg_elevated, border, text, muted| Self {
                accent: hex(accent),
                accent_text: hex(0xFFFFFF),
                bg: hex(bg),
                bg_sidebar: hex(bg_sidebar),
                sidebar_vibrancy,
                bg_elevated: hex(bg_elevated),
                border: hex(border),
                text: hex(text),
                text_muted: hex(muted),
                danger: hex(0xE5484D),
                warning: hex(0xF5A524),
                success: hex(0x30A46C),
                radius_panel: px(8.),
                radius_control: px(6.),
                font_size: px(13.),
            };
        if dark {
            shared(
                0x5B8CFF, 0x1C1C1E, 0x232326, false, 0x2A2A2D, 0x38383B, 0xF2F2F7, 0x98989D,
            )
        } else {
            shared(
                0x3B6CF0, 0xFFFFFF, 0xF5F5F7, true, 0xF7F7F8, 0xE5E5EA, 0x1D1D1F, 0x6E6E73,
            )
        }
    }

    /// Writes these tokens into gpui-component's global theme.
    fn write_into(&self, theme: &mut Theme, mono: SharedString) {
        theme.background = self.bg;
        theme.foreground = self.text;
        theme.border = self.border;
        theme.input = self.border;
        theme.ring = self.accent;
        theme.primary = self.accent;
        // gpui-component's Button paints its primary fill from `tokens.button_primary*`,
        // which the theme config derived from the stock (near-black) primary at load
        // time. Editing `primary` alone reaches `tokens.primary` but not these, so set
        // the button fields too. Hover/active use gpui-component's own fallback rules.
        let dark = theme.mode.is_dark();
        let hover = self.bg.blend(self.accent.opacity(0.9));
        let active = self.accent.darken(if dark { 0.2 } else { 0.1 });
        theme.primary_foreground = self.accent_text;
        theme.primary_hover = hover;
        theme.primary_active = active;
        theme.button_primary = self.accent;
        theme.button_primary_foreground = self.accent_text;
        theme.button_primary_hover = hover;
        theme.button_primary_active = active;
        theme.link = self.accent;
        theme.muted = self.bg_elevated;
        theme.muted_foreground = self.text_muted;
        theme.secondary = self.bg_elevated;
        theme.popover = self.bg_elevated;
        theme.popover_foreground = self.text;
        theme.sidebar = self.bg_sidebar;
        theme.sidebar_foreground = self.text;
        theme.sidebar_border = self.border;
        theme.sidebar_primary = self.accent;
        theme.title_bar = self.bg_sidebar;
        theme.title_bar_border = self.border;
        theme.danger = self.danger;
        theme.warning = self.warning;
        theme.success = self.success;
        theme.radius = self.radius_control;
        theme.radius_lg = self.radius_panel;
        theme.font_size = self.font_size;
        theme.mono_font_family = mono;
    }
}

/// Picks "SF Mono" if the system exposes it by name, else Menlo.
fn mono_family(cx: &App) -> SharedString {
    let installed = cx
        .text_system()
        .all_font_names()
        .iter()
        .any(|name| name == MONO_PREFERRED);
    if installed {
        MONO_PREFERRED.into()
    } else {
        MONO_FALLBACK.into()
    }
}

/// Sets gpui-component's mode from the window appearance (or the override) and applies
/// our tokens.
///
/// Call once after opening a window and again from `observe_window_appearance`.
pub fn apply(window: &mut Window, cx: &mut App) {
    let system = window.appearance();
    apply_mode(system, cx);
}

/// [`apply`] without a window: after a Settings change. Redraws every window.
pub fn reapply(cx: &mut App) {
    let system = cx.window_appearance();
    apply_mode(system, cx);
    cx.refresh_windows();
}

fn apply_mode(system: WindowAppearance, cx: &mut App) {
    let prefs = prefs(cx);
    Theme::change(mode(prefs.appearance, system), None, cx);
    let dark = Theme::global(cx).is_dark();
    let mut tokens = VaultTheme::for_appearance(dark);
    tokens.font_size = px(tokens.font_size.as_f32() * prefs.scale);
    let mono = mono_family(cx);
    Theme::update(cx, |theme| tokens.write_into(theme, mono));
}

#[cfg(test)]
mod tests {
    use gpui::{
        AppContext as _, Context, InteractiveElement as _, IntoElement, ParentElement as _, Render,
        Styled as _, TestAppContext, VisualTestContext, div,
    };
    use gpui_component::Root;
    use gpui_component::button::{Button, ButtonVariants as _};

    use super::*;

    struct PrimaryButton;

    impl Render for PrimaryButton {
        fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
            div().p_4().child(
                div()
                    .flex()
                    .debug_selector(|| "primary-button".into())
                    .child(Button::new("go").primary().label("Go")),
            )
        }
    }

    /// The solid fill of the largest quad painted inside the primary button.
    fn primary_button_fill(appearance: Appearance, cx: &mut TestAppContext) -> Hsla {
        cx.update(gpui_component::init);
        cx.update(|cx| {
            cx.set_global(ThemePrefs {
                appearance,
                scale: 1.0,
            })
        });
        let window = cx.add_window(|window, cx| {
            apply(window, cx);
            let view = cx.new(|_| PrimaryButton);
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        vcx.run_until_parked();
        let area = vcx.debug_bounds("primary-button").expect("button rendered");
        vcx.update(|window, _| {
            let area = area.scale(window.scale_factor());
            window
                .painted_quads()
                .into_iter()
                .filter(|q| area.intersect(&q.bounds) == q.bounds)
                .max_by(|a, b| {
                    let size = |q: &gpui::Quad| q.bounds.size.width.0 * q.bounds.size.height.0;
                    size(a).total_cmp(&size(b))
                })
                .and_then(|q| q.background.as_solid())
                .expect("button paints a solid fill")
        })
    }

    #[gpui::test]
    fn primary_button_uses_accent_light(cx: &mut TestAppContext) {
        let fill = primary_button_fill(Appearance::Light, cx);
        assert_eq!(fill, VaultTheme::for_appearance(false).accent);
        assert_eq!(fill, hex(0x3B6CF0));
    }

    #[gpui::test]
    fn primary_button_uses_accent_dark(cx: &mut TestAppContext) {
        let fill = primary_button_fill(Appearance::Dark, cx);
        assert_eq!(fill, VaultTheme::for_appearance(true).accent);
        assert_eq!(fill, hex(0x5B8CFF));
    }

    #[test]
    fn override_beats_system() {
        let dark = WindowAppearance::Dark;
        assert_eq!(mode(Appearance::System, dark), ThemeMode::Dark);
        assert_eq!(mode(Appearance::Light, dark), ThemeMode::Light);
        assert_eq!(
            mode(Appearance::Dark, WindowAppearance::Light),
            ThemeMode::Dark
        );
    }
}
