//! Vault design tokens (specs/05-ui.md §5) layered on top of gpui-component's theme.
//!
//! gpui-component keeps one global `Theme`. `Theme::change` reloads the registered
//! light/dark config and wipes any field edits. So we always go through [`apply`]:
//! sync the mode with the window appearance first, then overwrite our tokens via
//! `Theme::update`.
//!
//! The accent follows the macOS accent colour when [`AccentSource`] yields one; the
//! spec blues are the fallback.

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

/// Near-black label used on light accent fills (the light theme's `text`).
const DARK_ACCENT_TEXT: u32 = 0x1D1D1F;
/// White label, the default on accent fills.
const LIGHT_ACCENT_TEXT: u32 = 0xFFFFFF;
/// Below this white-on-accent contrast the label flips to near-black. Chosen to match
/// native macOS, which keeps white labels on every accent but yellow: 4.5:1 or 3:1
/// would also flip red, pink, graphite (4.5) and orange, green (3:1, about 2.4-2.6:1).
const MIN_CONTRAST: f32 = 2.0;

/// WCAG 2 relative luminance of an opaque sRGB colour.
fn relative_luminance(color: Hsla) -> f32 {
    let c = color.to_rgb();
    let lin = |v: f32| {
        if v <= 0.040_45 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b)
}

/// WCAG 2 contrast ratio between two colours (1.0 to 21.0).
fn contrast(a: Hsla, b: Hsla) -> f32 {
    let (la, lb) = (relative_luminance(a), relative_luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// Label colour for an accent fill: white, unless white falls below [`MIN_CONTRAST`]
/// and near-black reaches it (05 §5). In practice only a yellow accent flips.
pub fn text_on_accent(accent: Hsla) -> Hsla {
    let light = hex(LIGHT_ACCENT_TEXT);
    let dark = hex(DARK_ACCENT_TEXT);
    if contrast(accent, light) < MIN_CONTRAST && contrast(accent, dark) >= MIN_CONTRAST {
        dark
    } else {
        light
    }
}

/// Where the accent colour comes from. The app installs [`AccentSource::system`];
/// tests install a plain function so they never touch AppKit. Without a global, the
/// accent falls back to the spec values (and in tests stays there).
#[derive(Clone, Copy)]
pub struct AccentSource(pub fn() -> Option<Hsla>);

impl Global for AccentSource {}

impl AccentSource {
    /// `NSColor.controlAccentColor` via `vault-macos` (main thread only; `None` elsewhere).
    /// Unused in test builds, which inject a fake.
    #[cfg_attr(test, allow(dead_code))]
    pub fn system() -> Self {
        Self(system_accent)
    }
}

#[cfg_attr(test, allow(dead_code))]
fn system_accent() -> Option<Hsla> {
    vault_macos::system_accent_color().map(|c| {
        // Accent fills are opaque; ignore any alpha AppKit reports.
        gpui::Rgba {
            r: c.r,
            g: c.g,
            b: c.b,
            a: 1.0,
        }
        .into()
    })
}

/// The current accent override, if any.
fn current_accent(cx: &App) -> Option<Hsla> {
    cx.try_global::<AccentSource>()
        .and_then(|source| (source.0)())
}

impl VaultTheme {
    pub fn for_appearance(dark: bool) -> Self {
        let shared =
            |accent, bg, bg_sidebar, sidebar_vibrancy, bg_elevated, border, text, muted| Self {
                accent: hex(accent),
                accent_text: hex(LIGHT_ACCENT_TEXT),
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

    /// Replaces the spec accent with `accent` (the system accent) when given, and picks
    /// a readable label colour for it.
    pub fn with_accent(mut self, accent: Option<Hsla>) -> Self {
        if let Some(accent) = accent {
            self.accent = accent;
            self.accent_text = text_on_accent(accent);
        }
        self
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
    let mut tokens = VaultTheme::for_appearance(dark).with_accent(current_accent(cx));
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
        primary_button_fill_with(appearance, None, cx)
    }

    /// Like [`primary_button_fill`] with `source` installed as the accent source.
    fn primary_button_fill_with(
        appearance: Appearance,
        source: Option<AccentSource>,
        cx: &mut TestAppContext,
    ) -> Hsla {
        cx.update(gpui_component::init);
        cx.update(|cx| {
            cx.set_global(ThemePrefs {
                appearance,
                scale: 1.0,
            });
            if let Some(source) = source {
                cx.set_global(source);
            }
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

    /// A saturated red like the macOS "Red" accent.
    fn red() -> Option<Hsla> {
        Some(hex(0xE0383E))
    }

    /// A yellow like the macOS "Yellow" accent.
    fn yellow() -> Option<Hsla> {
        Some(hex(0xFFC600))
    }

    fn no_accent() -> Option<Hsla> {
        None
    }

    #[gpui::test]
    fn primary_button_follows_system_accent_light(cx: &mut TestAppContext) {
        let fill = primary_button_fill_with(Appearance::Light, Some(AccentSource(red)), cx);
        assert_eq!(fill, hex(0xE0383E));
    }

    #[gpui::test]
    fn primary_button_follows_system_accent_dark(cx: &mut TestAppContext) {
        let fill = primary_button_fill_with(Appearance::Dark, Some(AccentSource(red)), cx);
        assert_eq!(fill, hex(0xE0383E));
    }

    #[gpui::test]
    fn no_system_accent_uses_spec_fallback(cx: &mut TestAppContext) {
        let light = primary_button_fill_with(Appearance::Light, Some(AccentSource(no_accent)), cx);
        assert_eq!(light, hex(0x3B6CF0));
        cx.update(|cx| {
            cx.set_global(ThemePrefs {
                appearance: Appearance::Dark,
                scale: 1.0,
            });
            reapply(cx);
            assert_eq!(Theme::global(cx).button_primary, hex(0x5B8CFF));
        });
    }

    #[gpui::test]
    fn yellow_accent_gets_dark_label(cx: &mut TestAppContext) {
        let fill = primary_button_fill_with(Appearance::Light, Some(AccentSource(yellow)), cx);
        assert_eq!(fill, hex(0xFFC600));
        cx.update(|cx| {
            let theme = Theme::global(cx);
            assert_eq!(theme.button_primary_foreground, hex(DARK_ACCENT_TEXT));
            assert_eq!(theme.primary_foreground, hex(DARK_ACCENT_TEXT));
        });
    }

    #[gpui::test]
    fn accent_change_reapplies(cx: &mut TestAppContext) {
        primary_button_fill_with(Appearance::Light, Some(AccentSource(red)), cx);
        cx.update(|cx| {
            cx.set_global(AccentSource(yellow));
            reapply(cx);
            assert_eq!(Theme::global(cx).button_primary, hex(0xFFC600));
        });
    }

    #[test]
    fn label_contrast_on_accents() {
        let white = hex(LIGHT_ACCENT_TEXT);
        let dark = hex(DARK_ACCENT_TEXT);
        // Yellow: white is unreadable, near-black is fine.
        assert_eq!(text_on_accent(hex(0xFFC600)), dark);
        assert!(contrast(hex(0xFFC600), dark) >= MIN_CONTRAST);
        // Red (macOS "Red" accent) keeps white, like native controls.
        assert_eq!(text_on_accent(hex(0xE0383E)), white);
        assert_eq!(text_on_accent(hex(0xFF5257)), white);
        // Orange and green keep white too (native macOS labels).
        assert_eq!(text_on_accent(hex(0xF7821B)), white);
        assert_eq!(text_on_accent(hex(0x62BA46)), white);
        // Spec light blue passes with white.
        assert_eq!(text_on_accent(hex(0x3B6CF0)), white);
        // A dark accent keeps white.
        assert_eq!(text_on_accent(hex(0x1F3A93)), white);
        // Reference points: black/white is 21:1, equal colours 1:1.
        assert!((contrast(hex(0x000000), white) - 21.0).abs() < 0.01);
        assert!((contrast(white, white) - 1.0).abs() < 0.001);
        // Spec dark blue also clears 3:1 with white.
        assert_eq!(text_on_accent(hex(0x5B8CFF)), white);
        // Spec fallback tokens are unaffected by the label rule.
        assert_eq!(
            VaultTheme::for_appearance(true)
                .with_accent(None)
                .accent_text,
            white
        );
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
