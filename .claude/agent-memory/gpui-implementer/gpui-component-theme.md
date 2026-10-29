---
name: gpui-component-theme
description: How to override gpui-component 0.8.1 theme colors safely and follow system light/dark
metadata:
  type: reference
---

gpui-component 0.8.1 theme facts (see [[gpui-api-facts]]):
- Global `gpui_component::Theme` derefs to `ThemeColor`, so you can write `theme.background`, `theme.primary`, etc. Other fields: `mode: ThemeMode`, `font_family`, `font_size` (default 16px), `mono_font_family`, `mono_font_size`, `radius`, `radius_lg`, `shadow`, `focus_ring`.
- ThemeColor names follow shadcn: background, foreground, border, input, ring, primary(+_foreground/_hover/_active), secondary, muted, muted_foreground, accent (hover bg, not brand), popover, sidebar*, title_bar*, danger, warning, success, info, link, list*, table*.
- `Theme::change(mode, Option<&mut Window>, cx)` and `Theme::sync_system_appearance(Some(window), cx)` RELOAD the registered config and wipe field edits.
- Override with `Theme::update(cx, |theme| ..)` AFTER every sync. vault does this in `theme::apply(window, cx)`, called on window open and from `observe_window_appearance`.
- Read with `cx.theme()` (trait `ActiveTheme`). `Theme::global(cx).is_dark()`.
- Explicit `mono_font_family` is used as-is with no fallback, so check `cx.text_system().all_font_names()` first.
- Alternative not yet tried: register a custom `ThemeConfig` (JSON with "mode", "colors", "radius") in `ThemeRegistry` and set `theme.light_theme` / `dark_theme`.
- `Theme` also has `tokens: ThemeTokens` (legacy component tokens, e.g. `tokens.sidebar`, `tokens.sidebar_accent`). Editing `theme.sidebar` does not update `theme.tokens.sidebar`; widgets that read `tokens` ignore our overrides.
- Button (0.8.1) paints primary fill from `theme.tokens.button_primary` / `_hover` / `_active` (src/button/button.rs bg_color/hovered/active) and text from `theme.button_primary_foreground`; only outline/border use `theme.primary`. `Theme::update` reconciles each edited ThemeColor field into its OWN token only, so set `theme.button_primary*` (ThemeColor fields) explicitly; editing `primary` leaves buttons near-black (light) / near-white (dark). The config derived button_primary from primary at load time (schema.rs ~815). vault sets them in `theme::write_into` (fixed 2026-10-29).
- Dark default `primary_foreground` is neutral-900, so a blue primary needs `primary_foreground` set too. Config fallbacks: hover = `background.blend(primary.opacity(0.9))`, active = `primary.darken(0.1 light / 0.2 dark)` (`Colorize` trait, `gpui_component::Colorize`).
- Brand accent is `theme.primary` (+ `primary_foreground`). `theme.accent` is the hover background. Focus ring colour is `theme.ring`.
