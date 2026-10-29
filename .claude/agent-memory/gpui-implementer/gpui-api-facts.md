---
name: gpui-api-facts
description: Verified gpui-pre 0.3.10 / gpui-component 0.8.1 signatures for app startup, windows, titlebar, Root, flex helpers, appearance
metadata:
  type: reference
---

Verified against gpui-pre 0.3.10 + gpui-component 0.8.1 by compiling (see [[gpui-version-pins]]).

- No `Application::new()`. Use `gpui_platform::application() -> gpui::Application`, then `.with_quit_mode(gpui::QuitMode::LastWindowClosed)`, `.with_assets(..)`, `.run(|cx: &mut App| ..)`. QuitMode::Default = Explicit on macOS.
- `gpui_component::init(cx)` must run first in `run`.
- `cx.open_window(WindowOptions, |window: &mut Window, cx: &mut App| -> Entity<V>) -> gpui::Result<WindowHandle<V>>` (`gpui::Result` = anyhow re-export).
- Root: `gpui_component::Root` (re-exported from gpui-base). Wrap content: `cx.new(|cx| Root::new(view, window, cx))`. `Root::new(view: impl Into<AnyView>, window, cx: &mut Context<Root>)`.
- WindowOptions fields: `window_bounds: Option<WindowBounds>`, `window_min_size: Option<Size<Pixels>>`, `titlebar: Option<TitlebarOptions>`, `app_owns_titlebar_drag: bool` (set true only if rendering gpui_component::TitleBar), `window_background: WindowBackgroundAppearance {Opaque, Transparent, Blurred..}`, `..Default::default()`.
- `TitlebarOptions { title: Option<SharedString>, appears_transparent: bool, traffic_light_position: Option<Point<Pixels>> }`. `TitleBar::title_bar_options()` / `TitleBar::window_options()` give defaults (lights at 9,9).
- `WindowBounds::Windowed(Bounds::centered(None, size(px(w), px(h)), cx))`. `gpui::{size, point, px, rgb}`; `rgb(u32).into() -> Hsla`.
- Flex: `gpui_component::{h_flex, v_flex}` (from gpui-base) and `StyledExt` gives `.v_flex()` on div.
- Appearance: `cx.observe_window_appearance(window, |this, window, cx| ..) -> Subscription` inside `Context<T>`; store the Subscription. `window.appearance()`, `cx.window_appearance()`.
- `cx.activate(true)`, `cx.quit()`, `cx.on_window_closed(|cx, window_id| ..)`.
- Imports that were needed: `gpui::AppContext as _` (for `cx.new`), `ParentElement as _`, `Styled as _`, `gpui_component::ActiveTheme as _` (for `cx.theme()`).
- CGWindowList showed the 1100x720 window at 1078x706. Cause not found, not gpui clamping.

Verified in P2.5 (app shell), all compiled + clippy clean:
- Actions: `gpui::actions!(vault, [Lock, ..])` (doc comments allowed per item). `KeyBinding::new("cmd-l", Lock, None)`; `cx.bind_keys([..])`. Global handler `cx.on_action(|_: &Lock, cx: &mut App| ..)` runs when no focused element handled it; works for menu items too.
- Menus: `cx.set_menus([Menu::new("File").items([MenuItem::action("Lock", Lock), MenuItem::separator()])])`. First menu = app menu.
- Quit hook: `cx.on_app_quit(|cx| async {}) -> Subscription` (call `.detach()`). `window.on_window_should_close(cx: &App, |window, cx| -> bool)`.
- Spawning: `Context::spawn(async move |weak: WeakEntity<T>, cx: &mut AsyncApp| ..)`; `App::spawn(async move |cx: &mut AsyncApp| ..)`. Background: `cx.background_executor().spawn(fut) -> Task<R>` (Send). Timer: `cx.background_executor().timer(Duration).await`. Dropping a Task cancels it (debounce = replace an `Option<Task<()>>`).
- `Entity::update(cx, ..) -> R` (no Result); `WeakEntity::update(cx, ..) -> Result<R>`. `AsyncApp::update(|cx| ..) -> R`.
- Observers: `cx.observe(&e, |this, e, cx|)`, `cx.observe_in(&e, window, |this, e, window, cx|)`, `cx.subscribe_in(&e, window, |this, e, ev: &Evt, window, cx|)`, `cx.observe_window_bounds(window, |this, window, cx|)` fires on resize AND move. `cx.defer_in(window, |this, window, cx|)`.
- Window geometry: `window.window_bounds().get_bounds()` (restore bounds even if fullscreen); `Pixels::as_f32()`; `Bounds::new(point(..), size(..))`.
- Focus: `window.focus(&handle, cx)`, `window.blur(cx)` (both take cx). Setting focus is just id+refresh, safe from observers.
- File dialog: `cx.prompt_for_paths(PathPromptOptions { files, directories, multiple, prompt: Option<SharedString> })` -> futures oneshot `Receiver<Result<Option<Vec<PathBuf>>>>`; await gives `Result<Result<Option<..>>, Canceled>`. Save panel: `cx.prompt_for_new_path(&Path, Option<&str>) -> Receiver<Result<Option<PathBuf>>>`. Wrapped as `ui::pick_path` / `ui::pick_new_path`. `cx.reveal_path(&Path)` = Reveal in Finder; `cx.open_with_system(&Path)`. No rfd needed.
- Animation: `el.with_animation(id, Animation::new(dur).with_easing(ease_out_quint()), |el, t| el.opacity(t))` (`AnimationExt`). State is keyed by element id: use `("name", counter)` to restart; a finished non-repeating animation stays at t=1. Easings: `gpui::{ease_in_out, ease_out_quint(), bounce(..)}`. Repeating: `Animation::new(d).repeat()`. Reduce Motion: `cx.reduce_motion() -> bool` (gpui-base `init`, called by `gpui_component::init`, reads the macOS setting into it; tests never consult the platform).
- Capture activity: `div().id(..).capture_any_mouse_down(cx.listener(..)).capture_key_down(cx.listener(..))`.
- `window.dispatch_action(Box::new(Lock), cx)` from a click handler.
- Tests: dev-dep `gpui = { package = "gpui-pre", version = "=0.3.10", features = ["test-support"] }`; `#[gpui::test] fn t(cx: &mut TestAppContext)`; `cx.new(..)`, `entity.update(cx, ..)`, `entity.read_with(cx, |s, _| ..)`, `cx.run_until_parked()` runs background tasks deterministically.
- Headless launch smoke test: `HOME=<scratch> perl -e 'alarm 6; exec @ARGV' target/debug/vault-app`; exit 142 = alarm, i.e. no panic. `dirs` honours $HOME, so app data lands in the scratch HOME.
See [[gpui-component-widgets]] for widget APIs.

Verified in P2.6 (main screen), compiled + clippy clean + headless render tests:
- Action dispatch with NOTHING focused goes to the root dispatch node only, so element-level `.on_action` handlers are skipped. vault registers every action globally (`cx.on_action`) and moves focus through a request field in AppState that the view applies in its `observe_in` callback.
- Virtual list, variable height: `gpui::{list, ListState, ListAlignment}`. `ListState::new(count, ListAlignment::Top, px(overdraw))` (Rc handle, Clone). `list(state.clone(), move |ix, &mut Window, &mut App| -> AnyElement).size_full()`. `state.reset(n)` jumps to top; keep position with `let top = state.logical_scroll_top(); reset(n); state.scroll_to(top)`. `scroll_to_reveal_item(ix)`, `item_count()`. `uniform_list(id, count, |Range, &mut Window, &mut App| Vec<E>)` + `UniformListScrollHandle` is the fixed-height alternative.
- Clipboard: `cx.write_to_clipboard(ClipboardItem::new_string(String))`, `cx.read_from_clipboard() -> Option<ClipboardItem>`, `item.text() -> Option<String>`. No clear API: write an empty string. The test platform has an in-memory clipboard.
- `cx.open_url(&str)`. `cx.active_window() -> Option<AnyWindowHandle>`, then `.update(cx, |_, window, _| window.minimize_window() / window.zoom_window())`.
- Menus: `MenuItem::action(name, A).checked(bool)`, `MenuItem::submenu(Menu::new("Sort By").items([..]))`, `MenuItem::os_action("Copy", gpui_component::input::Copy, OsAction::Copy)` (Undo/Redo/Cut/Copy/Paste/SelectAll live in `gpui_component::input`). Re-call `cx.set_menus` to move a checkmark.
- Keymap contexts: `div().track_focus(&h).key_context("ItemList")` + `KeyBinding::new("down", NextItem, Some("ItemList"))`. Keys: "cmd-shift-r", "cmd-alt-s", "cmd-backspace", "escape", "enter", "cmd-,".
- Focus/Tab: `cx.focus_handle()`, `handle.is_focused(window)`, `contains_focused(window, cx)`. A plain div becomes a Tab stop with `.id(..).tab_index(0)`; style keyboard focus with `.focus_visible(|s| s.border_color(..))` (put a transparent 1 px border on the base so layout does not shift). Focusable divs fire `on_click` on Enter/Space (`ClickEvent::Keyboard`). gpui-component Root binds Tab/Shift-Tab to `focus_next/prev`. gpui-component Buttons are Tab stops by default.
- Styled: `.truncate()`, `.line_clamp(n)`, `.whitespace_normal()`, `gpui::transparent_black()`, `gpui::white()`, `hsla.opacity(f)`. Strings with `\n` render as multiple lines.
- Edition 2024: `fn render_x(&self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement` captures the `&mut` borrows, so two such calls in one render fail E0499. Return `AnyElement` (or `+ use<>`).
- Headless render tests: `let window = cx.add_window(|window, cx| Root::new(view, window, cx));` then `VisualTestContext::from_window(window.into(), cx)`. Use `vcx.update(|window, cx| ..)`, `vcx.dispatch_action(SomeAction)` (reaches global `cx.on_action` handlers, e.g. menu-only actions), `vcx.simulate_keystrokes("down cmd-d")`, `vcx.simulate_input("text")`, `vcx.simulate_resize(size(..))`, `vcx.run_until_parked()`. Call `gpui_component::init`, bind keys, and register global handlers inside `cx.update` first. Timers only fire on `cx.executor().advance_clock(d)`, so infinite 1 s tickers do not hang `run_until_parked`.

Verified in P3.4: tests with real background OS threads (notify watcher) work inside `#[gpui::test]`: loop `entity.update(cx, |s, cx| s.tick(..))` + `std::thread::sleep(25ms)` until a deadline. gpui timers still need `cx.executor().advance_clock(d)` then `run_until_parked()` (e.g. to fire a 2 s debounced autosave).

Verified in P4.3a (Security tab, concealed clipboard), compiled + clippy + headless tests:
- Inside `cx.observe_in(&state, window, |this, state, window, cx| ..)` you may call `state.update(cx, ..)` on the SAME observed entity (no re-entrancy panic); its `cx.notify()` re-fires the observer, so guard with a flag (vault: `measuring`) to avoid a loop. Used for "measure on tab open".
- Reduce Motion: vault-app no longer uses `cx.reduce_motion()`; it reads `vault_macos::reduce_motion_enabled()` once a second in the autolock tick into `AppState.reduce_motion` (tests set it via `set_reduce_motion`).
- A child view entity inside a Dialog: `div().child(entity.clone())` in the parent's body works; the child entity outlives the dialog, so clear its password inputs from an observer when the sheet/form closes.
- vault-app's system pasteboard is vault-macos only (`write_concealed -> Option<ChangeCount>`, `clear_if_unchanged`); gpui's `write_to_clipboard` is no longer used for secrets.

Verified in P4.3b (Touch ID UI):
- `cx.observe_window_activation(window, |this, window, cx| ..) -> Subscription` (in `Context<T>`); read `window.is_window_active()` inside to tell activate from deactivate. vault uses it so a lock does not pop Touch ID at once; the next window activation does.
- Calling `other.update(cx, ..)` on the observed AppState from a view's `appear()` (itself run inside the root's `observe_in(&state)`) is fine; that is how the unlock screen auto-starts Touch ID.
- Swapping a platform impl only in tests: `#[cfg(not(test))] field: real(), #[cfg(test)] field: fake(),` inside a struct literal compiles; mark the unused real impl `#[cfg_attr(test, allow(dead_code))]` or clippy `--all-targets -D warnings` fails.

Verified in P5.A (polish, second window), compiled + clippy + headless tests:
- Text scaling: `window.set_rem_size(px(16. * scale))` from each window root's `render` (check `window.rem_size()` first) scales every rem-based size (text_sm, p_2...). gpui-component 0.8.1 Root ALSO sets rem to theme.font_size each frame (see 2026-10-29 note). px() sizes need explicit scaling (vault: `theme::scaled(v, cx)`).
- Appearance override without a window: `Theme::change(ThemeMode::Dark|Light | WindowAppearance.into(), None, cx)` then token `Theme::update`, then `cx.refresh_windows()`. `cx.window_appearance()` gives the system value. Prefs live in a gpui `Global` (`cx.set_global`, `cx.try_global::<T>()`).
- `cx.set_reduce_motion(bool)` (gpui App): gpui-component's dialog/tab transitions read it; once the app sets it, gpui-base's system reader stops overriding it.
- Drag: `cx.has_active_drag()` is public, but the active drag value is `pub(crate)`. To know which row is dragged, set an `Rc<Cell<Option<key>>>` inside the `on_drag` constructor closure. `.drag_over::<T>(|style, &T, w, cx| ..)` receives the dragged value (use it to pick a top or bottom 2 px drop line).
- Second window: `cx.open_window(options, |window, cx| cx.new(|cx| Root::new(view, window, cx)))` works from inside an entity update (`Context<AppState>` derefs to App) and in `TestAppContext` (`cx.windows().len()` counts it). `window.remove_window()` from an `observe_in` callback closes it (verified in tests).
- `Totp::parse_uri` + `vault_macos::scan_qr_from_screen` run off-thread via `cx.background_executor().spawn`; test seams are `#[cfg(test)]`-swapped struct fields (see [[gpui-component-widgets]]).
- Window-scoped global actions: `cx.active_window()` returns `Option<AnyWindowHandle>`; compare `.window_id()` with the main window's id, which vault stores in a `Global` set from `VaultRoot::new` via `window.window_handle().window_id()`. In tests, `cx.update_window(handle, |_, window, _| window.activate_window())` really changes `cx.active_window()`, and `cx.dispatch_action(handle, A)` reaches global `cx.on_action` handlers. A mutation check confirmed the test bites.
- `vcx.simulate_input("..")` types into the focused gpui-component Input and `simulate_keystrokes("enter")` fires `InputEvent::PressEnter`.

## Runtime debugging without Screen Recording (verified 2026-10-29)
- gpui logs through the `log` crate. Since 2026-10-29 vault-app initialises `env_logger` (^0.11.8, resolves 0.11.11) in main(): `env_logger::init_from_env(env_logger::Env::default().default_filter_or("warn"))`. Use `RUST_LOG=debug` to see gpui logs. Tests never call main, so no logger in tests.
- Asserting painted colours headlessly: `window.painted_quads() -> Vec<gpui::Quad>` (test-support; `q.bounds: Bounds<ScaledPixels>`, `q.background.as_solid() -> Option<Hsla>`). Scale `vcx.debug_bounds(..)` with `.scale(window.scale_factor())` (test window sf = 2). `Bounds::contains` excludes the far edge, so test containment with `area.intersect(&q.bounds) == q.bounds`. Example: theme.rs primary button tests.
- `Window::render_to_image()` returns `image::RgbaImage` (`.save(path)` writes PNG). It is gated on `test-support`: build with `cargo build -p vault-app --features gpui/test-support,gpui_macos/test-support`. Call it from `cx.spawn` after a timer via `WindowHandle::update`. `screencapture` fails here ("could not create image from display").
- `window.text_system().shape_line(text, size, &[TextRun{len,font,color,background_color,underline,strikethrough}], None)` gives width and per-run `font_id`.

Verified 2026-10-29 (lock closes overlays, menu rows), compiled + clippy + headless tests:
- Closing another window from inside an entity update: keep `AnyWindowHandle`s (`cx.open_window(..)?.into()`), then `cx.defer(move |cx: &mut App| { handle.update(cx, |_, window, _| window.remove_window()).ok(); })`. `Context<T>` has no `defer(f(&mut App))` of its own; it derefs to `App::defer`. Deferring avoids failing when the caller runs inside that window's update. `AnyWindowHandle::update(cx, |AnyView, &mut Window, &mut App| R) -> Result<R>`.
- gpui-component `window.close_dialog(cx)` closes the top non-closing dialog (with exit transition) and does NOT call the dialog's `on_close`. `has_active_dialog` ignores dialogs that are closing, so it reads false right after a close.
- Left-aligned menu rows in a Popover: `h_flex().id(..).tab_index(0).justify_start().hover(..).active(|s| s.bg(..))` with a fixed `w(px(20.))` icon box; Button centres its icon+label, so avoid it for menu rows.

Verified 2026-10-29 (tags editing, TOTP hint, QR from image), compiled + clippy + headless tests:
- Asserting rendered content headlessly: `div().debug_selector(|| format!("totp-code {code}"))` (InteractiveElement; a no-op outside debug + `test-support` builds, so safe in app code), then `vcx.debug_bounds("totp-code 123 456").is_some()`. `debug_bounds` takes `&'static str`, so a computed key needs `Box::leak(s.into_boxed_str())`. Encoding the value in the selector lets a test check WHAT is shown, not just that something rendered.
- Key dispatch order (window.rs `dispatch_key_event`): matched keybinding actions fire FIRST, key_down listeners after. So a parent `on_key_down` cannot tell "backspace in an empty input" (the char is already gone).
- gpui-base Input's `Backspace` handler calls `cx.propagate()` when the cursor is at 0 with no selection. A parent `div().on_action(move |_: &gpui_component::input::Backspace, w, cx| ..)` therefore fires only for backspace-at-start; check the input is empty there.
- Child modules of `screens::main` can read `MainScreen`'s private fields (`m.editor.read(cx).rows`) in tests: Rust privacy is module-tree based.
- `vcx.app.borrow()` gives `&App` for helpers like `ui::input_is_empty(&state, &vcx.app.borrow())`.
- Pasting via `cx.write_to_clipboard(..)` + `simulate_keystrokes("cmd-v")` into a single-line Input drops the trailing newline but keeps leading spaces.
- Keyboard click on a focusable div fires on KEY UP (gpui div.rs: key down records focus generation, key up clicks). `vcx.simulate_keystrokes` sends only KeyDown, so tests must follow with `vcx.simulate_event(gpui::KeyUpEvent { keystroke: gpui::Keystroke::parse("enter").unwrap() })`. Popover content (tab_group) takes focus on open; Tab N times reaches row N in order.
- Probing in tests: `.debug_selector(|| "name".into())` on an element + `vcx.debug_bounds("name") -> Option<Bounds>` + `vcx.simulate_click(b.center(), Modifiers::none())`. `VisualTestContext::run_until_parked` takes `&self`. Prune dead window handles with `cx.windows().contains(&h)`.

Verified 2026-10-29 (capture exclusion):
- `cx.observe_new::<T>(|this: &mut T, Option<&mut Window>, cx: &mut Context<T>| ..) -> Subscription` fires for every new entity of type T. `observe_new::<gpui_component::Root>` therefore fires once per window (main and backup viewers) without touching the code that opens them. It fires in `TestAppContext::add_window` too. vault defers `vault_macos::exclude_app_windows_from_capture()` from it in root.rs.
- Thread-local counters (`thread_local!` + `Cell`) work for asserting calls in `#[gpui::test]`, because the test executor runs on the test thread.
- Restoring a file with `mv backup file` keeps the backup's older mtime, so cargo reuses the stale (mutated) build. Use `cp` or `touch` after mutation checks.
- Asserting borders headlessly: `gpui::Quad` has pub `border_widths: Edges<ScaledPixels>`; a Div with a border but no background still paints a quad with exactly the element's bounds (scaled). Tag the element with `debug_selector`, scale `debug_bounds` by `window.scale_factor()`, match quad bounds within 0.5 and test `q.border_widths.bottom.0 > 0.`. Example: settings.rs `no_divider_after_the_last_row`.
- `cx.defer` wants `FnOnce(&mut App)`: a `fn(&App)` item does not coerce, wrap it in `|cx| f(cx)`. Launch-time policy globals: `impl gpui::Global`, `cx.has_global::<T>()` / `cx.try_global::<T>() -> Option<&T>`; tests set the global first instead of `std::env::set_var` (unsafe in edition 2024).

Verified 2026-10-29 (three-column grid alignment), compiled + clippy + headless tests:
- gpui-component `Input` has an INHERENT `h()` / `h_full()` (multi-line only) that shadows `Styled::h`, so `input.h(px(24.))` silently does nothing on a single-line input. Use `gpui::Styled::h(input, len)`; `refine_style(&self.style)` runs after `input_h(size)`, so the trait call wins.
- Rem: gpui-component 0.8.1 `Root` DOES set rem every frame (`RootPlugin::prepare`: `window.set_rem_size(theme.font_size)`; vault's font_size is 13). vault's `VaultRoot::render` then sets 16*scale for its subtree. Tests that wrap `MainScreen` directly in `Root` therefore lay out at rem 13 (small input = 19.5 px, not 24). Use explicit px sizes where a test asserts geometry.
- Painted borders: gpui paints a bordered quad once PER EDGE (4 identical quads, each with a thin `content_mask` strip). Find the top divider by `q.border_widths.top > 0` and `content_mask.bounds` being a strip at the quad's top. Example: main.rs `top_divider_y`.
- A `focus_ring` (transparent border_1) insets the column's content by 1 px in x and y; account for it when aligning with a sibling column.
- macOS titlebar: gpui sizes AppKit's titlebar container to `2 * traffic_light_position.y + button height` (14), full window width. With `app_owns_titlebar_drag: false`, `_opaqueRectForWindowMoveWhenInTitlebar` returns an empty rect, so AppKit treats the whole band as a window-move region, including under gpui controls placed there.
