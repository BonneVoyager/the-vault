---
name: gpui-component-widgets
description: Verified gpui-component 0.8.1 widget APIs - Input/Textarea, Button, dropdown menus, controlled Popover, Dialog, Slider, Switch, Checkbox, TabBar, drag-drop reorder, icons, resizable, Sidebar caveats
metadata:
  type: reference
---

Verified by compiling vault-app P2.5 (see [[gpui-api-facts]], [[gpui-version-pins]]).

- Input: `gpui_component::input::{Input, InputState, InputEvent}`. `InputState` is `gpui_base::input::InputBaseState<InputMode>`, source in `gpui-base-0.8.1/src/input/base/state.rs`. Build: `cx.new(|cx| InputState::new(window, cx).masked(true).placeholder("..."))`. Read: `state.read(cx).text()` -> `&Rope` (`.to_string()`, `.len()`); `.value()` -> SharedString (avoid for secrets). Write: `set_value(impl Into<InputContent> /* &str, String */, window, cx)`, `focus(window, cx)`. Events: `InputEvent::{Change, PressEnter { secondary, shift }, Focus, Blur}` via `cx.subscribe_in`. Element: `Input::new(&state)` with `.disabled(bool)`, `.mask_toggle()`, `.cleanable(bool)`, `.prefix/.suffix`. Masked text still lives in the rope and undo history until cleared.
- Button: `gpui_component::button::{Button, ButtonVariants as _}`; `Button::new(id).primary()/.ghost().label(..).loading(bool).on_click(|&ClickEvent, &mut Window, &mut App|)`; `.disabled()` needs `gpui_component::Disableable`, `.small()/.large()` need `Sizable`. Button is Styled (`.w_full()`).
- `gpui_component::spinner::Spinner::new()`; `gpui_component::tag::Tag::{info, success, warning, danger, secondary}()` + `.child(..)`.
- Icons: `gpui_component::Icon::new(gpui_kit_assets::IconName::Lock).large().text_color(..)`. Default `gpui_kit_assets::Assets` only embeds ~101 icons (list in `default-icons.txt`; no lock/vault/key). Extras: `gpui_kit_assets::icon_assets!(ExtraIcons, [Lock]);` then a composite `AssetSource` that tries ExtraIcons then `Assets`; register with `application().with_assets(..)`. vault does this in `src/assets.rs`.
- Resizable: `gpui_component::resizable::{h_resizable, resizable_panel, ResizableState}`. `h_resizable("id").with_state(&entity).on_resize(|&Entity<ResizableState>, &mut Window, &mut App|).child(resizable_panel().size(px(220.)).size_range(px(180.)..px(320.)).fixed().child(el))`. `ResizableState::default()`; `state.read(cx).sizes() -> &Vec<Pixels>`. `.fixed()` keeps a panel's width when the window resizes.
- Theme fields used for chrome: `popover`, `border`, `radius`, `radius_lg`, `sidebar`, `sidebar_border`, `accent` (hover bg), `muted_foreground`, `danger/warning/success`, `font_size`.

Verified in P2.6 (main screen):
- Button tooltip + VoiceOver: `.tooltip(impl Into<SharedString>)`, `.accessibility_label(..)`, `.icon(Icon::new(IconName::Copy))`, `.text_color(..)`. Wrapped as `ui::icon_button(id, icon, label)` in vault-app.
- Dropdown: `use gpui_component::menu::DropdownMenu as _;` then `button.dropdown_menu(|menu: PopupMenu, &mut Window, &mut Context<PopupMenu>| menu.menu_with_check("Name", checked, Box::new(Action)))`. The menu dispatches via `window.dispatch_action`, so global `cx.on_action` handlers receive it.
- `gpui_component::progress::ProgressCircle::new(id).value(0..=100).color(hsla).size(px(18.)).accessibility_label(..)` is a canvas arc ring. The value transitions with theme motion, so a wrap from 3% to 100% animates.
- Input: `.small()`, `.cleanable(true)`, `.prefix(Icon..)`, `.suffix(div()..)`.
- `Tag::secondary().small().child(..)`. `Icon::new(..).size_4()/.size_3()/.size(px(48.))`.
- Extra icons that exist in gpui-kit-assets 0.8.1: KeyRound, StickyNote, CreditCard, IdCard, Tag, LayoutList, Lock. Defaults include Copy, Eye, EyeOff, ExternalLink, Star, StarFill, SortAscending, Inbox, Search, Plus, Settings, ChevronRight/Down. Variant names live in `target/debug/build/gpui-kit-assets-*/out/icon_name.rs`.
- Resizable: `resizable_panel().visible(false)` renders an empty div but keeps the panel's slot in `ResizableState`. To hide a column, vault renders a second `h_resizable` with its own state. `ResizablePanelGroup` has no `.size_full()`.
- `gpui_component::sidebar::Sidebar` was NOT used: it paints from `theme.tokens.sidebar*` (a separate legacy token struct that `Theme::update` field edits do not reach), has no dividers between menus, and its rows are not Tab stops. `SidebarMenuItem` does have `.suffix(..)`, `.active(..)` and collapsible children.

Verified in P2.7 (edit mode, generator, settings), compiled + clippy + headless tests:
- Controlled Popover: `gpui_component::popover::Popover::new(id).anchor(gpui::Anchor::TopRight|BottomLeft..).trigger(button).open(bool).on_open_change(|&bool, w, cx|).content(|&mut PopoverState, w, cx| el)`. `.open()` syncs WITHOUT calling on_open_change; trigger click/Enter/Space, Esc, click-outside DO call it, so write the requested bool back to app state there and give the trigger no `on_click`. Opening moves focus into the content, so Esc inside closes it. Wrapped as `ui::popover` in vault-app.
- Dialog (macOS-sheet-like, slides down): `use gpui_component::WindowExt as _; window.open_dialog(cx, |dialog, w, cx| dialog.title("..").w(px(560.)).child(entity.clone()).on_close(|_, w, cx| ..))`; `window.has_active_dialog(cx)`, `window.close_dialog(cx)`. Root mounts dialog/sheet/notification layers itself. Esc closes and fires `on_close`. Needs `&mut Window`, so global actions set a flag and the root view opens it in `observe_in`.
- Slider: `gpui_component::slider::{Slider, SliderState, SliderEvent}`; `cx.new(|_| SliderState::new().min(8.).max(64.).step(1.).default_value(20.))`; `Slider::new(&e).accessibility_label(..)`; subscribe `SliderEvent::{Change(v), Release(v)}`, `v.end()` = single value.
- `switch::Switch::new(id).checked(b).on_click(|&bool, w, cx|)` (controlled, `.disabled()` needs `Disableable`); `checkbox::Checkbox::new(id).label(..).checked(b).on_click(|&bool, ..|)`.
- Tabs: `tab::{TabBar, Tab}`; `TabBar::new(id).segmented()/.underline().small().selected_index(i).child(Tab::new().label(..)).on_click(|&usize, w, cx|)`.
- Menus with closures: `menu.item(gpui_component::menu::PopupMenuItem::new(label).checked(b).on_click(|&ClickEvent, w, cx|))` inside `.dropdown_menu(..)`. `dropdown_menu` returns a wrapper type, not `Button`: return `impl IntoElement`.
- Multi-line: `input::{TextareaState, Textarea}`; `TextareaState::new(w, cx).auto_grow(3, 10)`; same `text()`, `set_value`, `InputEvent` as InputState. `Input::new(&s).mask_toggle()` gives the eye toggle on a masked input.
- Input `escape` propagates unless `clean_on_escape`, so an outer `KeyBinding("escape", X, Some("Ctx"))` still fires while typing. `cmd-backspace` in an input is DeleteToBeginningOfLine and does not propagate.
- No sortable list in gpui-component 0.8.1. Use gpui: `div().id(..).on_drag(value, |v, offset, w, cx| cx.new(|_| PreviewView))` on a handle, and `.drag_over::<T>(|style, &T, w, cx| style..)` + `.on_drop(|&T, w, cx|)` on targets. Drag needs a `Render` view for the preview.
- Text tinting: `gpui::StyledText::new(s).with_highlights(vec![(byte_range, HighlightStyle { color: Some(c), ..Default::default() })])`.
- More icons verified to exist (add via ExtraIcons): GripVertical, WandSparkles. Defaults already include Delete, ArrowUp/Down, RefreshCw, ChevronsUpDown.

Verified in P3.4 (sync banners, Sync & Backup / Import-Export tabs), compiled + clippy + headless tests:
- Alert: `gpui_component::alert::Alert::{error, warning, info, success}(id, message: impl Into<Text>)` (&str/String/SharedString work), `.small()`, `.title(..)`, `.banner()`, `.on_close(..)`. RenderOnce, Styled. Icons TriangleAlert/CircleX are in the default set.
- `TabBar::new(id).segmented().small().selected_index(i).children([Tab::new().label(..)]).on_click(|&usize, w, cx|)` works as a segmented control (retention 0.5x/1x/2x/4x). `Tab::disabled(bool)` exists.
- `Tag::warning()/info()/danger()` + `.small().child(text)`; Tag has no id, wrap in `div().id(..)` if you need one.
- `Button::danger()` (needs `ButtonVariants`) for red confirms; `.loading(bool)` shows a spinner.

Verified in P4.3b: `IconName::FingerprintPattern` exists (added to ExtraIcons in assets.rs). Verified in P4.3a: `Switch::new(id).disabled(true).tooltip("..").accessibility_label(..)` (placeholder toggle); `Spinner::new().small()`; disclosure = `Button::new(id).ghost().small().icon(Icon::new(IconName::ChevronRight|ChevronDown)).label("Advanced")`; `Button::danger()` + `.loading(busy)` for the red rotate confirm.

Verified 2026-10-29: `Sizable::xsmall()` exists (Button). Default icon set includes Close, CircleCheck, CircleX, FolderOpen, Check (no Image/Upload icon by default). Tag chips: `Tag::secondary().small().child(h_flex().child(text).child(icon_button(..).xsmall()))` renders a removable chip. vault-macos exports `scan_qr_from_image_file(&Path)` at the crate root (not `vault_macos::qr::`).

Verified 2026-10-29 (master password meter):
- `InputState::set_value(..)` emits NO `InputEvent::Change` (and clears undo). After filling a field programmatically, recompute anything derived from it yourself.
- Masking at runtime: `state.update(cx, |s, cx| s.set_masked(bool, window, cx))`. There is no `InputState::is_masked()`; read it as `state.read(cx).presentation().is_masked()` (wrapped as `ui::input_is_masked`). `toggle_masked(window, cx)` also exists.
- `Button::new(id).link().small().label(..)` (ButtonVariants) renders a text link.
- vault-app shared helpers: `ui::MasterPasswordCheck` (strength/confirm gate + suggest/reveal) and `ui::submit_gate(name, ready, button)`, which adds a `"<name> ready|blocked"` debug selector so headless tests can see whether a primary button is enabled.

Verified 2026-10-29 (password warning badges), compiled:
- Tooltip on a plain div: `div().id(..).tooltip(move |window, cx| gpui_component::tooltip::Tooltip::new(text.clone()).build(window, cx))` (`Tooltip::new(impl Into<Text>)`, `build(self, &mut Window, &mut App) -> AnyView`). gpui-base's `Tooltip::new(id)` is a different, unstyled popup; don't confuse them.
- VoiceOver label on a div: `.aria_label(impl Into<SharedString>)` (InteractiveElement), `.role(accesskit::Role)`.
- Red "!" badge without an icon asset: `div().size(px(16.)).rounded_full().bg(theme.danger).flex().items_center().justify_center().text_color(white()).font_weight(BOLD).text_size(px(11.)).child("!")` (vault: `list::alert_dot`). `theme.secondary` exists for a neutral card bg.
- Layout assertions in headless tests: `vcx.debug_bounds(a).unwrap().bottom()` / `.top()` are `Pixels`; compare `footer.top() - row.bottom() == px(12.)` to prove nothing sits between two elements.
- Icons: vault imports `gpui_kit_assets::IconName` (full Lucide catalog, generated `icon_name.rs` in target/*/build/gpui-kit-assets-*/out). Only `default-icons.txt` icons are served by `gpui_kit_assets::Assets`; any other variant must be listed in `icon_assets!(ExtraIcons, [..])` in assets.rs or it renders blank. `IconName::Trash` = icons/trash.svg = Lucide "trash-2" shape (with inner lines); `IconName::Delete` is the backspace-x glyph.
- `Spinner` animates via `with_animation`, which honours gpui's reduce-motion flag (static glyph, no frames); `.large()`, `.color(Hsla)`. Uses `IconName::Loader`, which is in gpui-kit-assets default-icons.
- Square icon-only Button of an exact side: `Button::new(id).ghost().with_size(px_value).icon(..)` (Size::Size(px) with no label sets `.size(px)`). Button is InteractiveElement, so `.debug_selector` works on it directly. Distinct tooltip vs VoiceOver text: `.tooltip("Lock  ⌘L").accessibility_label("Lock vault")` (ui::icon_button uses one label for both).

Verified 2026-10-29 (0.8.1): `Button::icon(..)` on `.with_size(px)` draws the icon at 3/4 of that size (`icon_size` setter is pub(crate) only), so a 28 px square button gets a 21 px, heavier glyph. To match a `size_4` nav icon: `.with_size(side).w(side).h(side).child(Icon::new(..).size_4().text_color(muted))`; with a child the button is in "normal" mode where `Size::Size` sets only `px(size*0.2)`, so the explicit w/h survive. In Icon-only mode the button's `.size(px)` overrides user w/h.

Verified 2026-10-29 (cursors, 0.8.1):
- Pointer cursor by default ONLY on `Button` link/text variants (`.link()`, `.text()`, e.g. Input's mask toggle and clear "x"). Normal Button calls `cursor_default()` then re-applies the caller's style last, so `.cursor_pointer()` on a Button wins; disabled/loading keep the caller's cursor too, so set it conditionally. Switch, Checkbox, Tab, Slider and PopupMenu rows set no cursor (disabled Switch shows not-allowed); all but menu rows are Styled and take `.cursor_pointer()`.
- PopupMenu rows have no style hook. Pointer workaround: `PopupMenuItem::element(|_, _| h_flex().relative().flex_1().self_stretch()...child(div().absolute().top_0().bottom_0().left(px(-8.)).right(px(-8.)).cursor_pointer()))` (8 px = private INNER_PADDING); render the check mark yourself. vault: `ui::menu_item`.
- Dialog's built-in close button (absolute top-right, gpui-base `DialogClose`) keeps the arrow: use `.close_button(false)` and put your own button in `.title(element)` (title accepts any element; give it `w_full()`).
- gpui-component Switch's outer wrapper has no element id; the inner gpui-base switch carries the id.
- vault-app rule: every click target goes through `ui::Clickable` (`.clickable()` / `.clickable_when(enabled)`; false sets the arrow explicitly). `ui::icon_button` already includes `.clickable()`.

Verified 2026-10-30 (no-categories change): `IconName` (generated in gpui-kit-assets build.rs) derives Clone, Copy, Debug, Eq, PartialEq, Hash, so `format!("{icon:?}")` gives "KeyRound" and works in debug selectors. `Tag` implements `Styled` (`Tag::secondary().small().flex_none()` compiles). Removable chip (Tag small + xsmall icon button) is 26 px tall vs 24 px for the small Input at rem 13: a wrapping chip row grows 2 px on the first chip. Fix that kept layout stable: `h_flex().id(..).flex_none().h(theme::scaled(28.))` + `.items_center().overflow_x_scroll()` (no `flex_wrap`), children `flex_none`.

Verified 2026-10-30 (backup delete): gpui-component 0.8.1 `Button::accessibility_label` is a plain setter (`Option` overwrite), so `ui::icon_button(id, icon, "Delete backup").accessibility_label(format!(..))` gives a short tooltip and a longer VoiceOver label. Cursor-audit `click(suffix)` finds tuple ids like `("delete-backup", ix)` by their name.
