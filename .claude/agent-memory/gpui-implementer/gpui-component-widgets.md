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
