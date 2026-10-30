//! Item list (specs/05-ui.md §2.3): search, sort menu, virtualised 56 px rows with A–Z
//! group headers, empty and no-results states.

use gpui::{
    Anchor, AnyElement, App, Context, Entity, FocusHandle, FontWeight, Hsla,
    InteractiveElement as _, IntoElement, ParentElement as _, SharedString,
    StatefulInteractiveElement as _, Styled as _, Window, div, list, prelude::FluentBuilder as _,
    px, rgb,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::menu::DropdownMenu as _;
use gpui_component::tooltip::Tooltip;
use gpui_component::{ActiveTheme as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;

use super::MainScreen;

use crate::actions::{LIST_CONTEXT, SortAlphabetical, SortRecentlyModified};
use crate::audit::Issue;
use crate::listing::{self, Row};
use crate::state::{AppState, GeneratorTarget, Sort};
use crate::templates::Template;
use crate::ui::{self, Clickable as _};

/// Row height at the default text size; scaled by the text size step.
const ROW_HEIGHT: f32 = 56.;
const HEADER_HEIGHT: f32 = 26.;
const AVATAR: f32 = 32.;

/// Letter-avatar backgrounds; white text reads on all of them in both appearances.
const PALETTE: [u32; 8] = [
    0x3B6CF0, 0x30A46C, 0xE5484D, 0xC2790A, 0x8E4EC6, 0x12A594, 0xD6409F, 0xE5622E,
];

/// The 32 px (or `size`) rounded letter avatar for an item.
pub fn avatar(id: vault_core::Uuid, title: &str, size: f32) -> gpui::Div {
    let color: Hsla = rgb(PALETTE[listing::avatar_slot(id, PALETTE.len())]).into();
    div()
        .flex_shrink_0()
        .size(px(size))
        .rounded(px(size / 4.))
        .bg(color)
        .flex()
        .items_center()
        .justify_center()
        .text_color(gpui::white())
        .font_weight(FontWeight::SEMIBOLD)
        .when(size > 36., |d| d.text_lg())
        .child(listing::avatar_letter(title))
}

/// Apple-style red circle with a white "!" (password warnings).
pub fn alert_dot(size: f32, cx: &App) -> gpui::Div {
    div()
        .flex_shrink_0()
        .size(px(size))
        .rounded_full()
        .bg(cx.theme().danger)
        .flex()
        .items_center()
        .justify_center()
        .text_color(gpui::white())
        .font_weight(FontWeight::BOLD)
        .text_size(px(size * 0.7))
        .line_height(px(size))
        .child("!")
}

/// Trailing badge for a list row whose item has password `issues`. The tooltip and
/// VoiceOver label name every issue ("Weak password, Reused password").
fn issue_badge(ix: usize, issues: &[Issue], cx: &App) -> AnyElement {
    let label: SharedString = issues
        .iter()
        .map(Issue::short)
        .collect::<Vec<_>>()
        .join(", ")
        .into();
    let tip = label.clone();
    alert_dot(16., cx)
        .id(("issue-badge", ix))
        .aria_label(label.clone())
        // Tests find the badge by this key (no-op outside test builds).
        .debug_selector(move || format!("issue-badge {label}"))
        .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
        .into_any_element()
}

fn render_row(
    rows: &[Row],
    ix: usize,
    state: &Entity<AppState>,
    focus: &FocusHandle,
    list_focused: bool,
    cx: &mut App,
) -> AnyElement {
    let theme = cx.theme();
    match rows.get(ix) {
        Some(Row::Header(label)) => div()
            .h(crate::theme::scaled(HEADER_HEIGHT, cx))
            .px(px(20.))
            .pt(px(8.))
            .text_xs()
            .font_weight(FontWeight::SEMIBOLD)
            .text_color(theme.muted_foreground)
            .child(label.clone())
            .into_any_element(),
        Some(Row::Item(id)) => {
            let s = state.read(cx);
            let Some(item) = s.unlocked_vault().and_then(|v| v.get(*id)) else {
                return div()
                    .h(crate::theme::scaled(ROW_HEIGHT, cx))
                    .into_any_element();
            };
            let selected = s.selection == Some(*id);
            let (title, subtitle, favorite) =
                (item.title.clone(), listing::subtitle(item), item.favorite);
            let issues = s.listing.issues(*id);
            let badge = (!issues.is_empty()).then(|| issue_badge(ix, issues, cx));
            let (fg, muted) = if selected && list_focused {
                (
                    theme.primary_foreground,
                    theme.primary_foreground.opacity(0.8),
                )
            } else {
                (theme.foreground, theme.muted_foreground)
            };
            let (id, state, focus) = (*id, state.clone(), focus.clone());
            div()
                .h(crate::theme::scaled(ROW_HEIGHT, cx))
                .px(px(8.))
                .py(px(2.))
                .child(
                    ui::h_flex()
                        .id(("item-row", ix))
                        .size_full()
                        .px(px(8.))
                        .gap(px(10.))
                        .rounded(theme.radius_lg)
                        .clickable()
                        .map(|row| match (selected, list_focused) {
                            (true, true) => row.bg(theme.primary),
                            (true, false) => row.bg(theme.primary.opacity(0.14)),
                            _ => row.hover(|st| st.bg(theme.accent)),
                        })
                        .child(avatar(id, &title, AVATAR))
                        .child(
                            ui::v_flex()
                                .flex_1()
                                .min_w_0()
                                .child(
                                    div()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(fg)
                                        .truncate()
                                        .child(if title.trim().is_empty() {
                                            "Untitled".to_owned()
                                        } else {
                                            title
                                        }),
                                )
                                .when(!subtitle.is_empty(), |col| {
                                    col.child(
                                        div()
                                            .text_xs()
                                            .text_color(muted)
                                            .truncate()
                                            .child(subtitle),
                                    )
                                }),
                        )
                        .when(favorite, |row| {
                            row.child(Icon::new(IconName::StarFill).size_4().text_color(
                                if selected && list_focused {
                                    fg
                                } else {
                                    theme.warning
                                },
                            ))
                        })
                        .children(badge)
                        .on_click(move |event, window, cx| {
                            state.update(cx, |s, cx| s.select(id, cx));
                            window.focus(&focus, cx);
                            if event.click_count() == 2
                                && let Err(err) =
                                    crate::screens::open_item_window(state.clone(), id, cx)
                            {
                                state.update(cx, |s, cx| {
                                    s.show_toast(format!("Could not open item: {err}"), cx)
                                });
                            }
                        }),
                )
                .into_any_element()
        }
        None => div().into_any_element(),
    }
}

/// Width of the icon slot in menu rows, so every label starts at the same x.
const MENU_ICON_SLOT: f32 = 20.;

/// The ⌘N Templates menu: one row per template. Uses the title the picker was opened with.
/// Rows are laid out like the sidebar's: fixed icon slot, left-aligned label.
fn template_picker(state: &Entity<AppState>, cx: &App) -> AnyElement {
    let theme = cx.theme();
    let height = crate::theme::scaled(28., cx);
    let rows = Template::ALL.into_iter().map(|template| {
        let state = state.clone();
        ui::h_flex()
            .id(SharedString::from(format!("new-{}", template.tag())))
            .debug_selector(move || format!("new-{}", template.tag()))
            .tab_index(0)
            .w_full()
            .h(height)
            .px(px(8.))
            .gap(px(8.))
            .justify_start()
            .rounded(theme.radius)
            .text_sm()
            .clickable()
            .hover(|style| style.bg(theme.accent))
            .active(|style| style.bg(theme.primary.opacity(0.16)))
            .map(|row| ui::focus_ring(row, cx))
            .child(
                ui::h_flex()
                    .flex_none()
                    .w(px(MENU_ICON_SLOT))
                    .justify_center()
                    .child(
                        Icon::new(template.icon())
                            .size_4()
                            .text_color(theme.muted_foreground),
                    ),
            )
            .child(div().flex_1().min_w_0().truncate().child(template.label()))
            // Focusable divs also fire `on_click` on Enter / Space.
            .on_click(move |_, _, cx| {
                state.update(cx, |s, cx| {
                    let title = s.template_picker.clone().unwrap_or_default();
                    s.begin_new(template, title, cx);
                });
            })
    });
    ui::v_flex()
        .w(px(180.))
        .gap(px(2.))
        .children(rows)
        .into_any_element()
}

pub const EMPTY_VAULT: &str = "This vault is empty";
pub const NO_RESULTS: &str = "No results";
pub const NO_ITEMS_HERE: &str = "No items here";

/// The empty-state message the list shows instead of rows, if any.
pub fn list_placeholder(s: &AppState) -> Option<&'static str> {
    if s.counts.all == 0 {
        Some(EMPTY_VAULT)
    } else if s.listing.items.is_empty() && !s.query.trim().is_empty() {
        Some(NO_RESULTS)
    } else if s.listing.items.is_empty() {
        Some(NO_ITEMS_HERE)
    } else {
        None
    }
}

/// Centred icon, message and one call-to-action that opens the kind picker with `title`.
fn empty_state(
    icon: IconName,
    badge: Option<IconName>,
    message: impl Into<SharedString>,
    action: Option<(SharedString, String)>,
    state: &Entity<AppState>,
    cx: &App,
) -> impl IntoElement {
    let state = state.clone();
    let theme = cx.theme();
    ui::v_flex()
        .flex_1()
        .items_center()
        .justify_center()
        .gap(px(12.))
        .px(px(24.))
        .child(ui::illustration(icon, badge, cx))
        .child(
            div()
                .text_color(theme.muted_foreground)
                .text_center()
                .child(message.into()),
        )
        .when_some(action, |col, (label, title)| {
            col.child(
                Button::new("empty-create")
                    .debug_selector(|| "empty-create".into())
                    .primary()
                    .small()
                    .label(label)
                    .clickable()
                    .on_click(move |_, _, cx| {
                        state.update(cx, |s, cx| s.open_template_picker(title.clone(), cx));
                    }),
            )
        })
}

impl MainScreen {
    pub(super) fn render_list(&self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let list_focused = self.list_focus.is_focused(window);
        let s = self.state.read(cx);
        let theme = cx.theme();
        let sort = s.sort;
        let query = s.query.trim().to_owned();
        let placeholder = list_placeholder(s);
        let rows = s.listing.rows.clone();
        let item_count = s.listing.items.len();
        let picker_open = s.template_picker.is_some();
        let generator_open = s.generator_target == Some(GeneratorTarget::Global);

        let sort_button = ui::icon_button("sort", IconName::SortAscending, "Sort items")
            .dropdown_menu(move |menu, _, _| {
                menu.item(ui::menu_item(
                    "Name",
                    sort == Sort::Alphabetical,
                    |_, window, cx| window.dispatch_action(Box::new(SortAlphabetical), cx),
                ))
                .item(ui::menu_item(
                    "Recently Modified",
                    sort == Sort::RecentlyModified,
                    |_, window, cx| window.dispatch_action(Box::new(SortRecentlyModified), cx),
                ))
                // "Recently Created" stays hidden until core items carry a created_at.
            });

        // The search row sits in the title-bar band, centred on the traffic lights.
        let header = ui::h_flex()
            .flex_none()
            // Symmetric padding: at the default text size the row is exactly the band.
            .py(px(ui::SEARCH_TOP))
            .px(px(ui::COLUMN_PAD_X))
            .gap(px(4.))
            .child(
                ui::no_window_drag(div())
                    .flex_1()
                    .debug_selector(|| "list-search".into())
                    .child(
                        // `Input::h` is an inherent multi-line-only setter that shadows
                        // `Styled::h`; call the trait method to size the single-line frame.
                        gpui::Styled::h(
                            ui::input(&self.search).small(),
                            crate::theme::scaled(ui::SEARCH_HEIGHT, cx),
                        )
                        .cleanable(true)
                        .prefix(
                            Icon::new(IconName::Search)
                                .size_4()
                                .text_color(theme.muted_foreground),
                        )
                        .suffix(
                            div()
                                .text_xs()
                                .text_color(theme.muted_foreground)
                                .child("⌘F"),
                        ),
                    ),
            )
            .child(ui::no_window_drag(div()).flex_none().child(sort_button))
            .child(ui::no_window_drag(div()).flex_none().child({
                let state = self.state.clone();
                let generator = self.generator.clone();
                ui::popover(
                    "generator-global",
                    ui::icon_button(
                        "generator",
                        IconName::WandSparkles,
                        "Password generator  ⌘G",
                    ),
                    Anchor::TopRight,
                    generator_open,
                    move |open, _, cx| {
                        state.update(cx, |s, cx| {
                            if open {
                                s.open_generator(GeneratorTarget::Global, cx);
                            } else {
                                s.close_generator(cx);
                            }
                        });
                    },
                    move |_, _| generator.clone().into_any_element(),
                )
            }));

        let body: AnyElement = if placeholder == Some(EMPTY_VAULT) {
            empty_state(
                IconName::KeyRound,
                Some(IconName::Plus),
                EMPTY_VAULT,
                Some(("Create your first item".into(), String::new())),
                &self.state,
                cx,
            )
            .into_any_element()
        } else if placeholder == Some(NO_RESULTS) {
            empty_state(
                IconName::Search,
                Some(IconName::CircleX),
                NO_RESULTS,
                Some((
                    format!(
                        "Create \u{2018}{}\u{2019}",
                        crate::text::truncate(&query, 24)
                    )
                    .into(),
                    query.clone(),
                )),
                &self.state,
                cx,
            )
            .into_any_element()
        } else if placeholder == Some(NO_ITEMS_HERE) {
            empty_state(IconName::Inbox, None, NO_ITEMS_HERE, None, &self.state, cx)
                .into_any_element()
        } else {
            let state = self.state.clone();
            let focus = self.list_focus.clone();
            list(self.list_state.clone(), move |ix, _window, cx| {
                render_row(&rows, ix, &state, &focus, list_focused, cx)
            })
            .size_full()
            .into_any_element()
        };

        let footer = super::column_footer(theme.border, cx)
            .debug_selector(|| "list-footer".into())
            .justify_between()
            .child({
                let state = self.state.clone();
                let picker_state = self.state.clone();
                ui::popover(
                    "kind-picker",
                    Button::new("new-item")
                        .ghost()
                        .small()
                        .icon(Icon::new(IconName::Plus))
                        .label("New")
                        .tooltip("New item  ⌘N")
                        .clickable(),
                    Anchor::BottomLeft,
                    picker_open,
                    move |open, _, cx| {
                        state.update(cx, |s, cx| {
                            if open {
                                s.open_template_picker(String::new(), cx);
                            } else {
                                s.close_template_picker(cx);
                            }
                        });
                    },
                    move |_, cx| template_picker(&picker_state, cx),
                )
            })
            .child(
                div()
                    .debug_selector(|| "list-footer-count".into())
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(match item_count {
                        1 => "1 item".to_owned(),
                        n => format!("{n} items"),
                    }),
            );

        ui::v_flex()
            .size_full()
            .border_r_1()
            .border_color(theme.border)
            .child(header)
            .child(
                ui::v_flex()
                    .id("item-list")
                    .debug_selector(|| "item-list".into())
                    .track_focus(&self.list_focus)
                    .key_context(LIST_CONTEXT)
                    .flex_1()
                    .min_h_0()
                    .mx(px(2.))
                    .rounded(theme.radius)
                    .map(|el| ui::focus_ring(el, cx))
                    .child(body),
            )
            .child(footer)
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gpui::{AppContext as _, TestAppContext, VisualTestContext};
    use gpui_component::Root;
    use vault_core::{KdfParams, SecretString, Uuid};
    use vault_sync::{NoopHooks, SyncedVault};

    use super::*;
    use crate::actions;
    use crate::state::Mode;

    /// The main screen over an empty unlocked vault.
    fn open(
        dir: &std::path::Path,
        cx: &mut TestAppContext,
    ) -> (Entity<AppState>, VisualTestContext) {
        let vault = SyncedVault::create(
            &dir.join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(|cx| {
            gpui_component::init(cx);
            actions::bind_keys(cx);
            actions::register(&state, cx);
        });
        state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
        let window = cx.add_window(|window, cx| {
            crate::theme::apply(window, cx);
            let view = cx.new(|cx| MainScreen::new(state.clone(), None, window, cx));
            Root::new(view, window, cx)
        });
        let vcx = VisualTestContext::from_window(window.into(), cx);
        vcx.run_until_parked();
        (state, vcx)
    }

    /// Presses and releases `key`. gpui fires a focused element's keyboard click on key
    /// up, and `simulate_keystrokes` sends only key down.
    fn press(vcx: &mut VisualTestContext, key: &'static str) {
        vcx.simulate_keystrokes(key);
        vcx.simulate_event(gpui::KeyUpEvent {
            keystroke: gpui::Keystroke::parse(key).unwrap(),
        });
    }

    /// Opens the New popover with ⌘N, tabs `tabs` times, presses `key`, and returns the
    /// kind of the item being created.
    fn pick(tabs: usize, key: &'static str, cx: &mut TestAppContext) -> Option<Template> {
        let dir = tempfile::tempdir().unwrap();
        let (state, mut vcx) = open(dir.path(), cx);
        vcx.simulate_keystrokes("cmd-n");
        vcx.run_until_parked();
        assert!(state.read_with(&vcx, |s, _| s.template_picker.is_some()));
        for _ in 0..tabs {
            vcx.simulate_keystrokes("tab");
        }
        press(&mut vcx, key);
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| match &s.mode {
            Mode::New(template, buffer) => {
                // The template's fields and its one tag; no category.
                assert_eq!(buffer.item.tags, [template.tag()]);
                let fields: Vec<_> = buffer
                    .item
                    .fields
                    .iter()
                    .map(|f| (f.name.as_str(), f.kind))
                    .collect();
                assert_eq!(fields, template.fields());
                Some(*template)
            }
            _ => None,
        })
    }

    #[gpui::test]
    fn template_picker_row_activates_with_enter(cx: &mut TestAppContext) {
        assert_eq!(pick(1, "enter", cx), Some(Template::Login));
    }

    #[gpui::test]
    fn template_picker_row_activates_with_space(cx: &mut TestAppContext) {
        assert_eq!(pick(2, "space", cx), Some(Template::Note));
    }

    /// "No results" offers "Create '<query>'": it opens the Templates menu, and the
    /// picked template starts a new item titled with the query.
    #[gpui::test]
    fn create_from_query_opens_templates_with_the_query_as_title(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, mut vcx) = open(dir.path(), cx);
        state.update(&mut vcx, |s, cx| {
            let device = s.device_id();
            s.vault
                .as_mut()
                .unwrap()
                .edit(|v| v.insert(vault_core::Item::new("GitHub", device, 1), 1))
                .unwrap();
            s.vault_changed();
            s.set_query("Bank".into(), cx);
        });
        vcx.run_until_parked();
        assert_eq!(
            state.read_with(&vcx, |s, _| list_placeholder(s)),
            Some(NO_RESULTS)
        );

        let button = vcx.debug_bounds("empty-create").expect("Create button");
        vcx.simulate_click(button.center(), gpui::Modifiers::none());
        vcx.run_until_parked();
        assert_eq!(
            state.read_with(&vcx, |s, _| s.template_picker.clone()),
            Some("Bank".to_owned()),
            "the Templates menu opens with the query"
        );

        let row = vcx.debug_bounds("new-card").expect("Templates menu shown");
        vcx.simulate_click(row.center(), gpui::Modifiers::none());
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| match &s.mode {
            Mode::New(template, buffer) => {
                assert_eq!(*template, Template::Card);
                assert_eq!(buffer.item.title, "Bank");
                assert!(s.template_picker.is_none());
            }
            other => panic!("not creating: {}", matches!(other, Mode::View)),
        });
    }
}
