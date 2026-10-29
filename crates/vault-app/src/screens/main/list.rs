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
use gpui_component::{ActiveTheme as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;

use super::MainScreen;
use vault_core::ItemKind;

use super::sidebar::{kind_label, kind_singular};
use crate::actions::{LIST_CONTEXT, SortAlphabetical, SortRecentlyModified};
use crate::listing::{self, Row};
use crate::state::{AppState, GeneratorTarget, Sort};
use crate::ui;

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
                        .cursor_pointer()
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
                        .on_click(move |_, window, cx| {
                            state.update(cx, |s, cx| s.select(id, cx));
                            window.focus(&focus, cx);
                        }),
                )
                .into_any_element()
        }
        None => div().into_any_element(),
    }
}

/// The ⌘N kind picker: one row per item kind. Uses the title the picker was opened with.
fn kind_picker(state: &Entity<AppState>) -> AnyElement {
    let rows = ItemKind::ALL.into_iter().map(|kind| {
        let (_, icon) = kind_label(kind);
        let state = state.clone();
        Button::new(SharedString::from(format!("new-{}", kind.as_str())))
            .ghost()
            .small()
            .w_full()
            .icon(Icon::new(icon))
            .label(kind_singular(kind))
            .on_click(move |_, _, cx| {
                state.update(cx, |s, cx| {
                    let title = s.kind_picker.clone().unwrap_or_default();
                    s.begin_new(kind, title, cx);
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
                    .primary()
                    .small()
                    .label(label)
                    .on_click(move |_, _, cx| {
                        state.update(cx, |s, cx| s.open_kind_picker(title.clone(), cx));
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
        let picker_open = s.kind_picker.is_some();
        let generator_open = s.generator_target == Some(GeneratorTarget::Global);

        let sort_button = ui::icon_button("sort", IconName::SortAscending, "Sort items")
            .dropdown_menu(move |menu, _, _| {
                menu.menu_with_check(
                    "Name",
                    sort == Sort::Alphabetical,
                    Box::new(SortAlphabetical),
                )
                .menu_with_check(
                    "Recently Modified",
                    sort == Sort::RecentlyModified,
                    Box::new(SortRecentlyModified),
                )
                // "Recently Created" stays hidden until core items carry a created_at.
            });

        let header = ui::h_flex()
            .px(px(12.))
            .pb(px(8.))
            .gap(px(4.))
            .child(
                div().flex_1().child(
                    ui::input(&self.search)
                        .small()
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
            .child(sort_button)
            .child({
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
            });

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

        let footer =
            ui::h_flex()
                .px(px(12.))
                .py(px(8.))
                .border_t_1()
                .border_color(theme.border)
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
                            .tooltip("New item  ⌘N"),
                        Anchor::BottomLeft,
                        picker_open,
                        move |open, _, cx| {
                            state.update(cx, |s, cx| {
                                if open {
                                    s.open_kind_picker(String::new(), cx);
                                } else {
                                    s.close_kind_picker(cx);
                                }
                            });
                        },
                        move |_, _| kind_picker(&picker_state),
                    )
                })
                .child(div().text_xs().text_color(theme.muted_foreground).child(
                    match item_count {
                        1 => "1 item".to_owned(),
                        n => format!("{n} items"),
                    },
                ));

        ui::v_flex()
            .size_full()
            .pt(px(ui::TITLEBAR_HEIGHT))
            .border_r_1()
            .border_color(theme.border)
            .child(header)
            .child(
                ui::v_flex()
                    .id("item-list")
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
