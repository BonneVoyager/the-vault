//! Item list (specs/05-ui.md §2.3): search, sort menu, virtualised 56 px rows with A–Z
//! group headers, empty and no-results states.

use gpui::{
    Anchor, AnyElement, App, Context, Entity, FocusHandle, FontWeight, InteractiveElement as _,
    IntoElement, ParentElement as _, SharedString, StatefulInteractiveElement as _, Styled as _,
    Window, div, list, prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::InputState;
use gpui_component::tooltip::Tooltip;
use gpui_component::{ActiveTheme as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::Item;

use super::MainScreen;
use super::icon_view::item_tile;

use crate::actions::{
    LIST_CONTEXT, SortAlphabetical, SortRecentlyCreated, SortRecentlyModified, ToggleSidebar,
    sidebar_menu_title,
};
use crate::audit::{FieldIssue, Issue};
use crate::listing::{self, Row};
use crate::state::{AppState, Filter, GeneratorTarget, NO_DELETED_ITEMS, Sort, TRASH_INFO};
use crate::templates::Template;
use crate::ui::{self, Clickable as _};

/// Row height at the default text size; scaled by the text size step.
const ROW_HEIGHT: f32 = 56.;
const HEADER_HEIGHT: f32 = 26.;
const AVATAR: f32 = 32.;

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

/// The distinct issue kinds among an item's field issues, weak before reused.
fn issue_kinds(issues: &[FieldIssue]) -> Vec<Issue> {
    let mut kinds: Vec<Issue> = Vec::new();
    for fi in issues {
        if !kinds.iter().any(|k| k.same_kind(&fi.issue)) {
            kinds.push(fi.issue);
        }
    }
    kinds.sort_by_key(|k| matches!(k, Issue::Reused { .. }));
    kinds
}

/// Trailing badge for a list row whose item has password `issues`. The tooltip and
/// VoiceOver label name each issue kind once ("Weak password, Reused password").
fn issue_badge(ix: usize, issues: &[FieldIssue], cx: &App) -> AnyElement {
    let label: SharedString = issue_kinds(issues)
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

/// Tab index of the list column's buttons (Sort, generator, New). Everything else in
/// the window keeps index 0 in document order (sidebar rows, toggle, search, list,
/// detail); these come after the detail column so search → list → detail is direct
/// (05 §6).
const TOOLBAR_TAB_INDEX: isize = 1;

/// An A–Z group header row of the item list.
pub(crate) fn group_header(label: SharedString, cx: &App) -> AnyElement {
    div()
        .h(crate::theme::scaled(HEADER_HEIGHT, cx))
        .px(px(20.))
        .pt(px(8.))
        .text_xs()
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(cx.theme().muted_foreground)
        .child(label)
        .into_any_element()
}

/// The height of an item row at the current text size (an empty slot keeps it).
pub(crate) fn item_row_height(cx: &App) -> gpui::Pixels {
    crate::theme::scaled(ROW_HEIGHT, cx)
}

/// One item row of a list (05 §2.3), shared by the main list and the backup viewer: the
/// 56 px slot, the 32 px tile, title and subtitle, favourite star, issue badge and the
/// selection and hover fills. `selected` draws the selection, `active` its focused
/// (accent) form; `images` resolves custom icon images (`None`: the automatic tile).
#[allow(clippy::too_many_arguments)]
pub(crate) fn item_row(
    ix: usize,
    item: &Item,
    images: Option<&AppState>,
    issues: &[FieldIssue],
    selected: bool,
    active: bool,
    on_click: impl Fn(&gpui::ClickEvent, &mut Window, &mut App) + 'static,
    cx: &App,
) -> AnyElement {
    let theme = cx.theme();
    let (title, subtitle, favorite) = (item.title.clone(), listing::subtitle(item), item.favorite);
    let badge = (!issues.is_empty()).then(|| issue_badge(ix, issues, cx));
    let (fg, muted) = if selected && active {
        (
            theme.primary_foreground,
            theme.primary_foreground.opacity(0.8),
        )
    } else {
        (theme.foreground, theme.muted_foreground)
    };
    div()
        .h(item_row_height(cx))
        .px(px(8.))
        .py(px(2.))
        .child(
            ui::h_flex()
                .id(("item-row", ix))
                .debug_selector(move || format!("item-row {ix}"))
                .size_full()
                .px(px(8.))
                .gap(px(10.))
                .rounded(theme.radius_lg)
                .clickable()
                .map(|row| match (selected, active) {
                    (true, true) => row.bg(theme.primary),
                    (true, false) => row.bg(theme.primary.opacity(0.14)),
                    _ => row.hover(|st| st.bg(theme.accent)),
                })
                .child(item_tile(item, images, AVATAR, cx))
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
                            col.child(div().text_xs().text_color(muted).truncate().child(subtitle))
                        }),
                )
                .when(favorite, |row| {
                    row.child(Icon::new(IconName::StarFill).size_4().text_color(
                        if selected && active {
                            fg
                        } else {
                            theme.warning
                        },
                    ))
                })
                .children(badge)
                .on_click(on_click),
        )
        .into_any_element()
}

/// The list's search field (05 §2.3), shared by the main list and the backup viewer:
/// small, scaled with the text size, clear button, search glyph and the ⌘F hint.
pub(crate) fn search_field(search: &Entity<InputState>, cx: &App) -> impl IntoElement {
    let muted = cx.theme().muted_foreground;
    // `Input::h` is an inherent multi-line-only setter that shadows `Styled::h`; call
    // the trait method to size the single-line frame.
    gpui::Styled::h(
        ui::input(search).small(),
        crate::theme::scaled(ui::SEARCH_HEIGHT, cx),
    )
    .cleanable(true)
    .prefix(Icon::new(IconName::Search).size_4().text_color(muted))
    .suffix(div().text_xs().text_color(muted).child("⌘F"))
}

fn render_row(
    rows: &[Row],
    ix: usize,
    state: &Entity<AppState>,
    focus: &FocusHandle,
    list_focused: bool,
    cx: &mut App,
) -> AnyElement {
    match rows.get(ix) {
        Some(Row::Header(label)) => group_header(label.clone(), cx),
        Some(Row::Item(id)) => {
            let s = state.read(cx);
            let Some(item) = s.unlocked_vault().and_then(|v| v.get(*id)) else {
                return div().h(item_row_height(cx)).into_any_element();
            };
            let selected = s.selection == Some(*id);
            // A trashed item opens no item window (05 §2.3 "Recently Deleted").
            let trashed = item.is_deleted();
            let (id, state_c, focus) = (*id, state.clone(), focus.clone());
            let on_click = move |event: &gpui::ClickEvent, window: &mut Window, cx: &mut App| {
                let state = &state_c;
                state.update(cx, |s, cx| s.select(id, cx));
                window.focus(&focus, cx);
                if event.click_count() == 2
                    && !trashed
                    && let Err(err) = crate::screens::open_item_window(state.clone(), id, cx)
                {
                    state.update(cx, |s, cx| {
                        s.show_toast(format!("Could not open item: {err}"), cx)
                    });
                }
            };
            item_row(
                ix,
                item,
                Some(s),
                s.listing.issues(id),
                selected,
                list_focused,
                on_click,
                cx,
            )
        }
        None => div().into_any_element(),
    }
}

/// The ⌘N Templates menu rows. Uses the title the picker was opened with.
fn template_rows(state: &Entity<AppState>) -> Vec<ui::MenuRow> {
    Template::ALL
        .into_iter()
        .map(|template| {
            let state = state.clone();
            ui::menu_row(format!("new-{}", template.tag()), template.label())
                .icon(template.icon())
                .on_click(move |_, _, cx| {
                    state.update(cx, |s, cx| {
                        let title = s.template_picker.clone().unwrap_or_default();
                        s.begin_new(template, title, cx);
                    });
                })
        })
        .collect()
}

/// Called with the order picked in the sort menu.
pub(crate) type OnSort = std::rc::Rc<dyn Fn(Sort, &mut Window, &mut App)>;

/// Sort menu rows, `current` checked; a pick runs `on_select`. Shared by the main list
/// (which dispatches its sort actions) and the backup viewer (a window-local order).
fn sort_rows(current: Sort, on_select: &OnSort) -> Vec<ui::MenuRow> {
    [
        ("sort-name", "Name", Sort::Alphabetical),
        ("sort-modified", "Recently Modified", Sort::RecentlyModified),
        ("sort-created", "Recently Created", Sort::RecentlyCreated),
    ]
    .into_iter()
    .map(|(id, label, sort)| {
        let on_select = on_select.clone();
        ui::menu_row(id, label)
            .checked(current == sort)
            .on_click(move |_, window, cx| on_select(sort, window, cx))
    })
    .collect()
}

/// The list's Sort button and its menu (05 §2.3), shared by the main list and the
/// backup viewer. `on_toggle` opens or closes the menu (`open` is its state);
/// `on_select` gets the picked order and must close the menu.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sort_menu(
    focus: &FocusHandle,
    open: bool,
    current: Sort,
    on_toggle: impl Fn(bool, &mut Window, &mut App) + 'static,
    on_select: OnSort,
    window: &mut Window,
    cx: &mut App,
) -> gpui_component::popover::Popover {
    ui::menu_popover(
        "sort-menu",
        ui::icon_button("sort", IconName::SortAscending, "Sort items")
            .debug_selector(|| "sort".into())
            .track_focus(focus)
            .tab_index(TOOLBAR_TAB_INDEX),
        Anchor::TopLeft,
        open,
        on_toggle,
        move |_, _| sort_rows(current, &on_select),
        window,
        cx,
    )
}

/// The list heading while the sidebar is collapsed: the active filter as the sidebar
/// names it, and the count the sidebar shows next to it.
pub fn filter_heading(s: &AppState) -> (String, usize) {
    match &s.filter {
        Filter::All => ("All Items".into(), s.counts.all),
        Filter::Favorites => ("Favorites".into(), s.counts.favorites),
        Filter::RecentlyDeleted => (RECENTLY_DELETED.into(), s.counts.deleted),
        Filter::Tag(tag) => s
            .counts
            .tags
            .iter()
            .find(|(t, _)| crate::templates::tag_matches(t, tag))
            .map(|(t, n)| (format!("#{t}"), *n))
            .unwrap_or_else(|| (format!("#{tag}"), 0)),
    }
}

/// The sidebar button at the left of the search row, in both sidebar states.
fn sidebar_toggle(sidebar_visible: bool) -> Button {
    let title = sidebar_menu_title(sidebar_visible);
    ui::icon_button("sidebar-toggle", IconName::PanelLeft, title)
        .tooltip(format!("{title}  \u{2303}\u{2318}S"))
        .debug_selector(move || format!("sidebar-toggle {title}"))
        .on_click(|_, window, cx| window.dispatch_action(Box::new(ToggleSidebar), cx))
}

pub const EMPTY_VAULT: &str = "This vault is empty";
pub const NO_RESULTS: &str = "No results";
pub const NO_ITEMS_HERE: &str = "No items here";
pub const RECENTLY_DELETED: &str = "Recently Deleted";

/// The empty-state message the list shows instead of rows, if any.
pub fn list_placeholder(s: &AppState) -> Option<&'static str> {
    let trash = s.filter == Filter::RecentlyDeleted;
    if trash && s.listing.items.is_empty() {
        Some(if s.query.trim().is_empty() {
            NO_DELETED_ITEMS
        } else {
            NO_RESULTS
        })
    } else if s.counts.all == 0 && !trash {
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

/// The muted card above the Recently Deleted rows.
fn trash_info(cx: &App) -> impl IntoElement {
    let theme = cx.theme();
    div()
        .flex_none()
        .debug_selector(|| "trash-info".into())
        .mx(px(ui::COLUMN_PAD_X - 2.))
        .mb(px(6.))
        .px(px(10.))
        .py(px(8.))
        .rounded(theme.radius)
        .bg(theme.muted)
        .text_xs()
        .text_color(theme.muted_foreground)
        .child(TRASH_INFO)
}

/// Recently Deleted with nothing in it: large trash glyph, title, the retention sentence.
fn trash_empty_state(cx: &App) -> impl IntoElement {
    let theme = cx.theme();
    ui::v_flex()
        .flex_1()
        .size_full()
        .items_center()
        .justify_center()
        .gap(px(12.))
        .px(px(24.))
        .debug_selector(|| "trash-empty".into())
        .child(ui::illustration(IconName::Trash, None, cx))
        .child(
            div()
                .font_weight(FontWeight::SEMIBOLD)
                .text_center()
                .child(NO_DELETED_ITEMS),
        )
        .child(
            div()
                .text_sm()
                .text_color(theme.muted_foreground)
                .text_center()
                .child(TRASH_INFO),
        )
}

impl MainScreen {
    pub(super) fn render_list(&self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        // Focus anywhere inside the list (05 §2.3): the selection is drawn active.
        let list_focused = self.list_focus.contains_focused(window, cx);
        let picker_open = self.state.read(cx).template_picker.is_some();
        // Built first: the menu keeps its focus handles in element state (`&mut App`).
        let kind_picker = {
            let state = self.state.clone();
            let picker_state = self.state.clone();
            ui::menu_popover(
                "kind-picker",
                Button::new("new-item")
                    .debug_selector(|| "new-item".into())
                    .ghost()
                    .small()
                    .icon(Icon::new(IconName::Plus))
                    .label("New")
                    .tooltip("New item  ⌘N")
                    .tab_index(TOOLBAR_TAB_INDEX)
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
                move |_, _| template_rows(&picker_state),
                window,
                cx,
            )
        };
        let (sort_open, sort) = {
            let s = self.state.read(cx);
            (s.sort_menu_open, s.sort)
        };
        let sort_button = {
            let state = self.state.clone();
            let select_state = self.state.clone();
            sort_menu(
                &self.sort_focus,
                sort_open,
                sort,
                move |open, _, cx| {
                    state.update(cx, |s, cx| {
                        if open {
                            s.open_sort_menu(cx);
                        } else {
                            s.close_sort_menu(cx);
                        }
                    });
                },
                std::rc::Rc::new(move |sort, window, cx| {
                    select_state.update(cx, |s, cx| s.close_sort_menu(cx));
                    let action: Box<dyn gpui::Action> = match sort {
                        Sort::Alphabetical => Box::new(SortAlphabetical),
                        Sort::RecentlyModified => Box::new(SortRecentlyModified),
                        Sort::RecentlyCreated => Box::new(SortRecentlyCreated),
                    };
                    window.dispatch_action(action, cx);
                }),
                window,
                cx,
            )
        };
        let s = self.state.read(cx);
        let theme = cx.theme();
        let query = s.query.trim().to_owned();
        let placeholder = list_placeholder(s);
        let rows = s.listing.rows.clone();
        let item_count = s.listing.items.len();
        let generator_open = s.generator_target == Some(GeneratorTarget::Global);
        let collapsed = self.sidebar_collapsed();
        let heading = collapsed.then(|| filter_heading(s));
        let trash = s.filter == Filter::RecentlyDeleted;

        // The search row sits in the title-bar band, centred on the traffic lights.
        // Left padding comes from `slide_header`: wider while the sidebar is collapsed,
        // so the toggle sits right of the traffic lights.
        let header = ui::h_flex()
            .flex_none()
            // Exactly the band at the default text size, the search field centred on the
            // traffic lights; the save-blocked strip sits right under this height.
            .h(super::header_height(cx))
            .items_center()
            .px(px(ui::COLUMN_PAD_X))
            .gap(px(4.))
            .child(
                ui::no_window_drag(div())
                    .flex_none()
                    .child(sidebar_toggle(!collapsed)),
            )
            .child(
                ui::no_window_drag(div())
                    .flex_1()
                    .debug_selector(|| "list-search".into())
                    .child(search_field(&self.search, cx)),
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
                    )
                    .tab_index(TOOLBAR_TAB_INDEX),
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
        } else if placeholder == Some(NO_DELETED_ITEMS) {
            trash_empty_state(cx).into_any_element()
        } else if placeholder == Some(NO_RESULTS) && trash {
            // Nothing to create from a search of the trash.
            empty_state(
                IconName::Search,
                Some(IconName::CircleX),
                NO_RESULTS,
                None,
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
            let rows = list(self.list_state.clone(), move |ix, _window, cx| {
                render_row(&rows, ix, &state, &focus, list_focused, cx)
            })
            .size_full();
            if trash {
                ui::v_flex()
                    .size_full()
                    .child(trash_info(cx))
                    .child(div().flex_1().min_h_0().child(rows))
                    .into_any_element()
            } else {
                rows.into_any_element()
            }
        };

        let footer = super::column_footer(theme.border, cx)
            .debug_selector(|| "list-footer".into())
            .justify_between()
            .child(kind_picker)
            // No Lock button (owner, 2026-10-31): ⌘L and File ▸ Lock only.
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

        // Collapsed only: the active filter the sidebar would show selected.
        let heading = heading.map(|(title, count)| {
            ui::h_flex()
                .flex_none()
                .px(px(ui::COLUMN_PAD_X))
                .pb(px(6.))
                .gap(px(8.))
                .debug_selector(|| "list-filter-heading".into())
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .truncate()
                        .font_weight(FontWeight::SEMIBOLD)
                        .debug_selector({
                            let title = title.clone();
                            move || format!("list-filter-title {title}")
                        })
                        .child(title),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .debug_selector(move || format!("list-filter-count {count}"))
                        .child(count.to_string()),
                )
        });

        ui::v_flex()
            .size_full()
            .border_r_1()
            .border_color(theme.border)
            .child(self.slide_header(header))
            .children(super::save_blocked::spacer(
                s,
                &self.state,
                "save-blocked-spacer-list",
                Some(self.right_width),
                0.,
                cx,
            ))
            .children(heading)
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

    /// L-10: after lock and unlock the collapsed-sidebar heading is "All Items", never the
    /// tag the previous session filtered by.
    #[gpui::test]
    fn heading_forgets_the_tag_across_lock(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, mut vcx) = open(dir.path(), cx);
        state.update(&mut vcx, |s, cx| {
            s.set_filter(Filter::Tag("secret-project".into()), cx);
            assert_eq!(filter_heading(s).0, "#secret-project");
            s.lock(cx);
            assert_eq!(filter_heading(s), ("All Items".into(), 0));
        });
        state.update(&mut vcx, |s, cx| {
            s.unlock(SecretString::new("pw".into()), cx)
        });
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert!(!s.locked);
            assert_eq!(filter_heading(s).0, "All Items");
        });
    }

    /// The badge names each kind once, weak before reused, whatever the field order.
    #[test]
    fn issue_kinds_are_distinct_weak_first() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let fi = |field, issue| FieldIssue { field, issue };
        let weak = Issue::Weak { bits: 10. };
        let reused = Issue::Reused { count: 2 };
        let kinds = issue_kinds(&[
            fi(a, reused),
            fi(b, weak),
            fi(b, Issue::Reused { count: 3 }),
            fi(a, Issue::Weak { bits: 20. }),
        ]);
        assert_eq!(kinds, [weak, reused]);
        assert_eq!(issue_kinds(&[fi(a, weak), fi(b, weak)]), [weak]);
        assert!(issue_kinds(&[]).is_empty());
    }

    #[gpui::test]
    fn template_picker_row_activates_with_enter(cx: &mut TestAppContext) {
        // ⌘N opens the menu with the first row (Login) focused.
        assert_eq!(pick(0, "enter", cx), Some(Template::Login));
    }

    #[gpui::test]
    fn template_picker_row_activates_with_space(cx: &mut TestAppContext) {
        assert_eq!(pick(1, "space", cx), Some(Template::Note));
    }

    /// ⌘N lists the six templates in spec order (05 §2.3): Login, Note, Card, Identity,
    /// Server, License, each row with its template icon.
    #[gpui::test]
    fn template_menu_lists_six_rows_in_order(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, mut vcx) = open(dir.path(), cx);
        vcx.simulate_keystrokes("cmd-n");
        vcx.run_until_parked();
        assert!(state.read_with(&vcx, |s, _| s.template_picker.is_some()));
        let tops: Vec<_> = ["login", "note", "card", "identity", "server", "license"]
            .into_iter()
            .map(|tag| {
                let sel: &'static str = Box::leak(format!("new-{tag}").into());
                vcx.debug_bounds(sel)
                    .unwrap_or_else(|| panic!("{sel} row"))
                    .top()
            })
            .collect();
        assert!(tops.windows(2).all(|w| w[0] < w[1]), "{tops:?}");
        assert!(vcx.debug_bounds("new-other").is_none());
        assert_eq!(Template::ALL.len(), 6);
    }

    /// Server and License are picked like any template: their preset fields and tag.
    #[gpui::test]
    fn template_picker_offers_server(cx: &mut TestAppContext) {
        assert_eq!(pick(4, "enter", cx), Some(Template::Server));
    }

    #[gpui::test]
    fn template_picker_offers_license(cx: &mut TestAppContext) {
        assert_eq!(pick(5, "enter", cx), Some(Template::License));
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

    /// From the search field into the list by keyboard, then ↓: the selected row is drawn
    /// with the full primary colour, not the inactive tint (05 §2.3).
    #[gpui::test]
    fn keyboard_entry_draws_the_selection_active(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, mut vcx) = open(dir.path(), cx);
        state.update(&mut vcx, |s, _| {
            let device = s.device_id();
            for title in ["Alpha", "Beta"] {
                s.vault
                    .as_mut()
                    .unwrap()
                    .edit(|v| v.insert(vault_core::Item::new(title, device, 1), 1))
                    .unwrap();
            }
            s.vault_changed();
        });
        vcx.run_until_parked();
        let before = state.read_with(&vcx, |s, _| s.selection);
        vcx.simulate_keystrokes("cmd-f");
        // Enter in the search field is one keyboard way into the list (Tab is another).
        vcx.simulate_keystrokes("enter");
        vcx.simulate_keystrokes("down");
        vcx.update(|window, _| window.refresh());
        vcx.run_until_parked();
        let selected = state.read_with(&vcx, |s, _| s.selection);
        assert!(
            selected.is_some() && selected != before,
            "↓ moved the selection"
        );
        let ix = state.read_with(&vcx, |s, _| {
            s.listing
                .rows
                .iter()
                .position(|r| matches!(r, Row::Item(id) if Some(*id) == selected))
                .unwrap()
        });
        let row = vcx
            .debug_bounds(Box::leak(format!("item-row {ix}").into_boxed_str()))
            .expect("selected row drawn");
        let painted = vcx.update(|window, cx| {
            let primary = cx.theme().primary;
            let row = row.scale(window.scale_factor());
            let near = |a: gpui::ScaledPixels, b: gpui::ScaledPixels| (a.0 - b.0).abs() < 1.;
            window.painted_quads().iter().any(|q| {
                near(q.bounds.origin.x, row.origin.x)
                    && near(q.bounds.origin.y, row.origin.y)
                    && near(q.bounds.size.width, row.size.width)
                    && q.background.as_solid() == Some(primary)
            })
        });
        assert!(painted, "selected row painted in theme.primary");
    }
}
