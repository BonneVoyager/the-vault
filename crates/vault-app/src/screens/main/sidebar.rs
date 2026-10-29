//! Sidebar (specs/05-ui.md §2.3): sections with right-aligned muted counts, collapsible
//! alphabetical tags, Settings at the bottom.
//!
//! Hand-rolled rather than gpui-component's `Sidebar`: that widget paints from
//! `theme.tokens` (which our theme overrides do not reach), has no dividers between
//! menus, and its rows are not Tab stops.

use gpui::{
    App, Context, ElementId, InteractiveElement as _, IntoElement, ParentElement as _,
    SharedString, StatefulInteractiveElement as _, Styled as _, Window, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::{ActiveTheme as _, Icon};
use gpui_kit_assets::IconName;
use vault_core::ItemKind;

use super::MainScreen;
use crate::actions::OpenSettings;
use crate::state::Filter;
use crate::ui;

/// Sidebar label and icon for an item kind.
pub fn kind_label(kind: ItemKind) -> (&'static str, IconName) {
    match kind {
        ItemKind::Login => ("Logins", IconName::KeyRound),
        ItemKind::Note => ("Notes", IconName::StickyNote),
        ItemKind::Card => ("Cards", IconName::CreditCard),
        ItemKind::Identity => ("Identities", IconName::IdCard),
        // A kind from a newer app version: no sidebar category, shown under All only.
        ItemKind::Other => ("Other", IconName::Inbox),
    }
}

/// Singular name of an item kind ("Login", "Identity").
pub fn kind_singular(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "Login",
        ItemKind::Note => "Note",
        ItemKind::Card => "Card",
        ItemKind::Identity => "Identity",
        ItemKind::Other => "Item",
    }
}

/// One clickable, Tab-reachable sidebar row.
fn nav_row(
    id: impl Into<ElementId>,
    icon: IconName,
    label: impl Into<SharedString>,
    count: Option<usize>,
    selected: bool,
    on_click: impl Fn(&mut Window, &mut App) + 'static,
    cx: &App,
) -> impl IntoElement {
    let height = crate::theme::scaled(28., cx);
    let theme = cx.theme();
    let label = label.into();
    ui::h_flex()
        .id(id)
        .tab_index(0)
        .h(height)
        .px(px(8.))
        .gap(px(8.))
        .rounded(theme.radius)
        .text_sm()
        .cursor_pointer()
        .map(|row| {
            if selected {
                row.bg(theme.primary.opacity(0.16))
            } else {
                row.hover(|style| style.bg(theme.accent))
            }
        })
        .map(|row| ui::focus_ring(row, cx))
        .child(Icon::new(icon).size_4().text_color(if selected {
            theme.primary
        } else {
            theme.muted_foreground
        }))
        .child(div().flex_1().min_w_0().truncate().child(label))
        .when_some(count, |row, n| {
            row.child(
                div()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(n.to_string()),
            )
        })
        .on_click(move |_, window, cx| on_click(window, cx))
}

impl MainScreen {
    pub(super) fn render_sidebar(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let s = self.state.read(cx);
        let theme = cx.theme();
        let filter = s.filter.clone();
        let counts = s.counts.clone();
        let tags_open = s.tags_open;
        let name = s.vault_name();

        let pick = |f: Filter| {
            let state = self.state.clone();
            move |_: &mut Window, cx: &mut App| {
                state.update(cx, |s, cx| s.set_filter(f.clone(), cx));
            }
        };

        let kinds = ItemKind::ALL.into_iter().map(|kind| {
            let (label, icon) = kind_label(kind);
            nav_row(
                SharedString::from(format!("nav-{}", kind.as_str())),
                icon,
                label,
                Some(counts.kind(kind)),
                filter == Filter::Kind(kind),
                pick(Filter::Kind(kind)),
                cx,
            )
        });

        let tags_toggle = {
            let state = self.state.clone();
            move |_: &mut Window, cx: &mut App| state.update(cx, |s, cx| s.toggle_tags(cx))
        };
        let tags = counts.tags.iter().enumerate().map(|(i, (tag, n))| {
            nav_row(
                ("nav-tag", i),
                IconName::Tag,
                format!("#{tag}"),
                Some(*n),
                matches!(&filter, Filter::Tag(t) if t.eq_ignore_ascii_case(tag)),
                pick(Filter::Tag(tag.clone())),
                cx,
            )
        });

        ui::v_flex()
            .size_full()
            .bg(theme.sidebar)
            .border_r_1()
            .border_color(theme.sidebar_border)
            // The sidebar extends under the transparent titlebar; keep clear of the lights.
            .pt(px(ui::TITLEBAR_HEIGHT))
            .child(
                div()
                    .px(px(16.))
                    .pb(px(8.))
                    .text_xs()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .text_color(theme.muted_foreground)
                    .truncate()
                    .child(name),
            )
            .child(
                ui::v_flex()
                    .id("sidebar-sections")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .px(px(8.))
                    .gap(px(1.))
                    .child(nav_row(
                        "nav-all",
                        IconName::LayoutList,
                        "All Items",
                        Some(counts.all),
                        filter == Filter::All,
                        pick(Filter::All),
                        cx,
                    ))
                    .child(nav_row(
                        "nav-favorites",
                        IconName::Star,
                        "Favorites",
                        Some(counts.favorites),
                        filter == Filter::Favorites,
                        pick(Filter::Favorites),
                        cx,
                    ))
                    .child(ui::divider(cx).my(px(6.)))
                    .children(kinds)
                    .child(ui::divider(cx).my(px(6.)))
                    .child(nav_row(
                        "nav-tags",
                        if tags_open {
                            IconName::ChevronDown
                        } else {
                            IconName::ChevronRight
                        },
                        "Tags",
                        None,
                        false,
                        tags_toggle,
                        cx,
                    ))
                    .when(tags_open, |col| {
                        col.when(counts.tags.is_empty(), |col| {
                            col.child(
                                div()
                                    .px(px(32.))
                                    .py(px(4.))
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .child("No tags"),
                            )
                        })
                        .children(tags)
                    }),
            )
            .child(
                super::column_footer(theme.border, cx)
                    .debug_selector(|| "sidebar-footer".into())
                    .child(
                        div()
                            .flex_1()
                            .debug_selector(|| "sidebar-footer-content".into())
                            .child(nav_row(
                                "nav-settings",
                                IconName::Settings,
                                "Settings",
                                None,
                                false,
                                |window, cx| window.dispatch_action(Box::new(OpenSettings), cx),
                                cx,
                            )),
                    ),
            )
            .into_any_element()
    }
}
