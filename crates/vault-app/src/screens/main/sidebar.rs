//! Sidebar (specs/05-ui.md §2.3): All Items, Favorites, then collapsible alphabetical
//! tags (template tags carry their template's icon), with right-aligned muted counts.
//! No category rows since 2026-10-30. No bottom bar since 2026-10-31: Settings is ⌘,
//! and the app menu only; Lock is ⌘L and File ▸ Lock only (no Lock button anywhere).
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

use super::MainScreen;
use crate::state::Filter;
use crate::ui::{self, Clickable as _};

/// Height of a sidebar row.
fn row_height(cx: &App) -> gpui::Pixels {
    crate::theme::scaled(28., cx)
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
    let height = row_height(cx);
    let theme = cx.theme();
    let label = label.into();
    let selector_label = label.clone();
    let selector_count_label = label.clone();
    ui::h_flex()
        .id(id)
        .debug_selector(move || format!("nav {selector_label} icon={icon:?}"))
        .tab_index(0)
        .h(height)
        .px(px(8.))
        .gap(px(8.))
        .rounded(theme.radius)
        .text_sm()
        .clickable()
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
            let label = selector_count_label.clone();
            row.child(
                div()
                    .debug_selector(move || format!("nav-count {label} {n}"))
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

        let tags_toggle = {
            let state = self.state.clone();
            move |_: &mut Window, cx: &mut App| state.update(cx, |s, cx| s.toggle_tags(cx))
        };
        let tags = counts.tags.iter().enumerate().map(|(i, (tag, n))| {
            nav_row(
                ("nav-tag", i),
                crate::templates::tag_icon(tag),
                format!("#{tag}"),
                Some(*n),
                matches!(&filter, Filter::Tag(t) if crate::templates::tag_matches(t, tag)),
                pick(Filter::Tag(tag.clone())),
                cx,
            )
        });

        ui::v_flex()
            .size_full()
            .debug_selector(|| "sidebar-column".into())
            // Lets the main screen see focus inside (a Tab-focused row) when collapsing.
            .track_focus(&self.sidebar_focus)
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

    use crate::actions;
    use crate::root::VaultRoot;
    use crate::state::{AppState, Screen};
    use crate::templates::Template;

    /// All Items and Favorites, then tags; template tags carry their template's icon and
    /// every other tag the generic tag glyph. No category rows.
    #[gpui::test]
    fn sidebar_has_no_category_rows_and_shows_tag_icons(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.vault");
        let mut vault = SyncedVault::create(
            &path,
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        vault
            .edit(|v| {
                for (i, t) in Template::ALL.into_iter().enumerate() {
                    v.insert(t.new_item(t.label(), device, i as u64), i as u64);
                }
                let mut work = vault_core::Item::new("Other", device, 9);
                work.tags = vec!["work".into()];
                v.insert(work, 9);
            })
            .unwrap();
        vault.save().unwrap();
        let path = vault.path().to_owned();
        drop(vault);
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(|cx| {
            gpui_component::init(cx);
            actions::bind_keys(cx);
            actions::register(&state, cx);
        });
        let window = cx.add_window(|window, cx| {
            crate::theme::apply(window, cx);
            let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        state.update(&mut vcx, |s, cx| s.open_vault(path, cx));
        vcx.run_until_parked();
        state.update(&mut vcx, |s, cx| {
            s.unlock(SecretString::new("pw".into()), cx)
        });
        vcx.run_until_parked();
        assert_eq!(state.read_with(&vcx, |s, _| s.screen), Screen::Main);

        let all = vcx
            .debug_bounds("nav All Items icon=LayoutList")
            .expect("All Items");
        let fav = vcx
            .debug_bounds("nav Favorites icon=Star")
            .expect("Favorites");
        assert!(all.top() < fav.top());
        for gone in ["Logins", "Notes", "Cards", "Identities"] {
            for icon in ["KeyRound", "StickyNote", "CreditCard", "IdCard", "Inbox"] {
                let sel: &'static str = Box::leak(format!("nav {gone} icon={icon}").into());
                assert!(vcx.debug_bounds(sel).is_none(), "{gone} row still shown");
            }
        }
        let mut last = fav.top();
        for (tag, icon) in [
            ("card", "CreditCard"),
            ("identity", "IdCard"),
            ("login", "KeyRound"),
            ("note", "StickyNote"),
            ("work", "Tag"),
        ] {
            let sel: &'static str = Box::leak(format!("nav #{tag} icon={icon}").into());
            let row = vcx
                .debug_bounds(sel)
                .unwrap_or_else(|| panic!("#{tag} with the {icon} glyph"));
            assert!(row.top() > last, "#{tag} sorted after the rows above");
            last = row.top();
        }
        state.read_with(&vcx, |s, _| {
            assert_eq!(s.counts.all, 5);
            assert_eq!(s.counts.tags.len(), 5);
        });
    }

    /// No bottom bar (2026-10-31): no Settings row or Lock button in the sidebar.
    /// Settings opens with ⌘, and from the app menu's "Settings…" item.
    #[gpui::test]
    fn no_bottom_bar_and_settings_opens_from_cmd_comma_and_the_app_menu(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.vault");
        drop(
            SyncedVault::create(
                &path,
                &SecretString::new("pw".into()),
                KdfParams::for_tests(),
                Uuid::new_v4(),
                Arc::new(NoopHooks),
            )
            .unwrap(),
        );
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(|cx| {
            gpui_component::init(cx);
            actions::bind_keys(cx);
            actions::register(&state, cx);
            actions::set_menus(Default::default(), true, cx);
        });
        let window = cx.add_window(|window, cx| {
            crate::theme::apply(window, cx);
            let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        state.update(&mut vcx, |s, cx| s.open_vault(path, cx));
        vcx.run_until_parked();
        state.update(&mut vcx, |s, cx| {
            s.unlock(SecretString::new("pw".into()), cx)
        });
        vcx.run_until_parked();
        assert_eq!(state.read_with(&vcx, |s, _| s.screen), Screen::Main);

        assert!(vcx.debug_bounds("nav All Items icon=LayoutList").is_some());
        for gone in [
            "sidebar-footer",
            "sidebar-settings",
            "sidebar-lock",
            "nav Settings icon=Settings",
        ] {
            assert!(vcx.debug_bounds(gone).is_none(), "{gone} still rendered");
        }

        // ⌘, opens the settings sheet.
        vcx.simulate_keystrokes("cmd-,");
        vcx.run_until_parked();
        assert!(state.read_with(&vcx, |s, _| s.settings_open));
        state.update(&mut vcx, |s, cx| s.open_settings(false, cx));
        vcx.run_until_parked();
        assert!(!state.read_with(&vcx, |s, _| s.settings_open));

        // The app menu has "Settings…" bound to the same action, and it opens the sheet.
        let menus = vcx.cx.update(|cx| cx.get_menus()).unwrap();
        let app_menu = &menus[0];
        let settings = app_menu
            .items
            .iter()
            .find_map(|item| match item {
                gpui::OwnedMenuItem::Action { name, action, .. } if name == "Settings…" => {
                    Some(action.boxed_clone())
                }
                _ => None,
            })
            .expect("Settings… in the app menu");
        assert!(settings.partial_eq(&actions::OpenSettings));
        vcx.update(|window, cx| window.dispatch_action(settings, cx));
        vcx.run_until_parked();
        assert!(state.read_with(&vcx, |s, _| s.settings_open));
    }
}
