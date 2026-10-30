//! A movable, item-pinned detail window. It reads the live vault by ID so a selection
//! change in the main window cannot change its contents. The window closes on lock.

use std::collections::HashSet;
use std::time::Duration;

use gpui::{
    App, AppContext as _, Bounds, Context, Entity, InteractiveElement as _, IntoElement,
    ParentElement as _, Render, Styled as _, Subscription, TitlebarOptions, Window, WindowBounds,
    WindowOptions, div, prelude::FluentBuilder as _, px, size,
};
use gpui_component::{ActiveTheme as _, Root};
use vault_core::{ExposeSecret as _, FieldKind, SecretString, Uuid};

use super::main::detail::{DetailAction, DetailActions, ReadDetail};
use crate::state::{AppState, CopyTarget, parse_totp};
use crate::{text, theme, ui};

pub fn open_item_window(
    state: Entity<AppState>,
    id: Uuid,
    cx: &mut App,
) -> gpui::Result<gpui::AnyWindowHandle> {
    let title = state
        .read(cx)
        .unlocked_vault()
        .and_then(|vault| vault.get(id))
        .map(|item| item.title.clone())
        .unwrap_or_else(|| "Item details".into());
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
            None,
            size(px(480.), px(620.)),
            cx,
        ))),
        window_min_size: Some(size(px(360.), px(360.))),
        titlebar: Some(TitlebarOptions {
            title: Some(title.clone().into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let handle = cx.open_window(options, |window, cx| {
        window.set_window_title(&title);
        theme::apply(window, cx);
        let view = cx.new(|cx| ItemWindow::new(state, id, window, cx));
        cx.new(|cx| Root::new(view, window, cx))
    })?;
    Ok(handle.into())
}

struct ItemWindow {
    state: Entity<AppState>,
    id: Uuid,
    revealed: HashSet<String>,
    history_open: bool,
    status_clear: Option<gpui::Task<()>>,
    status: Option<String>,
    _ticker: gpui::Task<()>,
    _subscription: Subscription,
}

impl ItemWindow {
    fn new(state: Entity<AppState>, id: Uuid, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let subscription = cx.observe_in(&state, window, move |_, state, window, cx| {
            let s = state.read(cx);
            let exists = s
                .unlocked_vault()
                .and_then(|vault| vault.get(id))
                .is_some_and(|item| !item.is_deleted());
            if !s.main_active() || !exists {
                window.remove_window();
            } else {
                cx.notify();
            }
        });
        let ticker = cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(1)).await;
                if this.update(cx, |_, cx| cx.notify()).is_err() {
                    break;
                }
            }
        });
        Self {
            state,
            id,
            revealed: HashSet::new(),
            history_open: false,
            status_clear: None,
            status: None,
            _ticker: ticker,
            _subscription: subscription,
        }
    }

    fn act(&mut self, action: DetailAction, cx: &mut Context<Self>) {
        match action {
            DetailAction::Reveal(name) => {
                if !self.revealed.remove(&name) {
                    self.revealed.insert(name);
                }
                cx.notify();
            }
            DetailAction::ToggleHistory => {
                self.history_open = !self.history_open;
                cx.notify();
            }
            DetailAction::Copy(target) => self.copy(target, cx),
            DetailAction::CopyHistory(stamp) => {
                let ix = self
                    .state
                    .read(cx)
                    .unlocked_vault()
                    .and_then(|v| v.get(self.id))
                    .and_then(|item| item.history.iter().position(|h| h.replaced_at == stamp));
                if let Some(ix) = ix {
                    self.copy(CopyTarget::History(ix), cx);
                }
            }
            DetailAction::OpenUrl(ix) => {
                let url = self
                    .state
                    .read(cx)
                    .unlocked_vault()
                    .and_then(|v| v.get(self.id))
                    .and_then(|item| item.fields.get(ix))
                    .filter(|f| f.kind == FieldKind::Url)
                    .and_then(|field| text::browser_url(field.value.expose_secret()));
                if let Some(url) = url {
                    cx.open_url(&url);
                }
            }
        }
    }

    fn copy(&mut self, target: CopyTarget, cx: &mut Context<Self>) {
        let value = {
            let s = self.state.read(cx);
            let Some(item) = s.unlocked_vault().and_then(|vault| vault.get(self.id)) else {
                return;
            };
            match target {
                CopyTarget::Field(ix) => item.fields.get(ix).and_then(|field| {
                    if field.kind == FieldKind::Totp {
                        parse_totp(&field.value)
                            .map(|totp| SecretString::new(totp.code(text::now_millis() / 1000)))
                    } else {
                        Some(field.value.clone())
                    }
                }),
                CopyTarget::History(ix) => item.history.get(ix).map(|h| h.value.clone()),
                _ => None,
            }
        };
        let Some(value) = value else {
            return;
        };
        let Some(secs) = self
            .state
            .update(cx, |s, cx| s.copy_value_for_window(value, cx))
        else {
            return;
        };
        self.status = Some(format!("Copied — clears in {secs} s"));
        self.status_clear = Some(cx.spawn(async move |this, cx| {
            cx.background_executor().timer(Duration::from_secs(2)).await;
            this.update(cx, |this, cx| {
                this.status = None;
                cx.notify();
            })
            .ok();
        }));
        cx.notify();
    }
}

impl Render for ItemWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let rem = theme::rem_size(cx);
        if window.rem_size() != rem {
            window.set_rem_size(rem);
        }
        let weak = cx.entity().downgrade();
        let actions = DetailActions(std::rc::Rc::new(move |action, cx| {
            weak.update(cx, |this, cx| this.act(action, cx)).ok();
        }));
        let s = self.state.read(cx);
        let theme = cx.theme();
        let content = s
            .unlocked_vault()
            .and_then(|v| v.get(self.id))
            .filter(|item| !item.is_deleted())
            .map(|item| {
                window.set_window_title(&item.title);
                ReadDetail {
                    state: &self.state,
                    revealed: &self.revealed,
                    history_open: self.history_open,
                    actions,
                    standalone: true,
                }
                .render_item(item, s, cx)
            });
        div()
            .id("item-window")
            .debug_selector(|| "item-window".into())
            .size_full()
            .relative()
            .border_1()
            .border_color(gpui::transparent_black())
            .bg(theme.background)
            .text_color(theme.foreground)
            .text_size(theme.font_size)
            .children(content)
            .when_some(self.status.clone(), |root, status| {
                root.child(ui::detail_copy_feedback(status, cx))
            })
    }
}
