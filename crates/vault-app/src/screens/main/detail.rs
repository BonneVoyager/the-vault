//! Detail column (specs/05-ui.md §2.3). Read mode: fields per `FieldKind`, reveal and
//! copy, password history, live TOTP with countdown ring, modified footer, copy pill,
//! inline delete confirm. Edit and new-item modes hand the column to the `Editor`.
//!
//! Secrets are exposed only for a revealed field, a TOTP code, or the copy actions.

use std::time::Duration;

use gpui::{
    Animation, AnimationExt as _, AnyElement, App, Context, Entity, FontWeight,
    InteractiveElement as _, IntoElement, ParentElement as _, SharedString,
    StatefulInteractiveElement as _, Styled as _, Window, div, ease_in_out,
    prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::progress::ProgressCircle;
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{ExposeSecret, Field, FieldKind, Item};

use super::MainScreen;
use super::list::avatar;
use super::prompts;
use super::sidebar::kind_singular;
use super::sync_banners;
use crate::actions::{DETAIL_CONTEXT, DeleteItem, EditItem, ToggleFavorite};
use crate::state::{AppState, CopyTarget, ToastPlace, parse_totp};
use crate::{text, ui};

/// History entries shown in the disclosure (01 §4 caps history at 10 anyway).
const HISTORY_SHOWN: usize = 10;
/// The code turns amber and the ring pulses under this many seconds (§2.3 "under 5 s").
const TOTP_URGENT_SECS: u32 = 5;

/// True when the selected item shows a TOTP code (the view then re-renders every second).
pub fn shows_totp(s: &AppState) -> bool {
    s.main_active()
        && s.selected_item()
            .is_some_and(|item| item.fields.iter().any(|f| f.kind == FieldKind::Totp))
}

/// Copy button for `target`.
fn copy_button(
    id: impl Into<gpui::ElementId>,
    label: &str,
    target: CopyTarget,
    state: &Entity<AppState>,
) -> Button {
    let state = state.clone();
    ui::icon_button(id, IconName::Copy, label)
        .on_click(move |_, _, cx| state.update(cx, |s, cx| s.copy(target, cx)))
}

fn reveal_button(
    ix: usize,
    name: &str,
    revealed: bool,
    what: &str,
    state: &Entity<AppState>,
) -> Button {
    let (icon, verb) = if revealed {
        (IconName::EyeOff, "Hide")
    } else {
        (IconName::Eye, "Reveal")
    };
    let state = state.clone();
    let name = name.to_owned();
    ui::icon_button(("reveal", ix), icon, &format!("{verb} {what}"))
        .on_click(move |_, _, cx| state.update(cx, |s, cx| s.toggle_reveal(&name, cx)))
}

/// Value text in the monospace font (passwords, codes, card numbers).
fn mono(text: impl Into<SharedString>, cx: &App) -> gpui::Div {
    div()
        .font_family(cx.theme().mono_font_family.clone())
        .child(text.into())
}

pub const ONBOARDING_TITLE: &str = "Your vault is ready";
pub const SELECT_AN_ITEM: &str = "Select an item";

/// The placeholder the detail column shows when no item is open, if any.
pub fn detail_placeholder(s: &AppState) -> Option<&'static str> {
    if s.is_editing() || s.selected_item().is_some() {
        None
    } else if s.onboarding_visible() {
        Some(ONBOARDING_TITLE)
    } else if s.counts.all > 0 {
        Some(SELECT_AN_ITEM)
    } else {
        None
    }
}

/// The tips shown on the first-run card.
pub const ONBOARDING_TIPS: [(&str, &str); 3] = [
    ("\u{2318}N", "Create a new item"),
    ("\u{2318}F", "Search your vault"),
    ("\u{2318}G", "Generate a strong password"),
];

/// First-run card after creating a vault: three shortcuts and a dismiss button.
fn onboarding(state: &Entity<AppState>, cx: &App) -> impl IntoElement {
    let theme = cx.theme();
    let state = state.clone();
    let tips = ONBOARDING_TIPS.iter().map(|(keys, what)| {
        ui::h_flex()
            .gap(px(12.))
            .child(
                div()
                    .w(px(44.))
                    .px(px(6.))
                    .py(px(2.))
                    .rounded(theme.radius)
                    .bg(theme.muted)
                    .text_sm()
                    .text_center()
                    .font_family(theme.mono_font_family.clone())
                    .child(*keys),
            )
            .child(div().text_sm().child(*what))
    });
    ui::v_flex()
        .size_full()
        .items_center()
        .justify_center()
        .child(
            ui::card(cx)
                .w(px(340.))
                .gap(px(12.))
                .child(ui::illustration(IconName::Lock, Some(IconName::Star), cx))
                .child(
                    div()
                        .text_lg()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child(ONBOARDING_TITLE),
                )
                .children(tips)
                .child(
                    ui::h_flex().justify_end().child(
                        Button::new("onboarding-dismiss")
                            .primary()
                            .small()
                            .label("Got it")
                            .on_click(move |_, _, cx| {
                                state.update(cx, |s, cx| s.dismiss_onboarding(cx));
                            }),
                    ),
                ),
        )
}

impl MainScreen {
    pub(super) fn render_detail(&self, _window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let s = self.state.read(cx);
        let toast = s
            .toast
            .as_ref()
            .filter(|t| t.place == ToastPlace::Detail)
            .map(|t| t.message.clone());

        // Selecting another item (or entering edit mode) fades the column in (05 §5).
        let motion_key =
            s.selection.map_or(0, |id| id.as_u128() as usize) ^ usize::from(s.is_editing());
        let reduce_motion = s.reduce_motion || s.selection.is_none();
        let content: AnyElement = match s.selected_item() {
            _ if s.is_editing() => self.editor.clone().into_any_element(),
            Some(item) => self.render_item(item, s, cx).into_any_element(),
            None if detail_placeholder(s) == Some(ONBOARDING_TITLE) => {
                onboarding(&self.state, cx).into_any_element()
            }
            None if detail_placeholder(s) == Some(SELECT_AN_ITEM) => ui::v_flex()
                .size_full()
                .items_center()
                .justify_center()
                .gap(px(12.))
                .child(ui::illustration(
                    IconName::LayoutList,
                    Some(IconName::ChevronRight),
                    cx,
                ))
                .child(
                    div()
                        .text_color(cx.theme().muted_foreground)
                        .child(SELECT_AN_ITEM),
                )
                .child(ui::muted("\u{2191}\u{2193} to move through the list", cx).text_xs())
                .into_any_element(),
            None => div().into_any_element(),
        };

        let banners = sync_banners::render(s, &self.state, &self.key_input, cx);

        ui::v_flex()
            .id("detail")
            .track_focus(&self.detail_focus)
            .key_context(DETAIL_CONTEXT)
            .size_full()
            .relative()
            .map(|el| ui::focus_ring(el, cx))
            .children(banners)
            .child(ui::panel_in(
                div().flex_1().min_h_0().child(content),
                ("detail-in", motion_key),
                0.,
                reduce_motion,
            ))
            .when_some(toast, |col, message| {
                col.child(
                    ui::h_flex()
                        .absolute()
                        .bottom(px(20.))
                        .left_0()
                        .right_0()
                        .justify_center()
                        .child(ui::pill(message, cx)),
                )
            })
            .into_any_element()
    }

    fn render_item(&self, item: &Item, s: &AppState, cx: &App) -> impl IntoElement {
        let theme = cx.theme();
        let now = text::now_millis();
        let device = if item.device_id == s.device_id() {
            "this Mac".to_owned()
        } else {
            text::short_id(item.device_id)
        };
        let first_password = item
            .fields
            .iter()
            .position(|f| f.kind == FieldKind::Password);

        let favorite = ui::icon_button(
            "favorite",
            if item.favorite {
                IconName::StarFill
            } else {
                IconName::Star
            },
            if item.favorite {
                "Remove from Favorites  ⌘D"
            } else {
                "Add to Favorites  ⌘D"
            },
        )
        .when(item.favorite, |b| b.text_color(theme.warning))
        .on_click(|_, window, cx| window.dispatch_action(Box::new(ToggleFavorite), cx));

        let header = ui::h_flex()
            .gap(px(14.))
            .child(avatar(item.id, &item.title, 44.))
            .child(
                ui::v_flex()
                    .flex_1()
                    .min_w_0()
                    .child(
                        div()
                            .text_xl()
                            .font_weight(FontWeight::SEMIBOLD)
                            .truncate()
                            .child(item.title.clone()),
                    )
                    .child(ui::muted(kind_singular(item.kind), cx)),
            )
            .child(favorite)
            .child(
                ui::icon_button("delete", IconName::Delete, "Delete  ⌘⌫")
                    .on_click(|_, window, cx| window.dispatch_action(Box::new(DeleteItem), cx)),
            )
            .child(
                Button::new("edit")
                    .small()
                    .label("Edit")
                    .tooltip("Edit  ⌘E")
                    .on_click(|_, window, cx| window.dispatch_action(Box::new(EditItem), cx)),
            );

        let mut fields: Vec<AnyElement> = Vec::with_capacity(item.fields.len() + 1);
        for (ix, field) in item.fields.iter().enumerate() {
            fields.push(self.render_field(ix, field, item, s, now, cx));
            if Some(ix) == first_password && !item.history.is_empty() {
                fields.push(self.render_history(item, s, now, cx));
            }
        }

        ui::v_flex()
            .id("detail-scroll")
            .size_full()
            .overflow_y_scroll()
            .pt(px(ui::content_top(s)))
            .px(px(28.))
            .pb(px(64.))
            .gap(px(12.))
            .child(header)
            .children(prompts::delete(s, &self.state, cx))
            .when(!item.tags.is_empty(), |col| {
                col.child(
                    ui::h_flex().gap(px(6.)).flex_wrap().children(
                        item.tags
                            .iter()
                            .map(|t| Tag::secondary().small().child(format!("#{t}"))),
                    ),
                )
            })
            .child(ui::divider(cx))
            .when(item.fields.is_empty(), |col| {
                col.child(ui::muted("This item has no fields.", cx))
            })
            .child(ui::v_flex().children(fields))
            .child(ui::divider(cx))
            .child(ui::muted(
                format!(
                    "modified {} · {device}",
                    text::relative(now, item.modified_at)
                ),
                cx,
            ))
    }

    fn render_field(
        &self,
        ix: usize,
        field: &Field,
        item: &Item,
        s: &AppState,
        now: u64,
        cx: &App,
    ) -> AnyElement {
        let theme = cx.theme();
        let revealed = s.revealed.contains(&field.name);
        let value = field.value.expose_secret();
        let card_number = crate::listing::is_card_number(item, field);
        // Extra buttons before the copy button, which every field gets.
        let mut buttons: Vec<AnyElement> = Vec::new();

        let copy_label = match field.kind {
            _ if card_number => "Copy card number".to_owned(),
            FieldKind::Password => "Copy password  ⌘⇧C".to_owned(),
            FieldKind::Totp => "Copy one-time code  ⌘⇧T".to_owned(),
            FieldKind::Url => "Copy website".to_owned(),
            FieldKind::Notes => "Copy notes".to_owned(),
            _ => format!("Copy {}", field.name),
        };

        let shown: AnyElement = match field.kind {
            _ if card_number => {
                buttons.push(
                    reveal_button(ix, &field.name, revealed, "card number", &self.state)
                        .into_any_element(),
                );
                if revealed {
                    mono(value.to_string(), cx).into_any_element()
                } else {
                    mono(text::mask_card(value), cx).into_any_element()
                }
            }
            FieldKind::Password => {
                buttons.push(
                    reveal_button(ix, &field.name, revealed, "password  ⌘⇧R", &self.state)
                        .into_any_element(),
                );
                if revealed {
                    mono(value.to_string(), cx).into_any_element()
                } else {
                    mono(text::DOTS, cx)
                        .text_color(theme.muted_foreground)
                        .into_any_element()
                }
            }
            FieldKind::Totp => self.render_totp(ix, field, now, cx),
            FieldKind::Url => {
                let state = self.state.clone();
                buttons.push(
                    ui::icon_button(("open", ix), IconName::ExternalLink, "Open in browser  ⌘⇧O")
                        .on_click(move |_, _, cx| {
                            state.update(cx, |s, cx| s.open_url(Some(ix), cx));
                        })
                        .into_any_element(),
                );
                div()
                    .text_color(theme.link)
                    .truncate()
                    .child(value.to_string())
                    .into_any_element()
            }
            // Plain text: markdown is deliberately not rendered (§2.3).
            FieldKind::Notes => div()
                .whitespace_normal()
                .child(value.to_string())
                .into_any_element(),
            FieldKind::Text
            | FieldKind::Email
            | FieldKind::Date
            | FieldKind::MonthYear
            | FieldKind::Number => div().truncate().child(value.to_string()).into_any_element(),
        };
        buttons.push(
            copy_button(
                ("copy", ix),
                &copy_label,
                CopyTarget::Field(ix),
                &self.state,
            )
            .into_any_element(),
        );

        ui::v_flex()
            .py(px(8.))
            .gap(px(2.))
            .border_b_1()
            .border_color(theme.border)
            .child(
                div()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(field.name.clone()),
            )
            .child(
                ui::h_flex()
                    .gap(px(4.))
                    .min_h(px(28.))
                    .child(div().flex_1().min_w_0().child(shown))
                    .children(buttons),
            )
            .into_any_element()
    }

    fn render_totp(&self, ix: usize, field: &Field, now_ms: u64, cx: &App) -> AnyElement {
        let theme = cx.theme();
        let Some(totp) = parse_totp(&field.value) else {
            return ui::muted("Invalid one-time code setup", cx).into_any_element();
        };
        let now = now_ms / 1000;
        let remaining = totp.seconds_remaining(now);
        let period = totp.period().max(1);
        let urgent = remaining < TOTP_URGENT_SECS;
        let color = if urgent { theme.warning } else { theme.primary };
        // Fraction of the period left, as 0–100 for the ring.
        let pct = remaining as f32 / period as f32 * 100.;

        let ring = ui::h_flex()
            .gap(px(6.))
            .child(
                ProgressCircle::new(("totp-ring", ix))
                    .value(pct)
                    .color(color)
                    .size(px(18.))
                    .accessibility_label(format!("{remaining} seconds left")),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(if urgent {
                        theme.warning
                    } else {
                        theme.muted_foreground
                    })
                    .child(format!("{remaining}s")),
            );
        // Not colour alone (§6): below 5 s the ring also pulses, unless Reduce Motion is on.
        let ring: AnyElement = if urgent && !self.state.read(cx).reduce_motion {
            ring.with_animation(
                ("totp-pulse", ix),
                Animation::new(Duration::from_millis(900)).repeat(),
                |el, t| el.opacity(0.35 + 0.65 * (1. - ease_in_out((t * 2. - 1.).abs()))),
            )
            .into_any_element()
        } else {
            ring.into_any_element()
        };

        ui::h_flex()
            .gap(px(12.))
            .child(
                mono(text::group_code(&totp.code(now)), cx)
                    .text_lg()
                    .font_weight(FontWeight::SEMIBOLD)
                    .when(urgent, |d| d.text_color(theme.warning)),
            )
            .child(ring)
            .into_any_element()
    }

    fn render_history(&self, item: &Item, s: &AppState, now: u64, cx: &App) -> AnyElement {
        let theme = cx.theme();
        let open = s.history_open;
        let state = self.state.clone();
        let count = item.history.len().min(HISTORY_SHOWN);
        let toggle = ui::h_flex()
            .id("history-toggle")
            .tab_index(0)
            .gap(px(4.))
            .py(px(6.))
            .rounded(theme.radius)
            .map(|el| ui::focus_ring(el, cx))
            .cursor_pointer()
            .text_xs()
            .text_color(theme.muted_foreground)
            .child(
                Icon::new(if open {
                    IconName::ChevronDown
                } else {
                    IconName::ChevronRight
                })
                .size_3(),
            )
            .child(format!("Password history ({count})"))
            .on_click(move |_, _, cx| state.update(cx, |s, cx| s.toggle_history(cx)));

        let entries = item
            .history
            .iter()
            .take(HISTORY_SHOWN)
            .enumerate()
            .map(|(j, h)| {
                ui::h_flex()
                    .pl(px(18.))
                    .gap(px(8.))
                    .child(
                        mono(text::DOTS, cx)
                            .text_color(theme.muted_foreground)
                            .flex_1(),
                    )
                    .child(ui::muted(
                        format!(
                            "replaced {} ({})",
                            text::date(h.replaced_at),
                            text::relative(now, h.replaced_at)
                        ),
                        cx,
                    ))
                    .child(copy_button(
                        ("history-copy", j),
                        "Copy previous password",
                        CopyTarget::History(j),
                        &self.state,
                    ))
            });

        ui::v_flex()
            .pb(px(6.))
            .border_b_1()
            .border_color(theme.border)
            .child(toggle)
            .when(open, |col| col.children(entries))
            .into_any_element()
    }
}
