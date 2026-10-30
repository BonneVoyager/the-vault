//! Detail column (specs/05-ui.md §2.3). Read mode: fields per `FieldKind`, reveal and
//! copy, password history, live TOTP with countdown ring, modified footer, copy pill,
//! inline delete confirm. Edit and new-item modes hand the column to the `Editor`.
//!
//! Secrets are exposed only for a revealed field, a TOTP code, or the copy actions.

use std::time::Duration;
use std::{collections::HashSet, rc::Rc};

use gpui::{
    Animation, AnimationExt as _, AnyElement, App, Context, Entity, ExternalPaths, FontWeight,
    InteractiveElement as _, IntoElement, ParentElement as _, SharedString,
    StatefulInteractiveElement as _, Styled as _, Window, div, ease_in_out,
    prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::progress::ProgressCircle;
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{ExposeSecret, Field, FieldKind, HistoryEntry, Item};

use super::MainScreen;
use super::attachments;
use super::list::{alert_dot, avatar};
use super::prompts;
use super::sidebar::kind_singular;
use super::sync_banners;
use crate::actions::{DETAIL_CONTEXT, DeleteItem, EditItem, ToggleFavorite};
use crate::audit::Issue;
use crate::state::{AppState, CopyTarget, Mode, ToastPlace, parse_totp};
use crate::ui::Clickable as _;
use crate::{text, ui};

/// History entries shown in the disclosure (01 §4 caps history at 10 anyway).
const HISTORY_SHOWN: usize = 10;
/// The code turns amber and the ring pulses under this many seconds (§2.3 "under 5 s").
const TOTP_URGENT_SECS: u32 = 5;

#[derive(Clone)]
pub(crate) enum DetailAction {
    Copy(CopyTarget),
    CopyHistory(u64),
    Reveal(String),
    OpenUrl(usize),
    ToggleHistory,
}

#[derive(Clone)]
pub(crate) struct DetailActions(pub Rc<DetailHandler>);

type DetailHandler = dyn Fn(DetailAction, &mut App);

impl DetailActions {
    fn main(state: Entity<AppState>) -> Self {
        Self(Rc::new(move |action, cx| {
            state.update(cx, |s, cx| match action {
                DetailAction::Copy(target) => s.copy(target, cx),
                DetailAction::CopyHistory(stamp) => {
                    if let Some(ix) = s
                        .selected_item()
                        .and_then(|item| item.history.iter().position(|h| h.replaced_at == stamp))
                    {
                        s.copy(CopyTarget::History(ix), cx);
                    }
                }
                DetailAction::Reveal(name) => s.toggle_reveal(&name, cx),
                DetailAction::OpenUrl(ix) => s.open_url(Some(ix), cx),
                DetailAction::ToggleHistory => s.toggle_history(cx),
            })
        }))
    }
}

/// One read-mode renderer for the main detail column and pinned item windows.
pub(crate) struct ReadDetail<'a> {
    pub state: &'a Entity<AppState>,
    pub revealed: &'a HashSet<String>,
    pub history_open: bool,
    pub actions: DetailActions,
    pub standalone: bool,
}

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
    actions: &DetailActions,
) -> Button {
    let actions = actions.clone();
    ui::icon_button(id, IconName::Copy, label)
        .on_click(move |_, _, cx| (actions.0)(DetailAction::Copy(target), cx))
}

fn reveal_button(
    ix: usize,
    name: &str,
    revealed: bool,
    what: &str,
    actions: &DetailActions,
) -> Button {
    let (icon, verb) = if revealed {
        (IconName::EyeOff, "Hide")
    } else {
        (IconName::Eye, "Reveal")
    };
    let actions = actions.clone();
    let name = name.to_owned();
    ui::icon_button(("reveal", ix), icon, &format!("{verb} {what}"))
        .on_click(move |_, _, cx| (actions.0)(DetailAction::Reveal(name.clone()), cx))
}

/// A field's value area in read mode: clicking it does exactly what the row's Copy
/// button does (`AppState::copy`), so a masked value is copied without being revealed.
/// Focusable, so Enter or Space on it copies too (gpui clicks a focused div on key up).
fn copy_on_click(
    ix: usize,
    what: &str,
    shown: AnyElement,
    actions: &DetailActions,
    cx: &App,
) -> impl IntoElement {
    let actions = actions.clone();
    ui::copy_value_area(("field-value", ix), what, cx)
        // Tests click the value by this key (no-op outside test builds).
        .debug_selector(move || format!("field-value {ix}"))
        .on_click(move |_, _, cx| (actions.0)(DetailAction::Copy(CopyTarget::Field(ix)), cx))
        .child(shown)
}

/// Value text in the monospace font (passwords, codes, card numbers).
fn mono(text: impl Into<SharedString>, cx: &App) -> gpui::Div {
    div()
        .font_family(cx.theme().mono_font_family.clone())
        .child(text.into())
}

/// Apple-style warning card for one password issue: red "!" at left, bold title, body.
/// Not dismissable; it disappears when a save fixes the password.
fn issue_banner(issue: &Issue, cx: &App) -> impl IntoElement {
    let theme = cx.theme();
    let title = issue.title();
    ui::h_flex()
        .items_start()
        .gap(px(12.))
        .p(px(12.))
        .rounded(theme.radius_lg)
        .bg(theme.secondary)
        .border_1()
        .border_color(theme.border)
        // Tests find the banner by this key (no-op outside test builds).
        .debug_selector(move || format!("issue-banner {title}"))
        .child(alert_dot(20., cx))
        .child(
            ui::v_flex()
                .flex_1()
                .min_w_0()
                .gap(px(2.))
                .child(div().font_weight(FontWeight::SEMIBOLD).child(title))
                .child(
                    div()
                        .text_sm()
                        .text_color(theme.muted_foreground)
                        .whitespace_normal()
                        .child(issue.body()),
                ),
        )
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
                            .clickable()
                            .on_click(move |_, _, cx| {
                                state.update(cx, |s, cx| s.dismiss_onboarding(cx));
                            }),
                    ),
                ),
        )
}

impl MainScreen {
    pub(super) fn render_detail(&self, _window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        // A selection change wipes the decrypted attachment preview before anything draws.
        self.state
            .update(cx, |s, cx| s.follow_attachment_selection(cx));
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
        let content: AnyElement = match s.shown_item() {
            // Edit mode and onboarding are controls throughout, including in the band.
            _ if s.is_editing() => ui::no_window_drag(div().size_full())
                .child(self.render_editing(s, cx))
                .into_any_element(),
            Some(item) => ReadDetail {
                state: &self.state,
                revealed: &s.revealed,
                history_open: s.history_open,
                actions: DetailActions::main(self.state.clone()),
                standalone: false,
            }
            .render_item(item, s, cx)
            .into_any_element(),
            None if detail_placeholder(s) == Some(ONBOARDING_TITLE) => {
                ui::no_window_drag(div().size_full())
                    .child(onboarding(&self.state, cx))
                    .into_any_element()
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
        let save_sheet = attachments::save_sheet(s, &self.state, cx);
        let droppable = s.can_attach();
        let drop_state = self.state.clone();
        let drop_tint = cx.theme().primary.opacity(0.08);

        ui::v_flex()
            .id("detail")
            .debug_selector(|| "detail-column".into())
            .track_focus(&self.detail_focus)
            .key_context(DETAIL_CONTEXT)
            .size_full()
            .relative()
            .map(|el| ui::focus_ring(el, cx))
            // Files dropped from Finder become attachments of the shown item.
            .when(droppable, |col| {
                col.drag_over::<ExternalPaths>(move |style, _, _, _| style.bg(drop_tint))
                    .on_drop(move |paths: &ExternalPaths, _, cx| {
                        let paths = paths.paths().to_vec();
                        drop_state.update(cx, |s, cx| s.add_attachment_files(paths, cx));
                    })
            })
            .children(
                banners
                    .into_iter()
                    .map(|b| ui::no_window_drag(div()).child(b)),
            )
            .child(ui::panel_in(
                div().flex_1().min_h_0().child(content),
                ("detail-in", motion_key),
                0.,
                reduce_motion,
            ))
            .when_some(toast, |col, message| {
                col.child(ui::detail_copy_feedback(message, cx))
            })
            .children(save_sheet)
            .into_any_element()
    }

    /// Edit mode: the editor, with the attachments strip pinned below it (existing items
    /// only; a new item is not in the vault yet).
    fn render_editing(&self, s: &AppState, cx: &App) -> AnyElement {
        let editor = self.editor.clone().into_any_element();
        let strip = match (&s.mode, s.shown_item()) {
            (Mode::Edit(_), Some(item)) => attachments::section(s, &self.state, item, true, cx),
            _ => None,
        };
        let Some(strip) = strip else {
            return editor;
        };
        ui::v_flex()
            .size_full()
            .child(div().flex_1().min_h_0().child(editor))
            .child(
                div()
                    .id("attachments-edit")
                    .flex_none()
                    .max_h(px(220.))
                    .overflow_y_scroll()
                    .px(px(ui::COLUMN_PAD_X - ui::FOCUS_RING_WIDTH))
                    .py(px(8.))
                    .border_t_1()
                    .border_color(cx.theme().border)
                    .child(strip),
            )
            .into_any_element()
    }
}

impl ReadDetail<'_> {
    pub(crate) fn render_item(
        &self,
        item: &Item,
        s: &AppState,
        cx: &App,
    ) -> gpui::Stateful<gpui::Div> {
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
            .debug_selector(|| "detail-header".into())
            .gap(px(14.))
            .child(avatar(item.id, &item.title, 44.))
            .child(
                ui::v_flex()
                    .flex_1()
                    .min_w_0()
                    .child(
                        div()
                            .debug_selector({
                                let title = item.title.clone();
                                move || format!("detail-title {title}")
                            })
                            .text_xl()
                            .font_weight(FontWeight::SEMIBOLD)
                            .truncate()
                            .child(item.title.clone()),
                    )
                    .child(ui::muted(kind_singular(item.kind), cx)),
            )
            // The buttons reach into the title-bar band: clicks there must not move the window.
            .when(!self.standalone, |header| {
                header.child(
                    ui::no_window_drag(ui::h_flex())
                        .debug_selector(|| "detail-header-buttons".into())
                        .flex_none()
                        .gap(px(14.))
                        .child(favorite)
                        .child(
                            ui::icon_button("delete", IconName::Trash, "Delete  ⌘⌫").on_click(
                                |_, window, cx| window.dispatch_action(Box::new(DeleteItem), cx),
                            ),
                        )
                        .child(
                            Button::new("edit")
                                .small()
                                .label("Edit")
                                .tooltip("Edit  ⌘E")
                                .clickable()
                                .on_click(|_, window, cx| {
                                    window.dispatch_action(Box::new(EditItem), cx)
                                }),
                        ),
                )
            });

        let mut fields: Vec<AnyElement> = Vec::with_capacity(item.fields.len() + 1);
        for (ix, field) in item.fields.iter().enumerate() {
            fields.push(self.render_field(ix, field, item, now, cx));
            if Some(ix) == first_password && !item.history.is_empty() {
                fields.push(self.render_history(item, now, cx));
            }
        }

        ui::v_flex()
            .id("detail-scroll")
            .size_full()
            .overflow_y_scroll()
            .pt(px(if self.standalone {
                16.
            } else {
                ui::content_top(s)
            }))
            .px(px(ui::COLUMN_PAD_X - ui::FOCUS_RING_WIDTH))
            .pb(px(64.))
            .gap(px(12.))
            .child(header)
            // Everything below the header holds controls and can scroll up into the
            // title-bar band; mark it so clicks there never move the window.
            .when(!self.standalone, |col| {
                col.children(
                    prompts::delete(s, self.state, cx).map(|p| ui::no_window_drag(div()).child(p)),
                )
            })
            .when(!item.tags.is_empty(), |col| {
                col.child(
                    ui::h_flex().gap(px(6.)).flex_wrap().children(
                        item.tags
                            .iter()
                            .map(|t| Tag::secondary().small().child(format!("#{t}"))),
                    ),
                )
            })
            .children(
                s.listing
                    .issues(item.id)
                    .iter()
                    .map(|issue| ui::no_window_drag(div()).child(issue_banner(issue, cx))),
            )
            .child(ui::divider(cx))
            // Every field row (and the history disclosure) draws its own bottom border, so
            // the last row's border already closes the group above the footer. Only the
            // no-fields message needs a rule of its own.
            .when(item.fields.is_empty(), |col| {
                col.child(ui::muted("This item has no fields.", cx))
                    .child(ui::divider(cx))
            })
            .child(ui::no_window_drag(ui::v_flex()).children(fields))
            .children(
                (if self.standalone {
                    attachments::reference_section(s, item, cx)
                } else {
                    attachments::section(s, self.state, item, false, cx)
                })
                .map(|a| ui::no_window_drag(div()).child(a)),
            )
            .child(
                ui::muted(
                    format!(
                        "modified {} · {device}",
                        text::relative(now, item.modified_at)
                    ),
                    cx,
                )
                .debug_selector(|| "detail-footer".into()),
            )
    }

    fn render_field(
        &self,
        ix: usize,
        field: &Field,
        item: &Item,
        now: u64,
        cx: &App,
    ) -> AnyElement {
        let theme = cx.theme();
        let revealed = self.revealed.contains(&field.name);
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
                    reveal_button(ix, &field.name, revealed, "card number", &self.actions)
                        .into_any_element(),
                );
                if revealed {
                    mono(value.to_string(), cx).into_any_element()
                } else {
                    mono(text::mask_card(value), cx).into_any_element()
                }
            }
            // A field kind from a newer app version may hold a secret: keep it concealed
            // behind the same reveal toggle as a password.
            FieldKind::Password | FieldKind::Other => {
                let what = if field.kind == FieldKind::Password {
                    "password  ⌘⇧R"
                } else {
                    "value"
                };
                buttons.push(
                    reveal_button(ix, &field.name, revealed, what, &self.actions)
                        .into_any_element(),
                );
                if revealed {
                    mono(value.to_string(), cx).into_any_element()
                } else {
                    mono(text::DOTS, cx)
                        .debug_selector(move || format!("field-masked {ix}"))
                        .text_color(theme.muted_foreground)
                        .into_any_element()
                }
            }
            FieldKind::Totp => self.render_totp(ix, field, now, cx),
            FieldKind::Url => {
                let actions = self.actions.clone();
                buttons.push(
                    ui::icon_button(("open", ix), IconName::ExternalLink, "Open in browser  ⌘⇧O")
                        .on_click(move |_, _, cx| {
                            (actions.0)(DetailAction::OpenUrl(ix), cx);
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
                &self.actions,
            )
            .into_any_element(),
        );

        ui::v_flex()
            .debug_selector(move || format!("field-row {ix}"))
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
                    .child(copy_on_click(ix, &field.name, shown, &self.actions, cx))
                    .children(buttons),
            )
            .into_any_element()
    }

    fn render_totp(&self, ix: usize, field: &Field, now_ms: u64, cx: &App) -> AnyElement {
        let theme = cx.theme();
        let Some(totp) = parse_totp(&field.value) else {
            return ui::muted("Invalid one-time code setup", cx)
                .debug_selector(|| "totp-invalid".into())
                .into_any_element();
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

        let code = text::group_code(&totp.code(now));
        ui::h_flex()
            .gap(px(12.))
            .child(
                mono(code.clone(), cx)
                    // Tests find the shown code by this key (no-op outside test builds).
                    .debug_selector(move || format!("totp-code {code}"))
                    .text_lg()
                    .font_weight(FontWeight::SEMIBOLD)
                    .when(urgent, |d| d.text_color(theme.warning)),
            )
            .child(ring)
            .into_any_element()
    }

    fn render_history(&self, item: &Item, now: u64, cx: &App) -> AnyElement {
        let entries: Vec<&HistoryEntry> = item.history.iter().collect();
        history_view(
            &entries,
            None,
            self.state,
            self.history_open,
            self.actions.clone(),
            now,
            cx,
        )
    }
}

/// Password history disclosure (§2.3): a toggle and, when open, the previous values
/// masked with their timestamps, each copyable. `removed` is `Some(pending removals)` in
/// edit mode, which adds a trash button per entry and a "Clear history" button; removing
/// never reveals a value.
pub(super) fn history_disclosure(
    history: &[&HistoryEntry],
    removed: Option<usize>,
    s: &AppState,
    state: &Entity<AppState>,
    now: u64,
    cx: &App,
) -> AnyElement {
    history_view(
        history,
        removed,
        state,
        s.history_open,
        DetailActions::main(state.clone()),
        now,
        cx,
    )
}

fn history_view(
    history: &[&HistoryEntry],
    removed: Option<usize>,
    state: &Entity<AppState>,
    open: bool,
    actions: DetailActions,
    now: u64,
    cx: &App,
) -> AnyElement {
    let theme = cx.theme();
    let editing = removed.is_some();
    let count = history.len().min(HISTORY_SHOWN);
    let pending = removed.unwrap_or(0);
    let toggle = {
        let actions = actions.clone();
        ui::h_flex()
            .id("history-toggle")
            .debug_selector(|| "history-toggle".into())
            .tab_index(0)
            .gap(px(4.))
            .py(px(6.))
            .rounded(theme.radius)
            .map(|el| ui::focus_ring(el, cx))
            .clickable()
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
            .when(pending > 0, |row| {
                row.child(format!("\u{b7} {pending} removed on save"))
            })
            .on_click(move |_, _, cx| (actions.0)(DetailAction::ToggleHistory, cx))
    };

    let entries = history
        .iter()
        .take(HISTORY_SHOWN)
        .enumerate()
        .map(|(j, h)| {
            let stamp = h.replaced_at;
            let copy = {
                let actions = actions.clone();
                // By stamp in the stored item: in edit mode the shown list skips removals.
                ui::icon_button(
                    ("history-copy", j),
                    IconName::Copy,
                    "Copy previous password",
                )
                .debug_selector(move || format!("history-copy {j}"))
                .on_click(move |_, _, cx| (actions.0)(DetailAction::CopyHistory(stamp), cx))
            };
            let remove = editing.then(|| {
                let state = state.clone();
                ui::icon_button(
                    ("history-remove", j),
                    IconName::Trash,
                    "Remove from history",
                )
                .debug_selector(move || format!("history-remove {j}"))
                .on_click(move |_, _, cx| {
                    state.update(cx, |s, cx| s.edit(cx, |b| b.remove_history(stamp)))
                })
            });
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
                        text::date(stamp),
                        text::relative(now, stamp)
                    ),
                    cx,
                ))
                .child(copy)
                .children(remove)
        });

    let clear = (editing && count > 0).then(|| {
        let state = state.clone();
        ui::h_flex().pl(px(18.)).pt(px(2.)).child(
            Button::new("history-clear")
                .debug_selector(|| "history-clear".into())
                .link()
                .xsmall()
                .label("Clear history")
                .clickable()
                .on_click(move |_, _, cx| {
                    state.update(cx, |s, cx| s.edit(cx, |b| b.clear_history()))
                }),
        )
    });

    ui::v_flex()
        .pb(px(6.))
        .border_b_1()
        .border_color(theme.border)
        .child(toggle)
        .when(open, |col| col.children(entries).children(clear))
        .into_any_element()
}

#[cfg(test)]
mod tests {
    //! Headless render tests for the password warnings and the field-group separator.

    use std::sync::Arc;

    use gpui::{AppContext as _, TestAppContext, VisualTestContext};
    use gpui_component::Root;
    use vault_core::{ItemKind, KdfParams, SecretString, Uuid};
    use vault_sync::{NoopHooks, SyncedVault};

    use super::super::MainScreen;
    use super::*;
    use crate::actions;
    use crate::clipboard::fake::FakePasteboard;

    const STRONG: &str = "correct-Horse-battery-staple-42";
    const TOTP_URI: &str = "otpauth://totp/GitHub:chris?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";

    fn login(title: &str, password: &str, device: Uuid) -> Item {
        let mut item = Item::new(ItemKind::Login, title, device, 1);
        item.fields.push(Field::new(
            "username",
            FieldKind::Text,
            SecretString::new("chris".into()),
            1,
        ));
        item.fields.push(Field::new(
            "password",
            FieldKind::Password,
            SecretString::new(password.into()),
            1,
        ));
        item
    }

    /// The main screen over a vault holding one login per `(title, password)`.
    fn open(
        dir: &std::path::Path,
        logins: &[(&str, &str)],
        cx: &mut TestAppContext,
    ) -> (Entity<AppState>, Vec<Uuid>, VisualTestContext) {
        let logins = logins.to_vec();
        open_items(
            dir,
            move |device| logins.iter().map(|(t, pw)| login(t, pw, device)).collect(),
            cx,
        )
    }

    /// The main screen over a vault holding the items `make(device_id)` builds.
    fn open_items(
        dir: &std::path::Path,
        make: impl FnOnce(Uuid) -> Vec<Item>,
        cx: &mut TestAppContext,
    ) -> (Entity<AppState>, Vec<Uuid>, VisualTestContext) {
        let mut vault = SyncedVault::create(
            &dir.join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let ids = vault
            .edit(|v| {
                make(v.device_id())
                    .into_iter()
                    .map(|item| v.insert(item, 1))
                    .collect::<Vec<_>>()
            })
            .unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(|cx| {
            gpui_component::init(cx);
            actions::bind_keys(cx);
            actions::register(&state, cx);
        });
        state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
        let mut main = None;
        let window = cx.add_window(|window, cx| {
            crate::theme::apply(window, cx);
            let view = cx.new(|cx| MainScreen::new(state.clone(), None, window, cx));
            main = Some(view.clone());
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        let main = main.unwrap();
        vcx.update(|window, cx| main.update(cx, |m, cx| m.appear(window, cx)));
        vcx.run_until_parked();
        (state, ids, vcx)
    }

    fn select(state: &Entity<AppState>, id: Uuid, vcx: &mut VisualTestContext) {
        vcx.update(|_, cx| state.update(cx, |s, cx| s.select(id, cx)));
        vcx.run_until_parked();
    }

    fn shown(key: &'static str, vcx: &mut VisualTestContext) -> bool {
        vcx.debug_bounds(key).is_some()
    }

    /// Edits the selected item's password field to `password` and saves.
    fn change_password(state: &Entity<AppState>, password: &str, vcx: &mut VisualTestContext) {
        vcx.update(|_, cx| {
            state.update(cx, |s, cx| {
                s.begin_edit(cx);
                let b = s.edit_buffer().unwrap();
                let ix = b
                    .item
                    .fields
                    .iter()
                    .position(|f| f.kind == FieldKind::Password)
                    .unwrap();
                let key = b.keys[ix];
                s.set_edit_value(key, SecretString::new(password.into()), cx);
                s.save_edit(cx);
                assert!(!s.is_editing());
            });
        });
        vcx.run_until_parked();
    }

    #[gpui::test]
    fn weak_password_shows_badge_and_banner_until_fixed(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, ids, mut vcx) = open(dir.path(), &[("Bank", "123")], cx);
        select(&state, ids[0], &mut vcx);
        assert!(shown("issue-badge Weak password", &mut vcx));
        assert!(shown("issue-banner Weak Password", &mut vcx));
        assert!(!shown("issue-banner Reused Password", &mut vcx));

        change_password(&state, STRONG, &mut vcx);
        assert!(!shown("issue-badge Weak password", &mut vcx));
        assert!(!shown("issue-banner Weak Password", &mut vcx));
    }

    #[gpui::test]
    fn reused_password_flags_both_items(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, ids, mut vcx) = open(dir.path(), &[("Alpha", STRONG), ("Beta", STRONG)], cx);
        select(&state, ids[0], &mut vcx);
        // One badge per row, both rows flagged.
        assert!(shown("issue-badge Reused password", &mut vcx));
        let rows = state.read_with(&vcx, |s, _| s.listing.issues.len());
        assert_eq!(rows, 2);
        assert!(shown("issue-banner Reused Password", &mut vcx));
        assert!(!shown("issue-banner Weak Password", &mut vcx));

        change_password(&state, "an-entirely-Different-passphrase-7", &mut vcx);
        assert!(!shown("issue-badge Reused password", &mut vcx));
        assert!(!shown("issue-banner Reused Password", &mut vcx));
    }

    #[gpui::test]
    fn search_reuses_the_audit_and_edits_redo_it(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, ids, mut vcx) = open(dir.path(), &[("Alpha", "123"), ("Beta", STRONG)], cx);
        let before = state.read_with(&vcx, |s, _| s.listing.issues.clone());
        vcx.update(|_, cx| state.update(cx, |s, cx| s.set_query("Al".into(), cx)));
        let after = state.read_with(&vcx, |s, _| s.listing.issues.clone());
        assert!(std::rc::Rc::ptr_eq(&before, &after), "search re-audited");
        assert_eq!(after.len(), 1);

        vcx.update(|_, cx| state.update(cx, |s, cx| s.set_query(String::new(), cx)));
        select(&state, ids[0], &mut vcx);
        change_password(&state, STRONG, &mut vcx);
        let edited = state.read_with(&vcx, |s, _| s.listing.issues.clone());
        assert!(!std::rc::Rc::ptr_eq(&before, &edited));
        // Alpha now shares Beta's password.
        assert!(
            edited
                .values()
                .all(|v| matches!(v.as_slice(), [Issue::Reused { count: 2 }]))
        );
    }

    /// Opens one login (username, password, totp) with a fake pasteboard installed.
    fn open_with_board(
        dir: &std::path::Path,
        cx: &mut TestAppContext,
    ) -> (Entity<AppState>, FakePasteboard, VisualTestContext) {
        let (state, ids, mut vcx) = open_items(
            dir,
            |device| {
                let mut item = login("GitHub", STRONG, device);
                item.fields.push(Field::new(
                    "totp",
                    FieldKind::Totp,
                    SecretString::new(TOTP_URI.into()),
                    1,
                ));
                vec![item]
            },
            cx,
        );
        let board = FakePasteboard::default();
        vcx.update(|_, cx| {
            state.update(cx, |s, _| {
                s.set_pasteboard(Box::new(board.clone()));
                s.settings.clipboard_clear_secs = 30;
            });
        });
        select(&state, ids[0], &mut vcx);
        (state, board, vcx)
    }

    fn click(key: &'static str, vcx: &mut VisualTestContext) {
        let at = vcx.debug_bounds(key).expect(key).center();
        vcx.simulate_click(at, gpui::Modifiers::none());
        vcx.run_until_parked();
    }

    #[gpui::test]
    fn clicking_the_password_copies_it_and_keeps_it_masked(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, board, mut vcx) = open_with_board(dir.path(), cx);
        click("field-value 1", &mut vcx);
        assert_eq!(board.contents().as_deref(), Some(STRONG));
        state.read_with(&vcx, |s, _| {
            let toast = s.toast.as_ref().expect("copied pill");
            assert_eq!(toast.message.as_ref(), "Copied — clears in 30 s");
            assert_eq!(toast.place, ToastPlace::Detail);
            assert!(s.revealed.is_empty(), "the click revealed the password");
        });
        // Same auto-clear as the Copy button.
        vcx.executor().advance_clock(Duration::from_secs(31));
        vcx.run_until_parked();
        assert_eq!(board.contents(), None);
    }

    #[gpui::test]
    fn clicking_the_totp_copies_the_current_code(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (_state, board, mut vcx) = open_with_board(dir.path(), cx);
        let totp = parse_totp(&SecretString::new(TOTP_URI.into())).unwrap();
        let before = totp.code(text::now_millis() / 1000);
        click("field-value 2", &mut vcx);
        let after = totp.code(text::now_millis() / 1000);
        let copied = board.contents().expect("copied");
        assert_eq!(copied.len(), 6);
        assert!(copied.bytes().all(|b| b.is_ascii_digit()));
        assert!(copied == before || copied == after, "not the current code");
    }

    #[gpui::test]
    fn enter_on_a_focused_value_copies(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (_state, board, mut vcx) = open_with_board(dir.path(), cx);
        click("field-value 0", &mut vcx);
        assert_eq!(board.contents().as_deref(), Some("chris"));
        board.set("elsewhere");
        // The click focused the value area; Enter clicks it again (on key up).
        vcx.simulate_keystrokes("enter");
        vcx.simulate_event(gpui::KeyUpEvent {
            keystroke: gpui::Keystroke::parse("enter").unwrap(),
        });
        vcx.run_until_parked();
        assert_eq!(board.contents().as_deref(), Some("chris"));
    }

    #[gpui::test]
    fn clicking_in_edit_mode_copies_nothing(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, board, mut vcx) = open_with_board(dir.path(), cx);
        let at = vcx.debug_bounds("field-value 1").unwrap().center();
        vcx.update(|_, cx| state.update(cx, |s, cx| s.begin_edit(cx)));
        vcx.run_until_parked();
        assert!(
            !shown("field-value 1", &mut vcx),
            "editor shows click-to-copy"
        );
        vcx.simulate_click(at, gpui::Modifiers::none());
        vcx.run_until_parked();
        assert_eq!(board.contents(), None);
        state.read_with(&vcx, |s, _| assert!(s.toast.is_none()));
    }

    #[gpui::test]
    fn one_rule_between_last_field_and_footer(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, ids, mut vcx) = open(dir.path(), &[("Alpha", STRONG)], cx);
        select(&state, ids[0], &mut vcx);
        let last = vcx.debug_bounds("field-row 1").expect("last field row");
        let footer = vcx.debug_bounds("detail-footer").expect("footer");
        // The last row's own bottom border is the only rule: the footer follows after
        // exactly one column gap, with no extra divider (1 px + another gap) between.
        assert_eq!(footer.top() - last.bottom(), px(12.));
    }
}
