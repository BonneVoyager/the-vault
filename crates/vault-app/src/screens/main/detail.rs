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
    prelude::FluentBuilder as _, px, relative,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::progress::ProgressCircle;
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{ExposeSecret, Field, FieldKind, HistoryEntry, Item};

use super::MainScreen;
use super::attachments;
use super::icon_view::item_tile;
use super::list::alert_dot;
use super::prompts;
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

/// Top and bottom padding of a field row (owner 2026-10-31: was 12 px in the detail
/// column and item window, 8 px in the backup viewer; now 7 px everywhere).
pub(crate) const FIELD_ROW_PAD_Y: f32 = 7.;

/// Label and value text colours of a field row, Apple Passwords style (owner
/// 2026-10-31): the label in the foreground colour, the value (revealed or masked
/// secrets and notes included) in the muted foreground. Links, the urgent one-time
/// code and the copy/reveal buttons keep their own colours.
pub(crate) fn field_row_colors(cx: &App) -> (gpui::Hsla, gpui::Hsla) {
    let theme = cx.theme();
    (theme.foreground, theme.muted_foreground)
}

/// One field row, shared by the detail column, item windows and the backup viewer: the
/// label column, then the value (filling the width) and its buttons.
pub(crate) fn field_row(
    ix: usize,
    label: SharedString,
    value: impl IntoElement,
    buttons: Vec<AnyElement>,
    cx: &App,
) -> gpui::Div {
    let theme = cx.theme();
    let (label_color, value_color) = field_row_colors(cx);
    ui::h_flex()
        .debug_selector(move || format!("field-row {ix}"))
        .w_full()
        .items_start()
        .py(px(FIELD_ROW_PAD_Y))
        .gap(px(16.))
        .border_b_1()
        .border_color(theme.border)
        .child(
            div()
                .debug_selector(move || format!("field-label {ix}"))
                .w(relative(0.26))
                .min_w(px(80.))
                .max_w(px(140.))
                .flex_shrink_0()
                .pt(px(3.))
                .whitespace_normal()
                .text_color(label_color)
                // Display only: the stored name keeps its spelling ("username" shows
                // "Username"; the editor's name inputs show it as stored).
                .child({
                    let shown = text::capitalize_first(&label);
                    let selector = format!("field-label-text {ix} {shown}");
                    div().debug_selector(move || selector.clone()).child(shown)
                }),
        )
        .child(
            ui::h_flex()
                .debug_selector(move || format!("field-content {ix}"))
                .flex_1()
                .min_w_0()
                .items_start()
                .gap(px(4.))
                .min_h(px(28.))
                .child(
                    ui::h_flex()
                        .flex_1()
                        .min_w_0()
                        .text_color(value_color)
                        .child(value),
                )
                .child(ui::h_flex().flex_none().gap(px(4.)).children(buttons)),
        )
}

/// A section heading row (01 §4 `"section"`), shared like [`field_row`]: the name
/// upper-cased, bold and small in the muted foreground (a macOS grouped-table section
/// header), spanning the row, with no value, actions, click-to-copy or pointer. Its
/// rule is 2 px instead of the 1 px hairline. A heading below other rows gets extra
/// space above it; as the first row it sits under the tags rule like any first row.
pub(crate) fn section_row(ix: usize, name: &str, cx: &App) -> gpui::Div {
    let theme = cx.theme();
    let heading = name.trim().to_uppercase();
    let selector = format!("section-row {ix} {heading}");
    let top = if ix == 0 {
        FIELD_ROW_PAD_Y
    } else {
        FIELD_ROW_PAD_Y + SECTION_GAP
    };
    div()
        .debug_selector(move || selector.clone())
        .w_full()
        .pt(px(top))
        .pb(px(FIELD_ROW_PAD_Y))
        .border_b_2()
        .border_color(theme.border)
        .text_xs()
        .font_weight(FontWeight::BOLD)
        .text_color(theme.muted_foreground)
        .whitespace_normal()
        .child(heading)
}

/// Extra space above a section heading that follows other rows.
pub(crate) const SECTION_GAP: f32 = 12.;

/// The footer line: "created <date> · modified <date> · <device>", or without the
/// created part when the item's creation time is unknown (older vaults). Both dates use
/// the same rule: relative within 30 days ("37m ago"), else the UTC date (2021-10-03).
pub(crate) fn footer_text(item: &Item, now: u64, device: &str) -> String {
    let modified = text::relative(now, item.modified_at);
    match item.created_at {
        Some(created) => format!(
            "created {} · modified {modified} · {device}",
            text::relative(now, created)
        ),
        None => format!("modified {modified} · {device}"),
    }
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
        self.state.update(cx, |s, cx| {
            s.follow_attachment_selection(cx);
            s.load_icon_images(cx);
        });
        let s = self.state.read(cx);
        let toast = s
            .toast
            .as_ref()
            .filter(|t| t.place == ToastPlace::Detail)
            .map(|t| t.message.clone());

        // Selecting another item fades the column in (05 §5). Entering or leaving edit
        // mode does not: keying on the mode replayed the fade from transparent (a blink).
        let motion_key = s.selection.map_or(0, |id| id.as_u128() as usize);
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
                div()
                    .flex_1()
                    .min_h_0()
                    .child(content)
                    // Records this content's identity per frame (tests only).
                    .children(ui::test_probe("detail-content-probe")),
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
            .child(item_tile(item, Some(s), 44., cx))
            .child(
                ui::v_flex().flex_1().min_w_0().child(
                    div()
                        .debug_selector({
                            let title = item.title.clone();
                            move || format!("detail-title {title}")
                        })
                        .text_xl()
                        .font_weight(FontWeight::SEMIBOLD)
                        .truncate()
                        .child(item.title.clone()),
                ),
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
            // The rule and the rows form one group without the column's gap, so the
            // first row sits under the rule exactly as each row sits under the one above:
            // only its own `FIELD_ROW_PAD_Y` top padding. Every field row (and the history
            // disclosure) draws its own bottom border, so the last row's border already
            // closes the group above the footer. Only the no-fields message needs a rule
            // of its own.
            .child(
                ui::v_flex()
                    .child(ui::divider(cx).debug_selector(|| "detail-fields-rule".into()))
                    .when(item.fields.is_empty(), |col| {
                        col.child(ui::muted("This item has no fields.", cx).py(px(FIELD_ROW_PAD_Y)))
                            .child(ui::divider(cx))
                    })
                    .child(ui::no_window_drag(ui::v_flex()).children(fields)),
            )
            .children(
                (if self.standalone {
                    attachments::reference_section(s, item, cx)
                } else {
                    attachments::section(s, self.state, item, false, cx)
                })
                .map(|a| ui::no_window_drag(div()).child(a)),
            )
            .child(
                ui::muted(footer_text(item, now, &device), cx)
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
        if field.kind == FieldKind::Section {
            return section_row(ix, &field.name, cx).into_any_element();
        }
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
            // Rendered as a heading before this match (see `render_field`); unreachable.
            FieldKind::Section => div().into_any_element(),
            FieldKind::Text | FieldKind::Email | FieldKind::Date | FieldKind::MonthYear => {
                div().truncate().child(value.to_string()).into_any_element()
            }
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

        field_row(
            ix,
            field.name.clone().into(),
            copy_on_click(ix, &field.name, shown, &self.actions, cx),
            buttons,
            cx,
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
            .min_w_0()
            .flex_wrap()
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
#[path = "detail_tests.rs"]
mod tests;
