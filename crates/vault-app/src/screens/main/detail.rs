//! Detail column (specs/05-ui.md §2.3). Read mode: fields per `FieldKind`, reveal and
//! copy, password history, live TOTP with countdown ring, modified footer, copy pill,
//! inline delete confirm. Edit and new-item modes hand the column to the `Editor`.
//!
//! Secrets are exposed only for a revealed field, a TOTP code, or the copy actions.

use std::time::Duration;
use std::{collections::HashSet, rc::Rc};

use gpui::{
    Animation, AnimationExt as _, AnyElement, App, Context, Entity, ExternalPaths, FontWeight,
    InteractiveElement as _, IntoElement, ParentElement as _, Pixels, SharedString,
    StatefulInteractiveElement as _, Styled as _, Window, div, ease_in_out,
    prelude::FluentBuilder as _, px, relative,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::progress::ProgressCircle;
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{ExposeSecret, Field, FieldKind, HistoryEntry, Item, Uuid};

use super::MainScreen;
use super::attachments;
use super::icon_view::item_tile;
use super::list::alert_dot;
use super::prompts;
use super::sync_banners;
use crate::actions::{DETAIL_CONTEXT, DeleteItem, EditItem, RecoverItem, ToggleFavorite};
use crate::audit::FieldIssue;
use crate::state::{AppState, CopyTarget, Mode, ToastPlace, expiry_text, parse_totp};
use crate::ui::Clickable as _;
use crate::{text, ui};

/// History entries shown in the disclosure (01 §4 caps history at 10 anyway).
const HISTORY_SHOWN: usize = 10;
/// The code turns amber and the ring pulses under this many seconds (§2.3 "under 5 s").
const TOTP_URGENT_SECS: u32 = 5;
/// Height cap of the pinned tags block (about two and a half rows of small tags, so a
/// clipped third row shows there is more to scroll).
const TAGS_MAX_H: f32 = 64.;

#[derive(Clone)]
pub(crate) enum DetailAction {
    Copy(CopyTarget),
    /// A history entry by `(replaced_at, field_id)`: entries of two fields saved in one
    /// edit share a stamp.
    CopyHistory(u64, Option<Uuid>),
    Reveal(Uuid),
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
                DetailAction::CopyHistory(stamp, field) => {
                    if let Some(ix) = s.viewed_item().and_then(|item| {
                        item.history
                            .iter()
                            .position(|h| h.replaced_at == stamp && h.field_id == field)
                    }) {
                        s.copy(CopyTarget::History(ix), cx);
                    }
                }
                DetailAction::Reveal(field) => s.toggle_reveal(field, cx),
                DetailAction::OpenUrl(ix) => s.open_url(Some(ix), cx),
                DetailAction::ToggleHistory => s.toggle_history(cx),
            })
        }))
    }
}

/// One read-mode renderer for the main detail column and pinned item windows.
pub(crate) struct ReadDetail<'a> {
    pub state: &'a Entity<AppState>,
    pub revealed: &'a HashSet<Uuid>,
    pub history_open: bool,
    pub actions: DetailActions,
    pub standalone: bool,
    /// Width of the field rows (`rows_width` of the column), for the label column cap.
    pub rows_width: Pixels,
    /// ⌥ is held (05 §2.3 "Hold ⌥ to reveal"): masked values render revealed without
    /// touching `revealed`. The reveal buttons keep showing the per-field toggle.
    pub peek: bool,
    /// Where the item comes from (the open vault, or a backup in the backup viewer).
    pub source: ItemSource<'a>,
    /// Header buttons in place of Favorite / Delete / Edit, for standalone windows only
    /// (the main detail column draws its own; both would duplicate the header buttons).
    /// `None` shows none.
    pub header_buttons: Option<AnyElement>,
}

/// The vault a [`ReadDetail`] item belongs to.
#[derive(Clone, Copy)]
pub(crate) enum ItemSource<'a> {
    /// The open vault: notices from `AppState::listing`, custom icon images and
    /// attachment states from the live session.
    Live,
    /// A decrypted backup (03 §4 "Restore"): password notices judged against the backup's
    /// own items (`issues`), the automatic tile (backups hold no blobs), and attachments
    /// listed as Missing (`attachments::backup_section`).
    Backup(&'a crate::audit::Issues),
}

/// True when the selected item shows a TOTP code (the view then re-renders every second).
pub fn shows_totp(s: &AppState) -> bool {
    s.main_active()
        && s.viewed_item()
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
    field: Uuid,
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
    ui::icon_button(("reveal", ix), icon, &format!("{verb} {what}"))
        // Tests click the toggle by this key (no-op outside test builds).
        .debug_selector(move || format!("field-reveal {ix}"))
        .on_click(move |_, _, cx| (actions.0)(DetailAction::Reveal(field), cx))
}

/// A field's value area in read mode: clicking it does exactly what the row's Copy
/// button does (`AppState::copy`), so a masked value is copied without being revealed.
/// Focusable, so Enter or Space on it copies too (gpui clicks a focused div on key up).
fn copy_on_click(
    ix: usize,
    field: Uuid,
    what: &str,
    shown: AnyElement,
    actions: &DetailActions,
    cx: &App,
) -> impl IntoElement {
    let actions = actions.clone();
    ui::copy_value_area(("field-value", ix), what, cx)
        // Tests click the value by this key (no-op outside test builds).
        .debug_selector(move || format!("field-value {ix}"))
        .on_click(move |_, _, cx| (actions.0)(DetailAction::Copy(CopyTarget::Field(field)), cx))
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

/// Gap between a field's icon and its label (05 "Field icons").
pub(crate) const FIELD_ICON_GAP: f32 = 8.;

/// The item title's text style, shared by the read-mode header and the editor's title
/// input so pressing Edit does not change the title's look (05, 2026-11-16).
pub(crate) fn title_text<E: gpui::Styled>(el: E) -> E {
    el.text_xl().font_weight(FontWeight::SEMIBOLD)
}

/// Gap between a field row's label column and its value column.
pub(crate) const FIELD_ROW_GAP: f32 = 16.;

/// Minimum height of a field row's value line (fits the row's icon buttons).
pub(crate) const FIELD_LINE_MIN_H: f32 = 28.;

/// The label column's base rule: 26 % of the row, 80 to 140 px.
const LABEL_MIN: f32 = 80.;
const LABEL_MAX: f32 = 140.;
/// Cap on a column widened to fit a long label, as a fraction of the row.
const LABEL_FIT_CAP: f32 = 0.40;

/// The label column's width rule, shared by read mode and the editor's rows (the editor
/// passes `editor::edit_label_width`: 140 px on wide rows, owner 2026-11-21). `width`
/// is [`label_width`]: `None` keeps the base rule (26 % of the row, 80 to 140 px)
/// untouched; `Some` is the widened column for a long label.
pub(crate) fn label_column<E: gpui::Styled>(el: E, width: Option<Pixels>) -> E {
    let el = el.flex_shrink_0();
    match width {
        Some(w) => el.w(w),
        None => el
            .w(relative(0.26))
            .min_w(px(LABEL_MIN))
            .max_w(px(LABEL_MAX)),
    }
}

/// The label column's width for rows `row` wide (owner 2026-11-20):
/// `max(base, min(fit, 40 % of row))`, or `None` (the base rule) when the fit does not
/// widen it. Computed here because Taffy has no `min()`/`calc()`.
pub(crate) fn label_width(fit: Option<Pixels>, row: Pixels) -> Option<Pixels> {
    let base = (row * 0.26).clamp(px(LABEL_MIN), px(LABEL_MAX));
    let w = fit?.min(row * LABEL_FIT_CAP);
    (w > base).then_some(w)
}

/// Width of the field rows in a column `column` wide, the rows inset by the column's
/// horizontal padding (`render_item`'s `pad_x`; the editor uses the same).
pub(crate) fn rows_width(column: f32) -> Pixels {
    px((column - 2. * (ui::COLUMN_PAD_X - ui::FOCUS_RING_WIDTH)).max(0.))
}

/// The width the label column needs to show every displayed label of `fields` on one
/// line (05 §2.3, owner 2026-11-20): the widest name (sections and empty
/// names ignored) shaped as read mode draws it (theme font at `theme.font_size`, which
/// already carries the text-size scale; regular weight), plus the icon slot (`size_4`,
/// 1 rem, and the gap) when any field draws an icon. Read mode and the editor both pass
/// their fields here, so the two columns stay equal. Not cached: each render costs one
/// `shape_line` (a layout-cache hit when unchanged) and a few small allocations per
/// named field, negligible next to the rows themselves.
pub(crate) fn label_fit<'a>(
    fields: impl IntoIterator<Item = &'a Field>,
    window: &Window,
    cx: &App,
) -> Option<Pixels> {
    let font = gpui::font(cx.theme().font_family.clone());
    let size = cx.theme().font_size;
    let (mut widest, mut icon) = (None::<Pixels>, false);
    for field in fields {
        if field.kind == FieldKind::Section {
            continue;
        }
        icon |= field.icon_name().and_then(crate::icon::symbol).is_some();
        let shown = field.name.replace('\n', " ");
        if shown.trim().is_empty() {
            continue;
        }
        let run = gpui::TextRun {
            len: shown.len(),
            font: font.clone(),
            color: gpui::black(),
            background_color: None,
            underline: None,
            strikethrough: None,
        };
        let width = window
            .text_system()
            .shape_line(shown.into(), size, &[run], None)
            .width;
        widest = Some(widest.map_or(width, |w: Pixels| w.max(width)));
    }
    let slot = if icon {
        window.rem_size() + px(FIELD_ICON_GAP)
    } else {
        px(0.)
    };
    // 1 px against sub-pixel rounding in the wrap.
    widest.map(|w| (w + slot + px(1.)).ceil())
}

/// One field row, shared by the detail column, item windows and the backup viewer: the
/// label column, then the value (filling the width) and its buttons. `icon` is the
/// field's stored icon name: a known symbol is drawn left of the label (05 "Field
/// icons"); none or an unknown name leaves the row as it is without one. `issues` are
/// the field's password notices, one [`issue_strip`] each under the value (05 §2.3
/// "Password notices").
#[allow(clippy::too_many_arguments)]
pub(crate) fn field_row(
    ix: usize,
    label: SharedString,
    icon: Option<&str>,
    label_w: Option<Pixels>,
    value: impl IntoElement,
    buttons: Vec<AnyElement>,
    issues: &[FieldIssue],
    cx: &App,
) -> gpui::Div {
    let theme = cx.theme();
    let (label_color, value_color) = field_row_colors(cx);
    let symbol = icon.and_then(crate::icon::symbol);
    let icon_color = theme.muted_foreground;
    ui::h_flex()
        .debug_selector(move || format!("field-row {ix}"))
        .w_full()
        .items_start()
        .py(px(FIELD_ROW_PAD_Y))
        .gap(px(FIELD_ROW_GAP))
        .border_b_1()
        .border_color(theme.border)
        .child(
            label_column(div(), label_w)
                .debug_selector(move || format!("field-label {ix}"))
                .pt(px(3.))
                .whitespace_normal()
                .text_color(label_color)
                .when_some(symbol, |col, symbol| {
                    // A one-line-tall box (zero-width text sets its height) centres the
                    // icon on the label's first line.
                    col.flex().items_start().gap(px(FIELD_ICON_GAP)).child(
                        ui::h_flex()
                            .flex_none()
                            .debug_selector(move || format!("field-row-icon {ix} {symbol:?}"))
                            .child(Icon::new(symbol).size_4().text_color(icon_color))
                            .child(div().w_0().overflow_hidden().child("\u{200b}")),
                    )
                })
                // The label shows the stored name exactly as typed (owner 2026-11-22:
                // no display-time capitalisation).
                .child({
                    let selector = format!("field-label-text {ix} {label}");
                    div()
                        .debug_selector(move || selector.clone())
                        .when(symbol.is_some(), |d| d.flex_1().min_w_0())
                        .child(label)
                }),
        )
        .child(
            ui::v_flex()
                .flex_1()
                .min_w_0()
                .gap(px(ISSUE_STRIP_GAP))
                .child(
                    ui::h_flex()
                        .debug_selector(move || format!("field-content {ix}"))
                        .w_full()
                        .min_w_0()
                        .items_start()
                        .gap(px(4.))
                        .min_h(px(FIELD_LINE_MIN_H))
                        .child(
                            ui::h_flex()
                                .flex_1()
                                .min_w_0()
                                .text_color(value_color)
                                .child(value),
                        )
                        .child(ui::h_flex().flex_none().gap(px(4.)).children(buttons)),
                )
                .children(issues.iter().map(|fi| issue_strip(fi, cx))),
        )
}

/// Space above and between password notice strips.
pub(crate) const ISSUE_STRIP_GAP: f32 = 4.;

/// One password notice under a password field (05 §2.3 "Password notices"): a 12 px red
/// "!", the bold title and the body on one line (wrapping when narrow) on a muted red
/// background. Not clickable, not dismissable. Tests find it as
/// "issue-strip <field id> <title>".
pub(crate) fn issue_strip(fi: &FieldIssue, cx: &App) -> gpui::Div {
    let theme = cx.theme();
    let title = fi.issue.title();
    let selector = format!("issue-strip {} {title}", fi.field);
    let (dot, text) = (
        format!("issue-dot {} {title}", fi.field),
        format!("issue-text {} {title}", fi.field),
    );
    ui::h_flex()
        .debug_selector(move || selector.clone())
        .w_full()
        .min_w_0()
        .items_start()
        .gap(px(6.))
        .px(px(8.))
        .py(px(6.))
        .rounded(px(4.))
        // The danger tint of the delete confirm and the other danger cards.
        .bg(theme.danger.opacity(0.10))
        .text_xs()
        .text_color(theme.foreground)
        // The dot is centred on the first text line: a one-line-tall box (zero-width
        // text in the strip's style sets its height, so it follows the text size), as
        // `field_row` does for field icons.
        .child(
            ui::h_flex()
                .flex_none()
                .child(alert_dot(12., cx).debug_selector(move || dot.clone()))
                .child(div().w_0().overflow_hidden().child("\u{200b}")),
        )
        .child(
            div()
                .debug_selector(move || text.clone())
                .flex_1()
                .min_w_0()
                .whitespace_normal()
                .child(
                    gpui::StyledText::new(format!("{title} {}", fi.issue.body())).with_highlights(
                        [(
                            0..title.len(),
                            gpui::HighlightStyle {
                                font_weight: Some(FontWeight::BOLD),
                                ..Default::default()
                            },
                        )],
                    ),
                ),
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

/// Under a trashed item's title (pinned header): when it goes, and Delete (permanently) / Recover.
fn trash_card(deleted_at: u64, now: u64, cx: &App) -> impl IntoElement {
    let theme = cx.theme();
    let message = expiry_text(deleted_at, now);
    ui::v_flex()
        .debug_selector(|| "trash-card".into())
        .gap(px(10.))
        .px(px(12.))
        .py(px(10.))
        .rounded(theme.radius)
        .bg(theme.muted)
        .child(
            div()
                .text_sm()
                .debug_selector({
                    let message = message.clone();
                    move || format!("trash-expiry {message}")
                })
                .child(message),
        )
        .child(
            ui::h_flex()
                .justify_end()
                .gap(px(8.))
                .child(
                    Button::new("trash-delete")
                        .debug_selector(|| "trash-delete".into())
                        .small()
                        .label("Delete")
                        .text_color(theme.danger)
                        .tooltip("Delete permanently  \u{2318}\u{232b}")
                        .clickable()
                        .on_click(|_, window, cx| window.dispatch_action(Box::new(DeleteItem), cx)),
                )
                .child(
                    Button::new("trash-recover")
                        .debug_selector(|| "trash-recover".into())
                        .primary()
                        .small()
                        .label("Recover")
                        .tooltip("Recover  \u{2318}\u{21e7}Z")
                        .clickable()
                        .on_click(|_, window, cx| {
                            window.dispatch_action(Box::new(RecoverItem), cx)
                        }),
                ),
        )
}

pub const ONBOARDING_TITLE: &str = "Your vault is ready";
pub const SELECT_AN_ITEM: &str = "Select an item";

/// The placeholder the detail column shows when no item is open, if any.
pub fn detail_placeholder(s: &AppState) -> Option<&'static str> {
    if s.is_editing() || s.viewed_item().is_some() {
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
    pub(super) fn render_detail(&self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
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

        // No fade on a selection change or on Edit/Cancel (owner 2026-10-31): the new
        // content paints on the next frame. A fade keyed on the selection (or the mode)
        // showed as a blink.
        // The detail column's width as laid out this frame (`MainScreen::render`); the
        // editor's rows have the same width, so it gets it too.
        let rows_width = rows_width(self.right_width - self.fitted[1]);
        self.editor.read(cx).set_rows_width(rows_width);
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
                rows_width,
                source: ItemSource::Live,
                header_buttons: None,
                // Also checked against the window's live modifiers and the focus, so a
                // key-up that went to another dispatch path cannot leave values revealed.
                peek: s.option_reveal
                    && ui::option_alone(&window.modifiers())
                    && self.focus_in_screen(window, cx),
            }
            .render_item(item, s, window, cx)
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
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .child(content)
                    // Records this content's identity per frame (tests only).
                    .children(ui::test_probe("detail-content-probe")),
            )
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
        mut self,
        item: &Item,
        s: &AppState,
        window: &Window,
        cx: &App,
    ) -> gpui::Div {
        let theme = cx.theme();
        let fit = label_width(label_fit(&item.fields, window, cx), self.rows_width);
        let now = text::now_millis();
        let device = if item.device_id == s.device_id() {
            "this Mac".to_owned()
        } else {
            text::short_id(item.device_id)
        };
        // Recently Deleted: read-only, no header buttons; Recover / Delete in a card under the title.
        let trashed = item.is_deleted();
        let backup = matches!(self.source, ItemSource::Backup(_));
        debug_assert!(
            self.standalone || self.header_buttons.is_none(),
            "header_buttons is for standalone windows; the main column has its own"
        );
        let header_buttons = self.header_buttons.take();

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
            .child(item_tile(item, (!backup).then_some(s), 44., cx))
            .child(
                ui::v_flex().flex_1().min_w_0().child(
                    div()
                        .debug_selector({
                            let title = item.title.clone();
                            move || format!("detail-title {title}")
                        })
                        .map(title_text)
                        .truncate()
                        .child(item.title.clone()),
                ),
            )
            // The buttons reach into the title-bar band: clicks there must not move the window.
            .when(!self.standalone && !trashed, |header| {
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
            })
            .when_some(header_buttons, |header, buttons| {
                header.child(
                    ui::no_window_drag(ui::h_flex())
                        .debug_selector(|| "detail-header-buttons".into())
                        .flex_none()
                        .gap(px(14.))
                        .child(buttons),
                )
            });

        let mut fields: Vec<AnyElement> = Vec::with_capacity(item.fields.len() + 1);
        for (ix, field) in item.fields.iter().enumerate() {
            fields.push(self.render_field(ix, field, item, now, fit, cx));
            if let Some(history) = self.render_history(item, ix, now, cx) {
                fields.push(history);
            }
        }

        let pad_x = px(ui::COLUMN_PAD_X - ui::FOCUS_RING_WIDTH);

        // Pinned (05 §2.3 "Detail header is pinned"): the header, the trash card (if
        // trashed), the inline delete confirm, the tags and the rule under them stay put; everything else scrolls.
        let pinned = ui::v_flex()
            .debug_selector(|| "detail-pinned".into())
            .flex_none()
            .pt(px(if self.standalone {
                16.
            } else {
                ui::content_top(s)
            }))
            .px(pad_x)
            .gap(px(12.))
            .child(header)
            // Recently Deleted: the expiry card sits under the title, and its inline
            // confirm (from the card's Delete) directly below it, both above the tags.
            .children(
                item.deleted_at
                    .filter(|_| !self.standalone)
                    .map(|at| ui::no_window_drag(div()).child(trash_card(at, now, cx))),
            )
            .when(!self.standalone, |col| {
                col.children(
                    prompts::delete(s, self.state, cx).map(|p| ui::no_window_drag(div()).child(p)),
                )
            })
            .when(!item.tags.is_empty(), |col| {
                col.child(
                    // Capped with its own scroll: many wrapping tags must not squeeze the
                    // fields out of a small window.
                    ui::h_flex()
                        .id("detail-tags")
                        .debug_selector(|| "detail-tags".into())
                        // The editor's tags row height: Edit does not move the rows.
                        .min_h(crate::theme::scaled(super::editor::TAGS_ROW_HEIGHT, cx))
                        .max_h(px(TAGS_MAX_H))
                        .overflow_y_scroll()
                        .gap(px(6.))
                        .flex_wrap()
                        .children(
                            item.tags
                                .iter()
                                .map(|t| Tag::secondary().small().child(format!("#{t}"))),
                        ),
                )
            })
            .child(ui::divider(cx).debug_selector(|| "detail-fields-rule".into()));

        // The rows sit under the pinned rule exactly as each row sits under the one
        // above: only their own `FIELD_ROW_PAD_Y` top padding, so the scroll area has no
        // top padding. Password notices sit inside their field's row. Every field row
        // (and the history disclosure) draws its own bottom border, so the last row's
        // border already closes the group above the footer. Only the no-fields message
        // needs a closing rule of its own.
        let scroll = ui::v_flex()
            .id("detail-scroll")
            .debug_selector(|| "detail-scroll".into())
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .px(pad_x)
            .pb(px(64.))
            .gap(px(12.))
            .child(
                ui::v_flex()
                    .when(item.fields.is_empty(), |col| {
                        col.child(ui::muted("This item has no fields.", cx).py(px(FIELD_ROW_PAD_Y)))
                            .child(ui::divider(cx))
                    })
                    .child(ui::no_window_drag(ui::v_flex()).children(fields)),
            )
            .children(
                (if backup {
                    attachments::backup_section(item, cx)
                } else if self.standalone || trashed {
                    attachments::reference_section(s, item, cx)
                } else {
                    attachments::section(s, self.state, item, false, cx)
                })
                .map(|a| ui::no_window_drag(div()).child(a)),
            )
            .child(
                ui::muted(footer_text(item, now, &device), cx)
                    .debug_selector(|| "detail-footer".into()),
            );

        // No id: the scroll area keeps the element path it had before the header was
        // pinned (scroll state, cursor audit names).
        ui::v_flex().size_full().child(pinned).child(scroll)
    }

    fn render_field(
        &self,
        ix: usize,
        field: &Field,
        item: &Item,
        now: u64,
        fit: Option<Pixels>,
        cx: &App,
    ) -> AnyElement {
        if field.kind == FieldKind::Section {
            return section_row(ix, &field.name, cx).into_any_element();
        }
        let theme = cx.theme();
        let revealed = self.revealed.contains(&field.id);
        let shown_plain = revealed || self.peek;
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
            // An empty name would read "Copy " (01 §4: names may be empty).
            _ if field.name.trim().is_empty() => "Copy value".to_owned(),
            _ => format!("Copy {}", field.name),
        };

        let shown: AnyElement = match field.kind {
            _ if card_number => {
                buttons.push(
                    reveal_button(ix, field.id, revealed, "card number", &self.actions)
                        .into_any_element(),
                );
                if shown_plain {
                    mono(value.to_string(), cx).into_any_element()
                } else {
                    mono(text::mask_card(value), cx).into_any_element()
                }
            }
            // A field kind from a newer app version may hold a secret: keep it concealed
            // behind the same reveal toggle as a password.
            // A PIN renders like a password (05 §2.3 `pin`); ⌘⇧R stays password-only.
            FieldKind::Password | FieldKind::Pin | FieldKind::Other => {
                let what = match field.kind {
                    FieldKind::Password => "password  ⌘⇧R",
                    FieldKind::Pin => "PIN",
                    _ => "value",
                };
                buttons.push(
                    reveal_button(ix, field.id, revealed, what, &self.actions).into_any_element(),
                );
                if shown_plain {
                    mono(value.to_string(), cx)
                        .debug_selector(move || format!("field-plain {ix}"))
                        .into_any_element()
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
            // GFM Markdown (owner 2026-10-31; safety rules in `notes`).
            FieldKind::Notes => div()
                .debug_selector(move || format!("field-notes {ix}"))
                .w_full()
                .min_w_0()
                .child(super::notes::notes_view(("notes", ix), value, self.state))
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
                CopyTarget::Field(field.id),
                &self.actions,
            )
            .into_any_element(),
        );

        // A rendered note is selectable text with links: no click-to-copy on its body
        // (the row's Copy button copies the raw Markdown).
        let value = if field.kind == FieldKind::Notes {
            div().flex_1().min_w_0().child(shown).into_any_element()
        } else {
            copy_on_click(ix, field.id, &field.name, shown, &self.actions, cx).into_any_element()
        };
        let live;
        let all: &[FieldIssue] = match self.source {
            ItemSource::Backup(issues) => issues.get(&item.id).map_or(&[], Vec::as_slice),
            ItemSource::Live => {
                live = self.state.read(cx);
                live.listing.issues(item.id)
            }
        };
        let issues: Vec<FieldIssue> = all
            .iter()
            .filter(|fi| fi.field == field.id)
            .copied()
            .collect();
        field_row(
            ix,
            field.name.clone().into(),
            field.icon_name(),
            fit,
            value,
            buttons,
            &issues,
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

    /// The history disclosure under row `row`, when it owns any entries.
    fn render_history(&self, item: &Item, row: usize, now: u64, cx: &App) -> Option<AnyElement> {
        let entries: Vec<&HistoryEntry> = item
            .history
            .iter()
            .filter(|h| history_row(&item.fields, h) == Some(row))
            .collect();
        if entries.is_empty() {
            return None;
        }
        Some(history_view(
            History {
                entries: &entries,
                fields: &item.fields,
                row,
            },
            None,
            self.state,
            self.history_open,
            self.actions.clone(),
            now,
            cx,
        ))
    }
}

/// The row whose disclosure shows history entry `h` (05 §2.3, owner decision 2026-11-17):
/// an entry whose field is a current password or PIN sits under that field's row; an
/// entry of a removed field (or without a field id) under the first password row, else
/// the first PIN row (a removed PIN's entries on a Card).
pub(super) fn history_row(fields: &[Field], h: &HistoryEntry) -> Option<usize> {
    h.field_id
        .and_then(|id| {
            fields
                .iter()
                .position(|f| f.id == id && matches!(f.kind, FieldKind::Password | FieldKind::Pin))
        })
        .or_else(|| fields.iter().position(|f| f.kind == FieldKind::Password))
        .or_else(|| fields.iter().position(|f| f.kind == FieldKind::Pin))
}

/// Password history disclosure (§2.3): a toggle and, when open, the previous values
/// masked with their timestamps, each copyable. `removed` is `Some(pending removals)` in
/// edit mode, which adds a trash button per entry and a "Clear history" button; removing
/// never reveals a value.
pub(super) fn history_disclosure(
    history: History<'_>,
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

/// History entries of row `row` and the item's fields (to name the field each belonged to).
pub(super) struct History<'a> {
    pub entries: &'a [&'a HistoryEntry],
    pub fields: &'a [Field],
    pub row: usize,
}

fn history_view(
    History {
        entries: history,
        fields,
        row,
    }: History<'_>,
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
    // A PIN row's disclosure: its own label and selectors (" pin<row>" suffix); a password
    // row other than the first gets " pw<row>" so element ids stay unique; one shared open
    // flag for the item.
    let pin = fields.get(row).is_some_and(|f| f.kind == FieldKind::Pin);
    let first_password = fields.iter().position(|f| f.kind == FieldKind::Password);
    // Wording: "PIN history", "Password history" on the first password row, and the
    // field's display name on later password rows ("Recovery history"; "Password" when
    // the name is empty) so two disclosures are told apart.
    let (what, sfx, id_sfx) = if pin {
        ("PIN".to_owned(), format!(" pin{row}"), format!("-pin{row}"))
    } else if first_password == Some(row) {
        ("Password".to_owned(), String::new(), String::new())
    } else {
        let name = fields.get(row).map_or("", |f| f.name.trim());
        let what = if name.is_empty() {
            "Password".to_owned()
        } else {
            text::capitalize_first(name)
        };
        (what, format!(" pw{row}"), format!("-pw{row}"))
    };
    let label = format!("{what} history ({count})");
    let id = |name: &str| SharedString::from(format!("{name}{id_sfx}"));
    let toggle = {
        let actions = actions.clone();
        let (sfx, note_sfx) = (sfx.clone(), sfx.clone());
        ui::h_flex()
            .id(id("history-toggle"))
            .debug_selector(move || format!("history-toggle{sfx}"))
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
            .child({
                // Tests read the wording from the selector (no painted-text API).
                let label = label.clone();
                let selector = format!("history-label {label}");
                div().debug_selector(move || selector).child(label)
            })
            .when(pending > 0, |row| {
                // Tests read the count from the selector (no painted-text API).
                row.child(
                    div()
                        .debug_selector(move || format!("history-removed {pending}{note_sfx}"))
                        .child(format!("\u{b7} {pending} removed on save")),
                )
            })
            .on_click(move |_, _, cx| (actions.0)(DetailAction::ToggleHistory, cx))
    };

    let entries = history
        .iter()
        .take(HISTORY_SHOWN)
        .enumerate()
        .map(|(j, h)| {
            let (stamp, field_id) = (h.replaced_at, h.field_id);
            // Version 2 entries know their field: say which one (its name now, or that it
            // was removed). Entries without a field id read as before.
            let field = h.field_id.map(|id| {
                fields.iter().find(|f| f.id == id).map_or_else(
                    || "removed field".to_owned(),
                    |f| text::capitalize_first(&f.name),
                )
            });
            let copy = {
                let actions = actions.clone();
                let sfx = sfx.clone();
                // By stamp in the stored item: in edit mode the shown list skips removals.
                ui::icon_button(
                    (id("history-copy"), j),
                    IconName::Copy,
                    if pin {
                        "Copy previous PIN"
                    } else {
                        "Copy previous password"
                    },
                )
                .debug_selector(move || format!("history-copy {j}{sfx}"))
                .on_click(move |_, _, cx| {
                    (actions.0)(DetailAction::CopyHistory(stamp, field_id), cx)
                })
            };
            let remove = editing.then(|| {
                let state = state.clone();
                let sfx = sfx.clone();
                ui::icon_button(
                    (id("history-remove"), j),
                    IconName::Trash,
                    "Remove from history",
                )
                .debug_selector(move || format!("history-remove {j}{sfx}"))
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
                .child({
                    let replaced = format!(
                        "replaced {} ({})",
                        text::date(stamp),
                        text::relative(now, stamp)
                    );
                    let line = match field.as_deref() {
                        Some(name) if !name.is_empty() => format!("{name} \u{b7} {replaced}"),
                        _ => replaced,
                    };
                    // Tests read which field the entry names ("-" when it names none).
                    let selector = format!(
                        "history-entry {j} {}{sfx}",
                        field.as_deref().filter(|n| !n.is_empty()).unwrap_or("-")
                    );
                    // The line gives way (truncated) before the buttons do.
                    ui::muted(line, cx)
                        .min_w_0()
                        .truncate()
                        .debug_selector(move || selector.clone())
                })
                .child(div().flex_none().child(copy))
                .children(remove.map(|r| div().flex_none().child(r)))
        });

    // Marks only this disclosure's entries, by (stamp, field id). Removal itself is per
    // stamp in core, so an entry of another field sharing the stamp (both fields changed
    // in one save) goes with it.
    let stamps: Vec<_> = history
        .iter()
        .map(|h| (h.replaced_at, h.field_id))
        .collect();
    let clear_sfx = sfx.clone();
    let clear = (editing && count > 0).then(|| {
        let state = state.clone();
        ui::h_flex().pl(px(18.)).pt(px(2.)).child(
            Button::new(id("history-clear"))
                .debug_selector(move || format!("history-clear{clear_sfx}"))
                .link()
                .xsmall()
                .label("Clear history")
                .clickable()
                .on_click(move |_, _, cx| {
                    state.update(cx, |s, cx| {
                        s.edit(cx, |b| {
                            b.clear_history(|h| stamps.contains(&(h.replaced_at, h.field_id)))
                        })
                    })
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
