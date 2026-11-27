//! Launch → choose vault (specs/05-ui.md §2.1).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use gpui::{
    Context, Entity, FocusHandle, InteractiveElement as _, IntoElement, ParentElement as _, Render,
    SharedString, StatefulInteractiveElement as _, Styled as _, Subscription, Window, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::spinner::Spinner;
use gpui_component::{ActiveTheme as _, Disableable as _};
use gpui_kit_assets::IconName;

use crate::cloud;
use crate::persist;
use crate::state::{AppState, Busy, ChooseIntent, LEGACY_LAYOUT, Screen};
use crate::ui::{self, Clickable as _};

/// The welcome card's subtitle with recent vaults listed, and without.
const WELCOME_WITH_RECENTS: &str = "Open a recent vault, create a new one, or open a file.";
const WELCOME_NO_RECENTS: &str = "Create a new vault or open one you already have.";

/// The create form's icon (the unlock card's, at half size) and subtitle.
const CREATE_ICON_SIZE: f32 = 64.;
const CREATE_SUBTITLE: &str = "Choose a name, a folder and a master password.";

/// Side of the still app icon at the left of a recent-vault row, in points.
const RECENT_ICON_SIZE: f32 = 28.;

/// The recent row's hover-only × (owner decision 2026-11-27, option A).
const FORGET_LABEL: &str = "Remove from Recents";

/// The create form's overlay while the KDF calibrates (owner decision 2026-11-27).
const CALIBRATING: &str = "Calibrating encryption for this Mac…";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Home,
    Create,
}

pub struct ChooseScreen {
    state: Entity<AppState>,
    step: Step,
    name: Entity<InputState>,
    password: Entity<InputState>,
    confirm: Entity<InputState>,
    folder: Option<PathBuf>,
    /// Live strength and confirmation checks on the master password.
    check: ui::MasterPasswordCheck,
    /// Local validation message; vault errors come from `AppState::error`.
    problem: Option<SharedString>,
    /// The recent row under the pointer: its × is drawn.
    hovered_recent: Option<PathBuf>,
    /// One focus handle per recent row's ×, so a hidden × stays a Tab stop.
    forget_focus: HashMap<PathBuf, FocusHandle>,
    /// `AppState::busy` was `Calibrating` at the last notify.
    was_calibrating: bool,
    /// "Create new vault": takes focus when a focused × removed the last recent.
    create_focus: FocusHandle,
    /// Tracked by the dimmed create form while calibrating, to tell (and drop) focus
    /// that Tab moved into it.
    form_focus: FocusHandle,
    _subscriptions: Vec<Subscription>,
}

impl ChooseScreen {
    pub fn new(state: Entity<AppState>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let name = ui::text_input("Vault name", window, cx);
        ui::set_input(&name, "Personal", window, cx);
        let password = ui::password_input("Master password", window, cx);
        let confirm = ui::password_input("Confirm master password", window, cx);
        let subscriptions = vec![
            cx.observe_in(&state, window, |this, state, window, cx| {
                let s = state.read(cx);
                let calibrating = s.busy == Some(Busy::Calibrating);
                let here = s.screen == Screen::Choose && this.step == Step::Create;
                if here && calibrating && !this.was_calibrating {
                    // The form goes under the overlay: no caret left in a hidden field.
                    window.blur(cx);
                } else if here && !calibrating && this.was_calibrating {
                    // Creating failed (the passwords were cleared at submit): type again.
                    ui::focus_input(&this.password, window, cx);
                }
                this.was_calibrating = calibrating;
                cx.notify();
            }),
            cx.subscribe_in(&password, window, |this, _, ev: &InputEvent, window, cx| {
                if matches!(ev, InputEvent::Change) {
                    this.check.edited(&this.password, window, cx);
                    this.recheck(cx);
                }
            }),
            cx.subscribe_in(
                &confirm,
                window,
                |this, _, ev: &InputEvent, window, cx| match ev {
                    InputEvent::PressEnter { .. } => this.submit_create(window, cx),
                    InputEvent::Change => this.recheck(cx),
                    _ => {}
                },
            ),
        ];
        Self {
            state,
            step: Step::Home,
            name,
            password,
            confirm,
            folder: dirs::document_dir(),
            check: ui::MasterPasswordCheck::default(),
            problem: None,
            hovered_recent: None,
            forget_focus: HashMap::new(),
            was_calibrating: false,
            create_focus: cx.focus_handle().tab_stop(true),
            form_focus: cx.focus_handle(),
            _subscriptions: subscriptions,
        }
    }

    /// Called by the root view when the screen becomes visible, and again whenever
    /// `AppState::choose_request` is set while it is visible.
    pub fn appear(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let request = self.state.update(cx, |s, _| s.choose_request.take());
        // ⌘O on the Home step: the file panel, as the "Open existing vault…" link.
        if request == Some(ChooseIntent::OpenFile)
            && self.step == Step::Home
            && self.state.read(cx).busy.is_none()
        {
            self.open_existing(cx);
            return;
        }
        self.step = match request {
            Some(ChooseIntent::Create) => Step::Create,
            Some(ChooseIntent::Home | ChooseIntent::OpenFile) | None => Step::Home,
        };
        self.problem = None;
        // Never leave a typed password behind in a hidden form.
        self.clear_passwords(window, cx);
        if self.step == Step::Create {
            ui::focus_input(&self.name, window, cx);
        }
        cx.notify();
    }

    fn recheck(&mut self, cx: &mut Context<Self>) {
        self.check.refresh(&self.password, &self.confirm, cx);
        self.problem = None;
        cx.notify();
    }

    fn suggest(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.state.read(cx).busy.is_some() {
            return;
        }
        self.check
            .suggest(&self.password, &self.confirm, window, cx);
        self.problem = None;
        cx.notify();
    }

    /// Never leave a typed password behind in a hidden form.
    fn clear_passwords(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        ui::clear_input(&self.password, window, cx);
        ui::clear_input(&self.confirm, window, cx);
        self.check.reset(&self.password, window, cx);
    }

    fn start_create(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.step = Step::Create;
        self.problem = None;
        self.state.update(cx, |s, _| s.error = None);
        ui::focus_input(&self.name, window, cx);
        cx.notify();
    }

    fn back(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.step = Step::Home;
        self.problem = None;
        self.clear_passwords(window, cx);
        self.state.update(cx, |s, _| s.error = None);
        cx.notify();
    }

    fn open_existing(&mut self, cx: &mut Context<Self>) {
        let pick = ui::pick_vault_package(cx);
        let state = self.state.clone();
        cx.spawn(async move |_, cx| {
            if let Some(path) = pick.await {
                state.update(cx, |s, cx| s.open_vault(path, cx));
            }
        })
        .detach();
    }

    fn choose_folder(&mut self, cx: &mut Context<Self>) {
        if self.state.read(cx).busy.is_some() {
            return;
        }
        let pick = ui::pick_path(true, "Choose", cx);
        cx.spawn(async move |this, cx| {
            if let Some(dir) = pick.await {
                this.update(cx, |this, cx| {
                    this.folder = Some(dir);
                    this.problem = None;
                    cx.notify();
                })
                .ok();
            }
        })
        .detach();
    }

    /// The recent row's ×: drops `path` from the recents (and recent.json). The vault
    /// file, Touch ID and the Keychain are untouched.
    /// From a focused ×, focus moves to the next row's × (the previous one after the
    /// last row), or to "Create new vault" when no recents are left.
    fn forget_recent(&mut self, path: &Path, window: &mut Window, cx: &mut Context<Self>) {
        if self.state.read(cx).busy.is_some() {
            return;
        }
        if self.hovered_recent.as_deref() == Some(path) {
            self.hovered_recent = None;
        }
        let had_focus = self
            .forget_focus
            .get(path)
            .is_some_and(|f| f.is_focused(window));
        if had_focus {
            let recent = &self.state.read(cx).recent_vaults;
            let ix = recent.iter().position(|p| p == path);
            let next = ix
                .and_then(|ix| {
                    recent
                        .get(ix + 1)
                        .or_else(|| recent.get(ix.checked_sub(1)?))
                })
                .and_then(|p| self.forget_focus.get(p));
            window.focus(next.unwrap_or(&self.create_focus), cx);
        }
        self.state.update(cx, |s, cx| {
            s.forget(path);
            cx.notify();
        });
    }

    /// Keeps one focus handle per recent row (see `forget_focus`).
    fn sync_forget_focus(&mut self, cx: &mut Context<Self>) {
        let recent = self.state.read(cx).recent_vaults.clone();
        self.forget_focus.retain(|p, _| recent.contains(p));
        for path in recent {
            self.forget_focus
                .entry(path)
                .or_insert_with(|| cx.focus_handle().tab_stop(true));
        }
    }

    fn target_path(&self, cx: &Context<Self>) -> Result<PathBuf, &'static str> {
        let name = ui::input_text(&self.name, cx);
        let name = name.trim();
        if name.is_empty() || name.contains('/') || name.starts_with('.') {
            return Err("Enter a vault name without slashes.");
        }
        let folder = self
            .folder
            .as_ref()
            .ok_or("Choose a folder for the vault.")?;
        Ok(folder.join(format!("{name}.vault")))
    }

    fn submit_create(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.state.read(cx).busy.is_some() {
            return;
        }
        let path = match self.target_path(cx) {
            Ok(p) => p,
            Err(msg) => {
                self.problem = Some(msg.into());
                cx.notify();
                return;
            }
        };
        self.check.refresh(&self.password, &self.confirm, cx);
        if self.check.is_empty() {
            self.problem = Some("Choose a master password.".into());
        } else if !self.check.ready() && self.check.problem().is_none() {
            // Weak or finished-but-different already shows under the meter; this is
            // Enter on a confirmation that is still too short.
            self.problem = Some(ui::PASSWORDS_DIFFER.into());
        }
        if !self.check.ready() {
            cx.notify();
            return;
        }
        let password = ui::input_secret(&self.password, cx);
        self.clear_passwords(window, cx);
        self.state
            .update(cx, |s, cx| s.create_vault(path, password, cx));
    }

    /// The recent row's × at its right edge: drawn while the row is hovered or the ×
    /// has keyboard focus; otherwise an empty slot of its size holding its focus handle,
    /// so the row does not shift and Tab still reaches it (as the editor's ↑/↓).
    fn forget_button(
        &self,
        ix: usize,
        path: &Path,
        enabled: bool,
        window: &Window,
        cx: &Context<Self>,
    ) -> gpui::AnyElement {
        let Some(focus) = self.forget_focus.get(path) else {
            return div().into_any_element();
        };
        // Over the row's right end, centred on the row's spacer (rows differ in height).
        fn place<E: gpui::Styled>(el: E) -> E {
            el.absolute()
                .right(px(10.))
                .top(gpui::relative(0.5))
                .mt(gpui::rems(-0.75))
        }
        // A × never takes click focus (gpui-component Button), so focus here came from
        // Tab (or from removing the row above).
        let show = all_forget()
            || focus.is_focused(window)
            || self.hovered_recent.as_deref() == Some(path);
        if !show {
            // A Tab stop only while the × would work: a disabled × leaves the Tab order.
            return place(div().id(("forget-slot", ix)).size_6())
                .when(enabled, |slot| {
                    slot.track_focus(focus)
                        .on_mouse_down(gpui::MouseButton::Left, |_, window, _| {
                            window.prevent_default()
                        })
                })
                .into_any_element();
        }
        let shown = path.display().to_string();
        let path = path.to_owned();
        place(ui::icon_button(
            ("forget", ix),
            IconName::Close,
            FORGET_LABEL,
        ))
        .map(|b| {
            if enabled {
                b.track_focus(focus)
            } else {
                b.tab_stop(false)
            }
        })
        .flex_none()
        .debug_selector(move || format!("choose-forget {shown}"))
        .disabled(!enabled)
        .clickable_when(enabled)
        .on_click(cx.listener(move |this, _, window, cx| {
            // Never the row's own click: that would open the vault.
            cx.stop_propagation();
            this.forget_recent(&path, window, cx);
        }))
        .into_any_element()
    }

    /// The welcome card (05 §2.1): the unlock card (05 §2.2) with the still app icon, a
    /// title and a subtitle, then the recent vaults, the primary Create button and the
    /// quiet Open link (owner decision 2026-11-24, option B).
    fn render_home(&self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        let state = self.state.read(cx);
        let busy = state.busy;
        let error = state.error.clone();
        let recent = state.recent_vaults.clone();
        let legacy = state.legacy_recents.clone();
        let theme = cx.theme();
        let subtitle = if recent.is_empty() {
            WELCOME_NO_RECENTS
        } else {
            WELCOME_WITH_RECENTS
        };
        let mut controls = ui::v_flex();
        if !recent.is_empty() {
            let rows = recent.into_iter().enumerate().map(|(ix, path)| {
                let name = persist::vault_name(&path);
                let shown = path.display().to_string();
                // A plain file is the old single-file layout: listed, never opened.
                let legacy = legacy.contains(&path);
                let openable = busy.is_none() && !legacy;
                let state = self.state.clone();
                let forget = self.forget_button(ix, &path, busy.is_none(), window, cx);
                let hover_path = path.clone();
                let row = ui::h_flex()
                    .id(("recent", ix))
                    .debug_selector(move || {
                        format!("recent {ix} {}", if legacy { "legacy" } else { "openable" })
                    })
                    .w_full()
                    .gap(px(10.))
                    .px(px(10.))
                    .py(px(6.))
                    .rounded(theme.radius)
                    .clickable_when(openable)
                    .on_hover(cx.listener(move |this, hovered: &bool, _, cx| {
                        let now = if *hovered {
                            Some(hover_path.clone())
                        } else {
                            this.hovered_recent.clone().filter(|p| *p != hover_path)
                        };
                        if now != this.hovered_recent {
                            this.hovered_recent = now;
                            cx.notify();
                        }
                    }))
                    .when(openable, |row| {
                        row.hover(|s| s.bg(theme.accent)).on_click(move |_, _, cx| {
                            let path = path.clone();
                            state.update(cx, |s, cx| s.open_vault(path, cx));
                        })
                    })
                    .child(
                        gpui::img(crate::assets::APP_ICON)
                            .size(px(RECENT_ICON_SIZE))
                            .flex_shrink_0(),
                    )
                    .child(
                        ui::v_flex()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div()
                                    .text_sm()
                                    .overflow_hidden()
                                    .text_ellipsis()
                                    .when(legacy, |d| d.text_color(theme.muted_foreground))
                                    .child(name),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .overflow_hidden()
                                    .text_ellipsis()
                                    .child(shown),
                            )
                            .when(legacy, |col| {
                                col.child(
                                    div()
                                        .text_xs()
                                        .text_color(theme.danger)
                                        .child(LEGACY_LAYOUT),
                                )
                            }),
                    )
                    // The ×'s place: it is drawn over it, not inside the row, so the
                    // row's click and pointer rules never cover it (and the row stays
                    // hovered under it: the × blocks no hitbox).
                    .child(div().flex_none().size_6());
                div().relative().w_full().child(row).child(forget)
            });
            controls = controls.child(ui::v_flex().w_full().gap(px(2.)).children(rows));
        }
        if busy == Some(Busy::Opening) {
            controls = controls.child(busy_row("Opening vault…", cx));
        }
        if busy == Some(Busy::Calibrating) {
            controls = controls.child(busy_row(CALIBRATING, cx));
        }
        if let Some(error) = error {
            controls = controls.child(div().text_sm().text_color(theme.danger).child(error));
        }
        let controls = controls
            .child(
                Button::new("create")
                    .primary()
                    .w_full()
                    .label("Create new vault")
                    .track_focus(&self.create_focus)
                    .disabled(busy.is_some())
                    .clickable_when(busy.is_none())
                    .on_click(cx.listener(|this, _, window, cx| this.start_create(window, cx))),
            )
            .child(
                // Styled as the unlock screen's "Open another vault…" link.
                div()
                    .w_full()
                    .flex()
                    .justify_center()
                    .debug_selector(move || {
                        format!(
                            "choose-open {}",
                            if busy.is_some() { "busy" } else { "ready" }
                        )
                    })
                    .child(
                        ui::quiet_link(
                            "open",
                            "Open existing vault…",
                            "Open existing vault…",
                            "⌘O",
                            busy.is_none(),
                            cx,
                        )
                        .on_click(cx.listener(|this, _, _, cx| this.open_existing(cx))),
                    ),
            );
        ui::unlock_card(
            ui::UnlockCard {
                prefix: "choose",
                icon: gpui::img(crate::assets::APP_ICON)
                    .size_full()
                    .into_any_element(),
                icon_size: ui::UNLOCK_ICON_SIZE,
                badge: None,
                name: "Welcome to Vault".into(),
                title: true,
                subtitle: Some(subtitle.into()),
                controls,
                unlocking: None,
            },
            cx,
        )
    }

    fn render_create(&self, cx: &mut Context<Self>) -> gpui::Div {
        let state = self.state.read(cx);
        let busy = state.busy;
        let error = self.problem.clone().or_else(|| state.error.clone());
        let ready = self.check.ready();
        let theme = cx.theme();
        let folder_text = self
            .folder
            .as_ref()
            .map(|f| f.display().to_string())
            .unwrap_or_else(|| "No folder chosen".into());
        let provider = self.folder.as_deref().and_then(cloud::provider_label);

        let calibrating = busy == Some(Busy::Calibrating);
        let form = ui::v_flex()
            .w_full()
            .gap(px(12.))
            .child(
                div()
                    .w_full()
                    .debug_selector(|| "create-name".into())
                    .child(ui::input(&self.name).readonly(calibrating)),
            )
            .child(
                ui::h_flex()
                    .w_full()
                    .gap(px(8.))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_sm()
                            .overflow_hidden()
                            .text_ellipsis()
                            .child(folder_text),
                    )
                    .child(
                        Button::new("folder")
                            .debug_selector(|| "create-folder".into())
                            .label("Choose…")
                            .clickable()
                            .on_click(cx.listener(|this, _, _, cx| this.choose_folder(cx))),
                    ),
            )
            .when_some(provider, |col, provider| {
                col.child(ui::h_flex().w_full().child(ui::info_label(
                    format!("In {provider}: syncs to your other devices"),
                    cx,
                )))
            })
            // A revealed (or suggested) master password is never copied out.
            .child(ui::refuse_plain_copy(
                div()
                    .w_full()
                    .debug_selector(|| "create-password".into())
                    .child(
                        ui::input(&self.password)
                            .mask_toggle()
                            .readonly(calibrating),
                    ),
            ))
            .child(ui::master_password_feedback(
                &self.check,
                "create-suggest",
                cx.listener(|this, _, window, cx| this.suggest(window, cx)),
                cx,
            ))
            .child(ui::input(&self.confirm).readonly(calibrating))
            // Dimmed and frozen while calibrating (owner decision 2026-11-27, option A):
            // the overlay occludes the pointer, `render` drops any focus Tab moves in,
            // the fields are read-only meanwhile and the actions check `busy`.
            .when(calibrating, |form| {
                ui::covered(form, ui::Cover::Dim).track_focus(&self.form_focus)
            })
            .debug_selector(move || {
                format!(
                    "create-form {}",
                    if calibrating { "dimmed" } else { "live" }
                )
            });
        let mut controls = ui::v_flex().child(div().relative().w_full().child(form).when(
            calibrating,
            |wrap| {
                wrap.child(ui::busy_overlay(
                    "create-calibrating",
                    CALIBRATING,
                    ui::Cover::Dim,
                    cx,
                ))
            },
        ));
        if let Some(error) = error {
            controls = controls.child(div().text_sm().text_color(theme.danger).child(error));
        }
        let controls = controls
            .child(
                ui::submit_gate(
                    "create-submit",
                    ready && busy.is_none(),
                    Button::new("do-create")
                        .primary()
                        .w_full()
                        .label("Create vault")
                        // gpui-component 0.8.1 draws the loading spinner only in place
                        // of an icon, and a disabled button takes the disabled colours:
                        // while calibrating the button is loading (inert) with a spinner
                        // icon, not disabled.
                        .loading(calibrating)
                        .when(calibrating, |b| {
                            b.icon(Spinner::new())
                                .debug_selector(|| "create-loading".into())
                        })
                        .disabled(!calibrating && (busy.is_some() || !ready))
                        .clickable_when(busy.is_none() && ready)
                        .on_click(
                            cx.listener(|this, _, window, cx| this.submit_create(window, cx)),
                        ),
                )
                .w_full(),
            )
            .child(
                // The welcome card's Open link style; Esc does the same.
                div()
                    .w_full()
                    .flex()
                    .justify_center()
                    .debug_selector(move || {
                        format!(
                            "create-back {}",
                            if busy.is_some() { "busy" } else { "ready" }
                        )
                    })
                    .child(
                        ui::quiet_link("back", "Back", "Back", "esc", busy.is_none(), cx)
                            .on_click(cx.listener(|this, _, window, cx| this.back(window, cx))),
                    ),
            );
        ui::unlock_card(
            ui::UnlockCard {
                prefix: "create",
                icon: gpui::img(crate::assets::APP_ICON)
                    .size_full()
                    .into_any_element(),
                icon_size: CREATE_ICON_SIZE,
                badge: None,
                name: "Create a new vault".into(),
                title: true,
                subtitle: Some(CREATE_SUBTITLE.into()),
                controls,
                unlocking: None,
            },
            cx,
        )
        // Esc goes back, as the Back link. A focused field passes Esc on (its own
        // `input::Escape` propagates when it has nothing to dismiss), so this sees it
        // after the field; with a button focused no binding matches and it lands here.
        .on_key_down(cx.listener(|this, ev: &gpui::KeyDownEvent, window, cx| {
            if ev.keystroke.key == "escape" && !ev.keystroke.modifiers.modified() {
                cx.stop_propagation();
                if this.state.read(cx).busy.is_none() {
                    this.back(window, cx);
                }
            }
        }))
    }
}

#[cfg(test)]
thread_local! {
    static ALL_FORGET: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Tests only: while alive, every recent row draws its ×, as the cursor audit's scan
/// moves no hover. Dropping it restores the hover/focus-only ×.
#[cfg(test)]
#[must_use]
pub(crate) struct AllForgetForTests(());

#[cfg(test)]
impl AllForgetForTests {
    pub(crate) fn on() -> Self {
        ALL_FORGET.with(|a| a.set(true));
        Self(())
    }
}

#[cfg(test)]
impl Drop for AllForgetForTests {
    fn drop(&mut self) {
        ALL_FORGET.with(|a| a.set(false));
    }
}

fn all_forget() -> bool {
    #[cfg(test)]
    return ALL_FORGET.with(std::cell::Cell::get);
    #[cfg(not(test))]
    false
}

fn busy_row(text: &'static str, cx: &gpui::App) -> gpui::Div {
    ui::h_flex()
        .gap(px(8.))
        .child(Spinner::new())
        .child(ui::muted(text, cx))
}

impl Render for ChooseScreen {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let card = match self.step {
            Step::Home => {
                self.sync_forget_focus(cx);
                self.render_home(window, cx)
            }
            Step::Create => {
                // Tab can still reach the dimmed fields while calibrating: drop that
                // focus before it draws (no caret, no keys).
                let calibrating = self.state.read(cx).busy == Some(Busy::Calibrating);
                if calibrating && self.form_focus.contains_focused(window, cx) {
                    window.blur(cx);
                }
                self.render_create(cx)
            }
        };
        ui::centered(cx).child(card)
    }
}

#[cfg(test)]
mod tests {
    use gpui::{AppContext as _, Modifiers, TestAppContext, VisualTestContext};
    use gpui_component::Root;
    use vault_core::Uuid;

    use super::*;
    use crate::theme;

    /// 8 chars from lower + digits: about 41 bits, below the minimum.
    pub(crate) const WEAK: &str = "letmein1";
    pub(crate) const STRONG: &str = "correct-horse-battery-staple";

    fn window(
        cx: &mut TestAppContext,
    ) -> (Entity<AppState>, Entity<ChooseScreen>, VisualTestContext) {
        window_with_recents(Vec::new(), cx)
    }

    fn window_with_recents(
        recent: Vec<PathBuf>,
        cx: &mut TestAppContext,
    ) -> (Entity<AppState>, Entity<ChooseScreen>, VisualTestContext) {
        cx.update(gpui_component::init);
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), recent, false));
        let mut view = None;
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let v = cx.new(|cx| ChooseScreen::new(state.clone(), window, cx));
            view = Some(v.clone());
            Root::new(v, window, cx)
        });
        let vcx = VisualTestContext::from_window(window.into(), cx);
        (state, view.unwrap(), vcx)
    }

    fn type_into(input: &Entity<InputState>, text: &str, vcx: &mut VisualTestContext) {
        vcx.update(|window, cx| {
            ui::clear_input(input, window, cx);
            ui::focus_input(input, window, cx);
        });
        vcx.simulate_input(text);
        vcx.run_until_parked();
    }

    fn shown(key: &'static str, vcx: &mut VisualTestContext) -> bool {
        vcx.debug_bounds(key).is_some()
    }

    fn weak_message() -> &'static str {
        Box::leak(format!("master-problem {}", ui::WEAK_MASTER_PASSWORD).into_boxed_str())
    }

    /// Weak blocks Create (button and Enter), strong + matching enables it, and
    /// "Suggest passphrase" fills both fields, reveals the password once and enables it.
    #[gpui::test]
    fn create_requires_a_strong_master_password(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, view, mut vcx) = window(cx);
        let (password, confirm) =
            view.read_with(&vcx, |v, _| (v.password.clone(), v.confirm.clone()));
        vcx.update(|window, cx| {
            view.update(cx, |v, cx| {
                v.folder = Some(dir.path().to_owned());
                v.start_create(window, cx);
            })
        });
        vcx.run_until_parked();
        assert!(shown("create-submit blocked", &mut vcx), "empty form");
        assert!(!shown(weak_message(), &mut vcx), "no nagging before typing");

        type_into(&password, WEAK, &mut vcx);
        type_into(&confirm, WEAK, &mut vcx);
        assert!(shown(weak_message(), &mut vcx));
        assert!(shown("create-submit blocked", &mut vcx));
        let button = vcx.debug_bounds("create-submit blocked").unwrap();
        vcx.simulate_click(button.center(), Modifiers::none());
        vcx.simulate_keystrokes("enter");
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| assert!(s.busy.is_none(), "weak never submits"));
        assert!(!dir.path().join("Personal.vault").exists());

        // Strong but not yet confirmed: still blocked, no strength message.
        type_into(&password, STRONG, &mut vcx);
        type_into(&confirm, "correct", &mut vcx);
        assert!(!shown(weak_message(), &mut vcx));
        assert!(shown("create-submit blocked", &mut vcx));
        type_into(&confirm, STRONG, &mut vcx);
        assert!(shown("create-submit ready", &mut vcx));
        assert!(!shown("master-write-it-down", &mut vcx));

        // Suggest: both fields hold the same phrase, readable, and Create is enabled.
        vcx.update(|window, cx| {
            ui::clear_input(&password, window, cx);
            ui::clear_input(&confirm, window, cx);
            view.update(cx, |v, cx| v.suggest(window, cx));
        });
        vcx.run_until_parked();
        let (pw, again, masked) = vcx.update(|_, cx| {
            (
                ui::input_text(&password, cx),
                ui::input_text(&confirm, cx),
                ui::input_is_masked(&password, cx),
            )
        });
        assert_eq!(pw.split('-').count(), 4, "a 4-word passphrase");
        assert_eq!(pw, again);
        assert!(!masked, "revealed once");
        assert!(shown("master-write-it-down", &mut vcx));
        assert!(shown("create-submit ready", &mut vcx));

        // The revealed phrase never reaches the pasteboard: ⌘C/⌘X are swallowed.
        vcx.update(|window, cx| {
            cx.write_to_clipboard(gpui::ClipboardItem::new_string("before".into()));
            ui::focus_input(&password, window, cx);
        });
        vcx.simulate_keystrokes("cmd-a cmd-c cmd-x");
        vcx.run_until_parked();
        vcx.update(|_, cx| {
            let board = cx.read_from_clipboard().and_then(|c| c.text());
            assert_eq!(board.as_deref(), Some("before"));
            assert_eq!(ui::input_text(&password, cx), pw, "Cut removed nothing");
        });

        // Editing the revealed phrase masks it again and drops the note.
        vcx.update(|window, cx| ui::focus_input(&password, window, cx));
        vcx.simulate_input("x");
        vcx.run_until_parked();
        assert!(vcx.update(|_, cx| ui::input_is_masked(&password, cx)));
        assert!(!shown("master-write-it-down", &mut vcx));

        // Back clears the passwords and re-masks.
        vcx.update(|window, cx| view.update(cx, |v, cx| v.back(window, cx)));
        vcx.update(|_, cx| {
            assert!(ui::input_is_empty(&password, cx));
            assert!(ui::input_is_empty(&confirm, cx));
        });
    }

    fn subtitle_key(text: &str) -> &'static str {
        Box::leak(format!("choose-subtitle {text}").into_boxed_str())
    }

    /// The welcome is the unlock card: the 128 pt still icon, and the subtitle for a
    /// first run without recent vaults.
    #[gpui::test]
    fn home_is_the_unlock_card(cx: &mut TestAppContext) {
        let (_state, _view, mut vcx) = window(cx);
        vcx.run_until_parked();
        assert!(shown("choose-card", &mut vcx));
        assert!(shown("choose-vault-name", &mut vcx));
        let icon = vcx.debug_bounds("choose-icon").unwrap();
        assert_eq!(icon.size.width, px(ui::UNLOCK_ICON_SIZE));
        assert_eq!(icon.size.height, px(ui::UNLOCK_ICON_SIZE));
        assert!(shown(subtitle_key(WELCOME_NO_RECENTS), &mut vcx));
        assert!(!shown(subtitle_key(WELCOME_WITH_RECENTS), &mut vcx));
        // Create and the Open link sit below the icon.
        let open = vcx.debug_bounds("choose-open ready").unwrap();
        assert!(open.top() > icon.bottom());
    }

    /// With recent vaults the subtitle points at them, and the rows come before the
    /// Create button and the Open link.
    #[gpui::test]
    fn home_subtitle_follows_the_recents(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("New.vault");
        std::fs::create_dir(&package).unwrap();
        let (_state, _view, mut vcx) = window_with_recents(vec![package], cx);
        vcx.run_until_parked();
        assert!(shown(subtitle_key(WELCOME_WITH_RECENTS), &mut vcx));
        assert!(!shown(subtitle_key(WELCOME_NO_RECENTS), &mut vcx));
        let row = vcx.debug_bounds("recent 0 openable").unwrap();
        let open = vcx.debug_bounds("choose-open ready").unwrap();
        assert!(row.bottom() <= open.top(), "recents first");
    }

    /// While a vault is opening the Open link is disabled: a click shows no file panel.
    #[gpui::test]
    fn open_link_is_disabled_while_busy(cx: &mut TestAppContext) {
        let (state, _view, mut vcx) = window(cx);
        state.update(&mut vcx, |s, cx| {
            s.busy = Some(Busy::Opening);
            cx.notify();
        });
        vcx.run_until_parked();
        assert!(!shown("choose-open ready", &mut vcx));
        let open = vcx.debug_bounds("choose-open busy").unwrap();
        vcx.simulate_click(open.center(), Modifiers::none());
        vcx.run_until_parked();
        assert!(!vcx.did_prompt_for_paths(), "busy: no file panel");

        state.update(&mut vcx, |s, cx| {
            s.busy = None;
            cx.notify();
        });
        vcx.run_until_parked();
        let open = vcx.debug_bounds("choose-open ready").unwrap();
        vcx.simulate_click(open.center(), Modifiers::none());
        vcx.run_until_parked();
        assert!(vcx.did_prompt_for_paths(), "idle: the file panel opens");
    }

    fn open_create(view: &Entity<ChooseScreen>, vcx: &mut VisualTestContext) {
        vcx.update(|window, cx| view.update(cx, |v, cx| v.start_create(window, cx)));
        vcx.run_until_parked();
    }

    /// The create form is the unlock card with a 64 pt icon, its title and subtitle.
    #[gpui::test]
    fn create_is_the_unlock_card_with_a_small_icon(cx: &mut TestAppContext) {
        let (_state, view, mut vcx) = window(cx);
        open_create(&view, &mut vcx);
        assert!(shown("create-card", &mut vcx));
        assert!(!shown("choose-card", &mut vcx));
        let icon = vcx.debug_bounds("create-icon").unwrap();
        assert_eq!(icon.size.width, px(CREATE_ICON_SIZE));
        assert_eq!(icon.size.height, px(CREATE_ICON_SIZE));
        assert!(shown(
            Box::leak(format!("create-subtitle {CREATE_SUBTITLE}").into_boxed_str()),
            &mut vcx
        ));
        // Create above the Back link.
        let create = vcx.debug_bounds("create-submit blocked").unwrap();
        let back = vcx.debug_bounds("create-back ready").unwrap();
        assert!(create.bottom() <= back.top());
    }

    /// While calibrating, the Back link and Esc do nothing; idle, Esc in a field goes
    /// back to the welcome card.
    #[gpui::test]
    fn back_is_disabled_while_calibrating_and_esc_goes_back(cx: &mut TestAppContext) {
        let (state, view, mut vcx) = window(cx);
        open_create(&view, &mut vcx);
        state.update(&mut vcx, |s, cx| {
            s.busy = Some(Busy::Calibrating);
            cx.notify();
        });
        vcx.run_until_parked();
        assert!(!shown("create-back ready", &mut vcx));
        let back = vcx.debug_bounds("create-back busy").unwrap();
        vcx.simulate_click(back.center(), Modifiers::none());
        vcx.simulate_keystrokes("escape");
        vcx.run_until_parked();
        view.read_with(&vcx, |v, _| assert_eq!(v.step, Step::Create, "busy: stays"));

        state.update(&mut vcx, |s, cx| {
            s.busy = None;
            cx.notify();
        });
        let name = view.read_with(&vcx, |v, _| v.name.clone());
        vcx.update(|window, cx| ui::focus_input(&name, window, cx));
        vcx.simulate_keystrokes("escape");
        vcx.run_until_parked();
        view.read_with(&vcx, |v, _| assert_eq!(v.step, Step::Home, "Esc: back"));
        assert!(shown("choose-card", &mut vcx));
    }

    fn forget_key(path: &std::path::Path) -> &'static str {
        Box::leak(format!("choose-forget {}", path.display()).into_boxed_str())
    }

    fn hover(selector: &'static str, vcx: &mut VisualTestContext) {
        let at = vcx.debug_bounds(selector).unwrap().center();
        vcx.simulate_mouse_move(at, None, Modifiers::none());
        vcx.run_until_parked();
    }

    fn click_at(selector: &'static str, vcx: &mut VisualTestContext) {
        let at = vcx.debug_bounds(selector).unwrap().center();
        vcx.simulate_click(at, Modifiers::none());
        vcx.run_until_parked();
    }

    /// The × sits inside its row's right end, centred on the row's height, and the row
    /// stays hovered (the × stays) with the pointer on the × itself.
    fn forget_in_place(row: &'static str, path: &std::path::Path, vcx: &mut VisualTestContext) {
        let row = vcx.debug_bounds(row).unwrap();
        let x = vcx.debug_bounds(forget_key(path)).unwrap();
        assert!((x.center().y - row.center().y).abs() <= px(0.5), "centred");
        assert!(
            x.right() <= row.right() && x.left() > row.center().x,
            "right end"
        );
        vcx.simulate_mouse_move(x.center(), None, Modifiers::none());
        vcx.run_until_parked();
        assert_eq!(
            vcx.debug_bounds(forget_key(path)),
            Some(x),
            "no flicker under the pointer"
        );
    }

    fn nothing_opened(state: &Entity<AppState>, vcx: &VisualTestContext) {
        state.read_with(vcx, |s, _| {
            assert!(s.busy.is_none(), "nothing opening");
            assert!(s.error.is_none(), "nothing was attempted");
            assert!(s.vault.is_none());
            assert_eq!(s.screen, Screen::Choose);
        });
    }

    /// The × shows only on the hovered row; clicking it drops that recent without
    /// opening it or touching the file, and the last one gone brings the no-recents
    /// subtitle (owner decision 2026-11-27, option A).
    #[gpui::test]
    fn forget_removes_a_recent_without_opening_it(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("A.vault"), dir.path().join("B.vault"));
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let (state, _view, mut vcx) = window_with_recents(vec![a.clone(), b.clone()], cx);
        vcx.run_until_parked();
        assert!(!shown(forget_key(&a), &mut vcx), "hidden until hovered");
        assert!(!shown(forget_key(&b), &mut vcx));

        hover("recent 0 openable", &mut vcx);
        assert!(shown(forget_key(&a), &mut vcx));
        assert!(!shown(forget_key(&b), &mut vcx), "only the hovered row");
        forget_in_place("recent 0 openable", &a, &mut vcx);
        hover("choose-open ready", &mut vcx);
        assert!(!shown(forget_key(&a), &mut vcx), "gone with the pointer");

        hover("recent 0 openable", &mut vcx);
        click_at(forget_key(&a), &mut vcx);
        nothing_opened(&state, &vcx);
        state.read_with(&vcx, |s, _| assert_eq!(s.recent_vaults, vec![b.clone()]));
        assert!(a.is_dir(), "the vault itself is untouched");
        assert!(shown(subtitle_key(WELCOME_WITH_RECENTS), &mut vcx));
        // The card shrinks and stays centred, so B need not be under the pointer.

        hover("recent 0 openable", &mut vcx);
        click_at(forget_key(&b), &mut vcx);
        nothing_opened(&state, &vcx);
        state.read_with(&vcx, |s, _| assert!(s.recent_vaults.is_empty()));
        assert!(!shown("recent 0 openable", &mut vcx));
        assert!(shown(subtitle_key(WELCOME_NO_RECENTS), &mut vcx));
        assert!(!shown(subtitle_key(WELCOME_WITH_RECENTS), &mut vcx));
    }

    /// While a vault opens the × is drawn disabled and does nothing.
    #[gpui::test]
    fn forget_is_inert_while_busy(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("A.vault");
        std::fs::create_dir(&a).unwrap();
        let (state, _view, mut vcx) = window_with_recents(vec![a.clone()], cx);
        state.update(&mut vcx, |s, cx| {
            s.busy = Some(Busy::Opening);
            cx.notify();
        });
        vcx.run_until_parked();
        // The row's selector reads "legacy" or "openable" by layout only.
        hover("recent 0 openable", &mut vcx);
        click_at(forget_key(&a), &mut vcx);
        state.read_with(&vcx, |s, _| {
            assert_eq!(s.recent_vaults, vec![a.clone()], "busy: kept");
            assert_eq!(s.busy, Some(Busy::Opening));
        });

        state.update(&mut vcx, |s, cx| {
            s.busy = None;
            cx.notify();
        });
        vcx.run_until_parked();
        hover("recent 0 openable", &mut vcx);
        click_at(forget_key(&a), &mut vcx);
        state.read_with(&vcx, |s, _| {
            assert!(s.recent_vaults.is_empty(), "idle: gone")
        });
    }

    /// A muted legacy row (not clickable itself) can be removed too.
    #[gpui::test]
    fn forget_removes_a_legacy_recent(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("Old.vault");
        std::fs::write(&old, b"old single-file vault").unwrap();
        let (state, _view, mut vcx) = window_with_recents(vec![old.clone()], cx);
        vcx.run_until_parked();
        hover("recent 0 legacy", &mut vcx);
        // The legacy row is taller (its notice): the × still centres on it.
        forget_in_place("recent 0 legacy", &old, &mut vcx);
        click_at(forget_key(&old), &mut vcx);
        nothing_opened(&state, &vcx);
        state.read_with(&vcx, |s, _| {
            assert!(s.recent_vaults.is_empty());
            assert!(s.legacy_recents.is_empty());
        });
        assert_eq!(std::fs::read(&old).unwrap(), b"old single-file vault");
        assert!(shown(subtitle_key(WELCOME_NO_RECENTS), &mut vcx));
    }

    fn set_busy(state: &Entity<AppState>, busy: Option<Busy>, vcx: &mut VisualTestContext) {
        state.update(vcx, |s, cx| {
            s.busy = busy;
            cx.notify();
        });
        vcx.run_until_parked();
    }

    /// The most opaque fill painted inside `selector`'s bounds.
    fn max_fill_alpha(selector: &'static str, vcx: &mut VisualTestContext) -> f32 {
        let area = vcx.debug_bounds(selector).unwrap();
        vcx.update(|window, _| {
            let area = area.scale(window.scale_factor());
            window
                .painted_quads()
                .iter()
                .filter(|q| area.intersect(&q.bounds) == q.bounds)
                .filter_map(|q| q.background.as_solid())
                .map(|c| c.a)
                .fold(0., f32::max)
        })
    }

    fn focused_nothing(vcx: &mut VisualTestContext) -> bool {
        vcx.update(|window, cx| window.focused(cx).is_none())
    }

    /// While calibrating (owner decision 2026-11-27, option A) the form stays drawn,
    /// dimmed to 40 % under the spinner and the calibrating text, and frozen: clicks on
    /// Choose…, Suggest passphrase, the mask toggle and the fields, Tab and typing change
    /// nothing and leave focus nowhere. Create shows its loading spinner, Back is off.
    /// When it ends the form is live again with the password field focused.
    #[gpui::test]
    fn calibrating_dims_and_freezes_the_form(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, view, mut vcx) = window(cx);
        view.update(&mut vcx, |v, _| v.folder = Some(dir.path().to_owned()));
        open_create(&view, &mut vcx);
        let (name, password, confirm) = view.read_with(&vcx, |v, _| {
            (v.name.clone(), v.password.clone(), v.confirm.clone())
        });
        type_into(&password, STRONG, &mut vcx);
        type_into(&confirm, STRONG, &mut vcx);
        let card = vcx.debug_bounds("create-card").unwrap();
        let field = vcx.debug_bounds("create-name").unwrap();
        let folder = vcx.debug_bounds("create-folder").unwrap();
        let suggest = vcx.debug_bounds("create-suggest").unwrap();
        let pw = vcx.debug_bounds("create-password").unwrap();
        // The mask toggle sits at the field's right end.
        let mask = gpui::point(pw.right() - px(14.), pw.center().y);
        let lit = max_fill_alpha("create-name", &mut vcx);
        assert!(shown("create-form live", &mut vcx));
        assert!(!shown("create-calibrating", &mut vcx));
        assert!(!shown("create-loading", &mut vcx));

        set_busy(&state, Some(Busy::Calibrating), &mut vcx);
        let overlay = vcx.debug_bounds("create-calibrating").unwrap();
        assert!(overlay.contains(&field.center()), "over the fields");
        assert_eq!(
            vcx.debug_bounds("create-card").unwrap(),
            card,
            "card unchanged"
        );
        assert!(shown("create-form dimmed", &mut vcx));
        assert_eq!(
            vcx.debug_bounds("create-name").unwrap(),
            field,
            "still drawn, in place"
        );
        let dim = max_fill_alpha("create-name", &mut vcx);
        assert!(lit > 0.);
        assert!(
            (dim - lit * ui::DIMMED_OPACITY).abs() < 0.02,
            "dimmed to 40 %: {lit} -> {dim}"
        );
        assert!(
            shown("create-loading", &mut vcx),
            "Create shows its spinner"
        );
        let create = vcx.debug_bounds("create-submit blocked").unwrap();
        assert!(create.top() >= overlay.bottom());
        assert!(shown("create-back busy", &mut vcx));
        assert!(focused_nothing(&mut vcx), "no caret left in a frozen field");

        let masked = vcx.update(|_, cx| ui::input_is_masked(&password, cx));
        for at in [folder.center(), suggest.center(), mask, field.center()] {
            vcx.simulate_click(at, Modifiers::none());
            vcx.run_until_parked();
            assert!(focused_nothing(&mut vcx), "a click focuses nothing");
        }
        for _ in 0..3 {
            vcx.simulate_keystrokes("tab");
            vcx.run_until_parked();
            assert!(focused_nothing(&mut vcx), "Tab lands nowhere in the form");
        }
        // Root's Tab action is `focus_next` (a test Tab with nothing focused does not
        // reach it): it can land on a dimmed field's Tab stop; the next frame drops it.
        for _ in 0..3 {
            vcx.update(|window, cx| window.focus_next(cx));
            vcx.simulate_input("x");
            vcx.run_until_parked();
            assert!(
                focused_nothing(&mut vcx),
                "focus_next lands nowhere in the form"
            );
        }
        vcx.simulate_keystrokes("shift-tab");
        vcx.simulate_input("abc");
        vcx.simulate_keystrokes("backspace enter");
        vcx.run_until_parked();
        assert!(focused_nothing(&mut vcx));
        assert!(!vcx.did_prompt_for_paths(), "no folder panel");
        view.read_with(&vcx, |v, _| {
            assert_eq!(v.folder.as_deref(), Some(dir.path()));
            assert!(!v.check.suggested, "no passphrase suggested");
        });
        vcx.update(|_, cx| {
            assert_eq!(ui::input_text(&name, cx), "Personal");
            assert_eq!(ui::input_text(&password, cx), STRONG);
            assert_eq!(ui::input_text(&confirm, cx), STRONG);
            assert_eq!(ui::input_is_masked(&password, cx), masked, "mask unchanged");
        });

        set_busy(&state, None, &mut vcx);
        assert!(!shown("create-calibrating", &mut vcx));
        assert!(shown("create-form live", &mut vcx));
        assert!(!shown("create-loading", &mut vcx));
        assert!((max_fill_alpha("create-name", &mut vcx) - lit).abs() < 0.001);
        assert!(
            vcx.update(|window, cx| {
                gpui::Focusable::focus_handle(password.read(cx), cx).is_focused(window)
            }),
            "the password field takes the cursor again"
        );
        type_into(&name, "Work", &mut vcx);
        vcx.update(|_, cx| assert_eq!(ui::input_text(&name, cx), "Work"));
    }

    /// Key down and up: a focused element's keyboard click fires on the key up.
    fn press(key: &'static str, vcx: &mut VisualTestContext) {
        vcx.simulate_keystrokes(key);
        vcx.simulate_event(gpui::KeyUpEvent {
            keystroke: gpui::Keystroke::parse(key).unwrap(),
        });
        vcx.run_until_parked();
    }

    fn forget_focused(
        path: &std::path::Path,
        view: &Entity<ChooseScreen>,
        vcx: &mut VisualTestContext,
    ) -> bool {
        vcx.update(|window, cx| {
            view.read(cx)
                .forget_focus
                .get(path)
                .is_some_and(|f| f.is_focused(window))
        })
    }

    /// Tab reaches the hidden × slots (no pointer needed): the focused one shows its ×,
    /// Enter removes that recent without opening it, and focus moves to the next row's
    /// ×, then to "Create new vault" when none are left. While a vault opens the × is
    /// out of the Tab order and Enter removes nothing.
    #[gpui::test]
    fn forget_by_keyboard_moves_focus_on(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("A.vault"), dir.path().join("B.vault"));
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let (state, view, mut vcx) = window_with_recents(vec![a.clone(), b.clone()], cx);
        vcx.run_until_parked();
        // Nothing focused: Tab needs a focused element in Root's context first.
        let first = view.read_with(&vcx, |v, _| v.forget_focus[&a].clone());
        vcx.update(|window, cx| window.focus(&first, cx));
        vcx.run_until_parked();
        assert!(
            shown(forget_key(&a), &mut vcx),
            "focused: shown without hover"
        );
        assert!(!shown(forget_key(&b), &mut vcx));
        vcx.simulate_keystrokes("tab");
        vcx.run_until_parked();
        assert!(
            forget_focused(&b, &view, &mut vcx),
            "Tab reaches the next hidden ×"
        );
        assert!(shown(forget_key(&b), &mut vcx));
        assert!(!shown(forget_key(&a), &mut vcx));
        vcx.simulate_keystrokes("shift-tab");
        vcx.run_until_parked();
        assert!(forget_focused(&a, &view, &mut vcx));

        press("enter", &mut vcx);
        vcx.run_until_parked();
        nothing_opened(&state, &vcx);
        state.read_with(&vcx, |s, _| assert_eq!(s.recent_vaults, vec![b.clone()]));
        assert!(
            forget_focused(&b, &view, &mut vcx),
            "focus moves to the next ×"
        );
        assert!(shown(forget_key(&b), &mut vcx));

        press("enter", &mut vcx);
        vcx.run_until_parked();
        nothing_opened(&state, &vcx);
        state.read_with(&vcx, |s, _| assert!(s.recent_vaults.is_empty()));
        assert!(
            vcx.update(|window, cx| view.read(cx).create_focus.is_focused(window)),
            "no rows left: Create new vault"
        );
    }

    /// The last row's × hands focus to the row above; busy, the × is no Tab stop and
    /// Enter keeps the recent.
    #[gpui::test]
    fn forget_by_keyboard_last_row_and_busy(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("A.vault"), dir.path().join("B.vault"));
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let (state, view, mut vcx) = window_with_recents(vec![a.clone(), b.clone()], cx);
        vcx.run_until_parked();
        let last = view.read_with(&vcx, |v, _| v.forget_focus[&b].clone());
        vcx.update(|window, cx| window.focus(&last, cx));
        vcx.run_until_parked();
        press("enter", &mut vcx);
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| assert_eq!(s.recent_vaults, vec![a.clone()]));
        assert!(forget_focused(&a, &view, &mut vcx), "the row above");

        set_busy(&state, Some(Busy::Opening), &mut vcx);
        press("enter", &mut vcx);
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert_eq!(s.recent_vaults, vec![a.clone()], "kept")
        });
        // Out of the Tab order: Tab from Create never lands on the ×.
        let create = view.read_with(&vcx, |v, _| v.create_focus.clone());
        set_busy(&state, None, &mut vcx);
        vcx.update(|window, cx| window.focus(&create, cx));
        set_busy(&state, Some(Busy::Opening), &mut vcx);
        for _ in 0..4 {
            vcx.simulate_keystrokes("tab");
            vcx.run_until_parked();
            assert!(!forget_focused(&a, &view, &mut vcx), "busy: no Tab stop");
        }
        press("enter", &mut vcx);
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert_eq!(s.recent_vaults, vec![a.clone()], "kept")
        });
    }

    /// A recent vault in the old single-file layout is listed with the explanation and
    /// clicking it opens nothing; a package next to it stays openable.
    #[gpui::test]
    fn legacy_recent_is_listed_but_not_opened(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("Old.vault");
        std::fs::write(&old, b"old single-file vault").unwrap();
        let package = dir.path().join("New.vault");
        std::fs::create_dir(&package).unwrap();
        let (state, _view, mut vcx) = window_with_recents(vec![old, package], cx);
        vcx.run_until_parked();
        assert!(shown("recent 0 legacy", &mut vcx));
        assert!(shown("recent 1 openable", &mut vcx));
        let row = vcx.debug_bounds("recent 0 legacy").unwrap();
        vcx.simulate_click(row.center(), Modifiers::none());
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert!(s.busy.is_none());
            assert!(s.error.is_none(), "nothing was attempted");
            assert!(s.vault.is_none());
        });
    }
}
