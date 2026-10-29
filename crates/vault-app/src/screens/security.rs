//! Settings ▸ Security tab (specs/05-ui.md §2.5).
//!
//! Rows: Touch ID (toggle; turning it off asks for the master password), master password
//! with an inline change form, encryption strength with an inline re-calibrate prompt, and an "Advanced"
//! disclosure holding the red rotate-vault-key confirm. The state lives in
//! `AppState::security`; this view owns only the password inputs and clears them whenever
//! their form closes.

use gpui::{
    AnyElement, App, Context, Entity, IntoElement, ParentElement as _, Render, Styled as _,
    Subscription, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::spinner::Spinner;
use gpui_component::switch::Switch;
use gpui_component::{ActiveTheme as _, Disableable as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{ExposeSecret as _, SecretString, strength_bits};

use crate::state::{AppState, Busy, SECURITY_TAB, SecurityForm};
use crate::ui;

/// Text of the red rotate confirm.
pub const ROTATE_WARNING: &str = "Rotating replaces the key that encrypts every item. \
     Other Macs must re-enter the master password, and Touch ID must be set up again.";

/// What a single-password prompt does with the password.
type Submit = fn(&mut AppState, SecretString, &mut Context<AppState>);

/// One master-password prompt: shown while `form` is open, cleared when it closes,
/// Enter or its button submits.
struct Prompt {
    form: SecurityForm,
    input: Entity<InputState>,
    submit: Submit,
}

const PROMPTS: [(SecurityForm, Submit); 3] = [
    (SecurityForm::Recalibrate, |s, pw, cx| {
        s.recalibrate_kdf(pw, cx)
    }),
    (SecurityForm::RotateKey, |s, pw, cx| s.rotate_key(pw, cx)),
    (SecurityForm::DisableTouchId, |s, pw, cx| {
        s.disable_touch_id(pw, cx)
    }),
];

/// Subscribes `f` to Enter in `input`.
fn on_enter(
    input: &Entity<InputState>,
    window: &mut Window,
    cx: &mut Context<SecurityView>,
    f: impl Fn(&mut SecurityView, &mut Window, &mut Context<SecurityView>) + 'static,
) -> Subscription {
    cx.subscribe_in(
        input,
        window,
        move |this, _, ev: &InputEvent, window, cx| {
            if let InputEvent::PressEnter { .. } = ev {
                f(this, window, cx);
            }
        },
    )
}

pub struct SecurityView {
    state: Entity<AppState>,
    current: Entity<InputState>,
    new: Entity<InputState>,
    confirm: Entity<InputState>,
    /// The single master-password prompts: re-calibrate, rotate, turn Touch ID off.
    prompts: Vec<Prompt>,
    strength: f64,
    _subscriptions: Vec<Subscription>,
}

impl SecurityView {
    pub fn new(state: Entity<AppState>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let current = ui::password_input("Current master password", window, cx);
        let new = ui::password_input("New master password", window, cx);
        let confirm = ui::password_input("Confirm new master password", window, cx);
        let prompts: Vec<Prompt> = PROMPTS
            .iter()
            .map(|&(form, submit)| Prompt {
                form,
                input: ui::password_input("Master password", window, cx),
                submit,
            })
            .collect();

        let mut subscriptions = vec![
            cx.subscribe_in(&new, window, |this, input, ev: &InputEvent, _, cx| {
                if matches!(ev, InputEvent::Change) {
                    let secret = ui::input_secret(input, cx);
                    this.strength = strength_bits(secret.expose_secret());
                    cx.notify();
                }
            }),
            cx.observe_in(&state, window, |this, state, window, cx| {
                let (form, visible, unlocked) = {
                    let s = state.read(cx);
                    (
                        s.security.form,
                        s.settings_open && s.settings_tab == SECURITY_TAB,
                        !s.locked,
                    )
                };
                let form = form.filter(|_| visible);
                if form != Some(SecurityForm::ChangePassword) {
                    this.clear_change_form(window, cx);
                }
                for p in &this.prompts {
                    if form != Some(p.form) {
                        clear(&p.input, window, cx);
                    }
                }
                // "On tab open": measure once per KDF params while the tab is visible.
                if visible && unlocked {
                    state.update(cx, |s, cx| s.measure_kdf(cx));
                }
                cx.notify();
            }),
        ];
        for input in [&current, &new, &confirm] {
            subscriptions.push(on_enter(input, window, cx, Self::submit_change));
        }
        for p in &prompts {
            let form = p.form;
            subscriptions.push(on_enter(&p.input, window, cx, move |this, w, cx| {
                this.submit_prompt(form, w, cx)
            }));
        }

        Self {
            state,
            current,
            new,
            confirm,
            prompts,
            strength: 0.,
            _subscriptions: subscriptions,
        }
    }

    fn clear_change_form(&mut self, window: &mut Window, cx: &mut App) {
        clear(&self.current, window, cx);
        clear(&self.new, window, cx);
        clear(&self.confirm, window, cx);
        self.strength = 0.;
    }

    fn open(&mut self, form: Option<SecurityForm>, window: &mut Window, cx: &mut Context<Self>) {
        self.state.update(cx, |s, cx| s.set_security_form(form, cx));
        let first = match form {
            Some(SecurityForm::ChangePassword) => Some(&self.current),
            Some(f) => self.prompt(f),
            None => None,
        };
        if let Some(input) = first {
            ui::focus_input(input, window, cx);
        }
    }

    fn submit_change(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.state.read(cx).busy.is_some() || ui::input_is_empty(&self.current, cx) {
            return;
        }
        let current = ui::input_secret(&self.current, cx);
        let new = ui::input_secret(&self.new, cx);
        let confirm = ui::input_secret(&self.confirm, cx);
        // The current-password field is cleared at once; new/confirm stay so a mismatch
        // can be fixed. All three clear when the form closes.
        clear(&self.current, window, cx);
        self.state.update(cx, |s, cx| {
            s.change_master_password(current, new, confirm, cx)
        });
    }

    fn prompt(&self, form: SecurityForm) -> Option<&Entity<InputState>> {
        self.prompts
            .iter()
            .find(|p| p.form == form)
            .map(|p| &p.input)
    }

    /// Reads and clears the prompt's password, then hands it to the state.
    fn submit_prompt(&mut self, form: SecurityForm, window: &mut Window, cx: &mut Context<Self>) {
        let Some(p) = self.prompts.iter().find(|p| p.form == form) else {
            return;
        };
        let submit = p.submit;
        if let Some(password) = take(&p.input, window, cx) {
            self.state.update(cx, |s, cx| submit(s, password, cx));
        }
    }
}

fn clear(input: &Entity<InputState>, window: &mut Window, cx: &mut App) {
    if !ui::input_is_empty(input, cx) {
        ui::clear_input(input, window, cx);
    }
}

/// Reads and clears a password input; `None` if it is empty.
fn take(input: &Entity<InputState>, window: &mut Window, cx: &mut App) -> Option<SecretString> {
    if ui::input_is_empty(input, cx) {
        return None;
    }
    let secret = ui::input_secret(input, cx);
    ui::clear_input(input, window, cx);
    Some(secret)
}

/// A labelled row: label (with an optional caption) left, control right.
fn row(label: &'static str, caption: Option<String>, control: AnyElement, cx: &App) -> gpui::Div {
    let theme = cx.theme();
    ui::h_flex()
        .py(px(10.))
        .gap(px(12.))
        .border_b_1()
        .border_color(theme.border)
        .child(
            ui::v_flex()
                .flex_1()
                .gap(px(2.))
                .child(div().text_sm().child(label))
                .when_some(caption, |col, c| col.child(ui::muted(c, cx).text_xs())),
        )
        .child(control)
}

/// A tinted strip under a row holding an inline form.
fn strip(danger: bool, cx: &App) -> gpui::Div {
    let theme = cx.theme();
    let tint = if danger { theme.danger } else { theme.border };
    ui::v_flex()
        .gap(px(8.))
        .my(px(8.))
        .px(px(12.))
        .py(px(10.))
        .rounded(theme.radius)
        .bg(tint.opacity(if danger { 0.10 } else { 0.25 }))
        .border_1()
        .border_color(tint.opacity(0.5))
}

fn error_line(error: Option<gpui::SharedString>, cx: &App) -> Option<gpui::Div> {
    error.map(|e| div().text_sm().text_color(cx.theme().danger).child(e))
}

impl SecurityView {
    /// The Touch ID toggle (04 §2 policy: on only after a password unlock in this
    /// session) plus the password prompt for turning it off.
    fn touch_id_row(&self, cx: &mut Context<Self>) -> AnyElement {
        let s = self.state.read(cx);
        let enabled = s.touch_enabled();
        let stale = s
            .vault_id
            .and_then(|id| s.settings.touch_id.get(&id))
            .is_some_and(|p| p.stale);
        let blocker = s.touch_enable_blocker();
        let busy = s.busy;
        let disabling = s.security.form == Some(SecurityForm::DisableTouchId);
        let error = s.security.error.clone().filter(|_| disabling);
        let caption = if enabled {
            Some(
                "The master password is still required after a restart, every 7 days and \
                 after 5 failed attempts."
                    .to_owned(),
            )
        } else if stale {
            Some("Touch ID must be set up again.".to_owned())
        } else {
            blocker.filter(|_| !s.locked).map(str::to_owned)
        };
        let switch_off = !enabled && blocker.is_some();
        let toggle = Switch::new("touch-id")
            .checked(enabled)
            .disabled(busy.is_some() || switch_off || disabling)
            .accessibility_label("Unlock with Touch ID")
            .when_some(blocker.filter(|_| switch_off), |sw, why| sw.tooltip(why))
            .on_click(cx.listener(|this, on: &bool, w, cx| {
                if *on {
                    this.state.update(cx, |s, cx| s.enable_touch_id(cx));
                } else {
                    this.open(Some(SecurityForm::DisableTouchId), w, cx);
                }
            }));
        let toggle = ui::h_flex()
            .gap(px(8.))
            .when(busy == Some(Busy::EnablingTouchId), |r| {
                r.child(Spinner::new().small())
            })
            .child(toggle)
            .into_any_element();
        let mut col = ui::v_flex().child(row("Unlock with Touch ID", caption, toggle, cx));
        if disabling {
            let working = busy == Some(Busy::DisablingTouchId);
            col = col.child(
                strip(false, cx)
                    .child(
                        div()
                            .text_sm()
                            .child("Enter your master password to turn off Touch ID."),
                    )
                    .children(
                        self.prompt(SecurityForm::DisableTouchId)
                            .map(|i| ui::input(i).small().mask_toggle()),
                    )
                    .children(error_line(error, cx))
                    .child(
                        ui::h_flex()
                            .gap(px(8.))
                            .justify_end()
                            .child(
                                Button::new("touch-off-cancel")
                                    .ghost()
                                    .small()
                                    .label("Cancel")
                                    .disabled(working)
                                    .on_click(cx.listener(|this, _, w, cx| this.open(None, w, cx))),
                            )
                            .child(
                                Button::new("touch-off-submit")
                                    .primary()
                                    .small()
                                    .label("Turn Off")
                                    .loading(working)
                                    .on_click(cx.listener(|this, _, w, cx| {
                                        this.submit_prompt(SecurityForm::DisableTouchId, w, cx)
                                    })),
                            ),
                    ),
            );
        }
        col.into_any_element()
    }

    fn change_form(
        &self,
        busy: bool,
        error: Option<gpui::SharedString>,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        strip(false, cx)
            .child(ui::input(&self.current).small().mask_toggle())
            .child(ui::input(&self.new).small().mask_toggle())
            .child(ui::strength_meter(self.strength, cx))
            .child(ui::input(&self.confirm).small().mask_toggle())
            .children(error_line(error, cx))
            .child(
                ui::h_flex()
                    .gap(px(8.))
                    .justify_end()
                    .child(
                        Button::new("change-cancel")
                            .ghost()
                            .small()
                            .label("Cancel")
                            .disabled(busy)
                            .on_click(cx.listener(|this, _, w, cx| this.open(None, w, cx))),
                    )
                    .child(
                        Button::new("change-submit")
                            .primary()
                            .small()
                            .label("Change Password")
                            .loading(busy)
                            .on_click(cx.listener(|this, _, w, cx| this.submit_change(w, cx))),
                    ),
            )
    }

    fn recalibrate_form(
        &self,
        busy: bool,
        error: Option<gpui::SharedString>,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        strip(false, cx)
            .child(div().text_sm().child(
                "Re-calibrating measures this Mac and re-protects the vault key so one unlock \
                 takes about half a second. Enter your master password.",
            ))
            .children(
                self.prompt(SecurityForm::Recalibrate)
                    .map(|i| ui::input(i).small().mask_toggle()),
            )
            .children(error_line(error, cx))
            .when(busy, |col| {
                col.child(ui::muted(
                    "Measuring this Mac\u{2026} this can take a few seconds.",
                    cx,
                ))
            })
            .child(
                ui::h_flex()
                    .gap(px(8.))
                    .justify_end()
                    .child(
                        Button::new("recalibrate-cancel")
                            .ghost()
                            .small()
                            .label("Cancel")
                            .disabled(busy)
                            .on_click(cx.listener(|this, _, w, cx| this.open(None, w, cx))),
                    )
                    .child(
                        Button::new("recalibrate-submit")
                            .primary()
                            .small()
                            .label("Re-calibrate")
                            .loading(busy)
                            .on_click(cx.listener(|this, _, w, cx| {
                                this.submit_prompt(SecurityForm::Recalibrate, w, cx)
                            })),
                    ),
            )
    }

    fn rotate_form(
        &self,
        busy: bool,
        error: Option<gpui::SharedString>,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        strip(true, cx)
            .child(div().text_sm().child(ROTATE_WARNING))
            .children(
                self.prompt(SecurityForm::RotateKey)
                    .map(|i| ui::input(i).small().mask_toggle()),
            )
            .children(error_line(error, cx))
            .child(
                ui::h_flex()
                    .gap(px(8.))
                    .justify_end()
                    .child(
                        Button::new("rotate-cancel")
                            .ghost()
                            .small()
                            .label("Cancel")
                            .disabled(busy)
                            .on_click(cx.listener(|this, _, w, cx| this.open(None, w, cx))),
                    )
                    .child(
                        Button::new("rotate-submit")
                            .danger()
                            .small()
                            .label("Rotate Key")
                            .loading(busy)
                            .on_click(cx.listener(|this, _, w, cx| {
                                this.submit_prompt(SecurityForm::RotateKey, w, cx)
                            })),
                    ),
            )
    }
}

impl Render for SecurityView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let touch_row = self.touch_id_row(cx);
        let s = self.state.read(cx);
        if s.locked || s.vault_path.is_none() {
            return ui::v_flex()
                .child(touch_row)
                .child(div().py(px(10.)).child(ui::muted(
                    "Unlock the vault to change its security settings.",
                    cx,
                )))
                .into_any_element();
        }
        let form = s.security.form;
        let error = s.security.error.clone();
        let advanced = s.security.advanced_open;
        let measuring = s.security.measuring;
        let seconds = s.kdf_seconds();
        let kdf = s.current_kdf();
        let busy = s.busy;
        let any_busy = busy.is_some();

        let strength_text = match (seconds, measuring) {
            (Some(secs), _) => format!("~{secs:.1} s on this Mac"),
            (None, true) => "Measuring\u{2026}".to_owned(),
            (None, false) => "Not measured".to_owned(),
        };
        let params = kdf.map(|k| {
            format!(
                "Argon2id, {} MiB, {} passes, {} lanes",
                k.m_cost_kib / 1024,
                k.t_cost,
                k.p_cost
            )
        });

        let change_button = Button::new("change-password")
            .small()
            .label("Change\u{2026}")
            .disabled(any_busy || form == Some(SecurityForm::ChangePassword))
            .on_click(
                cx.listener(|this, _, w, cx| this.open(Some(SecurityForm::ChangePassword), w, cx)),
            );
        let recalibrate_button = Button::new("recalibrate")
            .small()
            .label("Re-calibrate\u{2026}")
            .disabled(any_busy || form == Some(SecurityForm::Recalibrate))
            .on_click(
                cx.listener(|this, _, w, cx| this.open(Some(SecurityForm::Recalibrate), w, cx)),
            );
        let strength_control = ui::h_flex()
            .gap(px(8.))
            .when(measuring && seconds.is_none(), |r| {
                r.child(Spinner::new().small())
            })
            .child(recalibrate_button)
            .into_any_element();

        let state = self.state.clone();
        let disclosure = Button::new("security-advanced")
            .ghost()
            .small()
            .icon(Icon::new(if advanced {
                IconName::ChevronDown
            } else {
                IconName::ChevronRight
            }))
            .label("Advanced")
            .accessibility_label(if advanced {
                "Advanced, expanded"
            } else {
                "Advanced, collapsed"
            })
            .on_click(move |_, _, cx| state.update(cx, |s, cx| s.toggle_security_advanced(cx)));

        let error_for = |f: SecurityForm| if form == Some(f) { error.clone() } else { None };
        let mut body = ui::v_flex()
            .child(touch_row)
            .child(row(
                "Master password",
                None,
                change_button.into_any_element(),
                cx,
            ))
            .when(form == Some(SecurityForm::ChangePassword), |col| {
                col.child(self.change_form(
                    busy == Some(Busy::ChangingPassword),
                    error_for(SecurityForm::ChangePassword),
                    cx,
                ))
            })
            .child(row(
                "Encryption strength",
                Some(match params {
                    Some(p) => format!("{strength_text} \u{b7} {p}"),
                    None => strength_text,
                }),
                strength_control,
                cx,
            ))
            .when(form == Some(SecurityForm::Recalibrate), |col| {
                col.child(self.recalibrate_form(
                    busy == Some(Busy::Recalibrating),
                    error_for(SecurityForm::Recalibrate),
                    cx,
                ))
            })
            .child(div().pt(px(8.)).child(disclosure));
        if advanced {
            let rotate_button = Button::new("rotate-key")
                .small()
                .danger()
                .label("Rotate\u{2026}")
                .disabled(any_busy || form == Some(SecurityForm::RotateKey))
                .on_click(
                    cx.listener(|this, _, w, cx| this.open(Some(SecurityForm::RotateKey), w, cx)),
                );
            body = body
                .child(row(
                    "Rotate vault key",
                    Some("Replace the key that encrypts every item.".to_owned()),
                    rotate_button.into_any_element(),
                    cx,
                ))
                .when(form == Some(SecurityForm::RotateKey), |col| {
                    col.child(self.rotate_form(
                        busy == Some(Busy::RotatingKey),
                        error_for(SecurityForm::RotateKey),
                        cx,
                    ))
                });
        }
        body.into_any_element()
    }
}
