//! Launch → choose vault (specs/05-ui.md §2.1).

use std::path::PathBuf;

use gpui::{
    Context, Entity, FontWeight, InteractiveElement as _, IntoElement, ParentElement as _, Render,
    SharedString, StatefulInteractiveElement as _, Styled as _, Subscription, Window, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::spinner::Spinner;
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Disableable as _};

use crate::cloud;
use crate::persist;
use crate::state::{AppState, Busy, ChooseIntent};
use crate::ui::{self, Clickable as _};

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
    _subscriptions: Vec<Subscription>,
}

impl ChooseScreen {
    pub fn new(state: Entity<AppState>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let name = ui::text_input("Vault name", window, cx);
        ui::set_input(&name, "Personal", window, cx);
        let password = ui::password_input("Master password", window, cx);
        let confirm = ui::password_input("Confirm master password", window, cx);
        let subscriptions = vec![
            cx.observe(&state, |_, _, cx| cx.notify()),
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
            _subscriptions: subscriptions,
        }
    }

    /// Called by the root view when the screen becomes visible, and again whenever
    /// `AppState::choose_request` is set while it is visible.
    pub fn appear(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let request = self.state.update(cx, |s, _| s.choose_request.take());
        self.step = match request {
            Some(ChooseIntent::Create) => Step::Create,
            Some(ChooseIntent::Home) | None => Step::Home,
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
        let pick = ui::pick_path(false, "Open Vault", cx);
        let state = self.state.clone();
        cx.spawn(async move |_, cx| {
            if let Some(path) = pick.await {
                state.update(cx, |s, cx| s.open_vault(path, cx));
            }
        })
        .detach();
    }

    fn choose_folder(&mut self, cx: &mut Context<Self>) {
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

    fn render_home(&self, cx: &mut Context<Self>) -> gpui::Div {
        let state = self.state.read(cx);
        let busy = state.busy;
        let error = state.error.clone();
        let recent = state.recent_vaults.clone();
        let theme = cx.theme();
        let mut card = ui::card(cx)
            .child(
                div()
                    .text_xl()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Welcome to vault"),
            )
            .child(ui::muted(
                "Create a new vault or open one you already have.",
                cx,
            ))
            .child(
                Button::new("create")
                    .primary()
                    .label("Create new vault")
                    .disabled(busy.is_some())
                    .clickable_when(busy.is_none())
                    .on_click(cx.listener(|this, _, window, cx| this.start_create(window, cx))),
            )
            .child(
                Button::new("open")
                    .label("Open existing vault…")
                    .disabled(busy.is_some())
                    .clickable_when(busy.is_none())
                    .on_click(cx.listener(|this, _, _, cx| this.open_existing(cx))),
            );
        if busy == Some(Busy::Opening) {
            card = card.child(busy_row("Opening vault…", cx));
        }
        if busy == Some(Busy::Calibrating) {
            card = card.child(busy_row("Calibrating encryption for this Mac…", cx));
        }
        if let Some(error) = error {
            card = card.child(div().text_sm().text_color(theme.danger).child(error));
        }
        if !recent.is_empty() {
            let rows = recent.into_iter().enumerate().map(|(ix, path)| {
                let name = persist::vault_name(&path);
                let shown = path.display().to_string();
                let state = self.state.clone();
                div()
                    .id(("recent", ix))
                    .px(px(10.))
                    .py(px(6.))
                    .rounded(cx.theme().radius)
                    .clickable_when(busy.is_none())
                    .hover(|s| s.bg(cx.theme().accent))
                    .when(busy.is_none(), |row| {
                        row.on_click(move |_, _, cx| {
                            let path = path.clone();
                            state.update(cx, |s, cx| s.open_vault(path, cx));
                        })
                    })
                    .child(div().child(name))
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .overflow_hidden()
                            .text_ellipsis()
                            .child(shown),
                    )
            });
            card = card
                .child(div().h(px(1.)).bg(cx.theme().border))
                .child(ui::muted("Recent vaults", cx))
                .child(ui::v_flex().gap(px(2.)).children(rows));
        }
        card
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

        let mut card = ui::card(cx)
            .child(
                div()
                    .text_xl()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Create a new vault"),
            )
            .child(field_label("Name", cx))
            .child(ui::input(&self.name))
            .child(field_label("Location", cx))
            .child(
                ui::h_flex()
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
                            .label("Choose…")
                            .clickable()
                            .on_click(cx.listener(|this, _, _, cx| this.choose_folder(cx))),
                    ),
            )
            .when_some(provider, |card, provider| {
                card.child(ui::h_flex().child(
                    Tag::info().child(format!("In {provider}: syncs to your other devices")),
                ))
            })
            .child(field_label("Master password", cx))
            .child(ui::input(&self.password).mask_toggle())
            .child(ui::master_password_feedback(
                &self.check,
                "create-suggest",
                cx.listener(|this, _, window, cx| this.suggest(window, cx)),
                cx,
            ))
            .child(ui::input(&self.confirm));
        if busy == Some(Busy::Calibrating) {
            card = card.child(busy_row("Calibrating encryption for this Mac…", cx));
        }
        if let Some(error) = error {
            card = card.child(div().text_sm().text_color(theme.danger).child(error));
        }
        card.child(
            ui::h_flex()
                .justify_end()
                .gap(px(8.))
                .child(
                    Button::new("back")
                        .ghost()
                        .label("Back")
                        .disabled(busy.is_some())
                        .clickable_when(busy.is_none())
                        .on_click(cx.listener(|this, _, window, cx| this.back(window, cx))),
                )
                .child(ui::submit_gate(
                    "create-submit",
                    ready && busy.is_none(),
                    Button::new("do-create")
                        .primary()
                        .label("Create vault")
                        .loading(busy == Some(Busy::Calibrating))
                        .disabled(busy.is_some() || !ready)
                        .clickable_when(busy.is_none() && ready)
                        .on_click(
                            cx.listener(|this, _, window, cx| this.submit_create(window, cx)),
                        ),
                )),
        )
    }
}

fn field_label(text: &'static str, cx: &gpui::App) -> gpui::Div {
    div()
        .text_xs()
        .font_weight(FontWeight::MEDIUM)
        .text_color(cx.theme().muted_foreground)
        .child(text)
}

fn busy_row(text: &'static str, cx: &gpui::App) -> gpui::Div {
    ui::h_flex()
        .gap(px(8.))
        .child(Spinner::new())
        .child(ui::muted(text, cx))
}

impl Render for ChooseScreen {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let card = match self.step {
            Step::Home => self.render_home(cx),
            Step::Create => self.render_create(cx),
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
        cx.update(gpui_component::init);
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
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
}
