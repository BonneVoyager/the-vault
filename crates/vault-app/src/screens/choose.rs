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
use vault_core::{ExposeSecret as _, strength_bits};

use crate::cloud;
use crate::persist;
use crate::state::{AppState, Busy, ChooseIntent};
use crate::ui;

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
    strength: f64,
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
            cx.subscribe_in(&password, window, |this, input, ev: &InputEvent, _, cx| {
                if matches!(ev, InputEvent::Change) {
                    let secret = ui::input_secret(input, cx);
                    this.strength = strength_bits(secret.expose_secret());
                    this.problem = None;
                    cx.notify();
                }
            }),
            cx.subscribe_in(
                &confirm,
                window,
                |this, _, ev: &InputEvent, window, cx| match ev {
                    InputEvent::PressEnter { .. } => this.submit_create(window, cx),
                    InputEvent::Change => {
                        this.problem = None;
                        cx.notify();
                    }
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
            strength: 0.,
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
        ui::clear_input(&self.password, window, cx);
        ui::clear_input(&self.confirm, window, cx);
        self.strength = 0.;
        if self.step == Step::Create {
            ui::focus_input(&self.name, window, cx);
        }
        cx.notify();
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
        ui::clear_input(&self.password, window, cx);
        ui::clear_input(&self.confirm, window, cx);
        self.strength = 0.;
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
        let password = ui::input_secret(&self.password, cx);
        let confirm = ui::input_secret(&self.confirm, cx);
        if password.expose_secret().is_empty() {
            self.problem = Some("Choose a master password.".into());
        } else if password.expose_secret() != confirm.expose_secret() {
            self.problem = Some("The passwords do not match.".into());
        }
        drop(confirm);
        if self.problem.is_some() {
            cx.notify();
            return;
        }
        ui::clear_input(&self.password, window, cx);
        ui::clear_input(&self.confirm, window, cx);
        self.strength = 0.;
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
                    .on_click(cx.listener(|this, _, window, cx| this.start_create(window, cx))),
            )
            .child(
                Button::new("open")
                    .label("Open existing vault…")
                    .disabled(busy.is_some())
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
                    .cursor_pointer()
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
                            .on_click(cx.listener(|this, _, _, cx| this.choose_folder(cx))),
                    ),
            )
            .when_some(provider, |card, provider| {
                card.child(ui::h_flex().child(
                    Tag::info().child(format!("In {provider}: syncs to your other devices")),
                ))
            })
            .child(field_label("Master password", cx))
            .child(ui::input(&self.password))
            .child(ui::strength_meter(self.strength, cx))
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
                        .on_click(cx.listener(|this, _, window, cx| this.back(window, cx))),
                )
                .child(
                    Button::new("do-create")
                        .primary()
                        .label("Create vault")
                        .loading(busy == Some(Busy::Calibrating))
                        .disabled(busy.is_some())
                        .on_click(
                            cx.listener(|this, _, window, cx| this.submit_create(window, cx)),
                        ),
                ),
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
