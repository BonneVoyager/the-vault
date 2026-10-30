//! Inline credentials for an encrypted KeePass import, hosted by Settings.

use gpui::{
    Context, Entity, InteractiveElement as _, IntoElement, ParentElement as _, Render, Styled as _,
    Subscription, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::{ActiveTheme as _, Disableable as _, Sizable as _};
use vault_core::Uuid;

use crate::state::{AppState, Busy, TRANSFER_TAB};
use crate::ui::Clickable as _;
use crate::{text, ui};

pub(super) struct KdbxImportView {
    state: Entity<AppState>,
    password: Entity<InputState>,
    seen: Option<Uuid>,
    was_importing: bool,
    _subscriptions: Vec<Subscription>,
}

impl KdbxImportView {
    pub fn new(state: Entity<AppState>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let password = ui::password_input("KeePass database password", window, cx);
        let subscriptions = vec![
            cx.subscribe_in(
                &password,
                window,
                |this, _, event: &InputEvent, window, cx| {
                    if let InputEvent::PressEnter { .. } = event {
                        this.submit(window, cx);
                    }
                },
            ),
            cx.observe_in(&state, window, |this, state, window, cx| {
                let s = state.read(cx);
                let id = s.kdbx_import.as_ref().map(|request| request.id);
                let visible = s.settings_open && s.settings_tab == TRANSFER_TAB && id.is_some();
                let busy = s.busy == Some(Busy::Importing);
                if (this.seen != id || !visible || busy) && !ui::input_is_empty(&this.password, cx)
                {
                    ui::clear_input(&this.password, window, cx);
                }
                if visible && !busy && (this.seen != id || this.was_importing) {
                    cx.defer_in(window, move |this, window, cx| {
                        let s = this.state.read(cx);
                        if s.settings_open
                            && s.settings_tab == TRANSFER_TAB
                            && s.kdbx_import.as_ref().map(|request| request.id) == id
                            && s.busy.is_none()
                        {
                            ui::focus_input(&this.password, window, cx);
                        }
                    });
                }
                this.seen = id;
                this.was_importing = busy;
                cx.notify();
            }),
        ];
        Self {
            state,
            password,
            seen: None,
            was_importing: false,
            _subscriptions: subscriptions,
        }
    }

    fn submit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.state.read(cx).busy.is_some() {
            return;
        }
        let password = ui::input_secret(&self.password, cx);
        ui::clear_input(&self.password, window, cx);
        // A small database can finish before the busy-state notification is observed.
        self.was_importing = true;
        self.state.update(cx, |s, cx| s.import_kdbx(password, cx));
    }
}

impl Render for KdbxImportView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let s = self.state.read(cx);
        let Some(request) = &s.kdbx_import else {
            return div().into_any_element();
        };
        let busy = s.busy.is_some();
        let theme = cx.theme();
        ui::v_flex().debug_selector(|| "kdbx-import-form".into()).w_full().min_w_0().p(px(12.)).gap(px(10.))
            .on_action(cx.listener(|this, _: &gpui_component::dialog::Confirm, window, cx| {
                this.submit(window, cx);
            }))
            .rounded(theme.radius).bg(theme.secondary)
            .child(div().text_sm().truncate().child(format!("Import {}", text::file_name(&request.path))))
            .child(ui::input(&self.password).mask_toggle().disabled(busy))
            .child(ui::h_flex().gap(px(8.))
                .child(ui::muted(request.keyfile.as_deref().map(text::file_name).unwrap_or_else(|| "No key file selected".into()), cx).text_xs().flex_1().min_w_0().truncate())
                .child(Button::new("kdbx-keyfile").label("Choose key file…").small().disabled(busy).clickable_when(!busy)
                    .on_click(cx.listener(|this, _, _, cx| this.state.update(cx, |s, cx| s.choose_kdbx_keyfile(cx)))))
                .when(request.keyfile.is_some(), |row| row.child(
                    Button::new("kdbx-keyfile-clear").label("Remove").ghost().small().disabled(busy).clickable_when(!busy)
                        .on_click(cx.listener(|this, _, _, cx| this.state.update(cx, |s, cx| s.clear_kdbx_keyfile(cx)))))))
            .child(ui::muted("KDBX 3 and 4. Imports entries, custom fields, TOTP URIs, tags, group paths and password history. Attachments, custom icons and auto-type settings are not imported. Leave the password blank for a key-file-only database.", cx).text_xs().whitespace_normal())
            .when_some(request.error.clone(), |col, error| col.child(div().text_sm().whitespace_normal().text_color(theme.danger).child(error)))
            .child(ui::h_flex().justify_end().gap(px(8.))
                .child(Button::new("kdbx-cancel").label("Cancel").ghost().clickable()
                    .on_click(cx.listener(|this, _, _, cx| this.state.update(cx, |s, cx| s.cancel_kdbx_import(cx)))))
                .child(Button::new("kdbx-import").label("Import").primary().loading(s.busy == Some(Busy::Importing)).disabled(busy).clickable_when(!busy)
                    .on_click(cx.listener(|this, _, window, cx| this.submit(window, cx)))))
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::{AppContext as _, Focusable as _, TestAppContext, VisualTestContext};
    use gpui_component::Root;
    use std::sync::Arc;
    use vault_core::{KdfParams, SecretString};
    use vault_sync::{NoopHooks, SyncedVault};

    #[gpui::test]
    fn password_form_retries_clears_credentials_and_imports_on_enter(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let vault = SyncedVault::create(
            &dir.path().join("target.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(gpui_component::init);
        let input = std::rc::Rc::new(std::cell::RefCell::new(None));
        let capture = input.clone();
        let _observe = cx.update(|cx| {
            cx.observe_new::<KdbxImportView>(move |view, _, _| {
                *capture.borrow_mut() = Some(view.password.clone());
            })
        });
        state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
        let path = dir.path().join("source.kdbx");
        std::fs::write(
            &path,
            include_bytes!("../../../vault-core/tests/fixtures/keepass-v4.kdbx"),
        )
        .unwrap();
        let window = cx.add_window(|window, cx| {
            crate::theme::apply(window, cx);
            let item = cx.new(|cx| crate::root::VaultRoot::new(state.clone(), None, window, cx));
            Root::new(item, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        state.update(&mut vcx, |s, cx| s.request_kdbx_import(path, cx));
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("kdbx-import-form").is_some());
        vcx.simulate_input("wrong");
        vcx.simulate_keystrokes("enter");
        vcx.run_until_parked();
        assert!(state.read_with(&vcx, |s, _| s.kdbx_import.as_ref().unwrap().error.is_some()));
        assert!(
            state.read_with(&vcx, |s, _| s.settings_open),
            "Settings stays open for retry"
        );
        vcx.update(|window, cx| {
            let input = input.borrow();
            let input = input.as_ref().unwrap();
            assert!(ui::input_is_empty(input, cx), "submitted password cleared");
            assert!(
                input.read(cx).focus_handle(cx).is_focused(window),
                "password refocused for retry"
            );
        });
        vcx.simulate_input("kdbx-password");
        vcx.simulate_keystrokes("enter");
        vcx.run_until_parked();
        assert_eq!(state.read_with(&vcx, |s, _| s.counts.all), 2);
        assert!(vcx.debug_bounds("kdbx-import-form").is_none());
    }
}
