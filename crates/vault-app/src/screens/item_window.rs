//! A movable, item-pinned detail window (specs/05-ui.md §2.3). It reads the live vault by
//! ID so a selection change in the main window cannot change its contents. One window per
//! item, tracked in `AppState`: it closes on lock and vault switch (`AppState::lock`) and
//! when its item is deleted (its own observer).

use std::collections::HashSet;
use std::time::Duration;

use gpui::{
    AnyWindowHandle, App, AppContext as _, Bounds, Context, Entity, InteractiveElement as _,
    IntoElement, ParentElement as _, Render, Styled as _, Subscription, Task, TitlebarOptions,
    Window, WindowBounds, WindowOptions, div, prelude::FluentBuilder as _, px, size,
};
use gpui_component::{ActiveTheme as _, Root};
use vault_core::{ExposeSecret as _, FieldKind, SecretString, Uuid};

use super::main::detail::{DetailAction, DetailActions, ReadDetail};
use crate::state::{AppState, CopyTarget, parse_totp};
use crate::{text, theme, ui};

/// Longest window title, in characters (an ellipsis included), so a huge item title
/// cannot stretch the title bar or the Window menu.
const TITLE_MAX_CHARS: usize = 120;
/// Window title for an item whose title is blank.
const UNTITLED: &str = "Untitled";

/// The window title for an item titled `title` (owner decision 2026-10-31: the item's
/// name, following renames): trimmed, control characters (newlines, tabs) shown as
/// spaces, "Untitled" when blank, cut to [`TITLE_MAX_CHARS`] with a trailing ellipsis.
fn window_title_for(title: &str) -> String {
    let clean: String = title
        .trim()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let clean = clean.trim();
    if clean.is_empty() {
        return UNTITLED.to_owned();
    }
    if clean.chars().count() <= TITLE_MAX_CHARS {
        return clean.to_owned();
    }
    let mut cut: String = clean.chars().take(TITLE_MAX_CHARS - 1).collect();
    cut.truncate(cut.trim_end().len());
    cut.push('\u{2026}');
    cut
}

/// The window title for item `id` as it is now in `s`.
fn item_title(s: &AppState, id: Uuid) -> String {
    let title = s
        .unlocked_vault()
        .and_then(|vault| vault.get(id))
        .map_or("", |item| item.title.as_str());
    window_title_for(title)
}

/// Opens the window pinned to `id`, or brings its existing window to the front.
pub fn open_item_window(
    state: Entity<AppState>,
    id: Uuid,
    cx: &mut App,
) -> gpui::Result<AnyWindowHandle> {
    if let Some(handle) = state.update(cx, |s, cx| s.item_window(id, cx)) {
        handle.update(cx, |_, window, _| window.activate_window())?;
        return Ok(handle);
    }
    let title = item_title(state.read(cx), id);
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
    let view_state = state.clone();
    let handle: AnyWindowHandle = cx
        .open_window(options, |window, cx| {
            window.set_window_title(&title);
            theme::apply(window, cx);
            let view = cx.new(|cx| ItemWindow::new(view_state, id, title, window, cx));
            cx.new(|cx| Root::new(view, window, cx))
        })?
        .into();
    state.update(cx, |s, _| s.track_item_window(id, handle));
    Ok(handle)
}

/// The pinned item is live and has a TOTP field, so its code needs a re-render every
/// second (the item-window twin of `detail::shows_totp`).
fn pinned_totp(s: &AppState, id: Uuid) -> bool {
    s.main_active()
        && s.unlocked_vault()
            .and_then(|vault| vault.get(id))
            .filter(|item| !item.is_deleted())
            .is_some_and(|item| item.fields.iter().any(|f| f.kind == FieldKind::Totp))
}

struct ItemWindow {
    state: Entity<AppState>,
    id: Uuid,
    revealed: HashSet<String>,
    history_open: bool,
    status_clear: Option<gpui::Task<()>>,
    status: Option<String>,
    /// Re-renders every wall-clock second; only while the item has a TOTP field.
    ticker: Option<Task<()>>,
    /// The window title last set (the item's title, see [`window_title_for`]).
    title: String,
    _subscription: Subscription,
}

impl ItemWindow {
    fn new(
        state: Entity<AppState>,
        id: Uuid,
        title: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let subscription = cx.observe_in(&state, window, move |this, state, window, cx| {
            let s = state.read(cx);
            let exists = s
                .unlocked_vault()
                .and_then(|vault| vault.get(id))
                .is_some_and(|item| !item.is_deleted());
            if !s.main_active() || !exists {
                window.remove_window();
            } else {
                // A rename (here or merged from another device) retitles the window.
                let title = item_title(s, id);
                if title != this.title {
                    window.set_window_title(&title);
                    this.title = title;
                }
                this.sync_ticker(cx);
                cx.notify();
            }
        });
        let mut this = Self {
            state,
            id,
            revealed: HashSet::new(),
            history_open: false,
            status_clear: None,
            status: None,
            ticker: None,
            title,
            _subscription: subscription,
        };
        this.sync_ticker(cx);
        this
    }

    /// Starts or stops the one-second ticker as the item gains or loses a TOTP field.
    fn sync_ticker(&mut self, cx: &mut Context<Self>) {
        if !pinned_totp(self.state.read(cx), self.id) {
            self.ticker = None;
        } else if self.ticker.is_none() {
            self.ticker = Some(cx.spawn(async move |this, cx| {
                loop {
                    let to_next_second = 1000 - text::now_millis() % 1000;
                    cx.background_executor()
                        .timer(Duration::from_millis(to_next_second + 5))
                        .await;
                    if this.update(cx, |_, cx| cx.notify()).is_err() {
                        break;
                    }
                }
            }));
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gpui::TestAppContext;
    use vault_core::{Field, Item, KdfParams};
    use vault_sync::{NoopHooks, SyncedVault};

    use super::*;
    use crate::state::{ChooseIntent, Screen};

    const TOTP_URI: &str = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";

    /// An unlocked state with a plain item and an item with a TOTP field.
    fn setup(dir: &std::path::Path, cx: &mut TestAppContext) -> (Entity<AppState>, Uuid, Uuid) {
        let mut vault = SyncedVault::create(
            &dir.join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        let (plain, totp) = vault
            .edit(|v| {
                let mut plain = Item::new("Plain", device, 10);
                plain.fields.push(Field::new(
                    "password",
                    FieldKind::Password,
                    SecretString::new("hunter2".into()),
                    10,
                ));
                let mut totp = Item::new("With code", device, 10);
                totp.fields.push(Field::new(
                    "totp",
                    FieldKind::Totp,
                    SecretString::new(TOTP_URI.into()),
                    10,
                ));
                (v.insert(plain, 10), v.insert(totp, 10))
            })
            .unwrap();
        vault.save().unwrap();
        cx.update(gpui_component::init);
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
        (state, plain, totp)
    }

    fn open(state: &Entity<AppState>, id: Uuid, cx: &mut TestAppContext) -> AnyWindowHandle {
        let handle = cx
            .update(|cx| open_item_window(state.clone(), id, cx))
            .unwrap();
        cx.run_until_parked();
        handle
    }

    fn window_count(cx: &mut TestAppContext) -> usize {
        cx.update(|cx| cx.windows().len())
    }

    fn ticking(handle: AnyWindowHandle, cx: &mut TestAppContext) -> bool {
        let root = handle.downcast::<Root>().unwrap();
        cx.update(|cx| {
            let view = root.read(cx).unwrap().view().clone();
            view.downcast::<ItemWindow>()
                .unwrap()
                .read(cx)
                .ticker
                .is_some()
        })
    }

    /// The read-only attachment rows leave out the item's icon image.
    #[gpui::test]
    fn icon_blob_is_not_listed(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, plain, _) = setup(dir.path(), cx);
        state.update(cx, |s, _| {
            s.vault
                .as_mut()
                .unwrap()
                .edit(|v| {
                    let icon = vault_core::attachment::new_ref("icon.png", 900, 11).unwrap();
                    let scan = vault_core::attachment::new_ref("scan.pdf", 900, 11).unwrap();
                    let icon_id = icon.id;
                    v.add_attachment_ref(plain, icon, 11)?;
                    v.add_attachment_ref(plain, scan, 11)?;
                    v.update(plain, 12, |it| {
                        it.icon = Some(crate::icon::image_icon(icon_id))
                    })
                })
                .unwrap()
                .unwrap();
            s.vault_changed();
        });
        let handle = open(&state, plain, cx);
        let mut vcx = gpui::VisualTestContext::from_window(handle, cx);
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("reference-attachment scan.pdf").is_some());
        assert!(vcx.debug_bounds("reference-attachment icon.png").is_none());
    }

    fn title_of(handle: AnyWindowHandle, cx: &mut TestAppContext) -> Option<String> {
        gpui::VisualTestContext::from_window(handle, cx).window_title()
    }

    fn rename(state: &Entity<AppState>, id: Uuid, title: &str, cx: &mut TestAppContext) {
        let title = title.to_owned();
        state.update(cx, |s, cx| {
            s.vault
                .as_mut()
                .unwrap()
                .edit(|v| v.update(id, 20, move |it| it.title = title))
                .unwrap()
                .unwrap();
            s.vault_changed();
            cx.notify();
        });
        cx.run_until_parked();
    }

    #[gpui::test]
    fn title_follows_renames_live(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, plain, _) = setup(dir.path(), cx);
        let handle = open(&state, plain, cx);
        assert_eq!(title_of(handle, cx).as_deref(), Some("Plain"));
        rename(&state, plain, "  Bank of Mars \n login ", cx);
        assert_eq!(
            title_of(handle, cx).as_deref(),
            Some("Bank of Mars   login"),
            "trimmed, newline shown as a space"
        );
        // A huge title is cut to 120 characters, ellipsis included.
        rename(&state, plain, &"é".repeat(500), cx);
        let long = title_of(handle, cx).unwrap();
        assert_eq!(long.chars().count(), TITLE_MAX_CHARS);
        assert!(long.ends_with('\u{2026}'));
    }

    #[gpui::test]
    fn blank_title_shows_untitled(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, plain, _) = setup(dir.path(), cx);
        rename(&state, plain, "   ", cx);
        let handle = open(&state, plain, cx);
        assert_eq!(title_of(handle, cx).as_deref(), Some(UNTITLED));
        rename(&state, plain, "Back again", cx);
        assert_eq!(title_of(handle, cx).as_deref(), Some("Back again"));
        rename(&state, plain, "", cx);
        assert_eq!(title_of(handle, cx).as_deref(), Some(UNTITLED));
        assert_eq!(window_title_for("\t\n"), UNTITLED);
        assert_eq!(
            window_title_for(&"a".repeat(120)),
            "a".repeat(120),
            "120 fits"
        );
    }

    #[gpui::test]
    fn second_open_focuses_the_existing_window(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, plain, totp) = setup(dir.path(), cx);
        let first = open(&state, plain, cx);
        let other = open(&state, totp, cx);
        cx.update_window(other, |_, window, _| window.activate_window())
            .unwrap();
        assert_eq!(cx.update(|cx| cx.active_window()), Some(other));
        let before = window_count(cx);

        let again = open(&state, plain, cx);
        assert_eq!(again, first, "same window, not a new one");
        assert_eq!(window_count(cx), before);
        assert_eq!(
            cx.update(|cx| cx.active_window()),
            Some(first),
            "brought forward"
        );
        assert_eq!(state.read_with(cx, |s, _| s.item_windows.len()), 2);
        let title = gpui::VisualTestContext::from_window(first, cx).window_title();
        assert_eq!(
            title.as_deref(),
            Some("Plain"),
            "titled with the item's name"
        );

        // Closed by the user, then reopened: a fresh window, the dead handle forgotten.
        cx.update_window(first, |_, window, _| window.remove_window())
            .unwrap();
        cx.run_until_parked();
        let reopened = open(&state, plain, cx);
        assert_ne!(reopened, first);
        state.read_with(cx, |s, _| {
            assert_eq!(s.item_windows.len(), 2);
            assert!(!s.item_windows.iter().any(|(_, h)| *h == first));
        });
    }

    #[gpui::test]
    fn lock_closes_item_windows(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, plain, totp) = setup(dir.path(), cx);
        let before = window_count(cx);
        open(&state, plain, cx);
        open(&state, totp, cx);
        assert_eq!(window_count(cx), before + 2);
        state.update(cx, |s, cx| s.lock(cx));
        cx.run_until_parked();
        assert_eq!(window_count(cx), before);
        assert!(state.read_with(cx, |s, _| s.item_windows.is_empty()));
    }

    #[gpui::test]
    fn vault_switch_closes_item_windows(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, plain, _) = setup(dir.path(), cx);
        let before = window_count(cx);
        open(&state, plain, cx);
        state.update(cx, |s, cx| s.switch_vault(ChooseIntent::Home, cx));
        cx.run_until_parked();
        assert_eq!(state.read_with(cx, |s, _| s.screen), Screen::Choose);
        assert_eq!(window_count(cx), before);
        assert!(state.read_with(cx, |s, _| s.item_windows.is_empty()));
    }

    #[gpui::test]
    fn deleting_the_item_closes_its_window(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, plain, totp) = setup(dir.path(), cx);
        let before = window_count(cx);
        let doomed = open(&state, plain, cx);
        open(&state, totp, cx);
        state.update(cx, |s, cx| {
            s.select(plain, cx);
            s.request_delete(cx);
            s.confirm_delete(cx);
        });
        cx.run_until_parked();
        assert!(state.read_with(cx, |s, _| {
            s.unlocked_vault().unwrap().get(plain).unwrap().is_deleted()
        }));
        assert_eq!(
            window_count(cx),
            before + 1,
            "only the deleted item's window"
        );
        assert!(!cx.update(|cx| cx.windows().contains(&doomed)));
        assert_eq!(
            state.update(cx, |s, cx| s.item_window(plain, cx)),
            None,
            "its handle is pruned"
        );
    }

    #[gpui::test]
    fn ticker_runs_only_with_a_totp_field(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, plain, totp) = setup(dir.path(), cx);
        let plain_window = open(&state, plain, cx);
        let totp_window = open(&state, totp, cx);
        assert!(!ticking(plain_window, cx), "no TOTP, no ticker");
        assert!(ticking(totp_window, cx));
    }
}
