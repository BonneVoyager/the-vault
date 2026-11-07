//! A movable, item-pinned detail window (specs/05-ui.md §2.3). It reads the live vault by
//! ID so a selection change in the main window cannot change its contents. One window per
//! item, tracked in `AppState`: it closes on lock and vault switch (`AppState::lock`) and
//! when its item is deleted (its own observer).

use std::collections::HashSet;
use std::time::Duration;

use gpui::{
    AnyWindowHandle, App, AppContext as _, Bounds, Context, Entity, FocusHandle,
    InteractiveElement as _, IntoElement, ParentElement as _, Render, Styled as _, Subscription,
    Task, TitlebarOptions, Window, WindowBounds, WindowOptions, div, prelude::FluentBuilder as _,
    px, size,
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
    // Its focus-ring entry goes when it closes (any close path).
    ui::forget_closed_windows(cx);
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
    revealed: HashSet<Uuid>,
    history_open: bool,
    status_clear: Option<gpui::Task<()>>,
    status: Option<String>,
    /// Re-renders every wall-clock second; only while the item has a TOTP field.
    ticker: Option<Task<()>>,
    /// The window title last set (the item's title, see [`window_title_for`]).
    title: String,
    /// Hold ⌥ to reveal, for this window only (05 §2.3): set while ⌥ alone is held
    /// and this window is key. Separate from `AppState::option_reveal` so the main
    /// window's detail never reveals along with it.
    option_reveal: bool,
    /// Tracked on the window's root so ⌥ changes reach it (they follow the focus
    /// path) and a focus move into an overlay ends the reveal.
    focus: FocusHandle,
    _subscriptions: Vec<Subscription>,
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
                // Lock, vault switch, or the item gone. The window is about to go, so
                // this is defensive: it matters only if something still holds the view
                // after the close (the tests do).
                this.option_reveal = false;
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
        let focus = cx.focus_handle();
        window.focus(&focus, cx);
        let subscriptions = vec![
            subscription,
            // A key-up while another window is key never reaches this one: drop the
            // hold-⌥ reveal when it loses key status.
            cx.observe_window_activation(window, |this, window, cx| {
                if !window.is_window_active() {
                    this.set_option_reveal(false, cx);
                }
            }),
            // Focus moved outside the window's view (an overlay under Root): its ⌥ key-up
            // would miss our listener.
            cx.on_focus_out(&focus, window, |this: &mut Self, _, _, cx| {
                this.set_option_reveal(false, cx);
            }),
        ];
        let mut this = Self {
            state,
            id,
            revealed: HashSet::new(),
            history_open: false,
            status_clear: None,
            status: None,
            ticker: None,
            title,
            option_reveal: false,
            focus,
            _subscriptions: subscriptions,
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

    /// Follows ⌥ in this window; re-renders only when the flag flips. Never touches
    /// `revealed`.
    fn set_option_reveal(&mut self, held: bool, cx: &mut Context<Self>) {
        if self.option_reveal != held {
            self.option_reveal = held;
            cx.notify();
        }
    }

    fn act(&mut self, action: DetailAction, cx: &mut Context<Self>) {
        match action {
            DetailAction::Reveal(field) => {
                if !self.revealed.remove(&field) {
                    self.revealed.insert(field);
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
                CopyTarget::Field(field) => {
                    item.field_by_id(field).and_then(|field| match field.kind {
                        FieldKind::Totp => parse_totp(&field.value)
                            .map(|totp| SecretString::new(totp.code(text::now_millis() / 1000))),
                        // A heading has nothing to copy; its stored value never leaves the
                        // vault (a stale index or a crafted vault must not reach it).
                        FieldKind::Section => None,
                        _ => Some(field.value.clone()),
                    })
                }
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
        // Focus rings follow keyboard focus moves only (`ui::update_focus_ring`).
        ui::update_focus_ring(window, cx);
        // ⌥ follows the focus path, so focus pointing at nothing (a clicked control
        // that stopped being drawn, a closed overlay) would silence the hold-⌥ reveal.
        if window.is_window_active() && window.focused(cx).is_none() {
            window.focus(&self.focus, cx);
        }
        let weak = cx.entity().downgrade();
        let actions = DetailActions(std::rc::Rc::new(move |action, cx| {
            weak.update(cx, |this, cx| this.act(action, cx)).ok();
        }));
        // Also checked against the live modifiers, key status and focus, so a key-up
        // that went elsewhere cannot leave values revealed.
        let peek = self.option_reveal
            && ui::option_alone(&window.modifiers())
            && window.is_window_active()
            && self.focus.contains_focused(window, cx);
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
                    peek,
                }
                .render_item(item, s, cx)
            });
        ui::clear_focus_ring_on_click(div())
            .id("item-window")
            .debug_selector(|| "item-window".into())
            .track_focus(&self.focus)
            // Hold ⌥ to reveal (05 §2.3), this window only.
            .on_modifiers_changed(
                cx.listener(|this, ev: &gpui::ModifiersChangedEvent, _, cx| {
                    this.set_option_reveal(ui::option_alone(&ev.modifiers), cx);
                }),
            )
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

    /// The item window's copy-by-index skips a section, even with a planted value.
    #[gpui::test]
    fn copying_a_section_by_index_copies_nothing(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, plain, _) = setup(dir.path(), cx);
        let board = crate::clipboard::fake::FakePasteboard::default();
        state.update(cx, |s, _| {
            s.set_pasteboard(Box::new(board.clone()));
            s.vault
                .as_mut()
                .unwrap()
                .edit(|v| {
                    v.update(plain, 20, |it| {
                        it.fields.insert(
                            0,
                            Field::new(
                                "Username",
                                FieldKind::Section,
                                SecretString::new("SHOULD-NOT-SHOW".into()),
                                20,
                            ),
                        );
                    })
                })
                .unwrap()
                .unwrap();
            s.vault_changed();
        });
        let handle = open(&state, plain, cx);
        let root = handle.downcast::<Root>().unwrap();
        cx.update(|cx| {
            let view = root.read(cx).unwrap().view().clone();
            let window = view.downcast::<ItemWindow>().unwrap();
            let section = state
                .read(cx)
                .unlocked_vault()
                .unwrap()
                .get(plain)
                .unwrap()
                .fields[0]
                .id;
            window.update(cx, |w, cx| w.copy(CopyTarget::Field(section), cx));
        });
        cx.run_until_parked();
        assert_eq!(
            board.contents(),
            None,
            "the planted value never reaches the pasteboard"
        );
        // The field after it still copies normally.
        cx.update(|cx| {
            let view = root.read(cx).unwrap().view().clone();
            let window = view.downcast::<ItemWindow>().unwrap();
            let next = state
                .read(cx)
                .unlocked_vault()
                .unwrap()
                .get(plain)
                .unwrap()
                .fields[1]
                .id;
            window.update(cx, |w, cx| w.copy(CopyTarget::Field(next), cx));
        });
        cx.run_until_parked();
        assert_eq!(board.contents().as_deref(), Some("hunter2"));
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

    fn option() -> gpui::Modifiers {
        gpui::Modifiers {
            alt: true,
            ..Default::default()
        }
    }

    fn hold(mods: gpui::Modifiers, vcx: &mut gpui::VisualTestContext) {
        vcx.simulate_modifiers_change(mods);
        vcx.run_until_parked();
    }

    fn shown(key: &'static str, vcx: &mut gpui::VisualTestContext) -> bool {
        vcx.debug_bounds(key).is_some()
    }

    fn option_flag(handle: AnyWindowHandle, cx: &mut TestAppContext) -> bool {
        let root = handle.downcast::<Root>().unwrap();
        cx.update(|cx| {
            let view = root.read(cx).unwrap().view().clone();
            view.downcast::<ItemWindow>()
                .unwrap()
                .read(cx)
                .option_reveal
        })
    }

    /// The main window over `state`, showing `id` in its detail column.
    fn main_window(
        state: &Entity<AppState>,
        id: Uuid,
        cx: &mut TestAppContext,
    ) -> gpui::VisualTestContext {
        let mut main = None;
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view =
                cx.new(|cx| super::super::main::MainScreen::new(state.clone(), None, window, cx));
            main = Some(view.clone());
            Root::new(view, window, cx)
        });
        let mut vcx = gpui::VisualTestContext::from_window(window.into(), cx);
        let main = main.unwrap();
        vcx.update(|window, cx| main.update(cx, |m, cx| m.appear(window, cx)));
        state.update(&mut vcx, |s, cx| s.select(id, cx));
        vcx.run_until_parked();
        vcx
    }

    /// The item window's password row and the main detail's, as (item, main) plain.
    fn plain_rows(
        item: &mut gpui::VisualTestContext,
        main: &mut gpui::VisualTestContext,
    ) -> (bool, bool) {
        let item_plain = shown("field-plain 0", item);
        assert_ne!(item_plain, shown("field-masked 0", item));
        let main_plain = shown("field-plain 0", main);
        assert_ne!(main_plain, shown("field-masked 0", main));
        (item_plain, main_plain)
    }

    /// 05 §2.3 hold ⌥ in an item window: its own rows reveal while it is key and ⌥ is
    /// held; the main window's detail of the same item stays masked; release re-masks.
    #[gpui::test]
    fn option_held_reveals_only_the_key_item_window(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, plain, _) = setup(dir.path(), cx);
        let mut main = main_window(&state, plain, cx);
        let handle = open(&state, plain, cx);
        let mut item = gpui::VisualTestContext::from_window(handle, cx);
        item.update(|window, _| window.activate_window());
        item.run_until_parked();
        assert_eq!(plain_rows(&mut item, &mut main), (false, false));

        hold(option(), &mut item);
        assert!(option_flag(handle, cx));
        assert_eq!(
            plain_rows(&mut item, &mut main),
            (true, false),
            "only the key item window reveals"
        );
        assert!(
            !state.read_with(cx, |s, _| s.option_reveal),
            "global flag untouched"
        );
        assert!(state.read_with(cx, |s, _| s.revealed.is_empty()));

        hold(gpui::Modifiers::none(), &mut item);
        assert_eq!(plain_rows(&mut item, &mut main), (false, false), "release");

        // ⌥ in a chord does not reveal.
        hold(
            gpui::Modifiers {
                alt: true,
                platform: true,
                ..Default::default()
            },
            &mut item,
        );
        assert_eq!(plain_rows(&mut item, &mut main), (false, false));
    }

    /// The item window losing key status ends its reveal; so does a ⌥ the window never
    /// heard (inactive window).
    #[gpui::test]
    fn option_reveal_in_item_window_clears_on_blur(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, plain, _) = setup(dir.path(), cx);
        let mut main = main_window(&state, plain, cx);
        let handle = open(&state, plain, cx);
        let mut item = gpui::VisualTestContext::from_window(handle, cx);
        item.update(|window, _| window.activate_window());
        item.run_until_parked();

        hold(option(), &mut item);
        assert_eq!(plain_rows(&mut item, &mut main), (true, false));
        item.deactivate_window();
        item.run_until_parked();
        assert!(!option_flag(handle, cx), "blur clears the flag");
        assert_eq!(plain_rows(&mut item, &mut main), (false, false));

        // Main window key with ⌥ held: the main detail reveals, the item window not.
        hold(gpui::Modifiers::none(), &mut item);
        main.update(|window, _| window.activate_window());
        main.run_until_parked();
        hold(option(), &mut main);
        assert_eq!(plain_rows(&mut item, &mut main), (false, true));
        // Switching key to the item window drops the main window's reveal.
        item.update(|window, _| window.activate_window());
        item.run_until_parked();
        assert!(!state.read_with(cx, |s, _| s.option_reveal));
        assert_eq!(plain_rows(&mut item, &mut main), (false, false));
    }

    /// Lock while ⌥ is held: the window closes as before, nothing stays revealed.
    #[gpui::test]
    fn option_reveal_in_item_window_ends_on_lock(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, plain, _) = setup(dir.path(), cx);
        let handle = open(&state, plain, cx);
        let mut item = gpui::VisualTestContext::from_window(handle, cx);
        item.update(|window, _| window.activate_window());
        item.run_until_parked();
        hold(option(), &mut item);
        assert!(option_flag(handle, cx));
        assert!(shown("field-plain 0", &mut item));

        state.update(cx, |s, cx| s.lock(cx));
        cx.run_until_parked();
        assert!(!cx.update(|cx| cx.windows().contains(&handle)), "closed");
        assert!(state.read_with(cx, |s, _| s.item_windows.is_empty()));
    }

    fn item_view(handle: AnyWindowHandle, cx: &mut TestAppContext) -> Entity<ItemWindow> {
        let root = handle.downcast::<Root>().unwrap();
        cx.update(|cx| {
            let view = root.read(cx).unwrap().view().clone();
            view.downcast::<ItemWindow>().unwrap()
        })
    }

    /// Focus moving into an overlay under Root (outside the view) ends the reveal, and
    /// once focus points at nothing the window takes it back, so ⌥ works again.
    #[gpui::test]
    fn option_reveal_in_item_window_clears_when_focus_leaves(cx: &mut TestAppContext) {
        use gpui_component::WindowExt as _;
        let dir = tempfile::tempdir().unwrap();
        let (state, plain, _) = setup(dir.path(), cx);
        let handle = open(&state, plain, cx);
        let mut item = gpui::VisualTestContext::from_window(handle, cx);
        item.update(|window, _| window.activate_window());
        item.run_until_parked();
        hold(option(), &mut item);
        assert!(shown("field-plain 0", &mut item));

        let overlay = item.update(|window, cx| {
            let focus = cx.focus_handle();
            let inner = focus.clone();
            window.open_dialog(cx, move |dialog, _, _| {
                dialog
                    .title("Overlay")
                    .child(div().track_focus(&inner).child("overlay"))
            });
            focus
        });
        item.run_until_parked();
        item.update(|window, cx| window.focus(&overlay, cx));
        item.run_until_parked();
        assert!(item.update(|window, _| overlay.is_focused(window)));
        assert!(!option_flag(handle, cx), "focus left the view");
        assert!(shown("field-masked 0", &mut item));
        assert!(!shown("field-plain 0", &mut item));

        // Focus pointing at nothing: the window refocuses its root on the next frame.
        hold(gpui::Modifiers::none(), &mut item);
        item.update(|window, cx| {
            window.close_all_dialogs(cx);
            window.blur(cx);
        });
        item.run_until_parked();
        let focus = item_view(handle, cx).read_with(cx, |v, _| v.focus.clone());
        assert!(
            item.update(|window, _| focus.is_focused(window)),
            "refocused"
        );
        hold(option(), &mut item);
        assert!(shown("field-plain 0", &mut item), "⌥ works again");
    }

    /// Soft-deleting the item while ⌥ is held clears the flag and closes the window.
    #[gpui::test]
    fn option_reveal_in_item_window_ends_on_delete(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, plain, _) = setup(dir.path(), cx);
        let handle = open(&state, plain, cx);
        let view = item_view(handle, cx);
        let mut item = gpui::VisualTestContext::from_window(handle, cx);
        item.update(|window, _| window.activate_window());
        item.run_until_parked();
        hold(option(), &mut item);
        assert!(view.read_with(cx, |v, _| v.option_reveal));

        state.update(cx, |s, cx| {
            s.select(plain, cx);
            s.request_delete(cx);
            s.confirm_delete(cx);
        });
        cx.run_until_parked();
        assert!(state.read_with(cx, |s, _| {
            s.unlocked_vault().unwrap().get(plain).unwrap().is_deleted()
        }));
        assert!(!cx.update(|cx| cx.windows().contains(&handle)), "closed");
        assert!(!view.read_with(cx, |v, _| v.option_reveal), "flag cleared");
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
