//! Actions, keymap, menu bar and global handlers (specs/05-ui.md §4).
//!
//! Handlers are registered on the app, not on views: gpui dispatches to the root node
//! when nothing is focused, so a view-level handler could miss a menu click. Each
//! handler mutates `AppState`; focus moves go through `AppState::request_focus`, which
//! the main screen applies.

use gpui::{
    Action, App, Context, Entity, KeyBinding, Menu, MenuItem, OsAction, WeakEntity, actions,
};
use gpui_component::input;

use crate::root::VaultRoot;
use crate::state::{AppState, ChooseIntent, CopyTarget, FocusTarget, GeneratorTarget, Sort};

actions!(
    vault,
    [
        /// ⌘L: lock the vault.
        Lock,
        /// ⌘O: back to the choose-vault screen.
        OpenVault,
        /// File ▸ New Vault.
        NewVault,
        /// ⌘,: settings sheet.
        OpenSettings,
        /// App ▸ About.
        About,
        /// ⌘Q.
        Quit,
        /// ⌘W: close the active window; lock first when closing the vault window.
        CloseWindow,
        /// ⌘F: focus the search field.
        Search,
        /// ⌘N: new item (Templates menu).
        NewItem,
        /// ⌘E: edit the selected item.
        EditItem,
        /// ⌘S: save the edit.
        SaveItem,
        /// Esc in the detail column: cancel the edit or dismiss an inline confirm.
        CancelEdit,
        /// ⌘C on a focused row, ⌘⇧U anywhere.
        CopyUsername,
        /// ⌘⇧C.
        CopyPassword,
        /// ⌘⇧T.
        CopyTotp,
        /// ⌘⇧R.
        RevealPassword,
        /// ⌘⇧O.
        OpenUrl,
        /// ⌘D.
        ToggleFavorite,
        /// ⌘⌫: inline confirm, then delete (in Recently Deleted: delete permanently).
        DeleteItem,
        /// ⌘⇧Z in Recently Deleted: recover the trashed item.
        RecoverItem,
        /// ⌘G: password generator popover.
        Generator,
        /// ⌃⌘S, View ▸ Hide Sidebar / Show Sidebar.
        ToggleSidebar,
        /// ↓ in the list.
        NextItem,
        /// ↑ in the list.
        PrevItem,
        /// ⌘1.
        FocusList,
        /// ⌘2, and ⏎ in the list.
        FocusDetail,
        /// View ▸ Sort By ▸ Name.
        SortAlphabetical,
        /// View ▸ Sort By ▸ Recently Modified.
        SortRecentlyModified,
        /// ⌘M.
        Minimize,
        /// Window ▸ Zoom.
        Zoom,
        /// Help ▸ Vault Help (placeholder).
        ShowHelp,
        /// File ▸ Import CSV…: CSV via the open panel.
        Import,
        /// File ▸ Import 1Password (1PUX)…: a `.1pux` export via the open panel.
        Import1Pux,
        /// File ▸ Import KeePass (KDBX)…
        ImportKdbx,
        /// File ▸ Export…: Settings ▸ Import / Export with the red confirm showing.
        Export,
    ]
);

/// ⌃⌘S, as in Finder and Passwords.
pub const TOGGLE_SIDEBAR_KEYS: &str = "ctrl-cmd-s";

/// View menu title of [`ToggleSidebar`] for the current sidebar state.
pub fn sidebar_menu_title(sidebar_visible: bool) -> &'static str {
    if sidebar_visible {
        "Hide Sidebar"
    } else {
        "Show Sidebar"
    }
}

/// Key context of the focused item list (↑/↓/⏎/⌘C).
pub const LIST_CONTEXT: &str = "ItemList";
/// Key context of the focused detail column (Esc).
pub const DETAIL_CONTEXT: &str = "ItemDetail";

pub fn bind_keys(cx: &mut App) {
    let list = Some(LIST_CONTEXT);
    crate::screens::icon_view::bind_keys(cx);
    cx.bind_keys([
        KeyBinding::new("cmd-l", Lock, None),
        KeyBinding::new("cmd-o", OpenVault, None),
        KeyBinding::new("cmd-,", OpenSettings, None),
        KeyBinding::new("cmd-q", Quit, None),
        KeyBinding::new("cmd-w", CloseWindow, None),
        KeyBinding::new("cmd-f", Search, None),
        KeyBinding::new("cmd-n", NewItem, None),
        KeyBinding::new("cmd-e", EditItem, None),
        KeyBinding::new("cmd-s", SaveItem, None),
        KeyBinding::new("escape", CancelEdit, Some(DETAIL_CONTEXT)),
        KeyBinding::new("cmd-c", CopyUsername, list),
        KeyBinding::new("cmd-shift-u", CopyUsername, None),
        KeyBinding::new("cmd-shift-c", CopyPassword, None),
        KeyBinding::new("cmd-shift-t", CopyTotp, None),
        KeyBinding::new("cmd-shift-r", RevealPassword, None),
        KeyBinding::new("cmd-shift-o", OpenUrl, None),
        KeyBinding::new("cmd-d", ToggleFavorite, None),
        KeyBinding::new("cmd-backspace", DeleteItem, None),
        KeyBinding::new("cmd-shift-z", RecoverItem, None),
        KeyBinding::new("cmd-g", Generator, None),
        KeyBinding::new(TOGGLE_SIDEBAR_KEYS, ToggleSidebar, None),
        KeyBinding::new("down", NextItem, list),
        KeyBinding::new("up", PrevItem, list),
        KeyBinding::new("enter", FocusDetail, list),
        KeyBinding::new("cmd-1", FocusList, None),
        KeyBinding::new("cmd-2", FocusDetail, None),
        KeyBinding::new("cmd-m", Minimize, None),
    ]);
}

/// Installs the menu bar from the state's sort and sidebar visibility.
pub fn refresh_menus(s: &AppState, cx: &mut App) {
    install_menus(s.sort, s.sidebar_visible(), s.viewing_trash(), cx);
}

/// Installs the menu bar. Called again when the sort changes, to move the checkmark, and
/// when the sidebar toggles, to flip "Hide Sidebar" / "Show Sidebar".
pub fn set_menus(sort: Sort, sidebar_visible: bool, cx: &mut App) {
    install_menus(sort, sidebar_visible, false, cx);
}

/// The Item menu's delete rows. In Recently Deleted (`trash`) ⌘⌫ deletes permanently and
/// Recover joins it; elsewhere Recover is absent. Absent rather than disabled: the macOS
/// menu enables an item whenever its action has a handler (`validateMenuItem:`), so
/// `MenuItem::disabled` does not stick for globally handled actions.
fn delete_items(trash: bool) -> Vec<MenuItem> {
    if trash {
        vec![
            MenuItem::action("Recover", RecoverItem),
            MenuItem::action("Delete Permanently\u{2026}", DeleteItem),
        ]
    } else {
        vec![MenuItem::action("Delete\u{2026}", DeleteItem)]
    }
}

/// [`set_menus`] with the Recently Deleted rows when `trash`.
fn install_menus(sort: Sort, sidebar_visible: bool, trash: bool, cx: &mut App) {
    cx.set_menus([
        Menu::new("Vault").items([
            MenuItem::action("About Vault", About),
            MenuItem::separator(),
            MenuItem::action("Settings…", OpenSettings),
            MenuItem::separator(),
            MenuItem::action("Quit Vault", Quit),
        ]),
        Menu::new("File").items([
            MenuItem::action("New Vault…", NewVault),
            MenuItem::action("Open Vault…", OpenVault),
            MenuItem::action("Close Window", CloseWindow),
            MenuItem::separator(),
            MenuItem::action("Import CSV\u{2026}", Import),
            MenuItem::action("Import 1Password (1PUX)\u{2026}", Import1Pux),
            MenuItem::action("Import KeePass (KDBX)…", ImportKdbx),
            MenuItem::action("Export…", Export),
            MenuItem::separator(),
            MenuItem::action("Lock", Lock),
        ]),
        Menu::new("Edit").items([
            MenuItem::os_action("Undo", input::Undo, OsAction::Undo),
            MenuItem::os_action("Redo", input::Redo, OsAction::Redo),
            MenuItem::separator(),
            MenuItem::os_action("Cut", input::Cut, OsAction::Cut),
            MenuItem::os_action("Copy", input::Copy, OsAction::Copy),
            MenuItem::os_action("Paste", input::Paste, OsAction::Paste),
            MenuItem::os_action("Select All", input::SelectAll, OsAction::SelectAll),
            MenuItem::separator(),
            MenuItem::action("Find", Search),
        ]),
        Menu::new("Item").items(
            [
                MenuItem::action("New Item", NewItem),
                MenuItem::action("Edit", EditItem),
                MenuItem::action("Save", SaveItem),
                MenuItem::action("Cancel Edit", CancelEdit),
                MenuItem::separator(),
                MenuItem::action("Next Item", NextItem),
                MenuItem::action("Previous Item", PrevItem),
                MenuItem::separator(),
                MenuItem::action("Copy Username", CopyUsername),
                MenuItem::action("Copy Password", CopyPassword),
                MenuItem::action("Copy One-Time Code", CopyTotp),
                MenuItem::action("Reveal Password", RevealPassword),
                MenuItem::action("Open Website", OpenUrl),
                MenuItem::separator(),
                MenuItem::action("Favorite", ToggleFavorite),
            ]
            .into_iter()
            .chain(delete_items(trash))
            .chain([
                MenuItem::separator(),
                MenuItem::action("Password Generator", Generator),
            ]),
        ),
        Menu::new("View").items([
            MenuItem::submenu(
                Menu::new("Sort By").items([
                    MenuItem::action("Name", SortAlphabetical).checked(sort == Sort::Alphabetical),
                    MenuItem::action("Recently Modified", SortRecentlyModified)
                        .checked(sort == Sort::RecentlyModified),
                ]),
            ),
            MenuItem::separator(),
            MenuItem::action(sidebar_menu_title(sidebar_visible), ToggleSidebar),
            MenuItem::action("Item List", FocusList),
            MenuItem::action("Item Details", FocusDetail),
        ]),
        Menu::new("Window").items([
            MenuItem::action("Minimize", Minimize),
            MenuItem::action("Zoom", Zoom),
        ]),
        Menu::new("Help").items([MenuItem::action("Vault Help", ShowHelp)]),
    ]);
}

/// The main window's id and view. Item shortcuts act on the live vault only from this window.
pub struct MainWindow(pub gpui::WindowId, pub WeakEntity<VaultRoot>);

impl gpui::Global for MainWindow {}

/// Whether item actions may run: the main window (or no window) is active. In the
/// backup viewer, ⌘D, ⌘⇧C, ⌘E, ↑/↓... would otherwise act on the live vault.
pub fn in_main_window(cx: &App) -> bool {
    match (cx.active_window(), cx.try_global::<MainWindow>()) {
        (Some(active), Some(main)) => active.window_id() == main.0,
        _ => true,
    }
}

/// Like [`on`], but a no-op unless the main window is active.
fn on_main<A: Action>(
    state: &Entity<AppState>,
    cx: &mut App,
    f: impl Fn(&mut AppState, &mut Context<AppState>) + 'static,
) {
    let state = state.clone();
    cx.on_action(move |_: &A, cx| {
        if in_main_window(cx) {
            state.update(cx, |s, cx| f(s, cx));
        }
    });
}

/// Registers `f` as the global handler of action `A`.
fn on<A: Action>(
    state: &Entity<AppState>,
    cx: &mut App,
    f: impl Fn(&mut AppState, &mut Context<AppState>) + 'static,
) {
    let state = state.clone();
    cx.on_action(move |_: &A, cx| state.update(cx, |s, cx| f(s, cx)));
}

fn sort_by(sort: Sort) -> impl Fn(&mut AppState, &mut Context<AppState>) {
    move |s, cx| {
        s.set_sort(sort, cx);
        refresh_menus(s, cx);
    }
}

/// Global action handlers. Each runs when no focused element handled the action.
pub fn register(state: &Entity<AppState>, cx: &mut App) {
    on::<Lock>(state, cx, |s, cx| s.lock(cx));
    on::<OpenVault>(state, cx, |s, cx| s.switch_vault(ChooseIntent::Home, cx));
    on::<NewVault>(state, cx, |s, cx| s.switch_vault(ChooseIntent::Create, cx));
    on::<OpenSettings>(state, cx, |s, cx| s.open_settings(true, cx));
    on::<About>(state, cx, |s, cx| {
        s.show_toast(format!("Vault {}", env!("CARGO_PKG_VERSION")), cx);
    });
    on::<ShowHelp>(state, cx, |s, cx| {
        s.show_toast("Help is not available yet", cx)
    });
    on::<Import>(state, cx, |s, cx| s.choose_import_path(cx));
    on::<Import1Pux>(state, cx, |s, cx| s.choose_import_1pux(cx));
    on::<ImportKdbx>(state, cx, |s, cx| s.choose_import_kdbx(cx));
    on::<Export>(state, cx, |s, cx| s.request_export(cx));
    cx.on_action(|_: &Quit, cx| cx.quit());
    let close_state = state.clone();
    cx.on_action(move |_: &CloseWindow, cx| {
        let Some(handle) = cx.active_window() else {
            return;
        };
        let main = cx
            .try_global::<MainWindow>()
            .map(|main| (main.0, main.1.clone()));
        let state = close_state.clone();
        // Actions run inside the active window's dispatch. Defer the update until
        // that window is available again, as for Minimize and Zoom.
        cx.defer(move |cx| {
            handle
                .update(cx, |_, window, cx| {
                    if let Some((id, root)) = &main
                        && handle.window_id() == *id
                        && root
                            .update(cx, |root, cx| root.prepare_to_close(window, cx))
                            .is_err()
                    {
                        state.update(cx, |s, cx| s.lock(cx));
                    }
                    window.remove_window();
                })
                .ok();
        });
    });

    on_main::<Search>(state, cx, |s, cx| s.request_focus(FocusTarget::Search, cx));
    on_main::<FocusList>(state, cx, |s, cx| s.request_focus(FocusTarget::List, cx));
    on_main::<FocusDetail>(state, cx, |s, cx| s.request_focus(FocusTarget::Detail, cx));
    on_main::<NextItem>(state, cx, |s, cx| s.select_offset(1, cx));
    on_main::<PrevItem>(state, cx, |s, cx| s.select_offset(-1, cx));
    on_main::<ToggleSidebar>(state, cx, |s, cx| {
        s.toggle_sidebar(cx);
        refresh_menus(s, cx);
    });
    on_main::<SortAlphabetical>(state, cx, sort_by(Sort::Alphabetical));
    on_main::<SortRecentlyModified>(state, cx, sort_by(Sort::RecentlyModified));

    on_main::<CopyUsername>(state, cx, |s, cx| s.copy(CopyTarget::Username, cx));
    on_main::<CopyPassword>(state, cx, |s, cx| s.copy(CopyTarget::Password, cx));
    on_main::<CopyTotp>(state, cx, |s, cx| s.copy(CopyTarget::Totp, cx));
    on_main::<RevealPassword>(state, cx, |s, cx| s.toggle_reveal_password(cx));
    on_main::<OpenUrl>(state, cx, |s, cx| s.open_url(None, cx));
    on_main::<ToggleFavorite>(state, cx, |s, cx| s.toggle_favorite(cx));

    on_main::<NewItem>(state, cx, |s, cx| s.open_template_picker(String::new(), cx));
    on_main::<EditItem>(state, cx, |s, cx| s.begin_edit(cx));
    on_main::<SaveItem>(state, cx, |s, cx| s.save_edit(cx));
    on_main::<CancelEdit>(state, cx, |s, cx| s.cancel_edit(cx));
    on_main::<DeleteItem>(state, cx, |s, cx| s.request_delete(cx));
    on_main::<RecoverItem>(state, cx, |s, cx| s.recover_selected(cx));
    on_main::<Generator>(state, cx, |s, cx| {
        s.open_generator(GeneratorTarget::Global, cx)
    });

    cx.on_action(|_: &Minimize, cx| on_active_window(cx, WindowCommand::Minimize));
    cx.on_action(|_: &Zoom, cx| on_active_window(cx, WindowCommand::Zoom));
}

/// A platform command on the active window (Window menu, ⌘M).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowCommand {
    Minimize,
    Zoom,
}

#[cfg(test)]
thread_local! {
    /// Commands that reached a window (the test platform cannot minimize or zoom).
    pub static WINDOW_COMMANDS: std::cell::RefCell<Vec<WindowCommand>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Runs `command` on the active window once the current dispatch ends. Global action
/// handlers run inside the window's own update (keystrokes and menu items are both
/// dispatched through `Window::dispatch_action`), where that window is checked out of
/// the app: updating it again from here fails with "window not found", so the update
/// must be deferred.
fn on_active_window(cx: &mut App, command: WindowCommand) {
    let Some(handle) = cx.active_window() else {
        return;
    };
    cx.defer(move |cx| {
        handle
            .update(cx, |_, window, _| {
                #[cfg(test)]
                {
                    let _ = window;
                    WINDOW_COMMANDS.with(|c| c.borrow_mut().push(command));
                }
                #[cfg(not(test))]
                match command {
                    WindowCommand::Minimize => window.minimize_window(),
                    WindowCommand::Zoom => window.zoom_window(),
                }
            })
            .ok();
    });
}
