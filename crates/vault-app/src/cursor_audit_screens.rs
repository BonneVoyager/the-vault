use std::path::{Path, PathBuf};
use std::sync::Arc;

use gpui::{AppContext as _, Entity, TestAppContext, VisualTestContext, px, size};
use gpui_component::Root;
use vault_core::{Field, FieldKind, Item, KdfParams, SecretString, Uuid};
use vault_sync::{NoopHooks, SyncedVault};

use super::{Case, audit, install};
use crate::root::VaultRoot;
use crate::state::{AppState, ChooseIntent, GenTab, GeneratorTarget};
use crate::{actions, theme};

const PW: &str = "pw";

/// A 1x1 PNG.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0xf0,
    0x1f, 0x00, 0x05, 0x00, 0x01, 0xff, 0x89, 0x99, 0x3d, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
    0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

fn field(name: &str, kind: FieldKind, value: &str) -> Field {
    Field::new(name, kind, SecretString::new(value.into()), 1)
}

/// A saved vault with a login carrying every field kind, password history and tags,
/// plus a card. Returns the login's id.
fn vault(dir: &Path) -> (SyncedVault, Uuid) {
    let mut v = SyncedVault::create(
        &dir.join("t.vault"),
        &SecretString::new(PW.into()),
        KdfParams::for_tests(),
        Uuid::new_v4(),
        Arc::new(NoopHooks),
    )
    .unwrap();
    let device = v.device_id();
    let id = v
        .edit(|v| {
            let mut gh = Item::new("GitHub", device, 1);
            gh.tags = vec!["infra".into(), "work".into()];
            gh.fields = vec![
                field("username", FieldKind::Text, "chris"),
                field("password", FieldKind::Password, "old"),
                field(
                    "totp",
                    FieldKind::Totp,
                    "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
                ),
                field("website", FieldKind::Url, "github.com"),
                field("email", FieldKind::Email, "c@example.com"),
                field("born", FieldKind::Date, "2000-01-01"),
                field("expiry", FieldKind::MonthYear, "12/29"),
                // A removed `number` field now loads as an unknown kind (masked).
                {
                    let mut pin = field("pin", FieldKind::Other, "1234");
                    pin.kind_raw = Some("number".into());
                    pin
                },
                field("notes", FieldKind::Notes, "line one\nline two"),
            ];
            let id = v.insert(gh, 1);
            v.set_field_named(id, "password", SecretString::new("new".into()), 2)
                .unwrap();
            v.insert(
                crate::templates::tagged(crate::templates::Template::Card, "Visa", device, 3),
                3,
            );
            id
        })
        .unwrap();
    v.save().unwrap();
    (v, id)
}

/// The app's root view in a `width` x `height` window, with the inspector hooks.
fn app(
    recent: Vec<PathBuf>,
    height: f32,
    cx: &mut TestAppContext,
) -> (Entity<AppState>, VisualTestContext) {
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), recent, false));
    cx.update(|cx| {
        gpui_component::init(cx);
        actions::bind_keys(cx);
        actions::register(&state, cx);
        install(cx);
    });
    let window = cx.add_window(|window, cx| {
        theme::apply(window, cx);
        let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
        Root::new(view, window, cx)
    });
    let vcx = VisualTestContext::from_window(window.into(), cx);
    vcx.simulate_resize(size(px(1100.), px(height)));
    vcx.run_until_parked();
    (state, vcx)
}

/// Window height that shows the whole detail and editor columns.
const TALL: f32 = 1400.;
/// Window height for states that add a popover, menu or sheet: enough for it.
const SHORT: f32 = 960.;

/// The main window over the populated vault, the login selected, with two
/// attachments.
fn main_window(
    dir: &Path,
    height: f32,
    cx: &mut TestAppContext,
) -> (Entity<AppState>, VisualTestContext) {
    let (v, id) = vault(dir);
    let (state, mut vcx) = app(Vec::new(), height, cx);
    state.update(&mut vcx, |s, cx| {
        s.set_attachment_store(crate::state::attachments_fake());
        s.install_unlocked_for_tests(v);
        s.select(id, cx);
        cx.notify();
    });
    vcx.run_until_parked();
    let (png, txt) = (dir.join("photo.png"), dir.join("notes.txt"));
    std::fs::write(&png, PNG).unwrap();
    std::fs::write(&txt, b"hello").unwrap();
    state.update(&mut vcx, |s, cx| s.add_attachment_files(vec![png, txt], cx));
    vcx.run_until_parked();
    (state, vcx)
}

/// Clicks the element named `suffix` (at least 24 px in both directions).
fn click(suffix: &str, vcx: &mut VisualTestContext) {
    let hit = super::find(vcx, suffix, 24.).unwrap_or_else(|| panic!("no {suffix} on screen"));
    vcx.simulate_click(hit.at, gpui::Modifiers::none());
    vcx.run_until_parked();
}

/// Sidebar, list and detail controls present in every main-window read-mode state.
const MAIN: &[&str] = &[
    "nav-all",
    "nav-favorites",
    "nav-tags",
    "nav-tag",
    "sidebar-toggle",
    "sort",
    "generator",
    "item-row",
    "new-item",
    "favorite",
    "delete",
    "edit",
];

#[gpui::test]
fn choose_home(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    // A real single-file vault from the old layout: listed, but not clickable.
    let legacy = dir.path().join("old.vault");
    std::fs::write(&legacy, b"old single-file vault").unwrap();
    let recent = vec![
        dir.path().join("a.vault"),
        dir.path().join("b.vault"),
        legacy,
    ];
    let (_, mut vcx) = app(recent, 720., cx);
    audit(
        Case {
            label: "choose",
            targets: &["create", "open", "recent-0", "recent-1"],
            disabled: &["recent-2"],
        },
        &mut vcx,
    );
}

#[gpui::test]
fn choose_create(cx: &mut TestAppContext) {
    let (state, mut vcx) = app(Vec::new(), 720., cx);
    state.update(&mut vcx, |s, cx| s.switch_vault(ChooseIntent::Create, cx));
    audit(
        Case {
            label: "create",
            targets: &["back", "folder", "create-suggest", "toggle-mask"],
            // Empty password: Create stays off.
            disabled: &["do-create"],
        },
        &mut vcx,
    );
}

#[gpui::test]
fn unlock(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let path = vault(dir.path()).0.path().to_owned();
    let (state, mut vcx) = app(Vec::new(), 720., cx);
    state.update(&mut vcx, |s, cx| s.open_vault(path, cx));
    audit(
        Case {
            label: "unlock",
            targets: &["unlock", "switch"],
            disabled: &[],
        },
        &mut vcx,
    );
}

/// Detail with every field kind, TOTP, password history open, tags and attachments
/// with a preview open.
#[gpui::test]
fn main_read(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, mut vcx) = main_window(dir.path(), TALL, cx);
    state.update(&mut vcx, |s, cx| {
        s.toggle_history(cx);
        // By name: both files share an `added_at`, so their order is the random ids'.
        let item = s.selected_item().unwrap();
        let png = item.attachments.iter().find(|a| a.name == "photo.png");
        let png = png.unwrap().id;
        s.toggle_attachment_preview(png, cx);
    });
    let targets = [
        MAIN,
        &[
            "field-value",
            "copy",
            "reveal",
            "open",
            "history-toggle",
            "history-copy",
            "attachment-preview",
            "attachment-save",
            "attachment-preview-close",
        ],
    ]
    .concat();
    audit(
        Case {
            label: "main",
            targets: &targets,
            disabled: &[],
        },
        &mut vcx,
    );
}

/// A section heading first and between fields: plain content, never the pointer (its
/// row has no id, so the audit names it after its non-clickable ancestor, which must
/// not show the pointer); the fields around it keep theirs.
#[gpui::test]
fn main_read_with_sections(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, mut vcx) = main_window(dir.path(), TALL, cx);
    state.update(&mut vcx, |s, cx| {
        let id = s.selection.unwrap();
        s.vault
            .as_mut()
            .unwrap()
            .edit(|v| {
                v.update(id, 5, |it| {
                    it.fields
                        .insert(0, field("Account", FieldKind::Section, ""));
                    it.fields
                        .insert(3, field("Security", FieldKind::Section, ""));
                })
            })
            .unwrap()
            .unwrap();
        s.vault_changed();
        cx.notify();
    });
    vcx.run_until_parked();
    assert!(vcx.debug_bounds("section-row 0 ACCOUNT").is_some());
    assert!(vcx.debug_bounds("section-row 3 SECURITY").is_some());
    audit(
        Case {
            label: "main, sections",
            targets: &[MAIN, &["field-value", "copy", "reveal"]].concat(),
            disabled: &[],
        },
        &mut vcx,
    );
}

/// Sidebar collapsed (⌃⌘S): the toggle and the list footer's Lock keep the pointer.
#[gpui::test]
fn main_sidebar_collapsed(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, mut vcx) = main_window(dir.path(), TALL, cx);
    state.update(&mut vcx, |s, cx| s.toggle_sidebar(cx));
    // The slide runs on real time and ends on its own last frame.
    std::thread::sleep(crate::ui::SIDEBAR_MOTION * 2);
    for _ in 0..2 {
        vcx.update(|window, _| window.refresh());
        vcx.run_until_parked();
    }
    audit(
        Case {
            label: "main, sidebar collapsed",
            targets: &[
                "sidebar-toggle",
                "sort",
                "generator",
                "item-row",
                "new-item",
                "favorite",
                "edit",
            ],
            disabled: &[],
        },
        &mut vcx,
    );
}

#[gpui::test]
fn main_sort_menu(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (_, mut vcx) = main_window(dir.path(), SHORT, cx);
    click("sort", &mut vcx);
    audit(
        Case {
            label: "sort menu",
            targets: &["items.0", "items.1"],
            disabled: &[],
        },
        &mut vcx,
    );
}

#[gpui::test]
fn main_generator_password(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, mut vcx) = main_window(dir.path(), SHORT, cx);
    state.update(&mut vcx, |s, cx| {
        s.open_generator(GeneratorTarget::Global, cx)
    });
    audit(
        Case {
            label: "generator",
            targets: &[
                "tabs-inner.0",
                "tabs-inner.1",
                "slider",
                "gen-lower",
                "gen-upper",
                "gen-digits",
                "gen-symbols",
                "gen-regenerate",
                "gen-copy",
            ],
            disabled: &[],
        },
        &mut vcx,
    );
}

#[gpui::test]
fn main_generator_passphrase(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, mut vcx) = main_window(dir.path(), SHORT, cx);
    state.update(&mut vcx, |s, cx| {
        s.open_generator(GeneratorTarget::Global, cx);
        s.update_generator(cx, |g| g.set_tab(GenTab::Passphrase));
    });
    audit(
        Case {
            label: "passphrase",
            targets: &["slider", "gen-sep", "gen-capitalize", "gen-number"],
            disabled: &[],
        },
        &mut vcx,
    );
}

#[gpui::test]
fn main_template_picker(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, mut vcx) = main_window(dir.path(), SHORT, cx);
    state.update(&mut vcx, |s, cx| s.open_template_picker(String::new(), cx));
    audit(
        Case {
            label: "Templates menu",
            targets: &["new-login", "new-note", "new-card", "new-identity"],
            disabled: &[],
        },
        &mut vcx,
    );
}

#[gpui::test]
fn main_delete_prompt(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, mut vcx) = main_window(dir.path(), SHORT, cx);
    state.update(&mut vcx, |s, cx| s.request_delete(cx));
    audit(
        Case {
            label: "delete prompt",
            targets: &["delete-confirm", "delete-cancel"],
            disabled: &[],
        },
        &mut vcx,
    );
}

#[gpui::test]
fn main_empty_vault(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let v = SyncedVault::create(
        &dir.path().join("t.vault"),
        &SecretString::new(PW.into()),
        KdfParams::for_tests(),
        Uuid::new_v4(),
        Arc::new(NoopHooks),
    )
    .unwrap();
    let (state, mut vcx) = app(Vec::new(), 720., cx);
    state.update(&mut vcx, |s, cx| {
        s.install_unlocked_for_tests(v);
        cx.notify();
    });
    audit(
        Case {
            label: "empty vault",
            targets: &["empty-create", "new-item", "nav-all"],
            disabled: &[],
        },
        &mut vcx,
    );
}

/// The last field row's move-down button (disabled; the first row's move-up is too).
fn last_move_down(state: &Entity<AppState>, vcx: &VisualTestContext) -> String {
    let last = state.read_with(vcx, |s, _| s.edit_buffer().unwrap().keys.len() - 1);
    format!("move-down-{last}")
}

#[gpui::test]
fn edit_mode(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, mut vcx) = main_window(dir.path(), TALL, cx);
    state.update(&mut vcx, |s, cx| {
        s.begin_edit(cx);
        s.toggle_history(cx);
    });
    let last_down = last_move_down(&state, &vcx);
    audit(
        Case {
            label: "edit",
            targets: &[
                "cancel-edit",
                "save-edit",
                "remove-tag",
                "move-up",
                "move-down",
                "remove-field",
                "generate-btn",
                "scan-qr-file",
                "toggle-mask",
                "add-field",
                "attachment-add",
                "attachment-remove",
                "history-toggle",
                "history-copy",
                "history-remove",
                "history-clear",
            ],
            // First row cannot move up, last row cannot move down.
            disabled: &["move-up-0", &last_down],
        },
        &mut vcx,
    );
}

#[gpui::test]
fn edit_add_field_menu(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, mut vcx) = main_window(dir.path(), TALL, cx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    click("add-field", &mut vcx);
    let last_down = last_move_down(&state, &vcx);
    audit(
        Case {
            label: "add field menu",
            targets: &["items.0", "items.1", "items.2"],
            disabled: &["move-up-0", &last_down],
        },
        &mut vcx,
    );
}

#[gpui::test]
fn edit_field_generator(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, mut vcx) = main_window(dir.path(), SHORT, cx);
    state.update(&mut vcx, |s, cx| {
        s.begin_edit(cx);
        let key = s.edit_buffer().unwrap().keys[1];
        s.open_generator(GeneratorTarget::Field(key), cx);
    });
    let last_down = last_move_down(&state, &vcx);
    audit(
        Case {
            label: "field generator",
            targets: &["gen-use", "gen-copy", "gen-regenerate"],
            disabled: &["move-up-0", &last_down],
        },
        &mut vcx,
    );
}

#[gpui::test]
fn edit_icon_picker(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, mut vcx) = main_window(dir.path(), SHORT, cx);
    // A symbol first: the colour row is enabled (on the automatic logo it is not).
    state.update(&mut vcx, |s, cx| {
        s.begin_edit(cx);
        s.set_icon_picker(true, cx);
        s.choose_icon(crate::icon::PickerCell::Symbol(0), cx);
    });
    let last_down = last_move_down(&state, &vcx);
    audit(
        Case {
            label: "icon picker",
            targets: &[
                "edit-icon",
                "icon-auto",
                "icon-symbol",
                "icon-color",
                "icon-image",
            ],
            disabled: &["move-up-0", &last_down],
        },
        &mut vcx,
    );
    // Back to Automatic on the GitHub logo: the colour swatches are disabled.
    state.update(&mut vcx, |s, cx| {
        s.choose_icon(crate::icon::PickerCell::Automatic, cx);
        assert!(crate::icon::color_disabled_reason(&s.edit_buffer().unwrap().item).is_some());
    });
    audit(
        Case {
            label: "icon picker, logo",
            targets: &["edit-icon", "icon-auto", "icon-symbol", "icon-image"],
            disabled: &[
                "move-up-0",
                &last_down,
                "icon-color-0",
                "icon-color-1",
                "icon-color-2",
                "icon-color-3",
                "icon-color-4",
                "icon-color-5",
                "icon-color-6",
                "icon-color-7",
            ],
        },
        &mut vcx,
    );
}

/// The main window with Settings open on `tab`.
fn settings(
    tab: usize,
    dir: &Path,
    cx: &mut TestAppContext,
) -> (Entity<AppState>, VisualTestContext) {
    let (state, mut vcx) = main_window(dir, SHORT, cx);
    state.update(&mut vcx, |s, cx| {
        s.backup_now(cx);
        s.open_settings(true, cx);
        s.settings_tab = tab;
        cx.notify();
    });
    vcx.run_until_parked();
    (state, vcx)
}

const SETTINGS: &[&str] = &[
    "settings-close",
    "tabs-inner.0",
    "tabs-inner.1",
    "tabs-inner.2",
    "tabs-inner.3",
    "tabs-inner.4",
];

#[gpui::test]
fn settings_general(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (_, mut vcx) = settings(0, dir.path(), cx);
    let targets = [SETTINGS, &["auto-lock", "clipboard-clear", "lock-on-sleep"]].concat();
    audit(
        Case {
            label: "settings general",
            targets: &targets,
            disabled: &[],
        },
        &mut vcx,
    );
    click("auto-lock", &mut vcx);
    audit(
        Case {
            label: "auto-lock menu",
            targets: &["items.0", "items.1"],
            disabled: &[],
        },
        &mut vcx,
    );
}

#[gpui::test]
fn settings_sync(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, mut vcx) = settings(crate::state::SYNC_TAB, dir.path(), cx);
    let targets = [
        SETTINGS,
        &[
            "move-vault",
            "reveal-vault",
            "backup-enabled",
            "backup-now",
            "open-backup",
            "restore-backup",
            "delete-backup",
        ],
    ]
    .concat();
    audit(
        Case {
            label: "settings sync",
            targets: &targets,
            disabled: &[],
        },
        &mut vcx,
    );
    click("delete-backup", &mut vcx);
    audit(
        Case {
            label: "backup delete confirm",
            targets: &["backup-delete-cancel", "backup-delete-ok"],
            disabled: &[],
        },
        &mut vcx,
    );
    let backup = state.read_with(&vcx, |s, _| s.sync.backups[0].path.clone());
    click("backup-delete-ok", &mut vcx);
    state.read_with(&vcx, |s, _| {
        assert!(
            s.sync.backups.iter().all(|b| b.path != backup),
            "row still listed"
        );
    });
    assert!(!backup.exists());
}

#[gpui::test]
fn settings_security(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, mut vcx) = settings(crate::state::SECURITY_TAB, dir.path(), cx);
    state.update(&mut vcx, |s, cx| s.toggle_security_advanced(cx));
    let targets = [
        SETTINGS,
        &[
            "change-password",
            "recalibrate",
            "security-advanced",
            "rotate-key",
        ],
    ]
    .concat();
    audit(
        Case {
            label: "settings security",
            targets: &targets,
            // No Touch ID on the test platform: the switch is off and disabled.
            disabled: &["touch-id"],
        },
        &mut vcx,
    );
}

#[gpui::test]
fn settings_transfer(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (_, mut vcx) = settings(crate::state::TRANSFER_TAB, dir.path(), cx);
    let targets = [SETTINGS, &["import-csv", "export-csv", "import-kdbx"]].concat();
    audit(
        Case {
            label: "settings transfer",
            targets: &targets,
            disabled: &[],
        },
        &mut vcx,
    );
}

#[gpui::test]
fn settings_about(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (_, mut vcx) = settings(4, dir.path(), cx);
    audit(
        Case {
            label: "settings about",
            targets: SETTINGS,
            disabled: &[],
        },
        &mut vcx,
    );
}

#[gpui::test]
fn backup_viewer(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (mut v, _) = vault(dir.path());
    let backup = v.backup_now().unwrap();
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, _| s.install_unlocked_for_tests(v));
    cx.update(|cx| {
        gpui_component::init(cx);
        install(cx);
    });
    let handle = cx
        .update(|cx| crate::screens::open_backup_window(state.clone(), backup, cx))
        .unwrap();
    let mut vcx = VisualTestContext::from_window(handle, cx);
    vcx.simulate_resize(size(px(1100.), px(900.)));
    audit(
        Case {
            label: "backup prompt",
            targets: &["backup-open", "toggle-mask"],
            disabled: &[],
        },
        &mut vcx,
    );
    vcx.simulate_input(PW);
    vcx.simulate_keystrokes("enter");
    vcx.run_until_parked();
    audit(
        Case {
            label: "backup viewer",
            targets: &[
                "backup-row",
                "backup-copy",
                "backup-reveal",
                "backup-copy-item",
                "backup-replace",
            ],
            disabled: &[],
        },
        &mut vcx,
    );
}
