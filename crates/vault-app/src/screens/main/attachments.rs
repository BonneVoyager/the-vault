//! Detail ▸ Attachments section (specs/05-ui.md §2.3): one row per file with an icon,
//! name, size and blob state; Preview, "Save decrypted copy…" and Remove; "Add file…".
//! Also the confirm sheet before a decrypted copy is written, and the read-only rows of
//! the backup viewer (attachments are not backed up, so they all show as Missing).
//!
//! Renders `AppState` only; every action is an `AppState` method.

use gpui::{
    AnyElement, App, Entity, FontWeight, InteractiveElement as _, IntoElement, ParentElement as _,
    SharedString, Styled as _, div, img, prelude::FluentBuilder as _, px, uniform_list,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::spinner::Spinner;
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Disableable as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{AttachmentRef, Item, Uuid};
use vault_sync::AttachmentState;

use crate::state::{AppState, PreviewContent, PreviewKind, preview_kind, state_label};
use crate::ui::Clickable as _;
use crate::{text, ui};

/// Height of one text-preview line and the most the preview box grows to.
const LINE_HEIGHT: f32 = 18.;
const TEXT_PREVIEW_HEIGHT: f32 = 240.;
const IMAGE_PREVIEW_HEIGHT: f32 = 280.;

/// The section for `item`, or `None` when it has no attachments (read mode). In edit mode
/// (`editing`) it always shows, so files can be added.
pub fn section(
    s: &AppState,
    state: &Entity<AppState>,
    item: &Item,
    editing: bool,
    cx: &App,
) -> Option<AnyElement> {
    let pending: Vec<_> = s
        .attachments
        .pending
        .iter()
        .filter(|p| p.item == item.id)
        .collect();
    // Icon images are not attachments to the user (`AppState::is_hidden_attachment`).
    let shown: Vec<&AttachmentRef> = s.visible_attachments(item).collect();
    if !editing && shown.is_empty() && pending.is_empty() {
        return None;
    }
    let add = {
        let state = state.clone();
        Button::new("attachment-add")
            .ghost()
            .small()
            .icon(Icon::new(IconName::Plus))
            .label("Add file\u{2026}")
            .tooltip("Add files, or drop them on this column")
            .disabled(!s.can_attach() || s.busy.is_some())
            .clickable_when(s.can_attach() && s.busy.is_none())
            .on_click(move |_, _, cx| state.update(cx, |s, cx| s.pick_attachment_files(cx)))
    };
    let header = ui::h_flex().gap(px(8.)).child(section_title(cx)).child(add);

    let rows = shown.iter().map(|a| row(s, state, item.id, a, editing, cx));
    let pending_rows = pending.into_iter().map(|p| {
        let name = p.name.clone();
        row_shell(IconName::File, p.name.clone(), p.size, None, cx)
            .debug_selector(move || format!("attachment-pending {name}"))
            .child(ui::muted("Encrypting\u{2026}", cx).text_xs())
            .child(Spinner::new().small())
            .into_any_element()
    });

    Some(
        ui::v_flex()
            .debug_selector(|| "attachments-section".into())
            .gap(px(2.))
            .child(header)
            .when(
                shown.is_empty() && s.attachments.pending.is_empty(),
                |col| col.child(ui::muted("Drop files here or use Add file\u{2026}", cx).text_xs()),
            )
            .children(rows)
            .children(pending_rows)
            .into_any_element(),
    )
}

fn section_title(cx: &App) -> gpui::Div {
    div()
        .flex_1()
        .text_xs()
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(cx.theme().muted_foreground)
        .child("Attachments")
}

/// Read-only item windows use the same attachment title and rows.
pub(super) fn reference_section(s: &AppState, item: &Item, cx: &App) -> Option<AnyElement> {
    let shown: Vec<&AttachmentRef> = s.visible_attachments(item).collect();
    if shown.is_empty() {
        return None;
    }
    Some(
        ui::v_flex()
            .gap(px(2.))
            .child(section_title(cx))
            .children(shown.into_iter().map(|a| {
                let selector = format!("reference-attachment {}", a.name);
                row_shell(
                    if preview_kind(&a.name, a.size) == Some(PreviewKind::Text) {
                        IconName::FileText
                    } else {
                        IconName::File
                    },
                    a.name.clone().into(),
                    a.size,
                    tag_for(s.attachment_state(a.id)),
                    cx,
                )
                .debug_selector(move || selector.clone())
            }))
            .into_any_element(),
    )
}

/// Icon, name, size and an optional state tag; actions are appended by the caller.
fn row_shell(
    icon: IconName,
    name: SharedString,
    size: u64,
    label: Option<(&'static str, bool)>,
    cx: &App,
) -> gpui::Div {
    let theme = cx.theme();
    ui::h_flex()
        .gap(px(8.))
        .py(px(6.))
        .min_h(px(36.))
        .border_b_1()
        .border_color(theme.border)
        .child(Icon::new(icon).size_4().text_color(theme.muted_foreground))
        .child(div().flex_1().min_w_0().truncate().child(name))
        .child(ui::muted(text::file_size(size), cx).text_xs().flex_none())
        .when_some(label, |row, (label, danger)| {
            row.child(if danger {
                Tag::danger().small().child(label)
            } else {
                Tag::warning().small().child(label)
            })
        })
}

/// The tag for a blob state: Missing is red, Not downloaded amber.
fn tag_for(state: AttachmentState) -> Option<(&'static str, bool)> {
    state_label(state).map(|l| (l, state == AttachmentState::Missing))
}

fn state_key(state: AttachmentState) -> &'static str {
    match state {
        AttachmentState::Present => "Present",
        AttachmentState::NotDownloaded => "NotDownloaded",
        AttachmentState::Missing => "Missing",
    }
}

fn row(
    s: &AppState,
    state: &Entity<AppState>,
    item: Uuid,
    a: &AttachmentRef,
    editing: bool,
    cx: &App,
) -> AnyElement {
    let id = a.id;
    let blob = s.attachment_state(id);
    let kind = preview_kind(&a.name, a.size);
    let icon = match kind {
        Some(PreviewKind::Text) => IconName::FileText,
        _ => IconName::File,
    };
    let name: SharedString = a.name.clone().into();
    let selector = format!(
        "attachment-row {} {} {}",
        a.name,
        text::file_size(a.size),
        state_key(blob)
    );
    let mut el = row_shell(icon, name.clone(), a.size, tag_for(blob), cx)
        .debug_selector(move || selector.clone());

    let previewing = s
        .attachments
        .preview
        .as_ref()
        .filter(|p| p.id == id && p.item == item);

    // Remove and its confirm exist only in edit mode; read mode previews and saves.
    if editing && s.attachments.remove_confirm == Some(id) {
        let (cancel, confirm) = (state.clone(), state.clone());
        let label = name.clone();
        el = el.child(
            ui::h_flex()
                .gap(px(4.))
                .debug_selector(move || format!("attachment-remove-confirm {label}"))
                .child(ui::muted("Remove?", cx).text_xs())
                .child(
                    Button::new(("attachment-remove-cancel", id.as_u128() as u64))
                        .ghost()
                        .xsmall()
                        .label("Cancel")
                        .clickable()
                        .on_click(move |_, _, cx| {
                            cancel.update(cx, |s, cx| s.cancel_remove_attachment(cx))
                        }),
                )
                .child(
                    Button::new(("attachment-remove-ok", id.as_u128() as u64))
                        .danger()
                        .xsmall()
                        .label("Remove")
                        .clickable()
                        .on_click(move |_, _, cx| {
                            confirm.update(cx, |s, cx| s.confirm_remove_attachment(id, cx))
                        }),
                ),
        );
    } else {
        let readable = blob != AttachmentState::Missing;
        // The vault may be inside a task: every action waits for it.
        let busy = s.busy.is_some();
        let actions_name = name.clone();
        // One selector per element: the row already carries its own.
        el = el.child(div().debug_selector(move || {
            format!(
                "attachment-actions {actions_name} {}",
                if busy { "disabled" } else { "enabled" }
            )
        }));
        if s.attachments.reading == Some(id) {
            el = el.child(Spinner::new().small());
        } else if readable {
            if kind.is_some() {
                let st = state.clone();
                let (icon, label) = if previewing.is_some() {
                    (IconName::EyeOff, "Hide preview")
                } else {
                    (IconName::Eye, "Preview")
                };
                let label_name = name.clone();
                el = el.child(
                    div()
                        .debug_selector(move || format!("attachment-preview {label_name}"))
                        .child(
                            ui::icon_button(
                                ("attachment-preview", id.as_u128() as u64),
                                icon,
                                label,
                            )
                            .disabled(busy)
                            .clickable_when(!busy)
                            .on_click(move |_, _, cx| {
                                st.update(cx, |s, cx| s.toggle_attachment_preview(id, cx))
                            }),
                        ),
                );
            }
            let st = state.clone();
            el = el.child(
                ui::icon_button(
                    ("attachment-save", id.as_u128() as u64),
                    IconName::ArrowDown,
                    "Save decrypted copy\u{2026}",
                )
                .disabled(busy)
                .clickable_when(!busy)
                .on_click(move |_, _, cx| st.update(cx, |s, cx| s.save_attachment_copy(id, cx))),
            );
        }
        if editing {
            let st = state.clone();
            let remove_name = name.clone();
            el = el.child(
                div()
                    .debug_selector(move || format!("attachment-remove {remove_name}"))
                    .child(
                        ui::icon_button(
                            ("attachment-remove", id.as_u128() as u64),
                            IconName::Trash,
                            "Remove attachment",
                        )
                        .disabled(busy)
                        .clickable_when(!busy)
                        .on_click(move |_, _, cx| {
                            st.update(cx, |s, cx| s.request_remove_attachment(id, cx))
                        }),
                    ),
            );
        }
    }

    match previewing {
        Some(p) => ui::v_flex()
            .child(el)
            .child(preview(&p.content, &name, state, cx))
            .into_any_element(),
        None => el.into_any_element(),
    }
}

/// The decrypted preview under its row. Nothing here touches the disk. Visible text lines
/// are copied into gpui strings to draw them (freed, not zeroized, like a revealed
/// password); only the source buffer in `AppState` is zeroized.
fn preview(
    content: &PreviewContent,
    name: &SharedString,
    state: &Entity<AppState>,
    cx: &App,
) -> AnyElement {
    let theme = cx.theme();
    let name = name.clone();
    let (body, what): (AnyElement, &str) = match content {
        PreviewContent::Image(image) => (
            img(image.clone())
                .w_full()
                .h(px(IMAGE_PREVIEW_HEIGHT))
                .into_any_element(),
            "image",
        ),
        PreviewContent::Text(text) => {
            let count = text.line_count();
            let lines = text.clone();
            let font = theme.mono_font_family.clone();
            let height = (count as f32 * LINE_HEIGHT).min(TEXT_PREVIEW_HEIGHT);
            (
                uniform_list("attachment-text", count, move |range, _, _| {
                    range
                        .map(|ix| {
                            div()
                                .h(px(LINE_HEIGHT))
                                .whitespace_nowrap()
                                .truncate()
                                .child(SharedString::from(lines.line(ix).to_owned()))
                        })
                        .collect()
                })
                .font_family(font)
                .text_xs()
                .w_full()
                .h(px(height))
                .into_any_element(),
                "text",
            )
        }
        PreviewContent::Unavailable(why) => (ui::muted(why.clone(), cx).into_any_element(), "none"),
    };
    let close = state.clone();
    ui::v_flex()
        .debug_selector(move || format!("attachment-preview-shown {name} {what}"))
        .my(px(6.))
        .p(px(8.))
        .gap(px(6.))
        .rounded(theme.radius)
        .border_1()
        .border_color(theme.border)
        .bg(theme.secondary)
        .child(body)
        .child(
            ui::h_flex().justify_end().child(
                Button::new("attachment-preview-close")
                    .ghost()
                    .xsmall()
                    .label("Close preview")
                    .clickable()
                    .on_click(move |_, _, cx| close.update(cx, |s, cx| s.close_preview(cx))),
            ),
        )
        .into_any_element()
}

/// The confirm sheet before "Save decrypted copy…" writes plaintext: slides over the top
/// of the detail column. A real gpui-component dialog is not used because the root view
/// closes any dialog that is not the Settings sheet whenever the state changes.
pub fn save_sheet(s: &AppState, state: &Entity<AppState>, cx: &App) -> Option<AnyElement> {
    let request = s.attachments.save_confirm.as_ref()?;
    let theme = cx.theme();
    let (cancel, confirm) = (state.clone(), state.clone());
    Some(
        div()
            .absolute()
            .top_0()
            .left_0()
            .right_0()
            .bottom_0()
            .bg(gpui::black().opacity(0.15))
            .child(
                ui::v_flex()
                    .debug_selector(|| "attachment-save-confirm".into())
                    .mx(px(24.))
                    .mt(px(ui::TOP_BAND_HEIGHT))
                    .p(px(16.))
                    .gap(px(10.))
                    .rounded(theme.radius_lg)
                    .bg(theme.popover)
                    .border_1()
                    .border_color(theme.border)
                    .shadow_lg()
                    .child(div().font_weight(FontWeight::SEMIBOLD).child(format!(
                        "Save a decrypted copy of \u{2018}{}\u{2019}?",
                        request.name
                    )))
                    .child(div().child("This writes an unencrypted copy to disk."))
                    .child(
                        ui::muted(request.path.display().to_string(), cx)
                            .text_xs()
                            .truncate(),
                    )
                    .child(
                        ui::h_flex()
                            .justify_end()
                            .gap(px(8.))
                            .child(
                                Button::new("attachment-save-cancel")
                                    .small()
                                    .label("Cancel")
                                    .clickable()
                                    .on_click(move |_, _, cx| {
                                        cancel.update(cx, |s, cx| s.cancel_save_copy(cx))
                                    }),
                            )
                            .child(
                                Button::new("attachment-save-ok")
                                    .small()
                                    .danger()
                                    .label("Save Copy")
                                    .clickable()
                                    .on_click(move |_, _, cx| {
                                        confirm.update(cx, |s, cx| s.confirm_save_copy(cx))
                                    }),
                            ),
                    ),
            )
            .into_any_element(),
    )
}

/// Backup viewer rows: the backup has references but no blobs, so every row is Missing
/// and has no actions.
pub fn backup_section(item: &Item, cx: &App) -> Option<AnyElement> {
    let shown: Vec<&AttachmentRef> = item
        .attachments
        .iter()
        .filter(|a| !crate::icon::is_icon_attachment(item, a))
        .collect();
    if shown.is_empty() {
        return None;
    }
    let theme = cx.theme();
    let rows = shown.into_iter().map(|a| {
        let selector = format!("backup-attachment {} Missing", a.name);
        row_shell(
            IconName::File,
            a.name.clone().into(),
            a.size,
            tag_for(AttachmentState::Missing),
            cx,
        )
        .debug_selector(move || selector.clone())
    });
    Some(
        ui::v_flex()
            .pt(px(8.))
            .gap(px(2.))
            .child(
                div()
                    .text_xs()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme.muted_foreground)
                    .child("Attachments"),
            )
            .child(ui::muted("Attachments are not included in backups.", cx).text_xs())
            .children(rows)
            .into_any_element(),
    )
}

#[cfg(test)]
mod tests {
    //! Headless render tests: rows, states, which rows offer Preview, the preview itself,
    //! the edit-mode strip and the save confirm sheet.

    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use gpui::{AppContext as _, TestAppContext, VisualTestContext};
    use gpui_component::Root;
    use vault_core::{KdfParams, SecretString};
    use vault_sync::{NoopHooks, SyncedVault};

    use super::super::MainScreen;
    use super::*;
    use crate::actions;
    use crate::state::AttachmentStore;

    /// A 1×1 PNG.
    const PNG: &[u8] = &[
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f,
        0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8,
        0xcf, 0xc0, 0xf0, 0x1f, 0x00, 0x05, 0x00, 0x01, 0xff, 0x89, 0x99, 0x3d, 0x1d, 0x00, 0x00,
        0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
    ];

    fn open(
        dir: &Path,
        store: Arc<dyn AttachmentStore>,
        cx: &mut TestAppContext,
    ) -> (Entity<AppState>, Uuid, VisualTestContext) {
        let mut vault = SyncedVault::create(
            &dir.join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let id = vault
            .edit(|v| {
                let d = v.device_id();
                v.insert(Item::new("Passport", d, 1), 1)
            })
            .unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(|cx| {
            gpui_component::init(cx);
            actions::bind_keys(cx);
            actions::register(&state, cx);
        });
        state.update(cx, |s, cx| {
            s.set_attachment_store(store);
            s.install_unlocked_for_tests(vault);
            s.select(id, cx);
        });
        let mut main = None;
        let window = cx.add_window(|window, cx| {
            crate::theme::apply(window, cx);
            let view = cx.new(|cx| MainScreen::new(state.clone(), None, window, cx));
            main = Some(view.clone());
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        let main = main.unwrap();
        vcx.update(|window, cx| main.update(cx, |m, cx| m.appear(window, cx)));
        vcx.run_until_parked();
        (state, id, vcx)
    }

    fn file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn add(state: &Entity<AppState>, paths: Vec<PathBuf>, vcx: &mut VisualTestContext) {
        vcx.update(|_, cx| state.update(cx, |s, cx| s.add_attachment_files(paths, cx)));
        vcx.run_until_parked();
    }

    fn ids(state: &Entity<AppState>, item: Uuid, vcx: &VisualTestContext) -> Vec<Uuid> {
        state.read_with(vcx, |s, _| {
            s.selected_item()
                .filter(|i| i.id == item)
                .map(|i| i.attachments.iter().map(|a| a.id).collect())
                .unwrap()
        })
    }

    fn shown(key: &'static str, vcx: &mut VisualTestContext) -> bool {
        vcx.debug_bounds(key).is_some()
    }

    #[gpui::test]
    fn rows_show_sizes_states_and_preview_only_for_listed_kinds(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::state::attachments_fake();
        let (state, item, mut vcx) = open(dir.path(), store.clone(), cx);
        assert!(
            !shown("attachments-section", &mut vcx),
            "no section without files"
        );
        add(
            &state,
            vec![
                file(dir.path(), "notes.txt", &[b'a'; 1234]),
                file(dir.path(), "scan.pdf", &[0; 2_500_000]),
                file(dir.path(), "photo.heic", &[0; 10]),
            ],
            &mut vcx,
        );
        let [_, pdf, heic] = ids(&state, item, &vcx)[..] else {
            panic!("three refs")
        };
        store.set_state(pdf, AttachmentState::NotDownloaded);
        store.blobs.lock().unwrap().remove(&heic);
        vcx.update(|_, cx| state.update(cx, |_, cx| cx.notify()));
        vcx.run_until_parked();

        assert!(shown("attachments-section", &mut vcx));
        assert!(shown("attachment-row notes.txt 1.2 KB Present", &mut vcx));
        assert!(shown(
            "attachment-row scan.pdf 2.5 MB NotDownloaded",
            &mut vcx
        ));
        assert!(shown("attachment-row photo.heic 10 B Missing", &mut vcx));
        assert!(shown("attachment-preview notes.txt", &mut vcx));
        assert!(!shown("attachment-preview scan.pdf", &mut vcx));
        assert!(!shown("attachment-preview photo.heic", &mut vcx));
        // Read mode: Preview and Save only, no Remove (not even on a Missing row).
        for name in ["notes.txt", "scan.pdf", "photo.heic"] {
            let key: &'static str = Box::leak(format!("attachment-remove {name}").into_boxed_str());
            assert!(!shown(key, &mut vcx), "{name}");
        }
        // Rows sit between the fields and the footer.
        let section = vcx.debug_bounds("attachments-section").unwrap();
        let footer = vcx.debug_bounds("detail-footer").unwrap();
        assert!(section.bottom() <= footer.top());
    }

    #[gpui::test]
    fn pending_row_spins_until_sealed(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(dir.path(), crate::state::attachments_fake(), cx);
        let path = file(dir.path(), "big.bin", &[7; 4000]);
        vcx.update(|_, cx| state.update(cx, |s, cx| s.add_attachment_files(vec![path], cx)));
        // Drawn before the background task runs: the item stays on screen meanwhile.
        vcx.update(|window, _| window.refresh());
        let _ = vcx.update(|window, cx| window.draw(cx));
        assert!(shown("attachment-pending big.bin", &mut vcx));
        assert!(
            shown("detail-header", &mut vcx),
            "item still shown while sealing"
        );
        vcx.run_until_parked();
        assert!(!shown("attachment-pending big.bin", &mut vcx));
        assert!(shown("attachment-row big.bin 4.0 KB Present", &mut vcx));
    }

    #[gpui::test]
    fn row_actions_disabled_while_busy(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(dir.path(), crate::state::attachments_fake(), cx);
        add(&state, vec![file(dir.path(), "a.txt", b"a")], &mut vcx);
        assert!(shown("attachment-actions a.txt enabled", &mut vcx));
        let more = file(dir.path(), "b.txt", b"b");
        vcx.update(|_, cx| state.update(cx, |s, cx| s.add_attachment_files(vec![more], cx)));
        vcx.update(|window, _| window.refresh());
        let _ = vcx.update(|window, cx| window.draw(cx));
        assert!(shown("attachment-actions a.txt disabled", &mut vcx));
        vcx.run_until_parked();
        assert!(shown("attachment-actions a.txt enabled", &mut vcx));
    }

    #[gpui::test]
    fn image_and_text_previews_render(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, item, mut vcx) = open(dir.path(), crate::state::attachments_fake(), cx);
        add(
            &state,
            vec![
                file(dir.path(), "dot.png", PNG),
                file(dir.path(), "a.md", b"# hi"),
            ],
            &mut vcx,
        );
        let [png, md] = ids(&state, item, &vcx)[..] else {
            panic!("two refs")
        };
        vcx.update(|_, cx| state.update(cx, |s, cx| s.toggle_attachment_preview(png, cx)));
        vcx.run_until_parked();
        assert!(shown("attachment-preview-shown dot.png image", &mut vcx));
        // Only one decrypted attachment at a time.
        vcx.update(|_, cx| state.update(cx, |s, cx| s.toggle_attachment_preview(md, cx)));
        vcx.run_until_parked();
        assert!(shown("attachment-preview-shown a.md text", &mut vcx));
        assert!(!shown("attachment-preview-shown dot.png image", &mut vcx));
    }

    #[gpui::test]
    fn edit_mode_shows_section_and_save_sheet_confirms(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, item, mut vcx) = open(dir.path(), crate::state::attachments_fake(), cx);
        vcx.update(|_, cx| state.update(cx, |s, cx| s.begin_edit(cx)));
        vcx.run_until_parked();
        assert!(
            shown("attachments-section", &mut vcx),
            "edit mode offers Add file"
        );

        add(
            &state,
            vec![
                file(dir.path(), "k.txt", b"k"),
                file(dir.path(), "x.txt", b"x"),
            ],
            &mut vcx,
        );
        assert!(shown("attachment-row k.txt 1 B Present", &mut vcx));
        assert!(
            shown("attachment-remove x.txt", &mut vcx),
            "edit mode offers Remove"
        );
        // Remove through the UI: trash, then the inline confirm.
        let x = ids(&state, item, &vcx)[1];
        let trash = vcx.debug_bounds("attachment-remove x.txt").unwrap();
        vcx.simulate_click(trash.center(), gpui::Modifiers::none());
        vcx.run_until_parked();
        assert!(shown("attachment-remove-confirm x.txt", &mut vcx));
        vcx.update(|_, cx| state.update(cx, |s, cx| s.confirm_remove_attachment(x, cx)));
        vcx.run_until_parked();
        assert!(!shown("attachment-row x.txt 1 B Present", &mut vcx));
        assert_eq!(ids(&state, item, &vcx).len(), 1);
        let id = ids(&state, item, &vcx)[0];
        let out = dir.path().join("k-copy.txt");
        vcx.update(|_, cx| state.update(cx, |s, cx| s.save_attachment_to(id, out.clone(), cx)));
        vcx.run_until_parked();
        assert!(shown("attachment-save-confirm", &mut vcx));
        let ok = vcx.debug_bounds("attachment-save-confirm").unwrap();
        assert!(ok.size.height > px(0.));
        vcx.update(|_, cx| state.update(cx, |s, cx| s.confirm_save_copy(cx)));
        vcx.run_until_parked();
        assert!(!shown("attachment-save-confirm", &mut vcx));
        assert_eq!(std::fs::read(&out).unwrap(), b"k");
    }
}
