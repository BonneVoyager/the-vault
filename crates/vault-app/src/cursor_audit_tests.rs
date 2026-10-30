use super::*;

fn hit(name: &str, cursor: CursorStyle) -> Hit {
    Hit {
        name: name.into(),
        cursor,
        at: point(px(0.), px(0.)),
        bounds: Bounds::default(),
    }
}

#[test]
fn clean_drops_view_ids_type_names_and_code_locations() {
    assert_eq!(
        clean("view-1.gpui_component::root::Root.root.view-22.vault-root.unlock"),
        "root.vault-root.unlock"
    );
    assert_eq!(
        clean(
            "root.dialog-0.surface./u/.cargo/index.crates.io-19/gpui-component-0.8.1/src/\
             dialog/dialog.rs:830:66./u/x.rs:830:66-content.backups"
        ),
        "root.dialog-0.surface.backups"
    );
    assert_eq!(clean("view-x.item-row-3"), "view-x.item-row-3");
}

#[test]
fn kind_strips_numeric_suffixes() {
    assert_eq!(hit("a.edit-row-3", CursorStyle::Arrow).kind(), "edit-row");
    assert_eq!(
        hit("a.attachment-save-1076597436", CursorStyle::Arrow).kind(),
        "attachment-save"
    );
    assert_eq!(
        hit("a.dialog-instance-0", CursorStyle::Arrow).kind(),
        "dialog-instance"
    );
    assert_eq!(hit("a.unlock", CursorStyle::Arrow).kind(), "unlock");
}

/// The check bites: a click target with the arrow, a container with the pointer, an
/// input without the I-beam, a disabled control with the pointer and a missing target
/// all fail, by name.
#[test]
fn check_flags_each_kind_of_mistake() {
    let hits = [
        hit("root.vault-root.unlock", CursorStyle::Arrow),
        hit("root.detail-scroll", CursorStyle::PointingHand),
        hit("root.input-7.input-state", CursorStyle::Arrow),
        hit("root.do-create", CursorStyle::PointingHand),
        hit("root.switch", CursorStyle::PointingHand),
    ];
    let case = Case {
        label: "t",
        targets: &["switch", "back"],
        disabled: &["do-create"],
    };
    let failures = check(&case, &hits);
    let has = |s: &str| failures.iter().any(|f| f.contains(s));
    assert!(has("root.vault-root.unlock shows Arrow"), "{failures:?}");
    assert!(has("root.detail-scroll shows PointingHand"), "{failures:?}");
    assert!(has("input-state shows Arrow"), "{failures:?}");
    assert!(has("root.do-create shows PointingHand"), "{failures:?}");
    assert!(has("no back with the pointer"), "{failures:?}");
    assert_eq!(failures.len(), 5, "{failures:?}");
}
