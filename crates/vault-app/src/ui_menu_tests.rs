//! `ui::menu_popover` keyboard behaviour and content sizing.

use std::cell::RefCell;
use std::rc::Rc;

use gpui::{
    AppContext as _, Context, InteractiveElement as _, IntoElement, ParentElement as _, Render,
    Styled as _, TestAppContext, VisualTestContext, Window,
};
use gpui_component::Root;
use gpui_component::button::Button;

use super::{menu_popover, menu_row};

/// A trigger and a three-row menu; logs activations and toggles.
struct Menu {
    open: bool,
    log: Rc<RefCell<Vec<String>>>,
}

impl Render for Menu {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let this = cx.entity().downgrade();
        let log = self.log.clone();
        let rows_log = self.log.clone();
        gpui::div().size_full().child(menu_popover(
            "test-menu",
            Button::new("trigger")
                .debug_selector(|| "trigger".into())
                .label("Menu"),
            gpui::Anchor::TopLeft,
            self.open,
            move |open, _, cx| {
                log.borrow_mut().push(format!("toggle {open}"));
                _ = this.update(cx, |m, cx| {
                    m.open = open;
                    cx.notify();
                });
            },
            move |_, _| {
                ["a", "b", "c"]
                    .into_iter()
                    .map(|name| {
                        let log = rows_log.clone();
                        menu_row(format!("row-{name}"), name.to_uppercase())
                            .checked(name == "b")
                            .hint("⌘X")
                            .on_click(move |_, _, _| log.borrow_mut().push(name.into()))
                    })
                    .collect()
            },
            window,
            cx,
        ))
    }
}

fn open(cx: &mut TestAppContext) -> (gpui::Entity<Menu>, VisualTestContext) {
    cx.update(|cx| {
        gpui_component::init(cx);
        super::bind_menu_keys(cx);
    });
    let log = Rc::new(RefCell::new(Vec::new()));
    let mut menu = None;
    let window = cx.add_window(|window, cx| {
        crate::theme::apply(window, cx);
        let view = cx.new(|_| Menu { open: false, log });
        menu = Some(view.clone());
        Root::new(view, window, cx)
    });
    let vcx = VisualTestContext::from_window(window.into(), cx);
    vcx.run_until_parked();
    (menu.unwrap(), vcx)
}

/// Key down and up: a focused element's keyboard click fires on key up.
fn press(vcx: &mut VisualTestContext, key: &'static str) {
    vcx.simulate_keystrokes(key);
    vcx.simulate_event(gpui::KeyUpEvent {
        keystroke: gpui::Keystroke::parse(key).unwrap(),
    });
    vcx.run_until_parked();
}

/// Opens the menu the way ⌘N opens the Templates menu: a key press, then app state.
fn open_by_keyboard(menu: &gpui::Entity<Menu>, vcx: &mut VisualTestContext) {
    vcx.simulate_keystrokes("cmd-k");
    menu.update(vcx, |m, cx| {
        m.open = true;
        cx.notify();
    });
    vcx.run_until_parked();
    assert!(vcx.debug_bounds("row-c").is_some(), "rows drawn");
}

fn log(menu: &gpui::Entity<Menu>, vcx: &VisualTestContext) -> Vec<String> {
    menu.read_with(vcx, |m, _| m.log.borrow().clone())
}

#[gpui::test]
fn keyboard_open_focuses_the_first_row(cx: &mut TestAppContext) {
    let (menu, mut vcx) = open(cx);
    open_by_keyboard(&menu, &mut vcx);
    press(&mut vcx, "enter");
    assert_eq!(log(&menu, &vcx), ["a"]);
}

#[gpui::test]
fn arrows_move_between_rows(cx: &mut TestAppContext) {
    let (menu, mut vcx) = open(cx);
    open_by_keyboard(&menu, &mut vcx);
    press(&mut vcx, "down");
    press(&mut vcx, "down");
    // Stops at the last row.
    press(&mut vcx, "down");
    press(&mut vcx, "enter");
    press(&mut vcx, "up");
    press(&mut vcx, "space");
    assert_eq!(log(&menu, &vcx), ["c", "b"]);
}

#[gpui::test]
fn escape_reports_closed(cx: &mut TestAppContext) {
    let (menu, mut vcx) = open(cx);
    open_by_keyboard(&menu, &mut vcx);
    press(&mut vcx, "escape");
    assert_eq!(log(&menu, &vcx), ["toggle false"]);
    assert!(!menu.read_with(&vcx, |m, _| m.open));
    assert!(vcx.debug_bounds("row-a").is_none(), "menu gone");
}

/// Opened by a click no row has focus; ↓ reaches the first row.
#[gpui::test]
fn click_open_leaves_rows_unfocused_until_down(cx: &mut TestAppContext) {
    let (menu, mut vcx) = open(cx);
    let trigger = vcx.debug_bounds("trigger").unwrap();
    vcx.simulate_click(trigger.center(), gpui::Modifiers::none());
    vcx.run_until_parked();
    press(&mut vcx, "enter");
    assert_eq!(
        log(&menu, &vcx),
        ["toggle true"],
        "Enter with no row focused"
    );
    press(&mut vcx, "down");
    press(&mut vcx, "enter");
    assert_eq!(log(&menu, &vcx), ["toggle true", "a"]);
}

/// One row of a sizing menu: label, has an icon, `checked` (None: not checkable).
type Spec = (&'static str, bool, Option<bool>);

/// Menus rendered open side by side, one per entry of `menus`; menu `i` has id
/// `m{i}`, panel `m{i}-panel` and rows `m{i}-r{j}`.
struct Sizing {
    menus: Vec<Vec<Spec>>,
}

impl Render for Sizing {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let mut row = gpui::div().size_full().flex().gap(gpui::px(400.));
        for (i, specs) in self.menus.clone().into_iter().enumerate() {
            row = row.child(menu_popover(
                format!("m{i}"),
                Button::new(("trigger", i)).label("Menu"),
                gpui::Anchor::TopLeft,
                true,
                |_, _, _| {},
                move |_, _| {
                    specs
                        .iter()
                        .enumerate()
                        .map(|(j, &(label, icon, checked))| {
                            let mut row = menu_row(format!("m{i}-r{j}"), label);
                            if icon {
                                row = row.icon(super::IconName::Plus);
                            }
                            if let Some(checked) = checked {
                                row = row.checked(checked);
                            }
                            row
                        })
                        .collect()
                },
                window,
                cx,
            ));
        }
        row
    }
}

fn sized(cx: &mut TestAppContext, menus: Vec<Vec<Spec>>) -> VisualTestContext {
    cx.update(gpui_component::init);
    let window = cx.add_window(|window, cx| {
        crate::theme::apply(window, cx);
        let view = cx.new(|_| Sizing { menus });
        Root::new(view, window, cx)
    });
    let mut vcx = VisualTestContext::from_window(window.into(), cx);
    vcx.run_until_parked();
    // Popovers open on the first frame paint on the next.
    vcx.update(|window, _| window.refresh());
    vcx.run_until_parked();
    vcx
}

fn bounds(vcx: &mut VisualTestContext, selector: &str) -> gpui::Bounds<gpui::Pixels> {
    // `debug_bounds` takes `&'static str`; test-only leak.
    let key: &'static str = Box::leak(selector.to_owned().into_boxed_str());
    vcx.debug_bounds(key)
        .unwrap_or_else(|| panic!("{selector} drawn"))
}

#[gpui::test]
fn no_icons_labels_start_at_row_padding(cx: &mut TestAppContext) {
    let mut vcx = sized(cx, vec![vec![("Name", false, None), ("Date", false, None)]]);
    let panel = bounds(&mut vcx, "m0-panel");
    for row in ["m0-r0", "m0-r1"] {
        let label = bounds(&mut vcx, &format!("{row}-label"));
        assert_eq!(label.left() - panel.left(), gpui::px(8.), "{row}");
    }
}

#[gpui::test]
fn one_icon_reserves_the_slot_on_every_row(cx: &mut TestAppContext) {
    let mut vcx = sized(cx, vec![vec![("Login", true, None), ("Note", false, None)]]);
    let panel = bounds(&mut vcx, "m0-panel");
    let slot = gpui::px(8. + super::MENU_ICON_SLOT + 8.);
    for row in ["m0-r0", "m0-r1"] {
        let label = bounds(&mut vcx, &format!("{row}-label"));
        assert_eq!(label.left() - panel.left(), slot, "{row}");
    }
}

/// Unchecked rows of a checkable menu keep the column: 24 gap + 16 column + 8 padding
/// replace the 16 trailing padding.
#[gpui::test]
fn checkable_menu_is_wider_by_the_check_column(cx: &mut TestAppContext) {
    let mut vcx = sized(
        cx,
        vec![
            vec![("Name", false, None), ("Modified", false, None)],
            vec![
                ("Name", false, Some(false)),
                ("Modified", false, Some(false)),
            ],
        ],
    );
    let plain = bounds(&mut vcx, "m0-panel").size.width;
    let checkable = bounds(&mut vcx, "m1-panel").size.width;
    eprintln!("plain {plain:?} checkable {checkable:?}");
    assert_eq!(checkable - plain, gpui::px(24. + 16. + 8. - 16.));
}

/// The panel hugs its widest row: that row's label keeps its natural width plus the
/// row's 8 + 16 padding, and a longer label makes a wider panel.
#[gpui::test]
fn panel_width_is_its_widest_row(cx: &mut TestAppContext) {
    let mut vcx = sized(
        cx,
        vec![
            vec![("A", false, None), ("Short", false, None)],
            vec![("A", false, None), ("A much longer label", false, None)],
        ],
    );
    for i in 0..2 {
        let panel = bounds(&mut vcx, &format!("m{i}-panel"));
        let row = bounds(&mut vcx, &format!("m{i}-r1"));
        let label = bounds(&mut vcx, &format!("m{i}-r1-label"));
        assert_eq!(row.size.width, panel.size.width);
        assert_eq!(panel.size.width, label.size.width + gpui::px(8. + 16.));
        let short = bounds(&mut vcx, &format!("m{i}-r0"));
        assert_eq!(short.size.width, panel.size.width, "rows stretch");
    }
    let (short, long) = (
        bounds(&mut vcx, "m0-panel").size.width,
        bounds(&mut vcx, "m1-panel").size.width,
    );
    eprintln!("short {short:?} long {long:?}");
    assert!(long > short + gpui::px(40.), "{short:?} vs {long:?}");
}

/// Past the max width the panel stops growing and the label truncates.
#[gpui::test]
fn long_labels_stop_at_the_max_width(cx: &mut TestAppContext) {
    let long = "An extraordinarily long menu label that no native menu would ever want to show";
    let mut vcx = sized(cx, vec![vec![(long, false, None)]]);
    let panel = bounds(&mut vcx, "m0-panel");
    let label = bounds(&mut vcx, "m0-r0-label");
    assert_eq!(panel.size.width, gpui::px(320.));
    assert_eq!(label.size.width, gpui::px(320. - 8. - 16.));
}
