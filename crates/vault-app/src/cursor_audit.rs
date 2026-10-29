//! Headless pointer-cursor audit (debug test builds only).
//!
//! Rule under test: everything the user can click shows the pointer (hand) cursor, text
//! fields show the I-beam, disabled controls and plain content do not show the pointer.
//! `ui::Clickable` is how the app applies it.
//!
//! gpui's test platform keeps the cursor it was asked for in a private field, and test
//! windows build no accessibility tree, so neither can say which cursor an element shows.
//! gpui's element inspector can: in picking mode it reports the element under the mouse,
//! and its `DivInspectorState` holds that element's base style, including the cursor
//! (`mouse_cursor`), plus its bounds and element-id path.
//!
//! `scan` walks a grid over the window. At each point it steps down the hit-test stack
//! (inspector pick depth, driven by scroll events) until it reaches the first element
//! that sets a cursor. That is the rule gpui itself uses (`Frame::cursor_style`: the
//! topmost hovered hitbox with a cursor request wins; none means the arrow). Each point
//! is named after the topmost element under the mouse that is smaller than the window.
//!
//! Every clickable gpui element has an element id (`on_click` needs one), so every click
//! target shows up under its id. `check` then requires the pointer for every named element
//! except the non-clickable kinds listed in `rule`, which must not show it. A new click
//! target without the pointer therefore fails by name until it gets `.clickable()` or is
//! listed as not clickable.
//!
//! Limits: only `Div`-based elements are inspectable, so cursors set by custom elements
//! (none in vault-app) are invisible. Elements smaller than `STEP` in both directions
//! can fall between grid points. Hover-only cursor styles are not read.

#![cfg(all(test, debug_assertions))]

use std::cell::RefCell;
use std::collections::BTreeMap;

use gpui::{
    App, Bounds, CursorStyle, DivInspectorState, Empty, InspectorElementId, IntoElement as _,
    ParentElement as _, Pixels, PlatformInput, Point, ScrollDelta, ScrollEvent, VisualTestContext,
    Window, div, point, px, size,
};

thread_local! {
    /// What the inspector renderer saw for the active element in the last draw.
    static ACTIVE: RefCell<Option<Known>> = const { RefCell::new(None) };
}

/// Hooks gpui's inspector so each draw reports the active element. Once per app.
pub fn install(cx: &mut App) {
    cx.set_inspector_renderer(Box::new(|inspector, window, cx| {
        let id = inspector.active_element_id().cloned();
        let states = inspector.render_inspector_states(window, cx);
        // An active element that is not a Div records no state: keep its id anyway.
        ACTIVE.with(|a| {
            let mut a = a.borrow_mut();
            if a.is_none() {
                *a = id.map(|id| Known {
                    id,
                    cursor: None,
                    bounds: Bounds::default(),
                });
            }
        });
        div().children(states).into_any_element()
    }));
    cx.register_inspector_element(|_, _| {
        |id: InspectorElementId, state: &DivInspectorState, _: &mut Window, _: &mut App| {
            ACTIVE.with(|a| {
                *a.borrow_mut() = Some(Known {
                    id,
                    cursor: state.base_style.mouse_cursor,
                    bounds: state.bounds,
                })
            });
            Empty
        }
    });
}

#[derive(Clone, Debug)]
struct Known {
    id: InspectorElementId,
    cursor: Option<CursorStyle>,
    bounds: Bounds<Pixels>,
}

/// One element the scan named, with the cursor it showed and where.
#[derive(Clone, Debug)]
pub struct Hit {
    /// Element-id path without view ids, type names and code locations, e.g.
    /// `root.vault-root.unlock`.
    pub name: String,
    pub cursor: CursorStyle,
    /// The first grid point that showed this.
    pub at: Point<Pixels>,
    pub bounds: Bounds<Pixels>,
}

impl Hit {
    /// Whether `suffix` names this element or one of its ancestors: a dotted suffix
    /// must end the path or sit inside it; a single name matches any path segment or
    /// that segment's `kind` (so `copy` matches `copy-3` and its `label` child).
    pub fn matches(&self, suffix: &str) -> bool {
        if suffix.contains('.') {
            return self.name.ends_with(&format!(".{suffix}"))
                || self.name.contains(&format!(".{suffix}."));
        }
        self.name
            .split('.')
            .any(|seg| seg == suffix || kind_of(seg) == suffix)
    }

    /// The last segment's `kind_of`.
    pub fn kind(&self) -> &str {
        kind_of(self.name.rsplit('.').next().unwrap_or_default())
    }
}

/// A path segment without trailing `-<number>` parts: `edit-row-3` is `edit-row`.
fn kind_of(segment: &str) -> &str {
    let mut seg = segment;
    while let Some((head, tail)) = seg.rsplit_once('-') {
        if tail.is_empty() || !tail.bytes().all(|b| b.is_ascii_digit()) {
            break;
        }
        seg = head;
    }
    seg
}

/// Drops the noise gpui puts in element-id paths: view entity ids, type names,
/// gpui-component's derived child ids and code-location ids (file paths, whose dots
/// split them into several segments up to the `rs:<line>:<col>` one).
fn clean(path: &str) -> String {
    let mut out = Vec::new();
    let mut in_location = false;
    for s in path.split('.') {
        if in_location {
            in_location = !s.starts_with("rs:");
            continue;
        }
        if s.contains('/') {
            in_location = true;
            continue;
        }
        if s.contains("::") || s.contains(':') || is_view_id(s) {
            continue;
        }
        out.push(s);
    }
    out.join(".")
}

fn is_view_id(s: &str) -> bool {
    s.strip_prefix("view-")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

struct Scanner {
    known: Vec<Known>,
    /// Element seen at each pick depth for the previous point.
    previous: Vec<Option<usize>>,
}

impl Scanner {
    fn new() -> Self {
        Self {
            known: Vec::new(),
            previous: Vec::new(),
        }
    }

    /// Index of the inspector's active element, drawing only for one not seen yet.
    /// `hints` are tried first (the neighbouring point's stack usually matches).
    fn active(&mut self, hints: &[usize], window: &mut Window, cx: &mut App) -> Option<usize> {
        let is_active = |k: &Known, window: &mut Window, cx: &mut App| {
            window
                .with_inspector_state::<DivInspectorState, _>(Some(&k.id), cx, |_, _| ())
                .is_some()
        };
        for &h in hints {
            if is_active(&self.known[h], window, cx) {
                return Some(h);
            }
        }
        for i in 0..self.known.len() {
            if is_active(&self.known[i], window, cx) {
                return Some(i);
            }
        }
        // A new element: one draw records its state through the renderer.
        ACTIVE.with(|a| a.borrow_mut().take());
        window.draw(cx).clear(cx);
        let known = ACTIVE.with(|a| a.borrow_mut().take())?;
        self.known.push(known);
        Some(self.known.len() - 1)
    }

    fn scroll(at: Point<Pixels>, dy: f32, window: &mut Window, cx: &mut App) {
        window.dispatch_event(
            PlatformInput::Scroll(ScrollEvent {
                position: at,
                delta: ScrollDelta::Pixels(point(px(0.), px(dy))),
                ..Default::default()
            }),
            cx,
        );
    }

    /// The hit stack at `at`, topmost first, down to the first element with a cursor.
    fn stack(&mut self, at: Point<Pixels>, window: &mut Window, cx: &mut App) -> Vec<usize> {
        // Moves the mouse and goes back to pick depth 0 (the inspector clamps it), i.e.
        // the topmost element.
        Self::scroll(at, -100_000., window, cx);
        let mut out: Vec<usize> = Vec::new();
        let mut repeats = 0;
        for depth in 0..64 {
            let hints: Vec<usize> = [
                self.previous.get(depth).copied().flatten(),
                out.last().copied(),
            ]
            .into_iter()
            .flatten()
            .collect();
            let found = self.active(&hints, window, cx);
            if self.previous.len() <= depth {
                self.previous.resize(depth + 1, None);
            }
            self.previous[depth] = found;
            let Some(i) = found else {
                break;
            };
            if out.contains(&i) {
                // Hitboxes without an inspector id repeat the next element; at the
                // bottom of the stack the depth clamps and it repeats for good.
                repeats += 1;
                if repeats > 2 {
                    break;
                }
            } else {
                repeats = 0;
                out.push(i);
                if self.known[i].cursor.is_some() {
                    break;
                }
            }
            // One hitbox deeper (the inspector moves one layer per 36 px of scroll).
            Self::scroll(at, 36., window, cx);
        }
        out
    }
}

/// Grid step of the scan: every element at least this wide and tall contains a grid
/// point. vault's smallest click targets are 16 px (field grip) and 20 px (xsmall buttons).
const STEP: f32 = 12.;

/// Width the inspector panel takes from the window's content: the viewport minus the
/// widest element the inspector reports at the top-left corner (the window's root).
fn inspector_width(vcx: &mut VisualTestContext) -> Pixels {
    vcx.update(|window, cx| {
        window.toggle_inspector(cx);
        window.draw(cx).clear(cx);
        let mut scanner = Scanner::new();
        let stack = scanner.stack(point(px(1.), px(1.)), window, cx);
        let root = stack
            .iter()
            .map(|i| scanner.known[*i].bounds.size.width)
            .fold(px(0.), |a, b| if b > a { b } else { a });
        window.toggle_inspector(cx);
        window.draw(cx).clear(cx);
        window.viewport_size().width - root
    })
}

/// Scans the window and returns every element the scan named, once per cursor shown.
///
/// The window is widened by the inspector's panel while scanning, so the content keeps
/// its size and `Hit::at` points stay valid for clicks afterwards.
pub fn scan(vcx: &mut VisualTestContext) -> Vec<Hit> {
    scan_with(vcx, STEP, |_| false)
}

/// Where the element `suffix` is, from a coarse scan that stops at the first match.
/// `step` must not exceed the element's size.
pub fn find(vcx: &mut VisualTestContext, suffix: &str, step: f32) -> Option<Hit> {
    scan_with(vcx, step, |h| h.matches(suffix))
        .into_iter()
        .find(|h| h.matches(suffix))
}

fn scan_with(vcx: &mut VisualTestContext, step: f32, stop: impl Fn(&Hit) -> bool) -> Vec<Hit> {
    vcx.run_until_parked();
    let viewport = vcx.update(|window, _| window.viewport_size());
    let extra = inspector_width(vcx);
    vcx.simulate_resize(size(viewport.width + extra, viewport.height));
    vcx.run_until_parked();

    let mut scanner = Scanner::new();
    let mut hits: BTreeMap<(String, String), Hit> = BTreeMap::new();
    vcx.update(|window, cx| {
        window.toggle_inspector(cx);
        window.draw(cx).clear(cx);
        let (w, h) = (viewport.width.as_f32(), viewport.height.as_f32());
        let mut y = step / 2.;
        'grid: while y < h {
            let mut x = step / 2.;
            while x < w {
                let at = point(px(x), px(y));
                let stack = scanner.stack(at, window, cx);
                let owner = stack
                    .last()
                    .copied()
                    .filter(|i| scanner.known[*i].cursor.is_some());
                // Named after the topmost element under the mouse: a wrapper without an
                // id of its own (gpui-component's Switch) would carry its container's name.
                let named = stack.iter().copied().find(|i| {
                    let b = scanner.known[*i].bounds.size;
                    b.width < viewport.width || b.height < viewport.height
                });
                let cursor = owner
                    .and_then(|i| scanner.known[i].cursor)
                    .unwrap_or(CursorStyle::Arrow);
                let (name, bounds) = match named {
                    Some(i) => (
                        clean(&scanner.known[i].id.path.global_id.to_string()),
                        scanner.known[i].bounds,
                    ),
                    None => ("<window>".to_owned(), Bounds::default()),
                };
                let hit = hits
                    .entry((name.clone(), format!("{cursor:?}")))
                    .or_insert(Hit {
                        name,
                        cursor,
                        at,
                        bounds,
                    });
                if stop(hit) {
                    break 'grid;
                }
                x += step;
            }
            y += step;
        }
        window.toggle_inspector(cx);
        window.draw(cx).clear(cx);
    });
    vcx.simulate_resize(viewport);
    vcx.run_until_parked();
    hits.into_values().collect()
}

/// The cursor an element of a given kind must show.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Expect {
    /// A click target.
    Pointer,
    /// Text input: the I-beam.
    Text,
    /// A drag or resize handle with its own cursor.
    Exactly(CursorStyle),
    /// Not clickable (backgrounds, scroll areas, gaps, padding): anything but the hand.
    NotPointer,
}

/// What `hit` must show. Click targets are the default; everything else is listed here.
fn rule(hit: &Hit) -> Expect {
    match hit.kind() {
        // gpui-component's text area inside an input.
        "input-state" => Expect::Text,
        // An input's frame padding and its trailing hint ("⌘F").
        "input" | "suffix" => Expect::NotPointer,
        "resizable-handle" => Expect::Exactly(CursorStyle::ResizeColumn),
        // Field reorder handle (drag, not click).
        "grip" => Expect::Exactly(CursorStyle::OpenHand),
        // Window, column and section backgrounds; vault-root also holds the title-bar
        // drag band, which keeps the arrow.
        "<window>" | "root" | "vault-root" | "main-columns" | "resizable-panel" | "detail"
        | "detail-in" | "dialog-instance" | "dialog" | "surface" | "dialog-title" => {
            Expect::NotPointer
        }
        // Scroll containers and lists (the gaps between rows).
        "sidebar-sections" | "item-list" | "detail-scroll" | "editor-scroll" | "backups"
        | "backup-list" | "backup-detail" => Expect::NotPointer,
        // Editor row and section backgrounds (drop targets, not click targets) and the
        // TOTP hint line.
        "edit-row" | "edit-tags" | "attachments-edit" | "totp-hint" => Expect::NotPointer,
        // Padding inside segmented controls, popovers and menus.
        "tabs" | "tabs-inner" | "content" | "items" | "popup-menu" => Expect::NotPointer,
        _ => Expect::Pointer,
    }
}

/// What one screen state must show beyond the general rule.
struct Case<'a> {
    label: &'a str,
    /// Click targets that must be on screen with the pointer (matched by `Hit::matches`).
    targets: &'a [&'a str],
    /// Controls disabled in this state: on screen, without the pointer.
    disabled: &'a [&'a str],
}

/// Failures for one scan: every element that breaks its rule, by name.
fn check(case: &Case, hits: &[Hit]) -> Vec<String> {
    let mut failures = Vec::new();
    let at = |h: &Hit| format!("({:.0}, {:.0})", h.at.x.as_f32(), h.at.y.as_f32());
    for h in hits {
        let disabled = case.disabled.iter().any(|d| h.matches(d));
        let expect = if disabled {
            Expect::NotPointer
        } else {
            rule(h)
        };
        let ok = match expect {
            Expect::Pointer => h.cursor == CursorStyle::PointingHand,
            Expect::Text => h.cursor == CursorStyle::IBeam,
            Expect::Exactly(c) => h.cursor == c,
            Expect::NotPointer => h.cursor != CursorStyle::PointingHand,
        };
        if !ok {
            failures.push(format!(
                "[{}] {} shows {:?} at {} (element {:.0}x{:.0}), expected {:?}",
                case.label,
                h.name,
                h.cursor,
                at(h),
                h.bounds.size.width.as_f32(),
                h.bounds.size.height.as_f32(),
                expect
            ));
        }
    }
    for t in case.targets {
        if !hits
            .iter()
            .any(|h| h.matches(t) && h.cursor == CursorStyle::PointingHand)
        {
            failures.push(format!(
                "[{}] no {t} with the pointer on screen",
                case.label
            ));
        }
    }
    for d in case.disabled {
        if !hits.iter().any(|h| h.matches(d)) {
            failures.push(format!("[{}] disabled {d} not on screen", case.label));
        }
    }
    failures
}

/// Scans, checks against `case` and the general rule, and panics listing every failure.
/// Returns the hits for follow-up clicks.
fn audit(case: Case, vcx: &mut VisualTestContext) -> Vec<Hit> {
    let hits = scan(vcx);
    let failures = check(&case, &hits);
    let pointers = hits
        .iter()
        .filter(|h| h.cursor == CursorStyle::PointingHand);
    eprintln!(
        "cursor audit [{}]: {} elements, {} with the pointer",
        case.label,
        hits.len(),
        pointers.count()
    );
    if !failures.is_empty() {
        // Everything the scan saw, to tell a missing pointer from a renamed element.
        for h in &hits {
            eprintln!(
                "  {:?} {} at ({:.0}, {:.0})",
                h.cursor,
                h.name,
                h.at.x.as_f32(),
                h.at.y.as_f32()
            );
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    hits
}

#[cfg(test)]
mod tests {
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
}

/// The audit over every screen, one test per state so they run in parallel.
#[cfg(test)]
mod screens {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use gpui::{AppContext as _, Entity, TestAppContext, VisualTestContext, px, size};
    use gpui_component::Root;
    use vault_core::{Field, FieldKind, Item, ItemKind, KdfParams, SecretString, Uuid};
    use vault_sync::{NoopHooks, SyncedVault};

    use super::{Case, audit, install};
    use crate::root::VaultRoot;
    use crate::state::{AppState, ChooseIntent, GenTab, GeneratorTarget};
    use crate::{actions, theme};

    const PW: &str = "pw";

    /// A 1x1 PNG.
    const PNG: &[u8] = &[
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f,
        0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8,
        0xcf, 0xc0, 0xf0, 0x1f, 0x00, 0x05, 0x00, 0x01, 0xff, 0x89, 0x99, 0x3d, 0x1d, 0x00, 0x00,
        0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
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
                let mut gh = Item::new(ItemKind::Login, "GitHub", device, 1);
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
                    field("pin", FieldKind::Number, "1234"),
                    field("notes", FieldKind::Notes, "line one\nline two"),
                ];
                let id = v.insert(gh, 1);
                v.set_field(id, "password", SecretString::new("new".into()), 2)
                    .unwrap();
                v.insert(Item::new(ItemKind::Card, "Visa", device, 3), 3);
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
    const SHORT: f32 = 900.;

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
        "nav-login",
        "nav-tags",
        "nav-tag",
        "nav-settings",
        "sidebar-lock",
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
        let recent = vec![dir.path().join("a.vault"), dir.path().join("b.vault")];
        let (_, mut vcx) = app(recent, 720., cx);
        audit(
            Case {
                label: "choose",
                targets: &["create", "open", "recent-0", "recent-1"],
                disabled: &[],
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
            let png = s.selected_item().unwrap().attachments[0].id;
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
    fn main_kind_picker(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, mut vcx) = main_window(dir.path(), SHORT, cx);
        state.update(&mut vcx, |s, cx| s.open_kind_picker(String::new(), cx));
        audit(
            Case {
                label: "kind picker",
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
        let (_, mut vcx) = settings(crate::state::SYNC_TAB, dir.path(), cx);
        let targets = [
            SETTINGS,
            &[
                "move-vault",
                "reveal-vault",
                "backup-enabled",
                "backup-now",
                "open-backup",
                "restore-backup",
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
}
