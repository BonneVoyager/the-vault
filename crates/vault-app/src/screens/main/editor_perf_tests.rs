//! Edit-mode frame timing with many fields (owner report 2026-11-15: scrolling and field
//! drags slow down on large items). Ignored by default; run with
//! `cargo test -p vault-app --release -- editor::perf_tests --ignored --nocapture`.
//! Prints frame times only, never a field value.

use std::time::{Duration, Instant};

use gpui::{
    Modifiers, MouseButton, ScrollDelta, ScrollEvent, TestAppContext, VisualTestContext, point,
};
use vault_core::{HistoryEntry, SecretString};

use super::*;

const OTHER_ITEMS: usize = 299;
const FRAMES: usize = 40;

fn secret(s: String) -> SecretString {
    SecretString::new(s)
}

/// 299 saved items with one password each, then the edited item: 20 password, 30 text
/// and 10 notes fields with 10 history entries. Half the passwords are reused, some weak.
fn big_item(state: &Entity<AppState>, vcx: &mut VisualTestContext) {
    state.update(vcx, |s, cx| {
        let device = s.device_id();
        let mut items: Vec<vault_core::Item> = (0..OTHER_ITEMS)
            .map(|i| {
                let mut it = vault_core::Item::new(format!("Other {i}"), device, 10);
                it.fields = vec![vault_core::Field::new(
                    "Password",
                    FieldKind::Password,
                    secret(format!("shared-Passphrase-{}-x9", i % 40)),
                    10,
                )];
                it
            })
            .collect();
        let mut it = vault_core::Item::new("Big", device, 10);
        for i in 0..20 {
            let value = if i % 2 == 0 {
                format!("shared-Passphrase-{i}-x9")
            } else {
                format!("pw{i}")
            };
            it.fields.push(vault_core::Field::new(
                format!("Password {i}"),
                FieldKind::Password,
                secret(value),
                10,
            ));
        }
        for i in 0..30 {
            it.fields.push(vault_core::Field::new(
                format!("Text {i}"),
                FieldKind::Text,
                secret(format!("text value {i}")),
                10,
            ));
        }
        for i in 0..10 {
            it.fields.push(vault_core::Field::new(
                format!("Notes {i}"),
                FieldKind::Notes,
                secret(format!("line one {i}\nline two\nline three")),
                10,
            ));
        }
        it.history = (0..10u64)
            .map(|i| HistoryEntry {
                value: secret(format!("old-{i}")),
                replaced_at: 1_000 + i,
                field_id: Some(it.fields[(i as usize) % 20].id),
            })
            .collect();
        items.push(it);
        let ids = s
            .vault
            .as_mut()
            .unwrap()
            .edit(|v| {
                items
                    .into_iter()
                    .map(|it| v.insert(it, 10))
                    .collect::<Vec<_>>()
            })
            .unwrap();
        s.vault_changed();
        s.select(*ids.last().unwrap(), cx);
        s.begin_edit(cx);
    });
    vcx.run_until_parked();
}

fn report(label: &str, mut times: Vec<Duration>) {
    times.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1000.;
    let mean = times.iter().map(|d| ms(*d)).sum::<f64>() / times.len() as f64;
    println!(
        "{label:<12} n={} mean {mean:.2} ms  median {:.2} ms  max {:.2} ms",
        times.len(),
        ms(times[times.len() / 2]),
        ms(*times.last().unwrap()),
    );
}

/// `FRAMES` full window redraws.
fn frames(vcx: &mut VisualTestContext) -> Vec<Duration> {
    (0..FRAMES)
        .map(|_| {
            let t = Instant::now();
            vcx.update(|window, _| window.refresh());
            t.elapsed()
        })
        .collect()
}

/// Full window frames, wheel scrolls of the field column and drag moves over the rows.
#[gpui::test]
#[ignore = "timing harness; run by hand with --ignored --nocapture"]
fn edit_mode_frame_times_with_60_fields(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = super::tests::open(dir.path(), cx);
    big_item(&state, &mut vcx);
    let keys = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
    assert_eq!(keys.len(), 60);

    report("render", frames(&mut vcx));

    let scroll_at = |at: gpui::Point<Pixels>, vcx: &mut VisualTestContext| {
        (0..FRAMES)
            .map(|i| {
                let dy = if i % 2 == 0 { -40. } else { 40. };
                let t = Instant::now();
                vcx.simulate_event(ScrollEvent {
                    position: at,
                    delta: ScrollDelta::Pixels(point(px(0.), px(dy))),
                    ..Default::default()
                });
                t.elapsed()
            })
            .collect::<Vec<_>>()
    };
    let column = vcx.debug_bounds("editor-scroll").unwrap();
    // Over the rows: each step moves another row under the pointer, whose hover shows
    // its ↑/↓ (a second, synchronous frame on the test platform; on screen it lands in
    // the next frame the scroll draws anyway).
    report("scroll", scroll_at(column.center(), &mut vcx));
    // In the column's side padding: the scroll frame alone.
    let gutter = point(column.left() + px(4.), column.center().y);
    report("scroll-pad", scroll_at(gutter, &mut vcx));

    let none = Modifiers::none();
    let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
    let grip = vcx
        .debug_bounds(leak(format!("grip {}", keys[0])))
        .unwrap()
        .center();
    vcx.simulate_mouse_down(grip, MouseButton::Left, none);
    vcx.simulate_mouse_move(grip + point(px(0.), px(6.)), MouseButton::Left, none);
    vcx.run_until_parked();
    let rows: Vec<_> = (1..4)
        .map(|i| {
            vcx.debug_bounds(leak(format!("edit-row {}", keys[i])))
                .unwrap()
        })
        .collect();
    let moves = (0..FRAMES)
        .map(|i| {
            let b = rows[i % rows.len()];
            let frac = if i % 2 == 0 { 0.25 } else { 0.75 };
            let p = point(b.center().x, b.top() + b.size.height * frac);
            let t = Instant::now();
            vcx.simulate_mouse_move(p, MouseButton::Left, none);
            t.elapsed()
        })
        .collect();
    report("drag-move", moves);
    vcx.simulate_mouse_up(grip, MouseButton::Left, none);
    vcx.run_until_parked();
    state.update(&mut vcx, |s, cx| s.cancel_edit(cx));
    vcx.run_until_parked();
    // For comparison: the same item in read mode.
    report("read-mode", frames(&mut vcx));
}
