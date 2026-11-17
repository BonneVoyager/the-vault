---
name: gpui-perf-and-test-timing
description: Verified gpui-pre 0.3.10 / gpui-component 0.8.1 facts for frame cost in tests, drag refresh, edit-mode frames, where vault-app test-suite wall time goes (stale deps .o, FSEvents, opt deps), and why the cursor audit is slow (InputRateTracker)
metadata:
  type: reference
---

Verified 2026-11-15 against gpui-pre =0.3.10, gpui-component =0.8.1.

**Timing frames in tests**
- In test mode `App::flush_effects` draws every dirty window synchronously (app.rs ~2157), so
  `vcx.update(|w, _| w.refresh())` and `vcx.simulate_mouse_move/simulate_event(ScrollEvent{..})`
  each time one full window frame. `ScrollEvent` derives Default; `ScrollDelta::Pixels(point(..))`.
- `debug_selector` / `vcx.debug_bounds` need debug assertions: for optimised timing use
  `CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true CARGO_TARGET_DIR=target/perf cargo test --release`.
- Calling `Render::render` directly outside a draw panics (`Window::current_view` unwrap,
  window.rs ~5370). `VisualTestContext::draw` refreshes the window afterwards, so timing it also
  counts a full window frame (double count).
- Harness: `crates/vault-app/src/screens/main/editor_perf_tests.rs` (#[ignore]).

**Drag re-render is unavoidable app-side**
- During an active drag, every MouseMove calls `window.refresh()` (window.rs ~6013), which sets
  `refreshing = true`; cached views are reused only when `!window.refreshing` (view.rs:551).
  So every view re-renders on each drag move; an overlay entity / `.cached()` view does not help.

**What costs what (60 fields, opt build, ~15.6 ms frame vs 4.6 ms read mode)**
- Editor `render()` itself ~1 ms; the rest is layout/prepaint/paint of row widgets.
- 180 gpui-component `Button`s (↑/↓/remove) ~5 ms; value inputs ~4 ms; field icon popover
  button ~2.5 ms; name inputs ~2 ms. Button is heavy per instance (keyed focus-handle state,
  styling). Only fewer rendered rows (virtualisation) gets under 8 ms. See [[editor-virtualisation]].

**Hover-gated controls (2026-11-15, edit rows)**
- Rendering ↑/↓ only on the hovered/focused row (60 rows, 120 fewer Buttons) took the 60-field
  edit frame from ~15.9 to ~13.2 ms median (render and drag-move); runs vary ±2 ms, so run the
  harness 2-3 times. Read mode ~4.6 ms.
- `on_hover` also fires for layout-driven transitions (checked at paint, `window.defer`), so a
  wheel scroll under a stationary pointer changes the hovered row; the hover notify costs a SECOND
  synchronous frame in tests (harness "scroll" ~26.5 ms vs "scroll-pad" ~13.5 ms with the pointer
  in the column padding). On screen it lands in the next frame the scroll draws anyway.
- The cursor audit's inspector scan (scroll-event picking inside one `vcx.update`) never produces
  hover, and `simulate_mouse_move` before the scan does not survive it either: hover-only controls
  need a test switch (vault: `screens::show_all_arrows_for_tests`, thread-local) to be audited.

**Timed visual effects testable with the fake clock (2026-11-16, move flash)**
- Pattern: `with_animation((name, generation), ..)` for the visual fade (real time, keyed so
  re-renders do not replay it) + a `cx.spawn` `background_executor().timer(len)` that removes the
  element at the end (generation-checked; storing the Task cancels the previous one). Tests drive
  the end with `vcx.executor().advance_clock(..)`; only assert colour ranges at the start
  (0 < a <= max), never mid-fade values. Reduce Motion variant: plain solid `.bg`, same timer.
- "No redraws after" check: a `#[cfg(test)] renders` counter in the view. The open() harness has
  its own periodic re-renders (~2/s from app ticks), so compare against a baseline window taken
  before the effect, not against zero. Animation frames (`request_animation_frame`) are never
  delivered on the test platform, so this only catches notify loops.
- Frame-leak check: `vcx.update(|w, cx| w.simulate_next_frame(cx))` (test-support, returns how many
  `on_next_frame` callbacks ran) delivers one frame; call once, `run_until_parked`, call again and
  assert the second returns 0 (vault: editor_row_tests `assert_no_frame_loop`).

**Test-suite wall time (measured 2026-11-17, 546 vault-app tests, 10-core Mac)**
- Root cause of 600-930 s runs: `target/debug/deps` held 588k files (90 GB) of stale `*.o`.
  macOS dev builds keep per-CGU objects (split-debuginfo unpacked); every incremental rebuild of
  the vault_app test or bin adds ~256 new `.o` names and nothing removes them. Any process whose
  executable sits in a huge directory pays an O(entries) scan: launch ~2.9 s (CFBundleGetMainBundle
  readdir at NSView +initialize) and EVERY `FSEventStreamStart` ~2.5-9.5 s (fseventsd side, serialised
  across tests, so parallelism did nothing: 707 s wall, 447 s CPU). Same binary copied to a clean dir:
  watcher start 0.7 ms, suite 68.6 s. `debug = false` on the package stops the accumulation;
  `line-tables-only` does not. Check `ls target/debug/deps | wc -l` first when tests get slow.
- gpui::test has no global lock: TestPlatform uses NoopTextSystem, asset source `()` (no
  AllAssets/fonts in tests). Fixed cost: empty test ~1 ms, init+window ~3 ms, KdfParams::for_tests
  vault create ~66 ms (debug argon2), full MainScreen harness ~95 ms. 1/4/10 threads scale 9.9/2.9/2.0 s.
- `--config 'profile.dev.package."*".opt-level=1'`: suite 68.6 -> 24 s (O2 same, builds 40 s slower);
  clean build 71 -> 135 s. cursor_audit (25 tests) is 72% of test CPU; edit_icon_picker 56 s alone
  in debug, 10 s with opt deps. state::sync busy_save test waits a real 10 s lock timeout.
- libtest `--report-time` works on stable with `RUSTC_BOOTSTRAP=1 <bin> -Z unstable-options --report-time`.

**Cursor-audit cost (measured 2026-11-17, deps opt-level 1)**
- ~97% of each audit test is `scan`'s grid. Half the CPU is gpui's `InputRateTracker::record_input`
  (window.rs ~1346): every dispatched event that refreshes the window (an inspector pick change
  does) pushes an `Instant` and `retain`s the Vec over the last 100 ms -> O(events in 100 ms) per
  event, ~13 of ~15 us per scroll. Not reachable app-side (pub(crate), no phase trick); the fix is
  upstream (VecDeque + pop_front). The other half: one full window draw per newly seen element
  (~4.5 ms in edit/icon-picker screens). Hit-test lists are private, so dedupe of grid points by
  "same element" is NOT provably equivalent.
- Cheap wins taken: click via `vcx.debug_bounds` (add-field, sort have selectors) instead of a
  step-24 find scan; click from the previous audit's hits when the frame is unchanged; one audit
  per test so the two icon-picker states scan in parallel.
- Full suite from `target/debug/deps` ~25 s vs the same binary copied to /tmp ~16 s (deps dir had
  15.7k entries): the directory-size launch/FSEvents cost still dominates the post-audit tail.
- Profile with `sample <pid> 3 -f out.txt` (no samply/perf installed); read "Sort by top of stack".
