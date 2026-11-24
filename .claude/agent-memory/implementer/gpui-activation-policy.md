---
name: gpui-activation-policy
description: Dock/activation policy in vault-app goes through gpui App::set_activation_policy; gpui-pre-macos caches the policy and re-applies it in did_finish_launching; test platform ignores it (thread_local recorder in state/prefs.rs tests)
metadata:
  type: project
---
- Bundle is `LSUIElement = true` (scripts/Info.plist, 04 §5b). Without it Launch Services re-registers the app as foreground (Dock icon back) when reopened from Finder while accessory.
- `state::set_dock_icon(show, cx)` (state/prefs.rs) -> `cx.set_activation_policy(dock_policy(show))`; never call `vault_macos::set_dock_icon_visible` from the app: gpui-pre-macos caches `activation_policy` and re-applies it in `did_finish_launching` (sets cached policy, THEN calls our run callback) and in `request_windowing`. App never calls request_windowing/with_windowing.
- gpui `with_windowing(Headless)` would apply Accessory before the run loop (no Regular step at launch) but marks the app "headless" for `graphical_environment()`; not used.
- gpui TestPlatform's `set_activation_policy` is a no-op with no getter, so prefs.rs tests use a `#[cfg(test)]` thread_local recorder (`tests::take_applied_policies`). `reopen_main_window` re-asserts Accessory when show_in_dock is off.
- Crate-root private items in main.rs (`RunningVault`, `reopen_main_window`) are reachable from any module's tests.

**Why:** owner bug 2026-11-08, Dock icon returned on reopen from Finder.
**How to apply:** any Dock/menu-bar visibility work in vault-app; LSUIElement only applies to a packaged .app, not `cargo run`.

- Login launch (2026-11-10, 05 §2.5): main.rs skips open_main_window/activate/apply_main_min_size when `status_item::start_in_background(launched_as_login_item(), show_in_dock)`; no AppState field. autolock::install lives in VaultRoot::new, so it only runs once a window exists (fine: vault is locked). Test `background_start_opens_the_window_from_the_padlock` covers reopen with no MainWindow global.
- Hide Vault (2026-11-24, 04 §5c / 05 §2.5): status item's first menu item is "Hide Vault" while a main window exists. Detection in vault-app status_item.rs: `cx.observe_new::<VaultRoot>` + `cx.defer` (window not in `cx.windows()` while its root is being built) and `cx.on_window_closed` (fires from `remove_window` in gpui's update trail, also on TestPlatform, AFTER the window left `cx.windows()`, and BEFORE state observers flush, so SetWindowShown(false) logs before SetLocked(true)). Close path shared via `actions::close_window` / `close_main_window` (prepare_to_close = save geometry + lock; `remove_window` does NOT run on_window_should_close). `MenuBarItem.shown` survives reinstall.
- Sandboxed `cargo test -p vault-macos` can hang past 10 min (Keychain/Touch ID tests); it needs to run outside the sandbox.
- Sandbox gotchas (2026-11-24): harness=false AppKit test binaries exit 0 with NO output inside the sandbox (no WindowServer), so a sandboxed pass proves nothing; vault-app tests opening_a_window_releases_the_held_toast, status_item_failure_without_a_window_reverts_only, first_frame_after_unlock_is_at_rest_when_collapsed hang >60 s in the sandbox even at HEAD (checked via `git archive HEAD` copy sharing CARGO_TARGET_DIR); touch_id/sync tests fail there too.
