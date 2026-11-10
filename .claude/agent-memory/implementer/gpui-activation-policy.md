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
