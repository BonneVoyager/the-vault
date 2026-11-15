# PROGRESS

Current state is the last **CHECKPOINT** section; everything above it is history. The full log up to 2026-11-08 is archived verbatim in `docs/progress-history.md`; the condensed history below keeps only decisions, rules and open items. Entry format since then: one dated `###` section per wave, one line per package.

## History (condensed, 2026-10-28 → 2026-11-08)

Phases 1–5 shipped 2026-10-29 (core, CLI, app skeleton, sync, macOS, polish). All later work is waves on the shipped product; the owner commits after each checkpoint.

**Decisions in force** (owner's, with the date):
- 2026-10-29: macOS 15 minimum; attachments per-file key, 100 MB cap, 1 MiB chunks, **not backed up** (restored backups may reference missing blobs); passkey/PRF unlock parked until an rp_id domain exists; signing waits on a Developer ID.
- 2026-10-30: vault is a package `<name>.vault/{vault.bin, attachments/, backups/}`, no migration; categories removed, New = Templates (field presets + one tag); `number` kind removed; item detail windows kept; external bug hunt and Daybreak static scan triaged and fixed.
- 2026-10-31: item icons (auto brand logo, symbol+colour, custom image via hidden attachment); sidebar collapses Apple Passwords-style, no Settings/Lock buttons in the window; detail rows macOS-Passwords style; created date; sections as a field kind; field identity by id (duplicate and empty names allowed; format v2, auto-upgrade on password unlock, Touch ID re-enrol once); Markdown notes (images never load); per-attribute stamps for title/favorite/tags/icon; instant item switch; sync lab script; CI skipped, checks run manually.
- 2026-11-01: proptest merge laws restated to match 03 §5 (convergence in N rounds, one-sided +1); attachment tombstone cap merge-only; WaitingForBlobs sync event; NFC name comparison; Touch ID domain state via `LADomainState`; two-device sync checklist in docs; attachment-blob retention deferred; hardening wave after bug hunt 2026-11-01.
- 2026-11-03: Recently Deleted (trash) with restore and empty; 2026-11-04: unlock and window polish.
- 2026-11-06: external security review responses fixed; dist profile; unlock wheel as a frame strip (Codex); unlock success finish option A (snap stop + keyhole release); 1 MiB input cap in the editor; bug hunt 2026-11-06 fixes.
- 2026-11-07: hold-⌥ reveal in item windows; save-blocked strip and before-write sweep hook; Settings gating; ⌘1–⌘9 select sidebar rows; one shared menu popover for all main-window menus; menu key equivalents rule (focus-scoped shortcuts get unbound menu actions); field icons.
- 2026-11-08: item list is a Tab stop; field drag-to-reorder option A; Show Vault in Dock toggle (accessory policy) with menu bar padlock status item; Dock relaunch fix; bug hunt 2026-11-08 (`docs/qa/bug-hunt-2026-11-08.md`).

**Routing in force**: crypto/format/merge → crypto-implementer (Fable); vault-sync, vault-macos, non-UI app logic → implementer (Opus); vault-app → gpui-implementer (Opus); CLI, scripts, fixtures, docs → routine-implementer; checks → test-runner; vault-core/vault-macos reviews → security-reviewer (Fable); other reviews → code-reviewer (Opus); bug-hunter manual only, never automatic. Spec/README/docs sync is the orchestrator's housekeeping.

**Tools**: `cargo test --workspace`; `qa/spec-checks` (bug-hunter's regression ledger: `cargo test --no-fail-fast` inside it plus `cli/run_all.sh`); `scripts/sync-lab.sh` (18 scenarios, `--random --seed N --steps M`); `docs/two-device-sync-checklist.md` (manual, owner); `scripts/check-entitlements.sh`.

**Open list** (owner's call, carried forward): attachment-blob retention while a backup references them (deferred); CI (skipped by decision); passkey unlock (needs rp_id domain); signing and notarisation (needs Developer ID); two-Mac checklist run (owner); `map_la` folds BiometryNotAvailable into BiometryChanged; qa/spec-checks not rustfmt-clean; reference-style Markdown links; saves off the main thread; testing roadmap items in 00 (fuzzing, multi-device simulation, cargo-mutants, traceability, golden screenshots). Dropped by the owner 2026-11-13/15: About licenses, status item tooltip, secret-sharing feature (researched only, nothing in specs or code).

## Waves since the last archived checkpoint

### 2026-11-08 — Bug-hunt decisions: field order and concurrent CLI edits
- Owner decisions on the two notes from `docs/qa/bug-hunt-2026-11-08.md`: (a) concurrent CLI edits of one item stay last-writer-wins per attribute; callers serialise (03 §5, 00 overview). (b) field order travels with the item winner and has no stamp; a reorder alone propagates, a later edit of the same item on another device wins the order (03 §5 "Field order", 05 §2.5). Both already matched the code; spec only.
- vault-core tests pinning (b): `reorder_loses_to_a_later_edit_on_another_device`, `reorder_alone_propagates` in `tests/merge.rs` (+70 lines, no production change). `cargo test -p vault-core --test merge` 18 passed; fmt and clippy clean.
- Checkpoint: spec and test only, no UI. Nothing to eye-check. Bug hunt: run for this wave (2026-11-08; these decisions close its two open notes).

### 2026-11-10 — Launch at login starts in the background when the Dock icon is off (owner decision, option A)
- vault-macos `login_launch.rs`: `launched_as_login_item()` reads the current Apple Event (`oapp`, `prdt` = `lgit`) via safe objc2, main thread only, false otherwise (04 §5d). Features NSAppleEventManager, NSAppleEventDescriptor, objc2-core-services; no new crates. Main-thread test `tests/login_launch.rs`.
- vault-app: `status_item::start_in_background(login_launch, show_in_dock)`; a background start opens no window and does not activate, still opens the remembered vault and installs the padlock; the padlock, Finder or Spotlight opens the window via `reopen_main_window`. `apply_dock_icon` activates only when a window exists (review note). Settings: `LOGIN_HINT` "Starts in the menu bar when the Dock icon is off." under Launch at login, shared `hinted_row` with the Dock row (05 §2.5).
- Reviews: security-reviewer SHIP (no unsafe, forgery only skips the window); code-reviewer SHIP after the activate guard. Fallback when the padlock cannot be installed in a background start: setting reverts, Dock icon returns, toast is lost (no window), Dock click opens the window; spec'd.
- Checks: fmt, clippy clean; vault-macos 33 lib tests; vault-app full suite rerun after the follow-ups: 493 passed, 0 failed.
- Checkpoint: eye check pending. Bug hunt: not yet run for this wave.

### 2026-11-12 — Low-hanging wave: held toasts, live menus, Help sheet, Copy diagnostics, add-field focus (committed e392ae9)
- Toasts shown with no main window are held and get a full TTL when a window opens (05 §3 "Toasts without a window"); lock clears ordinary toasts; residual: toasts set from background results without an app context are not held. Menu bar follows state through an app-level observer (`actions::follow_state_with_menus`), builds on registration; closes the "Settings… after auto-lock with window closed" corner.
- Help ▸ Vault Help and ⌘? (`cmd-?`) open an in-app sheet rendering `docs/help.md` (include_str, notes renderer, tables supported) through a shared `open_sheet` helper with Settings; one sheet slot; locked or unlocked; reopen path when no window. Placeholder toast removed.
- Copy diagnostics button at the bottom of Settings ▸ Security: pure `diagnostics_text(&AppState, now, &Host)`; ordinary clipboard path, no clear timer; toast "Diagnostics copied". vault-macos `host.rs`: `os_version()`, `model_identifier()` (one libc sysctl `unsafe` with SAFETY; 04 §1b). `SyncUi::last_event` records label and time. Leak test covers titles, values, tags, path parts, device and vault ids, and error states.
- Add field focuses the new row's Value (or a Section's title) and scrolls to the bottom (`EditBuffer::focus_row`, `ScrollHandle::scroll_to_bottom`).
- Reviews: toasts/menus FIX FIRST (menus on registration) → fixed; Help/diagnostics FIX FIRST (host facts, error-state leak test) → fixed. App suite 504 then filtered reruns green; full workspace rerun in flight at commit time.
- Owner committed as e392ae9 before this entry was written. Eye checks 1–6 passed (2026-11-12). Owner report: edit-mode header does not stay pinned (spec 05 "Detail header is pinned" amended; fix queued after the notices wave). Bug hunt: not yet run for this wave.

### 2026-11-12 — Password notices per field (owner decision, option A; committed 84ac4d5)
- Spec 05 §2.3 "Password notices": compact strip inside each weak or reused password field's row, under the value, in read mode (detail, item window, backup viewer via shared `field_row`) and edit mode (live from the typed value, item excluded from reuse; backup viewer checks the backup's own items); item-level banner removed. `audit::Issues` per field (`FieldIssue`), `reuse_count`, `value_issues`; list badge dedupes kinds weak first; Reused body "Used by N other items…".
- Review: SHIP; two test gaps (backup reuse against backup items, trash shows no strips) dispatched as tests only. App suite 514 passed; fmt, clippy clean.
- Review test gaps closed: `backup_reuse_is_judged_against_the_backups_own_items`, `trashed_item_shows_no_password_notices`.
- Edit-mode pinned header (spec 05 "Detail header is pinned"): editor root split into a fixed part (icon, title, Save/Cancel, tags row, rule) and the `editor-scroll` fields column (`flex_1().min_h_0()`); drag handlers on the root; test `edit_header_and_tags_stay_pinned_while_fields_scroll`. App suite 517 passed; fmt, clippy clean.
- Pinned header committed as 35e2ee4. Eye checks passed (2026-11-13): notices 1–5 and pinned header 1–4. Bug hunt: not yet run for this wave (covers e392ae9, 84ac4d5, 35e2ee4).

### 2026-11-13 — Light-mode sidebar vibrancy (owner decision, option A)
- Spec 05 §5 "Sidebar vibrancy": light mode opens the main window blurred (`WindowBackgroundAppearance::Blurred`); the sidebar paints `#F5F5F7` at 0.70 alpha while active, solid when inactive; dark mode opaque and unchanged; mode follows appearance changes live. Pure `theme::window_background(dark)` and `theme::sidebar_fill(dark, active)`.
- Root skips its fill on Main; list and detail columns (`list-slot`, `detail-slot`) paint opaque `theme.background`; crossfade gets an opaque underlay that fades out under the sidebar; gpui-component's `Root` fill cleared for the main window only (`ui::main_root`) — found by the new root-fill test, without it no blur showed at all.
- Review FIX FIRST (Reduce Motion render loop from the eagerly built underlay; underlay width mid-slide; root/column fill tests) → all fixed. Tests: `window_background_is_blurred_only_in_light`, `sidebar_fill_is_translucent_only_light_and_active`, `light_sidebar_is_translucent_only_while_active`, `dark_sidebar_stays_opaque`, `reduce_motion_unlock_needs_no_fade_underlay`, `root_fill_is_skipped_on_main_and_back_after_lock`, `light_list_and_detail_columns_paint_opaque_background`. App suite 524 passed; fmt, clippy clean. Diff ~340 lines, mostly tests.
- Owner eye check 1: the active/inactive switch (0.70 translucent vs solid) read as a flash. Owner decision option A: one constant fill, `SIDEBAR_VIBRANCY_ALPHA` 0.88, activation changes nothing; spec amended. Tests `sidebar_fill_is_translucent_only_in_light`, `light_sidebar_fill_ignores_window_activation`. App suite 524 passed; fmt, clippy clean.
- Owner eye check 2 passed for light ("looks quite interesting"); owner decision option A: same in dark mode. Main window opened blurred in both appearances (`ui::main_options`, test `only_the_main_window_is_blurred`); render-time mode switching, `window_background` and the `sidebar_vibrancy` flag removed; `sidebar_fill(dark)` = tint at 0.88 in both. Tests `sidebar_fill_is_translucent_in_both_modes`, `dark_sidebar_fill_is_translucent_and_ignores_activation`, `dark_root_fill_is_skipped_on_main_and_back_after_lock`. App suite 525 passed; fmt, clippy clean. Diff ~390 lines, mostly tests.
- Eye checks passed in both modes (2026-11-13). Bug hunt: not yet run for this wave (covers e392ae9, 84ac4d5, 35e2ee4 and the vibrancy change).

### 2026-11-15 — Server and License templates (owner request; gpui-implementer, code-reviewer SHIP)
- Spec 05 §2.3 "New item" and the sidebar tag-icon list: Server = URL, Username, Password, Notes, `#server`, Lucide `server`; License = Version, License key (password kind), Website, `#license`, Lucide `file-badge`; appended after Identity. No special-casing; Server subtitle is its Username by the existing name lookup, License has none.
- `templates.rs` (+2 variants, `ALL` 6), `assets.rs` (FileBadge registered), tests extended in templates, assets, sidebar; new `template_menu_lists_six_rows_in_order`, `template_picker_offers_server`, `template_picker_offers_license`, `server_subtitle_is_its_username_and_license_has_none`. App suite 529 passed; fmt, clippy clean. Diff ~130 lines.
- Review NOTE: `new-other` absence check in list.rs proves little (harmless); sidebar fixture now has 10 rows so `#work` gets no ⌘ number, per spec.
- Process note: the implementer staged its files (and the already-modified PROGRESS.md and specs/05-ui.md) with `git add`, against the rule; left as found, owner informed.
- Owner dropped the status item tooltip and the share feature research (2026-11-15; no spec or code change for either).
- Owner committed as cdd111a (2026-11-15).

### 2026-11-15 — Bug hunt (bug-hunter) and PROGRESS compaction
- `docs/qa/bug-hunt-2026-11-15.md` against cdd111a: High 0, Medium 0, Low 0. 22 new checks (03 §5 field order with two and three devices, random scripts, both conflict-copy shapes; vault-macos `os_version`/`model_identifier`/`launched_as_login_item` driven directly, new macOS-only path dep in qa/spec-checks; CLI concurrent attribute and `--tag` edits; help.md shortcut table vs 05 §4). Ledger 249/249 debug, 35/35 release, CLI 107/107. Workspace: fmt, clippy clean; 1240 passed, 15 ignored. Code read: diagnostics text prints fixed labels only; sysctl `unsafe` and Apple-event read sound; only the sidebar paints without an opaque fill.
- Notes, not counted (owner's call): (1) License key is a password-kind field, so it gets Weak/Reused notices; (2) diagnostics prints Touch ID/passkey slot lines as yes/no while locked (unreachable: Settings opens only unlocked); (3) the CLI has no Server/License template.
- PROGRESS.md compacted: history to 2026-11-08 archived verbatim in `docs/progress-history.md`; condensed decisions, routing, tools and open list at the top.

## CHECKPOINT — Templates + bug hunt 2026-11-15
Committed: cdd111a (templates). Uncommitted: this compaction (PROGRESS.md, docs/progress-history.md), the hunt artefacts (docs/qa/bug-hunt-2026-11-15.md, qa/spec-checks changes), gpui-implementer agent memory. Index still holds the implementer's stray `git add` of PROGRESS.md and the memory file.
Workspace: fmt PASS, clippy PASS, tests 1240 passed / 15 ignored; QA ledger 249 + CLI 107 green.
Awaiting owner: decision on the License-key notice exemption (note 1); the two-Mac checklist run.
Open list: see the condensed history at the top.
Bug hunt: run for this wave (2026-11-15).
