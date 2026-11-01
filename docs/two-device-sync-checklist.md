# Two-device sync checklist (manual)

One person, two Macs (A and B), one vault package shared through iCloud Drive (pass 1) and again through Dropbox (pass 2). Tick the box per step. Citations in parentheses point to `specs/03-sync.md` (03), `04-macos.md` (04), `05-ui.md` (05) or the app source for the exact string.

What this checklist does not repeat: `scripts/sync-lab.sh` already proves, through the CLI and a fake cloud, the merge rules of 03 §5 (different fields, same field, delete vs edit, rename vs favourite, tag vs icon, field removal, attachment blob order, conflict copies in all four shapes, v1 upgrade, concurrent writers on one package). Scenarios 2 to 7 below repeat a lab case only for what the lab cannot show: the app's edit buffer stamping only the touched attribute on Save, the real provider's delivery, and the toasts. The lab never touches real iCloud/Dropbox, eviction, Touch ID, the Settings tabs or the lock path; those are scenarios 8 to 16.

## 1. Preconditions

- [ ] Both Macs: macOS 15+, same Apple ID (iCloud Drive on) and the same Dropbox account, both signed in and idle (no "syncing" badge).
- [ ] Both Macs: clocks set automatically. Wherever a step says "later", wait at least 10 s so the order is unambiguous (clock skew can flip a true conflict, 03 §5).
- [ ] Build on both: `cargo build --workspace`, then `cargo run -p vault-app` from a Terminal so stderr stays visible (README "Build and run"). The CLI is `cargo run -p vault-cli --` (README "CLI quick example").
- [ ] Pass 1 location: `~/Library/Mobile Documents/com~apple~CloudDocs/` (iCloud Drive in Finder), folder `vault-test`. Pass 2: `~/Dropbox/vault-test` or `~/Library/CloudStorage/Dropbox/vault-test`. Use a throwaway vault and master password of at least 50 bits (05 §2.1).
- [ ] Provider label: on A in the create dialog the hint badge reads "In iCloud Drive: syncs to your other devices" (pass 2: "In Dropbox: ...") (choose.rs, 05 §2.1). After opening, `Cmd+,` then Sync & Backup: the status line reads "Last saved <date> · iCloud Drive · watching for changes" (pass 2: "Dropbox") (settings.rs, 03 §1 provider label). A "Local folder" label means the path rules did not match: stop and fix the location.
- [ ] "Offline" below means Wi-Fi off on that Mac, and "online" means Wi-Fi on and wait for Finder to show no progress badge on the package. "Wait" means up to 2 min for the toast, then check Finder. In the Dropbox pass you may pause Dropbox sync from its menu instead.
- [ ] Reset to a clean synced state (both unlocked, same items) between scenarios unless a step says otherwise.

## 2. Scenarios

### S1 First sync of a new vault

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 1.1 | A | Create new vault `sync1.vault` in the test folder. Add item "Login1" (username, password, URL) and one tag. | Package shows as one item in Finder (UTI). Inside (Show Package Contents): `vault.bin`, `backups/`, no `.vault.bin.tmp-*` left (03 §1, §2). | [ ] |
| 1.2 | A | Wait for the upload badge to clear. | Settings shows a backup row (first save after unlock takes a snapshot) (03 §4). | [ ] |
| 1.3 | B | Wait for the package to appear. `Cmd+O` > Open existing vault, pick it, unlock with the master password. | Unlocks; "Login1" listed with the same fields and tag. Footer reads "created <d> · modified <d> · <device>" with A's device name (05 §2.3). | [ ] |
| 1.4 | B | Settings > Sync & Backup. | Same provider label as A; "watching for changes" (settings.rs). | [ ] |
| 1.5 | B | Add item "Login2", wait 5 s. | A (unlocked) lists "Login2" and shows the toast "Vault updated from another device" (sync.rs, 03 §3 step 6, 05 §3). | [ ] |
| 1.6 | A, B | `shasum <pkg>/vault.bin` on both after both idle. | Identical hashes (convergence, 03 §3 step 6e, §5). | [ ] |

### S2 Concurrent edits to different fields

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 2.1 | A, B | Both unlocked, "Login1" visible. Both go offline. | n/a | [ ] |
| 2.2 | A | Edit Username to `alice`, Save (`Cmd+S`). | Saved locally. | [ ] |
| 2.3 | B | Edit URL to `https://example.org`, Save. | Saved locally. | [ ] |
| 2.4 | A, B | Both online, Wait. | Both show `alice` and the new URL; each saw "Vault updated from another device" (03 §5 field merge by id; sync.rs). | [ ] |
| 2.5 | A, B | Compare `vault.bin` hashes when idle. | Identical (03 §5: idempotent, converges in two rounds). | [ ] |

### S3 Concurrent edit of the same field, history check

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 3.1 | A, B | Both offline. Note the current Password P0 (reveal with `Cmd+Shift+R`). | n/a | [ ] |
| 3.2 | A | Set Password to `from-A-1`, Save. | Saved. | [ ] |
| 3.3 | B | Wait 10 s. Set Password to `from-B-2`, Save. | Saved. | [ ] |
| 3.4 | A, B | Both online, Wait, reveal Password on both. | Both show `from-B-2`: greater `modified_at` wins whole (03 §5 field table). | [ ] |
| 3.5 | A, B | Open the password history disclosure on both. | `from-A-1` is in the list (the losing value is kept for password fields, 03 §5 clock skew paragraph); lines read "Password · replaced <date> (<relative>)" (detail.rs). Both devices list the same entries (union, cap 10, 03 §5). | [ ] |
| 3.6 | A | Reverse the roles once: B edits first, A edits 10 s later. | Now A's value wins on both. | [ ] |

### S4 Delete on A vs edit on B, both orders

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 4.1 | A, B | Order 1. Both offline. A deletes "Login2". Wait 10 s. B edits "Login2" (change Username), Save. | Local only. | [ ] |
| 4.2 | A, B | Both online, Wait. | "Login2" is present on both with B's edit: the edit is later than the delete, so the live item wins (03 §5 item table; 03 §9). | [ ] |
| 4.3 | A, B | Order 2. Both offline. B edits "Login2" (Username), Save. Wait 10 s. A deletes it. | Local only. | [ ] |
| 4.4 | A, B | Both online, Wait. | "Login2" is gone on both (tombstone wins when `deleted_at >= modified_at`, 03 §5). | [ ] |
| 4.5 | A, B | Open Settings > Sync & Backup on both. | A backup exists from the item-count decrease (03 §4). | [ ] |

### S5 Rename on A, favourite on B

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 5.1 | A, B | Both offline. A renames "Login1" to "Login1 renamed", Save. B stars it. | Local only. | [ ] |
| 5.2 | A, B | Both online, Wait. | Both show the new title and the star: per-attribute stamps, so neither attribute is lost (03 §5 item table, 2026-10-31). | [ ] |

### S6 Tag reorder on A vs icon change on B

The UI has no reorder control; "reorder" here means remove a tag chip and re-add it so it lands last (05 §2.3 edit mode, insertion order). Give "Login1" tags `one`, `two` first.

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 6.1 | A, B | Both offline. A edit mode: remove `one` with the x, add `one` again, Save. B edit mode: header tile > pick a symbol and a colour, Save. | Local only. | [ ] |
| 6.2 | A, B | Both online, Wait. | Both show tags in order `two`, `one` and B's icon; a reorder counts as a tag change and the icon is its own stamp, so both survive (03 §5). | [ ] |

### S7 Attachment added on A, opened on B (NotDownloaded then Present)

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 7.1 | A | Add file (a 20 MB file, so the blob lags the vault) to "Login1" via "Add file...". | Attachment row with name and size; blob written in `<pkg>/attachments/<id hex>.bin` (03 §1.1, 05 §2.3). | [ ] |
| 7.2 | B | Select "Login1" as soon as the vault update toast shows, before the blob finishes downloading (Finder shows progress on the blob). | Row state reads "Not downloaded yet" (or "Missing" while the blob has not arrived at all); the item itself opens normally (03 §1.1, attachments.rs). | [ ] |
| 7.3 | B | When Finder shows the blob complete, re-select the item. | The state label disappears (Present). Record whether the row updated without re-selecting. | [ ] |
| 7.4 | B | Preview (image or text) or "Save decrypted copy...". | Content matches the original; save shows the confirm "This writes an unencrypted copy to disk." (05 §2.3). | [ ] |
| 7.5 | A | Remove the attachment, Save. B waits. | B's row disappears (a removal tombstone survives merge, 03 §5). The blob is not deleted before 24 h (orphan grace, 03 §1.1): `attachments/` still holds it. | [ ] |

### S8 Eviction (iCloud pass only)

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 8.1 | B | Quit the app. In Finder, right-click the package > Show Package Contents, right-click `attachments/<id>.bin` (S7's blob, re-add it first if needed) > Remove Download. | The file shows the cloud icon (placeholder). | [ ] |
| 8.2 | B | Open the app, unlock, select "Login1". | Attachment row "Not downloaded yet"; the item and every other field work (03 §1.1, 04 §4). | [ ] |
| 8.3 | B | Preview the attachment. | Download starts and the content appears, or the row stays "Not downloaded yet" if it times out; no crash, no error blocking the item. Record which. | [ ] |
| 8.4 | B | Lock (`Cmd+L`). Remove Download on `vault.bin` itself. Unlock with the password. | Unlock works: the file is downloaded before it is read (03 §7, 04 §4). While waiting the unlock screen shows "Unlocking...". | [ ] |
| 8.5 | B | While unlocked, go offline, Remove Download on `vault.bin`, then have A change a field and wait for it to arrive online later. Stay offline 40 s. | After the 30 s download timeout the banner "Waiting for iCloud to download the vault..." appears; the in-memory vault stays usable (03 §7, sync_banners.rs). | [ ] |
| 8.6 | B | Go online. | The banner clears on the next successful poll or save, and A's change merges in with "Vault updated from another device" (03 §7 "retries on the next watcher event"; sync.rs). | [ ] |
| 8.7 | B | Dropbox pass: set `vault.bin` to Online only (Smart Sync), then edit on A. | No banner; B merges normally (04 §4: handled by the file provider). | [ ] |

### S9 Whole-package conflict copy (iCloud)

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 9.1 | A, B | Both unlocked, both offline. A edits Username of "Login1", B edits URL; both Save and wait 3 s (autosave is 2 s, 03 §8). | Local only. | [ ] |
| 9.2 | A, B | Both online. Look at the parent folder in Finder on both. | Either one vault with merged data (iCloud merged per file), or a sibling `sync1 2.vault` / `sync1 (<host>'s conflicted copy <date>).vault` (03 §6). Record which. | [ ] |
| 9.3 | A or B | If a sibling appeared, leave the app unlocked and Wait. | Toast "Merged a conflicted copy (<name of the copy>)" (sync.rs, 03 §6 step 5). The sibling is gone from the folder. | [ ] |
| 9.4 | A or B | Settings > Sync & Backup. | A backup row tagged "Conflict copy"; on disk `backups/conflict-<timestamp>-<original name>/` (03 §6 step 4, settings.rs). Both edits present in the item. | [ ] |
| 9.5 | the other | Wait. | Receives the merged `vault.bin` and the conflict package inside `backups/`; shows "Vault updated from another device" (03 §3). | [ ] |
| 9.6 | A, B | If no sibling appeared in 9.2, repeat 9.1 up to three times varying timing. | A sibling appearing is the goal; if it never does, record "not reproduced". | [ ] |

### S10 Per-file conflict copy (Dropbox pass only)

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 10.1 | A, B | As 9.1 with the package in Dropbox. | Local only. | [ ] |
| 10.2 | A, B | Both online. Show Package Contents. | `vault.bin` plus possibly `vault (<host>'s conflicted copy <date>).bin` (03 §6). | [ ] |
| 10.3 | A or B | Wait with the app unlocked. | Toast "Merged a conflicted copy (<file name>)"; the copy is gone from the package top level (sync.rs). | [ ] |
| 10.4 | A or B | Settings > Sync & Backup; Finder. | Row tagged "Conflict copy"; file `backups/conflict-<timestamp>-vault (...).vault.bin` (03 §6 step 4). Never deleted, only moved (03 §6). Both edits present. | [ ] |
| 10.5 | the other | Wait. | Converges; hashes of `vault.bin` equal. | [ ] |

### S11 Password change on A, unlock on B

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 11.1 | A | Settings > Security > change master password (meets the 50-bit minimum, 05 §2.5). Wait. | Success. | [ ] |
| 11.2 | B | Unlocked and idle during the change. | No prompt and no banner: the vault key is unchanged, B keeps working with its cached key (03 §5 header merge). If B shows "This vault was re-keyed on another device. Enter the master password to continue." instead, record it (that is the KeyMismatch path, 03 §8 `KeyMismatch`). | [ ] |
| 11.3 | B | Make an edit, wait 5 s, lock. Unlock with the OLD password. | Wrong password: field shakes, inline error (05 §2.2). | [ ] |
| 11.4 | B | Unlock with the NEW password. | Unlocks; B's edit and A's data are present (03 §5 header merge keeps the newer slot set on both sides). | [ ] |
| 11.5 | A | Edit something, wait. | B merges it; hashes converge. | [ ] |

### S12 Touch ID re-check after a merge replaces the slots

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 12.1 | B | Settings > Security > enable "Unlock with Touch ID". | Enabled. | [ ] |
| 12.2 | A | Change the master password again, Wait. | n/a | [ ] |
| 12.3 | B | Unlocked: wait for the merge. | Toast "Another device changed this vault's keys, so Touch ID must be set up again in Settings > Security." (touch_id.rs `SLOT_GONE`, 03 §5 header merge). | [ ] |
| 12.4 | B | Settings > Security. | Touch ID off; caption "Touch ID must be set up again." (security.rs). | [ ] |
| 12.5 | B | Lock. | Unlock screen offers only the password; Touch ID does not unlock. | [ ] |
| 12.6 | B | Repeat 12.1, then absorb a conflict copy (S9 or S10) that replaces the slots, if reproducible. | Same toast after "Merged a conflicted copy (...)" (sync.rs recheck after ConflictAbsorbed). | [ ] |

### S13 Backups visible in Settings

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 13.1 | A | Lock, unlock, edit one field, wait 3 s. | A new snapshot row appears (first save after unlock, 03 §4). | [ ] |
| 13.2 | A | Edit again within the hour. | No new snapshot (03 §4: one per hour). | [ ] |
| 13.3 | A | Delete an item. | An extra snapshot (item count decreased, 03 §4). | [ ] |
| 13.4 | A | "Back up now". | Toast "Backed up to <file name>" and a new row (sync.rs). | [ ] |
| 13.5 | B | Settings > Sync & Backup. | A's snapshots are listed too, because `backups/` lives in the synced package (03 §1). Same-second names get `-2`, `-3` suffixes (03 §4). | [ ] |
| 13.6 | A | Open one row, then Delete it (trash > "Delete this backup?" > Delete). | Row vanishes on A; the file disappears from `backups/` on B after sync. | [ ] |
| 13.7 | A | Inspect the "Conflict copy" and "Unsaved edits" rows from S9, S10, S15. | They are never pruned by retention (03 §8). Pruning of old snapshots (24 h, 30 d, 12 w) cannot be observed in one session; the unit tests cover it (03 §9). | [ ] |

### S14 Changes arriving while locked (ChangedWhileLocked)

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 14.1 | B | Lock (`Cmd+L`) and leave the app on the unlock screen. | n/a | [ ] |
| 14.2 | A | Edit "Login1" title and add an item; wait for upload. | n/a | [ ] |
| 14.3 | B | Watch the unlock screen for 30 s. | No toast and no change (the event has no UI, sync.rs; 03 §3 step 5). | [ ] |
| 14.4 | B | Unlock with the password. | The list shows A's title and new item immediately: the on-disk version is what opens (03 §3 step 5). Note whether a toast appears. | [ ] |
| 14.5 | B | Check Settings > Sync & Backup. | Nothing lost; no "Conflict copy" or "Unsaved edits" rows added by this step. | [ ] |

### S15 "Unsaved" backup after a lock-time save timeout

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 15.1 | A | In Terminal hold the save lock for 60 s: `python3 -c 'import fcntl,time;f=open("<pkg>/.lock","a");fcntl.flock(f,fcntl.LOCK_EX);time.sleep(60)'` | Lock held (03 §2). | [ ] |
| 15.2 | A | Within that minute edit a field and Save or wait for autosave. | The UI may freeze up to 10 s, then the toast "Another process is writing this vault. Try again in a moment." (sync.rs `SAVE_BUSY`, 03 §2). | [ ] |
| 15.3 | A | Lock (`Cmd+L`) while the lock is still held. | Toast "Could not save before locking (<error>). Unsaved changes were kept in the backups folder." (state.rs `LOCK_KEPT`, 03 §8 `Snapshotted`). If instead "Could not save or back up your unsaved changes before locking." appears, record it as a fail (`Unpreserved`). | [ ] |
| 15.4 | A | After the 60 s, unlock, open Settings > Sync & Backup. | A row tagged "Unsaved edits" with a `-unsaved` file in `backups/` (03 §4, settings.rs). The edit is not in the vault; "Open" on the row shows it. | [ ] |
| 15.5 | B | Wait. | B receives the backup file and never merges it into the vault; the row appears on B too and is not pruned (03 §8). | [ ] |

### S16 Remote change while editing

| # | Dev | Action | Expected | Pass |
|---|---|---|---|---|
| 16.1 | B | Open "Login1" in edit mode and change Username to `b-edit` without saving. | Dirty edit buffer. | [ ] |
| 16.2 | A | Change the same item's Username to `a-edit`, Save. | n/a | [ ] |
| 16.3 | B | Watch the edit form. | No discard dialog; toast "Vault updated from another device"; the Username row shows the badge "changed remotely - your edit will win on save" (editor.rs `REMOTE_BADGE`, 03 §3 dirty paragraph, 05 §3). | [ ] |
| 16.4 | B | Save. Wait. | `b-edit` on both (the later edit wins, 03 §5). | [ ] |

## 3. Pass 2 (Dropbox)

Move the vault to a fresh Dropbox folder (new vault, do not copy the iCloud one) and repeat S1 to S7, S10 (replaces S9), S11 to S16, and step 8.7 (skip 8.1 to 8.6). Provider label must read "Dropbox" in step 1.4.

## 4. What to collect when a step fails

- Terminal stderr of the app on both Macs (`vault: ...` lines, `backup taken: <path>`); start with `RUST_LOG=debug` for more.
- Screenshot of the toast or banner and of Settings > Sync & Backup.
- The whole package, copied before touching it (`cp -R`): `vault.bin`, `backups/` (snapshots, `-unsaved`, `conflict-*`), `attachments/`, and any sibling `* 2.vault` or `vault (... conflicted copy ...).bin` still unabsorbed. Note the `ls -l@` and `shasum vault.bin` per Mac.
- Inspect each side from the COPY (the CLI saves and merges when it runs `sync`; never run it on the live package): `export VAULT_FILE=<copy>`; `cargo run -p vault-cli -- list`; `cargo run -p vault-cli -- get "<title>" --ids --reveal` (add `--password-env VAR` to skip the prompt). Diff A's and B's output; field ids show which side holds which field.
- To see what the merge would do: `cargo run -p vault-cli -- sync` on the copy (prints the events and "synced: N conflict copies absorbed"; a problem line plus "not converged" is a fail).
- The Mac names, the exact wall-clock time of each edit, and whether Wi-Fi was off, so clock-order questions can be answered.
