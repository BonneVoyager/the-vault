# The Vault: security review

| | |
|---|---|
| **Date** | 2026-11-26 |
| **Commit reviewed** | `29ec705` (branch `main`, clean tree) |
| **Scope** | All five crates, the specs, the packaging scripts and the dependency set |
| **Method** | Manual source review in five parallel tracks, targeted reproductions outside the repository, `cargo deny`, `cargo audit`, and a baseline test run |
| **Prepared by** | Claude Code (AI review). This is not an independent professional audit and does not replace one. |
| **Remediation** | Tracked in the Status column of section 3 and in `PROGRESS.md`; moved here from the repository root on 2026-11-26. |

## 1. Verdict

**No way was found for someone without the vault key to read secrets or forge vault content.** The cryptographic design is sound, uses only standard RustCrypto primitives, and is implemented carefully. No Critical or High severity finding was identified.

The weaknesses are in what surrounds the cryptography: integrity and availability against an attacker who can write to the sync folder, the local policy around Touch ID and auto-lock, resource limits in the importers, and release hygiene.

| Severity | Count | Nature |
|---|---|---|
| Critical | 0 | |
| High | 0 | |
| Medium | 5 | One broken integrity guarantee, one data-destruction path, two bypassable local controls, one import denial of service |
| Low | 25 | Hardening, availability, output handling, build hygiene |
| Informational | 14 | Design limits, assurance gaps, documentation accuracy |

### The five things to fix first

1. **M-01: a spliced item record passes the integrity check after a merge.** An attacker with write access to the sync folder can silently revert one item (for example a password change) while everything else stays current. This contradicts the stated guarantee that rolled-back individual items are detected. Reproduced.
2. **M-02: a rolled-back vault file makes the app delete attachment blobs permanently.** Whole-file rollback is an accepted limit, but the app's own orphan cleanup turns it into unrecoverable loss, because attachments have no backup. Reproduced.
3. **M-03: the Touch ID "master password required" rules are stored in an unauthenticated settings file.** A future-dated timestamp disables the after-restart and 7-day rules with a one-line edit.
4. **M-04: auto-lock appears to stop while the icon picker's file dialog is open.** This covers idle lock, lock on sleep, lock on screen lock and the clipboard timer. Traced in code, not yet confirmed at runtime.
5. **M-05: a KeePass file under 1 MB can exhaust memory during import.** The gzip payload is inflated without a bound. Measured.

### What has not been verified

- **Touch ID has never run on real hardware** (I-01). The code matches the spec by reading, but the Secure Enclave path is untested and the packaged app, as configured, most likely cannot use it at all.
- **No signed, notarised build was inspected.** Only an unsigned local bundle exists.
- **The GUI was not run.** M-04 and L-12 depend on runtime behaviour.
- **The fuzzers were read, not run.**

## 2. Scope and method

### What the project is

A native macOS password manager in Rust. A vault is a package directory `<name>.vault/` holding one encrypted file (`vault.bin`), rotating backups and encrypted attachment blobs. The user can put it in any folder, including iCloud Drive or Dropbox; devices converge through a field-level merge. There is no server, no account and no network use.

### Trust boundaries and adversaries

| Adversary | Capability | In the project's threat model |
|---|---|---|
| Thief of a locked or powered-off Mac | Reads all files at rest | Yes |
| Compromised cloud storage account | Reads and writes every file in the sync folder, sees their history | Yes |
| Offline password guesser | Has the vault file | Yes |
| Sender of a hostile file | Gets the user to import a CSV, 1PUX or KDBX file, or pick an image | Implied by the import features |
| Person at the unlocked Mac, or with the login session and an enrolled finger | Uses the UI, edits the user's files | Partly: auto-lock and the Touch ID policy exist for this case |
| Malware running as the user while unlocked | Reads process memory | No, explicitly excluded |

### Review tracks

| Track | Covered |
|---|---|
| `vault-core` format, crypto, key hierarchy, merge, attachments, generator | Read in full, with three reproductions |
| `vault-sync` | Every source file, with five throwaway tests against the real crate |
| `vault-macos` | Every source file, every `unsafe` block, a QR decoding harness |
| `vault-app` | State and policy layer in depth; layout code only where it touches secrets |
| `vault-cli`, importers, export, TOTP, build, packaging, dependencies | Read, with CLI reproductions, importer probes and tool runs |

Each finding is marked **Confirmed** (traced in code, and reproduced where stated) or **Plausible** (traced in code, needs a runtime or hardware check).

### Baseline at this commit

| Check | Result |
|---|---|
| `cargo nextest run -p vault-core -p vault-sync -p vault-cli` | 671 passed, 12 skipped |
| `cargo deny check` | **Fails on advisories** (L-21); bans, licences and sources pass |
| `cargo audit` | 1 vulnerability, 19 warnings (L-21) |
| Repository after review | Unmodified apart from this report |

### Severity scale

Severity is rated against the project's own threat model.

| Level | Meaning |
|---|---|
| Critical | An in-scope attacker without the key reads secrets or forges content |
| High | A stated protection fails with realistic prerequisites and exposes secrets, or the whole vault is lost without recovery |
| Medium | A stated guarantee or control is broken or bypassable by an in-scope attacker, with integrity or availability impact or extra preconditions |
| Low | Hardening gap, limited impact, or needs a position the threat model excludes |
| Informational | Design limit, assurance gap or documentation issue |

## 3. Findings summary

| ID | Severity | Component | Finding | Status |
|---|---|---|---|---|
| M-01 | Medium | vault-core | Spliced item record passes the manifest check after a merge | Confirmed, reproduced. **Fixed 2026-11-26** (symmetric restamp, 02 guarantee 6) |
| M-02 | Medium | vault-sync | Rolled-back vault file causes permanent deletion of attachment blobs | Confirmed, reproduced. **Fixed 2026-11-26** (quarantine under `attachments/orphaned/`, 30-day grace, move-back on reappearance) |
| M-03 | Medium | vault-app | Touch ID policy state is unauthenticated and fails open on a future timestamp | Confirmed. **Partly fixed 2026-11-26** (future timestamp beyond 5 min denied); Keychain-held policy and boot-session id still open |
| M-04 | Medium | vault-app | Lock triggers and clipboard timer stall during the modal icon file panel | Plausible. **Not reproduced 2026-11-26** (owner: screen lock with the icon panel open locked the vault); idle timeout and clipboard timer with the panel open still unchecked |
| M-05 | Medium | importers | KDBX import inflates gzip data without a bound | Confirmed, measured. **Fixed 2026-11-27** (vendored keepass with a 256 MiB inflate cap under `vendor/keepass`, mapped to `TooLarge`; advisory draft in `docs/qa/keepass-rs-advisory-draft.md`, upstream advisory submitted 2026-11-27, PR pending maintainer response) |
| L-01 | Low | vault-core | Edited KDF costs make the correct password read as wrong | Confirmed, measured |
| L-02 | Low | vault-core | Legacy unstamped header: a key-less slot edit is merged and saved | Confirmed, reproduced. **Fixed 2026-11-27** (unstamped peer header never adopted; first save stamps with 1; Touch ID open of an unstamped vault blocks saving until a password unlock) |
| L-03 | Low | vault-core, app | Changing the master password does not revoke an old password | Confirmed (by design) |
| L-04 | Low | vault-sync | Backups are identified by file name only | Confirmed, reproduced. **Fixed 2026-11-27** (header check for listing and the hourly rule; full authentication before any deletion). Residual: a planted name still holds off hourly snapshots for its hour |
| L-05 | Low | vault-sync | Planted entries block all saving; edits are dropped at lock | Confirmed, reproduced |
| L-06 | Low | vault-sync | Unbounded directory work on the save path | Confirmed by reading. **Fixed 2026-11-27** (10,000-entry listing cap, 16 KiB header reads memoised per session, orphan pass only on reference change or daily) |
| L-07 | Low | vault-macos | A malformed QR image aborts the app | Confirmed in a harness. **Fixed 2026-11-26** (`catch_unwind`, seeded reproduction test) |
| L-08 | Low | vault-macos | The QR picker hands any file to ImageIO | Confirmed path |
| L-09 | Low | vault-app | Settings files are world-readable and carry security state | Confirmed. **Fixed 2026-11-26** (0600 files, 0700 directory) |
| L-10 | Low | vault-app | Tag filter survives lock and vault switch | Confirmed. **Fixed 2026-11-26** |
| L-11 | Low | vault-app | File names from the sync folder reach toasts and titles unsanitised | Confirmed. **Fixed 2026-11-26** (sanitised, cut at 60 chars) |
| L-12 | Low | vault-app | Plaintext export starts in `~/Documents` | Confirmed. **Fixed 2026-11-26** (starts in `~/Downloads`; cloud-synced pick asks a second confirm) |
| L-13 | Low | vault-app | Sleep time is not counted toward idle lock when lock-on-sleep is off | Plausible |
| L-14 | Low | importers | 1PUX entry-count and ZIP64 guard can be bypassed | Confirmed, reproduced. **Fixed 2026-11-26** (window widened, count re-checked after open) |
| L-15 | Low | importers | KDBX field de-duplication is quadratic | Confirmed, measured. **Fixed 2026-11-27** |
| L-16 | Low | importers | CSV rows and the 1PUX JSON tree are unbounded in memory | Confirmed, measured. **Fixed 2026-11-27** (100,000 items / 64 MiB imported text; `export.data` 16 MiB). Residual: the 1PUX tree still peaks near 640 MB |
| L-17 | Low | export | The CSV formula guard alters exported secrets | Confirmed. **Fixed 2026-11-27** (password and TOTP cells never guarded or stripped) |
| L-18 | Low | vault-cli | Masked card number writes raw control characters to the terminal | Confirmed, reproduced. **Fixed 2026-11-26** |
| L-19 | Low | vault-cli | A notes value can forge labelled output lines | Confirmed, reproduced. **Fixed 2026-11-26** (continuation lines indented) |
| L-20 | Low | vault-cli, core | `--kdf-test-params` is public and there is no KDF floor | Confirmed, reproduced. **Fixed 2026-11-27** (hidden, needs `VAULT_DEV_KDF=1`; `below_recommended` floor 64 MiB / 3 passes with a CLI warning; app warning not yet) |
| L-21 | Low | build | Dependency gate is failing | Confirmed |
| L-22 | Low | build | Release build is not locked and embeds builder paths | Confirmed. **Fixed 2026-11-27** (`--locked`, deny gate, `--remap-path-prefix`, `VaultGitRevision` in Info.plist); not yet exercised by a release build |
| L-23 | Low | build | Entitlement checker is a deny-list | Confirmed. **Fixed 2026-11-27** (equality with `scripts/entitlements.plist`) |
| L-24 | Low | build | Integer overflow is unchecked in the shipped profile | Confirmed. **Fixed 2026-11-26** |
| L-25 | Low | vault-cli | Export can leave a partial plaintext file | Confirmed by reading. **Fixed 2026-11-27** |
| I-01 to I-14 | Info | various | See section 6 | |

## 4. Medium severity findings

### M-01. Spliced item record passes the manifest check after a merge

**Component:** `vault-core` · **Status:** Confirmed, reproduced · **Location:** `crates/vault-core/src/vault/merge.rs:209-233`

**What the project claims.** The threat model lists "deleted or rolled-back individual items" as detected. `specs/02-core-api.md` guarantee 6 says that replacing an item record with an older record of the same item yields `Tampered(Manifest)`, and the merge code calls that guarantee unconditional.

**What happens.** The manifest binds each item as the pair `(id, modified_at)`. That only detects a rollback if every change of content also changes `modified_at`. The merge enforces this on one side only:

```rust
if merged.modified_at == ours.modified_at {
    merged.modified_at = ours.modified_at.saturating_add(1);
}
```

When the merged result keeps the *peer's* timestamp but differs from the peer's content, no bump is applied. The saved file then carries the peer's `(id, modified_at)` pair with new content, and the peer's earlier record for that item, which sat in the sync folder moments before, is a valid substitute: same id, same timestamp, same key, same AAD.

**Reproduction.** Device O changes a password at time 8. Device T edits the username of the same item at time 10. O merges T's file and saves.

```
O before merge                     item.modified_at=8  fields=[username=alice@1, password=NEW-password@8]
T before merge (file on disk)      item.modified_at=10 fields=[username=alice@example.com@10, password=old-password@1]
O after merge                      item.modified_at=10 fields=[username=alice@example.com@10, password=NEW-password@8]
record stamps: merged file (10), donor file (10)
SPLICED FILE UNLOCKS CLEANLY       item.modified_at=10 fields=[username=alice@example.com@10, password=old-password@1]
```

The last line is O's saved file with one record replaced by the record from T's earlier file. It unlocks with no error and the new password is gone. Source in appendix A.

**Impact.** An attacker with write access to the sync folder, and no key, can revert a single item to a peer's earlier version while every other item stays current. The realistic harm is a silently lost password change, which locks the user out of that account. No secret is disclosed.

**Limits on the attack.**

- It needs a merge of concurrent edits to the same item on two devices, where the merging device holds the older item timestamp.
- The revert persists if the merging device is locked or closed when the splice happens. An unlocked device still holds the new value in memory and writes it back at its next save.
- The same attacker can already replace the whole file with an older copy, which the project accepts. The added power here is selectivity: nothing else in the vault looks stale.
- The same pattern exists where a live item wins over a peer's stripped tombstone with a higher timestamp: the peer's tombstone record can be spliced over the live record.

**Recommendation.** Make the bump symmetric: when the merged item differs from the peer's item and carries the peer's timestamp, stamp it one past that timestamp, exactly as is already done for the local side. Add a regression test built from the reproduction, and re-run the merge property tests (`VAULT_PROPTEST_CASES=500`), since this changes when timestamps move. Two smaller cases share the root cause and deserve a decision: a `created_at`-only difference and an attachment reorder are both persisted without a restamp.

---

### M-02. Rolled-back vault file causes permanent deletion of attachment blobs

**Component:** `vault-sync` · **Status:** Confirmed, reproduced · **Location:** `crates/vault-sync/src/synced.rs:423`, `:459-463`, `:715`; `crates/vault-sync/src/synced/reconcile.rs:198-204`; `crates/vault-sync/src/attachments.rs:173-183`

**What happens.** At unlock the app re-reads `vault.bin`, adopts it, and then removes attachment blobs that the adopted state does not reference:

```rust
// Orphan cleanup once per unlock, only when memory provably matches what is on disk
if disk_read && !self.dirty && !self.key_mismatch && self.save_blocked.is_none() {
    self.prune_orphan_attachments();
}
```

An older authentic copy of `vault.bin` opens normally. Every blob added since that copy, and older than the 24-hour grace period, is then unlinked, and the deletion syncs to every device.

**Attack.**

1. The attacker takes any older authentic `vault.bin`, for example from the cloud provider's version history. No key is needed.
2. While the app is locked or closed, they put it back as `vault.bin`.
3. The user unlocks. The app deletes the blobs the old copy does not know.
4. Restoring the newest backup brings the references back, but the blobs are gone and show as missing.

**Reproduction** (throwaway test against the real crate, grace period advanced with the crate's own test hook):

```
F1 after unlock: blob exists = false
F1 after restoring newest snapshot: reference present = true, state = Missing
```

**Impact.** Permanent loss of attachments. The vault state itself stays recoverable from `backups/`, but attachments are excluded from backups by design (`specs/00-overview.md`, non-goals). An attacker with delete rights could remove blobs directly, which keeps this out of High; here a write alone is enough and the app does the deleting. A sync provider that resolves a conflict in favour of a stale file could plausibly trigger the same loss with no attacker at all (not tested).

A related consequence of the same adopt-at-unlock step: a rollback to a file from before a key rotation opens with the same password and is adopted, so later saves are sealed under the old key again.

**Recommendation.**

- Quarantine instead of deleting: move orphans into a subfolder with a second grace period, and move a blob back when a merge or restore references it again.
- Skip the unlock-time cleanup when the on-disk file changed since this process last verified it.
- Longer term, keep a local freshness anchor outside the sync folder (see I-02), so a stale file is recognised before anything destructive runs.

---

### M-03. Touch ID policy state is unauthenticated and fails open on a future timestamp

**Component:** `vault-app` · **Status:** Confirmed · **Location:** `crates/vault-app/src/state/touch_id.rs:41-54`, `:189-209`; `crates/vault-app/src/persist.rs:54-62`; `crates/vault-macos/src/idle.rs:249-275`

**What the project claims.** `specs/04-macos.md` §2: the master password is required after a reboot, after 7 days, and after 5 failed Touch ID attempts.

**What happens.** The three values behind those rules (`last_password_unlock_at`, `failed_touch_attempts`, `stale`) are plain fields in `~/Library/Application Support/dev.vault.app/settings.json`. Nothing authenticates them.

```rust
if self.boot_time == UNIX_EPOCH || policy.last_password_unlock_at < unix(self.boot_time) {
    return Err(TouchDenied::Rebooted);
}
let age = unix(SystemTime::now()).saturating_sub(policy.last_password_unlock_at);
if age > PASSWORD_MAX_AGE.as_secs() { return Err(TouchDenied::Expired); }
```

A timestamp in the future is never below the boot time, and `saturating_sub` turns its age into 0. One edit therefore satisfies the reboot rule and the 7-day rule permanently, and `failed_touch_attempts: 0` resets the third. The entry can be rebuilt from scratch, since it needs only the vault id and slot id, both of which are plaintext in the vault header.

**Further ways to reach the same state.**

- Launching the app with a different `HOME` substitutes a crafted settings file.
- With no attacker: if the clock is ahead during a password unlock and later corrected, the rules are suspended until real time catches up.
- The boot time comes from `kern.boottime`, which is believed to follow the wall clock when the clock is changed (not verified here). Setting the clock back would then read as "not rebooted".

**Impact.** Someone with the login session and a finger enrolled in macOS can keep Touch ID available where the policy says the master password is required. The Secure Enclave gate is unaffected: a matching finger is still needed, and the vault at rest is not weakened. If "login session plus enrolled finger" is considered out of scope, this is Low.

**Recommendation.**

- Treat `last_password_unlock_at > now` as expired. This is a one-line fail-closed fix.
- Store the policy state in the Keychain next to the wrapped key, or authenticate it with a Keychain-held key.
- Compare a boot session identifier (`kern.bootsessionuuid`) for equality instead of comparing times.
- Clear the state whenever the vault's enclave slot changes.

---

### M-04. Lock triggers and the clipboard timer stall during the modal icon file panel

**Component:** `vault-app`, `vault-macos` · **Status:** Plausible (structure confirmed in code, stall not reproduced at runtime) · **Location:** `crates/vault-app/src/state/icon_images.rs:419-441`; `crates/vault-macos/src/panel.rs:85-112`; `crates/vault-app/src/autolock.rs:55-104`

**What happens.** The icon image chooser runs a modal `NSOpenPanel` (`runModal`) from inside a gpui foreground task. Foreground tasks are blocks on the main dispatch queue, and a nested run loop started from inside such a block does not service that queue. While the panel is open, the following are all expected to be frozen:

- the 1-second idle tick that drives auto-lock,
- delivery of the screen-lock, will-sleep and user-switch signals,
- the continuation of the clipboard auto-clear timer.

A comment at `panel.rs:69-71` states that main-queue blocks still fire during the modal loop. That holds only when the modal loop is not itself started from a main-queue block.

**Scenario.**

1. The user is editing an item, clicks "Drop or choose image…", and walks away.
2. The idle timeout passes with no lock. If the Mac sleeps or the screen locks, the vault key and decrypted items stay in memory.
3. Someone cancels the panel. The idle check uses the smaller of system idle and app idle, and the click just reset system idle, so the vault stays unlocked.

**Impact.** Auto-lock is the main control the threat model names for the unlocked window. This is a reachable UI state in which it does not operate.

**Recommendation.** Settle it with one runtime check: open the image panel in edit mode, wait past the auto-lock time or lock the screen, cancel the panel, and see whether the vault is still unlocked. If confirmed, present the panel with a completion handler as gpui's own panels do. Independently, let the AppKit observers set a "lock requested" flag that is honoured before anything else runs, so locking never depends on a queued task.

---

### M-05. KDBX import inflates gzip data without a bound

**Component:** importers (`keepass` 0.17.0 through `vault-core`) · **Status:** Confirmed, measured · **Location:** `keepass-0.17.0/src/compression.rs:40-45`; `crates/vault-core/src/import/kdbx.rs:78-83`

**What happens.** `vault-core` bounds the KDBX input size (100 MiB) and the KDF parameters, but the dependency inflates the inner payload with `read_to_end` into an unbounded buffer and then copies it again.

| KDBX file | Inflated | Peak memory | Time |
|---|---|---|---|
| 66,131 bytes | 64 MiB | 378 MB | 0.07 s |
| 522,755 bytes | 512 MiB | 2.76 GB | 0.72 s |

Peak memory is about five times the inflated size and about 5,000 times the file size. A 100 MiB input can ask for hundreds of GiB. A second unbounded inflate exists for compressed binaries inside the database, so a nested bomb is likely (not run).

**Scenario.** An attacker sends a small "shared" `.kdbx` with its password. The import allocates until the process is killed while the vault is unlocked, and unsaved edits are lost.

**Impact.** Availability only. The project rated the equivalent 1PUX problem as Medium and fixed it on 2026-11-06; the KDBX path has no such bound.

**Recommendation.** Bound decompression: get a capped inflate upstream, carry a reviewed patch, or handle the outer KDBX layer in `vault-core` with a capped inflate. Until then, lower the input cap and state the limit in the README.

## 5. Low severity findings

### vault-core

**L-01. Edited KDF costs make the correct password read as wrong.** *Confirmed, measured.* `crates/vault-core/src/vault.rs:148-158`, `crates/vault-core/src/kdf.rs:51-63`.
The KDF parameters live in the plaintext header. On a current vault they are bound into the manifest, but the password path fails at the slot before the manifest is reached. A file-writing attacker who raises the costs to the accepted maxima gets this result with the correct password:

```
untouched file (64 MiB, t=3, p=4): Ok in 87.91ms
edited header (1 GiB, t=16, p=64), CORRECT password: Err(WrongPassword) in 9.70s
```

The user is told their password is wrong, not that the file was altered, and may conclude they forgot it. The spec documents the error mapping; the usability consequence is the finding. *Fix:* remember the last-seen KDF parameters per vault locally (I-02) and say "this vault's header changed" when they differ.

**L-02. Legacy unstamped header: a key-less slot edit is merged and saved.** *Confirmed, reproduced.* `crates/vault-core/src/format.rs:713-724`, `crates/vault-core/src/vault/merge.rs:176-198`.
A header without `slots_modified_at` is not bound into the manifest. On such a file, an attacker can overwrite the password slot, the edited copy still opens with the cached vault key, it wins the header merge on the final byte-comparison tie-break, and the next save writes a vault that the correct password no longer opens:

```
fixture stamped: false
planted copy opens with the cached key: true
merge: header_updated = true
next save, unlock with the correct password: Err(WrongPassword)
```

Exposure is narrow: only version 1.0 era files that never had a slot change, and the app upgrades those at the next password unlock. A vault used only through the CLI or only through Touch ID stays exposed. *Fix:* never adopt an unstamped peer header in a merge, and stamp an unstamped header at the first save.

**L-03. Changing the master password does not revoke an old password.** *Confirmed (by design).* `crates/vault-core/src/vault.rs:1314-1343`, `crates/vault-app/src/screens/security.rs:29-31`.
A password change re-wraps the same vault key. Anyone who knows the old password and holds any older copy of the file (a backup, cloud history) can unwrap that key and decrypt the current file, and with the key can also forge content that every device will accept. Only "Rotate vault key" changes this. The UI describes rotation as "Replace the key that encrypts every item" and gives no hint about when it matters. *Fix:* say in the change-password flow that a suspected compromise also needs a key rotation, or offer both in one step.

### vault-sync

**L-04. Backups are identified by file name only.** *Confirmed, reproduced.* `crates/vault-sync/src/backup.rs:283-367`, `:411-412`; `crates/vault-sync/src/synced.rs:764-771`, `:910-916`.
The kind and time of a backup come from its name; content is never read when listing or rotating. Planted names can therefore:

- **Evict real snapshots:** an empty file named for the end of a day, week or month wins that retention slot, and the app deletes the genuine snapshot.
- **Suppress new snapshots:** one planted name per hour stops hourly snapshots.
- **Pose as the newest backup:** an old authentic copy under a fresh name is listed first and restores cleanly.

```
F2 after retention: genuine snapshot exists = false, planted empty file exists = true
```

This matters because `backups/` is the only recovery path for the rollback the project accepts. *Fix:* let only validated files take a retention slot, never delete a validated snapshot in favour of an unvalidated one, and consider keeping the newest few snapshots outside the sync folder.

**L-05. Planted entries block all saving; edits are dropped at lock.** *Confirmed, reproduced.* `crates/vault-sync/src/synced/reconcile.rs:320-325`, `crates/vault-sync/src/synced.rs:500-509`, `:671-677`; `crates/vault-sync/src/package.rs:148-155`.
A 10-byte stub with a higher format version in place of `vault.bin`, plus a plain file named `backups`, refuses save and restore, and lock then cannot preserve the session's edits:

```
F3 save: the vault file was written by a newer version (format 65535); update this app
F3 lock: Unpreserved(UnsafePackageDir("…/test.vault/backups"))
```

The user is told, but the block lasts until someone repairs the folder by hand. *Fix:* when `backups/` is unusable, write the unsaved copy (sealed, mode 0600) to a local folder outside the sync location, and offer to quarantine the offending entry.

**L-06. Unbounded directory work on the save path.** *Confirmed by reading; timings not measured.* `crates/vault-sync/src/backup.rs:323-366`, `crates/vault-sync/src/attachments.rs:159-192`, `crates/vault-sync/src/synced/reconcile.rs:704-706`.
Every dirty save lists all of `backups/` while holding the package lock, and walks all of `attachments/`. A large number of planted names stalls saves and makes concurrent CLI commands time out. *Fix:* cap or cache the listings and move backup and cleanup work off the save path.

### vault-macos

**L-07. A malformed QR image aborts the app.** *Confirmed in a harness; the GUI abort is traced, not run.* `crates/vault-macos/src/qr.rs:98-112`.
The QR decoder (`rqrr` 0.11.0) contains a release-mode assertion that fired on 4 of 73,880 mutated inputs. The scan runs on a background executor whose trampoline does not catch unwinds, so the panic aborts the process. Unsaved edits are lost and a copied secret stays on the pasteboard because the clear timer dies with the app. *Fix:* wrap the decode in `catch_unwind` and treat a panic as "no code found"; add a fuzz target.

**L-08. The QR picker hands any file to ImageIO.** *Path confirmed; exploitation would need a separate ImageIO bug.* `crates/vault-macos/src/qr.rs:224-230`, `crates/vault-app/src/state/qr.rs:69`.
There is no type filter and no magic-byte check, unlike the icon picker. The system decoder accepts around 60 formats and sniffs by content, inside an unsandboxed process holding the decrypted vault. *Fix:* check for PNG and JPEG magic bytes before decoding and filter the panel.

### vault-app

**L-09. Settings files are world-readable and carry security state.** *Confirmed, including on this Mac.* `crates/vault-app/src/persist.rs:54-62`.
`settings.json`, `recent.json` and `window.json` are written mode 0644 through a fixed temp name. They hold vault paths, vault and slot ids, the M-03 state, and the auto-lock and lock-on-sleep settings. Not readable across users while `~/Library` stays 0700, so this is defence in depth. *Fix:* directory 0700, files 0600, random-suffix temp created exclusively, as the export code already does.

**L-10. Tag filter survives lock and vault switch.** *Confirmed.* `crates/vault-app/src/state/session.rs:62-82`, `crates/vault-app/src/screens/main/list.rs:315-328`.
A tag name from one vault stays in memory across lock and is drawn as the list heading of the next vault opened. Tag names are encrypted metadata. *Fix:* reset the filter on lock and on vault close.

**L-11. File names from the sync folder reach toasts and titles unsanitised.** *Confirmed for the unsanitised paths.* `crates/vault-app/src/state/sync.rs:363-364`, `:384-390`; `crates/vault-app/src/screens/backup.rs:168-170`.
A conflict copy with a crafted name puts attacker-chosen text, including bidirectional control characters, into a toast and the backup viewer title, next to a master password prompt. *Fix:* pass every disk-derived name through the existing `text::sanitize_line` with a length cap.

**L-12. Plaintext export starts in `~/Documents`.** *Confirmed.* `crates/vault-app/src/state/transfer.rs:92-97`.
That folder is often synced to iCloud, which would hand the whole vault in plaintext to the cloud-storage attacker. The confirmation warns about plaintext but not about location. *Fix:* start in Downloads and reuse the cloud-folder hint from the create flow.

**L-13. Sleep time is not counted toward idle lock when lock-on-sleep is off.** *Plausible.* `crates/vault-app/src/state.rs:1335-1336`.
The idle clock and the clipboard timer use monotonic time that does not advance during sleep. Only applies after the user turns the sleep trigger off. *Fix:* also track wall-clock time and act on wake.

### Importers, export, CLI

**L-14. The 1PUX entry-count and ZIP64 guard can be bypassed.** *Confirmed, reproduced.* `crates/vault-core/src/import.rs:212-218`.
The guard searches 65,562 bytes back for the end-of-directory record; the `zip` crate searches 65,572. A real record placed in that 10-byte gap, with a decoy inside its comment, passes the guard while `zip` reads the real one. An archive with 1,000,001 entries was accepted. This defeats a control added on 2026-11-06 and promised in `specs/02-core-api.md`. *Fix:* widen the window with margin, add a check on the entry count after the archive is opened, and turn the reproduction into a test.

**L-15. KDBX field de-duplication is quadratic.** *Confirmed, measured.* `crates/vault-core/src/import/kdbx.rs:466-476`.
One entry with 80,000 custom fields (a 296 KB file) takes 8.6 seconds; a few megabytes take tens of minutes. *Fix:* reuse the linear name tracker the 1PUX path already has.

**L-16. CSV rows and the 1PUX JSON tree are unbounded in memory.** *Confirmed, measured.* `crates/vault-core/src/import.rs:127-188`, `:554-555`.
An 800 KB CSV reaches 1.19 GB before the save cap refuses it; a 275 KB archive reaches 1.08 GB. The vault itself is protected by the save cap. *Fix:* cap rows or running size during import.

**L-17. The CSV formula guard alters exported secrets.** *Confirmed.* `crates/vault-core/src/export.rs:52-59`.
A leading `'` is added to any cell starting with `=`, `+`, `-`, `@`, tab or carriage return, including passwords. The project's own import reverses it; another password manager would store the altered password. *Fix:* say so in the export warning, or guard only non-secret columns.

**L-18. Masked card number writes raw control characters to the terminal.** *Confirmed, reproduced.* `crates/vault-cli/src/main.rs:497-506`.
The "last four" of a card number is printed without the sanitising every other path uses. A hostile import can place an escape sequence there. *Fix:* sanitise, or show the last four only when all are digits.

**L-19. A notes value can forge labelled output lines.** *Confirmed, reproduced.* `crates/vault-cli/src/main.rs:486-493`, `:962-967`.
Newlines in notes are printed as-is, so notes can contain a fake `password:` line that a script reading `vault get` output would pick up. *Fix:* indent continuation lines.

**L-20. `--kdf-test-params` is public and there is no KDF floor.** *Confirmed, reproduced.* `crates/vault-cli/src/main.rs:71-73`, `:841-842`; `crates/vault-core/src/kdf.rs:51-63`.
`vault init --kdf-test-params --allow-weak` creates a vault with an empty password under 8 MiB, one pass, with no warning. `KdfParams::validate` has ceilings only, so nothing flags such a vault later. *Fix:* hide and gate the flag, and warn at open when costs are below the recommended floor.

**L-25. Export can leave a partial plaintext file.** *Confirmed by reading.* `crates/vault-cli/src/main.rs:1129-1134`.
The non-`--force` export path does not fsync and does not remove its output on a failed write. *Fix:* route it through the helper the other paths use.

### Build and supply chain

**L-21. The dependency gate is failing.** *Confirmed.*
`cargo deny check` reports `advisories FAILED`. `CLAUDE.md` requires it to stay clean.

| Crate | Issue | Reachable here |
|---|---|---|
| `url` 2.5.8 | RUSTSEC-2026-0592, stack overflow in `Url::origin()` | No caller found in the workspace or its users of `url` |
| `heapless` 0.9.3 | RUSTSEC-2026-0574 to 0582, unsound types | Affected types are not referenced |
| `async-executor` 1.14.0 | Yanked | Ships in the app |
| `chrono`, `instant`, `paste`, `rustybuzz`, `ttf-parser` | Unmaintained | In the app graph |

*Fix:* `cargo update url form_urlencoded heapless async-executor`, then re-run both tools in the root, `qa/spec-checks` and `fuzz/`. This changes `Cargo.lock`, so it needs the owner's go-ahead.

**L-22. The release build is not locked and embeds builder paths.** *Confirmed.* `scripts/package.sh:124`.
The build runs without `--locked` and without the dependency gate, and the shipped binary contains 921 strings under the builder's home directory. *Fix:* add `--locked`, add `--remap-path-prefix`, run `cargo deny` first, and record the git revision.

**L-23. The entitlement checker is a deny-list.** *Confirmed.* `scripts/check-entitlements.sh:29-36`.
It rejects six named keys. `com.apple.security.cs.disable-executable-page-protection` is missing from the list, and any other entitlement passes. *Fix:* require the extracted entitlements to equal `scripts/entitlements.plist`.

**L-24. Integer overflow is unchecked in the shipped profile.** *Confirmed.* `Cargo.toml:13-23`.
*Fix:* add `overflow-checks = true` to `[profile.dist]`. The parsers handle attacker-controlled lengths, and a wrapped value is worse than a panic.

## 6. Informational findings

**I-01. Touch ID has never run on real hardware, and the packaged app most likely cannot use it.**
Every Keychain call uses the data-protection keychain (`crates/vault-macos/src/biometric.rs:287`, `:301`, `:407`), which needs a keychain access group entitlement and a provisioning profile. `scripts/entitlements.plist` is empty and the spec says to keep it empty. The project's own history records the real path as unverified, and the integration test passes vacuously on unsigned builds. It fails closed, so there is no exposure, but every claim in this report about Touch ID rests on code reading alone. The error mapping for an invalidated key and the prompt-per-unlock behaviour are untested. This is the largest assurance gap in the project.

**I-02. No local freshness anchor.**
Whole-file rollback is an accepted limit. A small record kept outside the sync folder (highest slot stamp and item timestamp seen, last KDF parameters, per vault) would let a device that has seen a newer state recognise a stale file. It would address the accepted rollback on known devices and reduce M-02 and L-01.

**I-03. The file reveals more than the README lists.**
The README says the file leaks only item count, item ids, modification times and creation time. An observer also learns:

- the ciphertext length of every item, which tracks content size,
- the key slot kinds, so whether Touch ID is enrolled, and when each slot was created,
- the time of the last credential change and the id of the device that made it,
- the KDF parameters,
- the number and exact sizes of attachments, and the names and times of backups.

None of this is a break, but the documentation should match.

**I-04. Some plaintext is not authenticated.**
The header `created_at`, unknown header keys, and unknown record-level keys are preserved and re-emitted but bound to nothing. An attacker can alter the first and inject the others, which persist across saves. The code comments note this.

**I-05. Secrets in memory are dropped, not always wiped.**
The CBOR value tree used for encoding and decoding, text input buffers, strings copied for drawing, and CoreFoundation copies of the Touch ID key are freed without zeroing. The key material proper and all `vault-core` secret types are zeroized. Memory disclosure on an unlocked machine is out of scope; the code documents most of these.

**I-06. A lock cannot wipe the key while a background task holds the vault.**
During Argon2, a large attachment operation or an iCloud wait, zeroization waits for the task to return.

**I-07. No Secure Event Input on password fields.** Keyloggers are out of scope; `NSSecureTextField` would provide this.

**I-08. Lock triggers are owned by the main window.**
Safe today because every path that removes the window locks first. A future windowless unlock would run with no auto-lock (`crates/vault-app/src/root.rs:176`, `:262`).

**I-09. The app is not sandboxed.** A memory-safety bug in any parser or system decoder runs with the user's full rights. This is the stated design for a Developer ID build.

**I-10. Test-only and dead capabilities are compiled into release builds.**
`Clipboard::write_plain` writes unconcealed text; a whole-screen QR scan removed from the spec on 2026-10-29 is still exported. Neither is called by the app.

**I-11. The UI toolkit is a third-party crates.io snapshot.**
`gpui-pre =0.3.10` is a maintainer's snapshot of Zed's gpui, not Zed's own crate. Trust rests on that publisher's account and the lock checksums. The app graph has 581 packages, 58 build scripts and 43 procedural macros.

**I-12. Fuzzing coverage is thin where it matters.**
Mutations of KDBX and 1PUX seeds rarely pass their integrity checks, so the mapping code is barely reached, and dependency panics are swallowed by `catch_unwind`. There are no targets for CSV import, TOTP URIs, attachment blobs or QR decoding. The corpus is not committed and nothing runs automatically.

**I-13. No continuous integration.** The four checks, the dependency gate and the fuzzers run only when someone runs them. L-21 is the visible result.

**I-14. Smaller items.**

- CLI secrets passed with `--set`, `--totp` and `--notes` are visible in `ps` and shell history (documented in the help).
- `--reveal` output maps tab to space and does not escape backslashes, so a revealed secret can be ambiguous.
- A TOTP period has no upper bound, allowing an effectively static code.
- KDBX KDF limits (64 iterations at 1 GiB) are looser than the vault's own.
- The notary password crosses the command line on the Apple ID path; the keychain-profile path does not.
- `codesign --deep` is harmless with one binary but would mis-sign future nested code.
- `.gitignore` has no patterns for vault packages, exported CSV files or signing material.
- Pasteboard change-count checks have microsecond races whose only effect is clearing another app's fresh copy.
- Master password strength (50 bits) is enforced in the UI and CLI, not in the state layer, so a future caller could skip it.

## 7. Controls verified as correct

These were checked against the code and found to do what the specs say. They are the reason there is no Critical or High finding.

### Cryptography and format (`vault-core`)

- **Primitives.** Argon2id (v1.3) for the password key, XChaCha20-Poly1305 for every seal, HKDF-SHA256 for subkeys, all from RustCrypto, with no hand-written comparison or padding (`crypto.rs`). `#![forbid(unsafe_code)]`.
- **Randomness.** Vault key, salts, slot ids and every nonce come from `OsRng`. Nonces are 24 random bytes, fresh on every write (`crypto.rs:41-52`, `vault.rs:1488`, `:1503`).
- **Domain separation.** Item, manifest and attachment keys are distinct HKDF outputs salted with the vault id (`crypto.rs:112-131`).
- **Binding.** Slot AAD binds magic, format version, vault id, slot id and kind. Item AAD binds vault id, item id, timestamp and version. Manifest AAD binds vault id, item count, version and the header digest (`format.rs:91-144`).
- **Tamper detection.** A flipped ciphertext byte, a record moved between vaults, a dropped or duplicated record, and a stripped, re-stamped or replaced header on a current vault all fail (`vault.rs:304-373`). M-01 is the one gap.
- **Hostile-input limits.** KDF parameters are range-checked before any Argon2 run (`kdf.rs:51-63`). Maps with duplicate keys, trailing bytes, duplicate slot ids and duplicate field ids are rejected (`format.rs:213-224`, `:296-307`, `:793-798`).
- **Attachments.** Per-attachment random key, per-chunk random nonce, AAD binding vault, attachment, chunk index and chunk count, so chunks cannot be swapped, reordered, truncated or moved (`attachment.rs:202-286`).
- **Secret types.** Field values are `SecretString`, keys are `Zeroizing`, and every type holding a secret has a redacting `Debug` (`item.rs:210-317`, `vault.rs:409-421`).
- **Generator.** Unbiased sampling from `OsRng`, the EFF large word list, and an honest entropy figure (`generator.rs:116-195`).

### Storage and sync (`vault-sync`)

- **No link following.** Reads open with `O_NOFOLLOW`, then verify a regular file on the handle; `backups/` and `attachments/` are checked before every use (`package.rs:148-155`, `:180-224`).
- **Atomic writes.** Exclusive temp file, mode 0600, random suffix, full fsync, identity check, no-replace rename, directory fsync, temp removed on every failure (`atomic.rs`). A partial file is never visible as `vault.bin`.
- **Permissions.** Files 0600 and directories 0700 on everything the app creates.
- **Size limits.** A 64 MiB cap checked before allocation on every read and write.
- **Locking.** `flock` on an open descriptor: no PID files, no stale-lock handling.
- **Conflict copies.** Type check, capped read, parse, vault id match and authentication with the vault key all happen before a merge; unusable candidates are left in place and nothing is deleted.
- **Rollback while unlocked.** An old authentic file is merged, not adopted; an older header loses; a planted pre-rotation file does not undo a rotation.
- **No secrets** on disk, in logs or in `Debug` output; no `unwrap` or `panic!` in non-test code; `#![forbid(unsafe_code)]`.

### macOS integration (`vault-macos`)

- **Secure Enclave key.** P-256, enclave token, `WhenUnlockedThisDeviceOnly`, `PrivateKeyUsage | BiometryCurrentSet`, with no passcode or Watch fallback (`biometric.rs:380-409`).
- **Keychain item.** Holds only ciphertext, slot id and biometric domain state; not synchronizable (`biometric.rs:455-464`).
- **Per-unlock prompt.** A fresh `LAContext` each time, no reuse duration. A changed or missing biometric state forces re-enrolment. No error path returns success.
- **Pasteboard.** Current-host-only is set first, the concealed marker is written before the text, any failure clears the pasteboard, and clearing happens only if the change count is still the app's (`pasteboard.rs:102-125`).
- **Screen capture.** Exclusion is applied to every window; the debug override is compiled to a constant-false branch in release.
- **`unsafe`.** Every block has a `// SAFETY:` comment, and the claims were checked against the binding signatures. No `unsafe` exists outside this crate.

### Application (`vault-app`)

- **One lock path** behind every trigger, clearing windows, sheets, caches, the edit buffer, reveal state, search, the generator preview and the pasteboard (`state.rs:1179-1236`).
- **Lock during background work.** Every vault-holding task re-locks its result if a lock happened meanwhile.
- **Clipboard.** Every value copy goes through the concealed path; master password inputs refuse copy and cut.
- **Touch ID.** A missing policy entry, an unreadable boot time or a missing Keychain item denies it; enabling needs a password unlock in the session.
- **No network.** No network crate is in the macOS dependency graph, the shipped binary imports no socket functions, and gpui's HTTP client is the null client.
- **URLs.** Only `http` and `https` are opened; `file:`, `javascript:` and custom schemes are refused.
- **Attachments.** Previewed in memory only, never opened with a default handler; decrypted copies are saved through an exclusive 0600 temp.
- **No `unsafe` and no shell-outs** in the crate.

### CLI, importers and build

- **Master password** is read without echo or from a named environment variable, never from the command line.
- **Terminal output** is sanitised on every path except L-18. Sensitive kinds are masked without `--reveal`.
- **Export** needs `--yes`, creates the file exclusively with mode 0600, and refuses symlinks.
- **1PUX** reads only `export.data`, bounded before and during inflation; nothing is extracted.
- **KDBX** KDF parameters are bounded before any derivation; error text carries no dependency output.
- **TOTP** accepts 6 to 8 digits and SHA-1, SHA-256 or SHA-512; hostile URIs produce errors, not panics.
- **Dependencies** all come from crates.io with no git sources and no patches; the toolchain is pinned exactly.
- **Packaging** uses the hardened runtime with empty entitlements, a stripped binary, and notarisation of both app and disk image (read, not run).

## 8. Threat model claims against the evidence

| Claim (`specs/00-overview.md`) | Assessment |
|---|---|
| Stolen or lost laptop | **Holds.** Caveats: settings files disclose vault paths (L-09); the Touch ID path is unverified on hardware (I-01). |
| Compromised cloud storage, confidentiality | **Holds.** Metadata exposure is wider than documented (I-03). |
| Compromised cloud storage, integrity and availability | **Partly.** M-01, M-02, L-04 and L-05 give a writing attacker more than the documented whole-file rollback. |
| Offline brute force | **Holds** for vaults created normally (calibrated Argon2id, 50-bit minimum). Caveat: L-20. |
| Tampering with the file | **Holds with one gap** (M-01), plus L-02 on legacy files. |
| Casual clipboard snooping | **Holds by code.** The effect on Universal Clipboard was not tested on two devices. |
| Weak or reused item passwords | Present and working. |
| Controls for the unlocked window | Auto-lock has a suspected gap (M-04) and a minor one (L-13); zeroize on lock is good for key material and best effort elsewhere (I-05); hardened runtime is scripted but no signed build exists yet. |

### README statements that need correcting

| Statement | Issue |
|---|---|
| "swapped or rolled-back items are detected" | True except after a merge (M-01). |
| "The file leaks only the item count, item UUIDs, last-modified times, and creation time" | Understated (I-03). |
| "Touch ID unlock through a Secure Enclave wrapped key" | Implemented but never run on hardware; likely unusable as packaged (I-01). |
| "Argon2id, calibrated to at least 500 ms on your machine" | True for normal creation; calibration stops at 1 GiB, and a CLI flag bypasses it (L-20). |
| "Rotating encrypted backups" | Attachments are excluded (stated under limitations) and rotation trusts file names (L-04). |

## 9. Remediation plan

### Before anyone stores real secrets

| Item | Effort |
|---|---|
| M-01: symmetric timestamp bump in the merge, with a regression test | Small |
| M-03: treat a future timestamp as expired | Trivial |
| M-04: run the runtime check; replace the modal panel if confirmed | Small |
| M-02: quarantine orphaned blobs | Medium |
| M-05: bound KDBX decompression | Medium |
| L-07: `catch_unwind` around QR decoding | Trivial |
| L-21: update the flagged dependencies | Trivial |
| I-01: add the entitlement and run the Touch ID test on a signed build | Medium, needs a signing identity |

### Next

- **Storage:** validate backups before they take a retention slot (L-04); keep unsaved edits when the package is blocked (L-05); never adopt an unstamped header (L-02).
- **Local state:** settings files 0600 and the Touch ID policy in the Keychain (L-09, M-03).
- **Importers:** fix the 1PUX window, the quadratic loop and the row cap (L-14, L-15, L-16).
- **CLI:** close the two output gaps and gate the test flag (L-18, L-19, L-20, L-25).
- **Build:** `--locked`, path remapping, `overflow-checks`, an allow-list entitlement check (L-22, L-23, L-24).
- **UI:** reset the filter on lock, sanitise disk-derived names, move the export default, explain key rotation (L-10, L-11, L-12, L-03).

### Structural

- A local freshness anchor outside the sync folder (I-02).
- Continuous integration running the four checks, `cargo deny` and a nightly fuzz budget (I-13).
- Structure-aware fuzz targets for the importers and new targets for CSV, TOTP and QR (I-12).
- Corrected README and spec wording (section 8).
- An independent audit before any public release. The README already says the project has not had one; this review does not change that.

## 10. Limits of this review

- **Static analysis with targeted reproductions.** The GUI was not driven, and no signed or notarised build was examined.
- **No hardware tests.** Secure Enclave, Keychain access control, Universal Clipboard and screen-capture exclusion were assessed from code only.
- **Depth varied.** `vault-core`, `vault-sync` and `vault-macos` were read in full. In `vault-app` the state and policy code was read in depth; view code was read only where it handles secrets.
- **Dependencies were not audited** beyond advisory databases and the specific code paths cited.
- **Reproductions were built outside the repository** and are not committed. Appendix A gives the source for M-01; the others are described closely enough to rebuild.
- **An AI review misses things a human specialist would catch**, and can be wrong about platform behaviour it could not test. Findings marked Plausible should be confirmed before they drive design changes.

## Appendix A. Reproduction for M-01

A standalone binary depending on `vault-core` by path. It uses only public API.

```rust
use vault_core::format::VaultFile;
use vault_core::{ExposeSecret, Field, FieldKind, Item, KdfParams, LockedVault,
                 SecretString, UnlockedVault, Uuid};

fn s(v: &str) -> SecretString { SecretString::new(v.to_owned()) }

fn main() {
    let pw = s("correct horse battery staple");
    let (dev_o, dev_t) = (Uuid::from_u128(0x0A), Uuid::from_u128(0x0B));

    // Common ancestor, written by device O.
    let mut o = UnlockedVault::create(&pw, KdfParams::for_tests(), dev_o);
    let mut item = Item::new("Bank", dev_o, 1);
    item.fields.push(Field::new("username", FieldKind::Text, s("alice"), 1));
    item.fields.push(Field::new("password", FieldKind::Password, s("old-password"), 1));
    let id = o.insert(item, 1);
    let base = o.serialize();
    let pw_field = o.get(id).unwrap().field("password").unwrap().id;
    let user_field = o.get(id).unwrap().field("username").unwrap().id;

    // Device T opens the same file.
    let mut t = LockedVault::parse(&base).unwrap().unlock(&pw).unwrap();
    t.set_device_id(dev_t);

    // O changes the password at t=8; T edits the username at t=10.
    o.set_field(id, pw_field, s("NEW-password"), 8).unwrap();
    t.set_field(id, user_field, s("alice@example.com"), 10).unwrap();
    let file_t = t.serialize();            // visible in the sync folder

    // O merges T's file and saves.
    let on_disk_t = LockedVault::parse(&file_t).unwrap().unlock(&pw).unwrap();
    o.merge_from(&on_disk_t).unwrap();
    let file_o = o.serialize();

    // Attacker, no key: replace the item record in O's file with T's earlier record.
    let mut spliced = VaultFile::parse(&file_o).unwrap();
    let old = VaultFile::parse(&file_t).unwrap();
    let victim = spliced.items.iter_mut().find(|r| r.id == id).unwrap();
    *victim = old.items.iter().find(|r| r.id == id).unwrap().clone();

    let v = LockedVault::parse(&spliced.to_bytes()).unwrap().unlock(&pw)
        .expect("expected Tampered(Manifest); the spliced file unlocks instead");
    let f = v.get(id).unwrap().field("password").unwrap();
    assert_eq!(f.value.expose_secret(), "old-password");
}
```

## Appendix B. Other reproductions in brief

| Finding | How it was shown |
|---|---|
| L-01 | Create a vault with recommended parameters, parse the file, set `kdf` to the three maxima in the plaintext header, re-serialise, time `unlock` with the correct password. |
| L-02 | Unlock the unstamped fixture `v1-basic.vault`, export the key handle, overwrite the password slot's wrapped key with `0xFF` bytes in a copy, open the copy with `unlock_with_key`, `merge_from` it, serialise, unlock with the password. |
| M-02, L-04, L-05 | Five throwaway integration tests against `vault-sync` using its `test-support` hooks. |
| L-07 | A harness calling the same `rqrr` sequence as `decode_into` on mutated QR renders and block noise, with a fixed seed. |
| M-05, L-14, L-15, L-16 | A probe binary generating the hostile KDBX, 1PUX and CSV inputs and measuring time and peak memory in a release build. |
| L-18, L-19, L-20 | Shell scripts driving `vault-cli` against a throwaway vault. |
