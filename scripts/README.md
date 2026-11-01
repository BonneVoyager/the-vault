# Packaging

Run from anywhere; the script changes to the repo root.

    scripts/package.sh [--skip-sign] [--skip-notarize] [--dry-run]

Output: `target/package/Vault.app` and `target/package/Vault-<version>.dmg`.

The app icon is `assets/icon/Vault.icns`, built from `assets/icon/vault.svg` by
`assets/icon/build-icns.sh` (uses `rsvg-convert` if installed, else `qlmanage` and `sips`).
If the icns is missing, the script warns and builds an icon-less bundle. After the app is
stapled and the dmg built, the dmg is also signed, notarized and stapled (same credentials).

Required environment variables (checked before building, all missing ones listed):

- `VAULT_SIGN_IDENTITY`: e.g. `Developer ID Application: Name (TEAMID)`
- Preferred: `VAULT_NOTARY_KEYCHAIN_PROFILE`, a profile made with `xcrun notarytool store-credentials`; replaces the next line.
- `VAULT_NOTARY_APPLE_ID`, `VAULT_NOTARY_TEAM_ID`, `VAULT_NOTARY_PASSWORD` (app-specific password)

Flags: `--skip-sign` (also skips notarization) and `--skip-notarize` drop the matching
variables. `--dry-run` prints codesign, notarytool and hdiutil commands without running
them; secrets are never printed. `entitlements.plist` is empty until gpui needs more.

With the Apple ID path the password is visible in `ps` during `--wait`; use a keychain profile to avoid that.

Vault files are package directories named `<name>.vault/`. `Info.plist` exports the UTI
`dev.vault.app` (conforms to `com.apple.package` and `public.data`, extension `vault`) and
declares a matching document type with `LSTypeIsPackage`, so Finder shows a vault as a single
file and opens it with Vault. The UTI reuses the app icon (`Vault.icns`); no separate document
icon is bundled. Launch Services reads this when the app is first registered, so a freshly
copied app may need `lsregister -f Vault.app` before existing folders are recognised.

# Sync lab

A one-Mac, multi-device sync lab driven through `target/debug/vault` (`cargo build -p vault-cli` first).

    scripts/sync-lab.sh [--keep] [--scenario NAME]
    scripts/sync-lab.sh --random --seed N --steps M [--keep]

Devices A, B and C each get their own package copy, `HOME` and `VAULT_DEVICE_ID` (the CLI honours that
variable through `vault-macos`), so nothing touches the real profile. `cloud_sync SRC DST` copies
`vault.bin` and the attachment blobs (not backups) with `--delay ms`, `--drop`, `--only vault|blobs`,
and `--conflict sibling|inpackage`, which places the Dropbox/iCloud-style conflict copy instead of
overwriting. Temp dirs live in `scripts/sync-lab/tmp/` (git-ignored) and are removed unless `--keep`.
Output is one PASS/FAIL line per scenario; exit status is non-zero on any FAIL.

Random mode plans every operation in `scripts/sync-lab/model.py` from the model state and random numbers
drawn in the parent shell, so a seed replays (`--selfcheck --seed N --steps M` runs it twice and diffs the
operation logs). The model, fed only by the operations, applies the 03 §5 merge rules; after each full
exchange round both devices must match it (titles, favorites, tags, icons, fields, decrypted attachment
bytes) and each other (including `vault.bin` bytes). Model fields are keyed by name, which stays valid because random mode never renames or re-adds a field. Unsynced edits are tracked from the model's own operations; a lab-dirty, model-clean device (a merge rewrite) is accepted, the reverse fails. The first divergence prints seed, step and lab path.

The receiver runs `vault sync` after every delivery. A delivery is a plain overwrite only when the
receiver has no package, or the sender holds the cloud's current version and the receiver has no unsynced
edits; otherwise it is a conflict copy in one of four shapes (Dropbox-style and numbered, sibling and
in-package). `--scenario NAME` runs one scenario, `--continue` keeps going after a failure, and the lab
directory of a failure is always kept. The script builds `vault-cli` first.
