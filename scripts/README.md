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
`dev.aurora.vault` (conforms to `com.apple.package` and `public.data`, extension `vault`) and
declares a matching document type with `LSTypeIsPackage`, so Finder shows a vault as a single
file and opens it with Vault. The UTI reuses the app icon (`Vault.icns`); no separate document
icon is bundled. Launch Services reads this when the app is first registered, so a freshly
copied app may need `lsregister -f Vault.app` before existing folders are recognised.
