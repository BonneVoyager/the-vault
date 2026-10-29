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
