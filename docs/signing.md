# Signing a Touch-ID-capable build

Security review I-01 (`docs/qa/security-review-2026-11-26.md`): Touch ID has never run on
real hardware. `crates/vault-macos/src/biometric.rs` stores the wrapped key in the
**data-protection keychain** (`kSecUseDataProtectionKeychain`) and keeps the wrapping key in
the Secure Enclave. macOS only lets a binary use that keychain when it is signed with an
application identifier and a keychain access group that a **provisioning profile** embedded
in the bundle allows. An unsigned or ad-hoc signed build gets `errSecMissingEntitlement`
(-34018), so Touch ID fails closed and is never usable.

`scripts/package.sh` builds such an app when you set `VAULT_TEAM_ID`. Without it, the build is
unchanged: the empty `scripts/entitlements.plist` is used and no profile is embedded.

Nothing here needs your identity in the repository. Certificates, profiles and passwords stay
in your keychain and in files outside the checkout. `.gitignore` already ignores `*.p12`,
`*.cer`, `*.mobileprovision`, `*.provisionprofile` and `notary-*.json`.

## What the signed build contains

With `VAULT_TEAM_ID=ABCDE12345` (an example; the bundle id is read from `scripts/Info.plist`,
currently `dev.vault.app`), `scripts/check-entitlements.sh --render` turns
`scripts/entitlements.plist.in` into:

```xml
<dict>
	<key>com.apple.application-identifier</key>
	<string>ABCDE12345.dev.vault.app</string>
	<key>com.apple.developer.team-identifier</key>
	<string>ABCDE12345</string>
	<key>keychain-access-groups</key>
	<array>
		<string>ABCDE12345.dev.vault.app</string>
	</array>
</dict>
```

`package.sh` then:

1. Checks, before it builds anything: the Team ID is 10 characters (A-Z, 0-9);
   `VAULT_PROVISION_PROFILE` points at a readable profile; the profile's team is
   `VAULT_TEAM_ID`; its App ID is exactly `<TEAMID>.dev.vault.app`; and its
   `keychain-access-groups` allows `<TEAMID>.dev.vault.app` or `<TEAMID>.*`. It also reads the
   team (OU) of the `VAULT_SIGN_IDENTITY` certificate. This last check is best effort: if the
   certificate cannot be found by name, it prints a warning and continues.
2. Copies the profile into the bundle as `Vault.app/Contents/embedded.provisionprofile`.
3. Signs with the rendered entitlements and the hardened runtime. `--deep` stays because the
   bundle holds one binary (see the comment in `package.sh` for when that must change).
4. Runs `scripts/check-entitlements.sh`. It renders the same template again and requires the
   signed entitlements to **equal** it after `plutil` normalisation. It also requires the
   hardened runtime flag, `TeamIdentifier=<VAULT_TEAM_ID>` in `codesign -dvv`, and the
   embedded profile.
5. Notarises, staples, builds the dmg, then signs, notarises and staples the dmg (as before).

## One-time setup in the Apple Developer account

You need a paid Apple Developer Program membership. Creating a Developer ID certificate
requires the Account Holder role.

1. **Find your Team ID.** Go to developer.apple.com/account and open Membership details. The
   Team ID is the 10-character value. It becomes `VAULT_TEAM_ID`.
2. **Create a Developer ID Application certificate.** Use either of these routes:
   - Xcode: Settings > Accounts > select the team > Manage Certificates > `+` >
     *Developer ID Application*.
   - Portal: Certificates, Identifiers & Profiles > Certificates > `+` >
     *Developer ID Application*. Create the CSR in Keychain Access (Certificate Assistant >
     Request a Certificate From a Certificate Authority > Saved to disk). Upload it, download
     the `.cer` and double-click it so it lands in the login keychain next to its private key.

   Check that the identity is available:
   ```
   security find-identity -v -p codesigning
   ```
   It should list `"Developer ID Application: <Name> (<TEAMID>)"`. That full quoted string, or
   its SHA-1 hash, becomes `VAULT_SIGN_IDENTITY`. With the hash, the pre-build team check only
   warns. The post-sign check still applies.
3. **Register the App ID.** Go to Identifiers > `+` > App IDs > App. Choose platform macOS and
   an **explicit** Bundle ID `dev.vault.app`, the same as `CFBundleIdentifier` in
   `scripts/Info.plist`. Under Capabilities, enable **Keychain Sharing** if the portal lists
   it for macOS. Explicit bundle ids are unique across all teams. If `dev.vault.app` is
   already taken, stop: changing it means changing `scripts/Info.plist` *and* `BUNDLE_ID` in
   `crates/vault-macos/src/device.rs`, which also moves the app's data directory. That is a
   separate, reviewed change.
4. **Create a Developer ID provisioning profile.** Go to Profiles > `+` > Distribution >
   **Developer ID**. Select the App ID `dev.vault.app` and the Developer ID Application
   certificate from step 2, name the profile (for example "Vault Developer ID"), then
   Generate and Download. You get a `.provisionprofile` file. Keep it outside the repository,
   for example `~/Signing/Vault_Developer_ID.provisionprofile`.

   Inspect it:
   ```
   security cms -D -i ~/Signing/Vault_Developer_ID.provisionprofile | plutil -p -
   ```
   Expect `TeamIdentifier => [<TEAMID>]`, `com.apple.application-identifier =>
   "<TEAMID>.dev.vault.app"`, a `keychain-access-groups` array containing `<TEAMID>.*` (or
   the explicit group), and a `DeveloperCertificates` entry for the certificate from step 2.
   If `keychain-access-groups` is missing, `package.sh` stops with a message. In that case,
   enable Keychain Sharing on the App ID and regenerate the profile.
5. **Notarisation credentials** (already supported; see `scripts/README.md`). The preferred
   way is a keychain profile:
   ```
   xcrun notarytool store-credentials vault-notary --apple-id <apple id> --team-id <TEAMID>
   ```
   It prompts for an app-specific password from appleid.apple.com.

## Environment variables

| Variable | Required | Meaning |
|---|---|---|
| `VAULT_SIGN_IDENTITY` | yes, unless `--skip-sign` | `Developer ID Application: <Name> (<TEAMID>)` or its SHA-1 |
| `VAULT_TEAM_ID` | for Touch ID | 10-character Team ID; turns on the entitlements and profile |
| `VAULT_PROVISION_PROFILE` | when `VAULT_TEAM_ID` is set | path to the Developer ID `.provisionprofile` |
| `VAULT_NOTARY_KEYCHAIN_PROFILE` | preferred, unless `--skip-notarize` | `notarytool` keychain profile name |
| `VAULT_NOTARY_APPLE_ID`, `VAULT_NOTARY_TEAM_ID`, `VAULT_NOTARY_PASSWORD` | alternative to the above | Apple ID notarisation |

`--skip-sign` ignores `VAULT_TEAM_ID` and prints a note: an unsigned bundle never gets a profile.

## Build

Run a dry run first. It does the real checks and build but only prints `codesign`,
`notarytool` and `hdiutil`:

```
export VAULT_SIGN_IDENTITY="Developer ID Application: <Name> (<TEAMID>)"
export VAULT_TEAM_ID=<TEAMID>
export VAULT_PROVISION_PROFILE=~/Signing/Vault_Developer_ID.provisionprofile
export VAULT_NOTARY_KEYCHAIN_PROFILE=vault-notary
scripts/package.sh --dry-run
```

Then build for real. Use `--skip-notarize` for a quick local signed build, or no flag for
the full release:

```
scripts/package.sh --skip-notarize      # signed, not notarised: fine for the Touch ID test on this Mac
scripts/package.sh                      # signed, notarised, stapled app and dmg
```

## Verify the signature

```
codesign -d --entitlements :- target/package/Vault.app    # the three keys above, nothing else
codesign -dvv target/package/Vault.app 2>&1 | grep -E 'TeamIdentifier|flags|Authority'
                                                          # TeamIdentifier=<TEAMID>, flags include runtime,
                                                          # Authority=Developer ID Application: ...
ls target/package/Vault.app/Contents/embedded.provisionprofile
VAULT_TEAM_ID=<TEAMID> scripts/check-entitlements.sh target/package/Vault.app
                                                          # after notarisation; add --skip-notarize before
spctl -a -vv -t execute target/package/Vault.app          # after notarisation:
                                                          # "accepted  source=Notarized Developer ID"
xcrun stapler validate target/package/Vault.app
```

If the app is killed at launch (`Killed: 9`, or a crash report naming AMFI or "No matching
profile found"), the entitlements and the profile disagree. Compare
`codesign -d --entitlements :-` with the `Entitlements` dict of the profile, and check that
the profile lists the signing certificate.

## Touch ID verification

### What the automated tests prove today

`crates/vault-macos/tests/biometric.rs`, run by `cargo test -p vault-macos`:

- `available_does_not_panic`, `enroll_rejects_short_kek` and `unknown_vault_is_not_enrolled`
  only check that the calls return.
- `unenroll_unknown_vault_is_ok` accepts `Ok` **or** `Keychain(-34018)`.

On the unsigned `cargo test` binary the data-protection keychain refuses every call
(-34018 or -25300), so these tests **pass vacuously**. They do not distinguish a working
keychain from a refused one.

- `enroll_unlock_unenroll` is `#[ignore]`d. It is the real acceptance test for
  **enrol and unlock**. It creates a Secure Enclave key and enrols a random 32-byte KEK, then
  asserts `is_enrolled`. It unlocks (one Touch ID prompt) and unenrols, then asserts that the
  returned slot id and KEK equal the enrolled ones and that the vault is no longer enrolled.
  It does **not** cover invalidation on a biometry change. No automated test does: the unit
  tests in `src/biometric.rs` (`biometry_changed_rules`, `decrypt_auth_failed_mapping`,
  `status_mapping`, `preflight_error_mapping`) only check the mapping of domain states and
  error codes. Invalidation is proven by the manual checklist below, step 6.

### Running the ignored test against your signing identity (untried)

A bare test executable cannot carry a provisioning profile, and AMFI kills a binary that
claims `keychain-access-groups` without one. The workaround is to wrap the test binary in a
throwaway bundle with the same bundle id and profile. This has not been tried yet. If it is
killed or still gets -34018, use the manual checklist, which covers the same ground.

```
cargo test -p vault-macos --test biometric --no-run 2>&1 | grep -o 'target/debug/deps/biometric-[0-9a-f]*'
BIN=target/debug/deps/biometric-<hash>          # from the line above
T=/tmp/VaultBiometricTest.app
rm -rf "$T" && mkdir -p "$T/Contents/MacOS"
cp "$BIN" "$T/Contents/MacOS/biometric"
cp "$VAULT_PROVISION_PROFILE" "$T/Contents/embedded.provisionprofile"
sed 's/@VERSION@/0.0.0/g' scripts/Info.plist > "$T/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleExecutable biometric" "$T/Contents/Info.plist"
VAULT_TEAM_ID=<TEAMID> scripts/check-entitlements.sh --render /tmp/vault-entitlements.plist
codesign --force --options runtime --entitlements /tmp/vault-entitlements.plist \
  --sign "$VAULT_SIGN_IDENTITY" "$T"
"$T/Contents/MacOS/biometric" --include-ignored --nocapture --test-threads=1
```

Pass: all five tests pass and `enroll_unlock_unenroll` shows one Touch ID prompt. To confirm
the keychain is really reachable, look for an explicit failure rather than a vacuous pass: a
run whose `enroll_unlock_unenroll` fails with `Keychain(-34018)` means the entitlements did
not take effect. The test uses random vault ids in the real app's access group and unenrols
afterwards. Delete `/tmp/VaultBiometricTest.app` when you are done.

### Manual checklist (signed app; required for the biometry-change case)

Use `target/package/Vault.app` from a signed build (notarised or `--skip-notarize`), a
throwaway vault, and a Mac with Touch ID.

1. Open the app and create or open a throwaway vault. Unlock it with the master password.
2. Settings > Security > turn on **Unlock with Touch ID**. Expect no error toast and the
   caption "The master password is still required after a restart, every 7 days and after 5
   failed attempts."
3. Lock (Cmd-L). Click **Unlock with Touch ID** and touch the sensor. Expect the vault to
   unlock.
4. Lock again and unlock with Touch ID again. Expect a fresh Touch ID prompt each time, never
   a silent unlock.
5. Lock, click **Unlock with Touch ID**, then press Cancel. Expect to stay on the unlock
   screen with no failure message (cancelling does not count as a failed attempt).
6. **Biometry change.** In System Settings > Touch ID & Password, add a fingerprint. Back in
   Vault, lock and click **Unlock with Touch ID**. Expect no unlock: the toast "Touch ID
   enrollment is no longer valid; enter your master password", with no Touch ID prompt
   because the change is detected before prompting. Settings > Security should then show
   "Touch ID must be set up again." This is the re-enrol hint.
7. Unlock with the master password and turn Touch ID on again. Lock and unlock with Touch ID
   (works again). Remove the fingerprint you added and repeat step 6. Expect the same re-enrol
   hint.
8. Restart the Mac. Expect Touch ID to be refused with "Enter your master password. It is
   required after a restart."
9. Turn Touch ID off in Settings > Security, entering the master password. Expect the toggle
   off and no Touch ID button on the unlock screen.

Record the date, macOS version, Mac model and the result of each step against I-01 in
`docs/qa/security-review-2026-11-26.md`.
