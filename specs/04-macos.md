# 04 — `vault-macos`: platform integration

The only crate allowed `unsafe` and macOS-only dependencies. Everything here is behind a small trait or function so `vault-app` can be built with stub impls on CI machines without a Secure Enclave.

Dependencies: `objc2`, `objc2-foundation`, `objc2-app-kit`, `objc2-local-authentication`, `security-framework` (Keychain), `core-foundation`. Pin all with `=` (this crate overrides the CLAUDE.md caret rule).

Minimum target: macOS 15 (passkey PRF needs it; `LSMinimumSystemVersion 15.0`).

## 1. Device identity

`device_id() -> Uuid` — generated once, stored in `~/Library/Application Support/<bundle id>/device_id`. Used as `device_id` in items and in the Dropbox conflict pattern. Not secret.

## 2. Touch ID convenience unlock

Goal: after the user has unlocked with the master password once on this Mac, subsequent unlocks can use Touch ID. Security property: the vault key never leaves the process unencrypted except in memory; the wrapping key lives in the Secure Enclave and requires biometry to use.

Design (per vault, keyed by `vault_id`):

```
1. On "Enable Touch ID" (requires vault unlocked):
   a. Create a Secure Enclave key:
        SecKeyCreateRandomKey with
          kSecAttrKeyType = kSecAttrKeyTypeECSECPrimeRandom
          kSecAttrKeySizeInBits = 256
          kSecAttrTokenID = kSecAttrTokenIDSecureEnclave
          kSecAttrAccessControl = SecAccessControlCreateWithFlags(
              kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
              kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet)
          kSecAttrApplicationTag = "<bundle id>.enclave.<vault_id>"
   b. Generate kek = 32 random bytes.
   c. vault.add_enclave_slot(kek) → slot_id   (vault-core)
   d. Encrypt kek with the SE public key (SecKeyCreateEncryptedData, eciesEncryptionCofactorVariableIVX963SHA256AESGCM)
      → store ciphertext in Keychain generic password item:
          service = "<bundle id>.enclave", account = "<vault_id>", data = CBOR{ slot_id, ciphertext }
          kSecAttrAccessibleWhenUnlockedThisDeviceOnly, no iCloud sync
   e. zeroize kek.
2. On unlock via Touch ID:
   a. Load Keychain item → { slot_id, ciphertext }
   b. SecKeyCreateDecryptedData with the SE private key. The OS prompts Touch ID (LAContext with reason "Unlock <vault name>").
   c. vault.unlock_with_kek(slot_id, kek); zeroize kek.
3. On "Disable Touch ID" or on biometry change (BiometryCurrentSet invalidates the key → decryption errors):
   a. remove Keychain item, delete SE key, vault.remove_slot(slot_id) (requires master password).
```

Policy, enforced by `vault-app`, not here:
- Master password required after reboot (detect via boot time), after 7 days, and after 5 failed Touch ID attempts. The failure counter resets only on a password unlock; creating a vault counts as a password unlock. If boot time cannot be read, require the password (fail closed).
- Touch ID can be enabled only after a successful master-password unlock in this session.
- `rotate_vault_key` drops the enclave slot; Touch ID must be re-enrolled afterwards. Biometry change is detected by comparing the stored `evaluatedPolicyDomainState`; on mismatch the enrolment is stale and the user re-enrols.

### 2b. Passkey unlock (post-phase-5, macOS 15)

Uses `ASAuthorizationPlatformPublicKeyCredentialProvider` with the PRF extension. Enrol: register a passkey for `rp_id` with `prf_salt` → `(credential_id, prf_output)`; derive the KEK per `01` §2 and `vault.add_passkey_slot(...)`. Unlock: assertion with `prf_salt` → `prf_output` → KEK → `unlock_with_kek`. The passkey syncs through iCloud Keychain, so a second Mac needs no extra enrolment. Constraints: a native app may only use an `rp_id` it is associated with, which means an Associated Domains entitlement and an `apple-app-site-association` file hosted on that domain (owner to choose the domain); the PRF output must be verified identical across devices before cross-device unlock is advertised. API: `Passkey::register(vault_id, prf_salt) -> Result<(Vec<u8>, SecretVec<u8>), MacError>`, `Passkey::assert(credential_id, prf_salt, reason) -> Result<SecretVec<u8>, MacError>`, `Passkey::available() -> bool`.

API:

```rust
pub struct Biometric;
impl Biometric {
    pub fn available() -> bool;
    pub fn enroll(vault_id: Uuid, kek: &SecretVec<u8>, slot_id: Uuid) -> Result<(), MacError>;
    pub fn unlock(vault_id: Uuid, reason: &str) -> Result<(Uuid, SecretVec<u8>), MacError>;  // (slot_id, kek)
    pub fn is_enrolled(vault_id: Uuid) -> bool;
    pub fn unenroll(vault_id: Uuid) -> Result<(), MacError>;
}
pub enum MacError { NotAvailable, UserCancelled, BiometryChanged, Keychain(i32), Other(String) }
```

## 3. Pasteboard

```rust
pub struct Clipboard;
impl Clipboard {
    /// Prepares the pasteboard with NSPasteboardContentsOptions.currentHostOnly (never reaches Universal Clipboard),
    /// then writes org.nspasteboard.ConcealedType BEFORE public.utf8-plain-text so no poller sees the text unmarked.
    /// On any write failure the pasteboard is cleared and None is returned.
    pub fn write_concealed(text: &SecretString) -> Option<ChangeCount>;
    /// Clears only if the pasteboard changeCount is still ours.
    pub fn clear_if_unchanged(cc: ChangeCount);
}
```

`vault-app` schedules `clear_if_unchanged` after the configured delay (default 30 s). Also clear on lock.

### 3b. Screen capture (best effort)

`window::exclude_app_windows_from_capture() -> usize` sets `NSWindow.sharingType = .none` on every app window; `vault-app` calls it on the main thread whenever a window is created. Apple documents this constant as legacy and says it must not be relied on to hide content, so it is set as best effort only and never described to the user as protection.

## 4. iCloud eviction (`CloudHooks` impl for `vault-sync`)

```rust
pub struct ICloudHooks;
impl CloudHooks for ICloudHooks {
    fn is_evicted(&self, path) -> bool
        // NSURL.resourceValuesForKeys([NSURLUbiquitousItemDownloadingStatusKey])
        // evicted ⇔ status == NSURLUbiquitousItemDownloadingStatusNotDownloaded
        // non-ubiquitous paths → false
    fn ensure_downloaded(&self, path, timeout)
        // NSFileManager.startDownloadingUbiquitousItemAtURL, then poll status every 250 ms until Current or timeout
    fn pin(&self, path)
        // no public API to pin; best-effort: touch the file's atime hourly while the app runs
}
```

Detecting "is this path inside iCloud Drive": `NSURL.isUbiquitousItemKey` resource value. Dropbox needs nothing special (it keeps a real file on disk; smart sync placeholders are handled by the file provider transparently on 15+).

## 5. Idle and lock triggers

```rust
pub fn seconds_since_user_input() -> f64;          // CGEventSourceSecondsSinceLastEventType(kCGEventSourceStateHIDSystemState, kCGAnyInputEventType)
pub fn on_screen_locked(cb: impl Fn() + Send + 'static) -> Subscription;   // NSDistributedNotificationCenter "com.apple.screenIsLocked", DeliverImmediately
pub fn on_will_sleep(cb: impl Fn() + Send + 'static) -> Subscription;      // NSWorkspace.willSleepNotification
pub fn on_user_switched(cb: impl Fn() + Send + 'static) -> Subscription;   // NSWorkspace.sessionDidResignActiveNotification (fast user switch)
pub fn boot_time() -> SystemTime;                                            // sysctl kern.boottime
```

`Subscription` is a `#[must_use]` guard that removes the observer on drop; drop it on the main thread. Callbacks run on the main thread.

## 6. Security-scoped bookmarks

Only needed if the app is sandboxed. v1 ships outside the App Store, unsandboxed, Developer ID signed. Leave a `bookmark` module stub with a TODO; do not implement now.

## 7. Packaging — `scripts/package.sh`

1. `cargo build --release -p vault-app`
2. Assemble `Vault.app/Contents/{MacOS,Resources,Info.plist}`; Info.plist sets `LSMinimumSystemVersion 14.0`, `NSFaceIDUsageDescription` (required even for Touch ID), `CFBundleIdentifier`, `NSHighResolutionCapable`.
3. `codesign --deep --options runtime --entitlements entitlements.plist --sign "Developer ID Application: …"`. Entitlements: `com.apple.security.cs.allow-jit` **not** needed; keep the list empty except what gpui requires (check at integration time).
3b. `scripts/check-entitlements.sh <app>` runs on the signed bundle and fails the build if the signature lacks the hardened-runtime flag or if any of these is set: `com.apple.security.get-task-allow`, `cs.disable-library-validation`, `cs.allow-dyld-environment-variables`, `cs.allow-unsigned-executable-memory`, `cs.allow-jit`, `cs.debugger`. `--skip-sign` skips it; `--dry-run` prints it.
4. `xcrun notarytool submit … --wait`, `xcrun stapler staple`. Credentials: a notarytool keychain profile is preferred over env vars so no password appears on argv.
5. Produce a `.dmg` with `create-dmg` or `hdiutil`.

Signing identity and notarization credentials come from env vars; the script fails loudly if they're missing. Never commit them.

## 8. Tests

Most of this crate can't run on CI without hardware. Required:
- `Clipboard` round-trip (write, read back via NSPasteboard, clear, assert empty) — runs on any Mac.
- `ICloudHooks::is_evicted` on a non-ubiquitous temp path → false.
- `Biometric` has an `#[ignore]`d integration test that enrolls/unlocks/unenrolls with a throwaway vault id; run manually.
- Everything else gets a stub implementation behind `cfg(not(target_os = "macos"))` or a `stub` feature so `vault-app` compiles on Linux CI with Touch ID reported unavailable.
