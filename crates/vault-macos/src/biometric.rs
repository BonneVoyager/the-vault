//! Touch ID convenience unlock (spec 04 §2).
//!
//! A per-vault Secure Enclave P-256 key (tag `<bundle id>.enclave.<vault_id>`,
//! usable only after a biometric match with the *current* enrolled finger set)
//! wraps the enclave-slot KEK with ECIES. The wrapped KEK plus the slot id live
//! in a non-synchronising generic-password Keychain item
//! (service `<bundle id>.enclave`, account `<vault_id>`).
//!
//! This module never touches the vault file; `vault-app` pairs it with
//! `UnlockedVault::add_enclave_slot` / `LockedVault::unlock_with_kek` /
//! `remove_slot` and enforces the policy rules of §2.

use secrecy::SecretVec;
use uuid::Uuid;

use crate::MacError;
use crate::device::BUNDLE_ID;

/// Keychain service of the wrapped-KEK item.
fn service() -> String {
    format!("{BUNDLE_ID}.enclave")
}

/// `kSecAttrApplicationTag` of the Secure Enclave key for `vault_id`.
fn key_tag(vault_id: Uuid) -> String {
    format!("{BUNDLE_ID}.enclave.{vault_id}")
}

/// Touch ID unlock via a Secure Enclave wrapped KEK.
pub struct Biometric;

impl Biometric {
    /// True when `LAContext` can evaluate
    /// `deviceOwnerAuthenticationWithBiometrics` (Touch ID hardware present,
    /// a finger enrolled, not locked out). Secure Enclave support is assumed:
    /// every Mac with Touch ID has one (T2 or Apple Silicon).
    pub fn available() -> bool {
        imp::available()
    }

    /// Creates (or replaces) the Secure Enclave key for `vault_id`, wraps
    /// `kek` with it and stores `{slot_id, ciphertext}` in the Keychain.
    pub fn enroll(vault_id: Uuid, kek: &SecretVec<u8>, slot_id: Uuid) -> Result<(), MacError> {
        imp::enroll(vault_id, kek, slot_id)
    }

    /// Unwraps the KEK for `vault_id`. Shows the Touch ID prompt with
    /// `reason`. Returns `(slot_id, kek)`.
    pub fn unlock(vault_id: Uuid, reason: &str) -> Result<(Uuid, SecretVec<u8>), MacError> {
        imp::unlock(vault_id, reason)
    }

    /// True when the Keychain item for `vault_id` exists. Never prompts.
    pub fn is_enrolled(vault_id: Uuid) -> bool {
        imp::is_enrolled(vault_id)
    }

    /// Deletes the Keychain item and the Secure Enclave key for `vault_id`.
    /// Succeeds when either is already absent.
    pub fn unenroll(vault_id: Uuid) -> Result<(), MacError> {
        imp::unenroll(vault_id)
    }
}

/// CBOR codec of the Keychain item data:
/// `{ "slot_id": bytes(16), "ciphertext": bytes, "domain_state": bytes }`.
/// `domain_state` is optional on decode so items written before it existed still
/// decode; `unlock` treats a missing state as a biometry change.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod payload {
    use ciborium::Value;
    use uuid::Uuid;

    use crate::MacError;

    const SLOT_ID: &str = "slot_id";
    const CIPHERTEXT: &str = "ciphertext";
    const DOMAIN_STATE: &str = "domain_state";

    /// Decoded Keychain item. `Debug` is hand-written and redacts the
    /// ciphertext and domain state.
    #[derive(PartialEq, Eq)]
    pub(crate) struct Payload {
        pub slot_id: Uuid,
        pub ciphertext: Vec<u8>,
        /// `LAContext.evaluatedPolicyDomainState` at enroll time.
        pub domain_state: Option<Vec<u8>>,
    }

    impl std::fmt::Debug for Payload {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Payload")
                .field("slot_id", &self.slot_id)
                .field("ciphertext", &"[redacted]")
                .field(
                    "domain_state",
                    &self.domain_state.as_ref().map(|_| "[redacted]"),
                )
                .finish()
        }
    }

    pub(crate) fn encode(p: &Payload) -> Vec<u8> {
        let mut entries = vec![
            (
                Value::Text(SLOT_ID.into()),
                Value::Bytes(p.slot_id.as_bytes().to_vec()),
            ),
            (
                Value::Text(CIPHERTEXT.into()),
                Value::Bytes(p.ciphertext.clone()),
            ),
        ];
        if let Some(ds) = &p.domain_state {
            entries.push((Value::Text(DOMAIN_STATE.into()), Value::Bytes(ds.clone())));
        }
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut out)
            .expect("writing CBOR to a Vec cannot fail");
        out
    }

    fn malformed(what: &str) -> MacError {
        MacError::Other(format!("malformed Touch ID keychain item: {what}"))
    }

    /// Decodes and validates: only the known keys, each at most once, a
    /// 16-byte slot id, a non-empty ciphertext, an optional non-empty domain
    /// state, no trailing bytes.
    pub(crate) fn decode(data: &[u8]) -> Result<Payload, MacError> {
        let mut reader = data;
        let value: Value = ciborium::from_reader(&mut reader).map_err(|_| malformed("not CBOR"))?;
        if !reader.is_empty() {
            return Err(malformed("trailing bytes"));
        }
        let Value::Map(entries) = value else {
            return Err(malformed("not a map"));
        };
        let (mut slot_id, mut ciphertext, mut domain_state) = (None, None, None);
        for (k, v) in entries {
            match (k, v) {
                (Value::Text(k), Value::Bytes(b)) if k == SLOT_ID && slot_id.is_none() => {
                    let bytes: [u8; 16] = b.try_into().map_err(|_| malformed("slot_id length"))?;
                    slot_id = Some(Uuid::from_bytes(bytes));
                }
                (Value::Text(k), Value::Bytes(b)) if k == CIPHERTEXT && ciphertext.is_none() => {
                    if b.is_empty() {
                        return Err(malformed("empty ciphertext"));
                    }
                    ciphertext = Some(b);
                }
                (Value::Text(k), Value::Bytes(b))
                    if k == DOMAIN_STATE && domain_state.is_none() =>
                {
                    if b.is_empty() {
                        return Err(malformed("empty domain_state"));
                    }
                    domain_state = Some(b);
                }
                _ => return Err(malformed("unexpected entry")),
            }
        }
        match (slot_id, ciphertext) {
            (Some(slot_id), Some(ciphertext)) => Ok(Payload {
                slot_id,
                ciphertext,
                domain_state,
            }),
            _ => Err(malformed("missing field")),
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ptr::{self, NonNull};

    use objc2::rc::Retained;
    use objc2_core_foundation::{
        CFBoolean, CFData, CFDictionary, CFError, CFNumber, CFRetained, CFString, CFType,
        kCFErrorUnderlyingErrorKey,
    };
    use objc2_local_authentication::{LAContext, LAError, LAPolicy};
    use objc2_security::{
        SecAccessControl, SecAccessControlCreateFlags, SecItemAdd, SecItemCopyMatching,
        SecItemDelete, SecKey, errSecAuthFailed, errSecInvalidKeyRef, errSecItemNotFound,
        errSecSuccess, errSecUserCanceled, kSecAttrAccessControl, kSecAttrAccessible,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAttrAccount, kSecAttrApplicationTag,
        kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits,
        kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrService, kSecAttrSynchronizable,
        kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassGenericPassword,
        kSecClassKey, kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
        kSecMatchLimit, kSecMatchLimitOne, kSecPrivateKeyAttrs, kSecReturnAttributes,
        kSecReturnData, kSecReturnRef, kSecUseAuthenticationContext, kSecUseDataProtectionKeychain,
        kSecValueData,
    };
    use secrecy::{ExposeSecret, SecretVec};
    use uuid::Uuid;

    use super::payload::{self, Payload};
    use super::{key_tag, service};
    use crate::MacError;

    /// KEK length (spec 01 §2: enclave slot KEK is 32 random bytes).
    const KEK_LEN: usize = 32;
    const LA_ERROR_DOMAIN: &str = "com.apple.LocalAuthentication";

    type Pairs<'a> = Vec<(&'static CFString, &'a CFType)>;

    type Dict = CFRetained<CFDictionary<CFString, CFType>>;

    fn dict(pairs: &Pairs<'_>) -> Dict {
        let keys: Vec<&CFString> = pairs.iter().map(|(k, _)| *k).collect();
        let vals: Vec<&CFType> = pairs.iter().map(|(_, v)| *v).collect();
        CFDictionary::from_slices(&keys, &vals)
    }

    fn cf_true() -> &'static CFType {
        CFBoolean::new(true).as_ref()
    }

    /// Takes ownership of a `CFErrorRef` out-parameter.
    fn take_error(err: *mut CFError) -> Option<CFRetained<CFError>> {
        // SAFETY: Security out-parameters return a +1 (create-rule) CFError or NULL.
        NonNull::new(err).map(|p| unsafe { CFRetained::from_raw(p) })
    }

    /// A fresh `LAContext` after a successful biometric `canEvaluatePolicy`
    /// preflight (never prompts). On failure returns the LAError code.
    fn preflight() -> Result<Retained<LAContext>, isize> {
        // SAFETY: plain `[[LAContext alloc] init]`; any thread.
        let ctx = unsafe { LAContext::new() };
        // SAFETY: preflight only, never prompts; the policy is a valid constant.
        match unsafe {
            ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
        } {
            Ok(()) => Ok(ctx),
            Err(e) if e.domain().to_string() == LA_ERROR_DOMAIN => Err(e.code()),
            Err(_) => Err(LAError::BiometryNotAvailable.0),
        }
    }

    /// `evaluatedPolicyDomainState`: opaque hash of the enrolled finger set, set after a
    /// successful biometric `canEvaluatePolicy`/evaluation. Deprecated in macOS 15 in favour
    /// of `LADomainState`, which does not exist on our macOS 14 floor. Apple warns it may
    /// change across major OS updates; that only forces a password unlock and re-enroll.
    fn domain_state(ctx: &LAContext) -> Option<Vec<u8>> {
        // SAFETY: property getter on a context we own. (NSData::to_vec is enabled through
        // objc2-local-authentication's LAContext feature.)
        #[allow(deprecated)]
        let data = unsafe { ctx.evaluatedPolicyDomainState() }?;
        Some(data.to_vec())
    }

    pub(super) fn available() -> bool {
        preflight().is_ok()
    }

    /// Generic-password query matching the item for `vault_id`.
    fn item_query<'a>(service: &'a CFString, account: &'a CFString) -> Pairs<'a> {
        // SAFETY: immutable CFString constants exported by Security.framework.
        unsafe {
            vec![
                (kSecClass, kSecClassGenericPassword.as_ref()),
                (kSecAttrService, service.as_ref()),
                (kSecAttrAccount, account.as_ref()),
                (kSecUseDataProtectionKeychain, cf_true()),
            ]
        }
    }

    /// Query matching the Secure Enclave private key for `tag`.
    fn key_query(tag: &CFData) -> Pairs<'_> {
        // SAFETY: immutable CFString constants exported by Security.framework.
        unsafe {
            vec![
                (kSecClass, kSecClassKey.as_ref()),
                (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom.as_ref()),
                (kSecAttrKeyClass, kSecAttrKeyClassPrivate.as_ref()),
                (kSecAttrApplicationTag, tag.as_ref()),
                (kSecUseDataProtectionKeychain, cf_true()),
            ]
        }
    }

    fn strings(
        vault_id: Uuid,
    ) -> (
        CFRetained<CFString>,
        CFRetained<CFString>,
        CFRetained<CFData>,
    ) {
        (
            CFString::from_str(&service()),
            CFString::from_str(&vault_id.to_string()),
            CFData::from_bytes(key_tag(vault_id).as_bytes()),
        )
    }

    fn delete(pairs: &Pairs<'_>) -> Result<(), MacError> {
        // SAFETY: the query is a CFDictionary<CFString, CFType> of valid Security attributes.
        match unsafe { SecItemDelete(dict(pairs).as_opaque()) } {
            s if s == errSecSuccess || s == errSecItemNotFound => Ok(()),
            s => Err(MacError::Keychain(s)),
        }
    }

    /// `SecItemCopyMatching` returning one object, or the OSStatus.
    fn copy_matching(pairs: &Pairs<'_>) -> Result<CFRetained<CFType>, i32> {
        let mut out: *const CFType = ptr::null();
        // SAFETY: valid query dictionary; `out` is a valid out-pointer that receives a +1
        // reference (or stays NULL) per the SecItemCopyMatching contract.
        let status = unsafe { SecItemCopyMatching(dict(pairs).as_opaque(), &mut out) };
        if status != errSecSuccess {
            return Err(status);
        }
        // SAFETY: on success `out` holds a create-rule reference we now own.
        NonNull::new(out.cast_mut())
            .map(|p| unsafe { CFRetained::from_raw(p) })
            .ok_or(errSecItemNotFound)
    }

    pub(super) fn is_enrolled(vault_id: Uuid) -> bool {
        let (service, account, _) = strings(vault_id);
        let mut q = item_query(&service, &account);
        // Attributes only: existence check that never returns the data and never prompts.
        // SAFETY: immutable CFString/CFBoolean constants exported by Security/CoreFoundation.
        unsafe {
            q.push((kSecReturnAttributes, cf_true()));
            q.push((kSecMatchLimit, kSecMatchLimitOne.as_ref()));
        }
        copy_matching(&q).is_ok()
    }

    pub(super) fn unenroll(vault_id: Uuid) -> Result<(), MacError> {
        let (service, account, tag) = strings(vault_id);
        let item = delete(&item_query(&service, &account));
        let key = delete(&key_query(&tag));
        item.and(key)
    }

    pub(super) fn enroll(
        vault_id: Uuid,
        kek: &SecretVec<u8>,
        slot_id: Uuid,
    ) -> Result<(), MacError> {
        if kek.expose_secret().len() != KEK_LEN {
            return Err(MacError::Other(format!("kek must be {KEK_LEN} bytes")));
        }
        let ctx = preflight().map_err(|_| MacError::NotAvailable)?;
        let domain_state = domain_state(&ctx)
            .ok_or_else(|| MacError::Other("biometric domain state unavailable".into()))?;
        drop(ctx);
        // Overwrite semantics: drop any previous item and key for this vault.
        unenroll(vault_id)?;
        let (service, account, tag) = strings(vault_id);

        let mut err: *mut CFError = ptr::null_mut();
        // SAFETY: protection is a kSecAttrAccessible* constant; `err` is a valid out-pointer.
        let acl = unsafe {
            SecAccessControl::with_flags(
                None,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly.as_ref(),
                SecAccessControlCreateFlags::PrivateKeyUsage
                    | SecAccessControlCreateFlags::BiometryCurrentSet,
                &mut err,
            )
        }
        .ok_or_else(|| cf_error(take_error(err)))?;

        let bits = CFNumber::new_i32(256);
        // SAFETY: immutable CFString constants exported by Security.framework.
        let private_attrs = dict(&unsafe {
            vec![
                (kSecAttrIsPermanent, cf_true()),
                (kSecAttrApplicationTag, tag.as_ref()),
                (kSecAttrAccessControl, acl.as_ref()),
            ]
        });
        // SAFETY: as above.
        let params = dict(&unsafe {
            vec![
                (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom.as_ref()),
                (kSecAttrKeySizeInBits, bits.as_ref()),
                (kSecAttrTokenID, kSecAttrTokenIDSecureEnclave.as_ref()),
                (kSecPrivateKeyAttrs, private_attrs.as_ref()),
                (kSecUseDataProtectionKeychain, cf_true()),
            ]
        });
        let mut err: *mut CFError = ptr::null_mut();
        // SAFETY: `params` holds valid SecKeyCreateRandomKey attributes; `err` is a valid
        // out-pointer.
        let private = unsafe { SecKey::new_random_key(params.as_opaque(), &mut err) }
            .ok_or_else(|| cf_error(take_error(err)))?;

        let result = wrap_and_store(&private, kek, slot_id, domain_state, &service, &account);
        if result.is_err() {
            // Best effort: do not leave an orphaned enclave key behind.
            let _ = delete(&key_query(&tag));
        }
        result
    }

    fn wrap_and_store(
        private: &SecKey,
        kek: &SecretVec<u8>,
        slot_id: Uuid,
        domain_state: Vec<u8>,
        service: &CFString,
        account: &CFString,
    ) -> Result<(), MacError> {
        // SAFETY: `private` is a valid SecKey; SecKeyCopyPublicKey has no other preconditions.
        let public = unsafe { private.public_key() }
            .ok_or_else(|| MacError::Other("secure enclave key has no public key".into()))?;
        // The CF copy of the KEK is released (not zeroed) when `plain` drops; CFData offers no
        // wipe hook. The Rust-side copy is the caller's SecretVec.
        let plain = CFData::from_bytes(kek.expose_secret());
        let mut err: *mut CFError = ptr::null_mut();
        // SAFETY: valid key, algorithm constant and plaintext; `err` is a valid out-pointer.
        let ciphertext = unsafe {
            public.encrypted_data(
                kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
                &plain,
                &mut err,
            )
        }
        .ok_or_else(|| cf_error(take_error(err)))?;
        drop(plain);

        let data = CFData::from_bytes(&payload::encode(&Payload {
            slot_id,
            ciphertext: ciphertext.to_vec(),
            domain_state: Some(domain_state),
        }));
        let mut q = item_query(service, account);
        // SAFETY: immutable CFString/CFBoolean constants exported by Security/CoreFoundation.
        unsafe {
            q.push((kSecValueData, data.as_ref()));
            q.push((
                kSecAttrAccessible,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly.as_ref(),
            ));
            q.push((kSecAttrSynchronizable, CFBoolean::new(false).as_ref()));
        }
        // SAFETY: valid attribute dictionary; NULL result pointer is allowed.
        match unsafe { SecItemAdd(dict(&q).as_opaque(), ptr::null_mut()) } {
            s if s == errSecSuccess => Ok(()),
            s => Err(MacError::Keychain(s)),
        }
    }

    pub(super) fn unlock(vault_id: Uuid, reason: &str) -> Result<(Uuid, SecretVec<u8>), MacError> {
        let (service, account, tag) = strings(vault_id);

        let mut q = item_query(&service, &account);
        // SAFETY: immutable CFString/CFBoolean constants exported by Security/CoreFoundation.
        unsafe {
            q.push((kSecReturnData, cf_true()));
            q.push((kSecMatchLimit, kSecMatchLimitOne.as_ref()));
        }
        let data = copy_matching(&q)
            .map_err(MacError::Keychain)?
            .downcast::<CFData>()
            .map_err(|_| MacError::Other("keychain item data is not CFData".into()))?;
        let Payload {
            slot_id,
            ciphertext,
            domain_state: enrolled_state,
        } = payload::decode(&data.to_vec())?;
        // Items written before domain_state existed cannot be checked: force a re-enroll.
        let Some(enrolled_state) = enrolled_state else {
            return Err(MacError::BiometryChanged);
        };

        // Detect a changed finger set before prompting: BiometryCurrentSet keys then fail
        // with a generic errSecAuthFailed only after the user has touched the sensor.
        let ctx = preflight().map_err(map_la)?;
        if domain_state(&ctx).as_deref() != Some(enrolled_state.as_slice()) {
            return Err(MacError::BiometryChanged);
        }
        // SAFETY: setter on a context we own; the string is copied.
        unsafe { ctx.setLocalizedReason(&objc2_foundation::NSString::from_str(reason)) };
        // SAFETY: LAContext is an NSObject; Objective-C objects are valid CFTypeRefs
        // (toll-free retain/release), and `ctx` outlives every use of the reference.
        let ctx_cf: &CFType = unsafe { &*Retained::as_ptr(&ctx).cast::<CFType>() };

        let mut kq = key_query(&tag);
        // SAFETY: immutable CFString/CFBoolean constants exported by Security/CoreFoundation.
        unsafe {
            kq.push((kSecReturnRef, cf_true()));
            kq.push((kSecMatchLimit, kSecMatchLimitOne.as_ref()));
            kq.push((kSecUseAuthenticationContext, ctx_cf));
        }
        let key = match copy_matching(&kq) {
            Ok(obj) => obj
                .downcast::<SecKey>()
                .map_err(|_| MacError::Other("keychain returned a non-key object".into()))?,
            // Item present but key gone: the enrollment is unusable; re-enroll with the password.
            Err(s) if s == errSecItemNotFound => return Err(MacError::BiometryChanged),
            Err(s) => return Err(map_status(s)),
        };

        let ct = CFData::from_bytes(&ciphertext);
        let mut err: *mut CFError = ptr::null_mut();
        // SAFETY: valid private key, algorithm constant and ciphertext; `err` is a valid
        // out-pointer. This call shows the Touch ID prompt.
        let plain = unsafe {
            key.decrypted_data(
                kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
                &ct,
                &mut err,
            )
        }
        .ok_or_else(|| {
            let changed = domain_state(&ctx).as_deref() != Some(enrolled_state.as_slice());
            decrypt_error(take_error(err), changed)
        })?;
        drop(ctx);

        // The CFData buffer is released, not wiped (no API for it); our copy is a SecretVec.
        let kek = SecretVec::new(plain.to_vec());
        drop(plain);
        if kek.expose_secret().len() != KEK_LEN {
            return Err(MacError::Other("unwrapped kek has the wrong length".into()));
        }
        Ok((slot_id, kek))
    }

    fn map_status(status: i32) -> MacError {
        match status {
            s if s == errSecUserCanceled => MacError::UserCancelled,
            s if s == errSecInvalidKeyRef => MacError::BiometryChanged,
            s => MacError::Keychain(s),
        }
    }

    fn map_la(code: isize) -> MacError {
        match LAError(code) {
            LAError::UserCancel
            | LAError::SystemCancel
            | LAError::AppCancel
            | LAError::UserFallback => MacError::UserCancelled,
            LAError::BiometryNotAvailable | LAError::BiometryNotEnrolled => {
                MacError::BiometryChanged
            }
            LAError::BiometryLockout => MacError::Other("Touch ID is locked out".into()),
            _ => MacError::Other(format!("LocalAuthentication error {code}")),
        }
    }

    /// Maps a `SecKeyCreateDecryptedData` failure. `errSecAuthFailed` is what an
    /// invalidated BiometryCurrentSet key returns, but also what a failed match can return:
    /// it means BiometryChanged only when the domain state differs from the enrolled one;
    /// otherwise the LAError nested in the userInfo (if any) decides.
    fn decrypt_error(err: Option<CFRetained<CFError>>, domain_changed: bool) -> MacError {
        let Some(err) = err else {
            return cf_error(None);
        };
        let is_la = err
            .domain()
            .is_some_and(|d| d.to_string() == LA_ERROR_DOMAIN);
        if is_la || err.code() != errSecAuthFailed as isize {
            return cf_error(Some(err));
        }
        if domain_changed {
            return MacError::BiometryChanged;
        }
        match underlying_la_code(&err) {
            Some(code) => map_la(code),
            None => MacError::Keychain(errSecAuthFailed),
        }
    }

    /// First LocalAuthentication error code in the `NSUnderlyingError` chain (depth ≤ 4).
    fn underlying_la_code(err: &CFError) -> Option<isize> {
        // SAFETY: immutable CFString constant exported by CoreFoundation.
        let key = unsafe { kCFErrorUnderlyingErrorKey }?;
        let mut current = err.user_info()?;
        for _ in 0..4 {
            // SAFETY: CFError userInfo dictionaries have CFString keys and CFType values.
            let info = unsafe { current.cast_unchecked::<CFString, CFType>() };
            let next = info.get(key)?.downcast::<CFError>().ok()?;
            if next
                .domain()
                .is_some_and(|d| d.to_string() == LA_ERROR_DOMAIN)
            {
                return Some(next.code());
            }
            current = next.user_info()?;
        }
        None
    }

    fn cf_error(err: Option<CFRetained<CFError>>) -> MacError {
        let Some(err) = err else {
            return MacError::Other("Security framework call failed without an error".into());
        };
        let code = err.code();
        let domain = err.domain().map(|d| d.to_string()).unwrap_or_default();
        if domain == LA_ERROR_DOMAIN {
            map_la(code)
        } else {
            // NSOSStatusErrorDomain (and CryptoTokenKit) codes are OSStatus values.
            map_status(i32::try_from(code).unwrap_or(i32::MIN))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn status_mapping() {
            assert!(matches!(map_status(-128), MacError::UserCancelled));
            assert!(matches!(map_status(-67712), MacError::BiometryChanged));
            assert!(matches!(map_status(-25293), MacError::Keychain(-25293)));
            assert!(matches!(map_la(-2), MacError::UserCancelled));
            assert!(matches!(map_la(-4), MacError::UserCancelled));
            assert!(matches!(map_la(-6), MacError::BiometryChanged));
            assert!(matches!(map_la(-7), MacError::BiometryChanged));
            assert!(matches!(map_la(-8), MacError::Other(_)));
        }

        fn error(domain: &str, code: isize, underlying: Option<&CFError>) -> CFRetained<CFError> {
            let info = underlying.map(|u| {
                // SAFETY: immutable CFString constant exported by CoreFoundation.
                let key = unsafe { kCFErrorUnderlyingErrorKey }.unwrap();
                let value: &CFType = u.as_ref();
                CFDictionary::<CFString, CFType>::from_slices(&[key], &[value])
            });
            // SAFETY: valid domain string and a CFString-keyed userInfo dictionary.
            unsafe {
                CFError::new(
                    None,
                    Some(&CFString::from_str(domain)),
                    code,
                    info.as_deref().map(|d| d.as_opaque()),
                )
            }
            .unwrap()
        }

        #[test]
        fn decrypt_auth_failed_mapping() {
            const OS: &str = "NSOSStatusErrorDomain";
            let auth = || error(OS, -25293, None);
            // Finger set changed (or no enrolled state): BiometryChanged.
            assert!(matches!(
                decrypt_error(Some(auth()), true),
                MacError::BiometryChanged
            ));
            // Unchanged, no nested LAError: plain keychain error.
            assert!(matches!(
                decrypt_error(Some(auth()), false),
                MacError::Keychain(-25293)
            ));
            // Unchanged, nested LAError decides.
            let cancel = error(LA_ERROR_DOMAIN, -2, None);
            let wrapped = error(OS, -25293, Some(&cancel));
            assert!(matches!(
                decrypt_error(Some(wrapped), false),
                MacError::UserCancelled
            ));
            let lockout = error(LA_ERROR_DOMAIN, -8, None);
            let mid = error("CryptoTokenKit", -9, Some(&lockout));
            let wrapped = error(OS, -25293, Some(&mid));
            assert!(matches!(
                decrypt_error(Some(wrapped), false),
                MacError::Other(_)
            ));
            // Other codes keep the generic mapping regardless of domain state.
            assert!(matches!(
                decrypt_error(Some(error(OS, -128, None)), true),
                MacError::UserCancelled
            ));
            assert!(matches!(
                decrypt_error(Some(error(LA_ERROR_DOMAIN, -2, None)), true),
                MacError::UserCancelled
            ));
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use secrecy::SecretVec;
    use uuid::Uuid;

    use crate::MacError;

    pub(super) fn available() -> bool {
        false
    }
    pub(super) fn enroll(_: Uuid, _: &SecretVec<u8>, _: Uuid) -> Result<(), MacError> {
        Err(MacError::NotAvailable)
    }
    pub(super) fn unlock(_: Uuid, _: &str) -> Result<(Uuid, SecretVec<u8>), MacError> {
        Err(MacError::NotAvailable)
    }
    pub(super) fn is_enrolled(_: Uuid) -> bool {
        false
    }
    pub(super) fn unenroll(_: Uuid) -> Result<(), MacError> {
        Err(MacError::NotAvailable)
    }
}

#[cfg(test)]
mod tests {
    use super::payload::{Payload, decode, encode};
    use super::*;
    use ciborium::Value;

    fn cbor(v: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(v, &mut out).unwrap();
        out
    }

    #[test]
    fn payload_round_trip() {
        for domain_state in [Some(vec![9u8; 32]), None] {
            let p = Payload {
                slot_id: Uuid::new_v4(),
                ciphertext: vec![7u8; 97],
                domain_state,
            };
            assert_eq!(decode(&encode(&p)).unwrap(), p);
        }
    }

    #[test]
    fn payload_debug_redacts_secrets() {
        let p = Payload {
            slot_id: Uuid::nil(),
            ciphertext: vec![0xAB; 4],
            domain_state: Some(vec![0xCD; 4]),
        };
        let s = format!("{p:?}");
        assert!(s.contains("[redacted]"));
        assert!(!s.contains("171") && !s.contains("205"), "{s}");
    }

    #[test]
    fn payload_without_domain_state_still_decodes() {
        let t = |s: &str| Value::Text(s.into());
        let slot = Uuid::new_v4();
        let old = cbor(&Value::Map(vec![
            (t("slot_id"), Value::Bytes(slot.as_bytes().to_vec())),
            (t("ciphertext"), Value::Bytes(vec![1, 2, 3])),
        ]));
        let p = decode(&old).unwrap();
        assert_eq!(p.slot_id, slot);
        assert_eq!(p.domain_state, None);
    }

    #[test]
    fn payload_rejects_malformed() {
        let t = |s: &str| Value::Text(s.into());
        let b = |n: usize| Value::Bytes(vec![1; n]);
        let good = encode(&Payload {
            slot_id: Uuid::new_v4(),
            ciphertext: vec![1, 2, 3],
            domain_state: Some(vec![4]),
        });
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0xff, 0x00],
            [good.clone(), vec![0]].concat(),
            cbor(&Value::Array(vec![b(16), b(3)])),
            cbor(&Value::Map(vec![(t("slot_id"), b(16))])),
            cbor(&Value::Map(vec![
                (t("slot_id"), b(15)),
                (t("ciphertext"), b(3)),
            ])),
            cbor(&Value::Map(vec![
                (t("slot_id"), b(16)),
                (t("ciphertext"), b(0)),
            ])),
            cbor(&Value::Map(vec![
                (t("slot_id"), b(16)),
                (t("ciphertext"), t("x")),
            ])),
            cbor(&Value::Map(vec![
                (t("slot_id"), b(16)),
                (t("slot_id"), b(16)),
            ])),
            cbor(&Value::Map(vec![
                (t("slot_id"), b(16)),
                (t("ciphertext"), b(3)),
                (t("extra"), b(1)),
            ])),
            cbor(&Value::Map(vec![
                (t("slot_id"), b(16)),
                (t("ciphertext"), b(3)),
                (t("domain_state"), b(0)),
            ])),
            cbor(&Value::Map(vec![
                (t("slot_id"), b(16)),
                (t("ciphertext"), b(3)),
                (t("domain_state"), t("x")),
            ])),
            cbor(&Value::Map(vec![
                (t("slot_id"), b(16)),
                (t("ciphertext"), b(3)),
                (t("domain_state"), b(2)),
                (t("domain_state"), b(2)),
            ])),
        ];
        for (i, data) in cases.iter().enumerate() {
            assert!(
                matches!(decode(data), Err(MacError::Other(_))),
                "case {i} accepted"
            );
        }
    }

    #[test]
    fn names_follow_spec() {
        let id = Uuid::nil();
        assert_eq!(service(), "dev.aurora.vault.enclave");
        assert_eq!(
            key_tag(id),
            "dev.aurora.vault.enclave.00000000-0000-0000-0000-000000000000"
        );
    }
}
