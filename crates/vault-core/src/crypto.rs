//! Private crypto helpers: Argon2id KEK, HKDF subkeys, XChaCha20-Poly1305 seal/open and key
//! wrap/unwrap. Nothing here composes AAD; see [`crate::format`] for the AAD layouts.
//!
//! Only RustCrypto primitives are used. There is deliberately no comparison code of our own:
//! the AEAD tag check is the only secret-dependent comparison.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::kdf::KdfParams;

/// Length of every symmetric key in the format.
pub(crate) const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length.
pub(crate) const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub(crate) const TAG_LEN: usize = 16;
/// Length of a wrapped `vault_key`: 32 bytes ciphertext + 16 bytes tag.
pub(crate) const WRAPPED_KEY_LEN: usize = KEY_LEN + TAG_LEN;

/// A 32-byte key that is wiped on drop.
pub(crate) type Key32 = Zeroizing<[u8; KEY_LEN]>;
/// A 24-byte XChaCha20 nonce. Nonces are public; no zeroization needed.
pub(crate) type Nonce = [u8; NONCE_LEN];

const HKDF_INFO_ITEM: &[u8] = b"vault/item/v1";
const HKDF_INFO_MANIFEST: &[u8] = b"vault/manifest/v1";
const HKDF_INFO_ATTACHMENT: &[u8] = b"vault/attachment/v1";

/// Fresh 24-byte nonce from the OS RNG (01 §5).
pub(crate) fn random_nonce() -> Nonce {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Fresh random 32-byte key from the OS RNG.
pub(crate) fn random_key() -> Key32 {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(key.as_mut());
    key
}

/// `Argon2id(NFC(password), salt, m, t, p) -> 32 bytes` (01 §2).
///
/// Returns [`VaultError::Malformed`] if the parameters fail [`KdfParams::validate`] or are
/// rejected by Argon2 (e.g. `m_cost` smaller than `8 * p_cost`), which can only happen with a
/// damaged or hostile header.
pub(crate) fn derive_kek(password: &SecretString, params: &KdfParams) -> Result<Key32, VaultError> {
    params.validate()?;
    // The NFC pass has to materialise a new String; it is moved (not copied) into Zeroizing.
    let normalized: Zeroizing<String> = Zeroizing::new(password.expose_secret().nfc().collect());
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|e| VaultError::Malformed(format!("invalid kdf params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(normalized.as_bytes(), &params.salt, kek.as_mut())
        .map_err(|e| VaultError::Malformed(format!("kdf failed: {e}")))?;
    Ok(kek)
}

/// Copy a caller-supplied KEK (an `enclave` slot's Keychain key) into a zeroizing 32-byte key.
///
/// Returns [`VaultError::Malformed`] if the length is not exactly [`KEY_LEN`]: a KEK of any
/// other length can never have wrapped a slot, and reporting it as `WrongPassword` would hide
/// a caller bug.
pub(crate) fn kek_from_bytes(kek: &SecretVec<u8>) -> Result<Key32, VaultError> {
    let bytes = kek.expose_secret();
    if bytes.len() != KEY_LEN {
        return Err(VaultError::Malformed(format!(
            "kek must be {KEY_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(bytes);
    Ok(key)
}

/// The vault key and every subkey derived from it (01 §3). No `Debug`.
pub(crate) struct Keys {
    /// Random at creation, never derived, never exported. Read only by slot management
    /// (`change_password`, `add_enclave_slot`, `rotate_vault_key`) to wrap it into a slot.
    pub vault_key: Key32,
    /// `HKDF-SHA256(ikm=vault_key, salt=vault_id, info="vault/item/v1")`.
    pub item_key: Key32,
    /// `HKDF-SHA256(ikm=vault_key, salt=vault_id, info="vault/manifest/v1")`.
    pub manifest_key: Key32,
    /// `HKDF-SHA256(ikm=vault_key, salt=vault_id, info="vault/attachment/v1")`. Derived for
    /// spec completeness; attachments arrive in v1.1 so it is unused today.
    #[allow(dead_code)]
    pub attach_key: Key32,
}

impl Keys {
    pub fn from_vault_key(vault_key: Key32, vault_id: Uuid) -> Self {
        let item_key = hkdf_subkey(&vault_key, vault_id, HKDF_INFO_ITEM);
        let manifest_key = hkdf_subkey(&vault_key, vault_id, HKDF_INFO_MANIFEST);
        let attach_key = hkdf_subkey(&vault_key, vault_id, HKDF_INFO_ATTACHMENT);
        Self {
            vault_key,
            item_key,
            manifest_key,
            attach_key,
        }
    }
}

fn hkdf_subkey(vault_key: &Key32, vault_id: Uuid, info: &[u8]) -> Key32 {
    let hk = Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), vault_key.as_ref());
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(info, okm.as_mut())
        .expect("32-byte HKDF-SHA256 output is always within the 255*32 limit");
    okm
}

fn cipher(key: &Key32) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
}

/// XChaCha20-Poly1305 encrypt. Returns `ciphertext || tag`. Infallible for in-memory sizes.
pub(crate) fn seal(key: &Key32, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    cipher(key)
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail")
}

/// XChaCha20-Poly1305 decrypt. `None` on any tag failure (wrong key, nonce, AAD or ciphertext).
/// The tag comparison inside the AEAD is the only comparison; we add none of our own.
pub(crate) fn open(
    key: &Key32,
    nonce: &Nonce,
    aad: &[u8],
    ct: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    cipher(key)
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
        .map(Zeroizing::new)
}

/// Wrap `vault_key` under `kek` for a key slot: 48 bytes = 32 ct + 16 tag.
pub(crate) fn wrap_key(
    kek: &Key32,
    nonce: &Nonce,
    aad: &[u8],
    vault_key: &Key32,
) -> [u8; WRAPPED_KEY_LEN] {
    let ct = seal(kek, nonce, aad, vault_key.as_ref());
    let mut out = [0u8; WRAPPED_KEY_LEN];
    out.copy_from_slice(&ct);
    out
}

/// Unwrap a slot's `wrapped_key`. `None` if the tag fails.
pub(crate) fn unwrap_key(
    kek: &Key32,
    nonce: &Nonce,
    aad: &[u8],
    wrapped: &[u8; WRAPPED_KEY_LEN],
) -> Option<Key32> {
    let plain = open(kek, nonce, aad, wrapped)?;
    if plain.len() != KEY_LEN {
        return None;
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&plain);
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_is_nfc_normalised_before_argon2() {
        let params = KdfParams::for_tests();
        // "é" as precomposed U+00E9 vs decomposed "e" + U+0301.
        let a = SecretString::new("caf\u{e9}".to_owned());
        let b = SecretString::new("cafe\u{301}".to_owned());
        let ka = derive_kek(&a, &params).unwrap();
        let kb = derive_kek(&b, &params).unwrap();
        assert_eq!(ka.as_ref(), kb.as_ref());
    }

    #[test]
    fn invalid_kdf_params_are_malformed() {
        let mut params = KdfParams::for_tests();
        params.m_cost_kib = 1;
        let err = derive_kek(&SecretString::new("x".to_owned()), &params).unwrap_err();
        assert!(matches!(err, VaultError::Malformed(_)));
    }

    #[test]
    fn wrap_unwrap_roundtrip_and_aad_binding() {
        let kek = random_key();
        let vk = random_key();
        let nonce = random_nonce();
        let wrapped = wrap_key(&kek, &nonce, b"aad", &vk);
        assert_eq!(
            unwrap_key(&kek, &nonce, b"aad", &wrapped).unwrap().as_ref(),
            vk.as_ref()
        );
        assert!(unwrap_key(&kek, &nonce, b"aae", &wrapped).is_none());
        assert!(unwrap_key(&random_key(), &nonce, b"aad", &wrapped).is_none());
    }

    #[test]
    fn subkeys_differ_per_info_and_vault_id() {
        let vk = random_key();
        let a = Keys::from_vault_key(vk.clone(), Uuid::from_u128(1));
        let b = Keys::from_vault_key(vk, Uuid::from_u128(2));
        assert_ne!(a.item_key.as_ref(), a.manifest_key.as_ref());
        assert_ne!(a.item_key.as_ref(), a.attach_key.as_ref());
        assert_ne!(a.item_key.as_ref(), b.item_key.as_ref());
    }
}
