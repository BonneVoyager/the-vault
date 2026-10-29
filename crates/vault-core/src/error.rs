//! Error types per `specs/01-vault-format.md` §7, plus one documented extension:
//! [`VaultError::NoUsableSlot`] (forward compatibility, 01 §9) is not in the §7 listing yet
//! and is pending a spec amendment.

use uuid::Uuid;

/// Every failure `vault-core` can report while parsing, unlocking or verifying a vault.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    /// The first four bytes are not `b"RVLT"`.
    #[error("not a vault file (bad magic)")]
    BadMagic,
    /// `format_version` is newer than this build supports.
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u16),
    /// The byte string ends before the fixed prefix or the declared header does.
    #[error("vault file is truncated")]
    Truncated,
    /// CBOR or structural damage (wrong types, missing keys, trailing bytes, ...).
    #[error("vault file is malformed: {0}")]
    Malformed(String),
    /// Every `password` slot failed to unwrap and the header parsed cleanly.
    #[error("wrong password")]
    WrongPassword,
    /// The header parsed cleanly but holds no slot this build can unlock with the credential
    /// offered: `unlock` found no `password` slot at all, or `unlock_with_kek` was pointed at
    /// a slot whose `kind` this build does not know (written by a newer version, 01 §9).
    /// Distinct from [`VaultError::WrongPassword`] so the app can say "this vault uses an
    /// unlock method this version does not support" instead of "wrong password".
    #[error("no key slot this version can unlock (vault written by a newer version?)")]
    NoUsableSlot,
    /// An AEAD tag or the manifest cross-check failed.
    #[error("vault file has been tampered with: {0:?}")]
    Tampered(TamperKind),
}

/// Which part of the file failed its integrity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TamperKind {
    /// Reserved by the spec for structural header damage. Per 01 §7, slot tag failures are
    /// reported as [`VaultError::WrongPassword`], and structural damage as
    /// [`VaultError::Malformed`], so this variant is currently never produced by this crate.
    Header,
    /// The item record with this id failed its AEAD tag (modified, swapped between vaults,
    /// or its plaintext `modified_at` was edited).
    Item(Uuid),
    /// The manifest failed its tag or its `(id, modified_at)` pairs do not match the records.
    Manifest,
    /// Reserved by the spec. The item count is bound into the manifest AAD, so a count
    /// mismatch surfaces as [`TamperKind::Manifest`]; this variant is currently never produced.
    ItemCount,
}
