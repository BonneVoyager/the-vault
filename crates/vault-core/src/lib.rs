#![forbid(unsafe_code)]
//! `vault-core`: file format, cryptography and item model for the vault password manager.
//!
//! Pure library: no I/O, no clock (except `KdfParams::calibrate`, which times itself with a
//! monotonic `Instant`), no async, no logging. Bytes in, bytes out. See `specs/01-vault-format.md`
//! and `specs/02-core-api.md`.

pub mod error;
pub mod format;
pub mod item;
pub mod kdf;
pub mod vault;

mod crypto;

pub use error::{TamperKind, VaultError};
pub use format::{FORMAT_VERSION, Header, KeySlot, MAGIC, SlotKind};
pub use item::{Extras, Field, FieldKind, HistoryEntry, Item, ItemKind, Millis};
pub use kdf::KdfParams;
#[cfg(feature = "sync")]
pub use vault::VaultKeyHandle;
pub use vault::{LockedVault, UnlockedVault};
pub use vault::{MergeReport, merge};

// Re-exported so callers do not need to depend on these crates directly for the public API.
pub use secrecy::{ExposeSecret, SecretString, SecretVec};
pub use uuid::Uuid;

pub mod export;
pub mod generator;
pub mod import;
pub mod search;
pub mod totp;

pub use export::{PlaintextExport, export_csv};
pub use generator::{PassphraseSpec, PasswordSpec, passphrase, password, strength_bits};
pub use import::{CsvMapping, ImportError, import_1pux, import_csv};
pub use search::{Query, search};
pub use totp::{Totp, TotpError};
