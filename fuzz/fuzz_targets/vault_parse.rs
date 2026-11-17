//! `LockedVault::parse` on arbitrary bytes, then the read-only accessors and both cheap
//! unlock paths (no Argon2: the header's KDF params are attacker-controlled).
//!
//! `unlock_with_key` uses the real vault key of `v2-basic.vault` (unlocked once with the
//! fixture password), so mutants of that seed that keep its `vault_id` and item records
//! decrypt and reach the inner item/manifest decoders. `VaultKeyHandle` has no constructor
//! from raw bytes, so a fixed all-zero key is not expressible through the public API.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use vault_core::{KdfParams, LockedVault, SecretString, SecretVec, Uuid, VaultKeyHandle};

const SEED_VAULT: &[u8] = include_bytes!("../../crates/vault-core/tests/fixtures/v2-basic.vault");
const SEED_PASSWORD: &str = "correct horse battery staple";

fn seed_key() -> Option<&'static VaultKeyHandle> {
    static KEY: OnceLock<Option<VaultKeyHandle>> = OnceLock::new();
    KEY.get_or_init(|| {
        let locked = LockedVault::parse(SEED_VAULT).ok()?;
        let unlocked = locked
            .unlock(&SecretString::new(SEED_PASSWORD.to_owned()))
            .ok()?;
        Some(unlocked.export_vault_key())
    })
    .as_ref()
}

fuzz_target!(|data: &[u8]| {
    let key = seed_key();
    let Ok(vault) = LockedVault::parse(data) else {
        return;
    };
    let _ = vault.vault_id();
    let _: &KdfParams = vault.kdf_params();
    let header = vault.header();
    let _ = header.digest();
    let _ = header.slots_stamp();
    let _ = header.to_bytes();
    let _ = vault.item_summaries().count();
    let slots: Vec<Uuid> = vault.slots().map(|(id, _kind)| id).collect();
    let zero_kek = SecretVec::new(vec![0u8; 32]);
    for id in slots {
        let _ = vault.unlock_with_kek(id, &zero_kek);
    }
    if let Some(key) = key
        && let Ok(unlocked) = vault.unlock_with_key(key, Uuid::nil())
    {
        let _ = unlocked.items_including_deleted().count();
        let _ = unlocked.serialize();
    }
});
