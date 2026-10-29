//! Argon2id parameters and calibration (`01-vault-format.md` §2, §6).

use std::time::{Duration, Instant};

use rand::RngCore;
use rand::rngs::OsRng;
use secrecy::SecretString;

use crate::crypto;
use crate::error::VaultError;

/// Default memory cost: 64 MiB.
pub const RECOMMENDED_M_COST_KIB: u32 = 64 * 1024;
/// Default iteration count.
pub const RECOMMENDED_T_COST: u32 = 3;
/// Default parallelism.
pub const RECOMMENDED_P_COST: u32 = 4;
/// Calibration never raises `m_cost` beyond 1 GiB.
pub const MAX_M_COST_KIB: u32 = 1024 * 1024;
/// Memory cost used by [`KdfParams::for_tests`]: 8 MiB.
pub const TEST_M_COST_KIB: u32 = 8 * 1024;
/// Upper bound accepted for `t_cost` (header parsing and construction).
pub const MAX_T_COST: u32 = 64;
/// Upper bound accepted for `p_cost` (header parsing and construction).
pub const MAX_P_COST: u32 = 64;

/// Argon2id parameters stored in the plaintext header (`kdf` map).
///
/// The salt is public (it lives in the header), so this type may derive `Debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Lanes / threads.
    pub p_cost: u32,
    /// 32 random bytes from `OsRng`.
    pub salt: [u8; 32],
}

impl KdfParams {
    /// Reject parameters outside the ranges this crate is willing to run: every cost must be
    /// non-zero, `m_cost_kib <= 1 GiB` (the 01 §6 calibration ceiling), `t_cost <= 64`,
    /// `p_cost <= 64`. A hostile header must not be able to make Argon2 allocate terabytes or
    /// iterate for hours before the password is even checked.
    pub fn validate(&self) -> Result<(), VaultError> {
        let bad = |what: &str| Err(VaultError::Malformed(format!("kdf.{what}: out of range")));
        if self.m_cost_kib == 0 || self.m_cost_kib > MAX_M_COST_KIB {
            return bad("m_cost");
        }
        if self.t_cost == 0 || self.t_cost > MAX_T_COST {
            return bad("t_cost");
        }
        if self.p_cost == 0 || self.p_cost > MAX_P_COST {
            return bad("p_cost");
        }
        Ok(())
    }

    fn with_random_salt(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Self {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        Self {
            m_cost_kib,
            t_cost,
            p_cost,
            salt,
        }
    }

    /// 64 MiB / 3 / 4 with a fresh random salt.
    pub fn recommended() -> Self {
        Self::with_random_salt(
            RECOMMENDED_M_COST_KIB,
            RECOMMENDED_T_COST,
            RECOMMENDED_P_COST,
        )
    }

    /// 8 MiB / 1 / 1 with a fresh random salt. Fast enough for unit tests; never use for a
    /// real vault.
    pub fn for_tests() -> Self {
        Self::with_random_salt(TEST_M_COST_KIB, 1, 1)
    }

    /// Start at [`KdfParams::recommended`] and double `m_cost` until a single derivation takes
    /// at least `target` or `m_cost` reaches [`MAX_M_COST_KIB`] (01 §6).
    ///
    /// This is the only place in the crate that reads a clock; it uses a monotonic
    /// `Instant`, not wall-clock time, and performs no I/O.
    pub fn calibrate(target: Duration) -> Self {
        let mut params = Self::recommended();
        let probe = SecretString::new("vault-kdf-calibration".to_owned());
        loop {
            let started = Instant::now();
            // Recommended-derived params are always valid for Argon2; a failure here would be
            // an allocation error, which we treat as "slow enough" rather than panicking.
            let _ = crypto::derive_kek(&probe, &params);
            if started.elapsed() >= target || params.m_cost_kib >= MAX_M_COST_KIB {
                return params;
            }
            params.m_cost_kib = params.m_cost_kib.saturating_mul(2).min(MAX_M_COST_KIB);
        }
    }
}
