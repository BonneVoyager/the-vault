mod common;

use std::time::Duration;

use common::*;
use vault_core::KdfParams;
use vault_core::kdf::{
    RECOMMENDED_M_COST_KIB, RECOMMENDED_P_COST, RECOMMENDED_T_COST, TEST_M_COST_KIB,
};

#[test]
fn recommended_and_for_tests() {
    let r = KdfParams::recommended();
    assert_eq!(
        (r.m_cost_kib, r.t_cost, r.p_cost),
        (RECOMMENDED_M_COST_KIB, 3, 4)
    );
    let t = KdfParams::for_tests();
    assert_eq!((t.m_cost_kib, t.t_cost, t.p_cost), (TEST_M_COST_KIB, 1, 1));
    assert_ne!(r.salt, t.salt, "random salts");
    assert_ne!(KdfParams::recommended().salt, r.salt);
}

#[test]
fn validate_bounds() {
    use vault_core::VaultError;
    use vault_core::kdf::{MAX_M_COST_KIB, MAX_P_COST, MAX_T_COST};
    assert!(KdfParams::recommended().validate().is_ok());
    assert!(KdfParams::for_tests().validate().is_ok());
    let mut p = KdfParams::for_tests();
    p.m_cost_kib = MAX_M_COST_KIB;
    p.t_cost = MAX_T_COST;
    p.p_cost = MAX_P_COST;
    assert!(p.validate().is_ok());
    for edit in [
        (|p: &mut KdfParams| p.m_cost_kib = 0) as fn(&mut KdfParams),
        |p| p.m_cost_kib = MAX_M_COST_KIB + 1,
        |p| p.t_cost = 0,
        |p| p.t_cost = MAX_T_COST + 1,
        |p| p.p_cost = 0,
        |p| p.p_cost = MAX_P_COST + 1,
    ] {
        let mut p = KdfParams::for_tests();
        edit(&mut p);
        assert!(matches!(
            p.validate().unwrap_err(),
            VaultError::Malformed(_)
        ));
    }
}

/// V-08: a tampered `t_cost` must not turn every unlock attempt into a half-minute Argon2
/// run. Calibration never leaves `t = 3`, so 16 is already generous.
#[test]
fn t_cost_is_capped_at_16_in_validate_and_in_the_parser() {
    use vault_core::kdf::MAX_T_COST;
    use vault_core::{LockedVault, VaultError};
    assert_eq!(MAX_T_COST, 16);
    let mut p = KdfParams::for_tests();
    p.t_cost = 16;
    assert!(p.validate().is_ok());
    p.t_cost = 17;
    assert!(matches!(
        p.validate().unwrap_err(),
        VaultError::Malformed(m) if m.contains("t_cost")
    ));
    p.t_cost = 64;
    assert!(p.validate().is_err(), "the old ceiling is gone");

    // The parser rejects the header before any Argon2 work; 16 still parses (and the KEK is
    // simply wrong for the stored slots, so it is a WrongPassword, never a hang).
    let v = new_vault();
    let bytes = v.serialize();
    let t17 = rewrite(&bytes, |f| f.header.kdf.t_cost = 17);
    assert!(matches!(
        LockedVault::parse(&t17),
        Err(VaultError::Malformed(m)) if m.contains("t_cost")
    ));
    let t16 = rewrite(&bytes, |f| f.header.kdf.t_cost = 16);
    let locked = LockedVault::parse(&t16).unwrap();
    assert_eq!(locked.kdf_params().t_cost, 16);
    assert_eq!(locked.unlock(&pw()).unwrap_err(), VaultError::WrongPassword);
}

#[test]
fn calibrate_tiny_target_returns_recommended() {
    // One 64 MiB derivation always exceeds 1 ms, so no doubling happens.
    let p = KdfParams::calibrate(Duration::from_millis(1));
    assert_eq!(p.m_cost_kib, RECOMMENDED_M_COST_KIB);
    assert_eq!(p.t_cost, RECOMMENDED_T_COST);
    assert_eq!(p.p_cost, RECOMMENDED_P_COST);
    assert!(p.m_cost_kib >= RECOMMENDED_M_COST_KIB);
    assert!(
        p.validate().is_ok(),
        "calibrate never leaves the accepted bounds"
    );
}
