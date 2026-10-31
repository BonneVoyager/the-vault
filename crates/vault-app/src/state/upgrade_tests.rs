//! Format upgrade on unlock (01 §9 Version 2): a password unlock of a version 1 file
//! upgrades it once, saves, toasts and forgets Touch ID; a Touch ID unlock never does.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use gpui::{AppContext as _, Entity, TestAppContext};
use vault_core::{LockedVault, SecretString, SecretVec, Uuid};
use vault_sync::VAULT_FILE_NAME;

use super::*;
use crate::biometric::fake::{Call, FakeBiometrics};

const V1_BASIC: &[u8] = include_bytes!("../../../vault-core/tests/fixtures/v1-basic.vault");
/// The password of core's version 1 fixtures (vault-core/tests/fixtures.rs).
const PASSWORD: &str = "correct horse battery staple";

fn pw() -> SecretString {
    SecretString::new(PASSWORD.into())
}

/// A vault package at `dir/t.vault` holding `bytes`.
fn package(dir: &Path, bytes: &[u8]) -> PathBuf {
    let pkg = dir.join("t.vault");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(pkg.join(VAULT_FILE_NAME), bytes).unwrap();
    pkg
}

fn version_on_disk(pkg: &Path) -> u16 {
    let bytes = std::fs::read(pkg.join(VAULT_FILE_NAME)).unwrap();
    LockedVault::parse(&bytes).unwrap().header().format_version
}

fn opened(pkg: PathBuf, cx: &mut TestAppContext) -> (Entity<AppState>, Arc<FakeBiometrics>) {
    let bio = FakeBiometrics::new();
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    state.update(cx, |s, cx| {
        s.set_biometrics(bio.clone());
        s.open_vault(pkg, cx);
    });
    cx.run_until_parked();
    (state, bio)
}

#[gpui::test]
fn password_unlock_upgrades_a_v1_file_once(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let pkg = package(dir.path(), V1_BASIC);
    assert_eq!(version_on_disk(&pkg), 1, "fixture is version 1");
    let (state, bio) = opened(pkg.clone(), cx);
    state.update(cx, |s, cx| s.unlock(pw(), cx));
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert!(!s.locked);
        assert_eq!(
            s.toast.as_ref().map(|t| t.message.to_string()).as_deref(),
            Some(UPGRADED)
        );
        let v = s.unlocked_vault().unwrap();
        assert_eq!(v.header().format_version, vault_core::FORMAT_VERSION);
        assert!(!s.touch.enrolled);
    });
    assert_eq!(version_on_disk(&pkg), vault_core::FORMAT_VERSION, "saved");
    assert!(
        bio.calls().iter().any(|c| matches!(c, Call::Unenroll(_))),
        "Keychain cleanup"
    );

    // Once: the next password unlock finds a current file and says nothing.
    state.update(cx, |s, cx| {
        s.lock(cx);
        s.toast = None;
        s.unlock(pw(), cx);
    });
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert!(!s.locked);
        assert!(
            s.toast
                .as_ref()
                .is_none_or(|t| t.message.as_ref() != UPGRADED)
        );
    });
    // Touch ID can be turned on again after the upgrade.
    state.read_with(cx, |s, _| assert_eq!(s.touch_enable_blocker(), None));
}

#[gpui::test]
fn touch_id_unlock_never_upgrades(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    // A version 1 file with an enclave slot for `kek` (a save keeps the version).
    let kek = SecretVec::new(vec![7u8; 32]);
    let mut unlocked = LockedVault::parse(V1_BASIC).unwrap().unlock(&pw()).unwrap();
    let slot = unlocked.add_enclave_slot(&kek, 1_000);
    let bytes = unlocked.serialize();
    let pkg = package(dir.path(), &bytes);
    assert_eq!(version_on_disk(&pkg), 1);
    let before = std::fs::read(pkg.join(VAULT_FILE_NAME)).unwrap();

    let (state, bio) = opened(pkg.clone(), cx);
    let vault_id = state.read_with(cx, |s, _| s.vault_id.unwrap());
    bio.with(|i| {
        i.enrolled.insert(vault_id, (slot, vec![7u8; 32]));
    });
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    state.update(cx, |s, cx| {
        s.settings.touch_id.insert(
            vault_id,
            TouchIdPolicy {
                slot_id: slot,
                enrolled_at: now,
                last_password_unlock_at: now,
                failed_touch_attempts: 0,
                stale: false,
            },
        );
        s.refresh_touch();
        assert!(s.touch_policy().is_ok(), "{:?}", s.touch_policy());
        s.touch_unlock(cx);
    });
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert!(!s.locked, "unlocked with Touch ID");
        assert_eq!(s.unlocked_vault().unwrap().header().format_version, 1);
        assert!(
            s.toast
                .as_ref()
                .is_none_or(|t| t.message.as_ref() != UPGRADED)
        );
        assert!(s.touch.enrolled, "enrolment untouched");
    });
    assert!(!bio.calls().iter().any(|c| matches!(c, Call::Unenroll(_))));
    assert_eq!(version_on_disk(&pkg), 1);
    let after = std::fs::read(pkg.join(VAULT_FILE_NAME)).unwrap();
    assert_eq!(after, before, "file left as is");
}

#[gpui::test]
fn failed_save_discards_the_upgrade(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let pkg = package(dir.path(), V1_BASIC);
    let (state, bio) = opened(pkg.clone(), cx);
    // The upgrade's save fails before the file is replaced: the package folder turns
    // read-only right before the primary write (gpui tests run background work on this
    // thread, where the hook lives).
    use std::os::unix::fs::PermissionsExt as _;
    let ro = pkg.clone();
    vault_sync::before_next_primary_write_for_tests(move || {
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
    });
    state.update(cx, |s, cx| s.unlock(pw(), cx));
    cx.run_until_parked();
    std::fs::set_permissions(&pkg, std::fs::Permissions::from_mode(0o700)).unwrap();
    state.read_with(cx, |s, _| {
        assert!(!s.locked, "re-opened from disk, still unlocked");
        let toast = s.toast.as_ref().map(|t| t.message.to_string()).unwrap();
        assert!(
            toast.starts_with("Could not upgrade the vault format"),
            "{toast}"
        );
        let v = s.unlocked_vault().unwrap();
        assert_eq!(v.header().format_version, 1, "upgrade discarded in memory");
        assert!(!s.vault.as_ref().unwrap().is_dirty());
    });
    assert_eq!(version_on_disk(&pkg), 1);
    assert!(
        !bio.calls().iter().any(|c| matches!(c, Call::Unenroll(_))),
        "no unenroll"
    );

    // A later edit and save still writes version 1.
    state.update(cx, |s, cx| {
        let id = s.unlocked_vault().unwrap().items().next().unwrap().id;
        s.vault
            .as_mut()
            .unwrap()
            .edit(|v| v.update(id, crate::text::now_millis(), |it| it.title.push('!')))
            .unwrap()
            .unwrap();
        s.vault_changed();
        s.save_now(cx);
    });
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert!(!s.vault.as_ref().unwrap().is_dirty(), "saved")
    });
    assert_eq!(version_on_disk(&pkg), 1, "the edit did not write format 2");
    assert!(!bio.calls().iter().any(|c| matches!(c, Call::Unenroll(_))));

    // The next password unlock retries and succeeds.
    state.update(cx, |s, cx| {
        s.lock(cx);
        s.unlock(pw(), cx);
    });
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert_eq!(
            s.toast.as_ref().map(|t| t.message.to_string()).as_deref(),
            Some(UPGRADED)
        );
    });
    assert_eq!(version_on_disk(&pkg), vault_core::FORMAT_VERSION);
}

#[gpui::test]
fn save_error_after_the_rename_still_counts_as_upgraded(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let pkg = package(dir.path(), V1_BASIC);
    let (state, bio) = opened(pkg.clone(), cx);
    // The file is replaced but the directory fsync fails: save reports an error.
    vault_sync::fail_next_dir_syncs_for_tests(1_000);
    state.update(cx, |s, cx| s.unlock(pw(), cx));
    cx.run_until_parked();
    vault_sync::fail_next_dir_syncs_for_tests(0);
    // The disk decides: format 2 landed, so the upgrade is finished properly.
    assert_eq!(version_on_disk(&pkg), vault_core::FORMAT_VERSION);
    state.read_with(cx, |s, _| {
        assert!(!s.locked);
        assert_eq!(
            s.toast.as_ref().map(|t| t.message.to_string()).as_deref(),
            Some(UPGRADED)
        );
        assert_eq!(
            s.unlocked_vault().unwrap().header().format_version,
            vault_core::FORMAT_VERSION
        );
    });
    assert!(bio.calls().iter().any(|c| matches!(c, Call::Unenroll(_))));
}
