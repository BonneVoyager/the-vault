//! vault-macos host facts and login-launch detection, driven as a library (added 2026-11-15, written
//! from the specs before reading the source). The rest of vault-macos stays code read only.
//!
//! - 04 §1b "`os_version() -> String` ("15.1.1", from `NSProcessInfo.operatingSystemVersion`) and
//!   `model_identifier() -> String` ("Mac15,6", from `libc::sysctlbyname("hw.model")` ... "unknown"
//!   on any error, bad length or non-UTF-8). Patch version omitted when 0. No network, no secrets."
//! - 04 §5d "`vault_macos::launched_as_login_item() -> bool` ... main thread only
//!   (`MainThreadMarker`; off-main → false) ... False ... when there is no current event".
//!
//! Independent references: `sw_vers -productVersion` and `sysctl -n hw.model`.
#![cfg(target_os = "macos")]
use std::process::Command;

fn sh(cmd: &str, args: &[&str]) -> String {
    let o = Command::new(cmd).args(args).output().unwrap();
    assert!(o.status.success(), "{cmd} failed");
    String::from_utf8(o.stdout).unwrap().trim().to_string()
}

/// 04 §1b os_version: "major.minor[.patch]", patch omitted when 0, equal to sw_vers.
#[test]
fn hf01_os_version_matches_sw_vers() {
    let got = vault_macos::os_version();
    let sw = sh("sw_vers", &["-productVersion"]);
    let p: Vec<u32> = sw.split('.').map(|x| x.parse().unwrap()).collect();
    let (maj, min, pat) = (p[0], *p.get(1).unwrap_or(&0), *p.get(2).unwrap_or(&0));
    let want = if pat == 0 {
        format!("{maj}.{min}")
    } else {
        format!("{maj}.{min}.{pat}")
    };
    assert_eq!(got, want, "04 §1b os_version vs sw_vers {sw:?}");
}

/// 04 §1b model_identifier equals `sysctl -n hw.model`; printable ASCII, no NUL or newline.
#[test]
fn hf02_model_identifier_matches_sysctl() {
    let got = vault_macos::model_identifier();
    let want = sh("sysctl", &["-n", "hw.model"]);
    assert_eq!(got, want, "04 §1b model_identifier vs sysctl hw.model");
    assert!(
        got.chars().all(|c| c.is_ascii_graphic()),
        "non-printable in {got:?}"
    );
    assert!(got.len() < 256);
}

/// 04 §1b "No network, no secrets": neither string carries the host name or the user name.
#[test]
fn hf03_host_facts_carry_no_identity() {
    let host = sh("hostname", &[]);
    let short = host.split('.').next().unwrap_or("").to_string();
    let user = std::env::var("USER").unwrap_or_default();
    for s in [vault_macos::os_version(), vault_macos::model_identifier()] {
        for bad in [&host, &short, &user] {
            if bad.len() >= 3 {
                assert!(!s.contains(bad.as_str()), "host fact contains identity");
            }
        }
    }
}

/// 04 §5d off-main → false; also "False ... when there is no current event". Test threads are
/// never the main thread; a spawned thread double-checks.
#[test]
fn hf04_login_item_off_main_is_false() {
    assert!(!vault_macos::launched_as_login_item(), "test thread");
    let r = std::thread::spawn(vault_macos::launched_as_login_item)
        .join()
        .expect("no panic off-main");
    assert!(!r, "spawned thread");
}

/// 04 §1b called from many threads at once (Copy diagnostics may run on any executor): stable
/// values, no panic.
#[test]
fn hf05_host_facts_are_thread_safe_and_stable() {
    let (o, m) = (vault_macos::os_version(), vault_macos::model_identifier());
    let hs: Vec<_> = (0..32)
        .map(|_| {
            std::thread::spawn(|| {
                (0..50)
                    .map(|_| (vault_macos::os_version(), vault_macos::model_identifier()))
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    for h in hs {
        for (a, b) in h.join().expect("no panic") {
            assert_eq!((a.as_str(), b.as_str()), (o.as_str(), m.as_str()));
        }
    }
}
