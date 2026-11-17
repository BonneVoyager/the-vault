//! Harness (2026-11-17), 03 §2: "The lock wait is 10 s (`SaveLockTimeout`, nothing written); test
//! builds may shorten it process-wide through the hidden, `test-support`-gated
//! `shorten_lock_timeout_for_tests`, which can only lower it, and production code has no override."
//!
//! `lock_hook <dir> <arg>...` runs in its own process because the override is process-wide.
//! It creates `<dir>/lh.vault`, saves once (so `.lock` exists), has a perl child hold
//! `flock(LOCK_EX)` on `.lock`, applies each arg in order (`<ms>` = call the hook with that many
//! milliseconds, `race` = 16 threads call it at once with 900..=8900 ms and one with 700 ms,
//! `none` = no call), then times one dirty save. Prints one line:
//! `elapsed_ms=.. err=.. unchanged=.. tmp_left=.. dirty=.. after=.. disp_path=.. disp_pw=..`.
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PW: &str = "lock hook check password";

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let dir = std::path::PathBuf::from(&a[1]);
    let pkg = dir.join("lh.vault");
    let dev = uuid::Uuid::new_v4();
    let pw = secrecy::SecretString::new(PW.to_string());
    let hooks: std::sync::Arc<dyn vault_sync::CloudHooks> =
        std::sync::Arc::new(vault_sync::NoopHooks);
    let mut s =
        vault_sync::SyncedVault::create(&pkg, &pw, vault_core::KdfParams::for_tests(), dev, hooks)
            .unwrap();
    s.edit(|v| v.insert(vault_core::Item::new("one".to_string(), dev, 1000), 1000))
        .unwrap();
    s.save().unwrap();
    let lockp = pkg.join(".lock");
    assert!(lockp.exists(), "03 §2: .lock created by a save");
    let mut perl = Command::new("perl")
        .args([
            "-MFcntl=:flock",
            "-e",
            "$|=1; open(my $f, '>>', $ARGV[0]) or die; flock($f, LOCK_EX) or die; print \"locked\\n\"; sleep 120",
        ])
        .arg(&lockp)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(perl.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "locked");
    for arg in &a[2..] {
        match arg.as_str() {
            "none" => {}
            "race" => {
                let hs: Vec<_> = (0..17u64)
                    .map(|k| {
                        std::thread::spawn(move || {
                            let ms = if k == 16 { 700 } else { 900 + k * 500 };
                            vault_sync::shorten_lock_timeout_for_tests(Duration::from_millis(ms));
                        })
                    })
                    .collect();
                for h in hs {
                    h.join().unwrap();
                }
            }
            ms => vault_sync::shorten_lock_timeout_for_tests(Duration::from_millis(
                ms.parse().unwrap(),
            )),
        }
    }
    let before = std::fs::read(pkg.join("vault.bin")).unwrap();
    s.edit(|v| v.insert(vault_core::Item::new("two".to_string(), dev, 2000), 2000))
        .unwrap();
    let t = Instant::now();
    let r = s.save();
    let el = t.elapsed().as_millis();
    let unchanged = std::fs::read(pkg.join("vault.bin")).unwrap() == before;
    let tmp_left = std::fs::read_dir(&pkg)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().contains(".tmp"));
    let dirty = s.is_dirty();
    let (err, disp) = match &r {
        Ok(()) => ("ok".to_string(), String::new()),
        Err(e) => {
            let d = format!("{e:?}");
            (
                d.split(['(', ' ', '{']).next().unwrap().to_string(),
                e.to_string(),
            )
        }
    };
    let _ = perl.kill();
    let _ = perl.wait();
    let r2 = s.save();
    let n = vault_core::LockedVault::parse(&std::fs::read(pkg.join("vault.bin")).unwrap())
        .unwrap()
        .unlock(&pw)
        .unwrap()
        .items()
        .count();
    println!(
        "elapsed_ms={el} err={err} unchanged={unchanged} tmp_left={tmp_left} dirty={dirty} after={} disp_path={} disp_pw={}",
        if r2.is_ok() && n == 2 { "ok" } else { "FAILED" },
        disp.contains(pkg.to_string_lossy().as_ref()),
        disp.contains(PW)
    );
}
