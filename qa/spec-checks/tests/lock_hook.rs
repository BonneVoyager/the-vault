//! 03 §2 save lock and its test hook (2026-11-17), written from the spec before reading the source:
//! "The lock wait is 10 s (`SaveLockTimeout`, nothing written); test builds may shorten it
//! process-wide through the hidden, `test-support`-gated `shorten_lock_timeout_for_tests`, which
//! can only lower it, and production code has no override."
//! The override is process-wide, so every library case runs in its own `lock_hook` child process.
//! The production case drives `target/debug/vault` (built by `cargo build -p vault-cli`, without
//! `test-support`) against a `.lock` held by a perl `flock`.
use spec_checks::dev::*;
use spec_checks::*;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Instant;

struct Out {
    elapsed: u128,
    err: String,
    line: String,
}
fn hook(args: &[&str]) -> Out {
    let d = tempdir();
    let ds = d.path().to_string_lossy().into_owned();
    let mut a = vec![ds.as_str()];
    a.extend_from_slice(args);
    let (out, status) = run_child("lock_hook", &a, 75, 512);
    assert!(status.starts_with("exit0"), "{args:?}: {status}");
    let kv = |k: &str| {
        out.split_whitespace()
            .find_map(|p| p.strip_prefix(&format!("{k}=")))
            .unwrap_or_else(|| panic!("{k} missing in {out}"))
            .to_string()
    };
    let o = Out {
        elapsed: kv("elapsed_ms").parse().unwrap(),
        err: kv("err"),
        line: out.clone(),
    };
    // "nothing written": on every timed-out save the file is unchanged, no tmp is left, the vault
    // stays dirty, the edit is written once the lock is free, and the error text has no password.
    if o.err != "ok" {
        assert_eq!(kv("unchanged"), "true", "{out}");
        assert_eq!(kv("tmp_left"), "false", "{out}");
        assert_eq!(kv("dirty"), "true", "{out}");
    }
    assert_eq!(kv("after"), "ok", "{out}");
    assert_eq!(kv("disp_pw"), "false", "{out}");
    o
}

/// lh01: with no override the save waits the full 10 s and fails with SaveLockTimeout.
#[test]
fn lh01_default_wait_is_10s() {
    let o = hook(&["none"]);
    assert_eq!(o.err, "SaveLockTimeout", "{}", o.line);
    assert!((9_500..=14_000).contains(&o.elapsed), "{}", o.line);
}

/// lh02: the hook lowers the wait process-wide.
#[test]
fn lh02_hook_lowers() {
    let o = hook(&["1000"]);
    assert_eq!(o.err, "SaveLockTimeout", "{}", o.line);
    assert!((900..=3_000).contains(&o.elapsed), "{}", o.line);
}

/// lh03: "can only lower it": a value above 10 s does not raise the wait.
#[test]
fn lh03_hook_cannot_raise_above_default() {
    let o = hook(&["60000"]);
    assert_eq!(o.err, "SaveLockTimeout", "{}", o.line);
    assert!(o.elapsed <= 14_000, "raised past 10 s: {}", o.line);
}

/// lh04: "can only lower it": after lowering to 1 s, a later 5 s call keeps 1 s.
#[test]
fn lh04_hook_cannot_raise_after_lowering() {
    let o = hook(&["1000", "5000"]);
    assert_eq!(o.err, "SaveLockTimeout", "{}", o.line);
    assert!(
        o.elapsed <= 3_000,
        "second call raised the wait: {}",
        o.line
    );
}

/// lh05: zero is the lowest value: the save gives up at once, never hangs or panics.
#[test]
fn lh05_zero_gives_up_at_once() {
    let o = hook(&["0"]);
    assert_eq!(o.err, "SaveLockTimeout", "{}", o.line);
    assert!(o.elapsed <= 1_500, "{}", o.line);
}

/// lh06: concurrent callers: the minimum wins (17 threads, smallest 700 ms).
#[test]
fn lh06_concurrent_calls_keep_minimum() {
    let o = hook(&["race"]);
    assert_eq!(o.err, "SaveLockTimeout", "{}", o.line);
    assert!((600..=2_500).contains(&o.elapsed), "{}", o.line);
}

fn vault_bin() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/vault")
}
fn hold_lock(lock: &Path) -> Child {
    let mut c = Command::new("perl")
        .args([
            "-MFcntl=:flock",
            "-e",
            "$|=1; open(my $f, '>>', $ARGV[0]) or die; flock($f, LOCK_EX) or die; print \"locked\\n\"; sleep 120",
        ])
        .arg(lock)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut l = String::new();
    BufReader::new(c.stdout.take().unwrap())
        .read_line(&mut l)
        .unwrap();
    assert_eq!(l.trim(), "locked");
    c
}

/// lh07: production CLI (no test-support): `vault add` against a held `.lock` waits the full 10 s,
/// fails, writes nothing, and environment variables that look like overrides change nothing
/// ("production code has no override"). Two packages run in parallel: one plain, one with every
/// plausible override variable set to a tiny value.
#[test]
fn lh07_cli_waits_10s_and_has_no_env_override() {
    let d = tempdir();
    let envs: Vec<(&str, &str)> = vec![
        ("VAULT_LOCK_TIMEOUT", "0"),
        ("VAULT_LOCK_TIMEOUT_MS", "1"),
        ("VAULT_SAVE_LOCK_TIMEOUT", "0"),
        ("VAULT_SAVE_LOCK_TIMEOUT_MS", "1"),
        ("VAULT_TEST_LOCK_TIMEOUT_MS", "1"),
        ("LOCK_TIMEOUT_MS", "1"),
        ("RUST_TEST_THREADS", "1"),
    ];
    let mut jobs = vec![];
    for (k, with_env) in [("p", false), ("e", true)] {
        let p = d.path().join(format!("{k}.vault"));
        let mut a = Dev::create(&p);
        a.add_login("seed", now_ms());
        a.s.save().unwrap();
        drop(a);
        let before = std::fs::read(p.join("vault.bin")).unwrap();
        let perl = hold_lock(&p.join(".lock"));
        let mut c = Command::new(vault_bin());
        c.arg("--vault")
            .arg(&p)
            .args(["--password-env", "QA_MPW", "add", "--title", "blocked"])
            .env("QA_MPW", PW)
            .env_remove("VAULT_FILE")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if with_env {
            for (k, v) in &envs {
                c.env(k, v);
            }
        }
        let t = Instant::now();
        let child = c.spawn().unwrap();
        jobs.push((p, before, perl, child, t, with_env));
    }
    for (p, before, mut perl, child, t, with_env) in jobs {
        let o = child.wait_with_output().unwrap();
        let el = t.elapsed().as_millis();
        let _ = perl.kill();
        let _ = perl.wait();
        let msg = format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(
            !o.status.success(),
            "env={with_env}: add succeeded under a held lock: {msg}"
        );
        assert!(el >= 9_500, "env={with_env}: gave up after {el} ms: {msg}");
        assert!(el <= 20_000, "env={with_env}: waited {el} ms: {msg}");
        assert_eq!(
            std::fs::read(p.join("vault.bin")).unwrap(),
            before,
            "nothing written"
        );
        assert!(!msg.contains(PW), "master password in output");
        assert!(
            !ls(&p).iter().any(|n| n.contains(".tmp")),
            "tmp left: {:?}",
            ls(&p)
        );
        eprintln!("lh07 env={with_env} {el} ms: {}", msg.trim());
    }
}

/// lh08: the feature is not enabled in what ships: the normal-edge feature graph of vault-app and
/// vault-cli (no dev edges) does not activate vault-sync/test-support.
#[test]
fn lh08_shipping_graph_has_no_test_support() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for pkg in ["vault-app", "vault-cli"] {
        let o = Command::new("cargo")
            .current_dir(&root)
            .args([
                "tree",
                "-p",
                pkg,
                "-e",
                "normal,build,features",
                "-i",
                "vault-sync",
                "--offline",
            ])
            .output()
            .unwrap();
        let s = String::from_utf8_lossy(&o.stdout);
        assert!(
            o.status.success(),
            "{pkg}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(s.contains("vault-sync"), "{pkg}: {s}");
        assert!(
            !s.contains("test-support"),
            "{pkg} enables vault-sync test-support on normal edges:\n{s}"
        );
    }
}
