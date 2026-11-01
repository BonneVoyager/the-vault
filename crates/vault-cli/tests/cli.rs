use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

const PW: &str = "correct horse battery staple";
const TOTP_URI: &str = "otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&issuer=Example";

fn vault(file: &Path, pw: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vault"))
        .args([
            "--vault",
            file.to_str().unwrap(),
            "--password-env",
            "VAULT_TEST_PW",
        ])
        .args(args)
        .env("VAULT_TEST_PW", pw)
        .env("VAULT_ITEM_PASSWORD", "s3cret-item-pw")
        .env("VAULT_DEVICE_ID", "11111111-1111-4111-8111-111111111111")
        .output()
        .unwrap()
}

fn ok(o: &Output) -> String {
    assert!(
        o.status.success(),
        "failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout.clone()).unwrap()
}

#[test]
fn full_flow() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.vault");
    ok(&vault(&f, PW, &["init", "--kdf-test-params"]));
    // Refuses to overwrite.
    assert!(
        !vault(&f, PW, &["init", "--kdf-test-params"])
            .status
            .success()
    );

    ok(&vault(
        &f,
        PW,
        &[
            "add",
            "--template",
            "login",
            "--title",
            "GitHub",
            "--username",
            "octo",
            "--password-field",
            "--url",
            "https://github.com",
            "--totp",
            TOTP_URI,
            "--tag",
            "dev",
        ],
    ));
    let list = ok(&vault(&f, PW, &["list"]));
    assert!(list.contains("GitHub") && list.contains("octo"), "{list}");
    assert!(list.contains("dev") && list.contains("login"), "{list}");
    let tagged = ok(&vault(&f, PW, &["list", "--tag", "dev"]));
    assert!(tagged.contains("GitHub"), "{tagged}");
    assert!(
        !ok(&vault(&f, PW, &["list", "--tag", "card"])).contains("GitHub"),
        "tag filter must exclude non-matching items"
    );
    let got = ok(&vault(&f, PW, &["get", "GitHub"]));
    assert!(
        got.contains("tags:  dev, login") && !got.contains("kind:"),
        "{got}"
    );

    let masked = ok(&vault(&f, PW, &["get", "github"]));
    assert!(masked.contains("********") && !masked.contains("s3cret-item-pw"));
    assert!(!masked.contains("JBSWY3DPEHPK3PXP"), "{masked}");
    let shown = ok(&vault(&f, PW, &["get", "GitHub", "--reveal"]));
    assert!(shown.contains("s3cret-item-pw") && shown.contains("JBSWY3DPEHPK3PXP"));

    let code = ok(&vault(&f, PW, &["totp", "GitHub"]));
    let digits = code.split_whitespace().next().unwrap();
    assert_eq!(digits.len(), 6);
    assert!(digits.chars().all(|c| c.is_ascii_digit()));

    let csv = dir.path().join("out.csv");
    let csv_s = csv.to_str().unwrap();
    assert!(!vault(&f, PW, &["export", "--out", csv_s]).status.success());
    ok(&vault(&f, PW, &["export", "--out", csv_s, "--yes"]));
    let mode = std::fs::metadata(&csv).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let again = vault(&f, PW, &["export", "--out", csv_s, "--yes"]);
    assert!(
        !again.status.success(),
        "must not overwrite without --force"
    );
    ok(&vault(
        &f,
        PW,
        &["export", "--out", csv_s, "--yes", "--force"],
    ));
    let vmode = std::fs::metadata(f.join("vault.bin"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(vmode, 0o600);
    assert!(std::fs::read_to_string(&csv).unwrap().contains("GitHub"));

    let g = dir.path().join("b.vault");
    ok(&vault(&g, PW, &["init", "--kdf-test-params"]));
    ok(&vault(
        &g,
        PW,
        &["import", "--format", "csv", "--in", csv_s],
    ));
    assert!(ok(&vault(&g, PW, &["list"])).contains("GitHub"));

    let id = ok(&vault(&f, PW, &["list"]))
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(id.len(), 8);
    ok(&vault(&f, PW, &["rm", "GitHub"]));
    let gone = vault(&f, PW, &["get", "GitHub"]);
    assert!(!gone.status.success());
    assert!(String::from_utf8_lossy(&gone.stderr).contains("no item matches"));
    assert!(!ok(&vault(&f, PW, &["list"])).contains("GitHub"));

    let bad = vault(&f, "nope", &["list"]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("wrong password"));

    let j = vault(&g, PW, &["import", "--format", "json", "--in", csv_s]);
    assert!(!j.status.success());
    assert!(String::from_utf8_lossy(&j.stderr).contains("unsupported format"));
}

#[test]
fn gen_default_length() {
    let o = Command::new(env!("CARGO_BIN_EXE_vault"))
        .arg("gen")
        .output()
        .unwrap();
    assert_eq!(ok(&o).trim().chars().count(), 20);
}

#[test]
fn init_missing_parent_reports_path() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("nope").join("a.vault");
    let o = vault(&f, PW, &["init", "--kdf-test-params"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("nope"));
}

#[test]
fn totp_field_via_env() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.vault");
    ok(&vault(&f, PW, &["init", "--kdf-test-params"]));
    let o = Command::new(env!("CARGO_BIN_EXE_vault"))
        .args([
            "--vault",
            f.to_str().unwrap(),
            "--password-env",
            "VAULT_TEST_PW",
        ])
        .args(["add", "--template", "login", "--title", "X", "--totp-field"])
        .env("VAULT_TEST_PW", PW)
        .env("VAULT_ITEM_TOTP", TOTP_URI)
        .env("VAULT_DEVICE_ID", "11111111-1111-4111-8111-111111111111")
        .output()
        .unwrap();
    ok(&o);
    let code = ok(&vault(&f, PW, &["totp", "X"]));
    assert_eq!(code.split_whitespace().next().unwrap().len(), 6);
    assert!(
        std::fs::read_dir(dir.path()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-"))
    );
}

#[test]
fn unparsable_device_id_errors() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.vault");
    let o = Command::new(env!("CARGO_BIN_EXE_vault"))
        .args([
            "--vault",
            f.to_str().unwrap(),
            "--password-env",
            "VAULT_TEST_PW",
            "init",
            "--kdf-test-params",
        ])
        .env("VAULT_TEST_PW", PW)
        .env("VAULT_DEVICE_ID", "not-a-uuid")
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("VAULT_DEVICE_ID"));
    assert!(!f.exists());
}

#[test]
fn legacy_single_file_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("old.vault");
    std::fs::write(&f, b"legacy").unwrap();
    let o = vault(&f, PW, &["list"]);
    assert_eq!(o.status.code(), Some(1));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("not a vault package"), "{err}");
}

#[test]
fn add_templates_tag_items() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.vault");
    ok(&vault(&f, PW, &["init", "--kdf-test-params"]));
    ok(&vault(
        &f,
        PW,
        &["add", "--template", "card", "--title", "Visa"],
    ));
    ok(&vault(&f, PW, &["add", "--title", "Plain"]));
    let cards = ok(&vault(&f, PW, &["list", "--tag", "card"]));
    assert!(
        cards.contains("Visa") && !cards.contains("Plain"),
        "{cards}"
    );
    let logins = ok(&vault(&f, PW, &["list", "--tag", "login"]));
    assert!(
        logins.contains("Plain") && !logins.contains("Visa"),
        "{logins}"
    );
    assert!(
        !vault(&f, PW, &["add", "--template", "bogus", "--title", "Z"])
            .status
            .success()
    );
}

#[test]
fn forward_fixture_masks_unknown_fields() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../vault-core/tests/fixtures/v1-forward.vault");
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("fwd.vault");
    std::fs::create_dir(&f).unwrap();
    std::fs::copy(&fixture, f.join("vault.bin")).unwrap();

    let list = ok(&vault(&f, PW, &["list"]));
    assert!(
        list.lines().any(|l| l.contains("Future thing")),
        "list: {list}"
    );

    let get = ok(&vault(&f, PW, &["get", "Future thing"]));
    assert!(get.contains("future: ********"), "get: {get}");
    assert!(!get.contains("future-value"), "get: {get}");
}

#[test]
fn init_refuses_weak_master_password() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.vault");
    let o = vault(&f, "123", &["init", "--kdf-test-params"]);
    assert_eq!(o.status.code(), Some(1));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("master password too weak"), "{err}");
    assert!(err.contains("--allow-weak"), "{err}");
    assert!(!f.exists());
}

#[test]
fn init_allow_weak_bypasses_check() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.vault");
    ok(&vault(
        &f,
        "123",
        &["init", "--kdf-test-params", "--allow-weak"],
    ));
    assert!(f.exists());
}

fn attach_setup() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.vault");
    ok(&vault(&f, PW, &["init", "--kdf-test-params"]));
    ok(&vault(
        &f,
        PW,
        &["add", "--template", "login", "--title", "Docs"],
    ));
    (dir, f)
}

#[test]
fn attach_round_trip() {
    let (dir, f) = attach_setup();
    let empty = dir.path().join("empty.bin");
    let big = dir.path().join("big.bin");
    std::fs::write(&empty, b"").unwrap();
    let bytes: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&big, &bytes).unwrap();

    let empty_id = ok(&vault(
        &f,
        PW,
        &["attach", "add", "Docs", empty.to_str().unwrap()],
    ))
    .trim()
    .to_owned();
    let big_id = ok(&vault(
        &f,
        PW,
        &["attach", "add", "Docs", big.to_str().unwrap()],
    ))
    .trim()
    .to_owned();

    let list = ok(&vault(&f, PW, &["attach", "list", "Docs"]));
    assert_eq!(list.lines().count(), 2, "{list}");
    assert!(
        list.contains(&empty_id) && list.contains("empty.bin"),
        "{list}"
    );
    assert!(list.contains(&big_id) && list.contains("big.bin"), "{list}");
    assert!(list.contains("1500000"), "{list}");
    assert!(list.contains("present"), "{list}");

    let out = dir.path().join("out.bin");
    ok(&vault(
        &f,
        PW,
        &["attach", "get", "Docs", &big_id, out.to_str().unwrap()],
    ));
    assert_eq!(std::fs::read(&out).unwrap(), bytes);
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // Refuses to overwrite and leaves the existing file alone.
    assert!(
        !vault(
            &f,
            PW,
            &["attach", "get", "Docs", &big_id, out.to_str().unwrap()]
        )
        .status
        .success()
    );
    assert_eq!(std::fs::read(&out).unwrap(), bytes);

    let out0 = dir.path().join("out0.bin");
    ok(&vault(
        &f,
        PW,
        &["attach", "get", "Docs", &empty_id, out0.to_str().unwrap()],
    ));
    assert_eq!(std::fs::read(&out0).unwrap(), b"");

    ok(&vault(&f, PW, &["attach", "rm", "Docs", &big_id]));
    let list = ok(&vault(&f, PW, &["attach", "list", "Docs"]));
    assert!(
        !list.contains(&big_id) && list.contains(&empty_id),
        "{list}"
    );

    let out2 = dir.path().join("out2.bin");
    let o = vault(
        &f,
        PW,
        &["attach", "get", "Docs", &big_id, out2.to_str().unwrap()],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(!out2.exists());
}

#[test]
fn attach_refuses_oversize_file() {
    let (dir, f) = attach_setup();
    let huge = dir.path().join("huge.bin");
    std::fs::File::create(&huge)
        .unwrap()
        .set_len(101_000_000)
        .unwrap();
    let o = vault(&f, PW, &["attach", "add", "Docs", huge.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.starts_with("error: ") && err.contains("file is larger than 100 MB"),
        "{err}"
    );
    assert_eq!(ok(&vault(&f, PW, &["attach", "list", "Docs"])), "");
}

#[test]
fn gen_rejects_degenerate_sizes() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("g.vault");
    let o = vault(&f, PW, &["gen", "--length", "2"]);
    assert_eq!(o.status.code(), Some(1));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("length must be at least 4 for the enabled character classes"),
        "{err}"
    );
    // Fewer classes lower the minimum.
    let o = vault(
        &f,
        PW,
        &[
            "gen",
            "--length",
            "2",
            "--no-symbols",
            "--no-digits",
            "--no-upper",
        ],
    );
    assert!(o.status.success());
    assert_eq!(ok(&o).trim().len(), 2);
    let o = vault(
        &f,
        PW,
        &["gen", "--length", "1", "--no-symbols", "--no-digits"],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("at least 2"));

    let o = vault(&f, PW, &["gen", "--passphrase", "--words", "0"]);
    assert_eq!(o.status.code(), Some(1));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("words must be at least 1"), "{err}");
    assert!(
        ok(&vault(&f, PW, &["gen", "--passphrase", "--words", "1"]))
            .trim()
            .len()
            > 1
    );
}

#[test]
fn attach_get_removed_reports_not_found() {
    let (dir, f) = attach_setup();
    let src = dir.path().join("x.bin");
    std::fs::write(&src, b"data").unwrap();
    let id = ok(&vault(
        &f,
        PW,
        &["attach", "add", "Docs", src.to_str().unwrap()],
    ))
    .trim()
    .to_owned();
    ok(&vault(&f, PW, &["attach", "rm", "Docs", &id]));
    let out = dir.path().join("o.bin");
    let o = vault(
        &f,
        PW,
        &["attach", "get", "Docs", &id, out.to_str().unwrap()],
    );
    assert_eq!(o.status.code(), Some(1));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("attachment not found"), "{err}");
    assert!(!out.exists());
}

fn snapshot_count(pkg: &Path) -> usize {
    std::fs::read_dir(pkg.join("backups"))
        .map(|d| d.filter_map(Result::ok).count())
        .unwrap_or(0)
}

#[test]
fn cli_writes_create_backups() {
    let (dir, f) = attach_setup();
    for t in ["One", "Two", "Three"] {
        ok(&vault(&f, PW, &["add", "--template", "note", "--title", t]));
    }
    ok(&vault(&f, PW, &["rm", "Two"]));
    assert!(snapshot_count(&f) >= 1, "no backups after add/rm");

    let src = dir.path().join("b.bin");
    std::fs::write(&src, b"payload").unwrap();
    let before = snapshot_count(&f);
    ok(&vault(
        &f,
        PW,
        &["attach", "add", "Docs", src.to_str().unwrap()],
    ));
    assert!(snapshot_count(&f) >= 1 && snapshot_count(&f) >= before);
}

#[test]
fn concurrent_adds_lose_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("c.vault");
    ok(&vault(
        &f,
        PW,
        &["init", "--kdf-test-params", "--allow-weak"],
    ));
    for run in 0..3 {
        for r in 0..10 {
            let spawn = |t: String| {
                Command::new(env!("CARGO_BIN_EXE_vault"))
                    .args([
                        "--vault",
                        f.to_str().unwrap(),
                        "--password-env",
                        "VAULT_TEST_PW",
                    ])
                    .args(["add", "--template", "note", "--title", &t])
                    .env("VAULT_TEST_PW", PW)
                    .env("VAULT_DEVICE_ID", "11111111-1111-4111-8111-111111111111")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap()
            };
            let a = spawn(format!("A{run}-{r}"));
            let b = spawn(format!("B{run}-{r}"));
            for c in [a, b] {
                let o = c.wait_with_output().unwrap();
                assert!(
                    o.status.success(),
                    "concurrent add failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                );
            }
        }
        let list = ok(&vault(&f, PW, &["list"]));
        let expected = (run + 1) * 20;
        for r in 0..=run {
            for r2 in 0..10 {
                for p in ["A", "B"] {
                    let t = format!("{p}{r}-{r2}");
                    assert!(list.contains(&t), "lost item {t}; run {run}\n{list}");
                }
            }
        }
        assert_eq!(list.lines().count(), expected, "{list}");
    }
}

#[test]
fn export_force_is_atomic_and_refuses_symlink() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.vault");
    ok(&vault(&f, PW, &["init", "--kdf-test-params"]));
    ok(&vault(
        &f,
        PW,
        &["add", "--template", "login", "--title", "GitHub"],
    ));

    let out_dir = dir.path().join("o");
    std::fs::create_dir(&out_dir).unwrap();
    let target = out_dir.join("target.txt");
    std::fs::write(&target, "original").unwrap();
    let link = out_dir.join("link.csv");
    symlink(&target, &link).unwrap();
    let r = vault(
        &f,
        PW,
        &[
            "export",
            "--out",
            link.to_str().unwrap(),
            "--yes",
            "--force",
        ],
    );
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("refusing to overwrite a symlink"));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "original");
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );

    let reg = out_dir.join("reg.csv");
    std::fs::write(&reg, "old").unwrap();
    std::fs::set_permissions(&reg, std::fs::Permissions::from_mode(0o644)).unwrap();
    let held = std::fs::File::open(&reg).unwrap();
    ok(&vault(
        &f,
        PW,
        &["export", "--out", reg.to_str().unwrap(), "--yes", "--force"],
    ));
    assert_eq!(
        std::fs::metadata(&reg).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(std::fs::read_to_string(&reg).unwrap().contains("GitHub"));
    // The previously opened handle still sees the old inode, not the new contents.
    assert_eq!(std::io::read_to_string(held).unwrap(), "old");
    let names: Vec<_> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 3, "no temp left: {names:?}");
}

#[test]
fn terminal_control_characters_are_escaped() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("t.vault");
    ok(&vault(&f, PW, &["init", "--kdf-test-params"]));
    let evil = "Evil\u{1b}[31mRED\u{202e}rtl";
    ok(&vault(
        &f,
        PW,
        &["add", "--title", evil, "--username", "u\u{7}x"],
    ));
    ok(&vault(&f, PW, &["add", "--title", "Plain Title"]));
    ok(&vault(
        &f,
        PW,
        &["add", "--title", "Notes", "--notes", "line1\nline2\rX"],
    ));
    let notes = ok(&vault(&f, PW, &["get", "--reveal", "Notes"]));
    assert!(notes.contains("notes: line1\nline2\\u{d}X"), "{notes}");
    let miss = vault(&f, PW, &["get", "no\u{1b}[2Jmatch"]);
    let err = String::from_utf8_lossy(&miss.stderr);
    assert!(!err.contains('\u{1b}') && err.contains("\\u{1b}"), "{err}");
    let escaped = "Evil\\u{1b}[31mRED\\u{202e}rtl";

    let list = ok(&vault(&f, PW, &["list"]));
    assert!(list.contains(escaped), "{list}");
    assert!(list.contains("u\\u{7}x"), "{list}");
    assert!(list.contains("Plain Title"), "{list}");
    assert!(
        !list.contains('\u{1b}') && !list.contains('\u{202e}'),
        "{list}"
    );

    let get = ok(&vault(&f, PW, &["get", "--reveal", "Plain Title"]));
    assert!(get.contains("title: Plain Title"), "{get}");
    let get = ok(&vault(&f, PW, &["get", "--reveal", evil]));
    assert!(get.contains(escaped), "{get}");
    assert!(get.contains("u\\u{7}x"), "{get}");
    assert!(
        !get.contains('\u{1b}') && !get.contains('\u{202e}'),
        "{get}"
    );

    let src = dir.path().join("a\u{1b}[2Jb.bin");
    std::fs::write(&src, b"x").unwrap();
    ok(&vault(
        &f,
        PW,
        &["attach", "add", "Plain Title", src.to_str().unwrap()],
    ));
    let al = ok(&vault(&f, PW, &["attach", "list", "Plain Title"]));
    assert!(al.contains("a\\u{1b}[2Jb.bin"), "{al}");
    assert!(!al.contains('\u{1b}'), "{al}");
}

#[test]
fn upgrade_v1_fixture_then_noop() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../vault-core/tests/fixtures/v1-basic.vault");
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("old.vault");
    std::fs::create_dir(&f).unwrap();
    std::fs::copy(&fixture, f.join("vault.bin")).unwrap();

    let before = vault(&f, PW, &["list"]);
    assert!(before.status.success());
    let hint = String::from_utf8_lossy(&before.stderr);
    assert!(
        hint.contains("Vault is format 1; run `vault upgrade`"),
        "{hint}"
    );

    let up = ok(&vault(&f, PW, &["upgrade"]));
    assert!(up.contains("upgraded to version 2"), "{up}");
    assert!(up.contains("Touch ID"), "{up}");

    let after = vault(&f, PW, &["list"]);
    assert!(after.status.success());
    assert!(
        !String::from_utf8_lossy(&after.stderr).contains("run `vault upgrade`"),
        "hint must disappear"
    );
    let bytes_before = std::fs::read(f.join("vault.bin")).unwrap();
    let again = ok(&vault(&f, PW, &["upgrade"]));
    assert_eq!(
        std::fs::read(f.join("vault.bin")).unwrap(),
        bytes_before,
        "no-op upgrade must not rewrite the file"
    );
    assert!(again.contains("already at version 2"), "{again}");
}

fn core_item(pkg: &Path, title: &str) -> vault_core::Item {
    let mut sv = vault_sync::SyncedVault::open(
        pkg,
        "11111111-1111-4111-8111-111111111111".parse().unwrap(),
        std::sync::Arc::new(vault_sync::NoopHooks),
    )
    .unwrap();
    sv.unlock(&vault_core::SecretString::new(PW.to_owned()))
        .unwrap();
    sv.vault()
        .unwrap()
        .items()
        .find(|i| i.title == title)
        .unwrap_or_else(|| panic!("no item {title}"))
        .clone()
}

fn field_id(get_ids: &str, label: &str, nth: usize) -> String {
    get_ids
        .lines()
        .filter(|l| l.starts_with(&format!("{label}: ")))
        .nth(nth)
        .and_then(|l| l.rsplit_once("(id "))
        .map(|(_, id)| id.trim_end_matches(')').to_owned())
        .unwrap_or_else(|| panic!("no field {label} #{nth} in {get_ids}"))
}

#[test]
fn edit_flags_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("e.vault");
    ok(&vault(&f, PW, &["init", "--kdf-test-params"]));
    ok(&vault(
        &f,
        PW,
        &[
            "add",
            "--title",
            "Site",
            "--username",
            "octo",
            "--tag",
            "dev",
        ],
    ));
    assert!(!vault(&f, PW, &["edit", "Site"]).status.success());

    let out = ok(&vault(
        &f,
        PW,
        &[
            "edit",
            "Site",
            "--title",
            "Site2",
            "--favorite",
            "--tag",
            "work",
            "--untag",
            "dev",
            "--icon",
            "symbol:key:#112233",
            "--set",
            "username=bob",
            "--set",
            "newfield=hello",
            "--add",
            "section:Extras",
            "--add",
            "text:dup=1",
            "--add",
            "text:dup=2",
        ],
    ));
    assert!(out.starts_with("updated "), "{out}");
    let it = core_item(&f, "Site2");
    assert!(it.favorite);
    assert!(it.tags.iter().any(|t| t == "work") && !it.tags.iter().any(|t| t == "dev"));
    assert_eq!(it.icon.as_ref().unwrap().value, "key");
    let get = ok(&vault(&f, PW, &["get", "Site2", "--ids", "--reveal"]));
    assert!(get.contains("Icon: symbol key #112233"), "{get}");
    assert!(
        get.contains("username: bob") && get.contains("newfield: hello"),
        "{get}"
    );
    assert!(get.lines().any(|l| l.starts_with("EXTRAS")), "{get}");
    let section = it
        .fields
        .iter()
        .find(|f| f.kind == vault_core::FieldKind::Section)
        .unwrap();
    assert!(vault_core::ExposeSecret::expose_secret(&section.value).is_empty());

    // Ambiguous name is refused and changes nothing.
    let bad = vault(&f, PW, &["edit", "Site2", "--title", "X", "--set", "dup=z"]);
    assert!(!bad.status.success());
    let err = String::from_utf8_lossy(&bad.stderr);
    assert!(err.contains("ambiguous: 2 fields named \"dup\""), "{err}");
    core_item(&f, "Site2");
    // Addressing by id works, and --set-env keeps the value off the command line.
    let id = field_id(&get, "dup", 1);
    ok(&vault(
        &f,
        PW,
        &["edit", "Site2", "--set", &format!("{id}=two")],
    ));
    let o = Command::new(env!("CARGO_BIN_EXE_vault"))
        .args([
            "--vault",
            f.to_str().unwrap(),
            "--password-env",
            "VAULT_TEST_PW",
        ])
        .args(["edit", "Site2", "--set-env", "username=EDIT_SECRET"])
        .env("VAULT_TEST_PW", PW)
        .env("EDIT_SECRET", "from-env")
        .env("VAULT_DEVICE_ID", "11111111-1111-4111-8111-111111111111")
        .output()
        .unwrap();
    ok(&o);
    let get = ok(&vault(&f, PW, &["get", "Site2", "--ids", "--reveal"]));
    assert!(get.contains("username: from-env"), "{get}");
    assert!(get.contains("dup: two") && get.contains("dup: 1"), "{get}");

    // rm-field leaves a tombstone.
    ok(&vault(
        &f,
        PW,
        &["edit", "Site2", "--rm-field", &id, "--icon", "auto"],
    ));
    let it = core_item(&f, "Site2");
    assert!(it.removed_fields.iter().any(|t| t.id.to_string() == id));
    assert!(!it.fields.iter().any(|f| f.id.to_string() == id));
    assert!(it.icon.is_none());
    assert!(
        !vault(&f, PW, &["edit", "Site2", "--rm-field", &id])
            .status
            .success()
    );
}

#[test]
fn help_documents_device_id() {
    let o = Command::new(env!("CARGO_BIN_EXE_vault"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains("VAULT_DEVICE_ID"));
}

fn vault_dev(file: &Path, device: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vault"))
        .args([
            "--vault",
            file.to_str().unwrap(),
            "--password-env",
            "VAULT_TEST_PW",
        ])
        .args(args)
        .env("VAULT_TEST_PW", PW)
        .env("VAULT_DEVICE_ID", device)
        .output()
        .unwrap()
}

#[test]
fn device_id_env_is_recorded_per_item() {
    const A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("d.vault");
    ok(&vault_dev(&f, A, &["init", "--kdf-test-params"]));
    ok(&vault_dev(
        &f,
        A,
        &["add", "--template", "note", "--title", "ByA"],
    ));
    ok(&vault_dev(
        &f,
        B,
        &["add", "--template", "note", "--title", "ByB"],
    ));
    let a = ok(&vault_dev(&f, A, &["get", "ByA", "--ids"]));
    let b = ok(&vault_dev(&f, A, &["get", "ByB", "--ids"]));
    assert!(a.contains(&format!("Device: {A}")), "{a}");
    assert!(b.contains(&format!("Device: {B}")), "{b}");
    assert!(!ok(&vault_dev(&f, A, &["get", "ByA"])).contains("Device:"));
}

/// A vault with one local item, plus a second package holding one remote item, built before
/// the local `add` so the remote copy is placed only after the last write.
fn sync_setup(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let f = dir.join("s.vault");
    ok(&vault(&f, PW, &["init", "--kdf-test-params"]));
    let remote = dir.join("remote.vault");
    std::fs::create_dir(&remote).unwrap();
    std::fs::copy(f.join("vault.bin"), remote.join("vault.bin")).unwrap();
    ok(&vault(
        &remote,
        PW,
        &["add", "--template", "note", "--title", "Remote"],
    ));
    ok(&vault(
        &f,
        PW,
        &["add", "--template", "note", "--title", "Local"],
    ));
    (f, remote)
}

fn assert_synced(f: &Path) {
    let out = ok(&vault(f, PW, &["sync"]));
    assert!(out.contains("1 conflict copies absorbed"), "{out}");
    let list = ok(&vault(f, PW, &["list"]));
    assert!(list.contains("Local") && list.contains("Remote"), "{list}");
    let backups: Vec<String> = std::fs::read_dir(f.join("backups"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        backups
            .iter()
            .filter(|n| n.starts_with("conflict-"))
            .count(),
        1,
        "{backups:?}"
    );
    let again = ok(&vault(f, PW, &["sync"]));
    assert!(again.contains("0 conflict copies absorbed"), "{again}");
}

#[test]
fn sync_absorbs_sibling_package() {
    let dir = tempfile::tempdir().unwrap();
    let (f, remote) = sync_setup(dir.path());
    let sibling = dir.path().join("s 2.vault");
    std::fs::rename(&remote, &sibling).unwrap();
    assert_synced(&f);
    assert!(
        !sibling.exists(),
        "sibling package must be moved to backups"
    );
}

#[test]
fn sync_absorbs_in_package_copy() {
    let dir = tempfile::tempdir().unwrap();
    let (f, remote) = sync_setup(dir.path());
    let copy = f.join("vault (host's conflicted copy 2026-01-01).bin");
    std::fs::copy(remote.join("vault.bin"), &copy).unwrap();
    // The helper's package would itself be a sibling candidate; only the in-package copy stays.
    std::fs::remove_dir_all(&remote).unwrap();
    assert_synced(&f);
    assert!(!copy.exists(), "copy must be moved to backups");
}

#[test]
fn sync_output_escapes_conflict_file_names() {
    let dir = tempfile::tempdir().unwrap();
    let (f, remote) = sync_setup(dir.path());
    let copy = f.join("vault (h\u{1b}[31most's conflicted copy 2026-01-01).bin");
    std::fs::copy(remote.join("vault.bin"), &copy).unwrap();
    std::fs::remove_dir_all(&remote).unwrap();
    let o = vault(&f, PW, &["sync"]);
    let out = ok(&o);
    assert!(out.contains("1 conflict copies absorbed"), "{out}");
    assert!(
        !out.contains('\u{1b}') && out.contains("\\u{1b}"),
        "{out:?}"
    );
}

#[test]
fn sync_save_failure_still_reports_events() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (f, remote) = sync_setup(dir.path());
    let sibling = dir.path().join("s 2.vault");
    std::fs::rename(&remote, &sibling).unwrap();
    // A package that cannot be written: the merge happens, the save fails.
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o500)).unwrap();
    let o = vault(&f, PW, &["sync"]);
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(o.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        stderr.contains("error:"),
        "drained events must be printed: {stderr}"
    );
    assert!(!String::from_utf8_lossy(&o.stdout).contains("synced:"));
}

#[test]
fn id_prefix_from_list_works_everywhere() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("p.vault");
    ok(&vault(&f, PW, &["init", "--kdf-test-params"]));
    ok(&vault(
        &f,
        PW,
        &["add", "--template", "note", "--title", "Pfx"],
    ));
    let list = ok(&vault(&f, PW, &["list"]));
    let prefix = list.split_whitespace().next().unwrap().to_owned();
    assert_eq!(prefix.len(), 8, "{list}");
    assert!(ok(&vault(&f, PW, &["get", &prefix])).contains("title: Pfx"));
    ok(&vault(&f, PW, &["edit", &prefix, "--title", "Pfx2"]));
    assert!(ok(&vault(&f, PW, &["attach", "list", &prefix])).is_empty());
    ok(&vault(&f, PW, &["rm", &prefix]));
    assert!(!vault(&f, PW, &["get", &prefix]).status.success());
}

#[test]
fn closed_stdout_exits_quietly() {
    use std::process::Stdio;
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("b.vault");
    ok(&vault(&f, PW, &["init", "--kdf-test-params"]));
    ok(&vault(
        &f,
        PW,
        &["add", "--template", "note", "--title", "Pipe"],
    ));
    let mut child = Command::new(env!("CARGO_BIN_EXE_vault"))
        .args([
            "--vault",
            f.to_str().unwrap(),
            "--password-env",
            "VAULT_TEST_PW",
            "list",
        ])
        .env("VAULT_TEST_PW", PW)
        .env("VAULT_DEVICE_ID", "11111111-1111-4111-8111-111111111111")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Close the read end before the program has unlocked and printed anything.
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{:?}", out.status);
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("panicked"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn export_survives_closed_stderr() {
    use std::process::Stdio;
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("x.vault");
    ok(&vault(&f, PW, &["init", "--kdf-test-params"]));
    ok(&vault(
        &f,
        PW,
        &["add", "--template", "note", "--title", "Exp"],
    ));
    let csv = dir.path().join("out.csv");
    let mut child = Command::new(env!("CARGO_BIN_EXE_vault"))
        .args([
            "--vault",
            f.to_str().unwrap(),
            "--password-env",
            "VAULT_TEST_PW",
        ])
        .args(["export", "--yes", "--out", csv.to_str().unwrap()])
        .env("VAULT_TEST_PW", PW)
        .env("VAULT_DEVICE_ID", "11111111-1111-4111-8111-111111111111")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stderr.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(std::fs::read_to_string(&csv).unwrap().contains("Exp"));
}
