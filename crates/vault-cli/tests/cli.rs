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
