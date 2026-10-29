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
            "--kind",
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
    let vmode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
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
        .args(["add", "--kind", "login", "--title", "X", "--totp-field"])
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
fn forward_fixture_shows_real_kinds_and_masks_unknown_fields() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../vault-core/tests/fixtures/v1-forward.vault");
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("fwd.vault");
    std::fs::copy(&fixture, &f).unwrap();

    let list = ok(&vault(&f, PW, &["list"]));
    assert!(
        list.lines()
            .any(|l| l.contains("future-item-kind") && l.contains("Future thing")),
        "list: {list}"
    );

    let get = ok(&vault(&f, PW, &["get", "Future thing"]));
    assert!(get.contains("kind:  future-item-kind"), "get: {get}");
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
