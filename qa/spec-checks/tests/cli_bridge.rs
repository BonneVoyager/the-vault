//! Decodes files written by the CLI binary with the independent decoder (01 §2 header fields).
use spec_checks::*;
use std::process::Command;

fn vault_bin() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/vault")
}

/// 01 §2 "created_at: u64 unix seconds" on the header and on each slot; 00 "Explicitly accepted
/// leaks: ... vault creation time" implies a real value is stored.
#[test]
fn b01_cli_init_header_created_at() {
    let d = tempdir();
    let p = d.path().join("c.vault");
    let st = Command::new(vault_bin())
        .args([
            "--vault",
            p.to_str().unwrap(),
            "--password-env",
            "QA_MPW",
            "init",
            "--kdf-test-params",
        ])
        .env("QA_MPW", "tidy-Walrus-orbit-Velvet-42")
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );
    let b = std::fs::read(p.join("vault.bin")).unwrap();
    let raw = split(&b);
    let ca = u64_of(get(&raw.header, "created_at").unwrap());
    let slot_ca: Vec<u64> = get(&raw.header, "slots")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|s| u64_of(get(s, "created_at").unwrap()))
        .collect();
    assert!(
        ca > 1_600_000_000 && slot_ca.iter().all(|c| *c > 1_600_000_000),
        "header created_at={ca}, slot created_at={slot_ca:?}"
    );
    // the independent decoder opens a CLI-made vault (spec AADs, HKDF labels, NFC)
    indep::open_file(&b, "tidy-Walrus-orbit-Velvet-42");
}

// ---------------------------------------------------------------------------------------------
// 2026-10-31 additions: upgrade command, sections, icons, field ids, created_at.
// ---------------------------------------------------------------------------------------------
use secrecy::ExposeSecret;
use spec_checks::dev::*;
use vault_core::*;

fn cli(pkg: &std::path::Path, password: &str, args: &[&str]) -> (i32, String) {
    let out = Command::new(vault_bin())
        .arg("--vault")
        .arg(pkg)
        .args(["--password-env", "QA_MPW"])
        .args(args)
        .env("QA_MPW", password)
        .env_remove("VAULT_FILE")
        .output()
        .unwrap();
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), s)
}
fn pkg_from_bytes(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::create_dir_all(&p).unwrap();
    std::fs::write(p.join("vault.bin"), bytes).unwrap();
    p
}

/// 01 §9 "the CLI exposes it as an explicit command" (README: `vault upgrade`): v1 -> v2, opens,
/// contents kept; a second run is a no-op; a wrong password changes nothing and exits cleanly.
#[test]
fn b02_cli_upgrade() {
    let d = tempdir();
    let p = pkg_from_bytes(d.path(), "u.vault", &fixture("v1-basic.vault"));
    let before = std::fs::read(p.join("vault.bin")).unwrap();
    let (rc, out) = cli(
        &p,
        "wrong horse battery staple",
        &["upgrade", "--allow-weak"],
    );
    assert!(rc != 0 && rc != 101, "wrong password: rc={rc} {out}");
    assert!(!out.contains("wrong horse"), "password echoed");
    assert_eq!(
        std::fs::read(p.join("vault.bin")).unwrap(),
        before,
        "wrong password leaves the file untouched"
    );
    let (rc, out) = cli(&p, FIXTURE_PW, &["upgrade", "--allow-weak"]);
    assert_eq!(rc, 0, "{out}");
    let after = std::fs::read(p.join("vault.bin")).unwrap();
    assert_eq!(version_of(&after), 2, "upgrade writes version 2: {out}");
    let u = LockedVault::parse(&after)
        .unwrap()
        .unlock(&pw(FIXTURE_PW))
        .unwrap();
    let u0 = LockedVault::parse(&before)
        .unwrap()
        .unlock(&pw(FIXTURE_PW))
        .unwrap();
    assert_eq!(
        snap_vault(&u),
        snap_vault(&u0),
        "contents and ids unchanged"
    );
    let (rc, out2) = cli(&p, FIXTURE_PW, &["upgrade", "--allow-weak"]);
    assert_eq!(rc, 0, "second upgrade is a no-op, not an error: {out2}");
    assert_eq!(version_of(&std::fs::read(p.join("vault.bin")).unwrap()), 2);
    eprintln!("INFO upgrade output: {out:?} / second run: {out2:?}");
    let (rc, out) = cli(&p, FIXTURE_PW, &["list"]);
    assert_eq!(rc, 0, "{out}");
}

/// 01 §9 upgrade "drops enclave, recovery and opaque slots", via the CLI.
#[test]
fn b03_cli_upgrade_drops_enclave_slot() {
    let d = tempdir();
    let mut v = LockedVault::parse(&fixture("v1-basic.vault"))
        .unwrap()
        .unlock(&pw(FIXTURE_PW))
        .unwrap();
    v.add_enclave_slot(&secrecy::SecretVec::new(vec![1; 32]), 1_800_000_000_000);
    let b = v.serialize();
    assert_eq!(version_of(&b), 1);
    let p = pkg_from_bytes(d.path(), "e.vault", &b);
    let (rc, out) = cli(&p, FIXTURE_PW, &["upgrade", "--allow-weak"]);
    assert_eq!(rc, 0, "{out}");
    let after = std::fs::read(p.join("vault.bin")).unwrap();
    let kinds: Vec<String> = get(&split(&after).header, "slots")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|s| get(s, "kind").unwrap().as_text().unwrap().to_string())
        .collect();
    assert_eq!(kinds, vec!["password"], "enclave slot dropped");
    assert!(
        out.to_lowercase().contains("touch id") || out.to_lowercase().contains("slot"),
        "INFO: CLI does not mention the dropped slot: {out:?}"
    );
}

/// 01 §9 + 03 §3: the CLI upgrades the file while another handle (the app) holds the v1 vault
/// unlocked; that handle then saves an edit. The vault must still open with the password.
#[test]
fn b04_cli_upgrade_while_app_holds_v1() {
    let d = tempdir();
    let p = pkg_from_bytes(d.path(), "live.vault", &fixture("v1-basic.vault"));
    let dev = uuid::Uuid::new_v4();
    let mut app = SyncedVault::open(&p, dev, hooks()).unwrap();
    app.unlock(&pw(FIXTURE_PW)).unwrap();
    let (rc, out) = cli(&p, FIXTURE_PW, &["upgrade", "--allow-weak"]);
    assert_eq!(rc, 0, "{out}");
    let id = app.vault().unwrap().items().next().unwrap().id;
    app.edit(|v| v.update(id, now_ms(), |it| it.favorite = true))
        .unwrap()
        .unwrap();
    app.save().unwrap();
    let disk = std::fs::read(p.join("vault.bin")).unwrap();
    let r = LockedVault::parse(&disk).and_then(|l| l.unlock(&pw(FIXTURE_PW)));
    assert!(
        r.is_ok(),
        "after `vault upgrade` and an app save the file is version {} and the password fails: {:?}",
        version_of(&disk),
        r.err()
    );
    let (rc, out) = cli(&p, FIXTURE_PW, &["list"]);
    assert_eq!(rc, 0, "CLI can no longer open the vault: {out}");
}

fn section_pkg(d: &std::path::Path) -> (std::path::PathBuf, uuid::Uuid) {
    let p = d.join("sec.vault");
    let mut a = Dev::create(&p);
    let dev = a.dev;
    let id =
        a.s.edit(move |v| {
            let mut it = Item::new("Sectioned", dev, 100);
            it.fields.push(Field::new(
                "Zebrahead",
                FieldKind::Section,
                pw("SECTIONSECRETQQ"),
                100,
            ));
            it.fields
                .push(Field::new("username", FieldKind::Text, pw("bob"), 100));
            it.fields.push(Field::new(
                "password",
                FieldKind::Password,
                pw("pw-visible-on-reveal"),
                100,
            ));
            v.insert(it, 100)
        })
        .unwrap();
    a.s.save().unwrap();
    (p, id)
}

/// 05 §2.3 "A section's stored value is treated as empty and is never rendered, copied, revealed,
/// searched or exported"; 01 §4 "skipped by CSV export and search". Black-box over every CLI
/// command that prints item data.
#[test]
fn b05_section_value_never_in_cli_output() {
    let d = tempdir();
    let (p, id) = section_pkg(d.path());
    let mut leaks = vec![];
    let ids = id.to_string();
    for args in [
        vec!["get", "Sectioned"],
        vec!["get", "Sectioned", "--reveal"],
        vec!["get", "Sectioned", "--reveal", "--ids"],
        vec!["get", ids.as_str(), "--reveal"],
        vec!["list"],
        vec!["list", "SECTIONSECRETQQ"],
        vec!["list", "Zebrahead"],
        vec!["totp", "Sectioned"],
    ] {
        let (rc, out) = cli(&p, PW, &args);
        if rc == 101 {
            leaks.push(format!("{args:?}: panic"));
        }
        if out.contains("SECTIONSECRETQQ") {
            leaks.push(format!("{args:?} printed the section value: {out}"));
        }
        if args[0] == "list" && args.len() == 2 && out.contains("Sectioned") {
            leaks.push(format!(
                "{args:?} matched the item through its section: {out}"
            ));
        }
        if args.len() >= 3 && args[2] == "--reveal" && !out.contains("pw-visible-on-reveal") {
            leaks.push(format!(
                "{args:?}: --reveal did not reveal the password (control): {out}"
            ));
        }
    }
    let csv = d.path().join("e.csv");
    let (rc, out) = cli(&p, PW, &["export", "--out", csv.to_str().unwrap(), "--yes"]);
    assert_eq!(rc, 0, "{out}");
    let c = std::fs::read_to_string(&csv).unwrap();
    if c.contains("SECTIONSECRETQQ") || c.contains("Zebrahead") {
        leaks.push(format!("export contains the section: {c}"));
    }
    assert!(leaks.is_empty(), "{}", leaks.join("\n"));
}

/// 05 §2.3 item icon: "stored through the attachment path as icon { kind: "image", value:
/// <attachment id> } ... The icon blob never appears in any attachment list, count, window or the
/// backup viewer". Checked on `vault attach list`, with the id written in uuid text form.
#[test]
fn b06_icon_blob_hidden_from_attach_list() {
    let d = tempdir();
    let p = d.path().join("ic.vault");
    let mut a = Dev::create(&p);
    let item = a.add_login("Iconic", now_ms());
    let icon_id =
        a.s.add_attachment(item, "icon-blob.png", &b"\x89PNG fake"[..], 9, now_ms())
            .unwrap();
    a.s.add_attachment(item, "real-doc.txt", &b"hello"[..], 5, now_ms())
        .unwrap();
    a.s.edit(|v| {
        v.update(item, now_ms(), |it| {
            it.icon = Some(ItemIcon::new("image", icon_id.to_string()))
        })
    })
    .unwrap()
    .unwrap();
    a.s.save().unwrap();
    let (rc, out) = cli(&p, PW, &["attach", "list", "Iconic"]);
    assert_eq!(rc, 0, "{out}");
    assert!(
        out.contains("real-doc.txt"),
        "control: ordinary attachment listed: {out}"
    );
    assert!(
        !out.contains("icon-blob.png") && !out.contains(&icon_id.to_string()),
        "icon blob listed: {out}"
    );
    let (_, g) = cli(&p, PW, &["get", "Iconic"]);
    assert!(!g.contains("icon-blob.png"), "icon blob shown by get: {g}");
    if g.contains("2 attachment") {
        panic!("get counts the icon blob as an attachment: {g}");
    }
    // the icon blob is referenced, so it must survive (not an orphan) and stay openable
    assert_eq!(format!("{:?}", a.s.attachment_state(icon_id)), "Present");
}

/// 02 Field.id + CLI `get --ids` ("Show each field's id in a trailing column"): ids printed match
/// the file's field ids.
#[test]
fn b07_get_ids_match_file() {
    let d = tempdir();
    let (p, id) = section_pkg(d.path());
    let (rc, out) = cli(&p, PW, &["get", "Sectioned", "--ids"]);
    assert_eq!(rc, 0, "{out}");
    let v = read_vault(&p);
    for f in &v.get(id).unwrap().fields {
        if f.kind != FieldKind::Section {
            assert!(
                out.contains(&f.id.to_string()),
                "field {} id {} missing from `get --ids`: {out}",
                f.name,
                f.id
            );
        }
    }
    let _ = v.get(id).unwrap().fields[0].value.expose_secret();
}

/// 02 "Item::new sets Some(now)" on the CLI add path; README `vault add`.
#[test]
fn b08_cli_add_sets_created_at() {
    let d = tempdir();
    let p = d.path().join("ca.vault");
    let (rc, out) = cli(
        &p,
        "tidy-Walrus-orbit-Velvet-42",
        &["init", "--kdf-test-params"],
    );
    assert_eq!(rc, 0, "{out}");
    let t0 = now_ms();
    let (rc, out) = cli(
        &p,
        "tidy-Walrus-orbit-Velvet-42",
        &["add", "--title", "New", "--username", "u"],
    );
    assert_eq!(rc, 0, "{out}");
    let o = indep::open_file(
        &std::fs::read(p.join("vault.bin")).unwrap(),
        "tidy-Walrus-orbit-Velvet-42",
    );
    let ca = get(&o.items[0].2, "created_at").map(u64_of);
    assert!(
        matches!(ca, Some(c) if c + 5_000 >= t0 && c <= now_ms() + 5_000),
        "created_at {ca:?} vs now {t0}"
    );
    for f in get(&o.items[0].2, "fields").unwrap().as_array().unwrap() {
        assert_eq!(
            bytes_of(get(f, "id").expect("CLI-written field has an id")).len(),
            16
        );
    }
    assert_eq!(
        version_of(&std::fs::read(p.join("vault.bin")).unwrap()),
        2,
        "init writes version 2"
    );
}

/// 03 §2 lock + 01 §9: `vault upgrade` racing six `vault add` processes on a v1 vault: no lost
/// items, the result is version 2 and opens with the password.
#[test]
fn b09_concurrent_upgrade_and_adds() {
    let d = tempdir();
    let p = pkg_from_bytes(d.path(), "race.vault", &fixture("v1-basic.vault"));
    let mut kids = vec![];
    for k in 0..6 {
        let title = format!("race{k}");
        kids.push(
            Command::new(vault_bin())
                .arg("--vault")
                .arg(&p)
                .args([
                    "--password-env",
                    "QA_MPW",
                    "add",
                    "--title",
                    &title,
                    "--username",
                    "u",
                ])
                .env("QA_MPW", FIXTURE_PW)
                .env_remove("VAULT_FILE")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        if k == 2 {
            kids.push(
                Command::new(vault_bin())
                    .arg("--vault")
                    .arg(&p)
                    .args(["--password-env", "QA_MPW", "upgrade", "--allow-weak"])
                    .env("QA_MPW", FIXTURE_PW)
                    .env_remove("VAULT_FILE")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
        }
    }
    let mut errs = vec![];
    for k in kids {
        let o = k.wait_with_output().unwrap();
        if !o.status.success() {
            errs.push(String::from_utf8_lossy(&o.stderr).into_owned());
        }
    }
    let disk = std::fs::read(p.join("vault.bin")).unwrap();
    let u = LockedVault::parse(&disk).and_then(|l| l.unlock(&pw(FIXTURE_PW)));
    assert!(
        u.is_ok(),
        "version {} does not open: {:?}; process errors {errs:?}",
        version_of(&disk),
        u.as_ref().err()
    );
    let u = u.unwrap();
    let n = u.items().filter(|i| i.title.starts_with("race")).count();
    assert_eq!(
        (n, version_of(&disk)),
        (6, 2),
        "items kept and version 2; process errors {errs:?}"
    );
    assert!(errs.is_empty(), "{errs:?}");
}

// ---------------------------------------------------------------------------------------------
// 2026-11-01 additions: VAULT_DEVICE_ID and `edit` (00 phase 1 "later dev-tool additions").
// ---------------------------------------------------------------------------------------------

fn cli_env(pkg: &std::path::Path, env: &[(&str, &str)], args: &[&str]) -> (i32, String) {
    let mut c = Command::new(vault_bin());
    c.arg("--vault")
        .arg(pkg)
        .args(["--password-env", "QA_MPW"])
        .args(args)
        .env("QA_MPW", "tidy-Walrus-orbit-Velvet-42")
        .env_remove("VAULT_FILE")
        .env_remove("VAULT_DEVICE_ID");
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output().unwrap();
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), s)
}

/// 00 phase 1: "`VAULT_DEVICE_ID` overrides the stored device id for one process": items written
/// under the override carry it (01 §4 device_id); the next process without it uses the stored id
/// again, and the stored id is the same across two plain runs.
#[test]
fn b10_vault_device_id_override_is_per_process() {
    let d = tempdir();
    let p = d.path().join("dv.vault");
    let (rc, out) = cli_env(&p, &[], &["init", "--kdf-test-params"]);
    assert_eq!(rc, 0, "{out}");
    let forced = uuid::Uuid::new_v4();
    let fs = forced.to_string();
    let (rc, out) = cli_env(
        &p,
        &[("VAULT_DEVICE_ID", &fs)],
        &["add", "--title", "Forced"],
    );
    assert_eq!(rc, 0, "{out}");
    for t in ["Plain1", "Plain2"] {
        let (rc, out) = cli_env(&p, &[], &["add", "--title", t]);
        assert_eq!(rc, 0, "{out}");
    }
    let o = indep::open_file(
        &std::fs::read(p.join("vault.bin")).unwrap(),
        "tidy-Walrus-orbit-Velvet-42",
    );
    let dev_of = |title: &str| -> Vec<u8> {
        let it = o
            .items
            .iter()
            .find(|x| get(&x.2, "title").and_then(|v| v.as_text()) == Some(title))
            .unwrap();
        bytes_of(get(&it.2, "device_id").unwrap())
    };
    assert_eq!(
        dev_of("Forced"),
        forced.as_bytes().to_vec(),
        "override used"
    );
    assert_ne!(
        dev_of("Plain1"),
        forced.as_bytes().to_vec(),
        "override persisted"
    );
    assert_eq!(dev_of("Plain1"), dev_of("Plain2"), "stored id is stable");
}

/// 02 update semantics through `vault edit`: a rename (`--set` keeps the id) and `--rm-field`
/// write what the spec says: same field id after a value change, and a removed_fields marker for
/// a removed id (01 §4 "removed_fields ... written only when non-empty").
#[test]
fn b11_cli_edit_keeps_ids_and_writes_markers() {
    let d = tempdir();
    let p = d.path().join("ed.vault");
    assert_eq!(cli_env(&p, &[], &["init", "--kdf-test-params"]).0, 0);
    let (rc, out) = cli_env(&p, &[], &["add", "--title", "E", "--username", "alice"]);
    assert_eq!(rc, 0, "{out}");
    let ids = |p: &std::path::Path| -> Vec<(String, Vec<u8>)> {
        let o = indep::open_file(
            &std::fs::read(p.join("vault.bin")).unwrap(),
            "tidy-Walrus-orbit-Velvet-42",
        );
        get(&o.items[0].2, "fields")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    get(f, "name").unwrap().as_text().unwrap().to_string(),
                    bytes_of(get(f, "id").unwrap()),
                )
            })
            .collect()
    };
    let before = ids(&p);
    let (rc, out) = cli_env(&p, &[], &["edit", "E", "--set", "username=bob"]);
    assert_eq!(rc, 0, "{out}");
    let after = ids(&p);
    assert_eq!(before, after, "a value change keeps every field id");
    let victim = uuid::Uuid::from_slice(&after[0].1).unwrap().to_string();
    let (rc, out) = cli_env(&p, &[], &["edit", "E", "--rm-field", &victim]);
    assert_eq!(rc, 0, "{out}");
    let o = indep::open_file(
        &std::fs::read(p.join("vault.bin")).unwrap(),
        "tidy-Walrus-orbit-Velvet-42",
    );
    let rf = get(&o.items[0].2, "removed_fields").expect("removed_fields written");
    assert!(
        rf.as_array()
            .unwrap()
            .iter()
            .any(|m| bytes_of(get(m, "id").unwrap()) == after[0].1),
        "marker for the removed id"
    );
}
