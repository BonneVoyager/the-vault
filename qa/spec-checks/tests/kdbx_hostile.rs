//! Hostile KeePass databases (02 import_kdbx "Error text never includes dependency parser errors or
//! secret values"; review D-7: KeePass parsing behind catch_unwind, `KdbxMalformed`). Deeply nested
//! groups are a valid KDBX structure; a recursive parser or the importer's group-path walk must not
//! overflow the stack (an overflow aborts the process; catch_unwind cannot catch it).
//! A passing check shows the behaviour on these inputs, not a proof.
use spec_checks::*;

fn rust_argon2_ver() -> ::argon2_rs::Version {
    ::argon2_rs::Version::Version13
}

fn nested_db(depth: usize) -> Vec<u8> {
    std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(move || {
            let mut db = keepass::Database::new();
            db.config.kdf_config = keepass::config::KdfConfig::Argon2 {
                iterations: 1,
                memory: 1 << 20,
                parallelism: 1,
                version: rust_argon2_ver(),
            };
            let mut id = db.root_mut().id();
            for _ in 0..depth {
                let mut g = db.group_mut(id).unwrap();
                let mut c = g.add_group();
                c.name = "g".into();
                id = c.id();
            }
            {
                let mut g = db.group_mut(id).unwrap();
                let mut e = g.add_entry();
                e.set_unprotected("Title", "deep");
                e.set_protected("Password", "deep-secret");
            }
            let mut out = vec![];
            db.save(&mut out, keepass::DatabaseKey::new().with_password("kp"))
                .unwrap();
            out
        })
        .unwrap()
        .join()
        .unwrap()
}

/// Depth 200 / 2 000 / 20 000 on a 2 MiB and an 8 MiB thread stack: the importer returns Ok or a
/// clean Err; the process must not abort.
#[test]
fn kh01_deep_group_nesting_no_abort() {
    let d = tempdir();
    let mut bad = vec![];
    let depths: Vec<usize> = std::env::var("QA_KDBX_DEPTHS")
        .map(|v| v.split(',').map(|x| x.parse().unwrap()).collect())
        .unwrap_or(vec![0, 10, 60, 200, 2_000, 20_000]);
    for depth in depths {
        let db = nested_db(depth);
        let p = d.path().join(format!("deep{depth}.kdbx"));
        std::fs::write(&p, &db).unwrap();
        // Debug builds have much larger stack frames; a 2 MiB thread overflows at depth 200 there
        // (noted in the report, not counted). The shipped build is release/dist.
        let stacks: &[&str] = if cfg!(debug_assertions) {
            &["8192"]
        } else {
            &["2048", "8192"]
        };
        for kib in stacks {
            let (out, st) = run_child(
                "open_kdbx_stack",
                &[p.to_str().unwrap(), "kp", *kib],
                120,
                3000,
            );
            eprintln!("depth {depth} stack {kib} KiB: {out} [{st}]");
            if !st.starts_with("exit0") || out.starts_with("PANIC") {
                bad.push(format!("depth {depth}, {kib} KiB stack: {st} {out}"));
            }
            if out.contains("deep-secret") {
                bad.push("secret in output".into());
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 02 import_kdbx "Input limits: database 100 MiB": a legitimate 70 MiB database (one entry with a
/// 70 MB attachment, which import does not transfer) imports.
#[test]
fn kh02_seventy_mib_database_within_limit() {
    let db = std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(|| {
            let mut db = keepass::Database::new();
            db.config.kdf_config = keepass::config::KdfConfig::Argon2 {
                iterations: 1,
                memory: 1 << 20,
                parallelism: 1,
                version: rust_argon2_ver(),
            };
            db.config.compression_config = keepass::config::CompressionConfig::None;
            {
                let mut root = db.root_mut();
                let mut e = root.add_entry();
                e.set_unprotected("Title", "big");
                e.set_protected("Password", "p");
                let data: Vec<u8> = (0..70_000_000u32).map(|i| (i % 251) as u8).collect();
                e.add_attachment("scan.pdf", keepass::db::Value::Unprotected(data));
            }
            let mut out = vec![];
            db.save(&mut out, keepass::DatabaseKey::new().with_password("kp"))
                .unwrap();
            out
        })
        .unwrap()
        .join()
        .unwrap();
    assert!(
        db.len() > 64 * 1024 * 1024 && db.len() < 100 * 1024 * 1024,
        "{}",
        db.len()
    );
    let d = tempdir();
    let p = d.path().join("big.kdbx");
    std::fs::write(&p, &db).unwrap();
    let (out, st) = run_child("open_kdbx", &[p.to_str().unwrap(), "kp"], 240, 6000);
    eprintln!("70 MiB kdbx: {out} [{st}]");
    assert_eq!(out, "OK 1", "{st}");
}

/// Added during the code-read pass. 02 import_1pux "zip + JSON" sets no input limit; the core
/// reads only `export.data`. A 1Password export carries document attachments under `files/`, so
/// a legitimate archive can exceed 64 MiB while its `export.data` is small. The core must import
/// it (the app and CLI wrappers are checked by code read: both refuse any file over 64 MiB).
#[test]
fn kh03_large_1pux_with_files_imports_in_core() {
    use std::io::Write;
    let json = br#"{"accounts":[{"vaults":[{"items":[{"uuid":"a1","createdAt":1700000000,"updatedAt":1700000000,"state":"active","categoryUuid":"001","details":{"loginFields":[{"designation":"username","value":"u"},{"designation":"password","value":"p"}],"notesPlain":"","sections":[],"passwordHistory":[]},"overview":{"title":"Big export","url":"https://x.example"}}]}]}]}"#;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let stored = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .large_file(true);
        z.start_file("export.data", stored).unwrap();
        z.write_all(json).unwrap();
        z.start_file("files/scan.pdf", stored).unwrap();
        let chunk: Vec<u8> = (0..1u32 << 20).map(|i| (i % 251) as u8).collect();
        for _ in 0..70 {
            z.write_all(&chunk).unwrap();
        }
        z.finish().unwrap();
    }
    let bytes = buf.into_inner();
    assert!(bytes.len() as u64 > 64 * 1024 * 1024);
    let d = tempdir();
    let p = d.path().join("big.1pux");
    std::fs::write(&p, &bytes).unwrap();
    let (out, st) = run_child("open_1pux", &[p.to_str().unwrap()], 120, 2000);
    eprintln!("70 MiB 1pux: {out} [{st}]");
    assert_eq!(out, "OK 1", "{st}");
}

/// Added during the code-read pass. 05 §2.5 "Incorrect credentials leave the prompt open for
/// retry"; review D-7 added `KdbxMalformed` so a damaged database is not reported as a wrong
/// password. A database that opens with the right password but whose content the parser
/// rejects (here 500 nested groups) must not be classified as wrong credentials.
#[test]
fn kh04_rejected_content_is_not_wrong_credentials() {
    let db = nested_db(500);
    let d = tempdir();
    let p = d.path().join("deep.kdbx");
    std::fs::write(&p, &db).unwrap();
    let (out, st) = run_child(
        "open_kdbx_stack",
        &[p.to_str().unwrap(), "kp", "65536"],
        120,
        3000,
    );
    eprintln!("depth 500, correct password: {out} [{st}]");
    let (wrong, _) = run_child(
        "open_kdbx_stack",
        &[p.to_str().unwrap(), "nope", "65536"],
        120,
        3000,
    );
    eprintln!("depth 500, wrong password: {wrong}");
    assert!(
        out.starts_with("OK") || !out.contains("[KdbxCredentials]"),
        "right password reported as wrong credentials: {out}"
    );
}
