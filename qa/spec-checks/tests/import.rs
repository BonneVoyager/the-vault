//! Import / export (02 "import / export"): CSV round trip, 1PUX and KDBX hostile inputs.
use secrecy::ExposeSecret;
use spec_checks::*;
use std::io::Write;
use uuid::Uuid;
use vault_core::import::*;
use vault_core::*;

fn field<'a>(it: &'a Item, name: &str) -> Option<&'a str> {
    it.fields.iter().find(|f| f.name == name).map(|f| f.value.expose_secret().as_str())
}

/// 02: export_csv -> import_csv round trip; imported items get fresh ids, modified_at = now,
/// device_id of the importer.
#[test]
fn i01_csv_round_trip() {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw("p"), KdfParams::for_tests(), dev);
    let nasty = ["plain", "comma, inside", "quote \" inside", "new\nline", "  spaces  ", "\u{1F511} unicode", "=cmd|' /C calc'!A0", ""];
    let mut ids = vec![];
    for (i, s) in nasty.iter().enumerate() {
        let mut it = Item::new(format!("T{i} {s}"), dev, 1);
        it.fields.push(Field::new("username", FieldKind::Text, pw(s), 1));
        it.fields.push(Field::new("password", FieldKind::Password, pw(&format!("pw{s}")), 1));
        it.fields.push(Field::new("url", FieldKind::Url, pw("https://example.com/a?b=c,d"), 1));
        it.fields.push(Field::new("notes", FieldKind::Notes, pw(&format!("note {s}")), 1));
        ids.push(v.insert(it, 1));
    }
    let dead = v.insert(Item::new("deleted one", dev, 1), 1);
    v.delete(dead, 2).unwrap();
    let out = export::export_csv(&v);
    let text = String::from_utf8(out.0.clone()).unwrap();
    assert!(!text.contains("deleted one"), "tombstones exported");
    let importer = Uuid::new_v4();
    let items = import_csv(&out.0, &CsvMapping::default(), importer, 777).unwrap_or_else(|e| panic!("default mapping cannot read our own export: {e:?}\nheader: {}", text.lines().next().unwrap_or("")));
    assert_eq!(items.len(), nasty.len(), "header: {}", text.lines().next().unwrap_or(""));
    for it in &items {
        assert!(!ids.contains(&it.id), "fresh ids");
        assert_eq!(it.device_id, importer);
        assert_eq!(it.modified_at, 777);
    }
    for (i, s) in nasty.iter().enumerate() {
        let it = items.iter().find(|x| x.title == format!("T{i} {s}")).unwrap_or_else(|| panic!("title T{i} lost"));
        assert_eq!(field(it, "username").unwrap_or(""), *s, "username {i}");
        assert_eq!(field(it, "password").unwrap_or(""), format!("pw{s}"), "password {i}");
        assert_eq!(field(it, "notes").unwrap_or(""), format!("note {s}"), "notes {i}");
    }
}

/// Hostile CSV: never panic.
#[test]
fn i02_csv_hostile() {
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        b"\xff\xfe\x00garbage".to_vec(),
        b"title,username\n\"unterminated".to_vec(),
        b"a,b,c\n1\n1,2,3,4,5,6,7,8\n".to_vec(),
        format!("title,password\n{},x\n", "y".repeat(5_000_000)).into_bytes(),
        b"\xef\xbb\xbftitle,username,password\nBOM,u,p\n".to_vec(),
        std::iter::repeat_n(b'\n', 100_000).collect(),
    ];
    for c in cases {
        let r = std::panic::catch_unwind(|| import_csv(&c, &CsvMapping::default(), Uuid::new_v4(), 1).map(|v| v.len()));
        assert!(r.is_ok(), "panic on {:?}", String::from_utf8_lossy(&c[..c.len().min(40)]));
    }
}

fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let opt = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated).large_file(true);
        for (n, d) in entries {
            z.start_file(*n, opt).unwrap();
            z.write_all(d).unwrap();
        }
        z.finish().unwrap();
    }
    buf.into_inner()
}

/// 1PUX hostile archives: no panic, bounded memory/time (child process).
#[test]
fn i03_1pux_hostile() {
    let d = tempdir();
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("not a zip", b"hello".to_vec()),
        ("empty zip", zip_with(&[])),
        ("no export.data", zip_with(&[("other.txt", b"x")])),
        ("bad json", zip_with(&[("export.data", b"{not json")])),
        ("wrong shape", zip_with(&[("export.data", br#"{"accounts": 5}"#)])),
        ("deep json", zip_with(&[("export.data", &[b'['; 200_000])])),
        ("null item", zip_with(&[("export.data", br#"{"accounts":[{"vaults":[{"items":[null]}]}]}"#)])),
    ];
    // ~2 GB of zeros in export.data compresses to ~2 MB: a decompression bomb
    let mut big = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut big);
        let opt = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated).large_file(true);
        z.start_file("export.data", opt).unwrap();
        let chunk = vec![b' '; 1 << 20];
        for _ in 0..2048 {
            z.write_all(&chunk).unwrap();
        }
        z.finish().unwrap();
    }
    cases.push(("2 GB decompression bomb", big.into_inner()));
    let mut bad = vec![];
    for (name, bytes) in cases {
        let p = d.path().join("x.1pux");
        std::fs::write(&p, &bytes).unwrap();
        let (out, st) = run_child("open_1pux", &[p.to_str().unwrap()], 60, 1024);
        // lenient schema handling may return OK 0 for well-formed but odd JSON; never a panic/OOM
        let lenient_ok = matches!(name, "wrong shape" | "null item") && out == "OK 0";
        if !(st.starts_with("exit0") && (out.starts_with("ERR") || lenient_ok)) {
            bad.push(format!("{name}: {st} {out}"));
        } else {
            eprintln!("{name}: {st}");
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

fn make_kdbx(password: &str, kdf: keepass::config::KdfConfig) -> Vec<u8> {
    let mut db = keepass::Database::new();
    db.config.kdf_config = kdf;
    {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected("Title", "Entry One");
        e.set_unprotected("UserName", "alice");
        e.set_protected("Password", "kp-secret-1");
        e.set_unprotected("URL", "https://one.example");
        e.set_unprotected("Notes", "n1");
        e.set_protected("PIN", "4321");
        e.set_unprotected("otp", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP");
    }
    let mut out = vec![];
    db.save(&mut out, keepass::DatabaseKey::new().with_password(password)).unwrap();
    out
}
fn fast_argon() -> keepass::config::KdfConfig {
    keepass::config::KdfConfig::Argon2 { iterations: 1, memory: 1 << 20, parallelism: 1, version: rust_argon2_ver() }
}

/// 02 import_kdbx: entries map to login fields; wrong password error; error text never includes
/// secrets or parser internals; input limits 100 MiB db, 1 MiB key file.
#[test]
fn i04_kdbx_basic_and_limits() {
    let db = make_kdbx("kdbx pass", fast_argon());
    let items = import_kdbx(&db, &pw("kdbx pass"), None, Uuid::new_v4(), 5).expect("import");
    assert_eq!(items.len(), 1);
    let it = &items[0];
    assert_eq!(it.title, "Entry One");
    let pwf = it.fields.iter().find(|f| f.value.expose_secret() == "kp-secret-1").expect("password mapped");
    assert!(pwf.kind.is_sensitive());
    let pin = it.fields.iter().find(|f| f.value.expose_secret() == "4321").expect("custom protected field kept");
    assert!(pin.kind.is_sensitive(), "protected custom field remains concealed");
    assert!(it.fields.iter().any(|f| matches!(f.kind, FieldKind::Totp)), "otp -> TOTP");
    let e = import_kdbx(&db, &pw("wrong pass"), None, Uuid::new_v4(), 5).err().expect("wrong password fails");
    let msg = format!("{e} {e:?}");
    assert!(!msg.contains("wrong pass") && !msg.contains("kdbx pass"), "error leaks password: {msg}");
    let big = vec![0u8; 100 * 1024 * 1024 + 1];
    let t = std::time::Instant::now();
    assert!(import_kdbx(&big, &pw("x"), None, Uuid::new_v4(), 5).is_err());
    assert!(t.elapsed().as_secs() < 2, "100 MiB limit checked first");
    let kf = vec![0u8; 1024 * 1024 + 1];
    assert!(import_kdbx(&db, &pw("kdbx pass"), Some(&kf), Uuid::new_v4(), 5).is_err(), "1 MiB key file limit");
}

/// Truncation and bit flips of a KDBX: no panic, never a different success.
#[test]
fn i05_kdbx_corruption_sweep() {
    use rand::{Rng, SeedableRng};
    let db = make_kdbx("kdbx pass", fast_argon());
    let mut bad = vec![];
    let step = (db.len() / 300).max(1);
    for cut in (0..db.len()).step_by(step) {
        let s = db[..cut].to_vec();
        match std::panic::catch_unwind(move || import_kdbx(&s, &pw("kdbx pass"), None, Uuid::new_v4(), 1).map(|v| v.len())) {
            Err(_) => bad.push(format!("cut {cut}: panic")),
            // dropping only the 36-byte terminator block keeps every entry (keepass leniency, see Notes)
            Ok(Ok(n)) if cut == db.len() - 36 && n == 1 => {}
            Ok(Ok(_)) => bad.push(format!("cut {cut}: accepted")),
            Ok(Err(e)) => {
                let m = format!("{e}");
                if m.contains("kdbx pass") {
                    bad.push(format!("cut {cut}: leaks password"));
                }
            }
        }
    }
    let mut rng = rand::rngs::StdRng::seed_from_u64(3);
    for _ in 0..300 {
        let mut m = db.clone();
        let p = rng.gen_range(0..m.len());
        m[p] ^= 1 << rng.gen_range(0..8);
        let r = with_timeout(20, move || std::panic::catch_unwind(move || import_kdbx(&m, &pw("kdbx pass"), None, Uuid::new_v4(), 1).map(|v| v.len())).is_ok());
        match r {
            Some(true) => {}
            Some(false) => bad.push(format!("flip at {p}: panic")),
            None => bad.push(format!("flip at {p}: hang")),
        }
    }
    bad.truncate(15);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// KDBX 4 outer header: rewrite KDF parameters in the VariantDictionary (field 11) and fix the
/// unkeyed SHA-256 header hash. The KDF runs before any key check, so attacker-chosen costs reach
/// it unless the importer caps them (spec: "Input limits: database 100 MiB, key file 1 MiB").
fn patch_kdbx_kdf(db: &[u8], patch: &dyn Fn(&str, &mut Vec<u8>)) -> Vec<u8> {
    use sha2::Digest;
    let mut pos = 12;
    let mut out = db[..12].to_vec();
    loop {
        let id = db[pos];
        let len = u32::from_le_bytes(db[pos + 1..pos + 5].try_into().unwrap()) as usize;
        let mut data = db[pos + 5..pos + 5 + len].to_vec();
        pos += 5 + len;
        if id == 11 {
            // VariantDictionary: u16 version, then (type u8, klen u32, key, vlen u32, value)*, 0
            let mut nd = data[..2].to_vec();
            let mut q = 2;
            loop {
                let t = data[q];
                if t == 0 {
                    nd.push(0);
                    break;
                }
                let kl = u32::from_le_bytes(data[q + 1..q + 5].try_into().unwrap()) as usize;
                let key = String::from_utf8(data[q + 5..q + 5 + kl].to_vec()).unwrap();
                let vl = u32::from_le_bytes(data[q + 5 + kl..q + 9 + kl].try_into().unwrap()) as usize;
                let mut val = data[q + 9 + kl..q + 9 + kl + vl].to_vec();
                q += 9 + kl + vl;
                patch(&key, &mut val);
                nd.push(t);
                nd.extend_from_slice(&(kl as u32).to_le_bytes());
                nd.extend_from_slice(key.as_bytes());
                nd.extend_from_slice(&(val.len() as u32).to_le_bytes());
                nd.extend_from_slice(&val);
            }
            data = nd;
        }
        out.push(id);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&data);
        if id == 0 {
            break;
        }
    }
    let hash = sha2::Sha256::digest(&out);
    out.extend_from_slice(&hash);
    out.extend_from_slice(&db[pos + 32..]);
    out
}

#[test]
fn i06_kdbx_hostile_kdf_header() {
    let d = tempdir();
    let db = make_kdbx("kdbx pass", fast_argon());
    // sanity: the patcher round-trips an unmodified header
    let same = patch_kdbx_kdf(&db, &|_, _| {});
    assert!(import_kdbx(&same, &pw("kdbx pass"), None, Uuid::new_v4(), 1).is_ok(), "patcher sanity");
    let cases: Vec<(&str, Box<dyn Fn(&str, &mut Vec<u8>)>)> = vec![
        ("argon2 memory 64 GiB", Box::new(|k, v| if k == "M" { *v = (64u64 << 30).to_le_bytes().to_vec() })),
        ("argon2 memory 4 GiB", Box::new(|k, v| if k == "M" { *v = (4u64 << 30).to_le_bytes().to_vec() })),
        ("argon2 iterations 2^32", Box::new(|k, v| if k == "I" { *v = (1u64 << 32).to_le_bytes().to_vec() })),
        ("argon2 parallelism 2^24", Box::new(|k, v| if k == "P" { *v = (1u32 << 24).to_le_bytes().to_vec() })),
        ("argon2 memory 0", Box::new(|k, v| if k == "M" { *v = 0u64.to_le_bytes().to_vec() })),
    ];
    let mut bad = vec![];
    for (name, f) in cases {
        let m = patch_kdbx_kdf(&db, &*f);
        let p = d.path().join("h.kdbx");
        std::fs::write(&p, &m).unwrap();
        let t = std::time::Instant::now();
        let (out, st) = run_child("open_kdbx", &[p.to_str().unwrap(), "kdbx pass"], 30, 1500);
        let line = format!("{name}: {st} {out} in {:.1?}", t.elapsed());
        eprintln!("{line}");
        if !(st.starts_with("exit0") && out.starts_with("ERR")) || t.elapsed().as_secs() > 10 {
            bad.push(line);
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// KDBX 4 with AES-KDF and attacker rounds: 2^40 rounds would run for hours before any key check.
#[test]
fn i07_kdbx_hostile_aes_rounds() {
    let d = tempdir();
    let db = make_kdbx("kdbx pass", keepass::config::KdfConfig::Aes { rounds: 10 });
    let m = patch_kdbx_kdf(&db, &|k, v| if k == "R" { *v = (1u64 << 40).to_le_bytes().to_vec() });
    let p = d.path().join("aes.kdbx");
    std::fs::write(&p, &m).unwrap();
    let t = std::time::Instant::now();
    let (out, st) = run_child("open_kdbx", &[p.to_str().unwrap(), "kdbx pass"], 30, 1500);
    let line = format!("AES-KDF 2^40 rounds: {st} {out} in {:.1?}", t.elapsed());
    eprintln!("{line}");
    assert!(st.starts_with("exit0") && out.starts_with("ERR") && t.elapsed().as_secs() <= 10, "{line}");
}
fn rust_argon2_ver() -> ::argon2_rs::Version {
    ::argon2_rs::Version::Version13
}

/// Truncation at KDBX 4 HMAC-block boundaries: dropping only the terminating empty block, or
/// dropping whole data blocks of a multi-block database.
#[test]
fn i08_kdbx_block_boundary_truncation() {
    // single-block database: the last 36 bytes are the terminator block (32 HMAC + u32 size 0)
    let db = make_kdbx("kdbx pass", fast_argon());
    assert_eq!(&db[db.len() - 4..], &[0, 0, 0, 0], "terminator block size field");
    let cut = db[..db.len() - 36].to_vec();
    let r = import_kdbx(&cut, &pw("kdbx pass"), None, Uuid::new_v4(), 1);
    eprintln!("terminator dropped: {:?}", r.as_ref().map(|v| v.len()).map_err(|e| e.to_string()));
    // multi-block database: ~3 MB of incompressible protected notes -> several 1 MiB blocks
    use rand::RngCore;
    let mut noise = vec![0u8; 3 * 1024 * 1024];
    rand::thread_rng().fill_bytes(&mut noise);
    let hexs: String = noise.iter().map(|b| format!("{b:02x}")).collect();
    let mut kdb = keepass::Database::new();
    kdb.config.kdf_config = fast_argon();
    kdb.config.compression_config = keepass::config::CompressionConfig::None;
    {
        let mut root = kdb.root_mut();
        for i in 0..3 {
            let mut e = root.add_entry();
            e.set_unprotected("Title", format!("E{i}"));
            e.set_unprotected("Notes", hexs[i * 2_000_000..(i + 1) * 2_000_000].to_string());
        }
    }
    let mut big = vec![];
    kdb.save(&mut big, keepass::DatabaseKey::new().with_password("kdbx pass")).unwrap();
    let full = import_kdbx(&big, &pw("kdbx pass"), None, Uuid::new_v4(), 1).unwrap().len();
    // walk the block stream from the end of the outer header (+64 hash/HMAC) to find boundaries
    let mut pos = 12;
    loop {
        let id = big[pos];
        let len = u32::from_le_bytes(big[pos + 1..pos + 5].try_into().unwrap()) as usize;
        pos += 5 + len;
        if id == 0 {
            break;
        }
    }
    pos += 64;
    let mut bounds = vec![];
    while pos + 36 <= big.len() {
        let sz = u32::from_le_bytes(big[pos + 32..pos + 36].try_into().unwrap()) as usize;
        bounds.push(pos);
        pos += 36 + sz;
        if sz == 0 {
            break;
        }
    }
    let mut accepted = vec![];
    for b in &bounds[1..] {
        if let Ok(v) = import_kdbx(&big[..*b], &pw("kdbx pass"), None, Uuid::new_v4(), 1) {
            accepted.push(format!("cut at block boundary {b} of {}: {} of {full} entries", big.len(), v.len()));
        }
    }
    eprintln!("blocks: {}; accepted truncations: {accepted:?}", bounds.len());
    assert!(accepted.iter().all(|a| a.contains(&format!("{full} of {full}"))), "data blocks silently dropped: {accepted:?}");
    // Not asserted: the keepass parser accepts a stream whose empty terminator block is missing; every
    // entry is still present and HMAC-verified. Recorded under Notes.
    if let Ok(n) = r {
        assert_eq!(n.len(), 1, "terminator-less stream lost entries");
    }
}
