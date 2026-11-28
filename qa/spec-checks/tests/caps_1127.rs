//! Bug hunt 2026-11-27: 02 importer caps (L-14, L-16, M-05), the KDF floor (L-20) and the TOTP
//! period cap (I-14), written from the spec text before reading the source.
use spec_checks::*;
use std::io::Write;
use uuid::Uuid;
use vault_core::import::*;
use vault_core::*;

fn is_too_large<T>(r: &Result<T, ImportError>) -> bool {
    matches!(r, Err(ImportError::TooLarge { .. }))
        || matches!(r, Err(e) if format!("{e:?}").starts_with("TooLarge"))
}
fn desc<T>(r: &Result<Vec<T>, ImportError>) -> String {
    match r {
        Ok(v) => format!("Ok({} items)", v.len()),
        Err(e) => format!("Err({e:?})"),
    }
}

/// 02: "CSV and 1PUX imports fail with `ImportError::TooLarge` past 100 000 items or 64 MiB of
/// imported text". CSV: 100 000 rows import, 100 001 do not; one 65 MiB value does not.
#[test]
fn ic01_csv_item_and_text_caps() {
    let mk = |n: usize| {
        let mut s = String::from("title,username,password,url,notes,totp\n");
        for k in 0..n {
            s.push_str(&format!("t{k},u,p,,,\n"));
        }
        s.into_bytes()
    };
    let mut bad = vec![];
    let r = import_csv(&mk(100_000), &CsvMapping::default(), Uuid::new_v4(), 1);
    if r.as_ref().map(|v| v.len()).ok() != Some(100_000) {
        bad.push(format!("100 000 rows: {}", desc(&r)));
    }
    let r = import_csv(&mk(100_001), &CsvMapping::default(), Uuid::new_v4(), 1);
    if !is_too_large(&r) {
        bad.push(format!("100 001 rows: {}", desc(&r)));
    }
    let big = format!(
        "title,username,password,url,notes,totp\nbig,u,p,,{},\n",
        "n".repeat(65 * 1024 * 1024)
    )
    .into_bytes();
    let r = import_csv(&big, &CsvMapping::default(), Uuid::new_v4(), 1);
    if !is_too_large(&r) {
        bad.push(format!("65 MiB note: {}", desc(&r)));
    }
    // 64 MiB of text spread over many items (titles + values), each small
    let mut s = String::from("title,username,password,url,notes,totp\n");
    let v = "v".repeat(1000);
    for k in 0..70_000 {
        s.push_str(&format!("t{k},{v},p,,,\n"));
    }
    let r = import_csv(s.as_bytes(), &CsvMapping::default(), Uuid::new_v4(), 1);
    if !is_too_large(&r) {
        bad.push(format!("~67 MiB over 70 000 items: {}", desc(&r)));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

fn zip_entries(entries: &[(String, Vec<u8>)], deflate: bool) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let opt = zip::write::SimpleFileOptions::default().compression_method(if deflate {
            zip::CompressionMethod::Deflated
        } else {
            zip::CompressionMethod::Stored
        });
        for (n, d) in entries {
            z.start_file(n.as_str(), opt).unwrap();
            z.write_all(d).unwrap();
        }
        z.finish().unwrap();
    }
    buf.into_inner()
}
const ITEM: &str = r#"{"uuid":"a1","createdAt":1700000000,"updatedAt":1700000000,"state":"active","categoryUuid":"001","details":{"loginFields":[],"notesPlain":"","sections":[],"passwordHistory":[]},"overview":{"title":"T","url":""}}"#;
fn export_data(items: usize) -> Vec<u8> {
    let mut s = String::from(r#"{"accounts":[{"vaults":[{"items":["#);
    for k in 0..items {
        if k > 0 {
            s.push(',');
        }
        s.push_str(ITEM);
    }
    s.push_str("]}]}]}");
    s.into_bytes()
}

/// 02: `import_1pux` "refuses, with `ImportError::TooLarge`, an archive that declares more than
/// 10 000 entries or a ZIP64 central directory"; "`export.data` is then bounded at 16 MiB from its
/// declared size before inflation and again while inflating".
#[test]
fn ic02_1pux_archive_caps() {
    let mut bad = vec![];
    let ok_one = zip_entries(&[("export.data".into(), export_data(1))], true);
    let r = import_1pux(&ok_one, Uuid::new_v4(), 1);
    if r.as_ref().map(|v| v.len()).ok() != Some(1) {
        bad.push(format!("control archive: {}", desc(&r)));
    }
    let mut many: Vec<(String, Vec<u8>)> = vec![("export.data".into(), export_data(1))];
    for k in 0..9_999 {
        many.push((format!("files/f{k}"), vec![]));
    }
    let at_cap = zip_entries(&many, false);
    let r = import_1pux(&at_cap, Uuid::new_v4(), 1);
    if is_too_large(&r) || r.is_err() {
        bad.push(format!("exactly 10 000 entries: {}", desc(&r)));
    }
    many.push(("files/one-more".into(), vec![]));
    let over = zip_entries(&many, false);
    let r = import_1pux(&over, Uuid::new_v4(), 1);
    if !is_too_large(&r) {
        bad.push(format!("10 001 entries: {}", desc(&r)));
    }
    // export.data declared 17 MiB (valid JSON followed by whitespace)
    let mut big = export_data(1);
    big.extend(std::iter::repeat_n(b' ', 17 * 1024 * 1024));
    let z = zip_entries(&[("export.data".into(), big.clone())], true);
    let r = import_1pux(&z, Uuid::new_v4(), 1);
    if !is_too_large(&r) {
        bad.push(format!("export.data 17 MiB declared: {}", desc(&r)));
    }
    // the same, with the declared uncompressed size patched down to 100 bytes in both headers
    let mut lie = z.clone();
    let real = (big.len() as u32).to_le_bytes();
    let mut patched = 0;
    for p in 0..lie.len().saturating_sub(4) {
        if lie[p..p + 4] == real {
            lie[p..p + 4].copy_from_slice(&100u32.to_le_bytes());
            patched += 1;
        }
    }
    let r = import_1pux(&lie, Uuid::new_v4(), 1);
    eprintln!(
        "INFO lying export.data size ({patched} fields patched): {}",
        desc(&r)
    );
    if r.is_ok() {
        bad.push(format!(
            "export.data declared 100 B, inflates to 17 MiB: {}",
            desc(&r)
        ));
    }
    // ZIP64 end of central directory (record + locator), EOCD fields set to the ZIP64 markers
    let base = zip_entries(&[("export.data".into(), export_data(1))], true);
    let eocd = base.len() - 22;
    assert_eq!(&base[eocd..eocd + 4], &[0x50, 0x4b, 0x05, 0x06]);
    let cd_size = u32::from_le_bytes(base[eocd + 12..eocd + 16].try_into().unwrap()) as u64;
    let cd_off = u32::from_le_bytes(base[eocd + 16..eocd + 20].try_into().unwrap()) as u64;
    let mut z64 = base[..eocd].to_vec();
    let rec_off = z64.len() as u64;
    z64.extend_from_slice(&[0x50, 0x4b, 0x06, 0x06]);
    z64.extend_from_slice(&44u64.to_le_bytes());
    z64.extend_from_slice(&45u16.to_le_bytes());
    z64.extend_from_slice(&45u16.to_le_bytes());
    z64.extend_from_slice(&0u32.to_le_bytes());
    z64.extend_from_slice(&0u32.to_le_bytes());
    z64.extend_from_slice(&1u64.to_le_bytes());
    z64.extend_from_slice(&1u64.to_le_bytes());
    z64.extend_from_slice(&cd_size.to_le_bytes());
    z64.extend_from_slice(&cd_off.to_le_bytes());
    z64.extend_from_slice(&[0x50, 0x4b, 0x06, 0x07]);
    z64.extend_from_slice(&0u32.to_le_bytes());
    z64.extend_from_slice(&rec_off.to_le_bytes());
    z64.extend_from_slice(&1u32.to_le_bytes());
    z64.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
    z64.extend_from_slice(&[0xff; 8]);
    z64.extend_from_slice(&[0, 0]);
    let r = import_1pux(&z64, Uuid::new_v4(), 1);
    if !is_too_large(&r) {
        bad.push(format!("ZIP64 central directory: {}", desc(&r)));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 02: 1PUX "past 100 000 items" is `TooLarge` (the items fit in a 16 MiB `export.data`).
#[test]
fn ic03_1pux_item_cap() {
    let shapes = [
        r#"{"overview":{"title":"T"}}"#,
        r#"{"uuid":"a","overview":{"title":"T"}}"#,
        r#"{"uuid":"a","details":{},"overview":{"title":"T"}}"#,
        r#"{"uuid":"a","state":"active","details":{},"overview":{"title":"T"}}"#,
        r#"{"uuid":"a","state":"active","categoryUuid":"001","details":{"loginFields":[]},"overview":{"title":"T"}}"#,
    ];
    let wrap = |item: &str, n: usize| {
        let mut s = String::from(r#"{"accounts":[{"vaults":[{"items":["#);
        for k in 0..n {
            if k > 0 {
                s.push(',');
            }
            s.push_str(item);
        }
        s.push_str("]}]}]}");
        s.into_bytes()
    };
    let shape = shapes
        .iter()
        .find(|sh| {
            let z = zip_entries(&[("export.data".into(), wrap(sh, 1))], true);
            import_1pux(&z, Uuid::new_v4(), 1).map(|v| v.len()).ok() == Some(1)
        })
        .expect("a minimal 1PUX item shape imports");
    eprintln!("INFO minimal 1PUX item: {shape}");
    let mut bad = vec![];
    for (n, want_ok) in [(100_000usize, true), (100_001, false)] {
        let data = wrap(shape, n);
        assert!(
            data.len() < 16 * 1024 * 1024 + 1,
            "fixture {} bytes",
            data.len()
        );
        let z = zip_entries(&[("export.data".into(), data)], true);
        let r = import_1pux(&z, Uuid::new_v4(), 1);
        let ok = if want_ok {
            r.as_ref().map(|v| v.len()).ok() == Some(n)
        } else {
            is_too_large(&r)
        };
        if !ok {
            bad.push(format!("{n} items: {}", desc(&r)));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 02 KeePass: "The gzip inflate inside the dependency ... is capped at 256 MiB of output ...;
/// exceeding it is `ImportError::TooLarge`, whose text names only that bound." A KDBX4 whose
/// compressed XML inflates past 256 MiB (one 300 MiB note).
#[test]
fn ic04_kdbx_inflate_cap() {
    let mut db = keepass::Database::new();
    db.config.kdf_config = keepass::config::KdfConfig::Argon2 {
        iterations: 1,
        memory: 1 << 20,
        parallelism: 1,
        version: argon2_rs::Version::Version13,
    };
    {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected("Title", "bomb");
        e.set_unprotected("Notes", "a".repeat(300 * 1024 * 1024));
    }
    let mut out = vec![];
    db.save(&mut out, keepass::DatabaseKey::new().with_password("k"))
        .unwrap();
    drop(db);
    eprintln!("INFO KDBX bomb file {} bytes", out.len());
    let r = with_timeout(300, move || {
        let r = import_kdbx(&out, &pw("k"), None, Uuid::new_v4(), 1);
        match r {
            Ok(v) => format!("Ok({})", v.len()),
            Err(e) => format!("Err({e:?}) / {e}"),
        }
    })
    .expect("import of the KDBX bomb hung");
    eprintln!("INFO KDBX bomb: {r}");
    assert!(r.starts_with("Err(TooLarge"), "{r}");
    let lower = r.to_lowercase();
    assert!(
        !(lower.contains("xml")
            || lower.contains("io error")
            || lower.contains("gzip")
            || lower.contains("deflate")),
        "error text names more than the bound: {r}"
    );
}

/// 02 kdf: "`KdfParams::below_recommended()` is true below 64 MiB or 3 passes (the least
/// `calibrate` produces); it is advisory and `validate` does not enforce it".
#[test]
fn kf01_below_recommended_boundaries() {
    let k = |m: u32, t: u32, p: u32| KdfParams {
        m_cost_kib: m,
        t_cost: t,
        p_cost: p,
        salt: [0; 32],
    };
    let mut bad = vec![];
    for (m, t, p, want) in [
        (65_536, 3, 4, false),
        (65_535, 3, 4, true),
        (65_536, 2, 4, true),
        (65_536, 3, 1, false),
        (1 << 20, 16, 64, false),
        (8_192, 1, 1, true),
        (131_072, 2, 4, true),
        (32_768, 16, 4, true),
    ] {
        if k(m, t, p).below_recommended() != want {
            bad.push(format!("({m},{t},{p}) below_recommended = {}", !want));
        }
    }
    if KdfParams::recommended().below_recommended() {
        bad.push("recommended() is below the floor".into());
    }
    if !KdfParams::for_tests().below_recommended() {
        bad.push("for_tests() is not below the floor".into());
    }
    if k(8_192, 1, 1).validate().is_err() {
        bad.push("validate enforces the floor (02: advisory only)".into());
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 02 totp: "a period of 1–300 s (`MAX_PERIOD`; a URI outside that range is `InvalidUri`, a
/// missing period is 30". Hostile spellings never yield a period outside 1..=300; a repeated
/// parameter cannot smuggle a large one; codes stay right at the edges.
#[test]
fn tp01_period_cap_spellings() {
    let sec = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let u = |q: &str| format!("otpauth://totp/x?secret={sec}{q}");
    let mut bad = vec![];
    let mut info = vec![];
    for q in [
        "&period=0",
        "&period=301",
        "&period=4294967296",
        "&period=4294967297",
        "&period=-30",
        "&period=30.5",
        "&period=",
        "&period=%2B30",
        "&period=+30",
        "&period=0030",
        "&period=%33%30",
        "&period=30&period=100000",
        "&period=100000&period=30",
        "&PERIOD=100000",
        "&period=1e3",
        "&period=18446744073709551616",
    ] {
        match Totp::parse_uri(&u(q)) {
            Ok(t) => {
                info.push(format!("{q} -> Ok({})", t.period()));
                if !(1..=300).contains(&t.period()) {
                    bad.push(format!("{q}: period {}", t.period()));
                }
                let rt = Totp::parse_uri(secrecy::ExposeSecret::expose_secret(&t.to_uri()));
                if rt.as_ref().map(|x| x.period()).ok() != Some(t.period()) {
                    bad.push(format!(
                        "{q}: to_uri round trip {:?}",
                        rt.map(|x| x.period())
                    ));
                }
                for ts in [0u64, 1_700_000_000, u32::MAX as u64] {
                    let r = t.seconds_remaining(ts);
                    if r == 0 || r > t.period() {
                        bad.push(format!("{q}: seconds_remaining({ts}) = {r}"));
                    }
                }
            }
            Err(e) => info.push(format!("{q} -> {e:?}")),
        }
    }
    match Totp::parse_uri(&u("")) {
        Ok(t) if t.period() == 30 => {}
        other => bad.push(format!("missing period: {:?}", other.map(|t| t.period()))),
    }
    for (q, p) in [("&period=1", 1u32), ("&period=300", 300)] {
        if Totp::parse_uri(&u(q)).map(|t| t.period()).ok() != Some(p) {
            bad.push(format!("{q} rejected"));
        }
    }
    eprintln!("INFO {}", info.join("; "));
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
