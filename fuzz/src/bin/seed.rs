//! Generates the `inner_payload` and `import_1pux` seed corpora (written to the gitignored
//! corpus) and the committed seeds of `import_csv`, `totp_uri`, `attachment_blob` and
//! `export_csv_roundtrip` (written to `fuzz/seeds/`, deterministic, no fixture plaintext).
//! Usage: `seed <fixtures-dir> <corpus-dir> <seeds-dir>` (run via `fuzz/seed.sh`).
use serde_json::{Value, json};
use std::io::Write;
use std::path::Path;
use vault_core::attachment::seal;
use vault_core::format::{encode_item_plain, encode_manifest};
use vault_core::{LockedVault, SecretString};

#[path = "../../fuzz_targets/common/attachment.rs"]
mod fixed_attachment;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let fixtures = Path::new(&args[1]);
    let corpus = Path::new(&args[2]);
    write_committed_seeds(Path::new(&args[3]));
    let inner = corpus.join("inner_payload");
    let pux = corpus.join("import_1pux");
    std::fs::create_dir_all(&inner).unwrap();
    std::fs::create_dir_all(&pux).unwrap();
    let pw = SecretString::new("correct horse battery staple".to_owned());
    for e in std::fs::read_dir(fixtures).unwrap() {
        let p = e.unwrap().path();
        if p.extension().and_then(|x| x.to_str()) != Some("vault") {
            continue;
        }
        let bytes = std::fs::read(&p).unwrap();
        let locked = LockedVault::parse(&bytes).unwrap();
        let version = locked.header().format_version;
        let sel: u8 = if version == 1 { 1 } else { 2 };
        let v = locked.unlock(&pw).unwrap();
        let stem = p.file_stem().unwrap().to_str().unwrap().to_owned();
        let mut pairs = Vec::new();
        for (i, item) in v.items_including_deleted().enumerate() {
            let mut out = vec![sel];
            out.extend_from_slice(&encode_item_plain(item));
            std::fs::write(inner.join(format!("{stem}-item{i}")), out).unwrap();
            pairs.push((item.id, item.modified_at));
        }
        pairs.sort();
        let mut out = vec![sel];
        out.extend_from_slice(&encode_manifest(&pairs));
        std::fs::write(inner.join(format!("{stem}-manifest")), out).unwrap();
    }
    for (name, data) in [
        ("sample", sample()),
        ("empty", json!({"accounts": []})),
        ("zero-items", export(vec![])),
    ] {
        std::fs::write(pux.join(format!("{name}.1pux")), archive(&data)).unwrap();
    }
}

fn archive(data: &Value) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, d) in [
        ("export.attributes", b"{}".to_vec()),
        ("export.data", data.to_string().into_bytes()),
    ] {
        w.start_file(name, opts).unwrap();
        w.write_all(&d).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn export(items: Vec<Value>) -> Value {
    json!({"accounts": [{"vaults": [{"attrs": {}, "items": items}]}]})
}

// Mirrors crates/vault-core/tests/onepux.rs `sample()`.
fn sample() -> Value {
    let history: Vec<Value> = (1..=12)
        .map(|i| json!({"value": format!("old{i}"), "time": 1000 + i}))
        .collect();
    export(vec![
        json!({
            "uuid": "a", "favIndex": 1, "createdAt": 1, "updatedAt": 2, "state": "active",
            "categoryUuid": "001",
            "details": {
                "loginFields": [
                    {"value": "alice", "name": "u", "fieldType": "T", "designation": "username"},
                    {"value": "s3cret", "name": "p", "fieldType": "P", "designation": "password"}
                ],
                "notesPlain": "some notes",
                "sections": [{"title": "Extra", "fields": [
                    {"title": "one-time", "id": "t", "value": {"totp": "otpauth://totp/x?secret=ABC"}},
                    {"title": "username", "id": "u2", "value": {"string": "dup"}},
                    {"title": "username", "id": "u3", "value": {"string": "dup2"}},
                    {"title": "since", "id": "d", "value": {"date": 1_700_000_000}},
                    {"title": "", "id": "fallback-id", "value": {"email": "a@b.c"}}
                ]}],
                "passwordHistory": history
            },
            "overview": {"title": "Example", "url": "https://example.com", "tags": ["work", "dev"],
                         "urls": [{"url": "https://example.com"}]}
        }),
        json!({"uuid": "b", "favIndex": 0, "state": "active", "categoryUuid": "003",
               "details": {"notesPlain": "note body"}, "overview": {"title": "My note"}}),
        json!({"uuid": "c", "state": "active", "categoryUuid": "002",
               "details": {"sections": [{"title": "", "fields": [
                   {"title": "number", "id": "ccnum", "value": {"creditCardNumber": "4111111111111111"}},
                   {"title": "expiry date", "id": "expiry", "value": {"monthYear": 202912}},
                   {"title": "verification number", "id": "cvv", "value": {"concealed": "123"}}
               ]}]},
               "overview": {"title": "Visa"}}),
        json!({"uuid": "d", "state": "active", "categoryUuid": "004",
               "details": {"sections": [{"title": "Name", "fields": [
                   {"title": "first name", "id": "fn", "value": {"string": "Alice"}}]}]},
               "overview": {"title": ""}}),
        json!({"uuid": "e", "state": "archived", "categoryUuid": "001",
               "details": {}, "overview": {"title": "Old"}}),
    ])
}

/// The committed seeds. Every file is deterministic, so rerunning leaves `git status` clean.
fn write_committed_seeds(seeds: &Path) {
    let put = |target: &str, name: &str, bytes: &[u8]| {
        let dir = seeds.join(target);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), bytes).unwrap();
    };

    put(
        "import_csv",
        "three-rows-csv.txt",
        b"title,username,password,url,notes,totp\n\
          Example,alice,s3cret,https://example.com,some notes,\n\
          \"Quoted, title\",bob,\"p\"\"w\nd\",https://b.test,'=SUM(A1),otpauth://totp/B:bob?secret=JBSWY3DPEHPK3PXP\n\
          Note only,,,,\"line1\nline2\",\n",
    );

    put(
        "totp_uri",
        "basic.txt",
        b"otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
    );
    put(
        "totp_uri",
        "sha256-8-digits-60s.txt",
        b"otpauth://totp/ACME%20Co:john?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ\
          &issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
    );

    // Sealed under the reference `attachment_blob` derives from the blob length (one chunk,
    // `size = len - 16`), so the target decrypts it successfully.
    let plain = b"attachment seed: one short chunk sealed under the fixed fuzz reference.\n";
    let r = fixed_attachment::fixed_ref(plain.len() + 16);
    let mut blob = Vec::new();
    seal(fixed_attachment::VAULT_ID, r, &plain[..], &mut blob).unwrap();
    put("attachment_blob", "sealed-one-chunk.bin", &blob);

    // Layout: see `fuzz_targets/export_csv_roundtrip.rs`. Kinds index `FieldKind::ALL`
    // (0 text, 1 password, 3 totp, 4 url, 5 notes, 6 email); names index `NAMES`.
    let mut one = vec![1u8];
    item(&mut one, "Example", &[(6, 0, "alice"), (1, 1, "s3cret")]);
    put("export_csv_roundtrip", "one-login.bin", &one);
    let mut three = vec![3u8];
    item(
        &mut three,
        "=formula, \"quoted\"",
        &[
            (0, 0, "-user"),
            (1, 1, "p\nw,d"),
            (4, 2, "https://x.test"),
            (3, 4, "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ"),
        ],
    );
    item(&mut three, "Note", &[(5, 3, "line1\r\nline2")]);
    item(&mut three, "", &[]);
    put("export_csv_roundtrip", "three-items.bin", &three);
}

/// Append one item in the `export_csv_roundtrip` input layout.
fn item(out: &mut Vec<u8>, title: &str, fields: &[(u8, u8, &str)]) {
    out.push(u8::try_from(title.len()).unwrap());
    out.extend_from_slice(title.as_bytes());
    out.push(u8::try_from(fields.len()).unwrap());
    for (kind, name, value) in fields {
        out.extend_from_slice(&[*kind, *name, u8::try_from(value.len()).unwrap()]);
        out.extend_from_slice(value.as_bytes());
    }
}
