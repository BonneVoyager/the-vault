//! Generates the `inner_payload` and `import_1pux` seed corpora; nothing generated is committed.
//! Usage: `seed <fixtures-dir> <corpus-dir>` (run via `fuzz/seed.sh`).
use std::io::Write;
use std::path::Path;
use serde_json::{Value, json};
use vault_core::{LockedVault, SecretString};
use vault_core::format::{encode_item_plain, encode_manifest};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let fixtures = Path::new(&args[1]);
    let corpus = Path::new(&args[2]);
    let inner = corpus.join("inner_payload");
    let pux = corpus.join("import_1pux");
    std::fs::create_dir_all(&inner).unwrap();
    std::fs::create_dir_all(&pux).unwrap();
    let pw = SecretString::new("correct horse battery staple".to_owned());
    for e in std::fs::read_dir(fixtures).unwrap() {
        let p = e.unwrap().path();
        if p.extension().and_then(|x| x.to_str()) != Some("vault") { continue; }
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
    for (name, data) in [("sample", sample()), ("empty", json!({"accounts": []})), ("zero-items", export(vec![]))] {
        std::fs::write(pux.join(format!("{name}.1pux")), archive(&data)).unwrap();
    }
}

fn archive(data: &Value) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, d) in [("export.attributes", b"{}".to_vec()), ("export.data", data.to_string().into_bytes())] {
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
    let history: Vec<Value> = (1..=12).map(|i| json!({"value": format!("old{i}"), "time": 1000 + i})).collect();
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
