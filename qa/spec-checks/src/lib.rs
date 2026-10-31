//! Shared helpers for spec checks. Temp dirs live under qa/spec-checks/tmp/.
use std::path::PathBuf;

pub fn tmp_root() -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tmp");
    std::fs::create_dir_all(&p).unwrap();
    p
}

pub fn tempdir() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("chk-").tempdir_in(tmp_root()).unwrap()
}

pub fn pw(s: &str) -> secrecy::SecretString {
    secrecy::SecretString::new(s.to_string())
}

/// Runs `f` on a thread; returns None if it does not finish within `secs`.
pub fn with_timeout<T: Send + 'static>(secs: u64, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(std::time::Duration::from_secs(secs)).ok()
}

// ---------------------------------------------------------------------------
// Independent decoder for the 01-vault-format.md layout (no vault-core code).
// ---------------------------------------------------------------------------
pub use ciborium::Value;

pub struct RawFile {
    pub version: u16,
    pub header_len: u32,
    pub header_bytes: Vec<u8>,
    pub header: Value,
    pub body_bytes: Vec<u8>,
    pub body: Vec<Value>,
}

/// 01 §1: magic(4) | version u16 BE | header_len u32 BE | header CBOR | body CBOR array.
pub fn split(bytes: &[u8]) -> RawFile {
    assert_eq!(&bytes[0..4], b"RVLT", "01 §1 magic");
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    let header_len = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
    let hend = 10 + header_len as usize;
    let header_bytes = bytes[10..hend].to_vec();
    let header: Value = ciborium::from_reader(&header_bytes[..]).unwrap();
    let body_bytes = bytes[hend..].to_vec();
    let body: Value = ciborium::from_reader(&body_bytes[..]).unwrap();
    let body = match body {
        Value::Array(a) => a,
        _ => panic!("body is not an array"),
    };
    RawFile { version, header_len, header_bytes, header, body_bytes, body }
}

pub fn join(version: u16, header: &Value, body: &[Value]) -> Vec<u8> {
    let mut h = Vec::new();
    ciborium::into_writer(header, &mut h).unwrap();
    let mut out = b"RVLT".to_vec();
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(h.len() as u32).to_be_bytes());
    out.extend_from_slice(&h);
    ciborium::into_writer(&Value::Array(body.to_vec()), &mut out).unwrap();
    out
}

pub fn enc(v: &Value) -> Vec<u8> {
    let mut o = Vec::new();
    ciborium::into_writer(v, &mut o).unwrap();
    o
}

pub fn get<'a>(m: &'a Value, k: &str) -> Option<&'a Value> {
    match m {
        Value::Map(e) => e.iter().find(|(kk, _)| kk.as_text() == Some(k)).map(|(_, v)| v),
        _ => None,
    }
}
pub fn get_mut<'a>(m: &'a mut Value, k: &str) -> Option<&'a mut Value> {
    match m {
        Value::Map(e) => e.iter_mut().find(|(kk, _)| kk.as_text() == Some(k)).map(|(_, v)| v),
        _ => None,
    }
}
pub fn bytes_of(v: &Value) -> Vec<u8> {
    v.as_bytes().unwrap().clone()
}
pub fn u64_of(v: &Value) -> u64 {
    let i: i128 = v.as_integer().unwrap().into();
    i as u64
}
pub fn set(m: &mut Value, k: &str, v: Value) {
    if let Some(x) = get_mut(m, k) {
        *x = v;
    } else if let Value::Map(e) = m {
        e.push((Value::Text(k.into()), v));
    }
}

/// RFC 8949 §4.2.1 canonical map: keys sorted by their encoded bytes, recursively; minimal ints
/// are implied by ciborium's encoder, so we check key order and that re-encoding is identical.
pub fn is_canonical(v: &Value) -> bool {
    match v {
        Value::Map(e) => {
            let keys: Vec<Vec<u8>> = e.iter().map(|(k, _)| enc(k)).collect();
            keys.windows(2).all(|w| w[0] < w[1]) && e.iter().all(|(k, v)| is_canonical(k) && is_canonical(v))
        }
        Value::Array(a) => a.iter().all(is_canonical),
        Value::Tag(_, b) => is_canonical(b),
        _ => true,
    }
}

pub mod indep {
    //! Independent crypto from 01 §2-§4, built on RustCrypto crates directly.
    use super::*;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    pub fn kek_password(password_nfc: &str, salt: &[u8], m: u32, t: u32, p: u32) -> [u8; 32] {
        let params = argon2::Params::new(m, t, p, Some(32)).unwrap();
        let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut out = [0u8; 32];
        a.hash_password_into(password_nfc.as_bytes(), salt, &mut out).unwrap();
        out
    }
    pub fn hkdf(vault_key: &[u8], vault_id: &[u8], info: &str) -> [u8; 32] {
        let h = hkdf::Hkdf::<sha2::Sha256>::new(Some(vault_id), vault_key);
        let mut o = [0u8; 32];
        h.expand(info.as_bytes(), &mut o).unwrap();
        o
    }
    pub fn open(key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        let c = XChaCha20Poly1305::new_from_slice(key).unwrap();
        c.decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad }).ok()
    }
    pub fn seal(key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> Vec<u8> {
        let c = XChaCha20Poly1305::new_from_slice(key).unwrap();
        c.encrypt(XNonce::from_slice(nonce), Payload { msg: pt, aad }).unwrap()
    }
    pub fn slot_aad(version: u16, vault_id: &[u8], slot_id: &[u8], kind: &str) -> Vec<u8> {
        let mut a = b"RVLT".to_vec();
        a.extend_from_slice(&version.to_be_bytes());
        a.extend_from_slice(vault_id);
        a.extend_from_slice(slot_id);
        a.extend_from_slice(kind.as_bytes());
        a
    }
    pub fn item_aad(vault_id: &[u8], id: &[u8], modified_at: u64, version: u16) -> Vec<u8> {
        let mut a = vault_id.to_vec();
        a.extend_from_slice(id);
        a.extend_from_slice(&modified_at.to_be_bytes());
        a.extend_from_slice(&version.to_be_bytes());
        a
    }
    pub fn manifest_aad(vault_id: &[u8], count: u32, version: u16, digest: Option<&[u8]>) -> Vec<u8> {
        let mut a = vault_id.to_vec();
        a.extend_from_slice(&count.to_be_bytes());
        a.extend_from_slice(&version.to_be_bytes());
        if let Some(d) = digest {
            a.extend_from_slice(d);
        }
        a
    }
    /// 01 §4 header_digest over canonical { kdf, slots, slots_modified_at, slots_device_id? }.
    pub fn header_digest(header: &Value) -> Option<Vec<u8>> {
        use sha2::Digest;
        let sma = get(header, "slots_modified_at")?.clone();
        let mut entries = vec![
            (Value::Text("kdf".into()), get(header, "kdf").unwrap().clone()),
            (Value::Text("slots".into()), get(header, "slots").unwrap().clone()),
            (Value::Text("slots_modified_at".into()), sma),
        ];
        if let Some(d) = get(header, "slots_device_id") {
            entries.push((Value::Text("slots_device_id".into()), d.clone()));
        }
        entries.sort_by_key(|(k, _)| enc(k));
        Some(sha2::Sha256::digest(enc(&Value::Map(entries))).to_vec())
    }

    pub struct Opened {
        pub vault_key: Vec<u8>,
        pub item_key: [u8; 32],
        pub manifest_key: [u8; 32],
        pub vault_id: Vec<u8>,
        pub items: Vec<(Vec<u8>, u64, Value)>, // id, modified_at, plaintext map
        pub manifest: Value,
    }

    /// Opens a file with a password using only the spec. Panics with a message naming the
    /// spec step that failed.
    pub fn open_file(bytes: &[u8], password: &str) -> Opened {
        let raw = split(bytes);
        let h = &raw.header;
        let vault_id = bytes_of(get(h, "vault_id").unwrap());
        let kdf = get(h, "kdf").unwrap();
        assert_eq!(get(kdf, "alg").unwrap().as_text(), Some("argon2id"));
        let kek = kek_password(
            password,
            &bytes_of(get(kdf, "salt").unwrap()),
            u64_of(get(kdf, "m_cost").unwrap()) as u32,
            u64_of(get(kdf, "t_cost").unwrap()) as u32,
            u64_of(get(kdf, "p_cost").unwrap()) as u32,
        );
        let mut vault_key = None;
        for s in get(h, "slots").unwrap().as_array().unwrap() {
            if get(s, "kind").unwrap().as_text() != Some("password") {
                continue;
            }
            let aad = slot_aad(raw.version, &vault_id, &bytes_of(get(s, "id").unwrap()), "password");
            if let Some(k) = open(&kek, &bytes_of(get(s, "nonce").unwrap()), &bytes_of(get(s, "wrapped_key").unwrap()), &aad) {
                vault_key = Some(k);
                break;
            }
        }
        let vault_key = vault_key.expect("01 §2: no password slot unwrapped with the spec AAD");
        let item_key = hkdf(&vault_key, &vault_id, "vault/item/v1");
        let manifest_key = hkdf(&vault_key, &vault_id, "vault/manifest/v1");
        let mut items = Vec::new();
        let n = raw.body.len();
        for r in &raw.body[..n - 1] {
            assert_eq!(get(r, "t").unwrap().as_text(), Some("item"));
            let id = bytes_of(get(r, "id").unwrap());
            let ma = u64_of(get(r, "modified_at").unwrap());
            let aad = item_aad(&vault_id, &id, ma, raw.version);
            let pt = open(&item_key, &bytes_of(get(r, "nonce").unwrap()), &bytes_of(get(r, "ct").unwrap()), &aad)
                .expect("01 §4: item did not open with the spec AAD and HKDF item key");
            items.push((id, ma, ciborium::from_reader(&pt[..]).unwrap()));
        }
        let m = &raw.body[n - 1];
        assert_eq!(get(m, "t").unwrap().as_text(), Some("manifest"), "01 §4 manifest last");
        let digest = header_digest(h);
        let aad = manifest_aad(&vault_id, (n - 1) as u32, raw.version, digest.as_deref());
        let pt = open(&manifest_key, &bytes_of(get(m, "nonce").unwrap()), &bytes_of(get(m, "ct").unwrap()), &aad)
            .expect("01 §4: manifest did not open with the spec AAD");
        let manifest = ciborium::from_reader(&pt[..]).unwrap();
        Opened { vault_key, item_key, manifest_key, vault_id, items, manifest }
    }
}

// ---------------------------------------------------------------------------
// Item snapshots for equality across devices (Item has no PartialEq by spec).
// ---------------------------------------------------------------------------
use secrecy::ExposeSecret;
pub fn snap_item(i: &vault_core::Item) -> String {
    // 2026-10-31: field identity is `id` (01 §4); the snapshot includes ids, removed_fields,
    // created_at, icon and history field_id so equality covers the new merge state.
    let mut fields: Vec<String> = i
        .fields
        .iter()
        .map(|f| format!("{}|{}|{:?}|{:?}|{}|{}|{:?}", f.id, f.name, f.kind, f.kind_raw, f.value.expose_secret(), f.modified_at, f.section))
        .collect();
    fields.sort();
    let order: Vec<String> = i.fields.iter().map(|f| f.id.to_string()).collect();
    let hist: Vec<String> = i.history.iter().map(|h| format!("{}@{}#{:?}", h.value.expose_secret(), h.replaced_at, h.field_id)).collect();
    let mut rf: Vec<String> = i.removed_fields.iter().map(|t| format!("{}@{}", t.id, t.removed_at)).collect();
    rf.sort();
    let mut tags = i.tags.clone();
    tags.sort();
    let icon = i.icon.as_ref().map(|c| format!("{}:{}:{:?}", c.kind, c.value, c.color));
    format!(
        "{}|{}|{:?}|{}|{:?}|{:?}|{:?}|rf={:?}|ca={:?}|icon={:?}|ma={}|order={}",
        i.id, i.title, i.deleted_at, i.favorite, tags, fields, hist, rf, i.created_at, icon, i.modified_at, order.len()
    )
}
pub fn snap_vault(v: &vault_core::UnlockedVault) -> Vec<String> {
    let mut s: Vec<String> = v.items_including_deleted().map(snap_item).collect();
    s.sort();
    s
}
/// Content-only snapshot: ignores timestamps (used where only convergence of values matters).
pub fn snap_content(v: &vault_core::UnlockedVault) -> Vec<String> {
    let mut s: Vec<String> = v
        .items_including_deleted()
        .map(|i| {
            let mut f: Vec<String> = i.fields.iter().map(|f| format!("{}={}", f.name, f.value.expose_secret())).collect();
            f.sort();
            format!("{}|{}|del={}|{:?}", i.id, i.title, i.deleted_at.is_some(), f)
        })
        .collect();
    s.sort();
    s
}

/// Runs a harness binary with a wall-clock limit (seconds) and a memory limit (ulimit -v is not
/// enforced on macOS, so we watch RSS by polling `ps`). Returns (stdout, status description).
pub fn run_child(bin: &str, args: &[&str], secs: u64, max_rss_mb: u64) -> (String, String) {
    use std::process::{Command, Stdio};
    let exe = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/debug").join(bin);
    let mut c = Command::new(&exe).args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let start = std::time::Instant::now();
    let mut peak = 0u64;
    loop {
        if let Some(st) = c.try_wait().unwrap() {
            let mut out = String::new();
            use std::io::Read;
            c.stdout.take().unwrap().read_to_string(&mut out).unwrap();
            let mut err = String::new();
            c.stderr.take().unwrap().read_to_string(&mut err).unwrap();
            let status = if st.success() { format!("exit0 peak={peak}MB") } else { format!("FAIL {st} peak={peak}MB stderr={}", err.lines().take(3).collect::<Vec<_>>().join(" / ")) };
            return (out.trim().to_string(), status);
        }
        let ps = Command::new("ps").args(["-o", "rss=", "-p", &c.id().to_string()]).output().unwrap();
        let rss: u64 = String::from_utf8_lossy(&ps.stdout).trim().parse().unwrap_or(0);
        peak = peak.max(rss / 1024);
        if peak > max_rss_mb {
            let _ = c.kill();
            let _ = c.wait();
            return (String::new(), format!("KILLED rss {peak}MB > {max_rss_mb}MB"));
        }
        if start.elapsed().as_secs() > secs {
            let _ = c.kill();
            let _ = c.wait();
            return (String::new(), format!("KILLED timeout {secs}s"));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

// ---------------------------------------------------------------------------
// vault-sync helpers
// ---------------------------------------------------------------------------
pub mod dev {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    pub use vault_sync::{SyncEvent, SyncedVault};

    pub const PW: &str = "sync check password";

    pub fn hooks() -> Arc<dyn vault_sync::CloudHooks> {
        Arc::new(vault_sync::NoopHooks)
    }
    pub struct Dev {
        pub s: SyncedVault,
        pub rx: crossbeam_channel::Receiver<SyncEvent>,
        pub seen: Vec<String>,
        pub dev: uuid::Uuid,
    }
    impl Dev {
        pub fn create(path: &Path) -> Dev {
            let dev = uuid::Uuid::new_v4();
            let s = SyncedVault::create(path, &pw(PW), vault_core::KdfParams::for_tests(), dev, hooks()).unwrap();
            let rx = s.subscribe();
            Dev { s, rx, seen: vec![], dev }
        }
        pub fn open(path: &Path) -> Dev {
            let dev = uuid::Uuid::new_v4();
            let mut s = SyncedVault::open(path, dev, hooks()).unwrap();
            let rx = s.subscribe();
            s.unlock(&pw(PW)).unwrap();
            Dev { s, rx, seen: vec![], dev }
        }
        pub fn v(&self) -> &vault_core::UnlockedVault {
            self.s.vault().unwrap()
        }
        pub fn drain(&mut self) {
            self.s.poll();
            while let Ok(e) = self.rx.try_recv() {
                self.seen.push(format!("{e:?}"));
            }
        }
        /// Polls until `pred(events so far)` or timeout.
        pub fn wait_for(&mut self, secs: u64, pred: impl Fn(&[String]) -> bool) -> bool {
            let t = Instant::now();
            while t.elapsed() < Duration::from_secs(secs) {
                self.drain();
                if pred(&self.seen) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            false
        }
        pub fn add_login(&mut self, title: &str, now: u64) -> uuid::Uuid {
            let dev = self.dev;
            let t = title.to_string();
            self.s
                .edit(move |v| {
                    let mut it = vault_core::Item::new(t, dev, now);
                    it.fields.push(vault_core::Field::new("username", vault_core::FieldKind::Text, pw("u"), now));
                    it.fields.push(vault_core::Field::new("password", vault_core::FieldKind::Password, pw("p"), now));
                    v.insert(it, now)
                })
                .unwrap()
        }
    }
    pub fn now_ms() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
    }
    pub fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }
    pub fn ls(p: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(p).map(|r| r.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
        v.sort();
        v
    }
    pub fn copy_dir(from: &Path, to: &Path) {
        let st = std::process::Command::new("cp").arg("-R").arg(from).arg(to).status().unwrap();
        assert!(st.success());
    }
    pub fn primary(pkg: &Path) -> PathBuf {
        pkg.join("vault.bin")
    }
    pub fn read_vault(pkg: &Path) -> vault_core::UnlockedVault {
        let b = std::fs::read(primary(pkg)).unwrap();
        vault_core::LockedVault::parse(&b).unwrap().unlock(&pw(PW)).unwrap()
    }
}

// ---------------------------------------------------------------------------
// 2026-10-31 additions: hand-built files (independent writer), UUIDv5, fixtures.
// ---------------------------------------------------------------------------
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/vault-core/tests/fixtures")
}
pub fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixtures_dir().join(name)).unwrap_or_else(|_| panic!("fixture {name} committed"))
}
/// Password of every committed fixture (01 §8).
pub const FIXTURE_PW: &str = "correct horse battery staple";

/// RFC 8949 §4.2.1 canonical form: map keys sorted by encoded bytes, recursively.
pub fn canon(v: Value) -> Value {
    match v {
        Value::Map(e) => {
            let mut e: Vec<(Value, Value)> = e.into_iter().map(|(k, v)| (canon(k), canon(v))).collect();
            e.sort_by_key(|(k, _)| enc(k));
            Value::Map(e)
        }
        Value::Array(a) => Value::Array(a.into_iter().map(canon).collect()),
        o => o,
    }
}
pub fn t(s: &str) -> Value {
    Value::Text(s.into())
}
pub fn i(n: u64) -> Value {
    Value::Integer(n.into())
}
pub fn map(e: Vec<(&str, Value)>) -> Value {
    Value::Map(e.into_iter().map(|(k, v)| (t(k), v)).collect())
}

/// UUIDv5 (RFC 4122 §4.3) computed directly with SHA-1, independent of the `uuid` crate's v5.
pub fn uuid5(ns: &[u8; 16], name: &[u8]) -> [u8; 16] {
    use sha1::Digest;
    let mut h = sha1::Sha1::new();
    h.update(ns);
    h.update(name);
    let d = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    b
}
/// 01 §9: UUIDv5(namespace = item id, "field:" || name || ":" || ordinal).
pub fn derived_field_id(item_id: &[u8; 16], name: &str, ordinal: usize) -> uuid::Uuid {
    let mut n = b"field:".to_vec();
    n.extend_from_slice(name.as_bytes());
    n.push(b':');
    n.extend_from_slice(ordinal.to_string().as_bytes());
    uuid::Uuid::from_bytes(uuid5(item_id, &n))
}

/// A field map as 01 §4 describes it. `id: None` omits the key (version 1 shape).
pub fn field_v(id: Option<[u8; 16]>, name: &str, kind: &str, value: &str, ma: u64) -> Value {
    let mut e = vec![("name", t(name)), ("kind", t(kind)), ("value", t(value)), ("modified_at", i(ma)), ("section", Value::Null)];
    if let Some(id) = id {
        e.push(("id", Value::Bytes(id.to_vec())));
    }
    map(e)
}
/// A minimal ItemPlain map (01 §4).
pub fn item_plain(title: &str, device: [u8; 16], fields: Vec<Value>) -> Value {
    map(vec![
        ("title", t(title)),
        ("deleted_at", Value::Null),
        ("device_id", Value::Bytes(device.to_vec())),
        ("favorite", Value::Bool(false)),
        ("tags", Value::Array(vec![])),
        ("fields", Value::Array(fields)),
        ("attachments", Value::Array(vec![])),
        ("history", Value::Array(vec![])),
    ])
}

/// Independent writer: seals items and the manifest with the spec AADs under `vault_key`, for the
/// given header (kept byte-for-byte; the digest is recomputed from it when it is stamped).
pub fn build_file(version: u16, header: &Value, vault_key: &[u8], items: &[([u8; 16], u64, Value)]) -> Vec<u8> {
    use rand::RngCore;
    let vault_id = bytes_of(get(header, "vault_id").unwrap());
    let item_key = indep::hkdf(vault_key, &vault_id, "vault/item/v1");
    let manifest_key = indep::hkdf(vault_key, &vault_id, "vault/manifest/v1");
    let mut body = vec![];
    let mut pairs: Vec<([u8; 16], u64)> = vec![];
    for (id, ma, pt) in items {
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = indep::seal(&item_key, &nonce, &enc(&canon(pt.clone())), &indep::item_aad(&vault_id, id, *ma, version));
        body.push(canon(map(vec![
            ("t", t("item")),
            ("id", Value::Bytes(id.to_vec())),
            ("modified_at", i(*ma)),
            ("nonce", Value::Bytes(nonce.to_vec())),
            ("ct", Value::Bytes(ct)),
        ])));
        pairs.push((*id, *ma));
    }
    pairs.sort();
    let man = Value::Array(pairs.iter().map(|(id, ma)| Value::Array(vec![Value::Bytes(id.to_vec()), i(*ma)])).collect());
    let digest = indep::header_digest(header);
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = indep::seal(&manifest_key, &nonce, &enc(&man), &indep::manifest_aad(&vault_id, items.len() as u32, version, digest.as_deref()));
    body.push(canon(map(vec![("t", t("manifest")), ("nonce", Value::Bytes(nonce.to_vec())), ("ct", Value::Bytes(ct))])));
    join(version, header, &body)
}

/// Starting points for hand-built files: (version, header, vault_key) of an empty file.
/// v1: the committed unstamped `v1-empty.vault`; v2: a fresh core-made vault (stamped).
pub fn empty_base(version: u16) -> (u16, Value, Vec<u8>) {
    let b = if version == 1 {
        fixture("v1-empty.vault")
    } else {
        vault_core::UnlockedVault::create(&pw(FIXTURE_PW), vault_core::KdfParams::for_tests(), uuid::Uuid::new_v4()).serialize()
    };
    let raw = split(&b);
    assert_eq!(raw.version, version);
    let o = indep::open_file(&b, FIXTURE_PW);
    (raw.version, raw.header, o.vault_key)
}

pub fn version_of(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[4], bytes[5]])
}
