//! Bug hunt 2026-11-27: format version 3 (01 §4 "Version 3", §9), written from the spec text
//! before reading the source. Complements `binding_v3.rs` (added by the builders with the
//! feature) with an independent writer that can put unknown keys on records, duplicate map keys,
//! a full tamper map on both unlock paths, downgrade relabels and v3 corruption sweeps.
use spec_checks::*;
use uuid::Uuid;
use vault_core::*;

const FPW: &str = FIXTURE_PW;

fn unlock_pw(b: &[u8]) -> Result<UnlockedVault, VaultError> {
    LockedVault::parse(b).and_then(|l| l.unlock(&pw(FPW)))
}
fn unlock_key(b: &[u8], v: &UnlockedVault) -> Result<UnlockedVault, VaultError> {
    LockedVault::parse(b).and_then(|l| l.unlock_with_key(&v.export_vault_key(), v.device_id()))
}

/// A core-made current-version vault with `n` login items (and optionally an enclave slot).
fn core_vault(n: usize, enclave: bool) -> (UnlockedVault, Vec<Uuid>) {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(FPW), KdfParams::for_tests(), dev);
    let mut ids = vec![];
    for k in 0..n {
        let mut it = Item::new(format!("Item {k}"), dev, 1_000 + k as u64);
        it.fields.push(Field::new(
            "password",
            FieldKind::Password,
            pw(&format!("pw-{k}")),
            1_000 + k as u64,
        ));
        ids.push(v.insert(it, 1_000 + k as u64));
    }
    if enclave {
        v.add_enclave_slot(&secrecy::SecretVec::new(vec![7u8; 32]), 5_000);
    }
    (v, ids)
}

/// One record for the independent writer: (id, modified_at, ItemPlain, record-level unknown keys).
#[derive(Clone)]
struct Rec {
    id: Vec<u8>,
    ma: u64,
    plain: Value,
    extras: Vec<(Value, Value)>,
}

/// Independent v1/v2/v3 writer per 01 §4: item records sealed with the item AAD, manifest
/// entries `[id, ma]` or (v3, record has unknown keys) `[id, ma, extras_digest]`, manifest AAD
/// with the version-dependent header digest and (v3) the manifest record's own extras digest.
/// `entries` lets a check override the manifest plaintext.
fn seal_file(
    version: u16,
    header: &Value,
    vault_key: &[u8],
    recs: &[Rec],
    manifest_extras: &[(Value, Value)],
    entries: Option<Value>,
) -> Vec<u8> {
    use rand::RngCore;
    let vault_id = bytes_of(get(header, "vault_id").unwrap());
    let item_key = indep::hkdf(vault_key, &vault_id, "vault/item/v1");
    let manifest_key = indep::hkdf(vault_key, &vault_id, "vault/manifest/v1");
    let mut body = vec![];
    for r in recs {
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = indep::seal(
            &item_key,
            &nonce,
            &enc(&canon(r.plain.clone())),
            &indep::item_aad(&vault_id, &r.id, r.ma, version),
        );
        let mut m = vec![
            (t("t"), t("item")),
            (t("id"), Value::Bytes(r.id.clone())),
            (t("modified_at"), i(r.ma)),
            (t("nonce"), Value::Bytes(nonce.to_vec())),
            (t("ct"), Value::Bytes(ct)),
        ];
        m.extend(r.extras.iter().cloned());
        body.push(canon(Value::Map(m)));
    }
    let man = entries.unwrap_or_else(|| {
        let mut sorted = recs.to_vec();
        sorted.sort_by(|a, b| a.id.cmp(&b.id));
        Value::Array(
            sorted
                .iter()
                .map(|r| {
                    let mut e = vec![Value::Bytes(r.id.clone()), i(r.ma)];
                    if version >= 3 && !r.extras.is_empty() {
                        e.push(Value::Bytes(indep::extras_digest(&r.extras)));
                    }
                    Value::Array(e)
                })
                .collect(),
        )
    });
    let digest = indep::header_digest(version, header);
    let rd = (version >= 3).then(|| indep::extras_digest(manifest_extras));
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = indep::seal(
        &manifest_key,
        &nonce,
        &enc(&man),
        &indep::manifest_aad(
            &vault_id,
            recs.len() as u32,
            version,
            digest.as_deref(),
            rd.as_deref(),
        ),
    );
    let mut m = vec![
        (t("t"), t("manifest")),
        (t("nonce"), Value::Bytes(nonce.to_vec())),
        (t("ct"), Value::Bytes(ct)),
    ];
    m.extend(manifest_extras.iter().cloned());
    body.push(canon(Value::Map(m)));
    join(version, &canon(header.clone()), &body)
}

/// Opens a core-made file independently and returns (header, vault_key, records without extras).
fn decompose(b: &[u8]) -> (u16, Value, Vec<u8>, Vec<Rec>) {
    let raw = split(b);
    let o = indep::open_file(b, FPW);
    let recs = o
        .items
        .iter()
        .map(|(id, ma, plain)| Rec {
            id: id.clone(),
            ma: *ma,
            plain: plain.clone(),
            extras: vec![],
        })
        .collect();
    (raw.version, raw.header, o.vault_key, recs)
}

fn kind(r: &Result<UnlockedVault, VaultError>) -> String {
    match r {
        Ok(_) => "Ok".into(),
        Err(VaultError::Tampered(TamperKind::Item(id))) => format!("Tampered(Item({id}))"),
        Err(VaultError::Malformed(_)) => "Malformed".into(),
        Err(e) => format!("{e:?}"),
    }
}

/// 01 §4 v3: "for a canonical file this equals the bytes at offsets 10..10+header_len": the
/// manifest of a core-made file opens with SHA-256 over the raw header bytes, and the header bytes
/// are canonical (01 "All CBOR is canonical").
#[test]
fn v3a_header_digest_is_sha256_of_header_bytes() {
    use sha2::Digest;
    let (v, _) = core_vault(2, true);
    let b = v.serialize();
    assert_eq!(version_of(&b), 3);
    let raw = split(&b);
    assert!(is_canonical(&raw.header), "header is canonical CBOR");
    assert_eq!(
        enc(&raw.header),
        raw.header_bytes,
        "header bytes re-encode identically"
    );
    let o = indep::open_file(&b, FPW);
    let m = raw.body.last().unwrap();
    let aad = indep::manifest_aad(
        &o.vault_id,
        (raw.body.len() - 1) as u32,
        3,
        Some(&sha2::Sha256::digest(&raw.header_bytes)),
        Some(&indep::extras_digest(&[])),
    );
    assert!(
        indep::open(
            &o.manifest_key,
            &bytes_of(get(m, "nonce").unwrap()),
            &bytes_of(get(m, "ct").unwrap()),
            &aad
        )
        .is_some(),
        "manifest opens with SHA-256(bytes 10..10+header_len)"
    );
}

/// 01 §4 v3 tamper map, password path: every header edit that leaves the password slot
/// unwrappable must be `Tampered(Manifest)` ("`created_at`, any header key, kdf, slots, stamp,
/// manifest-record key → Tampered(Manifest)"); a KDF edit is WrongPassword on this path (01 §2).
/// Key path: every one of them, KDF included, is `Tampered(Manifest)`.
#[test]
fn v3b_tamper_map_both_paths() {
    let (v, _) = core_vault(2, true);
    let b = v.serialize();
    let raw = split(&b);
    let edit = |f: &dyn Fn(&mut Value)| {
        let mut h = raw.header.clone();
        f(&mut h);
        join(3, &canon(h), &raw.body)
    };
    let slots_edit = |f: &dyn Fn(&mut Vec<Value>)| {
        edit(&|h: &mut Value| {
            if let Some(Value::Array(s)) = get_mut(h, "slots") {
                f(s)
            }
        })
    };
    let pw_slot = |s: &mut Vec<Value>| -> usize {
        s.iter()
            .position(|x| get(x, "kind").unwrap().as_text() == Some("password"))
            .unwrap()
    };
    let opaque = canon(map(vec![
        ("id", Value::Bytes(Uuid::new_v4().as_bytes().to_vec())),
        ("kind", t("future-kind")),
        ("blob", Value::Bytes(vec![1, 2, 3])),
    ]));
    let ca = u64_of(get(&raw.header, "created_at").unwrap());
    let sma = u64_of(get(&raw.header, "slots_modified_at").unwrap());
    let cases: Vec<(&str, Vec<u8>, bool)> = vec![
        // (label, file, password path expected to reach the manifest)
        (
            "created_at+1",
            edit(&|h| set(h, "created_at", i(ca + 1))),
            true,
        ),
        (
            "slots_modified_at+1",
            edit(&|h| set(h, "slots_modified_at", i(sma + 1))),
            true,
        ),
        (
            "slots_modified_at removed",
            edit(&|h| {
                if let Value::Map(e) = h {
                    e.retain(|(k, _)| k.as_text() != Some("slots_modified_at"))
                }
            }),
            true,
        ),
        (
            "slots_device_id changed",
            edit(&|h| set(h, "slots_device_id", Value::Bytes(vec![9; 16]))),
            true,
        ),
        ("header text extra", edit(&|h| set(h, "zz", t("x"))), true),
        (
            "header integer-key extra",
            edit(&|h| {
                if let Value::Map(e) = h {
                    e.push((Value::Integer(7.into()), t("x")))
                }
            }),
            true,
        ),
        (
            "kdf extra",
            edit(&|h| set(get_mut(h, "kdf").unwrap(), "zz", i(1))),
            true,
        ),
        (
            "password slot extra",
            slots_edit(&|s| {
                let k = pw_slot(s);
                set(&mut s[k], "zz", i(1))
            }),
            true,
        ),
        (
            "password slot created_at+1",
            slots_edit(&|s| {
                let k = pw_slot(s);
                let c = u64_of(get(&s[k], "created_at").unwrap());
                set(&mut s[k], "created_at", i(c + 1))
            }),
            true,
        ),
        (
            "enclave slot created_at+1",
            slots_edit(&|s| {
                let k = s
                    .iter()
                    .position(|x| get(x, "kind").unwrap().as_text() == Some("enclave"))
                    .unwrap();
                let c = u64_of(get(&s[k], "created_at").unwrap());
                set(&mut s[k], "created_at", i(c + 1))
            }),
            true,
        ),
        (
            "enclave slot removed",
            slots_edit(&|s| s.retain(|x| get(x, "kind").unwrap().as_text() != Some("enclave"))),
            true,
        ),
        ("slots reordered", slots_edit(&|s| s.reverse()), true),
        (
            "opaque slot appended",
            slots_edit(&|s| s.push(opaque.clone())),
            true,
        ),
        (
            "kdf m_cost+8 (in range)",
            edit(&|h| {
                let k = get_mut(h, "kdf").unwrap();
                let m = u64_of(get(k, "m_cost").unwrap());
                set(k, "m_cost", i(m + 8))
            }),
            false,
        ),
        (
            "kdf salt changed",
            edit(&|h| {
                set(
                    get_mut(h, "kdf").unwrap(),
                    "salt",
                    Value::Bytes(vec![3; 32]),
                )
            }),
            false,
        ),
    ];
    let mut bad = vec![];
    for (label, f, reaches) in &cases {
        let rp = unlock_pw(f);
        let rk = unlock_key(f, &v);
        let want_pw = if *reaches {
            "Tampered(Manifest)"
        } else {
            "WrongPassword"
        };
        if kind(&rp) != want_pw {
            bad.push(format!(
                "{label}: password path {} (want {want_pw})",
                kind(&rp)
            ));
        }
        if kind(&rk) != "Tampered(Manifest)" {
            bad.push(format!(
                "{label}: key path {} (want Tampered(Manifest))",
                kind(&rk)
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 01 "All CBOR is canonical"; 01 §4 v3 "Every plaintext byte of a v3 file is thereby bound except
/// the encoding form and the record order, both content-neutral". A header map with a duplicated
/// key is not a canonical encoding of any map; whatever the reader does with it, it must not open
/// with a header value that differs from the authenticated one.
#[test]
fn v3c_duplicate_header_keys_never_change_authenticated_values() {
    let (v, _) = core_vault(1, false);
    let b = v.serialize();
    let raw = split(&b);
    let ca = u64_of(get(&raw.header, "created_at").unwrap());
    let dup = |k: &str, val: Value, first: bool| {
        let mut h = raw.header.clone();
        if let Value::Map(e) = &mut h {
            let entry = (t(k), val);
            if first {
                e.insert(0, entry)
            } else {
                e.push(entry)
            }
        }
        // not canonicalised: keep the duplicate
        join(3, &h, &raw.body)
    };
    let mut bad = vec![];
    let mut info = vec![];
    for first in [true, false] {
        let f = dup("created_at", i(ca + 12345), first);
        for (path, r) in [("password", unlock_pw(&f)), ("key", unlock_key(&f, &v))] {
            info.push(format!(
                "dup created_at (first={first}) {path}: {}",
                kind(&r)
            ));
            if let Ok(u) = r {
                let seen = format!("{:?}", u.header());
                if !seen.contains(&ca.to_string()) || seen.contains(&(ca + 12345).to_string()) {
                    bad.push(format!(
                        "dup created_at (first={first}) {path} path: opened with the injected value"
                    ));
                }
                let out = u.serialize();
                let oh = split(&out).header;
                if u64_of(get(&oh, "created_at").unwrap()) != ca {
                    bad.push(format!(
                        "dup created_at (first={first}) {path} path: re-saved with created_at {}",
                        u64_of(get(&oh, "created_at").unwrap())
                    ));
                }
            }
        }
        let kdf = get(&raw.header, "kdf").unwrap().clone();
        let mut k2 = kdf.clone();
        set(&mut k2, "salt", Value::Bytes(vec![5; 32]));
        let f = dup("kdf", k2, first);
        let r = unlock_key(&f, &v);
        info.push(format!("dup kdf (first={first}) key: {}", kind(&r)));
        if let Ok(u) = r {
            let out = split(&u.serialize()).header;
            if get(&out, "kdf") != Some(&kdf) {
                bad.push(format!(
                    "dup kdf (first={first}): key path opened and re-saved a forged kdf"
                ));
            }
        }
    }
    eprintln!("INFO {}", info.join("; "));
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 01 §4 v3: "relabelled 2 or 1 opens nothing on either path ... both report `WrongPassword`";
/// "relabelled above `FORMAT_VERSION` it is `UnsupportedVersion`". Also for an empty vault.
#[test]
fn v3d_relabels() {
    let mut bad = vec![];
    for n in [0usize, 2] {
        let (v, _) = core_vault(n, false);
        let b = v.serialize();
        for to in [1u16, 2] {
            let mut f = b.clone();
            f[4..6].copy_from_slice(&to.to_be_bytes());
            for (path, r) in [("password", unlock_pw(&f)), ("key", unlock_key(&f, &v))] {
                if !matches!(r, Err(VaultError::WrongPassword)) {
                    bad.push(format!("{n} items, v3→{to}, {path} path: {}", kind(&r)));
                }
            }
        }
        for to in [4u16, 0xFFFF] {
            let mut f = b.clone();
            f[4..6].copy_from_slice(&to.to_be_bytes());
            let r = LockedVault::parse(&f);
            if !matches!(r, Err(VaultError::UnsupportedVersion(x)) if x == to) {
                bad.push(format!("{n} items, v3→{to}: parse {:?}", r.err()));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 01 §4 v3: record-level unknown keys. A file written by a newer writer with an unknown key on
/// an item record (entry carries its `extras_digest`) and on the manifest record opens; 01 §9
/// "writers preserve unknown keys they read", so the re-save keeps them and binds them; removing,
/// changing or moving the key is `Tampered(Item(id))`, "first in id order"; a stale entry digest
/// is the same; the manifest-record key is `Tampered(Manifest)`.
#[test]
fn v3e_record_extras_written_by_a_newer_writer() {
    let (v, _) = core_vault(3, false);
    let (ver, header, key, mut recs) = decompose(&v.serialize());
    assert_eq!(ver, 3);
    recs.sort_by(|a, b| a.id.cmp(&b.id));
    let x = vec![(t("zz_future"), t("keep me"))];
    recs[1].extras = x.clone();
    let mx = vec![(t("zz_manifest"), i(42))];
    let good = seal_file(3, &header, &key, &recs, &mx, None);
    let o = indep::try_open_file(&good, FPW);
    assert!(o.is_ok(), "independent writer self-check: {:?}", o.err());
    let mut bad = vec![];
    match unlock_pw(&good) {
        Err(e) => bad.push(format!(
            "a v3 file with record unknown keys does not open: {e:?}"
        )),
        Ok(u) => {
            let out = u.serialize();
            let raw = split(&out);
            let rec = raw
                .body
                .iter()
                .find(|r| get(r, "id").map(bytes_of) == Some(recs[1].id.clone()));
            if rec.and_then(|r| get(r, "zz_future")) != Some(&t("keep me")) {
                bad.push("01 §9: the item-record unknown key is not preserved on save".into());
            }
            if get(raw.body.last().unwrap(), "zz_manifest") != Some(&i(42)) {
                bad.push("01 §9: the manifest-record unknown key is not preserved on save".into());
            }
            if let Err(e) = indep::try_open_file(&out, FPW) {
                bad.push(format!("re-saved file fails the spec binding: {e}"));
            }
            // and a merge with itself keeps them too
            let mut u2 = unlock_pw(&out).unwrap();
            let peer = unlock_pw(&out).unwrap();
            u2.merge_from(&peer).unwrap();
            let raw2 = split(&u2.serialize());
            if !raw2.body.iter().any(|r| get(r, "zz_future").is_some()) {
                bad.push("self-merge drops the item-record unknown key".into());
            }
        }
    }
    let id1 = Uuid::from_slice(&recs[1].id).unwrap();
    let id0 = Uuid::from_slice(&recs[0].id).unwrap();
    let raw = split(&good);
    let body_edit = |f: &dyn Fn(&mut Vec<Value>)| {
        let mut body = raw.body.clone();
        f(&mut body);
        join(
            3,
            &raw.header,
            &body.into_iter().map(canon).collect::<Vec<_>>(),
        )
    };
    let pos = |body: &Vec<Value>, id: &[u8]| {
        body.iter()
            .position(|r| get(r, "id").map(bytes_of).as_deref() == Some(id))
            .unwrap()
    };
    let r1 = recs[1].id.clone();
    let r0 = recs[0].id.clone();
    let r2 = recs[2].id.clone();
    let cases: Vec<(&str, Vec<u8>, String)> = vec![
        (
            "removed",
            body_edit(&|b| {
                let k = pos(b, &r1);
                if let Value::Map(e) = &mut b[k] {
                    e.retain(|(k, _)| k.as_text() != Some("zz_future"))
                }
            }),
            format!("Tampered(Item({id1}))"),
        ),
        (
            "changed",
            body_edit(&|b| {
                let k = pos(b, &r1);
                set(&mut b[k], "zz_future", t("evil"))
            }),
            format!("Tampered(Item({id1}))"),
        ),
        (
            "added to a record without",
            body_edit(&|b| {
                let k = pos(b, &r2);
                set(&mut b[k], "zz_future", t("x"))
            }),
            format!("Tampered(Item({}))", Uuid::from_slice(&r2).unwrap()),
        ),
        (
            "moved to the first record",
            body_edit(&|b| {
                let k = pos(b, &r1);
                if let Value::Map(e) = &mut b[k] {
                    e.retain(|(k, _)| k.as_text() != Some("zz_future"))
                }
                let k = pos(b, &r0);
                set(&mut b[k], "zz_future", t("keep me"))
            }),
            format!("Tampered(Item({id0}))"),
        ),
        (
            "manifest key changed",
            body_edit(&|b| {
                let n = b.len() - 1;
                set(&mut b[n], "zz_manifest", i(43))
            }),
            "Tampered(Manifest)".into(),
        ),
        (
            "manifest key removed",
            body_edit(&|b| {
                let n = b.len() - 1;
                if let Value::Map(e) = &mut b[n] {
                    e.retain(|(k, _)| k.as_text() != Some("zz_manifest"))
                }
            }),
            "Tampered(Manifest)".into(),
        ),
    ];
    for (label, f, want) in &cases {
        for (path, r) in [("password", unlock_pw(f)), ("key", unlock_key(f, &v))] {
            if &kind(&r) != want {
                bad.push(format!("{label}: {path} path {} (want {want})", kind(&r)));
            }
        }
    }
    // A wrong entry digest written under the key (stale digest): Tampered(Item) too.
    let mut stale = recs.clone();
    stale[1].extras = vec![(t("zz_future"), t("other"))];
    let mut entries = recs.clone();
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    let man = Value::Array(
        entries
            .iter()
            .map(|r| {
                let mut e = vec![Value::Bytes(r.id.clone()), i(r.ma)];
                if !r.extras.is_empty() {
                    e.push(Value::Bytes(indep::extras_digest(&r.extras)));
                }
                Value::Array(e)
            })
            .collect(),
    );
    let f = seal_file(3, &header, &key, &stale, &mx, Some(man));
    let r = unlock_pw(&f);
    if kind(&r) != format!("Tampered(Item({id1}))") {
        bad.push(format!("stale entry digest: {}", kind(&r)));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 01 §4: "a three-element entry in a version 1 or 2 file is `Malformed`"; a v3 entry must be two
/// or three elements (a 4-element or a non-bytes digest is not a valid entry: never Ok).
#[test]
fn v3f_entry_shapes() {
    let mut bad = vec![];
    // version 2 file with a 3-element entry, sealed under the right key
    let (ver, header, key) = empty_base(2);
    let dev = [4u8; 16];
    let plain = item_plain("T", dev, vec![field_v(Some([1; 16]), "n", "text", "v", 5)]);
    let rec = Rec {
        id: Uuid::new_v4().as_bytes().to_vec(),
        ma: 5,
        plain,
        extras: vec![],
    };
    let man = Value::Array(vec![Value::Array(vec![
        Value::Bytes(rec.id.clone()),
        i(5),
        Value::Bytes(indep::extras_digest(&[])),
    ])]);
    let f = seal_file(
        ver,
        &header,
        &key,
        std::slice::from_ref(&rec),
        &[],
        Some(man),
    );
    let r = unlock_pw(&f);
    if kind(&r) != "Malformed" {
        bad.push(format!(
            "v2 three-element entry: {} (want Malformed)",
            kind(&r)
        ));
    }
    // the same file with two-element entries opens (writer self-check)
    let ok = seal_file(ver, &header, &key, std::slice::from_ref(&rec), &[], None);
    if let Err(e) = unlock_pw(&ok) {
        bad.push(format!("v2 control file does not open: {e:?}"));
    }
    // v3 shapes
    let (v, _) = core_vault(1, false);
    let (_, h3, k3, recs) = decompose(&v.serialize());
    let id = recs[0].id.clone();
    for (label, e) in [
        (
            "four elements",
            vec![
                Value::Bytes(id.clone()),
                i(recs[0].ma),
                Value::Bytes(vec![0; 32]),
                i(1),
            ],
        ),
        (
            "digest as text",
            vec![Value::Bytes(id.clone()), i(recs[0].ma), t("x")],
        ),
        (
            "digest 31 bytes",
            vec![
                Value::Bytes(id.clone()),
                i(recs[0].ma),
                Value::Bytes(vec![0; 31]),
            ],
        ),
        (
            "digest of empty map on a record without keys",
            vec![
                Value::Bytes(id.clone()),
                i(recs[0].ma),
                Value::Bytes(indep::extras_digest(&[])),
            ],
        ),
        ("one element", vec![Value::Bytes(id.clone())]),
    ] {
        let f = seal_file(
            3,
            &h3,
            &k3,
            &recs,
            &[],
            Some(Value::Array(vec![Value::Array(e)])),
        );
        let r = unlock_pw(&f);
        if r.is_ok() {
            bad.push(format!("v3 {label}: opened"));
        }
        eprintln!("INFO v3 entry {label}: {}", kind(&r));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 01 §4 v3: "records are compared as a sorted set": item records in any order open with the same
/// content; the manifest stays last (01 §1).
#[test]
fn v3g_record_order_is_neutral() {
    let (v, _) = core_vault(4, false);
    let b = v.serialize();
    let raw = split(&b);
    let n = raw.body.len();
    let mut body = raw.body.clone();
    body[..n - 1].reverse();
    let f = join(3, &raw.header, &body);
    match unlock_pw(&f) {
        Ok(u) => assert_eq!(snap_vault(&u), snap_vault(&v)),
        Err(e) => panic!("reordered item records: {e:?}"),
    }
}

/// 01 §4 v3 "Every plaintext byte of a v3 file is thereby bound except the encoding form and the
/// record order": one bit flipped at every bit of a v3 file (key path: all bits; password path:
/// one bit per header byte) never opens with content or header different from the original, and
/// never panics.
#[test]
fn v3h_bit_flip_sweep() {
    let (v, _) = core_vault(2, true);
    let b = v.serialize();
    let want_items = snap_vault(&v);
    let want_header = format!("{:?}", unlock_pw(&b).unwrap().header());
    let hend = 10 + split(&b).header_len as usize;
    let key = v.export_vault_key();
    let dev = v.device_id();
    let mut bad = vec![];
    let mut oks = 0;
    for pos in 0..b.len() {
        for bit in 0..8 {
            let mut f = b.clone();
            f[pos] ^= 1 << bit;
            let r = std::panic::catch_unwind(|| {
                LockedVault::parse(&f).and_then(|l| l.unlock_with_key(&key, dev))
            });
            match r {
                Err(_) => bad.push(format!("panic at byte {pos} bit {bit} (key path)")),
                Ok(Ok(u)) => {
                    oks += 1;
                    if snap_vault(&u) != want_items || format!("{:?}", u.header()) != want_header {
                        bad.push(format!(
                            "byte {pos} bit {bit}: key path opened different content"
                        ));
                    }
                }
                Ok(Err(_)) => {}
            }
        }
    }
    for pos in 0..hend {
        let mut f = b.clone();
        f[pos] ^= 1 << (pos % 8);
        let r = std::panic::catch_unwind(|| unlock_pw(&f));
        match r {
            Err(_) => bad.push(format!("panic at byte {pos} (password path)")),
            Ok(Ok(u)) => {
                oks += 1;
                if snap_vault(&u) != want_items || format!("{:?}", u.header()) != want_header {
                    bad.push(format!(
                        "byte {pos}: password path opened different content"
                    ));
                }
            }
            Ok(Err(_)) => {}
        }
    }
    eprintln!("INFO v3 flips that still opened (content identical): {oks}");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 01 §1 / §4: every proper prefix of a v3 file (fixture with metadata and a fresh file with an
/// enclave slot) is an error, never Ok, never a panic.
#[test]
fn v3i_every_cut() {
    let (v, _) = core_vault(2, true);
    let mut bad = vec![];
    for (label, b) in [
        ("fresh", v.serialize()),
        ("v3-meta", fixture("v3-meta.vault")),
        ("v3-basic", fixture("v3-basic.vault")),
    ] {
        for cut in 0..b.len() {
            let f = b[..cut].to_vec();
            let r = std::panic::catch_unwind(|| unlock_pw(&f));
            match r {
                Err(_) => bad.push(format!("{label}: panic at cut {cut}")),
                Ok(Ok(_)) => bad.push(format!("{label}: cut {cut} opened")),
                Ok(Err(_)) => {}
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad[..bad.len().min(20)].join("\n"));
}

/// 02 `upgrade_format`: "no-op when current"; 01 §9: `upgrade_format` "moves a file to 3 and, as
/// for 2, drops enclave, recovery and opaque slots". On a v3 vault: slots, header and items stay.
/// On a v2 file built for this vault with an enclave and an opaque slot: version 3, password slot
/// only, items intact, header stamped.
#[test]
fn v3j_upgrade_noop_when_current_and_from_v2() {
    let (mut v, _) = core_vault(2, true);
    let before = split(&v.serialize()).header;
    v.upgrade_format(&pw(FPW), 9_000).unwrap();
    let after = split(&v.serialize()).header;
    assert_eq!(
        get(&after, "slots"),
        get(&before, "slots"),
        "upgrade on v3 kept the slots"
    );
    assert_eq!(
        get(&after, "slots_modified_at"),
        get(&before, "slots_modified_at"),
        "upgrade on v3 is a no-op: no restamp"
    );
    // v2 with an enclave slot and an opaque slot
    let (_, mut h2, key) = empty_base(2);
    if let Some(Value::Array(s)) = get_mut(&mut h2, "slots") {
        s.push(canon(map(vec![
            ("id", Value::Bytes(Uuid::new_v4().as_bytes().to_vec())),
            ("kind", t("future-kind")),
            ("x", i(1)),
        ])));
    }
    let dev = [3u8; 16];
    let plain = item_plain(
        "Kept",
        dev,
        vec![field_v(Some([2; 16]), "n", "text", "v", 5)],
    );
    let rec = Rec {
        id: Uuid::new_v4().as_bytes().to_vec(),
        ma: 5,
        plain,
        extras: vec![],
    };
    let f = seal_file(2, &h2, &key, &[rec], &[], None);
    let mut u = unlock_pw(&f).expect("hand-built v2 opens");
    u.upgrade_format(&pw(FPW), 10_000).unwrap();
    let out = u.serialize();
    assert_eq!(version_of(&out), 3);
    let kinds: Vec<String> = match get(&split(&out).header, "slots") {
        Some(Value::Array(s)) => s
            .iter()
            .map(|x| get(x, "kind").unwrap().as_text().unwrap().to_string())
            .collect(),
        _ => vec![],
    };
    assert_eq!(
        kinds,
        vec!["password"],
        "opaque slot dropped by the upgrade to 3"
    );
    let u2 = unlock_pw(&out).unwrap();
    assert_eq!(u2.items().count(), 1);
    assert!(indep::try_open_file(&out, FPW).is_ok());
}

/// 01 §2 KDF range: "The parser rejects anything outside as `Malformed` before any Argon2 run",
/// on a version 3 file too (time-bounded).
#[test]
fn v3k_hostile_kdf_in_v3_header_rejected_before_argon2() {
    let (v, _) = core_vault(1, false);
    let b = v.serialize();
    let raw = split(&b);
    let mut bad = vec![];
    for (k, val) in [
        ("m_cost", 1_048_577u64),
        ("m_cost", 0),
        ("t_cost", 17),
        ("t_cost", u32::MAX as u64),
        ("p_cost", 65),
        ("p_cost", 0),
        ("m_cost", u64::MAX),
    ] {
        let mut h = raw.header.clone();
        set(get_mut(&mut h, "kdf").unwrap(), k, i(val));
        let f = join(3, &canon(h), &raw.body);
        let r = with_timeout(10, move || match LockedVault::parse(&f) {
            Err(VaultError::Malformed(_)) => "Malformed".to_string(),
            Err(e) => format!("{e:?}"),
            Ok(l) => format!("parsed; unlock {:?}", l.unlock(&pw(FPW)).err()),
        });
        match r {
            Some(s) if s == "Malformed" => {}
            other => bad.push(format!("{k}={val}: {other:?}")),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
