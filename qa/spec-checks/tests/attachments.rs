//! Attachments (01 §4 "Attachments", 03 §1.1, 03 §8) and orphan cleanup.
use spec_checks::dev::*;
use spec_checks::*;
use std::io::Read;

fn hex(id: uuid::Uuid) -> String {
    id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

/// 01 §4: blob layout, chunking, AAD; 03 §1.1 path and mode 0600; round trip via open_attachment.
#[test]
fn a01_sizes_layout_and_independent_decrypt() {
    let d = tempdir();
    let pkg = d.path().join("at.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("host", now_ms());
    let mib = 1_048_576usize;
    for size in [0usize, 1, mib - 1, mib, mib + 1, 3 * mib - 5] {
        let data = pattern(size);
        let aid =
            a.s.add_attachment(item, "f.bin", &data[..], size as u64, now_ms())
                .unwrap();
        let path = pkg.join("attachments").join(format!("{}.bin", hex(aid)));
        assert!(path.exists(), "01 §4 blob path attachments/<32 hex>.bin");
        assert_eq!(mode(&path), 0o600, "03 §1.1 blob mode 0600");
        let chunks = if size == 0 { 1 } else { size.div_ceil(mib) };
        let blob = std::fs::read(&path).unwrap();
        assert_eq!(
            blob.len(),
            size + 16 * chunks,
            "size {size}: blob = sum(chunk+16)"
        );
        let r = a
            .v()
            .get(item)
            .unwrap()
            .attachments
            .iter()
            .find(|r| r.id == aid)
            .unwrap()
            .clone();
        assert_eq!(r.size, size as u64);
        assert_eq!(r.chunk_nonces.len(), chunks);
        // independent decrypt of every chunk with the spec AAD
        let vid = a.v().vault_id();
        let mut off = 0;
        let mut out = vec![];
        for i in 0..chunks {
            let pl = if i + 1 < chunks { mib } else { size - i * mib };
            let ct = &blob[off..off + pl + 16];
            off += pl + 16;
            let mut aad = vid.as_bytes().to_vec();
            aad.extend_from_slice(aid.as_bytes());
            aad.extend_from_slice(&(i as u32).to_be_bytes());
            aad.extend_from_slice(&(chunks as u32).to_be_bytes());
            aad.extend_from_slice(&1u16.to_be_bytes());
            out.extend(
                indep::open(&r.key[..], &r.chunk_nonces[i], ct, &aad).expect("chunk AAD per 01 §4"),
            );
        }
        assert_eq!(out, data);
        let mut rd = a.s.open_attachment(item, aid).unwrap();
        let mut got = vec![];
        rd.read_to_end(&mut got).unwrap();
        assert_eq!(got, data, "size {size} round trip");
        assert!(matches!(
            a.s.attachment_state(aid),
            vault_sync::AttachmentState::Present
        ));
    }
    a.s.save().unwrap();
    // keys are per attachment and random
    let keys: std::collections::HashSet<Vec<u8>> = a
        .v()
        .get(item)
        .unwrap()
        .attachments
        .iter()
        .map(|r| r.key[..].to_vec())
        .collect();
    assert_eq!(keys.len(), 6);
}

/// 01 §4: chunks cannot be swapped, reordered, truncated or moved between vaults; tampering detected.
#[test]
fn a02_blob_tamper() {
    let d = tempdir();
    let pkg = d.path().join("tb.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("host", now_ms());
    let mib = 1_048_576usize;
    let data = pattern(2 * mib + 10);
    let aid =
        a.s.add_attachment(item, "f", &data[..], data.len() as u64, now_ms())
            .unwrap();
    let path = pkg.join("attachments").join(format!("{}.bin", hex(aid)));
    let orig = std::fs::read(&path).unwrap();
    let read_all = |a: &Dev| -> Result<Vec<u8>, String> {
        let mut r =
            a.s.open_attachment(item, aid)
                .map_err(|e| format!("{e:?}"))?;
        let mut v = vec![];
        r.read_to_end(&mut v).map_err(|e| format!("{e}"))?;
        Ok(v)
    };
    let c = mib + 16;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("flip first byte", {
            let mut b = orig.clone();
            b[0] ^= 1;
            b
        }),
        ("flip last byte", {
            let mut b = orig.clone();
            let n = b.len();
            b[n - 1] ^= 1;
            b
        }),
        ("truncate last chunk", orig[..2 * c].to_vec()),
        ("truncate 1 byte", orig[..orig.len() - 1].to_vec()),
        ("extra byte", {
            let mut b = orig.clone();
            b.push(0);
            b
        }),
        ("extra chunk", {
            let mut b = orig.clone();
            b.extend_from_slice(&orig[..c]);
            b
        }),
        ("swap chunk 0 and 1", {
            let mut b = orig[c..2 * c].to_vec();
            b.extend_from_slice(&orig[..c]);
            b.extend_from_slice(&orig[2 * c..]);
            b
        }),
        ("empty", vec![]),
    ];
    for (name, bytes) in cases {
        std::fs::write(&path, &bytes).unwrap();
        let r = read_all(&a);
        assert!(
            r.is_err(),
            "{name}: tampered blob read succeeded ({} bytes)",
            r.map(|v| v.len()).unwrap_or(0)
        );
    }
    std::fs::remove_file(&path).unwrap();
    assert!(
        matches!(
            a.s.attachment_state(aid),
            vault_sync::AttachmentState::Missing
        ),
        "absent blob -> Missing"
    );
    assert!(a.s.open_attachment(item, aid).is_err());
    // the item stays usable
    assert!(a.v().get(item).is_some());
}

/// 01 §4 "Maximum size is 100 MB; larger files are refused before encryption"; declared size
/// must match the stream.
#[test]
fn a03_size_limits_and_mismatch() {
    let d = tempdir();
    let pkg = d.path().join("sz.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("host", now_ms());
    let t = std::time::Instant::now();
    let r = a.s.add_attachment(
        item,
        "big",
        std::io::repeat(0).take(100_000_001),
        100_000_001,
        now_ms(),
    );
    assert!(r.is_err(), "over 100 MB refused");
    assert!(t.elapsed().as_secs() < 3, "refused before encryption");
    let before = a.v().get(item).unwrap().attachments.len();
    let r = a.s.add_attachment(item, "short", &b"abc"[..], 10, now_ms());
    assert!(r.is_err(), "stream shorter than declared size");
    let r2 =
        a.s.add_attachment(item, "long", &b"abcdefghijkl"[..], 3, now_ms());
    // longer stream than declared: either refused or truncated to size; never a ref whose blob is unreadable
    if let Ok(aid) = r2 {
        let mut rd = a.s.open_attachment(item, aid).unwrap();
        let mut v = vec![];
        rd.read_to_end(&mut v).unwrap();
        assert_eq!(v.len(), 3);
    }
    let after = a.v().get(item).unwrap().attachments.len();
    assert!(after - before <= 1, "failed adds left refs behind");
    // no stray tmp files after failures
    let names = ls(&pkg.join("attachments"));
    assert!(
        !names.iter().any(|n| n.contains("tmp")),
        "tmp left: {names:?}"
    );
    // unknown item
    assert!(
        a.s.add_attachment(uuid::Uuid::new_v4(), "x", &b"a"[..], 1, now_ms())
            .is_err()
    );
}

/// 03 §1.1 orphan cleanup: unreferenced blob deleted only after the 24 h grace; referenced blobs
/// (incl. on tombstones) never; stale tmp files after 1 h.
#[test]
fn a04_orphan_cleanup() {
    let d = tempdir();
    let pkg = d.path().join("oc.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("host", now_ms());
    let keep =
        a.s.add_attachment(item, "keep", &b"k"[..], 1, now_ms())
            .unwrap();
    let gone =
        a.s.add_attachment(item, "gone", &b"g"[..], 1, now_ms())
            .unwrap();
    let item2 = a.add_login("tomb", now_ms());
    let tomb =
        a.s.add_attachment(item2, "t", &b"t"[..], 1, now_ms())
            .unwrap();
    a.s.save().unwrap();
    a.s.remove_attachment(item, gone, now_ms()).unwrap();
    a.s.edit(|v| v.delete(item2, now_ms())).unwrap().unwrap();
    // a foreign/orphan blob that arrived from a peer + a stale tmp
    let stray = uuid::Uuid::new_v4();
    let att = pkg.join("attachments");
    std::fs::write(att.join(format!("{}.bin", hex(stray))), b"peer blob").unwrap();
    std::fs::write(att.join(".tmp-deadbeef"), b"x").unwrap();
    a.s.save().unwrap();
    let p = |id| att.join(format!("{}.bin", hex(id)));
    assert!(p(gone).exists(), "within 24 h grace the orphan stays");
    assert!(p(stray).exists());
    a.s.set_prune_clock_offset_for_tests(std::time::Duration::from_secs(25 * 3600));
    a.add_login("trigger", now_ms());
    a.s.save().unwrap();
    assert!(!p(gone).exists(), "orphan deleted after 24 h");
    assert!(
        !p(stray).exists(),
        "unreferenced peer blob deleted after 24 h"
    );
    assert!(p(keep).exists(), "referenced blob kept");
    assert!(p(tomb).exists(), "blob referenced by a tombstone kept");
}

/// 03 §6 step 4: whole-package conflict copy -> copy blobs we lack (never replacing), then move.
#[test]
fn a05_conflict_package_brings_blobs() {
    let d = tempdir();
    let pkg = d.path().join("cb.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("host", now_ms());
    a.s.save().unwrap();
    let st = tempdir();
    let staging = st.path().join("staging.vault");
    copy_dir(&pkg, &staging);
    let mut c = Dev::open(&staging);
    let aid =
        c.s.add_attachment(item, "from-copy", &b"conflict data"[..], 13, now_ms())
            .unwrap();
    c.s.save().unwrap();
    drop(c);
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    std::fs::rename(&staging, d.path().join("cb 2.vault")).unwrap();
    let got = a.wait_for(10, |e| e.iter().any(|x| x.starts_with("ConflictAbsorbed")));
    assert!(got, "{:?}", a.seen);
    let mut rd =
        a.s.open_attachment(item, aid)
            .expect("blob copied from conflict package");
    let mut v = vec![];
    rd.read_to_end(&mut v).unwrap();
    assert_eq!(v, b"conflict data");
}

/// 03 §6 step 2: a conflict copy arriving while locked is deferred and absorbed at next unlock.
#[test]
fn a06_conflict_while_locked_deferred() {
    let d = tempdir();
    let pkg = d.path().join("dl.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("base", now_ms());
    a.s.save().unwrap();
    let st = tempdir();
    let staging = st.path().join("staging.vault");
    copy_dir(&pkg, &staging);
    let mut c = Dev::open(&staging);
    let cid = c.add_login("from-conflict", now_ms());
    c.s.save().unwrap();
    drop(c);
    a.s.start_watching().unwrap();
    let _ = a.s.lock();
    std::thread::sleep(std::time::Duration::from_millis(700));
    std::fs::copy(staging.join("vault.bin"), pkg.join("vault 2.bin")).unwrap();
    a.wait_for(3, |_| false);
    assert!(pkg.join("vault 2.bin").exists(), "not touched while locked");
    a.s.unlock(&pw(PW)).unwrap();
    a.wait_for(5, |e| e.iter().any(|x| x.starts_with("ConflictAbsorbed")));
    assert!(
        a.v().get(cid).is_some(),
        "absorbed at next unlock; events {:?}",
        a.seen
    );
    assert!(!pkg.join("vault 2.bin").exists());
}

/// 03 §6 "Never delete a conflict copy": a same-id copy that our key cannot open (rotated elsewhere)
/// or that is corrupt stays on disk (in place or in backups).
#[test]
fn a07_unopenable_conflict_copy_never_deleted() {
    let d = tempdir();
    let pkg = d.path().join("nd.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("base", now_ms());
    a.s.save().unwrap();
    let st = tempdir();
    let staging = st.path().join("staging.vault");
    copy_dir(&pkg, &staging);
    let mut c = Dev::open(&staging);
    c.s.edit(|v| v.rotate_vault_key(&pw(PW), now_ms()))
        .unwrap()
        .unwrap();
    c.s.save().unwrap();
    drop(c);
    let good = std::fs::read(staging.join("vault.bin")).unwrap();
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    std::fs::write(pkg.join("vault 2.bin"), &good).unwrap();
    std::fs::write(pkg.join("vault 3.bin"), &good[..good.len() / 2]).unwrap();
    a.wait_for(4, |_| false);
    for n in ["vault 2.bin", "vault 3.bin"] {
        let in_place = pkg.join(n).exists();
        let in_backups = ls(&pkg.join("backups"))
            .iter()
            .any(|x| x.contains(n.trim_end_matches(".bin")));
        assert!(in_place || in_backups, "{n} deleted; events {:?}", a.seen);
    }
}
