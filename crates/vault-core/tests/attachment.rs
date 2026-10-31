//! Attachment blobs (01 §4 "Attachments (v1.1)"): seal/open round trips, every tamper case,
//! the size cap, reference persistence through serialize/parse, and the merge rule.

mod common;

use std::io::Cursor;

use common::{new_vault, pw, sample_item};
use vault_core::attachment::{
    self, ATTACHMENT_VERSION, AttachmentError, CHUNK_SIZE, MAX_ATTACHMENT_SIZE, blob_file_name,
    new_ref, open, seal,
};
use vault_core::vault::ATTACHMENT_TOMBSTONE_CAP;
use vault_core::{AttachmentRef, AttachmentTombstone, Item, LockedVault, Uuid};

const TAG: usize = 16;

fn vid() -> Uuid {
    Uuid::from_u128(0x1234_5678_9abc_def0_1234_5678_9abc_def0)
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Seals and hands the reference back (`seal` consumes it: one ref, one seal).
fn seal_bytes(vault_id: Uuid, r: AttachmentRef, plain: &[u8]) -> (AttachmentRef, Vec<u8>) {
    let mut out = Vec::new();
    let before = r.clone();
    let (r, n) = seal(vault_id, r, Cursor::new(plain), &mut out).unwrap();
    assert_eq!(n, out.len() as u64);
    assert_eq!(n, plain.len() as u64 + TAG as u64 * r.chunk_count() as u64);
    assert_eq!(r.id, before.id);
    assert_eq!(r.chunk_nonces, before.chunk_nonces);
    assert_eq!(r.key.as_ref(), before.key.as_ref());
    (r, out)
}

fn open_bytes(vault_id: Uuid, r: &AttachmentRef, blob: &[u8]) -> Result<Vec<u8>, AttachmentError> {
    let mut out = Vec::new();
    open(vault_id, r, Cursor::new(blob), &mut out)?;
    Ok(out)
}

fn assert_tampered(res: Result<Vec<u8>, AttachmentError>) {
    match res {
        Err(AttachmentError::Tampered) => {}
        Err(e) => panic!("expected Tampered, got {e:?}"),
        Ok(_) => panic!("expected Tampered, got Ok"),
    }
}

/// A sealed sample: (ref, plaintext, blob).
fn sample(len: usize) -> (AttachmentRef, Vec<u8>, Vec<u8>) {
    let plain = pattern(len);
    let r = new_ref("f.bin", len as u64, 1_700_000_000_000).unwrap();
    let (r, blob) = seal_bytes(vid(), r, &plain);
    (r, plain, blob)
}

#[test]
fn round_trip_every_boundary_size() {
    for (len, chunks) in [
        (0usize, 1usize),
        (1, 1),
        (CHUNK_SIZE, 1),
        (CHUNK_SIZE + 1, 2),
        (2 * CHUNK_SIZE + 7, 3),
    ] {
        let (r, plain, blob) = sample(len);
        assert_eq!(r.chunk_count(), chunks, "chunk count for {len}");
        assert_eq!(blob.len(), len + chunks * TAG, "blob length for {len}");
        let back = open_bytes(vid(), &r, &blob).unwrap();
        assert_eq!(back, plain, "round trip for {len}");
    }
}

#[test]
fn seal_rejects_input_length_mismatch() {
    let r = new_ref("f", 10, 1).unwrap();
    let mut out = Vec::new();
    let short = seal(vid(), r.clone(), Cursor::new(vec![1u8; 9]), &mut out);
    assert!(
        matches!(
            short,
            Err(AttachmentError::SizeMismatch {
                expected: 10,
                actual: 9
            })
        ),
        "{short:?}"
    );
    let mut out = Vec::new();
    let long = seal(vid(), r, Cursor::new(vec![1u8; 11]), &mut out);
    assert!(
        matches!(
            long,
            Err(AttachmentError::SizeMismatch {
                expected: 10,
                actual: 11
            })
        ),
        "{long:?}"
    );
    // Inconsistent references are refused before anything is written.
    let mut bad = new_ref("f", 10, 1).unwrap();
    bad.chunk_nonces.push([0; 24]);
    let mut out = Vec::new();
    let res = seal(vid(), bad, Cursor::new(vec![1u8; 10]), &mut out);
    assert!(
        matches!(res, Err(AttachmentError::InvalidRef(_))),
        "{res:?}"
    );
    assert!(out.is_empty());
}

#[test]
fn size_cap() {
    assert!(matches!(
        new_ref("big", MAX_ATTACHMENT_SIZE + 1, 1),
        Err(AttachmentError::TooLarge { size: 100_000_001 })
    ));
    let r = new_ref("max", MAX_ATTACHMENT_SIZE, 1).unwrap();
    assert_eq!(r.chunk_count(), 96);
    let mut r = new_ref("ok", 1, 1).unwrap();
    r.size = MAX_ATTACHMENT_SIZE + 1;
    let mut out = Vec::new();
    assert!(matches!(
        seal(vid(), r, Cursor::new(vec![0u8; 1]), &mut out),
        Err(AttachmentError::TooLarge { .. })
    ));
}

#[test]
fn tamper_flip_a_byte_in_each_chunk() {
    let (r, _, blob) = sample(2 * CHUNK_SIZE + 7);
    let offsets = [
        0,
        CHUNK_SIZE + TAG + 5,
        2 * (CHUNK_SIZE + TAG) + 3,
        blob.len() - 1,
    ];
    for off in offsets {
        let mut bad = blob.clone();
        bad[off] ^= 0x01;
        assert_tampered(open_bytes(vid(), &r, &bad));
    }
}

#[test]
fn tamper_swap_two_chunks() {
    let (r, _, blob) = sample(3 * CHUNK_SIZE);
    let c = CHUNK_SIZE + TAG;
    let mut bad = Vec::with_capacity(blob.len());
    bad.extend_from_slice(&blob[c..2 * c]);
    bad.extend_from_slice(&blob[..c]);
    bad.extend_from_slice(&blob[2 * c..]);
    assert_eq!(bad.len(), blob.len());
    assert_tampered(open_bytes(vid(), &r, &bad));
}

#[test]
fn tamper_drop_last_chunk() {
    let (r, _, blob) = sample(2 * CHUNK_SIZE + 7);
    let c = CHUNK_SIZE + TAG;
    assert_tampered(open_bytes(vid(), &r, &blob[..2 * c]));
    // Also a truncated last chunk and a truncated first chunk.
    assert_tampered(open_bytes(vid(), &r, &blob[..blob.len() - 1]));
    assert_tampered(open_bytes(vid(), &r, &blob[..c - 1]));
    assert_tampered(open_bytes(vid(), &r, &[]));
}

#[test]
fn tamper_append_bytes() {
    for len in [0, 7, CHUNK_SIZE, 2 * CHUNK_SIZE + 7] {
        let (r, _, mut blob) = sample(len);
        blob.push(0);
        assert_tampered(open_bytes(vid(), &r, &blob));
        blob.extend_from_slice(&[0u8; CHUNK_SIZE + TAG]);
        assert_tampered(open_bytes(vid(), &r, &blob));
    }
}

#[test]
fn tamper_other_vault_other_id() {
    let (r, _, blob) = sample(CHUNK_SIZE + 1);
    assert_tampered(open_bytes(Uuid::from_u128(1), &r, &blob));
    let mut other = r.clone();
    other.id = Uuid::new_v4();
    assert_tampered(open_bytes(vid(), &other, &blob));
}

/// Builds a one-chunk blob by hand with the documented construction and a chosen attachment
/// version. Positive control: version 1 opens; version 2 is Tampered. Also pins the AAD
/// layout end to end, independent of the builder.
fn hand_sealed(r: &AttachmentRef, plain: &[u8], version: u16) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
    assert_eq!(r.chunk_count(), 1);
    let mut aad = Vec::new();
    aad.extend_from_slice(vid().as_bytes());
    aad.extend_from_slice(r.id.as_bytes());
    aad.extend_from_slice(&0u32.to_be_bytes());
    aad.extend_from_slice(&1u32.to_be_bytes());
    aad.extend_from_slice(&version.to_be_bytes());
    assert_eq!(
        aad,
        vault_core::format::attachment_chunk_aad(version, vid(), r.id, 0, 1)
    );
    XChaCha20Poly1305::new(Key::from_slice(r.key.as_ref()))
        .encrypt(
            XNonce::from_slice(&r.chunk_nonces[0]),
            Payload {
                msg: plain,
                aad: &aad,
            },
        )
        .unwrap()
}

#[test]
fn aad_binds_the_attachment_version_not_the_file_version() {
    assert_eq!(ATTACHMENT_VERSION, 1);
    let plain = pattern(100);
    let r = new_ref("v", 100, 1).unwrap();
    let (r, blob) = seal_bytes(vid(), r, &plain);
    assert_eq!(blob, hand_sealed(&r, &plain, ATTACHMENT_VERSION));
    assert_eq!(open_bytes(vid(), &r, &blob).unwrap(), plain);
    let foreign = hand_sealed(&r, &plain, 2);
    assert_ne!(foreign, blob);
    assert_tampered(open_bytes(vid(), &r, &foreign));
}

#[test]
fn tamper_change_chunk_count_via_ref() {
    let (r, _, blob) = sample(2 * CHUNK_SIZE + 7);
    let mut fewer = r.clone();
    fewer.chunk_nonces.pop();
    assert_tampered(open_bytes(vid(), &fewer, &blob));
    let mut more = r.clone();
    more.chunk_nonces.push([0u8; 24]);
    assert_tampered(open_bytes(vid(), &more, &blob));
    // A reference with no nonces is a caller bug, not a blob problem.
    let mut none = r.clone();
    none.chunk_nonces.clear();
    assert!(matches!(
        open_bytes(vid(), &none, &blob),
        Err(AttachmentError::InvalidRef(_))
    ));
}

#[test]
fn tamper_wrong_key_or_nonce_or_size() {
    let (r, _, blob) = sample(5);
    let mut k = r.clone();
    k.key[0] ^= 1;
    assert_tampered(open_bytes(vid(), &k, &blob));
    let mut n = r.clone();
    n.chunk_nonces[0][0] ^= 1;
    assert_tampered(open_bytes(vid(), &n, &blob));
    let mut s = r.clone();
    s.size = 6;
    assert_tampered(open_bytes(vid(), &s, &blob));
}

#[test]
fn open_writes_nothing_for_a_blob_with_trailing_bytes_and_partial_output_on_late_failure() {
    let (r, plain, mut blob) = sample(CHUNK_SIZE + 1);
    // Trailing bytes after a full last chunk are detected before that chunk is decrypted.
    let (r1, _, mut blob1) = sample(CHUNK_SIZE);
    blob1.push(0);
    let mut out = Vec::new();
    assert!(open(vid(), &r1, Cursor::new(&blob1), &mut out).is_err());
    assert!(out.is_empty());
    // A failure in chunk 2 leaves chunk 1 in `out` (documented: discard on Err).
    let last = blob.len() - 1;
    blob[last] ^= 1;
    let mut out = Vec::new();
    assert!(open(vid(), &r, Cursor::new(&blob), &mut out).is_err());
    assert_eq!(out, plain[..CHUNK_SIZE]);
}

#[test]
fn blob_name_is_32_hex_plus_bin() {
    let id = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
    assert_eq!(blob_file_name(id), "0123456789abcdef0123456789abcdef.bin");
    assert_eq!(attachment::chunk_count(0), 1);
}

#[test]
fn debug_redacts_key() {
    let r = new_ref("secret-name-is-fine", 3, 1).unwrap();
    let s = format!("{r:?}");
    assert!(s.contains("secret-name-is-fine"));
    assert!(s.contains("[REDACTED]"));
    let hex: String = r.key.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!s.contains(&hex[..8]));
    let dec = format!("{}, {}, {}", r.key[0], r.key[1], r.key[2]);
    assert!(!s.contains(&dec));
}

fn vault_with_item() -> (vault_core::UnlockedVault, Uuid) {
    let mut v = new_vault();
    let id = v.insert(sample_item(1, 100), 100);
    (v, id)
}

#[test]
fn ref_survives_serialize_parse_and_add_remove_bump_modified_at() {
    let (mut v, id) = vault_with_item();
    let before = v.get(id).unwrap().modified_at;
    let a = new_ref("a.txt", 0, 200).unwrap();
    let b = new_ref("b.bin", 2 * CHUNK_SIZE as u64 + 7, 201).unwrap();
    let (aid, bid) = (a.id, b.id);
    let (akey, bnonces) = (a.key.clone(), b.chunk_nonces.clone());
    v.add_attachment_ref(id, a, 200).unwrap();
    let m1 = v.get(id).unwrap().modified_at;
    assert!(m1 > before && m1 >= 200);
    v.add_attachment_ref(id, b, 150).unwrap();
    let m2 = v.get(id).unwrap().modified_at;
    assert_eq!(m2, m1 + 1, "skewed clock still strictly advances");
    assert_eq!(v.get(id).unwrap().device_id, v.device_id());

    let dup = new_ref("dup", 1, 1).map(|mut d| {
        d.id = aid;
        d
    });
    assert!(v.add_attachment_ref(id, dup.unwrap(), 300).is_err());
    assert!(
        v.add_attachment_ref(Uuid::nil(), new_ref("x", 1, 1).unwrap(), 300)
            .is_err()
    );

    let bytes = v.serialize();
    let u = LockedVault::parse(&bytes).unwrap().unlock(&pw()).unwrap();
    let item = u.get(id).unwrap();
    assert_eq!(item.attachments.len(), 2);
    let a2 = item.attachment(aid).unwrap();
    assert_eq!(a2.name, "a.txt");
    assert_eq!(a2.size, 0);
    assert_eq!(a2.added_at, 200);
    assert_eq!(a2.key.as_ref(), akey.as_ref());
    assert_eq!(a2.chunk_nonces.len(), 1);
    let b2 = item.attachment(bid).unwrap();
    assert_eq!(b2.chunk_nonces, bnonces);
    assert_eq!(b2.size, 2 * CHUNK_SIZE as u64 + 7);
    let mut ids: Vec<_> = u.attachment_ids().collect();
    ids.sort();
    let mut want = vec![aid, bid];
    want.sort();
    assert_eq!(ids, want);
    assert!(vault_core::merge::item_eq(v.get(id).unwrap(), item));

    let mut u = u;
    assert!(u.remove_attachment_ref(id, Uuid::nil(), 400).is_err());
    u.remove_attachment_ref(id, aid, 400).unwrap();
    assert_eq!(u.get(id).unwrap().modified_at, 400);
    assert_eq!(u.attachment_ids().collect::<Vec<_>>(), vec![bid]);
    // Tombstones keep their references for orphan GC.
    u.delete(id, 500).unwrap();
    assert_eq!(u.attachment_ids().collect::<Vec<_>>(), vec![bid]);
    assert!(u.items().next().is_none());
}

#[test]
fn invalid_refs_are_refused_on_every_write_path() {
    let (mut v, id) = vault_with_item();
    let mut bad = new_ref("bad", 5, 1).unwrap();
    bad.chunk_nonces.push([0; 24]);
    let mut huge = new_ref("huge", 5, 1).unwrap();
    huge.size = MAX_ATTACHMENT_SIZE + 1;
    let before = v.get(id).unwrap().modified_at;
    for r in [bad.clone(), huge.clone()] {
        assert!(matches!(
            v.add_attachment_ref(id, r, 100),
            Err(vault_core::VaultError::Malformed(_))
        ));
    }
    assert!(v.get(id).unwrap().attachments.is_empty());
    assert_eq!(v.get(id).unwrap().modified_at, before, "nothing restamped");

    // `update` rolls the item back wholesale.
    let title = v.get(id).unwrap().title.clone();
    let err = v.update(id, 100, |item| {
        item.title = "changed".into();
        item.attachments.push(bad.clone());
    });
    assert!(matches!(err, Err(vault_core::VaultError::Malformed(_))));
    assert_eq!(v.get(id).unwrap().title, title);
    assert!(v.get(id).unwrap().attachments.is_empty());
    assert_eq!(v.get(id).unwrap().modified_at, before);

    // `try_insert` reports, `insert` panics; nothing lands either way.
    let mut item = Item::new("n", Uuid::nil(), 1);
    item.attachments.push(huge);
    let iid = item.id;
    assert!(matches!(
        v.try_insert(item.clone(), 100),
        Err(vault_core::VaultError::Malformed(_))
    ));
    assert!(v.get(iid).is_none());
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut w = new_vault();
        w.insert(item, 100)
    }));
    assert!(res.is_err(), "insert must panic on an invalid reference");

    // Valid references pass through every path and the file still opens.
    let good = new_ref("good", 5, 1).unwrap();
    let gid = good.id;
    v.update(id, 200, |item| item.attachments.push(good))
        .unwrap();
    let u = LockedVault::parse(&v.serialize())
        .unwrap()
        .unlock(&pw())
        .unwrap();
    assert!(u.get(id).unwrap().attachment(gid).is_some());
}

#[test]
fn add_and_remove_on_a_tombstone() {
    let (mut v, id) = vault_with_item();
    v.delete(id, 500).unwrap();
    let r = new_ref("late", 1, 600).unwrap();
    let rid = r.id;
    v.add_attachment_ref(id, r, 600).unwrap();
    let item = v.get(id).unwrap();
    assert!(item.is_deleted());
    assert_eq!(item.attachments.len(), 1);
    assert_eq!(item.modified_at, 600);
    assert_eq!(item.deleted_at, Some(500), "still a tombstone");
    assert_eq!(v.attachment_ids().collect::<Vec<_>>(), vec![rid]);
    let u = LockedVault::parse(&v.serialize())
        .unwrap()
        .unlock(&pw())
        .unwrap();
    assert_eq!(u.get(id).unwrap().attachments.len(), 1);
    v.remove_attachment_ref(id, rid, 700).unwrap();
    assert!(v.get(id).unwrap().attachments.is_empty());
    assert_eq!(v.get(id).unwrap().modified_at, 700);
}

#[test]
fn old_file_without_attachments_key_still_parses() {
    // A v1 writer always wrote `attachments: []`; the decoder also accepts a missing key.
    let item = Item::new("n", Uuid::nil(), 1);
    let plain = vault_core::format::encode_item_plain(&item);
    let mut v: ciborium::Value = ciborium::from_reader(plain.as_slice()).unwrap();
    let ciborium::Value::Map(entries) = &mut v else {
        panic!()
    };
    entries.retain(|(k, _)| k != &ciborium::Value::Text("attachments".into()));
    let mut bytes = Vec::new();
    ciborium::into_writer(&v, &mut bytes).unwrap();
    let back =
        vault_core::format::decode_item_plain(&bytes, item.id, 1, vault_core::FORMAT_VERSION)
            .unwrap();
    assert!(back.attachments.is_empty());
}

#[test]
fn parser_rejects_inconsistent_refs() {
    let (mut v, id) = vault_with_item();
    let r = new_ref("a", 5, 1).unwrap();
    v.add_attachment_ref(id, r, 10).unwrap();
    let plain_ok = vault_core::format::encode_item_plain(v.get(id).unwrap());
    assert!(
        vault_core::format::decode_item_plain(&plain_ok, id, 10, vault_core::FORMAT_VERSION)
            .is_ok()
    );

    // Too many nonces for the size.
    let mut bad = v.get(id).unwrap().clone();
    bad.attachments[0].chunk_nonces.push([0; 24]);
    let plain = vault_core::format::encode_item_plain(&bad);
    assert!(matches!(
        vault_core::format::decode_item_plain(&plain, id, 10, vault_core::FORMAT_VERSION),
        Err(vault_core::VaultError::Malformed(_))
    ));
    // Over the cap.
    let mut bad = v.get(id).unwrap().clone();
    bad.attachments[0].size = MAX_ATTACHMENT_SIZE + 1;
    bad.attachments[0].chunk_nonces = vec![[0; 24]; 96];
    let plain = vault_core::format::encode_item_plain(&bad);
    assert!(matches!(
        vault_core::format::decode_item_plain(&plain, id, 10, vault_core::FORMAT_VERSION),
        Err(vault_core::VaultError::Malformed(_))
    ));
}

/// Two unlocked copies of the same vault.
fn two_copies(
    v: &vault_core::UnlockedVault,
) -> (vault_core::UnlockedVault, vault_core::UnlockedVault) {
    let bytes = v.serialize();
    let a = LockedVault::parse(&bytes).unwrap().unlock(&pw()).unwrap();
    let b = LockedVault::parse(&bytes).unwrap().unlock(&pw()).unwrap();
    (a, b)
}

fn att_ids(item: &Item) -> Vec<Uuid> {
    item.attachments.iter().map(|a| a.id).collect()
}

#[test]
fn merge_unions_refs_sorted_by_added_at_then_id() {
    let (mut v, id) = vault_with_item();
    let shared = new_ref("shared", 1, 300).unwrap();
    let shared_id = shared.id;
    v.add_attachment_ref(id, shared, 300).unwrap();
    let (mut a, mut b) = two_copies(&v);
    a.set_device_id(Uuid::from_u128(0xA));
    b.set_device_id(Uuid::from_u128(0xB));

    let x = new_ref("x", 1, 100).unwrap();
    let y = new_ref("y", 1, 200).unwrap();
    let (xid, yid) = (x.id, y.id);
    a.add_attachment_ref(id, x, 1000).unwrap();
    b.add_attachment_ref(id, y, 1001).unwrap();

    let ra = a.merge_from(&b).unwrap();
    assert_eq!(ra.updated, 1);
    let rb = b.merge_from(&a).unwrap();
    assert_eq!(rb.updated, 1);
    let want = vec![xid, yid, shared_id];
    assert_eq!(att_ids(a.get(id).unwrap()), want);
    assert_eq!(att_ids(b.get(id).unwrap()), want);
    // Content converged in one round; the record timestamp takes one more (the merge bump,
    // see `merge_from`), after which the merge is a no-op in both directions.
    a.merge_from(&b).unwrap();
    b.merge_from(&a).unwrap();
    assert!(vault_core::merge::item_eq(
        a.get(id).unwrap(),
        b.get(id).unwrap()
    ));
    let again = a.merge_from(&b).unwrap();
    assert!(!again.changed(), "{again:?}");
    assert_eq!(again.unchanged, 1);

    // Same added_at: id order decides.
    let (mut c, mut d) = two_copies(&a);
    let mut p = new_ref("p", 1, 50).unwrap();
    let mut q = new_ref("q", 1, 50).unwrap();
    p.id = Uuid::from_u128(2);
    q.id = Uuid::from_u128(1);
    c.add_attachment_ref(id, p, 2000).unwrap();
    d.add_attachment_ref(id, q, 2000).unwrap();
    c.merge_from(&d).unwrap();
    d.merge_from(&c).unwrap();
    assert_eq!(
        att_ids(c.get(id).unwrap())[..2],
        [Uuid::from_u128(1), Uuid::from_u128(2)]
    );
    assert_eq!(att_ids(c.get(id).unwrap()), att_ids(d.get(id).unwrap()));
}

#[test]
fn removed_ref_stays_removed_after_merge_both_ways() {
    let (mut v, id) = vault_with_item();
    let r = new_ref("r", 1, 300).unwrap();
    let keep = new_ref("keep", 1, 301).unwrap();
    let (rid, kid) = (r.id, keep.id);
    v.add_attachment_ref(id, r, 300).unwrap();
    v.add_attachment_ref(id, keep, 301).unwrap();
    let (mut a, mut b) = two_copies(&v);
    a.set_device_id(Uuid::from_u128(0xA));
    b.set_device_id(Uuid::from_u128(0xB));
    a.remove_attachment_ref(id, rid, 1000).unwrap();
    assert_eq!(att_ids(a.get(id).unwrap()), vec![kid]);
    assert_eq!(
        a.get(id).unwrap().removed_attachments,
        vec![AttachmentTombstone {
            id: rid,
            removed_at: 1000
        }]
    );
    // B keeps editing the item so it is the metadata winner on both sides.
    b.update(id, 2000, |item| item.title = "B edit".into())
        .unwrap();

    let ra = a.merge_from(&b).unwrap();
    assert_eq!(ra.updated, 1);
    assert_eq!(att_ids(a.get(id).unwrap()), vec![kid], "a: still removed");
    assert_eq!(a.get(id).unwrap().title, "B edit");
    let rb = b.merge_from(&a).unwrap();
    assert_eq!(rb.updated, 1);
    assert_eq!(att_ids(b.get(id).unwrap()), vec![kid], "b: removal applied");
    assert_eq!(b.get(id).unwrap().removed_attachments.len(), 1);
    assert_eq!(a.attachment_ids().collect::<Vec<_>>(), vec![kid]);
    assert_eq!(b.attachment_ids().collect::<Vec<_>>(), vec![kid]);
    a.merge_from(&b).unwrap();
    b.merge_from(&a).unwrap();
    assert!(vault_core::merge::item_eq(
        a.get(id).unwrap(),
        b.get(id).unwrap()
    ));
    assert!(!a.merge_from(&b).unwrap().changed());

    // Re-adding a removed id is refused (the next merge would drop it again).
    let mut again = new_ref("again", 1, 5000).unwrap();
    again.id = rid;
    assert!(a.add_attachment_ref(id, again, 5000).is_err());

    // An item tombstone keeps its references wholesale (no union with a live loser).
    let (mut a, mut b) = two_copies(&v);
    a.delete(id, 2000).unwrap();
    b.remove_attachment_ref(id, rid, 1500).unwrap();
    a.merge_from(&b).unwrap();
    assert!(a.get(id).unwrap().is_deleted());
    assert_eq!(att_ids(a.get(id).unwrap()), vec![rid, kid]);
}

#[test]
fn removal_under_a_clock_behind_the_add_still_wins_the_merge() {
    // The device that added the ref had its clock far ahead; the removing device's `now` is
    // behind added_at. added_at is clamped on add and the marker is lifted to it on remove.
    let (mut v, id) = vault_with_item();
    let far = 9_000_000;
    let r = new_ref("r", 1, far).unwrap();
    let rid = r.id;
    v.add_attachment_ref(id, r, far).unwrap();
    assert_eq!(v.get(id).unwrap().attachment(rid).unwrap().added_at, far);
    // Clamp: an added_at beyond the item's new stamp is pulled back to it.
    let later = new_ref("later", 1, far + 500).unwrap();
    let lid = later.id;
    v.add_attachment_ref(id, later, 10).unwrap();
    let item = v.get(id).unwrap();
    assert_eq!(item.attachment(lid).unwrap().added_at, item.modified_at);
    assert!(item.modified_at < far + 500);

    let (mut a, mut b) = two_copies(&v);
    a.set_device_id(Uuid::from_u128(0xA));
    b.set_device_id(Uuid::from_u128(0xB));
    a.remove_attachment_ref(id, rid, 10).unwrap();
    let marker = a.get(id).unwrap().removed_attachments[0];
    assert_eq!(marker.id, rid);
    assert!(marker.removed_at >= far, "marker lifted to added_at");
    assert_eq!(a.get(id).unwrap().modified_at, marker.removed_at);
    // B edits later still, so B is the metadata winner on both sides.
    b.update(id, far + 1000, |item| item.title = "B".into())
        .unwrap();
    a.merge_from(&b).unwrap();
    b.merge_from(&a).unwrap();
    assert_eq!(att_ids(a.get(id).unwrap()), vec![lid]);
    assert_eq!(att_ids(b.get(id).unwrap()), vec![lid]);
    a.merge_from(&b).unwrap();
    b.merge_from(&a).unwrap();
    assert!(vault_core::merge::item_eq(
        a.get(id).unwrap(),
        b.get(id).unwrap()
    ));

    // insert/update refuse a ref whose id has a marker, like add_attachment_ref.
    let mut again = new_ref("again", 1, 1).unwrap();
    again.id = rid;
    let err = a.update(id, far + 2000, |item| item.attachments.push(again.clone()));
    assert!(matches!(err, Err(vault_core::VaultError::Malformed(_))));
    assert_eq!(att_ids(a.get(id).unwrap()), vec![lid], "rolled back");
    let mut item = Item::new("n", Uuid::nil(), 1);
    item.removed_attachments.push(AttachmentTombstone {
        id: rid,
        removed_at: 5,
    });
    item.attachments.push(again);
    assert!(matches!(
        a.try_insert(item, 1),
        Err(vault_core::VaultError::Malformed(_))
    ));
}

#[test]
fn attachment_tombstones_survive_serialize_parse_and_are_omitted_when_empty() {
    let (mut v, id) = vault_with_item();
    // No removals: the optional key is absent, so the v1 layout is unchanged.
    let plain = vault_core::format::encode_item_plain(v.get(id).unwrap());
    let pv: ciborium::Value = ciborium::from_reader(plain.as_slice()).unwrap();
    let ciborium::Value::Map(entries) = pv else {
        panic!()
    };
    assert!(
        !entries
            .iter()
            .any(|(k, _)| k == &ciborium::Value::Text("removed_attachments".into()))
    );

    let r = new_ref("r", 1, 300).unwrap();
    let rid = r.id;
    v.add_attachment_ref(id, r, 300).unwrap();
    v.remove_attachment_ref(id, rid, 400).unwrap();
    let plain = vault_core::format::encode_item_plain(v.get(id).unwrap());
    let pv: ciborium::Value = ciborium::from_reader(plain.as_slice()).unwrap();
    let ciborium::Value::Map(entries) = pv else {
        panic!()
    };
    let (_, arr) = entries
        .iter()
        .find(|(k, _)| k == &ciborium::Value::Text("removed_attachments".into()))
        .expect("key present when non-empty");
    let ciborium::Value::Array(items) = arr else {
        panic!()
    };
    assert_eq!(items.len(), 1);
    let ciborium::Value::Map(m) = &items[0] else {
        panic!()
    };
    assert_eq!(
        m,
        &vec![
            (
                ciborium::Value::Text("id".into()),
                ciborium::Value::Bytes(rid.as_bytes().to_vec())
            ),
            (
                ciborium::Value::Text("removed_at".into()),
                ciborium::Value::Integer(400.into())
            ),
        ],
        "exact CBOR shape, canonical key order"
    );

    let u = LockedVault::parse(&v.serialize())
        .unwrap()
        .unlock(&pw())
        .unwrap();
    let item = u.get(id).unwrap();
    assert!(item.attachments.is_empty());
    assert_eq!(
        item.removed_attachments,
        vec![AttachmentTombstone {
            id: rid,
            removed_at: 400
        }]
    );
    assert!(vault_core::merge::item_eq(v.get(id).unwrap(), item));
    assert_eq!(u.attachment_ids().count(), 0);
}

#[test]
fn attachment_tombstones_are_capped_and_purged() {
    let (mut v, id) = vault_with_item();
    let n = ATTACHMENT_TOMBSTONE_CAP + 10;
    let mut ids = Vec::new();
    for i in 0..n as u64 {
        let r = new_ref("r", 1, i).unwrap();
        ids.push(r.id);
        v.add_attachment_ref(id, r, i).unwrap();
    }
    for (i, rid) in ids.iter().enumerate() {
        v.remove_attachment_ref(id, *rid, 10_000 + i as u64)
            .unwrap();
    }
    let item = v.get(id).unwrap();
    assert!(item.attachments.is_empty());
    assert_eq!(item.removed_attachments.len(), ATTACHMENT_TOMBSTONE_CAP);
    // Newest first; the 10 oldest removals fell off.
    assert_eq!(item.removed_attachments[0].id, ids[n - 1]);
    assert!(
        item.removed_attachments
            .iter()
            .all(|t| t.removed_at >= 10_010)
    );
    let stamps: Vec<_> = item
        .removed_attachments
        .iter()
        .map(|t| t.removed_at)
        .collect();
    let mut sorted = stamps.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(stamps, sorted);

    // Purge: markers older than the cutoff go; items are untouched; count is items only.
    let modified = item.modified_at;
    assert_eq!(v.purge_tombstones_older_than(10_050), 0);
    let item = v.get(id).unwrap();
    assert_eq!(item.removed_attachments.len(), n - 50);
    assert!(
        item.removed_attachments
            .iter()
            .all(|t| t.removed_at >= 10_050)
    );
    assert_eq!(item.modified_at, modified, "purge does not restamp");
    assert_eq!(v.purge_tombstones_older_than(u64::MAX), 0);
    assert!(v.get(id).unwrap().removed_attachments.is_empty());

    // The cap is also enforced on insert/update and in a merge.
    let mut item = Item::new("n", Uuid::nil(), 1);
    for i in 0..n as u64 {
        item.removed_attachments.push(AttachmentTombstone {
            id: Uuid::new_v4(),
            removed_at: i,
        });
    }
    let iid = v.insert(item, 1);
    assert_eq!(
        v.get(iid).unwrap().removed_attachments.len(),
        ATTACHMENT_TOMBSTONE_CAP
    );
    v.update(iid, 2, |item| {
        item.removed_attachments.push(AttachmentTombstone {
            id: Uuid::nil(),
            removed_at: 99_999,
        })
    })
    .unwrap();
    let t = &v.get(iid).unwrap().removed_attachments;
    assert_eq!(t.len(), ATTACHMENT_TOMBSTONE_CAP);
    assert_eq!(t[0].id, Uuid::nil());
}
