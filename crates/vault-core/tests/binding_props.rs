//! Property tests of the version 3 plaintext binding primitives (01 §4, I-04): the manifest
//! entry codec round-trips, and `extras_digest` depends on the content of an unknown-key
//! map, not on the order its entries were read in, and tells different maps apart.
//!
//! No Argon2 here, so the default case count is proptest's own (256); set
//! `VAULT_PROPTEST_CASES` to override, as for `merge_props`.

use std::collections::BTreeSet;

use ciborium::Value;
use proptest::prelude::*;
use vault_core::Extras;
use vault_core::format::{
    DIGEST_LEN, ManifestEntry, decode_manifest, encode_manifest_entries, extras_digest,
    item_record_digest, manifest_record_digest,
};
use vault_core::{Millis, Uuid};

fn cases() -> u32 {
    std::env::var("VAULT_PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256)
}

/// A small CBOR value tree: scalars plus shallow arrays and maps (map keys text, unique).
fn value() -> BoxedStrategy<Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<u64>().prop_map(Value::from),
        any::<i32>().prop_map(|i| Value::from(i64::from(i))),
        "[a-z_]{0,12}".prop_map(Value::Text),
        proptest::collection::vec(any::<u8>(), 0..24).prop_map(Value::Bytes),
    ]
    .boxed();
    leaf.prop_recursive(2, 12, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            extras_with(inner).prop_map(Value::Map),
        ]
        .boxed()
    })
    .boxed()
}

/// Unknown-key map entries with unique text keys (the parser rejects duplicate keys, so a
/// map with two equal keys is not a valid `Extras`).
fn extras_with(values: impl Strategy<Value = Value> + Clone) -> impl Strategy<Value = Extras> {
    proptest::collection::vec(("x_[a-z0-9]{0,8}", values), 0..5).prop_map(|entries| {
        let mut seen = BTreeSet::new();
        entries
            .into_iter()
            .filter(|(k, _)| seen.insert(k.clone()))
            .map(|(k, v)| (Value::Text(k), v))
            .collect()
    })
}

fn extras() -> impl Strategy<Value = Extras> {
    extras_with(value())
}

fn entry() -> impl Strategy<Value = ManifestEntry> {
    (
        any::<u128>(),
        any::<Millis>(),
        proptest::option::of(any::<[u8; DIGEST_LEN]>()),
    )
        .prop_map(|(id, modified_at, extras_digest)| ManifestEntry {
            id: Uuid::from_u128(id),
            modified_at,
            extras_digest,
        })
}

/// Canonical content of a map: entries sorted by key (keys are unique text).
fn canonical(e: &Extras) -> Vec<(Value, Value)> {
    let mut c = e.clone();
    c.sort_by(|(a, _), (b, _)| match (a, b) {
        (Value::Text(a), Value::Text(b)) => a.cmp(b),
        _ => unreachable!("text keys only"),
    });
    c
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// `decode_manifest(encode_manifest_entries(e)) == e`, for any entry list, with and
    /// without digests; a digest-less entry costs exactly two elements.
    #[test]
    fn manifest_entries_round_trip(entries in proptest::collection::vec(entry(), 0..8)) {
        let plain = encode_manifest_entries(&entries);
        prop_assert_eq!(decode_manifest(&plain).unwrap(), entries.clone());
        let stripped: Vec<ManifestEntry> = entries
            .iter()
            .map(|e| ManifestEntry { extras_digest: None, ..*e })
            .collect();
        let short = encode_manifest_entries(&stripped);
        let digests = entries.iter().filter(|e| e.extras_digest.is_some()).count();
        prop_assert_eq!(plain.len(), short.len() + digests * (2 + DIGEST_LEN));
    }

    /// `extras_digest` is insensitive to the order entries were read in.
    #[test]
    fn extras_digest_is_order_insensitive(e in extras(), seed in any::<u64>()) {
        let mut shuffled = e.clone();
        // Deterministic permutation from the seed (no rand dependency in tests).
        let n = shuffled.len();
        for i in (1..n).rev() {
            let j = (seed.wrapping_mul(6364136223846793005).wrapping_add(i as u64) % (i as u64 + 1)) as usize;
            shuffled.swap(i, j);
        }
        prop_assert_eq!(extras_digest(&shuffled), extras_digest(&e));
        prop_assert_eq!(item_record_digest(3, &shuffled), item_record_digest(3, &e));
        prop_assert_eq!(manifest_record_digest(3, &shuffled), manifest_record_digest(3, &e));
    }

    /// Two maps have the same digest iff they have the same canonical content; the
    /// version gates hold for every map.
    #[test]
    fn extras_digest_separates_different_maps(a in extras(), b in extras()) {
        let same = canonical(&a) == canonical(&b);
        prop_assert_eq!(extras_digest(&a) == extras_digest(&b), same);
        for v in [1u16, 2] {
            prop_assert_eq!(item_record_digest(v, &a), None);
            prop_assert_eq!(manifest_record_digest(v, &a), None);
        }
        prop_assert_eq!(item_record_digest(3, &a).is_some(), !a.is_empty());
        prop_assert_eq!(manifest_record_digest(3, &a), Some(extras_digest(&a)));
        // Dropping or adding one entry always changes the digest.
        if let Some((k, v)) = a.first() {
            let mut without = a.clone();
            without.remove(0);
            prop_assert_ne!(extras_digest(&without), extras_digest(&a));
            let mut doubled = without.clone();
            doubled.push((k.clone(), v.clone()));
            prop_assert_eq!(extras_digest(&doubled), extras_digest(&a));
        }
    }
}
