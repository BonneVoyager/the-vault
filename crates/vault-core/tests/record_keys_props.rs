//! Property test of the merge and the upgrade with record-level unknown keys (01 §4 and
//! §9, 03 §5, 02 guarantee 6; bug hunt 2026-11-27 N10, its security review and the owner
//! decision of the same day).
//!
//! Two or three devices start from files that hold the same items with different
//! record-level keys, different `created_at`, one item possibly missing, and a mix of
//! format versions. A version 1 start carries keys named `evil`, planted in the plaintext
//! (nothing binds them); a version 3 start carries keys named `x`, written by a holder of
//! the vault key (the manifest binds them). A random script of edits, content-free
//! restamps, deletes, strips, recoveries, upgrades and merges runs on skewed clocks, then
//! full rounds of pairwise merges. Every merge reads the peer from its file and is checked
//! for:
//!
//! - every file written opens on the key path (`unlock_with_key`; the target needs the
//!   `sync` feature, see `Cargo.toml`);
//! - no item stamp decreases;
//! - the gate: a peer below version 3 never changes our record-level keys, and an item
//!   only it holds arrives without keys in a version 3 vault;
//! - **no unbound key is ever bound**: no version 3 file, however it came about (upgrade,
//!   a merge that adopted a version 3 header, any later merge or save), carries an `evil`
//!   key on a record, in the header's top level, in the kdf map, in a slot map or in the
//!   manifest record (a version 1 start has one at each), and its manifest has a digest
//!   for exactly the records that carry keys;
//! - guarantee 6 against both inputs: with either input's record spliced over the saved
//!   one the file is `Tampered`, unless that record *is* the saved one (in a file below 3
//!   the unbound keys do not count). The one exception is the documented shared pair: a
//!   result equal to ours keeps our pair even if the peer used it for other content.
//!
//! After N rounds the N devices are at a fixpoint (a further round changes nothing) with
//! equal items, and equal record-level keys whenever the fleet ended on version 3.
//!
//! The starting files are built once per shape and cached (the build runs Argon2; the test
//! itself only does for the occasional `upgrade_format` step). `VAULT_PROPTEST_CASES`
//! overrides the case count.

mod common;

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use ciborium::Value;
use common::*;
use proptest::prelude::*;
use vault_core::format::VaultFile;
use vault_core::vault::merge::item_eq;
use vault_core::{Item, LockedVault, UnlockedVault, Uuid, VaultError, VaultKeyHandle};

/// Record-level keys of a version 3 start (bound) and of a version 1 start (unbound).
const BOUND: [&[(&str, u64)]; 3] = [&[], &[("x", 1)], &[("x", 2)]];
const UNBOUND: [&[(&str, u64)]; 3] = [&[], &[("evil", 1)], &[("evil", 2)]];
const CREATED: [Option<u64>; 3] = [Some(1_000), Some(400), None];
const FIELDS: [&str; 3] = ["username", "url", "notes"];

fn item_id(i: u8) -> Uuid {
    Uuid::from_u128(0xB000 + u128::from(i % 2))
}

fn dev_id(d: usize) -> Uuid {
    Uuid::from_u128(0xD000 + d as u128)
}

/// The same record on every device: fixed item and field ids, no history.
fn base_item(i: u8) -> Item {
    let mut item = sample_item(u64::from(i), 1_000);
    item.id = item_id(i);
    for (j, f) in item.fields.iter_mut().enumerate() {
        f.id = Uuid::from_u128((u128::from(i + 1) << 32) | j as u128);
    }
    item.history.clear();
    item
}

/// The shape of a device's starting file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Start {
    /// Index into [`CREATED`] for item 0.
    created: u8,
    /// Indexes into [`BOUND`] or [`UNBOUND`] for item 0 and item 1.
    keys: [u8; 2],
    /// Whether the file holds item 1 at all.
    has_second: bool,
    /// A version 3 file with bound keys, or a version 1 file with planted ones.
    v3: bool,
}

fn vault_key() -> &'static VaultKeyHandle {
    static KEY: OnceLock<VaultKeyHandle> = OnceLock::new();
    KEY.get_or_init(|| unstamped_vault().export_vault_key())
}

fn open(bytes: &[u8], d: usize) -> Result<UnlockedVault, VaultError> {
    LockedVault::parse(bytes)?.unlock_with_key(vault_key(), dev_id(d))
}

/// The manifest key every device shares (they all descend from the fixture).
fn shared_manifest_key() -> &'static [u8; 32] {
    static KEY: OnceLock<zeroize::Zeroizing<[u8; 32]>> = OnceLock::new();
    KEY.get_or_init(|| manifest_key(unstamped_bytes()))
}

/// The starting file for `start`, built once: the version 1 fixture with the base items
/// (written as device 0), then either the unbound keys planted, or the upgrade to version
/// 3 followed by the bound keys. Every file wraps the fixture's vault key; independently
/// upgraded files differ in their headers, which the header merge settles.
fn start_file(mut start: Start) -> Vec<u8> {
    static POOL: OnceLock<Mutex<BTreeMap<Start, Vec<u8>>>> = OnceLock::new();
    if !start.has_second {
        start.keys[1] = 0;
    }
    let mut pool = POOL.get_or_init(Mutex::default).lock().unwrap();
    pool.entry(start)
        .or_insert_with(|| {
            let mut v = unstamped_vault();
            v.set_device_id(dev_id(0));
            let mut first = base_item(0);
            first.created_at = CREATED[usize::from(start.created)];
            v.insert(first, 1_000);
            if start.has_second {
                v.insert(base_item(1), 1_000);
            }
            if start.v3 {
                v.upgrade_format(&pw(), 5_000).unwrap();
            }
            let keysets = if start.v3 { BOUND } else { UNBOUND };
            for i in 0..=u8::from(start.has_second) {
                let keys = keysets[usize::from(start.keys[usize::from(i)])];
                v = with_record_keys(&v, item_id(i), keys, dev_id(0));
            }
            let bytes = v.serialize();
            if start.v3 {
                return bytes;
            }
            // Planted keys at the other plaintext sites too. Version 1 binds neither the
            // header's top-level unknown keys nor the manifest record's. The kdf and slot
            // maps of this (already saved, hence stamped) file are under the v1.1 digest,
            // so they are written the way a blind first save binds planted keys: by a
            // key holder.
            let evil = || (Value::Text("evil".into()), Value::Integer(1.into()));
            rewrite_with_key(&bytes, |f| {
                f.header.extras.push(evil());
                f.manifest.extras.push(evil());
                f.header.kdf_extras.push(evil());
                for slot in f.header.slots.iter_mut().filter_map(|s| s.as_key_mut()) {
                    slot.extras.push(evil());
                }
            })
        })
        .clone()
}

#[derive(Debug, Clone)]
enum Op {
    Edit { item: u8, field: u8, v: u8 },
    Touch { item: u8 },
    Delete { item: u8 },
    Strip { item: u8 },
    Recover { item: u8 },
    Upgrade,
    Merge { from: u8 },
}

#[derive(Debug, Clone)]
struct Step {
    dev: u8,
    dt: i16,
    op: Op,
}

fn start_strategy() -> impl Strategy<Value = Start> {
    (
        0u8..3,
        0u8..3,
        0u8..3,
        prop::bool::weighted(0.8),
        any::<bool>(),
    )
        .prop_map(|(created, k0, k1, has_second, v3)| Start {
            created,
            keys: [k0, k1],
            has_second,
            v3,
        })
}

fn step_strategy(n: u8) -> impl Strategy<Value = Step> {
    let op = prop_oneof![
        4 => (0u8..2, 0u8..3, 0u8..3).prop_map(|(item, field, v)| Op::Edit { item, field, v }),
        2 => (0u8..2).prop_map(|item| Op::Touch { item }),
        3 => (0u8..2).prop_map(|item| Op::Delete { item }),
        2 => (0u8..2).prop_map(|item| Op::Strip { item }),
        2 => (0u8..2).prop_map(|item| Op::Recover { item }),
        1 => Just(Op::Upgrade),
        3 => (0u8..n).prop_map(|from| Op::Merge { from }),
    ];
    (0..n, -30i16..120, op).prop_map(|(dev, dt, op)| Step { dev, dt, op })
}

type Scenario = (usize, Vec<Start>, Vec<u64>, Vec<Step>, Vec<Vec<u32>>);

fn scenario() -> impl Strategy<Value = Scenario> {
    prop_oneof![Just(2u8), Just(3u8)].prop_flat_map(|n| {
        (
            Just(usize::from(n)),
            prop::collection::vec(start_strategy(), 3),
            prop::collection::vec(0u64..2_000, 3),
            prop::collection::vec(step_strategy(n), 0..=14),
            prop::collection::vec(prop::collection::vec(any::<u32>(), 6), 4),
        )
    })
}

fn same_item(a: &Item, b: &Item) -> bool {
    item_eq(a, b) && a.created_at == b.created_at
}

fn bound(v: &UnlockedVault) -> bool {
    v.header().format_version >= vault_core::format::PLAINTEXT_BINDING_VERSION
}

/// The canonical bytes of each record's unknown keys in a written file (empty map: none).
fn file_keys(bytes: &[u8]) -> BTreeMap<Uuid, [u8; 32]> {
    let file = VaultFile::parse(bytes).unwrap();
    file.items
        .iter()
        .map(|r| (r.id, vault_core::format::extras_digest(&r.extras)))
        .collect()
}

fn stamps(v: &UnlockedVault) -> BTreeMap<Uuid, u64> {
    v.items_including_deleted()
        .map(|i| (i.id, i.modified_at))
        .collect()
}

fn no_stamp_decreased(
    before: &BTreeMap<Uuid, u64>,
    after: &BTreeMap<Uuid, u64>,
) -> Result<(), TestCaseError> {
    for (id, b) in before {
        if let Some(a) = after.get(id) {
            prop_assert!(a >= b, "stamp of {id} went from {b} to {a}");
        }
    }
    Ok(())
}

/// Invariant C: a version 3 file vouches for no key that a pre-3 file carried. The planted
/// keys are the ones named `evil`; the manifest must hold a digest for exactly the records
/// that carry keys, so nothing is bound out of sight either.
fn no_unbound_key_is_bound(bytes: &[u8]) -> Result<(), TestCaseError> {
    let file = VaultFile::parse(bytes).unwrap();
    if file.header.format_version < vault_core::format::PLAINTEXT_BINDING_VERSION {
        return Ok(());
    }
    let evil = |keys: &[(Value, Value)]| keys.iter().any(|(k, _)| k.as_text() == Some("evil"));
    prop_assert!(
        !evil(&file.header.extras),
        "planted key in a version 3 header"
    );
    prop_assert!(
        !evil(&file.manifest.extras),
        "planted key in a version 3 manifest record"
    );
    prop_assert!(
        !evil(&file.header.kdf_extras),
        "planted key in a version 3 kdf map"
    );
    for slot in file.header.slots.iter().filter_map(|s| s.as_key()) {
        prop_assert!(!evil(&slot.extras), "planted key in a version 3 slot map");
    }
    let entries = manifest_entries(shared_manifest_key(), bytes);
    for rec in &file.items {
        prop_assert!(
            !evil(&rec.extras),
            "planted key on record {} of a version 3 file",
            rec.id
        );
        let entry = entries.iter().find(|e| e.id == rec.id).unwrap();
        prop_assert_eq!(entry.extras_digest.is_some(), !rec.extras.is_empty());
    }
    Ok(())
}

/// `devs[i].merge_from(devs[j] as read from its file)` with every per-merge check of the
/// module docs. Returns whether anything changed (items or header).
fn checked_merge(devs: &mut [UnlockedVault], i: usize, j: usize) -> Result<bool, TestCaseError> {
    let fail = |what: &str, e: VaultError| TestCaseError::fail(format!("{what}: {e}"));
    let (ours_file, theirs_file) = (devs[i].serialize(), devs[j].serialize());
    let before = open(&ours_file, i).map_err(|e| fail("our file", e))?;
    let peer = open(&theirs_file, j).map_err(|e| fail("peer file", e))?;
    let (ours_bound, peer_bound) = (bound(&before), bound(&peer));

    let report = devs[i].merge_from(&peer).unwrap();
    let saved = devs[i].serialize();
    let after = open(&saved, i).map_err(|e| fail("merged file", e))?;
    no_unbound_key_is_bound(&saved)?;
    // A version 3 peer always moves us to version 3 (its header is stamped).
    prop_assert!(
        !peer_bound || bound(&after),
        "still below 3 after a version 3 peer"
    );
    no_stamp_decreased(&stamps(&before), &stamps(&after))?;

    let none = vault_core::format::extras_digest(&Vec::new());
    let keys_of = |keys: &BTreeMap<Uuid, [u8; 32]>, id: Uuid| keys.get(&id).copied();
    let (keys_before, keys_peer, keys_after) = (
        file_keys(&ours_file),
        file_keys(&theirs_file),
        file_keys(&saved),
    );
    for a in after.items_including_deleted() {
        let id = a.id;
        let ours = before.get(id);
        // The gate: unbound keys of a peer are never taken.
        if !peer_bound {
            match ours {
                Some(_) => prop_assert_eq!(keys_of(&keys_after, id), keys_of(&keys_before, id)),
                None if ours_bound => prop_assert_eq!(keys_of(&keys_after, id), Some(none)),
                None => {}
            }
        }
        // Guarantee 6 against both inputs. Our own unbound keys, dropped on the way to
        // version 3, are not a change of the record: the merge runs as if ours had none
        // (and our old record, sealed under the old version, cannot be spliced anyway).
        let ours_keys = match keys_of(&keys_before, id) {
            Some(_) if peer_bound && !ours_bound => Some(none),
            keys => keys,
        };
        let changed =
            ours.is_none_or(|o| !same_item(o, a)) || keys_of(&keys_after, id) != ours_keys;
        for (donor_file, donor_keys, is_peer) in [
            (&ours_file, &keys_before, false),
            (&theirs_file, &keys_peer, true),
        ] {
            if !donor_keys.contains_key(&id) || (is_peer && !changed) {
                continue;
            }
            match open(&splice(&saved, donor_file, id), i) {
                Err(VaultError::Tampered(_)) => {}
                Err(e) => return Err(fail("spliced file", e)),
                Ok(spliced) => {
                    let same = same_item(spliced.get(id).unwrap(), a)
                        && (!bound(&after) || keys_of(donor_keys, id) == keys_of(&keys_after, id));
                    prop_assert!(
                        same,
                        "a different record of {id} was accepted (peer: {is_peer})"
                    );
                }
            }
        }
    }
    Ok(report.changed())
}

fn run_script(
    devs: &mut [UnlockedVault],
    skews: &[u64],
    steps: &[Step],
) -> Result<(), TestCaseError> {
    let n = devs.len();
    let mut clocks: Vec<u64> = (0..n).map(|d| 2_000 + skews[d]).collect();
    for step in steps {
        let d = usize::from(step.dev);
        clocks[d] = clocks[d].saturating_add_signed(i64::from(step.dt));
        let now = clocks[d];
        let before = stamps(&devs[d]);
        // Errors (an absent item, a live item stripped, a tombstone edited) are part of the
        // script: the operation simply does not apply.
        match step.op {
            Op::Edit { item, field, v } => {
                let name = FIELDS[usize::from(field)];
                let _ = devs[d].set_field_named(item_id(item), name, secret(format!("v{v}")), now);
            }
            Op::Touch { item } => drop(devs[d].update(item_id(item), now, |_| {})),
            Op::Delete { item } => drop(devs[d].delete(item_id(item), now)),
            Op::Strip { item } => drop(devs[d].delete_permanently(item_id(item), now)),
            Op::Recover { item } => drop(devs[d].recover(item_id(item), now)),
            Op::Upgrade => {
                devs[d].upgrade_format(&pw(), now).unwrap();
                no_unbound_key_is_bound(&devs[d].serialize())?;
            }
            Op::Merge { from } => {
                let from = usize::from(from);
                if from != d {
                    checked_merge(devs, d, from)?;
                }
            }
        }
        no_stamp_decreased(&before, &stamps(&devs[d]))?;
    }
    Ok(())
}

/// Every ordered pair `(dst, src)` of `n` devices, sorted by the generated keys.
fn ordered(n: usize, keys: &[u32]) -> Vec<(usize, usize)> {
    let mut pairs: Vec<_> = (0..n)
        .flat_map(|i| (0..n).filter(move |j| *j != i).map(move |j| (i, j)))
        .zip(keys.iter().copied())
        .collect();
    pairs.sort_by_key(|&(_, k)| k);
    pairs.into_iter().map(|(pair, _)| pair).collect()
}

fn cases() -> u32 {
    std::env::var("VAULT_PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// N devices reach a fixpoint within N rounds of pairwise merges in any order,
    /// whatever the mix of format versions: a device below 3 contributes no record-level
    /// key, before or after it moves to version 3, so nothing waits for its upgrade.
    #[test]
    fn devices_with_record_level_keys_reach_a_fixpoint(
        (n, starts, skews, steps, orders) in scenario(),
    ) {
        let mut devs = Vec::with_capacity(n);
        for (d, start) in starts.iter().take(n).enumerate() {
            devs.push(open(&start_file(*start), d).unwrap());
        }
        run_script(&mut devs, &skews, &steps)?;

        for order in orders.iter().take(n) {
            for (i, j) in ordered(n, order) {
                checked_merge(&mut devs, i, j)?;
            }
        }
        // Fixpoint: nothing left to do, in any direction.
        for (i, j) in ordered(n, &orders[0]) {
            prop_assert!(!checked_merge(&mut devs, i, j)?, "{i} <- {j} still changes");
        }
        let all_bound = devs.iter().all(bound);
        prop_assert!(all_bound || !devs.iter().any(bound), "versions differ at the fixpoint");
        for pair in devs.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            let (xs, ys): (Vec<_>, Vec<_>) =
                (a.items_including_deleted().collect(), b.items_including_deleted().collect());
            prop_assert_eq!(xs.len(), ys.len());
            for (x, y) in xs.iter().zip(&ys) {
                prop_assert!(same_item(x, y), "item {} differs at the fixpoint", x.id);
            }
            if all_bound {
                prop_assert_eq!(file_keys(&a.serialize()), file_keys(&b.serialize()));
            }
        }
    }
}
