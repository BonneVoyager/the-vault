//! Property tests of the merge laws (03-sync.md §5, 02 guarantee 9): commutativity,
//! idempotence, convergence, monotone stamps and delete/resurrect, over random edit scripts
//! on two or three "devices" with skewed, sometimes backwards-running clocks.
//!
//! Ids are deterministic (derived from small slots) so a shrunk case is reproducible.
//!
//! Set `VAULT_PROPTEST_CASES` (a u32) to override the cases per law for a deeper pass, e.g.
//! `VAULT_PROPTEST_CASES=500 cargo test -p vault-core --test merge_props`. Unset or
//! unparsable values fall back to the default of 24.

mod common;

use std::collections::BTreeMap;

use common::*;
use proptest::prelude::*;
use vault_core::vault::merge::item_eq;
use vault_core::vault::{FIELD_TOMBSTONE_CAP, MergeReport};
use vault_core::{ExposeSecret, Field, FieldKind, Item, ItemIcon, UnlockedVault, Uuid, VaultError};

// ---------------------------------------------------------------------------------------
// Scripts
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Op {
    Insert { slot: u8 },
    Title { item: u8, t: u8 },
    Favorite { item: u8, v: bool },
    Tags { item: u8, tags: Vec<u8> },
    Icon { item: u8, icon: Option<u8> },
    SetField { item: u8, field: u8, v: u8 },
    AddField { item: u8, slot: u8, v: u8 },
    RemoveField { item: u8, field: u8 },
    Delete { item: u8 },
    Merge { from: u8 },
}

#[derive(Debug, Clone)]
struct Step {
    dev: u8,
    dt: i16,
    op: Op,
}

fn op_strategy(allow_merge: bool) -> impl Strategy<Value = Op> {
    let edits = prop_oneof![
        2 => (0u8..3).prop_map(|slot| Op::Insert { slot }),
        2 => (any::<u8>(), 0u8..4).prop_map(|(item, t)| Op::Title { item, t }),
        2 => (any::<u8>(), any::<bool>()).prop_map(|(item, v)| Op::Favorite { item, v }),
        2 => (any::<u8>(), prop::collection::vec(0u8..4, 0..4))
            .prop_map(|(item, tags)| Op::Tags { item, tags }),
        2 => (any::<u8>(), prop::option::of(0u8..3))
            .prop_map(|(item, icon)| Op::Icon { item, icon }),
        4 => (any::<u8>(), any::<u8>(), 0u8..4)
            .prop_map(|(item, field, v)| Op::SetField { item, field, v }),
        3 => (any::<u8>(), 0u8..3, 0u8..4)
            .prop_map(|(item, slot, v)| Op::AddField { item, slot, v }),
        3 => (any::<u8>(), any::<u8>())
            .prop_map(|(item, field)| Op::RemoveField { item, field }),
        2 => any::<u8>().prop_map(|item| Op::Delete { item }),
    ];
    if allow_merge {
        prop_oneof![8 => edits, 2 => any::<u8>().prop_map(|from| Op::Merge { from })].boxed()
    } else {
        edits.boxed()
    }
}

fn steps_strategy(n: u8, allow_merge: bool) -> impl Strategy<Value = Vec<Step>> {
    prop::collection::vec(
        (0..n, -30i16..120, op_strategy(allow_merge)).prop_map(|(dev, dt, op)| Step {
            dev,
            dt,
            op,
        }),
        0..=30,
    )
}

/// Device count, skews, and a script (merges optional).
fn scenario(allow_merge: bool) -> impl Strategy<Value = (u8, Vec<u64>, Vec<Step>)> {
    prop_oneof![Just(2u8), Just(3u8)].prop_flat_map(move |n| {
        (
            Just(n),
            prop::collection::vec(0u64..2_000, 3),
            steps_strategy(n, allow_merge),
        )
    })
}

// ---------------------------------------------------------------------------------------
// Snapshots (secrets exposed: test-only)
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
struct Content {
    id: Uuid,
    title: String,
    deleted_at: Option<u64>,
    device_id: Uuid,
    favorite: bool,
    tags: Vec<String>,
    icon: Option<(String, String, Option<String>)>,
    stamps: [Option<u64>; 4],
    fields: Vec<(Uuid, String, String, String, u64, Option<String>)>,
    history: Vec<(String, u64)>,
    removed_history: Vec<u64>,
    removed_fields: Vec<(Uuid, u64)>,
}

#[derive(Debug, Clone, PartialEq)]
struct Snap {
    content: Content,
    modified_at: u64,
    created_at: Option<u64>,
}

fn snap(i: &Item) -> Snap {
    Snap {
        content: Content {
            id: i.id,
            title: i.title.clone(),
            deleted_at: i.deleted_at,
            device_id: i.device_id,
            favorite: i.favorite,
            tags: i.tags.clone(),
            icon: i
                .icon
                .as_ref()
                .map(|x| (x.kind.clone(), x.value.clone(), x.color.clone())),
            stamps: [
                i.title_modified_at,
                i.favorite_modified_at,
                i.tags_modified_at,
                i.icon_modified_at,
            ],
            fields: i
                .fields
                .iter()
                .map(|f| {
                    (
                        f.id,
                        f.name.clone(),
                        f.kind_str().to_owned(),
                        f.value.expose_secret().clone(),
                        f.modified_at,
                        f.section.clone(),
                    )
                })
                .collect(),
            history: i
                .history
                .iter()
                .map(|h| (h.value.expose_secret().clone(), h.replaced_at))
                .collect(),
            removed_history: i.removed_history.clone(),
            removed_fields: i
                .removed_fields
                .iter()
                .map(|t| (t.id, t.removed_at))
                .collect(),
        },
        modified_at: i.modified_at,
        created_at: i.created_at,
    }
}

fn snaps(v: &UnlockedVault) -> Vec<Snap> {
    v.items_including_deleted().map(snap).collect()
}

/// Only the parts of two snapshots that differ, for readable failures.
fn diff(x: &Snap, y: &Snap) -> String {
    let (a, b) = (&x.content, &y.content);
    let mut out = format!("item {}\n", a.id);
    macro_rules! d {
        ($($f:ident),*) => {$(
            if a.$f != b.$f {
                out += &format!("  {}: {:?}  vs  {:?}\n", stringify!($f), a.$f, b.$f);
            }
        )*};
    }
    d!(
        title,
        deleted_at,
        device_id,
        favorite,
        tags,
        icon,
        stamps,
        history,
        removed_history,
        removed_fields
    );
    if a.fields != b.fields {
        out += &format!(
            "  fields:\n    {:?}\n    {:?}\n",
            a.fields
                .iter()
                .map(|f| (f.0.as_u128() & 0xFF, &f.3, f.4))
                .collect::<Vec<_>>(),
            b.fields
                .iter()
                .map(|f| (f.0.as_u128() & 0xFF, &f.3, f.4))
                .collect::<Vec<_>>()
        );
    }
    if x.modified_at != y.modified_at {
        out += &format!("  modified_at: {} vs {}\n", x.modified_at, y.modified_at);
    }
    if x.created_at != y.created_at {
        out += &format!("  created_at: {:?} vs {:?}\n", x.created_at, y.created_at);
    }
    out
}

/// Item-wise equality of two vaults (items, fields, stamps, tombstones, removed_fields).
fn same(a: &UnlockedVault, b: &UnlockedVault) -> Result<(), TestCaseError> {
    let (sa, sb) = (snaps(a), snaps(b));
    prop_assert_eq!(sa.len(), sb.len());
    for (x, y) in sa.iter().zip(&sb) {
        prop_assert!(x == y, "items differ:\n{}", diff(x, y));
    }
    for (x, y) in a.items_including_deleted().zip(b.items_including_deleted()) {
        prop_assert!(
            item_eq(x, y),
            "item_eq disagrees with snapshots for {}",
            x.id
        );
    }
    Ok(())
}

/// Equality ignoring `modified_at`, which may differ by at most 1 per item (the one-sided
/// +1 bump of 03 §5).
fn same_but_bump(a: &UnlockedVault, b: &UnlockedVault) -> Result<(), TestCaseError> {
    let (sa, sb) = (snaps(a), snaps(b));
    prop_assert_eq!(sa.len(), sb.len());
    for (x, y) in sa.iter().zip(&sb) {
        let mut y2 = y.clone();
        y2.modified_at = x.modified_at;
        prop_assert!(x == &y2, "items differ:\n{}", diff(x, y));
        prop_assert!(
            x.modified_at.abs_diff(y.modified_at) <= 1,
            "modified_at differs by more than 1:\n{}",
            diff(x, y)
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Simulation
// ---------------------------------------------------------------------------------------

#[derive(Clone)]
struct ItemStamps {
    live: bool,
    modified_at: u64,
    attrs: [u64; 4],
    fields: BTreeMap<Uuid, u64>,
}

fn stamps_of(v: &UnlockedVault) -> BTreeMap<Uuid, ItemStamps> {
    v.items_including_deleted()
        .map(|i| {
            (
                i.id,
                ItemStamps {
                    live: !i.is_deleted(),
                    modified_at: i.modified_at,
                    attrs: [
                        i.title_stamp(),
                        i.favorite_stamp(),
                        i.tags_stamp(),
                        i.icon_stamp(),
                    ],
                    fields: i.fields.iter().map(|f| (f.id, f.modified_at)).collect(),
                },
            )
        })
        .collect()
}

fn check_monotone(
    before: &BTreeMap<Uuid, ItemStamps>,
    after: &BTreeMap<Uuid, ItemStamps>,
) -> Result<(), TestCaseError> {
    for (id, b) in before {
        let a = after.get(id);
        prop_assert!(a.is_some(), "item {id} vanished");
        let a = a.unwrap();
        prop_assert!(
            a.modified_at >= b.modified_at,
            "modified_at decreased on {id}: {} -> {}",
            b.modified_at,
            a.modified_at
        );
        // A tombstone win replaces the item wholesale (03 §5), so finer stamps are only
        // compared while the item is live both before and after.
        if !(a.live && b.live) {
            continue;
        }
        for k in 0..4 {
            prop_assert!(
                a.attrs[k] >= b.attrs[k],
                "attribute stamp {k} decreased on {id}: {:?} -> {:?}",
                b.attrs,
                a.attrs
            );
        }
        for (fid, t) in &b.fields {
            if let Some(t2) = a.fields.get(fid) {
                prop_assert!(t2 >= t, "field stamp decreased");
            }
        }
    }
    Ok(())
}

fn base_item(i: u64) -> Item {
    let mut item = sample_item(i, 1_000);
    item.id = Uuid::from_u128(0xB000 + u128::from(i));
    for (j, f) in item.fields.iter_mut().enumerate() {
        f.id = Uuid::from_u128((u128::from(i + 1) << 32) | j as u128);
    }
    item.history.clear();
    item
}

fn dev_id(d: usize) -> Uuid {
    Uuid::from_u128(0xD000 + d as u128)
}

fn dup(v: &UnlockedVault) -> UnlockedVault {
    let mut c = unlock(&v.serialize()).unwrap();
    c.set_device_id(v.device_id());
    c
}

/// Mutable access to `devs[i]` and shared access to `devs[j]`, `i != j`.
fn two(devs: &mut [UnlockedVault], i: usize, j: usize) -> (&mut UnlockedVault, &UnlockedVault) {
    assert_ne!(i, j);
    if i < j {
        let (lo, hi) = devs.split_at_mut(j);
        (&mut lo[i], &hi[0])
    } else {
        let (lo, hi) = devs.split_at_mut(i);
        (&mut hi[0], &lo[j])
    }
}

struct Sim {
    devs: Vec<UnlockedVault>,
    clocks: Vec<u64>,
    /// Assert the monotone-stamp law (law 4) after every step; only that law's test sets it.
    check: bool,
}

impl Sim {
    fn new(n: usize, skews: &[u64], base_items: u64) -> Self {
        let mut first = new_vault();
        first.set_device_id(dev_id(0));
        for i in 0..base_items {
            first.insert(base_item(i), 1_000);
        }
        let mut devs = vec![];
        for d in 1..n {
            let mut v = unlock(&first.serialize()).unwrap();
            v.set_device_id(dev_id(d));
            devs.push(v);
        }
        devs.insert(0, first);
        let clocks = (0..n).map(|d| 2_000 + skews[d]).collect();
        Self {
            devs,
            clocks,
            check: false,
        }
    }

    fn apply(&mut self, step: &Step) -> Result<(), TestCaseError> {
        let d = usize::from(step.dev);
        let n = self.devs.len();
        self.clocks[d] = self.clocks[d]
            .saturating_add_signed(i64::from(step.dt))
            .max(1);
        let now = self.clocks[d];
        let before = stamps_of(&self.devs[d]);
        let before_snaps = snaps(&self.devs[d]);
        let mut merged = false;
        {
            let v = &mut self.devs[d];
            let ids: Vec<Uuid> = v.items_including_deleted().map(|i| i.id).collect();
            let pick = |sel: u8| (!ids.is_empty()).then(|| ids[usize::from(sel) % ids.len()]);
            // Errors (unknown field, ...) are legal outcomes of a random script.
            let _ = match &step.op {
                Op::Insert { slot } => {
                    let id = Uuid::from_u128(
                        (1 << 64) | (0xC000 + ((d as u128) << 4) + u128::from(*slot)),
                    );
                    if v.get(id).is_none() {
                        let mut it = base_item(u64::from(*slot));
                        it.id = id;
                        for (j, f) in it.fields.iter_mut().enumerate() {
                            f.id = Uuid::from_u128((id.as_u128() << 8) | j as u128);
                        }
                        it.modified_at = now;
                        for f in &mut it.fields {
                            f.modified_at = now;
                        }
                        it.created_at = Some(now);
                        v.insert(it, now);
                    }
                    Ok(())
                }
                Op::Title { item, t } => pick(*item).map_or(Ok(()), |id| {
                    v.update(id, now, |i| i.title = format!("title{t}"))
                }),
                Op::Favorite { item, v: fav } => {
                    pick(*item).map_or(Ok(()), |id| v.update(id, now, |i| i.favorite = *fav))
                }
                Op::Tags { item, tags } => pick(*item).map_or(Ok(()), |id| {
                    v.update(id, now, |i| {
                        i.tags = tags.iter().map(|t| format!("g{t}")).collect();
                    })
                }),
                Op::Icon { item, icon } => pick(*item).map_or(Ok(()), |id| {
                    v.update(id, now, |i| {
                        i.icon = icon.map(|n| ItemIcon::new("symbol", format!("i{n}")));
                    })
                }),
                Op::SetField {
                    item,
                    field,
                    v: val,
                } => pick(*item).map_or(Ok(()), |id| {
                    let item = v.get(id).unwrap();
                    if item.fields.is_empty() {
                        return Ok(());
                    }
                    let fid = item.fields[usize::from(*field) % item.fields.len()].id;
                    v.set_field(id, fid, secret(format!("val{val}")), now)
                }),
                Op::AddField { item, slot, v: val } => pick(*item).map_or(Ok(()), |id| {
                    let fid = Uuid::from_u128(
                        (1 << 100)
                            | ((id.as_u128() & 0xFFFF_FFFF) << 16)
                            | ((d as u128) << 8)
                            | u128::from(*slot),
                    );
                    if v.get(id).unwrap().field_by_id(fid).is_some() {
                        return Ok(());
                    }
                    v.update(id, now, |i| {
                        let mut f =
                            Field::new("added", FieldKind::Text, secret(format!("val{val}")), now);
                        f.id = fid;
                        i.fields.push(f);
                    })
                }),
                Op::RemoveField { item, field } => pick(*item).map_or(Ok(()), |id| {
                    let item = v.get(id).unwrap();
                    if item.fields.is_empty() {
                        return Ok(());
                    }
                    let fid = item.fields[usize::from(*field) % item.fields.len()].id;
                    v.remove_field(id, fid, now)
                }),
                Op::Delete { item } => pick(*item).map_or(Ok(()), |id| v.delete(id, now)),
                Op::Merge { .. } => {
                    merged = true;
                    Ok::<(), VaultError>(())
                }
            };
        }
        if let Op::Merge { from } = &step.op {
            debug_assert!(merged);
            let src = (d + 1 + usize::from(*from) % (n - 1)) % n;
            let (dst, other) = two(&mut self.devs, d, src);
            dst.merge_from(other).unwrap();
            if !self.check {
                return Ok(());
            }
            // Every item whose content changed has a strictly greater modified_at (03 §5).
            let after = snaps(dst);
            let old: BTreeMap<Uuid, &Snap> =
                before_snaps.iter().map(|s| (s.content.id, s)).collect();
            for s in &after {
                if let Some(o) = old.get(&s.content.id)
                    && o.content != s.content
                {
                    prop_assert!(
                        s.modified_at > o.modified_at,
                        "merge changed content without bumping modified_at: {:?} -> {:?}",
                        o,
                        s
                    );
                }
            }
        }
        if self.check {
            check_monotone(&before, &stamps_of(&self.devs[d]))?;
        }
        Ok(())
    }

    fn run(&mut self, steps: &[Step]) -> Result<(), TestCaseError> {
        for s in steps {
            self.apply(s)?;
        }
        Ok(())
    }
}

/// One full round: every ordered pair (dst, src) once, in the given order, live merges.
fn round(devs: &mut [UnlockedVault], order: &[(usize, usize)]) {
    for &(i, j) in order {
        let (dst, src) = two(devs, i, j);
        dst.merge_from(src).unwrap();
    }
}

fn pairs(n: usize) -> Vec<(usize, usize)> {
    (0..n)
        .flat_map(|i| (0..n).filter(move |j| *j != i).map(move |j| (i, j)))
        .collect()
}

/// The ordered pairs of `n` devices sorted by the generated `keys` (a shrinkable shuffle).
fn ordered(n: usize, keys: &[u32]) -> Vec<(usize, usize)> {
    let mut p: Vec<_> = pairs(n).into_iter().zip(keys.iter().copied()).collect();
    p.sort_by_key(|&(_, k)| k);
    p.into_iter().map(|(pair, _)| pair).collect()
}

fn all_same(devs: &[UnlockedVault]) -> Result<(), TestCaseError> {
    for w in devs.windows(2) {
        same(&w[0], &w[1])?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Laws
// ---------------------------------------------------------------------------------------

/// Cases per law: each case runs Argon2 (test KDF params) once per device, which dominates.
const CASES: u32 = 24;

/// Case count: `VAULT_PROPTEST_CASES` if set and parsable, else `CASES`.
fn cases() -> u32 {
    std::env::var("VAULT_PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(CASES)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// Law 1: after one exchange the vaults are equal up to `modified_at` (|delta| <= 1),
    /// after a second exchange fully equal.
    #[test]
    fn merge_is_commutative((n, skews, steps) in scenario(true), base in 1u64..=3) {
        let mut sim = Sim::new(usize::from(n), &skews, base);
        sim.run(&steps)?;
        let a_snap = dup(&sim.devs[0]);
        let b_snap = dup(&sim.devs[1]);
        sim.devs[0].merge_from(&b_snap).unwrap();
        sim.devs[1].merge_from(&a_snap).unwrap();
        same_but_bump(&sim.devs[0], &sim.devs[1])?;
        // A second exchange makes them fully equal.
        let a_snap = dup(&sim.devs[0]);
        let b_snap = dup(&sim.devs[1]);
        sim.devs[0].merge_from(&b_snap).unwrap();
        sim.devs[1].merge_from(&a_snap).unwrap();
        same(&sim.devs[0], &sim.devs[1])?;
    }

    /// Law 2: a second merge of the same other vault changes nothing.
    #[test]
    fn merge_is_idempotent((n, skews, steps) in scenario(true), base in 1u64..=3) {
        let mut sim = Sim::new(usize::from(n), &skews, base);
        sim.run(&steps)?;
        let (a, other) = two(&mut sim.devs, 0, 1);
        a.merge_from(other).unwrap();
        let after_first = snaps(a);
        let items = after_first.len();
        let report = a.merge_from(other).unwrap();
        prop_assert_eq!(
            report,
            MergeReport { added: 0, updated: 0, deleted: 0, unchanged: items, header_updated: false }
        );
        prop_assert!(!report.changed());
        prop_assert_eq!(snaps(a), after_first);
    }

    /// Law 3: after an edit-only phase, every device is equal after N full rounds (N devices) of
    /// pairwise merges in any order.
    #[test]
    fn devices_converge_in_n_rounds(
        (n, skews, steps) in scenario(false),
        base in 1u64..=3,
        keys in prop::collection::vec(prop::collection::vec(any::<u32>(), 6), 3),
    ) {
        let n = usize::from(n);
        let mut sim = Sim::new(n, &skews, base);
        sim.run(&steps)?;
        for k in keys.iter().take(n) {
            round(&mut sim.devs, &ordered(n, k));
        }
        all_same(&sim.devs)?;
        // And a third pass finds nothing left to do.
        for (i, j) in pairs(n) {
            let (dst, src) = two(&mut sim.devs, i, j);
            prop_assert!(!dst.merge_from(src).unwrap().changed());
        }
    }

    /// Law 3, cap: more than 64 `removed_fields` markers spread over the devices need up to
    /// N + 1 rounds, and no removed field ever comes back.
    #[test]
    fn devices_converge_in_n_plus_one_rounds_when_the_marker_cap_fires(
        n in 2usize..=3,
        owners in prop::collection::vec(0usize..3, FIELD_TOMBSTONE_CAP + 6..=FIELD_TOMBSTONE_CAP + 26),
        t0 in 50u64..500,
        keys in prop::collection::vec(prop::collection::vec(any::<u32>(), 6), 4),
    ) {
        let mut item = Item::new("Many", Uuid::nil(), 10);
        item.id = Uuid::from_u128(0xCA9);
        for i in 0..owners.len() {
            let mut f = Field::new(format!("f{i}"), FieldKind::Text, secret("x"), 10);
            f.id = Uuid::from_u128(0xF00 + i as u128);
            item.fields.push(f);
        }
        let mut first = new_vault();
        first.set_device_id(dev_id(0));
        let id = first.insert(item, 10);
        let mut devs = vec![first];
        for d in 1..n {
            let mut v = unlock(&devs[0].serialize()).unwrap();
            v.set_device_id(dev_id(d));
            devs.push(v);
        }
        for (i, owner) in owners.iter().enumerate() {
            let d = owner % n;
            devs[d]
                .remove_field(id, Uuid::from_u128(0xF00 + i as u128), t0 + i as u64)
                .unwrap();
        }
        for k in keys.iter().take(n + 1) {
            round(&mut devs, &ordered(n, k));
        }
        all_same(&devs)?;
        // With three devices a field can legally come back (03 §5 accepted limit: a device
        // that missed a dropped marker); with two it must not (merge_hunt L1).
        if n == 2 {
            for v in &devs {
                prop_assert!(v.get(id).unwrap().fields.is_empty(), "a removed field came back");
            }
        }
    }

    /// Law 4: stamps never decrease across any op or merge, and a merge that changed content
    /// bumped `modified_at` (both checked inside `Sim::apply`, per step).
    #[test]
    fn stamps_are_monotone((n, skews, steps) in scenario(true), base in 1u64..=3) {
        let mut sim = Sim::new(usize::from(n), &skews, base);
        sim.check = true;
        sim.run(&steps)?;
    }

    /// Law 5 (guarantee 9): a delete survives a merge with an older copy that still holds the
    /// item; an edit stamped after the tombstone resurrects it, one stamped at or before it
    /// does not (03 §5: tombstone wins iff `deleted_at >= other.modified_at`).
    #[test]
    fn delete_wins_over_older_copy_and_later_edit_resurrects(
        base in 1u64..=3,
        target in any::<u8>(),
        now_d in 1u64..5_000,
        edit in prop::option::of((1u64..5_000, 0u8..4)),
    ) {
        let mut a = Sim::new(2, &[0, 0], base);
        let id = Uuid::from_u128(0xB000 + u128::from(u64::from(target) % base));
        let old_b = dup(&a.devs[1]);
        a.devs[0].delete(id, now_d).unwrap();
        let deleted_at = a.devs[0].get(id).unwrap().deleted_at.unwrap();
        let mut resurrect = false;
        if let Some((now_e, val)) = edit {
            let b = &mut a.devs[1];
            let fid = b.get(id).unwrap().fields[0].id;
            b.set_field(id, fid, secret(format!("edit{val}")), now_e).unwrap();
            resurrect = b.get(id).unwrap().modified_at > deleted_at;
            if now_e > deleted_at {
                prop_assert!(resurrect);
            }
        }
        let a_snap = dup(&a.devs[0]);
        let b_snap = dup(&a.devs[1]);
        a.devs[0].merge_from(&b_snap).unwrap();
        a.devs[1].merge_from(&a_snap).unwrap();
        // A tie on `modified_at` (tombstone vs. edit) leaves the two sides one apart after the
        // first round (the +1 bump of 03 §5 lands on one side only); the second round
        // converges them (03 §5: two rounds).
        let a_snap = dup(&a.devs[0]);
        let b_snap = dup(&a.devs[1]);
        a.devs[0].merge_from(&b_snap).unwrap();
        a.devs[1].merge_from(&a_snap).unwrap();
        same(&a.devs[0], &a.devs[1])?;
        for v in &a.devs {
            let item = v.get(id).unwrap();
            prop_assert_eq!(item.is_deleted(), !resurrect);
            if !resurrect {
                prop_assert_eq!(item.deleted_at, Some(deleted_at));
            }
            prop_assert_eq!(v.items().count(), base as usize - usize::from(!resurrect));
        }
        // The older copy never brings a deleted item back, in either state.
        if !resurrect {
            let report = a.devs[0].merge_from(&old_b).unwrap();
            prop_assert!(!report.changed());
            prop_assert!(a.devs[0].get(id).unwrap().is_deleted());
            let mut old_b = old_b;
            let report = old_b.merge_from(&a.devs[0]).unwrap();
            prop_assert_eq!(report.deleted, 1);
            prop_assert!(old_b.get(id).unwrap().is_deleted());
        }
    }
}

/// Regression for `devices_converge_in_n_rounds` (shrunk by hand): three devices each add a
/// field to the same item, then live sequential merge rounds. One item stays one
/// millisecond apart after two rounds (three are needed) (the +1 bump of 03 §5 cascades across three devices).
#[test]
fn replay_three_devices_two_rounds() {
    use Op::*;
    let s = |dev, dt, op| Step { dev, dt, op };
    let steps = vec![
        s(
            0,
            -27,
            SetField {
                item: 80,
                field: 219,
                v: 1,
            },
        ),
        s(
            1,
            58,
            RemoveField {
                item: 210,
                field: 115,
            },
        ),
        s(1, 71, Title { item: 139, t: 3 }),
        s(
            2,
            70,
            SetField {
                item: 60,
                field: 199,
                v: 2,
            },
        ),
        s(
            2,
            108,
            Tags {
                item: 18,
                tags: vec![0, 1, 3],
            },
        ),
        s(
            1,
            -25,
            AddField {
                item: 170,
                slot: 2,
                v: 0,
            },
        ),
        s(
            2,
            3,
            AddField {
                item: 56,
                slot: 0,
                v: 3,
            },
        ),
        s(
            0,
            57,
            AddField {
                item: 65,
                slot: 1,
                v: 3,
            },
        ),
    ];
    let mut sim = Sim::new(3, &[0, 19, 0], 3);
    sim.run(&steps).unwrap();
    round(
        &mut sim.devs,
        &[(1, 0), (0, 2), (0, 1), (2, 1), (2, 0), (1, 2)],
    );
    round(
        &mut sim.devs,
        &[(1, 0), (0, 2), (2, 1), (1, 2), (0, 1), (2, 0)],
    );
    // Two rounds can leave `modified_at` one apart with three devices; the bound is N = 3.
    round(
        &mut sim.devs,
        &[(0, 1), (1, 2), (2, 0), (1, 0), (2, 1), (0, 2)],
    );
    all_same(&sim.devs).unwrap();
}
