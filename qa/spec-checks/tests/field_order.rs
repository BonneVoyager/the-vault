//! Field order (03 §5 "Field order", owner decision 2026-11-08) and concurrent CLI edits of one item
//! (03 §5 "Concurrent CLI edits of one item"; 00 phase 1 "concurrent CLI edits of one item from
//! several processes are last-writer-wins per attribute and callers serialise them"). Added
//! 2026-11-15, written from the specs before reading the source.
//!
//! Spec sentences under test:
//! - F1 "The merged list is the item winner's fields in the winner's order (the item with the greater
//!   `modified_at`, tie → greater `device_id`, tie → item payload bytes), followed by the loser's
//!   fields the winner lacks, in the loser's order."
//! - F2 "A reorder alone restamps the item (02 `update`), so it propagates when nothing else changed"
//! - F3 "a later edit of the same item on another device wins the order too and the reorder is lost."
//! - F4 (02 `update`) "a field whose name, kind, value or section changed without a bumped
//!   `modified_at` is bumped to `now`": a reorder changes none of those, so no field is restamped.
//! - C1 "two processes that each read the item, change the same stamped attribute (for example
//!   `edit --tag` on both) and save, both report success and the greater stamp wins"
//! - C2 "Edits to different fields or items survive." and 01 §4 "per-attribute stamps so concurrent
//!   edits of different attributes on two devices both survive".
//!
//! Passing shows the behaviour on these inputs; it is not a proof.
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use secrecy::ExposeSecret;
use spec_checks::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use uuid::Uuid;
use vault_core::*;

type Plain = BTreeMap<[u8; 16], (u64, Value)>;

/// Decrypts every item record with the spec's HKDF item key (01 §3, §4). The canonical ItemPlain
/// keeps the `fields` array in stored order, so comparing it compares field order too.
fn plain(bytes: &[u8], vault_key: &[u8]) -> Plain {
    let raw = split(bytes);
    let vid = bytes_of(get(&raw.header, "vault_id").unwrap());
    let ik = indep::hkdf(vault_key, &vid, "vault/item/v1");
    let mut out = BTreeMap::new();
    let n = raw.body.len();
    for r in &raw.body[..n - 1] {
        let id = bytes_of(get(r, "id").unwrap());
        let ma = u64_of(get(r, "modified_at").unwrap());
        let pt = indep::open(
            &ik,
            &bytes_of(get(r, "nonce").unwrap()),
            &bytes_of(get(r, "ct").unwrap()),
            &indep::item_aad(&vid, &id, ma, raw.version),
        )
        .expect("item opens with the spec AAD");
        let v: Value = ciborium::from_reader(&pt[..]).unwrap();
        out.insert(id.try_into().unwrap(), (ma, canon(v)));
    }
    out
}

fn compare(x: &Plain, y: &Plain, ma_slack: u64) -> Option<String> {
    if x.keys().collect::<Vec<_>>() != y.keys().collect::<Vec<_>>() {
        return Some(format!("item sets differ ({} vs {})", x.len(), y.len()));
    }
    for (id, (ma_x, px)) in x {
        let (ma_y, py) = &y[id];
        if ma_x.abs_diff(*ma_y) > ma_slack {
            return Some(format!(
                "item {}: modified_at {ma_x} vs {ma_y}",
                Uuid::from_bytes(*id)
            ));
        }
        if enc(px) != enc(py) {
            let fo = |p: &Value| -> Vec<Vec<u8>> {
                match get(p, "fields") {
                    Some(Value::Array(fs)) => fs
                        .iter()
                        .filter_map(|f| get(f, "id").map(bytes_of))
                        .collect(),
                    _ => vec![],
                }
            };
            let what = if fo(px) != fo(py) {
                "field order/set"
            } else {
                "other content"
            };
            return Some(format!(
                "item {}: ItemPlain differs ({what})",
                Uuid::from_bytes(*id)
            ));
        }
    }
    None
}

struct Net {
    devs: Vec<UnlockedVault>,
    key: Vec<u8>,
}
impl Net {
    fn with_devices(ids: &[Uuid]) -> Net {
        let base = UnlockedVault::create(&pw("order"), KdfParams::for_tests(), Uuid::new_v4());
        let bytes = base.serialize();
        let key = indep::open_file(&bytes, "order").vault_key;
        let l = LockedVault::parse(&bytes).unwrap();
        let k = base.export_vault_key();
        Net {
            devs: ids
                .iter()
                .map(|d| l.unlock_with_key(&k, *d).unwrap())
                .collect(),
            key,
        }
    }
    fn new(n: usize) -> Net {
        let ids: Vec<Uuid> = (0..n).map(|_| Uuid::new_v4()).collect();
        Net::with_devices(&ids)
    }
    fn file(&self, d: usize) -> Vec<u8> {
        self.devs[d].serialize()
    }
    fn open_as(&self, bytes: &[u8], as_dev: usize) -> UnlockedVault {
        LockedVault::parse(bytes)
            .unwrap()
            .unlock_with_key(
                &self.devs[as_dev].export_vault_key(),
                self.devs[as_dev].device_id(),
            )
            .unwrap()
    }
    fn state(&self, d: usize) -> Plain {
        plain(&self.file(d), &self.key)
    }
    fn pull(&mut self, to: usize, from: usize) -> MergeReport {
        let f = self.file(from);
        let t = self.open_as(&f, to);
        self.devs[to].merge_from(&t).unwrap()
    }
    /// One simultaneous exchange between i and j (both read the other's file first).
    fn exchange(&mut self, i: usize, j: usize) {
        let (fi, fj) = (self.file(i), self.file(j));
        let ti = self.open_as(&fj, i);
        let tj = self.open_as(&fi, j);
        self.devs[i].merge_from(&ti).unwrap();
        self.devs[j].merge_from(&tj).unwrap();
    }
    /// One simultaneous round over all devices.
    fn round(&mut self) {
        let n = self.devs.len();
        let files: Vec<Vec<u8>> = (0..n).map(|d| self.file(d)).collect();
        for to in 0..n {
            for (from, f) in files.iter().enumerate() {
                if from != to {
                    let t = self.open_as(f, to);
                    self.devs[to].merge_from(&t).unwrap();
                }
            }
        }
    }
    fn converged(&self) -> Option<String> {
        let s0 = self.state(0);
        for d in 1..self.devs.len() {
            if let Some(e) = compare(&s0, &self.state(d), 0) {
                return Some(format!("dev 0 vs {d}: {e}"));
            }
        }
        None
    }
    /// Item "Seed" with text fields f, g, h (stamped `now`) on every device.
    fn seed(&mut self, now: u64) -> (Uuid, [Uuid; 3]) {
        let d0 = self.devs[0].device_id();
        let mut it = Item::new("Seed", d0, now);
        for n in ["f", "g", "h"] {
            it.fields
                .push(Field::new(n, FieldKind::Text, pw(&format!("{n}0")), now));
        }
        let f = [it.fields[0].id, it.fields[1].id, it.fields[2].id];
        let id = self.devs[0].insert(it, now);
        self.round();
        (id, f)
    }
}

fn any_item(v: &UnlockedVault, id: Uuid) -> &Item {
    v.items_including_deleted().find(|i| i.id == id).unwrap()
}
fn order(v: &UnlockedVault, id: Uuid) -> Vec<Uuid> {
    any_item(v, id).fields.iter().map(|f| f.id).collect()
}
fn fval(v: &UnlockedVault, id: Uuid, f: Uuid) -> String {
    any_item(v, id)
        .field_by_id(f)
        .unwrap()
        .value
        .expose_secret()
        .clone()
}
/// Puts the fields into the order given by `ids` (all ids must be present).
fn arrange(it: &mut Item, ids: &[Uuid]) {
    let mut out = vec![];
    for id in ids {
        let p = it.fields.iter().position(|f| f.id == *id).unwrap();
        out.push(it.fields.remove(p));
    }
    out.append(&mut it.fields);
    it.fields = out;
}
fn names(v: &UnlockedVault, id: Uuid) -> Vec<String> {
    any_item(v, id)
        .fields
        .iter()
        .map(|f| f.name.clone())
        .collect()
}

/// F1 with two devices and extras in the middle of the loser's list: the winner's order first, then
/// the loser's extra fields in the loser's order.
#[test]
fn fo01_winner_order_then_loser_extras_in_loser_order() {
    let mut n = Net::new(2);
    let (id, [f, g, h]) = n.seed(1000);
    let (x1, x2) = (
        Field::new("x1", FieldKind::Text, pw("a"), 2000),
        Field::new("x2", FieldKind::Text, pw("b"), 2000),
    );
    let (x1id, x2id) = (x1.id, x2.id);
    // loser A (dev 0) at 2000: [x1, h, f, x2, g]
    n.devs[0]
        .update(id, 2000, move |it| {
            it.fields.push(x1);
            it.fields.push(x2);
            arrange(it, &[x1id, h, f, x2id, g]);
        })
        .unwrap();
    assert_eq!(order(&n.devs[0], id), vec![x1id, h, f, x2id, g]);
    // winner B (dev 1) at 3000: adds y, keeps [f, g, h, y]
    let y = Field::new("y", FieldKind::Text, pw("c"), 3000);
    let yid = y.id;
    n.devs[1]
        .update(id, 3000, move |it| it.fields.push(y))
        .unwrap();
    n.exchange(0, 1);
    let want = vec![f, g, h, yid, x1id, x2id];
    for d in 0..2 {
        assert_eq!(
            order(&n.devs[d], id),
            want,
            "dev {d}: F1 winner order then loser extras in loser order; got names {:?}",
            names(&n.devs[d], id)
        );
    }
    n.exchange(0, 1);
    assert_eq!(n.converged(), None, "fully equal after two exchanges");
}

/// F2 + F4: a reorder alone restamps the item but no field; so a peer's older value edit of one
/// field survives the merge (field-level LWW) while the reorder wins the order.
#[test]
fn fo02_reorder_alone_restamps_item_not_fields() {
    let mut n = Net::new(2);
    let (id, [f, g, h]) = n.seed(1000);
    n.devs[0]
        .update(id, 3000, |it| arrange(it, &[h, f, g]))
        .unwrap();
    let it = n.devs[0].get(id).unwrap();
    assert!(it.modified_at >= 3000, "F2: reorder restamps the item");
    for fl in &it.fields {
        assert_eq!(
            fl.modified_at, 1000,
            "F4: a reorder must not restamp field {} (name/kind/value/section unchanged)",
            fl.name
        );
    }
    // B edits g's value at 2000 (before the reorder, after the seed)
    n.devs[1].set_field(id, g, pw("g-from-B"), 2000).unwrap();
    n.exchange(0, 1);
    for d in 0..2 {
        assert_eq!(
            order(&n.devs[d], id),
            vec![h, f, g],
            "dev {d}: reorder wins"
        );
        assert_eq!(
            fval(&n.devs[d], id, g),
            "g-from-B",
            "dev {d}: B's value edit lost to a reorder"
        );
    }
    n.exchange(0, 1);
    assert_eq!(n.converged(), None);
}

/// F3: a later edit of the same item elsewhere wins the order; the earlier reorder is lost
/// (accepted), but the content of both sides survives.
#[test]
fn fo03_later_edit_elsewhere_wins_order() {
    let mut n = Net::new(2);
    let (id, [f, g, h]) = n.seed(1000);
    n.devs[0]
        .update(id, 2000, |it| arrange(it, &[h, g, f]))
        .unwrap();
    n.devs[1].set_field(id, f, pw("f-B"), 3000).unwrap();
    n.exchange(0, 1);
    for d in 0..2 {
        assert_eq!(order(&n.devs[d], id), vec![f, g, h], "dev {d}: F3");
        assert_eq!(fval(&n.devs[d], id, f), "f-B");
    }
}

/// F1 tie: same `modified_at`, different devices → the greater `device_id` supplies the order, on
/// both sides after one exchange.
#[test]
fn fo04_same_millisecond_tie_greater_device_wins_order() {
    for _ in 0..8 {
        let mut n = Net::new(2);
        let (id, [f, g, h]) = n.seed(1000);
        n.devs[0]
            .update(id, 2000, |it| arrange(it, &[h, g, f]))
            .unwrap();
        n.devs[1]
            .update(id, 2000, |it| arrange(it, &[g, f, h]))
            .unwrap();
        let a_wins = n.devs[0].device_id() > n.devs[1].device_id();
        let want = if a_wins { vec![h, g, f] } else { vec![g, f, h] };
        n.exchange(0, 1);
        for d in 0..2 {
            assert_eq!(
                order(&n.devs[d], id),
                want,
                "dev {d}: tie → greater device_id (a_wins={a_wins})"
            );
        }
        n.exchange(0, 1);
        assert_eq!(n.converged(), None);
    }
}

/// F1 last tie-break: same millisecond AND a cloned device id → item payload bytes decide; both
/// sides hold the same order after one exchange and are fully equal after two.
#[test]
fn fo05_cloned_device_tie_converges_on_payload_bytes() {
    let dev = Uuid::new_v4();
    let mut n = Net::with_devices(&[dev, dev]);
    let (id, [f, g, h]) = n.seed(1000);
    n.devs[0]
        .update(id, 2000, |it| arrange(it, &[h, g, f]))
        .unwrap();
    n.devs[1]
        .update(id, 2000, |it| arrange(it, &[g, f, h]))
        .unwrap();
    n.exchange(0, 1);
    assert_eq!(
        order(&n.devs[0], id),
        order(&n.devs[1], id),
        "cloned-device tie: orders differ after one exchange"
    );
    n.exchange(0, 1);
    assert_eq!(n.converged(), None, "cloned-device tie: not fully equal");
}

/// F1 with three devices, a removal marker and two additions, in a fixed pull order, then rounds.
#[test]
fn fo06_three_devices_order_markers_converge() {
    let mut n = Net::new(3);
    let (id, [f, g, h]) = n.seed(1000);
    let x = Field::new("x", FieldKind::Text, pw("x"), 2000);
    let xid = x.id;
    n.devs[0]
        .update(id, 2000, move |it| {
            arrange(it, &[h, f, g]);
            it.fields.push(x);
        })
        .unwrap();
    let y = Field::new("y", FieldKind::Text, pw("y"), 3000);
    let yid = y.id;
    n.devs[1]
        .update(id, 3000, move |it| it.fields.push(y))
        .unwrap();
    n.devs[2]
        .update(id, 2500, |it| arrange(it, &[g, h, f]))
        .unwrap();
    n.devs[2].remove_field(id, f, 2500).unwrap();
    n.pull(0, 1);
    n.pull(2, 0);
    n.pull(1, 2);
    for _ in 0..3 {
        n.round();
    }
    assert_eq!(n.converged(), None, "three devices did not converge");
    let o = order(&n.devs[0], id);
    let pos = |u: Uuid| o.iter().position(|x| *x == u);
    assert_eq!(
        pos(f),
        None,
        "removed field came back: {:?}",
        names(&n.devs[0], id)
    );
    for u in [g, h, xid, yid] {
        assert!(pos(u).is_some(), "field lost: {:?}", names(&n.devs[0], id));
    }
    assert_eq!(o.len(), 4, "duplicate fields: {:?}", names(&n.devs[0], id));
    assert!(pos(g) < pos(h), "winner (B) order g before h lost");
    assert!(pos(yid) < pos(xid), "winner's y must precede loser extra x");
}

/// 03 §5 tombstone row + F2: a reorder after a delete is an edit and resurrects the item with that
/// order; a reorder before the delete does not.
#[test]
fn fo07_reorder_vs_delete() {
    let mut n = Net::new(2);
    let (id, [f, g, h]) = n.seed(1000);
    n.devs[0].delete(id, 2000).unwrap();
    n.devs[1]
        .update(id, 3000, |it| arrange(it, &[h, f, g]))
        .unwrap();
    n.exchange(0, 1);
    for d in 0..2 {
        assert!(
            n.devs[d].get(id).is_some_and(|i| i.deleted_at.is_none()),
            "dev {d}: reorder after delete must resurrect"
        );
        assert_eq!(order(&n.devs[d], id), vec![h, f, g]);
    }
    let mut n = Net::new(2);
    let (id, [f, g, h]) = n.seed(1000);
    n.devs[1]
        .update(id, 1500, |it| arrange(it, &[h, f, g]))
        .unwrap();
    n.devs[0].delete(id, 2000).unwrap();
    n.exchange(0, 1);
    for d in 0..2 {
        assert!(
            any_item(&n.devs[d], id).deleted_at.is_some(),
            "dev {d}: delete after reorder must stay deleted"
        );
    }
}

/// F1 + 03 §5 `removed_fields`: the winner removed g; the loser reordered g to the front and added z.
/// Merged list: winner order, then the loser's extras that no marker covers; no duplicates.
#[test]
fn fo08_markers_filter_loser_extras() {
    let mut n = Net::new(2);
    let (id, [f, g, h]) = n.seed(1000);
    let z = Field::new("z", FieldKind::Text, pw("z"), 2500);
    let zid = z.id;
    n.devs[1]
        .update(id, 2500, move |it| {
            it.fields.push(z);
            arrange(it, &[g, zid, h, f]);
        })
        .unwrap();
    n.devs[0]
        .update(id, 3000, |it| arrange(it, &[h, f, g]))
        .unwrap();
    n.devs[0].remove_field(id, g, 3000).unwrap();
    n.exchange(0, 1);
    for d in 0..2 {
        assert_eq!(
            order(&n.devs[d], id),
            vec![h, f, zid],
            "dev {d}: {:?}",
            names(&n.devs[d], id)
        );
    }
    n.exchange(0, 1);
    assert_eq!(n.converged(), None);
}

// ---------------------------------------------------------------------------------------------
// Merge laws (00 roadmap item 2) on random scripts that include reorders, which the 2026-11-01
// generator in merge_laws.rs does not produce.
// ---------------------------------------------------------------------------------------------

fn step(n: &mut Net, rng: &mut StdRng, d: usize, now: u64, ids: &[Uuid]) -> &'static str {
    let id = ids[rng.gen_range(0..ids.len())];
    let fields: Vec<Uuid> = n.devs[d]
        .get(id)
        .map(|it| it.fields.iter().map(|f| f.id).collect())
        .unwrap_or_default();
    let v = &mut n.devs[d];
    let pick = |rng: &mut StdRng| fields.get(rng.gen_range(0..fields.len().max(1))).copied();
    match rng.gen_range(0..14) {
        0..=2 => {
            let mut p = fields.clone();
            p.shuffle(rng);
            let _ = v.update(id, now, |it| arrange(it, &p));
            "shuffle"
        }
        3 | 4 => {
            if !fields.is_empty() {
                let from = rng.gen_range(0..fields.len());
                let to = rng.gen_range(0..fields.len());
                let _ = v.update(id, now, |it| {
                    let f = it.fields.remove(from);
                    it.fields.insert(to.min(it.fields.len()), f);
                });
            }
            "move one"
        }
        5 | 6 => {
            if let Some(f) = pick(rng) {
                let s = format!("v{}", rng.gen_range(0..5));
                let _ = v.set_field(id, f, pw(&s), now);
            }
            "set_field"
        }
        7 => {
            let at = rng.gen_range(0..=fields.len());
            let nm = ["n", "", "Password"][rng.gen_range(0..3)];
            let _ = v.update(id, now, |it| {
                let f = Field::new(nm, FieldKind::Text, pw("new"), now);
                it.fields.insert(at.min(it.fields.len()), f);
            });
            "insert field at position"
        }
        8 => {
            if let Some(f) = pick(rng) {
                let _ = v.remove_field(id, f, now);
            }
            "remove_field"
        }
        9 => {
            let t = format!("t{}", rng.gen_range(0..3));
            let _ = v.update(id, now, |it| it.title = t);
            "title"
        }
        10 => {
            if rng.gen_bool(0.3) {
                let _ = v.delete(id, now);
            }
            "delete"
        }
        _ => {
            let o = rng.gen_range(0..n.devs.len());
            if o != d {
                n.pull(d, o);
            }
            "pull"
        }
    }
}

fn script(seed: u64, nd: usize, steps: usize) -> Net {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut n = Net::new(nd);
    let d0 = n.devs[0].device_id();
    let mut ids = vec![];
    for k in 0..2u64 {
        let mut it = Item::new(format!("s{k}"), d0, 1000);
        for nm in ["a", "b", "c", "d"] {
            it.fields
                .push(Field::new(nm, FieldKind::Text, pw("0"), 1000));
        }
        ids.push(n.devs[0].insert(it, 1000));
    }
    n.round();
    let mut clock = vec![2000u64; nd];
    for _ in 0..steps {
        let d = rng.gen_range(0..nd);
        clock[d] = match rng.gen_range(0..10) {
            0 => *clock.iter().max().unwrap(),
            _ => clock[d] + rng.gen_range(1..20),
        };
        step(&mut n, &mut rng, d, clock[d], &ids);
    }
    n
}

/// 00 roadmap 2 laws, now with field reorders: one exchange → content (incl. order) equal within
/// 1 ms; two → fully equal; merging the same file twice changes nothing; N devices converge in N
/// rounds and stay there.
#[test]
fn fo09_merge_laws_with_reorders() {
    let mut bad = vec![];
    for seed in 0..120u64 {
        let nd = 2 + (seed % 2) as usize;
        let n = script(70_000 + seed, nd, 50);
        for i in 0..nd {
            for j in (i + 1)..nd {
                let (fx, fy) = (n.file(i), n.file(j));
                let mut x1 = n.open_as(&fx, i);
                let mut y1 = n.open_as(&fy, j);
                x1.merge_from(&n.open_as(&fy, i)).unwrap();
                y1.merge_from(&n.open_as(&fx, j)).unwrap();
                let (bx, by) = (x1.serialize(), y1.serialize());
                if let Some(e) = compare(&plain(&bx, &n.key), &plain(&by, &n.key), 1) {
                    bad.push(format!("seed {seed} pair {i}{j} one exchange: {e}"));
                }
                let mut x2 = n.open_as(&bx, i);
                let mut y2 = n.open_as(&by, j);
                x2.merge_from(&n.open_as(&by, i)).unwrap();
                y2.merge_from(&n.open_as(&bx, j)).unwrap();
                if let Some(e) = compare(
                    &plain(&x2.serialize(), &n.key),
                    &plain(&y2.serialize(), &n.key),
                    0,
                ) {
                    bad.push(format!("seed {seed} pair {i}{j} two exchanges: {e}"));
                }
                let mut x3 = n.open_as(&bx, i);
                let rep = x3.merge_from(&n.open_as(&fy, i)).unwrap();
                if compare(&plain(&bx, &n.key), &plain(&x3.serialize(), &n.key), 0).is_some()
                    || rep.added + rep.updated + rep.deleted > 0
                {
                    bad.push(format!("seed {seed} pair {i}{j}: not idempotent {rep:?}"));
                }
            }
        }
        let mut n = n;
        for _ in 0..nd {
            n.round();
        }
        if let Some(e) = n.converged() {
            bad.push(format!("seed {seed}: {nd} devices after {nd} rounds: {e}"));
        }
        let s0 = n.state(0);
        n.round();
        if let Some(e) = compare(&s0, &n.state(0), 0) {
            bad.push(format!("seed {seed}: extra round moved state: {e}"));
        }
    }
    let total = bad.len();
    bad.truncate(20);
    assert!(total == 0, "{total} violations:\n{}", bad.join("\n"));
}

// ---------------------------------------------------------------------------------------------
// Sync: two handles on one folder, and conflict copies of both shapes carrying a reorder.
// ---------------------------------------------------------------------------------------------
use spec_checks::dev::{Dev, PW, now_ms, read_vault};

/// F2 through vault-sync: A's reorder reaches disk and B's next save (pre-write merge) keeps it;
/// A's watcher then sees B's item.
#[test]
fn fo10_two_handles_reorder_survives_peer_save() {
    let d = tempdir();
    let p = d.path().join("fo.vault");
    let mut a = Dev::create(&p);
    let id = a.add_login("Item", now_ms());
    a.s.save().unwrap();
    let mut b = Dev::open(&p);
    let before = order(b.v(), id);
    let mut want = before.clone();
    want.reverse();
    let w = want.clone();
    a.s.edit(move |v| v.update(id, now_ms(), |it| arrange(it, &w)))
        .unwrap()
        .unwrap();
    a.s.save().unwrap();
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    let other = b.add_login("Other", now_ms());
    b.s.save().unwrap();
    assert_eq!(order(b.v(), id), want, "B's memory after pre-write merge");
    let disk = read_vault(&p);
    assert_eq!(order(&disk, id), want, "disk after B's save");
    assert!(disk.get(other).is_some());
    let t = std::time::Instant::now();
    while t.elapsed() < std::time::Duration::from_secs(15) && a.v().get(other).is_none() {
        a.drain();
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        a.v().get(other).is_some(),
        "A's watcher did not merge B's item; events {:?}",
        a.seen
    );
    assert_eq!(order(a.v(), id), want);
}

fn vault_bin() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/vault")
}
fn cli_cmd(pkg: &Path, args: &[&str], env: &[(&str, &str)]) -> Command {
    let mut c = Command::new(vault_bin());
    c.arg("--vault")
        .arg(pkg)
        .args(["--password-env", "QA_MPW"])
        .args(args)
        .env("QA_MPW", PW)
        .env_remove("VAULT_FILE")
        .env_remove("VAULT_DEVICE_ID");
    for (k, v) in env {
        c.env(k, v);
    }
    c
}
fn cli(pkg: &Path, args: &[&str]) -> (i32, String) {
    let out = cli_cmd(pkg, args, &[]).output().unwrap();
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), s)
}
fn spawn(pkg: &Path, args: &[&str], env: &[(&str, &str)]) -> Child {
    cli_cmd(pkg, args, env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}
fn finish(c: Child) -> (i32, String) {
    let o = c.wait_with_output().unwrap();
    let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&o.stderr));
    (o.status.code().unwrap_or(-1), s)
}
fn peer_copy(pkg: &Path, f: impl FnOnce(&mut UnlockedVault, u64)) -> Vec<u8> {
    let mut v = read_vault(pkg);
    f(&mut v, now_ms());
    v.serialize()
}

/// 03 §6 both shapes + F2: a newer reorder arriving in an in-package `vault 2.bin` and then in a
/// sibling `fo 2.vault/` is adopted by `vault sync`, and both copies move into `backups/`.
#[test]
fn fo11_conflict_copies_both_shapes_carry_reorder() {
    let d = tempdir();
    let p = d.path().join("fo.vault");
    let mut a = Dev::create(&p);
    let id = a.add_login("Item", now_ms());
    a.s.edit(|v| {
        v.update(id, now_ms(), |it| {
            it.fields.push(Field::new(
                "url",
                FieldKind::Url,
                pw("https://e.x"),
                now_ms(),
            ))
        })
    })
    .unwrap()
    .unwrap();
    a.s.save().unwrap();
    drop(a);
    let o0 = order(&read_vault(&p), id);
    let w1 = vec![o0[2], o0[0], o0[1]];
    let w = w1.clone();
    std::thread::sleep(std::time::Duration::from_millis(5));
    let b = peer_copy(&p, |v, now| {
        v.update(id, now, |it| arrange(it, &w)).unwrap()
    });
    std::fs::write(p.join("vault 2.bin"), b).unwrap();
    let (rc, o) = cli(&p, &["sync"]);
    assert_eq!(rc, 0, "{o}");
    assert_eq!(order(&read_vault(&p), id), w1, "per-file copy reorder");
    assert!(!p.join("vault 2.bin").exists(), "per-file copy not moved");
    // sibling package
    std::thread::sleep(std::time::Duration::from_millis(5));
    let w2 = vec![o0[1], o0[2], o0[0]];
    let w = w2.clone();
    let sib = d.path().join("fo 2.vault");
    std::fs::create_dir_all(&sib).unwrap();
    let b = peer_copy(&p, |v, now| {
        v.update(id, now, |it| arrange(it, &w)).unwrap()
    });
    std::fs::write(sib.join("vault.bin"), b).unwrap();
    let (rc, o) = cli(&p, &["sync"]);
    assert_eq!(rc, 0, "{o}");
    assert_eq!(order(&read_vault(&p), id), w2, "sibling package reorder");
    assert!(!sib.exists(), "sibling package not moved");
    let bk: Vec<String> = dev::ls(&p.join("backups"));
    assert!(
        bk.iter().filter(|x| x.starts_with("conflict-")).count() >= 2,
        "{bk:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Concurrent CLI edits of one item (C1, C2).
// ---------------------------------------------------------------------------------------------

fn cli_pkg(d: &Path) -> (PathBuf, Uuid) {
    let p = d.join("cc.vault");
    let mut a = Dev::create(&p);
    a.s.save().unwrap();
    drop(a);
    let (rc, o) = cli(
        &p,
        &[
            "add",
            "--title",
            "Item",
            "--username",
            "u0",
            "--url",
            "https://e.x",
            "--tag",
            "base",
        ],
    );
    assert_eq!(rc, 0, "{o}");
    let v = read_vault(&p);
    let id = v.items().find(|i| i.title == "Item").unwrap().id;
    (p, id)
}

/// C1: parallel `edit --tag tN` on one item: every process reports success; the surviving list is
/// one that some process wrote (base + its own tag, or a merge-safe superset); never empty, never
/// with a foreign tag.
#[test]
fn fo12_cli_concurrent_same_attribute() {
    let d = tempdir();
    let (p, id) = cli_pkg(d.path());
    let kids: Vec<Child> = (1..=6)
        .map(|k| spawn(&p, &["edit", "Item", "--tag", &format!("t{k}")], &[]))
        .collect();
    let res: Vec<(i32, String)> = kids.into_iter().map(finish).collect();
    for (rc, o) in &res {
        assert_eq!(*rc, 0, "C1: every process reports success: {o}");
    }
    let v = read_vault(&p);
    let tags = &v.get(id).unwrap().tags;
    assert!(tags.iter().any(|t| t == "base"), "base tag lost: {tags:?}");
    let new: Vec<&String> = tags.iter().filter(|t| t.starts_with('t')).collect();
    assert!(!new.is_empty(), "every tag lost: {tags:?}");
    for t in tags {
        // "login" is the template tag the CLI's default login template adds (05 §2.3)
        assert!(
            t == "base" || t == "login" || (t.len() == 2 && t.starts_with('t')),
            "foreign tag {t}"
        );
    }
    eprintln!("INFO C1: {} of 6 concurrent tags survived", new.len());
}

/// C2 + 01 §4 per-attribute stamps: concurrent edits of DIFFERENT attributes and fields of one item
/// (title, favorite, tags, icon, two different fields) from six processes all survive. Repeated to
/// give the interleavings a chance.
#[test]
fn fo13_cli_concurrent_distinct_attributes_all_survive() {
    let mut failures = vec![];
    for rep in 0..4 {
        let d = tempdir();
        let (p, id) = cli_pkg(d.path());
        let secret = format!("Env-Secret-{rep}-x");
        let jobs: Vec<Vec<String>> = vec![
            vec!["--title".into(), format!("Renamed{rep}")],
            vec!["--favorite".into()],
            vec!["--tag".into(), "solo".into()],
            vec!["--icon".into(), "symbol:Star".into()],
            vec!["--set".into(), format!("username=user{rep}")],
            vec!["--set-env".into(), "url=QA_URL".into()],
            vec!["--set-env".into(), "password=QA_SECRET".into()],
        ];
        let url = format!("https://r{rep}.example");
        // by id, not title: the title job renames the item while the others still resolve it
        let id_arg = id.to_string();
        let kids: Vec<Child> = jobs
            .iter()
            .map(|j| {
                let mut args = vec!["edit", id_arg.as_str()];
                args.extend(j.iter().map(|s| s.as_str()));
                spawn(&p, &args, &[("QA_URL", &url), ("QA_SECRET", &secret)])
            })
            .collect();
        let res: Vec<(i32, String)> = kids.into_iter().map(finish).collect();
        for (k, (rc, o)) in res.iter().enumerate() {
            if *rc != 0 {
                failures.push(format!("rep {rep} job {k}: rc {rc}: {o}"));
            }
            if o.contains(&secret) {
                failures.push(format!("rep {rep} job {k}: secret echoed"));
            }
        }
        let v = read_vault(&p);
        let it = v.get(id).unwrap();
        let field = |n: &str| {
            it.fields
                .iter()
                .find(|f| f.name.eq_ignore_ascii_case(n))
                .map(|f| f.value.expose_secret().clone())
        };
        let mut lost = vec![];
        if it.title != format!("Renamed{rep}") {
            lost.push("title");
        }
        if !it.favorite {
            lost.push("favorite");
        }
        if !it.tags.iter().any(|t| t == "solo") {
            lost.push("tag");
        }
        if it.icon.as_ref().map(|i| i.value.as_str()) != Some("Star") {
            lost.push("icon");
        }
        if field("username") != Some(format!("user{rep}")) {
            lost.push("username");
        }
        if field("url").or_else(|| field("website")) != Some(url.clone()) {
            lost.push("url");
        }
        if field("password") != Some(secret.clone()) {
            lost.push("password");
        }
        if !lost.is_empty() {
            failures.push(format!("rep {rep}: lost {lost:?}"));
        }
    }
    assert!(failures.is_empty(), "C2 violated:\n{}", failures.join("\n"));
}
