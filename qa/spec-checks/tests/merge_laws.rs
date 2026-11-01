//! Merge laws as restated in 00-overview.md "Testing roadmap" item 2 (2026-11-01), checked with
//! this ledger's own seeded generator (written before reading the project's merge_props.rs):
//!
//! - "commutativity (content equal after one exchange with `modified_at` within 1 ms, fully equal
//!   after two ...)"
//! - "idempotence"
//! - "convergence of N devices within N rounds (N+1 when the `removed_fields` cap fires)"
//! - "`modified_at` never decreases and attribute/field stamps never decrease while an item stays
//!   live (a tombstone win replaces the item wholesale)"
//! - "guarantee 9 incl. resurrection" (02 guarantee 9; 03 §5 tombstone row).
//!
//! "Content" here is the decrypted ItemPlain (canonical CBOR) of every item, which carries the
//! per-attribute stamps (01 §4), field stamps, markers, refs and history; "fully equal" adds the
//! record `modified_at`. A "round" is simultaneous: every device reads every other device's file
//! as it was at the start of the round, then merges them in device order. Passing shows the laws
//! hold on these generated scripts only; it is not a proof.
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use spec_checks::*;
use std::collections::BTreeMap;
use uuid::Uuid;
use vault_core::*;

type Plain = BTreeMap<[u8; 16], (u64, Value)>;

/// Decrypts every item record of `bytes` with the spec's HKDF item key (01 §3, §4).
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

fn is_live(p: &Value) -> bool {
    matches!(get(p, "deleted_at"), None | Some(Value::Null))
}

/// 01 §4: "a missing stamp reads as the item's modified_at".
fn attr_stamp(p: &Value, ma: u64, k: &str) -> u64 {
    match get(p, k) {
        Some(Value::Integer(_)) => u64_of(get(p, k).unwrap()),
        _ => ma,
    }
}

fn field_stamps(p: &Value) -> BTreeMap<Vec<u8>, u64> {
    let mut m = BTreeMap::new();
    if let Some(Value::Array(fs)) = get(p, "fields") {
        for f in fs {
            if let (Some(id), Some(ma)) = (get(f, "id"), get(f, "modified_at")) {
                m.insert(bytes_of(id), u64_of(ma));
            }
        }
    }
    m
}

/// Names of the ItemPlain keys whose values differ (values are not printed).
fn diff_keys(a: &Value, b: &Value) -> Vec<String> {
    let mut keys: Vec<String> = vec![];
    for src in [a, b] {
        if let Value::Map(e) = src {
            for (k, _) in e {
                if let Some(k) = k.as_text() {
                    if !keys.iter().any(|x| x == k) {
                        keys.push(k.to_string());
                    }
                }
            }
        }
    }
    keys.into_iter()
        .filter(|k| get(a, k).map(enc) != get(b, k).map(enc))
        .collect()
}

/// Compares two decrypted states. `ma_slack` = allowed |modified_at| difference.
fn compare(x: &Plain, y: &Plain, ma_slack: u64) -> Option<String> {
    if x.keys().collect::<Vec<_>>() != y.keys().collect::<Vec<_>>() {
        return Some(format!("item sets differ ({} vs {})", x.len(), y.len()));
    }
    for (id, (ma_x, px)) in x {
        let (ma_y, py) = &y[id];
        if ma_x.abs_diff(*ma_y) > ma_slack {
            return Some(format!(
                "item {}: modified_at {ma_x} vs {ma_y} (slack {ma_slack})",
                Uuid::from_bytes(*id)
            ));
        }
        if enc(px) != enc(py) {
            return Some(format!(
                "item {}: ItemPlain differs in {:?}",
                Uuid::from_bytes(*id),
                diff_keys(px, py)
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
    fn new(n: usize) -> Net {
        let base = UnlockedVault::create(&pw("laws"), KdfParams::for_tests(), Uuid::new_v4());
        let bytes = base.serialize();
        let key = indep::open_file(&bytes, "laws").vault_key;
        let l = LockedVault::parse(&bytes).unwrap();
        let k = base.export_vault_key();
        Net {
            devs: (0..n)
                .map(|_| l.unlock_with_key(&k, Uuid::new_v4()).unwrap())
                .collect(),
            key,
        }
    }
    fn file(&self, d: usize) -> Vec<u8> {
        self.devs[d].serialize()
    }
    /// What device `as_dev` gets when it reads `bytes`.
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
    /// One simultaneous round: everyone reads everyone's file first, then merges in order.
    fn round(&mut self) {
        let n = self.devs.len();
        let files: Vec<Vec<u8>> = (0..n).map(|d| self.file(d)).collect();
        for to in 0..n {
            for (from, f) in files.iter().enumerate() {
                if from != to {
                    let theirs = self.open_as(f, to);
                    self.devs[to].merge_from(&theirs).unwrap();
                }
            }
        }
    }
}

const NAMES: [&str; 5] = ["username", "password", "Password", "", "note"];
const KINDS: [FieldKind; 5] = [
    FieldKind::Text,
    FieldKind::Password,
    FieldKind::Url,
    FieldKind::Notes,
    FieldKind::Section,
];

fn val(rng: &mut StdRng) -> String {
    let pool = ["a", "b", "é", "e\u{301}", "🔑", " ", "x"];
    (0..rng.gen_range(0..4))
        .map(|_| pool[rng.gen_range(0..pool.len())])
        .collect()
}

/// One random operation by device `d` at its clock `now`. Errors (e.g. a deleted item) are ignored;
/// they are not what is checked here. Returns a label for failure messages.
fn step(n: &mut Net, rng: &mut StdRng, d: usize, now: u64, ids: &mut Vec<Uuid>) -> &'static str {
    let id = ids[rng.gen_range(0..ids.len())];
    let v = &mut n.devs[d];
    let fields: Vec<Uuid> = v
        .get(id)
        .map(|it| it.fields.iter().map(|f| f.id).collect())
        .unwrap_or_default();
    let pick = |rng: &mut StdRng| -> Option<Uuid> {
        if fields.is_empty() {
            None
        } else {
            Some(fields[rng.gen_range(0..fields.len())])
        }
    };
    match rng.gen_range(0..17) {
        0 => {
            let dev = v.device_id();
            let mut it = Item::new(format!("i{now}"), dev, now);
            it.fields
                .push(Field::new("username", FieldKind::Text, pw("u"), now));
            it.fields
                .push(Field::new("password", FieldKind::Password, pw("p"), now));
            ids.push(v.insert(it, now));
            "insert"
        }
        1 | 2 => {
            if let Some(f) = pick(rng) {
                let s = val(rng);
                let _ = v.set_field(id, f, pw(&s), now);
            }
            "set_field"
        }
        3 => {
            let s = val(rng);
            let _ = v.set_field_named(id, "password", pw(&s), now);
            "set_field_named(password)"
        }
        4 => {
            let name = NAMES[rng.gen_range(0..NAMES.len())].to_string();
            let kind = KINDS[rng.gen_range(0..KINDS.len())];
            let s = val(rng);
            let _ = v.update(id, now, |it| {
                it.fields.push(Field::new(name, kind, pw(&s), now))
            });
            "add field"
        }
        5 => {
            if let Some(f) = pick(rng) {
                let _ = v.remove_field(id, f, now);
            }
            "remove_field"
        }
        6 => {
            if let Some(f) = pick(rng) {
                let name = NAMES[rng.gen_range(0..NAMES.len())].to_string();
                let _ = v.update(id, now, |it| {
                    if let Some(x) = it.fields.iter_mut().find(|x| x.id == f) {
                        x.name = name;
                    }
                });
            }
            "rename field"
        }
        7 => {
            let t = format!("t{}", rng.gen_range(0..4));
            let _ = v.update(id, now, |it| it.title = t);
            "title"
        }
        8 => {
            let _ = v.update(id, now, |it| it.favorite = !it.favorite);
            "favorite"
        }
        9 => {
            let tag = ["a", "b", "c"][rng.gen_range(0..3)].to_string();
            let rev = rng.gen_bool(0.3);
            let _ = v.update(id, now, |it| {
                if rev {
                    it.tags.reverse();
                } else if let Some(p) = it.tags.iter().position(|x| *x == tag) {
                    it.tags.remove(p);
                } else {
                    it.tags.push(tag);
                }
            });
            "tags"
        }
        10 => {
            let sym = ["star", "key", ""][rng.gen_range(0..3)].to_string();
            let _ = v.update(id, now, |it| {
                it.icon = if sym.is_empty() {
                    None
                } else {
                    Some(ItemIcon::new("symbol", &sym))
                }
            });
            "icon"
        }
        11 => {
            if let Ok(r) = attachment::new_ref("f", 3, now) {
                let _ = v.add_attachment_ref(id, r, now);
            }
            "add_attachment_ref"
        }
        12 => {
            let refs: Vec<Uuid> = v
                .get(id)
                .map(|it| it.attachments.iter().map(|a| a.id).collect())
                .unwrap_or_default();
            if !refs.is_empty() {
                let r = refs[rng.gen_range(0..refs.len())];
                let _ = v.remove_attachment_ref(id, r, now);
            }
            "remove_attachment_ref"
        }
        13 => {
            let _ = v.delete(id, now);
            "delete"
        }
        _ => {
            let nd = n.devs.len();
            let o = rng.gen_range(0..nd);
            if o != d {
                let f = n.file(o);
                let theirs = n.open_as(&f, d);
                n.devs[d].merge_from(&theirs).unwrap();
            }
            "pull"
        }
    }
}

/// Monotonicity between two states of one device (roadmap item 2, fourth law).
fn monotone(before: &Plain, after: &Plain) -> Option<String> {
    for (id, (ma0, p0)) in before {
        let Some((ma1, p1)) = after.get(id) else {
            return Some(format!("item {} vanished", Uuid::from_bytes(*id)));
        };
        if ma1 < ma0 {
            return Some(format!(
                "item {}: modified_at decreased {ma0} -> {ma1}",
                Uuid::from_bytes(*id)
            ));
        }
        if is_live(p0) && is_live(p1) {
            for k in [
                "title_modified_at",
                "favorite_modified_at",
                "tags_modified_at",
                "icon_modified_at",
            ] {
                let (a, b) = (attr_stamp(p0, *ma0, k), attr_stamp(p1, *ma1, k));
                if b < a {
                    return Some(format!(
                        "item {}: {k} decreased {a} -> {b} while live",
                        Uuid::from_bytes(*id)
                    ));
                }
            }
            let (f0, f1) = (field_stamps(p0), field_stamps(p1));
            for (fid, s0) in &f0 {
                if let Some(s1) = f1.get(fid) {
                    if s1 < s0 {
                        return Some(format!(
                            "item {}: field stamp decreased {s0} -> {s1} while live",
                            Uuid::from_bytes(*id)
                        ));
                    }
                }
            }
        }
    }
    None
}

/// Runs one seeded script; returns the network and the monotonicity failures seen on the way.
fn script(seed: u64, nd: usize, steps: usize) -> (Net, Vec<String>) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut n = Net::new(nd);
    let mut ids = vec![];
    let d0 = n.devs[0].device_id();
    for k in 0..3u64 {
        let mut it = Item::new(format!("seed{k}"), d0, 1_000);
        it.fields
            .push(Field::new("username", FieldKind::Text, pw("u0"), 1_000));
        it.fields
            .push(Field::new("password", FieldKind::Password, pw("p0"), 1_000));
        ids.push(n.devs[0].insert(it, 1_000));
    }
    n.round();
    let mut clock = vec![2_000u64; nd];
    let mut bad = vec![];
    for s in 0..steps {
        let d = rng.gen_range(0..nd);
        clock[d] = match rng.gen_range(0..12) {
            0 => clock[d].saturating_sub(100), // clock went backwards
            1 => *clock.iter().max().unwrap(), // exact tie with the fastest device
            _ => clock[d] + rng.gen_range(1..25),
        };
        let now = clock[d];
        let before = n.state(d);
        let op = step(&mut n, &mut rng, d, now, &mut ids);
        let after = n.state(d);
        if let Some(e) = monotone(&before, &after) {
            bad.push(format!("seed {seed} step {s} dev {d} op {op}: {e}"));
        }
    }
    (n, bad)
}

/// 00 roadmap 2: commutativity, idempotence, monotonicity over 2- and 3-device scripts.
#[test]
fn ml01_commutativity_idempotence_monotonicity() {
    let mut bad: Vec<String> = vec![];
    for seed in 0..80u64 {
        let nd = 2 + (seed % 2) as usize;
        let (n, mono) = script(1_000 + seed, nd, 45);
        bad.extend(mono);
        for i in 0..nd {
            for j in (i + 1)..nd {
                let (fx, fy) = (n.file(i), n.file(j));
                // one exchange: x' = x <- y, y' = y <- x, both from the original files
                let mut x1 = n.open_as(&fx, i);
                let mut y1 = n.open_as(&fy, j);
                x1.merge_from(&n.open_as(&fy, i)).unwrap();
                y1.merge_from(&n.open_as(&fx, j)).unwrap();
                let (bx1, by1) = (x1.serialize(), y1.serialize());
                if let Some(e) = compare(&plain(&bx1, &n.key), &plain(&by1, &n.key), 1) {
                    bad.push(format!(
                        "seed {seed} pair {i}{j}: after one exchange not content-equal within 1 ms: {e}"
                    ));
                }
                // second exchange: fully equal
                let mut x2 = n.open_as(&bx1, i);
                let mut y2 = n.open_as(&by1, j);
                x2.merge_from(&n.open_as(&by1, i)).unwrap();
                y2.merge_from(&n.open_as(&bx1, j)).unwrap();
                if let Some(e) = compare(
                    &plain(&x2.serialize(), &n.key),
                    &plain(&y2.serialize(), &n.key),
                    0,
                ) {
                    bad.push(format!(
                        "seed {seed} pair {i}{j}: not fully equal after two exchanges: {e}"
                    ));
                }
                // idempotence: (x <- y) <- y == x <- y
                let mut x3 = n.open_as(&bx1, i);
                let rep = x3.merge_from(&n.open_as(&fy, i)).unwrap();
                if let Some(e) = compare(&plain(&bx1, &n.key), &plain(&x3.serialize(), &n.key), 0) {
                    bad.push(format!(
                        "seed {seed} pair {i}{j}: merging the same file twice changed state: {e}"
                    ));
                }
                if rep.added + rep.updated + rep.deleted > 0 || rep.header_updated {
                    bad.push(format!(
                        "seed {seed} pair {i}{j}: second identical merge reports changes {rep:?}"
                    ));
                }
            }
            // idempotence with itself
            let f = n.file(i);
            let mut x = n.open_as(&f, i);
            let rep = x.merge_from(&n.open_as(&f, i)).unwrap();
            if let Some(e) = compare(&plain(&f, &n.key), &plain(&x.serialize(), &n.key), 0) {
                bad.push(format!("seed {seed} dev {i}: x <- x changed state: {e}"));
            }
            if rep.added + rep.updated + rep.deleted > 0 || rep.header_updated {
                bad.push(format!("seed {seed} dev {i}: x <- x reports {rep:?}"));
            }
        }
    }
    bad.dedup();
    let total = bad.len();
    bad.truncate(25);
    assert!(total == 0, "{total} violations, first:\n{}", bad.join("\n"));
}

/// 00 roadmap 2: "convergence of N devices within N rounds". Scripts stay far below 64 removals
/// per item, so the `removed_fields` cap does not fire and the bound is N.
#[test]
fn ml02_convergence_within_n_rounds() {
    let mut bad: Vec<String> = vec![];
    for seed in 0..80u64 {
        let nd = 2 + (seed % 2) as usize;
        let (mut n, _) = script(5_000 + seed, nd, 45);
        for _ in 0..nd {
            n.round();
        }
        let s0 = n.state(0);
        for d in 1..nd {
            if let Some(e) = compare(&s0, &n.state(d), 0) {
                bad.push(format!(
                    "seed {seed}: {nd} devices not equal after {nd} rounds (dev 0 vs {d}): {e}"
                ));
            }
        }
        // and further rounds change nothing (fixpoint)
        n.round();
        if let Some(e) = compare(&s0, &n.state(0), 0) {
            bad.push(format!(
                "seed {seed}: extra round changed the converged state: {e}"
            ));
        }
    }
    let total = bad.len();
    bad.truncate(25);
    assert!(total == 0, "{total} violations, first:\n{}", bad.join("\n"));
}

/// 02 guarantee 9 "delete then merge_from an older copy that still has the item -> item stays
/// deleted", and 03 §5 "edit after delete resurrects", on random states from the generator.
#[test]
fn ml03_guarantee9_and_resurrection_on_random_states() {
    let mut bad: Vec<String> = vec![];
    for seed in 0..40u64 {
        let (mut n, _) = script(9_000 + seed, 2, 30);
        n.round();
        n.round();
        let live: Vec<Uuid> = n.devs[0].items().map(|i| i.id).collect();
        if live.is_empty() {
            continue;
        }
        let id = live[seed as usize % live.len()];
        let old = n.file(0);
        let t_del = n.devs[0].get(id).unwrap().modified_at + 1_000;
        n.devs[0].delete(id, t_del).unwrap();
        let older = n.open_as(&old, 0);
        n.devs[0].merge_from(&older).unwrap();
        if n.devs[0].get(id).map(|i| i.deleted_at.is_some()) != Some(true) {
            bad.push(format!(
                "seed {seed}: older copy undid the delete (guarantee 9)"
            ));
        }
        // device 1 never saw the delete and edits strictly later: the edit resurrects
        let t_edit = t_del + 50;
        n.devs[1]
            .update(id, t_edit, |it| it.title = "resurrected".into())
            .unwrap();
        n.round();
        n.round();
        for d in 0..2 {
            let it = n.devs[d].get(id).unwrap();
            if it.deleted_at.is_some() || it.title != "resurrected" {
                bad.push(format!(
                    "seed {seed} dev {d}: edit after delete did not resurrect (deleted={})",
                    it.deleted_at.is_some()
                ));
            }
        }
        // the delete strictly after an older edit wins wholesale on both
        let t2 = n.devs[0].get(id).unwrap().modified_at;
        n.devs[1]
            .update(id, t2 + 10, |it| it.favorite = !it.favorite)
            .unwrap();
        n.devs[0].delete(id, t2 + 20).unwrap();
        n.round();
        n.round();
        for d in 0..2 {
            if n.devs[d].get(id).map(|i| i.deleted_at.is_some()) != Some(true) {
                bad.push(format!(
                    "seed {seed} dev {d}: later delete lost to older edit"
                ));
            }
        }
        if let Some(e) = compare(&n.state(0), &n.state(1), 0) {
            bad.push(format!(
                "seed {seed}: not converged after delete/resurrect: {e}"
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §5 "title, favorite, tags (as one ordered list; a reorder counts as a change) and icon are
/// each merged by their own stamp": concurrent edits of four different attributes on three
/// devices all survive, in every pull order, and a tag reorder alone propagates.
#[test]
fn ml04_per_attribute_stamps_three_devices() {
    let orders: [[usize; 3]; 3] = [[0, 1, 2], [2, 1, 0], [1, 2, 0]];
    let mut bad = vec![];
    for ord in orders {
        let mut n = Net::new(3);
        let d0 = n.devs[0].device_id();
        let mut it = Item::new("base", d0, 1_000);
        it.tags = vec!["x".into(), "y".into()];
        let id = n.devs[0].insert(it, 1_000);
        n.round();
        n.devs[0]
            .update(id, 2_000, |it| it.title = "A title".into())
            .unwrap();
        n.devs[1]
            .update(id, 2_100, |it| it.favorite = true)
            .unwrap();
        n.devs[2]
            .update(id, 2_200, |it| {
                it.icon = Some(ItemIcon::new("symbol", "key"))
            })
            .unwrap();
        // a later, unrelated edit on device 0 must not drag device 0's older tags/icon along
        n.devs[0].update(id, 2_300, |it| it.tags.reverse()).unwrap();
        for _ in 0..3 {
            for &to in &ord {
                for from in 0..3 {
                    if from != to {
                        let f = n.file(from);
                        let th = n.open_as(&f, to);
                        n.devs[to].merge_from(&th).unwrap();
                    }
                }
            }
        }
        for d in 0..3 {
            let it = n.devs[d].get(id).unwrap();
            let got = (
                it.title.as_str(),
                it.favorite,
                it.icon.as_ref().map(|c| c.value.as_str()),
                it.tags.clone(),
            );
            if got
                != (
                    "A title",
                    true,
                    Some("key"),
                    vec!["y".to_string(), "x".to_string()],
                )
            {
                bad.push(format!("order {ord:?} dev {d}: {got:?}"));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §5 (2026-11-01): "a merge caps them at 64 by dropping, oldest `removed_at` first, only
/// markers whose reference neither side still holds". Device 1 still holds the 10 OLDEST removed
/// refs, so their markers must survive the cap in both merge directions (and the refs go).
#[test]
fn ml05_removed_attachments_cap_spares_referenced_markers() {
    let mut n = Net::new(2);
    let d0 = n.devs[0].device_id();
    let id = n.devs[0].insert(Item::new("att", d0, 100), 100);
    let mut held = vec![];
    for k in 0..10u64 {
        let r = attachment::new_ref("held", 1, 200 + k).unwrap();
        held.push(r.id);
        n.devs[0].add_attachment_ref(id, r, 200 + k).unwrap();
    }
    n.round();
    assert_eq!(n.devs[1].get(id).unwrap().attachments.len(), 10);
    let dev1_file = n.file(1);
    for (k, r) in held.iter().enumerate() {
        n.devs[0]
            .remove_attachment_ref(id, *r, 300 + k as u64)
            .unwrap();
    }
    for k in 0..70u64 {
        let r = attachment::new_ref("gone", 1, 400 + k).unwrap();
        let rid = r.id;
        n.devs[0].add_attachment_ref(id, r, 400 + k).unwrap();
        n.devs[0].remove_attachment_ref(id, rid, 500 + k).unwrap();
    }
    assert_eq!(
        n.devs[0].get(id).unwrap().removed_attachments.len(),
        80,
        "a local removal never drops markers"
    );
    let dev0_file = n.file(0);
    let mut bad = vec![];
    for dir in ["holder<-remover", "remover<-holder"] {
        let (mut ours, theirs) = if dir == "holder<-remover" {
            (n.open_as(&dev1_file, 1), n.open_as(&dev0_file, 1))
        } else {
            (n.open_as(&dev0_file, 0), n.open_as(&dev1_file, 0))
        };
        ours.merge_from(&theirs).unwrap();
        let it = ours.get(id).unwrap();
        let markers: Vec<Uuid> = it.removed_attachments.iter().map(|t| t.id).collect();
        let missing: Vec<&Uuid> = held.iter().filter(|h| !markers.contains(h)).collect();
        if !missing.is_empty() {
            bad.push(format!(
                "{dir}: {} markers of refs one side still held were dropped by the cap (kept {})",
                missing.len(),
                markers.len()
            ));
        }
        if it.attachments.iter().any(|a| held.contains(&a.id)) {
            bad.push(format!("{dir}: removed refs survived the merge"));
        }
        if markers.len() != 64 {
            bad.push(format!(
                "{dir}: {} markers after merge, want 64",
                markers.len()
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §5 same rule when MORE than 64 removed refs are still held by one side: none of those
/// markers may go; all unreferenced ones go first.
#[test]
fn ml06_removed_attachments_cap_when_held_exceed_64() {
    let mut n = Net::new(2);
    let d0 = n.devs[0].device_id();
    let id = n.devs[0].insert(Item::new("att", d0, 100), 100);
    let mut held = vec![];
    for k in 0..70u64 {
        let r = attachment::new_ref("held", 1, 1_000 + k).unwrap();
        held.push(r.id);
        n.devs[0].add_attachment_ref(id, r, 1_000 + k).unwrap();
    }
    n.round();
    let dev1_file = n.file(1);
    for k in 0..10u64 {
        let r = attachment::new_ref("gone", 1, 200 + k).unwrap();
        let rid = r.id;
        n.devs[0].add_attachment_ref(id, r, 200 + k).unwrap();
        n.devs[0].remove_attachment_ref(id, rid, 300 + k).unwrap();
    }
    for (k, r) in held.iter().enumerate() {
        n.devs[0]
            .remove_attachment_ref(id, *r, 2_000 + k as u64)
            .unwrap();
    }
    let mut ours = n.open_as(&dev1_file, 1);
    ours.merge_from(&n.open_as(&n.file(0), 1)).unwrap();
    let it = ours.get(id).unwrap();
    let markers: Vec<Uuid> = it.removed_attachments.iter().map(|t| t.id).collect();
    let kept_held = held.iter().filter(|h| markers.contains(h)).count();
    assert_eq!(kept_held, 70, "markers of held refs dropped by the cap");
    assert_eq!(
        markers.len(),
        70,
        "the 10 unreferenced markers go first (cap 64 cannot be met)"
    );
    assert!(it.attachments.is_empty(), "every held ref was removed");
    // convergence after rounds, no ref resurrected
    n.devs[1] = ours;
    for _ in 0..3 {
        n.round();
    }
    assert!(compare(&n.state(0), &n.state(1), 0).is_none());
    assert!(n.devs[0].get(id).unwrap().attachments.is_empty());
}

/// 03 §3 "Merge is idempotent" + 03 §5 "attachments are merged by union on id (sorted by
/// added_at, then id)": two refs added locally in decreasing `added_at` order (a clock that went
/// back, or a ref built before an earlier add) leave the item in a non-canonical order, so merging
/// the vault with an exact copy of its own file changes the item and bumps modified_at.
/// Minimised from ml01 (seeds 58, 75, ...).
#[test]
fn ml07_self_merge_idempotent_with_out_of_order_refs() {
    let mut n = Net::new(1);
    let d0 = n.devs[0].device_id();
    let id = n.devs[0].insert(Item::new("att", d0, 1_000), 1_000);
    let late = attachment::new_ref("late", 1, 2_000).unwrap();
    n.devs[0].add_attachment_ref(id, late, 2_000).unwrap();
    let early = attachment::new_ref("early", 1, 1_500).unwrap();
    n.devs[0].add_attachment_ref(id, early, 2_001).unwrap();
    let f = n.file(0);
    let mut x = n.open_as(&f, 0);
    let rep = x.merge_from(&n.open_as(&f, 0)).unwrap();
    let before = plain(&f, &n.key);
    let after = plain(&x.serialize(), &n.key);
    assert!(
        rep.updated == 0 && compare(&before, &after, 0).is_none(),
        "merging a vault with a copy of its own file changed it: {rep:?}, {:?}",
        compare(&before, &after, 0)
    );
}

/// Same law as ml07 with a sane clock: two refs created in the same millisecond (e.g. two files
/// dropped at once) carry the same `added_at`; when the second has the smaller id, the local
/// order differs from the merge order "(sorted by added_at, then id)" and a self-merge changes
/// the item.
#[test]
fn ml08_self_merge_idempotent_with_same_millisecond_refs() {
    let mut n = Net::new(1);
    let d0 = n.devs[0].device_id();
    let id = n.devs[0].insert(Item::new("att", d0, 1_000), 1_000);
    let mut a = attachment::new_ref("a", 1, 2_000).unwrap();
    let mut b = attachment::new_ref("b", 1, 2_000).unwrap();
    if a.id < b.id {
        std::mem::swap(&mut a, &mut b);
    }
    n.devs[0].add_attachment_ref(id, a, 2_000).unwrap();
    n.devs[0].add_attachment_ref(id, b, 2_000).unwrap();
    let f = n.file(0);
    let mut x = n.open_as(&f, 0);
    let rep = x.merge_from(&n.open_as(&f, 0)).unwrap();
    assert!(
        rep.updated == 0,
        "self-merge changed an item whose refs share added_at: {rep:?}"
    );
}
