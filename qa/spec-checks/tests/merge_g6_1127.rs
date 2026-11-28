//! Bug hunt 2026-11-27: 02 guarantee 6 across merges (security review M-01, "symmetric rule
//! 2026-11-26"), 03 §5 restamp sentence, and the 03 §5 header merge guard (L-02), written from the
//! spec text before reading the source.
//!
//! 02 g6: "For an id on both sides the merged result is compared with both input records (content,
//! stamps, `device_id` and `created_at`): equal to ours → unchanged; equal to theirs with
//! `theirs.modified_at > ours.modified_at` → theirs' record is adopted verbatim, stamp included;
//! otherwise (a record neither side wrote, or theirs' record at a stamp equal to ours) → stamped
//! `max(ours.modified_at, theirs.modified_at) + 1`."
use rand::{Rng, SeedableRng};
use spec_checks::w1127::*;
use spec_checks::*;
use std::collections::BTreeMap;
use uuid::Uuid;
use vault_core::*;

const FPW: &str = FIXTURE_PW;
type Recs = BTreeMap<Vec<u8>, (u64, Vec<u8>, Value)>;

fn short(id: &[u8]) -> String {
    Uuid::from_slice(id).unwrap().to_string()[..8].to_string()
}

/// Checks one merge against the g6 rule. Returns violations.
fn check_merge(o: &Recs, th: &Recs, m: &Recs, label: &str) -> Vec<String> {
    let mut bad = vec![];
    for (id, (mma, mp, _)) in m {
        match (o.get(id), th.get(id)) {
            (Some((oma, op, _)), Some((tma, tp, _))) => {
                // Equal plaintexts at different record stamps are normal (a merge restamp moves
                // only the record stamp), so each branch is judged on (plain, stamp).
                let ok = (mp == op && mma == oma)
                    || (mp == tp && tma > oma && mma == tma)
                    || (*mma == (*oma).max(*tma) + 1);
                // The security core of g6: never ours' or theirs' pair with other content.
                // (Keeping ours unchanged at a stamp the peer used concurrently is the spec's own
                // "equal to ours → unchanged" branch; the collision came from two local edits.)
                let unchanged = mp == op && mma == oma;
                let reuses = !unchanged && ((mma == oma && mp != op) || (mma == tma && mp != tp));
                if !ok || reuses {
                    bad.push(format!(
                        "{label}: item {} ours@{oma} theirs@{tma} merged@{mma} (merged=ours:{} merged=theirs:{} ours=theirs:{}){}",
                        short(id),
                        mp == op,
                        mp == tp,
                        op == tp,
                        if reuses { " REUSES A PAIR WITH OTHER CONTENT" } else { "" }
                    ));
                }
            }
            (None, Some((tma, tp, _))) => {
                if (mma, mp) != (tma, tp) {
                    bad.push(format!(
                        "{label}: item {} only in theirs@{tma} not taken verbatim (@{mma})",
                        short(id)
                    ));
                }
            }
            (Some((oma, op, _)), None) => {
                if (mma, mp) != (oma, op) {
                    bad.push(format!(
                        "{label}: item {} only in ours@{oma} changed (@{mma})",
                        short(id)
                    ));
                }
            }
            (None, None) => bad.push(format!("{label}: item {} from nowhere", short(id))),
        }
    }
    bad
}

struct Sim {
    devs: Vec<UnlockedVault>,
    key: Vec<u8>,
    rng: rand::rngs::StdRng,
    /// Per device: (id, ma) → canonical plains that device has held (its own history: previous
    /// files and backups, 02 g6 "our own pre-merge record in a backup or the previous file").
    ledger: Vec<BTreeMap<(Vec<u8>, u64), Vec<Vec<u8>>>>,
    clock: u64,
}

impl Sim {
    fn new(seed: u64, n: usize) -> Sim {
        let dev0 = Uuid::new_v4();
        let mut v = UnlockedVault::create(&pw(FPW), KdfParams::for_tests(), dev0);
        for k in 0..3 {
            let mut it = Item::new(format!("seed {k}"), dev0, 100);
            it.fields
                .push(Field::new("username", FieldKind::Text, pw("u"), 100));
            it.fields
                .push(Field::new("password", FieldKind::Password, pw("p"), 100));
            v.insert(it, 100);
        }
        let b = v.serialize();
        let key = indep::open_file(&b, FPW).vault_key;
        let mut devs = vec![v];
        for _ in 1..n {
            let mut d = LockedVault::parse(&b).unwrap().unlock(&pw(FPW)).unwrap();
            d.set_device_id(Uuid::new_v4());
            devs.push(d);
        }
        Sim {
            devs,
            key,
            rng: rand::rngs::StdRng::seed_from_u64(seed),
            ledger: vec![BTreeMap::new(); n],
            clock: 200,
        }
    }
    fn recs(&mut self, d: usize) -> Recs {
        let r = records(&self.devs[d].serialize(), &self.key);
        for (id, (ma, p, _)) in &r {
            let e = self.ledger[d].entry((id.clone(), *ma)).or_default();
            if !e.contains(p) {
                e.push(p.clone());
            }
        }
        r
    }
    fn now(&mut self) -> u64 {
        // A coarse shared clock so equal stamps across devices are common.
        self.clock += self.rng.gen_range(0..3);
        self.clock
    }
    fn local_op(&mut self, d: usize) {
        let now = self.now();
        let ids: Vec<Uuid> = self.devs[d]
            .items_including_deleted()
            .map(|i| i.id)
            .collect();
        let pick = if ids.is_empty() {
            None
        } else {
            Some(ids[self.rng.gen_range(0..ids.len())])
        };
        let op = self.rng.gen_range(0..10);
        let r: u32 = self.rng.r#gen();
        let v = &mut self.devs[d];
        match (op, pick) {
            (0, _) | (_, None) => {
                let dev = v.device_id();
                let mut it = Item::new(format!("new {r}"), dev, now);
                it.fields
                    .push(Field::new("password", FieldKind::Password, pw("x"), now));
                v.insert(it, now);
            }
            (1, Some(id)) => {
                let _ = v.update(id, now, |it| it.title = format!("t{}", r % 4));
            }
            (2, Some(id)) => {
                let _ = v.update(id, now, |it| it.favorite = r % 2 == 0);
            }
            (3, Some(id)) => {
                let _ = v.update(id, now, |it| it.tags.push(format!("g{}", r % 3)));
            }
            (4, Some(id)) => {
                let _ = v.set_field_named(id, "password", pw(&format!("pw{}", r % 5)), now);
            }
            (5, Some(id)) => {
                let _ = v.set_field_named(id, "username", pw(&format!("u{}", r % 5)), now);
            }
            (6, Some(id)) => {
                let _ = v.delete(id, now);
            }
            (7, Some(id)) => {
                let _ = v.recover(id, now);
            }
            (8, Some(id)) => {
                let _ = v.delete_permanently(id, now);
            }
            (_, Some(id)) => {
                let _ = v.update(id, now, |it| {
                    if r % 2 == 0 {
                        it.fields.retain(|f| f.name != "username");
                    } else {
                        it.fields
                            .push(Field::new("extra", FieldKind::Text, pw("e"), now));
                    }
                });
            }
        }
    }
    /// Merges `from` into `to` and checks the g6 rule and the pair ledger.
    fn merge(&mut self, to: usize, from: usize, label: &str) -> (Vec<String>, usize) {
        let o = self.recs(to);
        let th = self.recs(from);
        let peer = LockedVault::parse(&self.devs[from].serialize())
            .unwrap()
            .unlock_with_key(
                &self.devs[from].export_vault_key(),
                self.devs[from].device_id(),
            )
            .unwrap();
        self.devs[to].merge_from(&peer).unwrap();
        let m = records(&self.devs[to].serialize(), &self.key);
        let mut bad = check_merge(&o, &th, &m, label);
        // ledger: the merged record never takes a pair that ours' or theirs' history used with
        // other content; a collision with a third device's concurrent pair is INFO only.
        let mut reuse_info = 0;
        for (id, (ma, p, _)) in &m {
            if o.get(id).map(|x| (&x.0, &x.1)) == Some((ma, p)) {
                continue;
            }
            for (who, dv) in [("ours", to), ("theirs", from)] {
                if let Some(seen) = self.ledger[dv].get(&(id.clone(), *ma)) {
                    if seen.iter().any(|x| x != p) && !seen.contains(p) {
                        bad.push(format!(
                            "{label}: item {} merged@{ma}: {who} history held that pair with other content",
                            short(id)
                        ));
                    }
                }
            }
            for (dv, l) in self.ledger.iter().enumerate() {
                if dv != to && dv != from {
                    if let Some(seen) = l.get(&(id.clone(), *ma)) {
                        if !seen.contains(p) {
                            reuse_info += 1;
                        }
                    }
                }
            }
        }
        let _ = self.recs(to);
        (bad, reuse_info)
    }
}

/// g6 over random 2- and 3-device scripts with a coarse shared clock (equal stamps are common).
#[test]
fn g6a_random_scripts_follow_the_restamp_rule() {
    let mut bad = vec![];
    let mut merges = 0;
    let mut reuse = 0;
    for seed in 0..60u64 {
        let n = if seed % 2 == 0 { 2 } else { 3 };
        let mut s = Sim::new(seed, n);
        for d in 0..n {
            let _ = s.recs(d);
        }
        for step in 0..40 {
            let d = s.rng.gen_range(0..n);
            if s.rng.gen_bool(0.35) {
                let e = (d + s.rng.gen_range(1..n)) % n;
                let (b, r) = s.merge(d, e, &format!("seed {seed} step {step} {d}<-{e}"));
                bad.extend(b);
                reuse += r;
                merges += 1;
            } else {
                s.local_op(d);
                let _ = s.recs(d);
            }
        }
    }
    eprintln!(
        "INFO {merges} merges checked; {reuse} merged records at a pair a third device used with other content"
    );
    bad.truncate(25);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §5 "symmetric rule 2026-11-26": the same item edited differently on two devices at the same
/// stamp; A merges B and B merges A from the pre-merge states. Both sides restamp to `max + 1`
/// (theirs' record at a stamp equal to ours is not adopted verbatim) and hold equal content.
#[test]
fn g6b_equal_stamp_conflict_is_symmetric() {
    let mut bad = vec![];
    for (label, ea, eb) in [
        ("title vs title", 0, 0),
        ("title vs password", 0, 1),
        ("password vs password", 1, 1),
        ("delete vs title", 2, 0),
    ] {
        let mut s = Sim::new(7, 2);
        let id = s.devs[0].items().next().unwrap().id;
        let now = 5_000;
        let apply = |v: &mut UnlockedVault, e: u8, tag: &str| match e {
            0 => v
                .update(id, now, |it| it.title = format!("title {tag}"))
                .unwrap(),
            1 => v
                .set_field_named(id, "password", pw(&format!("pw {tag}")), now)
                .unwrap(),
            _ => v.delete(id, now).unwrap(),
        };
        apply(&mut s.devs[0], ea, "A");
        apply(&mut s.devs[1], eb, "B");
        let a0 = s.devs[0].serialize();
        let b0 = s.devs[1].serialize();
        let ra = records(&a0, &s.key);
        let rb = records(&b0, &s.key);
        let open = |b: &[u8], v: &UnlockedVault| {
            LockedVault::parse(b)
                .unwrap()
                .unlock_with_key(&v.export_vault_key(), v.device_id())
                .unwrap()
        };
        let pa = open(&a0, &s.devs[0]);
        let pb = open(&b0, &s.devs[1]);
        s.devs[0].merge_from(&pb).unwrap();
        s.devs[1].merge_from(&pa).unwrap();
        let ma = records(&s.devs[0].serialize(), &s.key);
        let mb = records(&s.devs[1].serialize(), &s.key);
        bad.extend(check_merge(&ra, &rb, &ma, &format!("{label} A<-B")));
        bad.extend(check_merge(&rb, &ra, &mb, &format!("{label} B<-A")));
        // 00 roadmap item 2: "content equal after one exchange with modified_at within 1 ms,
        // fully equal after two".
        let k = id.as_bytes().to_vec();
        if ma[&k].1 != mb[&k].1 || ma[&k].0.abs_diff(mb[&k].0) > 1 {
            bad.push(format!(
                "{label}: one exchange: A@{} B@{} content equal {}",
                ma[&k].0,
                mb[&k].0,
                ma[&k].1 == mb[&k].1
            ));
        }
        let a1 = s.devs[0].serialize();
        let b1 = s.devs[1].serialize();
        let pa1 = open(&a1, &s.devs[0]);
        let pb1 = open(&b1, &s.devs[1]);
        s.devs[0].merge_from(&pb1).unwrap();
        s.devs[1].merge_from(&pa1).unwrap();
        let ma2 = records(&s.devs[0].serialize(), &s.key);
        let mb2 = records(&s.devs[1].serialize(), &s.key);
        bad.extend(check_merge(
            &records(&a1, &s.key),
            &records(&b1, &s.key),
            &ma2,
            &format!("{label} 2nd A<-B"),
        ));
        bad.extend(check_merge(
            &records(&b1, &s.key),
            &records(&a1, &s.key),
            &mb2,
            &format!("{label} 2nd B<-A"),
        ));
        if ma2[&k].0 != mb2[&k].0 || ma2[&k].1 != mb2[&k].1 {
            bad.push(format!(
                "{label}: two exchanges: A@{} B@{} content equal {}",
                ma2[&k].0,
                mb2[&k].0,
                ma2[&k].1 == mb2[&k].1
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 02 g6 "This covers ... a `created_at` carry (which now restamps and reports `updated` instead of
/// being carried silently)" versus 01 §4 "a differing created_at alone is not a change and never
/// bumps modified_at". Two records of one item, identical except that ours has no `created_at`.
/// Records which sentence the code follows (INFO) and checks the part both agree on: the merged
/// result keeps the minimum known `created_at` and never reuses ours' pair for different content.
#[test]
fn g6c_created_at_carry() {
    let s = Sim::new(3, 1);
    let b = s.devs[0].serialize();
    let raw = split(&b);
    let recs = records(&b, &s.key);
    let (id, (ma, _, plain)) = recs.iter().next().unwrap();
    let mut with = plain.clone();
    set(&mut with, "created_at", i(50));
    let mut without = plain.clone();
    if let Value::Map(e) = &mut without {
        e.retain(|(k, _)| k.as_text() != Some("created_at"));
    }
    let mk = |p: &Value| {
        let mut rs: Vec<Rec> = recs
            .iter()
            .map(|(i2, (m2, _, p2))| Rec {
                id: i2.clone(),
                ma: *m2,
                plain: p2.clone(),
                extras: vec![],
            })
            .collect();
        for r in rs.iter_mut() {
            if &r.id == id {
                r.plain = p.clone();
            }
        }
        seal_file(raw.version, &raw.header, &s.key, &rs, &[])
    };
    let ours_b = mk(&without);
    let theirs_b = mk(&with);
    let mut ours = LockedVault::parse(&ours_b)
        .unwrap()
        .unlock(&pw(FPW))
        .unwrap();
    let theirs = LockedVault::parse(&theirs_b)
        .unwrap()
        .unlock(&pw(FPW))
        .unwrap();
    let rep = ours.merge_from(&theirs).unwrap();
    let m = records(&ours.serialize(), &s.key);
    let (mma, _, mp) = &m[id];
    eprintln!(
        "INFO created_at carry: report {rep:?}; merged stamp {mma} (inputs {ma}); created_at {:?}",
        get(mp, "created_at")
    );
    assert_eq!(
        get(mp, "created_at"),
        Some(&i(50)),
        "the minimum known created_at is kept"
    );
    assert!(
        mma > ma,
        "02 g6: the carried created_at changes ours' record, so it may not keep pair (id, {ma})"
    );
}

/// 03 §5 header merge guard (L-02): "a peer header without `slots_modified_at` is never adopted
/// whatever the tuple says: two unstamped headers keep ours, an unstamped ours adopts a stamped
/// theirs under the usual tuple". Same vault, same key: ours a stamped version 2 header, theirs an
/// unstamped version 3 header (greater format_version, so the tuple alone would pick it).
#[test]
fn hg01_unstamped_peer_header_never_adopted() {
    let s = Sim::new(11, 1);
    let b = s.devs[0].serialize();
    let raw = split(&b);
    assert_eq!(raw.version, 3);
    let recs: Vec<Rec> = records(&b, &s.key)
        .into_iter()
        .map(|(id, (ma, _, p))| Rec {
            id,
            ma,
            plain: p,
            extras: vec![],
        })
        .collect();
    let mut h2 = raw.header.clone();
    rewrap_password_slots(&mut h2, &s.key, 2, FPW);
    let ours_b = seal_file(2, &h2, &s.key, &recs, &[]);
    let mut h3u = raw.header.clone();
    if let Value::Map(e) = &mut h3u {
        e.retain(|(k, _)| {
            !matches!(
                k.as_text(),
                Some("slots_modified_at") | Some("slots_device_id")
            )
        });
    }
    let theirs_b = seal_file(3, &h3u, &s.key, &recs, &[]);
    let mut ours = LockedVault::parse(&ours_b)
        .unwrap()
        .unlock(&pw(FPW))
        .expect("v2 opens");
    let theirs = LockedVault::parse(&theirs_b)
        .unwrap()
        .unlock(&pw(FPW))
        .expect("unstamped v3 opens (its digest binds the whole header)");
    let rep = ours.merge_from(&theirs).unwrap();
    let out = ours.serialize();
    let mut bad = vec![];
    if rep.header_updated {
        bad.push(format!("report says header_updated: {rep:?}"));
    }
    if version_of(&out) != 2 {
        bad.push(format!(
            "merged file is version {} (unstamped v3 header adopted)",
            version_of(&out)
        ));
    }
    if LockedVault::parse(&out)
        .and_then(|l| l.unlock(&pw(FPW)))
        .is_err()
    {
        bad.push("merged file does not open with the password".into());
    }
    // Converse: an unstamped ours (v3) adopts a stamped theirs (v2 stamped)? The tuple ranks the
    // version first, so v3 unstamped ours keeps its header against a v2 stamped peer.
    let mut ours2 = LockedVault::parse(&theirs_b)
        .unwrap()
        .unlock(&pw(FPW))
        .unwrap();
    let theirs2 = LockedVault::parse(&ours_b)
        .unwrap()
        .unlock(&pw(FPW))
        .unwrap();
    let rep2 = ours2.merge_from(&theirs2).unwrap();
    let out2 = ours2.serialize();
    eprintln!(
        "INFO unstamped v3 ours <- stamped v2 theirs: {rep2:?}, version {}",
        version_of(&out2)
    );
    if version_of(&out2) != 3 {
        bad.push(
            "a merge lowered the version (01 §9 'A merge never lowers a file's version')".into(),
        );
    }
    if LockedVault::parse(&out2)
        .and_then(|l| l.unlock(&pw(FPW)))
        .is_err()
    {
        bad.push("merged (ours unstamped v3) file does not open".into());
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 03 §5: "two unstamped headers keep ours, an unstamped ours adopts a stamped theirs under the
/// usual tuple"; 01 §2 L-02: "A writer that saves a header without `slots_modified_at` stamps it
/// with 1 and its own device id on that save ... the in-memory header stays unstamped until
/// re-unlocked". Uses the committed unstamped `v1-basic.vault`.
#[test]
fn hg02_unstamped_pairs_and_the_stamp_on_save() {
    let b = fixture("v1-basic.vault");
    assert!(
        get(&split(&b).header, "slots_modified_at").is_none(),
        "fixture is unstamped"
    );
    let mut a = LockedVault::parse(&b).unwrap().unlock(&pw(FPW)).unwrap();
    let dev_a = Uuid::new_v4();
    a.set_device_id(dev_a);
    let peer = LockedVault::parse(&b).unwrap().unlock(&pw(FPW)).unwrap();
    let rep = a.merge_from(&peer).unwrap();
    let mut bad = vec![];
    if rep.header_updated {
        bad.push(format!("two unstamped headers: header_updated ({rep:?})"));
    }
    let out = a.serialize();
    let h = split(&out).header;
    if get(&h, "slots_modified_at") != Some(&i(1)) {
        bad.push(format!(
            "L-02: save stamps 1, got {:?}",
            get(&h, "slots_modified_at")
        ));
    }
    if get(&h, "slots_device_id").map(bytes_of) != Some(dev_a.as_bytes().to_vec()) {
        bad.push("L-02: save stamps our device id".into());
    }
    if format!("{:?}", a.header()).contains("slots_modified_at: Some(1)") {
        bad.push(
            "L-02: the in-memory header was stamped (spec: stays unstamped until re-unlocked)"
                .into(),
        );
    }
    // unstamped ours adopts a stamped theirs (a password change on the peer)
    let mut c = LockedVault::parse(&b).unwrap().unlock(&pw(FPW)).unwrap();
    let mut d = LockedVault::parse(&b).unwrap().unlock(&pw(FPW)).unwrap();
    d.set_device_id(Uuid::new_v4());
    d.change_password(
        &pw(FPW),
        &pw("new pass phrase 9"),
        KdfParams::for_tests(),
        77_000,
    )
    .unwrap();
    let rep = c.merge_from(&d).unwrap();
    if !rep.header_updated {
        bad.push(format!(
            "unstamped ours did not adopt the stamped peer header: {rep:?}"
        ));
    }
    let out = c.serialize();
    if LockedVault::parse(&out)
        .and_then(|l| l.unlock(&pw("new pass phrase 9")))
        .is_err()
    {
        bad.push(
            "after adopting the peer header the file does not open with the new password".into(),
        );
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 02 guarantee 11, restated from the spec: "Unlocking `v1-basic.vault`, merging a copy whose
/// password slot was overwritten without the key (opened via `unlock_with_key`), serialising and
/// unlocking with the password succeeds; the saved file carries `slots_modified_at = 1` and the
/// same edit on it is `Tampered(Manifest)` on the key path."
#[test]
fn hg03_guarantee_11() {
    let b = fixture("v1-basic.vault");
    let mut ours = LockedVault::parse(&b).unwrap().unlock(&pw(FPW)).unwrap();
    let raw = split(&b);
    let edit = |raw: &RawFile| {
        let mut h = raw.header.clone();
        if let Some(Value::Array(s)) = get_mut(&mut h, "slots") {
            for x in s.iter_mut() {
                if get(x, "kind").unwrap().as_text() == Some("password") {
                    set(x, "wrapped_key", Value::Bytes(vec![0xAB; 48]));
                }
            }
        }
        join(raw.version, &canon(h), &raw.body)
    };
    let forged = edit(&raw);
    let theirs = LockedVault::parse(&forged)
        .unwrap()
        .unlock_with_key(&ours.export_vault_key(), Uuid::new_v4())
        .expect("unstamped v1 header is not digest-bound, so the key path opens it");
    ours.merge_from(&theirs).unwrap();
    let out = ours.serialize();
    let mut bad = vec![];
    if LockedVault::parse(&out)
        .and_then(|l| l.unlock(&pw(FPW)))
        .is_err()
    {
        bad.push("merged file no longer opens with the password".into());
    }
    let h = split(&out).header;
    if get(&h, "slots_modified_at") != Some(&i(1)) {
        bad.push(format!(
            "saved file stamp {:?}, want 1",
            get(&h, "slots_modified_at")
        ));
    }
    let again = edit(&split(&out));
    let r = LockedVault::parse(&again)
        .unwrap()
        .unlock_with_key(&ours.export_vault_key(), Uuid::new_v4());
    if !matches!(r, Err(VaultError::Tampered(TamperKind::Manifest))) {
        bad.push(format!("same edit on the saved file: {:?}", r.err()));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
