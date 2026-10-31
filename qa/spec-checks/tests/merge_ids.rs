//! Merge keyed by field id (03 §5, 2026-10-31), removed_fields tombstones, created_at minimum,
//! icon as metadata. Two and three devices. Added 2026-10-31.
use secrecy::ExposeSecret;
use spec_checks::*;
use uuid::Uuid;
use vault_core::*;

struct Net {
    devs: Vec<UnlockedVault>,
}
impl Net {
    fn new(n: usize) -> Net {
        let base = UnlockedVault::create(&pw("pw"), KdfParams::for_tests(), Uuid::new_v4());
        let l = LockedVault::parse(&base.serialize()).unwrap();
        let k = base.export_vault_key();
        Net { devs: (0..n).map(|_| l.unlock_with_key(&k, Uuid::new_v4()).unwrap()).collect() }
    }
    fn disk(&self, from: usize, to: usize) -> UnlockedVault {
        let b = self.devs[from].serialize();
        LockedVault::parse(&b).unwrap().unlock_with_key(&self.devs[to].export_vault_key(), self.devs[to].device_id()).unwrap()
    }
    fn pull(&mut self, to: usize, from: usize) -> MergeReport {
        let d = self.disk(from, to);
        self.devs[to].merge_from(&d).unwrap()
    }
    fn all_pairs(&mut self, rounds: usize) {
        let n = self.devs.len();
        for _ in 0..rounds {
            for a in 0..n {
                for b in 0..n {
                    if a != b {
                        self.pull(a, b);
                    }
                }
            }
        }
    }
    fn assert_converged(&self) {
        let s = snap_vault(&self.devs[0]);
        for (i, d) in self.devs.iter().enumerate().skip(1) {
            assert_eq!(snap_vault(d), s, "device {i} differs");
        }
    }
}
/// Item with fields "username" and "password", seeded on device 0 and pulled everywhere.
fn seeded(n: &mut Net, now: u64) -> (Uuid, Uuid, Uuid) {
    let d0 = n.devs[0].device_id();
    let mut it = Item::new("Login", d0, now);
    it.fields.push(Field::new("username", FieldKind::Text, pw("u0"), now));
    it.fields.push(Field::new("password", FieldKind::Password, pw("p0"), now));
    let (u, p) = (it.fields[0].id, it.fields[1].id);
    let id = n.devs[0].insert(it, now);
    for i in 1..n.devs.len() {
        n.pull(i, 0);
    }
    (id, u, p)
}
fn fields(v: &UnlockedVault, id: Uuid) -> Vec<(Uuid, String, String)> {
    v.get(id).map(|i| i.fields.iter().map(|f| (f.id, f.name.clone(), f.value.expose_secret().clone())).collect()).unwrap_or_default()
}

/// 03 §5 "Field-level merge, keyed by field.id (2026-10-31; never by name)". Replaces the
/// name-keyed rule: two devices that each add a field called "pin" keep BOTH fields.
#[test]
fn mi01_same_name_added_on_two_devices_both_kept() {
    let mut n = Net::new(2);
    let (id, _, _) = seeded(&mut n, 100);
    n.devs[0].update(id, 200, |it| it.fields.push(Field::new("pin", FieldKind::Text, pw("1111"), 200))).unwrap();
    n.devs[1].update(id, 210, |it| it.fields.push(Field::new("pin", FieldKind::Text, pw("2222"), 210))).unwrap();
    n.all_pairs(2);
    for d in &n.devs {
        let pins: Vec<String> = fields(d, id).into_iter().filter(|f| f.1 == "pin").map(|f| f.2).collect();
        let mut s = pins.clone();
        s.sort();
        assert_eq!(s, vec!["1111", "2222"], "both same-named fields survive: {pins:?}");
    }
    n.assert_converged();
}

/// 03 §5 "greater modified_at wins whole (name, kind, value, section travel together, so a rename
/// is an edit)". A renames username->login at 300; B edits the value at 250 -> A's field wins whole.
/// B edits at 350 -> B's whole field wins (old name, new value). Never two fields.
#[test]
fn mi02_rename_vs_edit() {
    for (b_at, want_name, want_val) in [(250u64, "login", "u0"), (350u64, "username", "b-val")] {
        let mut n = Net::new(2);
        let (id, u, _) = seeded(&mut n, 100);
        n.devs[0].update(id, 300, |it| it.fields.iter_mut().find(|f| f.id == u).unwrap().name = "login".into()).unwrap();
        n.devs[1].set_field(id, u, pw("b-val"), b_at).unwrap();
        n.all_pairs(2);
        for d in &n.devs {
            let fs = fields(d, id);
            assert_eq!(fs.len(), 2, "rename is not delete+add: {fs:?}");
            let f = fs.iter().find(|f| f.0 == u).unwrap();
            assert_eq!((f.1.as_str(), f.2.as_str()), (want_name, want_val), "B at {b_at}");
        }
        n.assert_converged();
    }
}

/// 03 §5 removed_fields, two devices: "take theirs, unless our removed_fields carries a marker for
/// that id with removed_at >= modified_at"; "a field edited strictly after its marker survives
/// and the marker is dropped on both sides". Covers before / equal / after.
#[test]
fn mi03_removed_fields_two_devices() {
    for (edit_at, survives) in [(150u64, false), (200u64, false), (250u64, true)] {
        let mut n = Net::new(2);
        let (id, u, p) = seeded(&mut n, 100);
        n.devs[0].remove_field(id, u, 200).unwrap();
        n.devs[1].set_field(id, u, pw("edited"), edit_at).unwrap();
        // both merge directions, then a second round
        n.pull(0, 1);
        n.pull(1, 0);
        n.pull(0, 1);
        for (di, d) in n.devs.iter().enumerate() {
            let it = d.get(id).unwrap();
            assert_eq!(it.field_by_id(u).is_some(), survives, "edit at {edit_at} vs marker 200, device {di}");
            assert!(it.field_by_id(p).is_some(), "untouched field stays");
            let has_marker = it.removed_fields.iter().any(|t| t.id == u);
            if survives {
                assert!(!has_marker, "marker dropped on both sides when the edit is strictly later (device {di})");
                assert_eq!(it.field_by_id(u).unwrap().value.expose_secret(), "edited");
            } else {
                assert!(has_marker, "marker kept (device {di})");
            }
        }
        n.assert_converged();
    }
}

/// 03 §5 with three devices: A removes a field, B never sees A directly, C relays; a stale copy
/// from B (which still has the field, unedited) must not resurrect it anywhere; markers union with
/// the greatest removed_at per id.
#[test]
fn mi04_removed_fields_three_devices_relay() {
    let mut n = Net::new(3);
    let (id, u, p) = seeded(&mut n, 100);
    n.devs[0].remove_field(id, u, 300).unwrap();
    n.devs[1].set_field(id, p, pw("b-pass"), 310).unwrap(); // B edits a different field later
    n.pull(2, 0); // C learns the removal
    n.pull(2, 1); // C merges B (still has u at 100)
    assert!(n.devs[2].get(id).unwrap().field_by_id(u).is_none(), "stale copy did not resurrect on the relay");
    n.pull(1, 2); // B learns from C only
    assert!(n.devs[1].get(id).unwrap().field_by_id(u).is_none(), "removal reached B through C");
    n.all_pairs(2);
    for d in &n.devs {
        let it = d.get(id).unwrap();
        assert!(it.field_by_id(u).is_none());
        assert_eq!(it.field_by_id(p).unwrap().value.expose_secret(), "b-pass");
        assert_eq!(it.removed_fields.iter().filter(|t| t.id == u).count(), 1, "one marker per id");
    }
    n.assert_converged();
    // two devices remove the same field at different times -> greatest removed_at kept
    let mut n = Net::new(3);
    let (id, u, _) = seeded(&mut n, 100);
    n.devs[0].remove_field(id, u, 400).unwrap();
    n.devs[1].remove_field(id, u, 500).unwrap();
    n.all_pairs(2);
    for d in &n.devs {
        let m: Vec<u64> = d.get(id).unwrap().removed_fields.iter().filter(|t| t.id == u).map(|t| t.removed_at).collect();
        assert_eq!(m, vec![500], "greatest removed_at per id");
    }
    n.assert_converged();
}

/// 03 §5 "removed_fields markers are unioned (greatest removed_at per id)"; "a merge caps them at
/// 64 by dropping, oldest first, only markers whose field neither side still holds"; "Two devices
/// converge within two merge rounds, or three when the removed_fields cap fires" (ported
/// 2026-10-31 from a two-round check). 40 removals on A and 40 on B: after three rounds every
/// removal holds, both sides keep the 64 newest markers, the decrypted item payloads are
/// byte-equal, and further pulls change nothing.
#[test]
fn mi05_removed_fields_union_cap() {
    let mut n = Net::new(2);
    let d0 = n.devs[0].device_id();
    let mut it = Item::new("many", d0, 100);
    for k in 0..80 {
        it.fields.push(Field::new(format!("f{k}"), FieldKind::Text, pw("x"), 100));
    }
    let ids: Vec<Uuid> = it.fields.iter().map(|f| f.id).collect();
    let id = n.devs[0].insert(it, 100);
    n.pull(1, 0);
    for k in 0..40 {
        n.devs[0].remove_field(id, ids[k], 1_000 + 2 * k as u64).unwrap();
        n.devs[1].remove_field(id, ids[40 + k], 1_001 + 2 * k as u64).unwrap();
    }
    n.all_pairs(3);
    for d in &n.devs {
        let it = d.get(id).unwrap();
        assert!(it.fields.is_empty(), "all 80 removals applied: {} left", it.fields.len());
        assert_eq!(it.removed_fields.len(), 64);
        let stamps: Vec<u64> = it.removed_fields.iter().map(|t| t.removed_at).collect();
        let mut sorted = stamps.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(stamps, sorted, "newest first after merge");
        assert_eq!(*stamps.last().unwrap(), 1_000 + 16, "the 64 newest kept");
    }
    n.assert_converged();
    // byte-equal: the decrypted, canonical ItemPlain CBOR of every item is identical on both sides
    let plain = |v: &UnlockedVault| -> Vec<(Vec<u8>, u64, Vec<u8>)> {
        let mut x: Vec<(Vec<u8>, u64, Vec<u8>)> = indep::open_file(&v.serialize(), "pw").items.into_iter().map(|(i, m, pt)| (i, m, enc(&pt))).collect();
        x.sort();
        x
    };
    assert_eq!(plain(&n.devs[0]), plain(&n.devs[1]), "item payloads byte-equal after three rounds");
    let before = plain(&n.devs[0]);
    for (to, from) in [(0, 1), (1, 0), (0, 1)] {
        let r = n.pull(to, from);
        assert_eq!((r.added, r.updated, r.deleted, r.header_updated), (0, 0, 0, false), "further pull {to}<-{from} changed something: {r:?}");
    }
    assert_eq!(plain(&n.devs[0]), before, "further pulls leave the payloads unchanged");
    assert_eq!(plain(&n.devs[1]), before);
}

/// 01 §4 created_at: "a merge keeps the minimum of the two known values, or whichever side has
/// one, and a differing created_at alone is not a change and never bumps modified_at".
#[test]
fn mi06_created_at_minimum_not_a_change() {
    let mut n = Net::new(2);
    let (id, _, _) = seeded(&mut n, 100);
    let ma = n.devs[0].get(id).unwrap().modified_at;
    // Set different created_at on each side without changing anything else, via hand-made disk
    // copies: update() would restamp, so the copies are edited with the independent writer.
    let mk = |n: &Net, from: usize, ca: Option<u64>| -> UnlockedVault {
        let b = n.devs[from].serialize();
        let o = indep::open_file(&b, "pw");
        let raw = split(&b);
        let items: Vec<([u8; 16], u64, Value)> = o
            .items
            .iter()
            .map(|(iid, m, pt)| {
                let mut pt = pt.clone();
                if let Value::Map(e) = &mut pt {
                    e.retain(|(k, _)| k.as_text() != Some("created_at"));
                }
                if let Some(c) = ca {
                    set(&mut pt, "created_at", i(c));
                }
                (iid.as_slice().try_into().unwrap(), *m, pt)
            })
            .collect();
        let f = build_file(raw.version, &raw.header, &o.vault_key, &items);
        LockedVault::parse(&f).unwrap().unlock_with_key(&n.devs[from].export_vault_key(), Uuid::new_v4()).unwrap()
    };
    let older = mk(&n, 1, Some(50));
    let r = n.devs[0].merge_from(&older).unwrap();
    let it = n.devs[0].get(id).unwrap();
    assert_eq!(it.created_at, Some(50), "minimum kept");
    assert_eq!(it.modified_at, ma, "created_at alone never bumps modified_at");
    assert_eq!((r.added, r.updated, r.deleted), (0, 0, 0), "not a change: {r:?}");
    let newer = mk(&n, 1, Some(10_000));
    n.devs[0].merge_from(&newer).unwrap();
    assert_eq!(n.devs[0].get(id).unwrap().created_at, Some(50), "a larger value never replaces the minimum");
    // one side unknown -> the known one
    let mut m = Net::new(2);
    let (id2, _, _) = seeded(&mut m, 100);
    let unknown = mk(&m, 1, None);
    let mut mine = mk(&m, 0, None);
    mine.merge_from(&unknown).unwrap();
    assert_eq!(mine.get(id2).unwrap().created_at, None);
    m.devs[0].merge_from(&unknown).unwrap();
    assert_eq!(m.devs[0].get(id2).unwrap().created_at, Some(100), "whichever side has one");
    let mut u2 = mk(&m, 1, None);
    u2.merge_from(&m.disk(0, 1)).unwrap();
    assert_eq!(u2.get(id2).unwrap().created_at, Some(100), "unknown side adopts the known value");
    // created_at also follows when the other side wins metadata: B later title edit, A older created_at
    let mut k = Net::new(2);
    let (id3, _, _) = seeded(&mut k, 100);
    let mut a = mk(&k, 0, Some(7));
    let mut b = k.disk(1, 1);
    b.update(id3, 900, |it| it.title = "B title".into()).unwrap();
    a.merge_from(&b).unwrap();
    let it = a.get(id3).unwrap();
    assert_eq!((it.title.as_str(), it.created_at), ("B title", Some(7)), "minimum survives losing metadata");
}

/// 03 §5 metadata "taken from whichever item has the greater modified_at"; 01 §4 icon "merge treats
/// it as item metadata that travels with the metadata winner".
#[test]
fn mi07_icon_travels_with_metadata() {
    let mut n = Net::new(2);
    let (id, _, _) = seeded(&mut n, 100);
    n.devs[0].update(id, 300, |it| it.icon = Some(ItemIcon::new("symbol", "star"))).unwrap();
    n.devs[1].update(id, 400, |it| it.favorite = true).unwrap();
    n.all_pairs(2);
    for d in &n.devs {
        let it = d.get(id).unwrap();
        assert!(it.favorite);
        assert!(it.icon.is_none(), "B's later metadata wins as a whole, icon included (B had no icon)");
    }
    n.assert_converged();
    let mut n = Net::new(2);
    let (id, _, _) = seeded(&mut n, 100);
    n.devs[1].update(id, 300, |it| it.favorite = true).unwrap();
    let mut ic = ItemIcon::new("letter", "");
    ic.color = Some("#00ff00".into());
    n.devs[0].update(id, 400, |it| it.icon = Some(ic.clone())).unwrap();
    n.all_pairs(2);
    for d in &n.devs {
        let it = d.get(id).unwrap();
        assert_eq!(it.icon.as_ref().map(|c| (c.kind.as_str(), c.color.as_deref())), Some(("letter", Some("#00ff00"))));
    }
    n.assert_converged();
}

/// 01 §4 "section ... merges by id and stamp like any field"; history field_id survives merge.
#[test]
fn mi08_section_and_history_field_id_merge() {
    let mut n = Net::new(2);
    let (id, _, p) = seeded(&mut n, 100);
    n.devs[0].update(id, 200, |it| it.fields.insert(0, Field::new("Login details", FieldKind::Section, pw(""), 200))).unwrap();
    n.devs[1].set_field(id, p, pw("p1"), 210).unwrap();
    n.all_pairs(2);
    for d in &n.devs {
        let it = d.get(id).unwrap();
        assert!(it.fields.iter().any(|f| f.kind == FieldKind::Section && f.name == "Login details"));
        assert_eq!(it.history.iter().map(|h| (h.value.expose_secret().clone(), h.field_id)).collect::<Vec<_>>(), vec![("p0".into(), Some(p))]);
    }
    n.assert_converged();
}

/// 03 §5 "Merge is idempotent and commutative"; "Two devices converge within two merge rounds";
/// seeded random scripts on 2 and 3 devices with field add / rename / remove / re-add by id,
/// same-name adds, created_at, icons, deletes, clock skew and exact ties.
#[test]
fn mi09_random_scripts_with_field_ids_converge() {
    use rand::{Rng, SeedableRng};
    let mut failures = vec![];
    for seed in 0..80u64 {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xF1E1D + seed);
        let nd = 2 + (seed % 2) as usize;
        let mut n = Net::new(nd);
        let mut ids = vec![];
        for _ in 0..3 {
            ids.push(seeded(&mut n, 100).0);
        }
        let mut clock = vec![1_000u64; nd];
        for _ in 0..50 {
            let d = rng.gen_range(0..nd);
            clock[d] = match rng.gen_range(0..10) {
                0 => clock[d].saturating_sub(40),
                1 => 5_000,
                _ => clock[d] + rng.gen_range(1..15),
            };
            let now = clock[d];
            let id = ids[rng.gen_range(0..ids.len())];
            let fids: Vec<Uuid> = n.devs[d].get(id).map(|i| i.fields.iter().map(|f| f.id).collect()).unwrap_or_default();
            let pick = |rng: &mut rand::rngs::StdRng| if fids.is_empty() { None } else { Some(fids[rng.gen_range(0..fids.len())]) };
            match rng.gen_range(0..11) {
                0 => {
                    let _ = n.devs[d].delete(id, now);
                }
                1 => {
                    let _ = n.devs[d].update(id, now, |it| it.fields.push(Field::new("dup", FieldKind::Text, pw(&format!("{d}-{now}")), now)));
                }
                2 => {
                    if let Some(f) = pick(&mut rng) {
                        let _ = n.devs[d].remove_field(id, f, now);
                    }
                }
                3 => {
                    if let Some(f) = pick(&mut rng) {
                        let _ = n.devs[d].update(id, now, |it| {
                            if let Some(x) = it.fields.iter_mut().find(|x| x.id == f) {
                                x.name = format!("r{now}");
                            }
                        });
                    }
                }
                4 | 5 => {
                    if let Some(f) = pick(&mut rng) {
                        let _ = n.devs[d].set_field(id, f, pw(&format!("v{d}-{now}")), now);
                    }
                }
                6 => {
                    let _ = n.devs[d].update(id, now, |it| it.icon = if it.icon.is_some() { None } else { Some(ItemIcon::new("symbol", format!("s{now}"))) });
                }
                7 => {
                    let _ = n.devs[d].update(id, now, |it| it.title = format!("t{now}"));
                }
                8 => {
                    let dev = n.devs[d].device_id();
                    let mut it = Item::new("new", dev, now);
                    it.fields.push(Field::new("password", FieldKind::Password, pw("x"), now));
                    ids.push(n.devs[d].insert(it, now));
                }
                _ => {
                    let o = rng.gen_range(0..nd);
                    if o != d {
                        n.pull(d, o);
                    }
                }
            }
        }
        let x = n.disk(0, 0);
        let y = n.disk(1, 0);
        let mut xy = n.disk(0, 0);
        xy.merge_from(&y).unwrap();
        let mut yx = n.disk(1, 0);
        yx.merge_from(&x).unwrap();
        // commutative on content incl. field ids and markers (stamps may differ by the +1 bump)
        let content = |v: &UnlockedVault| -> Vec<String> {
            let mut s: Vec<String> = v
                .items_including_deleted()
                .map(|i| {
                    let mut f: Vec<String> = i.fields.iter().map(|f| format!("{}:{}={}", f.id, f.name, f.value.expose_secret())).collect();
                    f.sort();
                    let mut rf: Vec<Uuid> = i.removed_fields.iter().map(|t| t.id).collect();
                    rf.sort();
                    format!("{}|{}|del={}|{:?}|rf={:?}|icon={:?}|ca={:?}", i.id, i.title, i.deleted_at.is_some(), f, rf, i.icon.as_ref().map(|c| c.value.clone()), i.created_at)
                })
                .collect();
            s.sort();
            s
        };
        if content(&xy) != content(&yx) {
            let (cx, cy) = (content(&xy), content(&yx));
            let dx: Vec<&String> = cx.iter().filter(|l| !cy.contains(l)).collect();
            let dy: Vec<&String> = cy.iter().filter(|l| !cx.contains(l)).collect();
            failures.push(format!("seed {seed}: not commutative\n  x<-y only: {dx:?}\n  y<-x only: {dy:?}"));
            for it in x.items_including_deleted() {
                let Some(o) = y.items_including_deleted().find(|o| o.id == it.id) else { continue };
                for f in &it.fields {
                    if let Some(g) = o.field_by_id(f.id) {
                        if f.name != g.name || f.value.expose_secret() != g.value.expose_secret() {
                            failures.push(format!(
                                "  field {}: x=({}, {}, ma {}) item(ma {}, dev {}) | y=({}, {}, ma {}) item(ma {}, dev {})",
                                f.id, f.name, f.value.expose_secret(), f.modified_at, it.modified_at, it.device_id,
                                g.name, g.value.expose_secret(), g.modified_at, o.modified_at, o.device_id
                            ));
                        }
                    }
                }
            }
        }
        n.all_pairs(2);
        let s0 = snap_vault(&n.devs[0]);
        for k in 1..nd {
            if snap_vault(&n.devs[k]) != s0 {
                failures.push(format!("seed {seed}: device {k} differs after two rounds"));
            }
        }
        // a removed id is never present while its marker is >= the field stamp
        for it in n.devs[0].items_including_deleted() {
            for t in &it.removed_fields {
                if let Some(f) = it.field_by_id(t.id) {
                    if t.removed_at >= f.modified_at {
                        failures.push(format!("seed {seed}: field {} present with marker {} >= {}", t.id, t.removed_at, f.modified_at));
                    }
                }
            }
            let mut fid: Vec<Uuid> = it.fields.iter().map(|f| f.id).collect();
            let l = fid.len();
            fid.sort();
            fid.dedup();
            if fid.len() != l {
                failures.push(format!("seed {seed}: duplicate field ids after merge"));
            }
        }
        let before = snap_vault(&n.devs[0]);
        n.pull(0, 1);
        if snap_vault(&n.devs[0]) != before {
            failures.push(format!("seed {seed}: not idempotent"));
        }
        // the converged state survives a serialize/parse cycle
        let rt = n.disk(0, 0);
        if snap_vault(&rt) != before {
            failures.push(format!("seed {seed}: state changed across serialize"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Two devices with chosen device ids (A's bytes greater than B's).
fn pair(a: u8, b: u8) -> Net {
    let base = UnlockedVault::create(&pw("pw"), KdfParams::for_tests(), Uuid::from_bytes([a; 16]));
    let l = LockedVault::parse(&base.serialize()).unwrap();
    let k = base.export_vault_key();
    Net { devs: vec![l.unlock_with_key(&k, Uuid::from_bytes([a; 16])).unwrap(), l.unlock_with_key(&k, Uuid::from_bytes([b; 16])).unwrap()] }
}

/// 03 §5 field row "tie -> greater device_id of the owning item; tie -> ours" together with "Merge
/// is idempotent and commutative" and "Two devices converge within two merge rounds".
/// A and B edit the same field in the same millisecond; B also edits the title later. After A
/// merges B, A's item carries B's device_id (metadata winner) but keeps A's field (A > B). Now both
/// owning items carry B's device_id, the field tie falls through to "ours" on both sides, and the
/// devices never converge.
#[test]
fn mi10_field_tie_with_shared_item_device_id_converges() {
    let mut n = pair(0xF0, 0x10);
    let (id, u, _) = seeded(&mut n, 100);
    n.devs[0].set_field(id, u, pw("from-A"), 500).unwrap();
    n.devs[1].set_field(id, u, pw("from-B"), 500).unwrap();
    n.devs[1].update(id, 600, |it| it.title = "B title".into()).unwrap();
    n.all_pairs(4);
    let va = fields(&n.devs[0], id).into_iter().find(|f| f.0 == u).unwrap().2;
    let vb = fields(&n.devs[1], id).into_iter().find(|f| f.0 == u).unwrap().2;
    let da = n.devs[0].get(id).unwrap().device_id;
    let db = n.devs[1].get(id).unwrap().device_id;
    assert_eq!(va, vb, "after four all-pairs rounds A has {va:?}, B has {vb:?} (item device_id A={da}, B={db})");
}

/// 03 §5 "removed_fields markers are unioned (... cap 64 newest)" and "The former 'field deletion
/// is not tracked' limit is closed". One device removes 70 fields of an item while the other is
/// offline and unchanged; after the merge every removal should hold.
#[test]
fn mi11_removals_beyond_cap_resurrect() {
    let mut n = Net::new(2);
    let d0 = n.devs[0].device_id();
    let mut it = Item::new("many", d0, 100);
    for k in 0..70 {
        it.fields.push(Field::new(format!("f{k}"), FieldKind::Text, pw("x"), 100));
    }
    let ids: Vec<Uuid> = it.fields.iter().map(|f| f.id).collect();
    let id = n.devs[0].insert(it, 100);
    n.pull(1, 0);
    for (k, fid) in ids.iter().enumerate() {
        n.devs[0].remove_field(id, *fid, 1_000 + k as u64).unwrap();
    }
    n.pull(0, 1);
    let back: Vec<String> = n.devs[0].get(id).unwrap().fields.iter().map(|f| f.name.clone()).collect();
    assert!(back.is_empty(), "{} removed fields came back after merging the offline copy: {back:?}", back.len());
}
