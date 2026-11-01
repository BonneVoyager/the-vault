//! Merge rules (03 §5, 02 guarantee 9, 02 update/set_field) with two and three devices.
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
        let bytes = base.serialize();
        let l = LockedVault::parse(&bytes).unwrap();
        let k = base.export_vault_key();
        Net {
            devs: (0..n)
                .map(|_| l.unlock_with_key(&k, Uuid::new_v4()).unwrap())
                .collect(),
        }
    }
    /// What device `to` sees when it reads device `from`'s file.
    fn disk(&self, from: usize, to: usize) -> UnlockedVault {
        let b = self.devs[from].serialize();
        LockedVault::parse(&b)
            .unwrap()
            .unlock_with_key(&self.devs[to].export_vault_key(), self.devs[to].device_id())
            .unwrap()
    }
    fn pull(&mut self, to: usize, from: usize) -> MergeReport {
        let d = self.disk(from, to);
        self.devs[to].merge_from(&d).unwrap()
    }
}
fn val(v: &UnlockedVault, id: Uuid, name: &str) -> Option<String> {
    v.get(id)?
        .fields
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.value.expose_secret().clone())
}
fn login(dev: Uuid, now: u64) -> Item {
    let mut it = Item::new("Login", dev, now);
    it.fields
        .push(Field::new("username", FieldKind::Text, pw("u0"), now));
    it.fields
        .push(Field::new("password", FieldKind::Password, pw("p0"), now));
    it
}
fn seeded(n: &mut Net, now: u64) -> Uuid {
    let d0 = n.devs[0].device_id();
    let id = n.devs[0].insert(login(d0, now), now);
    for i in 1..n.devs.len() {
        n.pull(i, 0);
    }
    id
}

/// 03 §5 table rows "absent/present" and "present/absent".
#[test]
fn m01_absent_present() {
    let mut n = Net::new(2);
    let dd = n.devs[0].device_id();
    let id = n.devs[0].insert(login(dd, 10), 10);
    let r = n.pull(1, 0);
    assert_eq!(r.added, 1);
    assert!(n.devs[1].get(id).is_some());
    let mut m = Net::new(2);
    let dd = m.devs[0].device_id();
    let id2 = m.devs[0].insert(login(dd, 10), 10);
    m.pull(0, 1);
    assert!(m.devs[0].get(id2).is_some(), "present/absent keeps ours");
    // tombstone taken when absent
    let mut t = Net::new(2);
    let dd = t.devs[0].device_id();
    let id3 = t.devs[0].insert(login(dd, 10), 10);
    t.devs[0].delete(id3, 20).unwrap();
    t.pull(1, 0);
    assert!(
        t.devs[1]
            .items_including_deleted()
            .any(|i| i.id == id3 && i.deleted_at.is_some()),
        "absent/tombstone -> take tombstone"
    );
    assert!(
        t.devs[1]
            .get(id3)
            .map(|i| i.deleted_at.is_some())
            .unwrap_or(true)
    );
    assert!(
        !t.devs[1].items().any(|i| i.id == id3),
        "items() excludes tombstones"
    );
}

/// 03 §5: tombstone wins iff deleted_at >= other.modified_at; edit after delete resurrects.
/// 02 guarantee 9: delete then merge an older copy -> stays deleted.
#[test]
fn m02_tombstone_rules() {
    // delete later than edit -> deleted
    let mut n = Net::new(2);
    let id = seeded(&mut n, 100);
    n.devs[1]
        .set_field_named(id, "username", pw("b"), 150)
        .unwrap();
    n.devs[0].delete(id, 200).unwrap();
    n.pull(0, 1);
    n.pull(1, 0);
    for d in &n.devs {
        assert!(d.items().all(|i| i.id != id), "delete@200 beats edit@150");
    }
    // edit later than delete -> resurrect with the edit
    let mut n = Net::new(2);
    let id = seeded(&mut n, 100);
    n.devs[0].delete(id, 200).unwrap();
    n.devs[1]
        .set_field_named(id, "username", pw("late"), 300)
        .unwrap();
    n.pull(0, 1);
    n.pull(1, 0);
    for d in &n.devs {
        assert_eq!(val(d, id, "username").as_deref(), Some("late"));
        assert!(
            d.get(id).unwrap().deleted_at.is_none(),
            "edit after delete resurrects"
        );
    }
    // guarantee 9
    let mut n = Net::new(2);
    let id = seeded(&mut n, 100);
    let older = n.disk(0, 0);
    n.devs[0].delete(id, 200).unwrap();
    n.devs[0].merge_from(&older).unwrap();
    assert!(n.devs[0].items().all(|i| i.id != id), "guarantee 9");
}

/// 03 §5 field-level merge; 03 §9 "A edits username, B edits password ... both converge".
#[test]
fn m03_field_level_lww() {
    let mut n = Net::new(2);
    let id = seeded(&mut n, 100);
    n.devs[0]
        .set_field_named(id, "username", pw("from-a"), 200)
        .unwrap();
    n.devs[1]
        .set_field_named(id, "password", pw("from-b"), 210)
        .unwrap();
    n.pull(0, 1);
    n.pull(1, 0);
    for d in &n.devs {
        assert_eq!(val(d, id, "username").as_deref(), Some("from-a"));
        assert_eq!(val(d, id, "password").as_deref(), Some("from-b"));
    }
    assert_eq!(
        snap_content(&n.devs[0]),
        snap_content(&n.devs[1]),
        "contents equal after one round"
    );
    n.pull(0, 1);
    n.pull(1, 0);
    assert_eq!(
        snap_vault(&n.devs[0]),
        snap_vault(&n.devs[1]),
        "identical (incl. stamps) within two rounds"
    );
    // same field: greater modified_at wins regardless of merge direction
    let mut n = Net::new(2);
    let id = seeded(&mut n, 100);
    n.devs[0]
        .set_field_named(id, "username", pw("newer"), 400)
        .unwrap();
    n.devs[1]
        .set_field_named(id, "username", pw("older"), 300)
        .unwrap();
    n.pull(0, 1);
    n.pull(1, 0);
    for d in &n.devs {
        assert_eq!(val(d, id, "username").as_deref(), Some("newer"));
    }
    // same field, same stamp: tie -> greater device_id of the owning item
    let mut n = Net::new(2);
    let id = seeded(&mut n, 100);
    n.devs[0]
        .set_field_named(id, "username", pw("A"), 500)
        .unwrap();
    n.devs[1]
        .set_field_named(id, "username", pw("B"), 500)
        .unwrap();
    let (da, db) = (n.devs[0].device_id(), n.devs[1].device_id());
    n.pull(0, 1);
    n.pull(1, 0);
    let want = if da.as_bytes() > db.as_bytes() {
        "A"
    } else {
        "B"
    };
    for d in &n.devs {
        assert_eq!(
            val(d, id, "username").as_deref(),
            Some(want),
            "tie -> greater device_id"
        );
    }
    // depending on which device wins the tie, stamps settle in one or two rounds (03 §5)
    n.pull(0, 1);
    n.pull(1, 0);
    assert_eq!(snap_vault(&n.devs[0]), snap_vault(&n.devs[1]));
    // new field on one side only is taken
    let mut n = Net::new(2);
    let id = seeded(&mut n, 100);
    n.devs[1]
        .update(id, 600, |it| {
            it.fields
                .push(Field::new("pin", FieldKind::Text, pw("1234"), 600))
        })
        .unwrap();
    n.pull(0, 1);
    assert_eq!(val(&n.devs[0], id, "pin").as_deref(), Some("1234"));
}

/// 03 §5 metadata taken from the item with greater modified_at; device_id follows metadata.
#[test]
fn m04_metadata_lww() {
    let mut n = Net::new(2);
    let id = seeded(&mut n, 100);
    n.devs[1].update(id, 400, |it| it.favorite = true).unwrap();
    n.devs[0]
        .update(id, 500, |it| it.title = "Renamed".into())
        .unwrap();
    n.pull(0, 1);
    n.pull(1, 0);
    for d in &n.devs {
        let it = d.get(id).unwrap();
        assert_eq!(it.title, "Renamed");
        assert_eq!(
            it.device_id,
            n.devs[0].device_id(),
            "device_id of the side that supplied metadata"
        );
    }
    assert_eq!(snap_vault(&n.devs[0]), snap_vault(&n.devs[1]));
}

/// 02 set_field: password change pushes history, cap 10; 03 §5 history union + removed_history.
#[test]
fn m05_history_and_removed_history() {
    let mut n = Net::new(2);
    let id = seeded(&mut n, 100);
    for i in 0..15u64 {
        n.devs[0]
            .set_field_named(id, "password", pw(&format!("p{}", i + 1)), 1_000 + i)
            .unwrap();
    }
    let h = &n.devs[0].get(id).unwrap().history;
    assert_eq!(h.len(), 10, "history cap 10");
    assert!(
        h.iter().any(|e| e.value.expose_secret() == "p14"),
        "newest kept"
    );
    assert!(
        !h.iter().any(|e| e.value.expose_secret() == "p0"),
        "oldest dropped"
    );
    // text field change does not push history
    let before = n.devs[0].get(id).unwrap().history.len();
    n.devs[0]
        .set_field_named(id, "username", pw("x"), 2_000)
        .unwrap();
    assert_eq!(n.devs[0].get(id).unwrap().history.len(), before);
    // B diverges with its own password change -> union
    n.pull(1, 0);
    n.devs[1]
        .set_field_named(id, "password", pw("b-pass"), 3_000)
        .unwrap();
    n.devs[0]
        .set_field_named(id, "password", pw("a-pass"), 3_001)
        .unwrap();
    n.pull(0, 1);
    n.pull(1, 0);
    let ha: Vec<_> = n.devs[0]
        .get(id)
        .unwrap()
        .history
        .iter()
        .map(|e| (e.value.expose_secret().clone(), e.replaced_at))
        .collect();
    assert!(
        ha.iter().any(|(v, _)| v == "b-pass"),
        "conflict-losing password kept in history (03 §5 clock skew note): {ha:?}"
    );
    assert!(ha.len() <= 10);
    assert_eq!(snap_vault(&n.devs[0]), snap_vault(&n.devs[1]));
    // user deletes a history entry on A; B still has it; deletion survives merge
    let stamp = ha[0].1;
    n.devs[0]
        .update(id, 4_000, |it| {
            it.history.retain(|e| e.replaced_at != stamp);
            if !it.removed_history.contains(&stamp) {
                it.removed_history.push(stamp);
            }
        })
        .unwrap();
    n.pull(0, 1);
    n.pull(1, 0);
    for d in &n.devs {
        assert!(
            !d.get(id)
                .unwrap()
                .history
                .iter()
                .any(|e| e.replaced_at == stamp),
            "removed history entry stays removed"
        );
    }
}

/// 03 §5 attachments: union by id; removal tombstone survives merge with a device that still has the ref.
#[test]
fn m06_attachment_refs_merge() {
    let mut n = Net::new(2);
    let id = seeded(&mut n, 100);
    let r1 = attachment::new_ref("a.txt", 3, 200).unwrap();
    let r1id = r1.id;
    n.devs[0].add_attachment_ref(id, r1, 200).unwrap();
    let r2 = attachment::new_ref("b.txt", 3, 210).unwrap();
    let r2id = r2.id;
    n.devs[1].add_attachment_ref(id, r2, 210).unwrap();
    n.pull(0, 1);
    n.pull(1, 0);
    for d in &n.devs {
        let ids: Vec<Uuid> = d
            .get(id)
            .unwrap()
            .attachments
            .iter()
            .map(|a| a.id)
            .collect();
        assert!(ids.contains(&r1id) && ids.contains(&r2id), "union");
    }
    n.devs[0].remove_attachment_ref(id, r1id, 300).unwrap();
    // B touches the item later (field edit) but still holds the ref
    n.devs[1]
        .set_field_named(id, "username", pw("later"), 400)
        .unwrap();
    n.pull(1, 0);
    n.pull(0, 1);
    for d in &n.devs {
        let ids: Vec<Uuid> = d
            .get(id)
            .unwrap()
            .attachments
            .iter()
            .map(|a| a.id)
            .collect();
        assert!(!ids.contains(&r1id), "removal survives merge");
        assert!(ids.contains(&r2id));
    }
    let all: Vec<Uuid> = n.devs[0].attachment_ids().collect();
    assert!(all.contains(&r2id));
    // tombstoned item keeps refs for orphan protection (03 §1.1)
    n.devs[0].delete(id, 500).unwrap();
    assert!(
        n.devs[0].attachment_ids().any(|x| x == r2id),
        "tombstone keeps refs"
    );
    // validate_ref on write paths (01 §4): oversize ref refused
    assert!(
        attachment::new_ref("big", 100_000_001, 1).is_err(),
        "100 MB cap"
    );
    assert!(attachment::new_ref("max", 100_000_000, 1).is_ok());
}

/// 03 §5 timestamps monotone per item: every write stamps max(now, previous+1).
#[test]
fn m07_monotone_stamps() {
    let mut n = Net::new(1);
    let id = seeded(&mut n, 1_000);
    let ma0 = n.devs[0].get(id).unwrap().modified_at;
    n.devs[0]
        .set_field_named(id, "username", pw("back"), 10)
        .unwrap();
    let it = n.devs[0].get(id).unwrap();
    let f = it.fields.iter().find(|f| f.name == "username").unwrap();
    assert!(
        f.modified_at > 1_000,
        "field stamp moved forward despite clock going back: {}",
        f.modified_at
    );
    assert!(it.modified_at > ma0);
    let ma1 = it.modified_at;
    n.devs[0].delete(id, 5).unwrap();
    let it = n.devs[0]
        .items_including_deleted()
        .find(|i| i.id == id)
        .unwrap();
    assert!(it.deleted_at.unwrap() > ma0, "deleted_at monotone");
    assert!(it.modified_at > ma1);
    // tombstone written with a backwards clock still beats the older edit on another device
}

/// 02 update: changing a value without bumping modified_at -> update bumps it to now, others untouched;
/// item modified_at = max(...).
#[test]
fn m08_update_diff_bump() {
    let mut n = Net::new(1);
    let id = seeded(&mut n, 100);
    n.devs[0]
        .update(id, 5_000, |it| {
            let f = it.fields.iter_mut().find(|f| f.name == "username").unwrap();
            f.value = pw("changed");
        })
        .unwrap();
    let it = n.devs[0].get(id).unwrap();
    assert_eq!(
        it.fields
            .iter()
            .find(|f| f.name == "username")
            .unwrap()
            .modified_at,
        5_000
    );
    assert_eq!(
        it.fields
            .iter()
            .find(|f| f.name == "password")
            .unwrap()
            .modified_at,
        100,
        "untouched field keeps stamp"
    );
    assert_eq!(it.modified_at, 5_000);
    // section and kind changes are content too: must propagate under LWW
    let mut m = Net::new(2);
    let id = seeded(&mut m, 100);
    m.devs[0]
        .update(id, 6_000, |it| {
            let f = it.fields.iter_mut().find(|f| f.name == "username").unwrap();
            f.section = Some("S".into());
        })
        .unwrap();
    m.pull(1, 0);
    assert_eq!(
        m.devs[1]
            .get(id)
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == "username")
            .unwrap()
            .section
            .as_deref(),
        Some("S"),
        "section change propagates"
    );
}

/// 03 §5: merge requires same vault_id (else error).
#[test]
fn m09_foreign_vault_merge_refused() {
    let mut a = UnlockedVault::create(&pw("pw"), KdfParams::for_tests(), Uuid::new_v4());
    let b = UnlockedVault::create(&pw("pw"), KdfParams::for_tests(), Uuid::new_v4());
    assert!(a.merge_from(&b).is_err());
}

/// 03 §5 idempotent + commutative; "Two devices converge within two merge rounds"; three devices,
/// seeded random edit scripts including deletes, resurrects, ties and backward clocks.
#[test]
fn m10_random_scripts_converge() {
    use rand::{Rng, SeedableRng};
    let mut failures = vec![];
    for seed in 0..60u64 {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let nd = if seed % 2 == 0 { 2 } else { 3 };
        let mut n = Net::new(nd);
        let mut ids = vec![];
        for _ in 0..3 {
            ids.push(seeded(&mut n, 100));
        }
        let mut clock = vec![1_000u64; nd];
        for _step in 0..40 {
            let d = rng.gen_range(0..nd);
            // occasional clock skew backwards, occasional exact ties across devices
            clock[d] = match rng.gen_range(0..10) {
                0 => clock[d].saturating_sub(50),
                1 => 5_000,
                _ => clock[d] + rng.gen_range(1..20),
            };
            let now = clock[d];
            let id = ids[rng.gen_range(0..ids.len())];
            match rng.gen_range(0..8) {
                0 => {
                    let _ = n.devs[d].delete(id, now);
                }
                1 => {
                    let dev = n.devs[d].device_id();
                    ids.push(n.devs[d].insert(login(dev, now), now));
                }
                2 => {
                    let _ = n.devs[d].update(id, now, |it| it.title = format!("t{now}"));
                }
                3 => {
                    let _ = n.devs[d].update(id, now, |it| it.favorite = !it.favorite);
                }
                4 | 5 => {
                    let _ =
                        n.devs[d].set_field_named(id, "password", pw(&format!("p{d}-{now}")), now);
                }
                6 => {
                    let _ =
                        n.devs[d].set_field_named(id, "username", pw(&format!("u{d}-{now}")), now);
                }
                _ => {
                    let o = rng.gen_range(0..nd);
                    if o != d {
                        n.pull(d, o);
                    }
                }
            }
        }
        // commutativity on contents: X<-Y vs Y<-X
        if nd >= 2 {
            let x = n.disk(0, 0);
            let y = n.disk(1, 0);
            let mut xy = n.disk(0, 0);
            xy.merge_from(&y).unwrap();
            let mut yx = n.disk(1, 0);
            yx.merge_from(&x).unwrap();
            if snap_content(&xy) != snap_content(&yx) {
                failures.push(format!("seed {seed}: not commutative"));
            }
        }
        // two rounds of all-pairs
        for _round in 0..2 {
            for a in 0..nd {
                for b in 0..nd {
                    if a != b {
                        n.pull(a, b);
                    }
                }
            }
        }
        let s0 = snap_vault(&n.devs[0]);
        for i in 1..nd {
            if snap_vault(&n.devs[i]) != s0 {
                failures.push(format!("seed {seed}: device {i} differs after two rounds"));
            }
        }
        // idempotence: another round changes nothing
        let before = snap_vault(&n.devs[0]);
        n.pull(0, 1);
        if snap_vault(&n.devs[0]) != before {
            failures.push(format!("seed {seed}: not idempotent"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// 03 §5: "If a merge changes an item's content without changing its modified_at ... the merge
/// bumps modified_at by one so the manifest check and the other device see the change."
#[test]
fn m11_equal_stamp_content_change_visible() {
    let mut n = Net::new(3);
    let id = seeded(&mut n, 100);
    n.devs[0]
        .set_field_named(id, "username", pw("A"), 500)
        .unwrap();
    n.devs[1]
        .set_field_named(id, "username", pw("B"), 500)
        .unwrap();
    n.pull(2, 0);
    n.pull(2, 1); // C may now hold the tie winner with ma 500
    n.pull(0, 2);
    n.pull(1, 2);
    n.pull(2, 0);
    n.pull(2, 1);
    for _ in 0..2 {
        for a in 0..3 {
            for b in 0..3 {
                if a != b {
                    n.pull(a, b);
                }
            }
        }
    }
    let s = snap_vault(&n.devs[0]);
    assert_eq!(snap_vault(&n.devs[1]), s);
    assert_eq!(snap_vault(&n.devs[2]), s);
}

/// 03 §5 (attachments paragraph, merge-only cap): a local removal never drops a
/// `removed_attachments` marker; a merge caps them at 64, dropping oldest `removed_at` first,
/// and only markers whose reference neither side still holds.
#[test]
fn m12_tombstone_caps() {
    let mut n = Net::new(2);
    let id = seeded(&mut n, 100);
    for i in 0..80u64 {
        let r = attachment::new_ref("x", 1, 200 + i).unwrap();
        let rid = r.id;
        n.devs[0].add_attachment_ref(id, r, 200 + i).unwrap();
        n.devs[0].remove_attachment_ref(id, rid, 300 + i).unwrap();
    }
    let it = n.devs[0].get(id).unwrap();
    assert_eq!(
        it.removed_attachments.len(),
        80,
        "local removal must not cap markers"
    );
    let mut all: Vec<_> = it
        .removed_attachments
        .iter()
        .map(|t| (t.removed_at, t.id))
        .collect();
    all.sort();
    let newest: Vec<_> = all[16..].to_vec();

    // Device 1 never saw any of these refs: neither side holds them, so the merge caps.
    n.pull(1, 0);
    let it = n.devs[1].get(id).unwrap();
    assert_eq!(it.removed_attachments.len(), 64, "merge caps at 64");
    let mut got: Vec<_> = it
        .removed_attachments
        .iter()
        .map(|t| (t.removed_at, t.id))
        .collect();
    got.sort();
    assert_eq!(got, newest, "the 64 newest by removed_at survive");
}

/// 02 purge_tombstones_older_than removes only old tombstones.
#[test]
fn m13_purge() {
    let mut n = Net::new(1);
    let a = seeded(&mut n, 100);
    let b = seeded(&mut n, 100);
    n.devs[0].delete(a, 1_000).unwrap();
    n.devs[0].delete(b, 9_000).unwrap();
    assert_eq!(n.devs[0].purge_tombstones_older_than(5_000), 1);
    assert!(n.devs[0].items_including_deleted().all(|i| i.id != a));
    assert!(n.devs[0].items_including_deleted().any(|i| i.id == b));
}
