//! Recently Deleted (2026-11-03): 02 "Recently Deleted", 02 UnlockedVault delete/recover/
//! delete_permanently/expire_deleted/deleted_items, 03 §5 "both tombstones" row, 03 §1.1
//! "Recently Deleted and backups", 05 §2.3 "Recently Deleted".
//! Written from the specs only. A passing check shows the behaviour on these inputs, not a proof.
use secrecy::ExposeSecret;
use spec_checks::dev::{Dev, now_ms, primary};
use spec_checks::*;
use uuid::Uuid;
use vault_core::*;

struct Net {
    devs: Vec<UnlockedVault>,
}
impl Net {
    fn new(n: usize) -> Net {
        Self::with_ids(&(0..n).map(|_| Uuid::new_v4()).collect::<Vec<_>>())
    }
    fn with_ids(ids: &[Uuid]) -> Net {
        let base = UnlockedVault::create(&pw("pw"), KdfParams::for_tests(), Uuid::new_v4());
        let bytes = base.serialize();
        let l = LockedVault::parse(&bytes).unwrap();
        let k = base.export_vault_key();
        Net {
            devs: ids
                .iter()
                .map(|d| l.unlock_with_key(&k, *d).unwrap())
                .collect(),
        }
    }
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
    fn converge(&mut self) {
        for _ in 0..4 {
            for a in 0..self.devs.len() {
                for b in 0..self.devs.len() {
                    if a != b {
                        self.pull(a, b);
                    }
                }
            }
        }
    }
}

fn rich_item(v: &mut UnlockedVault, now: u64) -> Uuid {
    let dev = v.device_id();
    let mut it = Item::new("Bank", dev, now);
    it.tags = vec!["money".into(), "login".into()];
    it.favorite = true;
    it.fields
        .push(Field::new("username", FieldKind::Text, pw("alice"), now));
    it.fields
        .push(Field::new("password", FieldKind::Password, pw("pw-1"), now));
    it.fields
        .push(Field::new("pin", FieldKind::Password, pw("1234"), now));
    let id = v.insert(it, now);
    let pid = v.get(id).unwrap().fields[1].id;
    v.set_field(id, pid, pw("pw-2"), now + 1).unwrap(); // history entry
    let pin = v.get(id).unwrap().fields[2].id;
    v.remove_field(id, pin, now + 2).unwrap(); // removed_fields marker
    let r = attachment::new_ref("doc.pdf", 10, now + 3).unwrap();
    v.add_attachment_ref(id, r, now + 3).unwrap();
    let r2 = attachment::new_ref("gone.txt", 3, now + 4).unwrap();
    let r2id = r2.id;
    v.add_attachment_ref(id, r2, now + 4).unwrap();
    v.remove_attachment_ref(id, r2id, now + 5).unwrap(); // removed_attachments marker
    id
}

fn field_snap(it: &Item) -> Vec<(Uuid, String, String, u64)> {
    it.fields
        .iter()
        .map(|f| {
            (
                f.id,
                f.name.clone(),
                f.value.expose_secret().clone(),
                f.modified_at,
            )
        })
        .collect()
}

fn reopen(v: &UnlockedVault) -> UnlockedVault {
    LockedVault::parse(&v.serialize())
        .unwrap()
        .unlock(&pw("pw"))
        .unwrap()
}

fn plain_of(v: &UnlockedVault, id: Uuid) -> Value {
    let o = indep::open_file(&v.serialize(), "pw");
    o.items
        .into_iter()
        .find(|(i, _, _)| i == id.as_bytes())
        .unwrap()
        .2
}

fn plain_keys(p: &Value) -> Vec<String> {
    p.as_map()
        .unwrap()
        .iter()
        .map(|(k, _)| k.as_text().unwrap_or("?").to_string())
        .collect()
}

fn list_len(p: &Value, k: &str) -> usize {
    get(p, k).and_then(|v| v.as_array()).map_or(0, |a| a.len())
}

/// 02: "`delete` keeps the whole item under its tombstone: fields, history, attachment refs, extras
/// and the removal markers." `items()` excludes tombstones; `deleted_items()` lists tombstones that
/// still have content; the content survives a serialize/parse round trip; `attachment_ids` covers
/// tombstones ("all items incl. tombstones, for orphan cleanup").
#[test]
fn tr01_delete_keeps_content() {
    let mut v = UnlockedVault::create(&pw("pw"), KdfParams::for_tests(), Uuid::new_v4());
    let id = rich_item(&mut v, 1_000);
    let before = v.get(id).unwrap().clone();
    let aid = before.attachments[0].id;
    assert_eq!(before.history.len(), 1);
    assert_eq!(before.removed_fields.len(), 1);
    v.delete(id, 2_000).unwrap();
    let t = v.get(id).expect("02: delete keeps id");
    assert!(t.deleted_at.is_some_and(|d| d >= 2_000), "deleted_at set");
    assert_eq!(field_snap(t), field_snap(&before), "fields kept");
    assert_eq!(t.history.len(), 1, "history kept");
    assert_eq!(t.removed_fields.len(), 1, "removed_fields kept");
    assert_eq!(t.attachments.len(), 1, "attachment refs kept");
    assert!(t.has_content(), "02: has_content");
    assert!(
        !v.items().any(|i| i.id == id),
        "items() excludes tombstones"
    );
    assert!(v.items_including_deleted().any(|i| i.id == id));
    assert!(v.deleted_items().any(|i| i.id == id), "in the trash");
    assert!(
        v.attachment_ids().any(|a| a == aid),
        "02 attachment_ids incl. tombstones"
    );
    let p = plain_of(&v, id);
    assert_eq!(
        list_len(&p, "removed_attachments"),
        1,
        "markers kept on disk"
    );
    let r = reopen(&v);
    let t2 = r.get(id).unwrap();
    assert_eq!(field_snap(t2), field_snap(&before), "content persisted");
    assert!(r.deleted_items().any(|i| i.id == id));
    // 05 §2.3: deleted items never appear in search outside the trash filter
    let hits = search::search(
        &r,
        &search::Query {
            text: "Bank",
            tag: None,
            favorites_only: false,
        },
    );
    assert!(
        hits.iter().all(|i| i.id != id),
        "core search excludes trash"
    );
    let hits = search::search(
        &r,
        &search::Query {
            text: "",
            tag: Some("money"),
            favorites_only: false,
        },
    );
    assert!(hits.iter().all(|i| i.id != id), "tag filter excludes trash");
    let csv = export::export_csv(&r);
    let s = String::from_utf8_lossy(&csv.0);
    if s.contains("pw-2") {
        eprintln!("INFO export_csv includes an item that is in the trash");
    }
}

/// 02 recover: "clears deleted_at on a tombstone that still has content; restamps ... Err on
/// unknown id, a live item, or a stripped tombstone". "every mutation stamps modified_at = now and
/// device_id = self.device_id"; 03 §5 "every write stamps max(now, previous + 1)".
#[test]
fn tr02_recover() {
    let mut n = Net::new(2);
    let id = rich_item(&mut n.devs[0], 1_000);
    n.pull(1, 0);
    let before = n.devs[1].get(id).unwrap().clone();
    n.devs[1].delete(id, 5_000).unwrap();
    let t_mod = n.devs[1].get(id).unwrap().modified_at;
    // clock went backwards: recover at 10 must still restamp past the tombstone
    n.devs[1].recover(id, 10).unwrap();
    let r = n.devs[1].get(id).unwrap();
    assert!(r.deleted_at.is_none());
    assert!(r.modified_at > t_mod, "restamp max(now, prev+1)");
    assert_eq!(r.device_id, n.devs[1].device_id(), "device_id = self");
    assert_eq!(field_snap(r), field_snap(&before), "content back");
    assert!(n.devs[1].items().any(|i| i.id == id));
    assert!(!n.devs[1].deleted_items().any(|i| i.id == id));
    // the recovery propagates over the peer's tombstone? peer never saw the delete: live/live
    n.pull(0, 1);
    assert!(n.devs[0].get(id).unwrap().deleted_at.is_none());
    // errors
    assert!(
        n.devs[1].recover(Uuid::new_v4(), 6_000).is_err(),
        "unknown id"
    );
    assert!(n.devs[1].recover(id, 6_000).is_err(), "live item");
    n.devs[1].delete(id, 7_000).unwrap();
    n.devs[1].delete_permanently(id, 7_001).unwrap();
    assert!(n.devs[1].recover(id, 7_002).is_err(), "stripped tombstone");
}

/// 02: "Stripping a tombstone empties fields, history, attachments, removed_fields,
/// removed_attachments, removed_history and extras, keeps id, title, tags, favorite, icon,
/// created_at, deleted_at and the per-attribute stamps, and restamps modified_at = stamp(now,
/// previous) with device_id = self.device_id". delete_permanently: "Err on unknown id or a live
/// item".
#[test]
fn tr03_delete_permanently_strips() {
    let mut n = Net::new(2);
    let id = rich_item(&mut n.devs[0], 1_000);
    n.devs[0]
        .update(id, 1_100, |it| {
            it.icon = Some(ItemIcon {
                kind: "symbol".into(),
                value: "key".into(),
                color: Some("#ff0000".into()),
                extras: Default::default(),
            })
        })
        .unwrap();
    n.pull(1, 0);
    assert!(
        n.devs[1].delete_permanently(id, 1_500).is_err(),
        "live item"
    );
    assert!(
        n.devs[1].delete_permanently(Uuid::new_v4(), 1_500).is_err(),
        "unknown id"
    );
    n.devs[1].delete(id, 2_000).unwrap();
    let pre = n.devs[1].get(id).unwrap().clone();
    let pre_plain = plain_of(&n.devs[1], id);
    // clock behind: stamp(now, previous) must still exceed previous
    n.devs[1].delete_permanently(id, 1_200).unwrap();
    let s = n.devs[1].get(id).unwrap().clone();
    let mut bad = vec![];
    if !s.fields.is_empty() {
        bad.push("fields not emptied".to_string());
    }
    if !s.history.is_empty() {
        bad.push("history not emptied".into());
    }
    if !s.attachments.is_empty() {
        bad.push("attachments not emptied".into());
    }
    if !s.removed_fields.is_empty() {
        bad.push("removed_fields not emptied".into());
    }
    if s.has_content() {
        bad.push("has_content still true".into());
    }
    if s.title != pre.title
        || s.tags != pre.tags
        || s.favorite != pre.favorite
        || s.icon != pre.icon
        || s.created_at != pre.created_at
        || s.deleted_at != pre.deleted_at
    {
        bad.push("kept attribute changed".into());
    }
    if s.modified_at <= pre.modified_at {
        bad.push(format!(
            "modified_at {} not restamped past {}",
            s.modified_at, pre.modified_at
        ));
    }
    if s.device_id != n.devs[1].device_id() {
        bad.push("device_id not self".into());
    }
    let p = plain_of(&n.devs[1], id);
    for k in ["removed_attachments", "removed_history", "removed_fields"] {
        if list_len(&p, k) != 0 {
            bad.push(format!("{k} still on disk"));
        }
    }
    for k in [
        "title_modified_at",
        "favorite_modified_at",
        "tags_modified_at",
        "icon_modified_at",
    ] {
        if get(&pre_plain, k).is_some() && get(&p, k) != get(&pre_plain, k) {
            bad.push(format!(
                "{k} not kept: {:?} -> {:?}",
                get(&pre_plain, k),
                get(&p, k)
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    assert!(
        !n.devs[1].deleted_items().any(|i| i.id == id),
        "left the trash"
    );
    assert!(
        n.devs[1].items_including_deleted().any(|i| i.id == id),
        "id kept"
    );
    // a second delete_permanently on a stripped tombstone: unspecified; record
    let m = n.devs[1].get(id).unwrap().modified_at;
    let r = n.devs[1].delete_permanently(id, 9_000);
    eprintln!(
        "INFO delete_permanently on a stripped tombstone: {:?}, restamped: {}",
        r.is_ok(),
        n.devs[1].get(id).unwrap().modified_at != m
    );
    // propagation: the strip wins the whole-item merge on the peer that still has content
    n.pull(0, 1);
    let z = n.devs[0].get(id).unwrap();
    assert!(
        z.deleted_at.is_some() && !z.has_content(),
        "03 §5: permanent deletion propagates"
    );
}

/// 02 extras: the v1-forward fixture carries unknown keys at every level; a strip drops item extras
/// and keeps only the listed keys (plus the structural ones).
#[test]
fn tr04_strip_drops_extras_from_forward_fixture() {
    let b = fixture("v1-forward.vault");
    let mut v = LockedVault::parse(&b)
        .unwrap()
        .unlock(&pw(FIXTURE_PW))
        .unwrap();
    let ids: Vec<Uuid> = v.items_including_deleted().map(|i| i.id).collect();
    let o = indep::open_file(&b, FIXTURE_PW);
    let allowed = [
        "title",
        "deleted_at",
        "device_id",
        "favorite",
        "tags",
        "icon",
        "created_at",
        "title_modified_at",
        "favorite_modified_at",
        "tags_modified_at",
        "icon_modified_at",
        "fields",
        "attachments",
        "history",
        "removed_fields",
        "removed_attachments",
        "removed_history",
    ];
    let mut bad = vec![];
    for id in &ids {
        let had: Vec<String> = o
            .items
            .iter()
            .find(|(i, _, _)| i == id.as_bytes())
            .map(|(_, _, p)| plain_keys(p))
            .unwrap_or_default();
        if v.get(*id).unwrap().deleted_at.is_none() {
            v.delete(*id, 10_000_000_000_000).unwrap();
        }
        let _ = v.delete_permanently(*id, 10_000_000_000_001);
        let p = plain_of_pw(&v, *id, FIXTURE_PW);
        let extra: Vec<String> = plain_keys(&p)
            .into_iter()
            .filter(|k| !allowed.contains(&k.as_str()))
            .collect();
        if !extra.is_empty() {
            bad.push(format!("item {id}: kept extras {extra:?} (had {had:?})"));
        }
        for k in ["fields", "attachments", "history"] {
            if list_len(&p, k) != 0 {
                bad.push(format!("item {id}: {k} not empty"));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

fn plain_of_pw(v: &UnlockedVault, id: Uuid, pass: &str) -> Value {
    let o = indep::open_file(&v.serialize(), pass);
    o.items
        .into_iter()
        .find(|(i, _, _)| i == id.as_bytes())
        .unwrap()
        .2
}

/// 02 expire_deleted: "strips every tombstone with content whose deleted_at < cutoff, restamping
/// each; returns how many. Idempotent".
#[test]
fn tr05_expire_deleted() {
    let mut v = UnlockedVault::create(&pw("pw"), KdfParams::for_tests(), Uuid::new_v4());
    let a = rich_item(&mut v, 100);
    let b = rich_item(&mut v, 100);
    let c = rich_item(&mut v, 100);
    let live = rich_item(&mut v, 100);
    let old = rich_item(&mut v, 100);
    v.delete(old, 400).unwrap();
    v.delete_permanently(old, 450).unwrap();
    v.delete(a, 1_000).unwrap();
    v.delete(b, 2_000).unwrap();
    v.delete(c, 3_000).unwrap();
    let da = v.get(a).unwrap().deleted_at.unwrap();
    let db = v.get(b).unwrap().deleted_at.unwrap();
    let n1 = v.expire_deleted(db, 10_000);
    assert_eq!(
        n1, 1,
        "only deleted_at < cutoff (strict); the stripped one is not counted"
    );
    assert!(!v.get(a).unwrap().has_content() && da < db);
    assert!(
        v.get(b).unwrap().has_content(),
        "deleted_at == cutoff is kept"
    );
    assert!(v.get(live).unwrap().has_content() && v.get(live).unwrap().deleted_at.is_none());
    let snap: Vec<u64> = v.items_including_deleted().map(|i| i.modified_at).collect();
    assert_eq!(v.expire_deleted(db, 10_001), 0, "idempotent");
    let snap2: Vec<u64> = v.items_including_deleted().map(|i| i.modified_at).collect();
    assert_eq!(snap, snap2, "a no-op sweep restamps nothing");
    assert_eq!(v.expire_deleted(u64::MAX, 10_002), 2);
    assert_eq!(v.deleted_items().count(), 0);
    let ma = v.get(a).unwrap().modified_at;
    assert!(ma >= 10_000, "restamped at the sweep");
}

/// 02 has_content: "true when any of the emptied lists is non-empty". 05 §2.3: "⌘⌫ ... You can
/// recover it from Recently Deleted for 30 days." An item that has a title (and tags) but no
/// fields, history or attachments is a legitimate item; after `delete` it must be recoverable.
#[test]
fn tr06_item_without_fields_is_recoverable_after_delete() {
    let mut v = UnlockedVault::create(&pw("pw"), KdfParams::for_tests(), Uuid::new_v4());
    let dev = v.device_id();
    let mut it = Item::new("Only a title", dev, 100);
    it.tags = vec!["keep".into()];
    let id = v.insert(it, 100);
    v.delete(id, 200).unwrap();
    let in_trash = v.deleted_items().any(|i| i.id == id);
    let rec = v.recover(id, 300);
    assert!(
        in_trash && rec.is_ok(),
        "a deleted item without fields: in deleted_items = {in_trash}, recover = {:?} \
         (02 has_content is false for it, so it skips Recently Deleted and can never be recovered)",
        rec.err().map(|e| format!("{e:?}"))
    );
}

/// 03 §5 both tombstones: "whole-item last-writer-wins by modified_at ... A stripped tombstone is
/// restamped when stripped, so permanent deletion and 30-day expiry propagate". Three devices.
#[test]
fn tr07_strip_propagates_three_devices() {
    let mut n = Net::new(3);
    let id = rich_item(&mut n.devs[0], 100);
    n.converge();
    n.devs[0].delete(id, 1_000).unwrap();
    n.pull(1, 0);
    n.devs[1].expire_deleted(2_000, 5_000);
    // device 2 still has the live item (modified before the delete): order of pulls varies
    n.pull(2, 1);
    n.pull(0, 2);
    n.converge();
    let snaps: Vec<Vec<String>> = n.devs.iter().map(snap_vault).collect();
    assert!(snaps.windows(2).all(|w| w[0] == w[1]), "converged");
    let it = n.devs[0].get(id).unwrap();
    assert!(
        it.deleted_at.is_some() && !it.has_content(),
        "stripped everywhere"
    );
    assert!(n.devs.iter().all(|d| d.deleted_items().count() == 0));
}

/// 03 §5: "a recovery (live, restamped) beats any tombstone whose deleted_at is older than the
/// recovery, including a strip stamped later on another device (strips do not move deleted_at);
/// only a fresh delete after the recovery removes the item again".
#[test]
fn tr08_recover_vs_strip_race() {
    for strip_later in [true, false] {
        let mut n = Net::new(2);
        let id = rich_item(&mut n.devs[0], 100);
        n.devs[0].delete(id, 1_000).unwrap();
        n.pull(1, 0);
        let content = field_snap(n.devs[0].get(id).unwrap());
        let (tr, ts) = if strip_later {
            (2_000, 3_000)
        } else {
            (3_000, 2_000)
        };
        n.devs[0].recover(id, tr).unwrap();
        n.devs[1].delete_permanently(id, ts).unwrap();
        // simultaneous exchange
        let d0 = n.disk(0, 1);
        let d1 = n.disk(1, 0);
        n.devs[0].merge_from(&d1).unwrap();
        n.devs[1].merge_from(&d0).unwrap();
        n.converge();
        for (k, d) in n.devs.iter().enumerate() {
            let it = d.get(id).unwrap();
            assert!(
                it.deleted_at.is_none(),
                "strip_later={strip_later}: dev {k} item not live"
            );
            assert_eq!(field_snap(it), content, "dev {k}: content survives");
        }
        assert_eq!(snap_vault(&n.devs[0]), snap_vault(&n.devs[1]));
        // fresh delete after the recovery removes it again, with content (into the trash)
        n.devs[1].delete(id, 4_000).unwrap();
        n.converge();
        for d in &n.devs {
            assert!(d.deleted_items().any(|i| i.id == id));
        }
    }
}

/// 03 §5 both-tombstone tie: "tie → greater device_id, tie → greater canonical CBOR". Two devices
/// with a cloned device id delete in the same millisecond after diverging content edits; one
/// simultaneous exchange each way must converge.
#[test]
fn tr09_both_tombstone_tie_converges() {
    let same = Uuid::from_bytes([7; 16]);
    let mut n = Net::with_ids(&[same, same]);
    let id = rich_item(&mut n.devs[0], 100);
    n.pull(1, 0);
    let f0 = n.devs[0].get(id).unwrap().fields[0].id;
    n.devs[0].set_field(id, f0, pw("from-0"), 500).unwrap();
    n.devs[1].set_field(id, f0, pw("from-1"), 500).unwrap();
    n.devs[0].delete(id, 900).unwrap();
    n.devs[1].delete(id, 900).unwrap();
    assert_eq!(
        n.devs[0].get(id).unwrap().modified_at,
        n.devs[1].get(id).unwrap().modified_at
    );
    let d0 = n.disk(0, 1);
    let d1 = n.disk(1, 0);
    n.devs[0].merge_from(&d1).unwrap();
    n.devs[1].merge_from(&d0).unwrap();
    // 00 roadmap item 2: "content equal after one exchange with modified_at within 1 ms, fully
    // equal after two" (the +1 bump is one-sided)
    assert_eq!(
        snap_content(&n.devs[0]),
        snap_content(&n.devs[1]),
        "one exchange converges the content of the tie"
    );
    n.pull(0, 1);
    n.pull(1, 0);
    assert_eq!(
        snap_vault(&n.devs[0]),
        snap_vault(&n.devs[1]),
        "two rounds: fully equal"
    );
    let r = n.pull(0, 1);
    assert_eq!(r.updated + r.added + r.deleted, 0, "{r:?}");
}

/// 02 guarantee 9 with content: "`delete` then `merge_from` an older copy that still has the item →
/// item stays deleted", and the trash keeps the content.
#[test]
fn tr10_guarantee9_keeps_content() {
    let mut n = Net::new(2);
    let id = rich_item(&mut n.devs[0], 100);
    n.pull(1, 0);
    n.devs[0].delete(id, 1_000).unwrap();
    n.pull(0, 1);
    let it = n.devs[0].get(id).unwrap();
    assert!(it.deleted_at.is_some() && it.has_content());
    n.pull(1, 0);
    assert!(n.devs[1].deleted_items().any(|i| i.id == id));
    // edit after delete resurrects (03 §5 one-tombstone row)
    let mut m = Net::new(2);
    let id = rich_item(&mut m.devs[0], 100);
    m.pull(1, 0);
    m.devs[0].delete(id, 1_000).unwrap();
    let f = m.devs[1].get(id).unwrap().fields[0].id;
    m.devs[1].set_field(id, f, pw("later"), 2_000).unwrap();
    m.converge();
    assert!(m.devs[0].get(id).unwrap().deleted_at.is_none());
}

/// 02 purge_tombstones_older_than "is unchanged": a stripped tombstone older than the cutoff goes.
#[test]
fn tr11_purge_unchanged() {
    let mut v = UnlockedVault::create(&pw("pw"), KdfParams::for_tests(), Uuid::new_v4());
    let a = rich_item(&mut v, 100);
    v.delete(a, 200).unwrap();
    let n = v.purge_tombstones_older_than(1_000_000);
    eprintln!("INFO purge_tombstones_older_than removed {n} (tombstone with content)");
    assert!(v.items_including_deleted().all(|i| i.id != a) || n == 0);
}

/// 03 §1.1: "snapshots are byte copies of the vault file, so an item in the trash is inside any
/// snapshot taken during its window and comes back into the trash when that snapshot is restored;
/// after the window it is stripped from the file and absent from later snapshots. Snapshots are
/// not scrubbed."
#[test]
fn tr12_backups_not_scrubbed_and_restore_into_trash() {
    let d = tempdir();
    let pkg = d.path().join("tb.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("Trashy", now_ms());
    a.s.save().unwrap();
    a.s.edit(|v| v.delete(id, now_ms())).unwrap().unwrap();
    a.s.save().unwrap();
    let snap1 = a.s.backup_now().unwrap();
    a.s.edit(|v| v.delete_permanently(id, now_ms()))
        .unwrap()
        .unwrap();
    a.s.save().unwrap();
    let snap2 = a.s.backup_now().unwrap();
    let open = |p: &std::path::Path| {
        LockedVault::parse(&std::fs::read(p).unwrap())
            .unwrap()
            .unlock(&pw(spec_checks::dev::PW))
            .unwrap()
    };
    assert!(
        open(&snap1).deleted_items().any(|i| i.id == id),
        "snapshot 1 keeps trash"
    );
    assert!(!open(&snap2).deleted_items().any(|i| i.id == id));
    assert!(!open(&primary(&pkg)).deleted_items().any(|i| i.id == id));
    assert!(open(&snap1).get(id).unwrap().has_content(), "not scrubbed");
    a.s.restore_from(&snap1, &pw(spec_checks::dev::PW)).unwrap();
    let v = a.v();
    let it = v.get(id).expect("restored");
    assert!(
        it.deleted_at.is_some() && it.has_content(),
        "restored into the trash, not live: deleted_at={:?} content={}",
        it.deleted_at,
        it.has_content()
    );
    assert!(!v.items().any(|i| i.id == id));
}

/// 03 §1.1 orphan cleanup "a blob whose id is referenced by no item (live or tombstoned)"; 02
/// "attachment refs" kept on delete. A trashed item's attachment stays readable (05 §2.3: the trash
/// detail is the read-mode renderer with attachments) and referenced.
#[test]
fn tr13_trashed_attachment_stays_referenced() {
    let d = tempdir();
    let pkg = d.path().join("ta.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("WithFile", now_ms());
    let aid =
        a.s.add_attachment(id, "f.txt", &b"hello trash"[..], 11, now_ms())
            .unwrap();
    a.s.save().unwrap();
    a.s.edit(|v| v.delete(id, now_ms())).unwrap().unwrap();
    a.s.save().unwrap();
    assert!(a.v().attachment_ids().any(|x| x == aid));
    let r = a.s.open_attachment(id, aid);
    match r {
        Ok(mut rd) => {
            let mut s = vec![];
            std::io::Read::read_to_end(&mut rd, &mut s).unwrap();
            assert_eq!(s, b"hello trash");
        }
        Err(e) => eprintln!("INFO open_attachment on a trashed item: {e:?}"),
    }
    a.s.edit(|v| v.delete_permanently(id, now_ms()))
        .unwrap()
        .unwrap();
    assert!(
        !a.v().attachment_ids().any(|x| x == aid),
        "strip drops the ref"
    );
    a.s.save().unwrap();
    let blob = pkg
        .join("attachments")
        .join(format!("{}.bin", aid.simple()));
    assert!(blob.exists(), "03 §1.1: 24 h grace before an orphan goes");
}

/// 03 §9 two SyncedVault handles on one folder: delete on A reaches B into the trash, B recovers,
/// A sees the item live again; A deletes permanently, B ends stripped.
#[test]
fn tr14_two_handles_trash_round_trip() {
    let d = tempdir();
    let pkg = d.path().join("th.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("Shared", now_ms());
    a.s.save().unwrap();
    let mut b = Dev::open(&pkg);
    a.s.start_watching().unwrap();
    b.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    a.s.edit(|v| v.delete(id, now_ms())).unwrap().unwrap();
    a.s.save().unwrap();
    let t = std::time::Instant::now();
    while t.elapsed().as_secs() < 10 && !b.v().deleted_items().any(|i| i.id == id) {
        b.drain();
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        b.v().deleted_items().any(|i| i.id == id),
        "B sees it in the trash"
    );
    b.s.edit(|v| v.recover(id, now_ms())).unwrap().unwrap();
    b.s.save().unwrap();
    let t = std::time::Instant::now();
    while t.elapsed().as_secs() < 10 && a.v().get(id).unwrap().deleted_at.is_some() {
        a.drain();
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        a.v().get(id).unwrap().deleted_at.is_none(),
        "A sees the recovery"
    );
    a.s.edit(|v| {
        v.delete(id, now_ms()).unwrap();
        v.delete_permanently(id, now_ms())
    })
    .unwrap()
    .unwrap();
    a.s.save().unwrap();
    let t = std::time::Instant::now();
    while t.elapsed().as_secs() < 10 && b.v().get(id).unwrap().has_content() {
        b.drain();
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let it = b.v().get(id).unwrap();
    assert!(it.deleted_at.is_some() && !it.has_content(), "B stripped");
}

/// Corruption sweep over a file holding a trashed item with content and a stripped tombstone:
/// every cut offset fails cleanly; random bit flips never panic and never change items silently.
#[test]
fn tr15_corruption_sweep_with_trash() {
    let mut v = UnlockedVault::create(&pw("pw"), KdfParams::for_tests(), Uuid::new_v4());
    let a = rich_item(&mut v, 100);
    let b = rich_item(&mut v, 100);
    v.delete(a, 200).unwrap();
    v.delete(b, 200).unwrap();
    v.delete_permanently(b, 300).unwrap();
    let bytes = v.serialize();
    let snap = snap_vault(&reopen(&v));
    let try_open = |m: Vec<u8>| {
        std::panic::catch_unwind(move || {
            LockedVault::parse(&m)
                .and_then(|l| l.unlock(&pw("pw")))
                .map(|u| snap_vault(&u))
                .map_err(|e| format!("{e:?}"))
        })
    };
    let mut bad = vec![];
    for cut in 0..bytes.len() {
        match try_open(bytes[..cut].to_vec()) {
            Ok(Err(_)) => {}
            Ok(Ok(_)) => bad.push(format!("cut {cut}: accepted")),
            Err(_) => bad.push(format!("cut {cut}: panic")),
        }
    }
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x7a54);
    for _ in 0..600 {
        let mut m = bytes.clone();
        let p = rng.gen_range(0..m.len());
        m[p] ^= 1 << rng.gen_range(0..8);
        match try_open(m) {
            Ok(Ok(s)) if s != snap => bad.push(format!("flip at {p}: items changed")),
            Err(_) => bad.push(format!("flip at {p}: panic")),
            _ => {}
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 02 delete "keeps id AND content": `vault rm` (README: "Delete an item (tombstone)") leaves the
/// item in the trash with its fields, readable by vault-core.
#[test]
fn tr16_cli_rm_keeps_content() {
    let d = tempdir();
    let pkg = d.path().join("cr.vault");
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/vault");
    let run = |args: &[&str], env: &[(&str, &str)]| {
        let mut c = std::process::Command::new(&bin);
        c.arg("--vault")
            .arg(&pkg)
            .args(["--password-env", "QA_MPW"]);
        c.args(args).env("QA_MPW", spec_checks::dev::PW);
        for (k, v) in env {
            c.env(k, v);
        }
        let o = c.output().unwrap();
        assert!(
            o.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    };
    run(&["init", "--kdf-test-params", "--allow-weak"], &[]);
    run(
        &[
            "add",
            "--template",
            "login",
            "--title",
            "Gone",
            "--username",
            "me",
            "--password-field",
        ],
        &[("VAULT_ITEM_PASSWORD", "kept-secret")],
    );
    run(&["rm", "Gone"], &[]);
    let v = spec_checks::dev::read_vault(&pkg);
    let t = v
        .deleted_items()
        .find(|i| i.title == "Gone")
        .expect("in deleted_items after vault rm");
    assert!(
        t.fields
            .iter()
            .any(|f| f.value.expose_secret() == "kept-secret"),
        "password kept on the tombstone"
    );
}
