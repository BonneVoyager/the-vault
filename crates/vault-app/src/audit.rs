//! Weak and reused password warnings, modelled on Apple's Passwords app.
//!
//! Pure functions over an `UnlockedVault`. `AppState::vault_changed` audits once per
//! content change and stores the result on the listing, where the list badges and the
//! per-field strips (05 §2.3 "Password notices") read it. The editor checks the typed
//! value live with [`strength_bits`] and [`reuse_count`].
//! Compromised-password (data leak) checks are out of scope: the app makes no network
//! requests (00-overview).

use std::collections::HashMap;

pub use vault_core::generator::strength_bits;
use vault_core::{ExposeSecret, FieldKind, Item, UnlockedVault, Uuid};

/// A password scoring under this many bits of estimated entropy is weak. Same cut-off as
/// the "Weak" band of the generator's strength meter (`ui::strength_label`). Eased from 40
/// to 36 on 2026-11-17 (05 §2.1) so a 12-character random password (about 39.8 bits under
/// zxcvbn) is not flagged.
pub const WEAK_BELOW_BITS: f64 = 36.;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Issue {
    /// The password field scores `bits`.
    Weak { bits: f64 },
    /// The field's password is used by `count` live items, this one included.
    Reused { count: usize },
}

impl Issue {
    /// Bold strip title.
    pub fn title(&self) -> &'static str {
        match self {
            Issue::Weak { .. } => "Weak Password",
            Issue::Reused { .. } => "Reused Password",
        }
    }

    /// Short label for the list badge tooltip.
    pub fn short(&self) -> &'static str {
        match self {
            Issue::Weak { .. } => "Weak password",
            Issue::Reused { .. } => "Reused password",
        }
    }

    /// Strip body text.
    pub fn body(&self) -> String {
        match self {
            Issue::Weak { .. } => "This password is easy to guess and should be changed.".into(),
            Issue::Reused { count } => {
                let others = count.saturating_sub(1);
                let noun = if others == 1 { "item" } else { "items" };
                format!(
                    "Used by {others} other {noun}. Reuse lets one leak unlock several accounts."
                )
            }
        }
    }

    /// Same kind, ignoring the numbers (the list badge shows distinct kinds).
    pub fn same_kind(&self, other: &Issue) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

/// One issue of one password field.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FieldIssue {
    pub field: Uuid,
    pub issue: Issue,
}

/// Item id -> its password fields' issues.
pub type Issues = HashMap<Uuid, Vec<FieldIssue>>;

/// The issues of one password `value` held by item `item`: weak first, then reused
/// (against the other live items of `vault`). Empty for an empty value.
pub fn value_issues(vault: &UnlockedVault, value: &str, item: Uuid) -> Vec<Issue> {
    scored_value_issues(vault, value, strength_bits(value), item)
}

/// [`value_issues`] for a value whose [`strength_bits`] the caller already has (the
/// editor scores each typed value once, for the meter and the notices).
pub fn scored_value_issues(
    vault: &UnlockedVault,
    value: &str,
    bits: f64,
    item: Uuid,
) -> Vec<Issue> {
    if value.is_empty() {
        return Vec::new();
    }
    let mut issues = Vec::new();
    if bits < WEAK_BELOW_BITS {
        issues.push(Issue::Weak { bits });
    }
    let others = reuse_count(vault, value, item);
    if others > 0 {
        issues.push(Issue::Reused { count: others + 1 });
    }
    issues
}

/// How many live items other than `exclude` have a Password field equal to `value`
/// (each item counted once). Zero for an empty value.
pub fn reuse_count(vault: &UnlockedVault, value: &str, exclude: Uuid) -> usize {
    if value.is_empty() {
        return 0;
    }
    vault
        .items()
        .filter(|item| item.id != exclude)
        .filter(|item| {
            item.fields.iter().any(|f| {
                let v: &str = f.value.expose_secret();
                f.kind == FieldKind::Password && v == value
            })
        })
        .count()
}

/// Audits every live item's Password fields. Items without issues are absent from the
/// map. Every weak field and every reused field is listed, fields in item order, weak
/// before reused within a field. Empty passwords are skipped; the same password twice
/// in one item is not reuse.
///
/// Grouping keys are `&str` borrowed from the vault for the duration of this call; no
/// password is copied into an owned string. Each distinct value is scored with
/// [`strength_bits`] (zxcvbn, up to ~13 ms for a long random value) at most once per
/// call; the scores are dropped with the map when the call returns.
pub fn audit(vault: &UnlockedVault) -> Issues {
    // The item's non-empty passwords, borrowed: (field id, value).
    fn passwords(item: &Item) -> impl Iterator<Item = (Uuid, &str)> {
        item.fields.iter().filter_map(|f| {
            let value: &str = f.value.expose_secret();
            (f.kind == FieldKind::Password && !value.is_empty()).then_some((f.id, value))
        })
    }
    // Per distinct password value: the live items that use it (each id once) and its
    // strength, scored on first use below.
    #[derive(Default)]
    struct Seen {
        ids: Vec<Uuid>,
        bits: Option<f64>,
    }
    let mut by_value: HashMap<&str, Seen> = HashMap::new();
    for item in vault.items() {
        for (_, value) in passwords(item) {
            let ids = &mut by_value.entry(value).or_default().ids;
            if ids.last() != Some(&item.id) {
                ids.push(item.id);
            }
        }
    }

    let mut issues = Issues::new();
    for item in vault.items() {
        let mut found = Vec::new();
        for (field, value) in passwords(item) {
            // Every value was entered by the first pass.
            let seen = by_value.entry(value).or_default();
            let bits = *seen.bits.get_or_insert_with(|| strength_bits(value));
            let count = seen.ids.len();
            if bits < WEAK_BELOW_BITS {
                found.push(FieldIssue {
                    field,
                    issue: Issue::Weak { bits },
                });
            }
            if count >= 2 {
                found.push(FieldIssue {
                    field,
                    issue: Issue::Reused { count },
                });
            }
        }
        if !found.is_empty() {
            issues.insert(item.id, found);
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{Field, KdfParams, SecretString};

    const STRONG: &str = "correct-Horse-battery-staple-42";
    const STRONG_2: &str = "Tr0ub4dor&3-plus-much-more-entropy";

    fn vault() -> UnlockedVault {
        let pw = SecretString::new("pw".into());
        UnlockedVault::create(&pw, KdfParams::for_tests(), Uuid::new_v4())
    }

    fn login(v: &mut UnlockedVault, title: &str, passwords: &[&str]) -> Uuid {
        let mut item = Item::new(title, v.device_id(), 1);
        for (i, pw) in passwords.iter().enumerate() {
            item.fields.push(Field::new(
                format!("password{i}"),
                FieldKind::Password,
                SecretString::new((*pw).into()),
                1,
            ));
        }
        v.insert(item, 1)
    }

    fn field_ids(v: &UnlockedVault, id: Uuid) -> Vec<Uuid> {
        v.get(id).unwrap().fields.iter().map(|f| f.id).collect()
    }

    /// The issues of `id`, without field ids.
    fn kinds(issues: &Issues, id: Uuid) -> Vec<Issue> {
        issues[&id].iter().map(|f| f.issue).collect()
    }

    #[test]
    fn weak_password_is_flagged() {
        let mut v = vault();
        let id = login(&mut v, "Bank", &["123"]);
        let issues = audit(&v);
        assert_eq!(issues[&id][0].field, field_ids(&v, id)[0]);
        match kinds(&issues, id).as_slice() {
            [Issue::Weak { bits }] => assert!(*bits < WEAK_BELOW_BITS),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// 05 §2.1 / §2.3 (2026-11-17): Weak < 36, so a 12-character random generator output is
    /// not flagged while "password123" still is. zxcvbn spots chance patterns in about 0.4 %
    /// of 12-character outputs (measured over 5000: min 31.7 bits, 1st percentile 37.2,
    /// median 39.9), so a literal "none of 50" would fail about 1 run in 6; the test asserts
    /// the typical output clears the bar and at most 3 of 50 do not (false failure ~5e-5).
    #[test]
    fn twelve_char_random_is_not_weak_but_password123_is() {
        assert_eq!(WEAK_BELOW_BITS, 36.);
        let spec = vault_core::generator::PasswordSpec {
            length: 12,
            ..Default::default()
        };
        let mut bits: Vec<f64> = (0..50)
            .map(|_| {
                let pw = vault_core::generator::password(&spec);
                vault_core::strength_bits(pw.expose_secret())
            })
            .collect();
        bits.sort_by(f64::total_cmp);
        let weak = bits.iter().filter(|&&b| b < WEAK_BELOW_BITS).count();
        assert!(bits[25] >= WEAK_BELOW_BITS, "median {:.1} bits", bits[25]);
        assert!(weak <= 3, "{weak} of 50 flagged weak: {bits:?}");

        assert!(vault_core::strength_bits("password123") < WEAK_BELOW_BITS);
        let mut v = vault();
        let id = login(&mut v, "Old", &["password123"]);
        assert!(matches!(
            kinds(&audit(&v), id).as_slice(),
            [Issue::Weak { .. }]
        ));
    }

    #[test]
    fn strong_unique_passwords_have_no_issues() {
        let mut v = vault();
        login(&mut v, "A", &[STRONG]);
        login(&mut v, "B", &[STRONG_2]);
        login(&mut v, "Empty", &[""]);
        assert!(audit(&v).is_empty());
    }

    #[test]
    fn reuse_across_two_and_three_items() {
        let mut v = vault();
        let a = login(&mut v, "A", &[STRONG]);
        let b = login(&mut v, "B", &[STRONG]);
        let c = login(&mut v, "C", &[STRONG_2]);
        let issues = audit(&v);
        assert_eq!(kinds(&issues, a), [Issue::Reused { count: 2 }]);
        assert_eq!(kinds(&issues, b), [Issue::Reused { count: 2 }]);
        assert!(!issues.contains_key(&c));

        let d = login(&mut v, "D", &[STRONG]);
        let issues = audit(&v);
        for id in [a, b, d] {
            assert_eq!(kinds(&issues, id), [Issue::Reused { count: 3 }]);
        }
        assert_eq!(
            Issue::Reused { count: 3 }.body(),
            "Used by 2 other items. Reuse lets one leak unlock several accounts."
        );
        assert_eq!(
            Issue::Reused { count: 2 }.body(),
            "Used by 1 other item. Reuse lets one leak unlock several accounts."
        );
    }

    #[test]
    fn only_password_fields_are_audited() {
        let mut v = vault();
        let mut item = Item::new("Pin", v.device_id(), 1);
        for kind in [
            FieldKind::Text,
            FieldKind::Date,
            FieldKind::Notes,
            FieldKind::Pin,
            FieldKind::Other,
        ] {
            item.fields
                .push(Field::new("pin", kind, SecretString::new("123".into()), 1));
        }
        v.insert(item.clone(), 1);
        // Same weak, shared values in a second item: still not passwords.
        let mut twin = item;
        twin.id = Uuid::new_v4();
        let twin_id = v.insert(twin, 1);
        assert!(audit(&v).is_empty());
        // A short PIN shared by both items is no reuse and no weakness (05 §2.3 `pin`).
        assert_eq!(reuse_count(&v, "123", twin_id), 0);
    }

    #[test]
    fn every_weak_field_is_reported_in_item_order() {
        let mut v = vault();
        let id = login(&mut v, "Multi", &["abcdefgh", STRONG, "123"]);
        let fields = field_ids(&v, id);
        let issues = audit(&v);
        assert_eq!(
            issues[&id],
            [
                FieldIssue {
                    field: fields[0],
                    issue: Issue::Weak {
                        bits: strength_bits("abcdefgh")
                    },
                },
                FieldIssue {
                    field: fields[2],
                    issue: Issue::Weak {
                        bits: strength_bits("123")
                    },
                },
            ]
        );
    }

    #[test]
    fn every_reused_field_is_reported_with_its_own_count() {
        let mut v = vault();
        // A shares STRONG with B and STRONG_2 with C and D.
        let a = login(&mut v, "A", &[STRONG, STRONG_2]);
        let b = login(&mut v, "B", &[STRONG]);
        let c = login(&mut v, "C", &[STRONG_2]);
        let d = login(&mut v, "D", &[STRONG_2]);
        let issues = audit(&v);
        let fa = field_ids(&v, a);
        assert_eq!(
            issues[&a],
            [
                FieldIssue {
                    field: fa[0],
                    issue: Issue::Reused { count: 2 },
                },
                FieldIssue {
                    field: fa[1],
                    issue: Issue::Reused { count: 3 },
                },
            ]
        );
        assert_eq!(kinds(&issues, b), [Issue::Reused { count: 2 }]);
        assert_eq!(kinds(&issues, c), [Issue::Reused { count: 3 }]);
        assert_eq!(kinds(&issues, d), [Issue::Reused { count: 3 }]);
    }

    #[test]
    fn same_password_twice_in_one_item_is_not_reuse() {
        let mut v = vault();
        login(&mut v, "A", &[STRONG, STRONG]);
        assert!(audit(&v).is_empty());
    }

    #[test]
    fn weak_and_reused_both_reported_weak_first() {
        let mut v = vault();
        let a = login(&mut v, "A", &["123"]);
        let b = login(&mut v, "B", &["123"]);
        let issues = audit(&v);
        for id in [a, b] {
            assert!(issues[&id].iter().all(|f| f.field == field_ids(&v, id)[0]));
            assert!(matches!(
                kinds(&issues, id).as_slice(),
                [Issue::Weak { .. }, Issue::Reused { count: 2 }]
            ));
        }
    }

    #[test]
    fn reuse_count_excludes_the_item_and_counts_items_once() {
        let mut v = vault();
        let a = login(&mut v, "A", &[STRONG]);
        let b = login(&mut v, "B", &[STRONG, STRONG]);
        login(&mut v, "C", &[STRONG_2]);
        assert_eq!(reuse_count(&v, STRONG, a), 1);
        assert_eq!(reuse_count(&v, STRONG, b), 1);
        assert_eq!(reuse_count(&v, STRONG, Uuid::new_v4()), 2);
        assert_eq!(reuse_count(&v, "", Uuid::new_v4()), 0);
        assert_eq!(reuse_count(&v, "unused", a), 0);
        v.delete(b, 2).unwrap();
        assert_eq!(reuse_count(&v, STRONG, a), 0, "tombstones do not count");

        assert!(value_issues(&v, "", a).is_empty());
        assert!(matches!(
            value_issues(&v, STRONG_2, a).as_slice(),
            [Issue::Reused { count: 2 }]
        ));
        assert!(matches!(
            value_issues(&v, "123", a).as_slice(),
            [Issue::Weak { .. }]
        ));
    }

    #[test]
    fn shared_value_is_scored_once_with_identical_results() {
        let mut v = vault();
        let a = login(&mut v, "A", &["abcdefgh", STRONG]);
        let b = login(&mut v, "B", &["abcdefgh"]);
        let c = login(&mut v, "C", &[STRONG_2]);
        let issues = audit(&v);
        let bits = strength_bits("abcdefgh");
        let (fa, fb) = (field_ids(&v, a), field_ids(&v, b));
        // Both items carry the same bits, equal to a fresh score, weak before reused.
        assert_eq!(
            issues[&a],
            [
                FieldIssue {
                    field: fa[0],
                    issue: Issue::Weak { bits },
                },
                FieldIssue {
                    field: fa[0],
                    issue: Issue::Reused { count: 2 },
                },
            ]
        );
        assert_eq!(
            issues[&b],
            [
                FieldIssue {
                    field: fb[0],
                    issue: Issue::Weak { bits },
                },
                FieldIssue {
                    field: fb[0],
                    issue: Issue::Reused { count: 2 },
                },
            ]
        );
        assert!(!issues.contains_key(&c));
        // The per-value path agrees with the vault-wide audit, field by field.
        for id in [a, b] {
            let item = v.get(id).unwrap();
            let per_field: Vec<Issue> = item
                .fields
                .iter()
                .flat_map(|f| value_issues(&v, f.value.expose_secret(), id))
                .collect();
            assert_eq!(per_field, kinds(&issues, id));
        }
        // Deterministic: a second run over the same vault is identical.
        assert_eq!(audit(&v), issues);
    }

    /// 500 items of 20 pseudo-random characters, `distinct` distinct values.
    fn bench_vault(distinct: usize) -> UnlockedVault {
        const ALPHABET: &[u8] =
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#%&*+-=?@";
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let values: Vec<String> = (0..distinct)
            .map(|_| {
                (0..20)
                    .map(|_| {
                        seed = seed
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(1_442_695_040_888_963_407);
                        ALPHABET[(seed >> 33) as usize % ALPHABET.len()] as char
                    })
                    .collect()
            })
            .collect();
        let mut v = vault();
        for i in 0..500 {
            login(&mut v, &format!("Item {i}"), &[&values[i % distinct]]);
        }
        v
    }

    /// Timing only: `cargo test -p vault-app audit_timing -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn audit_timing_500_items() {
        for distinct in [50, 500] {
            let v = bench_vault(distinct);
            let _ = audit(&v); // warm-up
            let runs = 5;
            let start = std::time::Instant::now();
            for _ in 0..runs {
                std::hint::black_box(audit(&v));
            }
            let per_run = start.elapsed() / runs;
            eprintln!("audit: 500 items, {distinct} distinct values: {per_run:?} per run");
        }
    }

    #[test]
    fn tombstones_are_excluded() {
        let mut v = vault();
        let a = login(&mut v, "A", &[STRONG]);
        let b = login(&mut v, "B", &[STRONG]);
        let weak = login(&mut v, "Weak", &["123"]);
        v.delete(b, 2).unwrap();
        v.delete(weak, 2).unwrap();
        let issues = audit(&v);
        assert!(!issues.contains_key(&a));
        assert!(issues.is_empty());
    }
}
