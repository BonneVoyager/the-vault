//! Weak and reused item-password warnings, modelled on Apple's Passwords app.
//!
//! Pure functions over an `UnlockedVault`. `AppState::vault_changed` audits once per
//! content change and stores the result on the listing, where the list rows and the
//! detail banners read it.
//! Compromised-password (data leak) checks are out of scope: the app makes no network
//! requests (00-overview).

use std::collections::HashMap;

use vault_core::generator::strength_bits;
use vault_core::{ExposeSecret, FieldKind, UnlockedVault, Uuid};

/// A password scoring under this many bits of estimated entropy is weak. Same cut-off as
/// the "Weak" band of the generator's strength meter (`ui::strength_label`).
pub const WEAK_BELOW_BITS: f64 = 40.;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Issue {
    /// The item's weakest password field scores `bits`.
    Weak { bits: f64 },
    /// One of the item's passwords is used by `count` live items, this one included.
    Reused { count: usize },
}

impl Issue {
    /// Bold banner title.
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

    /// Banner body text.
    pub fn body(&self) -> String {
        match self {
            Issue::Weak { .. } => "This password is easy to guess and should be changed.".into(),
            Issue::Reused { count } => {
                let others = count.saturating_sub(1);
                let noun = if others == 1 { "item" } else { "items" };
                format!(
                    "This password is used by {others} other {noun}. \
                     Reuse lets one leak unlock several accounts."
                )
            }
        }
    }
}

pub type Issues = HashMap<Uuid, Vec<Issue>>;

/// Audits every live item's Password fields. Items without issues are absent from the
/// map. Each item gets at most one `Weak` (its weakest password) and one `Reused` (its
/// most shared password), in that order. Empty passwords are skipped.
///
/// Grouping keys are `&str` borrowed from the vault for the duration of this call; no
/// password is copied into an owned string.
pub fn audit(vault: &UnlockedVault) -> Issues {
    let mut weakest: Vec<(Uuid, f64)> = Vec::new();
    // Password value -> ids of the live items that use it (each id once).
    let mut by_value: HashMap<&str, Vec<Uuid>> = HashMap::new();
    for item in vault.items() {
        let mut min_bits: Option<f64> = None;
        for field in item.fields.iter().filter(|f| f.kind == FieldKind::Password) {
            let value = field.value.expose_secret();
            if value.is_empty() {
                continue;
            }
            let bits = strength_bits(value);
            min_bits = Some(min_bits.map_or(bits, |m: f64| m.min(bits)));
            let ids = by_value.entry(value).or_default();
            if ids.last() != Some(&item.id) {
                ids.push(item.id);
            }
        }
        if let Some(bits) = min_bits.filter(|b| *b < WEAK_BELOW_BITS) {
            weakest.push((item.id, bits));
        }
    }

    let mut issues = Issues::new();
    for (id, bits) in weakest {
        issues.entry(id).or_default().push(Issue::Weak { bits });
    }
    let mut shared: HashMap<Uuid, usize> = HashMap::new();
    for ids in by_value.values().filter(|ids| ids.len() >= 2) {
        for id in ids {
            let c = shared.entry(*id).or_default();
            *c = (*c).max(ids.len());
        }
    }
    for (id, count) in shared {
        issues.entry(id).or_default().push(Issue::Reused { count });
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{Field, Item, KdfParams, SecretString};

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

    #[test]
    fn weak_password_is_flagged() {
        let mut v = vault();
        let id = login(&mut v, "Bank", &["123"]);
        let issues = audit(&v);
        match issues[&id].as_slice() {
            [Issue::Weak { bits }] => assert!(*bits < WEAK_BELOW_BITS),
            other => panic!("unexpected {other:?}"),
        }
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
        assert_eq!(issues[&a], [Issue::Reused { count: 2 }]);
        assert_eq!(issues[&b], [Issue::Reused { count: 2 }]);
        assert!(!issues.contains_key(&c));

        let d = login(&mut v, "D", &[STRONG]);
        let issues = audit(&v);
        for id in [a, b, d] {
            assert_eq!(issues[&id], [Issue::Reused { count: 3 }]);
        }
        assert_eq!(
            Issue::Reused { count: 3 }.body(),
            "This password is used by 2 other items. Reuse lets one leak unlock several accounts."
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
            FieldKind::Other,
        ] {
            item.fields
                .push(Field::new("pin", kind, SecretString::new("123".into()), 1));
        }
        v.insert(item.clone(), 1);
        // Same weak, shared values in a second item: still not passwords.
        let mut twin = item;
        twin.id = Uuid::new_v4();
        v.insert(twin, 1);
        assert!(audit(&v).is_empty());
    }

    #[test]
    fn weakest_of_several_password_fields_is_reported() {
        let mut v = vault();
        let id = login(&mut v, "Multi", &[STRONG, "abcdefgh", "123"]);
        let issues = audit(&v);
        let expected = strength_bits("123");
        match issues[&id].as_slice() {
            [Issue::Weak { bits }] => assert_eq!(*bits, expected),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn reuse_count_is_the_most_shared_password() {
        let mut v = vault();
        // A shares STRONG with B and STRONG_2 with C and D.
        let a = login(&mut v, "A", &[STRONG, STRONG_2]);
        let b = login(&mut v, "B", &[STRONG]);
        let c = login(&mut v, "C", &[STRONG_2]);
        let d = login(&mut v, "D", &[STRONG_2]);
        let issues = audit(&v);
        assert_eq!(issues[&a], [Issue::Reused { count: 3 }]);
        assert_eq!(issues[&b], [Issue::Reused { count: 2 }]);
        assert_eq!(issues[&c], [Issue::Reused { count: 3 }]);
        assert_eq!(issues[&d], [Issue::Reused { count: 3 }]);
    }

    #[test]
    fn same_password_twice_in_one_item_is_not_reuse() {
        let mut v = vault();
        login(&mut v, "A", &[STRONG, STRONG]);
        assert!(audit(&v).is_empty());
    }

    #[test]
    fn weak_and_reused_both_reported() {
        let mut v = vault();
        let a = login(&mut v, "A", &["123"]);
        let b = login(&mut v, "B", &["123"]);
        let issues = audit(&v);
        for id in [a, b] {
            assert!(matches!(
                issues[&id].as_slice(),
                [Issue::Weak { .. }, Issue::Reused { count: 2 }]
            ));
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
