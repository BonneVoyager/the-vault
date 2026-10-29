use vault_core::ExposeSecret;
use vault_core::generator::{PassphraseSpec, PasswordSpec, passphrase, password, strength_bits};

const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/";
const AMBIGUOUS: &str = "0O1lI|`'\"";

#[test]
fn guarantee_10_one_of_each_class_at_length_4() {
    let spec = PasswordSpec {
        length: 4,
        ..PasswordSpec::default()
    };
    for _ in 0..200 {
        let pw = password(&spec);
        let s = pw.expose_secret();
        assert_eq!(s.chars().count(), 4);
        assert!(s.chars().any(|c| c.is_ascii_lowercase()), "{s}");
        assert!(s.chars().any(|c| c.is_ascii_uppercase()), "{s}");
        assert!(s.chars().any(|c| c.is_ascii_digit()), "{s}");
        assert!(s.chars().any(|c| SYMBOLS.contains(c)), "{s}");
    }
}

#[test]
fn short_length_raised_to_class_count() {
    let spec = PasswordSpec {
        length: 1,
        ..PasswordSpec::default()
    };
    assert_eq!(password(&spec).expose_secret().chars().count(), 4);
}

#[test]
fn exclude_ambiguous_holds() {
    let spec = PasswordSpec {
        length: 64,
        ..PasswordSpec::default()
    };
    for _ in 0..200 {
        let pw = password(&spec);
        assert!(!pw.expose_secret().chars().any(|c| AMBIGUOUS.contains(c)));
    }
}

#[test]
fn only_enabled_classes() {
    let spec = PasswordSpec {
        length: 30,
        lower: false,
        upper: false,
        digits: true,
        symbols: false,
        exclude_ambiguous: false,
    };
    assert!(
        password(&spec)
            .expose_secret()
            .chars()
            .all(|c| c.is_ascii_digit())
    );
}

#[test]
fn default_passphrase_shape() {
    let spec = PassphraseSpec::default();
    let mut checked = 0;
    while checked < 50 {
        let pw = passphrase(&spec);
        let s = pw.expose_secret();
        // A few EFF words contain '-' themselves; skip those draws so splitting is unambiguous.
        if s.matches('-').count() != 3 {
            continue;
        }
        checked += 1;
        let parts: Vec<&str> = s.split('-').collect();
        assert_eq!(parts.len(), 4);
        for p in &parts {
            assert!(p.chars().next().unwrap().is_ascii_uppercase(), "{s}");
        }
        let digits: String = s.chars().filter(char::is_ascii_digit).collect();
        assert_eq!(digits.len(), 1, "{s}");
        assert!(parts[3].ends_with(|c: char| c.is_ascii_digit()));
    }
}

#[test]
fn passphrase_options() {
    let spec = PassphraseSpec {
        words: 6,
        separator: ' ',
        capitalize: false,
        number: false,
    };
    let pw = passphrase(&spec);
    let s = pw.expose_secret();
    assert_eq!(s.split(' ').count(), 6);
    assert!(
        s.chars()
            .all(|c| c.is_ascii_lowercase() || c == ' ' || c == '-')
    );
}

#[test]
fn strength() {
    assert_eq!(strength_bits(""), 0.0);
    assert!((strength_bits("abcd") - 4.0 * 26f64.log2()).abs() < 1e-9);
    assert!(strength_bits("aA1!aA1!") > strength_bits("aaaaaaaa"));
}
