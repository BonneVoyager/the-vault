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

/// V-07: `min_length()` is what a UI should validate against; `password` clamps to it.
#[test]
fn min_length_is_the_enabled_class_count_and_password_clamps_to_it() {
    assert_eq!(PasswordSpec::default().min_length(), 4);
    let lower_symbols = PasswordSpec {
        length: 0,
        lower: true,
        upper: false,
        digits: false,
        symbols: true,
        exclude_ambiguous: false,
    };
    assert_eq!(lower_symbols.min_length(), 2);
    for _ in 0..50 {
        let pw = password(&lower_symbols);
        let s = pw.expose_secret();
        assert_eq!(s.chars().count(), 2, "{s}");
        assert!(s.chars().any(|c| c.is_ascii_lowercase()), "{s}");
        assert!(s.chars().any(|c| SYMBOLS.contains(c)), "{s}");
    }
    let only_digits = PasswordSpec {
        length: 0,
        lower: false,
        upper: false,
        digits: true,
        symbols: false,
        exclude_ambiguous: true,
    };
    assert_eq!(only_digits.min_length(), 1);
    let s = password(&only_digits);
    assert_eq!(s.expose_secret().len(), 1);
    assert!(s.expose_secret().chars().all(|c| c.is_ascii_digit()));
    // No class at all falls back to lowercase, so the minimum is still one character.
    let none = PasswordSpec {
        length: 0,
        lower: false,
        upper: false,
        digits: false,
        symbols: false,
        exclude_ambiguous: true,
    };
    assert_eq!(none.min_length(), 1);
    let s = password(&none);
    assert_eq!(s.expose_secret().len(), 1);
    assert!(s.expose_secret().chars().all(|c| c.is_ascii_lowercase()));
    // A length at or above the minimum is honoured exactly.
    let five = PasswordSpec {
        length: 5,
        ..PasswordSpec::default()
    };
    assert!(five.length >= five.min_length());
    assert_eq!(password(&five).expose_secret().chars().count(), 5);
}

/// V-07: zero words is treated as one; never an empty string or a lone digit.
#[test]
fn passphrase_zero_words_is_one_word() {
    let spec = PassphraseSpec {
        words: 0,
        separator: '-',
        capitalize: true,
        number: true,
    };
    for _ in 0..20 {
        let pw = passphrase(&spec);
        let s = pw.expose_secret();
        assert!(s.len() >= 2, "{s:?}");
        assert!(s.chars().next().unwrap().is_ascii_uppercase(), "{s}");
        assert!(s.chars().last().unwrap().is_ascii_digit(), "{s}");
        assert_eq!(s.chars().filter(char::is_ascii_digit).count(), 1, "{s}");
    }
    let bare = PassphraseSpec {
        words: 0,
        separator: ' ',
        capitalize: false,
        number: false,
    };
    let pw = passphrase(&bare);
    let s = pw.expose_secret();
    assert!(!s.is_empty());
    assert!(!s.contains(' '), "a single word has no separator: {s}");
    assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '-'), "{s}");
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
