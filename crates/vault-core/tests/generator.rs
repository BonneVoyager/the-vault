use vault_core::ExposeSecret;
use vault_core::generator::{
    PassphraseSpec, PasswordSpec, STRENGTH_SCORED_CHARS, generated_bits, generated_passphrase_bits,
    passphrase, password, strength_bits,
};

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
    assert!(strength_bits("aA1!aA1!") > strength_bits("aaaaaaaa"));
    assert!(strength_bits("password") < 20.0);
    assert!(
        strength_bits("Password1!") < 40.0,
        "a dictionary word with a suffix is weak"
    );
}

/// zxcvbn replaced the naive pool x length estimate with its run/tile rules (2026-11-17):
/// one more character must not move the score across the scale.
#[test]
fn strength_has_no_cliff_on_repetition() {
    let (a, b) = (
        strength_bits("erererreerererre"),
        strength_bits("erererreerererrer"),
    );
    assert!((a - b).abs() <= 10.0, "{a} vs {b}");
    assert!(strength_bits("aaaaaaaaaaa") < 50.0);
    assert!(strength_bits("abcabcabcabc") < 50.0);
}

/// The 50-bit master minimum (05 §2.1) must be clearable by the suggested passphrase, and a
/// default generated password must stay out of the weak band.
#[test]
fn generated_secrets_clear_the_master_minimum() {
    for _ in 0..200 {
        let p = passphrase(&PassphraseSpec::default());
        let bits = strength_bits(p.expose_secret());
        assert!(bits >= 50.0, "4-word passphrase scored {bits}");
        let pw = password(&PasswordSpec::default());
        let bits = strength_bits(pw.expose_secret());
        assert!(bits >= 50.0, "20-char password scored {bits}");
    }
}

#[test]
fn strength_scores_only_a_bounded_prefix() {
    let head = "Tr0ub4dor&3-correct-horse";
    let long = format!("{head}{}", "z".repeat(10_000));
    let capped: String = long.chars().take(STRENGTH_SCORED_CHARS).collect();
    assert_eq!(strength_bits(&long), strength_bits(&capped));
    assert!(strength_bits(&long) <= 64.0 + 1e-9);
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 0.05
}

/// 05 §2.4: the generator preview's meter is log2(pool) × length over the generator's own
/// pool. Default pool: 25 lower + 24 upper + 8 digits + 26 symbols (ambiguous excluded).
#[test]
fn generated_bits_is_pool_entropy_times_length() {
    let default = PasswordSpec::default();
    assert_eq!(default.length, 20);
    let b = generated_bits(&default);
    assert!(close(b, 20.0 * 83f64.log2()), "{b}"); // ≈ 127.5
    let all = PasswordSpec {
        exclude_ambiguous: false,
        ..PasswordSpec::default()
    };
    assert!(close(generated_bits(&all), 20.0 * 88f64.log2()), "≈ 129.2");
    let sixteen = PasswordSpec {
        length: 16,
        ..PasswordSpec::default()
    };
    assert!(
        close(generated_bits(&sixteen), 16.0 * 83f64.log2()),
        "≈ 102.0"
    );
    let lower_only = PasswordSpec {
        length: 10,
        lower: true,
        upper: false,
        digits: false,
        symbols: false,
        exclude_ambiguous: false,
    };
    assert!(close(generated_bits(&lower_only), 10.0 * 26f64.log2()));
    // No class enabled: lowercase, as `password` does; length raised to min_length().
    let none = PasswordSpec {
        length: 0,
        lower: false,
        upper: false,
        digits: false,
        symbols: false,
        exclude_ambiguous: true,
    };
    assert!(close(generated_bits(&none), 25f64.log2()));
    let short = PasswordSpec {
        length: 1,
        ..PasswordSpec::default()
    };
    assert!(close(generated_bits(&short), 4.0 * 83f64.log2()));
}

#[test]
fn generated_passphrase_bits_is_wordlist_entropy_plus_digit() {
    let plain = PassphraseSpec {
        number: false,
        ..PassphraseSpec::default()
    };
    assert_eq!(plain.words, 4);
    assert!(
        close(generated_passphrase_bits(&plain), 4.0 * 7776f64.log2()),
        "≈ 51.7"
    );
    let with_digit = PassphraseSpec::default();
    assert!(with_digit.number);
    assert!(close(
        generated_passphrase_bits(&with_digit),
        4.0 * 7776f64.log2() + 10f64.log2()
    ));
    // Capitalisation and separator add nothing; zero words is one word, as `passphrase` does.
    let other = PassphraseSpec {
        separator: '.',
        capitalize: false,
        ..PassphraseSpec::default()
    };
    assert_eq!(
        generated_passphrase_bits(&other),
        generated_passphrase_bits(&with_digit)
    );
    let zero = PassphraseSpec {
        words: 0,
        number: false,
        ..PassphraseSpec::default()
    };
    assert!(close(generated_passphrase_bits(&zero), 7776f64.log2()));
}
