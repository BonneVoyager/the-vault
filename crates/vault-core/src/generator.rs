//! Password and passphrase generator (`02-core-api.md` "generator").
//!
//! All randomness comes from `OsRng`.

use std::sync::OnceLock;

use rand::Rng;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use secrecy::SecretString;
use zeroize::Zeroizing;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/";
/// Characters that are easy to confuse when read or typed.
const AMBIGUOUS: &str = "0O1lI|`'\"";

const WORDLIST_RAW: &str = include_str!("../assets/eff_large_wordlist.txt");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordSpec {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordSpec {
    fn default() -> Self {
        Self {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
        }
    }
}

impl PasswordSpec {
    /// Number of character classes [`password`] draws from: the enabled ones, or 1 when none
    /// is enabled (lowercase is used then).
    fn class_count(&self) -> usize {
        let n = [self.lower, self.upper, self.digits, self.symbols]
            .into_iter()
            .filter(|&b| b)
            .count();
        n.max(1)
    }

    /// The shortest password [`password`] can produce for this spec: one character per
    /// enabled class (at least 1). A `length` below this is raised to it, so a UI that wants
    /// to refuse rather than silently lengthen should check `spec.length >= min_length()`.
    pub fn min_length(&self) -> usize {
        self.class_count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseSpec {
    pub words: usize,
    pub separator: char,
    pub capitalize: bool,
    pub number: bool,
}

impl Default for PassphraseSpec {
    fn default() -> Self {
        Self {
            words: 4,
            separator: '-',
            capitalize: true,
            number: true,
        }
    }
}

/// The classes [`password`] draws from for `spec`, after the class toggles and
/// exclude-ambiguous: the enabled ones, or lowercase alone when none is enabled.
fn spec_classes(spec: &PasswordSpec) -> Vec<Vec<char>> {
    let mut classes: Vec<Vec<char>> = Vec::new();
    for (enabled, set) in [
        (spec.lower, LOWER),
        (spec.upper, UPPER),
        (spec.digits, DIGITS),
        (spec.symbols, SYMBOLS),
    ] {
        if enabled {
            classes.push(class_chars(set, spec.exclude_ambiguous));
        }
    }
    if classes.is_empty() {
        classes.push(class_chars(LOWER, spec.exclude_ambiguous));
    }
    classes
}

fn class_chars(set: &str, exclude_ambiguous: bool) -> Vec<char> {
    set.chars()
        .filter(|c| !(exclude_ambiguous && AMBIGUOUS.contains(*c)))
        .collect()
}

/// Random password with at least one character from every enabled class.
///
/// **`length` is clamped up to [`PasswordSpec::min_length`]** (the number of enabled classes,
/// at least 1): the "one of each class" guarantee needs that many characters, so a request
/// for fewer yields exactly `min_length()` characters, never an empty or class-less string.
/// Callers that would rather reject such a request must validate `length` themselves. If no
/// class is enabled, lowercase is used.
pub fn password(spec: &PasswordSpec) -> SecretString {
    let classes = spec_classes(spec);
    debug_assert_eq!(classes.len(), spec.class_count());
    let length = spec.length.max(spec.min_length());
    let pool: Vec<char> = classes.iter().flatten().copied().collect();

    let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(length));
    for class in &classes {
        chars.push(class[OsRng.gen_range(0..class.len())]);
    }
    while chars.len() < length {
        chars.push(pool[OsRng.gen_range(0..pool.len())]);
    }
    chars.shuffle(&mut OsRng);
    SecretString::new(chars.iter().collect())
}

fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        WORDLIST_RAW
            .lines()
            .filter_map(|l| l.split_once('\t').map(|(_, w)| w.trim()))
            .filter(|w| !w.is_empty())
            .collect()
    })
}

/// Diceware-style passphrase from the bundled EFF large wordlist. With `number`, one random
/// digit is appended to the last word.
///
/// **`words` is clamped up to 1**: a request for zero words would otherwise return an empty
/// string (or a lone digit with `number`), which is not a passphrase. Callers that want to
/// refuse `words == 0` must validate it themselves.
pub fn passphrase(spec: &PassphraseSpec) -> SecretString {
    let list = wordlist();
    let mut out: Zeroizing<String> = Zeroizing::new(String::new());
    for i in 0..spec.words.max(1) {
        if i > 0 {
            out.push(spec.separator);
        }
        let w = list[OsRng.gen_range(0..list.len())];
        let mut cs = w.chars();
        match cs.next() {
            Some(first) if spec.capitalize => {
                out.extend(first.to_uppercase());
                out.extend(cs);
            }
            Some(_) => out.push_str(w),
            None => {}
        }
    }
    if spec.number {
        out.push(char::from(b'0' + OsRng.gen_range(0..10u8)));
    }
    SecretString::new(std::mem::take(&mut *out))
}

/// Entropy in bits of a [`password`] for `spec`: `log2(pool) × length`, where the pool is
/// the characters left after the class toggles and exclude-ambiguous and the length is the
/// one [`password`] actually produces (raised to [`PasswordSpec::min_length`]). This is the
/// generator preview's meter (05 §2.4): plain arithmetic over the generator's own uniform
/// choices, unlike [`strength_bits`], which estimates an arbitrary typed value. The
/// "one of each class" step makes the true figure very slightly lower (well under a bit
/// at the default settings); the uniform-pool figure is the one the spec names.
pub fn generated_bits(spec: &PasswordSpec) -> f64 {
    let pool: usize = spec_classes(spec).iter().map(Vec::len).sum();
    let length = spec.length.max(spec.min_length());
    (pool as f64).log2() * length as f64
}

/// Entropy in bits of a [`passphrase`] for `spec`: `log2(wordlist size) × words` (7776 words,
/// about 12.9 bits each; `words` raised to 1 as [`passphrase`] does), plus `log2(10)` when a
/// digit is appended. Capitalisation and the separator are fixed by the spec, so they add
/// nothing.
pub fn generated_passphrase_bits(spec: &PassphraseSpec) -> f64 {
    let words = spec.words.max(1) as f64;
    let digit = if spec.number { 10f64.log2() } else { 0.0 };
    (wordlist().len() as f64).log2() * words + digit
}

/// How many leading characters [`strength_bits`] scores. zxcvbn's matcher is super-linear
/// in the input length (about 14 ms for 100 random characters in a release build), so a
/// long value cannot stall an editor keystroke.
pub const STRENGTH_SCORED_CHARS: usize = 100;

/// Estimated strength in bits: `log2` of the number of guesses
/// [zxcvbn](https://crates.io/crates/zxcvbn) expects an attacker to need
/// (`guesses_log10 * log2(10)`). zxcvbn finds dictionary words, keyboard patterns, repeats,
/// sequences and dates, so repetition is penalised smoothly instead of by a fixed rule.
///
/// - Only the first [`STRENGTH_SCORED_CHARS`] characters are scored.
/// - The empty string scores `0.0`.
/// - zxcvbn counts guesses in a saturating `u64`, so the result never exceeds 64 bits: a
///   generated 20-character password or 4-word passphrase scores about 64.
/// - The scored prefix lives in a pre-sized `Zeroizing<String>` (never reallocated, so no
///   unwiped partial copy is left behind). zxcvbn makes its own transient copies of the
///   scored text (its own 100-character `String`, per-matcher char buffers, match tokens);
///   all are dropped before the call returns and none is cached.
/// - zxcvbn reads the clock for the current year (dates near it are guessed first), so a
///   value containing a recent year may score differently from one year to the next.
pub fn strength_bits(pw: &str) -> f64 {
    let mut scored: Zeroizing<String> = Zeroizing::new(String::with_capacity(
        pw.len().min(4 * STRENGTH_SCORED_CHARS),
    ));
    scored.extend(pw.chars().take(STRENGTH_SCORED_CHARS));
    if scored.is_empty() {
        return 0.0;
    }
    let log10 = zxcvbn::zxcvbn(&scored, &[]).guesses_log10();
    (log10 * std::f64::consts::LOG2_10).max(0.0)
}
