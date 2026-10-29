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

fn class_chars(set: &str, exclude_ambiguous: bool) -> Vec<char> {
    set.chars()
        .filter(|c| !(exclude_ambiguous && AMBIGUOUS.contains(*c)))
        .collect()
}

/// Random password with at least one character from every enabled class.
///
/// If `length` is below the number of enabled classes it is raised to that number. If no class
/// is enabled, lowercase is used.
pub fn password(spec: &PasswordSpec) -> SecretString {
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
    let length = spec.length.max(classes.len());
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
pub fn passphrase(spec: &PassphraseSpec) -> SecretString {
    let list = wordlist();
    let mut out: Zeroizing<String> = Zeroizing::new(String::new());
    for i in 0..spec.words {
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

/// Naive entropy estimate: `length * log2(pool)`, with the pool inferred from the character
/// classes present (26 lower, 26 upper, 10 digits, 32 for anything else).
pub fn strength_bits(pw: &str) -> f64 {
    let mut pool = 0u32;
    if pw.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if pw.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if pw.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if pw.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 32;
    }
    if pool == 0 {
        return 0.0;
    }
    pw.chars().count() as f64 * f64::from(pool).log2()
}
