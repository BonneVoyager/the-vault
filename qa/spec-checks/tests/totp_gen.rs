//! TOTP (02 "totp") against RFC 6238 vectors and an independent HMAC; generator (02 "generator",
//! guarantee 10); search ranking (02 "search").
use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use spec_checks::*;
use uuid::Uuid;
use vault_core::totp::Totp;
use vault_core::*;

fn b32(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buf = 0u64;
    let mut bits = 0;
    for &b in data {
        buf = (buf << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            out.push(A[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(A[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}
fn hotp(alg: &str, key: &[u8], counter: u64, digits: u32) -> String {
    let msg = counter.to_be_bytes();
    let h: Vec<u8> = match alg {
        "SHA1" => { let mut m = Hmac::<sha1::Sha1>::new_from_slice(key).unwrap(); m.update(&msg); m.finalize().into_bytes().to_vec() }
        "SHA256" => { let mut m = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap(); m.update(&msg); m.finalize().into_bytes().to_vec() }
        _ => { let mut m = Hmac::<sha2::Sha512>::new_from_slice(key).unwrap(); m.update(&msg); m.finalize().into_bytes().to_vec() }
    };
    let o = (h[h.len() - 1] & 0xf) as usize;
    let bin = ((h[o] as u32 & 0x7f) << 24) | ((h[o + 1] as u32) << 16) | ((h[o + 2] as u32) << 8) | h[o + 3] as u32;
    format!("{:0width$}", bin % 10u32.pow(digits), width = digits as usize)
}

/// RFC 6238 Appendix B vectors (8 digits, 30 s, SHA1/256/512).
#[test]
fn t01_rfc6238_vectors() {
    let keys = [
        ("SHA1", b"12345678901234567890".to_vec()),
        ("SHA256", b"12345678901234567890123456789012".to_vec()),
        ("SHA512", b"1234567890123456789012345678901234567890123456789012345678901234".to_vec()),
    ];
    let table: [(u64, [&str; 3]); 6] = [
        (59, ["94287082", "46119246", "90693936"]),
        (1111111109, ["07081804", "68084774", "25091201"]),
        (1111111111, ["14050471", "67062674", "99943326"]),
        (1234567890, ["89005924", "91819424", "93441116"]),
        (2000000000, ["69279037", "90698825", "38618901"]),
        (20000000000, ["65353130", "77737706", "47863826"]),
    ];
    for (i, (alg, key)) in keys.iter().enumerate() {
        let uri = format!("otpauth://totp/RFC:test?secret={}&algorithm={alg}&digits=8&period=30", b32(key));
        let t = Totp::parse_uri(&uri).unwrap_or_else(|e| panic!("{alg}: {e:?}"));
        for (ts, want) in &table {
            assert_eq!(t.code(*ts), want[i], "{alg} t={ts}");
            assert_eq!(hotp(alg, key, ts / 30, 8), want[i], "independent HMAC self-check");
        }
    }
}

/// Independent computation over digits 6/7/8, periods, algorithms, random secrets incl. short ones
/// ("no minimum secret length").
#[test]
fn t02_against_independent_hmac() {
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    let mut bad = vec![];
    for n in 0..300 {
        let len = [1usize, 5, 10, 16, 20, 32, 64][n % 7];
        let key: Vec<u8> = (0..len).map(|_| rng.r#gen()).collect();
        let alg = ["SHA1", "SHA256", "SHA512"][n % 3];
        let digits = [6u32, 7, 8][(n / 3) % 3];
        let period = [30u64, 60, 15, 1, 3600][(n / 9) % 5];
        let ts: u64 = rng.gen_range(0..4_000_000_000);
        let uri = format!("otpauth://totp/x?secret={}&algorithm={alg}&digits={digits}&period={period}", b32(&key));
        match Totp::parse_uri(&uri) {
            Ok(t) => {
                let want = hotp(alg, &key, ts / period, digits);
                if t.code(ts) != want {
                    bad.push(format!("{uri} t={ts}: {} != {want}", t.code(ts)));
                }
                if t.period() as u64 != period {
                    bad.push(format!("{uri}: period {}", t.period()));
                }
                let rem = t.seconds_remaining(ts) as u64;
                if rem != period - ts % period {
                    bad.push(format!("{uri} t={ts}: seconds_remaining {rem}"));
                }
            }
            Err(e) => bad.push(format!("{uri} (key len {len}): rejected {e:?}")),
        }
    }
    bad.truncate(10);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 02: scheme/host case-insensitive; secret normalised (case, padding, spaces, dashes); hotp rejected;
/// from_secret_base32 defaults SHA1/6/30; to_uri round-trips.
#[test]
fn t03_parse_normalisation() {
    let key = b"12345678901234567890";
    let s = b32(key);
    let want = hotp("SHA1", key, 1234567890 / 30, 6);
    let lower = s.to_lowercase();
    let spaced: String = s.chars().collect::<Vec<_>>().chunks(4).map(|c| c.iter().collect::<String>()).collect::<Vec<_>>().join(" ");
    let dashed = spaced.replace(' ', "-");
    let padded = format!("{s}{}", "=".repeat((8 - s.len() % 8) % 8));
    for (name, uri) in [
        ("upper scheme/host", format!("OTPAUTH://TOTP/x?secret={s}")),
        ("mixed", format!("OtpAuth://ToTp/x?secret={s}")),
        ("lowercase secret", format!("otpauth://totp/x?secret={lower}")),
        ("spaces %20", format!("otpauth://totp/x?secret={}", spaced.replace(' ', "%20"))),
        ("dashes", format!("otpauth://totp/x?secret={dashed}")),
        ("padding %3D", format!("otpauth://totp/x?secret={}", padded.replace('=', "%3D"))),
        ("issuer+label", format!("otpauth://totp/ACME%20Co:john@example.com?secret={s}&issuer=ACME%20Co")),
        ("algorithm lowercase", format!("otpauth://totp/x?secret={s}&algorithm=sha1")),
    ] {
        match Totp::parse_uri(&uri) {
            Ok(t) => assert_eq!(t.code(1234567890), want, "{name}"),
            Err(e) => panic!("{name}: {uri} rejected: {e:?}"),
        }
    }
    for (name, s2) in [("lowercase", lower.clone()), ("spaces", spaced.clone()), ("dashes", dashed.clone()), ("padding", padded.clone())] {
        let t = Totp::from_secret_base32(&s2).unwrap_or_else(|e| panic!("from_secret_base32 {name}: {e:?}"));
        assert_eq!(t.code(1234567890), want, "from_secret_base32 {name}");
        assert_eq!(t.period(), 30);
    }
    assert!(Totp::parse_uri(&format!("otpauth://hotp/x?secret={s}&counter=1")).is_err(), "hotp rejected");
    assert!(Totp::parse_uri("otpauth://totp/x").is_err(), "missing secret");
    assert!(Totp::parse_uri("otpauth://totp/x?secret=1!!!").is_err(), "bad base32");
    assert!(Totp::parse_uri("https://totp/x?secret=JBSWY3DP").is_err());
    let t = Totp::parse_uri(&format!("otpauth://totp/x?secret={s}&digits=7&period=45&algorithm=SHA256")).unwrap();
    let t2 = Totp::parse_uri(t.to_uri().expose_secret()).unwrap();
    for ts in [0u64, 59, 1234567890] {
        assert_eq!(t.code(ts), t2.code(ts), "to_uri round trip");
    }
    assert_eq!(t2.period(), 45);
}

/// Hostile URIs: no panic (period=0 would divide by zero), no hang.
#[test]
fn t04_hostile_uris_no_panic() {
    let s = "JBSWY3DPEHPK3PXP";
    let mut bad = vec![];
    for q in [
        "period=0", "period=-1", "period=18446744073709551615", "period=4294967296", "digits=0", "digits=10", "digits=99",
        "digits=-6", "algorithm=MD5", "algorithm=", "period=", "digits=", "secret=", "period=1e3",
    ] {
        let uri = format!("otpauth://totp/x?secret={s}&{q}");
        let r = std::panic::catch_unwind(|| {
            if let Ok(t) = Totp::parse_uri(&uri) {
                let _ = t.code(1_700_000_000);
                let _ = t.seconds_remaining(1_700_000_000);
                let _ = t.code(u64::MAX);
                let _ = t.to_uri();
            }
        });
        if r.is_err() {
            bad.push(q);
        }
    }
    let long = format!("otpauth://totp/x?secret={}", "A".repeat(1_000_000));
    let r = with_timeout(10, move || std::panic::catch_unwind(|| Totp::parse_uri(&long).map(|t| t.code(1))).is_ok());
    assert_eq!(r, Some(true), "1 MB secret: hang or panic");
    assert!(bad.is_empty(), "panics on: {bad:?}");
}

fn classes(s: &str) -> (bool, bool, bool, bool) {
    (
        s.chars().any(|c| c.is_ascii_lowercase()),
        s.chars().any(|c| c.is_ascii_uppercase()),
        s.chars().any(|c| c.is_ascii_digit()),
        s.chars().any(|c| !c.is_ascii_alphanumeric()),
    )
}

/// 02 guarantee 10 and "guarantees >= 1 char from each enabled class"; defaults; exclude ambiguous.
#[test]
fn g01_password_classes() {
    use vault_core::generator::*;
    for _ in 0..2000 {
        let p = password(&PasswordSpec { length: 4, lower: true, upper: true, digits: true, symbols: true, exclude_ambiguous: false });
        let p = p.expose_secret();
        assert_eq!(p.chars().count(), 4);
        assert_eq!(classes(p), (true, true, true, true), "{p}");
    }
    let mut ambiguous_seen = std::collections::BTreeSet::new();
    for _ in 0..500 {
        let p = password(&PasswordSpec { length: 64, lower: true, upper: true, digits: true, symbols: true, exclude_ambiguous: true });
        for c in p.expose_secret().chars() {
            if "0O1lI|".contains(c) {
                ambiguous_seen.insert(c);
            }
            assert!(c.is_ascii_graphic(), "non-printable or space {c:?}");
        }
    }
    assert!(ambiguous_seen.is_empty(), "exclude_ambiguous still produced {ambiguous_seen:?}");
    for (lo, up, di, sy) in [(true, false, false, false), (false, true, false, false), (false, false, true, false), (false, false, false, true), (false, true, true, false)] {
        let p = password(&PasswordSpec { length: 12, lower: lo, upper: up, digits: di, symbols: sy, exclude_ambiguous: true });
        let c = classes(p.expose_secret());
        assert_eq!(c, (lo, up, di, sy), "only enabled classes: {}", p.expose_secret());
    }
    // edge lengths and no classes: must not panic or hang
    for len in [0usize, 1, 2, 3, 10_000] {
        let r = with_timeout(10, move || {
            std::panic::catch_unwind(|| password(&PasswordSpec { length: len, lower: true, upper: true, digits: true, symbols: true, exclude_ambiguous: true }).expose_secret().len())
                .is_ok()
        });
        assert_eq!(r, Some(true), "length {len}");
    }
    let r = with_timeout(10, || std::panic::catch_unwind(|| password(&PasswordSpec { length: 10, lower: false, upper: false, digits: false, symbols: false, exclude_ambiguous: false })).is_ok());
    assert_eq!(r, Some(true), "no classes enabled: panic or hang");
}

/// Rough uniformity: 64k lowercase-only chars, each letter within +-15% of expectation.
#[test]
fn g02_uniformity() {
    use vault_core::generator::*;
    let mut counts = std::collections::HashMap::new();
    let mut n = 0;
    for _ in 0..1000 {
        let p = password(&PasswordSpec { length: 64, lower: true, upper: false, digits: false, symbols: false, exclude_ambiguous: false });
        for c in p.expose_secret().chars() {
            *counts.entry(c).or_insert(0usize) += 1;
            n += 1;
        }
    }
    let k = counts.len() as f64;
    assert!(k >= 26.0, "alphabet size {k}");
    let exp = n as f64 / k;
    for (c, v) in &counts {
        assert!((*v as f64 - exp).abs() / exp < 0.15, "char {c} count {v} vs {exp}");
    }
    // positions: the forced-class characters must not always sit at fixed positions
    let mut first_digit = std::collections::HashSet::new();
    for _ in 0..300 {
        let p = password(&PasswordSpec { length: 20, lower: true, upper: true, digits: true, symbols: true, exclude_ambiguous: true });
        first_digit.insert(p.expose_secret().chars().position(|c| c.is_ascii_digit()).unwrap());
    }
    assert!(first_digit.len() > 5, "digit position not shuffled: {first_digit:?}");
}

/// 02 passphrase: EFF large wordlist (7776 words), separator, capitalize, number.
#[test]
fn g03_passphrase() {
    use vault_core::generator::*;
    let mut words = std::collections::HashSet::new();
    for _ in 0..3000 {
        let p = passphrase(&PassphraseSpec { words: 4, separator: '-', capitalize: true, number: true });
        let s = p.expose_secret();
        // EFF large contains hyphenated words (drop-down, felt-tip, ...), so split may yield >4 parts
        let parts: Vec<&str> = s.split('-').collect();
        assert!(parts.len() >= 4, "{s}");
        assert!(s.chars().any(|c| c.is_ascii_digit()), "number: {s}");
        let caps = parts.iter().filter(|w| w.chars().next().is_some_and(|c| c.is_uppercase())).count();
        assert!(caps >= 4, "capitalize: {s}");
        for w in &parts {
            let base: String = w.chars().filter(|c| c.is_alphabetic()).collect::<String>().to_lowercase();
            words.insert(base);
        }
    }
    assert!(words.len() > 3000, "distinct words seen {}: wordlist looks smaller than EFF large", words.len());
    let p = passphrase(&PassphraseSpec { words: 6, separator: ' ', capitalize: false, number: false });
    let s = p.expose_secret();
    assert_eq!(s.split(' ').count(), 6);
    assert!(!s.chars().any(|c| c.is_ascii_digit() || c.is_uppercase()), "{s}");
    let p = passphrase(&PassphraseSpec { words: 3, separator: '\u{2022}', capitalize: false, number: false });
    assert_eq!(p.expose_secret().split('\u{2022}').count(), 3);
    for w in [0usize, 1] {
        assert!(std::panic::catch_unwind(|| passphrase(&PassphraseSpec { words: w, separator: '-', capitalize: true, number: true })).is_ok(), "words={w} panics");
    }
    // 4-word passphrase clears the 50-bit master minimum (05 §2.1 "Try a 4-word passphrase")
    let p = passphrase(&PassphraseSpec { words: 4, separator: '-', capitalize: true, number: true });
    let bits = strength_bits(p.expose_secret());
    assert!(bits >= 50.0, "suggested 4-word passphrase only {bits} bits by strength_bits");
}

/// 02 strength_bits sanity.
#[test]
fn g04_strength_bits() {
    use vault_core::generator::*;
    assert!(strength_bits("") <= 0.0 + f64::EPSILON);
    assert!(strength_bits("aaaaaaaa") < strength_bits("aZ3$kq9!"));
    assert!(strength_bits("password") < 40.0, "'password' weak");
    assert!(strength_bits("correct horse battery staple") >= 50.0);
    let g = password(&PasswordSpec { length: 20, lower: true, upper: true, digits: true, symbols: true, exclude_ambiguous: true });
    assert!(strength_bits(g.expose_secret()) >= 50.0);
    assert!(strength_bits(&"x".repeat(100_000)).is_finite());
}

/// 02 search: ranking title prefix > title substring > url host > username > tag > notes;
/// case-insensitive, Unicode-folded; stable by title; tombstones excluded; favorites/tag filters.
#[test]
fn q01_search_ranking() {
    use vault_core::search::*;
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw("p"), KdfParams::for_tests(), dev);
    let mk = |title: &str, url: &str, user: &str, tag: &str, notes: &str| {
        let mut it = Item::new(title, dev, 1);
        it.fields.push(Field::new("url", FieldKind::Url, pw(url), 1));
        it.fields.push(Field::new("username", FieldKind::Text, pw(user), 1));
        it.fields.push(Field::new("notes", FieldKind::Notes, pw(notes), 1));
        if !tag.is_empty() {
            it.tags.push(tag.into());
        }
        it
    };
    let notes = v.insert(mk("N", "", "", "", "mentions zeta here"), 1);
    let tag = v.insert(mk("T", "", "", "zeta", ""), 1);
    let user = v.insert(mk("U", "", "zeta@x.io", "", ""), 1);
    let host = v.insert(mk("H", "https://zeta.example.com/login", "", "", ""), 1);
    let sub = v.insert(mk("My Zeta", "", "", "", ""), 1);
    let pre_b = v.insert(mk("Zeta B", "", "", "", ""), 1);
    let pre_a = v.insert(mk("zeta a", "", "", "", ""), 1);
    let dead = v.insert(mk("Zeta dead", "", "", "", ""), 1);
    v.delete(dead, 2).unwrap();
    let r: Vec<Uuid> = search(&v, &Query { text: "ZETA", tag: None, favorites_only: false }).iter().map(|i| i.id).collect();
    assert_eq!(r, vec![pre_a, pre_b, sub, host, user, tag, notes], "rank order");
    let mut e = Item::new("\u{c9}cole", dev, 1);
    e.favorite = true;
    let eid = v.insert(e, 1);
    let r: Vec<Uuid> = search(&v, &Query { text: "\u{e9}co", tag: None, favorites_only: false }).iter().map(|i| i.id).collect();
    assert_eq!(r, vec![eid], "Unicode case folding");
    let r: Vec<Uuid> = search(&v, &Query { text: "", tag: None, favorites_only: true }).iter().map(|i| i.id).collect();
    assert_eq!(r, vec![eid]);
    let r: Vec<Uuid> = search(&v, &Query { text: "", tag: Some("zeta"), favorites_only: false }).iter().map(|i| i.id).collect();
    assert_eq!(r, vec![tag]);
    // a password value must never match
    let mut s = Item::new("Secretive", dev, 1);
    s.fields.push(Field::new("password", FieldKind::Password, pw("qqqxyzzy"), 1));
    v.insert(s, 1);
    assert!(search(&v, &Query { text: "qqqxyzzy", tag: None, favorites_only: false }).is_empty(), "search hits password values");
}
