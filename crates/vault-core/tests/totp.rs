use vault_core::{ExposeSecret, Totp, TotpError};

fn base32(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut out, mut buf, mut bits) = (String::new(), 0u32, 0);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn uri(alg: &str, secret: &[u8]) -> String {
    format!(
        "otpauth://totp/Test:a@b.c?secret={}&algorithm={alg}&digits=8&period=30",
        base32(secret)
    )
}

const S1: &[u8] = b"12345678901234567890";
const S256: &[u8] = b"12345678901234567890123456789012";
const S512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

#[test]
fn rfc6238_vectors() {
    let cases: [(&str, &[u8], u64, &str); 6] = [
        ("SHA1", S1, 59, "94287082"),
        ("SHA256", S256, 59, "46119246"),
        ("SHA512", S512, 59, "90693936"),
        ("SHA1", S1, 1111111109, "07081804"),
        ("SHA256", S256, 1111111109, "68084774"),
        ("SHA512", S512, 1111111109, "25091201"),
    ];
    for (alg, secret, t, want) in cases {
        let totp = Totp::parse_uri(&uri(alg, secret)).unwrap();
        assert_eq!(totp.code(t), want, "{alg} at {t}");
    }
}

#[test]
fn hotp_rejected() {
    let r = Totp::parse_uri("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=1");
    assert!(matches!(r, Err(TotpError::Unsupported(_))));
}

#[test]
fn bad_inputs() {
    assert!(matches!(
        Totp::parse_uri("https://x"),
        Err(TotpError::InvalidUri)
    ));
    assert!(matches!(
        Totp::from_secret_base32("!!!"),
        Err(TotpError::InvalidSecret)
    ));
    assert!(matches!(
        Totp::from_secret_base32(""),
        Err(TotpError::InvalidSecret)
    ));
}

#[test]
fn defaults_and_remaining() {
    let t = Totp::from_secret_base32("gezd gnbv gy3t qojq").unwrap();
    assert_eq!(t.period(), 30);
    assert_eq!(t.code(59).len(), 6);
    assert_eq!(t.seconds_remaining(59), 1);
    assert_eq!(t.seconds_remaining(60), 30);
    assert_eq!(t.seconds_remaining(0), 30);
}

#[test]
fn uri_round_trip() {
    for (alg, secret) in [("SHA1", S1), ("SHA256", S256), ("SHA512", S512)] {
        let a = Totp::parse_uri(&uri(alg, secret)).unwrap();
        let b = Totp::parse_uri(a.to_uri().expose_secret()).unwrap();
        assert_eq!(a.period(), b.period());
        for t in [0, 59, 1111111109, 2000000000] {
            assert_eq!(a.code(t), b.code(t));
        }
    }
    let custom = Totp::parse_uri(&format!(
        "otpauth://totp/x?secret={}&period=45&digits=7",
        base32(S1)
    ))
    .unwrap();
    assert_eq!(custom.period(), 45);
    assert_eq!(custom.code(100).len(), 7);
    let again = Totp::parse_uri(custom.to_uri().expose_secret()).unwrap();
    assert_eq!(again.period(), 45);
    assert_eq!(again.code(100), custom.code(100));
}

// ---- real-world otpauth URI shapes ----

const JB: &str = "JBSWY3DPEHPK3PXP";

/// Reference code for a plain base32 secret (SHA1 / 6 / 30), via the base32 entry point.
fn reference(secret: &str, t: u64) -> String {
    Totp::from_secret_base32(secret).unwrap().code(t)
}

/// Accepted URI must yield the reference code, 6 digits, and survive a `to_uri` round trip.
fn check_default(raw: &str, secret: &str) {
    let totp = Totp::parse_uri(raw).unwrap_or_else(|e| panic!("rejected {raw:?}: {e}"));
    assert_eq!(totp.period(), 30, "{raw:?}");
    for t in [0, 59, 1111111109] {
        let code = totp.code(t);
        assert_eq!(code.len(), 6, "{raw:?}");
        assert_eq!(code, reference(secret, t), "{raw:?} at {t}");
        let again = Totp::parse_uri(totp.to_uri().expose_secret()).unwrap();
        assert_eq!(again.code(t), code, "round trip {raw:?}");
    }
}

#[test]
fn google_authenticator_style() {
    check_default(
        &format!("otpauth://totp/Example:alice@google.com?secret={JB}&issuer=Example"),
        JB,
    );
}

#[test]
fn percent_encoded_label_and_issuer() {
    check_default(
        &format!("otpauth://totp/My%20Site:alice%40example.com?secret={JB}&issuer=My%20Site"),
        JB,
    );
}

#[test]
fn raw_space_in_label() {
    check_default(&format!("otpauth://totp/My Site:alice?secret={JB}"), JB);
}

#[test]
fn explicit_params() {
    let t = Totp::parse_uri(&format!(
        "otpauth://totp/x?secret={JB}&algorithm=SHA256&digits=8&period=60"
    ))
    .unwrap();
    assert_eq!(t.period(), 60);
    assert_eq!(t.code(59).len(), 8);
    let again = Totp::parse_uri(t.to_uri().expose_secret()).unwrap();
    assert_eq!(again.code(1234567), t.code(1234567));
    // Different algorithm gives a different code, so the param is honoured.
    let sha1 = Totp::parse_uri(&format!(
        "otpauth://totp/x?secret={JB}&algorithm=SHA1&digits=8&period=60"
    ))
    .unwrap();
    assert_ne!(sha1.code(1234567), t.code(1234567));
}

#[test]
fn lowercase_algorithm() {
    check_default(&format!("otpauth://totp/x?secret={JB}&algorithm=sha1"), JB);
}

#[test]
fn secret_normalisation() {
    check_default("otpauth://totp/x?secret=jbswy3dpehpk3pxp", JB);
    check_default("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP%3D%3D%3D%3D", JB);
    check_default("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP====", JB);
    check_default("otpauth://totp/x?secret=JBSW Y3DP-EHPK 3PXP", JB);
    check_default("otpauth://totp/x?secret=JBSW%20Y3DP-EHPK%203PXP", JB);
    check_default("otpauth://totp/x?secret=JBSW+Y3DP+EHPK+3PXP", JB);
}

#[test]
fn uppercase_scheme_and_host() {
    check_default(&format!("OTPAUTH://TOTP/Example:alice?secret={JB}"), JB);
    check_default(&format!("OtpAuth://Totp/Example:alice?secret={JB}"), JB);
}

#[test]
fn no_label() {
    check_default(&format!("otpauth://totp/?secret={JB}"), JB);
    check_default(&format!("otpauth://totp?secret={JB}"), JB);
}

#[test]
fn surrounding_whitespace() {
    check_default(&format!("otpauth://totp/x?secret={JB}\n"), JB);
    check_default(&format!("  \totpauth://totp/x?secret={JB}\r\n"), JB);
}

#[test]
fn short_and_odd_length_secrets() {
    // Real services issue 80-bit (16 char) and shorter secrets; no 128-bit minimum is enforced.
    for s in ["JBSWY3DPEH", "GEZDGNBVGY3TQOJQGEZDGNBVGY", "GEZDGNBV"] {
        check_default(&format!("otpauth://totp/x?secret={s}"), s);
        assert!(Totp::from_secret_base32(s).is_ok(), "{s}");
    }
}

#[test]
fn from_secret_base32_normalisation() {
    let want = reference(JB, 59);
    for raw in [
        "jbswy3dpehpk3pxp",
        "JBSWY3DPEHPK3PXP====",
        "JBSW Y3DP-EHPK 3PXP",
        " JBSWY3DPEHPK3PXP\n",
    ] {
        assert_eq!(
            Totp::from_secret_base32(raw).unwrap().code(59),
            want,
            "{raw:?}"
        );
    }
}

#[test]
fn stays_rejected() {
    assert!(matches!(
        Totp::parse_uri(&format!("otpauth://hotp/x?secret={JB}&counter=1")),
        Err(TotpError::Unsupported(_))
    ));
    assert!(matches!(
        Totp::parse_uri(&format!("OTPAUTH://HOTP/x?secret={JB}&counter=1")),
        Err(TotpError::Unsupported(_))
    ));
    assert!(matches!(
        Totp::parse_uri(&format!("otpauth://steam/x?secret={JB}")),
        Err(TotpError::Unsupported(_))
    ));
    assert!(Totp::parse_uri(&format!("https://totp/x?secret={JB}")).is_err());
    assert!(Totp::parse_uri("otpauth://totp/x?issuer=a").is_err());
    assert!(Totp::parse_uri("otpauth://totp/x?secret=").is_err());
    assert!(Totp::parse_uri("otpauth://totp/x?secret=!!!").is_err());
}

// ---- edge cases ----

fn parse(q: &str) -> Result<Totp, TotpError> {
    Totp::parse_uri(&format!("otpauth://totp/x?secret={JB}{q}"))
}

#[test]
fn bad_period() {
    for q in ["&period=0", "&period=", "&period=4294967296"] {
        assert!(matches!(parse(q), Err(TotpError::InvalidUri)), "{q}");
    }
}

#[test]
fn bad_digits() {
    // Today: unparsable digits are InvalidUri, out-of-range digits are Unsupported.
    assert!(matches!(parse("&digits="), Err(TotpError::InvalidUri)));
    assert!(matches!(parse("&digits=9"), Err(TotpError::Unsupported(_))));
}

#[test]
fn percent_decoding_edge_cases() {
    for label in ["a%", "a%4", "a%ZZ", "%80%FF", "%", "%%41"] {
        let r = Totp::parse_uri(&format!("otpauth://totp/{label}?secret={JB}"));
        match r {
            Ok(t) => assert_eq!(t.code(59).len(), 6, "{label}"),
            Err(e) => assert!(matches!(e, TotpError::InvalidUri), "{label}"),
        }
    }
    // Invalid escapes in the secret value must not panic either.
    for s in ["%", "%4", "%ZZ", "%80%FF"] {
        assert!(Totp::parse_uri(&format!("otpauth://totp/x?secret={s}")).is_err());
    }
}

#[test]
fn query_issuer_overrides_label() {
    let t = Totp::parse_uri(&format!("otpauth://totp/Old:bob?secret={JB}&issuer=New")).unwrap();
    let uri = t.to_uri();
    let u = uri.expose_secret();
    assert!(u.contains("issuer=New"), "{u}");
    assert!(!u.contains("Old"), "{u}");
}

#[test]
fn empty_label_issuer_dropped() {
    let t = Totp::parse_uri(&format!("otpauth://totp/:alice?secret={JB}")).unwrap();
    assert!(!t.to_uri().expose_secret().contains("issuer="));
}

#[test]
fn to_uri_encodes_label_and_round_trips() {
    // Query issuer is used so the label carries `/`, space and non-ASCII; the issuer has `:`.
    let raw = format!("otpauth://totp/a%2Fb c%C3%A9?secret={JB}&issuer=Foo%3ABar");
    let t = Totp::parse_uri(&raw).unwrap();
    let out = t.to_uri();
    let u = out.expose_secret();
    let label_end = u.find('?').unwrap();
    let label = &u["otpauth://totp/".len()..label_end];
    assert!(!label.contains(' '), "{u}");
    assert!(!label.contains("a/b"), "{u}");
    assert!(label.is_ascii(), "{u}");
    assert!(u.contains("Foo%3ABar") || u.contains("Foo%3abar"), "{u}");
    let again = Totp::parse_uri(u).unwrap();
    assert_eq!(again.code(59), t.code(59));
    assert_eq!(again.to_uri().expose_secret(), u);
}

#[test]
fn repeated_secret_last_wins() {
    let t = Totp::parse_uri(&format!(
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&secret={JB}"
    ))
    .unwrap();
    assert_eq!(t.code(59), reference(JB, 59));
}

#[test]
fn fragment_ignored() {
    let t = Totp::parse_uri(&format!(
        "otpauth://totp/x?secret={JB}#frag?secret=GEZDGNBV"
    ))
    .unwrap();
    assert_eq!(t.code(59), reference(JB, 59));
}

#[test]
fn encoded_separator_in_label() {
    let t = Totp::parse_uri(&format!("otpauth://totp/Example%3Aalice?secret={JB}")).unwrap();
    assert!(t.to_uri().expose_secret().contains("issuer=Example"));
}
