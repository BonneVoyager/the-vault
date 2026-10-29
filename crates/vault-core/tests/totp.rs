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
