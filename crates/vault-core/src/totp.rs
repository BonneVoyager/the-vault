//! TOTP codes from `otpauth://totp/...` URIs (`02-core-api.md` "totp").
//!
//! HOTP and Steam-style codes are out of scope. The secret is held in a `Zeroizing` buffer and
//! the type deliberately has no `Debug` impl.

use secrecy::SecretString;
use thiserror::Error;
use totp_rs::{Algorithm, Secret, TOTP};
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("invalid otpauth URI")]
    InvalidUri,
    #[error("invalid TOTP secret")]
    InvalidSecret,
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// Parsed TOTP configuration plus its secret.
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: usize,
    period: u32,
    issuer: Option<String>,
    account_name: String,
}

/// Percent-decode `s` (`+` becomes a space when `plus_space`). Invalid escapes are kept
/// literally. Output is a byte buffer so secrets stay in zeroizable memory.
fn percent_decode(s: &str, plus_space: bool) -> Zeroizing<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(b.len()));
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match b[i] {
            b'%' if i + 2 < b.len() && hex(b[i + 1]).is_some() && hex(b[i + 2]).is_some() => {
                out.push((hex(b[i + 1]).unwrap() * 16 + hex(b[i + 2]).unwrap()) as u8);
                i += 3;
                continue;
            }
            b'+' if plus_space => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    out
}

/// Strip whitespace, dashes and `=` padding and uppercase, then decode base32.
///
/// No minimum length is enforced: real services issue 80-bit (16 char) or shorter secrets,
/// which totp-rs's checked constructors would reject (they demand 128 bits).
fn decode_secret(raw: &[u8]) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let text = std::str::from_utf8(raw).map_err(|_| TotpError::InvalidSecret)?;
    let mut cleaned: Zeroizing<String> = Zeroizing::new(String::with_capacity(text.len()));
    cleaned.extend(
        text.chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .map(|c| c.to_ascii_uppercase()),
    );
    // Moved (not cloned) into `Secret`, which zeroizes on drop via totp-rs's `zeroize` feature.
    let encoded = Secret::Encoded(std::mem::take(&mut *cleaned));
    let bytes = Zeroizing::new(encoded.to_bytes().map_err(|_| TotpError::InvalidSecret)?);
    if bytes.is_empty() {
        return Err(TotpError::InvalidSecret);
    }
    Ok(bytes)
}

impl Totp {
    /// Parse an `otpauth://totp/...` URI. `otpauth://hotp` yields [`TotpError::Unsupported`].
    ///
    /// Lenient about real-world shapes: scheme and type are case-insensitive, the label may be
    /// empty, absent, percent-encoded or contain raw spaces, and the secret may be lowercase,
    /// padded, or grouped with spaces/dashes.
    pub fn parse_uri(uri: &str) -> Result<Self, TotpError> {
        let uri = uri.trim();
        let rest = uri
            .get(..10)
            .filter(|p| p.eq_ignore_ascii_case("otpauth://"))
            .map(|_| &uri[10..])
            .ok_or(TotpError::InvalidUri)?;
        let rest = rest.split('#').next().unwrap_or("");
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (kind, label) = path.split_once('/').unwrap_or((path, ""));
        if kind.eq_ignore_ascii_case("hotp") {
            return Err(TotpError::Unsupported("hotp".to_owned()));
        }
        if kind.eq_ignore_ascii_case("steam") {
            return Err(TotpError::Unsupported("steam".to_owned()));
        }
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(TotpError::InvalidUri);
        }

        // Split on a raw `:` first: `to_uri` encodes a colon inside the issuer as `%3A`, so the
        // separator is the only literal one. Labels that encode the separator itself
        // (`Example%3Aalice`) have no raw colon and are split after decoding.
        let dec = |s: &str| {
            String::from_utf8_lossy(&percent_decode(s, false))
                .trim()
                .to_owned()
        };
        let (issuer, account_name) = match label.split_once(':') {
            Some((i, a)) => (Some(dec(i)), dec(a)),
            None => {
                let full = dec(label);
                match full.split_once(':') {
                    Some((i, a)) => (Some(i.trim().to_owned()), a.trim().to_owned()),
                    None => (None, full),
                }
            }
        };
        let mut issuer = issuer.filter(|i| !i.is_empty());

        let mut algorithm = Algorithm::SHA1;
        let mut digits = 6usize;
        let mut period = 30u64;
        let mut secret = None;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = String::from_utf8_lossy(&percent_decode(key, true)).to_ascii_lowercase();
            let value = percent_decode(value, true);
            let text = || String::from_utf8_lossy(&value).trim().to_owned();
            match key.as_str() {
                "secret" => secret = Some(decode_secret(&value)?),
                "issuer" => {
                    let i = text();
                    if !i.is_empty() {
                        issuer = Some(i);
                    }
                }
                "algorithm" => {
                    algorithm = match text().to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::SHA1,
                        "SHA256" => Algorithm::SHA256,
                        "SHA512" => Algorithm::SHA512,
                        _ => return Err(TotpError::Unsupported("algorithm".to_owned())),
                    };
                }
                "digits" => digits = text().parse().map_err(|_| TotpError::InvalidUri)?,
                "period" => period = text().parse().map_err(|_| TotpError::InvalidUri)?,
                _ => {}
            }
        }
        let secret = secret.ok_or(TotpError::InvalidSecret)?;
        if !(6..=8).contains(&digits) {
            return Err(TotpError::Unsupported(format!("{digits} digits")));
        }
        let period = u32::try_from(period)
            .ok()
            .filter(|p| *p >= 1)
            .ok_or(TotpError::InvalidUri)?;
        Ok(Self {
            secret,
            algorithm,
            digits,
            period,
            issuer,
            account_name,
        })
    }

    /// Base32 secret with defaults SHA1 / 6 / 30 s. Same normalisation and length policy as
    /// [`Totp::parse_uri`]: spaces, dashes and padding are ignored, case is ignored.
    pub fn from_secret_base32(secret: &str) -> Result<Self, TotpError> {
        Ok(Self {
            secret: decode_secret(secret.as_bytes())?,
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            issuer: None,
            account_name: String::new(),
        })
    }

    fn engine(&self) -> TOTP {
        TOTP::new_unchecked(
            self.algorithm,
            self.digits,
            1,
            u64::from(self.period),
            self.secret.to_vec(),
            self.issuer.clone(),
            self.account_name.clone(),
        )
    }

    /// Zero-padded code for the step containing `unix_secs`.
    pub fn code(&self, unix_secs: u64) -> String {
        self.engine().generate(unix_secs)
    }

    /// Seconds until the current code expires, in `1..=period`.
    pub fn seconds_remaining(&self, unix_secs: u64) -> u32 {
        let period = u64::from(self.period);
        (period - unix_secs % period) as u32
    }

    pub fn period(&self) -> u32 {
        self.period
    }

    /// Canonical `otpauth://totp/...` URI including the secret.
    pub fn to_uri(&self) -> SecretString {
        SecretString::new(self.engine().get_url())
    }
}
