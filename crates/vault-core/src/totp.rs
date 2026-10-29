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

/// ASCII case-insensitive prefix test that never copies `s` (the URI carries the secret, so
/// it must not be lowercased into a plain `String`).
fn starts_with_ignore_ascii_case(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

impl Totp {
    /// Parse an `otpauth://totp/...` URI. `otpauth://hotp` yields [`TotpError::Unsupported`].
    pub fn parse_uri(uri: &str) -> Result<Self, TotpError> {
        let uri = uri.trim();
        if starts_with_ignore_ascii_case(uri, "otpauth://hotp") {
            return Err(TotpError::Unsupported("hotp".to_owned()));
        }
        if starts_with_ignore_ascii_case(uri, "otpauth://steam") {
            return Err(TotpError::Unsupported("steam".to_owned()));
        }
        // The unchecked variant skips the 128-bit minimum secret length, which real-world
        // (and RFC 6238 test) secrets do not always meet.
        let mut parsed = TOTP::from_url_unchecked(uri).map_err(|_| TotpError::InvalidUri)?;
        let secret = Zeroizing::new(std::mem::take(&mut parsed.secret));
        if secret.is_empty() {
            return Err(TotpError::InvalidSecret);
        }
        if !matches!(
            parsed.algorithm,
            Algorithm::SHA1 | Algorithm::SHA256 | Algorithm::SHA512
        ) {
            return Err(TotpError::Unsupported("algorithm".to_owned()));
        }
        if !(6..=8).contains(&parsed.digits) {
            return Err(TotpError::Unsupported(format!("{} digits", parsed.digits)));
        }
        let period = u32::try_from(parsed.step)
            .ok()
            .filter(|p| *p >= 1)
            .ok_or(TotpError::InvalidUri)?;
        Ok(Self {
            secret,
            algorithm: parsed.algorithm,
            digits: parsed.digits,
            period,
            issuer: parsed.issuer.take(),
            account_name: std::mem::take(&mut parsed.account_name),
        })
    }

    /// Base32 secret with defaults SHA1 / 6 digits / 30 s. Spaces, dashes and padding are ignored.
    pub fn from_secret_base32(secret: &str) -> Result<Self, TotpError> {
        let mut cleaned: Zeroizing<String> = Zeroizing::new(String::with_capacity(secret.len()));
        cleaned.extend(
            secret
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
                .map(|c| c.to_ascii_uppercase()),
        );
        // Moved (not cloned) into `Secret`, which zeroizes on drop via totp-rs's `zeroize` feature.
        let encoded = Secret::Encoded(std::mem::take(&mut *cleaned));
        let bytes = encoded.to_bytes().map_err(|_| TotpError::InvalidSecret)?;
        if bytes.is_empty() {
            return Err(TotpError::InvalidSecret);
        }
        Ok(Self {
            secret: Zeroizing::new(bytes),
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
