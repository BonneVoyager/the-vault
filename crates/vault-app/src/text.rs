//! Display formatting: relative times, dates, TOTP grouping, card masking.

use std::time::{SystemTime, UNIX_EPOCH};

/// Wall-clock now in Unix milliseconds (the core never reads a clock).
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// "just now", "5m ago", "2h ago", "3d ago", else the UTC date.
pub fn relative(now_ms: u64, then_ms: u64) -> String {
    let secs = now_ms.saturating_sub(then_ms) / 1000;
    match secs {
        0..60 => "just now".to_owned(),
        60..3600 => format!("{}m ago", secs / 60),
        3600..86_400 => format!("{}h ago", secs / 3600),
        86_400..2_592_000 => format!("{}d ago", secs / 86_400),
        _ => date(then_ms),
    }
}

/// `YYYY-MM-DD` (UTC) for Unix milliseconds.
pub fn date(ms: u64) -> String {
    // Howard Hinnant's civil_from_days.
    let days = i64::try_from(ms / 86_400_000).unwrap_or(0);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Last path component for messages, or the whole path if there is none.
pub fn file_name(path: &std::path::Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// `YYYY-MM-DD HH:MM UTC` for a `SystemTime` (backup list, last saved).
pub fn date_time(t: SystemTime) -> String {
    let ms = t
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let mins = (ms / 60_000) % (24 * 60);
    format!("{} {:02}:{:02} UTC", date(ms), mins / 60, mins % 60)
}

/// "512 B", "12.3 KB", "4.1 MB" (decimal units, like Finder).
pub fn file_size(bytes: u64) -> String {
    match bytes {
        0..1000 => format!("{bytes} B"),
        1000..1_000_000 => format!("{:.1} KB", bytes as f64 / 1e3),
        _ => format!("{:.1} MB", bytes as f64 / 1e6),
    }
}

/// "482193" → "482 193"; 8 digits → "1234 5678"; 7 → "123 4567".
pub fn group_code(code: &str) -> String {
    let split = code.len() / 2;
    if code.len() < 6 || !code.is_char_boundary(split) {
        return code.to_owned();
    }
    format!("{} {}", &code[..split], &code[split..])
}

/// Last four digits of a card number, ignoring spaces and dashes.
pub fn last4(number: &str) -> Option<String> {
    let digits: Vec<char> = number.chars().filter(char::is_ascii_digit).collect();
    (digits.len() >= 4).then(|| digits[digits.len() - 4..].iter().collect())
}

/// `•••• •••• •••• 4242`, or plain dots if the number is too short.
pub fn mask_card(number: &str) -> String {
    match last4(number) {
        Some(l) => format!("•••• •••• •••• {l}"),
        None => DOTS.to_owned(),
    }
}

/// Fixed-length mask so the dots do not leak a password's length.
pub const DOTS: &str = "••••••••••";

/// `s` with its first character upper-cased ("username" → "Username"); the rest is
/// untouched ("first name" → "First name", "iCloud" → "ICloud"). For field-name display
/// and template names; stored names are never rewritten with it.
pub fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// At most `max` characters, with an ellipsis when cut.
pub fn truncate(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_owned(),
    }
}

/// First 8 hex digits of a device id.
pub fn short_id(id: vault_core::Uuid) -> String {
    id.simple().to_string()[..8].to_owned()
}

/// A URL the browser may open: `http`/`https` as-is, no scheme gets `https://`.
///
/// Every other scheme (`file:`, `smb:`, `javascript:`, app deep links) returns `None`,
/// so a crafted item cannot launch local files or other apps.
pub fn browser_url(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    match scheme_of(raw) {
        Some(s) if s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https") => {
            Some(raw.to_owned())
        }
        Some(_) => None,
        None => Some(format!("https://{raw}")),
    }
}

/// The URI scheme of `raw`, if it has one. `host:8080/...` is a host and port, not a scheme.
fn scheme_of(raw: &str) -> Option<&str> {
    let (head, rest) = raw.split_once(':')?;
    let mut chars = head.chars();
    let scheme_like = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    let is_port = rest.starts_with(|c: char| c.is_ascii_digit());
    (scheme_like && !is_port).then_some(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_backup_times_and_sizes() {
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1_761_745_380);
        assert_eq!(date_time(t), "2025-10-29 13:43 UTC");
        assert_eq!(file_size(999), "999 B");
        assert_eq!(file_size(12_345), "12.3 KB");
        assert_eq!(file_size(4_100_000), "4.1 MB");
    }

    #[test]
    fn relative_times() {
        let now = 1_000_000_000_000;
        assert_eq!(relative(now, now), "just now");
        assert_eq!(relative(now, now - 5 * 60_000), "5m ago");
        assert_eq!(relative(now, now - 2 * 3_600_000), "2h ago");
        assert_eq!(relative(now, now - 3 * 86_400_000), "3d ago");
        assert_eq!(relative(now, 0), "1970-01-01");
        assert_eq!(
            relative(0, now),
            "just now",
            "future times do not underflow"
        );
    }

    #[test]
    fn dates() {
        assert_eq!(date(0), "1970-01-01");
        // 2026-10-29T12:00:00Z
        assert_eq!(date(1_793_275_200_000), "2026-10-29");
        // 2024-02-29 (leap day)
        assert_eq!(date(1_709_164_800_000), "2024-02-29");
    }

    #[test]
    fn codes_and_cards() {
        assert_eq!(group_code("482193"), "482 193");
        assert_eq!(group_code("12345678"), "1234 5678");
        assert_eq!(group_code("1234567"), "123 4567");
        assert_eq!(mask_card("4242-4242-4242-4242"), "•••• •••• •••• 4242");
        assert_eq!(mask_card("12"), DOTS);
        assert_eq!(truncate("abcdef", 3), "abc…");
        assert_eq!(truncate("abc", 3), "abc");
        assert!(browser_url("  ").is_none());
    }

    #[test]
    fn browser_url_allows_only_http_and_https() {
        assert_eq!(browser_url("github.com").unwrap(), "https://github.com");
        assert_eq!(
            browser_url(" console.hetzner.cloud/x ").unwrap(),
            "https://console.hetzner.cloud/x"
        );
        assert_eq!(
            browser_url("localhost:8080/a").unwrap(),
            "https://localhost:8080/a"
        );
        assert_eq!(browser_url("http://x").unwrap(), "http://x");
        assert_eq!(browser_url("HTTPS://x").unwrap(), "HTTPS://x");
        for bad in [
            "file:///etc/passwd",
            "smb://server/share",
            "javascript:alert(1)",
            "mailto:a@b.c",
            "slack://open",
            "vault+x://y",
        ] {
            assert!(browser_url(bad).is_none(), "{bad} must be rejected");
        }
    }
}
