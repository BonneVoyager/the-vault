//! Host facts for the Copy diagnostics block (spec 04 §1b): macOS version and Mac model
//! identifier. No network, no secrets.

pub use imp::{model_identifier, os_version};

#[cfg(target_os = "macos")]
mod imp {
    use objc2_foundation::NSProcessInfo;

    /// macOS version as "major.minor" or "major.minor.patch" (patch omitted when 0).
    pub fn os_version() -> String {
        let v = NSProcessInfo::processInfo().operatingSystemVersion();
        if v.patchVersion > 0 {
            format!("{}.{}.{}", v.majorVersion, v.minorVersion, v.patchVersion)
        } else {
            format!("{}.{}", v.majorVersion, v.minorVersion)
        }
    }

    /// Mac model identifier from `sysctlbyname("hw.model")`, e.g. "Mac15,6"; "unknown" on error.
    pub fn model_identifier() -> String {
        let mut buf = [0u8; 256];
        let mut len: libc::size_t = buf.len();
        // SAFETY: the name is a NUL-terminated C string literal; `buf` is a valid writable
        // buffer of `len` bytes and `len` points to its size, which the kernel updates to the
        // number of bytes written (never more than the given size). No new value is set
        // (null pointer, length 0).
        let rc = unsafe {
            libc::sysctlbyname(
                c"hw.model".as_ptr(),
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || len == 0 || len > buf.len() {
            return "unknown".to_owned();
        }
        let bytes = &buf[..len];
        let bytes = bytes.split(|b| *b == 0).next().unwrap_or_default();
        match std::str::from_utf8(bytes) {
            Ok(s) if !s.trim().is_empty() => s.trim().to_owned(),
            _ => "unknown".to_owned(),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn os_version() -> String {
        "unknown".to_owned()
    }

    pub fn model_identifier() -> String {
        "unknown".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_dotted_version(s: &str) -> bool {
        let parts: Vec<&str> = s.split('.').collect();
        (2..=3).contains(&parts.len())
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    }

    fn is_model(s: &str) -> bool {
        let Some(letters_end) = s.find(|c: char| !c.is_ascii_alphabetic()) else {
            return false;
        };
        let Some((major, minor)) = s[letters_end..].split_once(',') else {
            return false;
        };
        letters_end > 0
            && !major.is_empty()
            && !minor.is_empty()
            && major.bytes().all(|b| b.is_ascii_digit())
            && minor.bytes().all(|b| b.is_ascii_digit())
    }

    #[test]
    fn os_version_is_dotted_digits() {
        let v = os_version();
        assert!(!v.is_empty());
        #[cfg(target_os = "macos")]
        assert!(is_dotted_version(&v), "unexpected os_version {v:?}");
        #[cfg(not(target_os = "macos"))]
        assert_eq!(v, "unknown");
    }

    #[test]
    fn model_identifier_is_model_or_unknown() {
        let m = model_identifier();
        assert!(!m.is_empty());
        assert!(is_model(&m) || m == "unknown", "unexpected model {m:?}");
    }

    #[test]
    fn pattern_helpers() {
        assert!(is_dotted_version("15.1.1") && is_dotted_version("26.0"));
        assert!(
            !is_dotted_version("15") && !is_dotted_version("15.a") && !is_dotted_version("1.2.3.4")
        );
        assert!(is_model("Mac15,6") && is_model("MacBookPro18,1"));
        assert!(
            !is_model("Mac15") && !is_model("15,6") && !is_model("Mac15,") && !is_model("Mac,6")
        );
    }
}
