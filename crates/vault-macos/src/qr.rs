//! "Scan QR from screen" for TOTP fields (spec 05 §2.3 Edit mode, phase 5).
//!
//! Capture uses CoreGraphics `CGDisplayCreateImage`, one synchronous call per
//! active display. Apple deprecated it in macOS 14.4 in favour of
//! ScreenCaptureKit, but it still works on 14 and 15 and later. It needs the
//! Screen Recording permission. Each capture is drawn into an 8-bit
//! `DeviceGray` bitmap context, so CoreGraphics does the luma conversion and
//! no image crate is needed. QR codes are then decoded with `rqrr`.
//!
//! Migration note: if `CGDisplayCreateImage` stops working, switch to
//! ScreenCaptureKit's `SCScreenshotManager.captureImage` via
//! `objc2-screen-capture-kit`. That API is async (completion handler), so it
//! needs a bridge to a synchronous wait with a timeout. On macOS 15 and later
//! the system also re-prompts periodically for Screen Recording consent (TCC),
//! whichever API is used.
//!
//! Decoded payloads may hold TOTP secrets, so they are returned as
//! `SecretString`. Payloads are never logged or `Debug`-printed. Our gray
//! screen buffers are wrapped in `Zeroizing`.
//!
//! Accepted limitation, pending an owner decision on the `rqrr-zeroize` fork:
//! these copies of screen or payload data are NOT wiped on drop:
//! - the CG-owned `CGImage` returned by `CGDisplayCreateImage`, freed by
//!   CoreGraphics;
//! - `rqrr`'s internal pixel buffer inside `PreparedImage`;
//! - `rqrr`'s internal decode state (`RawData`, `CorrectedDataStream`) and the
//!   partially filled payload `Vec` when decoding fails part way.

use secrecy::{ExposeSecret, SecretString};

use crate::MacError;

/// True when this process may capture the screen (Screen Recording granted).
///
/// Never prompts. Always false off macOS.
pub fn screen_capture_permitted() -> bool {
    imp::permitted()
}

/// Capture every active display and decode all QR codes on it.
///
/// Returns the payloads deduplicated and in screen order. Displays are ordered
/// top-to-bottom then left-to-right by their global origin. Codes on one display
/// are ordered by the top-left corner of their bounds, also top-to-bottom then
/// left-to-right. Nothing is filtered: callers keep only `otpauth://` URIs.
///
/// When Screen Recording is not granted this asks macOS for it once and then
/// returns `MacError::NotAvailable`. macOS shows its own prompt only the first
/// time. The app must then show "Grant Screen Recording in System Settings";
/// the grant takes effect after the app restarts. Off macOS this always returns
/// `MacError::NotAvailable`.
pub fn scan_qr_from_screen() -> Result<Vec<SecretString>, MacError> {
    imp::scan()
}

/// Decode every QR code in an 8-bit grayscale image (0 = black, 255 = white).
///
/// `pixels` is row-major, top row first, with `width * height` bytes and no
/// row padding. If the slice length does not match, the result is empty.
/// Payloads are deduplicated and ordered top-to-bottom then left-to-right.
pub fn decode_qr_from_gray(width: usize, height: usize, pixels: &[u8]) -> Vec<SecretString> {
    let mut out = Vec::new();
    decode_into(width, height, pixels, &mut out);
    out
}

/// Decode `pixels` and append payloads not already in `out`.
fn decode_into(width: usize, height: usize, pixels: &[u8], out: &mut Vec<SecretString>) {
    if width == 0 || height == 0 || width.checked_mul(height) != Some(pixels.len()) {
        return;
    }
    let mut img =
        rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| pixels[y * width + x]);
    let mut found: Vec<((i32, i32), SecretString)> = img
        .detect_grids()
        .into_iter()
        .filter_map(|grid| {
            let top_left = grid.bounds[0];
            let (_, content) = grid.decode().ok()?;
            Some(((top_left.y, top_left.x), SecretString::new(content)))
        })
        .collect();
    found.sort_by_key(|(pos, _)| *pos);
    for (_, payload) in found {
        if !out
            .iter()
            .any(|seen| seen.expose_secret() == payload.expose_secret())
        {
            out.push(payload);
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::c_void;

    use objc2_core_foundation::{CFRetained, CGPoint, CGRect, CGSize};
    #[allow(deprecated)] // CGDisplayCreateImage, see the module docs.
    use objc2_core_graphics::{
        CGBitmapContextCreate, CGColorSpace, CGContext, CGDirectDisplayID, CGDisplayBounds,
        CGDisplayCreateImage, CGError, CGGetActiveDisplayList, CGImage, CGImageAlphaInfo,
        CGPreflightScreenCaptureAccess, CGRequestScreenCaptureAccess,
    };
    use secrecy::SecretString;
    use zeroize::Zeroizing;

    use crate::MacError;

    /// Upper bound on displays queried; macOS supports far fewer.
    const MAX_DISPLAYS: u32 = 32;

    pub fn permitted() -> bool {
        CGPreflightScreenCaptureAccess()
    }

    pub fn scan() -> Result<Vec<SecretString>, MacError> {
        if !CGPreflightScreenCaptureAccess() {
            // Registers the app in System Settings and shows the system prompt
            // the first time. It returns at once; the grant needs a relaunch.
            let _ = CGRequestScreenCaptureAccess();
            return Err(MacError::NotAvailable);
        }
        let captures = active_displays()?.into_iter().map(|display| {
            #[allow(deprecated)] // Deprecated in 14.4 for ScreenCaptureKit; still works.
            CGDisplayCreateImage(display)
        });
        decode_captures(captures)
    }

    /// Decode every capture. `None` is a display CoreGraphics refused to capture.
    ///
    /// Returns `MacError::NotAvailable` when no display yielded a usable image,
    /// so "capture refused" is distinct from "captured, but no QR found".
    pub(super) fn decode_captures(
        captures: impl IntoIterator<Item = Option<CFRetained<CGImage>>>,
    ) -> Result<Vec<SecretString>, MacError> {
        let mut out = Vec::new();
        let mut captured_any = false;
        for image in captures.into_iter().flatten() {
            if let Some((w, h, gray)) = gray_pixels(&image) {
                captured_any = true;
                super::decode_into(w, h, &gray, &mut out);
            }
        }
        if captured_any {
            Ok(out)
        } else {
            Err(MacError::NotAvailable)
        }
    }

    /// Active display ids, sorted top-to-bottom then left-to-right.
    fn active_displays() -> Result<Vec<CGDirectDisplayID>, MacError> {
        let mut ids = vec![0 as CGDirectDisplayID; MAX_DISPLAYS as usize];
        let mut count: u32 = 0;
        // SAFETY: `ids` has room for MAX_DISPLAYS entries and `count` is a valid
        // out-pointer; CoreGraphics writes at most MAX_DISPLAYS ids.
        let err = unsafe { CGGetActiveDisplayList(MAX_DISPLAYS, ids.as_mut_ptr(), &mut count) };
        if err != CGError::Success {
            return Err(MacError::Other(format!(
                "CGGetActiveDisplayList failed: {}",
                err.0
            )));
        }
        ids.truncate(count.min(MAX_DISPLAYS) as usize);
        ids.sort_by(|a, b| {
            let (ra, rb) = (CGDisplayBounds(*a).origin, CGDisplayBounds(*b).origin);
            (ra.y, ra.x)
                .partial_cmp(&(rb.y, rb.x))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(ids)
    }

    /// Draw `image` into an 8-bit DeviceGray bitmap and return its pixels,
    /// top row first, with no row padding.
    pub(super) fn gray_pixels(image: &CGImage) -> Option<(usize, usize, Zeroizing<Vec<u8>>)> {
        let w = CGImage::width(Some(image));
        let h = CGImage::height(Some(image));
        let len = w.checked_mul(h)?;
        if len == 0 {
            return None;
        }
        let mut buf = Zeroizing::new(vec![0xFFu8; len]);
        let space = CGColorSpace::new_device_gray()?;
        // SAFETY: `buf` holds exactly `w * h` bytes and outlives `ctx`, which is
        // dropped at the end of this function before `buf` is returned. The
        // layout is 8 bits per component, one component, `w` bytes per row, no
        // alpha: a combination CoreGraphics supports for DeviceGray.
        let ctx = unsafe {
            CGBitmapContextCreate(
                buf.as_mut_ptr().cast::<c_void>(),
                w,
                h,
                8,
                w,
                Some(&space),
                CGImageAlphaInfo::None.0,
            )
        }?;
        let rect = CGRect::new(CGPoint::new(0.0, 0.0), CGSize::new(w as f64, h as f64));
        CGContext::draw_image(Some(&ctx), rect, Some(image));
        drop(ctx);
        Some((w, h, buf))
    }

    #[cfg(test)]
    mod tests {
        use std::ffi::c_void;

        use objc2_core_foundation::CFRetained;
        use objc2_core_graphics::{
            CGBitmapContextCreate, CGBitmapContextCreateImage, CGColorSpace, CGImage,
            CGImageAlphaInfo,
        };

        use crate::MacError;

        /// Build an RGBA (premultiplied-last) CGImage, top row first.
        fn rgba_image(w: usize, h: usize, mut rgba: Vec<u8>) -> CFRetained<CGImage> {
            assert_eq!(rgba.len(), w * h * 4);
            let space = CGColorSpace::new_device_rgb().unwrap();
            // SAFETY: `rgba` holds w*h*4 bytes, matching 8 bpc, 4 components,
            // `w * 4` bytes per row, and outlives `ctx` (dropped below).
            let ctx = unsafe {
                CGBitmapContextCreate(
                    rgba.as_mut_ptr().cast::<c_void>(),
                    w,
                    h,
                    8,
                    w * 4,
                    Some(&space),
                    CGImageAlphaInfo::PremultipliedLast.0,
                )
            }
            .unwrap();
            // The image copies the bitmap, so `rgba` may be freed afterwards.
            let image = CGBitmapContextCreateImage(Some(&ctx)).unwrap();
            drop(ctx);
            image
        }

        /// The CGImage -> gray path keeps orientation (top row first) and luma.
        #[test]
        fn gray_pixels_keeps_orientation_and_luma() {
            let (w, h) = (4usize, 2usize);
            // Top row: black, white, red, white. Bottom row: all white.
            let mut rgba = vec![255u8; w * h * 4];
            rgba[0..4].copy_from_slice(&[0, 0, 0, 255]);
            rgba[8..12].copy_from_slice(&[255, 0, 0, 255]);
            let image = rgba_image(w, h, rgba);

            let (gw, gh, gray) = super::gray_pixels(&image).unwrap();
            assert_eq!((gw, gh), (w, h));
            assert!(gray[0] < 16, "black stays black at top-left: {}", gray[0]);
            assert!(gray[1] > 240, "white stays white: {}", gray[1]);
            assert!(
                gray[2] > 16 && gray[2] < 200,
                "red maps to mid gray: {}",
                gray[2]
            );
            assert!(gray[w..].iter().all(|&p| p > 240), "bottom row is white");
        }

        #[test]
        fn all_captures_refused_is_not_available() {
            assert!(matches!(
                super::decode_captures([None, None]),
                Err(MacError::NotAvailable)
            ));
            assert!(matches!(
                super::decode_captures(std::iter::empty()),
                Err(MacError::NotAvailable)
            ));
        }

        #[test]
        fn one_capture_without_qr_is_ok_empty() {
            let white = rgba_image(8, 8, vec![255u8; 8 * 8 * 4]);
            let got = super::decode_captures([None, Some(white)]).unwrap();
            assert!(got.is_empty());
        }

        #[test]
        fn decode_into_rejects_length_mismatch() {
            let mut out = Vec::new();
            super::super::decode_into(10, 10, &[255u8; 99], &mut out);
            assert!(out.is_empty());
            assert!(super::super::decode_qr_from_gray(0, 0, &[]).is_empty());
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use secrecy::SecretString;

    use crate::MacError;

    pub fn permitted() -> bool {
        false
    }

    pub fn scan() -> Result<Vec<SecretString>, MacError> {
        Err(MacError::NotAvailable)
    }
}
