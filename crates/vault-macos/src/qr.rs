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
//! `scan_qr_from_image_file` is the permission-free alternative: the user picks
//! a screenshot or exported QR image. AppKit's `NSBitmapImageRep` decodes it
//! (any format ImageIO reads: PNG, JPEG, HEIC, TIFF, GIF, BMP...) and the
//! first frame goes through the same gray conversion and decoder.
//!
//! Decoded payloads may hold TOTP secrets, so they are returned as
//! `SecretString`. Payloads are never logged or `Debug`-printed. Our gray
//! screen buffers are wrapped in `Zeroizing`.
//!
//! Accepted limitation, pending an owner decision on the `rqrr-zeroize` fork:
//! these copies of screen or payload data are NOT wiped on drop:
//! - the CG-owned `CGImage` returned by `CGDisplayCreateImage`, freed by
//!   CoreGraphics;
//! - for image files: the `NSData` copy of the file bytes and the decoded
//!   bitmap held by `NSBitmapImageRep` / its `CGImage` (our own read buffer
//!   is wrapped in `Zeroizing`);
//! - `rqrr`'s internal pixel buffer inside `PreparedImage`;
//! - `rqrr`'s internal decode state (`RawData`, `CorrectedDataStream`) and the
//!   partially filled payload `Vec` when decoding fails part way.

use std::path::Path;

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

/// Largest image accepted by [`scan_qr_from_image_file`], in pixels.
pub const MAX_IMAGE_PIXELS: usize = 50_000_000;

/// Largest image file accepted by [`scan_qr_from_image_file`], in bytes.
pub const MAX_IMAGE_FILE_BYTES: u64 = 100 * 1024 * 1024;

/// Decode every QR code in an image file (PNG, JPEG, HEIC, TIFF, ...).
///
/// Needs no Screen Recording permission. Only the first frame of multi-frame
/// files is read. Payloads are deduplicated and ordered like
/// [`decode_qr_from_gray`]; an image with no QR code gives `Ok(vec![])`.
///
/// Errors with `MacError::Other("could not read image: ...")` when the file
/// cannot be read, is not a decodable bitmap image, is larger than
/// [`MAX_IMAGE_FILE_BYTES`], or has more than [`MAX_IMAGE_PIXELS`] pixels.
/// Off macOS this always returns `MacError::NotAvailable`.
pub fn scan_qr_from_image_file(path: &Path) -> Result<Vec<SecretString>, MacError> {
    imp::scan_file(path)
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
    use std::io::Read;
    use std::path::Path;

    use objc2::AnyThread;
    use objc2_app_kit::{NSBitmapImageRep, NSImageRep};
    use objc2_core_foundation::{CFRetained, CGPoint, CGRect, CGSize};
    #[allow(deprecated)] // CGDisplayCreateImage, see the module docs.
    use objc2_core_graphics::{
        CGBitmapContextCreate, CGColorSpace, CGContext, CGDirectDisplayID, CGDisplayBounds,
        CGDisplayCreateImage, CGError, CGGetActiveDisplayList, CGImage, CGImageAlphaInfo,
        CGPreflightScreenCaptureAccess, CGRequestScreenCaptureAccess,
    };
    use objc2_foundation::NSData;
    use secrecy::SecretString;
    use zeroize::Zeroizing;

    use super::{MAX_IMAGE_FILE_BYTES, MAX_IMAGE_PIXELS};
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

    fn read_error(reason: impl std::fmt::Display) -> MacError {
        MacError::Other(format!("could not read image: {reason}"))
    }

    /// Refuse empty images and images over [`MAX_IMAGE_PIXELS`].
    fn check_dimensions(w: usize, h: usize) -> Result<(), MacError> {
        match w.checked_mul(h) {
            Some(0) => Err(read_error("image is empty")),
            Some(n) if n <= MAX_IMAGE_PIXELS => Ok(()),
            _ => Err(read_error(format_args!(
                "image is too large ({w}x{h} pixels, limit {MAX_IMAGE_PIXELS})"
            ))),
        }
    }

    /// Read at most [`MAX_IMAGE_FILE_BYTES`] of `path` into a wiped buffer.
    fn read_capped(path: &Path) -> Result<Zeroizing<Vec<u8>>, MacError> {
        use std::os::unix::fs::OpenOptionsExt;

        // O_NONBLOCK keeps open() from blocking on a FIFO with no writer; it
        // has no effect on reads from regular files. The type is checked on
        // the open handle, not the path, so the path cannot be swapped between
        // the check and the read.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .map_err(read_error)?;
        let meta = file.metadata().map_err(read_error)?;
        if !meta.is_file() {
            return Err(read_error("not a regular file"));
        }
        let too_big = || {
            read_error(format_args!(
                "file is larger than {MAX_IMAGE_FILE_BYTES} bytes"
            ))
        };
        let len = meta.len();
        if len > MAX_IMAGE_FILE_BYTES {
            return Err(too_big());
        }
        // Reserve the reported size plus one byte. For a regular file whose
        // size does not change while it is read, the buffer never reallocates,
        // so no unwiped copies are left behind. If the file grows meanwhile,
        // `Vec` may reallocate (leaving an unwiped copy), and `take` still
        // bounds the read.
        let mut bytes = Zeroizing::new(Vec::with_capacity(len as usize + 1));
        file.take(MAX_IMAGE_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(read_error)?;
        if bytes.len() as u64 > MAX_IMAGE_FILE_BYTES {
            return Err(too_big());
        }
        Ok(bytes)
    }

    pub fn scan_file(path: &Path) -> Result<Vec<SecretString>, MacError> {
        let bytes = read_capped(path)?;
        let data = NSData::with_bytes(&bytes);
        drop(bytes);
        // ImageIO decodes lazily: this parses the header, and the pixels are
        // only decoded when the CGImage is drawn below, after the size check.
        let rep = NSBitmapImageRep::initWithData(NSBitmapImageRep::alloc(), &data)
            .ok_or_else(|| read_error("not a supported image format"))?;
        let rep_ref: &NSImageRep = &rep;
        let (w, h) = (rep_ref.pixelsWide(), rep_ref.pixelsHigh());
        check_dimensions(
            usize::try_from(w).unwrap_or(0),
            usize::try_from(h).unwrap_or(0),
        )?;
        let image = rep
            .CGImage()
            .ok_or_else(|| read_error("image has no bitmap data"))?;
        // The CGImage size is what gray_pixels allocates for; check it too.
        check_dimensions(CGImage::width(Some(&image)), CGImage::height(Some(&image)))?;
        let (w, h, gray) =
            gray_pixels(&image).ok_or_else(|| read_error("could not convert to grayscale"))?;
        let mut out = Vec::new();
        super::decode_into(w, h, &gray, &mut out);
        Ok(out)
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
        fn check_dimensions_bounds() {
            let max = super::MAX_IMAGE_PIXELS;
            assert!(super::check_dimensions(max, 1).is_ok());
            assert!(super::check_dimensions(1, 1).is_ok());
            for (w, h) in [(0, 10), (10, 0), (max + 1, 1), (usize::MAX, 2)] {
                assert!(
                    matches!(super::check_dimensions(w, h), Err(MacError::Other(_))),
                    "{w}x{h}"
                );
            }
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

    pub fn scan_file(_path: &std::path::Path) -> Result<Vec<SecretString>, MacError> {
        Err(MacError::NotAvailable)
    }
}
