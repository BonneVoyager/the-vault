//! QR decoding for TOTP fields: "Scan QR from image" (spec 05 §2.3 Edit mode).
//!
//! The user picks a screenshot or exported QR image; no Screen Recording
//! permission is needed. (A whole-screen scan was removed from the spec on
//! 2026-10-29 and from this crate by security review 2026-11-26, I-10.) Only
//! PNG and JPEG are accepted, checked by their leading magic bytes before any
//! system decoder sees the file (security review 2026-11-26, L-08): ImageIO
//! sniffs some 60 formats by content, and this process holds the decrypted
//! vault. Accepted files are decoded by AppKit's `NSBitmapImageRep` (ImageIO)
//! and the first frame is drawn into an 8-bit `DeviceGray` bitmap context, so
//! CoreGraphics does the luma conversion and no image crate is needed. QR
//! codes are then decoded with `rqrr`.
//!
//! Decoded payloads may hold TOTP secrets, so they are returned as
//! `SecretString`. Payloads are never logged or `Debug`-printed. Our file and
//! gray buffers are wrapped in `Zeroizing`.
//!
//! Accepted limitation, pending an owner decision on the `rqrr-zeroize` fork:
//! these copies of image or payload data are NOT wiped on drop:
//! - the `NSData` copy of the file bytes and the decoded bitmap held by
//!   `NSBitmapImageRep` / its `CGImage` (our own read buffer is wrapped in
//!   `Zeroizing`);
//! - `rqrr`'s internal pixel buffer inside `PreparedImage`;
//! - `rqrr`'s internal decode state (`RawData`, `CorrectedDataStream`) and the
//!   partially filled payload `Vec` when decoding fails part way.

use std::path::Path;

use secrecy::{ExposeSecret, SecretString};

use crate::MacError;

/// Largest image accepted by [`scan_qr_from_image_file`], in pixels.
pub const MAX_IMAGE_PIXELS: usize = 50_000_000;

/// Largest image file accepted by [`scan_qr_from_image_file`], in bytes.
pub const MAX_IMAGE_FILE_BYTES: u64 = 100 * 1024 * 1024;

/// Decode every QR code in a PNG or JPEG image file.
///
/// Needs no Screen Recording permission. Payloads are deduplicated and ordered
/// like [`decode_qr_from_gray`]; an image with no QR code gives `Ok(vec![])`.
///
/// The file must start with the PNG signature or the JPEG SOI marker; any
/// other content (GIF, PDF, HEIC, TIFF, text, an empty file...) also gives
/// `Ok(vec![])` without reaching ImageIO.
///
/// Errors with `MacError::Other("could not read image: ...")` when the file
/// cannot be read, is not a regular file, is larger than
/// [`MAX_IMAGE_FILE_BYTES`], has the PNG or JPEG magic but does not decode, or
/// has more than [`MAX_IMAGE_PIXELS`] pixels. Off macOS this always returns
/// `MacError::NotAvailable`.
pub fn scan_qr_from_image_file(path: &Path) -> Result<Vec<SecretString>, MacError> {
    imp::scan_file(path)
}

/// Image formats [`scan_qr_from_image_file`] passes to the system decoder.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImageKind {
    Png,
    Jpeg,
}

/// PNG file signature (PNG spec §5.2).
const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
/// JPEG start-of-image marker followed by the first byte of the next marker.
const JPEG_MAGIC: [u8; 3] = [0xFF, 0xD8, 0xFF];

/// The format named by the leading magic bytes, or `None` for anything else.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn image_kind(bytes: &[u8]) -> Option<ImageKind> {
    if bytes.starts_with(&PNG_MAGIC) {
        Some(ImageKind::Png)
    } else if bytes.starts_with(&JPEG_MAGIC) {
        Some(ImageKind::Jpeg)
    } else {
        None
    }
}

/// How many times [`scan_qr_from_image_file`] has handed file bytes to ImageIO
/// on the calling thread. Tests use it to show refused files never reach the
/// system decoder. Always 0 off macOS. Only with the `test-support` feature.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn test_image_decoder_calls() -> u64 {
    imp::decoder_calls()
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

/// Runs a decode and maps a panic inside it to "no code found" (an empty list).
///
/// `rqrr` 0.11.0 has release-mode assertions (e.g. `geometry.rs:55`, `x <= i32::MAX as
/// f64`) that fire on some malformed images. The scans run on background executors that do
/// not catch unwinds, so an uncaught panic would abort the app (security review 2026-11-26,
/// L-07). The process panic hook still prints the panic message and location to stderr; the
/// messages in `rqrr` are static text or indices, never pixel data or payloads, so nothing
/// secret reaches the log. Payloads decoded before the panic are `SecretString`s and are
/// zeroized as the unwind drops them.
fn no_code_on_panic<T>(decode: impl FnOnce() -> Vec<T>) -> Vec<T> {
    // AssertUnwindSafe: the closure only reads borrowed pixels and builds a fresh Vec, so
    // no state shared with the caller can be left half-updated.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(decode)).unwrap_or_default()
}

/// Decode `pixels` and append payloads not already in `out`.
fn decode_into(width: usize, height: usize, pixels: &[u8], out: &mut Vec<SecretString>) {
    if width == 0 || height == 0 || width.checked_mul(height) != Some(pixels.len()) {
        return;
    }
    let mut found: Vec<((i32, i32), SecretString)> = no_code_on_panic(|| {
        let mut img = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
            pixels[y * width + x]
        });
        img.detect_grids()
            .into_iter()
            .filter_map(|grid| {
                let top_left = grid.bounds[0];
                let (_, content) = grid.decode().ok()?;
                Some(((top_left.y, top_left.x), SecretString::new(content)))
            })
            .collect()
    });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panicking_decode_is_no_code() {
        let found: Vec<SecretString> = no_code_on_panic(|| panic!("decoder assertion"));
        assert!(found.is_empty());
    }

    #[test]
    fn image_kind_matches_only_png_and_jpeg_magic() {
        assert_eq!(image_kind(&PNG_MAGIC), Some(ImageKind::Png));
        assert_eq!(
            image_kind(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR"),
            Some(ImageKind::Png)
        );
        assert_eq!(image_kind(&[0xFF, 0xD8, 0xFF, 0xE0]), Some(ImageKind::Jpeg));
        assert_eq!(image_kind(&JPEG_MAGIC), Some(ImageKind::Jpeg));
        for refused in [
            &b""[..],
            b"\x89PNG\r\n\x1a",     // PNG signature cut short
            b"\x89PNG\r\n\x1a\x0b", // last byte wrong
            &[0xFF, 0xD8],          // SOI without a following marker
            &[0xFF, 0xD8, 0x00],
            b"GIF89a",
            b"%PDF-1.7",
            b"II*\0",              // TIFF
            b"\0\0\0\x18ftypheic", // HEIC
            b"BM",
            b" \x89PNG\r\n\x1a\n", // signature not at offset 0
        ] {
            assert_eq!(image_kind(refused), None, "{refused:?}");
        }
    }

    #[test]
    fn non_panicking_decode_passes_through() {
        let found = no_code_on_panic(|| vec![1, 2]);
        assert_eq!(found, vec![1, 2]);
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::c_void;
    use std::io::Read;
    use std::path::Path;

    use objc2::AnyThread;
    use objc2_app_kit::{NSBitmapImageRep, NSImageRep};
    use objc2_core_foundation::{CGPoint, CGRect, CGSize};
    use objc2_core_graphics::{
        CGBitmapContextCreate, CGColorSpace, CGContext, CGImage, CGImageAlphaInfo,
    };
    use objc2_foundation::NSData;
    use secrecy::SecretString;
    use zeroize::Zeroizing;

    use super::{MAX_IMAGE_FILE_BYTES, MAX_IMAGE_PIXELS};
    use crate::MacError;

    #[cfg(feature = "test-support")]
    thread_local! {
        /// Calls into ImageIO from `scan_file` on this thread (see `decoder_calls`).
        static DECODER_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    #[cfg(feature = "test-support")]
    pub fn decoder_calls() -> u64 {
        DECODER_CALLS.with(std::cell::Cell::get)
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
        // L-08: only PNG and JPEG reach ImageIO; anything else is "no code
        // found". `NSBitmapImageRep` takes no type hint, so ImageIO still picks
        // the format itself, but the bytes it sees start with a PNG or JPEG
        // signature, which no other ImageIO format shares.
        if super::image_kind(&bytes).is_none() {
            return Ok(Vec::new());
        }
        let data = NSData::with_bytes(&bytes);
        drop(bytes);
        #[cfg(feature = "test-support")]
        DECODER_CALLS.with(|c| c.set(c.get() + 1));
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

    pub fn scan_file(_path: &std::path::Path) -> Result<Vec<SecretString>, MacError> {
        Err(MacError::NotAvailable)
    }

    #[cfg(feature = "test-support")]
    pub fn decoder_calls() -> u64 {
        0
    }
}
