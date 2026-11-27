//! QR decoding (spec 05 §2.3 "Scan QR from image"): the gray decoder and
//! `scan_qr_from_image_file`. Needs no permissions.

use qrcode::{Color, QrCode};
use secrecy::ExposeSecret;
use vault_macos::decode_qr_from_gray;

const URI: &str = "otpauth://totp/Test:a?secret=JBSWY3DPEHPK3PXP&issuer=Test";
const URI2: &str = "otpauth://totp/Other:b?secret=GEZDGNBVGY3TQOJQ&issuer=Other";

/// Pixels per module and quiet-zone width in modules.
const SCALE: usize = 4;
const QUIET: usize = 4;

/// White canvas of `w` x `h` gray pixels.
fn canvas(w: usize, h: usize) -> Vec<u8> {
    vec![255; w * h]
}

/// Side length in pixels of `data` rendered with its quiet zone.
fn rendered_side(data: &str) -> usize {
    (QrCode::new(data).unwrap().width() + 2 * QUIET) * SCALE
}

/// Draw `data` as a QR code with its quiet zone at pixel (`ox`, `oy`).
fn draw(buf: &mut [u8], stride: usize, ox: usize, oy: usize, data: &str) {
    let code = QrCode::new(data).unwrap();
    let n = code.width();
    let colors = code.to_colors();
    for my in 0..n {
        for mx in 0..n {
            if colors[my * n + mx] != Color::Dark {
                continue;
            }
            for dy in 0..SCALE {
                for dx in 0..SCALE {
                    let x = ox + (QUIET + mx) * SCALE + dx;
                    let y = oy + (QUIET + my) * SCALE + dy;
                    buf[y * stride + x] = 0;
                }
            }
        }
    }
}

fn exposed(v: &[secrecy::SecretString]) -> Vec<&str> {
    v.iter().map(|s| s.expose_secret().as_str()).collect()
}

#[test]
fn decodes_single_otpauth_code() {
    let side = rendered_side(URI);
    let mut buf = canvas(side, side);
    draw(&mut buf, side, 0, 0, URI);
    let got = decode_qr_from_gray(side, side, &buf);
    assert_eq!(exposed(&got), vec![URI]);
}

#[test]
fn all_white_returns_empty() {
    let buf = canvas(320, 200);
    assert!(decode_qr_from_gray(320, 200, &buf).is_empty());
}

#[test]
fn two_codes_returned_in_screen_order() {
    let (s1, s2) = (rendered_side(URI), rendered_side(URI2));
    let w = s1 + s2 + 40;
    let h = s1.max(s2) + 20;
    let mut buf = canvas(w, h);
    // URI2 on the left, URI on the right, both on the same row band.
    draw(&mut buf, w, 0, 10, URI2);
    draw(&mut buf, w, s2 + 40, 10, URI);
    let got = decode_qr_from_gray(w, h, &buf);
    assert_eq!(exposed(&got), vec![URI2, URI]);

    // Stacked vertically: the upper one comes first.
    let w = s1.max(s2);
    let h = s1 + s2 + 40;
    let mut buf = canvas(w, h);
    draw(&mut buf, w, 0, 0, URI);
    draw(&mut buf, w, 0, s1 + 40, URI2);
    let got = decode_qr_from_gray(w, h, &buf);
    assert_eq!(exposed(&got), vec![URI, URI2]);
}

#[test]
fn duplicate_codes_are_deduplicated() {
    let s = rendered_side(URI);
    let w = 2 * s + 40;
    let mut buf = canvas(w, s);
    draw(&mut buf, w, 0, 0, URI);
    draw(&mut buf, w, s + 40, 0, URI);
    let got = decode_qr_from_gray(w, s, &buf);
    assert_eq!(exposed(&got), vec![URI]);
}

#[test]
fn wrong_buffer_length_returns_empty() {
    let side = rendered_side(URI);
    let mut buf = canvas(side, side);
    draw(&mut buf, side, 0, 0, URI);
    buf.pop();
    assert!(decode_qr_from_gray(side, side, &buf).is_empty());
}

/// xorshift64, so the malformed image below is the same on every run.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// A QR render with scattered pixel flips and one inverted block, from `seed`. Found by a
/// seeded search; with the pinned `qrcode` 0.14.1 and `rqrr` 0.11.0, seed 1358 trips
/// `rqrr`'s `assertion failed: x <= i32::MAX as f64` (geometry.rs:55).
fn mutated_render(seed: u64) -> (usize, Vec<u8>) {
    const DATA: [&str; 3] = [URI, "x", "https://example.com/abc"];
    let mut rng = XorShift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let data = DATA[(rng.next() % 3) as usize];
    let scale = 1 + (rng.next() % 4) as usize;
    let quiet = (rng.next() % 5) as usize;
    let code = QrCode::new(data).unwrap();
    let n = code.width();
    let colors = code.to_colors();
    let side = (n + 2 * quiet) * scale;
    let mut px = canvas(side, side);
    for my in 0..n {
        for mx in 0..n {
            if colors[my * n + mx] != Color::Dark {
                continue;
            }
            for dy in 0..scale {
                for dx in 0..scale {
                    px[((quiet + my) * scale + dy) * side + (quiet + mx) * scale + dx] = 0;
                }
            }
        }
    }
    let flips = 1 + (rng.next() % 60) as usize;
    for _ in 0..flips {
        let i = (rng.next() as usize) % px.len();
        px[i] = 255 - px[i];
    }
    let block = 1 + (rng.next() % 8) as usize;
    let x0 = (rng.next() as usize) % side;
    let y0 = (rng.next() as usize) % side;
    for y in y0..(y0 + block).min(side) {
        for x in x0..(x0 + block).min(side) {
            px[y * side + x] = 255 - px[y * side + x];
        }
    }
    (side, px)
}

#[test]
fn decoder_panic_is_no_code() {
    let (side, px) = mutated_render(1358);
    // The raw rqrr sequence panics on this image; if a future rqrr fixes that, this
    // fixture no longer exercises the guard and needs a new seed.
    let raw = std::panic::catch_unwind(|| {
        let mut img =
            rqrr::PreparedImage::prepare_from_greyscale(side, side, |x, y| px[y * side + x]);
        for grid in img.detect_grids() {
            let _ = grid.decode();
        }
    });
    assert!(raw.is_err(), "fixture no longer trips rqrr");
    assert!(decode_qr_from_gray(side, side, &px).is_empty());
}

/// `scan_qr_from_image_file`: fixtures are rendered and encoded at test time,
/// so these need no permissions and no checked-in images.
#[cfg(target_os = "macos")]
mod image_file {
    use std::ffi::c_void;
    use std::path::{Path, PathBuf};

    use objc2::AnyThread;
    use objc2::runtime::AnyObject;
    use objc2_app_kit::{NSBitmapImageFileType, NSBitmapImageRep};
    use objc2_core_graphics::{
        CGBitmapContextCreate, CGBitmapContextCreateImage, CGColorSpace, CGImageAlphaInfo,
    };
    use objc2_foundation::{NSData, NSDictionary, NSString};
    use vault_macos::{MacError, scan_qr_from_image_file, test_image_decoder_calls};

    use super::{URI, URI2, canvas, draw, exposed, rendered_side};

    /// Encode a top-row-first gray buffer as an image file of `kind`.
    fn encode(w: usize, h: usize, mut gray: Vec<u8>, kind: NSBitmapImageFileType) -> Vec<u8> {
        assert_eq!(gray.len(), w * h);
        let space = CGColorSpace::new_device_gray().unwrap();
        // SAFETY: `gray` holds w*h bytes, matching 8 bpc, one component, `w`
        // bytes per row, no alpha, and outlives `ctx`, which is dropped below.
        let ctx = unsafe {
            CGBitmapContextCreate(
                gray.as_mut_ptr().cast::<c_void>(),
                w,
                h,
                8,
                w,
                Some(&space),
                CGImageAlphaInfo::None.0,
            )
        }
        .unwrap();
        let image = CGBitmapContextCreateImage(Some(&ctx)).unwrap();
        drop(ctx);
        let rep = NSBitmapImageRep::initWithCGImage(NSBitmapImageRep::alloc(), &image);
        let props = NSDictionary::<NSString, AnyObject>::new();
        // SAFETY: an empty dictionary trivially has the documented
        // NSBitmapImageRepPropertyKey -> value types.
        let data = unsafe { rep.representationUsingType_properties(kind, &props) }.unwrap();
        data.to_vec()
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn qr_canvas(data: &str) -> (usize, Vec<u8>) {
        let side = rendered_side(data);
        let mut buf = canvas(side, side);
        draw(&mut buf, side, 0, 0, data);
        (side, buf)
    }

    fn assert_read_error(result: Result<Vec<secrecy::SecretString>, MacError>, needle: &str) {
        match result {
            Err(MacError::Other(msg)) => {
                assert!(msg.starts_with("could not read image: "), "{msg}");
                assert!(msg.contains(needle), "{msg}");
            }
            Err(e) => panic!("expected Other, got {e}"),
            Ok(v) => panic!("expected an error, got {} payload(s)", v.len()),
        }
    }

    #[test]
    fn png_file_with_otpauth_code_decodes() {
        let dir = tempfile::tempdir().unwrap();
        let (side, buf) = qr_canvas(URI);
        let path = write(
            dir.path(),
            "code.png",
            &encode(side, side, buf, NSBitmapImageFileType::PNG),
        );
        let (got, calls) = scan_counted(&path);
        assert_eq!(calls, 1);
        assert_eq!(exposed(&got.unwrap()), vec![URI]);
    }

    #[test]
    fn jpeg_file_with_two_codes_decodes_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let (s1, s2) = (rendered_side(URI), rendered_side(URI2));
        let w = s1.max(s2);
        let h = s1 + s2 + 40;
        let mut buf = canvas(w, h);
        draw(&mut buf, w, 0, 0, URI2);
        draw(&mut buf, w, 0, s2 + 40, URI);
        let path = write(
            dir.path(),
            "codes.jpg",
            &encode(w, h, buf, NSBitmapImageFileType::JPEG),
        );
        let got = scan_qr_from_image_file(&path).unwrap();
        assert_eq!(exposed(&got), vec![URI2, URI]);
    }

    #[test]
    fn image_without_qr_is_ok_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "white.png",
            &encode(64, 48, canvas(64, 48), NSBitmapImageFileType::PNG),
        );
        assert!(scan_qr_from_image_file(&path).unwrap().is_empty());
    }

    /// Scan `path` and return the result with the number of ImageIO calls it made.
    fn scan_counted(path: &Path) -> (Result<Vec<secrecy::SecretString>, MacError>, u64) {
        let before = test_image_decoder_calls();
        let result = scan_qr_from_image_file(path);
        (result, test_image_decoder_calls() - before)
    }

    /// L-08: anything without the PNG or JPEG magic is "no code found" and never
    /// reaches ImageIO, even when the content is a format ImageIO would decode.
    #[test]
    fn non_png_jpeg_files_are_refused_before_decoding() {
        let dir = tempfile::tempdir().unwrap();
        let (side, buf) = qr_canvas(URI);
        // Real images ImageIO reads, each holding the QR code.
        let gif = encode(side, side, buf.clone(), NSBitmapImageFileType::GIF);
        let tiff = encode(side, side, buf.clone(), NSBitmapImageFileType::TIFF);
        let bmp = encode(side, side, buf, NSBitmapImageFileType::BMP);
        assert!(gif.starts_with(b"GIF8"));
        let mut random = vec![0u8; 4096];
        let mut rng = super::XorShift(0x5EED_1234);
        for b in &mut random {
            *b = rng.next() as u8;
        }
        random[0] = 0x00; // never a PNG or JPEG first byte
        let cases: [(&str, &[u8]); 7] = [
            ("code.gif", &gif),
            ("code.tiff", &tiff),
            ("code.bmp", &bmp),
            (
                "doc.pdf",
                b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n1 0 obj\n<< /Type /Catalog >>\nendobj\n",
            ),
            ("random.png", &random),
            ("empty.png", b""),
            ("notes.png", b"this is not an image\n"),
        ];
        for (name, bytes) in cases {
            let path = write(dir.path(), name, bytes);
            let (result, calls) = scan_counted(&path);
            assert_eq!(calls, 0, "{name} reached ImageIO");
            match result {
                Ok(found) => assert!(found.is_empty(), "{name} decoded a code"),
                Err(e) => panic!("{name}: expected no code found, got {e}"),
            }
        }
    }

    /// A file with the PNG or JPEG magic goes to ImageIO; if it then fails to decode,
    /// that is still a read error.
    #[test]
    fn magic_without_valid_image_is_other_error() {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in [
            ("bad.png", &b"\x89PNG\r\n\x1a\nnot really a png"[..]),
            ("bad.jpg", &b"\xFF\xD8\xFF\xE0not really a jpeg"[..]),
        ] {
            let path = write(dir.path(), name, bytes);
            let (result, calls) = scan_counted(&path);
            assert_eq!(calls, 1, "{name}");
            assert_read_error(result, "not a supported image format");
        }
    }

    /// A single-code JPEG made from the PNG fixture through ImageIO decodes.
    #[test]
    fn jpeg_from_png_fixture_decodes() {
        let dir = tempfile::tempdir().unwrap();
        let (side, buf) = qr_canvas(URI);
        let png = encode(side, side, buf, NSBitmapImageFileType::PNG);
        let rep = NSBitmapImageRep::imageRepWithData(&NSData::with_bytes(&png)).unwrap();
        let props = NSDictionary::<NSString, AnyObject>::new();
        // SAFETY: an empty dictionary trivially has the documented
        // NSBitmapImageRepPropertyKey -> value types.
        let jpeg =
            unsafe { rep.representationUsingType_properties(NSBitmapImageFileType::JPEG, &props) }
                .unwrap()
                .to_vec();
        assert!(jpeg.starts_with(&[0xFF, 0xD8, 0xFF]));
        let path = write(dir.path(), "code.jpg", &jpeg);
        let (result, calls) = scan_counted(&path);
        assert_eq!(calls, 1);
        assert_eq!(exposed(&result.unwrap()), vec![URI]);
    }

    #[test]
    fn missing_file_is_other_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_read_error(
            scan_qr_from_image_file(&dir.path().join("nope.png")),
            "No such file or directory",
        );
    }

    #[test]
    fn directory_is_other_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_read_error(scan_qr_from_image_file(dir.path()), "not a regular file");
    }

    /// A FIFO with no writer must fail at once, not block the caller forever.
    /// The scan runs on a helper thread so a regression fails the test after
    /// a timeout instead of hanging the test run.
    #[test]
    fn fifo_is_other_error_promptly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pipe.png");
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `c_path` is a valid NUL-terminated path that lives across the call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let (tx, rx) = std::sync::mpsc::channel();
        let scan_path = path.clone();
        std::thread::spawn(move || {
            let _ = tx.send(scan_qr_from_image_file(&scan_path));
        });
        let result = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("scan of a FIFO blocked");
        assert_read_error(result, "not a regular file");
    }

    #[test]
    fn character_device_is_other_error() {
        assert_read_error(
            scan_qr_from_image_file(Path::new("/dev/zero")),
            "not a regular file",
        );
    }

    /// One pixel over the cap is refused before the image is drawn. (ImageIO
    /// rejects hand-built PNGs with truncated pixel data at load time, so a
    /// real, highly compressible image is encoded here instead.)
    #[test]
    fn oversized_image_is_refused() {
        let (w, h) = (10_000usize, vault_macos::MAX_IMAGE_PIXELS / 10_000 + 1);
        let png = encode(w, h, canvas(w, h), NSBitmapImageFileType::PNG);
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "huge.png", &png);
        assert_read_error(scan_qr_from_image_file(&path), "too large");
    }
}
