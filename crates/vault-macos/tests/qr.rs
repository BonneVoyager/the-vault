//! QR decoding (spec 05 §2.3 "Scan QR from screen").
//!
//! The live screen test needs Screen Recording permission for the terminal
//! that runs it, so it is ignored by default. To run it, grant the terminal
//! app Screen Recording in System Settings > Privacy & Security, restart the
//! terminal, put an otpauth QR code on screen, and run:
//!
//!     cargo test -p vault-macos --test qr -- --ignored --nocapture
//!
//! It prints only the payload count and whether each starts with `otpauth://`.

use qrcode::{Color, QrCode};
use secrecy::ExposeSecret;
use vault_macos::{decode_qr_from_gray, scan_qr_from_screen, screen_capture_permitted};

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

#[test]
fn permission_check_does_not_panic() {
    let _ = screen_capture_permitted();
}

#[test]
#[ignore = "needs Screen Recording permission and a QR code on screen"]
fn scan_live_screen() {
    match scan_qr_from_screen() {
        Ok(found) => {
            println!("found {} payload(s)", found.len());
            for p in &found {
                println!("otpauth: {}", p.expose_secret().starts_with("otpauth://"));
            }
        }
        Err(e) => println!(
            "scan error: {e} (permitted = {})",
            screen_capture_permitted()
        ),
    }
}
