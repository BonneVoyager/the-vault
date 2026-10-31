//! Custom image icons (specs/05-ui.md §2.3 "Item icon picker"): turning a chosen PNG or
//! JPEG into the 128 px PNG stored as the item's hidden icon attachment. No gpui here.
//!
//! The input is refused when it is over [`MAX_INPUT_BYTES`], when it is not a PNG or JPEG
//! this build can decode, or when the header says a side is over [`MAX_SIDE`] px. The
//! header is read first (`image::ImageReader::into_dimensions`), so an oversized image is
//! refused without decoding any pixels. The pixel decode then runs with width, height and
//! allocation limits.
//!
//! Compressed PNG metadata is never inflated: [`strip_png_metadata`] drops the iCCP,
//! tEXt, zTXt, iTXt and eXIf chunks (the app uses none of them) before any decoder sees
//! the bytes, so a deflate bomb in an ICC profile costs nothing. The header read also
//! keeps a [`HEADER_ALLOC`] budget as a second guard: png 0.18 inflates iCCP with
//! `decompress_to_vec_bounded(.., budget)` (and drops the profile when it would exceed it).
//!
//! Stored icon blobs (written by this app as 128 px PNGs, but a vault may come from
//! anywhere) go through the same decoder with tighter limits: at most
//! [`STORED_MAX_BYTES`] and [`STORED_MAX_SIDE`] px per side ([`decode_stored`]).
//!
//! The picture is scaled to fit a [`TILE_PX`] square keeping its aspect ratio (small
//! images are scaled up too, so a 16 px favicon fills the tile like a large logo does),
//! centred on a transparent canvas and encoded as PNG. The original is not kept.

use std::io::Cursor;

use image::{DynamicImage, ImageFormat, ImageReader, Limits, RgbaImage, imageops};

/// Largest file accepted by "Drop or choose image…" (panel or drop).
pub const MAX_INPUT_BYTES: u64 = 512 * 1024;
/// Largest width or height accepted, read from the header before decoding.
pub const MAX_SIDE: u32 = 8192;
/// Side of the stored square PNG.
pub const TILE_PX: u32 = 128;
/// Name of the stored attachment (never shown: icon attachments are hidden).
pub const ATTACHMENT_NAME: &str = "icon.png";
/// Allocation budget for reading a header (chunk metadata such as an ICC profile). The
/// png decoder bounds iCCP inflation by it; `no_limits` would leave that unbounded.
pub const HEADER_ALLOC: u64 = 4 * 1024 * 1024;
/// Largest stored icon blob decoded, and its largest side (the app writes 128 px).
pub const STORED_MAX_BYTES: u64 = 256 * 1024;
pub const STORED_MAX_SIDE: u32 = 256;

/// Why an image was not used. `message` is the toast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The file is over [`MAX_INPUT_BYTES`].
    TooLarge,
    /// Not a PNG or JPEG, or it does not decode.
    Unreadable,
    /// A side is over [`MAX_SIDE`] px.
    TooManyPixels,
}

impl Refusal {
    pub fn message(self) -> &'static str {
        match self {
            Self::TooLarge => "Image is larger than 512 KB",
            Self::Unreadable => "Could not read this image. Choose a PNG or JPEG file.",
            Self::TooManyPixels => "Image is larger than 8192 × 8192 pixels",
        }
    }
}

/// Where the scaled picture sits on the canvas: its size and top-left offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fit {
    pub w: u32,
    pub h: u32,
    pub x: u32,
    pub y: u32,
}

/// Scales `w × h` to fit a `side` square keeping the aspect ratio, centred. The longer
/// side becomes `side`; the shorter one is rounded and at least 1 px. Odd leftovers put
/// the extra pixel after the picture (right or bottom).
pub fn fit(w: u32, h: u32, side: u32) -> Fit {
    let (w, h) = (w.max(1), h.max(1));
    let (fw, fh) = if w >= h {
        let fh = (u64::from(h) * u64::from(side) + u64::from(w) / 2) / u64::from(w);
        (side, u32::try_from(fh).unwrap_or(side).clamp(1, side))
    } else {
        let fw = (u64::from(w) * u64::from(side) + u64::from(h) / 2) / u64::from(h);
        (u32::try_from(fw).unwrap_or(side).clamp(1, side), side)
    };
    Fit {
        w: fw,
        h: fh,
        x: (side - fw) / 2,
        y: (side - fh) / 2,
    }
}

/// PNG or JPEG by magic bytes; anything else is `None`.
pub fn sniff(bytes: &[u8]) -> Option<ImageFormat> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(ImageFormat::Png)
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some(ImageFormat::Jpeg)
    } else {
        None
    }
}

/// PNG chunks dropped before decoding: compressed or free-form metadata.
const DROPPED_CHUNKS: [&[u8; 4]; 5] = [b"iCCP", b"tEXt", b"zTXt", b"iTXt", b"eXIf"];

/// `bytes` without the [`DROPPED_CHUNKS`] when it is a PNG (other chunks are copied
/// verbatim, CRCs included); JPEG and anything else unchanged. A PNG whose chunk lengths
/// run past the end is refused.
pub fn strip_png_metadata(bytes: &[u8]) -> Result<std::borrow::Cow<'_, [u8]>, Refusal> {
    const SIG: usize = 8;
    if sniff(bytes) != Some(ImageFormat::Png) {
        return Ok(std::borrow::Cow::Borrowed(bytes));
    }
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..SIG]);
    let mut i = SIG;
    while i < bytes.len() {
        let header = bytes.get(i..i + 8).ok_or(Refusal::Unreadable)?;
        let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let end = i
            .checked_add(12)
            .and_then(|n| n.checked_add(len))
            .filter(|end| *end <= bytes.len())
            .ok_or(Refusal::Unreadable)?;
        let kind = &header[4..8];
        if !DROPPED_CHUNKS.iter().any(|d| &d[..] == kind) {
            out.extend_from_slice(&bytes[i..end]);
        }
        i = end;
        if kind == b"IEND" {
            break;
        }
    }
    Ok(std::borrow::Cow::Owned(out))
}

/// Limits for decoding pixels of at most `max_side` per side: one RGBA frame of that
/// size plus the header budget.
fn pixel_limits(max_side: u32) -> Limits {
    let side = u64::from(max_side);
    let mut l = Limits::default();
    l.max_image_width = Some(max_side);
    l.max_image_height = Some(max_side);
    l.max_alloc = Some(side * side * 4 + HEADER_ALLOC);
    l
}

/// Width and height from the header only, read under [`HEADER_ALLOC`]; refuses a side
/// over `max_side`.
fn header_dims(bytes: &[u8], max_side: u32) -> Result<(u32, u32), Refusal> {
    let bytes = &*strip_png_metadata(bytes)?;
    let format = sniff(bytes).ok_or(Refusal::Unreadable)?;
    // No width/height limit here, so an oversized header reports its size (and gets its
    // own message) instead of a limit error; the allocation budget stays.
    let mut limits = Limits::default();
    limits.max_alloc = Some(HEADER_ALLOC);
    let mut r = ImageReader::with_format(Cursor::new(bytes), format);
    r.limits(limits);
    let (w, h) = r.into_dimensions().map_err(|_| Refusal::Unreadable)?;
    if w > max_side || h > max_side {
        return Err(Refusal::TooManyPixels);
    }
    if w == 0 || h == 0 {
        return Err(Refusal::Unreadable);
    }
    Ok((w, h))
}

/// Width and height from the header; refuses a side over [`MAX_SIDE`].
#[cfg(test)]
pub fn header_dimensions(bytes: &[u8]) -> Result<(u32, u32), Refusal> {
    header_dims(bytes, MAX_SIDE)
}

/// Header check, then a pixel decode limited to `max_side` per side.
fn decode_limited(bytes: &[u8], max_side: u32) -> Result<(DynamicImage, u32, u32), Refusal> {
    let bytes = &*strip_png_metadata(bytes)?;
    let format = sniff(bytes).ok_or(Refusal::Unreadable)?;
    let (w, h) = header_dims(bytes, max_side)?;
    let mut r = ImageReader::with_format(Cursor::new(bytes), format);
    r.limits(pixel_limits(max_side));
    let decoded = r.decode().map_err(|_| Refusal::Unreadable)?;
    Ok((decoded, w, h))
}

/// The stored icon for the chosen file's bytes: a [`TILE_PX`] square PNG.
pub fn prepare(bytes: &[u8]) -> Result<Vec<u8>, Refusal> {
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(Refusal::TooLarge);
    }
    let (decoded, w, h) = decode_limited(bytes, MAX_SIDE)?;
    encode(&compose(&decoded, w, h))
}

/// A stored icon blob's pixels (RGBA), or a refusal when it is over [`STORED_MAX_BYTES`],
/// over [`STORED_MAX_SIDE`] px per side, or does not decode.
pub fn decode_stored(bytes: &[u8]) -> Result<RgbaImage, Refusal> {
    if bytes.len() as u64 > STORED_MAX_BYTES {
        return Err(Refusal::TooLarge);
    }
    let (decoded, ..) = decode_limited(bytes, STORED_MAX_SIDE)?;
    Ok(decoded.into_rgba8())
}

/// The picture scaled into a transparent [`TILE_PX`] canvas.
fn compose(img: &DynamicImage, w: u32, h: u32) -> RgbaImage {
    let f = fit(w, h, TILE_PX);
    let scaled = if f.w <= w && f.h <= h {
        // Downscale: area averaging, every source pixel counts once.
        img.thumbnail_exact(f.w, f.h)
    } else {
        img.resize_exact(f.w, f.h, imageops::FilterType::CatmullRom)
    };
    let mut canvas = RgbaImage::new(TILE_PX, TILE_PX);
    imageops::overlay(
        &mut canvas,
        &scaled.to_rgba8(),
        i64::from(f.x),
        i64::from(f.y),
    );
    canvas
}

fn encode(canvas: &RgbaImage) -> Result<Vec<u8>, Refusal> {
    let mut out = Cursor::new(Vec::new());
    canvas
        .write_to(&mut out, ImageFormat::Png)
        .map_err(|_| Refusal::Unreadable)?;
    Ok(out.into_inner())
}

#[cfg(test)]
pub(crate) mod test_images {
    //! Images built in memory for tests.
    use super::*;

    /// A `w × h` PNG filled with `rgba`.
    pub fn png(w: u32, h: u32, rgba: [u8; 4]) -> Vec<u8> {
        encode(&RgbaImage::from_pixel(w, h, image::Rgba(rgba))).unwrap()
    }

    /// A `w × h` JPEG (opaque red).
    pub fn jpeg(w: u32, h: u32) -> Vec<u8> {
        let img = image::RgbImage::from_pixel(w, h, image::Rgb([200, 20, 20]));
        let mut out = Cursor::new(Vec::new());
        DynamicImage::ImageRgb8(img)
            .write_to(&mut out, ImageFormat::Jpeg)
            .unwrap();
        out.into_inner()
    }

    /// A PNG whose header claims `w × h` but has no pixel data: only the header can be
    /// read. Lets tests check the size refusal without building a huge image.
    pub fn png_header_only(w: u32, h: u32) -> Vec<u8> {
        png_with_chunks(w, h, &[])
    }

    /// A header-only PNG (see [`png_header_only`]) with `extra` chunks between IHDR and
    /// the empty IDAT.
    pub fn png_with_chunks(w: u32, h: u32, extra: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&w.to_be_bytes());
        ihdr.extend_from_slice(&h.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        let mut chunks: Vec<(&[u8], Vec<u8>)> = vec![(b"IHDR", ihdr)];
        chunks.extend(extra.iter().map(|(k, d)| (&k[..], d.clone())));
        chunks.push((b"IDAT", Vec::new()));
        chunks.push((b"IEND", Vec::new()));
        let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
        // The decoder reports the size once it reaches the first (here empty) IDAT.
        for (kind, data) in chunks {
            let mut chunk = kind.to_vec();
            chunk.extend_from_slice(&data);
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(&chunk);
            out.extend_from_slice(&crc32(&chunk).to_be_bytes());
        }
        out
    }

    /// A zlib stream that inflates to `n * 258 + 1` zero bytes: a literal 0, then `n`
    /// fixed-Huffman back-references of length 258 at distance 1 (13 bits each), so
    /// 8 MB of output costs about 50 KB. Built by hand: vault-app has no deflate encoder.
    pub fn zlib_zero_bomb(n: usize) -> Vec<u8> {
        struct Bits {
            out: Vec<u8>,
            acc: u32,
            len: u32,
        }
        impl Bits {
            /// `value`'s low `n` bits, least significant first (deflate header fields).
            fn put(&mut self, value: u32, n: u32) {
                for i in 0..n {
                    self.acc |= ((value >> i) & 1) << self.len;
                    self.len += 1;
                    if self.len == 8 {
                        self.out.push(self.acc as u8);
                        self.acc = 0;
                        self.len = 0;
                    }
                }
            }
            /// A Huffman code, most significant bit first.
            fn code(&mut self, code: u32, n: u32) {
                for i in (0..n).rev() {
                    self.put((code >> i) & 1, 1);
                }
            }
        }
        let mut b = Bits {
            out: vec![0x78, 0x01],
            acc: 0,
            len: 0,
        };
        b.put(1, 1); // BFINAL
        b.put(1, 2); // BTYPE = fixed Huffman
        b.code(0x30, 8); // literal 0
        for _ in 0..n {
            b.code(0xC5, 8); // length symbol 285 = 258
            b.code(0, 5); // distance code 0 = 1
        }
        b.code(0, 7); // end of block
        if b.len > 0 {
            b.out.push(b.acc as u8);
        }
        // Adler-32 of `n * 258 + 1` zeros: a = 1, b = length mod 65521.
        let total = (n as u64 * 258 + 1) % 65521;
        let adler = ((total as u32) << 16) | 1;
        b.out.extend_from_slice(&adler.to_be_bytes());
        b.out
    }

    /// A 16 × 16 PNG header whose iCCP profile inflates to about `bytes` bytes.
    pub fn png_iccp_bomb(bytes: usize) -> Vec<u8> {
        let mut iccp = b"bomb\0\0".to_vec(); // name, NUL, compression method 0
        iccp.extend(zlib_zero_bomb(bytes / 258));
        png_with_chunks(16, 16, &[(b"iCCP", iccp)])
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for b in data {
            crc ^= u32::from(*b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }
}

#[cfg(test)]
mod tests {
    use super::test_images::*;
    use super::*;

    fn decode(png: &[u8]) -> RgbaImage {
        image::load_from_memory_with_format(png, ImageFormat::Png)
            .unwrap()
            .to_rgba8()
    }

    #[test]
    fn fit_landscape_portrait_square_and_tiny() {
        // Landscape: full width, centred vertically.
        assert_eq!(
            fit(400, 200, 128),
            Fit {
                w: 128,
                h: 64,
                x: 0,
                y: 32
            }
        );
        // Portrait: full height, centred horizontally.
        assert_eq!(
            fit(300, 1000, 128),
            Fit {
                w: 38,
                h: 128,
                x: 45,
                y: 0
            }
        );
        // Square and exact.
        assert_eq!(
            fit(128, 128, 128),
            Fit {
                w: 128,
                h: 128,
                x: 0,
                y: 0
            }
        );
        // Tiny inputs scale up to fill the square.
        assert_eq!(
            fit(16, 16, 128),
            Fit {
                w: 128,
                h: 128,
                x: 0,
                y: 0
            }
        );
        assert_eq!(
            fit(3, 1, 128),
            Fit {
                w: 128,
                h: 43,
                x: 0,
                y: 42
            }
        );
        // A 1 px sliver stays at least 1 px; a zero side never divides by zero.
        assert_eq!(fit(8192, 1, 128).h, 1);
        assert_eq!(fit(1, 8192, 128).w, 1);
        assert_eq!(fit(0, 0, 128).w, 128);
        // Odd leftover goes after the picture.
        let f = fit(128, 127, 128);
        assert_eq!((f.h, f.y), (127, 0));
    }

    #[test]
    fn prepare_scales_into_a_transparent_square_png() {
        let out = prepare(&png(400, 200, [10, 200, 30, 255])).unwrap();
        assert!(out.starts_with(b"\x89PNG"));
        let img = decode(&out);
        assert_eq!(img.dimensions(), (TILE_PX, TILE_PX));
        // Bands above and below the picture are transparent; the middle is the colour.
        assert_eq!(img.get_pixel(64, 10).0[3], 0);
        assert_eq!(img.get_pixel(64, 120).0[3], 0);
        assert_eq!(img.get_pixel(64, 64).0, [10, 200, 30, 255]);

        // Portrait JPEG: transparent sides, opaque centre.
        let img = decode(&prepare(&jpeg(100, 400)).unwrap());
        assert_eq!(img.dimensions(), (TILE_PX, TILE_PX));
        assert_eq!(img.get_pixel(2, 64).0[3], 0);
        assert_eq!(img.get_pixel(64, 64).0[3], 255);

        // Tiny input fills the canvas.
        let img = decode(&prepare(&png(2, 2, [1, 2, 3, 255])).unwrap());
        assert_eq!(img.get_pixel(0, 0).0, [1, 2, 3, 255]);
        assert_eq!(img.get_pixel(127, 127).0, [1, 2, 3, 255]);
    }

    #[test]
    fn the_three_refusals() {
        // Over 512 KB, checked before anything is parsed.
        let mut big = png(4, 4, [0, 0, 0, 255]);
        big.resize(MAX_INPUT_BYTES as usize + 1, 0);
        assert_eq!(prepare(&big), Err(Refusal::TooLarge));
        // Not an image, a truncated PNG, a GIF.
        assert_eq!(prepare(b"hello world"), Err(Refusal::Unreadable));
        let png4 = png(4, 4, [0, 0, 0, 255]);
        assert_eq!(prepare(&png4[..png4.len() / 2]), Err(Refusal::Unreadable));
        assert_eq!(prepare(b"GIF89a\x01\x00\x01\x00"), Err(Refusal::Unreadable));
        // Header says too many pixels: refused from the header, no pixel data needed.
        assert_eq!(
            prepare(&png_header_only(8193, 10)),
            Err(Refusal::TooManyPixels)
        );
        assert_eq!(
            prepare(&png_header_only(10, 9000)),
            Err(Refusal::TooManyPixels)
        );
        assert_eq!(
            header_dimensions(&png_header_only(8192, 8192)),
            Ok((8192, 8192))
        );
        // Each refusal has its own message.
        let msgs = [
            Refusal::TooLarge.message(),
            Refusal::Unreadable.message(),
            Refusal::TooManyPixels.message(),
        ];
        assert!(msgs[0] != msgs[1] && msgs[1] != msgs[2] && msgs[0] != msgs[2]);
    }

    /// `png` with `chunk` inserted right after IHDR.
    fn insert_after_ihdr(png: &[u8], chunk_png: &[u8]) -> Vec<u8> {
        // The IHDR chunk is always 8 + 4 + 4 + 13 + 4 = 33 bytes from the start; the
        // donor's extra chunk sits between its own IHDR and its first IDAT.
        let extra_end = chunk_png.len() - 12 - 12; // donor's empty IDAT and IEND
        let mut out = png[..33].to_vec();
        out.extend_from_slice(&chunk_png[33..extra_end]);
        out.extend_from_slice(&png[33..]);
        out
    }

    /// The ICC profile the png decoder kept for `bytes` under `limits`.
    fn profile(bytes: &[u8], limits: Option<Limits>) -> Option<usize> {
        use image::ImageDecoder as _;
        let mut r = ImageReader::with_format(Cursor::new(bytes), ImageFormat::Png);
        match limits {
            Some(l) => r.limits(l),
            None => r.no_limits(),
        }
        let mut d = r.into_decoder().ok()?;
        d.icc_profile().ok().flatten().map(|p| p.len())
    }

    #[test]
    fn iccp_deflate_bomb_is_never_inflated() {
        // 64 MB of profile from ~400 KB of file, under the 512 KB input limit.
        let bomb = png_iccp_bomb(64 * 1024 * 1024);
        assert!((bomb.len() as u64) < MAX_INPUT_BYTES, "{}", bomb.len());
        // The old header read (`no_limits`) inflates all of it: a real bomb.
        assert!(profile(&bomb, None).is_some_and(|n| n > 60 * 1024 * 1024));

        // Now the chunk is stripped before any decoder sees the bytes: nothing to inflate.
        let stripped = strip_png_metadata(&bomb).unwrap();
        assert!(stripped.len() < 100, "iCCP gone: {} bytes", stripped.len());
        assert!(!stripped.windows(4).any(|w| w == b"iCCP"));
        assert_eq!(header_dimensions(&bomb), Ok((16, 16)));
        // The header-only fixture has no pixels.
        assert_eq!(prepare(&bomb), Err(Refusal::Unreadable));

        // Second guard: unstripped, the header budget stops inflation at HEADER_ALLOC
        // (`decompress_to_vec_bounded`) and png drops the profile.
        let mut budget = Limits::default();
        budget.max_alloc = Some(HEADER_ALLOC);
        assert_eq!(profile(&bomb, Some(budget)), None);
        let mut small = Limits::default();
        small.max_alloc = Some(HEADER_ALLOC);
        assert!(
            profile(&png_iccp_bomb(64 * 1024), Some(small)).is_some(),
            "control"
        );

        // A real picture carrying the bomb still works, without its profile.
        let real = insert_after_ihdr(&png(8, 8, [9, 8, 7, 255]), &bomb);
        assert!(profile(&real, None).is_some(), "fixture carries the bomb");
        assert!(prepare(&real).is_ok());

        // Truncated chunk lengths are refused, not read past the end.
        let mut cut = bomb.clone();
        cut.truncate(60);
        assert_eq!(strip_png_metadata(&cut).err(), Some(Refusal::Unreadable));
    }

    #[test]
    fn stored_blobs_have_tighter_limits() {
        let tile = png(128, 128, [1, 2, 3, 255]);
        assert_eq!(decode_stored(&tile).unwrap().dimensions(), (128, 128));
        assert!(decode_stored(&png(256, 256, [0, 0, 0, 255])).is_ok());
        assert_eq!(
            decode_stored(&png(257, 10, [0, 0, 0, 255])).err(),
            Some(Refusal::TooManyPixels)
        );
        assert_eq!(
            decode_stored(&png_header_only(8192, 8192)).err(),
            Some(Refusal::TooManyPixels)
        );
        let mut big = tile.clone();
        big.resize(STORED_MAX_BYTES as usize + 1, 0);
        assert_eq!(decode_stored(&big).err(), Some(Refusal::TooLarge));
        assert_eq!(
            decode_stored(&png_iccp_bomb(64 * 1024 * 1024)).err(),
            Some(Refusal::TooLarge),
            "a bomb is over the stored size anyway"
        );
        assert_eq!(
            decode_stored(&png_iccp_bomb(8 * 1024 * 1024)).err(),
            Some(Refusal::Unreadable),
            "a smaller bomb: stripped, and the header-only fixture has no pixels"
        );
    }
}
