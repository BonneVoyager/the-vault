use flate2::read::GzDecoder;
#[cfg(feature = "save_kdbx4")]
use flate2::write::GzEncoder;
#[cfg(feature = "save_kdbx4")]
use flate2::Compression as Flate2Compression;
use std::io::Read;
#[cfg(feature = "save_kdbx4")]
use std::io::Write;

/// Upper bound, in bytes, on the decompressed size of any gzip stream inside a database
/// (the KDBX3/KDBX4 payload and each compressed attachment).
///
/// A small file can declare a payload that inflates to many gigabytes, so inflating into an
/// unbounded buffer lets a hostile database exhaust memory. 256 MiB is far above any real
/// database; a larger default, or an option on `Database::parse` (which does not exist yet),
/// may be preferable for some callers.
pub const MAX_DECOMPRESSED_SIZE: usize = 256 * 1024 * 1024;

/// Message of the [`std::io::ErrorKind::InvalidData`] error returned when a gzip stream
/// inflates past [`MAX_DECOMPRESSED_SIZE`]. Compare against `error.to_string()` to tell this
/// case apart from flate2's own errors for a corrupt stream, whose messages are fixed literals
/// (none equals this one).
pub const DECOMPRESSED_SIZE_EXCEEDED: &str = "decompressed data exceeds the size limit";

pub trait Compression {
    #[cfg(feature = "save_kdbx4")]
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error>;
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error>;
}

pub struct NoCompression;

impl Compression for NoCompression {
    #[cfg(feature = "save_kdbx4")]
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        Ok(in_buffer.to_vec())
    }
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        Ok(in_buffer.to_vec())
    }
}

pub struct GZipCompression;

impl Compression for GZipCompression {
    #[cfg(feature = "save_kdbx4")]
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut res = Vec::new();
        let mut encoder = GzEncoder::new(&mut res, Flate2Compression::default());
        encoder.write_all(in_buffer)?;
        encoder.flush()?;
        encoder.finish()?;
        Ok(res)
    }
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        decompress_bounded(in_buffer, MAX_DECOMPRESSED_SIZE)
    }
}

/// Inflate `in_buffer`, failing with [`std::io::ErrorKind::InvalidData`] and the message
/// [`DECOMPRESSED_SIZE_EXCEEDED`] once more than `limit` bytes have been produced. Exactly
/// `limit` bytes succeed. At most `limit + 1` bytes are ever buffered.
fn decompress_bounded(in_buffer: &[u8], limit: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut res = Vec::new();
    let mut decoder = GzDecoder::new(in_buffer).take((limit as u64).saturating_add(1));
    decoder.read_to_end(&mut res)?;
    if res.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            DECOMPRESSED_SIZE_EXCEEDED,
        ));
    }
    Ok(res)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A gzip stream of `len` zero bytes, written in 64 KiB chunks so the test never holds
    /// the plaintext.
    fn zeros(len: usize) -> Vec<u8> {
        let chunk = [0u8; 64 * 1024];
        let mut encoder = GzEncoder::new(Vec::new(), Flate2Compression::fast());
        let mut remaining = len;
        while remaining > 0 {
            let n = remaining.min(chunk.len());
            encoder.write_all(chunk.get(..n).unwrap_or(&[])).unwrap();
            remaining -= n;
        }
        encoder.finish().unwrap()
    }

    #[test]
    fn small_stream_round_trips() {
        let plain = b"KeePass".repeat(100);
        let mut encoder = GzEncoder::new(Vec::new(), Flate2Compression::default());
        encoder.write_all(&plain).unwrap();
        let compressed = encoder.finish().unwrap();

        let out = GZipCompression.decompress(&compressed).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn output_over_the_limit_is_invalid_data() {
        let limit = 1024 * 1024;
        let bomb = zeros(16 * limit);
        assert!(
            bomb.len() < limit,
            "the cap must fire on the output, not the input"
        );

        let err = decompress_bounded(&bomb, limit).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), DECOMPRESSED_SIZE_EXCEEDED);
    }

    #[test]
    fn limit_is_inclusive() {
        let limit = 100 * 1024;

        let exact = decompress_bounded(&zeros(limit), limit).unwrap();
        assert_eq!(exact.len(), limit);

        let one_over = decompress_bounded(&zeros(limit + 1), limit).unwrap_err();
        assert_eq!(one_over.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn corrupt_stream_is_not_reported_as_over_the_limit() {
        let mut stream = zeros(1024);
        if let Some(last) = stream.last_mut() {
            *last ^= 0xff;
        }
        let err = decompress_bounded(&stream, 1024 * 1024).unwrap_err();
        assert_ne!(err.to_string(), DECOMPRESSED_SIZE_EXCEEDED);
    }
}
