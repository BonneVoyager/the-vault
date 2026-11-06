//! Size-capped reads of files that a user picks or a sync peer can plant: backups opened in
//! the viewer, CSV / 1PUX / KDBX imports. A thin wrapper over `vault_sync::read_capped` (the
//! same reader vault files go through, 03 §2): it wipes the bytes on drop and words the
//! too-large error for the user.
//!
//! The shared reader follows symlinks. That is fine here: every path is one the user chose
//! (an open panel, a backup row the user clicked), not one found by scanning a synced folder.

use std::io::{self, ErrorKind};
use std::path::Path;

use zeroize::Zeroizing;

/// Largest CSV or 1PUX file an import reads: 64 MiB, the same as a vault file.
pub const MAX_IMPORT_FILE_SIZE: u64 = 64 * 1024 * 1024;

/// Reads all of the regular file at `path`, refusing one larger than `cap` bytes with
/// [`ErrorKind::FileTooLarge`] (checked on `fstat` before allocating, and while reading) and
/// a non-regular file with [`ErrorKind::InvalidInput`]. The bytes are wiped on drop. Known
/// limit: if the file grows while being read, the shared reader's buffer may reallocate and
/// leave an unwiped copy of the first part; it cannot exceed `cap`.
pub fn read_capped(path: &Path, cap: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    match vault_sync::read_capped(path, cap) {
        Ok(bytes) => Ok(Zeroizing::new(bytes)),
        Err(e) if e.kind() == ErrorKind::FileTooLarge => Err(too_large(cap)),
        Err(e) => Err(e),
    }
}

/// The same wording in the app and the CLI.
fn too_large(cap: u64) -> io::Error {
    let limit = if cap >= 1024 * 1024 {
        format!("{} MiB", cap / (1024 * 1024))
    } else {
        format!("{cap} byte")
    };
    io::Error::new(
        ErrorKind::FileTooLarge,
        format!("file is larger than the {limit} limit"),
    )
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;

    #[test]
    fn reads_up_to_the_cap_and_refuses_one_byte_more() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"12345678").unwrap();
        assert_eq!(&*read_capped(&path, 8).unwrap(), b"12345678");
        let err = read_capped(&path, 7).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::FileTooLarge);
        assert_eq!(err.to_string(), "file is larger than the 7 byte limit");
    }

    #[test]
    fn refuses_a_sparse_file_over_64_mib_without_reading_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.csv");
        File::create(&path)
            .unwrap()
            .set_len(MAX_IMPORT_FILE_SIZE + 1)
            .unwrap();
        let err = read_capped(&path, MAX_IMPORT_FILE_SIZE).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::FileTooLarge);
        assert_eq!(err.to_string(), "file is larger than the 64 MiB limit");
    }

    #[test]
    fn empty_file_reads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e");
        std::fs::write(&path, b"").unwrap();
        assert!(read_capped(&path, 8).unwrap().is_empty());
    }

    #[test]
    fn refuses_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_capped(dir.path(), 8).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }
}
