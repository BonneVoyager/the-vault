//! Size-capped reads of files that a user picks: CSV / 1PUX / KDBX imports. A thin wrapper
//! over `vault_sync::read_capped` (the same reader vault files go through, 03 §2): it wipes
//! the bytes on drop and words the too-large error for the user.
//!
//! The shared reader follows symlinks. That is fine here: every path is one the user chose in
//! an open panel, not one found by scanning a synced folder. Backups (found by listing the
//! synced `backups/` folder) go through `vault_sync::read_package_entry_capped` instead,
//! which never follows a link (03 §2 D-1).

use std::io::{self, ErrorKind};
use std::path::Path;

use zeroize::Zeroizing;

/// Largest CSV file an import reads: 64 MiB, the same as a vault file. (KDBX has its own
/// limits in `state/kdbx.rs`: database 100 MiB, key file 1 MiB, per 02.)
pub const MAX_IMPORT_FILE_SIZE: u64 = 64 * 1024 * 1024;

/// Largest 1PUX archive an import reads: 1 GiB. A 1Password export carries document
/// attachments under `files/`, which the import skips; vault-core bounds the one entry it
/// does read (`export.data`), so this cap only keeps the whole-file read finite.
pub const MAX_1PUX_FILE_SIZE: u64 = 1024 * 1024 * 1024;

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
    const GIB: u64 = 1024 * 1024 * 1024;
    let limit = if cap >= GIB && cap.is_multiple_of(GIB) {
        format!("{} GiB", cap / GIB)
    } else if cap >= 1024 * 1024 {
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
    fn the_1pux_cap_is_1_gib_and_worded_in_gib() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.1pux");
        File::create(&path)
            .unwrap()
            .set_len(MAX_1PUX_FILE_SIZE + 1)
            .unwrap();
        let err = read_capped(&path, MAX_1PUX_FILE_SIZE).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::FileTooLarge);
        assert_eq!(err.to_string(), "file is larger than the 1 GiB limit");
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
