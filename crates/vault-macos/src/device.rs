//! Per-machine device identity (spec 04 §1). Not secret.

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::OnceLock;

use uuid::Uuid;

use crate::MacError;

/// Application bundle identifier; also the Application Support subdirectory name.
pub const BUNDLE_ID: &str = "dev.vault.app";

/// Environment variable that overrides the stored device id (same as `vault-cli`).
pub const DEVICE_ID_ENV: &str = "VAULT_DEVICE_ID";

const FILE_NAME: &str = "device_id";

/// Returns this machine's device id; never fails.
///
/// Calls [`try_device_id`]. On error it logs a warning and returns a random id
/// generated once per process (not persisted).
pub fn device_id() -> Uuid {
    match try_device_id() {
        Ok(id) => id,
        Err(e) => {
            static FALLBACK: OnceLock<Uuid> = OnceLock::new();
            let id = *FALLBACK.get_or_init(Uuid::new_v4);
            tracing::warn!(error = %e, fallback = %id, "using unpersisted device id");
            id
        }
    }
}

/// Returns this machine's device id.
///
/// `VAULT_DEVICE_ID` wins if set (an unparsable value is an error). Otherwise
/// reads `<data_dir>/dev.vault.app/device_id`, creating it on first use.
pub fn try_device_id() -> Result<Uuid, MacError> {
    if let Ok(v) = std::env::var(DEVICE_ID_ENV) {
        return v
            .trim()
            .parse()
            .map_err(|e| MacError::Other(format!("{DEVICE_ID_ENV} is not a UUID: {e}")));
    }
    let dir = dirs::data_dir()
        .ok_or_else(|| MacError::Other("no Application Support directory".into()))?
        .join(BUNDLE_ID);
    device_id_in(&dir).map_err(|e| MacError::Other(format!("{}: {e}", dir.display())))
}

/// Reads `dir/device_id`, creating `dir` and a fresh UUIDv4 file (mode 0600)
/// if it is missing, unreadable or does not contain a UUID.
pub fn device_id_in(dir: &Path) -> io::Result<Uuid> {
    let path = dir.join(FILE_NAME);
    if let Ok(s) = fs::read_to_string(&path)
        && let Ok(id) = s.trim().parse()
    {
        return Ok(id);
    }
    let id = Uuid::new_v4();
    fs::create_dir_all(dir)?;
    // Unique temp name + create_new: never follows a planted symlink and never
    // collides with a concurrent first run (app and CLI). Rename is atomic, so
    // readers see either no file or a complete id.
    let tmp = dir.join(format!(
        "{FILE_NAME}.tmp-{}-{}",
        std::process::id(),
        Uuid::new_v4().simple()
    ));
    let result = write_new(&tmp, id).and_then(|()| fs::rename(&tmp, &path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map(|()| id)
}

fn write_new(tmp: &Path, id: Uuid) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(tmp)?;
    // The umask can only clear bits, but set explicitly so the result never
    // depends on it.
    #[cfg(unix)]
    f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    writeln!(f, "{id}")?;
    f.sync_all()
}
