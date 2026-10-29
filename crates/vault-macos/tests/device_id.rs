use std::fs;
use std::os::unix::fs::PermissionsExt;

use uuid::Uuid;
use vault_macos::device_id_in;

#[test]
fn stable_across_calls_and_mode_0600() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("nested").join("dev.aurora.vault");
    let a = device_id_in(&dir).unwrap();
    let b = device_id_in(&dir).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.get_version_num(), 4);
    let mode = fs::metadata(dir.join("device_id"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn corrupt_file_is_replaced() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("device_id");
    fs::write(&path, b"not a uuid\xff").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    let id = device_id_in(tmp.path()).unwrap();
    assert_ne!(id, Uuid::nil());
    let on_disk: Uuid = fs::read_to_string(&path).unwrap().trim().parse().unwrap();
    assert_eq!(on_disk, id);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(device_id_in(tmp.path()).unwrap(), id);
}

#[test]
fn existing_id_is_kept() {
    let tmp = tempfile::tempdir().unwrap();
    let id = Uuid::new_v4();
    fs::write(tmp.path().join("device_id"), format!("{id}\n")).unwrap();
    assert_eq!(device_id_in(tmp.path()).unwrap(), id);
}

#[test]
fn no_temp_files_left_behind() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("device_id"), b"garbage").unwrap();
    device_id_in(tmp.path()).unwrap();
    let names: Vec<_> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["device_id"]);
}
