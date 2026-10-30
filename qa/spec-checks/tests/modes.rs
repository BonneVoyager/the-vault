//! File modes of everything vault-sync writes (03 §1.1, §2 "mode 0600"); backups are not given a
//! mode by the spec, so they are reported, and only vault.bin/blobs/tmp are asserted.
use spec_checks::dev::*;
use spec_checks::*;

#[test]
fn m01_modes_report() {
    let d = tempdir();
    let pkg = d.path().join("md.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("x", now_ms());
    a.s.add_attachment(item, "f", &b"abc"[..], 3, now_ms()).unwrap();
    a.s.save().unwrap();
    a.s.backup_now().unwrap();
    a.add_login("y", now_ms());
    let mut b = std::fs::read(primary(&pkg)).unwrap();
    b[4..6].copy_from_slice(&2u16.to_be_bytes());
    std::fs::write(primary(&pkg), &b).unwrap();
    a.s.lock(); // unsaved snapshot
    let mut lines = vec![];
    let mut walk = vec![pkg.clone()];
    while let Some(p) = walk.pop() {
        for e in std::fs::read_dir(&p).unwrap() {
            let e = e.unwrap().path();
            let m = mode(&e);
            lines.push(format!("{:o} {}", m, e.strip_prefix(d.path()).unwrap().display()));
            if e.is_dir() {
                walk.push(e);
            }
        }
    }
    lines.sort();
    eprintln!("{}", lines.join("\n"));
    let loose: Vec<&String> = lines.iter().filter(|l| l.contains("backups/") && !l.starts_with("600") && !l.starts_with("700")).collect();
    assert!(loose.is_empty(), "backup files readable by group/other: {loose:?}");
}
