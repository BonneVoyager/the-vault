//! Harness (2026-11-08): `field_icons <vault.bin> <password>` prints one line per field of every
//! item, incl. tombstones: `<title>\t<field name>\t<icon or ->`, sorted. Used by cli/run_all.sh to
//! check that CLI writes keep field icons (01 §4).
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let b = std::fs::read(&a[1]).unwrap();
    let v = vault_core::LockedVault::parse(&b)
        .and_then(|l| l.unlock(&secrecy::SecretString::new(a[2].clone())))
        .expect("open");
    let mut out: Vec<String> = v
        .items_including_deleted()
        .flat_map(|i| {
            i.fields.iter().map(move |f| {
                format!(
                    "{}\t{}\t{}",
                    i.title,
                    f.name,
                    f.icon.as_deref().unwrap_or("-")
                )
            })
        })
        .collect();
    out.sort();
    for l in out {
        println!("{l}");
    }
}
