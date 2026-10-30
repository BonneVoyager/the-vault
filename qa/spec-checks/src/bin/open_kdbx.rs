//! Child-process harness: `open_kdbx <path> <password> [keyfile]` runs import_kdbx.
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let b = std::fs::read(&a[1]).unwrap();
    let kf = a.get(3).map(|p| std::fs::read(p).unwrap());
    let r = vault_core::import::import_kdbx(&b, &secrecy::SecretString::new(a[2].clone()), kf.as_deref(), uuid::Uuid::new_v4(), 1);
    match r {
        Ok(v) => println!("OK {}", v.len()),
        Err(e) => println!("ERR {e}"),
    }
}
