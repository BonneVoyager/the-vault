//! Child-process harness: `open_file <path> <password>` parses + unlocks with vault-core and
//! prints OK/ERR <variant>. Used so aborts, stack overflows and OOM are observable.
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let b = std::fs::read(&a[1]).unwrap();
    let r = vault_core::LockedVault::parse(&b).and_then(|l| l.unlock(&secrecy::SecretString::new(a[2].clone())));
    match r {
        Ok(u) => println!("OK {}", u.items_including_deleted().count()),
        Err(e) => println!("ERR {e:?}"),
    }
}
