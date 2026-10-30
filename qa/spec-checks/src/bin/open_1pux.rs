//! Child-process harness: `open_1pux <path>` runs import_1pux.
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let b = std::fs::read(&a[1]).unwrap();
    match vault_core::import::import_1pux(&b, uuid::Uuid::new_v4(), 1) {
        Ok(v) => println!("OK {}", v.len()),
        Err(e) => println!("ERR {e}"),
    }
}
