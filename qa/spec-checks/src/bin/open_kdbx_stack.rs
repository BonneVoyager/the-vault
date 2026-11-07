//! Child-process harness: `open_kdbx_stack <path> <password> <stack KiB>` runs import_kdbx on a
//! thread with the given stack size, so a stack overflow (abort) in a recursive parser is observable.
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let b = std::fs::read(&a[1]).unwrap();
    let pass = a[2].clone();
    let kib: usize = a[3].parse().unwrap();
    let h = std::thread::Builder::new()
        .stack_size(kib * 1024)
        .spawn(move || {
            vault_core::import::import_kdbx(
                &b,
                &secrecy::SecretString::new(pass),
                None,
                uuid::Uuid::new_v4(),
                1,
            )
            .map(|v| v.len())
            .map_err(|e| {
                format!(
                    "{e} [{}]",
                    format!("{e:?}").split(['(', ' ', '{']).next().unwrap_or("")
                )
            })
        })
        .unwrap();
    match h.join() {
        Ok(Ok(n)) => println!("OK {n}"),
        Ok(Err(e)) => println!("ERR {e}"),
        Err(_) => println!("PANIC escaped"),
    }
}
