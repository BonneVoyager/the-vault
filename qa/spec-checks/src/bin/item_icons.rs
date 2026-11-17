//! Harness (2026-11-17): `item_icons <vault.bin> <password>` decodes the file with the ledger's
//! independent decoder (no vault-core parsing) and prints one line per item, sorted:
//! `<title debug>\t<icon map debug or ->`. Used by the CLI checks to see what `--icon` stored.
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let b = std::fs::read(&a[1]).unwrap();
    let o = spec_checks::indep::open_file(&b, &a[2]);
    let mut out: Vec<String> = o
        .items
        .iter()
        .map(|(_, _, pt)| {
            let title = match spec_checks::get(pt, "title") {
                Some(spec_checks::Value::Text(s)) => s.clone(),
                _ => String::new(),
            };
            let icon = match spec_checks::get(pt, "icon") {
                Some(spec_checks::Value::Map(m)) => {
                    let mut kv: Vec<String> = m
                        .iter()
                        .map(|(k, v)| match (k, v) {
                            (spec_checks::Value::Text(k), spec_checks::Value::Text(v)) => {
                                format!("{k}={v:?}")
                            }
                            (k, v) => format!("{k:?}={v:?}"),
                        })
                        .collect();
                    kv.sort();
                    kv.join(",")
                }
                Some(v) => format!("{v:?}"),
                None => "-".into(),
            };
            format!("{title:?}\t{icon}")
        })
        .collect();
    out.sort();
    for l in out {
        println!("{l}");
    }
}
