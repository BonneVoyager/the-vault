//! `export_csv` then `import_csv` on items built from the input; the import must succeed and
//! return one item per exported live item.
//!
//! Replaces an `item_decode` target: `inner_payload` already feeds the item record decoder
//! (`format::decode_item_plain`) directly, so a second target would duplicate it.
//!
//! Input layout (read with `arbitrary::Unstructured`, missing bytes read as zero / empty):
//! `item_count` u8 (mod 9), then per item `title_len` u8 + title bytes, `field_count` u8
//! (mod 7), then per field `kind` u8 (index into `FieldKind::ALL`, mod 10), `name` u8 (index
//! into `NAMES`, mod 8), `value_len` u8 + value bytes. Text is UTF-8 lossy.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use vault_core::{
    CsvMapping, Field, FieldKind, Item, KdfParams, LockedVault, SecretString, UnlockedVault, Uuid,
    VaultKeyHandle, export_csv, import_csv,
};

const NOW: u64 = 1_700_000_000_000;
/// Field names: the five CSV column names, a case variant, a section-like name and empty.
const NAMES: [&str; 8] = [
    "username", "password", "url", "notes", "totp", "Password", "Extra", "",
];

/// An empty vault serialised once (Argon2 runs once), and its vault key, so every input gets
/// a fresh vault through the cheap `unlock_with_key` path.
fn template() -> &'static (Vec<u8>, VaultKeyHandle) {
    static T: OnceLock<(Vec<u8>, VaultKeyHandle)> = OnceLock::new();
    T.get_or_init(|| {
        let password = SecretString::new("fuzz".to_owned());
        let v = UnlockedVault::create(&password, KdfParams::for_tests(), Uuid::nil());
        (v.serialize(), v.export_vault_key())
    })
}

fn byte(u: &mut Unstructured) -> u8 {
    u.arbitrary::<u8>().unwrap_or(0)
}

fn text(u: &mut Unstructured) -> String {
    let len = usize::from(byte(u));
    let bytes = u.bytes(len.min(u.len())).unwrap_or(&[]);
    String::from_utf8_lossy(bytes).into_owned()
}

fuzz_target!(|data: &[u8]| {
    let (bytes, key) = template();
    let mut vault = LockedVault::parse(bytes)
        .and_then(|l| l.unlock_with_key(key, Uuid::nil()))
        .expect("template vault reopens");
    let mut u = Unstructured::new(data);
    let count = byte(&mut u) % 9;
    for _ in 0..count {
        let mut item = Item::new(text(&mut u), Uuid::nil(), NOW);
        let fields = byte(&mut u) % 7;
        for _ in 0..fields {
            let kind = FieldKind::ALL[usize::from(byte(&mut u)) % FieldKind::ALL.len()];
            let name = NAMES[usize::from(byte(&mut u)) % NAMES.len()];
            let value = SecretString::new(text(&mut u));
            item.fields.push(Field::new(name, kind, value, NOW));
        }
        vault.insert(item, NOW);
    }
    let live = vault.items().count();
    let out = export_csv(&vault);
    let back = import_csv(&out.0, &CsvMapping::default(), Uuid::nil(), NOW)
        .expect("import of our own export succeeds");
    assert_eq!(back.len(), live, "one imported item per exported item");
});
