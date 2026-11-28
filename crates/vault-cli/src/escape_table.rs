//! Code points that must never reach a terminal raw: Unicode general categories Cf, Zl, Zp.
//! (Cc is covered by `char::is_control`.)

// Inclusive ranges of Cf, Zl and Zp, sorted, generated from Unicode 17.0.0
// (`unicodedata.unidata_version` of the generating Python) with:
// python3 -c "import unicodedata as u;r=[];s=None
// for c in range(0x110001):
//  f=c<0x110000 and u.category(chr(c)) in('Cf','Zl','Zp')
//  if f and s is None:s=c
//  if not f and s is not None:r.append((s,c-1));s=None
// print(', '.join('(0x%X, 0x%X)'%x for x in r))"
static FORMAT_RANGES: &[(u32, u32)] = &[
    (0xAD, 0xAD),
    (0x600, 0x605),
    (0x61C, 0x61C),
    (0x6DD, 0x6DD),
    (0x70F, 0x70F),
    (0x890, 0x891),
    (0x8E2, 0x8E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

/// True for Cc, Cf, Zl and Zp code points.
pub fn needs_escape(c: char) -> bool {
    if c.is_control() {
        return true;
    }
    let u = u32::from(c);
    FORMAT_RANGES
        .binary_search_by(|&(lo, hi)| {
            if hi < u {
                std::cmp::Ordering::Less
            } else if lo > u {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

#[cfg(test)]
pub fn ranges() -> &'static [(u32, u32)] {
    FORMAT_RANGES
}
