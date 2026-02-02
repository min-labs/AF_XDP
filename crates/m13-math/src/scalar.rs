use crate::GfSymbol;

/// Standard Scalar Row Addition.
/// Uses the TABLES for multiplication (Memory Lookup).
#[inline(always)]
pub fn row_add_scaled(dest: &mut [u8], src: &[u8], factor: GfSymbol) {
    let len = dest.len().min(src.len());
    for (d, s) in dest[..len].iter_mut().zip(src.iter()) {
        // d = d ^ (s * factor)
        *d = *d ^ GfSymbol(*s).mul(factor).0;
    }
}

/// Helper for pre-computing SIMD tables without relying on global TABLES.
/// Implements raw Rijndael polynomial multiplication (0x11B).
pub fn mul_gf8(a: u8, b: u8) -> u8 {
    let mut p = 0;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        if (b & 1) != 0 { p ^= a; }
        let carry = (a & 0x80) != 0;
        a <<= 1;
        if carry { a ^= 0x1B; } 
        b >>= 1;
    }
    p
}
