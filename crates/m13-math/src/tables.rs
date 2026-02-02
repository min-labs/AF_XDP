#![allow(dead_code)]

/// The Rijndael Polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)
const POLY: u16 = 0x11B;

pub struct GfTables {
    pub exp: [u8; 512], // Doubled to avoid modulo in inner loops
    pub log: [u8; 256],
}

/// Generates tables at compile time using Generator 3 (0x03).
/// Mathematical Proof: 3 generates the multiplicative group of GF(2^8) mod 0x11B.
const fn gen_tables() -> GfTables {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x = 1u16; // 3^0
    let mut i = 0;

    log[0] = 0; // Undefined, sentinel value

    while i < 255 {
        exp[i] = x as u8;
        exp[i + 255] = x as u8; // Duplicate for overflow handling
        log[x as usize] = i as u8;

        // Multiply x by 3 (0x03) in GF(2^8)
        // x * 3 = x * (x + 1) = (x * x) + x
        // xtime(x) ^ x
        let double_x = x << 1;
        
        // Check 9th bit for reduction
        let reduced = if double_x & 0x100 != 0 {
            double_x ^ POLY
        } else {
            double_x
        };

        x = reduced ^ x; // Final x * 3
        i += 1;
    }
    
    // Boundary fixup for the doubled table
    exp[510] = exp[0];
    exp[511] = exp[1];

    GfTables { exp, log }
}

/// The compile-time generated tables. Lives in .rodata.
pub static TABLES: GfTables = gen_tables();