use m13_core::{M13Error, M13Result};
use m13_math::{GfMatrix, GfSymbol};
use m13_cipher::generate_coefficients;

extern crate alloc;
use alloc::vec::Vec;

/// Generates a guaranteed invertible Cauchy Matrix from a seed.
/// L[i,j] = 1 / (x[i] + y[j])
pub fn generate_cauchy_matrix(size: usize, seed: u32) -> M13Result<GfMatrix> {
    if size * 2 > 256 {
        return Err(M13Error::InvalidState); // Matrix too large for field
    }

    let mut mat = GfMatrix::new(size, size);

    // 1. Generate a permutation of [0..255] using the Seed.
    let mut elements: Vec<u8> = (0..=255).collect();
    
    // Get randomness from the Cipher (Keystream)
    let randomness = generate_coefficients(seed, 0, 256);
    
    // Fisher-Yates Shuffle
    for i in (1..256).rev() {
        let j = (randomness[i] as usize) % (i + 1);
        elements.swap(i, j);
    }

    // 2. Split into X and Y sets (Disjoint by definition)
    let x_set = &elements[0..size];
    let y_set = &elements[size..2*size];

    // 3. Fill Matrix
    for r in 0..size {
        for c in 0..size {
            let x = GfSymbol(x_set[r]);
            let y = GfSymbol(y_set[c]);
            
            // Cauchy Denominator: x + y (XOR in GF2^8)
            // Since X and Y are disjoint, x != y, so sum != 0. Division is safe.
            let sum = x + y;
            mat.set(r, c, sum.inv());
        }
    }
    
    Ok(mat)
}