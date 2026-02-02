use m13_math::{GfMatrix, GfSymbol};
use m13_core::{M13Error, M13Result};

/// Inverts a square GF(2^8) matrix using Gaussian Elimination.
pub fn invert_matrix(matrix: &GfMatrix) -> M13Result<GfMatrix> {
    if matrix.rows != matrix.cols {
        return Err(M13Error::InvalidState);
    }
    let n = matrix.rows;
    let mut a = matrix.clone(); 
    let mut inv = GfMatrix::new(n, n);

    // Initialize Identity
    for i in 0..n {
        inv.set(i, i, GfSymbol::ONE);
    }

    for i in 0..n {
        // 1. Pivot
        let mut pivot_row = i;
        while pivot_row < n && a.get(pivot_row, i) == Some(GfSymbol::ZERO) {
            pivot_row += 1;
        }
        if pivot_row == n {
            return Err(M13Error::CryptoFailure); // Singular Matrix
        }

        // 2. Swap
        if pivot_row != i {
            for col in 0..n {
                let temp_a = a.get(i, col).unwrap();
                let temp_inv = inv.get(i, col).unwrap();
                
                a.set(i, col, a.get(pivot_row, col).unwrap());
                a.set(pivot_row, col, temp_a);
                
                inv.set(i, col, inv.get(pivot_row, col).unwrap());
                inv.set(pivot_row, col, temp_inv);
            }
        }

        // 3. Normalize
        let pivot = a.get(i, i).unwrap();
        let pivot_inv = pivot.inv();
        for col in 0..n {
            a.set(i, col, a.get(i, col).unwrap() * pivot_inv);
            inv.set(i, col, inv.get(i, col).unwrap() * pivot_inv);
        }

        // 4. Eliminate
        for row in 0..n {
            if row != i {
                let factor = a.get(row, i).unwrap();
                if factor != GfSymbol::ZERO {
                    for col in 0..n {
                        let val_a = a.get(row, col).unwrap() - (factor * a.get(i, col).unwrap());
                        a.set(row, col, val_a);
                        
                        let val_inv = inv.get(row, col).unwrap() - (factor * inv.get(i, col).unwrap());
                        inv.set(row, col, val_inv);
                    }
                }
            }
        }
    }

    Ok(inv)
}