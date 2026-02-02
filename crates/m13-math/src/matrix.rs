use crate::GfSymbol;
use m13_core::{M13Result, M13Error};
use zeroize::Zeroize;

use alloc::vec::Vec;

#[derive(Debug, Clone, Zeroize)]
pub struct GfMatrix {
    pub rows: usize,
    pub cols: usize,
    // Zeroize vector contents on drop.
    pub data: Vec<GfSymbol>,
}

impl GfMatrix {
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            data: alloc::vec![GfSymbol::ZERO; rows * cols],
        }
    }

    pub fn get(&self, r: usize, c: usize) -> Option<GfSymbol> {
        if r >= self.rows || c >= self.cols { return None; }
        Some(self.data[r * self.cols + c])
    }

    pub fn set(&mut self, r: usize, c: usize, val: GfSymbol) {
        if r < self.rows && c < self.cols {
            self.data[r * self.cols + c] = val;
        }
    }

    /// Matrix-Vector Multiplication (Y = A * X)
    /// No unwraps. Returns Error on mismatch.
    pub fn mul_vec(&self, x: &[GfSymbol]) -> M13Result<Vec<GfSymbol>> {
        if x.len() != self.cols {
            return Err(M13Error::InvalidState); // Dimension mismatch
        }

        let mut y = alloc::vec![GfSymbol::ZERO; self.rows];

        for r in 0..self.rows {
            let mut acc = GfSymbol::ZERO;
            for c in 0..self.cols {
                let coeff = self.data[r * self.cols + c];
                let val = x[c];
                // Using mul() for performance. 
                // For AONT (Sprint 6), we will introduce mul_vec_safe()
                acc = acc + (coeff * val);
            }
            y[r] = acc;
        }
        Ok(y)
    }
}