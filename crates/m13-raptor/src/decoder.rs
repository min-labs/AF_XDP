#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use m13_core::{M13Error, M13Result};
use m13_math::{GfMatrix, GfSymbol};
use m13_cipher::generate_coefficients;

const LDPC_OVERHEAD_S: usize = 16; 

/// The Fountain Decoder.
pub struct FountainDecoder {
    block_size_k: usize,
    extended_size_l: usize,
    symbol_size: usize,
    gen_id: u16,
    
    // The Equation Matrix acting on Intermediate Symbols (L)
    matrix: GfMatrix,
    // The Symbols Vector (RHS)
    symbols: GfMatrix, 
    
    count: usize,
    seen_symbols: Vec<u32>,
    is_solved: bool,
}

impl FountainDecoder {
    pub fn new(block_size_k: usize, symbol_size: usize, gen_id: u16) -> Self {
        let extended_size_l = block_size_k + LDPC_OVERHEAD_S;
        // Capacity: L + 8 overhead
        let capacity = extended_size_l + 8;
        
        let mut decoder = Self {
            block_size_k,
            extended_size_l,
            symbol_size,
            gen_id,
            matrix: GfMatrix::new(capacity, extended_size_l),
            symbols: GfMatrix::new(capacity, symbol_size),
            count: 0,
            seen_symbols: Vec::new(),
            is_solved: false,
        };

        // [AUDIT FIX] Initialize LDPC Constraints
        // These are "free" equations derived from the pre-coding structure.
        // Equation i: IS[K+i] + SUM(Neighbors in 0..K) = 0
        for i in 0..LDPC_OVERHEAD_S {
            let parity_idx = block_size_k + i;
            let seed = (gen_id as u32) << 16 | (parity_idx as u32);
            let neighbors = generate_coefficients(seed, gen_id, block_size_k);
            
            let row = decoder.count;
            
            // 1. Set Parity Coeff (Identity)
            decoder.matrix.set(row, parity_idx, GfSymbol::ONE);
            
            // 2. Set Neighbor Coeffs (XOR sum -> coeff 1)
            for j in 0..block_size_k {
                if neighbors[j] > 128 {
                    decoder.matrix.set(row, j, GfSymbol::ONE);
                }
            }
            
            // 3. RHS is 0 (Constraint)
            // symbols matrix initialized to 0, so no action needed.
            
            decoder.count += 1;
        }

        decoder
    }

    pub fn receive_symbol(&mut self, symbol_id: u32, payload: &[u8]) -> M13Result<Option<Vec<u8>>> {
        self.absorb(symbol_id, self.gen_id, payload)?;

        if self.is_decodable() && !self.is_solved {
            match self.decode() {
                Ok(data) => {
                    self.is_solved = true;
                    Ok(Some(data))
                },
                Err(M13Error::CryptoFailure) => Ok(None), 
                Err(e) => Err(e),
            }
        } else {
            Ok(None)
        }
    }

    fn absorb(&mut self, symbol_id: u32, gen_id: u16, payload: &[u8]) -> M13Result<()> {
        if gen_id != self.gen_id { return Err(M13Error::WireFormatError); }
        if self.seen_symbols.contains(&symbol_id) { return Ok(()); } 
        if self.count >= self.matrix.rows { return Ok(()); } 

        // 1. Construct Equation Row for Intermediate Symbols
        let row_coeffs = if (symbol_id as usize) < self.block_size_k {
            // Systematic: Identity maps directly to IS[0..K]
            let mut r = alloc::vec![GfSymbol::ZERO; self.extended_size_l];
            r[symbol_id as usize] = GfSymbol::ONE;
            r
        } else {
            // Coded: Generated from L intermediate symbols
            let raw = generate_coefficients(symbol_id, self.gen_id, self.extended_size_l);
            raw.iter().map(|&b| GfSymbol(b)).collect()
        };

        // 2. Insert into Matrix
        let slot = self.count;
        for c in 0..self.extended_size_l {
            self.matrix.set(slot, c, row_coeffs[c]);
        }
        for c in 0..self.symbol_size {
            let val = if c < payload.len() { payload[c] } else { 0 };
            self.symbols.set(slot, c, GfSymbol(val));
        }

        self.count += 1;
        self.seen_symbols.push(symbol_id);
        Ok(())
    }

    pub fn is_decodable(&self) -> bool {
        // We need L independent equations (including the S static constraints)
        self.count >= self.extended_size_l
    }

    pub fn decode(&self) -> M13Result<Vec<u8>> {
        if !self.is_decodable() { return Err(M13Error::InvalidState); }

        let rows = self.count;
        let cols = self.extended_size_l; 
        
        let mut a = self.matrix.clone();
        let mut b = self.symbols.clone();

        let mut pivot_row = 0;
        
        // Gaussian Elimination solving for Intermediate Symbols
        for col_idx in 0..cols {
            if pivot_row >= rows { break; }

            let mut curr = pivot_row;
            while curr < rows && a.get(curr, col_idx) == Some(GfSymbol::ZERO) {
                curr += 1;
            }
            
            if curr == rows { 
                return Err(M13Error::CryptoFailure); 
            }

            if curr != pivot_row {
                for c in 0..cols {
                    let temp = a.get(pivot_row, c).unwrap();
                    a.set(pivot_row, c, a.get(curr, c).unwrap());
                    a.set(curr, c, temp);
                }
                for c in 0..self.symbol_size {
                    let temp = b.get(pivot_row, c).unwrap();
                    b.set(pivot_row, c, b.get(curr, c).unwrap());
                    b.set(curr, c, temp);
                }
            }

            let p_val = a.get(pivot_row, col_idx).unwrap();
            let inv = p_val.inv();
            
            for c in col_idx..cols {
                a.set(pivot_row, c, a.get(pivot_row, c).unwrap() * inv);
            }
            for c in 0..self.symbol_size {
                b.set(pivot_row, c, b.get(pivot_row, c).unwrap() * inv);
            }

            for r in 0..rows {
                if r != pivot_row {
                    let factor = a.get(r, col_idx).unwrap();
                    if factor != GfSymbol::ZERO {
                        for c in col_idx..cols {
                            let val = a.get(r, c).unwrap() - (factor * a.get(pivot_row, c).unwrap());
                            a.set(r, c, val);
                        }
                        for c in 0..self.symbol_size {
                            let val = b.get(r, c).unwrap() - (factor * b.get(pivot_row, c).unwrap());
                            b.set(r, c, val);
                        }
                    }
                }
            }
            pivot_row += 1;
        }

        // Extract Source Symbols (0..K) from Intermediate Symbols (0..L)
        let mut result = Vec::with_capacity(self.block_size_k * self.symbol_size);
        for r in 0..self.block_size_k {
            for c in 0..self.symbol_size {
                result.push(b.get(r, c).unwrap().0);
            }
        }
        Ok(result)
    }
}