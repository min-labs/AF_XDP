#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use m13_core::{M13Error, M13Result};
use m13_math::{GfMatrix, GfSymbol};

pub struct RlncDecoder {
    gen_id: u16,
    k: usize,
    payload_size: usize,
    
    // Matrix [K x K] stores the GEVs
    matrix: GfMatrix,
    // Matrix [K x S] stores the Data
    data: GfMatrix,
    
    rank: usize,
}

impl RlncDecoder {
    pub fn new(gen_id: u16, k: usize, payload_size: usize) -> Self {
        Self {
            gen_id,
            k,
            payload_size,
            matrix: GfMatrix::new(k, k),
            data: GfMatrix::new(k, payload_size),
            rank: 0,
        }
    }

    /// Returns the Generation ID managed by this Decoder.
    pub fn gen_id(&self) -> u16 {
        self.gen_id
    }

    /// Process a packet. Returns true if innovative.
    pub fn absorb(&mut self, packet_bytes: &[u8]) -> M13Result<bool> {
        if packet_bytes.len() != self.k + self.payload_size {
            return Err(M13Error::WireFormatError);
        }

        let (gev_bytes, data_bytes) = packet_bytes.split_at(self.k);
        let mut row_gev: Vec<GfSymbol> = gev_bytes.iter().map(|&b| GfSymbol(b)).collect();
        let mut row_data: Vec<GfSymbol> = data_bytes.iter().map(|&b| GfSymbol(b)).collect();

        // Gaussian Elimination
        for r in 0..self.k {
            // Check if this row slot 'r' is taken (Pivot exists)
            if self.matrix.get(r, r) == Some(GfSymbol::ONE) {
                let factor = row_gev[r];
                if factor != GfSymbol::ZERO {
                    // Eliminate
                    for c in r..self.k {
                        let val = row_gev[c] - (factor * self.matrix.get(r, c).unwrap());
                        row_gev[c] = val;
                    }
                    for c in 0..self.payload_size {
                        let val = row_data[c] - (factor * self.data.get(r, c).unwrap());
                        row_data[c] = val;
                    }
                }
            } else {
                // Pivot empty! We assume we can claim it.
                // But first, is our candidate non-zero here?
                if row_gev[r] == GfSymbol::ZERO { continue; }

                // Normalize
                let inv = row_gev[r].inv();
                for c in r..self.k { row_gev[c] = row_gev[c] * inv; }
                for c in 0..self.payload_size { row_data[c] = row_data[c] * inv; }

                // Store
                for c in 0..self.k { self.matrix.set(r, c, row_gev[c]); }
                for c in 0..self.payload_size { self.data.set(r, c, row_data[c]); }
                
                self.rank += 1;
                return Ok(true);
            }
        }
        Ok(false) // Linear Dependence
    }

    pub fn is_complete(&self) -> bool {
        self.rank == self.k
    }

    /// Extract original packets.
    pub fn decode(&mut self) -> M13Result<Vec<Vec<u8>>> {
        if !self.is_complete() { return Err(M13Error::InvalidState); }

        // Back Substitution (Clear Upper Triangle)
        for r in (0..self.k).rev() {
            for row_above in 0..r {
                let factor = self.matrix.get(row_above, r).unwrap();
                if factor != GfSymbol::ZERO {
                    for c in 0..self.payload_size {
                        let val = self.data.get(row_above, c).unwrap() - (factor * self.data.get(r, c).unwrap());
                        self.data.set(row_above, c, val);
                    }
                }
            }
        }

        let mut output = Vec::new();
        for r in 0..self.k {
            let mut buf = Vec::with_capacity(self.payload_size);
            for c in 0..self.payload_size {
                buf.push(self.data.get(r, c).unwrap().0);
            }
            output.push(buf);
        }
        Ok(output)
    }
}