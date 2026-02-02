#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use m13_core::{M13Error, M13Result};
use m13_math::{GfSymbol};
use rand_core::{RngCore, CryptoRng};

/// Limits generation size to control complexity.
pub const MAX_RLNC_GENERATION: usize = 32;

/// A stored packet in the basis.
#[derive(Clone)]
struct BasisSlot {
    gev: Vec<GfSymbol>,
    data: Vec<GfSymbol>, // Data stored as Symbols for easy mixing
}

/// The Mesh Recoder.
/// Maintains a basis of Innovative Packets.
pub struct Recoder {
    gen_id: u16,
    generation_size_k: usize,
    basis: Vec<BasisSlot>, // Kept in triangular form
}

impl Recoder {
    pub fn new(gen_id: u16, k: usize) -> M13Result<Self> {
        if k == 0 || k > MAX_RLNC_GENERATION { return Err(M13Error::InvalidState); }
        Ok(Self {
            gen_id,
            generation_size_k: k,
            basis: Vec::with_capacity(k),
        })
    }

    /// Returns the Generation ID managed by this Recoder.
    pub fn gen_id(&self) -> u16 {
        self.gen_id
    }

    /// Ingest a packet from the wire.
    /// Returns `Ok(true)` if the packet was innovative (added to basis).
    /// Returns `Ok(false)` if the packet was linearly dependent (discarded).
    pub fn absorb(&mut self, data: &[u8]) -> M13Result<bool> {
        let k = self.generation_size_k;
        if data.len() <= k { return Err(M13Error::WireFormatError); }

        let (gev_raw, payload_raw) = data.split_at(k);
        
        // Convert to Symbols
        let mut candidate_gev: Vec<GfSymbol> = gev_raw.iter().map(|&b| GfSymbol(b)).collect();
        let mut candidate_data: Vec<GfSymbol> = payload_raw.iter().map(|&b| GfSymbol(b)).collect();

        // 1. Gaussian Reduction against Basis
        // We try to zero out the candidate's GEV using existing basis rows.
        for slot in &self.basis {
            // Find leading non-zero in slot (Pivot)
            if let Some(pivot_idx) = slot.gev.iter().position(|&x| x != GfSymbol::ZERO) {
                let factor = candidate_gev[pivot_idx];
                if factor != GfSymbol::ZERO {
                    // Eliminate
                    // candidate -= factor * slot
                    for i in pivot_idx..k {
                         candidate_gev[i] = candidate_gev[i] - (factor * slot.gev[i]);
                    }
                    for i in 0..candidate_data.len() {
                         candidate_data[i] = candidate_data[i] - (factor * slot.data[i]);
                    }
                }
            }
        }

        // 2. Innovation Check
        if let Some(pivot_idx) = candidate_gev.iter().position(|&x| x != GfSymbol::ZERO) {
            // It didn't reduce to zero! It's innovative.
            // Normalize to make the pivot 1
            let inv = candidate_gev[pivot_idx].inv();
            for x in &mut candidate_gev { *x = *x * inv; }
            for x in &mut candidate_data { *x = *x * inv; }

            // Store in Basis
            self.basis.push(BasisSlot {
                gev: candidate_gev,
                data: candidate_data,
            });
            
            Ok(true)
        } else {
            // Linearly Dependent (Redundant)
            Ok(false)
        }
    }

    /// Generate a mixed packet.
    /// P_out = sum( rand_i * Basis_i )
    pub fn recode<R: RngCore + CryptoRng>(&self, rng: &mut R) -> M13Result<Vec<u8>> {
        if self.basis.is_empty() { return Err(M13Error::InvalidState); }

        let data_len = self.basis[0].data.len();
        let k = self.generation_size_k;

        // 1. Generate Local Coefficients
        let mut local_coeffs = alloc::vec![0u8; self.basis.len()];
        rng.fill_bytes(&mut local_coeffs);

        // 2. Mix
        let mut out_gev = alloc::vec![GfSymbol::ZERO; k];
        let mut out_data = alloc::vec![GfSymbol::ZERO; data_len];

        for (i, slot) in self.basis.iter().enumerate() {
            let alpha = GfSymbol(local_coeffs[i]);
            if alpha == GfSymbol::ZERO { continue; }

            // Mix GEV
            for j in 0..k {
                out_gev[j] = out_gev[j] + (alpha * slot.gev[j]);
            }
            // Mix Data
            for j in 0..data_len {
                out_data[j] = out_data[j] + (alpha * slot.data[j]);
            }
        }

        // 3. Serialize
        let mut output = Vec::with_capacity(k + data_len);
        for s in out_gev { output.push(s.0); }
        for s in out_data { output.push(s.0); }
        
        Ok(output)
    }

    pub fn current_rank(&self) -> usize {
        self.basis.len()
    }
}