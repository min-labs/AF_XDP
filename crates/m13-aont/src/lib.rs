#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use m13_core::{M13Error, M13Result};
use m13_math::{GfSymbol};
use zeroize::Zeroize;
use rand_core::{RngCore, CryptoRng};

mod matrix;
mod solver;
use matrix::generate_cauchy_matrix;

/// Appendix B.1: Mode B Size Limit (64 bytes).
const MODE_B_MAX_SIZE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyMode {
    ModeA, // Bulk
    ModeB, // Critical
}

pub struct AontTransform;

impl AontTransform {
    pub fn transform<R: RngCore + CryptoRng>(
        payload: &[u8],
        seed: u32,
        mode: PrivacyMode,
        rng: &mut R
    ) -> M13Result<Vec<u8>> {
        let size = payload.len();

        match mode {
            PrivacyMode::ModeA => {
                // Fast Path: Table Mul
                let mat = generate_cauchy_matrix(size, seed)?;
                let input: Vec<GfSymbol> = payload.iter().map(|&b| GfSymbol(b)).collect();
                let output_gf = mat.mul_vec(&input)?;
                Ok(output_gf.iter().map(|s| s.0).collect())
            },
            
            PrivacyMode::ModeB => {
                // Entropy Guard
                if size > MODE_B_MAX_SIZE { return Err(M13Error::EntropyExhaustion); }

                // 1. Generate OTP (R)
                let mut pad = alloc::vec![0u8; size];
                rng.fill_bytes(&mut pad);
                
                // 2. Mask: C = M ^ R
                let mut c_masked = alloc::vec![0u8; size];
                for i in 0..size { c_masked[i] = payload[i] ^ pad[i]; }

                // 3. Bind: V = [C || R]
                let mut v_vec = Vec::with_capacity(size * 2);
                for &b in &c_masked { v_vec.push(GfSymbol(b)); }
                for &b in &pad { v_vec.push(GfSymbol(b)); }

                pad.zeroize(); // Scrub OTP

                // 4. Mix: Y = L * V
                let mat = generate_cauchy_matrix(size * 2, seed)?;
                let mut output = Vec::with_capacity(size * 2);

                // CRITICAL: Manual Constant-Time Loop
                let dim = size * 2;
                for r in 0..dim {
                    let mut acc = GfSymbol::ZERO;
                    for c in 0..dim {
                        let coeff = mat.get(r, c).ok_or(M13Error::InvalidState)?;
                        let val = v_vec[c];
                        acc = acc + coeff.mul_safe(val); // Constant Time
                    }
                    output.push(acc.0);
                }
                Ok(output)
            }
        }
    }

    /// Recover original data.
    pub fn recover(transformed: &[u8], seed: u32, mode: PrivacyMode) -> M13Result<Vec<u8>> {
        let size = transformed.len();
        
        match mode {
            PrivacyMode::ModeA => {
                let mat = generate_cauchy_matrix(size, seed)?;
                let inv = solver::invert_matrix(&mat)?;
                let input: Vec<GfSymbol> = transformed.iter().map(|&b| GfSymbol(b)).collect();
                let out = inv.mul_vec(&input)?;
                Ok(out.iter().map(|s| s.0).collect())
            },
            PrivacyMode::ModeB => {
                // Mode B matrix is 2N x 2N
                let mat = generate_cauchy_matrix(size, seed)?;
                let inv = solver::invert_matrix(&mat)?;
                
                // Recover V = [C | R]
                let input: Vec<GfSymbol> = transformed.iter().map(|&b| GfSymbol(b)).collect();
                let v = inv.mul_vec(&input)?;
                
                if v.len() % 2 != 0 { return Err(M13Error::WireFormatError); }
                let mid = v.len() / 2;
                
                let c_part = &v[0..mid];
                let r_part = &v[mid..];
                
                // Unmask M = C ^ R
                let mut m = Vec::with_capacity(mid);
                for i in 0..mid {
                    m.push((c_part[i] + r_part[i]).0);
                }
                Ok(m)
            }
        }
    }
}