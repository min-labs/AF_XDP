#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use m13_core::{M13Error, M13Result, M13Header, PacketType, M13_MAGIC};
use m13_math::{GfSymbol};
use m13_cipher::generate_coefficients;

/// Appendix D.1: Cap block size to prevent CPU exhaustion.
pub const MAX_BLOCK_SYMBOLS: usize = 256; 
/// [AUDIT FIX] RFC 6330 Pre-coding Overhead (Systematic LDPC)
/// We define L = K + S, where S is the number of constraint symbols.
const LDPC_OVERHEAD_S: usize = 16; 

/// The Fountain Encoder.
/// "Pours" symbols into the channel.
pub struct FountainEncoder {
    // Stores Intermediate Symbols (IS)
    // 0..K: Source Symbols
    // K..L: Parity Symbols (LDPC)
    intermediate_symbols: Vec<u8>,
    
    symbol_size: usize,
    block_size_k: usize, // K
    extended_size_l: usize, // L = K + S
    
    gen_id: u16,
    cursor: u32, // The current Symbol ID being generated
}

impl FountainEncoder {
    pub fn new(data: &[u8], symbol_size: usize, gen_id: u16) -> M13Result<Self> {
        if symbol_size == 0 { return Err(M13Error::InvalidState); }
        
        // Calculate K (Round up)
        let block_size_k = (data.len() + symbol_size - 1) / symbol_size;
        
        if block_size_k > MAX_BLOCK_SYMBOLS {
             return Err(M13Error::InvalidState); 
        }

        let extended_size_l = block_size_k + LDPC_OVERHEAD_S;
        let mut intermediate_symbols = alloc::vec![0u8; extended_size_l * symbol_size];

        // 1. Fill Source Symbols (0..K)
        for i in 0..block_size_k {
            let start = i * symbol_size;
            let src_start = i * symbol_size;
            let src_end = core::cmp::min(src_start + symbol_size, data.len());
            
            let dest = &mut intermediate_symbols[start..start + symbol_size];
            if src_start < data.len() {
                dest[0..(src_end - src_start)].copy_from_slice(&data[src_start..src_end]);
            }
        }

        // 2. [AUDIT FIX] PRE-CODING (Compute Parity K..L)
        // Static LDPC Generation: P[i] = XOR sum of a pseudo-random subset of Source
        for i in 0..LDPC_OVERHEAD_S {
            let parity_idx = block_size_k + i;
            // Generate constraint neighbors for this parity symbol
            // Seed = gen_id + parity_index (Deterministic)
            let seed = (gen_id as u32) << 16 | (parity_idx as u32);
            let neighbors = generate_coefficients(seed, gen_id, block_size_k);
            
            let parity_start = parity_idx * symbol_size;
            
            // Temporary buffer to accumulate XOR sum
            let mut acc = alloc::vec![0u8; symbol_size];
            
            for j in 0..block_size_k {
                // Density control: Only use neighbor if coeff > 128 (50% density)
                if neighbors[j] > 128 {
                     let src_start = j * symbol_size;
                     let src = &intermediate_symbols[src_start..src_start + symbol_size];
                     for b in 0..symbol_size {
                         acc[b] ^= src[b];
                     }
                }
            }
            
            // Store Parity
            intermediate_symbols[parity_start..parity_start + symbol_size].copy_from_slice(&acc);
        }

        Ok(Self {
            intermediate_symbols,
            symbol_size,
            block_size_k,
            extended_size_l,
            gen_id,
            cursor: 0,
        })
    }

    /// Produce the next packet in the stream.
    /// 0..K: Systematic Symbols (Source Data).
    /// K..∞: Repair Symbols (Linear Combinations of Intermediate Symbols).
    pub fn next_packet(&mut self) -> (M13Header, Vec<u8>) {
        let sym_id = self.cursor;
        self.cursor += 1;

        let payload = if (sym_id as usize) < self.block_size_k {
            // SYSTEMATIC PHASE: Send raw source symbol
            let start = (sym_id as usize) * self.symbol_size;
            self.intermediate_symbols[start..start + self.symbol_size].to_vec()
        } else {
            // REPAIR PHASE: Random Linear Combination of INTERMEDIATE Symbols (L)
            // Note: We mix both Source and Parity symbols now.
            let coeffs_raw = generate_coefficients(sym_id, self.gen_id, self.extended_size_l);
            
            let mut result = alloc::vec![GfSymbol::ZERO; self.symbol_size];

            for i in 0..self.extended_size_l {
                let coeff = GfSymbol(coeffs_raw[i]);
                if coeff == GfSymbol::ZERO { continue; }

                // Get intermediate symbol i
                let start = i * self.symbol_size;
                let chunk = &self.intermediate_symbols[start..start + self.symbol_size];
                
                for (j, &byte) in chunk.iter().enumerate() {
                    result[j] = result[j] + (coeff * GfSymbol(byte));
                }
            }
            result.iter().map(|s| s.0).collect()
        };

        let header = M13Header {
            magic: M13_MAGIC,
            version: 1,
            packet_type: if (sym_id as usize) < self.block_size_k { PacketType::Data } else { PacketType::Coded },
            gen_id: self.gen_id,
            symbol_id: sym_id,
            payload_len: payload.len() as u16,
            recoder_rank: 0,
            reserved: k_to_reserved(self.block_size_k), 
            auth_tag: [0u8; 16],
        };

        (header, payload)
    }

    pub fn num_source_symbols(&self) -> usize {
        self.block_size_k
    }
}

fn k_to_reserved(k: usize) -> u8 {
    if k > 255 { 255 } else { k as u8 }
}