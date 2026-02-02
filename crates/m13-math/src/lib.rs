#![no_std]
#![allow(unsafe_code)]
#![allow(improper_ctypes_definitions)]

extern crate alloc;

// --- PRESERVED LEGACY MODULES ---
pub mod tables; 
pub mod matrix; 
pub use matrix::GfMatrix;
pub use tables::TABLES;

// --- NEW SIMD ARCHITECTURE ---
pub mod scalar;

#[cfg(target_arch = "x86_64")]
mod avx2;
#[cfg(target_arch = "x86_64")]
mod avx512;

#[cfg(target_arch = "aarch64")]
mod neon;

use zeroize::Zeroize;

// --- GfSymbol Implementation ---
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Zeroize)]
#[repr(transparent)]
pub struct GfSymbol(pub u8);

impl GfSymbol {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    
    #[inline(always)]
    pub fn add(self, rhs: Self) -> Self { Self(self.0 ^ rhs.0) }
    #[inline(always)]
    pub fn sub(self, rhs: Self) -> Self { self.add(rhs) }
    
    #[inline]
    pub fn mul(self, rhs: Self) -> Self {
        if self.0 == 0 || rhs.0 == 0 { return Self::ZERO; }
        let idx = (TABLES.log[self.0 as usize] as usize) + (TABLES.log[rhs.0 as usize] as usize);
        Self(TABLES.exp[idx])
    }

    pub fn mul_safe(self, rhs: Self) -> Self {
        let mut p = 0u8;
        let mut a = self.0;
        let mut b = rhs.0;
        for _ in 0..8 {
            let mask = (b as i8).wrapping_shl(7).wrapping_shr(7) as u8;
            p ^= a & mask;
            let high_bit = (a & 0x80) != 0;
            a <<= 1;
            if high_bit { a ^= 0x1B; }
            b >>= 1;
        }
        Self(p)
    }
    
    pub fn inv(self) -> Self {
        if self.0 == 0 { return Self::ZERO; }
        let log_a = TABLES.log[self.0 as usize] as usize;
        let idx = 255 - log_a;
        Self(TABLES.exp[idx])
    }
}

// --- THE SIMD DISPATCHER ---
#[inline(always)]
pub fn row_add_scaled(dest: &mut [u8], src: &[u8], factor: GfSymbol) {
    if factor.0 == 0 || dest.len() == 0 { return; }
    
    if factor.0 == 1 {
        let len = dest.len().min(src.len());
        for (d, s) in dest[..len].iter_mut().zip(src) { *d ^= *s; }
        return;
    }

    // 1. INTEL / AMD DISPATCH
    #[cfg(target_arch = "x86_64")]
    unsafe {
        if cfg!(target_feature = "avx512f") && cfg!(target_feature = "avx512bw") {
            avx512::row_add_scaled_avx512(dest, src, factor.0);
            return;
        }
        if cfg!(target_feature = "avx2") {
            avx2::row_add_scaled_avx2(dest, src, factor.0);
            return;
        }
    }

    // 2. APPLE / ARM DISPATCH
    #[cfg(target_arch = "aarch64")]
    unsafe {
        neon::row_add_scaled_neon(dest, src, factor.0);
        return;
    }

    // 3. FALLBACK
    #[cfg(not(target_arch = "aarch64"))]
    scalar::row_add_scaled(dest, src, factor);
}

// --- PHYSICS REPORTING (HONESTY PROTOCOL) ---
pub fn get_active_engine() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if cfg!(target_feature = "avx512f") && cfg!(target_feature = "avx512bw") {
            return "AVX-512BW (ZEN4/ICELAKE) [64B/CYCLE]";
        }
        if cfg!(target_feature = "avx2") {
            return "AVX2 (TITAN/MODERN) [32B/CYCLE]";
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if cfg!(target_feature = "neon") {
             return "NEON (APPLE/ARM) [16B/CYCLE]";
        }
    }

    "SCALAR (FALLBACK) [1B/CYCLE]"
}

// Operator Overloads
impl core::ops::Add for GfSymbol { type Output = Self; fn add(self, rhs: Self) -> Self { self.add(rhs) } }
impl core::ops::Sub for GfSymbol { type Output = Self; fn sub(self, rhs: Self) -> Self { self.sub(rhs) } }
impl core::ops::Mul for GfSymbol { type Output = Self; fn mul(self, rhs: Self) -> Self { self.mul(rhs) } }
