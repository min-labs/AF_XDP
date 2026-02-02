#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
use crate::scalar;

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn row_add_scaled_neon(dest: &mut [u8], src: &[u8], factor: u8) {
    let len = dest.len().min(src.len());
    let mut i = 0;

    // 1. PRE-COMPUTE SHUFFLE TABLES (16 Bytes)
    let mut low_arr = [0u8; 16];
    let mut high_arr = [0u8; 16];
    
    for j in 0..16u8 {
        low_arr[j as usize] = scalar::mul_gf8(j, factor);
        high_arr[j as usize] = scalar::mul_gf8(j << 4, factor);
    }

    let tbl_lo = vld1q_u8(low_arr.as_ptr());
    let tbl_hi = vld1q_u8(high_arr.as_ptr());
    let mask = vdupq_n_u8(0x0F);

    // 2. VECTOR LOOP (16 Bytes/Cycle)
    while i + 16 <= len {
        let s_ptr = src.as_ptr().add(i);
        let d_ptr = dest.as_mut_ptr().add(i);

        let v_src = vld1q_u8(s_ptr);
        let v_dest = vld1q_u8(d_ptr);

        let lo = vandq_u8(v_src, mask);
        let hi = vshrq_n_u8(v_src, 4);

        let res_lo = vqtbl1q_u8(tbl_lo, lo);
        let res_hi = vqtbl1q_u8(tbl_hi, hi);

        let product = veorq_u8(res_lo, res_hi);
        let result = veorq_u8(v_dest, product);

        vst1q_u8(d_ptr, result);
        i += 16;
    }

    // 3. SCALAR TAIL
    if i < len {
        let f_sym = crate::GfSymbol(factor);
        scalar::row_add_scaled(&mut dest[i..], &src[i..], f_sym);
    }
}
