#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use crate::scalar;

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn row_add_scaled_avx2(dest: &mut [u8], src: &[u8], factor: u8) {
    let len = dest.len().min(src.len());
    let mut i = 0;

    let mut low_arr = [0u8; 16];
    let mut high_arr = [0u8; 16];
    
    for j in 0..16u8 {
        low_arr[j as usize] = scalar::mul_gf8(j, factor);
        high_arr[j as usize] = scalar::mul_gf8(j << 4, factor);
    }

    let v_lo_128 = _mm_loadu_si128(low_arr.as_ptr() as *const _);
    let v_hi_128 = _mm_loadu_si128(high_arr.as_ptr() as *const _);
    let tbl_lo = _mm256_broadcastsi128_si256(v_lo_128);
    let tbl_hi = _mm256_broadcastsi128_si256(v_hi_128);
    let mask = _mm256_set1_epi8(0x0F as i8);

    while i + 32 <= len {
        let s_ptr = src.as_ptr().add(i) as *const _;
        let d_ptr = dest.as_mut_ptr().add(i) as *mut _;

        let v_src = _mm256_loadu_si256(s_ptr);
        let v_dest = _mm256_loadu_si256(d_ptr);

        let lo = _mm256_and_si256(v_src, mask);
        let hi = _mm256_and_si256(_mm256_srli_epi64(v_src, 4), mask);

        let res_lo = _mm256_shuffle_epi8(tbl_lo, lo);
        let res_hi = _mm256_shuffle_epi8(tbl_hi, hi);

        let product = _mm256_xor_si256(res_lo, res_hi);
        let result = _mm256_xor_si256(v_dest, product);

        _mm256_storeu_si256(d_ptr, result);
        i += 32;
    }

    if i < len {
        let f_sym = crate::GfSymbol(factor);
        scalar::row_add_scaled(&mut dest[i..], &src[i..], f_sym);
    }
}
