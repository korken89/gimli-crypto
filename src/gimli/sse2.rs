//! # Gimli permutation - SSE2 SIMD implementation
//!
//! SIMD implementation of the Gimli permutation using x86-64 SSE2 intrinsics.
//!
//! The state layout naturally maps to 3 SSE2 vectors:
//! - Vector 0: state[0..4]   (row 0, all columns)
//! - Vector 1: state[4..8]   (row 1, all columns)
//! - Vector 2: state[8..12]  (row 2, all columns)
//!
//! This allows all 4 columns to be processed in parallel.

use super::{ROUND_CONSTANT, ROUNDS, State};
use core::arch::x86_64::*;

/// Apply the Gimli permutation using SSE2 SIMD.
///
/// # Safety
///
/// This function requires SSE2 support, which is available on all x86-64 targets.
/// The caller must ensure the code is running on a compatible CPU.
#[target_feature(enable = "sse2")]
pub(crate) unsafe fn gimli(state: &mut State) {
    // SAFETY: All SSE2 intrinsics are safe to use within this function as we have
    // the target_feature(enable = "sse2") attribute and the caller guarantees SSE2 support.
    unsafe {
        // Load state into SSE2 vectors (3 vectors for 3 rows)
        let mut row0 = _mm_loadu_si128(state.0.as_ptr().add(0) as *const __m128i);
        let mut row1 = _mm_loadu_si128(state.0.as_ptr().add(4) as *const __m128i);
        let mut row2 = _mm_loadu_si128(state.0.as_ptr().add(8) as *const __m128i);

        for round in (1..=ROUNDS).rev() {
            // SP-box layer: process all 4 columns in parallel
            // x = row0.rotate_left(24)
            let x = _mm_or_si128(_mm_slli_epi32(row0, 24), _mm_srli_epi32(row0, 8));
            // y = row1.rotate_left(9)
            let y = _mm_or_si128(_mm_slli_epi32(row1, 9), _mm_srli_epi32(row1, 23));
            // z = row2
            let z = row2;

            // row2 = x ^ (z << 1) ^ ((y & z) << 2)
            row2 = _mm_xor_si128(
                x,
                _mm_xor_si128(_mm_slli_epi32(z, 1), _mm_slli_epi32(_mm_and_si128(y, z), 2)),
            );

            // row1 = y ^ x ^ ((x | z) << 1)
            row1 = _mm_xor_si128(_mm_xor_si128(y, x), _mm_slli_epi32(_mm_or_si128(x, z), 1));

            // row0 = z ^ y ^ ((x & y) << 3)
            row0 = _mm_xor_si128(_mm_xor_si128(z, y), _mm_slli_epi32(_mm_and_si128(x, y), 3));

            // Small swap + round constant: rounds 24, 20, 16, 12, 8, 4.
            if round & 3 == 0 {
                // Swap adjacent pairs in row0: [0,1,2,3] -> [1,0,3,2]
                // Shuffle pattern: 0xB1 = 0b10_11_00_01 = [1,0,3,2]
                row0 = _mm_shuffle_epi32(row0, 0xB1);

                let constant = ROUND_CONSTANT | round;
                // Create a vector with constant in first lane, zeros elsewhere
                let const_vec = _mm_set_epi32(0, 0, 0, constant as i32);
                row0 = _mm_xor_si128(row0, const_vec);
            }

            // Big swap: rounds 22, 18, 14, 10, 6, 2
            if round & 3 == 2 {
                // Swap halves in row0: [0,1,2,3] -> [2,3,0,1]
                // Shuffle pattern: 0x4E = 0b01_00_11_10 = [2,3,0,1]
                row0 = _mm_shuffle_epi32(row0, 0x4E);
            }
        }

        // Store results back to state
        _mm_storeu_si128(state.0.as_mut_ptr().add(0) as *mut __m128i, row0);
        _mm_storeu_si128(state.0.as_mut_ptr().add(4) as *mut __m128i, row1);
        _mm_storeu_si128(state.0.as_mut_ptr().add(8) as *mut __m128i, row2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gimli_sse2_permutation() {
        // Test vector from Gimli specification
        let mut state = State([
            0x00000000, 0x9e3779ba, 0x3c6ef37a, 0xdaa66d46, 0x78dde724, 0x1715611a, 0xb54cdb2e,
            0x53845566, 0xf1bbcfc8, 0x8ff34a5a, 0x2e2ac522, 0xcc624026,
        ]);

        unsafe {
            gimli(&mut state);
        }

        let expected = State([
            0xba11c85a, 0x91bad119, 0x380ce880, 0xd24c2c68, 0x3eceffea, 0x277a921c, 0x4f73a0bd,
            0xda5a9cd8, 0x84b673f0, 0x34e52ff7, 0x9e2bef49, 0xf41bb8d6,
        ]);

        assert_eq!(state.0, expected.0);
    }

    #[test]
    fn test_gimli_sse2_matches_portable() {
        // Ensure SSE2 version matches the portable version
        use super::super::portable;

        let mut state_sse2 = State([
            0x12345678, 0x9abcdef0, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555,
            0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa,
        ]);

        let mut state_portable = state_sse2.clone();

        unsafe {
            gimli(&mut state_sse2);
        }
        portable::gimli(&mut state_portable);

        assert_eq!(state_sse2.0, state_portable.0);
    }
}
