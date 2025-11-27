//! # Gimli permutation - NEON SIMD implementation
//!
//! SIMD implementation of the Gimli permutation using ARM NEON intrinsics.
//!
//! The state layout naturally maps to 3 NEON vectors:
//! - Vector 0: state[0..4]   (row 0, all columns)
//! - Vector 1: state[4..8]   (row 1, all columns)
//! - Vector 2: state[8..12]  (row 2, all columns)
//!
//! This allows all 4 columns to be processed in parallel.

use super::State;
use core::arch::aarch64::*;

/// Number of rounds in Gimli permutation.
const ROUNDS: usize = 24;

/// Apply the Gimli permutation using NEON SIMD.
///
/// # Safety
///
/// This function requires NEON support, which is available on all aarch64 targets.
/// The caller must ensure the code is running on a compatible CPU.
#[target_feature(enable = "neon")]
pub(crate) unsafe fn gimli(state: &mut State) {
    // SAFETY: All NEON intrinsics are safe to use within this function as we have
    // the target_feature(enable = "neon") attribute and the caller guarantees NEON support.
    unsafe {
        // Load state into NEON vectors (3 vectors for 3 rows)
        let mut row0 = vld1q_u32(state.0.as_ptr().add(0));
        let mut row1 = vld1q_u32(state.0.as_ptr().add(4));
        let mut row2 = vld1q_u32(state.0.as_ptr().add(8));

        for round in (1..=ROUNDS).rev() {
            // SP-box layer: process all 4 columns in parallel
            // x = row0.rotate_left(24)
            let x = vorrq_u32(vshlq_n_u32(row0, 24), vshrq_n_u32(row0, 8));
            // y = row1.rotate_left(9)
            let y = vorrq_u32(vshlq_n_u32(row1, 9), vshrq_n_u32(row1, 23));
            // z = row2
            let z = row2;

            // row2 = x ^ (z << 1) ^ ((y & z) << 2)
            row2 = veorq_u32(
                x,
                veorq_u32(vshlq_n_u32(z, 1), vshlq_n_u32(vandq_u32(y, z), 2)),
            );
            // row1 = y ^ x ^ ((x | z) << 1)
            row1 = veorq_u32(veorq_u32(y, x), vshlq_n_u32(vorrq_u32(x, z), 1));
            // row0 = z ^ y ^ ((x & y) << 3)
            row0 = veorq_u32(veorq_u32(z, y), vshlq_n_u32(vandq_u32(x, y), 3));

            // Small swap: rounds 24, 20, 16, 12, 8, 4
            // Swap adjacent pairs in row0: [0,1,2,3] -> [1,0,3,2]
            if round & 3 == 0 {
                row0 = vrev64q_u32(row0);
            }

            // Big swap: rounds 22, 18, 14, 10, 6, 2
            // Swap halves in row0: [0,1,2,3] -> [2,3,0,1]
            if round & 3 == 2 {
                row0 = vextq_u32(row0, row0, 2);
            }

            // Add round constant: only on round multiples of 4
            if round & 3 == 0 {
                let constant = 0x9e377900u32 | round as u32;
                let const_vec = vsetq_lane_u32(constant, vdupq_n_u32(0), 0);
                row0 = veorq_u32(row0, const_vec);
            }
        }

        // Store results back to state
        vst1q_u32(state.0.as_mut_ptr().add(0), row0);
        vst1q_u32(state.0.as_mut_ptr().add(4), row1);
        vst1q_u32(state.0.as_mut_ptr().add(8), row2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gimli_neon_permutation() {
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
    fn test_gimli_neon_matches_portable() {
        // Ensure NEON version matches the portable version
        use super::super::portable;

        let mut state_neon = State([
            0x12345678, 0x9abcdef0, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555,
            0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa,
        ]);

        let mut state_portable = state_neon.clone();

        unsafe {
            gimli(&mut state_neon);
        }
        portable::gimli(&mut state_portable);

        assert_eq!(state_neon.0, state_portable.0);
    }
}
