//! Portable scalar implementation of the Gimli permutation.

use super::State;

/// Number of rounds in Gimli permutation.
const ROUNDS: usize = 24;

/// Portable implementation of the Gimli permutation.
pub(crate) fn gimli(state: &mut State) {
    for round in (1..=ROUNDS).rev() {
        // SP-box layer: apply to each column.
        for column in 0..4 {
            let x = state.0[column].rotate_left(24);
            let y = state.0[4 + column].rotate_left(9);
            let z = state.0[8 + column];

            state.0[8 + column] = x ^ (z << 1) ^ ((y & z) << 2);
            state.0[4 + column] = y ^ x ^ ((x | z) << 1);
            state.0[column] = z ^ y ^ ((x & y) << 3);
        }

        // Small swap: rounds 24, 20, 16, 12, 8, 4.
        if round & 3 == 0 {
            state.0.swap(0, 1);
            state.0.swap(2, 3);
        }

        // Big swap: rounds 22, 18, 14, 10, 6, 2.
        if round & 3 == 2 {
            state.0.swap(0, 2);
            state.0.swap(1, 3);
        }

        // Add round constant: only on round multiples of 4.
        if round & 3 == 0 {
            state.0[0] ^= 0x9e377900 | round as u32;
        }
    }
}
