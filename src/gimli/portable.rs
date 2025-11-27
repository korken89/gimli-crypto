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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gimli_permutation() {
        // Test vector from Gimli specification
        let mut state = State([
            0x00000000, 0x9e3779ba, 0x3c6ef37a, 0xdaa66d46, 0x78dde724, 0x1715611a, 0xb54cdb2e,
            0x53845566, 0xf1bbcfc8, 0x8ff34a5a, 0x2e2ac522, 0xcc624026,
        ]);

        gimli(&mut state);

        let expected = State([
            0xba11c85a, 0x91bad119, 0x380ce880, 0xd24c2c68, 0x3eceffea, 0x277a921c, 0x4f73a0bd,
            0xda5a9cd8, 0x84b673f0, 0x34e52ff7, 0x9e2bef49, 0xf41bb8d6,
        ]);

        assert_eq!(state.0, expected.0);
    }
}
