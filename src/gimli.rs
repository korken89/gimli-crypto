//! # Gimli permutation implementation
//!
//! The Gimli permutation operates on a 384-bit state as 12 32-bit words.

use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(target_arch = "aarch64")]
mod neon;
#[cfg(any(not(target_arch = "aarch64"), test))]
mod portable;

/// Gimli state: 12 u32 words (384 bits).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct State(pub(crate) [u32; 12]);

impl State {
    /// Create a new state.
    pub(crate) const fn new() -> Self {
        Self([0; _])
    }

    /// Get a mutable view of the state as bytes.
    #[inline(always)]
    pub(crate) const fn as_bytes_mut(&mut self) -> &mut [u8; 48] {
        // SAFETY: This is safe because:
        // - `[u32; 12]` and `[u8; 48]` have the same size (48 bytes).
        // - Both types have the same alignment requirements, the source is only stricter.
        // - u32 and u8 are both valid for any bit pattern.
        // - We're converting between valid representations of the same data.
        unsafe { core::mem::transmute(&mut self.0) }
    }

    /// Get an immutable view of the state as bytes.
    #[inline(always)]
    pub(crate) const fn as_bytes(&self) -> &[u8; 48] {
        // SAFETY: This is safe because:
        // - `[u32; 12]` and `[u8; 48]` have the same size (48 bytes).
        // - Both types have the same alignment requirements, the source is only stricter.
        // - u32 and u8 are both valid for any bit pattern.
        // - We're converting between valid representations of the same data.
        unsafe { core::mem::transmute(&self.0) }
    }
}

/// Apply the Gimli permutation to the state.
///
/// On aarch64 targets, this automatically uses the NEON SIMD implementation.
/// On other targets, it uses the portable implementation.
#[cfg(not(target_arch = "aarch64"))]
pub(crate) fn gimli(state: &mut State) {
    portable::gimli(state);
}

/// Apply the Gimli permutation to the state using NEON SIMD.
#[cfg(target_arch = "aarch64")]
pub(crate) fn gimli(state: &mut State) {
    // SAFETY: NEON is available on all aarch64 targets
    unsafe {
        neon::gimli(state);
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
