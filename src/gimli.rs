//! # Gimli permutation implementation
//!
//! The Gimli permutation operates on a 384-bit state as 12 32-bit words.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Number of rounds in Gimli permutation.
pub(crate) const ROUNDS: u32 = 24;

/// Round constant in the permutation.
pub(crate) const ROUND_CONSTANT: u32 = 0x9e37_7900;

// Always compile portable for benchmarking comparison
mod portable;
#[cfg(target_arch = "x86_64")]
mod sse2;

/// Gimli state: 12 u32 words (384 bits).
///
/// On x86_64 targets, this automatically uses the SSE2 SIMD implementation.
/// On other targets, it uses the portable implementation which the compiler
/// auto-vectorizes effectively.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct State(pub(crate) [u32; 12]);

impl State {
    /// Create a new state.
    #[inline(always)]
    pub const fn new() -> Self {
        Self([0; 12])
    }

    /// Get a mutable view of the state as bytes.
    #[inline(always)]
    pub const fn as_bytes_mut(&mut self) -> &mut [u8; 48] {
        // SAFETY: This is safe because:
        // - `[u32; 12]` and `[u8; 48]` have the same size (48 bytes).
        // - Both types have the same alignment requirements, the source is only stricter.
        // - u32 and u8 are both valid for any bit pattern.
        // - We're converting between valid representations of the same data.
        unsafe { core::mem::transmute(&mut self.0) }
    }

    /// Get an immutable view of the state as bytes.
    #[inline(always)]
    pub const fn as_bytes(&self) -> &[u8; 48] {
        // SAFETY: This is safe because:
        // - `[u32; 12]` and `[u8; 48]` have the same size (48 bytes).
        // - Both types have the same alignment requirements, the source is only stricter.
        // - u32 and u8 are both valid for any bit pattern.
        // - We're converting between valid representations of the same data.
        unsafe { core::mem::transmute(&self.0) }
    }
}

/// Apply the Gimli permutation to the state using SSE2 SIMD.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) fn gimli(state: &mut State) {
    // SAFETY: SSE2 is available on all x86_64 targets
    unsafe {
        sse2::gimli(state);
    }
}

/// Apply the Gimli permutation to the state using portable implementation.
#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub(crate) fn gimli(state: &mut State) {
    portable::gimli(state);
}

// Public benchmarking functions to compare implementations
#[doc(hidden)]
pub mod bench {
    pub use super::State;

    /// Apply Gimli permutation using portable implementation (for benchmarking).
    pub fn gimli_portable(state: &mut State) {
        super::portable::gimli(state);
    }

    /// Apply Gimli permutation using SIMD implementation (for benchmarking).
    ///
    /// On x86_64, this uses hand-written SSE2 for ~2x speedup.
    /// On other platforms, this is an alias for portable (compiler auto-vectorizes effectively).
    pub fn gimli_simd(state: &mut State) {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: SSE2 is available on all x86_64 targets
            unsafe {
                super::sse2::gimli(state);
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            super::portable::gimli(state);
        }
    }
}
