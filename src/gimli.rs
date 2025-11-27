//! # Gimli permutation implementation
//!
//! The Gimli permutation operates on a 384-bit state as 12 32-bit words.

use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(target_arch = "aarch64")]
mod neon;
#[cfg(any(not(any(target_arch = "aarch64", target_arch = "x86_64")), test))]
mod portable;
#[cfg(target_arch = "x86_64")]
mod sse2;

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
/// On x86_64 targets, this automatically uses the SSE2 SIMD implementation.
/// On other targets, it uses the portable implementation.
#[cfg(target_arch = "aarch64")]
pub(crate) fn gimli(state: &mut State) {
    // SAFETY: NEON is available on all aarch64 targets
    unsafe {
        neon::gimli(state);
    }
}

/// Apply the Gimli permutation to the state using SSE2 SIMD.
#[cfg(target_arch = "x86_64")]
pub(crate) fn gimli(state: &mut State) {
    // SAFETY: SSE2 is available on all x86_64 targets
    unsafe {
        sse2::gimli(state);
    }
}

/// Apply the Gimli permutation to the state using portable implementation.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(crate) fn gimli(state: &mut State) {
    portable::gimli(state);
}
