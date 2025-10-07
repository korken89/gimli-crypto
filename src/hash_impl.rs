//! # `hash/gimli24v1` implementation
//!
//! This module implements the `hash/gimli24v1` cryptographic hash function using a sponge
//! construction based on the Gimli permutation.
//!
//! # Sponge Construction
//!
//! The hash uses:
//! - Rate: 16 bytes (128 bits) - data absorbed per permutation
//! - Capacity: 32 bytes (256 bits) - security parameter
//! - Output: 32 bytes (256 bits)
//!
//! # Security
//!
//! `hash/gimli24v1` provides 256-bit security against collision attacks and 128-bit security
//! against preimage attacks (limited by the sponge capacity).
//!
//! # Usage
//!
//! ```
//! use gimli_crypto::{hash, Hasher};
//!
//! // One-shot hashing.
//! let digest = hash(b"Hello, World!");
//!
//! // Incremental hashing.
//! let mut hasher = Hasher::new();
//! hasher.update(b"Hello, ");
//! hasher.update(b"World!");
//! let digest2 = hasher.finalize();
//!
//! assert_eq!(digest, digest2);
//! ```

use crate::RATE;
use crate::gimli::{State, gimli};

/// `hash/gimli24v1` hash output size in bytes.
pub const HASH_SIZE: usize = 32;

/// Domain separation byte for XOF (extendable output function).
const DOMAIN_XOF: u8 = 0x1f;

/// Padding marker byte.
const PADDING_MARKER: u8 = 0x80;

/// Hash arbitrary-length input data using `hash/gimli24v1`.
///
/// This does not need any internal temporary buffer compared to the [`Hasher`] implementation.
///
/// # Example
///
/// ```
/// use gimli_crypto::hash;
///
/// let data = b"Hello, Gimli!";
/// let digest = hash(data);
/// assert_eq!(digest.len(), 32);
/// ```
pub fn hash(input: &[u8]) -> [u8; HASH_SIZE] {
    let mut state = State::new();

    // Absorb phase: process input in RATE-sized blocks.
    let mut iter = input.chunks_exact(RATE);

    for chunk in &mut iter {
        let state_bytes = state.as_bytes_mut();
        for i in 0..RATE {
            state_bytes[i] ^= chunk[i];
        }
        gimli(&mut state);
    }

    // Absorb final block with padding.
    let remainder = iter.remainder();
    let state_bytes = state.as_bytes_mut();
    for i in 0..remainder.len() {
        state_bytes[i] ^= remainder[i];
    }

    // Padding: domain separation at current position, padding marker at end of rate.
    state_bytes[remainder.len()] ^= DOMAIN_XOF;
    state_bytes[RATE - 1] ^= PADDING_MARKER;

    gimli(&mut state);

    // Squeeze phase: extract output.
    let mut output = [0u8; HASH_SIZE];

    // First block (16 bytes).
    output[..RATE].copy_from_slice(&state.as_bytes()[..RATE]);

    gimli(&mut state);

    // Second block (16 bytes).
    output[RATE..].copy_from_slice(&state.as_bytes()[..RATE]);

    output
}

/// Hasher for incremental hashing.
///
/// # Example
///
/// ```
/// use gimli_crypto::Hasher;
///
/// let mut hasher = Hasher::new();
/// hasher.update(b"Hello, ");
/// hasher.update(b"Gimli!");
/// let digest = hasher.finalize();
/// ```
#[derive(Clone)]
pub struct Hasher {
    state: State,
    buffer: [u8; RATE],
    buffer_len: usize,
}

impl Hasher {
    /// Create a new hasher.
    pub const fn new() -> Self {
        Self {
            state: State::new(),
            buffer: [0u8; RATE],
            buffer_len: 0,
        }
    }

    /// Update the hasher with more data.
    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;

        // TODO: Should it be optimized for reading full blocks from the input after the buffer
        // is full and incorporated in the state?
        while pos < data.len() {
            // Copy as much as we can: either all remaining input, or until buffer is full.
            let available = (data.len() - pos).min(RATE - self.buffer_len);
            self.buffer[self.buffer_len..self.buffer_len + available]
                .copy_from_slice(&data[pos..pos + available]);
            self.buffer_len += available;
            pos += available;

            // Full buffer, absorb it.
            if self.buffer_len == RATE {
                let state_bytes = self.state.as_bytes_mut();
                for i in 0..RATE {
                    state_bytes[i] ^= self.buffer[i];
                }
                gimli(&mut self.state);

                self.buffer_len = 0;
            }
        }
    }

    /// Finalize the hash and return the digest.
    pub fn finalize(mut self) -> [u8; HASH_SIZE] {
        // Process buffered data with padding.
        let state_bytes = self.state.as_bytes_mut();
        for i in 0..self.buffer_len {
            state_bytes[i] ^= self.buffer[i];
        }

        // Padding: domain separation at current position, padding marker at end of rate.
        state_bytes[self.buffer_len] ^= DOMAIN_XOF;
        state_bytes[RATE - 1] ^= PADDING_MARKER;

        gimli(&mut self.state);

        // Squeeze phase.
        let mut output = [0u8; HASH_SIZE];
        output[..RATE].copy_from_slice(&self.state.as_bytes()[..RATE]);

        gimli(&mut self.state);

        output[RATE..].copy_from_slice(&self.state.as_bytes()[..RATE]);

        output
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
