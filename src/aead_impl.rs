//! # `aead/gimli24v1` implementation
//!
//! This module implements the `aead/gimli24v1` authenticated encryption with associated data
//! (AEAD) cipher using a sponge-based construction on the Gimli permutation.
//!
//! # Usage
//!
//! This module provides `no_std`-compatible in-place encryption/decryption:
//!
//! ```
//! use gimli_crypto::{encrypt_in_place, decrypt_in_place, KEY_SIZE, NONCE_SIZE};
//!
//! let key = [0u8; KEY_SIZE];
//! let nonce = [1u8; NONCE_SIZE];
//! let mut data = *b"Secret message";
//! let aad = b"public header";
//!
//! // Encrypt in-place.
//! let tag = encrypt_in_place(&key, &nonce, aad, &mut data);
//!
//! // Decrypt in-place with authentication.
//! decrypt_in_place(&key, &nonce, aad, &mut data, &tag)
//!     .expect("authentication failed");
//!
//! assert_eq!(&data, b"Secret message");
//! ```
//!
//! For allocating APIs with separate input/output buffers, use the RustCrypto [`Aead`](crate::rustcrypto::GimliAead) trait.

use crate::gimli::{State, gimli};
use crate::{KEY_SIZE, NONCE_SIZE, RATE, STATE_LAST_BYTE, TAG_SIZE};
use subtle::ConstantTimeEq;

/// Authentication tag (16 bytes).
pub type Tag = [u8; TAG_SIZE];

/// Authentication tag verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticationFailed;

/// Initialize the Gimli AEAD state with key and nonce.
fn initialize(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE]) -> State {
    let mut state = State::new();
    let state_bytes = state.as_bytes_mut();

    // Load nonce (16 bytes) into state[0..16].
    state_bytes[..16].copy_from_slice(nonce);

    // Load key (32 bytes) into state[16..48].
    state_bytes[16..].copy_from_slice(key);

    gimli(&mut state);

    state
}

/// Process associated data.
fn process_aad(state: &mut State, associated_data: &[u8]) {
    let mut iter = associated_data.chunks_exact(RATE);

    // Process full blocks.
    for chunk in iter.by_ref() {
        let state_bytes = state.as_bytes_mut();
        for i in 0..RATE {
            state_bytes[i] ^= chunk[i];
        }
        gimli(state);
    }

    // Process remainder with domain separation.
    let remainder = iter.remainder();
    let state_bytes = state.as_bytes_mut();
    for i in 0..remainder.len() {
        state_bytes[i] ^= remainder[i];
    }

    state_bytes[remainder.len()] ^= 1;
    state_bytes[STATE_LAST_BYTE] ^= 1;

    gimli(state);
}

/// Encrypt plaintext using Gimli AEAD (in-place)
///
/// Encrypts the data in `buffer` in-place and returns the authentication tag.
/// The buffer contains plaintext on input and ciphertext on output.
#[must_use]
pub fn encrypt_in_place(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    associated_data: &[u8],
    buffer: &mut [u8],
) -> Tag {
    let mut state = initialize(key, nonce);

    // Process associated data.
    process_aad(&mut state, associated_data);

    // Process plaintext in-place.
    let mut iter = buffer.chunks_exact_mut(RATE);

    // Process full blocks.
    for chunk in &mut iter {
        let state_bytes = state.as_bytes_mut();

        for i in 0..RATE {
            state_bytes[i] ^= chunk[i];
        }
        chunk.copy_from_slice(&state_bytes[..16]);

        gimli(&mut state);
    }

    // Process remainder with domain separation.
    let remainder = iter.into_remainder();
    let state_bytes = state.as_bytes_mut();
    for i in 0..remainder.len() {
        state_bytes[i] ^= remainder[i];
    }
    remainder.copy_from_slice(&state_bytes[..remainder.len()]);

    state_bytes[remainder.len()] ^= 1;
    state_bytes[STATE_LAST_BYTE] ^= 1;

    gimli(&mut state);

    // Generate tag.
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&state.as_bytes()[..TAG_SIZE]);
    tag
}

/// Decrypt ciphertext using Gimli AEAD (in-place)
///
/// Decrypts the data in `buffer` in-place if authentication succeeds.
/// The buffer contains ciphertext on input and plaintext on output.
pub fn decrypt_in_place(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    associated_data: &[u8],
    buffer: &mut [u8],
    tag: &Tag,
) -> Result<(), AuthenticationFailed> {
    let mut state = initialize(key, nonce);

    // Process associated data.
    process_aad(&mut state, associated_data);

    // Process full blocks.
    let mut iter = buffer.chunks_exact_mut(RATE);
    for chunk in &mut iter {
        let state_bytes = state.as_bytes_mut();

        for i in 0..RATE {
            let ciphertext_byte = chunk[i];
            chunk[i] = state_bytes[i] ^ ciphertext_byte;
            state_bytes[i] = ciphertext_byte;
        }

        gimli(&mut state);
    }

    // Process remainder with domain separation.
    let state_bytes = state.as_bytes_mut();
    let remainder = iter.into_remainder();
    for i in 0..remainder.len() {
        let ciphertext_byte = remainder[i];
        remainder[i] = state_bytes[i] ^ ciphertext_byte;
        state_bytes[i] = ciphertext_byte;
    }

    state_bytes[remainder.len()] ^= 1;
    state_bytes[STATE_LAST_BYTE] ^= 1;

    gimli(&mut state);

    // Verify tag using constant-time comparison.
    let computed_tag = &state.as_bytes()[..TAG_SIZE];
    if computed_tag.ct_eq(tag).into() {
        Ok(())
    } else {
        Err(AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests;
