#![no_std]
#![doc = include_str!("../README.md")]

mod aead_impl;
mod gimli;
mod hash_impl;

mod rustcrypto_aead;
mod rustcrypto_hash;

pub use aead_impl::{AuthenticationFailed, Tag, decrypt_in_place, encrypt_in_place};
pub use hash_impl::{HASH_SIZE, Hasher, hash};
pub use rustcrypto_aead::GimliAead;
pub use rustcrypto_hash::GimliHash;

pub use aead::{self, AeadInPlace, KeyInit}; // For `GimliAead` users
pub use digest::{self, Digest, Update}; // For `GimpiHash` users

/// Gimli state size in bytes (48 bytes = 12 u32 words).
const STATE_SIZE: usize = 48;

/// Gimli nonce size in bytes.
pub const NONCE_SIZE: usize = 16;

/// Gimli key size in bytes.
pub const KEY_SIZE: usize = 32;

/// Gimli tag size in bytes.
pub const TAG_SIZE: usize = 16;

/// Gimli rate in bytes.
const RATE: usize = 16;

/// Last byte index of state (used for domain separation).
const STATE_LAST_BYTE: usize = STATE_SIZE - 1;
