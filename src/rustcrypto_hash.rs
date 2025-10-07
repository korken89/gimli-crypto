//! # RustCrypto Digest trait implementation
//!
//! This module provides implementations of the RustCrypto `digest` traits for Gimli hash.

use crate::Hasher as GimliHasher;
use digest::{
    HashMarker, Output, OutputSizeUser, Reset,
    block_buffer::Eager,
    consts::U32,
    core_api::{
        Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore, UpdateCore,
    },
};

/// `hash/gimli24v1` hash function implementing RustCrypto digest traits.
#[derive(Clone, Default)]
pub struct GimliHashCore {
    hasher: GimliHasher,
}

impl OutputSizeUser for GimliHashCore {
    type OutputSize = U32;
}

impl BlockSizeUser for GimliHashCore {
    type BlockSize = U32; // Block size is not strictly defined for sponge constructions.
}

impl BufferKindUser for GimliHashCore {
    type BufferKind = Eager;
}

impl UpdateCore for GimliHashCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.hasher.update(block.as_slice());
        }
    }
}

impl FixedOutputCore for GimliHashCore {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        // Process any remaining buffered data.
        let pos = buffer.get_pos();
        if pos > 0 {
            let data = buffer.get_data();
            self.hasher.update(&data[..pos]);
        }

        let result = core::mem::take(&mut self.hasher).finalize();
        out.copy_from_slice(&result);
    }
}

impl Reset for GimliHashCore {
    #[inline]
    fn reset(&mut self) {
        self.hasher = GimliHasher::new();
    }
}

impl HashMarker for GimliHashCore {}

/// `hash/gimli24v1` hash function implementing RustCrypto digest traits.
pub type GimliHash = CoreWrapper<GimliHashCore>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HASH_SIZE;
    use digest::Digest;

    #[test]
    fn hash_basic() {
        let mut hasher = GimliHash::new();
        hasher.update(b"Hello, World!");
        let result = hasher.finalize();

        assert_eq!(result.len(), HASH_SIZE);
    }

    #[test]
    fn hash_incremental() {
        let mut hasher1 = GimliHash::new();
        hasher1.update(b"Hello, ");
        hasher1.update(b"World!");
        let result1 = hasher1.finalize();

        let mut hasher2 = GimliHash::new();
        hasher2.update(b"Hello, World!");
        let result2 = hasher2.finalize();

        assert_eq!(result1, result2);
    }

    #[test]
    fn hash_empty() {
        extern crate std;
        use std::vec::Vec;

        let hasher = GimliHash::new();
        let result = hasher.finalize();

        // Test vector for empty input
        fn hex_to_bytes(hex: &str) -> Vec<u8> {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        }

        let expected =
            hex_to_bytes("b0634b2c0b082aedc5c0a2fe4ee3adcfc989ec05de6f00addb04b3aaac271f67");
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn hash_reset() {
        use digest::Reset;

        let mut hasher = GimliHash::new();
        hasher.update(b"First message");
        Reset::reset(&mut hasher);
        hasher.update(b"Second message");
        let result1 = hasher.finalize();

        let mut hasher2 = GimliHash::new();
        hasher2.update(b"Second message");
        let result2 = hasher2.finalize();

        assert_eq!(result1, result2);
    }

    #[test]
    fn hash_clone() {
        let mut hasher1 = GimliHash::new();
        hasher1.update(b"Common prefix");

        let mut hasher2 = hasher1.clone();

        hasher1.update(b" - branch 1");
        hasher2.update(b" - branch 2");

        let result1 = hasher1.finalize();
        let result2 = hasher2.finalize();

        assert_ne!(result1, result2);
    }
}
