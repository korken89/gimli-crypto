//! # RustCrypto AEAD trait implementation
//!
//! This module provides implementations of the RustCrypto `aead` traits for Gimli AEAD.

use crate::{KEY_SIZE, NONCE_SIZE, TAG_SIZE, decrypt_in_place, encrypt_in_place};
use aead::generic_array::GenericArray;
use aead::{
    AeadCore, AeadInPlace, Error, KeyInit, KeySizeUser,
    consts::{U16, U32},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// `aead/gimli24v1` cipher implementing RustCrypto traits.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GimliAead {
    key: [u8; KEY_SIZE],
}

impl KeySizeUser for GimliAead {
    type KeySize = U32;
}

impl KeyInit for GimliAead {
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        let mut s = Self {
            key: [0u8; KEY_SIZE],
        };
        s.key.copy_from_slice(key.as_slice());
        s
    }
}

impl AeadCore for GimliAead {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = aead::consts::U0;
}

/// Helper to convert between `GenericArray` and built-in array types. v0.14 does not make this
/// conversion easy in any sense.
#[inline(always)]
const fn ga_nonce_to_array(
    nonce: &GenericArray<u8, <GimliAead as AeadCore>::NonceSize>,
) -> &[u8; NONCE_SIZE] {
    // SAFETY: `GenericArray<T, N>` is `#[repr(transparent)]` over `[T; N]`,
    // guaranteeing identical layout. Transmuting `&GenericArray<u8, N>` to
    // `&[u8; N]` preserves the reference lifetime and validity.
    //
    // Preconditions verified at compile-time:
    // - Size equality: `mem::transmute` will fail to compile if
    //   `size_of::<GenericArray<T, N>>() != size_of::<[T; N]>()`
    // - Alignment: Both types have alignment of `T`
    unsafe { core::mem::transmute(nonce) }
}

/// Helper to convert between `GenericArray` and built-in array types. v0.14 does not make this
/// conversion easy in any sense.
#[inline(always)]
const fn ga_tag_to_array(
    tag: &GenericArray<u8, <GimliAead as AeadCore>::TagSize>,
) -> &[u8; TAG_SIZE] {
    // SAFETY: `GenericArray<T, N>` is `#[repr(transparent)]` over `[T; N]`,
    // guaranteeing identical layout. Transmuting `&GenericArray<u8, N>` to
    // `&[u8; N]` preserves the reference lifetime and validity.
    //
    // Preconditions verified at compile-time:
    // - Size equality: `mem::transmute` will fail to compile if
    //   `size_of::<GenericArray<T, N>>() != size_of::<[T; N]>()`
    // - Alignment: Both types have alignment of `T`
    unsafe { core::mem::transmute(tag) }
}

/// Helper to convert between `GenericArray` and built-in array types. v0.14 does not make this
/// conversion easy in any sense.
#[inline(always)]
const fn tag_array_to_ga(
    tag: [u8; TAG_SIZE],
) -> GenericArray<u8, <GimliAead as AeadCore>::TagSize> {
    // SAFETY: `GenericArray<T, N>` is `#[repr(transparent)]` over `[T; N]`,
    // guaranteeing identical layout. Transmuting owned `[u8; N]` to owned
    // `GenericArray<u8, N>` transfers ownership without copying and preserves
    // all bit patterns.
    //
    // Preconditions verified at compile-time:
    // - Size equality: `mem::transmute` will fail to compile if
    //   `size_of::<GenericArray<T, N>>() != size_of::<[T; N]>()`
    // - Alignment: Both types have alignment of `T`
    unsafe { core::mem::transmute(tag) }
}

impl AeadInPlace for GimliAead {
    #[inline]
    fn encrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>, Error> {
        let tag = encrypt_in_place(&self.key, ga_nonce_to_array(nonce), associated_data, buffer);

        Ok(tag_array_to_ga(tag))
    }

    #[inline]
    fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<(), Error> {
        decrypt_in_place(
            &self.key,
            ga_nonce_to_array(nonce),
            associated_data,
            buffer,
            ga_tag_to_array(tag),
        )
        .map_err(|_| Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aead::AeadInPlace;

    #[test]
    fn aead_roundtrip() {
        let key = GenericArray::from([1u8; 32]);
        let cipher = GimliAead::new(&key);

        let nonce = GenericArray::from([2u8; 16]);
        let plaintext = *b"Hello, RustCrypto AEAD!";
        let aad = b"associated data";

        let mut ciphertext = plaintext.clone();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, aad, &mut ciphertext)
            .expect("encryption failed");

        cipher
            .decrypt_in_place_detached(&nonce, aad, &mut ciphertext, &tag)
            .expect("decryption failed");

        assert_eq!(&ciphertext, b"Hello, RustCrypto AEAD!");
    }

    #[test]
    fn aead_in_place() {
        let key = GenericArray::from([42u8; 32]);
        let cipher = GimliAead::new(&key);

        let nonce = GenericArray::from([99u8; 16]);
        let aad = b"metadata";

        let mut buffer = *b"In-place test!  ";
        let original = buffer;

        let tag = cipher
            .encrypt_in_place_detached(&nonce, aad, &mut buffer)
            .expect("encryption failed");

        assert_ne!(&buffer, &original);

        cipher
            .decrypt_in_place_detached(&nonce, aad, &mut buffer, &tag)
            .expect("decryption failed");

        assert_eq!(&buffer, &original);
    }

    #[test]
    fn aead_wrong_tag() {
        let key = GenericArray::from([1u8; 32]);
        let cipher = GimliAead::new(&key);

        let nonce = GenericArray::from([2u8; 16]);
        let mut buffer = *b"Test message";

        let mut tag = cipher
            .encrypt_in_place_detached(&nonce, b"", &mut buffer)
            .expect("encryption failed");

        // Corrupt the tag
        tag[0] ^= 1;

        let result = cipher.decrypt_in_place_detached(&nonce, b"", &mut buffer, &tag);
        assert!(result.is_err());
    }
}
