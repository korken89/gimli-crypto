# gimli-crypto

A `no_std` compatible Rust implementation of the Gimli cryptographic permutation and its applications:
- AEAD (`aead/gimli24v1`): Authenticated Encryption with Associated Data
- Hash (`hash/gimli24v1`): Cryptographic hash function

Based on the [Gimli specification](https://gimli.cr.yp.to/) by Bernstein et al.

## Usage

### AEAD Encryption (In-Place)

```rust
use gimli_crypto::{encrypt_in_place, decrypt_in_place, KEY_SIZE, NONCE_SIZE};

let key = [0u8; KEY_SIZE];
let nonce = [1u8; NONCE_SIZE]; // MUST be unique per encryption!
let mut data = *b"Secret message!!";
let aad = b"public header";

// Encrypt in-place
let tag = encrypt_in_place(&key, &nonce, aad, &mut data);

// Decrypt in-place with authentication
decrypt_in_place(&key, &nonce, aad, &mut data, &tag)
    .expect("authentication failed");

assert_eq!(&data, b"Secret message!!");
```

### AEAD Encryption (RustCrypto Trait)

```rust
use gimli_crypto::GimliAead;
use aead::{AeadInPlace, KeyInit};
use aead::generic_array::GenericArray;

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
```

### Cryptographic Hash

```rust
use gimli_crypto::{hash, Hasher};

// One-shot hashing
let digest = hash(b"Hello, Gimli!");
assert_eq!(digest.len(), 32); // 256-bit output

// Incremental hashing
let mut hasher = Hasher::new();
hasher.update(b"Hello, ");
hasher.update(b"Gimli!");
let digest2 = hasher.finalize();

assert_eq!(digest, digest2);
```

### Hash (RustCrypto Digest Trait)

```rust
use gimli_crypto::GimliHash;
use digest::Digest;

let mut hasher = GimliHash::new();
hasher.update(b"Hello, ");
hasher.update(b"Gimli!");
let result = hasher.finalize();
```

## References

- [Gimli specification paper](https://cryptojedi.org/papers/gimlinistr2-20190927.pdf)
- [Gimli website](https://gimli.cr.yp.to/)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
