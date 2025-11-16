extern crate std;
use super::*;
use std::println;
use std::string::{String, ToString};
use std::vec::Vec;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_aead_roundtrip() {
    let key = [1u8; KEY_SIZE];
    let nonce = [2u8; NONCE_SIZE];
    let plaintext = b"Hello, Gimli AEAD!";
    let associated_data = b"associated data";

    // Encrypt
    let mut buffer = *plaintext;
    let tag = encrypt_in_place(&key, &nonce, associated_data, &mut buffer);

    // Decrypt
    decrypt_in_place(&key, &nonce, associated_data, &mut buffer, &tag)
        .expect("Decryption should succeed");

    assert_eq!(&buffer, plaintext);
}

#[test]
fn test_in_place_roundtrip() {
    let key = [42u8; KEY_SIZE];
    let nonce = [99u8; NONCE_SIZE];
    let original_data = b"In-place encryption!";
    let associated_data = b"metadata";

    let mut buffer = [0u8; 20];
    buffer.copy_from_slice(original_data);

    // Encrypt in-place
    let tag = encrypt_in_place(&key, &nonce, associated_data, &mut buffer);

    // Buffer should now contain ciphertext (different from plaintext)
    assert_ne!(&buffer[..], original_data);

    // Decrypt in-place
    decrypt_in_place(&key, &nonce, associated_data, &mut buffer, &tag)
        .expect("Decryption should succeed");

    // Should recover original data
    assert_eq!(&buffer[..], original_data);
}

struct TestVector {
    count: usize,
    key: [u8; KEY_SIZE],
    nonce: [u8; NONCE_SIZE],
    plaintext: Vec<u8>,
    associated_data: Vec<u8>,
    expected_ciphertext_and_tag: Vec<u8>,
}

fn parse_test_vectors() -> Vec<TestVector> {
    let test_data = include_str!("../../LWC_AEAD_KAT_256_128.txt");
    let mut vectors = Vec::new();

    let mut count = 0;
    let mut key_hex = String::new();
    let mut nonce_hex = String::new();
    let mut plaintext_hex = String::new();
    let mut associated_data_hex = String::new();
    let mut ciphertext_hex = String::new();

    for line in test_data.lines() {
        let line = line.trim();
        if line.is_empty() {
            // Process the test vector
            if !key_hex.is_empty() {
                let key_bytes = hex_to_bytes(&key_hex);
                let nonce_bytes = hex_to_bytes(&nonce_hex);
                let plaintext_bytes = if plaintext_hex.is_empty() {
                    Vec::new()
                } else {
                    hex_to_bytes(&plaintext_hex)
                };
                let associated_data_bytes = if associated_data_hex.is_empty() {
                    Vec::new()
                } else {
                    hex_to_bytes(&associated_data_hex)
                };
                let ciphertext_and_tag_bytes = hex_to_bytes(&ciphertext_hex);

                let mut key = [0u8; KEY_SIZE];
                key.copy_from_slice(&key_bytes);

                let mut nonce = [0u8; NONCE_SIZE];
                nonce.copy_from_slice(&nonce_bytes);

                vectors.push(TestVector {
                    count,
                    key,
                    nonce,
                    plaintext: plaintext_bytes,
                    associated_data: associated_data_bytes,
                    expected_ciphertext_and_tag: ciphertext_and_tag_bytes,
                });
            }

            // Reset for next test
            key_hex.clear();
            nonce_hex.clear();
            plaintext_hex.clear();
            associated_data_hex.clear();
            ciphertext_hex.clear();
        } else if let Some(stripped) = line.strip_prefix("Count = ") {
            count = stripped.parse().unwrap();
        } else if let Some(stripped) = line.strip_prefix("Key = ") {
            key_hex = stripped.to_string();
        } else if let Some(stripped) = line.strip_prefix("Nonce = ") {
            nonce_hex = stripped.to_string();
        } else if let Some(stripped) = line.strip_prefix("PT = ") {
            plaintext_hex = stripped.to_string();
        } else if let Some(stripped) = line.strip_prefix("AD = ") {
            associated_data_hex = stripped.to_string();
        } else if let Some(stripped) = line.strip_prefix("CT = ") {
            ciphertext_hex = stripped.to_string();
        }
    }

    vectors
}

#[test]
fn test_all_official_vectors() {
    let vectors = parse_test_vectors();

    // Under miri, only test every 20th vector to keep test time reasonable
    // Full coverage is still validated in regular test runs
    #[cfg(miri)]
    let test_vectors = vectors.iter().step_by(20);
    #[cfg(miri)]
    let test_vectors_len = test_vectors.clone().count();

    #[cfg(not(miri))]
    let test_vectors = vectors.iter();

    for vector in test_vectors {
        // Encrypt in-place
        let mut buffer = vector.plaintext.clone();
        let tag = encrypt_in_place(
            &vector.key,
            &vector.nonce,
            &vector.associated_data,
            &mut buffer,
        );

        // CT field contains ciphertext + tag concatenated
        let expected_length = vector.plaintext.len() + TAG_SIZE;
        assert_eq!(
            vector.expected_ciphertext_and_tag.len(),
            expected_length,
            "Count {}: Ciphertext+tag length mismatch",
            vector.count
        );

        // Verify ciphertext
        if !vector.plaintext.is_empty() {
            assert_eq!(
                &buffer,
                &vector.expected_ciphertext_and_tag[..vector.plaintext.len()],
                "Count {}: Ciphertext mismatch",
                vector.count
            );
        }

        // Verify tag
        assert_eq!(
            &tag[..],
            &vector.expected_ciphertext_and_tag[vector.plaintext.len()..],
            "Count {}: Tag mismatch",
            vector.count
        );

        // Decrypt and verify
        decrypt_in_place(
            &vector.key,
            &vector.nonce,
            &vector.associated_data,
            &mut buffer,
            &tag,
        )
        .unwrap_or_else(|_| panic!("Count {}: Decryption failed", vector.count));
        assert_eq!(
            &buffer, &vector.plaintext,
            "Count {}: Plaintext mismatch",
            vector.count
        );
    }

    #[cfg(miri)]
    println!(
        "Successfully tested {} of {} test vectors under miri",
        test_vectors_len,
        vectors.len()
    );

    #[cfg(not(miri))]
    println!("Successfully tested {} test vectors", vectors.len());
}

#[test]
fn test_authentication_failed() {
    let key = [1u8; KEY_SIZE];
    let nonce = [2u8; NONCE_SIZE];
    let plaintext = b"Hello, Gimli!";
    let associated_data = b"test";

    let mut buffer = *plaintext;
    let tag = encrypt_in_place(&key, &nonce, associated_data, &mut buffer);

    // Modify the tag to make authentication fail
    let mut bad_tag = tag;
    bad_tag[0] ^= 1;

    let result = decrypt_in_place(&key, &nonce, associated_data, &mut buffer, &bad_tag);

    assert_eq!(result, Err(AuthenticationFailed));
}
