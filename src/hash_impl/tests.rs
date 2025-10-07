extern crate std;
use super::*;
use std::vec::Vec;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

// Test vectors from https://crypto.stackexchange.com/a/51026 after it was highlighted that the vectors in the paper were wrong.

#[test]
fn test_vector_0() {
    let digest = hash(b"");
    let expected = hex_to_bytes("b0634b2c0b082aedc5c0a2fe4ee3adcfc989ec05de6f00addb04b3aaac271f67");
    assert_eq!(digest.as_slice(), expected.as_slice());
}

#[test]
fn test_vector_1() {
    let digest = hash(b"There's plenty for the both of us, may the best Dwarf win.");
    let expected = hex_to_bytes("4afb3ff784c7ad6943d49cf5da79facfa7c4434e1ce44f5dd4b28f91a84d22c8");
    assert_eq!(digest.as_slice(), expected.as_slice());
}

#[test]
fn test_vector_2() {
    let digest = hash(b"If anyone was to ask for my opinion, which I note they're not, I'd say we were taking the long way around.");
    let expected = hex_to_bytes("ba82a16a7b224c15bed8e8bdc88903a4006bc7beda78297d96029203ef08e07c");
    assert_eq!(digest.as_slice(), expected.as_slice());
}

#[test]
fn test_vector_3() {
    let digest = hash(b"Speak words we can all understand!");
    let expected = hex_to_bytes("8dd4d132059b72f8e8493f9afb86c6d86263e7439fc64cbb361fcbccf8b01267");
    assert_eq!(digest.as_slice(), expected.as_slice());
}

#[test]
fn test_vector_4() {
    let digest = hash(b"It's true you don't see many Dwarf-women. And in fact, they are so alike in voice and appearance, that they are often mistaken for Dwarf-men. And this in turn has given rise to the belief that there are no Dwarf-women, and that Dwarves just spring out of holes in the ground! Which is, of course, ridiculous.");
    let expected = hex_to_bytes("8887a5367d961d6734ee1a0d4aee09caca7fd6b606096ff69d8ce7b9a496cd2f");
    assert_eq!(digest.as_slice(), expected.as_slice());
}

#[test]
fn test_incremental_vs_oneshot() {
    let message = b"Hello, Gimli! This is a test message.";

    // One-shot hash
    let oneshot = hash(message);

    // Incremental hash
    let mut hasher = Hasher::new();
    hasher.update(b"Hello, ");
    hasher.update(b"Gimli! ");
    hasher.update(b"This is a test message.");
    let incremental = hasher.finalize();

    assert_eq!(oneshot, incremental);
}

#[test]
fn test_incremental_various_splits() {
    let message = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let oneshot = hash(message);

    // Split at various boundaries
    let mut hasher = Hasher::new();
    hasher.update(&message[..10]);
    hasher.update(&message[10..20]);
    hasher.update(&message[20..]);
    let incremental = hasher.finalize();

    assert_eq!(oneshot, incremental);
}

#[test]
fn test_different_messages() {
    let digest1 = hash(b"message1");
    let digest2 = hash(b"message2");
    assert_ne!(digest1, digest2);
}
