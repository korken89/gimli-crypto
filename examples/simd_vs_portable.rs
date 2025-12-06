//! Benchmark comparing SIMD vs portable Gimli implementations.
//!
//! This example encrypts 1 GB of random data using both the SIMD-optimized
//! and portable implementations of the Gimli permutation, measuring the
//! performance difference.
//!
//! **Performance characteristics by platform:**
//! - **x86_64**: Hand-written SSE2 provides ~2x speedup over portable
//! - **Other platforms**: Compiler auto-vectorizes portable effectively (minimal difference)
//!
//! Run with: cargo run --release --example simd_vs_portable

use gimli_crypto::{bench, KEY_SIZE, NONCE_SIZE};
use std::time::Instant;

const ONE_GB: usize = 1024 * 1024 * 1024; // 1 GB
const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB chunks

/// Encrypt data using a specific Gimli permutation implementation.
fn encrypt_with_impl<F>(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    data: &mut [u8],
    gimli_fn: F,
) where
    F: Fn(&mut bench::State),
{
    use gimli_crypto::bench::State;

    // Initialize state with key and nonce
    let mut state = State::new();
    let state_bytes: &mut [u8; 48] = unsafe {
        std::mem::transmute(state.as_bytes_mut())
    };

    // Load nonce (16 bytes) into state[0..16]
    state_bytes[..16].copy_from_slice(nonce);

    // Load key (32 bytes) into state[16..48]
    state_bytes[16..].copy_from_slice(key);

    gimli_fn(&mut state);

    // Process data in 16-byte blocks
    const RATE: usize = 16;
    let mut iter = data.chunks_exact_mut(RATE);

    for chunk in &mut iter {
        let state_bytes = state.as_bytes_mut();

        for i in 0..RATE {
            state_bytes[i] ^= chunk[i];
        }
        chunk.copy_from_slice(&state_bytes[..16]);

        gimli_fn(&mut state);
    }

    // Process remainder
    let remainder = iter.into_remainder();
    let state_bytes = state.as_bytes_mut();
    for i in 0..remainder.len() {
        state_bytes[i] ^= remainder[i];
    }
    remainder.copy_from_slice(&state_bytes[..remainder.len()]);
}

fn main() {
    println!("Gimli SIMD vs Portable Benchmark");
    println!("=================================");

    #[cfg(target_arch = "x86_64")]
    println!("Platform: x86_64 - Comparing hand-written SSE2 vs portable\n");

    #[cfg(not(target_arch = "x86_64"))]
    println!("Platform: {} - Both use portable (auto-vectorized)\n", std::env::consts::ARCH);

    // Generate random key and nonce
    println!("Generating random key and nonce...");
    let key: [u8; KEY_SIZE] = std::array::from_fn(|_| rand::random());
    let nonce: [u8; NONCE_SIZE] = std::array::from_fn(|_| rand::random());

    println!("Generating 1 GB of random data...");
    let mut data_simd = vec![0u8; ONE_GB];
    let mut data_portable = vec![0u8; ONE_GB];

    // Fill with random data
    for i in (0..ONE_GB).step_by(CHUNK_SIZE) {
        let end = (i + CHUNK_SIZE).min(ONE_GB);
        for byte in &mut data_simd[i..end] {
            *byte = rand::random();
        }
    }

    // Copy for portable version
    data_portable.copy_from_slice(&data_simd);

    println!("Data prepared. Starting benchmarks...\n");

    // Benchmark SIMD version
    println!("Running SIMD version...");
    let start_simd = Instant::now();
    encrypt_with_impl(&key, &nonce, &mut data_simd, bench::gimli_simd);
    let duration_simd = start_simd.elapsed();

    println!("SIMD completed in: {:.2?}", duration_simd);
    let throughput_simd = (ONE_GB as f64) / duration_simd.as_secs_f64() / (1024.0 * 1024.0);
    println!("SIMD throughput: {:.2} MB/s\n", throughput_simd);

    // Benchmark portable version
    println!("Running portable version...");
    let start_portable = Instant::now();
    encrypt_with_impl(&key, &nonce, &mut data_portable, bench::gimli_portable);
    let duration_portable = start_portable.elapsed();

    println!("Portable completed in: {:.2?}", duration_portable);
    let throughput_portable = (ONE_GB as f64) / duration_portable.as_secs_f64() / (1024.0 * 1024.0);
    println!("Portable throughput: {:.2} MB/s\n", throughput_portable);

    // Calculate speedup
    let speedup = duration_portable.as_secs_f64() / duration_simd.as_secs_f64();
    println!("=================================");
    println!("Results Summary:");
    println!("=================================");
    println!("SIMD:     {:.2?} ({:.2} MB/s)", duration_simd, throughput_simd);
    println!("Portable: {:.2?} ({:.2} MB/s)", duration_portable, throughput_portable);
    println!("Speedup:  {:.2}x", speedup);

    // Verify both produce the same output
    if data_simd == data_portable {
        println!("\n✓ Both implementations produce identical results");
    } else {
        println!("\n✗ WARNING: Implementations produce different results!");
    }
}
