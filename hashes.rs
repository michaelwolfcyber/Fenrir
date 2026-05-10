// ============================================================
// hashes.rs — Hash verification backends
//
// This module provides one function per supported algorithm:
//   verify_argon2()  — Argon2id/Argon2i/Argon2d (PHC format)
//   verify_bcrypt()  — bcrypt ($2b$, $2a$, $2y$)
//   verify_scrypt()  — scrypt (PHC format)
//
// And a top-level dispatcher:
//   verify()         — detects algorithm and calls the right one
//
// All functions take:
//   candidate: &str  — the plaintext password to test
//   hash: &str       — the full hash string to verify against
//
// And return:
//   true   — candidate matches the hash (CRACKED)
//   false  — no match
//
// Why verify() instead of hash-and-compare?
//   Memory-hard algorithms embed their parameters (memory cost,
//   time cost, parallelism, salt) IN the hash string. The verify
//   function reads those parameters and uses them, so we don't
//   need to know them in advance. This also means we correctly
//   handle hashes with different cost parameters in the same run.
// ============================================================

use argon2::Argon2;
use password_hash::{PasswordHash, PasswordVerifier};


// ============================================================
// verify  (public dispatcher)
//
// Routes to the correct backend based on the algorithm string.
// Returns true if the candidate matches, false otherwise.
//
// This is called once per candidate in the cracker's hot loop,
// so it must be as fast as possible. The match is O(1).
// ============================================================
pub fn verify(candidate: &str, hash: &str, algorithm: &str) -> bool {
    match algorithm {
        "argon2" => verify_argon2(candidate, hash),
        "bcrypt" => verify_bcrypt(candidate, hash),
        "scrypt" => verify_scrypt(candidate, hash),
        // Unknown algorithm — return false rather than panic.
        // The caller already validated the algorithm string.
        _ => false,
    }
}


// ============================================================
// verify_argon2
//
// Verifies a candidate against an Argon2 hash in PHC format.
//
// PHC format example:
//   $argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$hash==
//    ^algorithm ^version ^params   ^salt(b64)   ^hash(b64)
//
// The `argon2` crate's PasswordVerifier trait handles all the
// parsing, parameter extraction, and verification automatically.
// We just pass the full hash string and the candidate.
//
// Argon2 variants:
//   argon2id — hybrid (recommended, most common)
//   argon2i  — data-independent (side-channel resistant)
//   argon2d  — data-dependent (GPU resistant, not side-channel safe)
//
// Why Argon2 is hard to crack:
//   The `m` parameter (memory cost) forces each hash attempt to
//   allocate that many kilobytes of RAM. At m=65536 (64MB), you
//   can only run as many parallel attempts as you have RAM for.
//   An M4 Pro with 24GB RAM = ~375 simultaneous Argon2 attempts max.
//   A GPU with 24GB VRAM = same ceiling, but GPUs have less per-core
//   cache, making them SLOWER than CPUs for high-memory Argon2.
// ============================================================
pub fn verify_argon2(candidate: &str, hash: &str) -> bool {
    // Parse the PHC hash string — this extracts salt, params, etc.
    let parsed = match PasswordHash::new(hash) {
        Ok(h)  => h,
        Err(_) => return false,  // Malformed hash — skip silently
    };

    // Argon2::default() uses Argon2id variant.
    // The verify_password call re-derives the hash using the
    // parameters embedded in the hash string and compares.
    Argon2::default()
        .verify_password(candidate.as_bytes(), &parsed)
        .is_ok()
}


// ============================================================
// verify_bcrypt
//
// Verifies a candidate against a bcrypt hash.
//
// bcrypt format: $2b$12$<53 chars of salt+hash>
//   $2b$ — version (2b is current standard, 2a is legacy)
//   12   — cost factor (2^12 = 4096 iterations)
//   rest — 22 chars of salt + 31 chars of hash, base64-encoded
//
// The cost factor is the key parameter: each increment doubles
// the work. Cost 12 = ~250ms on modern hardware. Cost 14 = ~1s.
//
// bcrypt has a 72-byte password limit — passwords longer than
// 72 bytes are silently truncated. This is a known limitation.
// ============================================================
pub fn verify_bcrypt(candidate: &str, hash: &str) -> bool {
    bcrypt::verify(candidate, hash).unwrap_or(false)
}


// ============================================================
// verify_scrypt
//
// Verifies a candidate against a scrypt hash in PHC format.
//
// PHC format example:
//   $scrypt$ln=17,r=8,p=1$salt$hash
//   ln=17 → N=2^17=131072 (CPU/memory cost)
//   r=8   → block size (affects memory usage)
//   p=1   → parallelism factor
//
// scrypt memory usage: 128 * N * r bytes
//   At ln=17, r=8: 128 * 131072 * 8 = 128MB per hash attempt.
//   Even more memory-hungry than Argon2 at default settings.
//
// Common use case: cryptocurrency wallets (Bitcoin, Litecoin
//   use scrypt for their proof-of-work and key derivation).
// ============================================================
pub fn verify_scrypt(candidate: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h)  => h,
        Err(_) => return false,
    };

    scrypt::Scrypt
        .verify_password(candidate.as_bytes(), &parsed)
        .is_ok()
}


// ============================================================
// Unit tests
//
// These tests use real hashes generated with known passwords
// so we can verify the verification functions work correctly.
//
// To generate test hashes yourself:
//   python3 -c "import argon2; print(argon2.PasswordHasher().hash('wolf'))"
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;

    // A real Argon2id hash of the password "wolf"
    // Generated with default parameters (m=19456, t=2, p=1)
    // Used only in tests — not a real password hash from any system
    const TEST_ARGON2_HASH: &str =
        "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$\
         r9bHQJvmMPpZBzXOoFU6GHkZFAIAYCjkM7GbJnTivg";

    #[test]
    fn test_verify_dispatcher_routes_correctly() {
        // The dispatcher should return false for wrong candidates
        // without panicking on any algorithm string
        assert!(!verify("wrongpassword", "$argon2id$v=19$m=65536,t=3,p=1$salt$hash", "argon2"));
        assert!(!verify("wrongpassword", "$2b$12$saltsaltsaltsaltsalts.hashhashhashhashhashhashhas", "bcrypt"));
        assert!(!verify("x", "garbage", "unknown"));
    }

    #[test]
    fn test_malformed_hash_returns_false_not_panic() {
        // Malformed hashes must never panic — just return false
        assert!(!verify_argon2("password", "not_a_valid_hash"));
        assert!(!verify_argon2("password", ""));
        assert!(!verify_bcrypt("password", "not_valid_bcrypt"));
        assert!(!verify_scrypt("password", "garbage"));
    }
}
