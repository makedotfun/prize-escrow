//! Merkle leaves and proof verification for prize claims.
//!
//! `verify_proof`, `hash_pair` and `verify_proof_or_error`, and the unit tests below, are ported
//! from solana-foundation/rewards, program/src/utils/merkle_utils.rs at commit 4f5a8c6
//! (https://github.com/solana-foundation/rewards), under the MIT License:
//!
//!   MIT License
//!
//!   Copyright (c) 2026 Solana Foundation
//!
//!   Permission is hereby granted, free of charge, to any person obtaining a copy of this
//!   software and associated documentation files (the "Software"), to deal in the Software
//!   without restriction, including without limitation the rights to use, copy, modify, merge,
//!   publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
//!   to whom the Software is furnished to do so, subject to the following conditions:
//!
//!   The above copyright notice and this permission notice shall be included in all copies or
//!   substantial portions of the Software.
//!
//!   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
//!   INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
//!   PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
//!   FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
//!   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//!   DEALINGS IN THE SOFTWARE.
//!
//! Changes from upstream:
//! - keccak256 goes through `solana_keccak_hasher::hashv` (the sol_keccak256 syscall on chain)
//!   instead of const_crypto; the bytes are the same.
//! - The leaf drops the vesting schedule and adds the escrow address as a domain separator, so
//!   a proof for one escrow never verifies against another escrow's root:
//!   `leaf = keccak256(0x00 || keccak256(escrow || claimant || u64le(total_amount)))`.
//! - `hash_pair` is public (the integration tests build trees with it), and
//!   `verify_proof_or_error` returns EscrowError::InvalidMerkleProof.
//! - The schedule-specific leaf tests became escrow-domain tests; a keccak known-answer test
//!   pins the hash function.
//!
//! Tree shape (the off-chain builder must match): pairs are hashed in sorted order (smaller
//! first), so a proof is just the sibling list from leaf to root.

use anchor_lang::prelude::*;
use solana_keccak_hasher::hashv;

use crate::error::EscrowError;

/// Leaf prefix to prevent second preimage attacks.
pub const LEAF_PREFIX: &[u8] = &[0];
pub const HASH_SIZE: usize = 32;

fn keccak256(data: &[u8]) -> [u8; 32] {
    hashv(&[data]).to_bytes()
}

/// Compute the merkle leaf hash of a claim.
///
/// The leaf format is:
/// `keccak256(LEAF_PREFIX || keccak256(escrow || claimant || u64le(total_amount)))`
pub fn compute_leaf_hash(escrow: &Pubkey, claimant: &Pubkey, total_amount: u64) -> [u8; 32] {
    let inner_hash = hashv(&[
        escrow.as_ref(),
        claimant.as_ref(),
        &total_amount.to_le_bytes(),
    ])
    .to_bytes();

    // Outer hash: hash(LEAF_PREFIX || inner_hash)
    hashv(&[LEAF_PREFIX, &inner_hash]).to_bytes()
}

/// Verify a merkle proof against a root.
///
/// The proof is an array of sibling hashes from leaf to root.
/// For each level, if the current hash is less than the sibling,
/// hash(current || sibling), otherwise hash(sibling || current).
/// This sorted pair ordering ensures deterministic tree construction.
pub fn verify_proof(proof: &[[u8; 32]], root: &[u8; 32], leaf: &[u8; 32]) -> bool {
    let mut computed_hash = *leaf;

    for sibling in proof {
        computed_hash = hash_pair(&computed_hash, sibling);
    }

    computed_hash == *root
}

/// Hash two nodes together in sorted order (smaller first).
/// This ensures deterministic tree construction regardless of proof ordering.
pub fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; HASH_SIZE * 2];
    if a < b {
        data[0..HASH_SIZE].copy_from_slice(a);
        data[HASH_SIZE..HASH_SIZE * 2].copy_from_slice(b);
    } else {
        data[0..HASH_SIZE].copy_from_slice(b);
        data[HASH_SIZE..HASH_SIZE * 2].copy_from_slice(a);
    }
    keccak256(&data)
}

/// Verify a merkle proof and return error if invalid.
pub fn verify_proof_or_error(proof: &[[u8; 32]], root: &[u8; 32], leaf: &[u8; 32]) -> Result<()> {
    if verify_proof(proof, root, leaf) {
        Ok(())
    } else {
        Err(EscrowError::InvalidMerkleProof.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ESCROW: Pubkey = Pubkey::new_from_array([7u8; 32]);

    #[test]
    fn test_keccak256_known_answer() {
        // keccak256("") (Keccak-256, not NIST SHA3-256, whose empty digest is a7ffc6f8...).
        let empty: [u8; 32] = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(keccak256(&[]), empty);
    }

    #[test]
    fn test_compute_leaf_hash_layout() {
        let claimant = Pubkey::new_from_array([1u8; 32]);
        let mut inner = Vec::with_capacity(72);
        inner.extend_from_slice(ESCROW.as_ref());
        inner.extend_from_slice(claimant.as_ref());
        inner.extend_from_slice(&1000u64.to_le_bytes());
        let mut outer = vec![0u8];
        outer.extend_from_slice(&keccak256(&inner));

        assert_eq!(
            compute_leaf_hash(&ESCROW, &claimant, 1000),
            keccak256(&outer)
        );
    }

    #[test]
    fn test_compute_leaf_hash_deterministic() {
        let claimant = Pubkey::new_from_array([1u8; 32]);

        let hash1 = compute_leaf_hash(&ESCROW, &claimant, 1000);
        let hash2 = compute_leaf_hash(&ESCROW, &claimant, 1000);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_leaf_hash_different_inputs() {
        let claimant1 = Pubkey::new_from_array([1u8; 32]);
        let claimant2 = Pubkey::new_from_array([2u8; 32]);

        let hash1 = compute_leaf_hash(&ESCROW, &claimant1, 1000);
        let hash2 = compute_leaf_hash(&ESCROW, &claimant2, 1000);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_leaf_hash_different_amounts() {
        let claimant = Pubkey::new_from_array([1u8; 32]);

        let hash1 = compute_leaf_hash(&ESCROW, &claimant, 1000);
        let hash2 = compute_leaf_hash(&ESCROW, &claimant, 2000);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_leaf_hash_different_escrows() {
        let claimant = Pubkey::new_from_array([1u8; 32]);
        let other_escrow = Pubkey::new_from_array([8u8; 32]);

        let hash1 = compute_leaf_hash(&ESCROW, &claimant, 1000);
        let hash2 = compute_leaf_hash(&other_escrow, &claimant, 1000);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_leaf_proof_does_not_cross_escrows() {
        let claimant1 = Pubkey::new_from_array([1u8; 32]);
        let claimant2 = Pubkey::new_from_array([2u8; 32]);
        let other_escrow = Pubkey::new_from_array([8u8; 32]);

        let leaf1 = compute_leaf_hash(&ESCROW, &claimant1, 1000);
        let leaf2 = compute_leaf_hash(&ESCROW, &claimant2, 2000);
        let root = hash_pair(&leaf1, &leaf2);

        let replayed = compute_leaf_hash(&other_escrow, &claimant1, 1000);
        assert!(!verify_proof(&[leaf2], &root, &replayed));
    }

    #[test]
    fn test_hash_pair_commutative() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        let hash1 = hash_pair(&a, &b);
        let hash2 = hash_pair(&b, &a);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_pair_deterministic() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        let hash1 = hash_pair(&a, &b);
        let hash2 = hash_pair(&a, &b);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_verify_proof_single_leaf() {
        let claimant = Pubkey::new_from_array([1u8; 32]);
        let leaf = compute_leaf_hash(&ESCROW, &claimant, 1000);
        let root = leaf;
        let proof: Vec<[u8; 32]> = vec![];

        assert!(verify_proof(&proof, &root, &leaf));
    }

    #[test]
    fn test_verify_proof_two_leaves() {
        let claimant1 = Pubkey::new_from_array([1u8; 32]);
        let claimant2 = Pubkey::new_from_array([2u8; 32]);

        let leaf1 = compute_leaf_hash(&ESCROW, &claimant1, 1000);
        let leaf2 = compute_leaf_hash(&ESCROW, &claimant2, 2000);

        let root = hash_pair(&leaf1, &leaf2);

        assert!(verify_proof(&[leaf2], &root, &leaf1));
        assert!(verify_proof(&[leaf1], &root, &leaf2));
    }

    #[test]
    fn test_verify_proof_four_leaves() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut addr = [0u8; 32];
                addr[0] = i;
                compute_leaf_hash(
                    &ESCROW,
                    &Pubkey::new_from_array(addr),
                    1000 * (i as u64 + 1),
                )
            })
            .collect();

        let n01 = hash_pair(&leaves[0], &leaves[1]);
        let n23 = hash_pair(&leaves[2], &leaves[3]);
        let root = hash_pair(&n01, &n23);

        assert!(verify_proof(&[leaves[1], n23], &root, &leaves[0]));
        assert!(verify_proof(&[leaves[0], n23], &root, &leaves[1]));
        assert!(verify_proof(&[leaves[3], n01], &root, &leaves[2]));
        assert!(verify_proof(&[leaves[2], n01], &root, &leaves[3]));
    }

    #[test]
    fn test_verify_proof_invalid_proof() {
        let claimant1 = Pubkey::new_from_array([1u8; 32]);
        let claimant2 = Pubkey::new_from_array([2u8; 32]);

        let leaf1 = compute_leaf_hash(&ESCROW, &claimant1, 1000);
        let leaf2 = compute_leaf_hash(&ESCROW, &claimant2, 2000);

        let root = hash_pair(&leaf1, &leaf2);

        let wrong_sibling = [99u8; 32];
        assert!(!verify_proof(&[wrong_sibling], &root, &leaf1));
    }

    #[test]
    fn test_verify_proof_invalid_leaf() {
        let claimant1 = Pubkey::new_from_array([1u8; 32]);
        let claimant2 = Pubkey::new_from_array([2u8; 32]);

        let leaf1 = compute_leaf_hash(&ESCROW, &claimant1, 1000);
        let leaf2 = compute_leaf_hash(&ESCROW, &claimant2, 2000);

        let root = hash_pair(&leaf1, &leaf2);

        let wrong_leaf = compute_leaf_hash(&ESCROW, &claimant1, 9999);
        assert!(!verify_proof(&[leaf2], &root, &wrong_leaf));
    }

    #[test]
    fn test_verify_proof_or_error_success() {
        let claimant = Pubkey::new_from_array([1u8; 32]);
        let leaf = compute_leaf_hash(&ESCROW, &claimant, 1000);
        let root = leaf;
        let proof: Vec<[u8; 32]> = vec![];

        assert!(verify_proof_or_error(&proof, &root, &leaf).is_ok());
    }

    #[test]
    fn test_verify_proof_or_error_failure() {
        let claimant = Pubkey::new_from_array([1u8; 32]);
        let leaf = compute_leaf_hash(&ESCROW, &claimant, 1000);
        let wrong_root = [99u8; 32];
        let proof: Vec<[u8; 32]> = vec![];

        assert_eq!(
            verify_proof_or_error(&proof, &wrong_root, &leaf),
            Err(EscrowError::InvalidMerkleProof.into())
        );
    }
}
