//! state.rs: result_commitment and commit_hash, under the sha256 oracle, every input symbolic.

use {
    crate::oracle::{self, eq32, holds},
    anchor_lang::prelude::Pubkey,
    prize_escrow::{commit_hash, result_commitment, RESULT_COMMITMENT_DOMAIN},
};

/// The result commitment is sha256(RESULT_COMMITMENT_DOMAIN || result_sha256 || payout_root ||
/// u64le(total)), byte for byte (server/chain/result.ts resultCommitment hashes the same bytes),
/// and binds all three: two results share a commitment exactly when their document hash, payout
/// root and total are all the same, so an honest document hash with another root or total is
/// another result, which a challenge or a regrader's vote can tell apart.
#[kani::proof]
#[kani::stub(solana_sha256_hasher::hashv, crate::oracle::sha256_hashv)]
#[kani::unwind(104)]
fn the_result_commitment_binds_the_document_the_root_and_the_total() {
    let (doc, root, total): ([u8; 32], [u8; 32], u64) = kani::any();
    let c = result_commitment(&doc, &root, total);
    let sha256 = oracle::sha256();
    assert_eq!(sha256.queries(), 1);
    let (bytes, len) = sha256.preimage(0);
    let at = RESULT_COMMITMENT_DOMAIN.len();
    assert_eq!(at, 30);
    assert_eq!(len, at + 32 + 32 + 8);
    assert!(holds(&bytes, 0, RESULT_COMMITMENT_DOMAIN));
    assert!(holds(&bytes, at, &doc) && holds(&bytes, at + 32, &root));
    assert!(holds(&bytes, at + 64, &total.to_le_bytes()));
    assert!(eq32(&c, &sha256.digest(0)));

    let (doc2, root2, total2): ([u8; 32], [u8; 32], u64) = kani::any();
    let alike = eq32(&result_commitment(&doc2, &root2, total2), &c);
    kani::cover!(alike, "two results share a commitment");
    assert_eq!(
        alike,
        eq32(&doc2, &doc) && eq32(&root2, &root) && total2 == total
    );
}

/// A challenge's commit is sha256(alt_commitment || challenger || salt), byte for byte, and binds
/// all three: nobody can reveal another alternative, or another challenger's commit, under it.
#[kani::proof]
#[kani::stub(solana_sha256_hasher::hashv, crate::oracle::sha256_hashv)]
#[kani::unwind(104)]
fn a_commit_binds_the_alternative_the_challenger_and_the_salt() {
    let (alt, salt): ([u8; 32], [u8; 32]) = kani::any();
    let who = Pubkey::new_from_array(kani::any());
    let h = commit_hash(&alt, &who, &salt);
    let sha256 = oracle::sha256();
    assert_eq!(sha256.queries(), 1);
    let (bytes, len) = sha256.preimage(0);
    assert_eq!(len, 96);
    assert!(holds(&bytes, 0, &alt) && holds(&bytes, 32, who.as_ref()) && holds(&bytes, 64, &salt));
    assert!(eq32(&h, &sha256.digest(0)));

    let (alt2, salt2): ([u8; 32], [u8; 32]) = kani::any();
    let who2 = Pubkey::new_from_array(kani::any());
    let alike = eq32(&commit_hash(&alt2, &who2, &salt2), &h);
    kani::cover!(alike, "two commits share a hash");
    assert_eq!(
        alike,
        eq32(&alt2, &alt) && eq32(&who2.to_bytes(), &who.to_bytes()) && eq32(&salt2, &salt)
    );
}

/// No commit hash is ever a result commitment (their preimages are 96 and 102 bytes), so a
/// commit's seed can never stand for a challenge's alternative or the reverse.
#[kani::proof]
#[kani::stub(solana_sha256_hasher::hashv, crate::oracle::sha256_hashv)]
#[kani::unwind(104)]
fn a_commit_is_never_a_result_commitment() {
    let (alt, salt, doc, root): ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) = kani::any();
    let who = Pubkey::new_from_array(kani::any());
    let total: u64 = kani::any();
    kani::cover!(true, "a commit and a result commitment are both hashed");
    assert!(!eq32(
        &commit_hash(&alt, &who, &salt),
        &result_commitment(&doc, &root, total)
    ));
}
