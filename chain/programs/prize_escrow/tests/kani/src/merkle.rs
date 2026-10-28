//! merkle.rs: compute_leaf_hash, hash_pair and verify_proof. Every input is symbolic: the escrow,
//! each leaf's claimant and amount, the claim presented and every sibling of its proof.
//!
//! In two layers:
//! - The lemmas (the last four harnesses). Three run the real compute_leaf_hash and hash_pair
//!   under the keccak oracle (oracle::keccak_hashv): a leaf is the prefixed hash of its claim,
//!   byte for byte, and binds it; no leaf is ever a pair; a pair hashes its children smaller
//!   first and binds them in either order. The fourth: verify_proof is the fold of hash_pair up
//!   the siblings.
//! - The tree proofs run the real verify_proof over trees whose leaves and pairs come from the
//!   node model (oracle::model_leaf, model_pair), which assumes exactly what the lemmas prove of
//!   the real functions and nothing more. With the real functions under the byte-level oracle the
//!   three-leaf tree ran out of memory; on the node model all five sizes verify.
//!
//! The trees are the off-chain builder's shape for 1 to 5 leaves (tests/support/mod.rs
//! merkle_tree: pairs hashed with hash_pair, an odd node moved up a level unpaired), which covers
//! a single leaf, a pair, an odd node at the first level, a full level and an odd node at two
//! levels. The builder also sorts the leaf hashes first; the leaves here are in any order, so
//! every sorted order is among them. For a tree of any size, the lemmas carry the proofs level by
//! level from the root down: verify_proof is the fold, so a proof that verifies ends in a pair equal
//! to the root's, whose children it must then be (a pair binds its children); at the bottom the
//! presented leaf equals a node of the tree, which is no pair (no leaf is a pair), so a leaf, whose
//! claim it then is (a leaf binds its claim).

use {
    crate::oracle::{self, eq32, holds},
    anchor_lang::prelude::Pubkey,
    prize_escrow::merkle::{compute_leaf_hash, hash_pair, verify_proof, LEAF_PREFIX},
};

fn key() -> Pubkey {
    Pubkey::new_from_array(kani::any())
}

/// `a == b`, compared as words (oracle::eq32), not through memcmp's byte loop.
fn same_key(a: &Pubkey, b: &Pubkey) -> bool {
    eq32(&a.to_bytes(), &b.to_bytes())
}

/// The claim (e, c, a) is (escrow, claimant, amount).
fn is_claim(e: &Pubkey, c: &Pubkey, a: u64, escrow: &Pubkey, claim: &(Pubkey, u64)) -> bool {
    same_key(e, escrow) && same_key(c, &claim.0) && a == claim.1
}

/// The deepest proof a tree of up to 5 leaves has: ceil(log2 5).
const DEPTH: usize = 3;

/// A tree's leaf hashes, root, and each leaf's proof (leaf to root) and its length.
struct Tree<const N: usize> {
    leaves: [[u8; 32]; N],
    root: [u8; 32],
    proofs: [[[u8; 32]; DEPTH]; N],
    lens: [usize; N],
}

/// The off-chain builder's tree over `leaves`, in their order. Each node carries the set of
/// leaves under it (a bitmask), so a pair's sibling is appended to the proof of every one of them.
fn build<const N: usize>(leaves: [[u8; 32]; N]) -> Tree<N> {
    assert!((1..=1 << DEPTH).contains(&N));
    let mut level = leaves;
    let mut under: [u8; N] = core::array::from_fn(|i| 1 << i);
    let mut proofs = [[[0u8; 32]; DEPTH]; N];
    let mut lens = [0usize; N];
    let mut width = N;
    while width > 1 {
        let (mut i, mut next) = (0, 0);
        while i < width {
            if i + 1 < width {
                let (left, right) = (level[i], level[i + 1]);
                for leaf in 0..N {
                    if (under[i] >> leaf) & 1 == 1 {
                        proofs[leaf][lens[leaf]] = right;
                        lens[leaf] += 1;
                    }
                    if (under[i + 1] >> leaf) & 1 == 1 {
                        proofs[leaf][lens[leaf]] = left;
                        lens[leaf] += 1;
                    }
                }
                level[next] = hash_pair(&left, &right);
                under[next] = under[i] | under[i + 1];
                i += 2;
            } else {
                level[next] = level[i];
                under[next] = under[i];
                i += 1;
            }
            next += 1;
        }
        width = next;
    }
    Tree {
        leaves,
        root: level[0],
        proofs,
        lens,
    }
}

/// ceil(log2 n) for n >= 1.
fn depth_of(n: usize) -> usize {
    (usize::BITS - (n - 1).leading_zeros()) as usize
}

/// A tree of `N` symbolic claims under a symbolic escrow, and its claims.
fn any_tree<const N: usize>() -> (Pubkey, [(Pubkey, u64); N], Tree<N>) {
    let escrow = key();
    let claims: [(Pubkey, u64); N] = core::array::from_fn(|_| (key(), kani::any()));
    let tree = build::<N>(core::array::from_fn(|i| {
        compute_leaf_hash(&escrow, &claims[i].0, claims[i].1)
    }));
    (escrow, claims, tree)
}

/// What a claimant presents: any escrow, claimant and amount (claim recomputes the leaf from
/// them).
fn any_claim() -> (Pubkey, Pubkey, u64, [u8; 32]) {
    let (e, c, a) = (key(), key(), kani::any::<u64>());
    (e, c, a, compute_leaf_hash(&e, &c, a))
}

/// Every leaf of the tree proves into its root with its own proof, of at most ceil(log2 N)
/// siblings.
fn every_leaf_proves_into_the_root<const N: usize>() {
    let (_, _, tree) = any_tree::<N>();
    for i in 0..N {
        assert!(tree.lens[i] <= depth_of(N));
        assert!(verify_proof(
            &tree.proofs[i][..tree.lens[i]],
            &tree.root,
            &tree.leaves[i]
        ));
    }
    kani::cover!(true, "a tree is built and every proof checked");
}

/// The proof of each leaf in `at` proves no claim but that leaf's: no other claimant, amount or
/// escrow.
fn a_proof_proves_only_its_own_claim<const N: usize>(at: &[usize]) {
    let (escrow, claims, tree) = any_tree::<N>();
    let (e, c, a, leaf) = any_claim();
    for &i in at {
        if verify_proof(&tree.proofs[i][..tree.lens[i]], &tree.root, &leaf) {
            kani::cover!(true, "a claim verifies with a leaf's own proof");
            assert!(is_claim(&e, &c, a, &escrow, &claims[i]));
        }
    }
}

/// No siblings at all, of any length up to ceil(log2 N) + 1, prove a claim the tree lacks, or a
/// claim of the tree under another escrow.
fn no_proof_proves_a_claim_the_tree_lacks<const N: usize>() {
    let (escrow, claims, tree) = any_tree::<N>();
    let (e, c, a, leaf) = any_claim();
    let siblings: [[u8; 32]; DEPTH + 1] = kani::any();
    for d in 0..=depth_of(N) + 1 {
        if verify_proof(&siblings[..d], &tree.root, &leaf) {
            kani::cover!(true, "some siblings prove a claim");
            assert!(claims
                .iter()
                .any(|claim| is_claim(&e, &c, a, &escrow, claim)));
        }
    }
}

// The three properties above on trees of 1 to 5 leaves, each its own harness, on the node model.
kani::stub_set!(
    node_model,
    stub(
        prize_escrow::merkle::compute_leaf_hash,
        crate::oracle::model_leaf
    ),
    stub(prize_escrow::merkle::hash_pair, crate::oracle::model_pair),
);

#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn every_leaf_of_1_proves_into_the_root() {
    every_leaf_proves_into_the_root::<1>();
}

#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn a_proof_in_a_tree_of_1_proves_only_its_own_claim() {
    a_proof_proves_only_its_own_claim::<1>(&[0]);
}

#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn no_proof_proves_a_claim_a_tree_of_1_lacks() {
    no_proof_proves_a_claim_the_tree_lacks::<1>();
}

#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn every_leaf_of_2_proves_into_the_root() {
    every_leaf_proves_into_the_root::<2>();
}

#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn a_proof_in_a_tree_of_2_proves_only_its_own_claim() {
    a_proof_proves_only_its_own_claim::<2>(&[0, 1]);
}

#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn no_proof_proves_a_claim_a_tree_of_2_lacks() {
    no_proof_proves_a_claim_the_tree_lacks::<2>();
}

#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn every_leaf_of_3_proves_into_the_root() {
    every_leaf_proves_into_the_root::<3>();
}

#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn a_proof_in_a_tree_of_3_proves_only_its_own_claim() {
    a_proof_proves_only_its_own_claim::<3>(&[0, 1, 2]);
}

#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn no_proof_proves_a_claim_a_tree_of_3_lacks() {
    no_proof_proves_a_claim_the_tree_lacks::<3>();
}

#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn every_leaf_of_4_proves_into_the_root() {
    every_leaf_proves_into_the_root::<4>();
}

#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn a_proof_in_a_tree_of_4_proves_only_its_own_claim() {
    a_proof_proves_only_its_own_claim::<4>(&[0, 1, 2, 3]);
}

#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn no_proof_proves_a_claim_a_tree_of_4_lacks() {
    no_proof_proves_a_claim_the_tree_lacks::<4>();
}

#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn every_leaf_of_5_proves_into_the_root() {
    every_leaf_proves_into_the_root::<5>();
}

#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn a_proof_in_a_tree_of_5_proves_only_its_own_claim() {
    // Every leaf of the 4-leaf tree took 19 minutes; at five, one leaf per position up to
    // symmetry. Leaves 0 to 3 sit at depth 3 and trade places by swapping the two leaves of a pair
    // or the two pairs, which leaves every node as it was (a pair hashes its children in either
    // order: a_pair_hashes_its_children_smaller_first), and every claim is symbolic, so leaf 0
    // stands for all four; leaf 4 is the odd node, moved up to depth 1.
    a_proof_proves_only_its_own_claim::<5>(&[0, 4]);
}

#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn no_proof_proves_a_claim_a_tree_of_5_lacks() {
    no_proof_proves_a_claim_the_tree_lacks::<5>();
}

/// One level of any proof: two pairs hash alike exactly when they have the same two children, in
/// either order. With the two lemmas after it (a leaf binds its claim, and no inner node is a
/// leaf) and verify_proof being the fold of hash_pair up the siblings, it carries the trees'
/// proofs to a tree of any size, level by level from the root down.
#[kani::proof]
#[kani::stub(solana_keccak_hasher::hashv, crate::oracle::keccak_hashv)]
#[kani::unwind(70)]
fn a_pair_binds_its_two_children() {
    let (x, s, l, r): ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) = kani::any();
    let alike = eq32(&hash_pair(&x, &s), &hash_pair(&l, &r));
    kani::cover!(alike, "two pairs hash alike");
    kani::cover!(!alike, "two pairs hash apart");
    assert_eq!(
        alike,
        (eq32(&x, &l) && eq32(&s, &r)) || (eq32(&x, &r) && eq32(&s, &l))
    );
}

/// verify_proof is the fold of hash_pair from the leaf up the siblings, compared with the root, for
/// proofs of 0 to 4 siblings (a fact about verify_proof's loop, whatever hash_pair is: on the node
/// model, which keeps it fast).
#[kani::proof]
#[kani::use_stub_set(node_model)]
#[kani::unwind(70)]
fn verify_proof_folds_the_siblings_up_to_the_root() {
    let (leaf, root): ([u8; 32], [u8; 32]) = kani::any();
    let siblings: [[u8; 32]; 4] = kani::any();
    let mut node = leaf;
    for d in 0..=4 {
        let verified = verify_proof(&siblings[..d], &root, &leaf);
        kani::cover!(verified, "a proof verifies");
        assert_eq!(verified, eq32(&node, &root));
        if d < 4 {
            node = hash_pair(&node, &siblings[d]);
        }
    }
}

/// A leaf is keccak256(0x00 || keccak256(escrow || claimant || u64le(amount))), byte for byte;
/// it binds all three (two claims share a leaf exactly when they are the same claim); and no
/// inner node is ever a leaf (its preimage is 64 bytes, a leaf's 33), so an inner node can never
/// be claimed as a leaf with the rest of its proof.
#[kani::proof]
#[kani::stub(solana_keccak_hasher::hashv, crate::oracle::keccak_hashv)]
#[kani::unwind(70)]
fn a_leaf_is_the_prefixed_hash_of_its_escrow_claimant_and_amount() {
    let (e, c, a) = (key(), key(), kani::any::<u64>());
    let leaf = compute_leaf_hash(&e, &c, a);
    let keccak = oracle::keccak();
    assert_eq!(keccak.queries(), 2);
    let (inner, len) = keccak.preimage(0);
    assert!(len == 72 && holds(&inner, 0, e.as_ref()) && holds(&inner, 32, c.as_ref()));
    assert!(holds(&inner, 64, &a.to_le_bytes()));
    let (outer, len) = keccak.preimage(1);
    assert!(len == 1 + 32 && holds(&outer, 0, LEAF_PREFIX));
    assert!(holds(&outer, 1, &keccak.digest(0)));
    assert!(eq32(&leaf, &keccak.digest(1)));

    let (e2, c2, a2) = (key(), key(), kani::any::<u64>());
    let alike = eq32(&compute_leaf_hash(&e2, &c2, a2), &leaf);
    kani::cover!(alike, "two claims share a leaf");
    assert_eq!(alike, is_claim(&e2, &c2, a2, &e, &(c, a)));
    let (x, y): ([u8; 32], [u8; 32]) = kani::any();
    assert!(!eq32(&hash_pair(&x, &y), &leaf));
}

/// A pair hashes its two children smaller first, so its hash is the same in either order; an
/// empty proof proves exactly the root, and one sibling proves either child into their pair.
#[kani::proof]
#[kani::stub(solana_keccak_hasher::hashv, crate::oracle::keccak_hashv)]
#[kani::unwind(70)]
fn a_pair_hashes_its_children_smaller_first() {
    let (a, b): ([u8; 32], [u8; 32]) = kani::any();
    let ab = hash_pair(&a, &b);
    let (pair, len) = oracle::keccak().preimage(0);
    assert_eq!(len, 64);
    let (first, second): ([u8; 32], [u8; 32]) = (
        pair[..32].try_into().unwrap(),
        pair[32..64].try_into().unwrap(),
    );
    assert!(first <= second);
    assert!((eq32(&first, &a) && eq32(&second, &b)) || (eq32(&first, &b) && eq32(&second, &a)));
    assert!(eq32(&hash_pair(&b, &a), &ab));
    assert!(verify_proof(&[], &a, &a));
    assert_eq!(verify_proof(&[], &a, &b), eq32(&a, &b));
    assert!(verify_proof(&[b], &ab, &a));
    assert!(verify_proof(&[a], &ab, &b));
    kani::cover!(first < second, "two distinct children");
}
