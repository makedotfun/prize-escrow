//! The hash model the hashing proofs run under: keccak256 (`solana_keccak_hasher::hashv`, the
//! merkle leaves and pairs) and sha256 (`solana_sha256_hasher::hashv`, the result and commit
//! commitments), each stubbed by a lazily sampled random oracle that never collides.
//!
//! A query looks its bytes up among the queries the harness made so far: the same bytes get the
//! same digest (the oracle is a function), new bytes a fresh nondeterministic digest, assumed
//! distinct from every digest handed out before (no collision). A proof under it therefore holds
//! for every digest assignment that has no collision among the inputs queried: all a property
//! asks of the real hash is collision resistance, which no model checker can establish and these
//! proofs assume. The digests are otherwise unconstrained, so a claimant who "guesses" a digest
//! in advance is modelled too.
//!
//! A preimage is kept as the slices hashv was given, each cut into pieces of at most 32 bytes and
//! held as words (see Words), which keeps the solver's problem small. Two queries with the same
//! bytes but cut differently would look different, so every query also records its cut, and the
//! oracle asserts that two queries of the same length were cut the same way: in this program
//! every call site hashes its own fixed shape, and no two shapes share a length (keccak: 72, 33
//! and 64 bytes; sha256: 102 and 96), so equal pieces is equal bytes, and the assertion would
//! fail otherwise.
//!
//! Every preimage is kept, so a harness can also assert the exact bytes a function hashes. The
//! real functions' known answers stay with the unit tests (src/merkle.rs) and tests/commitment.rs.

// rustc sees no caller of the stubs: only Kani's #[kani::stub] reaches them.
#![allow(dead_code)]

use solana_hash::Hash;

/// The most pieces a preimage is cut into (result_commitment's: the 30-byte domain, two hashes and
/// the total's 8 bytes).
pub const MAX_PIECES: usize = 4;
const _: () = assert!(
    MAX_PIECES == 4,
    "cut_as and same_pieces compare four pieces"
);
/// The longest preimage, result_commitment's.
pub const MAX_INPUT: usize = 32 * MAX_PIECES;
/// The most queries one harness makes (the five-leaf tree makes 52).
pub const MAX_QUERIES: usize = 56;

/// 32 bytes as two little-endian u128 words. Comparing words is one bitvector comparison each,
/// where comparing byte arrays goes through CBMC's memcmp model, a loop over every byte: with
/// [u8; 32] keys the two-leaf tree spent 200 s in memcmp's symbolic execution alone.
type Words = [u128; 2];

fn words(bytes: &[u8; 32]) -> Words {
    let (lo, hi) = bytes.split_at(16);
    [
        u128::from_le_bytes(lo.try_into().unwrap()),
        u128::from_le_bytes(hi.try_into().unwrap()),
    ]
}

fn bytes_of(words: &Words) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&words[0].to_le_bytes());
    bytes[16..].copy_from_slice(&words[1].to_le_bytes());
    bytes
}

fn same(a: &Words, b: &Words) -> bool {
    a[0] == b[0] && a[1] == b[1]
}

#[derive(Clone, Copy)]
struct Preimage {
    len: usize,
    /// Each piece's length (0 past the last).
    cut: [usize; MAX_PIECES],
    /// The pieces, zero past their lengths.
    pieces: [Words; MAX_PIECES],
}

impl Preimage {
    const EMPTY: Preimage = Preimage {
        len: 0,
        cut: [0; MAX_PIECES],
        pieces: [[0; 2]; MAX_PIECES],
    };

    fn of(vals: &[&[u8]]) -> Preimage {
        let mut preimage = Preimage::EMPTY;
        let mut n = 0;
        for val in vals {
            for piece in val.chunks(32) {
                assert!(n < MAX_PIECES, "a preimage past the oracle's room");
                let mut padded = [0u8; 32];
                padded[..piece.len()].copy_from_slice(piece);
                preimage.pieces[n] = words(&padded);
                preimage.cut[n] = piece.len();
                preimage.len += piece.len();
                n += 1;
            }
        }
        preimage
    }

    /// Cut the same way as `other` (written out: a loop is more for symbolic execution to walk).
    fn cut_as(&self, other: &Preimage) -> bool {
        let (a, b) = (&self.cut, &other.cut);
        a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
    }

    /// The same pieces as `other` (cut the same way, so the same bytes).
    fn same_pieces(&self, other: &Preimage) -> bool {
        let (a, b) = (&self.pieces, &other.pieces);
        same(&a[0], &b[0]) && same(&a[1], &b[1]) && same(&a[2], &b[2]) && same(&a[3], &b[3])
    }

    /// The bytes, laid end to end (zero past `len`).
    fn bytes(&self) -> [u8; MAX_INPUT] {
        let mut bytes = [0u8; MAX_INPUT];
        let mut at = 0;
        for n in 0..MAX_PIECES {
            let piece = &bytes_of(&self.pieces[n])[..self.cut[n]];
            bytes[at..at + piece.len()].copy_from_slice(piece);
            at += piece.len();
        }
        bytes
    }
}

pub struct Oracle {
    count: usize,
    preimage: [Preimage; MAX_QUERIES],
    digest: [Words; MAX_QUERIES],
}

impl Oracle {
    const fn new() -> Self {
        Oracle {
            count: 0,
            preimage: [Preimage::EMPTY; MAX_QUERIES],
            digest: [[0; 2]; MAX_QUERIES],
        }
    }

    fn query(&mut self, vals: &[&[u8]]) -> [u8; 32] {
        let preimage = Preimage::of(vals);
        assert!(
            self.count < MAX_QUERIES,
            "more queries than the oracle's room"
        );
        let mut digest: Words = kani::any();
        let mut seen = false;
        for i in 0..self.count {
            let before = &self.preimage[i];
            if before.len == preimage.len {
                assert!(before.cut_as(&preimage), "one length, two shapes");
                if before.same_pieces(&preimage) {
                    digest = self.digest[i];
                    seen = true;
                }
            }
        }
        if !seen {
            for i in 0..self.count {
                kani::assume(!same(&self.digest[i], &digest));
            }
        }
        self.preimage[self.count] = preimage;
        self.digest[self.count] = digest;
        self.count += 1;
        bytes_of(&digest)
    }

    /// The `i`th preimage queried, laid end to end, and its length.
    pub fn preimage(&self, i: usize) -> ([u8; MAX_INPUT], usize) {
        assert!(i < self.count, "no such query");
        (self.preimage[i].bytes(), self.preimage[i].len)
    }

    /// The digest the `i`th query returned.
    pub fn digest(&self, i: usize) -> [u8; 32] {
        assert!(i < self.count, "no such query");
        bytes_of(&self.digest[i])
    }

    pub fn queries(&self) -> usize {
        self.count
    }
}

static mut KECCAK: Oracle = Oracle::new();
static mut SHA256: Oracle = Oracle::new();

/// The keccak256 oracle's record (read it between calls, never across one).
pub fn keccak() -> &'static Oracle {
    // SAFETY: a harness is single-threaded, and the stubs' &mut never outlives their call.
    unsafe { &*core::ptr::addr_of!(KECCAK) }
}

/// The sha256 oracle's record (read it between calls, never across one).
pub fn sha256() -> &'static Oracle {
    // SAFETY: as keccak().
    unsafe { &*core::ptr::addr_of!(SHA256) }
}

/// Stands in for `solana_keccak_hasher::hashv` (#[kani::stub]).
pub fn keccak_hashv(vals: &[&[u8]]) -> Hash {
    // SAFETY: as keccak(); no other reference to KECCAK is live during the call.
    let oracle = unsafe { &mut *core::ptr::addr_of_mut!(KECCAK) };
    Hash::new_from_array(oracle.query(vals))
}

/// Stands in for `solana_sha256_hasher::hashv` (#[kani::stub]).
pub fn sha256_hashv(vals: &[&[u8]]) -> Hash {
    // SAFETY: as keccak_hashv.
    let oracle = unsafe { &mut *core::ptr::addr_of_mut!(SHA256) };
    Hash::new_from_array(oracle.query(vals))
}

/// `bytes[at..at + part.len()] == part`, byte by byte (memcmp's model would loop over them anyway).
pub fn holds(bytes: &[u8; MAX_INPUT], at: usize, part: &[u8]) -> bool {
    part.iter().enumerate().all(|(i, b)| bytes[at + i] == *b)
}

/// `a == b` for 32-byte values, as words (see Words).
pub fn eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    same(&words(a), &words(b))
}

// ------------------------------------------------------------------------------- the node model

/// The tree proofs' model, one level up: compute_leaf_hash and hash_pair themselves stubbed by
/// one collision-free oracle over claims and unordered pairs, keyed on words, with no byte
/// marshalling or byte-wise compares left (at the byte level the three-leaf tree ran out of
/// memory). It is sound for exactly what the byte-level lemmas in merkle.rs prove of the real
/// functions under the keccak oracle above: a leaf binds its escrow, claimant and amount; a pair
/// binds its two children in either order (it hashes them smaller first); and no leaf is ever a
/// pair. A node digest here is fresh unless the same claim or the same pair was hashed before,
/// and distinct from every digest before it, leaf or pair: every digest assignment the real
/// functions can produce without a keccak collision is one of this model's.
pub const MAX_NODES: usize = 56;

/// A node's key: a claim (escrow, claimant, amount) or an unordered pair (smaller, larger).
#[derive(Clone, Copy)]
struct Node {
    leaf: bool,
    key: [u128; 5],
}

impl Node {
    const EMPTY: Node = Node {
        leaf: false,
        key: [0; 5],
    };

    fn same(&self, other: &Node) -> bool {
        let (a, b) = (&self.key, &other.key);
        self.leaf == other.leaf
            && a[0] == b[0]
            && a[1] == b[1]
            && a[2] == b[2]
            && a[3] == b[3]
            && a[4] == b[4]
    }
}

pub struct NodeOracle {
    count: usize,
    node: [Node; MAX_NODES],
    digest: [Words; MAX_NODES],
}

impl NodeOracle {
    const fn new() -> Self {
        NodeOracle {
            count: 0,
            node: [Node::EMPTY; MAX_NODES],
            digest: [[0; 2]; MAX_NODES],
        }
    }

    fn query(&mut self, node: Node) -> [u8; 32] {
        assert!(self.count < MAX_NODES, "more nodes than the oracle's room");
        let mut digest: Words = kani::any();
        let mut seen = false;
        for i in 0..self.count {
            if self.node[i].same(&node) {
                digest = self.digest[i];
                seen = true;
            }
        }
        if !seen {
            for i in 0..self.count {
                kani::assume(!same(&self.digest[i], &digest));
            }
        }
        self.node[self.count] = node;
        self.digest[self.count] = digest;
        self.count += 1;
        bytes_of(&digest)
    }
}

static mut NODES: NodeOracle = NodeOracle::new();

/// `bytes` as two big-endian u128 words: their order is the bytes' lexicographic order.
fn ordered(bytes: &[u8; 32]) -> (u128, u128) {
    let (hi, lo) = bytes.split_at(16);
    (
        u128::from_be_bytes(hi.try_into().unwrap()),
        u128::from_be_bytes(lo.try_into().unwrap()),
    )
}

/// Stands in for `prize_escrow::merkle::compute_leaf_hash` (#[kani::stub]).
pub fn model_leaf(
    escrow: &anchor_lang::prelude::Pubkey,
    claimant: &anchor_lang::prelude::Pubkey,
    total_amount: u64,
) -> [u8; 32] {
    let (e, c) = (words(&escrow.to_bytes()), words(&claimant.to_bytes()));
    let node = Node {
        leaf: true,
        key: [e[0], e[1], c[0], c[1], u128::from(total_amount)],
    };
    // SAFETY: as keccak_hashv, for NODES.
    unsafe { &mut *core::ptr::addr_of_mut!(NODES) }.query(node)
}

/// Stands in for `prize_escrow::merkle::hash_pair` (#[kani::stub]): the smaller child first, as
/// a_pair_hashes_its_children_smaller_first proves of the real one, so the key is unordered.
pub fn model_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (first, second) = if ordered(a) < ordered(b) {
        (a, b)
    } else {
        (b, a)
    };
    let (x, y) = (words(first), words(second));
    let node = Node {
        leaf: false,
        key: [x[0], x[1], y[0], y[1], 0],
    };
    // SAFETY: as keccak_hashv, for NODES.
    unsafe { &mut *core::ptr::addr_of_mut!(NODES) }.query(node)
}
