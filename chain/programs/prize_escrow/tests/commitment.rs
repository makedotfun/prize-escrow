//! The result commitment (state::result_commitment) against the vectors the server shares
//! (tests/fixtures/chain/commitment-vectors.json, which server/chain/result.ts resultCommitment
//! reproduces too): sha256("agent-fun/result-commitment/v1" || result_sha256 || payout_root ||
//! u64le(total)). Host-side only: the release build runs the same function through the sol_sha256
//! syscall, which tests/lifecycle.rs checks against what post_result, challenge and
//! arbiter_resolve store.
//!
//! Run review 4: arbiter_resolve stored whatever root, document hash and total the arbiter
//! passed, under a commitment nobody had voted on. The result in force is now always one of the
//! two committed sides (Escrow::side and Escrow::apply, which settle's AltApplied and
//! arbiter_resolve both use), so its commitment is always the one of its own fields.

use {
    anchor_lang::prelude::Pubkey,
    prize_escrow::{
        result_commitment, ArbiterChoice, Escrow, EscrowStatus, RESULT_COMMITMENT_DOMAIN,
    },
    serde_json::Value,
};

const VECTORS_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/chain/commitment-vectors.json"
));

fn hex32(text: &Value) -> [u8; 32] {
    let text = text.as_str().expect("a hex string");
    assert_eq!(text.len(), 64, "{text}");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

#[test]
fn every_commitment_vector_matches_the_programs_result_commitment() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("the vectors parse");
    assert_eq!(doc["schema"], "agent-fun/commitment-vectors/v1");
    assert_eq!(
        doc["domain"].as_str().unwrap().as_bytes(),
        RESULT_COMMITMENT_DOMAIN
    );
    let vectors = doc["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 6);
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let total: u64 = v["total"].as_str().unwrap().parse().expect("a u64");
        assert_eq!(
            result_commitment(
                &hex32(&v["result_sha256"]),
                &hex32(&v["payout_root"]),
                total
            ),
            hex32(&v["commitment"]),
            "{name}"
        );
    }
}

#[test]
fn the_commitment_moves_with_the_root_and_the_total_not_only_the_document() {
    let result = [0xab; 32];
    let honest = result_commitment(&result, &[0xcd; 32], 1_500_000);
    // The finding behind the commitment: the same document hash with a self-paying root, or the
    // same root with another total, is a different result.
    assert_ne!(result_commitment(&result, &[0xce; 32], 1_500_000), honest);
    assert_ne!(result_commitment(&result, &[0xcd; 32], 1_500_001), honest);
    assert_ne!(
        result_commitment(&[0xac; 32], &[0xcd; 32], 1_500_000),
        honest
    );
    // Swapping the two hashes is another commitment too (the fields are not symmetric).
    assert_ne!(
        result_commitment(&[0xcd; 32], &[0xab; 32], 1_500_000),
        honest
    );
}

fn total_of(v: &Value) -> u64 {
    v["total"].as_str().unwrap().parse().expect("a u64")
}

/// An escrow as post_result (`posted`) and a winning challenge (`alt`, which attest or
/// arbiter_resolve records from its Challenge PDA) leave it, each side stored with the commitment
/// challenge computes.
fn disputed(posted: &Value, alt: &Value) -> Escrow {
    let side = |v: &Value| {
        let (result, root, total) = (
            hex32(&v["result_sha256"]),
            hex32(&v["payout_root"]),
            total_of(v),
        );
        (
            result,
            root,
            total,
            result_commitment(&result, &root, total),
        )
    };
    let (result_sha256, payout_root, total, commitment) = side(posted);
    let (alt_result_sha256, alt_payout_root, alt_total, alt_commitment) = side(alt);
    let key = Pubkey::new_unique();
    Escrow {
        bump: 255,
        decimals: 6,
        status: EscrowStatus::Frozen,
        k: 2,
        n: 3,
        competition_id: [1; 16],
        sponsor: key,
        resolver: key,
        compliance: key,
        arbiter: key,
        refund_to: key,
        mint: key,
        challenger: key,
        rules_sha256: [1; 32],
        entries_root: [2; 32],
        payout_root,
        result_sha256,
        kit_sha256: [5; 32],
        commitment,
        alt_result_sha256,
        alt_payout_root,
        alt_commitment,
        entries_count: 3,
        challenge_count: 1,
        total,
        total_claimed: 0,
        alt_total,
        bond_lamports: 2_000_000,
        resolver_bond: 2_000_000,
        challenger_bond: 2_000_000,
        entries_deadline: 1,
        final_end: 1,
        resolve_deadline: 2,
        challenge_window: 3,
        attest_window: 4,
        hold_window: 5,
        claim_window: 6,
        challenge_deadline: 7,
        attest_deadline: 8,
        claim_deadline: 0,
        hard_deadline: 9,
        votes_result: 1,
        votes_alt: 1,
        regraders: [key; 5],
        deposited: total,
        stop_base: 0,
        freeze_since: 0,
        freeze_until: 0,
        frozen_secs: 0,
        reveal_grace: 0,
        commit_bond: 0,
        pending_commits: 0,
        reserved: [0; 64],
    }
}

#[test]
fn either_side_applied_is_a_result_whose_commitment_is_its_own() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("the vectors parse");
    let vectors = doc["vectors"].as_array().unwrap();
    for pair in vectors.windows(2) {
        let (posted, alt) = (&pair[0], &pair[1]);
        let names = format!(
            "{} then {}",
            posted["name"].as_str().unwrap(),
            alt["name"].as_str().unwrap()
        );
        for (choice, vector) in [
            (ArbiterChoice::Posted, posted),
            (ArbiterChoice::Alternative, alt),
        ] {
            let mut escrow = disputed(posted, alt);
            let side = escrow.side(choice);
            assert_eq!(side.commitment, hex32(&vector["commitment"]), "{names}");
            escrow.apply(choice);
            assert_eq!(
                (
                    escrow.result_sha256,
                    escrow.payout_root,
                    escrow.total,
                    escrow.commitment
                ),
                (
                    side.result_sha256,
                    side.payout_root,
                    side.total,
                    side.commitment
                ),
                "{names}: {choice:?} applied"
            );
            assert_eq!(
                escrow.commitment,
                result_commitment(&escrow.result_sha256, &escrow.payout_root, escrow.total),
                "{names}: {choice:?} applied"
            );
        }
    }
}
