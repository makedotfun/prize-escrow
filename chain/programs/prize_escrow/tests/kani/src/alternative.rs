//! state.rs: Escrow::record_alternative, which attest (a challenge's votes reaching k) and
//! arbiter_resolve (the arbiter choosing a challenge) write the winning alternative with, and
//! Escrow::clear_alternative, which arbiter_resolve undoes a recorded one with when the arbiter
//! keeps the posted result, on an Escrow and a ChallengeRecord every field of which is symbolic.

use {
    crate::zeroed,
    anchor_lang::prelude::Pubkey,
    prize_escrow::{ArbiterChoice, ChallengeRecord, Escrow, EscrowStatus},
};

fn any_key() -> Pubkey {
    Pubkey::new_from_array(kani::any())
}

/// An Escrow with every field any value it can hold on chain. A struct literal, not a decode of
/// symbolic bytes: Borsh's decode of an out-of-range status formats the tag (format!), which CBMC
/// ran past 10 minutes on; and a field added to Escrow fails to compile here until it is named,
/// so "nothing else changes" below always covers every field.
fn any_escrow() -> Escrow {
    Escrow {
        bump: kani::any(),
        decimals: kani::any(),
        status: match kani::any::<u8>() {
            0 => EscrowStatus::Open,
            1 => EscrowStatus::Challengeable,
            2 => EscrowStatus::Disputed,
            3 => EscrowStatus::Claimable,
            4 => EscrowStatus::Frozen,
            _ => EscrowStatus::Closed,
        },
        k: kani::any(),
        n: kani::any(),
        competition_id: kani::any(),
        sponsor: any_key(),
        resolver: any_key(),
        compliance: any_key(),
        arbiter: any_key(),
        refund_to: any_key(),
        mint: any_key(),
        challenger: any_key(),
        rules_sha256: kani::any(),
        entries_root: kani::any(),
        payout_root: kani::any(),
        result_sha256: kani::any(),
        kit_sha256: kani::any(),
        commitment: kani::any(),
        alt_result_sha256: kani::any(),
        alt_payout_root: kani::any(),
        alt_commitment: kani::any(),
        entries_count: kani::any(),
        challenge_count: kani::any(),
        total: kani::any(),
        total_claimed: kani::any(),
        alt_total: kani::any(),
        bond_lamports: kani::any(),
        resolver_bond: kani::any(),
        challenger_bond: kani::any(),
        entries_deadline: kani::any(),
        final_end: kani::any(),
        resolve_deadline: kani::any(),
        challenge_window: kani::any(),
        attest_window: kani::any(),
        hold_window: kani::any(),
        claim_window: kani::any(),
        challenge_deadline: kani::any(),
        attest_deadline: kani::any(),
        claim_deadline: kani::any(),
        hard_deadline: kani::any(),
        votes_result: kani::any(),
        votes_alt: kani::any(),
        regraders: core::array::from_fn(|_| any_key()),
        deposited: kani::any(),
        stop_base: kani::any(),
        freeze_since: kani::any(),
        freeze_until: kani::any(),
        frozen_secs: kani::any(),
        reveal_grace: kani::any(),
        commit_bond: kani::any(),
        pending_commits: kani::any(),
        reserved: kani::any(),
    }
}

/// A ChallengeRecord with every field any value, as any_escrow.
fn any_challenge() -> ChallengeRecord {
    ChallengeRecord {
        escrow: any_key(),
        challenger: any_key(),
        alt_result_sha256: kani::any(),
        alt_payout_root: kani::any(),
        alt_commitment: kani::any(),
        alt_total: kani::any(),
        bond: kani::any(),
        opened_at: kani::any(),
        index: kani::any(),
        votes: kani::any(),
        bump: kani::any(),
    }
}

/// For every escrow the program can hold: clear_alternative sets the challenger and the
/// alternative's document hash, payout root, total and commitment to what an escrow that never
/// recorded one holds (zero), and changes no other field: the posted result, the bonds, the votes,
/// the deadlines and the clocks stay. So once the arbiter keeps the posted result the escrow names
/// no winning challenger (has_challenger is false, so a vote it recorded reads only as the posted
/// side's: quorum_recorded is votes_result >= k), its Alternative side is all zero and its Posted
/// side is as posted.
#[kani::proof]
#[kani::unwind(70)]
fn clearing_an_alternative_forgets_it_and_nothing_else() {
    let mut escrow = any_escrow();
    let before = escrow.clone();
    kani::cover!(before.has_challenger(), "an alternative was recorded");
    escrow.clear_alternative();

    let never: Escrow = zeroed();
    let mut want = before.clone();
    want.challenger = never.challenger;
    want.alt_result_sha256 = never.alt_result_sha256;
    want.alt_payout_root = never.alt_payout_root;
    want.alt_total = never.alt_total;
    want.alt_commitment = never.alt_commitment;
    assert!(escrow == want);

    assert!(!escrow.has_challenger());
    assert_eq!(escrow.quorum_recorded(), escrow.votes_result >= escrow.k);
    assert_eq!(
        escrow.side(ArbiterChoice::Alternative),
        never.side(ArbiterChoice::Alternative)
    );
    assert_eq!(
        escrow.side(ArbiterChoice::Posted),
        before.side(ArbiterChoice::Posted)
    );
}

/// For every escrow and every challenge the program can hold: record_alternative writes the
/// challenge's challenger, document hash, payout root, total and commitment as the escrow's
/// alternative (side(Alternative) is the challenge's result) and changes no other field; and
/// clearing it again gives back the escrow as it was whenever it had none recorded, so an
/// alternative attest recorded and the arbiter overruled leaves no trace in the escrow.
#[kani::proof]
#[kani::unwind(70)]
fn recording_an_alternative_writes_it_and_nothing_else() {
    let mut escrow = any_escrow();
    let challenge = any_challenge();
    let before = escrow.clone();
    escrow.record_alternative(&challenge);

    let mut want = before.clone();
    want.challenger = challenge.challenger;
    want.alt_result_sha256 = challenge.alt_result_sha256;
    want.alt_payout_root = challenge.alt_payout_root;
    want.alt_total = challenge.alt_total;
    want.alt_commitment = challenge.alt_commitment;
    assert!(escrow == want);
    let side = escrow.side(ArbiterChoice::Alternative);
    assert_eq!(
        (side.result_sha256, side.payout_root, side.total, side.commitment),
        (
            challenge.alt_result_sha256,
            challenge.alt_payout_root,
            challenge.alt_total,
            challenge.alt_commitment
        )
    );

    escrow.clear_alternative();
    let never: Escrow = zeroed();
    let had_none = before.challenger == never.challenger
        && before.alt_result_sha256 == never.alt_result_sha256
        && before.alt_payout_root == never.alt_payout_root
        && before.alt_total == never.alt_total
        && before.alt_commitment == never.alt_commitment;
    kani::cover!(had_none, "an escrow with no alternative recorded");
    if had_none {
        assert!(escrow == before);
    }
}
