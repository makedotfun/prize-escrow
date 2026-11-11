//! The prize_escrow interface: the accounts, the 15 instructions and their account constraints,
//! the errors, events and constants, and the committed IDL the Kit client is generated from.
//!
//! The LiteSVM tests load the release build (`node scripts/chain/build.ts release` runs `anchor
//! build` for the canonical SBPF arch and writes target/deploy/prize_escrow.so), so build first. They check what holds whatever a handler does: each
//! instruction is dispatched, a well-formed account set passes account validation, and a wrong
//! signer, seed, address or destination is refused before any handler runs.
//!
//! Every instruction carries the two accounts #[event_cpi] appends (the event authority PDA
//! ["__event_authority"] and the program itself) and emits its event through a self-CPI: a wrong
//! event authority is refused at account validation, and nobody but the program can sign the
//! event instruction (run review 4: events were log lines a CPI caller could truncate away).

mod common;
mod mainnet;
mod program_so;

use {
    anchor_lang::{
        error::{ErrorCode as AnchorErrorCode, ERROR_CODE_OFFSET},
        event::EVENT_IX_TAG_LE,
        prelude::{Pubkey, Rent},
        solana_program::{
            instruction::{error::InstructionError, AccountMeta, Instruction},
            program_option::COption,
            program_pack::Pack,
            system_program,
        },
        AccountSerialize, Discriminator, InstructionData, Space, ToAccountMetas,
    },
    anchor_spl::{
        associated_token::{self, get_associated_token_address},
        token::{self, spl_token},
    },
    common::{config_init, config_pda},
    litesvm::{types::TransactionResult, LiteSVM},
    prize_escrow::{
        accounts as accts, bond_floor, commit_hash, instruction as ixs, result_commitment,
        ArbiterChoice, AttestSide, Attestation, ChallengeRecord, ClaimReceipt, CommitRecord,
        Config, Escrow, EscrowError, EscrowStatus, EscrowTerms, Proposal, ResultSide,
        ARBITER_SLACK, ATTESTATION_SEED, BOND_FLOOR_RENTS, CHALLENGE_SEED, CLAIM_SEED, COMMIT_SEED,
        CONFIG_SEED, DEFAULT_MIN_REGRADERS, ESCROW_SEED, EVENT_AUTHORITY_AND_BUMP, HOLD_GEO,
        HOLD_NONE, HOLD_REVIEW, HOLD_SANCTIONS, HOLD_TAX_FORM_REQUIRED, MAX_PROOF_LEN,
        MAX_PROPOSAL_BOND, MAX_REGRADERS, MAX_REVEAL_GRACE, MAX_REVIEW_WINDOW, MAX_WINDOW,
        MIN_ATTEST_WINDOW, MIN_CHALLENGE_WINDOW, MIN_CLAIM_WINDOW, MIN_HOLD_WINDOW,
        MIN_RESOLVE_WINDOW, MIN_REVEAL_GRACE, PROPOSAL_SEED, RESULT_COMMITMENT_DOMAIN,
        STOP_DURATION,
    },
    serde_json::Value,
    solana_account::Account,
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
    solana_transaction_error::TransactionError,
};

const IDL_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../idl/prize_escrow.json"
));

/// The PDA ["__event_authority"] that signs the program's event self-CPIs.
const EVENT_AUTHORITY: Pubkey = EVENT_AUTHORITY_AND_BUMP.0;
/// bond_floor under the SDK's Rent::default() (3,480 lamports a byte-year, threshold 2):
/// 2 x 890,880 lamports. Mainnet's floor, at the pinned rent, is checked by tests/feature_set.rs
/// and tests/lifecycle.rs.
const FLOOR: u64 = 1_781_760;

const CID: [u8; 16] = [0x11; 16];
const DECIMALS: u8 = 6;
const TOTAL: u64 = 5_000_000;
const BOND: u64 = 100_000_000;
const SOL: u64 = 1_000_000_000;

// ------------------------------------------------------------------------------------ layout

#[test]
fn account_sizes_are_pinned() {
    // Escrow: 5 u8 flags + competition_id 16 + 7 keys + 9 hashes (rules, entries root, payout
    // root, result, kit, commitment, and the winning alternative's result, root and commitment)
    // + entries_count and challenge_count u32 + 6 u64 amounts + 11 i64 deadlines and windows + 2
    // vote counters + 5 regraders; then the safeguards: deposited, stop_base, freeze_since,
    // freeze_until, frozen_secs, reveal_grace and commit_bond (7 x 8), pending_commits u32 and
    // 64 reserved bytes.
    assert_eq!(
        Escrow::INIT_SPACE,
        5 + 16 + 7 * 32 + 9 * 32 + 2 * 4 + 6 * 8 + 11 * 8 + 2 + 5 * 32 + 7 * 8 + 4 + 64
    );
    assert_eq!(Escrow::SPACE, 971);
    // CommitRecord: 2 keys (escrow, challenger) + the hash + slot, committed_at and bond + bump.
    assert_eq!(CommitRecord::INIT_SPACE, 2 * 32 + 32 + 3 * 8 + 1);
    assert_eq!(CommitRecord::SPACE, 129);
    // Config: bump, stop and max_house_regraders + 4 keys (admin, pending_admin, guardian,
    // arbiter) + 16 u64/i64 + the four lists at their longest (4 mints, 32 sponsors, 16 registry
    // entries of 33 bytes, 16 revoked keys, each with its 4-byte length) + what were 64 reserved
    // bytes: min_regraders (1), the curator, pending_value and pending_cap (48), retired (1),
    // live_escrows (4) and house_sponsors (4), and 6 still reserved. The size, and every field's
    // offset before them, are what they were: a Config written before the carve-outs reads
    // min_regraders 0, no curator (proposals off), nothing pending, not retired, no escrow
    // counted and no house sponsor.
    assert_eq!(
        Config::INIT_SPACE,
        3 + 4 * 32
            + 16 * 8
            + (4 + 4 * 32)
            + (4 + 32 * 32)
            + (4 + 16 * 33)
            + (4 + 16 * 32)
            + (1 + 32 + 8 + 8 + 1 + 4 + 4 + 6)
    );
    assert_eq!(Config::SPACE, 2539);
    // EscrowTerms at its longest (MAX_REGRADERS regraders): the total, the rules hash, 4 keys
    // (resolver, compliance, arbiter, refund_to), the regraders with their length, k, the bond
    // and 8 deadlines and windows.
    assert_eq!(
        EscrowTerms::INIT_SPACE,
        8 + 32 + 4 * 32 + (4 + 5 * 32) + 1 + 8 + 8 * 8
    );
    // Proposal: bump and decimals + competition_id 16 + 2 keys (sponsor, mint) + the terms whole
    // + opens_at, review_deadline, submitted_at and deposited + 32 reserved bytes.
    assert_eq!(
        Proposal::INIT_SPACE,
        2 + 16 + 2 * 32 + EscrowTerms::INIT_SPACE + 4 * 8 + 32
    );
    assert_eq!(Proposal::SPACE, 559);
    let terms = sample_terms(&Ids::fixed(), 1_800_000_000);
    let mut data = Vec::new();
    Proposal {
        bump: 255,
        decimals: DECIMALS,
        competition_id: CID,
        sponsor: Pubkey::new_unique(),
        mint: Pubkey::new_unique(),
        terms: EscrowTerms {
            regraders: (0..5).map(|_| Pubkey::new_unique()).collect(),
            ..terms
        },
        opens_at: 1,
        review_deadline: 1,
        submitted_at: 1,
        deposited: TOTAL,
        reserved: [0; 32],
    }
    .try_serialize(&mut data)
    .unwrap();
    assert_eq!(
        data.len(),
        Proposal::SPACE,
        "a full panel fills the account"
    );
    assert_eq!(&data[..8], Proposal::DISCRIMINATOR);
    assert_eq!(ClaimReceipt::SPACE, 74);
    assert_eq!(Attestation::SPACE, 74);
    // ChallengeRecord: 2 keys (escrow, challenger) + 3 hashes (the alternative's result, root and
    // commitment) + 3 u64/i64 (alt_total, bond, opened_at) + index u32 + votes and bump.
    assert_eq!(ChallengeRecord::INIT_SPACE, 2 * 32 + 3 * 32 + 3 * 8 + 4 + 2);
    assert_eq!(ChallengeRecord::SPACE, 198);
    let mut data = Vec::new();
    sample_challenge(&Pubkey::new_unique(), &Pubkey::new_unique(), 255)
        .try_serialize(&mut data)
        .unwrap();
    assert_eq!(data.len(), ChallengeRecord::SPACE);
    assert_eq!(&data[..8], ChallengeRecord::DISCRIMINATOR);

    let mut data = Vec::new();
    sample_escrow(&Ids::fixed(), 255, EscrowStatus::Closed)
        .try_serialize(&mut data)
        .unwrap();
    assert_eq!(data.len(), Escrow::SPACE);
    assert_eq!(&data[..8], Escrow::DISCRIMINATOR);

    let mut data = Vec::new();
    sample_receipt(Pubkey::new_unique(), 255)
        .try_serialize(&mut data)
        .unwrap();
    assert_eq!(data.len(), ClaimReceipt::SPACE);

    let mut data = Vec::new();
    Attestation {
        regrader: Pubkey::new_unique(),
        commitment: [9; 32],
        side: AttestSide::Alt,
        bump: 255,
    }
    .try_serialize(&mut data)
    .unwrap();
    assert_eq!(data.len(), Attestation::SPACE);
}

#[test]
fn constants_are_the_release_values() {
    // `cargo test` builds without the test-windows feature, like the release .so.
    assert_eq!(MIN_CHALLENGE_WINDOW, 24 * 60 * 60);
    assert_eq!(MIN_ATTEST_WINDOW, 24 * 60 * 60);
    assert_eq!(MIN_HOLD_WINDOW, 24 * 60 * 60);
    assert_eq!(MIN_CLAIM_WINDOW, 7 * 24 * 60 * 60);
    assert_eq!(BOND_FLOOR_RENTS, 2);
    assert_eq!(bond_floor(&Rent::default()), FLOOR);
    assert_eq!(MAX_WINDOW, i64::from(i32::MAX));
    assert_eq!(MAX_PROOF_LEN, 24);
    assert_eq!(MAX_REGRADERS, 5);
    assert_eq!(DEFAULT_MIN_REGRADERS, 1);
    assert_eq!(ARBITER_SLACK, 7 * 24 * 60 * 60);
    assert_eq!(RESULT_COMMITMENT_DOMAIN, b"agent-fun/result-commitment/v1");
    assert_eq!(ESCROW_SEED, b"escrow");
    assert_eq!(CLAIM_SEED, b"claim");
    assert_eq!(ATTESTATION_SEED, b"attestation");
    assert_eq!(CHALLENGE_SEED, b"challenge");
    assert_eq!(PROPOSAL_SEED, b"proposal");
    assert_eq!(MAX_REVIEW_WINDOW, 7 * 24 * 60 * 60);
    assert_eq!(MIN_RESOLVE_WINDOW, 14 * 24 * 60 * 60);
    assert_eq!(MAX_PROPOSAL_BOND, 1_000_000_000);
    assert_eq!(
        [
            HOLD_NONE,
            HOLD_SANCTIONS,
            HOLD_GEO,
            HOLD_TAX_FORM_REQUIRED,
            HOLD_REVIEW
        ],
        [0, 1, 2, 3, 4]
    );
    assert!((1..=4).all(prize_escrow::is_hold_reason));
    assert!(!prize_escrow::is_hold_reason(0) && !prize_escrow::is_hold_reason(5));
}

#[test]
fn quorum_is_k_of_n_with_2k_over_n() {
    let mut valid = Vec::new();
    for n in 0..=6u8 {
        for k in 0..=6u8 {
            if Escrow::quorum_ok(k, n) {
                valid.push((k, n));
            }
        }
    }
    assert_eq!(
        valid,
        [
            (1, 1),
            (2, 2),
            (2, 3),
            (3, 3),
            (3, 4),
            (4, 4),
            (3, 5),
            (4, 5),
            (5, 5)
        ]
    );
}

#[test]
fn escrow_helpers() {
    let ids = Ids::fixed();
    let (escrow_key, bump) = escrow_pda(&ids.sponsor, &CID);
    let mut escrow = sample_escrow(&ids, bump, EscrowStatus::Open);

    // The same address and bytes the generated Kit client (server/chain/generated) derives:
    // findEscrowPda({ sponsor: 32 x 0x01, competitionId: 16 x 0x11 }), findReceiptPda({ escrow,
    // claimant: program id }) and getClaimInstructionDataEncoder().encode({ totalAmount: 5n,
    // amount: 0n, proof: [32 x 0] }).
    assert_eq!(
        ids.sponsor.to_string(),
        "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"
    );
    assert_eq!(
        escrow_key.to_string(),
        "8utCBQdMUx3ZDoNov2GsHX8M7qxPH21vdVvPG1JUiji5"
    );
    assert_ne!(
        escrow_key,
        Pubkey::find_program_address(&[ESCROW_SEED, &CID], &prize_escrow::ID).0,
        "the sponsor is in the seeds"
    );
    assert_eq!(
        receipt_pda(&escrow_key, &prize_escrow::ID).0.to_string(),
        "tUQadBZsFxWpGbPUQsvowsevc7u2C2eYReizYFgCJpz"
    );
    let claim_data = ixs::Claim {
        total_amount: 5,
        amount: 0,
        proof: vec![[0; 32]],
    }
    .data();
    let mut want = vec![
        0x3e, 0xc6, 0xd6, 0xc1, 0xd5, 0x9f, 0x6c, 0xd2, 5, 0, 0, 0, 0, 0, 0, 0,
    ];
    want.extend_from_slice(&[0; 8]); // amount
    want.extend_from_slice(&[1, 0, 0, 0]); // proof length
    want.extend_from_slice(&[0; 32]);
    assert_eq!(claim_data, want);

    // signer_seeds re-derive the PDA (the vault authority signs with them).
    assert_eq!(
        Pubkey::create_program_address(&escrow.signer_seeds(), &prize_escrow::ID).unwrap(),
        escrow_key
    );

    assert!(ids.regraders.iter().all(|r| escrow.is_regrader(r)));
    assert!(!escrow.is_regrader(&ids.resolver));
    assert!(
        !escrow.is_regrader(&Pubkey::default()),
        "an empty slot is not a regrader"
    );
    escrow.n = 1;
    assert!(escrow.is_regrader(&ids.regraders[0]) && !escrow.is_regrader(&ids.regraders[1]));

    assert!(escrow.has_compliance() && escrow.has_challenger());
    escrow.compliance = Pubkey::default();
    escrow.challenger = Pubkey::default();
    assert!(!escrow.has_compliance() && !escrow.has_challenger());

    // A winning challenge is recorded from its Challenge PDA.
    let challenge = sample_challenge(&escrow_key, &ids.challenger, 254);
    escrow.record_alternative(&challenge);
    assert!(escrow.has_challenger());
    assert_eq!(
        (
            escrow.challenger,
            escrow.alt_result_sha256,
            escrow.alt_payout_root,
            escrow.alt_total,
            escrow.alt_commitment
        ),
        (
            ids.challenger,
            challenge.alt_result_sha256,
            challenge.alt_payout_root,
            challenge.alt_total,
            challenge.alt_commitment
        )
    );

    // The arbiter's sides, as stored (the alternative the winning challenge's), and the bonds the
    // winner takes: every bond held, two challengers' among them.
    let mut escrow = sample_escrow(&ids, bump, EscrowStatus::Frozen);
    escrow.alt_total = TOTAL - 1;
    escrow.challenger_bond = 2 * BOND;
    let posted = ResultSide {
        result_sha256: [4; 32],
        payout_root: [3; 32],
        total: TOTAL,
        commitment: [7; 32],
    };
    let alternative = ResultSide {
        result_sha256: [6; 32],
        payout_root: [8; 32],
        total: TOTAL - 1,
        commitment: [9; 32],
    };
    assert_eq!(escrow.side(ArbiterChoice::Posted), posted);
    assert_eq!(escrow.side(ArbiterChoice::Alternative), alternative);
    assert_eq!(
        escrow.bonds_to_winner(ArbiterChoice::Posted),
        Ok((3 * BOND, 0))
    );
    assert_eq!(
        escrow.bonds_to_winner(ArbiterChoice::Alternative),
        Ok((0, 3 * BOND))
    );
    let before = escrow.clone();
    escrow.apply(ArbiterChoice::Posted);
    assert_eq!(escrow, before, "applying the posted result changes nothing");
    escrow.apply(ArbiterChoice::Alternative);
    assert_eq!(escrow.side(ArbiterChoice::Posted), alternative);
    assert_eq!(
        escrow.side(ArbiterChoice::Alternative),
        alternative,
        "the alternative stays on record"
    );
    assert_eq!(escrow.kit_sha256, before.kit_sha256);
    escrow.resolver_bond = u64::MAX;
    assert_eq!(
        escrow.bonds_to_winner(ArbiterChoice::Posted),
        Err(EscrowError::MathOverflow.into())
    );

    let mut receipt = sample_receipt(ids.claimant, 254);
    assert_eq!(receipt.remaining(), Some(TOTAL / 2));
    assert!(!receipt.is_held());
    receipt.hold_reason = HOLD_GEO;
    assert!(receipt.is_held());
    receipt.amount_claimed = receipt.total_amount + 1;
    assert_eq!(receipt.remaining(), None);
}

#[test]
fn terms_bounds() {
    let now = 1_800_000_000;
    let good = sample_terms(&Ids::fixed(), now);
    assert_eq!(good.validate(now, FLOOR), Ok(()));

    let check = |edit: &dyn Fn(&mut EscrowTerms), want: EscrowError| {
        let mut terms = good.clone();
        edit(&mut terms);
        assert_eq!(terms.validate(now, FLOOR), Err(want.into()), "{terms:?}");
    };

    check(&|t| t.total = 0, EscrowError::InvalidAmount);
    check(&|t| t.bond_lamports = 0, EscrowError::InvalidAmount);
    // The bond floor (run review 4: one lamport bought a challenge).
    check(
        &|t| t.bond_lamports = FLOOR - 1,
        EscrowError::BondBelowFloor,
    );
    let mut at_floor = good.clone();
    at_floor.bond_lamports = FLOOR;
    assert_eq!(at_floor.validate(now, FLOOR), Ok(()));
    assert_eq!(
        good.validate(now, BOND + 1),
        Err(EscrowError::BondBelowFloor.into()),
        "the floor is the caller's (the cluster's rent), not a constant"
    );

    check(&|t| t.regraders.clear(), EscrowError::InvalidRegraderSet);
    check(
        &|t| t.regraders = (0..6).map(|_| Pubkey::new_unique()).collect(),
        EscrowError::InvalidRegraderSet,
    );
    check(&|t| t.k = 0, EscrowError::InvalidRegraderSet);
    check(&|t| t.k = 1, EscrowError::InvalidRegraderSet); // 2k > n fails for 1-of-3
    check(&|t| t.k = 4, EscrowError::InvalidRegraderSet);
    check(
        &|t| t.regraders[2] = t.regraders[0],
        EscrowError::InvalidRegraderSet,
    );
    check(
        &|t| t.regraders[1] = Pubkey::default(),
        EscrowError::InvalidRegraderSet,
    );

    check(
        &|t| t.challenge_window = MIN_CHALLENGE_WINDOW - 1,
        EscrowError::InvalidWindow,
    );
    check(
        &|t| t.attest_window = MIN_ATTEST_WINDOW - 1,
        EscrowError::InvalidWindow,
    );
    check(
        &|t| t.hold_window = MIN_HOLD_WINDOW - 1,
        EscrowError::InvalidWindow,
    );
    check(&|t| t.claim_window = 0, EscrowError::InvalidWindow);
    // Run review 4: a 1 s claim window was accepted without a compliance key.
    check(
        &|t| {
            t.compliance = Pubkey::default();
            t.claim_window = MIN_CLAIM_WINDOW - 1;
        },
        EscrowError::InvalidWindow,
    );
    check(
        &|t| t.claim_window = MAX_WINDOW + 1,
        EscrowError::InvalidWindow,
    );

    // With a compliance key a request must clear inside the claim window; without one nothing
    // is ever held, so any claim window from MIN_CLAIM_WINDOW up goes, even one shorter than
    // the hold window.
    check(
        &|t| {
            t.hold_window = MIN_CLAIM_WINDOW + 1;
            t.claim_window = MIN_CLAIM_WINDOW + 1;
        },
        EscrowError::ClaimWindowTooShort,
    );
    let mut ungated = good.clone();
    ungated.compliance = Pubkey::default();
    ungated.hold_window = MIN_CLAIM_WINDOW + 1;
    ungated.claim_window = MIN_CLAIM_WINDOW;
    assert_eq!(ungated.validate(now, FLOOR), Ok(()));

    check(&|t| t.entries_deadline = now, EscrowError::InvalidDeadlines);
    check(
        &|t| t.final_end = t.entries_deadline - 1,
        EscrowError::InvalidDeadlines,
    );
    check(
        &|t| t.final_end = t.resolve_deadline,
        EscrowError::InvalidDeadlines,
    );
    check(
        &|t| {
            t.final_end = t.entries_deadline;
            t.resolve_deadline = t.entries_deadline;
        },
        EscrowError::InvalidDeadlines,
    );
    check(
        &|t| t.hard_deadline = t.resolve_deadline,
        EscrowError::HardDeadlineTooEarly,
    );
    check(
        &|t| t.hard_deadline = earliest_hard_deadline(t) - 1,
        EscrowError::HardDeadlineTooEarly,
    );
    // A resolve deadline so late the sum overflows can have no hard deadline after it.
    check(
        &|t| {
            t.resolve_deadline = i64::MAX - 10;
            t.hard_deadline = i64::MAX;
        },
        EscrowError::HardDeadlineTooEarly,
    );

    let mut edge = good.clone();
    edge.regraders.truncate(1);
    edge.k = 1;
    edge.challenge_window = MIN_CHALLENGE_WINDOW;
    edge.attest_window = MIN_ATTEST_WINDOW;
    edge.hold_window = MIN_HOLD_WINDOW;
    edge.claim_window = MAX_WINDOW;
    edge.entries_deadline = now + 1;
    edge.final_end = now + 1;
    edge.resolve_deadline = now + 2;
    edge.hard_deadline = earliest_hard_deadline(&edge);
    assert_eq!(edge.validate(now, FLOOR), Ok(()));
    // The claim window at its minimum, and a hold window one second shorter than it.
    let mut gated_edge = edge.clone();
    gated_edge.claim_window = MIN_CLAIM_WINDOW;
    gated_edge.hold_window = MIN_CLAIM_WINDOW - 1;
    gated_edge.hard_deadline = earliest_hard_deadline(&gated_edge);
    assert_eq!(gated_edge.validate(now, FLOOR), Ok(()));
}

/// resolve_deadline + every window + ARBITER_SLACK: the earliest hard_deadline open_escrow takes.
fn earliest_hard_deadline(t: &EscrowTerms) -> i64 {
    t.resolve_deadline
        + t.challenge_window
        + t.attest_window
        + t.hold_window
        + t.claim_window
        + ARBITER_SLACK
}

// ------------------------------------------------------------------------------- the IDL

/// Every instruction: name, Rust discriminator, and whether it takes arguments.
fn instructions() -> Vec<(&'static str, &'static [u8], bool)> {
    vec![
        ("open_escrow", ixs::OpenEscrow::DISCRIMINATOR, true),
        ("fund", ixs::Fund::DISCRIMINATOR, true),
        ("commit_entries", ixs::CommitEntries::DISCRIMINATOR, true),
        ("post_result", ixs::PostResult::DISCRIMINATOR, true),
        (
            "challenge_commit",
            ixs::ChallengeCommit::DISCRIMINATOR,
            true,
        ),
        (
            "challenge_reveal",
            ixs::ChallengeReveal::DISCRIMINATOR,
            true,
        ),
        ("attest", ixs::Attest::DISCRIMINATOR, true),
        ("settle", ixs::Settle::DISCRIMINATOR, false),
        ("arbiter_resolve", ixs::ArbiterResolve::DISCRIMINATOR, true),
        ("request_claim", ixs::RequestClaim::DISCRIMINATOR, true),
        ("claim", ixs::Claim::DISCRIMINATOR, true),
        ("hold", ixs::Hold::DISCRIMINATOR, true),
        ("release_hold", ixs::ReleaseHold::DISCRIMINATOR, true),
        ("refund", ixs::Refund::DISCRIMINATOR, false),
        ("close_receipt", ixs::CloseReceipt::DISCRIMINATOR, false),
        ("close_challenge", ixs::CloseChallenge::DISCRIMINATOR, false),
        ("close_commit", ixs::CloseCommit::DISCRIMINATOR, false),
        (
            "close_attestation",
            ixs::CloseAttestation::DISCRIMINATOR,
            false,
        ),
        (
            "initialize_config",
            ixs::InitializeConfig::DISCRIMINATOR,
            true,
        ),
        ("propose_admin", ixs::ProposeAdmin::DISCRIMINATOR, true),
        ("accept_admin", ixs::AcceptAdmin::DISCRIMINATOR, false),
        ("set_config_role", ixs::SetConfigRole::DISCRIMINATOR, true),
        ("set_limits", ixs::SetLimits::DISCRIMINATOR, true),
        ("set_floors", ixs::SetFloors::DISCRIMINATOR, true),
        (
            "set_min_regraders",
            ixs::SetMinRegraders::DISCRIMINATOR,
            true,
        ),
        ("set_allowed", ixs::SetAllowed::DISCRIMINATOR, true),
        ("set_stop", ixs::SetStop::DISCRIMINATOR, true),
        ("extend_stop", ixs::ExtendStop::DISCRIMINATOR, true),
        ("set_freeze", ixs::SetFreeze::DISCRIMINATOR, true),
        ("extend_freeze", ixs::ExtendFreeze::DISCRIMINATOR, true),
        ("escalate", ixs::Escalate::DISCRIMINATOR, false),
        ("set_revoked", ixs::SetRevoked::DISCRIMINATOR, true),
        ("rotate_role", ixs::RotateRole::DISCRIMINATOR, true),
        (
            "set_proposal_policy",
            ixs::SetProposalPolicy::DISCRIMINATOR,
            true,
        ),
        ("submit_proposal", ixs::SubmitProposal::DISCRIMINATOR, true),
        (
            "set_proposal_rules",
            ixs::SetProposalRules::DISCRIMINATOR,
            true,
        ),
        (
            "approve_proposal",
            ixs::ApproveProposal::DISCRIMINATOR,
            false,
        ),
        ("close_proposal", ixs::CloseProposal::DISCRIMINATOR, true),
        ("retire", ixs::Retire::DISCRIMINATOR, false),
        ("close_escrow", ixs::CloseEscrow::DISCRIMINATOR, false),
        ("close_config", ixs::CloseConfig::DISCRIMINATOR, false),
    ]
}

/// The error codes in wire order; append only.
const ERRORS: [(EscrowError, &str); 118] = [
    (EscrowError::UnauthorizedResolver, "UnauthorizedResolver"),
    (EscrowError::UnauthorizedArbiter, "UnauthorizedArbiter"),
    (EscrowError::NotARegrader, "NotARegrader"),
    (EscrowError::InvalidStatus, "InvalidStatus"),
    (EscrowError::ChallengeWindowClosed, "ChallengeWindowClosed"),
    (EscrowError::ClaimWindowClosed, "ClaimWindowClosed"),
    (EscrowError::ClaimWindowNotElapsed, "ClaimWindowNotElapsed"),
    (EscrowError::DeadlineNotReached, "DeadlineNotReached"),
    (EscrowError::AttestWindowOpen, "AttestWindowOpen"),
    (EscrowError::AttestWindowClosed, "AttestWindowClosed"),
    (EscrowError::Underfunded, "Underfunded"),
    (EscrowError::Overfunded, "Overfunded"),
    (EscrowError::TotalMismatch, "TotalMismatch"),
    (EscrowError::InvalidMerkleProof, "InvalidMerkleProof"),
    (EscrowError::ProofTooDeep, "ProofTooDeep"),
    (EscrowError::AlreadyClaimed, "AlreadyClaimed"),
    (EscrowError::ExceedsAllocation, "ExceedsAllocation"),
    (EscrowError::NothingToClaim, "NothingToClaim"),
    (EscrowError::MintMismatch, "MintMismatch"),
    (EscrowError::DecimalsMismatch, "DecimalsMismatch"),
    (
        EscrowError::UnsupportedTokenProgram,
        "UnsupportedTokenProgram",
    ),
    (EscrowError::BondMismatch, "BondMismatch"),
    (EscrowError::InvalidResultHash, "InvalidResultHash"),
    (EscrowError::InvalidRegraderSet, "InvalidRegraderSet"),
    (EscrowError::NoQuorum, "NoQuorum"),
    (EscrowError::MathOverflow, "MathOverflow"),
    (EscrowError::EscrowClosed, "EscrowClosed"),
    (EscrowError::NothingToRefund, "NothingToRefund"),
    (EscrowError::HeldForCompliance, "HeldForCompliance"),
    (EscrowError::NotCleared, "NotCleared"),
    (EscrowError::HoldWindowOpen, "HoldWindowOpen"),
    (
        EscrowError::EntriesAlreadyCommitted,
        "EntriesAlreadyCommitted",
    ),
    (EscrowError::UnauthorizedSponsor, "UnauthorizedSponsor"),
    (
        EscrowError::UnauthorizedCompliance,
        "UnauthorizedCompliance",
    ),
    (EscrowError::InvalidDeadlines, "InvalidDeadlines"),
    (EscrowError::InvalidWindow, "InvalidWindow"),
    (EscrowError::InvalidAmount, "InvalidAmount"),
    (EscrowError::InvalidHoldReason, "InvalidHoldReason"),
    (EscrowError::EntriesWindowClosed, "EntriesWindowClosed"),
    (EscrowError::ResolveWindowClosed, "ResolveWindowClosed"),
    (EscrowError::NotHeld, "NotHeld"),
    (EscrowError::AlreadyRequested, "AlreadyRequested"),
    (EscrowError::EntriesWindowOpen, "EntriesWindowOpen"),
    (EscrowError::EntriesNotCommitted, "EntriesNotCommitted"),
    (EscrowError::ClaimWindowTooShort, "ClaimWindowTooShort"),
    (EscrowError::HardDeadlineTooEarly, "HardDeadlineTooEarly"),
    (EscrowError::BondBelowFloor, "BondBelowFloor"),
    (EscrowError::ChallengeMismatch, "ChallengeMismatch"),
    (EscrowError::AlternativeUnbacked, "AlternativeUnbacked"),
    (EscrowError::NotUpgradeAuthority, "NotUpgradeAuthority"),
    (EscrowError::UnauthorizedAdmin, "UnauthorizedAdmin"),
    (EscrowError::UnauthorizedGuardian, "UnauthorizedGuardian"),
    (EscrowError::NotPendingAdmin, "NotPendingAdmin"),
    (EscrowError::InvalidConfig, "InvalidConfig"),
    (EscrowError::KeyRevoked, "KeyRevoked"),
    (EscrowError::CannotRevokeAdmin, "CannotRevokeAdmin"),
    (EscrowError::AlreadyRevoked, "AlreadyRevoked"),
    (EscrowError::NotRevoked, "NotRevoked"),
    (EscrowError::ListFull, "ListFull"),
    (EscrowError::AlreadyListed, "AlreadyListed"),
    (EscrowError::NotListed, "NotListed"),
    (EscrowError::IntakeStopped, "IntakeStopped"),
    (EscrowError::PayoutStopped, "PayoutStopped"),
    (EscrowError::EscrowFrozen, "EscrowFrozen"),
    (EscrowError::NotAnEscalation, "NotAnEscalation"),
    (EscrowError::NotStopped, "NotStopped"),
    (EscrowError::AlreadyFrozen, "AlreadyFrozen"),
    (EscrowError::NotFrozen, "NotFrozen"),
    (EscrowError::MintNotAllowed, "MintNotAllowed"),
    (EscrowError::SponsorNotAllowed, "SponsorNotAllowed"),
    (EscrowError::RefundToNotSponsor, "RefundToNotSponsor"),
    (EscrowError::ArbiterNotConfig, "ArbiterNotConfig"),
    (EscrowError::ComplianceRequired, "ComplianceRequired"),
    (EscrowError::BondBelowMin, "BondBelowMin"),
    (EscrowError::WindowBelowFloor, "WindowBelowFloor"),
    (EscrowError::RegraderNotRegistered, "RegraderNotRegistered"),
    (EscrowError::TooManyHouseRegraders, "TooManyHouseRegraders"),
    (
        EscrowError::RegraderNotIndependent,
        "RegraderNotIndependent",
    ),
    (EscrowError::EscrowCapExceeded, "EscrowCapExceeded"),
    (EscrowError::GlobalCapExceeded, "GlobalCapExceeded"),
    (EscrowError::FlowLimitExceeded, "FlowLimitExceeded"),
    (EscrowError::VaultFrozen, "VaultFrozen"),
    (EscrowError::ClaimantAccountFrozen, "ClaimantAccountFrozen"),
    (EscrowError::RefundAccountFrozen, "RefundAccountFrozen"),
    (EscrowError::SponsorAccountFrozen, "SponsorAccountFrozen"),
    (EscrowError::CommitMismatch, "CommitMismatch"),
    (EscrowError::RevealTooEarly, "RevealTooEarly"),
    (EscrowError::RevealWindowClosed, "RevealWindowClosed"),
    (EscrowError::CommitsPendingReveal, "CommitsPendingReveal"),
    (EscrowError::RoleMismatch, "RoleMismatch"),
    (EscrowError::RegraderAlreadyVoted, "RegraderAlreadyVoted"),
    (EscrowError::QuorumRecorded, "QuorumRecorded"),
    (EscrowError::OverturnWindowOpen, "OverturnWindowOpen"),
    (EscrowError::RoleIsEscrow, "RoleIsEscrow"),
    (EscrowError::NoEntries, "NoEntries"),
    (
        EscrowError::UnchallengedResultBinds,
        "UnchallengedResultBinds",
    ),
    (EscrowError::PanelTooSmall, "PanelTooSmall"),
    (EscrowError::ProposalsDisabled, "ProposalsDisabled"),
    (EscrowError::UnauthorizedCurator, "UnauthorizedCurator"),
    (EscrowError::PendingCapExceeded, "PendingCapExceeded"),
    (EscrowError::ReviewWindowInvalid, "ReviewWindowInvalid"),
    (EscrowError::ReviewWindowClosed, "ReviewWindowClosed"),
    (EscrowError::SponsorRevoked, "SponsorRevoked"),
    (EscrowError::EscrowExists, "EscrowExists"),
    (EscrowError::CuratorNotIndependent, "CuratorNotIndependent"),
    (EscrowError::InvalidCloseReason, "InvalidCloseReason"),
    (EscrowError::SponsorIsCurator, "SponsorIsCurator"),
    (
        EscrowError::ProposalRoleNotIndependent,
        "ProposalRoleNotIndependent",
    ),
    (EscrowError::ResolveWindowTooShort, "ResolveWindowTooShort"),
    (EscrowError::ProposalBondTooHigh, "ProposalBondTooHigh"),
    (EscrowError::Retired, "Retired"),
    (EscrowError::NotRetired, "NotRetired"),
    (EscrowError::ChallengesOutstanding, "ChallengesOutstanding"),
    (EscrowError::CommitsOutstanding, "CommitsOutstanding"),
    (EscrowError::ValueOutstanding, "ValueOutstanding"),
    (EscrowError::EscrowsOutstanding, "EscrowsOutstanding"),
    (EscrowError::RulesNotSet, "RulesNotSet"),
    (EscrowError::RulesAlreadySet, "RulesAlreadySet"),
];

fn bytes(v: &Value) -> Vec<u8> {
    v.as_array()
        .expect("a byte array")
        .iter()
        .map(|b| u8::try_from(b.as_u64().expect("a byte")).expect("a byte"))
        .collect()
}

fn named<'a>(list: &'a Value, name: &str) -> &'a Value {
    list.as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == name)
        .unwrap_or_else(|| panic!("{name} is missing from the IDL"))
}

#[test]
fn committed_idl_matches_the_program() {
    let idl: Value = serde_json::from_str(IDL_JSON).expect("chain/idl/prize_escrow.json parses");
    assert_eq!(idl["address"], prize_escrow::ID.to_string());
    assert_eq!(idl["metadata"]["name"], "prize_escrow");
    assert_eq!(idl["metadata"]["spec"], "0.1.0");

    let expected = instructions();
    assert_eq!(
        idl["instructions"].as_array().unwrap().len(),
        expected.len()
    );
    for (name, disc, has_args) in &expected {
        let ix = named(&idl["instructions"], name);
        assert_eq!(bytes(&ix["discriminator"]), *disc, "{name} discriminator");
        assert_eq!(
            !ix["args"].as_array().unwrap().is_empty(),
            *has_args,
            "{name} args"
        );
    }

    let compliance = named(
        &named(&idl["instructions"], "claim")["accounts"],
        "compliance",
    );
    assert_eq!(compliance["optional"], true);
    assert_eq!(compliance["signer"], true);
    let open_args: Vec<&str> = named(&idl["instructions"], "open_escrow")["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert_eq!(open_args, ["competition_id", "terms"]);
    let arg_names = |name: &str| -> Vec<String> {
        named(&idl["instructions"], name)["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["name"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(arg_names("challenge_commit"), ["hash"]);
    assert_eq!(
        arg_names("challenge_reveal"),
        [
            "salt",
            "alt_result_sha256",
            "alt_payout_root",
            "alt_total",
            "alt_commitment"
        ]
    );
    assert_eq!(arg_names("attest"), ["commitment"]);
    // The arbiter chooses a side and names its commitment; it passes no root, document hash or
    // total of its own.
    assert_eq!(arg_names("arbiter_resolve"), ["choice", "commitment"]);
    let account_names = |name: &str| -> Vec<String> {
        named(&idl["instructions"], name)["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["name"].as_str().unwrap().to_owned())
            .collect()
    };
    // Every instruction emits through a self-CPI: #[event_cpi] appends the event authority and
    // the program to its accounts.
    for (name, _, _) in &expected {
        let names = account_names(name);
        assert_eq!(
            names[names.len() - 2..],
            ["event_authority", "program"],
            "{name} accounts"
        );
    }
    // settle reads the vault (an applied alternative's total) and pays no refund_to.
    assert_eq!(
        account_names("settle"),
        [
            "escrow",
            "mint",
            "vault",
            "resolver",
            "challenger",
            "token_program",
            "config",
            "event_authority",
            "program"
        ]
    );
    // challenge_reveal reads the vault too (the alternative's total), closes its commit and opens
    // its Challenge PDA.
    assert_eq!(
        account_names("challenge_reveal"),
        [
            "challenger",
            "config",
            "escrow",
            "mint",
            "vault",
            "commit",
            "challenge",
            "token_program",
            "system_program",
            "event_authority",
            "program"
        ]
    );
    assert_eq!(
        account_names("challenge_commit"),
        [
            "challenger",
            "config",
            "escrow",
            "commit",
            "system_program",
            "event_authority",
            "program"
        ]
    );
    // The commit PDA as the client derives it: ["commit", escrow, challenger, hash].
    let commit_seeds = &named(
        &named(&idl["instructions"], "challenge_commit")["accounts"],
        "commit",
    )["pda"]["seeds"];
    assert_eq!(bytes(&commit_seeds[0]["value"]), COMMIT_SEED);
    assert_eq!(
        [
            &commit_seeds[1]["path"],
            &commit_seeds[2]["path"],
            &commit_seeds[3]["path"]
        ],
        [
            &Value::from("escrow"),
            &Value::from("challenger"),
            &Value::from("hash")
        ]
    );
    // Every instruction that reads the Config derives it the same way: ["config"].
    for (name, _, _) in &expected {
        let accounts = named(&idl["instructions"], name)["accounts"]
            .as_array()
            .unwrap()
            .clone();
        if let Some(config) = accounts.iter().find(|a| a["name"] == "config") {
            let seeds = config["pda"]["seeds"].as_array().expect("config seeds");
            assert_eq!(seeds.len(), 1, "{name}");
            assert_eq!(bytes(&seeds[0]["value"]), CONFIG_SEED, "{name}");
        }
    }
    // The Challenge PDA as the client derives it: ["challenge", escrow, alt_commitment].
    let challenge_seeds = &named(
        &named(&idl["instructions"], "challenge_reveal")["accounts"],
        "challenge",
    )["pda"]["seeds"];
    assert_eq!(bytes(&challenge_seeds[0]["value"]), CHALLENGE_SEED);
    assert_eq!(
        (&challenge_seeds[1]["kind"], &challenge_seeds[1]["path"]),
        (&Value::from("account"), &Value::from("escrow"))
    );
    assert_eq!(
        (&challenge_seeds[2]["kind"], &challenge_seeds[2]["path"]),
        (&Value::from("arg"), &Value::from("alt_commitment"))
    );
    assert_eq!(
        account_names("attest"),
        [
            "regrader",
            "escrow",
            "attestation",
            "challenge",
            "system_program",
            "config",
            "event_authority",
            "program"
        ]
    );
    assert_eq!(
        named(
            &named(&idl["instructions"], "attest")["accounts"],
            "challenge"
        )["optional"],
        true
    );
    assert_eq!(
        account_names("arbiter_resolve"),
        [
            "arbiter",
            "escrow",
            "mint",
            "vault",
            "resolver",
            "challenge",
            "challenger",
            "token_program",
            "config",
            "event_authority",
            "program"
        ]
    );
    // refund pays no challenger: close_challenge returns a bond a refund left held.
    assert_eq!(
        account_names("refund"),
        [
            "payer",
            "escrow",
            "mint",
            "vault",
            "refund_to",
            "refund_to_token_account",
            "resolver",
            "token_program",
            "associated_token_program",
            "system_program",
            "config",
            "destination",
            "event_authority",
            "program"
        ]
    );
    // The way back (refund, close_proposal) keeps the associated token account the client derives
    // ([owner, token program, mint] under the associated token program) and takes an optional,
    // writable destination of the owner's instead (the #852 audit's P2-2).
    for (name, owner, ata) in [
        ("refund", "refund_to", "refund_to_token_account"),
        ("close_proposal", "sponsor", "sponsor_token_account"),
    ] {
        let accounts = &named(&idl["instructions"], name)["accounts"];
        let pda = &named(accounts, ata)["pda"];
        let seed = |i: usize| (&pda["seeds"][i]["kind"], &pda["seeds"][i]["path"]);
        assert_eq!(
            [seed(0), seed(1), seed(2)],
            [
                (&Value::from("account"), &Value::from(owner)),
                (&Value::from("account"), &Value::from("token_program")),
                (&Value::from("account"), &Value::from("mint")),
            ],
            "{name}'s {ata}"
        );
        assert_eq!(
            bytes(&pda["program"]["value"]),
            anchor_spl::associated_token::ID.to_bytes(),
            "{name}'s {ata}"
        );
        assert_eq!(named(accounts, ata)["writable"], true);
        let destination = named(accounts, "destination");
        assert_eq!(
            (&destination["optional"], &destination["writable"]),
            (&Value::from(true), &Value::from(true)),
            "{name}'s destination"
        );
    }
    assert_eq!(
        account_names("close_challenge"),
        [
            "escrow",
            "challenge",
            "challenger",
            "event_authority",
            "program"
        ]
    );
    // close_attestation: the vote at its PDA ["attestation", escrow, regrader], its rent to the
    // regrader; nobody signs.
    assert_eq!(
        account_names("close_attestation"),
        [
            "escrow",
            "attestation",
            "regrader",
            "event_authority",
            "program"
        ]
    );
    let attestation_seeds = &named(
        &named(&idl["instructions"], "close_attestation")["accounts"],
        "attestation",
    )["pda"]["seeds"];
    assert_eq!(bytes(&attestation_seeds[0]["value"]), ATTESTATION_SEED);
    assert_eq!(
        [&attestation_seeds[1]["path"], &attestation_seeds[2]["path"]],
        [&Value::from("escrow"), &Value::from("regrader")]
    );
    assert_eq!(arg_names("set_min_regraders"), ["min_regraders"]);
    // The proposals: the sponsor and the curator both sign the submit; the curator's rules hash
    // is the one term written after it; the approval takes no argument, so it cannot change a
    // term; the return goes to an account the sponsor owns, never an argument.
    assert_eq!(arg_names("set_proposal_policy"), ["curator", "pending_cap"]);
    assert_eq!(
        arg_names("submit_proposal"),
        ["competition_id", "terms", "opens_at", "review_deadline"]
    );
    assert_eq!(arg_names("set_proposal_rules"), ["rules_sha256"]);
    assert_eq!(
        named(&idl["instructions"], "set_proposal_rules")["args"][0]["type"],
        serde_json::json!({ "array": ["u8", 32] })
    );
    assert!(arg_names("approve_proposal").is_empty());
    assert_eq!(arg_names("close_proposal"), ["reason_sha256"]);
    assert_eq!(
        account_names("submit_proposal"),
        [
            "sponsor",
            "curator",
            "proposal",
            "mint",
            "sponsor_token_account",
            "proposal_vault",
            "escrow",
            "config",
            "token_program",
            "associated_token_program",
            "system_program",
            "event_authority",
            "program"
        ]
    );
    for signer in ["sponsor", "curator"] {
        assert_eq!(
            named(
                &named(&idl["instructions"], "submit_proposal")["accounts"],
                signer
            )["signer"],
            true,
            "{signer} signs the submit"
        );
    }
    // set_proposal_rules writes the proposal alone: the curator signs and pays nothing, and the
    // Config is read, never written.
    assert_eq!(
        account_names("set_proposal_rules"),
        [
            "curator",
            "proposal",
            "config",
            "event_authority",
            "program"
        ]
    );
    let rules_account = |account: &str| -> Value {
        named(
            &named(&idl["instructions"], "set_proposal_rules")["accounts"],
            account,
        )
        .clone()
    };
    assert_eq!(rules_account("curator")["signer"], true);
    assert_ne!(rules_account("curator")["writable"], true);
    assert_eq!(rules_account("proposal")["writable"], true);
    assert_ne!(rules_account("proposal")["signer"], true);
    assert_ne!(rules_account("config")["writable"], true);
    assert_eq!(
        account_names("approve_proposal"),
        [
            "curator",
            "proposal",
            "proposal_vault",
            "escrow",
            "escrow_vault",
            "mint",
            "sponsor",
            "config",
            "token_program",
            "associated_token_program",
            "system_program",
            "event_authority",
            "program"
        ]
    );
    assert_eq!(
        account_names("close_proposal"),
        [
            "authority",
            "proposal",
            "proposal_vault",
            "mint",
            "sponsor",
            "sponsor_token_account",
            "config",
            "token_program",
            "associated_token_program",
            "system_program",
            "destination",
            "event_authority",
            "program"
        ]
    );
    // The wind-down: retire and close_escrow are the admin's alone; close_config is the admin's
    // as the program's upgrade authority (its ProgramData read, as initialize_config's is); none
    // takes an argument, and close_escrow's lamports go to the escrow's refund_to (has_one).
    // close_receipt is anyone's: the claimant only receives the rent.
    for name in ["retire", "close_escrow", "close_config", "close_receipt"] {
        assert!(arg_names(name).is_empty(), "{name} takes no argument");
    }
    assert_eq!(
        account_names("retire"),
        ["admin", "config", "event_authority", "program"]
    );
    assert_eq!(
        account_names("close_escrow"),
        [
            "admin",
            "config",
            "escrow",
            "refund_to",
            "event_authority",
            "program"
        ]
    );
    assert_eq!(
        account_names("close_config"),
        [
            "admin",
            "config",
            "program_data",
            "recipient",
            "event_authority",
            "program"
        ]
    );
    let signs = |ix: &str, account: &str| -> bool {
        named(&named(&idl["instructions"], ix)["accounts"], account)["signer"] == true
    };
    for ix in ["retire", "close_escrow", "close_config"] {
        assert!(signs(ix, "admin"), "the admin signs {ix}");
    }
    assert!(!signs("close_escrow", "refund_to"));
    assert!(!signs("close_config", "recipient"));
    assert_eq!(
        account_names("close_receipt"),
        ["claimant", "escrow", "receipt", "event_authority", "program"]
    );
    assert!(
        !signs("close_receipt", "claimant"),
        "close_receipt is permissionless"
    );
    let close_config_data = &named(
        &named(&idl["instructions"], "close_config")["accounts"],
        "program_data",
    )["pda"];
    assert_eq!(
        bytes(&close_config_data["seeds"][0]["value"]),
        prize_escrow::ID.as_ref()
    );
    // The proposal PDA as the client derives it: ["proposal", sponsor, competition_id]; the
    // approval opens the escrow at ["escrow", proposal.sponsor, proposal.competition_id].
    let proposal_seeds = &named(
        &named(&idl["instructions"], "submit_proposal")["accounts"],
        "proposal",
    )["pda"]["seeds"];
    assert_eq!(bytes(&proposal_seeds[0]["value"]), PROPOSAL_SEED);
    assert_eq!(
        (&proposal_seeds[1]["kind"], &proposal_seeds[1]["path"]),
        (&Value::from("account"), &Value::from("sponsor"))
    );
    assert_eq!(
        (&proposal_seeds[2]["kind"], &proposal_seeds[2]["path"]),
        (&Value::from("arg"), &Value::from("competition_id"))
    );
    let approved_escrow_seeds = &named(
        &named(&idl["instructions"], "approve_proposal")["accounts"],
        "escrow",
    )["pda"]["seeds"];
    assert_eq!(bytes(&approved_escrow_seeds[0]["value"]), ESCROW_SEED);
    assert_eq!(
        [
            &approved_escrow_seeds[1]["path"],
            &approved_escrow_seeds[2]["path"]
        ],
        [
            &Value::from("proposal.sponsor"),
            &Value::from("proposal.competition_id")
        ]
    );
    // set_proposal_rules holds the proposal to its own PDA, read from the account it names:
    // ["proposal", proposal.sponsor, proposal.competition_id].
    let rules_proposal_seeds = &rules_account("proposal")["pda"]["seeds"];
    assert_eq!(rules_proposal_seeds.as_array().unwrap().len(), 3);
    assert_eq!(bytes(&rules_proposal_seeds[0]["value"]), PROPOSAL_SEED);
    assert_eq!(
        [
            &rules_proposal_seeds[1]["path"],
            &rules_proposal_seeds[2]["path"]
        ],
        [
            &Value::from("proposal.sponsor"),
            &Value::from("proposal.competition_id")
        ]
    );
    let variants = |name: &str| -> Vec<String> {
        named(&idl["types"], name)["type"]["variants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["name"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        variants("SettleOutcome"),
        ["Undisputed", "ResultUpheld", "AltApplied", "NoQuorum"]
    );
    assert_eq!(variants("ArbiterChoice"), ["Posted", "Alternative"]);
    assert_eq!(
        variants("StopState"),
        ["Normal", "IntakeStop", "PayoutStop"]
    );
    assert_eq!(variants("AllowList"), ["Mint", "Sponsor", "Regrader"]);
    assert_eq!(
        variants("EscrowRole"),
        ["Resolver", "Compliance", "Regrader"]
    );
    assert_eq!(variants("ConfigRole"), ["Guardian", "Arbiter"]);
    // Append only: the variant is the event's u8 tag (ProposalPolicySet follows MinRegradersSet).
    assert_eq!(
        variants("ConfigChange"),
        [
            "Initialized",
            "AdminProposed",
            "AdminAccepted",
            "GuardianSet",
            "ArbiterSet",
            "LimitsSet",
            "FloorsSet",
            "Allowed",
            "Disallowed",
            "MinRegradersSet",
            "ProposalPolicySet"
        ]
    );
    assert_eq!(
        variants("ProposalCloseKind"),
        ["Withdrawn", "Rejected", "Expired"]
    );
    let fields = |name: &str| -> Vec<String> {
        named(&idl["types"], name)["type"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap().to_owned())
            .collect()
    };
    // Config's min_regraders, then the proposal policy, the wind-down and the house sponsors, sit
    // where reserved began, so the fields before them keep their bytes; ConfigChanged appends the
    // first two in the same order, so an event from before either ends where its fields start.
    let config_fields = fields("Config");
    assert_eq!(
        config_fields[config_fields.len() - 9..],
        [
            "revoked",
            "min_regraders",
            "curator",
            "pending_value",
            "pending_cap",
            "retired",
            "live_escrows",
            "house_sponsors",
            "reserved"
        ]
    );
    assert_eq!(
        fields("ConfigRetired"),
        [
            "config",
            "by",
            "open_value",
            "pending_value",
            "live_escrows"
        ]
    );
    assert_eq!(
        fields("EscrowClosed"),
        [
            "escrow",
            "competition_id",
            "sponsor",
            "refund_to",
            "lamports",
            "live_escrows"
        ]
    );
    assert_eq!(
        fields("ConfigClosed"),
        ["config", "by", "recipient", "lamports"]
    );
    assert_eq!(
        fields("ProposalRulesSet"),
        ["proposal", "sponsor", "competition_id", "rules_sha256"]
    );
    let config_changed = fields("ConfigChanged");
    assert_eq!(
        config_changed[config_changed.len() - 5..],
        [
            "reveal_grace",
            "min_regraders",
            "curator",
            "pending_value",
            "pending_cap"
        ]
    );
    assert_eq!(
        fields("AttestationClosed"),
        [
            "escrow",
            "attestation",
            "regrader",
            "commitment",
            "side",
            "rent_returned"
        ]
    );
    assert_eq!(
        fields("Settled"),
        [
            "escrow",
            "outcome",
            "status",
            "votes_result",
            "votes_alt",
            "claim_deadline",
            "result_sha256",
            "payout_root",
            "total",
            "commitment",
            "challenger",
            "resolver_paid",
            "challenger_paid"
        ]
    );
    assert_eq!(
        fields("ArbiterResolved"),
        [
            "escrow",
            "arbiter",
            "choice",
            "payout_root",
            "result_sha256",
            "total",
            "commitment",
            "challenge",
            "challenger",
            "claim_deadline",
            "resolver_paid",
            "challenger_paid"
        ]
    );
    assert_eq!(
        fields("Challenged"),
        [
            "escrow",
            "commit",
            "challenge",
            "challenger",
            "commitment",
            "alt_result_sha256",
            "alt_payout_root",
            "alt_total",
            "alt_commitment",
            "challenger_bond",
            "index",
            "challenge_count",
            "attest_deadline"
        ]
    );
    assert_eq!(
        fields("Attested"),
        [
            "escrow",
            "regrader",
            "commitment",
            "side",
            "challenge",
            "votes",
            "quorum",
            "votes_result",
            "votes_alt"
        ]
    );
    // The escrow PDA as the client derives it: ["escrow", sponsor, competition_id].
    let escrow_seeds = &named(
        &named(&idl["instructions"], "open_escrow")["accounts"],
        "escrow",
    )["pda"]["seeds"];
    assert_eq!(bytes(&escrow_seeds[0]["value"]), ESCROW_SEED);
    assert_eq!(
        (&escrow_seeds[1]["kind"], &escrow_seeds[1]["path"]),
        (&Value::from("account"), &Value::from("sponsor"))
    );
    assert_eq!(
        (&escrow_seeds[2]["kind"], &escrow_seeds[2]["path"]),
        (&Value::from("arg"), &Value::from("competition_id"))
    );
    assert_eq!(escrow_seeds.as_array().unwrap().len(), 3);

    let accounts: [(&str, &[u8]); 7] = [
        ("Escrow", Escrow::DISCRIMINATOR),
        ("Proposal", Proposal::DISCRIMINATOR),
        ("ClaimReceipt", ClaimReceipt::DISCRIMINATOR),
        ("Attestation", Attestation::DISCRIMINATOR),
        ("ChallengeRecord", ChallengeRecord::DISCRIMINATOR),
        ("CommitRecord", CommitRecord::DISCRIMINATOR),
        ("Config", Config::DISCRIMINATOR),
    ];
    assert_eq!(idl["accounts"].as_array().unwrap().len(), accounts.len());
    for (name, disc) in accounts {
        assert_eq!(
            bytes(&named(&idl["accounts"], name)["discriminator"]),
            disc,
            "{name}"
        );
    }

    let events: [(&str, &[u8]); 31] = [
        (
            "ProposalSubmitted",
            prize_escrow::ProposalSubmitted::DISCRIMINATOR,
        ),
        (
            "ProposalApproved",
            prize_escrow::ProposalApproved::DISCRIMINATOR,
        ),
        (
            "ProposalRulesSet",
            prize_escrow::ProposalRulesSet::DISCRIMINATOR,
        ),
        (
            "ProposalClosed",
            prize_escrow::ProposalClosed::DISCRIMINATOR,
        ),
        (
            "ChallengeCommitted",
            prize_escrow::ChallengeCommitted::DISCRIMINATOR,
        ),
        ("CommitClosed", prize_escrow::CommitClosed::DISCRIMINATOR),
        ("ConfigChanged", prize_escrow::ConfigChanged::DISCRIMINATOR),
        ("StopChanged", prize_escrow::StopChanged::DISCRIMINATOR),
        ("FreezeChanged", prize_escrow::FreezeChanged::DISCRIMINATOR),
        ("Escalated", prize_escrow::Escalated::DISCRIMINATOR),
        (
            "RevocationChanged",
            prize_escrow::RevocationChanged::DISCRIMINATOR,
        ),
        ("RoleRotated", prize_escrow::RoleRotated::DISCRIMINATOR),
        ("EscrowOpened", prize_escrow::EscrowOpened::DISCRIMINATOR),
        ("EscrowFunded", prize_escrow::EscrowFunded::DISCRIMINATOR),
        (
            "EntriesCommitted",
            prize_escrow::EntriesCommitted::DISCRIMINATOR,
        ),
        ("ResultPosted", prize_escrow::ResultPosted::DISCRIMINATOR),
        ("Challenged", prize_escrow::Challenged::DISCRIMINATOR),
        ("Attested", prize_escrow::Attested::DISCRIMINATOR),
        ("Settled", prize_escrow::Settled::DISCRIMINATOR),
        (
            "ArbiterResolved",
            prize_escrow::ArbiterResolved::DISCRIMINATOR,
        ),
        (
            "ClaimRequested",
            prize_escrow::ClaimRequested::DISCRIMINATOR,
        ),
        ("Claimed", prize_escrow::Claimed::DISCRIMINATOR),
        ("HoldPlaced", prize_escrow::HoldPlaced::DISCRIMINATOR),
        ("HoldReleased", prize_escrow::HoldReleased::DISCRIMINATOR),
        ("Refunded", prize_escrow::Refunded::DISCRIMINATOR),
        ("ReceiptClosed", prize_escrow::ReceiptClosed::DISCRIMINATOR),
        (
            "ChallengeClosed",
            prize_escrow::ChallengeClosed::DISCRIMINATOR,
        ),
        (
            "AttestationClosed",
            prize_escrow::AttestationClosed::DISCRIMINATOR,
        ),
        ("ConfigRetired", prize_escrow::ConfigRetired::DISCRIMINATOR),
        ("EscrowClosed", prize_escrow::EscrowClosed::DISCRIMINATOR),
        ("ConfigClosed", prize_escrow::ConfigClosed::DISCRIMINATOR),
    ];
    assert_eq!(idl["events"].as_array().unwrap().len(), events.len());
    for (name, disc) in events {
        assert_eq!(
            bytes(&named(&idl["events"], name)["discriminator"]),
            disc,
            "{name}"
        );
    }

    let idl_errors: Vec<(u64, &str)> = idl["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["code"].as_u64().unwrap(), e["name"].as_str().unwrap()))
        .collect();
    let rust_errors: Vec<(u64, &str)> = ERRORS
        .iter()
        .enumerate()
        .map(|(i, (err, name))| {
            assert_eq!(u32::from(*err), ERROR_CODE_OFFSET + i as u32, "{name}");
            (u64::from(u32::from(*err)), *name)
        })
        .collect();
    assert_eq!(idl_errors, rust_errors);

    for (name, value) in [
        ("MIN_CHALLENGE_WINDOW", MIN_CHALLENGE_WINDOW.to_string()),
        ("MIN_ATTEST_WINDOW", MIN_ATTEST_WINDOW.to_string()),
        ("MIN_HOLD_WINDOW", MIN_HOLD_WINDOW.to_string()),
        ("MIN_CLAIM_WINDOW", MIN_CLAIM_WINDOW.to_string()),
        ("BOND_FLOOR_RENTS", BOND_FLOOR_RENTS.to_string()),
        ("MAX_WINDOW", MAX_WINDOW.to_string()),
        ("MAX_PROOF_LEN", MAX_PROOF_LEN.to_string()),
        ("MAX_REGRADERS", MAX_REGRADERS.to_string()),
        ("DEFAULT_MIN_REGRADERS", DEFAULT_MIN_REGRADERS.to_string()),
        ("ARBITER_SLACK", ARBITER_SLACK.to_string()),
        ("STOP_DURATION", STOP_DURATION.to_string()),
        ("MIN_REVEAL_GRACE", MIN_REVEAL_GRACE.to_string()),
        ("MAX_REVEAL_GRACE", MAX_REVEAL_GRACE.to_string()),
        ("MAX_REVIEW_WINDOW", MAX_REVIEW_WINDOW.to_string()),
        ("MIN_RESOLVE_WINDOW", MIN_RESOLVE_WINDOW.to_string()),
        ("MAX_PROPOSAL_BOND", MAX_PROPOSAL_BOND.to_string()),
    ] {
        assert_eq!(named(&idl["constants"], name)["value"], value, "{name}");
    }
}

// --------------------------------------------------------------------------- the program

/// Fixed role keys for layout tests; the LiteSVM world uses keypairs.
struct Ids {
    sponsor: Pubkey,
    resolver: Pubkey,
    compliance: Pubkey,
    arbiter: Pubkey,
    refund_to: Pubkey,
    mint: Pubkey,
    challenger: Pubkey,
    claimant: Pubkey,
    regraders: [Pubkey; 3],
}

impl Ids {
    fn fixed() -> Self {
        let k = |b: u8| Pubkey::new_from_array([b; 32]);
        Ids {
            sponsor: k(1),
            resolver: k(2),
            compliance: k(3),
            arbiter: k(4),
            refund_to: k(5),
            mint: k(6),
            challenger: k(7),
            claimant: k(8),
            regraders: [k(9), k(10), k(11)],
        }
    }
}

fn escrow_pda(sponsor: &Pubkey, competition_id: &[u8; 16]) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[ESCROW_SEED, sponsor.as_ref(), competition_id],
        &prize_escrow::ID,
    )
}

fn receipt_pda(escrow: &Pubkey, claimant: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[CLAIM_SEED, escrow.as_ref(), claimant.as_ref()],
        &prize_escrow::ID,
    )
}

fn attestation_pda(escrow: &Pubkey, regrader: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[ATTESTATION_SEED, escrow.as_ref(), regrader.as_ref()],
        &prize_escrow::ID,
    )
}

fn sample_terms(ids: &Ids, now: i64) -> EscrowTerms {
    EscrowTerms {
        total: TOTAL,
        rules_sha256: [1; 32],
        resolver: ids.resolver,
        compliance: ids.compliance,
        arbiter: ids.arbiter,
        refund_to: ids.refund_to,
        regraders: ids.regraders.to_vec(),
        k: 2,
        bond_lamports: BOND,
        entries_deadline: now + 3_600,
        final_end: now + 5_400,
        resolve_deadline: now + 7_200,
        challenge_window: MIN_CHALLENGE_WINDOW,
        attest_window: MIN_ATTEST_WINDOW,
        hold_window: MIN_HOLD_WINDOW,
        claim_window: 30 * 24 * 3_600,
        hard_deadline: now + 365 * 24 * 3_600,
    }
}

fn sample_escrow(ids: &Ids, bump: u8, status: EscrowStatus) -> Escrow {
    let mut regraders = [Pubkey::default(); 5];
    regraders[..3].copy_from_slice(&ids.regraders);
    Escrow {
        bump,
        decimals: DECIMALS,
        status,
        k: 2,
        n: 3,
        competition_id: CID,
        sponsor: ids.sponsor,
        resolver: ids.resolver,
        compliance: ids.compliance,
        arbiter: ids.arbiter,
        refund_to: ids.refund_to,
        mint: ids.mint,
        challenger: ids.challenger,
        rules_sha256: [1; 32],
        entries_root: [2; 32],
        payout_root: [3; 32],
        result_sha256: [4; 32],
        kit_sha256: [5; 32],
        commitment: [7; 32],
        alt_result_sha256: [6; 32],
        alt_payout_root: [8; 32],
        alt_commitment: [9; 32],
        entries_count: 3,
        challenge_count: 1,
        total: TOTAL,
        total_claimed: 0,
        alt_total: TOTAL,
        bond_lamports: BOND,
        resolver_bond: BOND,
        challenger_bond: BOND,
        entries_deadline: 1,
        final_end: 1,
        resolve_deadline: 2,
        challenge_window: MIN_CHALLENGE_WINDOW,
        attest_window: MIN_ATTEST_WINDOW,
        hold_window: MIN_HOLD_WINDOW,
        claim_window: 30 * 24 * 3_600,
        challenge_deadline: 3,
        attest_deadline: 4,
        claim_deadline: 5,
        hard_deadline: 6,
        votes_result: 0,
        votes_alt: 0,
        regraders,
        deposited: TOTAL,
        stop_base: 0,
        freeze_since: 0,
        freeze_until: 0,
        frozen_secs: 0,
        reveal_grace: MIN_REVEAL_GRACE,
        commit_bond: 0,
        pending_commits: 0,
        reserved: [0; 64],
    }
}

/// A challenge of `escrow` by `challenger` of the sample's alternative ([6; 32], [8; 32], TOTAL
/// - 1), stored with its real commitment.
fn sample_challenge(escrow: &Pubkey, challenger: &Pubkey, bump: u8) -> ChallengeRecord {
    ChallengeRecord {
        escrow: *escrow,
        challenger: *challenger,
        alt_result_sha256: [6; 32],
        alt_payout_root: [8; 32],
        alt_commitment: result_commitment(&[6; 32], &[8; 32], TOTAL - 1),
        alt_total: TOTAL - 1,
        bond: BOND,
        opened_at: 3,
        index: 0,
        votes: 0,
        bump,
    }
}

fn challenge_pda(escrow: &Pubkey, alt_commitment: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[CHALLENGE_SEED, escrow.as_ref(), alt_commitment.as_ref()],
        &prize_escrow::ID,
    )
}

fn sample_receipt(claimant: Pubkey, bump: u8) -> ClaimReceipt {
    ClaimReceipt {
        claimant,
        total_amount: TOTAL,
        amount_claimed: TOTAL / 2,
        requested_at: 0,
        hold_reason: HOLD_NONE,
        held_at: 0,
        bump,
    }
}

/// A LiteSVM with the program loaded, every role funded, a classic-Token mint, the sponsor's
/// token account, and an escrow (seeds ["escrow", sponsor, CID]) with its vault already in place.
struct World {
    svm: LiteSVM,
    payer: Keypair,
    sponsor: Keypair,
    resolver: Keypair,
    compliance: Keypair,
    arbiter: Keypair,
    challenger: Keypair,
    regrader: Keypair,
    claimant: Keypair,
    stranger: Keypair,
    regrader_keys: [Pubkey; 3],
    refund_to: Pubkey,
    mint: Pubkey,
    sponsor_token_account: Pubkey,
    escrow: Pubkey,
    vault: Pubkey,
}

impl World {
    fn new(status: EscrowStatus) -> Self {
        let mut svm = mainnet::svm();
        svm.add_program(prize_escrow::ID, program_so::bytes())
            .unwrap();

        let payer = Keypair::new();
        let sponsor = Keypair::new();
        let resolver = Keypair::new();
        let compliance = Keypair::new();
        let arbiter = Keypair::new();
        let challenger = Keypair::new();
        let regrader = Keypair::new();
        let claimant = Keypair::new();
        let stranger = Keypair::new();
        for kp in [
            &payer,
            &sponsor,
            &resolver,
            &compliance,
            &arbiter,
            &challenger,
            &regrader,
            &claimant,
            &stranger,
        ] {
            svm.airdrop(&kp.pubkey(), 10 * SOL).unwrap();
        }
        let regrader_keys = [
            regrader.pubkey(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        ];
        let refund_to = Pubkey::new_unique();

        let mint = Pubkey::new_unique();
        set_mint(&mut svm, mint, &sponsor.pubkey());
        let sponsor_token_account = Pubkey::new_unique();
        set_token_account(
            &mut svm,
            sponsor_token_account,
            mint,
            sponsor.pubkey(),
            4 * TOTAL,
        );

        let (escrow, bump) = escrow_pda(&sponsor.pubkey(), &CID);
        let ids = Ids {
            sponsor: sponsor.pubkey(),
            resolver: resolver.pubkey(),
            compliance: compliance.pubkey(),
            arbiter: arbiter.pubkey(),
            refund_to,
            mint,
            challenger: challenger.pubkey(),
            claimant: claimant.pubkey(),
            regraders: regrader_keys,
        };
        set_program_account(&mut svm, escrow, &sample_escrow(&ids, bump, status));
        // The Config every instruction reads, written in place (its creation by the upgrade
        // authority is tests/safeguards.rs's).
        let init = config_init(
            payer.pubkey(),
            payer.pubkey(),
            arbiter.pubkey(),
            &[mint],
            &[sponsor.pubkey()],
            &regrader_keys,
        );
        let config = Config::new(init, Config::pda().1, 0).unwrap();
        set_program_account(&mut svm, config_pda(), &config);
        let vault = get_associated_token_address(&escrow, &mint);
        set_token_account(&mut svm, vault, mint, escrow, TOTAL);

        World {
            svm,
            payer,
            sponsor,
            resolver,
            compliance,
            arbiter,
            challenger,
            regrader,
            claimant,
            stranger,
            regrader_keys,
            refund_to,
            mint,
            sponsor_token_account,
            escrow,
            vault,
        }
    }

    fn ids(&self) -> Ids {
        Ids {
            sponsor: self.sponsor.pubkey(),
            resolver: self.resolver.pubkey(),
            compliance: self.compliance.pubkey(),
            arbiter: self.arbiter.pubkey(),
            refund_to: self.refund_to,
            mint: self.mint,
            challenger: self.challenger.pubkey(),
            claimant: self.claimant.pubkey(),
            regraders: self.regrader_keys,
        }
    }

    /// Send `ix` with `payer` paying the fee and `signers` signing too.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn send(&mut self, ix: Instruction, signers: &[&Keypair]) -> TransactionResult {
        self.svm.expire_blockhash();
        let msg = Message::new_with_blockhash(
            &[ix],
            Some(&self.payer.pubkey()),
            &self.svm.latest_blockhash(),
        );
        let mut all = vec![&self.payer];
        all.extend_from_slice(signers);
        let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &all).unwrap();
        self.svm.send_transaction(tx)
    }

    fn put_receipt(&mut self, claimant: Pubkey) {
        let (receipt, bump) = receipt_pda(&self.escrow, &claimant);
        set_program_account(&mut self.svm, receipt, &sample_receipt(claimant, bump));
    }
}

fn rent(svm: &LiteSVM, len: usize) -> u64 {
    svm.minimum_balance_for_rent_exemption(len)
}

fn set_mint(svm: &mut LiteSVM, address: Pubkey, authority: &Pubkey) {
    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint {
        mint_authority: COption::Some(*authority),
        supply: 100 * TOTAL,
        decimals: DECIMALS,
        is_initialized: true,
        freeze_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    let lamports = rent(svm, data.len());
    svm.set_account(
        address,
        Account {
            lamports,
            data,
            owner: token::ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn set_token_account(svm: &mut LiteSVM, address: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64) {
    let mut data = vec![0u8; spl_token::state::Account::LEN];
    spl_token::state::Account {
        mint,
        owner,
        amount,
        delegate: COption::None,
        state: spl_token::state::AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    let lamports = rent(svm, data.len());
    svm.set_account(
        address,
        Account {
            lamports,
            data,
            owner: token::ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn set_program_account<T: AccountSerialize>(svm: &mut LiteSVM, address: Pubkey, value: &T) {
    let mut data = Vec::new();
    value.try_serialize(&mut data).unwrap();
    let lamports = rent(svm, data.len()) + 2 * BOND;
    svm.set_account(
        address,
        Account {
            lamports,
            data,
            owner: prize_escrow::ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn instruction(accounts: impl ToAccountMetas, data: impl InstructionData) -> Instruction {
    Instruction::new_with_bytes(
        prize_escrow::ID,
        &data.data(),
        accounts.to_account_metas(None),
    )
}

fn custom_code(result: &TransactionResult) -> Option<u32> {
    match result {
        Err(failed) => match &failed.err {
            TransactionError::InstructionError(0, InstructionError::Custom(code)) => Some(*code),
            _ => None,
        },
        Ok(_) => None,
    }
}

fn logs(result: &TransactionResult) -> String {
    match result {
        Ok(meta) => meta.pretty_logs(),
        Err(failed) => format!("{:?}\n{}", failed.err, failed.meta.pretty_logs()),
    }
}

/// The transaction failed with exactly `code` (an EscrowError or an Anchor ErrorCode).
fn assert_refused(result: TransactionResult, code: impl Into<u32>, what: &str) {
    let code = code.into();
    assert_eq!(
        custom_code(&result),
        Some(code),
        "{what}: expected error {code}, got {}",
        logs(&result)
    );
}

/// Account validation passed: the transaction succeeded, or failed past it: in a handler (an
/// EscrowError or a token-program error) or at a handler not built yet (its panic). Never an
/// Anchor instruction, constraint or account error (codes 100..6000).
fn assert_accounts_accepted(result: TransactionResult, what: &str) {
    if std::env::var_os("PRIZE_ESCROW_SHOW_LOGS").is_some() {
        eprintln!("{what}:\n{}", logs(&result));
    }
    let Err(failed) = &result else { return };
    let framework = custom_code(&result).is_some_and(|c| (100..ERROR_CODE_OFFSET).contains(&c));
    let handler_error = custom_code(&result).is_some();
    let stub_panic = failed.meta.logs.iter().any(|line| {
        let line = line.to_ascii_lowercase();
        line.contains("panicked") && line.contains("src/instructions/")
    });
    assert!(
        !framework && (handler_error || stub_panic),
        "{what}: account validation did not pass: {}",
        logs(&result)
    );
}

#[test]
fn every_instruction_is_dispatched() {
    let mut w = World::new(EscrowStatus::Open);
    for (name, disc, has_args) in instructions() {
        // No accounts and no arguments: the dispatcher finds the instruction, then Anchor
        // fails to read its arguments (or, with none, its first account).
        let result = w.send(
            Instruction::new_with_bytes(prize_escrow::ID, disc, vec![]),
            &[],
        );
        let want = if has_args {
            AnchorErrorCode::InstructionDidNotDeserialize
        } else {
            AnchorErrorCode::AccountNotEnoughKeys
        };
        assert_refused(result, want, name);
    }
    let unknown = w.send(
        Instruction::new_with_bytes(prize_escrow::ID, &[0u8; 8], vec![]),
        &[],
    );
    assert_refused(
        unknown,
        AnchorErrorCode::InstructionFallbackNotFound,
        "unknown",
    );
}

#[test]
fn open_escrow_accounts() {
    let mut w = World::new(EscrowStatus::Open);
    let cid = [0x22; 16];
    let (escrow, _) = escrow_pda(&w.sponsor.pubkey(), &cid);
    let terms = sample_terms(&w.ids(), 1_800_000_000);
    let open = |escrow: Pubkey, w: &World| {
        instruction(
            accts::OpenEscrow {
                sponsor: w.sponsor.pubkey(),
                escrow,
                mint: w.mint,
                sponsor_token_account: w.sponsor_token_account,
                vault: get_associated_token_address(&escrow, &w.mint),
                token_program: token::ID,
                associated_token_program: associated_token::ID,
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::OpenEscrow {
                competition_id: cid,
                terms: terms.clone(),
            },
        )
    };

    let (wrong, _) = escrow_pda(&w.sponsor.pubkey(), &[0x33; 16]);
    let ix = open(wrong, &w);
    let sponsor = w.sponsor.insecure_clone();
    assert_refused(
        w.send(ix, &[&sponsor]),
        AnchorErrorCode::ConstraintSeeds,
        "open_escrow with another competition's PDA",
    );
    let (squatted, _) = escrow_pda(&w.stranger.pubkey(), &cid);
    let ix = open(squatted, &w);
    assert_refused(
        w.send(ix, &[&sponsor]),
        AnchorErrorCode::ConstraintSeeds,
        "open_escrow with another sponsor's PDA for the competition",
    );

    let mut ix = open(escrow, &w);
    ix.accounts[3].pubkey = {
        let foreign = Pubkey::new_unique();
        set_token_account(&mut w.svm, foreign, w.mint, w.stranger.pubkey(), TOTAL);
        foreign
    };
    assert_refused(
        w.send(ix, &[&sponsor]),
        AnchorErrorCode::ConstraintTokenOwner,
        "open_escrow from someone else's token account",
    );

    let ix = open(escrow, &w);
    assert_accounts_accepted(w.send(ix, &[&sponsor]), "open_escrow");
}

#[test]
fn fund_commit_and_post_accounts() {
    let mut w = World::new(EscrowStatus::Open);
    let fund = |sponsor: Pubkey, from: Pubkey, w: &World| {
        instruction(
            accts::Fund {
                sponsor,
                escrow: w.escrow,
                mint: w.mint,
                sponsor_token_account: from,
                vault: w.vault,
                token_program: token::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Fund { amount: 1 },
        )
    };
    let stranger = w.stranger.insecure_clone();
    let strangers_account = Pubkey::new_unique();
    set_token_account(
        &mut w.svm,
        strangers_account,
        w.mint,
        stranger.pubkey(),
        TOTAL,
    );
    let ix = fund(stranger.pubkey(), strangers_account, &w);
    assert_refused(
        w.send(ix, &[&stranger]),
        EscrowError::UnauthorizedSponsor,
        "fund by a stranger",
    );
    let sponsor = w.sponsor.insecure_clone();
    let ix = fund(sponsor.pubkey(), w.sponsor_token_account, &w);
    assert_accounts_accepted(w.send(ix, &[&sponsor]), "fund");

    let commit = |resolver: Pubkey, w: &World| {
        instruction(
            accts::CommitEntries {
                resolver,
                escrow: w.escrow,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::CommitEntries {
                entries_root: [7; 32],
                entries_count: 3,
            },
        )
    };
    let ix = commit(stranger.pubkey(), &w);
    assert_refused(
        w.send(ix, &[&stranger]),
        EscrowError::UnauthorizedResolver,
        "commit_entries by a stranger",
    );
    let resolver = w.resolver.insecure_clone();
    let ix = commit(resolver.pubkey(), &w);
    assert_accounts_accepted(w.send(ix, &[&resolver]), "commit_entries");

    let post = |resolver: Pubkey, w: &World| {
        instruction(
            accts::PostResult {
                resolver,
                escrow: w.escrow,
                mint: w.mint,
                vault: w.vault,
                token_program: token::ID,
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::PostResult {
                payout_root: [3; 32],
                result_sha256: [4; 32],
                kit_sha256: [5; 32],
                total: TOTAL,
            },
        )
    };
    let ix = post(stranger.pubkey(), &w);
    assert_refused(
        w.send(ix, &[&stranger]),
        EscrowError::UnauthorizedResolver,
        "post_result by a stranger",
    );
    let ix = post(resolver.pubkey(), &w);
    assert_accounts_accepted(w.send(ix, &[&resolver]), "post_result");
}

#[test]
fn challenge_attest_settle_and_arbiter_accounts() {
    let mut w = World::new(EscrowStatus::Disputed);
    let challenger = w.challenger.insecure_clone();
    let alt_commitment = result_commitment(&[6; 32], &[8; 32], TOTAL);
    let salt = [0x5a; 32];
    let hash = commit_hash(&alt_commitment, &w.challenger.pubkey(), &salt);
    let commit_ix = |commit: Pubkey, w: &World| {
        instruction(
            accts::ChallengeCommit {
                challenger: w.challenger.pubkey(),
                config: config_pda(),
                escrow: w.escrow,
                commit,
                system_program: system_program::ID,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ChallengeCommit { hash },
        )
    };
    // The commit's PDA names its challenger: another's seeds are refused.
    let (foreign_commit, _) = CommitRecord::pda(&w.escrow, &w.stranger.pubkey(), &hash);
    let ix = commit_ix(foreign_commit, &w);
    assert_refused(
        w.send(ix, &[&challenger]),
        AnchorErrorCode::ConstraintSeeds,
        "a commit at another challenger's address",
    );
    let (commit, commit_bump) = CommitRecord::pda(&w.escrow, &w.challenger.pubkey(), &hash);
    let ix = commit_ix(commit, &w);
    assert_accounts_accepted(w.send(ix, &[&challenger]), "challenge_commit");

    // A commit in place for the reveal.
    set_program_account(
        &mut w.svm,
        commit,
        &CommitRecord {
            escrow: w.escrow,
            challenger: w.challenger.pubkey(),
            hash,
            slot: 0,
            committed_at: 0,
            bond: BOND,
            bump: commit_bump,
        },
    );
    let reveal_ix = |pda: Pubkey, w: &World| {
        instruction(
            accts::ChallengeReveal {
                challenger: w.challenger.pubkey(),
                config: config_pda(),
                escrow: w.escrow,
                mint: w.mint,
                vault: w.vault,
                commit,
                challenge: pda,
                token_program: token::ID,
                system_program: system_program::ID,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ChallengeReveal {
                salt,
                alt_result_sha256: [6; 32],
                alt_payout_root: [8; 32],
                alt_total: TOTAL,
                alt_commitment,
            },
        )
    };
    let (other, _) = challenge_pda(&w.escrow, &[0x55; 32]);
    let ix = reveal_ix(other, &w);
    assert_refused(
        w.send(ix, &[&challenger]),
        AnchorErrorCode::ConstraintSeeds,
        "a reveal into another commitment's PDA",
    );
    let (pda, _) = challenge_pda(&w.escrow, &alt_commitment);
    let ix = reveal_ix(pda, &w);
    // A stranger cannot reveal the challenger's commit: the commit's seeds name its challenger.
    let mut stranger_ix = ix.clone();
    stranger_ix.accounts[0].pubkey = w.stranger.pubkey();
    let stranger = w.stranger.insecure_clone();
    assert_refused(
        w.send(stranger_ix, &[&stranger]),
        AnchorErrorCode::ConstraintSeeds,
        "a reveal of another challenger's commit",
    );
    assert_accounts_accepted(w.send(ix, &[&challenger]), "challenge_reveal");

    // A Challenge PDA in place for attest and arbiter_resolve: the sample's (TOTAL - 1), and one
    // of another escrow with the same commitment.
    let sample = sample_challenge(&w.escrow, &w.challenger.pubkey(), 255);
    let (sample_pda, bump) = challenge_pda(&w.escrow, &sample.alt_commitment);
    set_program_account(
        &mut w.svm,
        sample_pda,
        &sample_challenge(&w.escrow, &w.challenger.pubkey(), bump),
    );
    let elsewhere = Pubkey::new_unique();
    let (foreign_pda, foreign_bump) = challenge_pda(&elsewhere, &sample.alt_commitment);
    set_program_account(
        &mut w.svm,
        foreign_pda,
        &sample_challenge(&elsewhere, &w.challenger.pubkey(), foreign_bump),
    );

    let regrader = w.regrader.insecure_clone();
    let attest =
        |attestation: Pubkey, challenge: Option<Pubkey>, commitment: [u8; 32], w: &World| {
            instruction(
                accts::Attest {
                    regrader: w.regrader.pubkey(),
                    escrow: w.escrow,
                    attestation,
                    challenge,
                    system_program: system_program::ID,
                    config: config_pda(),
                    event_authority: EVENT_AUTHORITY,
                    program: prize_escrow::ID,
                },
                ixs::Attest { commitment },
            )
        };
    let (wrong, _) = attestation_pda(&w.escrow, &w.stranger.pubkey());
    let ix = attest(wrong, None, [7; 32], &w);
    assert_refused(
        w.send(ix, &[&regrader]),
        AnchorErrorCode::ConstraintSeeds,
        "attest into another regrader's attestation",
    );
    let (attestation, _) = attestation_pda(&w.escrow, &regrader.pubkey());
    let ix = attest(attestation, Some(w.escrow), sample.alt_commitment, &w);
    assert_refused(
        w.send(ix, &[&regrader]),
        AnchorErrorCode::AccountDiscriminatorMismatch,
        "attest with an escrow posing as a challenge",
    );
    let ix = attest(attestation, Some(foreign_pda), sample.alt_commitment, &w);
    assert_refused(
        w.send(ix, &[&regrader]),
        EscrowError::ChallengeMismatch,
        "attest naming another escrow's challenge",
    );
    let ix = attest(attestation, Some(sample_pda), [7; 32], &w);
    assert_refused(
        w.send(ix, &[&regrader]),
        EscrowError::ChallengeMismatch,
        "attest naming a challenge of another commitment",
    );
    // This escrow's challenge record, of this commitment, but not at its own PDA.
    let off_pda = Pubkey::new_unique();
    set_program_account(
        &mut w.svm,
        off_pda,
        &sample_challenge(&w.escrow, &w.challenger.pubkey(), bump),
    );
    let ix = attest(attestation, Some(off_pda), sample.alt_commitment, &w);
    assert_refused(
        w.send(ix, &[&regrader]),
        EscrowError::ChallengeMismatch,
        "attest naming a challenge record off its PDA",
    );
    let ix = attest(attestation, Some(sample_pda), sample.alt_commitment, &w);
    assert_accounts_accepted(w.send(ix, &[&regrader]), "attest");

    let settle = |challenger: Option<Pubkey>, w: &World| {
        instruction(
            accts::Settle {
                escrow: w.escrow,
                mint: w.mint,
                vault: w.vault,
                resolver: w.resolver.pubkey(),
                challenger,
                token_program: token::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Settle {},
        )
    };
    let ix = settle(Some(w.stranger.pubkey()), &w);
    assert_refused(
        w.send(ix, &[]),
        AnchorErrorCode::ConstraintAddress,
        "settle paying a stranger as the challenger",
    );
    let mut ix = settle(Some(w.challenger.pubkey()), &w);
    ix.accounts[2].pubkey = {
        let foreign = Pubkey::new_unique();
        set_token_account(&mut w.svm, foreign, w.mint, w.escrow, 10 * TOTAL);
        foreign
    };
    assert_refused(
        w.send(ix, &[]),
        AnchorErrorCode::ConstraintAssociated,
        "settle reading another token account as the vault",
    );
    let ix = settle(Some(w.challenger.pubkey()), &w);
    assert_accounts_accepted(w.send(ix, &[]), "settle");
    let ix = settle(None, &w);
    assert_accounts_accepted(w.send(ix, &[]), "settle without a challenger");

    let resolve = |arbiter: Pubkey, challenge: Pubkey, w: &World| {
        instruction(
            accts::ArbiterResolve {
                arbiter,
                escrow: w.escrow,
                mint: w.mint,
                vault: w.vault,
                resolver: w.resolver.pubkey(),
                challenge: Some(challenge),
                challenger: Some(w.challenger.pubkey()),
                token_program: token::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ArbiterResolve {
                choice: ArbiterChoice::Alternative,
                commitment: sample.alt_commitment,
            },
        )
    };
    let stranger = w.stranger.insecure_clone();
    let ix = resolve(stranger.pubkey(), sample_pda, &w);
    assert_refused(
        w.send(ix, &[&stranger]),
        EscrowError::UnauthorizedArbiter,
        "arbiter_resolve by a stranger",
    );
    let arbiter = w.arbiter.insecure_clone();
    // The constraints pin the challenge account before the handler reads the status.
    let ix = resolve(arbiter.pubkey(), foreign_pda, &w);
    assert_refused(
        w.send(ix, &[&arbiter]),
        EscrowError::ChallengeMismatch,
        "arbiter_resolve naming another escrow's challenge, on a Disputed escrow",
    );
    let ix = resolve(arbiter.pubkey(), sample_pda, &w);
    assert_refused(
        w.send(ix, &[&arbiter]),
        EscrowError::InvalidStatus,
        "arbiter_resolve of a Disputed escrow",
    );
    let ix = resolve(arbiter.pubkey(), sample_pda, &w);
    assert_accounts_accepted(w.send(ix, &[&arbiter]), "arbiter_resolve");

    // Frozen: the arbiter's choice of a challenge of another escrow is refused.
    let mut frozen = World::new(EscrowStatus::Frozen);
    let (frozen_pda, bump) = challenge_pda(&frozen.escrow, &sample.alt_commitment);
    let mine = sample_challenge(&frozen.escrow, &frozen.challenger.pubkey(), bump);
    set_program_account(&mut frozen.svm, frozen_pda, &mine);
    let (foreign_pda, foreign_bump) = challenge_pda(&elsewhere, &sample.alt_commitment);
    set_program_account(
        &mut frozen.svm,
        foreign_pda,
        &sample_challenge(&elsewhere, &frozen.challenger.pubkey(), foreign_bump),
    );
    let arbiter = frozen.arbiter.insecure_clone();
    let ix = resolve(arbiter.pubkey(), foreign_pda, &frozen);
    assert_refused(
        frozen.send(ix, &[&arbiter]),
        EscrowError::ChallengeMismatch,
        "arbiter_resolve choosing another escrow's challenge",
    );
    let ix = resolve(arbiter.pubkey(), frozen_pda, &frozen);
    assert_accounts_accepted(
        frozen.send(ix, &[&arbiter]),
        "arbiter_resolve choosing its own challenge",
    );
}

#[test]
fn close_challenge_accounts() {
    let mut w = World::new(EscrowStatus::Claimable);
    let (pda, bump) = challenge_pda(&w.escrow, &result_commitment(&[6; 32], &[8; 32], TOTAL - 1));
    set_program_account(
        &mut w.svm,
        pda,
        &sample_challenge(&w.escrow, &w.challenger.pubkey(), bump),
    );
    let close = |challenge: Pubkey, challenger: Pubkey, w: &World| {
        instruction(
            accts::CloseChallenge {
                escrow: w.escrow,
                challenge,
                challenger,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::CloseChallenge {},
        )
    };
    let ix = close(pda, w.stranger.pubkey(), &w);
    assert_refused(
        w.send(ix, &[]),
        EscrowError::ChallengeMismatch,
        "close_challenge paying a stranger",
    );
    let elsewhere = Pubkey::new_unique();
    let (foreign, foreign_bump) = challenge_pda(&elsewhere, &[0x44; 32]);
    set_program_account(
        &mut w.svm,
        foreign,
        &sample_challenge(&elsewhere, &w.challenger.pubkey(), foreign_bump),
    );
    let ix = close(foreign, w.challenger.pubkey(), &w);
    assert_refused(
        w.send(ix, &[]),
        EscrowError::ChallengeMismatch,
        "close_challenge of another escrow's challenge",
    );
    let before = w.svm.get_account(&w.challenger.pubkey()).unwrap().lamports;
    let rent = w.svm.get_account(&pda).unwrap().lamports;
    let ix = close(pda, w.challenger.pubkey(), &w);
    let meta = w.send(ix, &[]);
    assert!(meta.is_ok(), "close_challenge: {}", logs(&meta));
    assert_eq!(
        w.svm.get_account(&w.challenger.pubkey()).unwrap().lamports,
        before + rent,
        "its rent back to its challenger"
    );
    assert!(w.svm.get_account(&pda).is_none_or(|a| a.lamports == 0));
}

#[test]
fn claim_accounts() {
    let mut w = World::new(EscrowStatus::Claimable);
    let claimant = w.claimant.insecure_clone();
    let compliance = w.compliance.insecure_clone();
    let stranger = w.stranger.insecure_clone();
    let (receipt, _) = receipt_pda(&w.escrow, &claimant.pubkey());

    let ix = instruction(
        accts::RequestClaim {
            claimant: claimant.pubkey(),
            payer: w.payer.pubkey(),
            escrow: w.escrow,
            receipt,
            system_program: system_program::ID,
            config: config_pda(),
            event_authority: EVENT_AUTHORITY,
            program: prize_escrow::ID,
        },
        ixs::RequestClaim {
            total_amount: TOTAL,
            proof: vec![[1; 32]; 3],
        },
    );
    assert_accounts_accepted(w.send(ix, &[&claimant]), "request_claim");

    let claim = |compliance: Option<Pubkey>, destination: Pubkey, w: &World| {
        instruction(
            accts::Claim {
                claimant: w.claimant.pubkey(),
                payer: w.payer.pubkey(),
                compliance,
                escrow: w.escrow,
                mint: w.mint,
                vault: w.vault,
                claimant_token_account: destination,
                receipt,
                token_program: token::ID,
                associated_token_program: associated_token::ID,
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Claim {
                total_amount: TOTAL,
                amount: 0,
                proof: vec![[1; 32]; 3],
            },
        )
    };
    let own_ata = get_associated_token_address(&claimant.pubkey(), &w.mint);

    let ix = claim(Some(stranger.pubkey()), own_ata, &w);
    assert_refused(
        w.send(ix, &[&claimant, &stranger]),
        EscrowError::UnauthorizedCompliance,
        "claim co-signed by a stranger",
    );

    // The destination owner pin: the claimant's own associated token account, nothing else.
    let foreign_ata = get_associated_token_address(&stranger.pubkey(), &w.mint);
    set_token_account(&mut w.svm, foreign_ata, w.mint, stranger.pubkey(), 0);
    let ix = claim(Some(compliance.pubkey()), foreign_ata, &w);
    assert_refused(
        w.send(ix, &[&claimant, &compliance]),
        AnchorErrorCode::ConstraintTokenOwner,
        "claim into someone else's token account",
    );
    let side_account = Pubkey::new_unique();
    set_token_account(&mut w.svm, side_account, w.mint, claimant.pubkey(), 0);
    let ix = claim(Some(compliance.pubkey()), side_account, &w);
    assert_refused(
        w.send(ix, &[&claimant, &compliance]),
        AnchorErrorCode::AccountNotAssociatedTokenAccount,
        "claim into a claimant-owned account that is not its associated one",
    );

    let ix = claim(Some(compliance.pubkey()), own_ata, &w);
    assert_accounts_accepted(w.send(ix, &[&claimant, &compliance]), "co-signed claim");
    let ix = claim(None, own_ata, &w);
    assert_accounts_accepted(w.send(ix, &[&claimant]), "claim without the co-signature");

    // The same claim against a vault of another mint: the escrow's mint pin refuses it.
    let other_mint = Pubkey::new_unique();
    set_mint(&mut w.svm, other_mint, &w.sponsor.pubkey());
    let other_vault = get_associated_token_address(&w.escrow, &other_mint);
    set_token_account(&mut w.svm, other_vault, other_mint, w.escrow, TOTAL);
    let mut ix = claim(
        None,
        get_associated_token_address(&claimant.pubkey(), &other_mint),
        &w,
    );
    ix.accounts[4].pubkey = other_mint;
    ix.accounts[5].pubkey = other_vault;
    assert_refused(
        w.send(ix, &[&claimant]),
        EscrowError::MintMismatch,
        "claim against another mint",
    );
}

#[test]
fn hold_and_release_accounts() {
    let mut w = World::new(EscrowStatus::Claimable);
    let claimant = w.claimant.pubkey();
    let (receipt, _) = receipt_pda(&w.escrow, &claimant);
    let hold = |compliance: Pubkey, receipt: Pubkey, w: &World| {
        instruction(
            accts::Hold {
                compliance,
                escrow: w.escrow,
                receipt,
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Hold {
                claimant,
                reason: HOLD_REVIEW,
            },
        )
    };
    let stranger = w.stranger.insecure_clone();
    let ix = hold(stranger.pubkey(), receipt, &w);
    assert_refused(
        w.send(ix, &[&stranger]),
        EscrowError::UnauthorizedCompliance,
        "hold by a stranger",
    );
    let compliance = w.compliance.insecure_clone();
    let (wrong, _) = receipt_pda(&w.escrow, &stranger.pubkey());
    let ix = hold(compliance.pubkey(), wrong, &w);
    assert_refused(
        w.send(ix, &[&compliance]),
        AnchorErrorCode::ConstraintSeeds,
        "hold on another claimant's receipt",
    );
    let ix = hold(compliance.pubkey(), receipt, &w);
    assert_accounts_accepted(w.send(ix, &[&compliance]), "hold");

    w.put_receipt(claimant);
    let release = |compliance: Pubkey, w: &World| {
        instruction(
            accts::ReleaseHold {
                compliance,
                escrow: w.escrow,
                receipt,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ReleaseHold { claimant },
        )
    };
    let ix = release(stranger.pubkey(), &w);
    assert_refused(
        w.send(ix, &[&stranger]),
        EscrowError::UnauthorizedCompliance,
        "release_hold by a stranger",
    );
    let ix = release(compliance.pubkey(), &w);
    assert_accounts_accepted(w.send(ix, &[&compliance]), "release_hold");
}

#[test]
fn refund_and_close_receipt_accounts() {
    let mut w = World::new(EscrowStatus::Frozen);
    let refund = |refund_to: Pubkey, w: &World| {
        instruction(
            accts::Refund {
                payer: w.payer.pubkey(),
                escrow: w.escrow,
                mint: w.mint,
                vault: w.vault,
                refund_to,
                refund_to_token_account: get_associated_token_address(&refund_to, &w.mint),
                resolver: w.resolver.pubkey(),
                token_program: token::ID,
                associated_token_program: associated_token::ID,
                system_program: system_program::ID,
                config: config_pda(),
                destination: None,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Refund {},
        )
    };
    let ix = refund(w.stranger.pubkey(), &w);
    assert_refused(
        w.send(ix, &[]),
        AnchorErrorCode::ConstraintHasOne,
        "refund to a stranger",
    );
    let ix = refund(w.refund_to, &w);
    assert_accounts_accepted(w.send(ix, &[]), "refund");

    let claimant = w.claimant.insecure_clone();
    w.put_receipt(claimant.pubkey());
    let (receipt, _) = receipt_pda(&w.escrow, &claimant.pubkey());
    let close = |claimant: Pubkey, w: &World| {
        instruction(
            accts::CloseReceipt {
                claimant,
                escrow: w.escrow,
                receipt,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::CloseReceipt {},
        )
    };
    // Nobody signs as the claimant (any fee payer sends it): the receipt's has_one and seeds pin
    // where its rent goes.
    let ix = close(w.stranger.pubkey(), &w);
    let refused = w.send(ix, &[]);
    assert!(
        matches!(
            custom_code(&refused),
            Some(c) if c == u32::from(AnchorErrorCode::ConstraintHasOne)
                || c == u32::from(AnchorErrorCode::ConstraintSeeds)
        ),
        "close_receipt paying a stranger: {}",
        logs(&refused)
    );
    let ix = close(claimant.pubkey(), &w);
    assert!(
        ix.accounts
            .iter()
            .all(|meta| meta.pubkey != claimant.pubkey() || !meta.is_signer),
        "close_receipt needs no claimant signature"
    );
    assert_accounts_accepted(w.send(ix, &[]), "close_receipt");
}

#[test]
fn events_ride_a_self_cpi_that_only_the_program_can_sign() {
    // The event authority is the PDA ["__event_authority"] of the program (what the Kit client
    // derives for every instruction).
    assert_eq!(
        EVENT_AUTHORITY,
        Pubkey::find_program_address(&[b"__event_authority"], &prize_escrow::ID).0
    );
    // The same address server/chain/escrow.ts eventAuthorityAddress() derives.
    assert_eq!(
        EVENT_AUTHORITY.to_string(),
        "FV9hAJBXtYcTSCbKEXdLGTpPxYq3ZSCufeaqwDTJ1KGN"
    );

    let mut w = World::new(EscrowStatus::Open);
    let sponsor = w.sponsor.insecure_clone();
    let fund = |event_authority: Pubkey, w: &World| {
        instruction(
            accts::Fund {
                sponsor: w.sponsor.pubkey(),
                escrow: w.escrow,
                mint: w.mint,
                sponsor_token_account: w.sponsor_token_account,
                vault: w.vault,
                token_program: token::ID,
                config: config_pda(),
                event_authority,
                program: prize_escrow::ID,
            },
            ixs::Fund { amount: 1 },
        )
    };

    // Another account in the event authority's slot is refused before the handler runs.
    let ix = fund(Pubkey::new_unique(), &w);
    assert_refused(
        w.send(ix, &[&sponsor]),
        AnchorErrorCode::ConstraintAddress,
        "fund with another account as the event authority",
    );

    // The real one: the event is an inner instruction of the program invoking itself with the
    // event authority signing, and nothing is logged as `Program data:`.
    let ix = fund(EVENT_AUTHORITY, &w);
    let result = w.send(ix, &[&sponsor]);
    let Ok(meta) = &result else {
        panic!("fund failed: {}", logs(&result))
    };
    let events: Vec<_> = meta
        .inner_instructions
        .iter()
        .flatten()
        .filter(|inner| inner.instruction.data.starts_with(EVENT_IX_TAG_LE))
        .collect();
    assert_eq!(events.len(), 1, "{}", logs(&result));
    assert_eq!(events[0].stack_height, 2);
    assert_eq!(
        &events[0].instruction.data[8..16],
        prize_escrow::EscrowFunded::DISCRIMINATOR
    );
    assert_eq!(events[0].instruction.accounts.len(), 1);
    assert!(!meta
        .logs
        .iter()
        .any(|line| line.starts_with("Program data: ")));

    // Nobody else can emit one: the event instruction needs the event authority's signature,
    // which only the program's own invoke_signed carries.
    let mut data = EVENT_IX_TAG_LE.to_vec();
    data.extend_from_slice(prize_escrow::EscrowFunded::DISCRIMINATOR);
    data.extend_from_slice(&[0; 32 + 32 + 8 + 8]);
    let forged = Instruction::new_with_bytes(
        prize_escrow::ID,
        &data,
        vec![AccountMeta::new_readonly(EVENT_AUTHORITY, false)],
    );
    assert_refused(
        w.send(forged, &[]),
        AnchorErrorCode::ConstraintSigner,
        "an event instruction from outside the program",
    );
    let stranger = w.stranger.insecure_clone();
    let forged = Instruction::new_with_bytes(
        prize_escrow::ID,
        &data,
        vec![AccountMeta::new_readonly(stranger.pubkey(), true)],
    );
    assert_refused(
        w.send(forged, &[&stranger]),
        AnchorErrorCode::ConstraintSeeds,
        "an event instruction signed by another key",
    );
}
