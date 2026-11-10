//! The proposals on the release build, on LiteSVM: a sponsor's deposit for review
//! (submit_proposal, co-signed by the Config's curator), its approval into the escrow its terms
//! open (approve_proposal) and its one way back (close_proposal: withdrawn by the sponsor,
//! rejected by the curator with a reason, expired by anyone after review_deadline).
//!
//! What holds: an approved proposal's escrow is field for field the one open_escrow opens with the
//! same terms at the same moment; every return puts the deposit and both rents back with the
//! sponsor; a revoked sponsor is held, neither approved nor returned; only the curator of the day
//! approves or rejects; the schedule keeps the review inside MAX_REVIEW_WINDOW and before the
//! competition opens; the pending cap, C_e and C_g hold proposals and direct opens together; a
//! donation never blocks an approval; IntakeStop stops submits and approvals but never the way
//! back, which only a PayoutStop holds; a proposal submitted with an all-zero rules hash is
//! approved only once the curator of the day sets it (set_proposal_rules), once and inside the
//! review.
//!
//! And the #852 audit's findings, its probes as the cases: a sponsor sets no self-dealing terms
//! (P2-1, probe P-B: itself or the curator as the resolver or the compliance key, a resolve window
//! under MIN_RESOLVE_WINDOW, a bond over MAX_PROPOSAL_BOND, at the submit and again at the
//! approval against today's curator); a sponsor that reassigned its associated token account's
//! owner pins neither its proposal nor its escrow's refund (P2-2, probes P-A and P-A2: the way
//! back takes any token account it owns); the curator sponsors nothing (P3-1, probe P-C); an
//! approval opens nothing over today's C_e (P3-2, probe P-D); a sponsor off the allowlist funds
//! nothing after its approval (P3-3); and past review_deadline anyone, a revoked curator included,
//! returns the deposit (P3-4, probe P-E).

mod mainnet;
mod program_so;
mod support;

use {
    anchor_lang::{
        error::ErrorCode as AnchorErrorCode, prelude::Pubkey, solana_program::program_pack::Pack,
        Discriminator,
    },
    litesvm::LiteSVM,
    prize_escrow::{
        AllowList, ConfigChange, ConfigChanged, ConfigRole, EscrowError, EscrowOpened,
        EscrowStatus, EscrowTerms, Proposal, ProposalApproved, ProposalCloseKind, ProposalClosed,
        ProposalRulesSet, ProposalSubmitted, Refunded, StopState, MAX_PROPOSAL_BOND,
        MAX_REVIEW_WINDOW, MIN_RESOLVE_WINDOW,
    },
    solana_keypair::Keypair,
    solana_signer::Signer,
    support::{
        expect_ok, expect_refused, keypair_derived, put_token_account, Chain, Panel, Role, Sent,
        World, DAY, HOUR, NOW, PENDING_CAP, SOL, SPONSOR_FUNDS, TOTAL,
    },
};

/// The competition id the tests propose (the world's own CID stays free for direct opens).
const PCID: [u8; 16] = [0x7c; 16];
/// Another, for a second proposal or a second direct open.
const OTHER: [u8; 16] = [0x7d; 16];
/// A rejection document's sha256.
const REASON: [u8; 32] = [0x4e; 32];
const NO_REASON: [u8; 32] = [0; 32];

/// The Config the support world creates (the sponsor allowlisted), proposals on (Role::Curator,
/// PENDING_CAP), nothing open or submitted, at NOW.
fn world() -> (LiteSVM, World) {
    let mut svm = mainnet::svm();
    svm.add_program(prize_escrow::ID, program_so::bytes())
        .unwrap();
    let w = World::create(&mut svm, Panel::HouseMajority, false);
    let policy =
        w.set_proposal_policy_ix(Role::Admin.pubkey(), Role::Curator.pubkey(), PENDING_CAP);
    let sent = expect_ok(
        w.send(&mut svm, policy, &[&Role::Admin.keypair()]),
        "set_proposal_policy",
    );
    let changed = sent.event::<ConfigChanged>();
    assert_eq!(
        (changed.change, changed.key, changed.by),
        (
            ConfigChange::ProposalPolicySet,
            Role::Curator.pubkey(),
            Role::Admin.pubkey()
        )
    );
    // The event carries the policy it set: the curator and the pending cap, nothing pending yet.
    assert_eq!(
        (changed.curator, changed.pending_cap, changed.pending_value),
        (Role::Curator.pubkey(), PENDING_CAP, 0)
    );
    (svm, w)
}

/// The sponsor's schedule for a submit at NOW: terms, opens_at, review_deadline.
fn plan() -> (EscrowTerms, i64, i64) {
    World::proposal_terms(NOW)
}

/// submit_proposal of `cid` by the sponsor from its funding account, the curator co-signing.
fn submit(svm: &mut LiteSVM, w: &World, cid: [u8; 16]) -> Sent {
    let (terms, opens_at, review_deadline) = plan();
    submit_with(svm, w, cid, &terms, opens_at, review_deadline)
}

fn submit_with(
    svm: &mut LiteSVM,
    w: &World,
    cid: [u8; 16],
    terms: &EscrowTerms,
    opens_at: i64,
    review_deadline: i64,
) -> Sent {
    let ix = w.submit_proposal_ix(
        Role::Sponsor.pubkey(),
        Role::Curator.pubkey(),
        w.funding,
        cid,
        terms,
        opens_at,
        review_deadline,
    );
    w.send(
        svm,
        ix,
        &[&Role::Sponsor.keypair(), &Role::Curator.keypair()],
    )
}

fn approve(svm: &mut LiteSVM, w: &World, curator: &Keypair, cid: [u8; 16]) -> Sent {
    let ix = w.approve_proposal_ix(curator.pubkey(), Role::Sponsor.pubkey(), cid);
    w.send(svm, ix, &[curator])
}

fn close(svm: &mut LiteSVM, w: &World, by: &Keypair, cid: [u8; 16], reason: [u8; 32]) -> Sent {
    let ix = w.close_proposal_ix(by.pubkey(), Role::Sponsor.pubkey(), cid, reason);
    w.send(svm, ix, &[by])
}

/// set_proposal_rules of the sponsor's proposal at `cid`, signed by `curator`.
fn set_rules(
    svm: &mut LiteSVM,
    w: &World,
    curator: &Keypair,
    cid: [u8; 16],
    rules_sha256: [u8; 32],
) -> Sent {
    let ix = support::instruction(
        prize_escrow::accounts::SetProposalRules {
            curator: curator.pubkey(),
            proposal: w.proposal_at(&sponsor(), &cid),
            config: prize_escrow::Config::pda().0,
            event_authority: support::EVENT_AUTHORITY,
            program: prize_escrow::ID,
        },
        prize_escrow::instruction::SetProposalRules { rules_sha256 },
    );
    w.send(svm, ix, &[curator])
}

/// submit_proposal of `cid` with the plan's terms but an all-zero rules hash: a deposit made
/// before its rules were written. Returns the terms as submitted.
fn submit_unruled(svm: &mut LiteSVM, w: &World, cid: [u8; 16]) -> EscrowTerms {
    let (mut terms, opens_at, review_deadline) = plan();
    terms.rules_sha256 = [0; 32];
    expect_ok(
        submit_with(svm, w, cid, &terms, opens_at, review_deadline),
        "submit_proposal, no rules",
    );
    terms
}

fn sponsor() -> Pubkey {
    Role::Sponsor.pubkey()
}

/// The raw EscrowOpened payload a transaction emitted.
fn opened_payload(sent: &Sent) -> Vec<u8> {
    let found: Vec<&Vec<u8>> = sent
        .events
        .iter()
        .filter(|p| p.starts_with(EscrowOpened::DISCRIMINATOR))
        .collect();
    assert_eq!(found.len(), 1, "one EscrowOpened: {}", sent.logs);
    found[0].clone()
}

/// What the rents of a proposal and its vault cost the sponsor.
fn proposal_rents(svm: &LiteSVM) -> u64 {
    svm.rent_exempt(Proposal::SPACE)
        + svm.rent_exempt(anchor_spl::token::spl_token::state::Account::LEN)
}

// ------------------------------------------------------------------------- the happy paths

#[test]
fn an_approved_proposal_opens_the_escrow_open_escrow_would() {
    let (mut svm, w) = world();
    let (terms, opens_at, review_deadline) = plan();
    let mut twin = svm.clone();
    let lamports_before = svm.lamports(&sponsor());

    let sent = expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    let submitted = sent.event::<ProposalSubmitted>();
    assert_eq!(
        (
            submitted.proposal,
            submitted.escrow,
            submitted.competition_id,
            submitted.sponsor,
            submitted.curator,
            submitted.mint,
            submitted.decimals,
            submitted.pending_value,
        ),
        (
            w.proposal_at(&sponsor(), &PCID),
            w.escrow_at(&sponsor(), &PCID),
            PCID,
            sponsor(),
            Role::Curator.pubkey(),
            w.mint,
            support::DECIMALS,
            TOTAL,
        )
    );
    let as_terms = EscrowTerms {
        total: submitted.total,
        rules_sha256: submitted.rules_sha256,
        resolver: submitted.resolver,
        compliance: submitted.compliance,
        arbiter: submitted.arbiter,
        refund_to: submitted.refund_to,
        regraders: submitted.regraders.clone(),
        k: submitted.k,
        bond_lamports: submitted.bond_lamports,
        entries_deadline: submitted.entries_deadline,
        final_end: submitted.final_end,
        resolve_deadline: submitted.resolve_deadline,
        challenge_window: submitted.challenge_window,
        attest_window: submitted.attest_window,
        hold_window: submitted.hold_window,
        claim_window: submitted.claim_window,
        hard_deadline: submitted.hard_deadline,
    };
    assert_eq!(as_terms, terms, "the event carries every term");
    assert_eq!(
        (
            submitted.opens_at,
            submitted.review_deadline,
            submitted.submitted_at
        ),
        (opens_at, review_deadline, NOW)
    );
    let proposal = w.proposal_state(&svm, &sponsor(), &PCID).unwrap();
    assert_eq!(
        (
            proposal.terms.clone(),
            proposal.deposited,
            proposal.opens_at,
            proposal.review_deadline
        ),
        (terms.clone(), TOTAL, opens_at, review_deadline)
    );
    assert_eq!(svm.tokens(&w.proposal_vault_at(&sponsor(), &PCID)), TOTAL);
    assert_eq!(svm.tokens(&w.funding), SPONSOR_FUNDS - TOTAL);
    assert_eq!(
        svm.lamports(&sponsor()),
        lamports_before - proposal_rents(&svm),
        "the sponsor pays both rents"
    );
    let config = w.config(&svm);
    assert_eq!((config.open_value, config.pending_value), (0, TOTAL));
    assert!(
        w.escrow_state_at(&svm, &sponsor(), &PCID).is_none(),
        "nothing is open before the approval"
    );

    // The curator approves an hour later; the twin opens the same terms directly at that moment.
    svm.set_time(NOW + HOUR);
    twin.set_time(NOW + HOUR);
    let curator_before = svm.lamports(&Role::Curator.pubkey());
    let approved = expect_ok(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        "approve_proposal",
    );
    let open = w.open_ix_at(sponsor(), w.funding, w.mint, PCID, &terms);
    let direct = expect_ok(
        w.send(&mut twin, open, &[&Role::Sponsor.keypair()]),
        "open_escrow",
    );

    let via_proposal = w.escrow_state_at(&svm, &sponsor(), &PCID).unwrap();
    let opened_directly = w.escrow_state_at(&twin, &sponsor(), &PCID).unwrap();
    assert_eq!(
        via_proposal, opened_directly,
        "the escrow is field for field open_escrow's"
    );
    assert_eq!(via_proposal.status, EscrowStatus::Open);
    assert_eq!(
        opened_payload(&approved),
        opened_payload(&direct),
        "the same EscrowOpened"
    );
    let event = approved.event::<ProposalApproved>();
    assert_eq!(
        (
            event.proposal,
            event.escrow,
            event.competition_id,
            event.sponsor,
            event.curator,
            event.amount,
            event.swept,
            event.pending_value,
            event.open_value
        ),
        (
            w.proposal_at(&sponsor(), &PCID),
            w.escrow_at(&sponsor(), &PCID),
            PCID,
            sponsor(),
            Role::Curator.pubkey(),
            TOTAL,
            0,
            0,
            TOTAL
        )
    );
    assert_eq!(svm.tokens(&w.escrow_vault_at(&sponsor(), &PCID)), TOTAL);
    assert_eq!(twin.tokens(&w.escrow_vault_at(&sponsor(), &PCID)), TOTAL);
    assert_eq!(w.config(&svm).open_value, w.config(&twin).open_value);
    assert_eq!(w.config(&svm).pending_value, 0);
    // The proposal and its vault are gone, their rent back with the sponsor; the curator paid
    // the escrow's rent and its vault's.
    assert!(w.proposal_state(&svm, &sponsor(), &PCID).is_none());
    assert_eq!(
        svm.lamports(&w.proposal_at(&sponsor(), &PCID)),
        0,
        "the proposal is closed"
    );
    assert_eq!(svm.lamports(&w.proposal_vault_at(&sponsor(), &PCID)), 0);
    assert_eq!(svm.lamports(&sponsor()), lamports_before);
    assert_eq!(
        curator_before - svm.lamports(&Role::Curator.pubkey()),
        svm.rent_exempt(prize_escrow::Escrow::SPACE)
            + svm.rent_exempt(anchor_spl::token::spl_token::state::Account::LEN)
    );
}

#[test]
fn a_sponsor_off_the_allowlist_opens_through_a_proposal_only() {
    let (mut svm, w) = world();
    let outsider = Role::Winner(0).keypair();
    let funding = Role::Winner(0).pubkey_derived(b"proposal-funding");
    put_token_account(&mut svm, funding, w.mint, outsider.pubkey(), TOTAL, false);
    let (mut terms, opens_at, review_deadline) = plan();
    terms.refund_to = outsider.pubkey();

    let open = w.open_ix_at(outsider.pubkey(), funding, w.mint, PCID, &terms);
    expect_refused(
        w.send(&mut svm, open, &[&outsider]),
        EscrowError::SponsorNotAllowed,
        "a direct open off the allowlist",
    );
    let ix = w.submit_proposal_ix(
        outsider.pubkey(),
        Role::Curator.pubkey(),
        funding,
        PCID,
        &terms,
        opens_at,
        review_deadline,
    );
    expect_ok(
        w.send(&mut svm, ix, &[&outsider, &Role::Curator.keypair()]),
        "submit_proposal off the allowlist",
    );
    let ix = w.approve_proposal_ix(Role::Curator.pubkey(), outsider.pubkey(), PCID);
    expect_ok(
        w.send(&mut svm, ix, &[&Role::Curator.keypair()]),
        "approve_proposal",
    );
    let escrow = w.escrow_state_at(&svm, &outsider.pubkey(), &PCID).unwrap();
    assert_eq!(
        (escrow.sponsor, escrow.refund_to, escrow.deposited),
        (outsider.pubkey(), outsider.pubkey(), TOTAL)
    );

    // The waiver is the allowlist's alone: refund_to must still be the sponsor.
    let mut terms = plan().0;
    terms.refund_to = Role::Attacker(0).pubkey();
    put_token_account(&mut svm, funding, w.mint, outsider.pubkey(), TOTAL, false);
    let ix = w.submit_proposal_ix(
        outsider.pubkey(),
        Role::Curator.pubkey(),
        funding,
        OTHER,
        &terms,
        opens_at,
        review_deadline,
    );
    expect_refused(
        w.send(&mut svm, ix, &[&outsider, &Role::Curator.keypair()]),
        EscrowError::RefundToNotSponsor,
        "refund_to another key",
    );
}

#[test]
fn a_rejection_returns_the_deposit_and_the_rents_and_names_its_reason() {
    let (mut svm, w) = world();
    let lamports_before = svm.lamports(&sponsor());
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    svm.set_time(NOW + DAY);

    expect_refused(
        close(&mut svm, &w, &Role::Curator.keypair(), PCID, NO_REASON),
        EscrowError::InvalidCloseReason,
        "a rejection without a reason",
    );
    let sent = expect_ok(
        close(&mut svm, &w, &Role::Curator.keypair(), PCID, REASON),
        "reject",
    );
    let closed = sent.event::<ProposalClosed>();
    assert_eq!(
        (
            closed.proposal,
            closed.sponsor,
            closed.amount,
            closed.kind,
            closed.reason_sha256,
            closed.by
        ),
        (
            w.proposal_at(&sponsor(), &PCID),
            sponsor(),
            TOTAL,
            ProposalCloseKind::Rejected,
            REASON,
            Role::Curator.pubkey()
        )
    );
    assert_eq!(
        svm.tokens(&w.funding) + svm.tokens(&w.ata(&sponsor())),
        SPONSOR_FUNDS,
        "the sponsor's balance is whole to the unit"
    );
    assert_eq!(svm.tokens(&w.ata(&sponsor())), TOTAL);
    assert_eq!(
        svm.lamports(&sponsor()),
        lamports_before,
        "both rents are back"
    );
    assert!(w.proposal_state(&svm, &sponsor(), &PCID).is_none());
    assert_eq!(svm.lamports(&w.proposal_vault_at(&sponsor(), &PCID)), 0);
    assert!(w.escrow_state_at(&svm, &sponsor(), &PCID).is_none());
    let config = w.config(&svm);
    assert_eq!((config.open_value, config.pending_value), (0, 0));

    // Closed is final: nothing approves or closes it again.
    expect_refused(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        AnchorErrorCode::AccountNotInitialized,
        "an approval of a returned proposal",
    );
    expect_refused(
        close(&mut svm, &w, &Role::Curator.keypair(), PCID, REASON),
        AnchorErrorCode::AccountNotInitialized,
        "a second rejection",
    );
}

#[test]
fn the_sponsor_withdraws_without_a_reason() {
    let (mut svm, w) = world();
    let lamports_before = svm.lamports(&sponsor());
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    expect_refused(
        close(&mut svm, &w, &Role::Sponsor.keypair(), PCID, REASON),
        EscrowError::InvalidCloseReason,
        "a withdrawal naming a reason",
    );
    let sent = expect_ok(
        close(&mut svm, &w, &Role::Sponsor.keypair(), PCID, NO_REASON),
        "withdraw",
    );
    let closed = sent.event::<ProposalClosed>();
    assert_eq!(
        (closed.kind, closed.by, closed.amount, closed.reason_sha256),
        (ProposalCloseKind::Withdrawn, sponsor(), TOTAL, NO_REASON)
    );
    assert_eq!(
        svm.tokens(&w.funding) + svm.tokens(&w.ata(&sponsor())),
        SPONSOR_FUNDS
    );
    // The sponsor paid its own token account's rent, and got the proposal's two back.
    assert_eq!(
        svm.lamports(&sponsor()),
        lamports_before - svm.rent_exempt(anchor_spl::token::spl_token::state::Account::LEN)
    );
    assert_eq!(w.config(&svm).pending_value, 0);
    // The competition id is free again: the sponsor may submit it anew.
    expect_ok(submit(&mut svm, &w, PCID), "a resubmit");
}

#[test]
fn a_stranger_returns_an_expired_proposal_only_after_its_review_deadline() {
    let (mut svm, w) = world();
    let (_, _, review_deadline) = plan();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    let stranger = Role::Attacker(0).keypair();

    svm.set_time(review_deadline);
    expect_refused(
        close(&mut svm, &w, &stranger, PCID, NO_REASON),
        EscrowError::DeadlineNotReached,
        "an expiry at review_deadline",
    );
    // The curator may still approve at review_deadline itself.
    let mut last_second = svm.clone();
    expect_ok(
        approve(&mut last_second, &w, &Role::Curator.keypair(), PCID),
        "an approval at review_deadline",
    );

    svm.set_time(review_deadline + 1);
    expect_refused(
        close(&mut svm, &w, &stranger, PCID, REASON),
        EscrowError::InvalidCloseReason,
        "an expiry naming a reason",
    );
    let sent = expect_ok(close(&mut svm, &w, &stranger, PCID, NO_REASON), "expire");
    let closed = sent.event::<ProposalClosed>();
    assert_eq!(
        (closed.kind, closed.by, closed.amount),
        (ProposalCloseKind::Expired, stranger.pubkey(), TOTAL)
    );
    assert_eq!(
        svm.tokens(&w.ata(&sponsor())),
        TOTAL,
        "the deposit goes to the sponsor, never the stranger"
    );
    assert_eq!(svm.tokens(&w.ata(&stranger.pubkey())), 0);
}

// ------------------------------------------------------------------------- the refusals

#[test]
fn an_approval_after_the_review_deadline_is_refused() {
    let (mut svm, w) = world();
    let (_, _, review_deadline) = plan();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    svm.set_time(review_deadline + 1);
    expect_refused(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        EscrowError::ReviewWindowClosed,
        "a late approval",
    );
    // Its way back stays open: the curator rejects, or anyone expires it.
    expect_ok(
        close(&mut svm, &w, &Role::Curator.keypair(), PCID, REASON),
        "a late rejection",
    );
}

#[test]
fn an_approval_that_loses_the_race_to_a_close_is_refused() {
    let (mut svm, w) = world();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    expect_ok(
        close(&mut svm, &w, &Role::Sponsor.keypair(), PCID, NO_REASON),
        "the withdrawal lands first",
    );
    expect_refused(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        AnchorErrorCode::AccountNotInitialized,
        "the approval after it",
    );
    assert!(w.escrow_state_at(&svm, &sponsor(), &PCID).is_none());
    assert_eq!(w.config(&svm).open_value, 0);
}

#[test]
fn a_revoked_sponsor_is_held_neither_approved_nor_returned() {
    let (mut svm, w) = world();
    let (_, _, review_deadline) = plan();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    let revoke = w.set_revoked_ix(Role::Guardian.pubkey(), sponsor(), true);
    expect_ok(
        w.send(&mut svm, revoke, &[&Role::Guardian.keypair()]),
        "the guardian's hold",
    );
    expect_refused(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        EscrowError::SponsorRevoked,
        "an approval of a held sponsor",
    );
    expect_refused(
        close(&mut svm, &w, &Role::Sponsor.keypair(), PCID, NO_REASON),
        EscrowError::SponsorRevoked,
        "a held sponsor's withdrawal",
    );
    expect_refused(
        close(&mut svm, &w, &Role::Curator.keypair(), PCID, REASON),
        EscrowError::SponsorRevoked,
        "a rejection of a held sponsor",
    );
    svm.set_time(review_deadline + 1);
    expect_refused(
        close(&mut svm, &w, &Role::Attacker(0).keypair(), PCID, NO_REASON),
        EscrowError::SponsorRevoked,
        "an expiry of a held sponsor",
    );
    assert_eq!(
        svm.tokens(&w.proposal_vault_at(&sponsor(), &PCID)),
        TOTAL,
        "the deposit is held"
    );
    // A revoked sponsor submits nothing either.
    let (terms, opens_at, review) = World::proposal_terms(review_deadline + 1);
    expect_refused(
        submit_with(&mut svm, &w, OTHER, &terms, opens_at, review),
        EscrowError::KeyRevoked,
        "a held sponsor's submit",
    );

    // The admin lifts the hold: the expiry runs.
    let unrevoke = w.set_revoked_ix(Role::Admin.pubkey(), sponsor(), false);
    expect_ok(
        w.send(&mut svm, unrevoke, &[&Role::Admin.keypair()]),
        "unrevoke",
    );
    expect_ok(
        close(&mut svm, &w, &Role::Attacker(0).keypair(), PCID, NO_REASON),
        "the expiry once unrevoked",
    );
    assert_eq!(svm.tokens(&w.ata(&sponsor())), TOTAL);
}

#[test]
fn a_revoked_or_replaced_curator_is_refused() {
    let (mut svm, w) = world();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    let curator = Role::Curator.keypair();

    // Revoked: it approves, rejects and co-signs nothing.
    let revoke = w.set_revoked_ix(Role::Guardian.pubkey(), curator.pubkey(), true);
    expect_ok(
        w.send(&mut svm, revoke, &[&Role::Guardian.keypair()]),
        "revoke the curator",
    );
    expect_refused(
        approve(&mut svm, &w, &curator, PCID),
        EscrowError::KeyRevoked,
        "a revoked curator's approval",
    );
    expect_refused(
        close(&mut svm, &w, &curator, PCID, REASON),
        EscrowError::KeyRevoked,
        "a revoked curator's rejection",
    );
    expect_refused(
        submit(&mut svm, &w, OTHER),
        EscrowError::KeyRevoked,
        "a revoked curator's co-signature",
    );
    let unrevoke = w.set_revoked_ix(Role::Admin.pubkey(), curator.pubkey(), false);
    expect_ok(
        w.send(&mut svm, unrevoke, &[&Role::Admin.keypair()]),
        "unrevoke",
    );

    // Replaced: the new curator reviews the pending proposal; the old one is a stranger.
    let successor = Role::Spare(0).keypair();
    let policy = w.set_proposal_policy_ix(Role::Admin.pubkey(), successor.pubkey(), PENDING_CAP);
    expect_ok(
        w.send(&mut svm, policy, &[&Role::Admin.keypair()]),
        "replace the curator",
    );
    expect_refused(
        approve(&mut svm, &w, &curator, PCID),
        EscrowError::UnauthorizedCurator,
        "the old curator's approval",
    );
    expect_refused(
        close(&mut svm, &w, &curator, PCID, NO_REASON),
        EscrowError::DeadlineNotReached,
        "the old curator closes only as anyone does, after review_deadline",
    );
    expect_refused(
        submit(&mut svm, &w, OTHER),
        EscrowError::UnauthorizedCurator,
        "the old curator's co-signature",
    );
    expect_refused(
        approve(&mut svm, &w, &Role::Attacker(0).keypair(), PCID),
        EscrowError::UnauthorizedCurator,
        "a stranger's approval",
    );
    expect_ok(
        approve(&mut svm, &w, &successor, PCID),
        "the new curator's approval",
    );

    // Off: nothing is submitted or approved, and the way back stays open.
    let off = w.set_proposal_policy_ix(Role::Admin.pubkey(), Pubkey::default(), PENDING_CAP);
    expect_ok(
        w.send(&mut svm, off, &[&Role::Admin.keypair()]),
        "proposals off",
    );
    let ix = w.submit_proposal_ix(
        sponsor(),
        successor.pubkey(),
        w.funding,
        OTHER,
        &plan().0,
        plan().1,
        plan().2,
    );
    expect_refused(
        w.send(&mut svm, ix, &[&Role::Sponsor.keypair(), &successor]),
        EscrowError::ProposalsDisabled,
        "a submit with proposals off",
    );
}

#[test]
fn proposals_off_still_return_what_is_pending() {
    let (mut svm, w) = world();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    let off = w.set_proposal_policy_ix(Role::Admin.pubkey(), Pubkey::default(), 0);
    expect_ok(
        w.send(&mut svm, off, &[&Role::Admin.keypair()]),
        "proposals off",
    );
    expect_refused(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        EscrowError::ProposalsDisabled,
        "an approval with proposals off",
    );
    expect_ok(
        close(&mut svm, &w, &Role::Sponsor.keypair(), PCID, NO_REASON),
        "the sponsor withdraws",
    );
    assert_eq!(svm.tokens(&w.ata(&sponsor())), TOTAL);
}

#[test]
fn the_review_stays_inside_its_window_and_before_the_competition_opens() {
    let (mut svm, w) = world();
    let (terms, opens_at, review_deadline) = plan();
    expect_refused(
        submit_with(
            &mut svm,
            &w,
            PCID,
            &terms,
            review_deadline - 1,
            review_deadline,
        ),
        EscrowError::ReviewWindowInvalid,
        "a review deadline later than opens_at",
    );
    expect_refused(
        submit_with(
            &mut svm,
            &w,
            PCID,
            &terms,
            terms.entries_deadline,
            review_deadline,
        ),
        EscrowError::ReviewWindowInvalid,
        "opening at the entries deadline",
    );
    expect_refused(
        submit_with(&mut svm, &w, PCID, &terms, opens_at, NOW),
        EscrowError::ReviewWindowInvalid,
        "a review deadline that has passed",
    );
    // At most MAX_REVIEW_WINDOW: one second more is refused, the window itself taken.
    let (far, far_opens, far_review) =
        World::proposal_terms(NOW + MAX_REVIEW_WINDOW - support::REVIEW);
    assert_eq!(far_review, NOW + MAX_REVIEW_WINDOW);
    expect_refused(
        submit_with(&mut svm, &w, PCID, &far, far_review + 1, far_review + 1),
        EscrowError::ReviewWindowInvalid,
        "a review past MAX_REVIEW_WINDOW",
    );
    expect_ok(
        submit_with(&mut svm, &w, PCID, &far, far_opens, far_review),
        "a review of exactly MAX_REVIEW_WINDOW",
    );
    // The terms are EscrowTerms::validate's, as open_escrow's are.
    let mut bad = terms.clone();
    bad.k = 1;
    expect_refused(
        submit_with(&mut svm, &w, OTHER, &bad, opens_at, review_deadline),
        EscrowError::InvalidRegraderSet,
        "terms validate refuses",
    );
}

#[test]
fn a_submit_needs_the_curator_signature_and_a_free_escrow_address() {
    let (mut svm, w) = world();
    let (terms, opens_at, review_deadline) = plan();

    // No co-signature: the curator account is not a signer.
    let mut ix = w.submit_proposal_ix(
        sponsor(),
        Role::Curator.pubkey(),
        w.funding,
        PCID,
        &terms,
        opens_at,
        review_deadline,
    );
    assert_eq!(ix.accounts[1].pubkey, Role::Curator.pubkey());
    ix.accounts[1].is_signer = false;
    expect_refused(
        w.send(&mut svm, ix, &[&Role::Sponsor.keypair()]),
        AnchorErrorCode::AccountNotSigner,
        "a submit the curator did not sign",
    );
    // Another key's co-signature.
    let stranger = Role::Attacker(0).keypair();
    let ix = w.submit_proposal_ix(
        sponsor(),
        stranger.pubkey(),
        w.funding,
        PCID,
        &terms,
        opens_at,
        review_deadline,
    );
    expect_refused(
        w.send(&mut svm, ix, &[&Role::Sponsor.keypair(), &stranger]),
        EscrowError::UnauthorizedCurator,
        "a stranger's co-signature",
    );

    // The escrow at the competition id exists already: opened directly first.
    let open = w.open_ix_at(sponsor(), w.funding, w.mint, PCID, &terms);
    expect_ok(
        w.send(&mut svm, open, &[&Role::Sponsor.keypair()]),
        "open_escrow at the id",
    );
    expect_refused(
        submit(&mut svm, &w, PCID),
        EscrowError::EscrowExists,
        "a proposal of an open escrow's id",
    );

    // One proposal per id at a time.
    expect_ok(submit(&mut svm, &w, OTHER), "submit_proposal");
    expect_refused(
        submit(&mut svm, &w, OTHER),
        0u32,
        "a second proposal of the same id",
    );
}

#[test]
fn an_approval_holds_the_terms_to_todays_config() {
    let (mut svm, w) = world();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    // The arbiter moved since the submit: the stored terms name the old one.
    let rotate = w.set_config_role_ix(
        Role::Admin.pubkey(),
        ConfigRole::Arbiter,
        Role::Spare(1).pubkey(),
    );
    expect_ok(
        w.send(&mut svm, rotate, &[&Role::Admin.keypair()]),
        "a new arbiter",
    );
    expect_refused(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        EscrowError::ArbiterNotConfig,
        "an approval against a drifted Config",
    );
    expect_ok(
        close(&mut svm, &w, &Role::Curator.keypair(), PCID, REASON),
        "the curator rejects instead",
    );
}

#[test]
fn frozen_token_accounts_are_refused_by_name() {
    let (mut svm, w) = world();
    put_token_account(&mut svm, w.funding, w.mint, sponsor(), SPONSOR_FUNDS, true);
    expect_refused(
        submit(&mut svm, &w, PCID),
        EscrowError::SponsorAccountFrozen,
        "a frozen funding account",
    );
    put_token_account(&mut svm, w.funding, w.mint, sponsor(), SPONSOR_FUNDS, false);
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    put_token_account(&mut svm, w.ata(&sponsor()), w.mint, sponsor(), 0, true);
    expect_refused(
        close(&mut svm, &w, &Role::Sponsor.keypair(), PCID, NO_REASON),
        EscrowError::SponsorAccountFrozen,
        "a return into a frozen account",
    );
    let vault = w.proposal_vault_at(&sponsor(), &PCID);
    put_token_account(
        &mut svm,
        vault,
        w.mint,
        w.proposal_at(&sponsor(), &PCID),
        TOTAL,
        true,
    );
    expect_refused(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        EscrowError::VaultFrozen,
        "an approval from a frozen vault",
    );
}

#[test]
fn a_donation_to_the_proposal_vault_does_not_block_the_approval() {
    let (mut svm, w) = world();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    let vault = w.proposal_vault_at(&sponsor(), &PCID);
    let donate = w.donate_tokens_to_ix(vault, 1);
    expect_ok(
        w.send(&mut svm, donate, &[&Role::Attacker(0).keypair()]),
        "a one-unit donation",
    );
    let mut rejected = svm.clone();

    let sent = expect_ok(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        "approve_proposal",
    );
    let event = sent.event::<ProposalApproved>();
    assert_eq!((event.amount, event.swept), (TOTAL, 1));
    assert_eq!(svm.tokens(&w.escrow_vault_at(&sponsor(), &PCID)), TOTAL + 1);
    assert_eq!(svm.lamports(&vault), 0, "the proposal vault closed");
    let escrow = w.escrow_state_at(&svm, &sponsor(), &PCID).unwrap();
    assert_eq!(
        (escrow.deposited, escrow.total),
        (TOTAL, TOTAL),
        "the caps count the deposit, not the donation"
    );
    assert_eq!(w.config(&svm).open_value, TOTAL);

    // Returned instead, the whole vault goes back: the donation too.
    let sent = expect_ok(
        close(&mut rejected, &w, &Role::Curator.keypair(), PCID, REASON),
        "reject",
    );
    assert_eq!(sent.event::<ProposalClosed>().amount, TOTAL + 1);
    assert_eq!(rejected.tokens(&w.ata(&sponsor())), TOTAL + 1);
    assert_eq!(w.config(&rejected).pending_value, 0);
}

// ------------------------------------------------------------------------- the caps

#[test]
fn the_pending_cap_holds_what_awaits_review() {
    let (mut svm, w) = world();
    let policy = w.set_proposal_policy_ix(Role::Admin.pubkey(), Role::Curator.pubkey(), TOTAL);
    expect_ok(
        w.send(&mut svm, policy, &[&Role::Admin.keypair()]),
        "a pending cap of one pot",
    );
    expect_ok(submit(&mut svm, &w, PCID), "the first proposal");
    expect_refused(
        submit(&mut svm, &w, OTHER),
        EscrowError::PendingCapExceeded,
        "a second over the pending cap",
    );
    expect_ok(
        close(&mut svm, &w, &Role::Sponsor.keypair(), PCID, NO_REASON),
        "the first withdrawn",
    );
    expect_ok(submit(&mut svm, &w, OTHER), "the second once room is back");
    // An approval frees the room too: the deposit is open value now.
    expect_ok(
        approve(&mut svm, &w, &Role::Curator.keypair(), OTHER),
        "approve",
    );
    let config = w.config(&svm);
    assert_eq!((config.pending_value, config.open_value), (0, TOTAL));
    expect_ok(submit(&mut svm, &w, PCID), "room for another");
}

#[test]
fn the_escrow_cap_holds_a_proposal() {
    let (mut svm, w) = world();
    let mut limits = World::limits(Panel::HouseMajority);
    limits.escrow_cap = TOTAL - 1;
    let ix = w.set_limits_ix(Role::Admin.pubkey(), limits);
    expect_ok(w.send(&mut svm, ix, &[&Role::Admin.keypair()]), "C_e");
    expect_refused(
        submit(&mut svm, &w, PCID),
        EscrowError::EscrowCapExceeded,
        "a proposal over C_e",
    );
}

#[test]
fn the_global_cap_counts_proposals_with_direct_opens() {
    let (mut svm, w) = world();
    let mut limits = World::limits(Panel::HouseMajority);
    limits.global_cap = 2 * TOTAL;
    let ix = w.set_limits_ix(Role::Admin.pubkey(), limits);
    expect_ok(
        w.send(&mut svm, ix, &[&Role::Admin.keypair()]),
        "C_g of two pots",
    );
    expect_ok(
        submit(&mut svm, &w, PCID),
        "a proposal takes one pot of room",
    );

    // A direct open lands between the submit and the approval: it takes the other pot's room,
    // never the proposal's.
    let terms = World::default_terms();
    let open = w.open_ix_at(sponsor(), w.funding, w.mint, w.cid, &terms);
    expect_ok(
        w.send(&mut svm, open, &[&Role::Sponsor.keypair()]),
        "a direct open within C_g",
    );
    let open = w.open_ix_at(sponsor(), w.funding, w.mint, OTHER, &terms);
    expect_refused(
        w.send(&mut svm, open, &[&Role::Sponsor.keypair()]),
        EscrowError::GlobalCapExceeded,
        "a direct open into the proposal's room",
    );
    let fund = w.fund_ix(sponsor(), 1);
    expect_refused(
        w.send(&mut svm, fund, &[&Role::Sponsor.keypair()]),
        EscrowError::GlobalCapExceeded,
        "a fund into the proposal's room",
    );
    let (terms, opens_at, review_deadline) = plan();
    expect_refused(
        submit_with(&mut svm, &w, OTHER, &terms, opens_at, review_deadline),
        EscrowError::GlobalCapExceeded,
        "a proposal past C_g",
    );

    expect_ok(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        "the approval still lands",
    );
    let config = w.config(&svm);
    assert_eq!((config.open_value, config.pending_value), (2 * TOTAL, 0));

    // A cap lowered under what is held refuses new deposits only: an approval is not one.
    let (mut svm, w) = world();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    let mut limits = World::limits(Panel::HouseMajority);
    limits.global_cap = 1;
    let ix = w.set_limits_ix(Role::Admin.pubkey(), limits);
    expect_ok(
        w.send(&mut svm, ix, &[&Role::Admin.keypair()]),
        "C_g lowered",
    );
    expect_ok(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        "the approval of a deposit already held",
    );
}

// ------------------------------------------------------------------------- the breakers

#[test]
fn intake_stop_refuses_the_submit_and_the_approval_but_not_the_way_back() {
    let (mut svm, w) = world();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    let stop = w.set_stop_ix(Role::Guardian.pubkey(), StopState::IntakeStop);
    expect_ok(
        w.send(&mut svm, stop, &[&Role::Guardian.keypair()]),
        "IntakeStop",
    );
    expect_refused(
        submit(&mut svm, &w, OTHER),
        EscrowError::IntakeStopped,
        "a submit under IntakeStop",
    );
    expect_refused(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        EscrowError::IntakeStopped,
        "an approval under IntakeStop",
    );
    expect_ok(
        close(&mut svm, &w, &Role::Curator.keypair(), PCID, REASON),
        "a rejection under IntakeStop",
    );
    assert_eq!(svm.tokens(&w.ata(&sponsor())), TOTAL);
}

#[test]
fn payout_stop_holds_the_way_back_until_it_lifts() {
    let (mut svm, w) = world();
    let (_, _, review_deadline) = plan();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    let stop = w.set_stop_ix(Role::Guardian.pubkey(), StopState::PayoutStop);
    expect_ok(
        w.send(&mut svm, stop, &[&Role::Guardian.keypair()]),
        "PayoutStop",
    );
    expect_refused(
        close(&mut svm, &w, &Role::Sponsor.keypair(), PCID, NO_REASON),
        EscrowError::PayoutStopped,
        "a withdrawal under PayoutStop",
    );
    expect_refused(
        close(&mut svm, &w, &Role::Curator.keypair(), PCID, REASON),
        EscrowError::PayoutStopped,
        "a rejection under PayoutStop",
    );
    expect_refused(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        EscrowError::IntakeStopped,
        "an approval under PayoutStop",
    );
    svm.set_time(review_deadline + 1);
    expect_refused(
        close(&mut svm, &w, &Role::Attacker(0).keypair(), PCID, NO_REASON),
        EscrowError::PayoutStopped,
        "an expiry under PayoutStop",
    );
    let lift = w.set_stop_ix(Role::Admin.pubkey(), StopState::Normal);
    expect_ok(
        w.send(&mut svm, lift, &[&Role::Admin.keypair()]),
        "the admin lifts it",
    );
    expect_ok(
        close(&mut svm, &w, &Role::Attacker(0).keypair(), PCID, NO_REASON),
        "the expiry once lifted",
    );
    assert_eq!(svm.tokens(&w.ata(&sponsor())), TOTAL);
}

// ------------------------------------------------------------------------- the policy

#[test]
fn the_policy_names_a_curator_of_its_own() {
    let (mut svm, w) = world();
    let policy =
        |w: &World, by: Pubkey, curator: Pubkey| w.set_proposal_policy_ix(by, curator, PENDING_CAP);
    let stranger = Role::Attacker(0).keypair();
    expect_refused(
        w.send(
            &mut svm,
            policy(&w, stranger.pubkey(), stranger.pubkey()),
            &[&stranger],
        ),
        EscrowError::UnauthorizedAdmin,
        "a policy not the admin's",
    );
    expect_refused(
        w.send(
            &mut svm,
            policy(&w, Role::Curator.pubkey(), Role::Curator.pubkey()),
            &[&Role::Curator.keypair()],
        ),
        EscrowError::UnauthorizedAdmin,
        "the curator names no curator",
    );
    for (role, what) in [
        (Role::Admin, "the admin"),
        (Role::Guardian, "the guardian"),
        (Role::Arbiter, "the arbiter"),
    ] {
        expect_refused(
            w.send(
                &mut svm,
                policy(&w, Role::Admin.pubkey(), role.pubkey()),
                &[&Role::Admin.keypair()],
            ),
            EscrowError::CuratorNotIndependent,
            what,
        );
    }
    let revoke = w.set_revoked_ix(Role::Guardian.pubkey(), Role::Spare(0).pubkey(), true);
    expect_ok(
        w.send(&mut svm, revoke, &[&Role::Guardian.keypair()]),
        "revoke a key",
    );
    expect_refused(
        w.send(
            &mut svm,
            policy(&w, Role::Admin.pubkey(), Role::Spare(0).pubkey()),
            &[&Role::Admin.keypair()],
        ),
        EscrowError::KeyRevoked,
        "a revoked curator",
    );
    let config = w.config(&svm);
    assert_eq!(
        (config.curator, config.pending_cap),
        (Role::Curator.pubkey(), PENDING_CAP)
    );

    // Nor does the curator's key become the guardian, the arbiter or the admin.
    for role in [ConfigRole::Guardian, ConfigRole::Arbiter] {
        let ix = w.set_config_role_ix(Role::Admin.pubkey(), role, Role::Curator.pubkey());
        expect_refused(
            w.send(&mut svm, ix, &[&Role::Admin.keypair()]),
            EscrowError::CuratorNotIndependent,
            "the curator in a Config role",
        );
    }
    let propose = prize_escrow::instruction::ProposeAdmin {
        new_admin: Role::Curator.pubkey(),
    };
    let accounts = prize_escrow::accounts::AdminConfig {
        admin: Role::Admin.pubkey(),
        config: prize_escrow::Config::pda().0,
        event_authority: support::EVENT_AUTHORITY,
        program: prize_escrow::ID,
    };
    expect_ok(
        w.send(
            &mut svm,
            support::instruction(accounts, propose),
            &[&Role::Admin.keypair()],
        ),
        "propose the curator as admin",
    );
    let accept = support::instruction(
        prize_escrow::accounts::AcceptAdmin {
            new_admin: Role::Curator.pubkey(),
            config: prize_escrow::Config::pda().0,
            event_authority: support::EVENT_AUTHORITY,
            program: prize_escrow::ID,
        },
        prize_escrow::instruction::AcceptAdmin {},
    );
    expect_refused(
        w.send(&mut svm, accept, &[&Role::Curator.keypair()]),
        EscrowError::CuratorNotIndependent,
        "the curator accepting the admin",
    );
}

// ------------------------------------------------------------------------- the #852 audit

/// P2-1, probe P-B: the terms a sponsor submits name neither it nor the curator as the resolver or
/// the compliance key, give post_result at least MIN_RESOLVE_WINDOW after final_end, and bond at
/// most MAX_PROPOSAL_BOND; each refusal by name, each bound itself accepted.
#[test]
fn a_sponsor_sets_no_self_dealing_terms() {
    let (mut svm, w) = world();
    let (terms, opens_at, review_deadline) = plan();
    let curator = Role::Curator.pubkey();
    // The probe as the audit sent it: resolver = compliance = sponsor, a resolve window of one
    // second and a bond of a million SOL, all at once.
    let mut probe = terms.clone();
    probe.resolver = sponsor();
    probe.compliance = sponsor();
    probe.resolve_deadline = probe.final_end + 1;
    probe.bond_lamports = 1_000_000 * SOL;
    expect_refused(
        submit_with(&mut svm, &w, PCID, &probe, opens_at, review_deadline),
        EscrowError::ProposalRoleNotIndependent,
        "probe P-B",
    );
    let changed = |change: &dyn Fn(&mut EscrowTerms)| {
        let mut t = terms.clone();
        change(&mut t);
        t
    };
    for (bad, want, what) in [
        (
            changed(&|t| t.resolver = sponsor()),
            EscrowError::ProposalRoleNotIndependent,
            "the sponsor as its resolver",
        ),
        (
            changed(&|t| t.compliance = sponsor()),
            EscrowError::ProposalRoleNotIndependent,
            "the sponsor as its compliance key",
        ),
        (
            changed(&|t| t.resolver = curator),
            EscrowError::ProposalRoleNotIndependent,
            "the curator as the resolver",
        ),
        (
            changed(&|t| t.compliance = curator),
            EscrowError::ProposalRoleNotIndependent,
            "the curator as the compliance key",
        ),
        (
            changed(&|t| t.resolve_deadline = t.final_end + 1),
            EscrowError::ResolveWindowTooShort,
            "a one-second resolve window",
        ),
        (
            changed(&|t| t.resolve_deadline = t.final_end + MIN_RESOLVE_WINDOW - 1),
            EscrowError::ResolveWindowTooShort,
            "a second under MIN_RESOLVE_WINDOW",
        ),
        (
            changed(&|t| t.bond_lamports = MAX_PROPOSAL_BOND + 1),
            EscrowError::ProposalBondTooHigh,
            "a lamport over MAX_PROPOSAL_BOND",
        ),
        (
            changed(&|t| t.bond_lamports = 1_000_000 * SOL),
            EscrowError::ProposalBondTooHigh,
            "a million SOL",
        ),
    ] {
        expect_refused(
            submit_with(&mut svm, &w, PCID, &bad, opens_at, review_deadline),
            want,
            what,
        );
    }
    let config = w.config(&svm);
    assert_eq!(config.pending_value, 0, "nothing refused is pending");
    // The bounds themselves pass, and an approval opens their escrow.
    assert_eq!(terms.resolve_deadline - terms.final_end, MIN_RESOLVE_WINDOW);
    let at_bounds = changed(&|t| t.bond_lamports = MAX_PROPOSAL_BOND);
    expect_ok(
        submit_with(&mut svm, &w, PCID, &at_bounds, opens_at, review_deadline),
        "a resolve window of MIN_RESOLVE_WINDOW and a bond of MAX_PROPOSAL_BOND",
    );
    expect_ok(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        "approve_proposal",
    );
    let escrow = w.escrow_state_at(&svm, &sponsor(), &PCID).unwrap();
    assert_eq!(escrow.bond_lamports, MAX_PROPOSAL_BOND);
    // A direct open is the allowlisted sponsor's own and keeps no such bound.
    let open = w.open_ix_at(sponsor(), w.funding, w.mint, OTHER, &probe_for_open(&terms));
    expect_ok(
        w.send(&mut svm, open, &[&Role::Sponsor.keypair()]),
        "open_escrow with a short resolve window and a large bond",
    );
}

/// Terms the proposal bounds refuse and open_escrow takes: a day's resolve window and a 2 SOL bond.
fn probe_for_open(terms: &EscrowTerms) -> EscrowTerms {
    let mut t = terms.clone();
    let shift = DAY - (t.resolve_deadline - t.final_end);
    t.resolve_deadline += shift;
    t.hard_deadline += shift;
    t.bond_lamports = 2 * SOL;
    t
}

/// P2-1 at the approval: the bounds are read again against today's Config, so a curator named
/// since the submit that is the proposal's resolver, or its sponsor, approves nothing.
#[test]
fn an_approval_holds_the_proposal_bounds_to_todays_curator() {
    let (mut svm, w) = world();
    let (mut terms, opens_at, review_deadline) = plan();
    terms.resolver = Role::Spare(0).pubkey();
    expect_ok(
        submit_with(&mut svm, &w, PCID, &terms, opens_at, review_deadline),
        "a resolver that is no curator yet",
    );
    expect_ok(submit(&mut svm, &w, OTHER), "a second proposal");
    let name = |svm: &mut LiteSVM, curator: Pubkey| {
        let ix = w.set_proposal_policy_ix(Role::Admin.pubkey(), curator, PENDING_CAP);
        expect_ok(w.send(svm, ix, &[&Role::Admin.keypair()]), "a new curator");
    };
    name(&mut svm, Role::Spare(0).pubkey());
    expect_refused(
        approve(&mut svm, &w, &Role::Spare(0).keypair(), PCID),
        EscrowError::ProposalRoleNotIndependent,
        "the curator approving the proposal it resolves",
    );
    // The sponsor named the curator: it approves none of its own.
    name(&mut svm, sponsor());
    expect_refused(
        approve(&mut svm, &w, &Role::Sponsor.keypair(), OTHER),
        EscrowError::SponsorIsCurator,
        "the sponsor approving its own proposal",
    );
    // Its way back stays open.
    expect_ok(
        close(&mut svm, &w, &Role::Sponsor.keypair(), OTHER, NO_REASON),
        "the sponsor withdraws",
    );
}

/// P3-1, probe P-C: the curator is never a proposal's sponsor, which one signature would submit
/// and approve, off the allowlist.
#[test]
fn the_curator_cannot_sponsor() {
    let (mut svm, w) = world();
    let curator = Role::Curator.keypair();
    let funding = Role::Curator.pubkey_derived(b"proposal-funding");
    put_token_account(&mut svm, funding, w.mint, curator.pubkey(), TOTAL, false);
    let (mut terms, opens_at, review_deadline) = plan();
    terms.refund_to = curator.pubkey();
    let ix = w.submit_proposal_ix(
        curator.pubkey(),
        curator.pubkey(),
        funding,
        PCID,
        &terms,
        opens_at,
        review_deadline,
    );
    expect_refused(
        w.send(&mut svm, ix, &[&curator]),
        EscrowError::SponsorIsCurator,
        "the curator as its own sponsor",
    );
    assert_eq!(svm.tokens(&funding), TOTAL);
    assert_eq!(w.config(&svm).pending_value, 0);
}

/// P3-2, probe P-D: an approval opens no escrow over today's C_e; the curator rejects instead. At
/// the cap the approval opens.
#[test]
fn an_approval_respects_a_lowered_escrow_cap() {
    let (mut svm, w) = world();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    let cap = |svm: &mut LiteSVM, escrow_cap: u64| {
        let mut limits = World::limits(Panel::HouseMajority);
        limits.escrow_cap = escrow_cap;
        let ix = w.set_limits_ix(Role::Admin.pubkey(), limits);
        expect_ok(w.send(svm, ix, &[&Role::Admin.keypair()]), "C_e");
    };
    cap(&mut svm, TOTAL - 1);
    let mut rejected = svm.clone();
    expect_refused(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        EscrowError::EscrowCapExceeded,
        "an approval over the lowered C_e",
    );
    assert!(w.escrow_state_at(&svm, &sponsor(), &PCID).is_none());
    assert_eq!(
        (w.config(&svm).pending_value, w.config(&svm).open_value),
        (TOTAL, 0)
    );
    expect_ok(
        close(&mut rejected, &w, &Role::Curator.keypair(), PCID, REASON),
        "the curator rejects instead",
    );
    assert_eq!(w.config(&rejected).pending_value, 0);
    cap(&mut svm, TOTAL);
    expect_ok(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        "an approval at C_e",
    );
}

/// P3-3: a sponsor off the allowlist deposits once, for the terms the curator approved, and funds
/// nothing after it; an allowlisted sponsor still funds its escrow, until the admin takes it off
/// the list.
#[test]
fn a_sponsor_off_the_allowlist_funds_nothing_after_its_approval() {
    let (mut svm, w) = world();
    let outsider = Role::Winner(0).keypair();
    let funding = Role::Winner(0).pubkey_derived(b"proposal-funding");
    put_token_account(
        &mut svm,
        funding,
        w.mint,
        outsider.pubkey(),
        2 * TOTAL,
        false,
    );
    let (mut terms, opens_at, review_deadline) = plan();
    terms.refund_to = outsider.pubkey();
    let ix = w.submit_proposal_ix(
        outsider.pubkey(),
        Role::Curator.pubkey(),
        funding,
        PCID,
        &terms,
        opens_at,
        review_deadline,
    );
    expect_ok(
        w.send(&mut svm, ix, &[&outsider, &Role::Curator.keypair()]),
        "submit_proposal off the allowlist",
    );
    let ix = w.approve_proposal_ix(Role::Curator.pubkey(), outsider.pubkey(), PCID);
    expect_ok(
        w.send(&mut svm, ix, &[&Role::Curator.keypair()]),
        "approve_proposal",
    );
    let escrow = w.escrow_at(&outsider.pubkey(), &PCID);
    let fund = w.fund_at_ix(outsider.pubkey(), funding, escrow, 1);
    expect_refused(
        w.send(&mut svm, fund, &[&outsider]),
        EscrowError::SponsorNotAllowed,
        "a user sponsor's fund after the approval",
    );
    assert_eq!(
        svm.tokens(&w.escrow_vault_at(&outsider.pubkey(), &PCID)),
        TOTAL
    );
    assert_eq!(
        w.escrow_state_at(&svm, &outsider.pubkey(), &PCID)
            .unwrap()
            .deposited,
        TOTAL
    );

    // The allowlisted sponsor's proposal-born escrow takes its fund, until it is off the list.
    expect_ok(submit(&mut svm, &w, OTHER), "submit_proposal");
    expect_ok(
        approve(&mut svm, &w, &Role::Curator.keypair(), OTHER),
        "approve_proposal",
    );
    let escrow = w.escrow_at(&sponsor(), &OTHER);
    let fund = w.fund_at_ix(sponsor(), w.funding, escrow, 1);
    expect_ok(
        w.send(&mut svm, fund.clone(), &[&Role::Sponsor.keypair()]),
        "an allowlisted sponsor's fund",
    );
    let off = w.set_allowed_ix(
        Role::Admin.pubkey(),
        AllowList::Sponsor,
        sponsor(),
        false,
        false,
    );
    expect_ok(
        w.send(&mut svm, off, &[&Role::Admin.keypair()]),
        "the sponsor off the allowlist",
    );
    expect_refused(
        w.send(&mut svm, fund, &[&Role::Sponsor.keypair()]),
        EscrowError::SponsorNotAllowed,
        "a fund once off the allowlist",
    );
}

/// P3-4, probe P-E: past review_deadline a return naming no reason is an expiry whoever signs it:
/// a revoked curator, the curator, the sponsor. Before it the revoked curator rejects nothing.
#[test]
fn past_the_review_deadline_anyone_expires_a_revoked_curator_included() {
    let (mut svm, w) = world();
    let (_, _, review_deadline) = plan();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    let curator = Role::Curator.keypair();
    let at_deadline = {
        let mut late = svm.clone();
        late.set_time(review_deadline + 1);
        late
    };
    let revoke = w.set_revoked_ix(Role::Guardian.pubkey(), curator.pubkey(), true);
    expect_ok(
        w.send(&mut svm, revoke, &[&Role::Guardian.keypair()]),
        "revoke the curator",
    );
    expect_refused(
        close(&mut svm, &w, &curator, PCID, REASON),
        EscrowError::KeyRevoked,
        "a revoked curator's rejection",
    );
    svm.set_time(review_deadline + 1);
    expect_refused(
        close(&mut svm, &w, &curator, PCID, REASON),
        EscrowError::KeyRevoked,
        "a revoked curator's rejection after review_deadline",
    );
    let sent = expect_ok(
        close(&mut svm, &w, &curator, PCID, NO_REASON),
        "a revoked curator's expiry (probe P-E)",
    );
    let closed = sent.event::<ProposalClosed>();
    assert_eq!(
        (closed.kind, closed.by, closed.amount),
        (ProposalCloseKind::Expired, curator.pubkey(), TOTAL)
    );
    assert_eq!(svm.tokens(&w.ata(&sponsor())), TOTAL);
    assert_eq!(w.config(&svm).pending_value, 0);

    // The curator and the sponsor, past review_deadline with no reason, expire it too.
    for (by, what) in [
        (Role::Curator.keypair(), "the curator"),
        (Role::Sponsor.keypair(), "the sponsor"),
    ] {
        let mut late = at_deadline.clone();
        let sent = expect_ok(close(&mut late, &w, &by, PCID, NO_REASON), what);
        assert_eq!(
            sent.event::<ProposalClosed>().kind,
            ProposalCloseKind::Expired,
            "{what}"
        );
    }
    // The curator naming a reason past review_deadline still rejects.
    let mut late = at_deadline.clone();
    let sent = expect_ok(
        close(&mut late, &w, &Role::Curator.keypair(), PCID, REASON),
        "a late rejection",
    );
    assert_eq!(
        sent.event::<ProposalClosed>().kind,
        ProposalCloseKind::Rejected
    );
}

/// The sponsor's associated token account created and its owner reassigned to `to` (classic
/// Token's SetAuthority, the #852 audit's probe P-A).
fn reassign_ata(svm: &mut LiteSVM, w: &World, to: Pubkey) {
    let create = w.create_ata_ix(Role::Payer.pubkey(), sponsor());
    expect_ok(w.send(svm, create, &[]), "the sponsor's token account");
    let ix = w.set_token_owner_ix(w.ata(&sponsor()), sponsor(), to);
    expect_ok(
        w.send(svm, ix, &[&Role::Sponsor.keypair()]),
        "its owner reassigned",
    );
}

/// A fresh token account the sponsor owns, which anyone may create (here the Payer).
fn sponsor_account(svm: &mut LiteSVM, w: &World, what: &[u8]) -> Pubkey {
    let key = keypair_derived(what);
    assert!(
        w.create_token_account(svm, &key, sponsor()),
        "a token account the sponsor owns"
    );
    key.pubkey()
}

/// P2-2, probe P-A: once the sponsor reassigned its associated token account's owner, a return
/// into it is refused, but every kind of return names another token account the sponsor owns,
/// and the deposit, the rents and pending_value come back. A destination the sponsor does not own,
/// or of another mint, is refused.
#[test]
fn a_reassigned_token_account_pins_no_proposal() {
    let (mut svm, w) = world();
    let (_, _, review_deadline) = plan();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    let attacker = Role::Attacker(0).pubkey();
    reassign_ata(&mut svm, &w, attacker);
    let not_owned = AnchorErrorCode::ConstraintTokenOwner;
    let destination = sponsor_account(&mut svm, &w, b"proposal/refuge");

    let mut late = svm.clone();
    late.set_time(review_deadline + 1);
    for (svm, by, reason, kind) in [
        (
            &mut svm.clone(),
            Role::Sponsor.keypair(),
            NO_REASON,
            ProposalCloseKind::Withdrawn,
        ),
        (
            &mut svm.clone(),
            Role::Curator.keypair(),
            REASON,
            ProposalCloseKind::Rejected,
        ),
        (
            &mut late,
            Role::Attacker(1).keypair(),
            NO_REASON,
            ProposalCloseKind::Expired,
        ),
    ] {
        let what = format!("{kind:?}");
        expect_refused(
            close(svm, &w, &by, PCID, reason),
            not_owned,
            &format!("{what} into the reassigned account"),
        );
        let ix = w.close_proposal_to_ix(by.pubkey(), sponsor(), PCID, reason, Some(destination));
        let sent = expect_ok(w.send(svm, ix, &[&by]), &what);
        assert_eq!(sent.event::<ProposalClosed>().kind, kind);
        assert_eq!(
            (svm.tokens(&destination), svm.tokens(&w.ata(&sponsor()))),
            (TOTAL, 0),
            "{what}: the deposit in the account named"
        );
        assert_eq!(w.config(svm).pending_value, 0, "{what}");
        assert!(w.proposal_state(svm, &sponsor(), &PCID).is_none(), "{what}");
    }

    // Never into an account the sponsor does not own, nor one of another mint.
    let elsewhere = w.ata(&attacker);
    let create = w.create_ata_ix(Role::Payer.pubkey(), attacker);
    expect_ok(
        w.send(&mut svm, create, &[]),
        "the attacker's token account",
    );
    let ix = w.close_proposal_to_ix(
        Role::Sponsor.pubkey(),
        sponsor(),
        PCID,
        NO_REASON,
        Some(elsewhere),
    );
    expect_refused(
        w.send(&mut svm, ix, &[&Role::Sponsor.keypair()]),
        not_owned,
        "a destination the attacker owns",
    );
    let other_mint = Role::Admin.pubkey_derived(b"other-mint");
    support::put_mint(&mut svm, other_mint, TOTAL);
    let foreign = Role::Sponsor.pubkey_derived(b"other-mint-account");
    put_token_account(&mut svm, foreign, other_mint, sponsor(), 0, false);
    let ix = w.close_proposal_to_ix(
        Role::Sponsor.pubkey(),
        sponsor(),
        PCID,
        NO_REASON,
        Some(foreign),
    );
    expect_refused(
        w.send(&mut svm, ix, &[&Role::Sponsor.keypair()]),
        AnchorErrorCode::ConstraintTokenMint,
        "a destination of another mint",
    );
    put_token_account(&mut svm, destination, w.mint, sponsor(), 0, true);
    let ix = w.close_proposal_to_ix(
        Role::Sponsor.pubkey(),
        sponsor(),
        PCID,
        NO_REASON,
        Some(destination),
    );
    expect_refused(
        w.send(&mut svm, ix, &[&Role::Sponsor.keypair()]),
        EscrowError::SponsorAccountFrozen,
        "a frozen destination",
    );
}

/// P2-2, probe P-A2: the escrow a proposal opened refunds past its resolve_deadline into another
/// token account the sponsor owns once its associated one was reassigned, and open_value falls;
/// never into one the sponsor does not own.
#[test]
fn a_reassigned_token_account_pins_no_refund() {
    let (mut svm, w) = world();
    let (terms, _, _) = plan();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    expect_ok(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        "approve_proposal",
    );
    let attacker = Role::Attacker(0).pubkey();
    reassign_ata(&mut svm, &w, attacker);
    svm.set_time(terms.resolve_deadline);
    let address = w.escrow_at(&sponsor(), &PCID);
    let escrow = w.escrow_state_at(&svm, &sponsor(), &PCID).unwrap();
    assert_eq!(w.config(&svm).open_value, TOTAL);
    expect_refused(
        w.send(&mut svm, w.refund_at_ix(address, &escrow, None), &[]),
        AnchorErrorCode::ConstraintTokenOwner,
        "a refund into the reassigned account",
    );
    let create = w.create_ata_ix(Role::Payer.pubkey(), attacker);
    expect_ok(
        w.send(&mut svm, create, &[]),
        "the attacker's token account",
    );
    expect_refused(
        w.send(
            &mut svm,
            w.refund_at_ix(address, &escrow, Some(w.ata(&attacker))),
            &[],
        ),
        AnchorErrorCode::ConstraintTokenOwner,
        "a refund into the attacker's account",
    );
    let destination = sponsor_account(&mut svm, &w, b"refund/refuge");
    let sent = expect_ok(
        w.send(
            &mut svm,
            w.refund_at_ix(address, &escrow, Some(destination)),
            &[],
        ),
        "a refund into another account the sponsor owns",
    );
    let refunded = sent.event::<Refunded>();
    assert_eq!((refunded.escrow, refunded.amount), (address, TOTAL));
    assert_eq!(svm.tokens(&destination), TOTAL);
    assert_eq!(svm.tokens(&w.ata(&sponsor())), 0);
    assert_eq!(w.config(&svm).open_value, 0, "open_value falls");
    assert_eq!(
        w.escrow_state_at(&svm, &sponsor(), &PCID).unwrap().status,
        EscrowStatus::Closed
    );
}

/// The way back's default is unchanged: with no destination named, refund and close_proposal
/// create the associated token account when it is absent, the caller paying its rent.
#[test]
fn with_no_destination_the_way_back_creates_the_associated_account() {
    let (mut svm, w) = world();
    let (terms, _, _) = plan();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal");
    expect_ok(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        "approve_proposal",
    );
    assert!(svm.account(&w.ata(&sponsor())).is_none());
    svm.set_time(terms.resolve_deadline);
    let address = w.escrow_at(&sponsor(), &PCID);
    let escrow = w.escrow_state_at(&svm, &sponsor(), &PCID).unwrap();
    let payer_before = svm.lamports(&Role::Payer.pubkey());
    expect_ok(
        w.send(&mut svm, w.refund_at_ix(address, &escrow, None), &[]),
        "refund",
    );
    assert_eq!(svm.tokens(&w.ata(&sponsor())), TOTAL);
    assert!(
        payer_before - svm.lamports(&Role::Payer.pubkey())
            >= svm.rent_exempt(anchor_spl::token::spl_token::state::Account::LEN),
        "the payer paid the associated account's rent"
    );
}

// ------------------------------------------------------------------------- the rules hash

/// A deposit submitted before its rules were written: submit_proposal takes the all-zero hash,
/// approve_proposal refuses it (RulesNotSet) until the curator writes the hash with
/// set_proposal_rules, once, and the approval then opens the escrow open_escrow opens with it.
#[test]
fn a_proposal_submitted_without_rules_lists_once_the_curator_sets_them() {
    let (mut svm, w) = world();
    let mut twin = svm.clone();
    let terms = submit_unruled(&mut svm, &w, PCID);
    let proposal_key = w.proposal_at(&sponsor(), &PCID);
    let submitted = w.proposal_state(&svm, &sponsor(), &PCID).unwrap();
    assert_eq!(
        submitted.terms, terms,
        "the submit stores the all-zero hash"
    );
    assert_eq!(svm.tokens(&w.proposal_vault_at(&sponsor(), &PCID)), TOTAL);
    expect_refused(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        EscrowError::RulesNotSet,
        "an approval before the rules are set",
    );

    // An hour later the curator sets the rules: the hash alone changes, nothing moves.
    svm.set_time(NOW + HOUR);
    let proposal_lamports = svm.lamports(&proposal_key);
    let curator_lamports = svm.lamports(&Role::Curator.pubkey());
    let sent = expect_ok(
        set_rules(&mut svm, &w, &Role::Curator.keypair(), PCID, support::RULES),
        "set_proposal_rules",
    );
    let set = sent.event::<ProposalRulesSet>();
    assert_eq!(
        (
            set.proposal,
            set.sponsor,
            set.competition_id,
            set.rules_sha256
        ),
        (proposal_key, sponsor(), PCID, support::RULES)
    );
    let ruled = EscrowTerms {
        rules_sha256: support::RULES,
        ..terms.clone()
    };
    assert_eq!(
        w.proposal_state(&svm, &sponsor(), &PCID).unwrap(),
        Proposal {
            terms: ruled.clone(),
            ..submitted
        },
        "only the rules hash changes"
    );
    assert_eq!(svm.lamports(&proposal_key), proposal_lamports);
    assert_eq!(
        svm.lamports(&Role::Curator.pubkey()),
        curator_lamports,
        "the curator pays nothing"
    );
    assert_eq!(svm.tokens(&w.proposal_vault_at(&sponsor(), &PCID)), TOTAL);
    let config = w.config(&svm);
    assert_eq!((config.open_value, config.pending_value), (0, TOTAL));

    // Set once: neither the same hash nor another is written again.
    for (again, label) in [
        (support::RULES, "the same hash again"),
        ([0x9a; 32], "another hash"),
    ] {
        expect_refused(
            set_rules(&mut svm, &w, &Role::Curator.keypair(), PCID, again),
            EscrowError::RulesAlreadySet,
            label,
        );
    }
    assert_eq!(
        w.proposal_state(&svm, &sponsor(), &PCID)
            .unwrap()
            .terms
            .rules_sha256,
        support::RULES
    );

    // The approval opens, with the set hash, the escrow the twin opens directly at that moment.
    svm.set_time(NOW + 2 * HOUR);
    twin.set_time(NOW + 2 * HOUR);
    let approved = expect_ok(
        approve(&mut svm, &w, &Role::Curator.keypair(), PCID),
        "approve_proposal",
    );
    let open = w.open_ix_at(sponsor(), w.funding, w.mint, PCID, &ruled);
    let direct = expect_ok(
        w.send(&mut twin, open, &[&Role::Sponsor.keypair()]),
        "open_escrow",
    );
    let via_proposal = w.escrow_state_at(&svm, &sponsor(), &PCID).unwrap();
    assert_eq!(
        via_proposal,
        w.escrow_state_at(&twin, &sponsor(), &PCID).unwrap(),
        "the escrow is field for field open_escrow's, the set hash its rules"
    );
    assert_eq!(via_proposal.status, EscrowStatus::Open);
    assert_eq!(opened_payload(&approved), opened_payload(&direct));
    assert!(w.proposal_state(&svm, &sponsor(), &PCID).is_none());
    assert_eq!(svm.tokens(&w.escrow_vault_at(&sponsor(), &PCID)), TOTAL);
}

/// The hash is written once and never over one the sponsor submitted, and the write is a real
/// one: an all-zero argument is refused.
#[test]
fn the_rules_are_set_once_never_over_a_submitted_hash() {
    let (mut svm, w) = world();
    expect_ok(submit(&mut svm, &w, PCID), "submit_proposal, with rules");
    let submitted = w.proposal_state(&svm, &sponsor(), &PCID).unwrap();
    assert_ne!(submitted.terms.rules_sha256, [0; 32]);
    expect_refused(
        set_rules(&mut svm, &w, &Role::Curator.keypair(), PCID, [0x9a; 32]),
        EscrowError::RulesAlreadySet,
        "a set over the submitted hash",
    );
    assert_eq!(
        w.proposal_state(&svm, &sponsor(), &PCID).unwrap(),
        submitted
    );

    submit_unruled(&mut svm, &w, OTHER);
    expect_refused(
        set_rules(&mut svm, &w, &Role::Curator.keypair(), OTHER, [0; 32]),
        EscrowError::RulesNotSet,
        "an all-zero hash",
    );
    expect_ok(
        set_rules(
            &mut svm,
            &w,
            &Role::Curator.keypair(),
            OTHER,
            support::RULES,
        ),
        "set_proposal_rules",
    );
    expect_refused(
        set_rules(&mut svm, &w, &Role::Curator.keypair(), OTHER, [0x9a; 32]),
        EscrowError::RulesAlreadySet,
        "a second set",
    );
}

/// Only the curator of the day sets the rules: not the sponsor, the admin or a stranger, not a
/// revoked curator, not a replaced one, and nobody while proposals are off.
#[test]
fn only_the_curator_of_the_day_sets_the_rules() {
    let (mut svm, w) = world();
    submit_unruled(&mut svm, &w, PCID);
    for (by, label) in [
        (Role::Sponsor.keypair(), "the sponsor"),
        (Role::Admin.keypair(), "the admin"),
        (Role::Attacker(0).keypair(), "a stranger"),
    ] {
        expect_refused(
            set_rules(&mut svm, &w, &by, PCID, support::RULES),
            EscrowError::UnauthorizedCurator,
            label,
        );
    }

    let curator = Role::Curator.keypair();
    let revoke = w.set_revoked_ix(Role::Guardian.pubkey(), curator.pubkey(), true);
    expect_ok(
        w.send(&mut svm, revoke, &[&Role::Guardian.keypair()]),
        "revoke the curator",
    );
    expect_refused(
        set_rules(&mut svm, &w, &curator, PCID, support::RULES),
        EscrowError::KeyRevoked,
        "a revoked curator",
    );
    let unrevoke = w.set_revoked_ix(Role::Admin.pubkey(), curator.pubkey(), false);
    expect_ok(
        w.send(&mut svm, unrevoke, &[&Role::Admin.keypair()]),
        "unrevoke",
    );

    let off = w.set_proposal_policy_ix(Role::Admin.pubkey(), Pubkey::default(), PENDING_CAP);
    let mut disabled = svm.clone();
    expect_ok(
        w.send(&mut disabled, off, &[&Role::Admin.keypair()]),
        "proposals off",
    );
    expect_refused(
        set_rules(&mut disabled, &w, &curator, PCID, support::RULES),
        EscrowError::ProposalsDisabled,
        "a set while proposals are off",
    );

    let successor = Role::Spare(0).keypair();
    let policy = w.set_proposal_policy_ix(Role::Admin.pubkey(), successor.pubkey(), PENDING_CAP);
    expect_ok(
        w.send(&mut svm, policy, &[&Role::Admin.keypair()]),
        "replace the curator",
    );
    expect_refused(
        set_rules(&mut svm, &w, &curator, PCID, support::RULES),
        EscrowError::UnauthorizedCurator,
        "the old curator",
    );
    let sent = expect_ok(
        set_rules(&mut svm, &w, &successor, PCID, support::RULES),
        "the new curator's set",
    );
    assert_eq!(
        sent.event::<ProposalRulesSet>().rules_sha256,
        support::RULES
    );
}

/// The rules are set inside the review, as the approval is: at review_deadline still, after it
/// never (ReviewWindowClosed), and the deposit then goes back as any expiry's does.
#[test]
fn the_rules_are_set_by_the_review_deadline() {
    let (mut svm, w) = world();
    let (_, _, review_deadline) = plan();
    submit_unruled(&mut svm, &w, PCID);

    let mut at_deadline = svm.clone();
    at_deadline.set_time(review_deadline);
    expect_ok(
        set_rules(
            &mut at_deadline,
            &w,
            &Role::Curator.keypair(),
            PCID,
            support::RULES,
        ),
        "a set at review_deadline",
    );

    svm.set_time(review_deadline + 1);
    expect_refused(
        set_rules(&mut svm, &w, &Role::Curator.keypair(), PCID, support::RULES),
        EscrowError::ReviewWindowClosed,
        "a set after review_deadline",
    );
    assert_eq!(
        w.proposal_state(&svm, &sponsor(), &PCID)
            .unwrap()
            .terms
            .rules_sha256,
        [0; 32]
    );
    expect_ok(
        close(&mut svm, &w, &Role::Attacker(0).keypair(), PCID, NO_REASON),
        "the expiry",
    );
    assert_eq!(svm.tokens(&w.ata(&sponsor())), TOTAL);
}

/// The rules wait on what the approval waits on: IntakeStop and PayoutStop both refuse the set
/// (IntakeStopped), and a held sponsor's proposal gets none (SponsorRevoked).
#[test]
fn the_rules_wait_on_the_stop_and_the_hold_as_the_approval_does() {
    let (mut svm, w) = world();
    submit_unruled(&mut svm, &w, PCID);

    for stop in [StopState::IntakeStop, StopState::PayoutStop] {
        let mut stopped = svm.clone();
        let ix = w.set_stop_ix(Role::Guardian.pubkey(), stop);
        expect_ok(
            w.send(&mut stopped, ix, &[&Role::Guardian.keypair()]),
            "the stop",
        );
        expect_refused(
            set_rules(
                &mut stopped,
                &w,
                &Role::Curator.keypair(),
                PCID,
                support::RULES,
            ),
            EscrowError::IntakeStopped,
            "a set under the stop",
        );
    }

    let mut held = svm.clone();
    let revoke = w.set_revoked_ix(Role::Guardian.pubkey(), sponsor(), true);
    expect_ok(
        w.send(&mut held, revoke, &[&Role::Guardian.keypair()]),
        "the guardian's hold",
    );
    expect_refused(
        set_rules(
            &mut held,
            &w,
            &Role::Curator.keypair(),
            PCID,
            support::RULES,
        ),
        EscrowError::SponsorRevoked,
        "a held sponsor's proposal",
    );

    expect_ok(
        set_rules(&mut svm, &w, &Role::Curator.keypair(), PCID, support::RULES),
        "set_proposal_rules, nothing stopped or held",
    );
}
