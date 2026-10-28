//! Regressions for the findings of the 2026-10-27 drill, one named test each, on the release build
//! (`node scripts/chain/build.ts release` first) with the release windows (72 h to challenge, 48 h
//! to attest, 72 h on hold), time moved by rewriting LiteSVM's Clock:
//! - F1: a quorum cannot settle before challenge_deadline.
//! - F2: a late challenge gets its full attest window.
//! - F3: the arbiter cannot pick a vote-less alternative.
//! - F4: a compliance key can be rotated off an escrow whose winners it holds.
//! - F5: rotate_role works on an in-flight escrow.
//! - F6: open refuses attacker terms (a foreign mint, arbiter, refund_to or regraders, a low bond,
//!   short windows).
//! - F7, the program's half: a claimant the honest rubric does not pay, once held, never clears,
//!   on the lapse path or with the co-signature (the server's half, the claim-screen job that holds
//!   it, is server/chain/jobs/claim-screen.ts and tests/unit/api-claims.test.ts).
//!
//! And the fixes of the #552 audit (with #536's blast-radius finding), one named test each:
//! - A1: an overturn of the posted result settles only at attest_deadline.
//! - A2: escalate refuses a recorded quorum once settle may apply it, and not before.
//! - A3: set_config_role refuses a revoked key.
//! - A4: request_claim waits while a PayoutStop or the escrow's freeze holds the payouts.
//! - A5: attest and arbiter_resolve pin the challenge account (and its challenger) they are
//!   passed.
//! - A6: the escrow is never its own resolver or compliance key (open, rotate).
//! - A7: commit_entries refuses an empty list.
//!
//! (The bucket's refill never running backwards is a property: tests/properties.rs.)
//!
//! The world (keys, Config, escrow, trees) is tests/support/mod.rs.

mod mainnet;
mod program_so;
mod support;

use {
    anchor_lang::prelude::Pubkey,
    litesvm::LiteSVM,
    prize_escrow::{
        AllowList, ArbiterChoice, ArbiterResolved, Challenged, ConfigRole, EscrowError, EscrowRole,
        EscrowStatus, EscrowTerms, Floors, RoleRotated, SettleOutcome, Settled, StopState,
        MAX_REVEAL_GRACE, MIN_ATTEST_WINDOW, MIN_CHALLENGE_WINDOW, MIN_CLAIM_WINDOW,
        MIN_HOLD_WINDOW, MIN_REVEAL_GRACE,
    },
    support::{
        expect_ok, expect_refused, put_mint, put_token_account, Chain, Panel, Role, Sent, Tree,
        World, ATTEST_WINDOW, BOND, CHALLENGE_WINDOW, DAY, ENTRIES_ROOT, FINAL_END, HARD_DEADLINE,
        HOLD_WINDOW, HOUR, MIN_BOND, PRIZES, TOTAL,
    },
};

/// The honest result posted at FINAL_END: its challenge window ends here, its attest window
/// (once challenged) at ATTEST_DEADLINE.
const CHALLENGE_DEADLINE: i64 = FINAL_END + CHALLENGE_WINDOW;
const ATTEST_DEADLINE: i64 = CHALLENGE_DEADLINE + ATTEST_WINDOW;

/// Tree indices of World::trees.
const HONEST: usize = 0;
const STEAL: usize = 1;
const EVIL_ROOT: usize = 2;

struct T {
    svm: LiteSVM,
    w: World,
    trees: Vec<Tree>,
}

impl T {
    /// The Config alone, no escrow opened yet, on `panel`.
    fn unopened(panel: Panel) -> T {
        let mut svm = mainnet::svm();
        svm.add_program(prize_escrow::ID, program_so::bytes())
            .unwrap();
        let w = World::create(&mut svm, panel, false);
        let trees = w.trees();
        T { svm, w, trees }
    }

    /// The escrow open with its entries root committed, on `panel`.
    fn open(panel: Panel) -> T {
        let mut svm = mainnet::svm();
        svm.add_program(prize_escrow::ID, program_so::bytes())
            .unwrap();
        let w = World::create(&mut svm, panel, true);
        let trees = w.trees();
        T { svm, w, trees }
    }

    /// The honest result posted by the resolver at FINAL_END (Challengeable).
    fn posted(panel: Panel) -> T {
        let mut t = T::open(panel);
        t.at(FINAL_END);
        expect_ok(t.post(Role::Resolver, HONEST), "post_result");
        assert_eq!(t.state().challenge_deadline, CHALLENGE_DEADLINE);
        t
    }

    fn at(&mut self, time: i64) {
        self.svm.set_time(time);
    }

    fn state(&self) -> prize_escrow::Escrow {
        self.w.state(&self.svm).expect("the escrow")
    }

    fn tree(&self, i: usize) -> Tree {
        self.trees[i].clone()
    }

    fn post(&mut self, resolver: Role, tree: usize) -> Sent {
        let ix = self.w.post_ix(resolver.pubkey(), &self.trees[tree], TOTAL);
        self.w.send(&mut self.svm, ix, &[resolver.key()])
    }

    fn challenge(&mut self, by: Role, tree: usize) -> Sent {
        let tree = self.tree(tree);
        self.w.challenge_with(&mut self.svm, by.key(), &tree)
    }

    fn attest(&mut self, regrader: Role, commitment: [u8; 32]) -> Sent {
        let ix = self.w.attest_ix(&self.svm, regrader.pubkey(), commitment);
        self.w.send(&mut self.svm, ix, &[regrader.key()])
    }

    fn settle(&mut self) -> Sent {
        let ix = self.w.settle_ix(&self.state());
        self.w.send(&mut self.svm, ix, &[])
    }

    fn refund(&mut self) -> Sent {
        let ix = self.w.refund_ix(&self.state());
        self.w.send(&mut self.svm, ix, &[])
    }

    /// The arbiter picks the posted result (`alt` None) or the challenge of tree `alt`.
    fn arbiter(&mut self, alt: Option<usize>) -> Sent {
        let e = self.state();
        let ix = match alt {
            None => self
                .w
                .arbiter_ix(&e, Role::Arbiter.pubkey(), None, e.commitment),
            Some(i) => {
                let commitment = self.trees[i].commitment;
                let ch = self
                    .w
                    .challenge(&self.svm, &commitment)
                    .expect("the challenge");
                self.w
                    .arbiter_ix(&e, Role::Arbiter.pubkey(), Some(&ch), commitment)
            }
        };
        self.w.send(&mut self.svm, ix, &[Role::Arbiter.key()])
    }

    fn guardian(&mut self, ix: anchor_lang::solana_program::instruction::Instruction) -> Sent {
        self.w.send(&mut self.svm, ix, &[Role::Guardian.key()])
    }

    fn admin(&mut self, ix: anchor_lang::solana_program::instruction::Instruction) -> Sent {
        self.w.send(&mut self.svm, ix, &[Role::Admin.key()])
    }

    fn rotate(&mut self, role: EscrowRole, old: Pubkey, new: Pubkey) -> Sent {
        let ix = self.w.rotate_ix(Role::Admin.pubkey(), role, old, new);
        self.admin(ix)
    }

    fn hold(&mut self, compliance: Role, claimant: Pubkey) -> Sent {
        let ix = self.w.hold_ix(compliance.pubkey(), claimant);
        self.w.send(&mut self.svm, ix, &[compliance.key()])
    }

    fn release(&mut self, compliance: Role, claimant: Pubkey) -> Sent {
        let ix = self.w.release_ix(compliance.pubkey(), claimant);
        self.w.send(&mut self.svm, ix, &[compliance.key()])
    }

    /// `claimant` claims its whole leaf of tree `tree`, co-signed by `compliance` when given.
    fn claim(&mut self, claimant: Role, tree: usize, compliance: Option<Role>) -> Sent {
        let t = &self.trees[tree];
        let leaf = t.leaf_of(&claimant.pubkey()).expect("a leaf");
        let ix = self.w.claim_ix(
            claimant.pubkey(),
            compliance.map(Role::pubkey),
            t.leaves[leaf].1,
            0,
            t.proofs[leaf].clone(),
        );
        let mut signers = vec![claimant.key()];
        signers.extend(compliance.map(Role::key));
        self.w.send(&mut self.svm, ix, &signers)
    }

    fn request(&mut self, claimant: Role, tree: usize) -> Sent {
        let t = &self.trees[tree];
        let leaf = t.leaf_of(&claimant.pubkey()).expect("a leaf");
        let ix =
            self.w
                .request_claim_ix(claimant.pubkey(), t.leaves[leaf].1, t.proofs[leaf].clone());
        self.w.send(&mut self.svm, ix, &[claimant.key()])
    }

    fn tokens(&self, owner: Role) -> u64 {
        self.svm.tokens(&self.w.ata(&owner.pubkey()))
    }
}

// ------------------------------------------------------------------------------------- F1

/// F1. A quorum, however early it forms, never settles before challenge_deadline: not a house
/// quorum answering a junk self-challenge in the first minute, not a quorum for that junk
/// alternative, not on a clock a freeze held back, and not while a commit made on the window's
/// last second may still be revealed. At challenge_deadline the same quorum settles.
#[test]
fn f1_a_quorum_cannot_settle_before_the_challenge_deadline() {
    // The house self-challenges at once and its regraders back the posted result at once.
    let mut t = T::posted(Panel::HouseMajority);
    t.at(FINAL_END + 60);
    expect_ok(
        t.challenge(Role::Attacker(2), STEAL),
        "a junk self-challenge",
    );
    let posted = t.state().commitment;
    expect_ok(t.attest(Role::Regrader(0), posted), "seat 0");
    expect_ok(t.attest(Role::Regrader(1), posted), "seat 1");
    assert_eq!((t.state().votes_result, t.state().k), (2, 2), "a quorum");
    for time in [
        FINAL_END + 61,
        FINAL_END + DAY,
        CHALLENGE_DEADLINE - HOUR,
        CHALLENGE_DEADLINE - 1,
    ] {
        t.at(time);
        expect_refused(
            t.settle(),
            EscrowError::DeadlineNotReached,
            &format!("settle at {time}"),
        );
        assert_eq!(t.state().status, EscrowStatus::Disputed);
    }
    // A refund never pre-empts it either: the quorum is recorded.
    expect_refused(t.refund(), EscrowError::QuorumRecorded, "refund");
    t.at(CHALLENGE_DEADLINE);
    let settled = expect_ok(t.settle(), "settle at challenge_deadline").event::<Settled>();
    assert_eq!(settled.outcome, SettleOutcome::ResultUpheld);

    // A quorum for the junk alternative itself waits as long.
    let mut t = T::posted(Panel::HouseMajority);
    t.at(FINAL_END + 60);
    expect_ok(t.challenge(Role::Attacker(2), STEAL), "a junk challenge");
    let junk = t.trees[STEAL].commitment;
    expect_ok(t.attest(Role::Regrader(0), junk), "seat 0 backs the junk");
    expect_ok(t.attest(Role::Regrader(1), junk), "seat 1 backs the junk");
    assert_eq!(t.state().challenger, Role::Attacker(2).pubkey(), "recorded");
    t.at(CHALLENGE_DEADLINE - 1);
    expect_refused(
        t.settle(),
        EscrowError::DeadlineNotReached,
        "the junk quorum early",
    );
    // The window it could not cut short is the guardian's: it escalates, and the arbiter keeps the
    // posted result.
    let escalate = t.w.escalate_ix(Role::Guardian.pubkey());
    expect_ok(t.guardian(escalate), "escalate inside the window");
    expect_ok(t.arbiter(None), "the arbiter keeps the posted result");
    assert_eq!(t.state().commitment, t.trees[HONEST].commitment);

    // A freeze holds the escrow clock: challenge_deadline moves later in wall time.
    let mut t = T::posted(Panel::HouseMajority);
    t.at(FINAL_END + 60);
    expect_ok(
        t.challenge(Role::Attacker(2), STEAL),
        "a junk self-challenge",
    );
    let posted = t.state().commitment;
    expect_ok(t.attest(Role::Regrader(0), posted), "seat 0");
    expect_ok(t.attest(Role::Regrader(1), posted), "seat 1");
    t.at(FINAL_END + HOUR);
    let freeze = t.w.set_freeze_ix(Role::Guardian.pubkey(), true);
    expect_ok(t.guardian(freeze), "freeze");
    t.at(FINAL_END + HOUR + DAY);
    let unfreeze = t.w.set_freeze_ix(Role::Admin.pubkey(), false);
    expect_ok(t.admin(unfreeze), "the admin unfreezes a day later");
    t.at(CHALLENGE_DEADLINE);
    expect_refused(
        t.settle(),
        EscrowError::DeadlineNotReached,
        "settle at the wall-clock deadline, a frozen day behind",
    );
    t.at(CHALLENGE_DEADLINE + DAY - 1);
    expect_refused(
        t.settle(),
        EscrowError::DeadlineNotReached,
        "one second short",
    );
    t.at(CHALLENGE_DEADLINE + DAY);
    expect_ok(t.settle(), "settle once the escrow clock reaches it");

    // A commit on the window's last second holds settle until its reveal grace is over.
    let mut t = T::posted(Panel::HouseMajority);
    t.at(FINAL_END + 60);
    expect_ok(
        t.challenge(Role::Attacker(2), STEAL),
        "a junk self-challenge",
    );
    let posted = t.state().commitment;
    expect_ok(t.attest(Role::Regrader(0), posted), "seat 0");
    expect_ok(t.attest(Role::Regrader(1), posted), "seat 1");
    t.at(CHALLENGE_DEADLINE - 1);
    let late = t.tree(EVIL_ROOT);
    let (hash, _) = t.w.commit_of(&Role::Watcher(0).pubkey(), &late);
    let commit = t.w.challenge_commit_ix(Role::Watcher(0).pubkey(), hash);
    expect_ok(
        t.w.send(&mut t.svm, commit, &[Role::Watcher(0).key()]),
        "a commit on the last second",
    );
    t.at(CHALLENGE_DEADLINE);
    expect_refused(
        t.settle(),
        EscrowError::CommitsPendingReveal,
        "inside the grace",
    );
    t.at(CHALLENGE_DEADLINE + MIN_REVEAL_GRACE);
    expect_ok(t.settle(), "settle once the grace is over");
}

// ------------------------------------------------------------------------------------- F2

/// F2. Every challenge the window admits gets the whole attest window: the attest deadline is
/// challenge_deadline + attest_window, so a challenge on the window's last second (the first, or
/// one joining a dispute) leaves the regraders attest_window + 1 seconds, a vote on its last
/// second counts, and nothing settles the dispute against it before then. One revealed in the
/// reveal grace keeps all but the grace (MAX_REVEAL_GRACE < MIN_ATTEST_WINDOW).
#[test]
fn f2_a_late_challenge_gets_its_full_attest_window() {
    // The first challenge, on the window's last second.
    let mut t = T::posted(Panel::IndependentMajority);
    t.at(CHALLENGE_DEADLINE - 1);
    let challenged = expect_ok(
        t.challenge(Role::Watcher(0), EVIL_ROOT),
        "a last-second challenge",
    )
    .event::<Challenged>();
    assert_eq!(challenged.attest_deadline, ATTEST_DEADLINE);
    assert!(challenged.attest_deadline - (CHALLENGE_DEADLINE - 1) > ATTEST_WINDOW);
    t.at(CHALLENGE_DEADLINE);
    expect_refused(
        t.settle(),
        EscrowError::AttestWindowOpen,
        "no quorum, window open",
    );
    t.at(ATTEST_DEADLINE - 1);
    expect_refused(t.settle(), EscrowError::AttestWindowOpen, "its last second");
    let alt = t.trees[EVIL_ROOT].commitment;
    expect_ok(
        t.attest(Role::Regrader(1), alt),
        "a vote on the window's last second",
    );
    expect_ok(t.attest(Role::Regrader(2), alt), "the quorum on it");
    // The overturn applies at attest_deadline (A1), the second after its last vote.
    expect_refused(
        t.settle(),
        EscrowError::OverturnWindowOpen,
        "the overturn on the window's last second",
    );
    t.at(ATTEST_DEADLINE);
    let settled = expect_ok(t.settle(), "settle").event::<Settled>();
    assert_eq!(settled.outcome, SettleOutcome::AltApplied);
    assert_eq!(t.state().payout_root, t.trees[EVIL_ROOT].root);

    // A second challenge joining a dispute on the window's last second: the same deadline.
    let mut t = T::posted(Panel::IndependentMajority);
    t.at(FINAL_END + 60);
    expect_ok(
        t.challenge(Role::Attacker(2), STEAL),
        "an early junk challenge",
    );
    t.at(CHALLENGE_DEADLINE - 1);
    let second = expect_ok(
        t.challenge(Role::Watcher(0), EVIL_ROOT),
        "a last-second second one",
    )
    .event::<Challenged>();
    assert_eq!((second.index, second.attest_deadline), (1, ATTEST_DEADLINE));
    t.at(ATTEST_DEADLINE - 1);
    let alt = t.trees[EVIL_ROOT].commitment;
    expect_ok(t.attest(Role::Regrader(1), alt), "seat 1 on the second");
    expect_ok(t.attest(Role::Regrader(2), alt), "seat 2 on the second");
    assert_eq!(t.state().challenger, Role::Watcher(0).pubkey());
    t.at(ATTEST_DEADLINE);
    let settled = expect_ok(t.settle(), "settle").event::<Settled>();
    assert_eq!(
        (settled.outcome, settled.challenger),
        (SettleOutcome::AltApplied, Role::Watcher(0).pubkey())
    );

    // Committed on the last second and revealed on the grace's last second: the attest window
    // less the grace, and a vote after attest_deadline is refused.
    let mut t = T::posted(Panel::IndependentMajority);
    t.at(CHALLENGE_DEADLINE - 1);
    let late = t.tree(EVIL_ROOT);
    let (hash, salt) = t.w.commit_of(&Role::Watcher(0).pubkey(), &late);
    let commit = t.w.challenge_commit_ix(Role::Watcher(0).pubkey(), hash);
    expect_ok(
        t.w.send(&mut t.svm, commit, &[Role::Watcher(0).key()]),
        "commit",
    );
    t.svm.next_slot();
    let grace = t.state().reveal_grace;
    assert!((MIN_REVEAL_GRACE..=MAX_REVEAL_GRACE).contains(&grace));
    t.at(CHALLENGE_DEADLINE + grace - 1);
    let reveal =
        t.w.challenge_reveal_ix(Role::Watcher(0).pubkey(), hash, salt, &late);
    let challenged = expect_ok(
        t.w.send(&mut t.svm, reveal, &[Role::Watcher(0).key()]),
        "a reveal on the grace's last second",
    )
    .event::<Challenged>();
    assert_eq!(challenged.attest_deadline, ATTEST_DEADLINE);
    assert!(ATTEST_DEADLINE - (CHALLENGE_DEADLINE + grace - 1) > ATTEST_WINDOW - grace);
    t.at(ATTEST_DEADLINE);
    expect_refused(
        t.attest(Role::Regrader(1), late.commitment),
        EscrowError::AttestWindowClosed,
        "a vote at attest_deadline",
    );
    let settled = expect_ok(t.settle(), "settle: no quorum").event::<Settled>();
    assert_eq!(settled.outcome, SettleOutcome::NoQuorum);
    assert_eq!(t.state().status, EscrowStatus::Frozen);
}

// ------------------------------------------------------------------------------------- F3

/// F3. The arbiter chooses only the posted result or an alternative a named regrader voted for: a
/// vote-less challenge is AlternativeUnbacked, whether the escrow froze on no quorum or the
/// guardian escalated it before anyone voted, so holding the arbiter and bonding a junk challenge
/// cannot put an arbitrary root in force.
#[test]
fn f3_the_arbiter_cannot_pick_a_vote_less_alternative() {
    // Two challenges, one with one vote, one with none; no quorum: Frozen.
    let mut t = T::posted(Panel::IndependentMajority);
    t.at(FINAL_END + 60);
    expect_ok(
        t.challenge(Role::Attacker(2), STEAL),
        "a vote-less junk challenge",
    );
    expect_ok(
        t.challenge(Role::Watcher(0), EVIL_ROOT),
        "a challenge one regrader backs",
    );
    let backed = t.trees[EVIL_ROOT].commitment;
    let posted = t.state().commitment;
    expect_ok(t.attest(Role::Regrader(1), backed), "one vote for it");
    expect_ok(
        t.attest(Role::Regrader(2), posted),
        "one vote for the posted result",
    );
    t.at(ATTEST_DEADLINE);
    expect_ok(t.settle(), "settle: no quorum");
    assert_eq!(t.state().status, EscrowStatus::Frozen);

    expect_refused(
        t.arbiter(Some(STEAL)),
        EscrowError::AlternativeUnbacked,
        "the vote-less one",
    );
    assert_eq!(t.state().status, EscrowStatus::Frozen);
    assert_eq!(t.state().payout_root, t.trees[HONEST].root);
    // Nor may it name another commitment than the chosen side's.
    let e = t.state();
    let ch = t.w.challenge(&t.svm, &backed).unwrap();
    let ix = t.w.arbiter_ix(
        &e,
        Role::Arbiter.pubkey(),
        Some(&ch),
        t.trees[STEAL].commitment,
    );
    expect_refused(
        t.w.send(&mut t.svm, ix, &[Role::Arbiter.key()]),
        EscrowError::InvalidResultHash,
        "a commitment that is not the chosen challenge's",
    );
    let resolved =
        expect_ok(t.arbiter(Some(EVIL_ROOT)), "the backed one").event::<ArbiterResolved>();
    assert_eq!(resolved.payout_root, t.trees[EVIL_ROOT].root);

    // Escalated by the guardian before any vote: every alternative is vote-less; only the posted
    // result can be chosen.
    let mut t = T::posted(Panel::IndependentMajority);
    t.at(FINAL_END + 60);
    expect_ok(t.challenge(Role::Attacker(2), STEAL), "a junk challenge");
    let escalate = t.w.escalate_ix(Role::Guardian.pubkey());
    expect_ok(t.guardian(escalate), "escalate");
    assert_eq!(t.state().status, EscrowStatus::Frozen);
    expect_refused(
        t.arbiter(Some(STEAL)),
        EscrowError::AlternativeUnbacked,
        "after escalate",
    );
    // Regraders cannot vote it up once Frozen.
    expect_refused(
        t.attest(Role::Regrader(1), t.trees[STEAL].commitment),
        EscrowError::InvalidStatus,
        "a vote on a Frozen escrow",
    );
    expect_ok(t.arbiter(None), "the posted result");
    assert_eq!(t.state().payout_root, t.trees[HONEST].root);
}

// ------------------------------------------------------------------------------------- F4

/// F4. A compliance key that has holds on an escrow's winners rotates off it: the new key releases
/// the holds and co-signs, the old one can neither release, hold nor co-sign there, and the held
/// winners are paid.
#[test]
fn f4_a_compliance_key_can_be_rotated_off_an_escrow_whose_winners_it_holds() {
    let mut t = T::posted(Panel::IndependentMajority);
    t.at(CHALLENGE_DEADLINE);
    expect_ok(t.settle(), "settle");
    for w in [Role::Winner(0), Role::Winner(1)] {
        expect_ok(
            t.hold(Role::Compliance, w.pubkey()),
            "the old key holds a winner",
        );
    }
    // The guardian revokes the compromised key; the admin rotates it off.
    let revoke =
        t.w.set_revoked_ix(Role::Guardian.pubkey(), Role::Compliance.pubkey(), true);
    expect_ok(t.guardian(revoke), "revoke the compliance key");
    expect_refused(
        t.rotate(
            EscrowRole::Compliance,
            Role::Spare(0).pubkey(),
            Role::Spare(1).pubkey(),
        ),
        EscrowError::RoleMismatch,
        "a rotation naming the wrong old key",
    );
    expect_refused(
        t.rotate(
            EscrowRole::Compliance,
            Role::Compliance.pubkey(),
            Role::Regrader(1).pubkey(),
        ),
        EscrowError::RegraderNotIndependent,
        "a regrader as the compliance key",
    );
    let rotated = expect_ok(
        t.rotate(
            EscrowRole::Compliance,
            Role::Compliance.pubkey(),
            Role::Spare(0).pubkey(),
        ),
        "rotate the compliance key on a Claimable escrow",
    )
    .event::<RoleRotated>();
    assert_eq!(
        (rotated.old, rotated.new),
        (Role::Compliance.pubkey(), Role::Spare(0).pubkey())
    );
    assert_eq!(t.state().compliance, Role::Spare(0).pubkey());

    // The old key is off the escrow.
    expect_refused(
        t.release(Role::Compliance, Role::Winner(0).pubkey()),
        EscrowError::UnauthorizedCompliance,
        "the old key releases",
    );
    expect_refused(
        t.hold(Role::Compliance, Role::Attacker(0).pubkey()),
        EscrowError::UnauthorizedCompliance,
        "the old key holds",
    );
    expect_refused(
        t.claim(Role::Winner(0), HONEST, Some(Role::Compliance)),
        EscrowError::UnauthorizedCompliance,
        "the old key co-signs",
    );
    // A held winner stays held for the new key too, until it releases.
    expect_refused(
        t.claim(Role::Winner(0), HONEST, Some(Role::Spare(0))),
        EscrowError::HeldForCompliance,
        "a held winner, the new key co-signing",
    );
    for (i, w) in [Role::Winner(0), Role::Winner(1)].into_iter().enumerate() {
        expect_ok(
            t.release(Role::Spare(0), w.pubkey()),
            "the new key releases",
        );
        expect_ok(
            t.claim(w, HONEST, Some(Role::Spare(0))),
            "the new key co-signs",
        );
        assert_eq!(t.tokens(w), PRIZES[i]);
    }
}

// ------------------------------------------------------------------------------------- F5

/// F5. rotate_role works on an escrow in flight: mid-dispute the admin replaces the resolver (who
/// then takes the bonds the posted result wins) and a seat that has not voted (the new key votes,
/// the old one no longer can), but never a seat that voted; and it rotates at every status but
/// Closed.
#[test]
fn f5_rotate_role_works_on_an_in_flight_escrow() {
    let mut t = T::posted(Panel::HouseMajority);
    t.at(FINAL_END + 60);
    expect_ok(
        t.challenge(Role::Attacker(2), STEAL),
        "a junk challenge: Disputed",
    );
    let posted = t.state().commitment;
    expect_ok(t.attest(Role::Regrader(0), posted), "seat 0 votes");

    expect_ok(
        t.rotate(
            EscrowRole::Resolver,
            Role::Resolver.pubkey(),
            Role::Spare(1).pubkey(),
        ),
        "rotate the resolver mid-dispute",
    );
    expect_refused(
        t.rotate(
            EscrowRole::Regrader,
            Role::Regrader(0).pubkey(),
            Role::Regrader(3).pubkey(),
        ),
        EscrowError::RegraderAlreadyVoted,
        "a seat that voted",
    );
    expect_refused(
        t.rotate(
            EscrowRole::Regrader,
            Role::Regrader(2).pubkey(),
            Role::Attacker(0).pubkey(),
        ),
        EscrowError::RegraderNotRegistered,
        "an unregistered key",
    );
    expect_refused(
        t.rotate(
            EscrowRole::Regrader,
            Role::Regrader(2).pubkey(),
            Role::Regrader(1).pubkey(),
        ),
        EscrowError::InvalidRegraderSet,
        "a key already on the panel",
    );
    expect_ok(
        t.rotate(
            EscrowRole::Regrader,
            Role::Regrader(2).pubkey(),
            Role::Regrader(3).pubkey(),
        ),
        "rotate an unvoted seat mid-dispute",
    );
    expect_refused(
        t.attest(Role::Regrader(2), posted),
        EscrowError::NotARegrader,
        "the rotated-out key",
    );
    expect_ok(
        t.attest(Role::Regrader(3), posted),
        "the new seat votes: the quorum",
    );
    assert_eq!(t.state().votes_result, 2);

    t.at(CHALLENGE_DEADLINE);
    let new_resolver = Role::Spare(1).pubkey();
    let before = t.svm.lamports(&new_resolver);
    let settled = expect_ok(t.settle(), "settle").event::<Settled>();
    assert_eq!(settled.outcome, SettleOutcome::ResultUpheld);
    assert_eq!(
        settled.resolver_paid,
        2 * BOND,
        "its bond and the junk challenger's"
    );
    assert_eq!(
        t.svm.lamports(&new_resolver) - before,
        2 * BOND,
        "paid to the new resolver"
    );

    // Every status but Closed: Open, Challengeable, Frozen and Claimable take a rotation too.
    let mut t = T::open(Panel::HouseMajority);
    expect_ok(
        t.rotate(
            EscrowRole::Compliance,
            Role::Compliance.pubkey(),
            Role::Spare(0).pubkey(),
        ),
        "Open",
    );
    t.at(FINAL_END);
    expect_ok(t.post(Role::Resolver, HONEST), "post");
    expect_ok(
        t.rotate(
            EscrowRole::Resolver,
            Role::Resolver.pubkey(),
            Role::Spare(1).pubkey(),
        ),
        "Challengeable",
    );
    let escalate = t.w.escalate_ix(Role::Guardian.pubkey());
    expect_ok(t.guardian(escalate), "escalate");
    expect_ok(
        t.rotate(
            EscrowRole::Regrader,
            Role::Regrader(1).pubkey(),
            Role::Regrader(4).pubkey(),
        ),
        "Frozen",
    );
    expect_ok(t.arbiter(None), "the arbiter keeps the posted result");
    expect_ok(
        t.rotate(
            EscrowRole::Compliance,
            Role::Spare(0).pubkey(),
            Role::Compliance.pubkey(),
        ),
        "Claimable",
    );
    let claim_deadline = t.state().claim_deadline;
    t.at(claim_deadline + 1);
    expect_ok(t.refund(), "refund");
    expect_refused(
        t.rotate(
            EscrowRole::Resolver,
            Role::Spare(1).pubkey(),
            Role::Resolver.pubkey(),
        ),
        EscrowError::EscrowClosed,
        "Closed",
    );
}

// ------------------------------------------------------------------------------------- F6

/// F6. open_escrow refuses terms an attacker who can reach the sponsor's signing path would write:
/// a mint off the allowlist, an arbiter other than the Config's, a refund_to other than the
/// sponsor, regraders that are unregistered, not independent of the resolver or the compliance
/// key, or more of the house's than the allowance, a bond under the Config's minimum or the rent
/// floor, and windows under the floors; and a sponsor off the allowlist. No escrow account is
/// left behind by any of them; the honest terms then open.
#[test]
fn f6_open_refuses_attacker_terms() {
    let mut t = {
        let mut svm = mainnet::svm();
        svm.add_program(prize_escrow::ID, program_so::bytes())
            .unwrap();
        let w = World::create(&mut svm, Panel::IndependentMajority, false);
        let trees = w.trees();
        T { svm, w, trees }
    };
    let good = World::default_terms();
    // A second house key registered, for a panel over the allowance (one house seat).
    let register = t.w.set_allowed_ix(
        Role::Admin.pubkey(),
        AllowList::Regrader,
        Role::Spare(1).pubkey(),
        true,
        true,
    );
    expect_ok(t.admin(register), "register a second house regrader");
    for (key, house) in [(Role::Resolver, false), (Role::Compliance, false)] {
        let register = t.w.set_allowed_ix(
            Role::Admin.pubkey(),
            AllowList::Regrader,
            key.pubkey(),
            true,
            house,
        );
        expect_ok(t.admin(register), "register a role key as a regrader");
    }
    // A mint nobody allowed, and the sponsor's account of it.
    let foreign = Role::Attacker(0).pubkey_derived(b"foreign-mint");
    let foreign_funding = Role::Sponsor.pubkey_derived(b"foreign-funding");
    put_mint(&mut t.svm, foreign, 10 * TOTAL);
    put_token_account(
        &mut t.svm,
        foreign_funding,
        foreign,
        Role::Sponsor.pubkey(),
        10 * TOTAL,
        false,
    );

    let with = |f: &dyn Fn(&mut EscrowTerms)| {
        let mut terms = good.clone();
        f(&mut terms);
        terms
    };
    let cases: Vec<(&str, EscrowTerms, EscrowError)> = vec![
        (
            "an arbiter other than the Config's",
            with(&|t| t.arbiter = Role::Attacker(0).pubkey()),
            EscrowError::ArbiterNotConfig,
        ),
        (
            "a refund_to other than the sponsor",
            with(&|t| t.refund_to = Role::Attacker(0).pubkey()),
            EscrowError::RefundToNotSponsor,
        ),
        (
            "an unregistered regrader",
            with(&|t| t.regraders[2] = Role::Attacker(1).pubkey()),
            EscrowError::RegraderNotRegistered,
        ),
        (
            "the resolver on the panel",
            with(&|t| t.regraders[2] = Role::Resolver.pubkey()),
            EscrowError::RegraderNotIndependent,
        ),
        (
            "the compliance key on the panel",
            with(&|t| t.regraders[1] = Role::Compliance.pubkey()),
            EscrowError::RegraderNotIndependent,
        ),
        (
            "two house regraders over an allowance of one",
            with(&|t| t.regraders[1] = Role::Spare(1).pubkey()),
            EscrowError::TooManyHouseRegraders,
        ),
        (
            "a panel the adversary's one key could carry (k = 1 of 3)",
            with(&|t| t.k = 1),
            EscrowError::InvalidRegraderSet,
        ),
        (
            "one regrader named twice",
            with(&|t| t.regraders[2] = t.regraders[1]),
            EscrowError::InvalidRegraderSet,
        ),
        (
            "a bond under the Config's minimum",
            with(&|t| t.bond_lamports = MIN_BOND - 1),
            EscrowError::BondBelowMin,
        ),
        (
            "a bond under the rent floor",
            with(&|t| t.bond_lamports = 1),
            EscrowError::BondBelowFloor,
        ),
        (
            "no bond",
            with(&|t| t.bond_lamports = 0),
            EscrowError::InvalidAmount,
        ),
        (
            "no compliance key",
            with(&|t| t.compliance = Pubkey::default()),
            EscrowError::ComplianceRequired,
        ),
        (
            "a challenge window under 72 h",
            with(&|t| t.challenge_window = MIN_CHALLENGE_WINDOW - 1),
            EscrowError::InvalidWindow,
        ),
        (
            "an attest window under 48 h",
            with(&|t| t.attest_window = MIN_ATTEST_WINDOW - 1),
            EscrowError::InvalidWindow,
        ),
        (
            "a hold window under 72 h",
            with(&|t| t.hold_window = MIN_HOLD_WINDOW - 1),
            EscrowError::InvalidWindow,
        ),
        (
            "a claim window under 7 days",
            with(&|t| t.claim_window = MIN_CLAIM_WINDOW - 1),
            EscrowError::InvalidWindow,
        ),
        (
            "a claim window no longer than the hold window",
            with(&|t| {
                t.hold_window = MIN_CLAIM_WINDOW;
                t.claim_window = MIN_CLAIM_WINDOW;
            }),
            EscrowError::ClaimWindowTooShort,
        ),
        (
            "a hard deadline before the windows end",
            with(&|t| t.hard_deadline -= 1),
            EscrowError::HardDeadlineTooEarly,
        ),
    ];
    let escrow = t.w.escrow();
    for (what, terms, want) in cases {
        let open = t.w.open_ix(&terms);
        expect_refused(
            t.w.send(&mut t.svm, open, &[Role::Sponsor.key()]),
            want,
            what,
        );
        assert!(t.svm.account(&escrow).is_none(), "{what}: no escrow");
    }

    // A foreign mint, from the sponsor's account of it.
    let open =
        t.w.open_ix_as(Role::Sponsor.pubkey(), foreign_funding, foreign, &good);
    expect_refused(
        t.w.send(&mut t.svm, open, &[Role::Sponsor.key()]),
        EscrowError::MintNotAllowed,
        "a mint off the allowlist",
    );
    // A sponsor nobody allowed, refunding to itself.
    let attacker = Role::Attacker(0);
    let mut own = good.clone();
    own.refund_to = attacker.pubkey();
    let open =
        t.w.open_ix_as(attacker.pubkey(), t.w.attacker_funding, t.w.mint, &own);
    expect_refused(
        t.w.send(&mut t.svm, open, &[attacker.key()]),
        EscrowError::SponsorNotAllowed,
        "a sponsor off the allowlist",
    );

    // Floors above the compiled minimums hold each window to the Config's.
    let floors = Floors {
        min_challenge_window: MIN_CHALLENGE_WINDOW + DAY,
        min_attest_window: MIN_ATTEST_WINDOW + DAY,
        min_hold_window: MIN_HOLD_WINDOW + DAY,
        min_claim_window: MIN_CLAIM_WINDOW + DAY,
        reveal_grace: MIN_REVEAL_GRACE,
    };
    let set = t.w.set_floors_ix(Role::Admin.pubkey(), floors);
    expect_ok(t.admin(set), "raise the floors");
    let long = with(&|t| {
        t.challenge_window = MIN_CHALLENGE_WINDOW + DAY;
        t.attest_window = MIN_ATTEST_WINDOW + DAY;
        t.hold_window = MIN_HOLD_WINDOW + DAY;
        t.claim_window = MIN_CLAIM_WINDOW + DAY;
        t.hard_deadline += 4 * DAY;
    });
    type Shorten<'a> = (&'a str, &'a dyn Fn(&mut EscrowTerms));
    let short: [Shorten; 4] = [
        ("challenge", &|t| t.challenge_window -= 1),
        ("attest", &|t| t.attest_window -= 1),
        ("hold", &|t| t.hold_window -= 1),
        ("claim", &|t| t.claim_window -= 1),
    ];
    for (which, f) in short {
        let mut terms = long.clone();
        f(&mut terms);
        let open = t.w.open_ix(&terms);
        expect_refused(
            t.w.send(&mut t.svm, open, &[Role::Sponsor.key()]),
            EscrowError::WindowBelowFloor,
            &format!("a {which} window under the Config's floor"),
        );
    }
    // A revoked resolver, and intake stopped.
    let revoke =
        t.w.set_revoked_ix(Role::Guardian.pubkey(), Role::Resolver.pubkey(), true);
    expect_ok(t.guardian(revoke), "revoke the resolver");
    let open = t.w.open_ix(&long);
    expect_refused(
        t.w.send(&mut t.svm, open, &[Role::Sponsor.key()]),
        EscrowError::KeyRevoked,
        "a revoked resolver",
    );
    let unrevoke =
        t.w.set_revoked_ix(Role::Admin.pubkey(), Role::Resolver.pubkey(), false);
    expect_ok(t.admin(unrevoke), "unrevoke");
    let stop =
        t.w.set_stop_ix(Role::Guardian.pubkey(), StopState::IntakeStop);
    expect_ok(t.guardian(stop), "IntakeStop");
    let open = t.w.open_ix(&long);
    expect_refused(
        t.w.send(&mut t.svm, open, &[Role::Sponsor.key()]),
        EscrowError::IntakeStopped,
        "intake stopped",
    );
    let unstop = t.w.set_stop_ix(Role::Admin.pubkey(), StopState::Normal);
    expect_ok(t.admin(unstop), "unstop");
    assert!(t.svm.account(&escrow).is_none(), "nothing opened");

    let open = t.w.open_ix(&long);
    expect_ok(
        t.w.send(&mut t.svm, open, &[Role::Sponsor.key()]),
        "the honest terms",
    );
    assert_eq!(t.state().status, EscrowStatus::Open);
}

// ------------------------------------------------------------------------------------- F7

/// F7, the program's half. A result the honest rubric does not match is in force (the house's
/// quorum and the guardian asleep): the claimant it pays is unknown to the server, which holds its
/// request (claim-screen's fail-closed rule). Held, it never clears: not on the lapse path once
/// the hold window passes, not with the co-signature, and a second request is refused too; the
/// claim window then lapses into a refund to the sponsor.
#[test]
fn f7_an_unknown_claimants_request_is_held_and_never_clears() {
    let mut t = T::open(Panel::HouseMajority);
    t.at(FINAL_END);
    expect_ok(
        t.post(Role::Resolver, STEAL),
        "a result paying the adversary",
    );
    t.at(FINAL_END + 60);
    expect_ok(
        t.challenge(Role::Watcher(0), HONEST),
        "the watcher challenges",
    );
    let posted = t.state().commitment;
    expect_ok(t.attest(Role::Regrader(0), posted), "house seat 0");
    expect_ok(t.attest(Role::Regrader(1), posted), "house seat 1");
    t.at(CHALLENGE_DEADLINE);
    expect_ok(t.settle(), "the house quorum settles");
    assert_eq!(t.state().payout_root, t.trees[STEAL].root);

    let unknown = Role::Attacker(0);
    expect_ok(t.request(unknown, STEAL), "the unknown claimant requests");
    let requested_at =
        t.w.receipt_state(&t.svm, &unknown.pubkey())
            .unwrap()
            .requested_at;
    // The server's claim-screen job holds it inside the hold window.
    t.at(CHALLENGE_DEADLINE + HOUR);
    expect_ok(
        t.hold(Role::Compliance, unknown.pubkey()),
        "held for review",
    );
    t.at(requested_at + HOLD_WINDOW);
    expect_refused(
        t.claim(unknown, STEAL, None),
        EscrowError::HeldForCompliance,
        "the lapse path, the hold window over",
    );
    expect_refused(
        t.claim(unknown, STEAL, Some(Role::Compliance)),
        EscrowError::HeldForCompliance,
        "even co-signed",
    );
    expect_refused(
        t.request(unknown, STEAL),
        EscrowError::HeldForCompliance,
        "a new request",
    );
    assert_eq!(t.tokens(unknown), 0);
    let claim_deadline = t.state().claim_deadline;
    t.at(claim_deadline + 1);
    expect_ok(t.refund(), "refund");
    assert_eq!(
        t.tokens(Role::Sponsor),
        TOTAL,
        "the pot back to the sponsor"
    );
}

// ------------------------------------------------------------------------------- the #552 audit

/// A1 (#536's blast-radius finding). An overturn waits for the whole attest window: a quorum for a
/// challenge's alternative, however early it formed, settles only at attest_deadline
/// (OverturnWindowOpen before it; a refund is refused meanwhile, QuorumRecorded), so on a house
/// panel the house's keys can no longer apply a challenge revealed in the reveal grace at
/// challenge_deadline (tests/blast_radius.rs). Until attest_deadline the guardian may still
/// escalate the recorded alternative to the arbiter; from it on the vote binds. Upholding the
/// posted result keeps challenge_deadline.
#[test]
fn a1_an_overturn_settles_only_at_the_attest_deadline() {
    // The resolver's root pays the adversary; the watcher's honest challenge reaches k at once.
    let overturned = || {
        let mut t = T::open(Panel::IndependentMajority);
        t.at(FINAL_END);
        expect_ok(
            t.post(Role::Resolver, STEAL),
            "a result paying the adversary",
        );
        t.at(FINAL_END + 60);
        expect_ok(
            t.challenge(Role::Watcher(0), HONEST),
            "the watcher's challenge",
        );
        let honest = t.trees[HONEST].commitment;
        expect_ok(t.attest(Role::Regrader(1), honest), "seat 1");
        expect_ok(t.attest(Role::Regrader(2), honest), "seat 2: the quorum");
        let e = t.state();
        assert_eq!(e.challenger, Role::Watcher(0).pubkey(), "recorded at k");
        assert_eq!(e.attest_deadline, ATTEST_DEADLINE);
        t
    };
    let mut t = overturned();
    for time in [
        CHALLENGE_DEADLINE,
        CHALLENGE_DEADLINE + DAY,
        ATTEST_DEADLINE - 1,
    ] {
        t.at(time);
        expect_refused(
            t.settle(),
            EscrowError::OverturnWindowOpen,
            &format!("the overturn's settle at {time}"),
        );
        expect_refused(
            t.refund(),
            EscrowError::QuorumRecorded,
            &format!("a refund at {time}"),
        );
        assert_eq!(t.state().status, EscrowStatus::Disputed);
    }
    t.at(ATTEST_DEADLINE);
    let settled = expect_ok(t.settle(), "settle at attest_deadline").event::<Settled>();
    assert_eq!(
        (settled.outcome, settled.challenger),
        (SettleOutcome::AltApplied, Role::Watcher(0).pubkey())
    );
    assert_eq!(t.state().payout_root, t.trees[HONEST].root);

    // On the attest window's last second the guardian may still hand it to the arbiter...
    let mut t = overturned();
    t.at(ATTEST_DEADLINE - 1);
    let escalate = t.w.escalate_ix(Role::Guardian.pubkey());
    expect_ok(t.guardian(escalate), "escalate a recorded alternative");
    assert_eq!(t.state().status, EscrowStatus::Frozen);
    expect_ok(
        t.arbiter(Some(HONEST)),
        "the arbiter applies the alternative",
    );
    assert_eq!(t.state().payout_root, t.trees[HONEST].root);
    // ...and at attest_deadline the vote binds.
    let mut t = overturned();
    t.at(ATTEST_DEADLINE);
    let escalate = t.w.escalate_ix(Role::Guardian.pubkey());
    expect_refused(
        t.guardian(escalate),
        EscrowError::QuorumRecorded,
        "escalate at attest_deadline",
    );
    expect_ok(t.settle(), "settle applies it");

    // A quorum upholding the posted result settles at challenge_deadline, as before.
    let mut t = T::posted(Panel::IndependentMajority);
    t.at(FINAL_END + 60);
    expect_ok(t.challenge(Role::Attacker(2), STEAL), "a junk challenge");
    let posted = t.state().commitment;
    expect_ok(t.attest(Role::Regrader(1), posted), "seat 1");
    expect_ok(t.attest(Role::Regrader(2), posted), "seat 2");
    t.at(CHALLENGE_DEADLINE);
    let settled = expect_ok(t.settle(), "upheld at challenge_deadline").event::<Settled>();
    assert_eq!(settled.outcome, SettleOutcome::ResultUpheld);
}

/// A2. A recorded quorum for the posted result binds from challenge_deadline, when settle may
/// uphold it: escalate refuses it from then on (QuorumRecorded), so the guardian never turns a
/// decided vote into a Frozen escrow that refunds past hard_deadline. Before it the guardian may
/// escalate however fast the quorum formed: on a house panel the house's keys can post a false
/// result, self-challenge it and vote it to k within seconds, and the challenge window is the
/// guardian's time to hand that to the arbiter.
#[test]
fn a2_escalate_refuses_a_posted_quorum_once_it_may_settle() {
    let house_quorum = || {
        let mut t = T::open(Panel::HouseMajority);
        t.at(FINAL_END);
        expect_ok(
            t.post(Role::Resolver, STEAL),
            "the house posts a result paying the adversary",
        );
        expect_ok(
            t.challenge(Role::Attacker(2), EVIL_ROOT),
            "and self-challenges it in the same second",
        );
        let posted = t.state().commitment;
        expect_ok(t.attest(Role::Regrader(0), posted), "house seat 0");
        expect_ok(
            t.attest(Role::Regrader(1), posted),
            "house seat 1: the quorum",
        );
        assert_eq!(t.state().votes_result, 2);
        t
    };
    let mut t = house_quorum();
    t.at(CHALLENGE_DEADLINE);
    let escalate = t.w.escalate_ix(Role::Guardian.pubkey());
    expect_refused(
        t.guardian(escalate),
        EscrowError::QuorumRecorded,
        "escalate at challenge_deadline",
    );
    let escalate = t.w.escalate_ix(Role::Admin.pubkey());
    expect_refused(
        t.admin(escalate),
        EscrowError::QuorumRecorded,
        "the admin's escalate too",
    );
    let settled = expect_ok(t.settle(), "the quorum settles").event::<Settled>();
    assert_eq!(settled.outcome, SettleOutcome::ResultUpheld);

    // Inside the window the guardian escalates it, an hour after the quorum formed.
    let mut t = house_quorum();
    t.at(FINAL_END + HOUR);
    let escalate = t.w.escalate_ix(Role::Guardian.pubkey());
    expect_ok(t.guardian(escalate), "escalate inside the window");
    assert_eq!(t.state().status, EscrowStatus::Frozen);
    t.at(CHALLENGE_DEADLINE);
    expect_refused(
        t.settle(),
        EscrowError::InvalidStatus,
        "the quorum's settle",
    );
    // No alternative a regrader backed: the arbiter would only keep the false root, so it waits,
    // and the pot goes back to the sponsor after hard_deadline.
    expect_refused(
        t.arbiter(Some(EVIL_ROOT)),
        EscrowError::AlternativeUnbacked,
        "the vote-less self-challenge",
    );
    t.at(HARD_DEADLINE + 1);
    expect_ok(t.refund(), "refund past hard_deadline");
    assert_eq!(
        t.tokens(Role::Sponsor),
        TOTAL,
        "the pot back to the sponsor"
    );
}

/// A3. set_config_role refuses a revoked key for the guardian and the arbiter (KeyRevoked), as
/// accept_admin and rotate_role refuse one; once the admin unrevokes it, the key takes the role.
#[test]
fn a3_set_config_role_refuses_a_revoked_key() {
    let mut t = T::open(Panel::IndependentMajority);
    let key = Role::Spare(0).pubkey();
    let revoke = t.w.set_revoked_ix(Role::Guardian.pubkey(), key, true);
    expect_ok(t.guardian(revoke), "the guardian revokes a key");
    for role in [ConfigRole::Guardian, ConfigRole::Arbiter] {
        let ix = t.w.set_config_role_ix(Role::Admin.pubkey(), role, key);
        expect_refused(
            t.admin(ix),
            EscrowError::KeyRevoked,
            &format!("the revoked key as the {role:?}"),
        );
    }
    let config = t.w.config(&t.svm);
    assert_eq!(
        (config.guardian, config.arbiter),
        (Role::Guardian.pubkey(), Role::Arbiter.pubkey())
    );
    let unrevoke = t.w.set_revoked_ix(Role::Admin.pubkey(), key, false);
    expect_ok(t.admin(unrevoke), "the admin unrevokes it");
    let ix =
        t.w.set_config_role_ix(Role::Admin.pubkey(), ConfigRole::Arbiter, key);
    expect_ok(t.admin(ix), "the key becomes the arbiter");
    assert_eq!(t.w.config(&t.svm).arbiter, key);
}

/// A4. request_claim, the first step of the claim that needs no co-signature, is refused while a
/// PayoutStop or the guardian's freeze of the escrow is in force (PayoutStopped, EscrowFrozen), as
/// claim is, so no hold window starts while the payouts are held.
#[test]
fn a4_request_claim_waits_while_payouts_are_held() {
    let mut t = T::posted(Panel::IndependentMajority);
    t.at(CHALLENGE_DEADLINE);
    expect_ok(t.settle(), "settle");
    let stop =
        t.w.set_stop_ix(Role::Guardian.pubkey(), StopState::PayoutStop);
    expect_ok(t.guardian(stop), "PayoutStop");
    expect_refused(
        t.request(Role::Winner(0), HONEST),
        EscrowError::PayoutStopped,
        "a request under a PayoutStop",
    );
    let unstop = t.w.set_stop_ix(Role::Admin.pubkey(), StopState::Normal);
    expect_ok(t.admin(unstop), "the admin lifts it");
    let freeze = t.w.set_freeze_ix(Role::Guardian.pubkey(), true);
    expect_ok(t.guardian(freeze), "the guardian's freeze");
    expect_refused(
        t.request(Role::Winner(0), HONEST),
        EscrowError::EscrowFrozen,
        "a request on a frozen escrow",
    );
    assert!(
        t.w.receipt_state(&t.svm, &Role::Winner(0).pubkey())
            .is_none(),
        "no request recorded"
    );
    let unfreeze = t.w.set_freeze_ix(Role::Admin.pubkey(), false);
    expect_ok(t.admin(unfreeze), "the admin unfreezes it");
    expect_ok(
        t.request(Role::Winner(0), HONEST),
        "the request once the payouts run",
    );
}

/// A5. attest and arbiter_resolve pin the challenge account in their account constraints: this
/// escrow's challenge of the named commitment, at its own PDA, and (arbiter_resolve) the
/// challenger account its challenger. A vote on the posted result passing a challenge, a record
/// off its PDA (only the program could write one; a LiteSVM account stands in for a future bug),
/// the posted result chosen with a challenge or a challenger passed, and a challenger that is
/// not the challenge's are each refused, and nothing is counted or paid.
#[test]
fn a5_attest_and_arbiter_resolve_pin_the_challenge_account() {
    let mut t = T::posted(Panel::IndependentMajority);
    t.at(FINAL_END + 60);
    expect_ok(t.challenge(Role::Watcher(0), EVIL_ROOT), "a challenge");
    let (posted, alt) = (t.state().commitment, t.trees[EVIL_ROOT].commitment);
    let pda = t.w.challenge_pda(&alt);
    let copy = Role::Attacker(3).pubkey_derived(b"challenge-copy");
    let account = t.svm.account(&pda).expect("the Challenge PDA");
    t.svm.put_account(copy, account);

    let regrader = Role::Regrader(0);
    let ix = t.w.attest_with_ix(regrader.pubkey(), posted, Some(pda));
    expect_refused(
        t.w.send(&mut t.svm, ix, &[regrader.key()]),
        EscrowError::ChallengeMismatch,
        "a vote on the posted result passing a challenge",
    );
    let ix = t.w.attest_with_ix(regrader.pubkey(), alt, Some(copy));
    expect_refused(
        t.w.send(&mut t.svm, ix, &[regrader.key()]),
        EscrowError::ChallengeMismatch,
        "a vote through a challenge record off its PDA",
    );
    let e = t.state();
    assert_eq!((e.votes_result, e.votes_alt), (0, 0), "nothing counted");
    expect_ok(
        t.attest(Role::Regrader(1), alt),
        "a vote through its own PDA",
    );

    let escalate = t.w.escalate_ix(Role::Guardian.pubkey());
    expect_ok(t.guardian(escalate), "escalate");
    let e = t.state();
    let watcher = Role::Watcher(0).pubkey();
    let refusals = [
        (
            "the posted result passing a challenge",
            ArbiterChoice::Posted,
            e.commitment,
            Some(pda),
            Some(watcher),
            EscrowError::InvalidResultHash,
        ),
        (
            "the posted result passing a challenger alone",
            ArbiterChoice::Posted,
            e.commitment,
            None,
            Some(watcher),
            EscrowError::ChallengeMismatch,
        ),
        (
            "the alternative through a record off its PDA",
            ArbiterChoice::Alternative,
            alt,
            Some(copy),
            Some(watcher),
            EscrowError::ChallengeMismatch,
        ),
        (
            "the alternative paying another challenger",
            ArbiterChoice::Alternative,
            alt,
            Some(pda),
            Some(Role::Attacker(2).pubkey()),
            EscrowError::ChallengeMismatch,
        ),
    ];
    for (what, choice, commitment, challenge, challenger, code) in refusals {
        let ix = t.w.arbiter_with_ix(
            &e,
            Role::Arbiter.pubkey(),
            choice,
            commitment,
            challenge,
            challenger,
        );
        expect_refused(t.w.send(&mut t.svm, ix, &[Role::Arbiter.key()]), code, what);
        assert_eq!(t.state().status, EscrowStatus::Frozen, "{what}");
    }
    let resolved = expect_ok(
        t.arbiter(Some(EVIL_ROOT)),
        "the alternative through its own PDA",
    )
    .event::<ArbiterResolved>();
    assert_eq!((resolved.challenge, resolved.challenger), (pda, watcher));
}

/// A6. The escrow is never its own resolver or compliance key (RoleIsEscrow): its address is a
/// PDA of this program, which never signs for it, so post_result could never land, or holds and
/// co-signatures never could and every claim would clear unscreened on the lapse path. open_escrow
/// refuses it (no escrow left behind), and so does rotate_role.
#[test]
fn a6_the_escrow_is_never_its_own_resolver_or_compliance_key() {
    let mut t = T::unopened(Panel::IndependentMajority);
    let escrow = t.w.escrow();
    let good = World::default_terms();
    for (what, terms) in [
        (
            "the escrow as its resolver",
            EscrowTerms {
                resolver: escrow,
                ..good.clone()
            },
        ),
        (
            "the escrow as its compliance key",
            EscrowTerms {
                compliance: escrow,
                ..good.clone()
            },
        ),
    ] {
        let ix = t.w.open_ix(&terms);
        expect_refused(
            t.w.send(&mut t.svm, ix, &[Role::Sponsor.key()]),
            EscrowError::RoleIsEscrow,
            what,
        );
        assert!(t.w.state(&t.svm).is_none(), "{what}: no escrow left behind");
    }
    let ix = t.w.open_ix(&good);
    expect_ok(
        t.w.send(&mut t.svm, ix, &[Role::Sponsor.key()]),
        "the honest terms open",
    );
    for (role, old) in [
        (EscrowRole::Resolver, Role::Resolver),
        (EscrowRole::Compliance, Role::Compliance),
    ] {
        expect_refused(
            t.rotate(role, old.pubkey(), escrow),
            EscrowError::RoleIsEscrow,
            &format!("rotating the escrow in as its {role:?}"),
        );
    }
    let e = t.state();
    assert_eq!(
        (e.resolver, e.compliance),
        (Role::Resolver.pubkey(), Role::Compliance.pubkey())
    );
}

/// A7. commit_entries refuses a root of no entries (NoEntries; the zero root stays
/// InvalidResultHash), as the server never commits an empty list; one entry or more commits.
#[test]
fn a7_commit_entries_refuses_an_empty_list() {
    let mut t = T::unopened(Panel::IndependentMajority);
    let ix = t.w.open_ix(&World::default_terms());
    expect_ok(t.w.send(&mut t.svm, ix, &[Role::Sponsor.key()]), "open");
    let resolver = Role::Resolver;
    for (what, root, count, code) in [
        (
            "a root of no entries",
            ENTRIES_ROOT,
            0,
            EscrowError::NoEntries,
        ),
        ("the zero root", [0; 32], 0, EscrowError::InvalidResultHash),
    ] {
        let ix = t.w.commit_entries_with_ix(resolver.pubkey(), root, count);
        expect_refused(t.w.send(&mut t.svm, ix, &[resolver.key()]), code, what);
        assert_eq!(t.state().entries_root, [0; 32], "{what}: nothing committed");
    }
    let ix =
        t.w.commit_entries_with_ix(resolver.pubkey(), ENTRIES_ROOT, 1);
    expect_ok(
        t.w.send(&mut t.svm, ix, &[resolver.key()]),
        "a root of one entry",
    );
    assert_eq!(
        (t.state().entries_root, t.state().entries_count),
        (ENTRIES_ROOT, 1)
    );
}
