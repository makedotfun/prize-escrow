//! The house path (the owner's ruling of 2026-11-10: "for house rewards no need for 72h challenge
//! window even with escrow for now"), on the release build (`node scripts/chain/build.ts release`
//! first) with the release windows, time moved by rewriting LiteSVM's Clock:
//! - the admin marks a listed sponsor as a house sponsor (set_allowed(Sponsor, key, true, true));
//!   Config.house_sponsors holds one bit per place on the sponsor list;
//! - an escrow a house sponsor opens may take any challenge window from 0: neither
//!   MIN_CHALLENGE_WINDOW nor the Config's min_challenge_window holds it, and with 0 the result
//!   settles and its winners claim (co-signed) the moment it is posted, with no clock move;
//! - every other bound holds a house sponsor (the attest, hold and claim windows and their
//!   floors), a sponsor listed but not marked keeps every floor, and a proposal never takes the
//!   house path, whoever its sponsor is;
//! - marking, unmarking and removing sponsors keeps every other sponsor's bit (on chain here, and
//!   as a property over random sequences of Config::allow_or_mark and disallow);
//! - a Config written before house_sponsors existed (mainnet's: its reserved bytes zero, written
//!   here in the old layout by hand) decodes with no house sponsor and opens exactly as before.
//!
//! The world (keys, Config, escrow, trees) is tests/support/mod.rs.

mod mainnet;
mod program_so;
mod support;

use {
    anchor_lang::{prelude::Pubkey, AccountDeserialize, AnchorSerialize, Discriminator},
    litesvm::LiteSVM,
    prize_escrow::{
        AllowList, Claimed, Config, ConfigChange, ConfigChanged, EscrowError, EscrowStatus,
        EscrowTerms, Floors, RegraderEntry, SettleOutcome, Settled, StopState, ARBITER_SLACK,
        MAX_SPONSORS, MAX_WINDOW, MIN_ATTEST_WINDOW, MIN_CHALLENGE_WINDOW, MIN_CLAIM_WINDOW,
        MIN_HOLD_WINDOW, MIN_REVEAL_GRACE,
    },
    proptest::prelude::*,
    support::{
        expect_ok, expect_refused, Chain, Panel, Role, Sent, Tree, World, DAY, FINAL_END, HOUR,
        PRIZES, TOTAL, USER_CID,
    },
};

/// Tree index of World::trees: the honest result.
const HONEST: usize = 0;

struct T {
    svm: LiteSVM,
    w: World,
    trees: Vec<Tree>,
}

impl T {
    /// The Config alone (the sponsor listed, not marked), no escrow opened yet.
    fn new() -> T {
        let mut svm = mainnet::svm();
        svm.add_program(prize_escrow::ID, program_so::bytes())
            .unwrap();
        let w = World::create(&mut svm, Panel::HouseMajority, false);
        let trees = w.trees();
        T { svm, w, trees }
    }

    fn at(&mut self, time: i64) {
        self.svm.set_time(time);
    }

    fn now(&self) -> i64 {
        self.svm.time()
    }

    fn config(&self) -> Config {
        self.w.config(&self.svm)
    }

    fn state(&self) -> prize_escrow::Escrow {
        self.w.state(&self.svm).expect("the escrow")
    }

    fn send(
        &mut self,
        ix: anchor_lang::solana_program::instruction::Instruction,
        by: &[Role],
    ) -> Sent {
        let keys: Vec<_> = by.iter().map(|r| r.key()).collect();
        self.w.send(&mut self.svm, ix, &keys)
    }

    /// set_allowed by the admin.
    fn set_allowed(&mut self, list: AllowList, key: Pubkey, allowed: bool, house: bool) -> Sent {
        let ix = self
            .w
            .set_allowed_ix(Role::Admin.pubkey(), list, key, allowed, house);
        self.send(ix, &[Role::Admin])
    }

    /// The admin marks (or unmarks) the world's sponsor as a house sponsor.
    fn mark_sponsor(&mut self, house: bool) -> ConfigChanged {
        let sent = expect_ok(
            self.set_allowed(AllowList::Sponsor, Role::Sponsor.pubkey(), true, house),
            "mark the sponsor",
        );
        sent.event::<ConfigChanged>()
    }

    fn set_floors(&mut self, floors: Floors) {
        let ix = self.w.set_floors_ix(Role::Admin.pubkey(), floors);
        expect_ok(self.send(ix, &[Role::Admin]), "set_floors");
    }

    /// open_escrow by the world's sponsor at the world's competition id.
    fn open(&mut self, terms: &EscrowTerms) -> Sent {
        let ix = self.w.open_ix(terms);
        self.send(ix, &[Role::Sponsor])
    }

    fn commit_entries(&mut self) {
        let ix = self.w.commit_entries_ix(Role::Resolver.pubkey());
        expect_ok(self.send(ix, &[Role::Resolver]), "commit_entries");
    }

    fn post(&mut self) -> Sent {
        let ix = self
            .w
            .post_ix(Role::Resolver.pubkey(), &self.trees[HONEST], TOTAL);
        self.send(ix, &[Role::Resolver])
    }

    fn settle(&mut self) -> Sent {
        let ix = self.w.settle_ix(&self.state());
        self.send(ix, &[])
    }

    /// `claimant` claims its whole leaf of the honest tree, co-signed by the compliance key when
    /// `cosigned`.
    fn claim(&mut self, claimant: Role, cosigned: bool) -> Sent {
        let t = &self.trees[HONEST];
        let leaf = t.leaf_of(&claimant.pubkey()).expect("a leaf");
        let ix = self.w.claim_ix(
            claimant.pubkey(),
            cosigned.then(|| Role::Compliance.pubkey()),
            t.leaves[leaf].1,
            0,
            t.proofs[leaf].clone(),
        );
        let mut by = vec![claimant];
        if cosigned {
            by.push(Role::Compliance);
        }
        self.send(ix, &by)
    }

    fn request(&mut self, claimant: Role) -> Sent {
        let t = &self.trees[HONEST];
        let leaf = t.leaf_of(&claimant.pubkey()).expect("a leaf");
        let ix =
            self.w
                .request_claim_ix(claimant.pubkey(), t.leaves[leaf].1, t.proofs[leaf].clone());
        self.send(ix, &[claimant])
    }

    fn tokens(&self, owner: Role) -> u64 {
        self.svm.tokens(&self.w.ata(&owner.pubkey()))
    }
}

/// The world's default terms with `challenge_window`, the hard deadline the earliest it may be.
fn terms_with(challenge_window: i64) -> EscrowTerms {
    let mut terms = World::default_terms();
    terms.challenge_window = challenge_window;
    terms.hard_deadline = earliest_hard(&terms);
    terms
}

/// The earliest hard deadline EscrowTerms::validate accepts for `terms`.
fn earliest_hard(terms: &EscrowTerms) -> i64 {
    terms.resolve_deadline
        + terms.challenge_window
        + terms.attest_window
        + terms.hold_window
        + terms.claim_window
        + ARBITER_SLACK
}

/// The release floors (the World's) with the challenge floor at `challenge`.
fn floors_with_challenge(challenge: i64) -> Floors {
    Floors {
        min_challenge_window: challenge,
        min_attest_window: MIN_ATTEST_WINDOW,
        min_hold_window: MIN_HOLD_WINDOW,
        min_claim_window: MIN_CLAIM_WINDOW,
        reveal_grace: MIN_REVEAL_GRACE,
    }
}

// ------------------------------------------------------------------------------ the house path

/// A house sponsor opens with challenge_window 0; the result posted at FINAL_END sets
/// challenge_deadline to that very second, so no challenge can be committed and the guardian's
/// escalate already finds the result bound (UnchallengedResultBinds), and settle (Undisputed,
/// Claimable) and a co-signed claim land at the same clock reading, back to back. A claim on the
/// lapse path still waits its hold window after request_claim.
#[test]
fn a_house_sponsor_opens_with_no_challenge_window_and_its_winners_claim_at_once() {
    let mut t = T::new();
    assert!(!t.config().is_house_sponsor(&Role::Sponsor.pubkey()));
    let changed = t.mark_sponsor(true);
    assert_eq!(
        (changed.change, changed.key, changed.list, changed.house),
        (
            ConfigChange::Allowed,
            Role::Sponsor.pubkey(),
            Some(AllowList::Sponsor),
            true
        ),
        "the event names the house sponsor"
    );
    let config = t.config();
    assert!(config.is_house_sponsor(&Role::Sponsor.pubkey()));
    assert_eq!(
        (config.sponsors.clone(), config.house_sponsors),
        (vec![Role::Sponsor.pubkey()], 1),
        "the sponsor keeps its place; its bit is set"
    );

    let terms = terms_with(0);
    let opened = expect_ok(
        t.open(&terms),
        "a house sponsor opens with no challenge window",
    );
    let opened = opened.event::<prize_escrow::EscrowOpened>();
    assert_eq!(opened.challenge_window, 0);
    assert_eq!(t.state().challenge_window, 0);
    t.commit_entries();

    t.at(FINAL_END);
    expect_ok(t.post(), "post_result");
    let posted = t.state();
    assert_eq!(
        (posted.status, posted.challenge_deadline),
        (EscrowStatus::Challengeable, FINAL_END),
        "challenge_deadline is the second the result landed"
    );

    // Nothing can challenge it: the window closed as it opened.
    let (hash, _) = t.w.commit_of(&Role::Watcher(0).pubkey(), &t.trees[1]);
    let ix = t.w.challenge_commit_ix(Role::Watcher(0).pubkey(), hash);
    expect_refused(
        t.send(ix, &[Role::Watcher(0)]),
        EscrowError::ChallengeWindowClosed,
        "a challenge at the second of the post",
    );
    // The guardian cannot hand it to the arbiter either: the unchallenged result binds.
    let ix = t.w.escalate_ix(Role::Guardian.pubkey());
    expect_refused(
        t.send(ix, &[Role::Guardian]),
        EscrowError::UnchallengedResultBinds,
        "escalate of the posted house result",
    );

    // settle and a co-signed claim, at the same clock reading.
    let settled = expect_ok(t.settle(), "settle at once").event::<Settled>();
    assert_eq!(
        (settled.outcome, settled.status, t.now()),
        (
            SettleOutcome::Undisputed,
            EscrowStatus::Claimable,
            FINAL_END
        )
    );
    assert_eq!(settled.claim_deadline, FINAL_END + terms.claim_window);
    let claimed =
        expect_ok(t.claim(Role::Winner(0), true), "a co-signed claim at once").event::<Claimed>();
    assert_eq!(
        (claimed.amount, claimed.cosigned, t.tokens(Role::Winner(0))),
        (PRIZES[0], true, PRIZES[0])
    );
    assert_eq!(t.now(), FINAL_END, "no clock moved");

    // The other winner, without the co-signature, still waits its hold window (unchanged).
    expect_ok(t.request(Role::Winner(1)), "request_claim");
    expect_refused(
        t.claim(Role::Winner(1), false),
        EscrowError::HoldWindowOpen,
        "an uncosigned claim inside the hold window",
    );
    t.at(FINAL_END + terms.hold_window);
    expect_ok(
        t.claim(Role::Winner(1), false),
        "the lapse path after the hold window",
    );
    assert_eq!(t.tokens(Role::Winner(1)), PRIZES[1]);
}

/// The waiver is any window from 0 to MAX_WINDOW, the Config's challenge floor included: a house
/// sponsor opens at 0 however high the admin set min_challenge_window, and anywhere up to
/// MAX_WINDOW; past it, or below 0, it is refused as before (InvalidWindow).
#[test]
fn a_house_sponsor_takes_any_challenge_window_from_zero_to_the_maximum() {
    for window in [-1, MAX_WINDOW + 1] {
        let mut t = T::new();
        t.mark_sponsor(true);
        expect_refused(
            t.open(&terms_with(window)),
            EscrowError::InvalidWindow,
            &format!("a house sponsor's challenge window of {window}"),
        );
    }
    for window in [0, 1, MIN_CHALLENGE_WINDOW - 1, MAX_WINDOW] {
        let mut t = T::new();
        t.mark_sponsor(true);
        t.set_floors(floors_with_challenge(MIN_CHALLENGE_WINDOW + DAY));
        expect_ok(
            t.open(&terms_with(window)),
            &format!(
                "a house sponsor's challenge window of {window} under a floor above the minimum"
            ),
        );
        assert_eq!(t.state().challenge_window, window);
    }
}

/// A sponsor listed but not marked keeps every floor: under the compiled minimum InvalidWindow,
/// under the Config's floor WindowBelowFloor, exactly as before the house path. A sponsor marked
/// and then unmarked is held again.
#[test]
fn a_sponsor_not_marked_keeps_the_challenge_floors() {
    let mut t = T::new();
    for window in [0, MIN_CHALLENGE_WINDOW - 1] {
        expect_refused(
            t.open(&terms_with(window)),
            EscrowError::InvalidWindow,
            &format!("a listed sponsor's challenge window of {window}"),
        );
    }
    t.set_floors(floors_with_challenge(MIN_CHALLENGE_WINDOW + HOUR));
    expect_refused(
        t.open(&terms_with(MIN_CHALLENGE_WINDOW)),
        EscrowError::WindowBelowFloor,
        "a listed sponsor's challenge window under the Config's floor",
    );

    // Marked, then unmarked: held again.
    let changed = t.mark_sponsor(true);
    assert!(changed.house);
    let changed = t.mark_sponsor(false);
    assert_eq!(
        (changed.change, changed.list, changed.house),
        (ConfigChange::Allowed, Some(AllowList::Sponsor), false)
    );
    let config = t.config();
    assert_eq!(
        (config.sponsors.clone(), config.house_sponsors),
        (vec![Role::Sponsor.pubkey()], 0),
        "unmarking keeps the sponsor listed"
    );
    expect_refused(
        t.open(&terms_with(0)),
        EscrowError::InvalidWindow,
        "an unmarked sponsor at 0",
    );
    expect_refused(
        t.open(&terms_with(MIN_CHALLENGE_WINDOW)),
        EscrowError::WindowBelowFloor,
        "an unmarked sponsor under the floor",
    );
    expect_ok(
        t.open(&terms_with(MIN_CHALLENGE_WINDOW + HOUR)),
        "an unmarked sponsor at the floor",
    );
}

/// The house path waives the challenge window alone: a house sponsor is still held to the
/// compiled minimums (InvalidWindow) and the Config's floors (WindowBelowFloor) of the attest, hold
/// and claim windows, and to every other bound (a claim window not over the hold window, the
/// hard deadline's sum, the allowlists).
#[test]
fn a_house_sponsor_keeps_every_other_bound() {
    let mut t = T::new();
    t.mark_sponsor(true);
    let base = terms_with(0);
    let with = |f: &dyn Fn(&mut EscrowTerms)| {
        let mut terms = base.clone();
        f(&mut terms);
        terms.hard_deadline = earliest_hard(&terms);
        terms
    };
    let compiled = [
        ("attest", with(&|t| t.attest_window = MIN_ATTEST_WINDOW - 1)),
        ("hold", with(&|t| t.hold_window = MIN_HOLD_WINDOW - 1)),
        ("claim", with(&|t| t.claim_window = MIN_CLAIM_WINDOW - 1)),
    ];
    for (what, terms) in compiled {
        expect_refused(
            t.open(&terms),
            EscrowError::InvalidWindow,
            &format!("a house sponsor's {what} window under the compiled minimum"),
        );
    }
    let mut hard_early = base.clone();
    hard_early.hard_deadline -= 1;
    expect_refused(
        t.open(&hard_early),
        EscrowError::HardDeadlineTooEarly,
        "a house sponsor's hard deadline one second early",
    );
    let mut claim_short = base.clone();
    claim_short.hold_window = claim_short.claim_window;
    claim_short.hard_deadline = earliest_hard(&claim_short);
    expect_refused(
        t.open(&claim_short),
        EscrowError::ClaimWindowTooShort,
        "a house sponsor's claim window not over its hold window",
    );

    // The Config's floors of the other windows, raised a day above the compiled minimums.
    t.set_floors(Floors {
        min_challenge_window: MIN_CHALLENGE_WINDOW,
        min_attest_window: MIN_ATTEST_WINDOW + DAY,
        min_hold_window: MIN_HOLD_WINDOW + DAY,
        min_claim_window: MIN_CLAIM_WINDOW + 2 * DAY,
        reveal_grace: MIN_REVEAL_GRACE,
    });
    let floored = [
        (
            "attest",
            with(&|t| {
                t.hold_window = MIN_HOLD_WINDOW + DAY;
                t.claim_window = MIN_CLAIM_WINDOW + 2 * DAY;
            }),
        ),
        (
            "hold",
            with(&|t| {
                t.attest_window = MIN_ATTEST_WINDOW + DAY;
                t.claim_window = MIN_CLAIM_WINDOW + 2 * DAY;
            }),
        ),
        (
            "claim",
            with(&|t| {
                t.attest_window = MIN_ATTEST_WINDOW + DAY;
                t.hold_window = MIN_HOLD_WINDOW + DAY;
            }),
        ),
    ];
    for (what, terms) in floored {
        expect_refused(
            t.open(&terms),
            EscrowError::WindowBelowFloor,
            &format!("a house sponsor's {what} window under the Config's floor"),
        );
    }
    let at_floors = with(&|t| {
        t.attest_window = MIN_ATTEST_WINDOW + DAY;
        t.hold_window = MIN_HOLD_WINDOW + DAY;
        t.claim_window = MIN_CLAIM_WINDOW + 2 * DAY;
    });
    expect_ok(
        t.open(&at_floors),
        "a house sponsor at every other floor, challenge 0",
    );

    // Taken off the sponsor list, a house sponsor is no sponsor at all.
    let mut t = T::new();
    t.mark_sponsor(true);
    expect_ok(
        t.set_allowed(AllowList::Sponsor, Role::Sponsor.pubkey(), false, false),
        "disallow the house sponsor",
    );
    assert_eq!(t.config().house_sponsors, 0);
    expect_refused(
        t.open(&terms_with(0)),
        EscrowError::InvalidWindow,
        "a removed house sponsor at 0",
    );
    expect_refused(
        t.open(&terms_with(MIN_CHALLENGE_WINDOW)),
        EscrowError::SponsorNotAllowed,
        "a removed house sponsor",
    );
    // Listed again, it comes back unmarked unless the admin marks it.
    expect_ok(
        t.set_allowed(AllowList::Sponsor, Role::Sponsor.pubkey(), true, false),
        "allow it again",
    );
    assert!(!t.config().is_house_sponsor(&Role::Sponsor.pubkey()));
}

/// A proposal never takes the house path: its sponsor marked as a house sponsor, submit_proposal
/// still refuses a challenge window under the compiled minimum (InvalidWindow) or the Config's
/// floor (WindowBelowFloor), and approve_proposal holds the terms to the floor of the day.
#[test]
fn a_proposal_never_takes_the_house_path() {
    let mut t = T::new();
    t.mark_sponsor(true);
    let policy = t.w.set_proposal_policy_ix(
        Role::Admin.pubkey(),
        Role::Curator.pubkey(),
        support::PENDING_CAP,
    );
    expect_ok(t.send(policy, &[Role::Admin]), "set_proposal_policy");
    let sponsor = Role::Sponsor.pubkey();
    let at = t.now();
    let (base, opens_at, review_deadline) = World::proposal_terms(at);
    let submit = |t: &mut T, window: i64| {
        let mut terms = base.clone();
        terms.challenge_window = window;
        terms.hard_deadline = earliest_hard(&terms);
        let ix = t.w.submit_proposal_ix(
            sponsor,
            Role::Curator.pubkey(),
            t.w.funding,
            USER_CID,
            &terms,
            opens_at,
            review_deadline,
        );
        t.send(ix, &[Role::Sponsor, Role::Curator])
    };
    for window in [0, MIN_CHALLENGE_WINDOW - 1] {
        expect_refused(
            submit(&mut t, window),
            EscrowError::InvalidWindow,
            &format!("a house sponsor's proposal with a challenge window of {window}"),
        );
    }
    t.set_floors(floors_with_challenge(MIN_CHALLENGE_WINDOW + HOUR));
    expect_refused(
        submit(&mut t, MIN_CHALLENGE_WINDOW),
        EscrowError::WindowBelowFloor,
        "a house sponsor's proposal under the Config's challenge floor",
    );

    // Submitted at the floor, then the floor raised: the approval refuses it as it would any
    // sponsor's.
    expect_ok(
        submit(&mut t, MIN_CHALLENGE_WINDOW + HOUR),
        "a house sponsor's proposal at the floor",
    );
    t.set_floors(floors_with_challenge(MIN_CHALLENGE_WINDOW + 2 * HOUR));
    t.at(review_deadline);
    let approve =
        t.w.approve_proposal_ix(Role::Curator.pubkey(), sponsor, USER_CID);
    expect_refused(
        t.send(approve, &[Role::Curator]),
        EscrowError::WindowBelowFloor,
        "approving a house sponsor's proposal under the raised floor",
    );
}

// ------------------------------------------------------------------------------ the marks

/// Marking, unmarking and removing sponsors on chain keeps every other sponsor's bit: each keeps
/// its mark as the list closes up behind a removed one. A mint or a regrader listed twice is still
/// AlreadyListed (only a sponsor takes a second set_allowed, as its mark).
#[test]
fn marks_follow_their_sponsors_through_removals() {
    let mut t = T::new();
    let keys: Vec<Pubkey> = (0..4)
        .map(|i| Role::Spare(0).pubkey_derived(&[i]))
        .collect();
    let houses = [true, false, true, true];
    for (key, house) in keys.iter().zip(houses) {
        let changed = expect_ok(
            t.set_allowed(AllowList::Sponsor, *key, true, house),
            "allow a sponsor",
        )
        .event::<ConfigChanged>();
        assert_eq!(changed.house, house);
    }
    t.mark_sponsor(true);
    // The list: the world's sponsor, then keys 0..4.
    let marked = |t: &T| -> Vec<bool> {
        let config = t.config();
        std::iter::once(Role::Sponsor.pubkey())
            .chain(keys.iter().copied())
            .map(|k| config.is_house_sponsor(&k))
            .collect()
    };
    assert_eq!(marked(&t), [true, true, false, true, true]);
    assert_eq!(t.config().house_sponsors, 0b11011);

    expect_ok(
        t.set_allowed(AllowList::Sponsor, keys[1], false, false),
        "remove the unmarked key 1",
    );
    let config = t.config();
    assert_eq!(
        config.sponsors,
        vec![Role::Sponsor.pubkey(), keys[0], keys[2], keys[3]]
    );
    assert_eq!(config.house_sponsors, 0b1111);
    assert!(!config.is_house_sponsor(&keys[1]));

    expect_ok(
        t.set_allowed(AllowList::Sponsor, keys[2], true, false),
        "unmark key 2",
    );
    expect_ok(
        t.set_allowed(AllowList::Sponsor, Role::Sponsor.pubkey(), false, false),
        "remove the first sponsor",
    );
    let config = t.config();
    assert_eq!(config.sponsors, vec![keys[0], keys[2], keys[3]]);
    assert_eq!(config.house_sponsors, 0b101);
    assert_eq!(
        [&keys[0], &keys[2], &keys[3]].map(|k| config.is_house_sponsor(k)),
        [true, false, true]
    );

    expect_refused(
        t.set_allowed(AllowList::Mint, t.w.mint, true, false),
        EscrowError::AlreadyListed,
        "a mint listed twice",
    );
    expect_refused(
        t.set_allowed(AllowList::Regrader, Role::Regrader(0).pubkey(), true, false),
        EscrowError::AlreadyListed,
        "a regrader listed twice",
    );
    expect_refused(
        t.set_allowed(AllowList::Sponsor, keys[1], false, false),
        EscrowError::NotListed,
        "removing a sponsor no longer listed",
    );
    expect_refused(
        t.set_allowed(AllowList::Sponsor, Pubkey::default(), true, true),
        EscrowError::InvalidConfig,
        "marking the default key",
    );
}

/// One edit of the sponsor list: set_allowed(Sponsor, key, true, house) or (key, false).
#[derive(Clone, Copy, Debug)]
enum Edit {
    Allow(u8, bool),
    Disallow(u8),
}

fn edits() -> impl Strategy<Value = Vec<Edit>> {
    // 40 keys over a 32-place list, so the list fills (ListFull) and keys come and go.
    let edit = prop_oneof![
        3 => (1u8..=40, any::<bool>()).prop_map(|(k, h)| Edit::Allow(k, h)),
        1 => (1u8..=40).prop_map(Edit::Disallow),
    ];
    prop::collection::vec(edit, 1..=160)
}

fn pk(byte: u8) -> Pubkey {
    Pubkey::new_from_array([byte; 32])
}

/// A Config with no sponsor, built as initialize_config builds one.
fn bare_config() -> Config {
    Config::new(
        prize_escrow::ConfigInit {
            admin: pk(201),
            guardian: pk(202),
            arbiter: pk(203),
            limits: prize_escrow::Limits {
                escrow_cap: 1,
                global_cap: 1,
                flow_capacity: 1,
                flow_period: 1,
                min_bond: 0,
                max_house_regraders: 0,
            },
            floors: floors_with_challenge(0),
            mints: vec![],
            sponsors: vec![],
            regraders: vec![],
        },
        255,
        0,
    )
    .expect("a valid Config")
}

proptest! {
    /// Over random sequences of set_allowed's sponsor edits (Config::allow_or_mark and disallow),
    /// against a list of (key, house) kept in order: every edit succeeds or fails as the list
    /// says (ListFull past MAX_SPONSORS new keys, NotListed for a key not listed), the sponsor list
    /// is the model's keys in order, every key's is_house_sponsor is its mark (false off the
    /// list), and no bit at or above the list's length is set.
    #[test]
    fn every_sponsor_keeps_its_mark_through_any_edits(edits in edits()) {
        let mut config = bare_config();
        let mut model: Vec<(Pubkey, bool)> = Vec::new();
        for edit in edits {
            match edit {
                Edit::Allow(k, house) => {
                    let key = pk(k);
                    let got = config.allow_or_mark(AllowList::Sponsor, key, house);
                    if let Some(entry) = model.iter_mut().find(|(m, _)| *m == key) {
                        prop_assert!(got.is_ok(), "re-marking {:?}", edit);
                        entry.1 = house;
                    } else if model.len() < MAX_SPONSORS {
                        prop_assert!(got.is_ok(), "adding {:?}", edit);
                        model.push((key, house));
                    } else {
                        prop_assert_eq!(code(got), u32::from(EscrowError::ListFull));
                    }
                }
                Edit::Disallow(k) => {
                    let key = pk(k);
                    let got = config.disallow(AllowList::Sponsor, key);
                    if let Some(i) = model.iter().position(|(m, _)| *m == key) {
                        prop_assert!(got.is_ok(), "removing {:?}", edit);
                        model.remove(i);
                    } else {
                        prop_assert_eq!(code(got), u32::from(EscrowError::NotListed));
                    }
                }
            }
            let listed: Vec<Pubkey> = model.iter().map(|(k, _)| *k).collect();
            prop_assert_eq!(&config.sponsors, &listed);
            for k in 1u8..=40 {
                let want = model.iter().any(|(m, h)| *m == pk(k) && *h);
                prop_assert_eq!(config.is_house_sponsor(&pk(k)), want, "key {} after {:?}", k, edit);
            }
            let above = u32::try_from(model.len()).unwrap();
            prop_assert_eq!(config.house_sponsors.checked_shr(above).unwrap_or(0), 0);
        }
    }

    /// Config::without_bit, bit by bit: the bits below the index stay, every bit above it moves
    /// down one place, the top bit is clear; an index past 31 changes nothing.
    #[test]
    fn without_bit_closes_up_the_bits(bits in any::<u32>(), index in 0usize..=40) {
        let got = Config::without_bit(bits, index);
        if index >= 32 {
            prop_assert_eq!(got, bits);
        } else {
            for j in 0..32 {
                let bit = |b: u32, i: usize| (b >> i) & 1;
                let want = if j < index { bit(bits, j) } else if j < 31 { bit(bits, j + 1) } else { 0 };
                prop_assert_eq!(bit(got, j), want, "bit {} of {:#034b} without {}", j, bits, index);
            }
        }
    }
}

fn code(result: anchor_lang::Result<()>) -> u32 {
    match result {
        Err(anchor_lang::error::Error::AnchorError(e)) => e.error_code_number,
        other => panic!("expected an AnchorError, got {other:?}"),
    }
}

// ------------------------------------------------------------------------------ the old layout

/// Config as it was before house_sponsors: the same fields to live_escrows, then 10 reserved
/// bytes. What mainnet's Config account holds today.
#[derive(AnchorSerialize)]
struct ConfigBefore {
    bump: u8,
    stop: StopState,
    max_house_regraders: u8,
    admin: Pubkey,
    pending_admin: Pubkey,
    guardian: Pubkey,
    arbiter: Pubkey,
    escrow_cap: u64,
    global_cap: u64,
    open_value: u64,
    flow_capacity: u64,
    flow_period: i64,
    flow_level: u64,
    flow_updated_at: i64,
    min_bond: u64,
    min_challenge_window: i64,
    min_attest_window: i64,
    min_hold_window: i64,
    min_claim_window: i64,
    reveal_grace: i64,
    stop_since: i64,
    stop_expires_at: i64,
    stopped_secs: i64,
    mints: Vec<Pubkey>,
    sponsors: Vec<Pubkey>,
    regraders: Vec<RegraderEntry>,
    revoked: Vec<Pubkey>,
    min_regraders: u8,
    curator: Pubkey,
    pending_value: u64,
    pending_cap: u64,
    retired: bool,
    live_escrows: u32,
    reserved: [u8; 10],
}

/// A Config account written in the layout before house_sponsors (its 10 reserved bytes zero),
/// from the world's own Config: decodes with no house sponsor, reads byte for byte as the new
/// layout with house_sponsors 0, and opens exactly as before: the release minimum challenge
/// window, never 0; the admin marks its sponsor as a house sponsor on it without a migration.
#[test]
fn a_config_from_before_the_field_has_no_house_sponsor() {
    let mut t = T::new();
    let key = Config::pda().0;
    let mut account = t.svm.get_account(&key).unwrap();
    let c = t.config();
    let before = ConfigBefore {
        bump: c.bump,
        stop: c.stop,
        max_house_regraders: c.max_house_regraders,
        admin: c.admin,
        pending_admin: c.pending_admin,
        guardian: c.guardian,
        arbiter: c.arbiter,
        escrow_cap: c.escrow_cap,
        global_cap: c.global_cap,
        open_value: c.open_value,
        flow_capacity: c.flow_capacity,
        flow_period: c.flow_period,
        flow_level: c.flow_level,
        flow_updated_at: c.flow_updated_at,
        min_bond: c.min_bond,
        min_challenge_window: c.min_challenge_window,
        min_attest_window: c.min_attest_window,
        min_hold_window: c.min_hold_window,
        min_claim_window: c.min_claim_window,
        reveal_grace: c.reveal_grace,
        stop_since: c.stop_since,
        stop_expires_at: c.stop_expires_at,
        stopped_secs: c.stopped_secs,
        mints: c.mints.clone(),
        sponsors: c.sponsors.clone(),
        regraders: c.regraders.clone(),
        revoked: c.revoked.clone(),
        min_regraders: c.min_regraders,
        curator: c.curator,
        pending_value: c.pending_value,
        pending_cap: c.pending_cap,
        retired: c.retired,
        live_escrows: c.live_escrows,
        reserved: [0; 10],
    };
    let mut data = Config::DISCRIMINATOR.to_vec();
    before.serialize(&mut data).unwrap();
    data.resize(Config::SPACE, 0);
    assert_eq!(
        data, account.data,
        "the old layout, reserved zero, is the new one's bytes with no house sponsor"
    );
    account.data = data;
    t.svm.set_account(key, account).unwrap();

    let decoded = Config::try_deserialize(&mut t.svm.get_account(&key).unwrap().data.as_slice())
        .expect("the old layout decodes");
    assert_eq!((decoded.house_sponsors, decoded.reserved), (0, [0; 6]));
    assert!(!decoded.is_house_sponsor(&Role::Sponsor.pubkey()));

    expect_refused(
        t.open(&terms_with(0)),
        EscrowError::InvalidWindow,
        "a challenge window of 0 on a Config from before the house path",
    );
    expect_refused(
        t.open(&terms_with(MIN_CHALLENGE_WINDOW - 1)),
        EscrowError::InvalidWindow,
        "a challenge window under the minimum on a Config from before the house path",
    );
    expect_ok(
        t.open(&terms_with(MIN_CHALLENGE_WINDOW)),
        "the release minimum on a Config from before the house path",
    );
    assert_eq!(t.state().challenge_window, MIN_CHALLENGE_WINDOW);

    // The admin marks the sponsor on the same account: no migration, no realloc.
    let mut t2 = T::new();
    let mut account = t2.svm.get_account(&key).unwrap();
    let mut data = Config::DISCRIMINATOR.to_vec();
    before.serialize(&mut data).unwrap();
    data.resize(Config::SPACE, 0);
    account.data = data;
    t2.svm.set_account(key, account).unwrap();
    t2.mark_sponsor(true);
    assert_eq!(t2.svm.get_account(&key).unwrap().data.len(), Config::SPACE);
    expect_ok(
        t2.open(&terms_with(0)),
        "a house sponsor marked on a Config from before the field",
    );
}
