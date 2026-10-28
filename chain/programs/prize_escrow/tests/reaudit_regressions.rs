//! Regressions for the findings of the #757 re-audit (.tmp/audit-program-2/AUDIT.md on e961baf's
//! program), one named test each, on the release build (`node scripts/chain/build.ts release`
//! first) with the release windows, time moved by rewriting LiteSVM's Clock:
//! - P2-2: the tests load the program from disk, held to PRIZE_ESCROW_SO_SHA256 when it is set,
//!   never bytes a test binary embedded at its last compile (tests/program_so).
//! - P3-1: escalate refuses a Challengeable escrow once its challenge window is over, as settle
//!   reads it: an unchallenged result binds at challenge_deadline (past the reveal grace while a
//!   commit is pending), as a recorded quorum binds once settle may apply it.
//! - P3-2: close_attestation returns a vote's rent to its regrader once the escrow is Closed.
//! - P3-3: the arbiter keeping the posted result over a recorded alternative clears `challenger`
//!   and the alt_* fields.
//! - P3-4: Config.min_regraders, 1 by default, which open_escrow holds every panel to and the admin
//!   raises with set_min_regraders, without an upgrade.
//! - P3-5: pay_bond keeps the escrow's own unbonded lamports, not the Rent sysvar's minimum of the
//!   day: after a rent increase the program never refuses a bond payout itself (#540's scenario,
//!   5,080 lamports per byte at open and 6,960 after), and a top-up of the escrow PDA by the
//!   shortfall, which the runtime asks for when the payout would leave the account below the new
//!   minimum, is never paid out.
//!
//! The world (keys, Config, escrow, trees) is tests/support/mod.rs.

mod mainnet;
mod program_so;
mod support;

use {
    anchor_lang::{prelude::Pubkey, AccountDeserialize, AccountSerialize},
    litesvm::LiteSVM,
    prize_escrow::{
        accounts as accts, instruction as ixs, ArbiterResolved, AttestSide, AttestationClosed,
        Config, ConfigChange, ConfigChanged, Escalated, EscrowError, EscrowStatus, EscrowTerms,
        SettleOutcome, Settled, BOND_FLOOR_RENTS, DEFAULT_MIN_REGRADERS, EVENT_AUTHORITY_AND_BUMP,
        MAX_REGRADERS, MIN_REVEAL_GRACE,
    },
    support::{
        expect_ok, expect_refused, instruction, Chain, Panel, Role, Sent, Tree, World,
        ATTEST_WINDOW, CHALLENGE_WINDOW, CLAIM_WINDOW, DAY, FINAL_END, HOUR, TOTAL,
    },
};

/// The honest result posted at FINAL_END: its challenge window ends here, its attest window
/// (once challenged) at ATTEST_DEADLINE, its claim window (settled at once) at CLAIM_DEADLINE.
const CHALLENGE_DEADLINE: i64 = FINAL_END + CHALLENGE_WINDOW;
const ATTEST_DEADLINE: i64 = CHALLENGE_DEADLINE + ATTEST_WINDOW;
const CLAIM_DEADLINE: i64 = CHALLENGE_DEADLINE + CLAIM_WINDOW;

/// Tree indices of World::trees.
const HONEST: usize = 0;
const STEAL: usize = 1;

/// Anchor's ConstraintSeeds and AccountNotInitialized.
const CONSTRAINT_SEEDS: u32 = 2006;
const ACCOUNT_NOT_INITIALIZED: u32 = 3012;

/// Mainnet's rent today (SIMD-0437), and the 6,960 lamports per byte the SIMD-0438 gate
/// (set_lamports_per_byte_to_6960, not active) would reset it to: #540's scenario.
const RENT_AT_OPEN: u64 = 5_080;
const RENT_RAISED: u64 = 6_960;

struct T {
    svm: LiteSVM,
    w: World,
    trees: Vec<Tree>,
}

impl T {
    fn new(panel: Panel, open: bool, rent_per_byte: Option<u64>) -> T {
        let mut svm = mainnet::svm();
        svm.add_program(prize_escrow::ID, program_so::bytes())
            .unwrap();
        if let Some(per_byte) = rent_per_byte {
            set_rent_per_byte(&mut svm, per_byte);
        }
        let w = World::create(&mut svm, panel, open);
        let trees = w.trees();
        T { svm, w, trees }
    }

    /// The Config alone, no escrow opened yet, on `panel`.
    fn unopened(panel: Panel) -> T {
        T::new(panel, false, None)
    }

    /// The honest result posted by the resolver at FINAL_END (Challengeable).
    fn posted(panel: Panel) -> T {
        let mut t = T::new(panel, true, None);
        t.at(FINAL_END);
        expect_ok(t.post(HONEST), "post_result");
        assert_eq!(t.state().challenge_deadline, CHALLENGE_DEADLINE);
        t
    }

    fn at(&mut self, time: i64) {
        self.svm.set_time(time);
    }

    fn state(&self) -> prize_escrow::Escrow {
        self.w.state(&self.svm).expect("the escrow")
    }

    fn send(
        &mut self,
        ix: anchor_lang::solana_program::instruction::Instruction,
        by: Role,
    ) -> Sent {
        self.w.send(&mut self.svm, ix, &[by.key()])
    }

    fn crank(&mut self, ix: anchor_lang::solana_program::instruction::Instruction) -> Sent {
        self.w.send(&mut self.svm, ix, &[])
    }

    fn post(&mut self, tree: usize) -> Sent {
        let ix = self
            .w
            .post_ix(Role::Resolver.pubkey(), &self.trees[tree], TOTAL);
        self.send(ix, Role::Resolver)
    }

    fn challenge(&mut self, by: Role, tree: usize) -> Sent {
        let tree = self.trees[tree].clone();
        self.w.challenge_with(&mut self.svm, by.key(), &tree)
    }

    /// `by` commits a challenge of tree `tree` and never reveals it.
    fn commit_only(&mut self, by: Role, tree: usize) -> Sent {
        let (hash, _) = self.w.commit_of(&by.pubkey(), &self.trees[tree]);
        let ix = self.w.challenge_commit_ix(by.pubkey(), hash);
        self.send(ix, by)
    }

    fn attest(&mut self, regrader: Role, commitment: [u8; 32]) -> Sent {
        let ix = self.w.attest_ix(&self.svm, regrader.pubkey(), commitment);
        self.send(ix, regrader)
    }

    fn escalate(&mut self, by: Role) -> Sent {
        let ix = self.w.escalate_ix(by.pubkey());
        self.send(ix, by)
    }

    fn settle(&mut self) -> Sent {
        let ix = self.w.settle_ix(&self.state());
        self.crank(ix)
    }

    fn refund(&mut self) -> Sent {
        let ix = self.w.refund_ix(&self.state());
        self.crank(ix)
    }

    /// The arbiter keeps the posted result.
    fn arbiter_posted(&mut self) -> Sent {
        let e = self.state();
        let ix = self
            .w
            .arbiter_ix(&e, Role::Arbiter.pubkey(), None, e.commitment);
        self.send(ix, Role::Arbiter)
    }

    fn lamports(&self, address: &Pubkey) -> u64 {
        self.svm.lamports(address)
    }

    fn escrow_lamports(&self) -> u64 {
        self.lamports(&self.w.escrow())
    }
}

/// Rewrites the Rent sysvar to `per_byte` lamports per byte (128 bytes of account overhead
/// included, as Rent::minimum_balance counts), keeping its exemption threshold as LiteSVM wrote it:
/// lamports_per_byte(_year) is the sysvar's first u64 and the threshold the f64 after it, in every
/// Rent layout.
fn set_rent_per_byte(svm: &mut LiteSVM, per_byte: u64) {
    let id = Pubkey::from_str_const("SysvarRent111111111111111111111111111111111");
    let mut account = svm.get_account(&id).expect("the Rent sysvar");
    let threshold = f64::from_le_bytes(account.data[8..16].try_into().unwrap());
    let per_byte_year = (per_byte as f64 / threshold) as u64;
    account.data[..8].copy_from_slice(&per_byte_year.to_le_bytes());
    svm.set_account(id, account).expect("the Rent sysvar");
    assert_eq!(
        svm.minimum_balance_for_rent_exemption(0),
        128 * per_byte,
        "rent at {per_byte} lamports per byte"
    );
}

// ------------------------------------------------------------------------------------ P2-2

/// P2-2. The tests run the bytes on disk: program_so::bytes() is what chain/target/deploy (or
/// PRIZE_ESCROW_SO) holds when the test runs, whatever a binary compiled earlier saw, and a pin
/// (PRIZE_ESCROW_SO_SHA256) refuses any other bytes, so a land gate that sets it can only pass on
/// the pair being landed.
#[test]
fn p2_2_the_tests_run_the_bytes_on_disk_held_to_their_pin() {
    let path = program_so::path();
    let loaded = program_so::bytes();
    let on_disk = std::fs::read(&path).expect("the release build on disk");
    assert_eq!(
        loaded,
        on_disk.as_slice(),
        "{} as it is now",
        path.display()
    );
    let sha = program_so::sha256_hex(loaded);
    if let Some(pin) = program_so::pinned_sha256() {
        assert_eq!(sha, pin, "the pinned bytes");
    }

    // The pin as the gate sets it: these bytes pass, any other sha256 (or no sha256) fails.
    assert_eq!(program_so::check(loaded, None), Ok(sha.clone()));
    assert_eq!(program_so::check(loaded, Some(&sha)), Ok(sha.clone()));
    assert_eq!(
        program_so::check(loaded, Some(&sha.to_ascii_uppercase())),
        Ok(sha.clone())
    );
    let other = "0".repeat(64);
    let refused = program_so::check(loaded, Some(&other)).expect_err("another pin");
    assert!(
        refused.contains(&sha) && refused.contains(&other),
        "{refused}"
    );
    assert!(
        program_so::check(loaded, Some("ccfce71a")).is_err(),
        "a short pin"
    );
    assert!(
        program_so::check(b"other bytes", Some(&sha)).is_err(),
        "other bytes under the pin"
    );
    // The program the tests run is an SBF ELF.
    assert_eq!(&loaded[..4], b"\x7fELF");
}

// ------------------------------------------------------------------------------------ P3-1

/// P3-1. An unchallenged result binds once its challenge window is over, as settle's
/// require_window_over reads it: escalate refuses a Challengeable escrow from challenge_deadline
/// (UnchallengedResultBinds, the admin's escalate too) and settle makes it Claimable; one second
/// earlier the guardian still escalates it. A commit pending at challenge_deadline may still open
/// a dispute, so escalate takes the escrow until the reveal grace ends; and a freeze holds the
/// escrow clock, so the window ends later in wall time.
#[test]
fn p3_1_escalate_refuses_an_unchallenged_result_once_its_window_is_over() {
    // Inside the window, to its last second, the guardian escalates a result nobody challenged.
    let mut t = T::posted(Panel::HouseMajority);
    t.at(CHALLENGE_DEADLINE - 1);
    let escalated = expect_ok(t.escalate(Role::Guardian), "escalate on the last second");
    assert_eq!(
        escalated.event::<Escalated>().from_status,
        EscrowStatus::Challengeable
    );
    assert_eq!(t.state().status, EscrowStatus::Frozen);

    // From challenge_deadline on the result binds: escalate is refused, settle makes it Claimable.
    let mut t = T::posted(Panel::HouseMajority);
    for time in [
        CHALLENGE_DEADLINE,
        CHALLENGE_DEADLINE + HOUR,
        ATTEST_DEADLINE + DAY,
    ] {
        t.at(time);
        expect_refused(
            t.escalate(Role::Guardian),
            EscrowError::UnchallengedResultBinds,
            &format!("the guardian's escalate at {time}"),
        );
        expect_refused(
            t.escalate(Role::Admin),
            EscrowError::UnchallengedResultBinds,
            &format!("the admin's escalate at {time}"),
        );
        assert_eq!(t.state().status, EscrowStatus::Challengeable);
    }
    let settled = expect_ok(t.settle(), "settle").event::<Settled>();
    assert_eq!(settled.outcome, SettleOutcome::Undisputed);
    assert_eq!(t.state().status, EscrowStatus::Claimable);

    // A commit on the window's last second may still be revealed in the grace: until the grace
    // ends the escrow may be escalated, from then on the result binds.
    let mut t = T::posted(Panel::HouseMajority);
    t.at(CHALLENGE_DEADLINE - 1);
    expect_ok(
        t.commit_only(Role::Attacker(2), STEAL),
        "a commit on the last second",
    );
    let reveal_deadline = CHALLENGE_DEADLINE + MIN_REVEAL_GRACE;
    assert_eq!(t.state().reveal_deadline().unwrap(), reveal_deadline);
    t.at(reveal_deadline);
    expect_refused(
        t.escalate(Role::Guardian),
        EscrowError::UnchallengedResultBinds,
        "escalate once the grace is over",
    );
    expect_ok(t.settle(), "settle once the grace is over");
    let mut t = T::posted(Panel::HouseMajority);
    t.at(CHALLENGE_DEADLINE - 1);
    expect_ok(
        t.commit_only(Role::Attacker(2), STEAL),
        "a commit on the last second",
    );
    t.at(reveal_deadline - 1);
    expect_refused(
        t.settle(),
        EscrowError::CommitsPendingReveal,
        "settle inside the grace",
    );
    expect_ok(
        t.escalate(Role::Guardian),
        "escalate inside the grace, while the commit may open a dispute",
    );

    // A freeze holds the escrow clock: at the wall-clock deadline the window is still open.
    let mut t = T::posted(Panel::HouseMajority);
    t.at(FINAL_END + HOUR);
    let freeze = t.w.set_freeze_ix(Role::Guardian.pubkey(), true);
    expect_ok(t.send(freeze, Role::Guardian), "freeze");
    t.at(FINAL_END + HOUR + DAY);
    let unfreeze = t.w.set_freeze_ix(Role::Admin.pubkey(), false);
    expect_ok(
        t.send(unfreeze, Role::Admin),
        "the admin unfreezes a day later",
    );
    t.at(CHALLENGE_DEADLINE + DAY - 1);
    expect_ok(
        t.escalate(Role::Guardian),
        "escalate on the escrow clock's last second of the window",
    );
}

// ------------------------------------------------------------------------------------ P3-2

/// P3-2. Every vote's rent comes back: once the escrow is Closed, anyone closes a regrader's
/// Attestation and its rent (which the regrader paid) goes to that regrader, whichever side it
/// voted. Not before (InvalidStatus while Claimable), not into another key (the PDA's seeds name
/// the regrader: ConstraintSeeds), and only once.
#[test]
fn p3_2_close_attestation_returns_a_votes_rent_once_the_escrow_is_closed() {
    let mut t = T::posted(Panel::HouseMajority);
    t.at(FINAL_END + HOUR);
    expect_ok(t.challenge(Role::Attacker(2), STEAL), "a junk challenge");
    let (posted, junk) = (t.state().commitment, t.trees[STEAL].commitment);
    let mut paid = Vec::new();
    for (seat, commitment) in [(0, posted), (1, posted), (2, junk)] {
        let regrader = Role::Regrader(seat);
        let before = t.lamports(&regrader.pubkey());
        expect_ok(
            t.attest(regrader, commitment),
            &format!("seat {seat} votes"),
        );
        paid.push(before - t.lamports(&regrader.pubkey()));
    }
    t.at(CHALLENGE_DEADLINE);
    let settled = expect_ok(t.settle(), "settle").event::<Settled>();
    assert_eq!(settled.outcome, SettleOutcome::ResultUpheld);

    // Claimable: the dispute is decided, but the escrow is not Closed.
    let seat0 = Role::Regrader(0).pubkey();
    let ix = t.w.close_attestation_ix(seat0);
    expect_refused(t.crank(ix), EscrowError::InvalidStatus, "while Claimable");

    t.at(CLAIM_DEADLINE + 1);
    expect_ok(t.refund(), "refund after the claim window");
    assert_eq!(t.state().status, EscrowStatus::Closed);
    let escrow_lamports = t.escrow_lamports();

    // Into another regrader's account: the attestation is not at that key's PDA.
    let seat1 = Role::Regrader(1).pubkey();
    let crossed = instruction(
        accts::CloseAttestation {
            escrow: t.w.escrow(),
            attestation: t.w.attestation(&seat0),
            regrader: seat1,
            event_authority: EVENT_AUTHORITY_AND_BUMP.0,
            program: prize_escrow::ID,
        },
        ixs::CloseAttestation {},
    );
    expect_refused(
        t.crank(crossed),
        CONSTRAINT_SEEDS,
        "seat 0's vote into seat 1",
    );

    for (seat, (commitment, side)) in [
        (posted, AttestSide::Result),
        (posted, AttestSide::Result),
        (junk, AttestSide::Alt),
    ]
    .into_iter()
    .enumerate()
    {
        let regrader = Role::Regrader(seat as u8).pubkey();
        let attestation = t.w.attestation(&regrader);
        let rent = t.lamports(&attestation);
        assert_eq!(rent, paid[seat], "seat {seat} paid exactly the rent");
        let before = t.lamports(&regrader);
        let ix = t.w.close_attestation_ix(regrader);
        let closed = expect_ok(t.crank(ix), &format!("close seat {seat}'s vote"))
            .event::<AttestationClosed>();
        assert_eq!(
            (closed.escrow, closed.attestation, closed.regrader),
            (t.w.escrow(), attestation, regrader)
        );
        assert_eq!((closed.commitment, closed.side), (commitment, side));
        assert_eq!(closed.rent_returned, rent);
        assert_eq!(
            t.lamports(&regrader) - before,
            rent,
            "seat {seat}'s rent back"
        );
        assert_eq!(t.lamports(&attestation), 0);
        assert!(t.w.voted(&t.svm, &regrader).is_none());
        let ix = t.w.close_attestation_ix(regrader);
        expect_refused(
            t.crank(ix),
            ACCOUNT_NOT_INITIALIZED,
            &format!("seat {seat}'s vote a second time"),
        );
    }
    assert_eq!(
        t.escrow_lamports(),
        escrow_lamports,
        "the escrow pays nothing"
    );
}

// ------------------------------------------------------------------------------------ P3-3

/// P3-3. A quorum's alternative the guardian escalated inside the attest window, which the
/// arbiter then turns down for the posted result, is no longer the escrow's winner: arbiter_resolve
/// clears `challenger` and the alt_* fields (state.rs: they name the challenger whose alternative
/// won), every bond goes to the resolver, and the Challenge PDA keeps its own record until
/// close_challenge returns its rent.
#[test]
fn p3_3_the_arbiter_keeping_the_posted_result_clears_a_recorded_alternative() {
    let mut t = T::posted(Panel::HouseMajority);
    t.at(FINAL_END + HOUR);
    expect_ok(t.challenge(Role::Attacker(2), STEAL), "a false challenge");
    let steal = t.trees[STEAL].commitment;
    expect_ok(t.attest(Role::Regrader(0), steal), "seat 0 backs it");
    expect_ok(t.attest(Role::Regrader(1), steal), "seat 1 backs it");
    let recorded = t.state();
    assert_eq!(
        (recorded.challenger, recorded.alt_commitment),
        (Role::Attacker(2).pubkey(), steal),
        "the quorum recorded the alternative"
    );
    t.at(ATTEST_DEADLINE - 1);
    expect_ok(
        t.escalate(Role::Guardian),
        "escalate inside the attest window",
    );
    let resolver_before = t.lamports(&Role::Resolver.pubkey());
    let (resolver_bond, challenger_bond) = (recorded.resolver_bond, recorded.challenger_bond);
    let resolved = expect_ok(t.arbiter_posted(), "the arbiter keeps the posted result")
        .event::<ArbiterResolved>();
    assert_eq!(
        (resolved.challenge, resolved.challenger),
        (Pubkey::default(), Pubkey::default())
    );
    let e = t.state();
    assert_eq!(e.status, EscrowStatus::Claimable);
    assert_eq!(e.commitment, t.trees[HONEST].commitment);
    assert_eq!(e.payout_root, t.trees[HONEST].root);
    assert_eq!(e.challenger, Pubkey::default(), "no challenger won");
    assert_eq!(
        (
            e.alt_result_sha256,
            e.alt_payout_root,
            e.alt_commitment,
            e.alt_total
        ),
        ([0; 32], [0; 32], [0; 32], 0),
        "no alternative won"
    );
    assert!(!e.has_challenger());
    assert_eq!(
        t.lamports(&Role::Resolver.pubkey()) - resolver_before,
        resolver_bond + challenger_bond,
        "every bond to the resolver"
    );
    let challenge =
        t.w.challenge(&t.svm, &steal)
            .expect("the challenge's own record");
    assert_eq!(
        (challenge.challenger, challenge.votes),
        (Role::Attacker(2).pubkey(), 2)
    );
    let ix = t.w.close_challenge_ix(&challenge);
    expect_ok(t.crank(ix), "close_challenge");
}

// ------------------------------------------------------------------------------------ P3-4

/// The default terms with the first `n` panel seats, k the bare majority.
fn panel_of(n: u8) -> EscrowTerms {
    let mut terms = World::default_terms();
    terms.regraders = (0..n).map(|s| Role::Regrader(s).pubkey()).collect();
    terms.k = n / 2 + 1;
    terms
}

/// P3-4. The panel floor is the admin's, on the Config: 1 by default (owner decision #541, so a
/// one-regrader panel opens), set_min_regraders raises it (1 to MAX_REGRADERS; InvalidConfig
/// otherwise; the admin's alone) without an upgrade, and open_escrow refuses a panel below it
/// (PanelTooSmall). A Config written before the field reads 0 there, which refuses no panel.
#[test]
fn p3_4_the_admin_raises_the_panel_floor_without_an_upgrade() {
    // The default floor: a one-regrader panel opens.
    let mut t = T::unopened(Panel::HouseMajority);
    assert_eq!(t.w.config(&t.svm).min_regraders, DEFAULT_MIN_REGRADERS);
    assert_eq!(DEFAULT_MIN_REGRADERS, 1);
    let ix = t.w.open_ix(&panel_of(1));
    expect_ok(
        t.send(ix, Role::Sponsor),
        "a one-regrader panel under the default",
    );

    // Raising it: the admin's alone, in bounds.
    let mut t = T::unopened(Panel::HouseMajority);
    let ix = t.w.set_min_regraders_ix(Role::Guardian.pubkey(), 3);
    expect_refused(
        t.send(ix, Role::Guardian),
        EscrowError::UnauthorizedAdmin,
        "the guardian",
    );
    for floor in [0, MAX_REGRADERS + 1] {
        let ix = t.w.set_min_regraders_ix(Role::Admin.pubkey(), floor);
        expect_refused(
            t.send(ix, Role::Admin),
            EscrowError::InvalidConfig,
            &format!("a floor of {floor}"),
        );
    }
    let ix = t.w.set_min_regraders_ix(Role::Admin.pubkey(), 3);
    let changed = expect_ok(t.send(ix, Role::Admin), "a floor of 3").event::<ConfigChanged>();
    assert_eq!(
        (changed.change, changed.by, changed.min_regraders),
        (ConfigChange::MinRegradersSet, Role::Admin.pubkey(), 3)
    );
    assert_eq!(t.w.config(&t.svm).min_regraders, 3);
    for n in [1, 2] {
        let ix = t.w.open_ix(&panel_of(n));
        expect_refused(
            t.send(ix, Role::Sponsor),
            EscrowError::PanelTooSmall,
            &format!("a panel of {n} under a floor of 3"),
        );
    }
    let ix = t.w.open_ix(&panel_of(3));
    expect_ok(t.send(ix, Role::Sponsor), "a panel of 3 under a floor of 3");

    // A Config from before the field (its byte zero, as `reserved` held it) refuses no panel.
    let mut t = T::unopened(Panel::HouseMajority);
    let config_key = Config::pda().0;
    let mut account = t.svm.get_account(&config_key).unwrap();
    let mut config = Config::try_deserialize(&mut account.data.as_slice()).unwrap();
    config.min_regraders = 0;
    let mut data = Vec::with_capacity(Config::SPACE);
    config.try_serialize(&mut data).unwrap();
    data.resize(Config::SPACE, 0);
    account.data = data;
    t.svm.set_account(config_key, account).unwrap();
    assert_eq!(t.w.config(&t.svm).min_regraders, 0);
    let ix = t.w.open_ix(&panel_of(1));
    expect_ok(
        t.send(ix, Role::Sponsor),
        "a one-regrader panel under a Config from before the floor",
    );
}

// ------------------------------------------------------------------------------------ P3-5

/// Settles, and when the runtime refuses the payout for the escrow's rent (the bond would leave
/// it below the cluster's rent-exempt minimum of now: InsufficientFundsForRent, which SIMD-0392
/// asks whenever the balance drops below it), tops the escrow PDA up by exactly the shortfall and
/// settles again. The program itself never refuses: no MathOverflow. Answers the top-up.
fn settle_topping_up_any_shortfall(t: &mut T) -> (Sent, u64) {
    let first = t.settle();
    if first.ok {
        return (first, 0);
    }
    assert!(
        first.code.is_none() && first.error.contains("InsufficientFundsForRent"),
        "only the runtime may refuse a bond payout for rent, never the program (got {:?} {}):\n{}",
        first.code,
        first.error,
        first.logs
    );
    let e = t.state();
    let bonds = e.resolver_bond + e.challenger_bond + e.commit_bond;
    let minimum = t
        .svm
        .minimum_balance_for_rent_exemption(prize_escrow::Escrow::SPACE);
    let shortfall = minimum - (t.escrow_lamports() - bonds);
    let ix = t.w.donate_lamports_ix(shortfall);
    expect_ok(t.send(ix, Role::Attacker(0)), "a top-up of the shortfall");
    (expect_ok(t.settle(), "settle after the top-up"), shortfall)
}

/// P3-5, #540's scenario. Opened and posted under 5,080 lamports per byte, the rent then raised to
/// 6,960 (the SIMD-0438 reset): the escrow holds its rent as funded at open plus the resolver's
/// bond, and paying the bond back would leave it below the new minimum. main's pay_bond, reading
/// the Rent sysvar of the day, refused that itself (6025 MathOverflow); now the escrow's own
/// floor (its lamports less its tracked bonds) never refuses it, the runtime asks for the
/// shortfall, and a top-up of exactly that settles it: the resolver gets its whole bond back and
/// the top-up stays in the escrow.
#[test]
fn p3_5_a_rent_increase_never_strands_a_bond_in_the_program() {
    let mut t = T::new(Panel::HouseMajority, true, Some(RENT_AT_OPEN));
    let escrow_rent = t.escrow_lamports();
    assert_eq!(
        escrow_rent,
        (128 + prize_escrow::Escrow::SPACE as u64) * RENT_AT_OPEN
    );
    t.at(FINAL_END);
    expect_ok(t.post(HONEST), "post_result");
    let bond = t.state().resolver_bond;
    assert_eq!(t.escrow_lamports(), escrow_rent + bond);
    set_rent_per_byte(&mut t.svm, RENT_RAISED);
    let minimum = t
        .svm
        .minimum_balance_for_rent_exemption(prize_escrow::Escrow::SPACE);
    assert!(
        escrow_rent < minimum && minimum <= escrow_rent + bond,
        "the bond payout would leave the escrow below the new minimum"
    );

    t.at(CHALLENGE_DEADLINE);
    let resolver_before = t.lamports(&Role::Resolver.pubkey());
    let (sent, top_up) = settle_topping_up_any_shortfall(&mut t);
    assert_eq!(
        top_up,
        minimum - escrow_rent,
        "the runtime asks for the shortfall"
    );
    let settled = sent.event::<Settled>();
    assert_eq!(
        (settled.outcome, settled.resolver_paid),
        (SettleOutcome::Undisputed, bond)
    );
    assert_eq!(t.lamports(&Role::Resolver.pubkey()) - resolver_before, bond);
    assert_eq!(
        t.escrow_lamports(),
        escrow_rent + top_up,
        "the top-up stays"
    );
    assert_eq!(t.state().resolver_bond, 0);
}

/// P3-5, the bond at its floor. Opened under 5,080 lamports per byte with the smallest bond
/// open_escrow takes there (bond_floor: 2 rent-exempt minimums of an empty account, the admin's
/// min_bond lowered to 0), the rent raised to 6,960: the escrow's rent and bond together are now
/// below the new minimum. main's pay_bond refused the payout (MathOverflow); now the program pays
/// the whole bond, and only the runtime's rent rule decides whether the escrow PDA needs the
/// shortfall first (SIMD-0392, active on mainnet, asks for it; the earlier rule lets an account
/// already below the minimum shrink).
#[test]
fn p3_5_a_bond_at_its_floor_is_paid_after_a_rent_increase() {
    let mut t = T::new(Panel::HouseMajority, false, Some(RENT_AT_OPEN));
    let mut limits = World::limits(Panel::HouseMajority);
    limits.min_bond = 0;
    let ix = t.w.set_limits_ix(Role::Admin.pubkey(), limits);
    expect_ok(t.send(ix, Role::Admin), "min_bond 0");
    let mut terms = World::default_terms();
    // state::bond_floor under the rent of now: BOND_FLOOR_RENTS minimums of an empty account.
    terms.bond_lamports = BOND_FLOOR_RENTS * t.svm.minimum_balance_for_rent_exemption(0);
    assert_eq!(terms.bond_lamports, 2 * 128 * RENT_AT_OPEN);
    let ix = t.w.open_ix(&terms);
    expect_ok(t.send(ix, Role::Sponsor), "open with the floor bond");
    let ix = t.w.commit_entries_ix(Role::Resolver.pubkey());
    expect_ok(t.send(ix, Role::Resolver), "commit_entries");
    let escrow_rent = t.escrow_lamports();
    t.at(FINAL_END);
    expect_ok(t.post(HONEST), "post_result");
    let bond = t.state().resolver_bond;
    assert_eq!(bond, terms.bond_lamports);
    set_rent_per_byte(&mut t.svm, RENT_RAISED);
    let minimum = t
        .svm
        .minimum_balance_for_rent_exemption(prize_escrow::Escrow::SPACE);
    assert!(
        escrow_rent + bond < minimum,
        "rent and bond under the new minimum"
    );

    t.at(CHALLENGE_DEADLINE);
    let resolver_before = t.lamports(&Role::Resolver.pubkey());
    let (sent, top_up) = settle_topping_up_any_shortfall(&mut t);
    assert!(top_up == 0 || top_up == minimum - escrow_rent, "{top_up}");
    assert_eq!(sent.event::<Settled>().resolver_paid, bond);
    assert_eq!(t.lamports(&Role::Resolver.pubkey()) - resolver_before, bond);
    assert_eq!(t.escrow_lamports(), escrow_rent + top_up);
}
