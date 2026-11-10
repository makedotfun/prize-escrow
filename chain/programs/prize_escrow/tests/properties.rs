//! Properties of the program's pure functions, under proptest: merkle proofs (verify_proof,
//! hash_pair, compute_leaf_hash, over trees the off-chain builder's shape), the result and commit
//! commitments, Escrow::bonds_to_winner, check_deposit (the program's own, compiled here from
//! src/instructions/open_escrow.rs, where it is pub(crate)), the stoppable escrow clock
//! (config::escrow_now with Config's stop and Escrow's freeze, against a timeline simulated hour by
//! hour), the claim flow bucket (Config::refill, take_flow, set_limits), the escalation that never
//! shortens a lapse, EscrowTerms::validate and Config::check_terms_policy (F6's open policy, and a
//! proposal's, which waives the sponsor allowlist alone) against reference predicates written from
//! their doc comments, Config::check_proposal_terms (the bounds a proposal's terms are held to),
//! and the caps' counters (Config::deposit, release, reserve_pending, approve_pending,
//! release_pending): open_value + pending_value is always the open deposits.
//!
//! PROPTEST_CASES raises the case count (default 256 per property).

mod support;

// The source open_escrow.rs reaches the program's modules and its ID through `crate::`.
use prize_escrow::{config, constants, error, events, state, EVENT_AUTHORITY_AND_BUMP, ID};

/// The program's open_escrow.rs, compiled into this test for its pub(crate) check_deposit.
#[allow(dead_code, unused_imports, reason = "only check_deposit is exercised")]
#[path = "../src/instructions/open_escrow.rs"]
mod open_escrow_src;

use {
    anchor_lang::prelude::Pubkey,
    prize_escrow::{
        commit_hash,
        merkle::{compute_leaf_hash, hash_pair, verify_proof},
        result_commitment, ArbiterChoice, Config, ConfigInit, Escrow, EscrowError, EscrowStatus,
        EscrowTerms, Floors, Limits, RegraderEntry, StopState, ARBITER_SLACK, MAX_PROPOSAL_BOND,
        MAX_REGRADERS, MAX_REVEAL_GRACE, MAX_WINDOW, MIN_ATTEST_WINDOW, MIN_CHALLENGE_WINDOW,
        MIN_CLAIM_WINDOW, MIN_HOLD_WINDOW, MIN_RESOLVE_WINDOW, MIN_REVEAL_GRACE,
        RESULT_COMMITMENT_DOMAIN, STOP_DURATION,
    },
    proptest::prelude::*,
    support::merkle_tree,
};

const HOUR: i64 = 3_600;

fn key() -> impl Strategy<Value = Pubkey> {
    any::<[u8; 32]>().prop_map(Pubkey::new_from_array)
}

/// An escrow with every field zero (Open, no compliance, no bonds).
fn blank_escrow() -> Escrow {
    Escrow {
        bump: 0,
        decimals: 6,
        status: EscrowStatus::Open,
        k: 0,
        n: 0,
        competition_id: [0; 16],
        sponsor: Pubkey::default(),
        resolver: Pubkey::default(),
        compliance: Pubkey::default(),
        arbiter: Pubkey::default(),
        refund_to: Pubkey::default(),
        mint: Pubkey::default(),
        challenger: Pubkey::default(),
        rules_sha256: [0; 32],
        entries_root: [0; 32],
        payout_root: [0; 32],
        result_sha256: [0; 32],
        kit_sha256: [0; 32],
        commitment: [0; 32],
        alt_result_sha256: [0; 32],
        alt_payout_root: [0; 32],
        alt_commitment: [0; 32],
        entries_count: 0,
        challenge_count: 0,
        total: 0,
        total_claimed: 0,
        alt_total: 0,
        bond_lamports: 0,
        resolver_bond: 0,
        challenger_bond: 0,
        entries_deadline: 0,
        final_end: 0,
        resolve_deadline: 0,
        challenge_window: 0,
        attest_window: 0,
        hold_window: 0,
        claim_window: 0,
        challenge_deadline: 0,
        attest_deadline: 0,
        claim_deadline: 0,
        hard_deadline: 0,
        votes_result: 0,
        votes_alt: 0,
        regraders: [Pubkey::default(); 5],
        deposited: 0,
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

fn limits(capacity: u64, period: i64) -> Limits {
    Limits {
        escrow_cap: u64::MAX,
        global_cap: u64::MAX,
        flow_capacity: capacity,
        flow_period: period,
        min_bond: 0,
        max_house_regraders: MAX_REGRADERS,
    }
}

fn config_at(now: i64, limits: Limits) -> Config {
    Config::new(
        ConfigInit {
            admin: Pubkey::new_from_array([1; 32]),
            guardian: Pubkey::new_from_array([2; 32]),
            arbiter: Pubkey::new_from_array([3; 32]),
            limits,
            floors: Floors {
                min_challenge_window: 0,
                min_attest_window: 0,
                min_hold_window: 0,
                min_claim_window: 0,
                reveal_grace: MIN_REVEAL_GRACE,
            },
            mints: vec![],
            sponsors: vec![],
            regraders: vec![],
        },
        255,
        now,
    )
    .expect("a valid Config")
}

fn code(err: anchor_lang::error::Error) -> u32 {
    match err {
        anchor_lang::error::Error::AnchorError(e) => e.error_code_number,
        anchor_lang::error::Error::ProgramError(e) => panic!("a program error: {e:?}"),
    }
}

fn is(result: anchor_lang::Result<()>, want: EscrowError) -> bool {
    result.is_err_and(|e| code(e) == u32::from(want))
}

// ----------------------------------------------------------------------------------- merkle

fn leaves() -> impl Strategy<Value = (Pubkey, Vec<(Pubkey, u64)>)> {
    (key(), prop::collection::vec((key(), 1..=u64::MAX), 1..=64))
}

/// A tree's leaf hashes, its root and each leaf's proof.
type Built = (Vec<[u8; 32]>, [u8; 32], Vec<Vec<[u8; 32]>>);

fn build(escrow: &Pubkey, leaves: &[(Pubkey, u64)]) -> Built {
    let hashes: Vec<[u8; 32]> = leaves
        .iter()
        .map(|(c, a)| compute_leaf_hash(escrow, c, *a))
        .collect();
    let (root, proofs) = merkle_tree(&hashes);
    (hashes, root, proofs)
}

proptest! {
    /// Every leaf of a tree the off-chain builder's shape proves into its root, with a proof of at
    /// most ceil(log2 n) siblings.
    #[test]
    fn every_leaf_proves_into_its_root((escrow, leaves) in leaves()) {
        let (hashes, root, proofs) = build(&escrow, &leaves);
        let depth = usize::BITS - (leaves.len() - 1).leading_zeros();
        for (leaf, proof) in hashes.iter().zip(&proofs) {
            prop_assert!(verify_proof(proof, &root, leaf));
            prop_assert!(proof.len() <= depth as usize);
        }
    }

    /// A leaf's proof proves no other claimant, amount or escrow, and no other leaf of the tree.
    #[test]
    fn a_proof_proves_nothing_but_its_own_leaf(
        (escrow, leaves) in leaves(),
        pick in any::<prop::sample::Index>(),
        other in key(),
        delta in 1..=u64::MAX,
    ) {
        let (hashes, root, proofs) = build(&escrow, &leaves);
        let i = pick.index(leaves.len());
        let (claimant, amount) = leaves[i];
        let proof = &proofs[i];
        prop_assume!(other != claimant && other != escrow);
        prop_assert!(!verify_proof(proof, &root, &compute_leaf_hash(&escrow, &other, amount)));
        prop_assert!(!verify_proof(proof, &root, &compute_leaf_hash(&escrow, &claimant, amount.wrapping_add(delta))));
        prop_assert!(!verify_proof(proof, &root, &compute_leaf_hash(&other, &claimant, amount)));
        for (j, leaf) in hashes.iter().enumerate() {
            if leaf != &hashes[i] {
                prop_assert!(!verify_proof(proof, &root, leaf), "leaf {} with leaf {}'s proof", j, i);
            }
        }
    }

    /// Flipping any one bit of a proof's siblings or of the root breaks it.
    #[test]
    fn a_flipped_bit_breaks_a_proof(
        (escrow, leaves) in leaves(),
        pick in any::<prop::sample::Index>(),
        bit in any::<prop::sample::Index>(),
    ) {
        let (hashes, root, proofs) = build(&escrow, &leaves);
        let i = pick.index(leaves.len());
        let mut proof = proofs[i].clone();
        let bits = 256 * (proof.len() + 1);
        let b = bit.index(bits);
        let mut root2 = root;
        if b < 256 {
            root2[b / 8] ^= 1 << (b % 8);
        } else {
            let (s, b) = ((b - 256) / 256, (b - 256) % 256);
            proof[s][b / 8] ^= 1 << (b % 8);
        }
        prop_assert!(!verify_proof(&proof, &root2, &hashes[i]));
    }

    /// Pairs hash in sorted order, so a pair's hash is its children's in either order, and an empty
    /// proof proves exactly the root.
    #[test]
    fn hash_pair_is_order_free_and_an_empty_proof_proves_the_root(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        prop_assert_eq!(hash_pair(&a, &b), hash_pair(&b, &a));
        prop_assert!(verify_proof(&[], &a, &a));
        prop_assert_eq!(verify_proof(&[], &a, &b), a == b);
        prop_assert!(verify_proof(&[b], &hash_pair(&a, &b), &a));
    }

    /// A leaf binds its escrow, its claimant and its amount: changing any one changes it.
    #[test]
    fn a_leaf_binds_escrow_claimant_and_amount(
        e in key(), c in key(), a in any::<u64>(), e2 in key(), c2 in key(), a2 in any::<u64>(),
    ) {
        let leaf = compute_leaf_hash(&e, &c, a);
        prop_assert_eq!(compute_leaf_hash(&e2, &c, a) == leaf, e2 == e);
        prop_assert_eq!(compute_leaf_hash(&e, &c2, a) == leaf, c2 == c);
        prop_assert_eq!(compute_leaf_hash(&e, &c, a2) == leaf, a2 == a);
    }
}

// ----------------------------------------------------------------------------------- commitments

proptest! {
    /// The result commitment is sha256 over the domain, the document hash, the payout root and the
    /// total's 8 little-endian bytes, laid end to end, and moves with each of them.
    #[test]
    fn the_result_commitment_is_the_domain_separated_hash_of_all_three(
        doc in any::<[u8; 32]>(), root in any::<[u8; 32]>(), total in any::<u64>(),
        doc2 in any::<[u8; 32]>(), root2 in any::<[u8; 32]>(), total2 in any::<u64>(),
    ) {
        let mut bytes = RESULT_COMMITMENT_DOMAIN.to_vec();
        bytes.extend_from_slice(&doc);
        bytes.extend_from_slice(&root);
        bytes.extend_from_slice(&total.to_le_bytes());
        let c = result_commitment(&doc, &root, total);
        prop_assert_eq!(c, solana_sha256_hasher::hashv(&[&bytes]).to_bytes());
        prop_assert_eq!(result_commitment(&doc2, &root, total) == c, doc2 == doc);
        prop_assert_eq!(result_commitment(&doc, &root2, total) == c, root2 == root);
        prop_assert_eq!(result_commitment(&doc, &root, total2) == c, total2 == total);
    }

    /// A challenge's commit binds its alternative, its challenger and its salt.
    #[test]
    fn a_commit_binds_the_alternative_the_challenger_and_the_salt(
        alt in any::<[u8; 32]>(), who in key(), salt in any::<[u8; 32]>(),
        alt2 in any::<[u8; 32]>(), who2 in key(), salt2 in any::<[u8; 32]>(),
    ) {
        let h = commit_hash(&alt, &who, &salt);
        prop_assert_eq!(commit_hash(&alt2, &who, &salt) == h, alt2 == alt);
        prop_assert_eq!(commit_hash(&alt, &who2, &salt) == h, who2 == who);
        prop_assert_eq!(commit_hash(&alt, &who, &salt2) == h, salt2 == salt);
    }
}

// ----------------------------------------------------------------------------------- bonds

proptest! {
    /// The side that wins takes every bond held, the loser nothing; a sum past u64 is MathOverflow
    /// for either side, never a wrapped payment.
    #[test]
    fn the_winner_takes_every_bond_or_the_sum_overflows(resolver in any::<u64>(), challengers in any::<u64>()) {
        let mut e = blank_escrow();
        e.resolver_bond = resolver;
        e.challenger_bond = challengers;
        match resolver.checked_add(challengers) {
            Some(all) => {
                prop_assert_eq!(e.bonds_to_winner(ArbiterChoice::Posted).unwrap(), (all, 0));
                prop_assert_eq!(e.bonds_to_winner(ArbiterChoice::Alternative).unwrap(), (0, all));
            }
            None => {
                prop_assert!(e.bonds_to_winner(ArbiterChoice::Posted).is_err_and(|x| code(x) == u32::from(EscrowError::MathOverflow)));
                prop_assert!(e.bonds_to_winner(ArbiterChoice::Alternative).is_err_and(|x| code(x) == u32::from(EscrowError::MathOverflow)));
            }
        }
    }

    /// The bond sums the program can hold (BOND_FLOOR_RENTS rents and up, a few dozen of them)
    /// never overflow, whichever side wins.
    #[test]
    fn realistic_bond_sums_pay_out_whole(bond in 1u64..=1_000_000 * 1_000_000_000, challenges in 0u64..=64) {
        let mut e = blank_escrow();
        e.resolver_bond = bond;
        e.challenger_bond = bond * challenges;
        let (to_resolver, to_challenger) = e.bonds_to_winner(ArbiterChoice::Alternative).unwrap();
        prop_assert_eq!(to_resolver + to_challenger, bond * (challenges + 1));
    }
}

// ----------------------------------------------------------------------------------- check_deposit

fn grown(before: u64, after: u64) -> Option<u64> {
    after.checked_sub(before)
}

proptest! {
    /// check_deposit passes exactly when the vault grew by the amount: Underfunded when it grew by
    /// less (or shrank), Overfunded when by more.
    #[test]
    fn check_deposit_accepts_exactly_the_amount(before in any::<u64>(), after in any::<u64>(), amount in any::<u64>()) {
        let result = open_escrow_src::check_deposit(before, after, amount);
        match grown(before, after) {
            Some(g) if g == amount => prop_assert!(result.is_ok()),
            Some(g) if g > amount => prop_assert!(is(result, EscrowError::Overfunded)),
            _ => prop_assert!(is(result, EscrowError::Underfunded)),
        }
    }

    /// Around the exact growth: one token short, exact, one over.
    #[test]
    fn check_deposit_is_exact_at_the_edges(before in 0u64..u64::MAX / 2, amount in 1u64..u64::MAX / 2) {
        let after = before + amount;
        prop_assert!(open_escrow_src::check_deposit(before, after, amount).is_ok());
        prop_assert!(is(open_escrow_src::check_deposit(before, after - 1, amount), EscrowError::Underfunded));
        prop_assert!(is(open_escrow_src::check_deposit(before, after + 1, amount), EscrowError::Overfunded));
        prop_assert!(is(open_escrow_src::check_deposit(after, before, amount), EscrowError::Underfunded));
    }
}

// ----------------------------------------------------------------------------------- the clock

/// What the breakers do to the clock, as their handlers do it (breakers.rs): each is skipped when
/// its handler would refuse it.
#[derive(Clone, Copy, Debug)]
enum Breaker {
    /// The guardian raises the stop (only an escalation).
    Guardian(StopState),
    /// The admin sets any level.
    Admin(StopState),
    /// The admin extends the stop in force by whole hours.
    ExtendStop(i64),
    Freeze,
    Unfreeze,
    /// The admin extends the freeze in force by whole hours.
    ExtendFreeze(i64),
}

fn level() -> impl Strategy<Value = StopState> {
    prop_oneof![
        Just(StopState::Normal),
        Just(StopState::IntakeStop),
        Just(StopState::PayoutStop)
    ]
}

fn breaker() -> impl Strategy<Value = Breaker> {
    prop_oneof![
        level().prop_map(Breaker::Guardian),
        level().prop_map(Breaker::Admin),
        (1i64..=200).prop_map(|h| Breaker::ExtendStop(h * HOUR)),
        Just(Breaker::Freeze),
        Just(Breaker::Unfreeze),
        (1i64..=200).prop_map(|h| Breaker::ExtendFreeze(h * HOUR)),
    ]
}

/// The timeline the clock must follow, kept independently of config.rs's accounting: the stop
/// level and its lapse in wall time, the freeze's lapse on the global clock, and the three clocks
/// (global, escrow), advanced an hour at a time. Every event and lapse falls on an hour, so within
/// an hour nothing changes and the simulation is exact.
#[derive(Clone, Debug)]
struct Timeline {
    wall: i64,
    stop: StopState,
    stop_until: i64,
    /// The freeze in force: [since, until) on the global clock.
    freeze: Option<(i64, i64)>,
    global: i64,
    escrow: i64,
}

impl Timeline {
    fn payout_stopped(&self) -> bool {
        self.stop == StopState::PayoutStop && self.wall < self.stop_until
    }

    fn level(&self) -> StopState {
        if self.wall < self.stop_until {
            self.stop
        } else {
            StopState::Normal
        }
    }

    fn frozen(&self) -> bool {
        self.freeze
            .is_some_and(|(since, until)| since <= self.global && self.global < until)
    }

    /// One hour of wall time.
    fn hour(&mut self) {
        if !self.payout_stopped() {
            if !self.frozen() {
                self.escrow += HOUR;
            }
            self.global += HOUR;
        }
        self.wall += HOUR;
    }

    fn apply(&mut self, b: Breaker) {
        let set = |t: &mut Timeline, level: StopState| {
            let in_force = t.level() != StopState::Normal;
            let escalation = level > t.level();
            let lapse = t.stop_until;
            t.stop = level;
            t.stop_until = if level == StopState::Normal {
                t.wall
            } else if escalation && in_force {
                (t.wall + STOP_DURATION).max(lapse)
            } else {
                t.wall + STOP_DURATION
            };
        };
        match b {
            Breaker::Guardian(level) if level > self.level() => set(self, level),
            Breaker::Admin(level) => set(self, level),
            Breaker::ExtendStop(extra) if self.level() != StopState::Normal => {
                self.stop_until += extra
            }
            Breaker::Freeze if !self.frozen() => {
                self.freeze = Some((self.global, self.global + STOP_DURATION))
            }
            Breaker::Unfreeze if self.frozen() => {
                self.freeze = Some((self.freeze.unwrap().0, self.global))
            }
            Breaker::ExtendFreeze(extra) if self.frozen() => {
                let (since, until) = self.freeze.unwrap();
                self.freeze = Some((since, until + extra));
            }
            _ => {}
        }
    }
}

/// The program's side: Config's stop and the escrow's freeze, moved by the same methods the
/// handlers call, with the handlers' own guards.
fn apply(config: &mut Config, escrow: &mut Escrow, now: i64, b: Breaker) {
    let global = config.global_now(now);
    match b {
        Breaker::Guardian(level) => {
            let from = config.stop_level(now);
            if level > from {
                config.set_stop(level, now, true);
            }
        }
        Breaker::Admin(level) => {
            let from = config.stop_level(now);
            config.set_stop(level, now, level > from);
        }
        Breaker::ExtendStop(extra) => {
            if config.stop_level(now) != StopState::Normal {
                config.stop_expires_at += extra;
            }
        }
        Breaker::Freeze => {
            if !escrow.is_frozen(global) {
                escrow.start_freeze(global, STOP_DURATION).unwrap();
            }
        }
        Breaker::Unfreeze => {
            if escrow.is_frozen(global) {
                escrow.end_freeze(global);
            }
        }
        Breaker::ExtendFreeze(extra) => {
            if escrow.is_frozen(global) {
                escrow.freeze_until += extra;
            }
        }
    }
}

proptest! {
    /// escrow_now is wall time less every second a PayoutStop (since the escrow opened) or the
    /// escrow's own freeze held it, counted once where they overlap, with the stops' and the
    /// freeze's lapses: it matches the hour-by-hour timeline at every hour and inside each, never
    /// runs backwards and never runs faster than wall time.
    #[test]
    fn the_escrow_clock_is_wall_time_less_every_stopped_second_counted_once(
        prior in 0i64..=1_000,
        events in prop::collection::vec((0usize..=400, breaker()), 0..=24),
        inside in 1i64..HOUR,
    ) {
        let open = 1_800_000_000 - 1_800_000_000 % HOUR;
        let mut config = config_at(open, limits(1, 1));
        // Stops before the escrow opened are not its own.
        config.stopped_secs = prior * HOUR;
        let mut escrow = blank_escrow();
        escrow.stop_base = config.global_stopped(open);
        let mut timeline = Timeline {
            wall: open,
            stop: StopState::Normal,
            stop_until: open,
            freeze: None,
            global: open - prior * HOUR,
            escrow: open,
        };
        let mut last = (open, prize_escrow::escrow_now(&escrow, &config, open));
        prop_assert_eq!(last.1, open);
        for (hours, b) in events {
            for _ in 0..hours {
                let now = timeline.wall;
                let running = timeline.escrow;
                // Inside the hour, the clock is linear: it runs all of it or none of it.
                let mut probe = timeline.clone();
                probe.hour();
                let rate = (probe.escrow - running) / HOUR;
                prop_assert_eq!(prize_escrow::escrow_now(&escrow, &config, now + inside), running + rate * inside);
                timeline.hour();
                let t = timeline.wall;
                let clock = prize_escrow::escrow_now(&escrow, &config, t);
                prop_assert_eq!(clock, timeline.escrow, "at wall {} (hour {})", t, (t - open) / HOUR);
                prop_assert_eq!(config.global_now(t), timeline.global);
                prop_assert!(clock >= last.1 && clock - last.1 <= t - last.0);
                last = (t, clock);
            }
            let now = timeline.wall;
            apply(&mut config, &mut escrow, now, b);
            timeline.apply(b);
            prop_assert_eq!(config.stop_level(now), timeline.level());
            prop_assert_eq!(escrow.is_frozen(config.global_now(now)), timeline.frozen());
            // A breaker changes no clock at the instant it lands.
            prop_assert_eq!(prize_escrow::escrow_now(&escrow, &config, now), last.1);
        }
    }

    /// An escalation never brings the lapse of the stop in force closer (#535's finding 2).
    #[test]
    fn an_escalation_never_shortens_the_stop_in_force(
        extended in 0i64..=MAX_WINDOW, since in 0i64..=1_000_000, later in 0i64..=10 * STOP_DURATION,
    ) {
        let t0 = 1_800_000_000;
        let mut config = config_at(t0, limits(1, 1));
        config.set_stop(StopState::IntakeStop, t0, false);
        config.stop_expires_at += extended;
        let now = t0 + since.min(STOP_DURATION + extended - 1);
        let lapse = config.stop_expires_at;
        prop_assume!(config.stop_level(now) == StopState::IntakeStop);
        config.set_stop(StopState::PayoutStop, now, true);
        prop_assert!(config.stop_expires_at >= lapse);
        prop_assert!(config.stop_expires_at >= now + STOP_DURATION);
        prop_assert_eq!(config.stop_level(now + later), if now + later < config.stop_expires_at { StopState::PayoutStop } else { StopState::Normal });
    }
}

// ----------------------------------------------------------------------------------- the bucket

#[derive(Clone, Copy, Debug)]
enum Flow {
    /// A take of this many percent of the first capacity.
    Take(u16),
    Limits(u64, i64),
}

proptest! {
    /// The bucket starts full, never holds more than its capacity, pays a take exactly when it holds
    /// it (refilled to now at capacity per period, floored), and over any run pays out at most its
    /// capacity plus capacity per period of the time elapsed.
    #[test]
    fn the_bucket_pays_at_most_its_capacity_and_its_rate(
        capacity in 1u64..=1_000_000_000_000_000,
        period in prop_oneof![1i64..=3_600, 3_600i64..=7 * 86_400, 1i64..=MAX_WINDOW],
        ops in prop::collection::vec((prop_oneof![Just(0i64), 0i64..=3_600, 0i64..=10 * 86_400], prop_oneof![
            8 => (0u16..=200).prop_map(Flow::Take),
            1 => (1u64..=1_000_000_000_000_000, prop_oneof![1i64..=86_400, 1i64..=MAX_WINDOW]).prop_map(|(c, p)| Flow::Limits(c, p)),
        ]), 1..=48),
    ) {
        let t0 = 1_800_000_000;
        let mut config = config_at(t0, limits(capacity, period));
        prop_assert_eq!(config.flow_level, capacity);
        let mut now = t0;
        let mut level = capacity as u128;
        let (mut cap, mut per) = (capacity as u128, period as u128);
        let mut taken = 0u128;
        // The most the bucket may pay from t0: its starting level plus each capacity's rate over
        // the time it was in force.
        let mut allowance = capacity as u128;
        for (dt, op) in ops {
            allowance += cap * dt as u128 / per;
            now += dt;
            level = (level + cap * dt as u128 / per).min(cap);
            match op {
                Flow::Take(percent) => {
                    let want = (u128::from(capacity) * u128::from(percent) / 100) as u64;
                    let result = config.take_flow(want, now);
                    if u128::from(want) <= level {
                        prop_assert!(result.is_ok());
                        level -= u128::from(want);
                        taken += u128::from(want);
                    } else {
                        prop_assert!(is(result, EscrowError::FlowLimitExceeded));
                    }
                }
                Flow::Limits(c, p) => {
                    config.set_limits(&limits(c, p), now).unwrap();
                    level = level.min(c as u128);
                    cap = c as u128;
                    per = p as u128;
                }
            }
            prop_assert_eq!(u128::from(config.flow_level), level);
            prop_assert!(config.flow_level <= config.flow_capacity);
            prop_assert!(taken <= allowance);
        }
    }

    /// A refill never adds for time that has not passed: a clock behind flow_updated_at (a wall
    /// clock read earlier than the last one, as Solana's stake-weighted timestamps allow) adds
    /// nothing and never moves flow_updated_at back, so a refill at the original time then credits
    /// nothing for the seconds already counted, and the credit up to any later time is what a
    /// single refill over the same span gives. It never fills past capacity, whatever the gap.
    #[test]
    fn a_refill_never_overfills_or_runs_backwards(
        capacity in 1u64..=u64::MAX, period in 1i64..=MAX_WINDOW, start in any::<u64>(), back in 1i64..=86_400, gap in 0i64..=i64::MAX / 4,
    ) {
        let t0 = 1_800_000_000;
        let mut config = config_at(t0, limits(capacity, period));
        config.flow_level = start % (capacity.saturating_add(1)).max(1);
        let before = config.flow_level;
        config.refill(t0 - back).unwrap();
        prop_assert_eq!(config.flow_level, before);
        config.refill(t0).unwrap();
        prop_assert_eq!(
            config.flow_level, before,
            "a refill back at t0 credited the seconds already counted"
        );
        prop_assert_eq!(
            config.flow_updated_at, t0,
            "a refill at an earlier time moved flow_updated_at back"
        );
        config.refill(t0 + gap).unwrap();
        prop_assert!(config.flow_level <= capacity);
        prop_assert!(config.flow_level >= before);
        let mut once = config_at(t0, limits(capacity, period));
        once.flow_level = before;
        once.refill(t0 + gap).unwrap();
        prop_assert_eq!(
            config.flow_level, once.flow_level,
            "the credit from t0 depends on the earlier clock read"
        );
    }
}

// ----------------------------------------------------------------------------------- open terms

fn pk(b: u8) -> Pubkey {
    if b == 0 {
        Pubkey::default()
    } else {
        Pubkey::new_from_array([b; 32])
    }
}

const SOME_BOND: u64 = 1_000_000_000;

prop_compose! {
    /// Terms validate accepts at `now` under `min_bond`: a strict-majority panel of keys 1 to 8,
    /// each window between its minimum and a few times it, the deadlines in order and the hard
    /// deadline at or past the earliest.
    fn valid_terms()(
        now in 1_700_000_000i64..=1_900_000_000,
        total in 1u64..=u64::MAX,
        bond_over in 0u64..=SOME_BOND,
        min_bond in 0u64..=200_000_000,
        panel in prop::sample::subsequence((1u8..=8).collect::<Vec<_>>(), 1..=usize::from(MAX_REGRADERS)).prop_shuffle(),
        k_pick in any::<prop::sample::Index>(),
        windows in (
            MIN_CHALLENGE_WINDOW..=4 * MIN_CHALLENGE_WINDOW,
            MIN_ATTEST_WINDOW..=4 * MIN_ATTEST_WINDOW,
            MIN_HOLD_WINDOW..=4 * MIN_HOLD_WINDOW,
            MIN_CLAIM_WINDOW..=8 * MIN_CLAIM_WINDOW,
        ),
        compliance in any::<bool>(),
        gaps in (1i64..=30 * 86_400, 0i64..=30 * 86_400, 1i64..=30 * 86_400, 0i64..=30 * 86_400),
    ) -> (EscrowTerms, i64, u64) {
        let n = panel.len();
        let k = (n / 2 + 1 + k_pick.index(n - n / 2)) as u8;
        let (challenge, attest, hold, mut claim) = windows;
        if compliance && claim <= hold {
            claim = hold + 1;
        }
        let entries = now + gaps.0;
        let final_end = entries + gaps.1;
        let resolve = final_end + gaps.2;
        let terms = EscrowTerms {
            total,
            rules_sha256: [1; 32],
            resolver: pk(30),
            compliance: if compliance { pk(40) } else { Pubkey::default() },
            arbiter: pk(3),
            refund_to: pk(20),
            regraders: panel.into_iter().map(pk).collect(),
            k,
            bond_lamports: min_bond.max(1) + bond_over,
            entries_deadline: entries,
            final_end,
            resolve_deadline: resolve,
            challenge_window: challenge,
            attest_window: attest,
            hold_window: hold,
            claim_window: claim,
            hard_deadline: resolve + challenge + attest + hold + claim + ARBITER_SLACK + gaps.3,
        };
        (terms, now, min_bond)
    }
}

/// One bound a mutation breaks (or tries to: the result is compared with the reference anyway).
#[derive(Clone, Copy, Debug)]
enum Break {
    Total,
    Bond,
    BondBelowMin,
    NoPanel,
    BigPanel,
    Duplicate,
    DefaultKey,
    KZero,
    KOver,
    KMinority,
    Window(u8, i64),
    ClaimNotOverHold,
    EntriesPast,
    FinalBeforeEntries,
    ResolveNotAfterFinal,
    HardEarly,
    Overflow,
}

fn breaks() -> impl Strategy<Value = Break> {
    let bad = prop_oneof![
        Just(0i64),
        Just(-1),
        Just(MAX_WINDOW + 1),
        Just(i64::MAX),
        Just(i64::MIN),
        Just(MIN_ATTEST_WINDOW - 1),
        Just(MIN_CHALLENGE_WINDOW - 1),
        Just(MIN_CLAIM_WINDOW - 1),
        Just(MAX_WINDOW),
    ];
    prop_oneof![
        Just(Break::Total),
        Just(Break::Bond),
        Just(Break::BondBelowMin),
        Just(Break::NoPanel),
        Just(Break::BigPanel),
        Just(Break::Duplicate),
        Just(Break::DefaultKey),
        Just(Break::KZero),
        Just(Break::KOver),
        Just(Break::KMinority),
        (0u8..4, bad).prop_map(|(w, v)| Break::Window(w, v)),
        Just(Break::ClaimNotOverHold),
        Just(Break::EntriesPast),
        Just(Break::FinalBeforeEntries),
        Just(Break::ResolveNotAfterFinal),
        Just(Break::HardEarly),
        Just(Break::Overflow),
    ]
}

/// `t` with `b` applied; the min_bond to validate it under.
fn broken(mut t: EscrowTerms, now: i64, mut min_bond: u64, b: Break) -> (EscrowTerms, i64, u64) {
    let earliest = |t: &EscrowTerms| {
        t.resolve_deadline
            + t.challenge_window
            + t.attest_window
            + t.hold_window
            + t.claim_window
            + ARBITER_SLACK
    };
    match b {
        Break::Total => t.total = 0,
        Break::Bond => t.bond_lamports = 0,
        Break::BondBelowMin => min_bond = t.bond_lamports + 1,
        Break::NoPanel => t.regraders.clear(),
        Break::BigPanel => {
            for b in 1u8..=8 {
                if t.regraders.len() < usize::from(MAX_REGRADERS) + 1
                    && !t.regraders.contains(&pk(b))
                {
                    t.regraders.push(pk(b));
                }
            }
        }
        Break::Duplicate => {
            let first = t.regraders[0];
            t.regraders.push(first);
        }
        Break::DefaultKey => t.regraders[0] = Pubkey::default(),
        Break::KZero => t.k = 0,
        Break::KOver => t.k = t.regraders.len() as u8 + 1,
        Break::KMinority => t.k = (t.regraders.len() / 2) as u8,
        Break::Window(w, v) => match w {
            0 => t.challenge_window = v,
            1 => t.attest_window = v,
            2 => t.hold_window = v,
            _ => t.claim_window = v,
        },
        Break::ClaimNotOverHold => {
            t.compliance = pk(40);
            t.hold_window = t.claim_window;
            t.hard_deadline = t.hard_deadline.max(earliest(&t));
        }
        Break::EntriesPast => t.entries_deadline = now,
        Break::FinalBeforeEntries => t.final_end = t.entries_deadline - 1,
        Break::ResolveNotAfterFinal => t.resolve_deadline = t.final_end,
        Break::HardEarly => t.hard_deadline = earliest(&t) - 1,
        Break::Overflow => {
            t.resolve_deadline = i64::MAX - 10;
            t.hard_deadline = i64::MAX;
        }
    }
    (t, now, min_bond)
}

/// Fully random terms, for the corners neither of the above reaches.
fn random_terms() -> impl Strategy<Value = (EscrowTerms, i64, u64)> {
    let instant = || {
        prop_oneof![
            3 => 1_800_000_000i64..=1_900_000_000,
            1 => any::<i64>(),
            1 => Just(i64::MAX),
            1 => Just(i64::MIN),
        ]
    };
    let window = || {
        prop_oneof![
            Just(MIN_CHALLENGE_WINDOW),
            Just(MIN_CLAIM_WINDOW),
            Just(MAX_WINDOW),
            0i64..=10 * MIN_CLAIM_WINDOW,
            any::<i64>(),
        ]
    };
    (
        any::<u64>(),
        any::<u64>(),
        prop::collection::vec(0u8..=8, 0..=7),
        0u8..=8,
        any::<bool>(),
        (window(), window(), window(), window()),
        (instant(), instant(), instant(), instant(), instant()),
        0u64..=200_000_000,
    )
        .prop_map(|(total, bond, panel, k, compliance, w, d, min_bond)| {
            let terms = EscrowTerms {
                total,
                rules_sha256: [1; 32],
                resolver: pk(30),
                compliance: if compliance {
                    pk(40)
                } else {
                    Pubkey::default()
                },
                arbiter: pk(3),
                refund_to: pk(20),
                regraders: panel.into_iter().map(pk).collect(),
                k,
                bond_lamports: bond,
                entries_deadline: d.0,
                final_end: d.1,
                resolve_deadline: d.2,
                challenge_window: w.0,
                attest_window: w.1,
                hold_window: w.2,
                claim_window: w.3,
                hard_deadline: d.3,
            };
            (terms, d.4, min_bond)
        })
}

fn any_terms() -> impl Strategy<Value = (EscrowTerms, i64, u64)> {
    prop_oneof![
        2 => valid_terms(),
        4 => (valid_terms(), breaks()).prop_map(|((t, now, min_bond), b)| broken(t, now, min_bond, b)),
        1 => random_terms(),
    ]
}

/// EscrowTerms::validate's bounds, from its doc comment; with `house_sponsor`,
/// validate_for_sponsor's: the challenge window from 0 instead of MIN_CHALLENGE_WINDOW, nothing
/// else waived.
fn valid(t: &EscrowTerms, now: i64, min_bond: u64, house_sponsor: bool) -> bool {
    let n = t.regraders.len();
    let distinct = t
        .regraders
        .iter()
        .enumerate()
        .all(|(i, r)| *r != Pubkey::default() && !t.regraders[..i].contains(r));
    let min_challenge = if house_sponsor {
        0
    } else {
        MIN_CHALLENGE_WINDOW
    };
    let windows = [
        (t.challenge_window, min_challenge),
        (t.attest_window, MIN_ATTEST_WINDOW),
        (t.hold_window, MIN_HOLD_WINDOW),
        (t.claim_window, MIN_CLAIM_WINDOW),
    ]
    .iter()
    .all(|(w, min)| *min <= *w && *w <= MAX_WINDOW);
    let earliest_hard = i128::from(t.resolve_deadline)
        + i128::from(t.challenge_window)
        + i128::from(t.attest_window)
        + i128::from(t.hold_window)
        + i128::from(t.claim_window)
        + i128::from(ARBITER_SLACK);
    t.total > 0
        && t.bond_lamports > 0
        && t.bond_lamports >= min_bond
        && (1..=usize::from(MAX_REGRADERS)).contains(&n)
        && t.k >= 1
        && usize::from(t.k) <= n
        && 2 * usize::from(t.k) > n
        && distinct
        && windows
        && (t.compliance == Pubkey::default() || t.claim_window > t.hold_window)
        && now < t.entries_deadline
        && t.entries_deadline <= t.final_end
        && t.final_end < t.resolve_deadline
        && earliest_hard <= i128::from(i64::MAX)
        && i128::from(t.hard_deadline) >= earliest_hard
}

proptest! {
    /// validate accepts exactly the documented bounds and never panics (overflow included); a
    /// quorum it accepts is a strict majority, so no two sides can both reach k. A house sponsor's
    /// (validate_for_sponsor) accepts exactly the same bounds but the challenge window's minimum,
    /// which is 0, and accepts everything validate accepts.
    #[test]
    fn terms_validate_accepts_exactly_the_documented_bounds((t, now, min_bond) in any_terms()) {
        let ok = t.validate(now, min_bond).is_ok();
        prop_assert_eq!(ok, valid(&t, now, min_bond, false), "{:?}", t);
        prop_assert_eq!(t.validate_for_sponsor(now, min_bond, false).is_ok(), ok);
        let house = t.validate_for_sponsor(now, min_bond, true);
        prop_assert_eq!(house.is_ok(), valid(&t, now, min_bond, true), "house {:?}", t);
        prop_assert!(!ok || house.is_ok(), "the house path refused what validate takes");
        // Where both refuse, they refuse alike unless the challenge window is the one bound apart.
        if let (Err(plain), Err(house)) = (t.validate(now, min_bond), house) {
            prop_assert!(
                code(plain) == code(house) || t.challenge_window < MIN_CHALLENGE_WINDOW,
                "{:?}", t
            );
        }
        if ok {
            prop_assert!(2 * u16::from(t.k) > t.regraders.len() as u16);
        }
    }
}

// ----------------------------------------------------------------------------------- open policy

prop_compose! {
    /// A Config with mints from keys 1 to 3, sponsors 10 to 13 (some of them house sponsors), a
    /// registry of keys 1 to 9 (some the house's), a minimum bond, floors and a few revoked keys.
    fn policy()(
        mints in prop::collection::btree_set(1u8..=3, 1..=3),
        sponsors in prop::collection::btree_set(10u8..=13, 1..=4),
        house_sponsors in any::<u32>(),
        registry in prop::collection::btree_map(1u8..=9, any::<bool>(), 3..=9),
        revoked in prop::collection::btree_set(prop_oneof![1u8..=9, 10u8..=13, Just(30u8), Just(40u8)], 0..=3),
        min_bond in 0u64..=200_000_000,
        floors in (0i64..=2 * MIN_CHALLENGE_WINDOW, 0i64..=2 * MIN_ATTEST_WINDOW, 0i64..=2 * MIN_HOLD_WINDOW, 0i64..=2 * MIN_CLAIM_WINDOW),
        max_house in 0u8..=MAX_REGRADERS,
    ) -> Config {
        let mut config = config_at(1_800_000_000, Limits { min_bond, max_house_regraders: max_house, ..limits(1, 1) });
        config.mints = mints.into_iter().map(pk).collect();
        config.sponsors = sponsors.into_iter().map(pk).collect();
        // One bit per listed sponsor, none above the list (set_allowed's invariant).
        config.house_sponsors = house_sponsors & ((1u32 << config.sponsors.len()) - 1);
        config.regraders = registry.into_iter().map(|(b, house)| RegraderEntry { key: pk(b), house }).collect();
        config.revoked = revoked.into_iter().map(pk).collect();
        config.set_floors(&Floors {
            min_challenge_window: floors.0,
            min_attest_window: floors.1,
            min_hold_window: floors.2,
            min_claim_window: floors.3,
            reveal_grace: MAX_REVEAL_GRACE,
        }).unwrap();
        config
    }
}

prop_compose! {
    /// A Config and terms its open policy accepts where it can (the mint and a sponsor allowed and
    /// not revoked, the Config's arbiter, unrevoked resolver and compliance keys other than the
    /// escrow's address, the bond and the windows at the Config's minimums, a registered panel
    /// within the house allowance), then, most of the time, one rule broken.
    fn policy_case()(
        config in policy(),
        (t, _, _) in valid_terms(),
        pick in any::<prop::sample::Index>(),
        rule in prop::option::weighted(0.6, 0u8..=15),
    ) -> (Config, Pubkey, Pubkey, Pubkey, EscrowTerms) {
        // The address of the escrow being opened (a PDA in the program; any key here).
        let escrow = pk(60);
        let free = |k: &Pubkey| !config.revoked.contains(k);
        let mint = config.mints[pick.index(config.mints.len())];
        let sponsor = config.sponsors.iter().copied().find(&free).unwrap_or(pk(14));
        let mut t = t;
        t.refund_to = sponsor;
        t.arbiter = config.arbiter;
        t.resolver = [pk(30), pk(31)].into_iter().find(&free).unwrap();
        t.compliance = [pk(40), pk(41)].into_iter().find(&free).unwrap();
        t.bond_lamports = t.bond_lamports.max(config.min_bond);
        t.challenge_window = t.challenge_window.max(config.min_challenge_window);
        t.attest_window = t.attest_window.max(config.min_attest_window);
        t.hold_window = t.hold_window.max(config.min_hold_window);
        t.claim_window = t.claim_window.max(config.min_claim_window).max(t.hold_window + 1);
        let mut house = 0;
        let panel: Vec<Pubkey> = config
            .regraders
            .iter()
            .filter(|e| free(&e.key))
            .filter(|e| {
                let fits = !e.house || house < config.max_house_regraders;
                house += u8::from(e.house && fits);
                fits
            })
            .map(|e| e.key)
            .take(t.regraders.len())
            .collect();
        if !panel.is_empty() {
            t.regraders = panel;
        }
        let revoked = config.revoked.first().copied();
        let house_key = config.regraders.iter().find(|e| e.house).map(|e| e.key);
        match rule {
            None => {}
            Some(0) => return (config, sponsor, pk(5), escrow, t),
            Some(1) => {
                t.refund_to = pk(15);
                return (config, pk(15), mint, escrow, t);
            }
            Some(2) => t.refund_to = pk(20),
            Some(3) => t.arbiter = pk(4),
            Some(4) => t.compliance = Pubkey::default(),
            Some(5) => t.bond_lamports = config.min_bond.saturating_sub(1),
            Some(6) => t.challenge_window = config.min_challenge_window - 1,
            Some(7) => t.regraders[0] = pk(50),
            Some(8) => {
                if let Some(h) = house_key {
                    t.regraders = vec![h; usize::from(config.max_house_regraders) + 1];
                }
            }
            Some(9) => t.regraders[0] = t.resolver,
            Some(10) => t.regraders[0] = t.compliance,
            Some(11) => t.resolver = revoked.unwrap_or(t.resolver),
            Some(12) => t.regraders[0] = revoked.unwrap_or(t.regraders[0]),
            Some(13) => t.resolver = escrow,
            Some(14) => t.compliance = escrow,
            _ => t.compliance = revoked.unwrap_or(t.compliance),
        }
        (config, sponsor, mint, escrow, t)
    }
}

/// Whether `sponsor` holds a set bit of house_sponsors at its place on the sponsor list.
fn marked_house(config: &Config, sponsor: &Pubkey) -> bool {
    config
        .sponsors
        .iter()
        .position(|s| s == sponsor)
        .is_some_and(|i| (config.house_sponsors >> i) & 1 == 1)
}

/// Config::check_terms_policy's rules, from its doc comment (validate's are the program's other
/// half): the sponsor allowlist only when `sponsor_allowlisted` (open_escrow), never for a
/// proposal; the challenge window's floor waived for open_escrow's house sponsor alone.
fn allowed(
    config: &Config,
    sponsor: &Pubkey,
    mint: &Pubkey,
    escrow: &Pubkey,
    t: &EscrowTerms,
    sponsor_allowlisted: bool,
) -> bool {
    let house = t
        .regraders
        .iter()
        .filter(|r| config.regraders.iter().any(|e| e.key == **r && e.house))
        .count();
    let challenge_floor = if sponsor_allowlisted && marked_house(config, sponsor) {
        0
    } else {
        config.min_challenge_window
    };
    let floors = t.challenge_window >= challenge_floor
        && t.attest_window >= config.min_attest_window
        && t.hold_window >= config.min_hold_window
        && t.claim_window >= config.min_claim_window;
    config.mints.contains(mint)
        && (!sponsor_allowlisted || config.sponsors.contains(sponsor))
        && t.refund_to == *sponsor
        && t.arbiter == config.arbiter
        && t.compliance != Pubkey::default()
        && t.resolver != *escrow
        && t.compliance != *escrow
        && t.bond_lamports >= config.min_bond
        && floors
        && t.regraders
            .iter()
            .all(|r| config.regraders.iter().any(|e| e.key == *r))
        && house <= usize::from(config.max_house_regraders)
        && !t.regraders.contains(&t.resolver)
        && !t.regraders.contains(&t.compliance)
        && [sponsor, &t.resolver, &t.compliance]
            .into_iter()
            .chain(t.regraders.iter())
            .all(|k| !config.revoked.contains(k))
}

proptest! {
    /// check_terms_policy accepts exactly the open policy (F6 as a property): the mint and the
    /// sponsor allowed, refund_to the sponsor, the Config's arbiter, a compliance key, the minimum
    /// bond, every window at its floor, every regrader registered, the house within its allowance,
    /// the panel independent of the resolver and the compliance key, neither of those the escrow's
    /// own address, and no key revoked; for a house sponsor, the challenge window from 0. A
    /// proposal's check (sponsor_allowlisted false) accepts exactly the same rules but the sponsor
    /// allowlist, never takes the house waiver, and waives nothing else: every other refusal
    /// stays, by the same error.
    #[test]
    fn the_open_policy_accepts_exactly_its_rules((config, sponsor, mint, escrow, t) in policy_case()) {
        let open = config.check_terms_policy(&sponsor, &mint, &escrow, &t, true);
        prop_assert_eq!(
            open.is_ok(),
            allowed(&config, &sponsor, &mint, &escrow, &t, true),
            "{:?}", t
        );
        let proposal = config.check_terms_policy(&sponsor, &mint, &escrow, &t, false);
        prop_assert_eq!(
            proposal.is_ok(),
            allowed(&config, &sponsor, &mint, &escrow, &t, false),
            "{:?}", t
        );
        // A refusal other than the allowlist's is the proposal's too, by the same error; behind
        // SponsorNotAllowed the proposal meets the rules after it (allowed(.., false) above). The
        // one rule open_escrow may waive that a proposal never does: a house sponsor's challenge
        // window under the floor, which the proposal refuses by WindowBelowFloor.
        let waived = u32::from(EscrowError::SponsorNotAllowed);
        let below_floor = u32::from(EscrowError::WindowBelowFloor);
        let house_waived =
            marked_house(&config, &sponsor) && t.challenge_window < config.min_challenge_window;
        match (open.map_err(code), proposal.map_err(code)) {
            (Err(e), Ok(())) => prop_assert_eq!(e, waived),
            (Err(e), Err(p)) => prop_assert!(
                e == waived || e == p || (house_waived && p == below_floor),
                "open {} but proposal {}", e, p
            ),
            (Ok(()), p) => prop_assert!(
                p.is_ok() || (house_waived && p == Err(below_floor)),
                "a proposal refused what open_escrow takes"
            ),
        }
    }
}

proptest! {
    /// Config::check_proposal_terms accepts exactly its rules (the #852 audit's P2-1 and P3-1),
    /// each refusal by its own error in the documented order: the sponsor not the curator
    /// (SponsorIsCurator), neither the resolver nor the compliance key the sponsor or the curator
    /// (ProposalRoleNotIndependent), resolve_deadline - final_end at least MIN_RESOLVE_WINDOW
    /// (ResolveWindowTooShort), the bond at most MAX_PROPOSAL_BOND (ProposalBondTooHigh). No
    /// curator named (Pubkey::default()) is no key's: it refuses nothing.
    #[test]
    fn the_proposal_bounds_accept_exactly_their_rules(
        (t, _, _) in valid_terms(),
        keys in (0u8..=3, 0u8..=3, 0u8..=3, 0u8..=4),
        window in prop_oneof![Just(MIN_RESOLVE_WINDOW - 1), Just(MIN_RESOLVE_WINDOW), 1i64..=2 * MIN_RESOLVE_WINDOW],
        bond in prop_oneof![Just(MAX_PROPOSAL_BOND), Just(MAX_PROPOSAL_BOND + 1), 1u64..=2 * MAX_PROPOSAL_BOND],
    ) {
        // Four keys of no Config role (50 to 53) for the sponsor, the resolver and the compliance
        // key, and the curator one of them or none named.
        let (sponsor, resolver, compliance) = (pk(50 + keys.0), pk(50 + keys.1), pk(50 + keys.2));
        let curator = if keys.3 == 0 { Pubkey::default() } else { pk(49 + keys.3) };
        let mut config = config_at(1_800_000_000, limits(1, 1));
        config.set_proposal_policy(curator, 0).unwrap();
        let mut t = t;
        t.resolver = resolver;
        t.compliance = compliance;
        t.resolve_deadline = t.final_end + window;
        t.bond_lamports = bond;
        let named = |k: &Pubkey| curator != Pubkey::default() && *k == curator;
        let want = if named(&sponsor) {
            Some(EscrowError::SponsorIsCurator)
        } else if [resolver, compliance].iter().any(|r| *r == sponsor || named(r)) {
            Some(EscrowError::ProposalRoleNotIndependent)
        } else if window < MIN_RESOLVE_WINDOW {
            Some(EscrowError::ResolveWindowTooShort)
        } else if bond > MAX_PROPOSAL_BOND {
            Some(EscrowError::ProposalBondTooHigh)
        } else {
            None
        };
        match (config.check_proposal_terms(&sponsor, &t), want) {
            (Ok(()), None) => {}
            (Err(e), Some(want)) => prop_assert_eq!(code(e), u32::from(want)),
            (got, want) => prop_assert!(false, "got {:?}, want {:?}", got.map_err(code), want),
        }
    }
}

/// Both generators reach both sides: a property that only ever saw refusals (or only
/// acceptances) would prove little.
#[test]
fn the_generators_reach_both_sides() {
    use proptest::{strategy::ValueTree, test_runner::TestRunner};
    let mut runner = TestRunner::deterministic();
    let (mut terms_ok, mut policy_ok) = (0, 0);
    let draws = 2_000;
    for _ in 0..draws {
        let (t, now, min_bond) = any_terms().new_tree(&mut runner).unwrap().current();
        terms_ok += usize::from(valid(&t, now, min_bond, false));
        let (config, sponsor, mint, escrow, t) =
            policy_case().new_tree(&mut runner).unwrap().current();
        policy_ok += usize::from(allowed(&config, &sponsor, &mint, &escrow, &t, true));
    }
    for (what, ok) in [("validate", terms_ok), ("check_terms_policy", policy_ok)] {
        assert!(
            (draws / 5..=draws * 4 / 5).contains(&ok),
            "{what}: {ok} of {draws} draws accepted"
        );
    }
}

// ------------------------------------------------------------------------- the caps' counters

/// One move on the caps' counters, as the instruction that makes it calls Config: open_escrow
/// (Config::deposit of a new escrow), fund (deposit on top of an escrow's), refund (release),
/// submit_proposal (reserve_pending), approve_proposal (approve_pending: the proposal becomes an
/// escrow holding its deposit), close_proposal (release_pending), and the admin moving C_e, C_g or
/// the pending cap. Indices pick among the escrows or proposals so far, modulo their count.
#[derive(Clone, Copy, Debug)]
enum CapOp {
    Open(u64),
    Fund(u8, u64),
    Refund(u8),
    Submit(u64),
    Approve(u8),
    Close(u8),
    Caps(u64, u64, u64),
}

fn cap_op() -> impl Strategy<Value = CapOp> {
    let amount = || prop_oneof![1u64..=400, Just(1u64), Just(u64::MAX)];
    prop_oneof![
        3 => amount().prop_map(CapOp::Open),
        2 => (any::<u8>(), amount()).prop_map(|(i, a)| CapOp::Fund(i, a)),
        2 => any::<u8>().prop_map(CapOp::Refund),
        4 => amount().prop_map(CapOp::Submit),
        3 => any::<u8>().prop_map(CapOp::Approve),
        2 => any::<u8>().prop_map(CapOp::Close),
        1 => (1u64..=600, 1u64..=1_500, 0u64..=1_000).prop_map(|(e, g, p)| CapOp::Caps(e, g, p)),
    ]
}

/// The reference ledger: each escrow's deposit and whether it is still open (not refunded), and
/// each proposal's deposit and whether it still awaits review.
#[derive(Default)]
struct Ledger {
    escrows: Vec<(u64, bool)>,
    proposals: Vec<(u64, bool)>,
}

impl Ledger {
    fn open(&self) -> u128 {
        self.escrows
            .iter()
            .filter(|e| e.1)
            .map(|e| u128::from(e.0))
            .sum()
    }

    fn pending(&self) -> u128 {
        self.proposals
            .iter()
            .filter(|p| p.1)
            .map(|p| u128::from(p.0))
            .sum()
    }
}

proptest! {
    /// Config's counters are the open deposits, whatever the order of opens, funds, refunds,
    /// submits, approvals, returns and cap changes: open_value is what every escrow not yet
    /// refunded deposited (an approved proposal's included), pending_value what every proposal
    /// awaiting review deposited, and the two together count against C_g. Every deposit is held to
    /// the caps in force at its moment, by the documented error in the documented order (C_e,
    /// then the pending cap, then C_g), and refused exactly when they would be exceeded; an
    /// approval moves its deposit from pending to open whatever C_g says since (its room was
    /// taken at the submit), and is refused exactly when the escrow it opens would be over today's
    /// C_e (EscrowCapExceeded, the proposal still pending); a refund or a return never fails for
    /// the counters' sake.
    #[test]
    fn open_value_and_pending_value_are_the_open_deposits(
        caps in (1u64..=600, 1u64..=1_500, 0u64..=1_000),
        ops in prop::collection::vec(cap_op(), 1..=60),
    ) {
        let mut config = config_at(1_800_000_000, Limits { escrow_cap: caps.0, global_cap: caps.1, ..limits(1, 1) });
        config.set_proposal_policy(Pubkey::new_from_array([9; 32]), caps.2).unwrap();
        let mut ledger = Ledger::default();
        for op in ops {
            let (c_e, c_g, c_p) = (
                u128::from(config.escrow_cap),
                u128::from(config.global_cap),
                u128::from(config.pending_cap),
            );
            let held = ledger.open() + ledger.pending();
            match op {
                CapOp::Open(amount) => {
                    let want = if u128::from(amount) > c_e {
                        Some(EscrowError::EscrowCapExceeded)
                    } else if held + u128::from(amount) > c_g {
                        Some(EscrowError::GlobalCapExceeded)
                    } else {
                        None
                    };
                    match (config.deposit(0, amount), want) {
                        (Ok(deposited), None) => {
                            prop_assert_eq!(deposited, amount);
                            ledger.escrows.push((amount, true));
                        }
                        (Err(e), Some(want)) => prop_assert_eq!(code(e), u32::from(want), "{:?}", op),
                        (got, want) => prop_assert!(false, "{:?}: got {:?}, want {:?}", op, got.map_err(code), want),
                    }
                }
                CapOp::Fund(i, amount) => {
                    let open: Vec<usize> = (0..ledger.escrows.len()).filter(|j| ledger.escrows[*j].1).collect();
                    if open.is_empty() {
                        continue;
                    }
                    let j = open[usize::from(i) % open.len()];
                    let deposited = ledger.escrows[j].0;
                    let want = if u128::from(deposited) + u128::from(amount) > c_e {
                        Some(EscrowError::EscrowCapExceeded)
                    } else if held + u128::from(amount) > c_g {
                        Some(EscrowError::GlobalCapExceeded)
                    } else {
                        None
                    };
                    match (config.deposit(deposited, amount), want) {
                        (Ok(total), None) => {
                            prop_assert_eq!(total, deposited + amount);
                            ledger.escrows[j].0 = total;
                        }
                        (Err(e), Some(want)) => prop_assert_eq!(code(e), u32::from(want), "{:?}", op),
                        (got, want) => prop_assert!(false, "{:?}: got {:?}, want {:?}", op, got.map_err(code), want),
                    }
                }
                CapOp::Refund(i) => {
                    let open: Vec<usize> = (0..ledger.escrows.len()).filter(|j| ledger.escrows[*j].1).collect();
                    if open.is_empty() {
                        continue;
                    }
                    let j = open[usize::from(i) % open.len()];
                    config.release(ledger.escrows[j].0);
                    ledger.escrows[j].1 = false;
                }
                CapOp::Submit(amount) => {
                    let pending = ledger.pending();
                    let want = if u128::from(amount) > c_e {
                        Some(EscrowError::EscrowCapExceeded)
                    } else if pending + u128::from(amount) > c_p {
                        Some(EscrowError::PendingCapExceeded)
                    } else if held + u128::from(amount) > c_g {
                        Some(EscrowError::GlobalCapExceeded)
                    } else {
                        None
                    };
                    match (config.reserve_pending(amount), want) {
                        (Ok(()), None) => ledger.proposals.push((amount, true)),
                        (Err(e), Some(want)) => prop_assert_eq!(code(e), u32::from(want), "{:?}", op),
                        (got, want) => prop_assert!(false, "{:?}: got {:?}, want {:?}", op, got.map_err(code), want),
                    }
                }
                CapOp::Approve(i) | CapOp::Close(i) => {
                    let pending: Vec<usize> = (0..ledger.proposals.len()).filter(|j| ledger.proposals[*j].1).collect();
                    if pending.is_empty() {
                        continue;
                    }
                    let j = pending[usize::from(i) % pending.len()];
                    let amount = ledger.proposals[j].0;
                    if matches!(op, CapOp::Approve(_)) {
                        // The escrow an approval opens is held to today's C_e (a C_e lowered since
                        // the submit refuses it, the proposal still pending); C_g is not read again.
                        match (config.approve_pending(amount), u128::from(amount) > c_e) {
                            (Ok(()), false) => {
                                ledger.proposals[j].1 = false;
                                ledger.escrows.push((amount, true));
                            }
                            (Err(e), true) => prop_assert_eq!(code(e), u32::from(EscrowError::EscrowCapExceeded), "{:?}", op),
                            (got, over) => prop_assert!(false, "{:?}: got {:?}, over C_e {}", op, got.map_err(code), over),
                        }
                    } else {
                        ledger.proposals[j].1 = false;
                        config.release_pending(amount);
                    }
                }
                CapOp::Caps(escrow_cap, global_cap, pending_cap) => {
                    config.set_limits(&Limits { escrow_cap, global_cap, ..limits(1, 1) }, 1_800_000_000).unwrap();
                    config.set_proposal_policy(config.curator, pending_cap).unwrap();
                }
            }
            prop_assert_eq!(u128::from(config.open_value), ledger.open(), "open_value after {:?}", op);
            prop_assert_eq!(u128::from(config.pending_value), ledger.pending(), "pending_value after {:?}", op);
            if matches!(op, CapOp::Open(_) | CapOp::Fund(..) | CapOp::Submit(_)) && u128::from(config.open_value) + u128::from(config.pending_value) > held {
                prop_assert!(
                    u128::from(config.open_value) + u128::from(config.pending_value) <= u128::from(config.global_cap),
                    "a deposit took the counters past C_g: {:?}", op
                );
            }
        }
    }
}

/// The counters' generator reaches every outcome: deposits taken and refused by each cap, and
/// approvals and returns of proposals that got in.
#[test]
fn the_cap_generator_reaches_every_outcome() {
    use proptest::{strategy::ValueTree, test_runner::TestRunner};
    let mut runner = TestRunner::deterministic();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..300 {
        let caps = (1u64..=600, 1u64..=1_500, 0u64..=1_000)
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let ops = prop::collection::vec(cap_op(), 1..=60)
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let mut config = config_at(
            1_800_000_000,
            Limits {
                escrow_cap: caps.0,
                global_cap: caps.1,
                ..limits(1, 1)
            },
        );
        config
            .set_proposal_policy(Pubkey::new_from_array([9; 32]), caps.2)
            .unwrap();
        let mut pending = Vec::new();
        for op in ops {
            match op {
                CapOp::Open(a) => {
                    seen.insert(match config.deposit(0, a) {
                        Ok(_) => "open ok".to_string(),
                        Err(e) => format!("open {}", code(e)),
                    });
                }
                CapOp::Submit(a) => {
                    seen.insert(match config.reserve_pending(a) {
                        Ok(()) => {
                            pending.push(a);
                            "submit ok".to_string()
                        }
                        Err(e) => format!("submit {}", code(e)),
                    });
                }
                CapOp::Approve(_) if !pending.is_empty() => {
                    config.approve_pending(pending.pop().unwrap()).unwrap();
                    seen.insert("approve".to_string());
                }
                CapOp::Close(_) if !pending.is_empty() => {
                    config.release_pending(pending.pop().unwrap());
                    seen.insert("close".to_string());
                }
                _ => {}
            }
        }
    }
    let (e, g, p) = (
        u32::from(EscrowError::EscrowCapExceeded),
        u32::from(EscrowError::GlobalCapExceeded),
        u32::from(EscrowError::PendingCapExceeded),
    );
    for want in [
        "open ok".to_string(),
        format!("open {e}"),
        format!("open {g}"),
        "submit ok".to_string(),
        format!("submit {e}"),
        format!("submit {p}"),
        format!("submit {g}"),
        "approve".to_string(),
        "close".to_string(),
    ] {
        assert!(seen.contains(&want), "{want} never happened: {seen:?}");
    }
}
