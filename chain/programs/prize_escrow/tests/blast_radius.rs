//! The per-actor blast radius, fuzzed: for each key set K the adversary may hold (the resolver,
//! the compliance key, one house regrader, all the house's keys, one multisig member, the
//! guardian, the house's keys with the guardian's, and nobody) on each panel (the house holding a
//! quorum, as owner decision #541 allows today, or independent regraders holding it), proptest
//! draws random step sequences, runs them on the release build in LiteSVM against live honest
//! parties, and the oracle (tests/support/model.rs) audits every transaction: the USDC moved
//! outside the honest rubric is at most bound(K), none of it before challenge_deadline on the
//! escrow clock (before attest_deadline under an applied alternative), and conservation, single
//! claims, single bond payments, one terminal state and privilege hold throughout. bound(K) is the
//! pot only for the house's keys with the guardian's on a house panel, 0 for every other K. Each sequence then drains (the honest parties alone, until the
//! escrow is Closed and every account closed) and the end state is checked too.
//!
//! A failing sequence is shrunk to a minimal one and printed with the oracle's trace.
//!
//! The directed tests below show the oracle is not vacuous: it flags a payout a program bug lets
//! through early, the house's keys with the guardian's drain the pot only after the window, an
//! honest guardian stops the same house quorum voting a false posted result, even one recorded in
//! the same second as the post, and the finding of this oracle (#536), fixed by #749: on a panel
//! the house holds a quorum of, the house's keys alone applied a challenge revealed in the reveal
//! grace at challenge_deadline, before any honest party could react; settle now applies an
//! overturn only at attest_deadline, and the guardian escalates it inside the attest window
//! (a_house_quorum_cannot_apply_a_challenge_revealed_in_the_grace).
//!
//! Bounded by default (BLAST_CASES sequences of up to BLAST_STEPS steps per K and panel, from the
//! fixed seed BLAST_SEED); a longer fuzz run raises them, e.g.
//! `BLAST_CASES=2000 BLAST_STEPS=160 BLAST_SEED=random cargo test -p prize_escrow --test blast_radius --release`.
//! BLAST_BOUND=0 holds every K to a bound of 0, a search for any drain at all.

mod mainnet;
mod program_so;
mod support;

use {
    anchor_lang::AccountSerialize,
    litesvm::LiteSVM,
    prize_escrow::EscrowStatus,
    proptest::{
        collection::vec,
        prelude::*,
        test_runner::{
            Config as ProptestConfig, RngAlgorithm, TestCaseError, TestError, TestRng, TestRunner,
        },
    },
    solana_account::Account,
    std::{cell::RefCell, collections::BTreeMap},
    support::{
        model::{Compromise, Model, Step, MAX_LATENCY},
        Chain, Panel, Role, World, ATTEST_WINDOW, CHALLENGE_WINDOW, CLAIM_WINDOW, FINAL_END, TOTAL,
    },
};

/// Drain rounds of MAX_LATENCY each: 100 days, past every deadline a stop or freeze can move.
const DRAIN: usize = 200;

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The world for K and the panel, just before the final phase ends.
fn base(panel: Panel, who: Compromise) -> (LiteSVM, Model) {
    let mut svm = mainnet::svm();
    svm.add_program(prize_escrow::ID, program_so::bytes())
        .unwrap();
    let world = World::create(&mut svm, panel, true);
    svm.set_time(FINAL_END - MAX_LATENCY);
    (svm, Model::new(world, who))
}

fn wait() -> impl Strategy<Value = Step> {
    prop_oneof![
        2 => Just(MAX_LATENCY as u32),
        1 => 1..=(MAX_LATENCY as u32),
        1 => 1u32..=600,
    ]
    .prop_map(Step::Wait)
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        24 => wait(),
        2 => Just(Step::React),
        4 => (any::<u8>(), any::<u8>()).prop_map(|(tree, total)| Step::Post { tree, total }),
        1 => Just(Step::CommitEntries),
        5 => (any::<u8>(), any::<u8>(), any::<bool>())
            .prop_map(|(tree, by, reveal)| Step::Challenge { tree, by, reveal }),
        6 => (any::<u8>(), any::<u8>()).prop_map(|(seat, tree)| Step::Attest { seat, tree }),
        3 => Just(Step::Settle),
        2 => Just(Step::Refund),
        1 => Just(Step::CloseChallenges),
        1 => Just(Step::CloseCommits),
        3 => any::<u8>().prop_map(|leaf| Step::RequestClaim { leaf }),
        5 => (any::<u8>(), any::<u8>(), any::<bool>())
            .prop_map(|(leaf, amount, cosign)| Step::Claim { leaf, amount, cosign }),
        2 => any::<u8>().prop_map(|claimant| Step::Hold { claimant }),
        2 => any::<u8>().prop_map(|claimant| Step::Release { claimant }),
        2 => any::<u8>().prop_map(|level| Step::Stop { level }),
        1 => Just(Step::ExtendStop),
        2 => any::<bool>().prop_map(|on| Step::Freeze { on }),
        1 => Just(Step::ExtendFreeze),
        2 => Just(Step::Escalate),
        2 => (any::<u8>(), any::<bool>()).prop_map(|(target, on)| Step::Revoke { target, on }),
        2 => any::<u8>().prop_map(|tree| Step::Arbiter { tree }),
        1 => any::<u8>().prop_map(|role| Step::Rotate { role }),
        1 => Just(Step::SetLimits),
        1 => any::<u8>().prop_map(|amount| Step::DonateTokens { amount }),
        1 => Just(Step::DonateLamports),
        4 => any::<u8>().prop_map(|tree| Step::Vote { tree }),
        4 => any::<u8>().prop_map(|tree| Step::Cash { tree }),
        6 => any::<u8>().prop_map(Step::Tick),
        6 => (any::<u8>(), any::<u8>()).prop_map(|(deadline, before)| Step::Approach { deadline, before }),
        4 => (any::<u8>(), any::<u8>()).prop_map(|(tree, by)| Step::Reveal { tree, by }),
    ]
}

/// The seed for K on the panel: BLAST_SEED as a number, "random" for a fresh one, else a fixed
/// default.
fn seed(panel: Panel, who: Compromise) -> (u64, [u8; 32]) {
    let n = match std::env::var("BLAST_SEED").as_deref() {
        Ok("random") => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
        Ok(v) => v.parse().unwrap_or(536),
        Err(_) => 536,
    };
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&n.to_le_bytes());
    // Each K and panel draws its own sequences from the one seed.
    bytes[8] = Compromise::ALL.iter().position(|c| *c == who).unwrap() as u8;
    bytes[9] = panel as u8;
    (n, bytes)
}

/// Runs the oracle for K on `panel`; panics with the minimal failing sequence.
fn fuzz(panel: Panel, who: Compromise) {
    let cases: u32 = env_or("BLAST_CASES", 32);
    let max_steps: usize = env_or("BLAST_STEPS", 120);
    let (seed_n, seed) = seed(panel, who);
    let (svm, mut model) = base(panel, who);
    // BLAST_BOUND holds the adversary to another bound than bound(K) (0: search for any drain).
    model.bound_override = std::env::var("BLAST_BOUND")
        .ok()
        .and_then(|b| b.parse().ok());
    let bound = model.bound_override.unwrap_or_else(|| who.bound(panel));
    let config = ProptestConfig {
        cases,
        failure_persistence: None,
        max_shrink_iters: env_or("BLAST_SHRINK", 4096),
        ..ProptestConfig::default()
    };
    let mut runner =
        TestRunner::new_with_rng(config, TestRng::from_seed(RngAlgorithm::ChaCha, &seed));
    let ends: RefCell<BTreeMap<String, u32>> = RefCell::new(BTreeMap::new());
    let drained = RefCell::new(0u32);
    let started = std::time::Instant::now();
    let result = runner.run(&vec(step(), 1..=max_steps), |steps| {
        let (mut svm, mut m) = (svm.clone(), model.clone());
        for s in &steps {
            m.step(&mut svm, *s).map_err(TestCaseError::fail)?;
        }
        let before_drain = m.world.state(&svm).map(|e| e.status);
        m.drain(&mut svm, DRAIN).map_err(TestCaseError::fail)?;
        *drained.borrow_mut() += 1;
        *ends
            .borrow_mut()
            .entry(format!(
                "{before_drain:?}{}",
                if m.outside_max > 0 {
                    ", adversary paid"
                } else {
                    ""
                }
            ))
            .or_default() += 1;
        Ok(())
    });
    match result {
        Ok(()) => eprintln!(
            "blast radius {who:?} on {panel:?}: {} sequences (<= {max_steps} steps, seed {seed_n}) in {:?}, bound {}; status before the drain: {:?}",
            drained.borrow(),
            started.elapsed(),
            bound,
            ends.borrow()
        ),
        Err(TestError::Fail(reason, steps)) => panic!(
            "blast radius {who:?} on {panel:?} (seed {seed_n}): minimal failing sequence of {} steps:\n{steps:?}\n{reason}",
            steps.len()
        ),
        Err(TestError::Abort(reason)) => panic!("blast radius {who:?} on {panel:?}: aborted: {reason}"),
    }
}

macro_rules! oracle {
    ($($name:ident: $who:ident on $panel:ident;)*) => {$(
        #[test]
        fn $name() {
            fuzz(Panel::$panel, Compromise::$who);
        }
    )*};
}

oracle! {
    nobody_on_a_house_panel: Nobody on HouseMajority;
    nobody_on_an_independent_panel: Nobody on IndependentMajority;
    the_resolver_on_a_house_panel: Resolver on HouseMajority;
    the_resolver_on_an_independent_panel: Resolver on IndependentMajority;
    the_compliance_key_on_a_house_panel: Compliance on HouseMajority;
    the_compliance_key_on_an_independent_panel: Compliance on IndependentMajority;
    one_house_regrader_on_a_house_panel: OneHouseRegrader on HouseMajority;
    one_house_regrader_on_an_independent_panel: OneHouseRegrader on IndependentMajority;
    all_house_keys_on_a_house_panel: AllHouseKeys on HouseMajority;
    all_house_keys_on_an_independent_panel: AllHouseKeys on IndependentMajority;
    one_multisig_member_on_a_house_panel: MultisigMember on HouseMajority;
    one_multisig_member_on_an_independent_panel: MultisigMember on IndependentMajority;
    the_guardian_on_a_house_panel: Guardian on HouseMajority;
    the_guardian_on_an_independent_panel: Guardian on IndependentMajority;
    the_house_and_the_guardian_on_a_house_panel: AllHouseKeysAndGuardian on HouseMajority;
    the_house_and_the_guardian_on_an_independent_panel: AllHouseKeysAndGuardian on IndependentMajority;
}

// ------------------------------------------------------------------- the oracle is not vacuous

/// The house's keys post the honest result (nothing for the watcher or the guardian to see), commit
/// a challenge paying the adversary on the window's last second, and once the window is over reveal
/// it in the reveal grace, vote it with the house's quorum, settle and claim it co-signed, inside
/// one BLIND: steps the oracle runs as written.
fn grace_reveal() -> Vec<Step> {
    let mut steps = vec![
        Step::Wait(MAX_LATENCY as u32),
        Step::Wait(1),
        Step::Post { tree: 0, total: 0 },
    ];
    // To one second before challenge_deadline, MAX_LATENCY at a time (the honest parties react
    // before each jump, and see nothing amiss).
    let jumps = (CHALLENGE_WINDOW / MAX_LATENCY) as usize + 1;
    steps.extend(std::iter::repeat_n(
        Step::Approach {
            deadline: 0,
            before: 1,
        },
        jumps,
    ));
    steps.extend([
        Step::Challenge {
            tree: 1,
            by: 0,
            reveal: false,
        },
        Step::Tick(1),
        Step::Reveal { tree: 1, by: 0 },
        Step::Vote { tree: 1 },
        Step::Settle,
        Step::Cash { tree: 1 },
    ]);
    steps
}

/// #536's finding, fixed by #749. On a panel the house holds a quorum of, the house's keys (a
/// server compromise) post the honest result, commit a challenge paying the adversary on the
/// challenge window's last second, reveal it in the reveal grace and vote it to k at once, all
/// inside BLIND, as before; but settle applies an overturn only at attest_deadline
/// (OverturnWindowOpen), so nothing moves at challenge_deadline. With the watcher and the guardian
/// honest nothing moves at all: the guardian's next look finds the recorded alternative well
/// inside the attest window, escalates it, and the arbiter keeps the honest posted result. With
/// the guardian's key too (or the guardian asleep) the same moves pay the adversary, at
/// attest_deadline and not a second before: the window the guardian gets.
#[test]
fn a_house_quorum_cannot_apply_a_challenge_revealed_in_the_grace() {
    let (mut svm, mut m) = base(Panel::HouseMajority, Compromise::AllHouseKeys);
    for step in grace_reveal() {
        m.step(&mut svm, step)
            .unwrap_or_else(|report| panic!("{report}"));
    }
    let e = m.world.state(&svm).unwrap();
    assert_eq!(
        (e.status, e.challenger),
        (EscrowStatus::Disputed, Role::Attacker(2).pubkey()),
        "the house's quorum for its alternative is recorded: {}",
        m.report()
    );
    assert!(
        m.trace.iter().any(|t| t.contains("Settle: refused 6092")),
        "its settle waits for attest_deadline (OverturnWindowOpen): {}",
        m.report()
    );
    assert_eq!(m.outside_max, 0, "{}", m.report());
    // The guardian's next look, well inside the attest window.
    m.step(&mut svm, Step::React)
        .unwrap_or_else(|report| panic!("{report}"));
    let looked_at = m.world.escrow_now(&svm);
    assert!(looked_at < e.attest_deadline, "inside the attest window");
    assert!(
        m.trace.iter().any(|t| t.contains("guardian escalate: ok")),
        "the guardian escalates the overturn: {}",
        m.report()
    );
    let e = m.world.state(&svm).unwrap();
    assert_eq!(
        (e.status, e.payout_root),
        (EscrowStatus::Claimable, m.trees[0].root),
        "the arbiter keeps the honest posted result: {}",
        m.report()
    );
    m.drain(&mut svm, DRAIN)
        .unwrap_or_else(|report| panic!("{report}"));
    assert_eq!(m.outside_max, 0, "{}", m.report());

    // The guardian's key too: the same moves, then the attest window waited out to its last
    // second. The overturn pays at attest_deadline itself.
    let (mut svm, mut m) = base(Panel::HouseMajority, Compromise::AllHouseKeysAndGuardian);
    let mut steps = grace_reveal();
    let jumps = (ATTEST_WINDOW / MAX_LATENCY) as usize + 1;
    steps.extend(std::iter::repeat_n(
        Step::Approach {
            deadline: 2,
            before: 1,
        },
        jumps,
    ));
    steps.extend([
        Step::Settle,
        Step::Cash { tree: 1 },
        Step::Tick(1),
        Step::Settle,
        Step::Cash { tree: 1 },
    ]);
    let mut paid_at = None;
    for step in steps {
        let before = m.outside(&svm);
        m.step(&mut svm, step)
            .unwrap_or_else(|report| panic!("{report}"));
        if m.outside(&svm) > before {
            paid_at.get_or_insert(m.world.escrow_now(&svm));
        }
    }
    let e = m.world.state(&svm).unwrap();
    assert_eq!(m.outside_max, TOTAL, "{}", m.report());
    assert_eq!(
        paid_at,
        Some(e.attest_deadline),
        "paid at attest_deadline itself: {}",
        m.report()
    );
    m.drain(&mut svm, DRAIN)
        .unwrap_or_else(|report| panic!("{report}"));

    // The same moves on a panel independent regraders hold a quorum of: one house vote is no
    // quorum, settle waits for the attest window, and the guardian hands the dispute to the arbiter.
    let (mut svm, mut m) = base(Panel::IndependentMajority, Compromise::AllHouseKeys);
    for step in grace_reveal() {
        m.step(&mut svm, step)
            .unwrap_or_else(|report| panic!("{report}"));
    }
    m.step(&mut svm, Step::React).unwrap();
    assert_eq!(m.outside_max, 0, "{}", m.report());
    m.drain(&mut svm, DRAIN)
        .unwrap_or_else(|report| panic!("{report}"));
    assert_eq!(m.outside_max, 0, "{}", m.report());
}

fn house_quorum_drain() -> Vec<Step> {
    let mut steps = vec![Step::Wait(MAX_LATENCY as u32), Step::Wait(1)];
    steps.push(Step::Post { tree: 1, total: 0 });
    // The watcher challenges it with the honest result: a dispute the house votes in.
    steps.push(Step::React);
    // Seats 0 and 1 vote the posted commitment once the watcher's challenge made it a dispute.
    steps.push(Step::Attest { seat: 0, tree: 5 });
    steps.push(Step::Attest { seat: 1, tree: 5 });
    let windows = (CHALLENGE_WINDOW / MAX_LATENCY) as usize + 1;
    steps.extend(std::iter::repeat_n(Step::Wait(MAX_LATENCY as u32), windows));
    steps.push(Step::Settle);
    // Leaf 2 is the "steal" tree's first leaf: the adversary's claimant, TOTAL - 1.
    steps.push(Step::Claim {
        leaf: 2,
        amount: 0,
        cosign: true,
    });
    steps
}

#[test]
fn a_house_quorum_with_the_guardian_drains_the_pot_only_after_the_challenge_window() {
    let (mut svm, mut m) = base(Panel::HouseMajority, Compromise::AllHouseKeysAndGuardian);
    let mut paid_at = None;
    for step in house_quorum_drain() {
        let before = m.outside(&svm);
        m.step(&mut svm, step)
            .unwrap_or_else(|report| panic!("{report}"));
        if m.outside(&svm) > before {
            paid_at = Some(m.world.escrow_now(&svm));
        }
    }
    let e = m.world.state(&svm).unwrap();
    assert_eq!(m.outside_max, TOTAL - 1, "{}", m.report());
    assert!(
        paid_at.unwrap() >= e.challenge_deadline,
        "paid at {paid_at:?}, challenge_deadline {}",
        e.challenge_deadline
    );
    m.drain(&mut svm, DRAIN)
        .unwrap_or_else(|report| panic!("{report}"));
}

#[test]
fn the_same_house_quorum_with_an_honest_guardian_moves_nothing() {
    let (mut svm, mut m) = base(Panel::HouseMajority, Compromise::AllHouseKeys);
    for step in house_quorum_drain() {
        m.step(&mut svm, step)
            .unwrap_or_else(|report| panic!("{report}"));
    }
    assert_eq!(m.outside_max, 0, "{}", m.report());
    assert_eq!(m.world.state(&svm).unwrap().status, EscrowStatus::Frozen);
    assert!(m.trace.iter().any(|t| t.contains("guardian escalate: ok")));
    m.drain(&mut svm, DRAIN)
        .unwrap_or_else(|report| panic!("{report}"));
}

/// The house's keys post a root paying the adversary and, in the same second, self-challenge it
/// and vote it to k: a quorum recorded before the guardian has looked. The guardian's next look is
/// still inside the challenge window, before that quorum may settle, so escalate takes it
/// (breakers::handle_escalate refuses a quorum for the posted result only from challenge_deadline)
/// and nothing moves.
#[test]
fn a_house_quorum_recorded_before_the_guardian_looks_is_still_escalated() {
    let (mut svm, mut m) = base(Panel::HouseMajority, Compromise::AllHouseKeys);
    let steps = [
        Step::Wait(MAX_LATENCY as u32),
        Step::Wait(1),
        Step::Post { tree: 1, total: 0 },
        Step::Challenge {
            tree: 2,
            by: 0,
            reveal: true,
        },
        // One past the trees: the posted commitment.
        Step::Vote { tree: 5 },
    ];
    for step in steps {
        m.step(&mut svm, step)
            .unwrap_or_else(|report| panic!("{report}"));
    }
    let e = m.world.state(&svm).unwrap();
    assert!(
        e.status == EscrowStatus::Disputed && e.votes_result >= e.k,
        "the house's quorum for its posted result: {}",
        m.report()
    );
    m.step(&mut svm, Step::React).unwrap();
    assert!(
        m.trace.iter().any(|t| t.contains("guardian escalate: ok")),
        "{}",
        m.report()
    );
    assert_eq!(m.world.state(&svm).unwrap().status, EscrowStatus::Frozen);
    let windows = (CHALLENGE_WINDOW / MAX_LATENCY) as usize + 1;
    for step in std::iter::repeat_n(Step::Wait(MAX_LATENCY as u32), windows)
        .chain([Step::Settle, Step::Cash { tree: 1 }])
    {
        m.step(&mut svm, step)
            .unwrap_or_else(|report| panic!("{report}"));
    }
    assert_eq!(m.outside_max, 0, "{}", m.report());
    m.drain(&mut svm, DRAIN)
        .unwrap_or_else(|report| panic!("{report}"));
    assert_eq!(m.outside_max, 0, "{}", m.report());
}

#[test]
fn the_oracle_flags_a_payout_before_the_challenge_deadline_and_over_the_bound() {
    // A program bug simulated by writing the escrow: Claimable on the adversary's root while the
    // challenge window still runs. The adversary's claim then moves USDC early and over bound(K).
    let (mut svm, mut m) = base(Panel::IndependentMajority, Compromise::Compliance);
    m.step(&mut svm, Step::Wait(MAX_LATENCY as u32)).unwrap();
    m.step(&mut svm, Step::Wait(1)).unwrap();
    let steal = m.trees[1].clone();
    let address = m.world.escrow();
    let mut account: Account = svm.account(&address).unwrap();
    let mut escrow = m.world.state(&svm).unwrap();
    let now = m.world.escrow_now(&svm);
    assert!(
        now < escrow.challenge_deadline,
        "inside the challenge window"
    );
    escrow.status = EscrowStatus::Claimable;
    escrow.payout_root = steal.root;
    escrow.claim_deadline = now + CLAIM_WINDOW;
    let mut data = Vec::new();
    escrow.try_serialize(&mut data).unwrap();
    account.data[..data.len()].copy_from_slice(&data);
    svm.put_account(address, account);
    m.in_force = None;
    m.last_status = Some(EscrowStatus::Claimable);
    let report = m
        .step(
            &mut svm,
            Step::Claim {
                leaf: 2,
                amount: 0,
                cosign: true,
            },
        )
        .expect_err("the oracle flags the early payout");
    assert!(report.contains("before challenge_deadline"), "{report}");
    assert!(
        report.contains("over bound(Compliance, IndependentMajority) = 0"),
        "{report}"
    );
}
