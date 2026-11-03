//! The blast-radius oracle under crucible (asymmetric-research/crucible: LibAFL with LiteSVM
//! 0.15.2). The world, the honest parties and every invariant are the integration tests' own
//! (chain/programs/prize_escrow/tests/support, compiled here by `#[path]`); crucible drives the
//! adversary's steps as typed actions, coverage-guided over the release build's sBPF edges, and
//! the invariant test asserts after every action that the oracle found no violation. The world is
//! the blast-radius test's (tests/blast_radius.rs base): the escrow open, and a user sponsor's
//! proposal submitted beside it (World::open_proposals), which the adversary's proposal moves
//! (action_proposal, Step::Proposal), the user sponsor's own moves when the adversary holds its
//! key (action_sponsor, Step::Sponsor: terms of its choosing, its token account's owner
//! reassigned, fund attempts) and the honest curator's review play against. The wind-down's
//! admin verbs and its permissionless close_receipt are the adversary's to try too
//! (action_wind_down, Step::WindDown).
//!
//! The key set and panel come from the environment (BLAST_K: one of Compromise's variant names,
//! default AllHouseKeys, UserSponsor for a malicious user sponsor; BLAST_PANEL: HouseMajority, the
//! default, or IndependentMajority; and
//! BLAST_BOUND, a bound to hold the adversary to instead of bound(K): 0 searches for any drain,
//! e.g. one by the house's keys with the guardian's on a house panel, the one K bound(K) lets
//! take the pot; the house quorum's grace reveal is refused since #749, settle applying an
//! overturn only at attest_deadline). Run it the way `crucible run` does, from this directory,
//! after `node scripts/chain/build.ts release`:
//!
//! ```text
//! cargo build --release --features blast_radius
//! BLAST_K=Resolver FUZZ_TIMEOUT_SECS=600 FUZZ_MAX_ACTIONS=120 FUZZ_CRASHES_DIR=crashes \
//!   target/release/invariant_test
//! ```

// The program bytes, held to PRIZE_ESCROW_SO_SHA256 when it is set, as the program tests hold them.
#[path = "../../../programs/prize_escrow/tests/program_so/mod.rs"]
mod program_so;
#[path = "../../../programs/prize_escrow/tests/support/mod.rs"]
mod support;

use {
    crucible_fuzzer::*,
    crucible_test_context::TxOutcome,
    solana_account::Account,
    solana_keypair::Keypair,
    solana_signer::Signer,
    support::{
        model::{Compromise, Model, Step, MAX_LATENCY},
        Chain, Panel, Sent, World, FINAL_END,
    },
};

type Pubkey = anchor_lang::prelude::Pubkey;
type Clock = anchor_lang::prelude::Clock;

/// crucible's context as the world's chain: every transaction goes through its own send path, so
/// its coverage and its state-pool bookkeeping see it.
impl Chain for TestContext {
    fn send(
        &mut self,
        ixs: &[anchor_lang::solana_program::instruction::Instruction],
        payer: &Keypair,
        signers: &[&Keypair],
    ) -> Sent {
        let mut all = vec![payer];
        for signer in signers {
            if all.iter().all(|kp| kp.pubkey() != signer.pubkey()) {
                all.push(signer);
            }
        }
        // The world sends one instruction per transaction (World::send).
        let [ix] = ixs else {
            panic!("one instruction per transaction, not {}", ixs.len())
        };
        let outcome = self.raw_call(ix.clone()).signers(&all).send();
        let events =
            |inner: &solana_message::inner_instruction::InnerInstructionsList| -> Vec<Vec<u8>> {
                inner
                    .iter()
                    .flatten()
                    .filter_map(|i| Sent::event_payload(&i.instruction.data))
                    .collect()
            };
        match outcome {
            Ok(TxOutcome::Success {
                logs,
                inner_instructions,
                ..
            }) => Sent {
                ok: true,
                code: None,
                error: String::new(),
                logs: logs.join("\n"),
                events: events(&inner_instructions),
            },
            Ok(TxOutcome::ProgramError {
                error,
                error_code,
                logs,
                ..
            }) => Sent {
                ok: false,
                code: error_code,
                error: format!("{error:?}"),
                logs: logs.join("\n"),
                events: Vec::new(),
            },
            Err(e) => Sent::unsigned(e.to_string()),
        }
    }

    fn account(&self, address: &Pubkey) -> Option<Account> {
        self.svm.get_account(address)
    }

    fn put_account(&mut self, address: Pubkey, account: Account) {
        self.svm.set_account(address, account).expect("set_account");
    }

    fn clock(&self) -> Clock {
        self.svm.get_sysvar::<Clock>()
    }

    fn set_clock(&mut self, clock: &Clock) {
        self.set_sysvar(clock);
    }

    fn next_slot(&mut self) {
        let clock = self.clock();
        self.warp_to_slot(clock.slot + 1);
        let mut moved = self.clock();
        moved.unix_timestamp = clock.unix_timestamp;
        self.set_sysvar(&moved);
    }

    fn airdrop(&mut self, to: &Pubkey, lamports: u64) {
        self.svm.airdrop(to, lamports).expect("airdrop");
    }

    fn rent_exempt(&self, len: usize) -> u64 {
        self.svm.minimum_balance_for_rent_exemption(len)
    }
}

/// The key set from BLAST_K (a Compromise variant's name), default AllHouseKeys.
fn compromise() -> Compromise {
    let wanted = std::env::var("BLAST_K").unwrap_or_else(|_| "AllHouseKeys".to_string());
    Compromise::ALL
        .into_iter()
        .find(|c| format!("{c:?}") == wanted)
        .unwrap_or_else(|| panic!("BLAST_K={wanted} is not one of {:?}", Compromise::ALL))
}

/// The panel from BLAST_PANEL, default HouseMajority.
fn panel() -> Panel {
    match std::env::var("BLAST_PANEL").as_deref() {
        Ok("IndependentMajority") => Panel::IndependentMajority,
        Ok("HouseMajority") | Err(_) => Panel::HouseMajority,
        Ok(other) => panic!("BLAST_PANEL={other} is not HouseMajority or IndependentMajority"),
    }
}

#[derive(Clone)]
struct BlastFixture {
    ctx: TestContext,
    model: Model,
}

#[fuzz_fixture]
impl BlastFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        // The release build (`node scripts/chain/build.ts release`, chain/target/deploy, or
        // PRIZE_ESCROW_SO), its sha256 checked and printed (tests/program_so), then loaded by path,
        // as crucible traces its sBPF edges from the file.
        program_so::bytes();
        let path = program_so::path();
        ctx.add_program(&prize_escrow::ID, path.to_str().expect("a UTF-8 path"))
            .expect("the release build (node scripts/chain/build.ts release)");
        let mut world = World::create(&mut ctx, panel(), true);
        ctx.set_time(FINAL_END - MAX_LATENCY);
        world.open_proposals(&mut ctx);
        let mut model = Model::new(world, compromise());
        model.bound_override = std::env::var("BLAST_BOUND").ok().map(|b| {
            b.parse()
                .unwrap_or_else(|_| panic!("BLAST_BOUND={b} is not a u64"))
        });
        Self { ctx, model }
    }

    fn run(&mut self, step: Step) {
        // A violation stays on the model; the invariant test reports it.
        let _ = self.model.step(&mut self.ctx, step);
    }

    pub fn action_wait(&mut self, #[range(1..43201)] secs: u32) {
        self.run(Step::Wait(secs));
    }

    pub fn action_react(&mut self) {
        self.run(Step::React);
    }

    pub fn action_tick(&mut self, #[range(1..61)] secs: u8) {
        self.run(Step::Tick(secs));
    }

    pub fn action_approach(&mut self, #[range(0..7)] deadline: u8, #[range(1..61)] before: u8) {
        self.run(Step::Approach { deadline, before });
    }

    pub fn action_post(&mut self, #[range(0..5)] tree: u8, #[range(0..5)] total: u8) {
        self.run(Step::Post { tree, total });
    }

    pub fn action_commit_entries(&mut self) {
        self.run(Step::CommitEntries);
    }

    pub fn action_challenge(
        &mut self,
        #[range(0..5)] tree: u8,
        #[range(0..2)] by: u8,
        #[range(0..2)] reveal: u8,
    ) {
        self.run(Step::Challenge {
            tree,
            by,
            reveal: reveal == 1,
        });
    }

    pub fn action_reveal(&mut self, #[range(0..5)] tree: u8, #[range(0..2)] by: u8) {
        self.run(Step::Reveal { tree, by });
    }

    pub fn action_attest(&mut self, #[range(0..3)] seat: u8, #[range(0..6)] tree: u8) {
        self.run(Step::Attest { seat, tree });
    }

    pub fn action_vote(&mut self, #[range(0..6)] tree: u8) {
        self.run(Step::Vote { tree });
    }

    pub fn action_settle(&mut self) {
        self.run(Step::Settle);
    }

    pub fn action_refund(&mut self) {
        self.run(Step::Refund);
    }

    pub fn action_close_challenges(&mut self) {
        self.run(Step::CloseChallenges);
    }

    pub fn action_close_commits(&mut self) {
        self.run(Step::CloseCommits);
    }

    pub fn action_request_claim(&mut self, #[range(0..10)] leaf: u8) {
        self.run(Step::RequestClaim { leaf });
    }

    pub fn action_claim(
        &mut self,
        #[range(0..10)] leaf: u8,
        #[range(0..5)] amount: u8,
        #[range(0..2)] cosign: u8,
    ) {
        self.run(Step::Claim {
            leaf,
            amount,
            cosign: cosign == 1,
        });
    }

    pub fn action_cash(&mut self, #[range(0..5)] tree: u8) {
        self.run(Step::Cash { tree });
    }

    pub fn action_hold(&mut self, #[range(0..4)] claimant: u8) {
        self.run(Step::Hold { claimant });
    }

    pub fn action_release(&mut self, #[range(0..4)] claimant: u8) {
        self.run(Step::Release { claimant });
    }

    pub fn action_stop(&mut self, #[range(0..3)] level: u8) {
        self.run(Step::Stop { level });
    }

    pub fn action_extend_stop(&mut self) {
        self.run(Step::ExtendStop);
    }

    pub fn action_freeze(&mut self, #[range(0..2)] on: u8) {
        self.run(Step::Freeze { on: on == 1 });
    }

    pub fn action_extend_freeze(&mut self) {
        self.run(Step::ExtendFreeze);
    }

    pub fn action_escalate(&mut self) {
        self.run(Step::Escalate);
    }

    pub fn action_revoke(&mut self, #[range(0..12)] target: u8, #[range(0..2)] on: u8) {
        self.run(Step::Revoke {
            target,
            on: on == 1,
        });
    }

    pub fn action_arbiter(&mut self, #[range(0..6)] tree: u8) {
        self.run(Step::Arbiter { tree });
    }

    pub fn action_rotate(&mut self, #[range(0..9)] role: u8) {
        self.run(Step::Rotate { role });
    }

    pub fn action_set_limits(&mut self) {
        self.run(Step::SetLimits);
    }

    pub fn action_donate_tokens(&mut self, #[range(0..4)] amount: u8) {
        self.run(Step::DonateTokens { amount });
    }

    pub fn action_donate_lamports(&mut self) {
        self.run(Step::DonateLamports);
    }

    /// The adversary's move on the sponsor's proposal (Step::Proposal's six ops: approve or
    /// reject as the curator, expire it as anyone, submit one of its own from the sponsor's
    /// funding, donate a token to its vault, name its own key the curator).
    pub fn action_proposal(&mut self, #[range(0..6)] op: u8) {
        self.run(Step::Proposal { op });
    }

    /// The user sponsor's move (Step::Sponsor's five ops, BLAST_K=UserSponsor holding its key:
    /// submit terms of its own, the curator co-signing whatever they are (`pick` 0 to 8: the
    /// house's, itself or the curator as the resolver or the compliance key, a one-second resolve
    /// window, a million-SOL bond, a resolver of its own, refund_to another key); withdraw a
    /// proposal; send the way back to the adversary's account; reassign its associated token
    /// account's owner; fund its proposal's escrow or the world's).
    pub fn action_sponsor(&mut self, #[range(0..5)] op: u8, #[range(0..9)] pick: u8) {
        self.run(Step::Sponsor { op, pick });
    }

    /// The wind-down (Step::WindDown's ops: retire, close_escrow to its refund_to or to the
    /// adversary, close_config to the adversary, each under its best key as the admin; close
    /// every receipt there is, its fee payer the only signer).
    pub fn action_wind_down(&mut self, #[range(0..8)] op: u8) {
        self.run(Step::WindDown { op });
    }
}

/// After every action: the oracle found nothing (the blast radius within bound(K) and never before
/// challenge_deadline, nor under an overturn before attest_deadline, conservation, single claims,
/// single bond payments, one terminal state, privilege).
#[invariant_test]
fn blast_radius(fixture: &mut BlastFixture) {
    fuzz_assert!(
        fixture.model.violations.is_empty(),
        "{}",
        fixture.model.report()
    );
}
