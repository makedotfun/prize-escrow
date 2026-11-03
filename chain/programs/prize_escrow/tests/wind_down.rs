//! The wind-down, on the release build with mainnet's feature set (`node scripts/chain/build.ts
//! release` first), time moved by rewriting LiteSVM's Clock:
//! - retire is the admin's alone and one way; it refuses the four intake instructions (open_escrow,
//!   fund, submit_proposal, approve_proposal) and nothing that pays out or closes.
//! - close_escrow refuses each of its guards on its own: not retired, an escrow not Closed, a
//!   challenge's bond held, a commit's bond held, refund_to not the escrow's, not the admin.
//! - close_config refuses each of its guards on its own: not retired, value open or pending, an
//!   escrow not closed, not the admin, an admin that is not the upgrade authority.
//! - A full drill (an escrow through a dispute, a settle, a claim and a refund, a proposal's escrow,
//!   a rejected proposal) ends with no account the program owns, each party paid back exactly the
//!   accounts it was due.
//! - After close_config, initialize_config creates a fresh Config and the same competition id
//!   opens again.
//!
//! The world (keys, Config, escrow, trees) is tests/support/mod.rs.

mod mainnet;
mod program_so;
mod support;

use {
    anchor_lang::{
        error::ErrorCode as AnchorErrorCode,
        prelude::Pubkey,
        solana_program::instruction::Instruction,
        AccountDeserialize, AccountSerialize,
    },
    litesvm::LiteSVM,
    prize_escrow::{
        ChallengeRecord, CommitRecord, Config, ConfigClosed, ConfigRetired, Escrow, EscrowClosed,
        EscrowError, EscrowStatus,
    },
    solana_keypair::Keypair,
    std::collections::BTreeMap,
    support::{
        expect_ok, expect_refused, set_upgrade_authority, Chain, Panel, Role, Sent, Tree, World,
        CHALLENGE_WINDOW, FINAL_END, PENDING_CAP, PRIZES, TOTAL,
    },
};

/// The honest result posted at FINAL_END: its challenge window ends here.
const CHALLENGE_DEADLINE: i64 = FINAL_END + CHALLENGE_WINDOW;

/// Tree indices of World::trees.
const HONEST: usize = 0;
const STEAL: usize = 1;
const EVIL_ROOT: usize = 2;

/// The competition ids the tests propose (the world's own CID is its direct open).
const PCID: [u8; 16] = [0x7c; 16];
const OTHER: [u8; 16] = [0x7d; 16];
/// A rejection document's sha256.
const REASON: [u8; 32] = [0x4e; 32];

/// LiteSVM's fee: every signature of a transaction, the payer's included.
const FEE_PER_SIGNATURE: u64 = 5_000;

struct T {
    svm: LiteSVM,
    w: World,
    trees: Vec<Tree>,
}

impl T {
    /// The Config, and (with `open`) the escrow open with its entries root committed.
    fn new(open: bool) -> T {
        let mut svm = mainnet::svm();
        svm.add_program(prize_escrow::ID, program_so::bytes())
            .unwrap();
        let w = World::create(&mut svm, Panel::HouseMajority, open);
        let trees = w.trees();
        T { svm, w, trees }
    }

    fn at(&mut self, time: i64) {
        self.svm.set_time(time);
    }

    fn state(&self) -> Escrow {
        self.w.state(&self.svm).expect("the escrow")
    }

    fn config(&self) -> Config {
        self.w.config(&self.svm)
    }

    fn send(&mut self, ix: Instruction, signers: &[&Keypair]) -> Sent {
        self.w.send(&mut self.svm, ix, signers)
    }

    fn admin(&mut self, ix: Instruction) -> Sent {
        self.send(ix, &[Role::Admin.key()])
    }

    fn retire(&mut self) -> Sent {
        let ix = self.w.retire_ix(Role::Admin.pubkey());
        self.admin(ix)
    }

    /// close_escrow by the admin of the escrow at `escrow`, its lamports to `refund_to`.
    fn close_escrow(&mut self, escrow: Pubkey, refund_to: Pubkey) -> Sent {
        let ix = self
            .w
            .close_escrow_ix(Role::Admin.pubkey(), escrow, refund_to);
        self.admin(ix)
    }

    /// close_escrow by the admin of the world's escrow, to the sponsor.
    fn close_main(&mut self) -> Sent {
        let escrow = self.w.escrow();
        self.close_escrow(escrow, Role::Sponsor.pubkey())
    }

    fn close_config(&mut self, recipient: Pubkey) -> Sent {
        let ix = self.w.close_config_ix(Role::Admin.pubkey(), recipient);
        self.admin(ix)
    }

    fn policy(&mut self) {
        let ix =
            self.w
                .set_proposal_policy_ix(Role::Admin.pubkey(), Role::Curator.pubkey(), PENDING_CAP);
        expect_ok(self.admin(ix), "set_proposal_policy");
    }

    /// submit_proposal of `cid` now by the sponsor from its funding account, the curator
    /// co-signing.
    fn submit(&mut self, cid: [u8; 16]) -> Sent {
        let (terms, opens_at, review_deadline) = World::proposal_terms(self.svm.time());
        let ix = self.w.submit_proposal_ix(
            Role::Sponsor.pubkey(),
            Role::Curator.pubkey(),
            self.w.funding,
            cid,
            &terms,
            opens_at,
            review_deadline,
        );
        self.send(ix, &[Role::Sponsor.key(), Role::Curator.key()])
    }

    fn approve(&mut self, cid: [u8; 16]) -> Sent {
        let ix = self
            .w
            .approve_proposal_ix(Role::Curator.pubkey(), Role::Sponsor.pubkey(), cid);
        self.send(ix, &[Role::Curator.key()])
    }

    fn reject(&mut self, cid: [u8; 16]) -> Sent {
        let ix =
            self.w
                .close_proposal_ix(Role::Curator.pubkey(), Role::Sponsor.pubkey(), cid, REASON);
        self.send(ix, &[Role::Curator.key()])
    }

    fn post(&mut self) -> Sent {
        let ix = self
            .w
            .post_ix(Role::Resolver.pubkey(), &self.trees[HONEST], TOTAL);
        self.send(ix, &[Role::Resolver.key()])
    }

    fn challenge(&mut self, by: Role, tree: usize) -> Sent {
        let tree = self.trees[tree].clone();
        self.w.challenge_with(&mut self.svm, by.key(), &tree)
    }

    /// A commit of `by`'s challenge with `tree`, never revealed: its hash.
    fn commit_only(&mut self, by: Role, tree: usize) -> [u8; 32] {
        let (hash, _) = self.w.commit_of(&by.pubkey(), &self.trees[tree]);
        let ix = self.w.challenge_commit_ix(by.pubkey(), hash);
        expect_ok(self.send(ix, &[by.key()]), "challenge_commit");
        hash
    }

    fn attest(&mut self, regrader: Role, commitment: [u8; 32]) -> Sent {
        let ix = self.w.attest_ix(&self.svm, regrader.pubkey(), commitment);
        self.send(ix, &[regrader.key()])
    }

    fn settle(&mut self) -> Sent {
        let ix = self.w.settle_ix(&self.state());
        self.send(ix, &[])
    }

    fn refund(&mut self) -> Sent {
        let ix = self.w.refund_ix(&self.state());
        self.send(ix, &[])
    }

    /// `winner` claims its whole leaf of the honest tree, the compliance key co-signing.
    fn claim(&mut self, winner: Role) -> Sent {
        let t = &self.trees[HONEST];
        let leaf = t.leaf_of(&winner.pubkey()).expect("a leaf");
        let ix = self.w.claim_ix(
            winner.pubkey(),
            Some(Role::Compliance.pubkey()),
            t.leaves[leaf].1,
            0,
            t.proofs[leaf].clone(),
        );
        self.send(ix, &[winner.key(), Role::Compliance.key()])
    }

    fn close_challenge(&mut self, tree: usize) -> Sent {
        let commitment = self.trees[tree].commitment;
        let challenge = self
            .w
            .challenge(&self.svm, &commitment)
            .expect("the challenge");
        let ix = self.w.close_challenge_ix(&challenge);
        self.send(ix, &[])
    }

    fn close_commit(&mut self, challenger: Role, hash: [u8; 32]) -> Sent {
        let commit = self.w.commit_pda(&challenger.pubkey(), &hash);
        let ix = self.w.close_commit_ix(&commit, challenger.pubkey());
        self.send(ix, &[])
    }

    /// Every account the program owns that holds lamports, by address.
    fn program_accounts(&self) -> BTreeMap<Pubkey, u64> {
        self.svm
            .get_program_accounts(&prize_escrow::ID)
            .into_iter()
            .filter(|(_, account)| account.lamports > 0)
            .map(|(address, account)| (address, account.lamports))
            .collect()
    }

    /// Rewrites the Anchor account at `address` with `edit` applied (its layout unchanged): a
    /// guard tested alone on an account every other guard accepts.
    fn patch<A: AccountSerialize + AccountDeserialize>(
        &mut self,
        address: &Pubkey,
        edit: impl FnOnce(&mut A),
    ) {
        let mut account = self.svm.get_account(address).expect("the account");
        let mut state = A::try_deserialize(&mut account.data.as_slice()).expect("its state");
        edit(&mut state);
        let mut data: &mut [u8] = &mut account.data;
        state.try_serialize(&mut data).expect("its state written back");
        self.svm.set_account(*address, account).unwrap();
    }

    fn patch_escrow(&mut self, edit: impl FnOnce(&mut Escrow)) {
        let escrow = self.w.escrow();
        self.patch(&escrow, edit);
    }

    fn patch_config(&mut self, edit: impl FnOnce(&mut Config)) {
        self.patch(&Config::pda().0, edit);
    }
}

// ------------------------------------------------------------------------------- retire

/// retire is the admin's alone and one way. Once retired, open_escrow, fund, submit_proposal and
/// approve_proposal refuse with Retired and change nothing; the curator's rejection still runs
/// (the payouts, settle, claims and refunds run after retire in the full drill below).
#[test]
fn retire_stops_intake_for_good() {
    let mut t = T::new(true);
    t.policy();
    expect_ok(t.submit(PCID), "submit_proposal");
    expect_ok(t.submit(OTHER), "submit_proposal");
    let before = t.config();
    assert_eq!(
        (before.open_value, before.live_escrows, before.retired),
        (TOTAL, 1, false),
        "the open counted"
    );

    for who in [Role::Guardian, Role::Arbiter, Role::Curator, Role::Attacker(0)] {
        let ix = t.w.retire_ix(who.pubkey());
        expect_refused(
            t.send(ix, &[who.key()]),
            EscrowError::UnauthorizedAdmin,
            &format!("retire by {who:?}"),
        );
    }
    assert!(!t.config().retired);

    let retired = expect_ok(t.retire(), "retire").event::<ConfigRetired>();
    assert_eq!(
        (
            retired.config,
            retired.by,
            retired.open_value,
            retired.pending_value,
            retired.live_escrows
        ),
        (
            Config::pda().0,
            Role::Admin.pubkey(),
            TOTAL,
            before.pending_value,
            1
        )
    );
    assert!(before.pending_value > 0, "two proposals pending");
    assert!(t.config().retired);
    expect_refused(t.retire(), EscrowError::Retired, "retire twice");

    // The four intake instructions, each with terms that would otherwise pass.
    let terms = World::default_terms();
    let open = t.w.open_ix_at(
        Role::Sponsor.pubkey(),
        t.w.funding,
        t.w.mint,
        [0x11; 16],
        &terms,
    );
    expect_refused(
        t.send(open, &[Role::Sponsor.key()]),
        EscrowError::Retired,
        "open_escrow",
    );
    let fund = t.w.fund_ix(Role::Sponsor.pubkey(), 1);
    expect_refused(
        t.send(fund, &[Role::Sponsor.key()]),
        EscrowError::Retired,
        "fund",
    );
    expect_refused(t.submit([0x12; 16]), EscrowError::Retired, "submit_proposal");
    expect_refused(t.approve(PCID), EscrowError::Retired, "approve_proposal");
    let after = t.config();
    assert_eq!(
        (after.open_value, after.pending_value, after.live_escrows),
        (TOTAL, before.pending_value, 1),
        "intake changed nothing"
    );
    assert_eq!(t.state().deposited, TOTAL, "nothing funded");

    // What winds down still runs: both proposals rejected, their deposits back.
    expect_ok(t.reject(PCID), "close_proposal");
    expect_ok(t.reject(OTHER), "close_proposal");
    assert_eq!(t.config().pending_value, 0);
    assert!(t.config().retired, "for good");
}

// ------------------------------------------------------------------------------- close_escrow

/// close_escrow refuses each guard on its own: before retire (NotRetired), an escrow not Closed
/// (InvalidStatus), a challenge's bond still held (ChallengesOutstanding), a commit's bond or a
/// pending commit (CommitsOutstanding), another refund_to (ConstraintHasOne), a signer not the
/// admin (UnauthorizedAdmin). The dispute here decides nothing, so the refund leaves both bonds in
/// the escrow until close_challenge and close_commit pay them back.
#[test]
fn close_escrow_refuses_each_guard_on_its_own() {
    let mut t = T::new(true);
    let escrow = t.w.escrow();
    t.at(FINAL_END);
    expect_ok(t.post(), "post_result");
    t.at(FINAL_END + 60);
    expect_ok(t.challenge(Role::Attacker(2), STEAL), "a challenge");
    let hash = t.commit_only(Role::Attacker(3), EVIL_ROOT);
    expect_refused(t.close_main(), EscrowError::NotRetired, "before retire");
    expect_ok(t.retire(), "retire");
    expect_refused(t.close_main(), EscrowError::InvalidStatus, "a Disputed escrow");

    // No vote: past hard_deadline the refund decides nothing and holds both bonds.
    let hard_deadline = t.state().hard_deadline;
    t.at(hard_deadline + 1);
    expect_ok(t.refund(), "refund");
    let closed = t.state();
    assert_eq!(closed.status, EscrowStatus::Closed);
    assert!(closed.challenger_bond > 0 && closed.commit_bond > 0);
    assert_eq!(closed.pending_commits, 1);
    expect_refused(
        t.close_main(),
        EscrowError::ChallengesOutstanding,
        "a challenge's bond held",
    );
    expect_ok(t.close_challenge(STEAL), "close_challenge");
    assert_eq!(t.state().challenger_bond, 0);
    expect_refused(
        t.close_main(),
        EscrowError::CommitsOutstanding,
        "a commit's bond held",
    );
    expect_ok(t.close_commit(Role::Attacker(3), hash), "close_commit");
    assert_eq!((t.state().commit_bond, t.state().pending_commits), (0, 0));

    // Each guard alone, on the escrow every other guard now accepts.
    t.patch_escrow(|e| e.status = EscrowStatus::Claimable);
    expect_refused(t.close_main(), EscrowError::InvalidStatus, "Claimable");
    t.patch_escrow(|e| e.status = EscrowStatus::Closed);
    t.patch_escrow(|e| e.challenger_bond = 1);
    expect_refused(
        t.close_main(),
        EscrowError::ChallengesOutstanding,
        "challenger_bond alone",
    );
    t.patch_escrow(|e| e.challenger_bond = 0);
    t.patch_escrow(|e| e.commit_bond = 1);
    expect_refused(
        t.close_main(),
        EscrowError::CommitsOutstanding,
        "commit_bond alone",
    );
    t.patch_escrow(|e| e.commit_bond = 0);
    t.patch_escrow(|e| e.pending_commits = 1);
    expect_refused(
        t.close_main(),
        EscrowError::CommitsOutstanding,
        "pending_commits alone",
    );
    t.patch_escrow(|e| e.pending_commits = 0);
    t.patch_config(|c| c.retired = false);
    expect_refused(t.close_main(), EscrowError::NotRetired, "retired alone");
    t.patch_config(|c| c.retired = true);
    expect_refused(
        t.close_escrow(escrow, Role::Attacker(0).pubkey()),
        AnchorErrorCode::ConstraintHasOne,
        "the lamports to another key",
    );
    for who in [Role::Guardian, Role::Curator, Role::Sponsor, Role::Attacker(0)] {
        let ix = t
            .w
            .close_escrow_ix(who.pubkey(), escrow, Role::Sponsor.pubkey());
        expect_refused(
            t.send(ix, &[who.key()]),
            EscrowError::UnauthorizedAdmin,
            &format!("close_escrow by {who:?}"),
        );
    }

    let lamports = t.svm.lamports(&escrow);
    let sponsor = t.svm.lamports(&Role::Sponsor.pubkey());
    let event = expect_ok(t.close_main(), "close_escrow").event::<EscrowClosed>();
    assert_eq!(
        (
            event.escrow,
            event.competition_id,
            event.sponsor,
            event.refund_to,
            event.lamports,
            event.live_escrows
        ),
        (
            escrow,
            t.w.cid,
            Role::Sponsor.pubkey(),
            Role::Sponsor.pubkey(),
            lamports,
            0
        )
    );
    assert_eq!(t.svm.lamports(&Role::Sponsor.pubkey()), sponsor + lamports);
    assert_eq!(t.svm.lamports(&escrow), 0);
    assert!(t.w.state(&t.svm).is_none());
    assert_eq!(t.config().live_escrows, 0);
    expect_refused(
        t.close_main(),
        AnchorErrorCode::AccountNotInitialized,
        "a second close",
    );
}

// ------------------------------------------------------------------------------- close_config

/// close_config refuses each guard on its own: before retire (NotRetired), a deposit open or
/// pending (ValueOutstanding), an escrow not closed (EscrowsOutstanding), a signer not the admin
/// (UnauthorizedAdmin), and an admin that is not the program's upgrade authority, another key or
/// none (NotUpgradeAuthority). Then it closes, its rent to the recipient.
#[test]
fn close_config_refuses_each_guard_on_its_own() {
    let mut t = T::new(true);
    t.policy();
    expect_ok(t.submit(PCID), "submit_proposal");
    let admin = Role::Admin.pubkey();
    expect_refused(t.close_config(admin), EscrowError::NotRetired, "before retire");
    expect_ok(t.retire(), "retire");
    expect_refused(
        t.close_config(admin),
        EscrowError::ValueOutstanding,
        "an escrow and a proposal",
    );
    expect_ok(t.reject(PCID), "close_proposal");
    expect_refused(
        t.close_config(admin),
        EscrowError::ValueOutstanding,
        "an escrow's deposit",
    );
    let hard_deadline = t.state().hard_deadline;
    t.at(hard_deadline + 1);
    expect_ok(t.refund(), "refund");
    assert_eq!(
        (t.config().open_value, t.config().live_escrows),
        (0, 1),
        "refunded, not closed"
    );
    expect_refused(
        t.close_config(admin),
        EscrowError::EscrowsOutstanding,
        "an escrow not closed",
    );
    expect_ok(t.close_main(), "close_escrow");

    // Each guard alone, on the Config every other guard now accepts.
    t.patch_config(|c| c.retired = false);
    expect_refused(t.close_config(admin), EscrowError::NotRetired, "retired alone");
    t.patch_config(|c| c.retired = true);
    t.patch_config(|c| c.open_value = 1);
    expect_refused(
        t.close_config(admin),
        EscrowError::ValueOutstanding,
        "open_value alone",
    );
    t.patch_config(|c| c.open_value = 0);
    t.patch_config(|c| c.pending_value = 1);
    expect_refused(
        t.close_config(admin),
        EscrowError::ValueOutstanding,
        "pending_value alone",
    );
    t.patch_config(|c| c.pending_value = 0);
    t.patch_config(|c| c.live_escrows = 1);
    expect_refused(
        t.close_config(admin),
        EscrowError::EscrowsOutstanding,
        "live_escrows alone",
    );
    t.patch_config(|c| c.live_escrows = 0);

    // The admin, as the upgrade authority: another upgrade authority, or none, refuses it, and
    // that other key cannot sign as the admin.
    set_upgrade_authority(&mut t.svm, Some(Role::Guardian.pubkey()));
    expect_refused(
        t.close_config(admin),
        EscrowError::NotUpgradeAuthority,
        "the upgrade authority another key",
    );
    let ix = t
        .w
        .close_config_ix(Role::Guardian.pubkey(), Role::Guardian.pubkey());
    expect_refused(
        t.send(ix, &[Role::Guardian.key()]),
        EscrowError::UnauthorizedAdmin,
        "the upgrade authority, not the admin",
    );
    set_upgrade_authority(&mut t.svm, None);
    expect_refused(
        t.close_config(admin),
        EscrowError::NotUpgradeAuthority,
        "an immutable program",
    );
    set_upgrade_authority(&mut t.svm, Some(admin));
    for who in [Role::Arbiter, Role::Curator, Role::Attacker(0)] {
        let ix = t.w.close_config_ix(who.pubkey(), who.pubkey());
        expect_refused(
            t.send(ix, &[who.key()]),
            EscrowError::UnauthorizedAdmin,
            &format!("close_config by {who:?}"),
        );
    }

    let config = Config::pda().0;
    let lamports = t.svm.lamports(&config);
    let recipient = Role::Spare(1).pubkey();
    let to = t.svm.lamports(&recipient);
    let closed = expect_ok(t.close_config(recipient), "close_config").event::<ConfigClosed>();
    assert_eq!(
        (closed.config, closed.by, closed.recipient, closed.lamports),
        (config, admin, recipient, lamports)
    );
    assert_eq!(t.svm.lamports(&recipient), to + lamports);
    assert_eq!(t.svm.lamports(&config), 0);
    assert!(t.program_accounts().is_empty(), "nothing left");
}

// ------------------------------------------------------------------------------- the drill

/// The whole wind-down. A direct escrow runs a dispute (a challenge revealed, a commit never
/// revealed, the house quorum), settles, pays one winner and refunds the rest; a proposal's escrow
/// (its rent the curator's) refunds unresolved; another proposal is rejected. Every one of those
/// runs after retire. Then the permissionless closes (nobody's key but the payer's) empty both
/// escrows of their children, the admin closes each escrow and the Config, and the program owns
/// no account. Each party gets back exactly the accounts (and the commit's bond) it was due, the
/// payer pays every fee and nothing else, and no other key moves a lamport.
#[test]
fn a_full_wind_down_leaves_no_program_account() {
    let mut t = T::new(true);
    t.policy();
    expect_ok(t.submit(PCID), "submit_proposal");
    expect_ok(t.submit(OTHER), "submit_proposal");
    expect_ok(t.approve(PCID), "approve_proposal");
    assert_eq!(t.config().live_escrows, 2, "the open and the approval");
    expect_ok(t.retire(), "retire");

    // After retire: the rejection, the result, its dispute, settle, a claim, both refunds.
    expect_ok(t.reject(OTHER), "close_proposal");
    t.at(FINAL_END);
    expect_ok(t.post(), "post_result");
    t.at(FINAL_END + 60);
    expect_ok(t.challenge(Role::Attacker(2), STEAL), "a challenge");
    let hash = t.commit_only(Role::Attacker(3), EVIL_ROOT);
    let posted = t.state().commitment;
    expect_ok(t.attest(Role::Regrader(0), posted), "seat 0");
    expect_ok(t.attest(Role::Regrader(1), posted), "seat 1");
    let reveal_deadline = t.state().reveal_deadline().unwrap();
    t.at(CHALLENGE_DEADLINE.max(reveal_deadline));
    expect_ok(t.settle(), "settle");
    assert_eq!(t.state().status, EscrowStatus::Claimable);
    expect_ok(t.claim(Role::Winner(0)), "claim");
    assert_eq!(
        t.svm.tokens(&t.w.ata(&Role::Winner(0).pubkey())),
        PRIZES[0]
    );
    let sponsor = Role::Sponsor.pubkey();
    let proposed = t.w.escrow_at(&sponsor, &PCID);
    let proposed_state = t
        .w
        .escrow_state_at(&t.svm, &sponsor, &PCID)
        .expect("the proposal's escrow");
    assert_eq!(proposed_state.refund_to, sponsor);
    let claim_deadline = t.state().claim_deadline;
    t.at(claim_deadline.max(proposed_state.hard_deadline) + 1);
    expect_ok(t.refund(), "refund");
    let refund = t.w.refund_at_ix(proposed, &proposed_state, None);
    expect_ok(t.send(refund, &[]), "refund of the proposal's escrow");
    let config = t.config();
    assert_eq!(
        (config.open_value, config.pending_value, config.live_escrows),
        (0, 0, 2)
    );

    // What the program holds now, and to whom each account goes.
    let escrow = t.w.escrow();
    let challenge = t.w.challenge_pda(&t.trees[STEAL].commitment);
    let commit = t.w.commit_pda(&Role::Attacker(3).pubkey(), &hash);
    let commit_bond = t
        .svm
        .anchor::<CommitRecord>(&commit)
        .expect("the commit")
        .bond;
    assert!(t.svm.anchor::<ChallengeRecord>(&challenge).is_some());
    let due: [(Pubkey, Role); 8] = [
        (t.w.receipt(&Role::Winner(0).pubkey()), Role::Winner(0)),
        (challenge, Role::Attacker(2)),
        (commit, Role::Attacker(3)),
        (t.w.attestation(&Role::Regrader(0).pubkey()), Role::Regrader(0)),
        (t.w.attestation(&Role::Regrader(1).pubkey()), Role::Regrader(1)),
        (escrow, Role::Sponsor),
        (proposed, Role::Sponsor),
        (Config::pda().0, Role::Admin),
    ];
    let held = t.program_accounts();
    let mut expected: Vec<Pubkey> = due.iter().map(|(address, _)| *address).collect();
    expected.sort();
    assert_eq!(
        held.keys().copied().collect::<Vec<_>>(),
        expected,
        "the program's accounts"
    );
    let mut owed: BTreeMap<Role, i128> = BTreeMap::new();
    for (address, role) in due {
        *owed.entry(role).or_default() += i128::from(held[&address]);
    }
    // The commit's bond sits in the escrow account: it goes to its challenger, not the sponsor.
    *owed.entry(Role::Sponsor).or_default() -= i128::from(commit_bond);
    *owed.entry(Role::Attacker(3)).or_default() += i128::from(commit_bond);
    let before: Vec<(Role, u64)> = Role::all()
        .into_iter()
        .map(|role| (role, t.svm.lamports(&role.pubkey())))
        .collect();

    // The children first, nobody but the payer signing, then the escrows and the Config.
    let mut signatures = 0;
    let ix = t.w.close_receipt_ix(Role::Winner(0).pubkey());
    expect_ok(t.send(ix, &[]), "close_receipt");
    expect_ok(t.close_challenge(STEAL), "close_challenge");
    expect_ok(t.close_commit(Role::Attacker(3), hash), "close_commit");
    for seat in 0..2 {
        let ix = t.w.close_attestation_ix(Role::Regrader(seat).pubkey());
        expect_ok(t.send(ix, &[]), "close_attestation");
    }
    signatures += 5;
    let closed = expect_ok(t.close_main(), "close_escrow").event::<EscrowClosed>();
    assert_eq!(
        (closed.lamports, closed.live_escrows),
        (held[&escrow] - commit_bond, 1)
    );
    let closed = expect_ok(t.close_escrow(proposed, sponsor), "close_escrow")
        .event::<EscrowClosed>();
    assert_eq!(
        (closed.escrow, closed.lamports, closed.live_escrows),
        (proposed, held[&proposed], 0)
    );
    let closed = expect_ok(t.close_config(Role::Admin.pubkey()), "close_config")
        .event::<ConfigClosed>();
    assert_eq!(closed.lamports, held[&Config::pda().0]);
    signatures += 3 * 2;
    assert!(t.program_accounts().is_empty(), "the program owns nothing");

    *owed.entry(Role::Payer).or_default() -= i128::from(FEE_PER_SIGNATURE * signatures);
    for (role, was) in before {
        let delta = i128::from(t.svm.lamports(&role.pubkey())) - i128::from(was);
        assert_eq!(
            delta,
            owed.get(&role).copied().unwrap_or(0),
            "{role:?}'s lamports"
        );
    }
}

// ------------------------------------------------------------------------------- start over

/// After close_config the upgrade authority's initialize_config creates a fresh Config at the same
/// PDA, not retired and counting nothing, and the sponsor opens the same competition id again: the
/// deployment starts over without a new program id.
#[test]
fn a_closed_config_initializes_afresh() {
    let mut t = T::new(true);
    expect_ok(t.retire(), "retire");
    let hard_deadline = t.state().hard_deadline;
    t.at(hard_deadline + 1);
    expect_ok(t.refund(), "refund");
    expect_ok(t.close_main(), "close_escrow");
    expect_ok(t.close_config(Role::Admin.pubkey()), "close_config");
    assert!(t.program_accounts().is_empty());

    let init = t.w.initialize_config_ix(
        Role::Admin.pubkey(),
        World::config_init(Panel::HouseMajority, t.w.mint),
    );
    expect_ok(t.admin(init), "initialize_config again");
    let fresh = t.config();
    assert_eq!(
        (
            fresh.admin,
            fresh.retired,
            fresh.live_escrows,
            fresh.open_value,
            fresh.pending_value
        ),
        (Role::Admin.pubkey(), false, 0, 0, 0)
    );
    let (terms, _, _) = World::proposal_terms(t.svm.time());
    let open = t.w.open_ix(&terms);
    expect_ok(
        t.send(open, &[Role::Sponsor.key()]),
        "open_escrow at the same competition id",
    );
    assert_eq!(t.state().status, EscrowStatus::Open);
    assert_eq!(
        (t.config().live_escrows, t.config().open_value),
        (1, TOTAL)
    );
}
