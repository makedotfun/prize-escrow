//! The blast-radius oracle. The adversary holds a key set K (`Compromise`: the resolver, the
//! compliance key, one house regrader, all the house's keys, one multisig member, the guardian,
//! or the house's keys with the guardian) plus keys of its own, and plays any sequence of `Step`s:
//! every instruction, signed by a key it holds where it holds one and by its own key where it
//! does not (an impersonation the program must refuse), wall time moving, tokens and lamports
//! donated. Every party it does not hold is honest and live, but never faster than the adversary:
//! the adversary moves first at every instant, and the honest parties react before wall time moves
//! on (`Wait`, at most MAX_LATENCY; `Approach`, to just before a deadline of the adversary's
//! choosing) and never stay blind for more than BLIND seconds (`Tick`, the adversary's own few
//! seconds, as across a deadline). Reacting, the resolver posts the honest result, the watcher
//! challenges any other with the honest alternative, the free regraders vote the honest side, the
//! guardian escalates to the arbiter a result the watcher cannot rebuild (posted, or a quorum's) the
//! honest side has no quorum against, and after the challenge window any dispute or pending commit
//! without an honest quorum (the program refuses it once a recorded quorum may settle:
//! QuorumRecorded, and an unchallenged result once its window and any reveal grace are over:
//! UnchallengedResultBinds), the arbiter applies the honest side, the compliance key holds every
//! claimant the honest rubric does not pay (F7's rule, fail-closed), the winners claim, and a crank
//! settles, refunds and closes what it may.
//!
//! After every transaction (the adversary's and the honest parties') the oracle asserts:
//! - the blast radius: the USDC the adversary's keys (and anyone but the honest winners, up to
//!   their prizes, and the sponsor's refund) received, less what it donated, is at most
//!   `Compromise::bound`; and none of it moved before challenge_deadline on the escrow clock, nor,
//!   while an alternative that overturned the posted result is in force, before attest_deadline;
//! - conservation per mint: vault + claimed + refunded == deposited + donated, and every token of
//!   the mint stays in an account the oracle knows;
//! - no leaf is claimed twice: each claimant's tokens are its receipt's amount_claimed, at most its
//!   leaf, and a leaf of the root in force;
//! - each bond is paid exactly once: the bonds taken in equal the bonds paid out plus those held,
//!   and the escrow account holds exactly its rent, the bonds held and any lamports donated;
//! - one terminal state: the status only moves along the lifecycle's edges, Closed is final, and
//!   the result in force never changes once Claimable;
//! - privilege: no instruction that needs a role the adversary does not hold succeeds for it, and
//!   the guardian only ever escalates the stop;
//! - the user sponsor's proposal, when the world has one (World::open_proposals: a sponsor off the
//!   allowlist; the curator's key is among the house's, and `Compromise::Curator` holds it alone):
//!   its deposit is conserved, it leaves only approved, into an escrow holding exactly the
//!   sponsor's terms, or returned to the sponsor, an approval lands by review_deadline and an
//!   expiry only after it, the escrow an approval opened is refunded to the sponsor once due, and
//!   Config's open_value and pending_value are always the open deposits. The honest curator
//!   approves a day into the review; the crank returns the proposal once review_deadline has
//!   passed, and refunds its escrow once due.
//! - the user sponsor's own moves (`Compromise::UserSponsor` holds its key alone; Step::Sponsor):
//!   a second proposal (USER_CID) on terms it chose, which the curator co-signs whatever they are
//!   (its co-signature screens the sponsor, not the terms: the house's own check of the terms is
//!   the server's) and rejects at its first look, since it approves only terms the house composed;
//!   so the program alone holds the terms, and no proposal it accepts names the sponsor or the
//!   curator as its resolver or compliance key, a resolve window under MIN_RESOLVE_WINDOW or a
//!   bond over MAX_PROPOSAL_BOND. Its associated token account's owner reassigned away (the #852
//!   audit's P2-2), the honest parties return what is its to a token account they create for it
//!   (close_proposal's and refund's `destination`), so nothing it does pins pending_value or
//!   open_value; and it never funds an escrow once its proposal opened it (the #852 audit's P3-3).
//!
//! The bound: 0 for every K except the house's keys with the guardian's (or the guardian asleep)
//! on a panel the house holds a quorum of (owner decision #541 allows it today): they vote a false
//! result through and claim it once the challenge window is over (an overturn once the attest
//! window is), so their bound is the pot. The house's keys alone, the guardian honest, move
//! nothing on that panel either. Until #749 they did (#536's finding): with the honest result
//! posted, a challenge committed on the window's last second was revealed in the reveal grace,
//! voted to k by the house's quorum and applied by settle at challenge_deadline, all inside BLIND,
//! before the guardian could look. Now settle applies an overturn only at attest_deadline, so the
//! guardian's next look finds the recorded alternative inside the attest window and escalates it
//! (`a_house_quorum_cannot_apply_a_challenge_revealed_in_the_grace` in tests/blast_radius.rs); and a
//! false posted result whose quorum the house records in the same second is still escalated
//! inside the challenge window, since escalate refuses a recorded quorum only once settle may
//! apply it (`a_house_quorum_recorded_before_the_guardian_looks_is_still_escalated`). The curator
//! alone holds no role in an open escrow and moves nothing of a proposal but into the escrow its
//! sponsor's terms open, or back to the sponsor: its bound is 0, and the winners are paid. The
//! user sponsor alone holds no role in any escrow but its own escrow's refund_to: whatever terms
//! it submits, whatever it does to its own token accounts and whatever it tries to fund, its bound
//! against everyone else's funds is 0, and the winners are paid.

use {
    super::*,
    prize_escrow::{
        ArbiterResolved, ChallengeClosed, ChallengeCommitted, CommitClosed, EscrowStatus,
        ProposalApproved, ProposalCloseKind, ProposalClosed, ProposalSubmitted, ReceiptClosed,
        Refunded, ResultPosted, Settled, MAX_PROPOSAL_BOND, MIN_RESOLVE_WINDOW,
    },
};

/// The rejection reason the curator names (any non-zero sha256).
const REASON: [u8; 32] = [0x4e; 32];

/// The longest wall time between two honest reactions: well inside every window (the shortest,
/// the challenge, attest and hold windows, are 24 h).
pub const MAX_LATENCY: i64 = 12 * HOUR;

/// The longest the adversary acts with no honest reaction since its last move: a minute, far
/// faster than the guardian (a key never on the server) reacts.
pub const BLIND: i64 = 60;

/// The key set K the adversary holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compromise {
    Nobody,
    Resolver,
    Compliance,
    OneHouseRegrader,
    /// The resolver, the compliance key and every house regrader: what a server compromise yields.
    AllHouseKeys,
    MultisigMember,
    Guardian,
    /// The house's keys and the guardian's (or a guardian asleep): the case the guardian exists for.
    AllHouseKeysAndGuardian,
    /// The Config's curator alone: it co-signs submits and approves or rejects proposals, and
    /// can do nothing else. Its proposal moves (Step::Proposal) run against the sponsor's
    /// proposal open_proposals submitted, and the oracle holds it to approving the terms as the
    /// sponsor submitted them or returning the deposit to the sponsor.
    Curator,
    /// A malicious user sponsor (Role::UserSponsor: off the allowlist, the sponsor of the
    /// world's proposal) alone: it submits a proposal on terms of its choosing, withdraws, sends
    /// the way back elsewhere, reassigns its associated token account's owner and tries to fund
    /// (Step::Sponsor), and holds no other role.
    UserSponsor,
}

impl Compromise {
    pub const ALL: [Compromise; 10] = [
        Compromise::Nobody,
        Compromise::Resolver,
        Compromise::Compliance,
        Compromise::OneHouseRegrader,
        Compromise::AllHouseKeys,
        Compromise::MultisigMember,
        Compromise::Guardian,
        Compromise::AllHouseKeysAndGuardian,
        Compromise::Curator,
        Compromise::UserSponsor,
    ];

    /// The roles whose keys the adversary holds. The curator's key is the server's (owner
    /// decision 1's default), so the house's keys include it.
    pub fn roles(self, panel: Panel) -> Vec<Role> {
        let house = || {
            let mut keys = vec![Role::Resolver, Role::Compliance, Role::Curator];
            keys.extend((0..SEATS).filter(|s| panel.house(*s)).map(Role::Regrader));
            keys
        };
        match self {
            Compromise::Nobody => vec![],
            Compromise::Resolver => vec![Role::Resolver],
            Compromise::Compliance => vec![Role::Compliance],
            Compromise::OneHouseRegrader => vec![Role::Regrader(0)],
            Compromise::AllHouseKeys => house(),
            Compromise::MultisigMember => vec![Role::Member],
            Compromise::Guardian => vec![Role::Guardian],
            Compromise::AllHouseKeysAndGuardian => {
                let mut keys = house();
                keys.push(Role::Guardian);
                keys
            }
            Compromise::Curator => vec![Role::Curator],
            Compromise::UserSponsor => vec![Role::UserSponsor],
        }
    }

    /// bound(K): the most of the sponsor's pot the adversary may move outside the honest rubric.
    /// The pot only for the house's keys with the guardian's on a panel the house holds a quorum
    /// of; the house's keys alone, the guardian honest, move nothing (see the module header).
    pub fn bound(self, panel: Panel) -> u64 {
        match (self, panel) {
            (Compromise::AllHouseKeysAndGuardian, Panel::HouseMajority) => TOTAL,
            _ => 0,
        }
    }

    /// Whether the honest winners must end with their whole prizes (nobody who could grief them
    /// is compromised: neither the curator nor the user sponsor holds a role in the world's
    /// escrow).
    pub fn winners_paid(self) -> bool {
        matches!(
            self,
            Compromise::Nobody
                | Compromise::MultisigMember
                | Compromise::Curator
                | Compromise::UserSponsor
        )
    }
}

/// One move of the fuzzer. Indices are taken modulo what they index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Every honest party reacts, then wall time moves `secs` (1 to MAX_LATENCY) and a slot passes.
    Wait(u32),
    /// The honest parties react, wall time standing still.
    React,
    /// Wall time moves `secs` (1 to BLIND) and a slot passes with no honest reaction, unless the
    /// honest parties would then have been blind for more than BLIND (they react first).
    Tick(u8),
    /// The honest parties react, then wall time moves to `before` (1 to BLIND) seconds of the
    /// escrow clock before one of the escrow's deadlines (challenge, reveal, attest, claim, hard,
    /// entries, resolve), at most MAX_LATENCY ahead: the adversary moves first there.
    Approach {
        deadline: u8,
        before: u8,
    },
    /// The adversary's challenger `by` reveals its pending commit of tree `tree`.
    Reveal {
        tree: u8,
        by: u8,
    },
    /// post_result with tree `tree` and a total from: its own, TOTAL, the vault, 1, its own - 1.
    Post {
        tree: u8,
        total: u8,
    },
    CommitEntries,
    /// A challenge with tree `tree` by the adversary's challenger `by`, revealed or left pending.
    Challenge {
        tree: u8,
        by: u8,
        reveal: bool,
    },
    /// Seat `seat` votes tree `tree`'s commitment (one past the trees: the posted commitment).
    Attest {
        seat: u8,
        tree: u8,
    },
    Settle,
    Refund,
    CloseChallenges,
    CloseCommits,
    /// request_claim of leaf `leaf` (of every tree's leaves, in order).
    RequestClaim {
        leaf: u8,
    },
    /// claim of leaf `leaf`, `amount` from: all, 1, half, the leaf, the leaf + 1.
    Claim {
        leaf: u8,
        amount: u8,
        cosign: bool,
    },
    Hold {
        claimant: u8,
    },
    Release {
        claimant: u8,
    },
    /// set_stop to Normal, IntakeStop or PayoutStop.
    Stop {
        level: u8,
    },
    ExtendStop,
    Freeze {
        on: bool,
    },
    ExtendFreeze,
    Escalate,
    Revoke {
        target: u8,
        on: bool,
    },
    /// arbiter_resolve: Posted (tree past the trees) or the challenge of tree `tree`.
    Arbiter {
        tree: u8,
    },
    /// rotate_role: resolver, compliance or a seat, to a spare.
    Rotate {
        role: u8,
    },
    /// set_limits raising every cap.
    SetLimits,
    /// Tokens into the vault from the adversary: 1, 10^6, a tenth of the pot, the pot.
    DonateTokens {
        amount: u8,
    },
    /// 1 SOL into the escrow account.
    DonateLamports,
    /// Every seat the adversary holds votes tree `tree`'s commitment (one past the trees: the
    /// posted one): a quorum's worth of Attest steps at once.
    Vote {
        tree: u8,
    },
    /// Each of the adversary's claimants in tree `tree` takes its leaf: co-signed when the
    /// adversary holds the compliance key, else a request and then a claim on the lapse path.
    Cash {
        tree: u8,
    },
    /// A move on the sponsor's proposal (World::open_proposals; nothing without one), `op` of:
    /// approve it as the curator, reject it as the curator with a reason, close it as anyone
    /// (an expiry), submit one more spending the sponsor's funding account under the adversary's
    /// own key as sponsor, send a token into its vault, name the adversary's own key the curator.
    Proposal {
        op: u8,
    },
    /// A move of the user sponsor's (Role::UserSponsor, signed by its key where the adversary
    /// holds it, an impersonation where not; nothing without the world's proposal), `op` of:
    /// - submit a proposal at USER_CID from its funding account, the curator co-signing, on the
    ///   house's terms (`pick` 0) or with one changed: the sponsor as the resolver (1) or the
    ///   compliance key (2), the curator as either (3, 4), a one-second resolve window (5), a
    ///   bond of a million SOL (6), a resolver of the adversary's own the program cannot tell
    ///   from the house's (7), refund_to the adversary's (8);
    /// - withdraw the world's proposal (`pick` even) or USER_CID's (odd);
    /// - send the way back to a token account the adversary owns instead: withdraw a proposal as
    ///   above, or refund the escrow the world's proposal opened (`pick` / 2 odd);
    /// - reassign its associated token account's owner to the adversary's key (created first when
    ///   absent);
    /// - fund the escrow its proposal opened (`pick` even) or the world's escrow (odd) from its
    ///   funding account.
    Sponsor {
        op: u8,
        pick: u8,
    },
    /// A wind-down move, `op` of: retire, close_escrow (its lamports to its refund_to, or to the
    /// adversary's own key), close_config (to the adversary's own key), each with the
    /// adversary's best key as the admin (the admin's alone: no compromise holds it); or
    /// close_receipt of every claimant's receipt, anyone's to send once the escrow is Closed
    /// (its rent to the claimant, never the sender).
    WindDown {
        op: u8,
    },
}

/// What must hold for an adversary's instruction to succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Needs {
    Nothing,
    Role(Role),
    Admin,
    /// Nothing the adversary may hold lets it: the program refuses it to every key.
    Never,
}

/// A bond no one posts (Step::Sponsor's pick 6, the #852 audit's probe P-B).
const MILLION_SOL: u64 = 1_000_000 * SOL;

/// The escrow as one transaction found it.
#[derive(Clone, Copy, Debug)]
struct Seen {
    escrow_now: i64,
    challenge_deadline: i64,
    attest_deadline: i64,
    /// Claimable on an alternative that overturned the posted result.
    overturned: bool,
    outside: u64,
}

/// A result in force: (result_sha256, payout_root, total, commitment).
pub type InForce = ([u8; 32], [u8; 32], u64, [u8; 32]);

/// The oracle's ledger and the honest parties' memory.
#[derive(Clone, Debug)]
pub struct Model {
    pub world: World,
    pub who: Compromise,
    pub held: Vec<Role>,
    pub trees: Vec<Tree>,
    /// Lamports of bond taken in (ResultPosted, ChallengeCommitted) and paid out (Settled,
    /// ArbiterResolved, Refunded, ChallengeClosed, CommitClosed), from the program's events.
    pub bonds_in: u64,
    pub bonds_out: u64,
    pub donated_tokens: u64,
    pub donated_lamports: u64,
    pub last_status: Option<EscrowStatus>,
    /// The result in force once the escrow is Claimable.
    pub in_force: Option<InForce>,
    /// Every commit (address, challenger) and challenge (alt commitment) a step sent.
    pub commits: Vec<(Pubkey, Pubkey)>,
    pub challenges: Vec<[u8; 32]>,
    /// The most the adversary ever held outside the rubric.
    pub outside_max: u64,
    pub violations: Vec<String>,
    pub trace: Vec<String>,
    /// Wall time of the honest parties' last reaction.
    pub last_react: i64,
    /// A bound to hold the adversary to instead of bound(K) (0: search for any drain at all).
    pub bound_override: Option<u64>,
    /// The user sponsor's proposals (World::open_proposals', and its own at USER_CID): the tokens
    /// the adversary sent into the world's proposal vault, what every submit deposited
    /// (ProposalSubmitted, the world's proposal's at open_proposals included), what went back to
    /// the sponsor (ProposalClosed, and the Refunded of the escrow the world's proposal opened),
    /// and what approve_proposal swept into its escrow's vault beyond the deposit
    /// (ProposalApproved).
    pub proposal_donated: u64,
    pub proposal_deposited: u64,
    pub proposal_returned: u64,
    pub proposal_swept: u64,
    /// Whether the world's proposal was returned (a ProposalClosed of its PDA).
    pub proposal_closed: bool,
    /// The user sponsor's proposal at USER_CID as last submitted (Step::Sponsor).
    pub user_proposal: Option<ProposalSetup>,
    /// The token accounts of the user sponsor's besides its associated one that the honest
    /// parties created once it reassigned that one's owner, oldest first (user_destination).
    pub user_refuges: Vec<Pubkey>,
    /// The world's escrow's receipts close_receipt closed (ReceiptClosed), each claimant with the
    /// amount_claimed its receipt recorded: the tokens stay with the claimant.
    pub receipts_closed: Vec<(Pubkey, u64)>,
    /// Each role with its associated token account of the mint and its ClaimReceipt PDA.
    accounts: Vec<(Role, Pubkey, Pubkey)>,
}

impl Model {
    /// A model over `world` (its escrow open, entries committed) with K = `who`.
    pub fn new(world: World, who: Compromise) -> Model {
        let trees = world.trees();
        let accounts = Role::all()
            .into_iter()
            .map(|r| (r, world.ata(&r.pubkey()), world.receipt(&r.pubkey())))
            .collect();
        let proposal_deposited = world.proposal.as_ref().map_or(0, |p| p.terms.total);
        Model {
            accounts,
            held: who.roles(world.panel),
            world,
            who,
            trees,
            bonds_in: 0,
            bonds_out: 0,
            donated_tokens: 0,
            donated_lamports: 0,
            last_status: Some(EscrowStatus::Open),
            in_force: None,
            commits: Vec::new(),
            challenges: Vec::new(),
            outside_max: 0,
            violations: Vec::new(),
            trace: Vec::new(),
            last_react: i64::MIN / 2,
            bound_override: None,
            proposal_donated: 0,
            proposal_deposited,
            proposal_returned: 0,
            proposal_swept: 0,
            proposal_closed: false,
            user_proposal: None,
            user_refuges: Vec::new(),
            receipts_closed: Vec::new(),
        }
    }

    pub fn honest(&self) -> &Tree {
        &self.trees[0]
    }

    /// Whether the adversary holds `key`.
    pub fn holds(&self, key: &Pubkey) -> bool {
        match Role::of(key) {
            Some(Role::Attacker(_)) => true,
            Some(role) => self.held.contains(&role),
            None => false,
        }
    }

    fn escrow(&self, c: &impl Chain) -> Escrow {
        self.world.state(c).expect("the escrow")
    }

    fn revoked(&self, c: &impl Chain, key: &Pubkey) -> bool {
        self.world.config(c).is_revoked(key)
    }

    fn tree_with_root(&self, root: &[u8; 32]) -> Option<&Tree> {
        self.trees.iter().find(|t| t.root == *root)
    }

    fn leaf(&self, flat: u8) -> (&Tree, usize) {
        let per = 2usize;
        let index = usize::from(flat) % (self.trees.len() * per);
        (&self.trees[index / per], index % per)
    }

    // --------------------------------------------------------------------- one transaction

    /// Sends `ix` and audits the world after it, `what` naming it in the trace.
    pub fn send(
        &mut self,
        c: &mut impl Chain,
        ix: Instruction,
        signers: &[&Keypair],
        what: &str,
    ) -> Sent {
        let before = self.seen(c);
        let sent = self.world.send(c, ix, signers);
        self.record(c, before, what, &sent);
        sent
    }

    fn record(&mut self, c: &mut impl Chain, before: Seen, what: &str, sent: &Sent) {
        if sent.ok {
            self.tally(sent);
            self.audit_proposal_events(c, sent, what);
        }
        self.trace.push(format!(
            "t={} {what}: {}",
            c.time(),
            if sent.ok {
                "ok".to_string()
            } else {
                sent.code
                    .map_or_else(|| sent.error.clone(), |code| format!("refused {code}"))
            }
        ));
        self.audit(c, before, what);
    }

    fn tally(&mut self, sent: &Sent) {
        for e in sent.events::<ResultPosted>() {
            self.bonds_in += e.resolver_bond;
        }
        for e in sent.events::<ChallengeCommitted>() {
            self.bonds_in += e.bond;
        }
        for e in sent.events::<Settled>() {
            self.bonds_out += e.resolver_paid + e.challenger_paid;
        }
        for e in sent.events::<ArbiterResolved>() {
            self.bonds_out += e.resolver_paid + e.challenger_paid;
        }
        let proposal_escrow = self.proposal_escrow();
        for e in sent.events::<Refunded>() {
            if Some(e.escrow) == proposal_escrow {
                // The escrow the world's proposal opened: its bonds are none of the world's
                // escrow's, and its vault goes back to the user sponsor.
                self.proposal_returned += e.amount;
            } else {
                self.bonds_out += e.resolver_paid;
            }
        }
        for e in sent.events::<ChallengeClosed>() {
            self.bonds_out += e.bond_returned;
        }
        for e in sent.events::<CommitClosed>() {
            self.bonds_out += e.bond_returned;
        }
        let escrow = self.world.escrow();
        for e in sent.events::<ReceiptClosed>() {
            if e.escrow == escrow {
                self.receipts_closed.push((e.claimant, e.amount_claimed));
            }
        }
        let world_proposal = self.world_proposal();
        for e in sent.events::<ProposalClosed>() {
            self.proposal_returned += e.amount;
            self.proposal_closed |= Some(e.proposal) == world_proposal;
        }
        for e in sent.events::<ProposalApproved>() {
            self.proposal_swept += e.swept;
        }
        for e in sent.events::<ProposalSubmitted>() {
            self.proposal_deposited += e.total;
        }
    }

    /// The world's proposal PDA (the user sponsor's, at PROPOSAL_CID), when it has one.
    fn world_proposal(&self) -> Option<Pubkey> {
        self.world
            .proposal
            .as_ref()
            .map(|p| self.world.proposal_at(&p.sponsor, &p.cid))
    }

    /// The escrow the world's proposal opens on approval, when it has one.
    fn proposal_escrow(&self) -> Option<Pubkey> {
        self.world
            .proposal
            .as_ref()
            .map(|p| self.world.escrow_at(&p.sponsor, &p.cid))
    }

    /// The roles whose associated token accounts hold what the rubric sends them besides prizes:
    /// the sponsor's refund, the user sponsor's returns and refunds. They claim nothing.
    fn is_sponsor(role: Role) -> bool {
        matches!(role, Role::Sponsor | Role::UserSponsor)
    }

    /// What the user sponsor's token accounts besides its associated one hold.
    fn refuged(&self, c: &impl Chain) -> u64 {
        self.user_refuges.iter().map(|r| c.tokens(r)).sum()
    }

    fn seen(&self, c: &impl Chain) -> Seen {
        let escrow = self.world.state(c);
        let config = self.world.config(c);
        Seen {
            escrow_now: escrow
                .as_ref()
                .map_or(0, |e| prize_escrow::escrow_now(e, &config, c.time())),
            challenge_deadline: escrow.as_ref().map_or(0, |e| e.challenge_deadline),
            attest_deadline: escrow.as_ref().map_or(0, |e| e.attest_deadline),
            overturned: escrow.as_ref().is_some_and(|e| {
                e.status == EscrowStatus::Claimable
                    && e.has_challenger()
                    && e.commitment == e.alt_commitment
            }),
            outside: self.outside(c),
        }
    }

    /// What the adversary's accounts (and every account but the honest winners', up to their
    /// prizes, and the sponsors') hold of the mint, less what the adversary donated.
    pub fn outside(&self, c: &impl Chain) -> u64 {
        let gross: u64 = self
            .accounts
            .iter()
            .filter(|(r, _, _)| !Self::is_sponsor(*r))
            .map(|(r, ata, _)| {
                let held = c.tokens(ata);
                match *r {
                    Role::Winner(i) => held.saturating_sub(PRIZES[usize::from(i)]),
                    _ => held,
                }
            })
            .sum();
        gross.saturating_sub(self.donated_tokens)
    }

    fn violation(&mut self, what: String) {
        self.violations.push(what);
    }

    /// Every invariant, after one transaction.
    fn audit(&mut self, c: &impl Chain, before: Seen, what: &str) {
        let w = self.world.clone();
        let Some(escrow) = w.state(c) else {
            return self.violation(format!("{what}: the escrow account is gone"));
        };

        // The blast radius, and nothing before challenge_deadline on the escrow clock (nothing
        // under an applied alternative, an overturn, before attest_deadline).
        let outside = self.outside(c);
        self.outside_max = self.outside_max.max(outside);
        let bound = self
            .bound_override
            .unwrap_or_else(|| self.who.bound(w.panel));
        if outside > bound {
            self.violation(format!(
                "{what}: {outside} moved outside the rubric, over bound({:?}, {:?}) = {bound}",
                self.who, w.panel
            ));
        }
        let (name, deadline) = if before.overturned {
            ("attest_deadline", before.attest_deadline)
        } else {
            ("challenge_deadline", before.challenge_deadline)
        };
        if outside > before.outside
            && (before.challenge_deadline == 0 || before.escrow_now < deadline)
        {
            self.violation(format!(
                "{what}: {} moved outside the rubric at escrow time {} before {name} {deadline}",
                outside - before.outside,
                before.escrow_now,
            ));
        }

        // Conservation per mint.
        let atas: Vec<(Role, u64, Pubkey)> = self
            .accounts
            .iter()
            .map(|(r, ata, receipt)| (*r, c.tokens(ata), *receipt))
            .collect();
        let vault = c.tokens(&w.vault());
        // What went back to the user sponsor may sit in a token account of its besides its
        // associated one (user_destination).
        let in_atas: u64 = atas.iter().map(|(_, b, _)| b).sum::<u64>() + self.refuged(c);
        // The user sponsor's proposals hold their deposits in their own vaults, then the world's
        // in its escrow's.
        let proposals: u64 = w.proposal.as_ref().map_or(0, |p| {
            [p.cid, USER_CID]
                .iter()
                .map(|cid| {
                    c.tokens(&w.proposal_vault_at(&p.sponsor, cid))
                        + c.tokens(&w.escrow_vault_at(&p.sponsor, cid))
                })
                .sum()
        });
        let tracked = vault
            + in_atas
            + c.tokens(&w.funding)
            + c.tokens(&w.attacker_funding)
            + c.tokens(&w.user_funding)
            + proposals;
        let supply = SPONSOR_FUNDS + ATTACKER_FUNDS + USER_FUNDS;
        if tracked != supply {
            self.violation(format!(
                "{what}: the mint's accounts the oracle knows hold {tracked}, not the supply {supply}"
            ));
        }
        if vault + in_atas != escrow.deposited + self.donated_tokens + self.proposal_returned {
            self.violation(format!(
                "{what}: vault {vault} + claimed and refunded {in_atas} != deposited {} + donated {} + the proposals' return {}",
                escrow.deposited, self.donated_tokens, self.proposal_returned
            ));
        }
        self.audit_proposal(c, &escrow, proposals, what);
        let claimed: u64 = atas
            .iter()
            .filter(|(r, _, _)| !Self::is_sponsor(*r))
            .map(|(_, b, _)| b)
            .sum();
        if claimed != escrow.total_claimed {
            self.violation(format!(
                "{what}: claimants hold {claimed}, total_claimed is {}",
                escrow.total_claimed
            ));
        }

        // No leaf claimed twice: each claimant holds what its one receipt records (or recorded
        // when close_receipt closed it, only ever on a Closed escrow), at most its leaf, and the
        // leaf is one of the root in force.
        if !self.receipts_closed.is_empty() && escrow.status != EscrowStatus::Closed {
            self.violation(format!(
                "{what}: a receipt closed while the escrow is {:?}",
                escrow.status
            ));
        }
        for (role, balance, receipt) in atas.iter().filter(|(r, _, _)| !Self::is_sponsor(*r)) {
            let receipt = c.anchor::<ClaimReceipt>(receipt);
            let closed = self
                .receipts_closed
                .iter()
                .find(|(claimant, _)| *claimant == role.pubkey())
                .map_or(0, |(_, amount)| *amount);
            let recorded = receipt.as_ref().map_or(closed, |r| r.amount_claimed);
            if *balance != recorded {
                self.violation(format!(
                    "{what}: {role:?} holds {balance}, its receipt records {recorded}"
                ));
            }
            if let Some(r) = receipt.filter(|r| r.amount_claimed > 0) {
                let in_root = self
                    .tree_with_root(&escrow.payout_root)
                    .is_some_and(|t| t.leaves.contains(&(role.pubkey(), r.total_amount)));
                if r.amount_claimed > r.total_amount || !in_root {
                    self.violation(format!(
                        "{what}: {role:?} claimed {} of a leaf {} that the root in force {}",
                        r.amount_claimed,
                        r.total_amount,
                        if in_root { "holds" } else { "does not hold" }
                    ));
                }
            }
        }

        // Each bond paid exactly once.
        let held = escrow.resolver_bond + escrow.challenger_bond + escrow.commit_bond;
        if self.bonds_in != self.bonds_out + held {
            self.violation(format!(
                "{what}: bonds in {} != out {} + held {held}",
                self.bonds_in, self.bonds_out
            ));
        }
        let lamports = c.lamports(&w.escrow());
        let want = c.rent_exempt(Escrow::SPACE) + held + self.donated_lamports;
        if lamports != want {
            self.violation(format!(
                "{what}: the escrow holds {lamports} lamports, not rent + bonds held + donated = {want}"
            ));
        }

        // One terminal state.
        if let Some(from) = self.last_status {
            if from != escrow.status && !edge(from, escrow.status) {
                self.violation(format!(
                    "{what}: status moved {from:?} -> {:?}",
                    escrow.status
                ));
            }
        }
        self.last_status = Some(escrow.status);
        let result = (
            escrow.result_sha256,
            escrow.payout_root,
            escrow.total,
            escrow.commitment,
        );
        match self.in_force {
            Some(fixed) if fixed != result => self.violation(format!(
                "{what}: the result in force changed after Claimable ({:?})",
                escrow.status
            )),
            None if escrow.status == EscrowStatus::Claimable => self.in_force = Some(result),
            _ => {}
        }
    }

    /// The proposals' invariants and the caps' counters, after one transaction (`proposals`: what
    /// the user sponsor's proposal vaults and the escrow vaults they open hold):
    /// - the deposits are conserved: those vaults + what went back to the sponsor == every
    ///   proposal's deposit + what the adversary sent into the world's proposal vault;
    /// - one way out: the world's proposal is pending (its account, as submitted), approved (its
    ///   escrow, no account) or returned to the sponsor (neither), and never two of them;
    /// - fixed terms: the escrow an approval opened holds exactly the sponsor's terms, sponsor,
    ///   mint and competition id, its deposit counted, Open with the deposit and the sweep in its
    ///   vault until its refund closes it; the user sponsor's own proposal (USER_CID, on terms the
    ///   house did not compose) never opens one;
    /// - the counters: Config.open_value is the open escrows' deposits (the world's until its
    ///   refund, the proposal's once approved and until its own), Config.pending_value the pending
    ///   proposals'.
    fn audit_proposal(&mut self, c: &impl Chain, escrow: &Escrow, proposals: u64, what: &str) {
        let w = self.world.clone();
        let config = w.config(c);
        let main_open = if escrow.status == EscrowStatus::Closed {
            0
        } else {
            escrow.deposited
        };
        // live_escrows counts the escrows open_escrow and approve_proposal opened and
        // close_escrow (the admin's alone, after retire) has not closed: the world's, and the one
        // the world's proposal opens once approved. No key the adversary may hold retires it.
        let opened_live = w
            .proposal
            .as_ref()
            .is_some_and(|p| w.escrow_state_at(c, &p.sponsor, &p.cid).is_some());
        let live = 1 + u32::from(opened_live);
        if config.live_escrows != live || config.retired {
            self.violation(format!(
                "{what}: live_escrows {} (retired {}), not the {live} escrows open and not retired",
                config.live_escrows, config.retired
            ));
        }
        let Some(p) = w.proposal.as_ref() else {
            if (config.open_value, config.pending_value) != (main_open, 0) {
                self.violation(format!(
                    "{what}: open_value {} and pending_value {} are not the open deposits {main_open} and 0",
                    config.open_value, config.pending_value
                ));
            }
            return;
        };
        let sponsor = p.sponsor;
        let pending = w.proposal_state(c, &sponsor, &p.cid);
        let opened = w.escrow_state_at(c, &sponsor, &p.cid);
        let own = w.proposal_state(c, &sponsor, &USER_CID);
        if w.escrow_state_at(c, &sponsor, &USER_CID).is_some() {
            self.violation(format!(
                "{what}: the user sponsor's own proposal opened an escrow, on terms the house did not compose"
            ));
        }
        let total = p.terms.total;
        if proposals + self.proposal_returned != self.proposal_deposited + self.proposal_donated {
            self.violation(format!(
                "{what}: the proposals' vaults and their escrows' {proposals} + returned {} != their deposits {} + donated {}",
                self.proposal_returned, self.proposal_deposited, self.proposal_donated
            ));
        }
        let returned = self.proposal_closed;
        match (&pending, &opened, returned) {
            (Some(_), None, false) | (None, Some(_), false) | (None, None, true) => {}
            _ => self.violation(format!(
                "{what}: the proposal is {} pending, {} approved, {} returned",
                pending.is_some(),
                opened.is_some(),
                returned
            )),
        }
        if let Some(stored) = &pending {
            if (
                &stored.terms,
                stored.opens_at,
                stored.review_deadline,
                stored.deposited,
            ) != (&p.terms, p.opens_at, p.review_deadline, total)
            {
                self.violation(format!(
                    "{what}: the stored proposal is not the one submitted"
                ));
            }
        }
        if let Some(e) = &opened {
            let terms = EscrowTerms {
                total: e.total,
                rules_sha256: e.rules_sha256,
                resolver: e.resolver,
                compliance: e.compliance,
                arbiter: e.arbiter,
                refund_to: e.refund_to,
                regraders: e.regraders[..usize::from(e.n)].to_vec(),
                k: e.k,
                bond_lamports: e.bond_lamports,
                entries_deadline: e.entries_deadline,
                final_end: e.final_end,
                resolve_deadline: e.resolve_deadline,
                challenge_window: e.challenge_window,
                attest_window: e.attest_window,
                hold_window: e.hold_window,
                claim_window: e.claim_window,
                hard_deadline: e.hard_deadline,
            };
            let refunded = e.status == EscrowStatus::Closed;
            if terms != p.terms
                || (e.sponsor, e.mint, e.competition_id, e.deposited)
                    != (sponsor, w.mint, p.cid, total)
                || !matches!(e.status, EscrowStatus::Open | EscrowStatus::Closed)
            {
                self.violation(format!(
                    "{what}: the approved escrow is not the sponsor's terms: {e:?}"
                ));
            }
            let in_vault = c.tokens(&w.escrow_vault_at(&sponsor, &p.cid));
            let want = if refunded {
                0
            } else {
                total + self.proposal_swept
            };
            if in_vault != want {
                self.violation(format!(
                    "{what}: the approved escrow's vault holds {in_vault}, not {want} (the deposit {total} + swept {}, until its refund)",
                    self.proposal_swept
                ));
            }
        }
        let want = (
            main_open
                + opened
                    .as_ref()
                    .filter(|e| e.status != EscrowStatus::Closed)
                    .map_or(0, |e| e.deposited),
            pending.as_ref().map_or(0, |p| p.deposited) + own.as_ref().map_or(0, |p| p.deposited),
        );
        if (config.open_value, config.pending_value) != want {
            self.violation(format!(
                "{what}: open_value {} and pending_value {} are not the open deposits {want:?}",
                config.open_value, config.pending_value
            ));
        }
    }

    /// When the program let a proposal in or out: every proposal it accepted holds the bounds the
    /// program holds a sponsor's terms to (Config::check_proposal_terms), an approval lands by
    /// review_deadline and only of the world's proposal (the house's terms), and every return is
    /// the kind its moment and signer make it: past review_deadline naming no reason an expiry
    /// whoever signs, else the sponsor's a withdrawal, the curator's a rejection and anyone else's
    /// refused.
    fn audit_proposal_events(&mut self, c: &impl Chain, sent: &Sent, what: &str) {
        let Some(p) = self.world.proposal.clone() else {
            return;
        };
        let now = c.time();
        let curator = self.world.config(c).curator;
        for e in sent.events::<ProposalSubmitted>() {
            let window = e.resolve_deadline - e.final_end;
            let roles = [e.resolver, e.compliance];
            if e.sponsor == curator
                || roles.iter().any(|r| *r == e.sponsor || *r == curator)
                || window < MIN_RESOLVE_WINDOW
                || e.bond_lamports > MAX_PROPOSAL_BOND
            {
                self.violation(format!(
                    "{what}: a proposal of self-dealing terms was accepted: sponsor {}, curator {curator}, resolver {}, compliance {}, resolve window {window} s, bond {}",
                    e.sponsor, e.resolver, e.compliance, e.bond_lamports
                ));
            }
        }
        let world_proposal = self.world_proposal();
        for e in sent.events::<ProposalApproved>() {
            if Some(e.proposal) != world_proposal || now > p.review_deadline {
                self.violation(format!(
                    "{what}: {} approved at {now} (the world's proposal's review_deadline {})",
                    e.proposal, p.review_deadline
                ));
            }
        }
        for e in sent.events::<ProposalClosed>() {
            let review_deadline = if Some(e.proposal) == world_proposal {
                p.review_deadline
            } else {
                self.user_proposal
                    .as_ref()
                    .map_or(i64::MAX, |u| u.review_deadline)
            };
            let expired = now > review_deadline && e.reason_sha256 == [0; 32];
            let kind = if expired {
                ProposalCloseKind::Expired
            } else if e.by == e.sponsor {
                ProposalCloseKind::Withdrawn
            } else if e.by == curator {
                ProposalCloseKind::Rejected
            } else {
                ProposalCloseKind::Expired
            };
            if e.kind != kind || (kind == ProposalCloseKind::Expired && !expired) {
                self.violation(format!(
                    "{what}: {:?} by {} at {now} (review_deadline {review_deadline})",
                    e.kind, e.by
                ));
            }
        }
    }

    /// The adversary's move on the sponsor's proposal (Step::Proposal); none without one.
    fn proposal_move(&mut self, c: &mut impl Chain, op: u8) {
        let w = self.world.clone();
        let Some(p) = w.proposal.clone() else {
            return;
        };
        let sponsor = p.sponsor;
        let curator = w.config(c).curator;
        let label = format!("{:?}", Step::Proposal { op });
        let (ix, signers, needs): (Instruction, Vec<&'static Keypair>, Needs) = match op % 6 {
            0 => {
                let key = self.as_key(&curator);
                (
                    w.approve_proposal_ix(key.pubkey(), sponsor, p.cid),
                    vec![key],
                    self.needs_key(&curator),
                )
            }
            1 => {
                let key = self.as_key(&curator);
                (
                    w.close_proposal_ix(key.pubkey(), sponsor, p.cid, REASON),
                    vec![key],
                    self.needs_key(&curator),
                )
            }
            2 => {
                let key = Role::Attacker(0).key();
                (
                    w.close_proposal_ix(key.pubkey(), sponsor, p.cid, [0; 32]),
                    vec![key],
                    Needs::Nothing,
                )
            }
            3 => {
                // The adversary's own key as the sponsor of a new proposal, paid from the user
                // sponsor's funding account, the curator co-signing where the adversary holds it.
                let key = Role::Attacker(0).key();
                let co = self.as_key(&curator);
                let (mut terms, opens_at, review_deadline) = World::proposal_terms(c.time());
                terms.refund_to = key.pubkey();
                (
                    w.submit_proposal_ix(
                        key.pubkey(),
                        co.pubkey(),
                        w.user_funding,
                        p.cid,
                        &terms,
                        opens_at,
                        review_deadline,
                    ),
                    vec![key, co],
                    Needs::Role(Role::UserSponsor),
                )
            }
            4 => {
                let vault = w.proposal_vault_at(&sponsor, &p.cid);
                let sent = self.send_donation(c, w.donate_tokens_to_ix(vault, 1), &label);
                if sent.ok {
                    self.proposal_donated += 1;
                    let seen = self.seen(c);
                    self.audit(c, seen, &label);
                }
                return;
            }
            _ => {
                let key = self.best_key();
                (
                    w.set_proposal_policy_ix(key.pubkey(), Role::Attacker(0).pubkey(), PENDING_CAP),
                    vec![key],
                    Needs::Admin,
                )
            }
        };
        self.send_needing(c, ix, &signers, needs, &label);
    }

    /// Sends the adversary's `ix` and flags a success it needs `needs` for and does not hold.
    fn send_needing(
        &mut self,
        c: &mut impl Chain,
        ix: Instruction,
        signers: &[&Keypair],
        needs: Needs,
        label: &str,
    ) -> Sent {
        let sent = self.send(c, ix, signers, label);
        if sent.ok {
            let allowed = match needs {
                Needs::Nothing => true,
                Needs::Role(role) => self.held.contains(&role),
                Needs::Admin | Needs::Never => false,
            };
            if !allowed {
                self.violation(format!(
                    "{label}: succeeded for an adversary holding {:?}, which it needs {needs:?} for",
                    self.held
                ));
            }
        }
        sent
    }

    /// Step::WindDown: retire, close_escrow or close_config under the adversary's best key as
    /// the admin (an impersonation: no compromise holds the admin's key), the lamports to the
    /// escrow's refund_to or the adversary's own key; or close_receipt of every receipt there is,
    /// the adversary paying the fee and signing nothing else.
    fn wind_down_move(&mut self, c: &mut impl Chain, op: u8) {
        let w = self.world.clone();
        let label = format!("{:?}", Step::WindDown { op });
        let key = self.best_key();
        let attacker = Role::Attacker(0).pubkey();
        let ix = match op % 4 {
            0 => w.retire_ix(key.pubkey()),
            1 => {
                let refund_to = if (op / 4).is_multiple_of(2) {
                    self.escrow(c).refund_to
                } else {
                    attacker
                };
                w.close_escrow_ix(key.pubkey(), w.escrow(), refund_to)
            }
            2 => w.close_config_ix(key.pubkey(), attacker),
            _ => {
                for role in Role::all() {
                    if Self::is_sponsor(role)
                        || c.anchor::<ClaimReceipt>(&w.receipt(&role.pubkey())).is_none()
                    {
                        continue;
                    }
                    let ix = w.close_receipt_ix(role.pubkey());
                    self.send_needing(c, ix, &[], Needs::Nothing, &label);
                }
                return;
            }
        };
        self.send_needing(c, ix, &[key], Needs::Admin, &label);
    }

    /// Where an honest party sends what goes back to the user sponsor (close_proposal's and
    /// refund's `destination`): None, its associated token account, while nothing is there (the
    /// program creates it) or the user sponsor still owns it; once its owner was reassigned away,
    /// the newest token account the honest parties created for the user sponsor that it still
    /// owns, or a new one (anyone may create a token account another key owns).
    fn user_destination(&mut self, c: &mut impl Chain) -> Option<Pubkey> {
        let user = Role::UserSponsor.pubkey();
        let ata = self.world.ata(&user);
        if token_owner(c, &ata).is_none_or(|owner| owner == user) {
            return None;
        }
        if let Some(refuge) = self.user_refuges.last().copied() {
            if token_owner(c, &refuge) == Some(user) {
                return Some(refuge);
            }
        }
        let index = self.user_refuges.len() as u32;
        let key = keypair_derived(&[b"user-refuge".as_slice(), &index.to_le_bytes()].concat());
        let created = self.world.create_token_account(c, &key, user);
        self.trace.push(format!(
            "t={} honest: a token account {} for the user sponsor: {}",
            c.time(),
            key.pubkey(),
            if created { "ok" } else { "failed" }
        ));
        if !created {
            return None;
        }
        self.user_refuges.push(key.pubkey());
        Some(key.pubkey())
    }

    /// The user sponsor's move (Step::Sponsor); none without the world's proposal.
    fn sponsor_move(&mut self, c: &mut impl Chain, op: u8, pick: u8) {
        let w = self.world.clone();
        let Some(p) = w.proposal.clone() else {
            return;
        };
        let user = p.sponsor;
        let key = self.as_key(&user);
        let curator = w.config(c).curator;
        let label = format!("{:?}", Step::Sponsor { op, pick });
        let attacker = Role::Attacker(0).pubkey();
        // A cid of the user sponsor's own: the world's proposal (even) or USER_CID's (odd).
        let cid = if pick.is_multiple_of(2) {
            p.cid
        } else {
            USER_CID
        };
        match op % 5 {
            0 => {
                let (mut terms, opens_at, review_deadline) = World::user_proposal_terms(c.time());
                match pick % 9 {
                    0 => {}
                    1 => terms.resolver = user,
                    2 => terms.compliance = user,
                    3 => terms.resolver = curator,
                    4 => terms.compliance = curator,
                    5 => terms.resolve_deadline = terms.final_end + 1,
                    6 => terms.bond_lamports = MILLION_SOL,
                    7 => terms.resolver = Role::Attacker(1).pubkey(),
                    _ => terms.refund_to = attacker,
                }
                let ix = w.submit_proposal_ix(
                    key.pubkey(),
                    curator,
                    w.user_funding,
                    USER_CID,
                    &terms,
                    opens_at,
                    review_deadline,
                );
                // The curator co-signs whatever the sponsor submits: the program alone holds the
                // terms (the module header).
                let co = Role::of(&curator).map_or(Role::Attacker(1).key(), Role::key);
                let sent =
                    self.send_needing(c, ix, &[key, co], Needs::Role(Role::UserSponsor), &label);
                if sent.ok {
                    self.user_proposal = Some(ProposalSetup {
                        sponsor: key.pubkey(),
                        cid: USER_CID,
                        terms,
                        opens_at,
                        review_deadline,
                        submitted_at: c.time(),
                    });
                }
            }
            1 => {
                // Past its review_deadline any signer's return naming no reason is an expiry,
                // which anyone may send; before it only the sponsor withdraws.
                let review_deadline = if cid == p.cid {
                    p.review_deadline
                } else {
                    self.user_proposal
                        .as_ref()
                        .map_or(i64::MAX, |u| u.review_deadline)
                };
                let needs = if c.time() > review_deadline {
                    Needs::Nothing
                } else {
                    Needs::Role(Role::UserSponsor)
                };
                let destination = self.user_destination(c);
                let ix = w.close_proposal_to_ix(key.pubkey(), user, cid, [0; 32], destination);
                self.send_needing(c, ix, &[key], needs, &label);
            }
            2 => {
                // The way back sent to the adversary's own associated token account, which the
                // user sponsor does not own: refused whoever signs.
                let elsewhere = w.ata(&attacker);
                if c.account(&elsewhere).is_none() {
                    let create = w.create_ata_ix(Role::Payer.pubkey(), attacker);
                    self.send_other(c, create, &[], &format!("{label}: its own token account"));
                }
                let (ix, signers) = if (pick / 2).is_multiple_of(2) {
                    let ix =
                        w.close_proposal_to_ix(key.pubkey(), user, cid, [0; 32], Some(elsewhere));
                    (ix, vec![key])
                } else {
                    // refund is anyone's: the Payer sends it, no signature of the sponsor's.
                    let address = w.escrow_at(&user, &p.cid);
                    let Some(e) = w.escrow_state_at(c, &user, &p.cid) else {
                        return;
                    };
                    (w.refund_at_ix(address, &e, Some(elsewhere)), vec![])
                };
                self.send_needing(c, ix, &signers, Needs::Never, &label);
            }
            3 => {
                // Its associated token account's owner reassigned to the adversary's key, the
                // account created first when absent (the #852 audit's probe P-A).
                let ata = w.ata(&user);
                if c.account(&ata).is_none() {
                    let create = w.create_ata_ix(Role::Payer.pubkey(), user);
                    self.send_other(c, create, &[], &format!("{label}: its token account"));
                }
                let ix = w.set_token_owner_ix(ata, key.pubkey(), attacker);
                let sent = self.send_other(c, ix, &[key], &label);
                if sent.ok && !self.held.contains(&Role::UserSponsor) {
                    self.violation(format!(
                        "{label}: the user sponsor's token account was reassigned by an adversary holding {:?}",
                        self.held
                    ));
                }
                let seen = self.seen(c);
                self.audit(c, seen, &label);
            }
            _ => {
                // A user sponsor adds nothing once its proposal opened its escrow (the #852
                // audit's P3-3), and the world's escrow is none of its.
                let escrow = if pick.is_multiple_of(2) {
                    w.escrow_at(&user, &p.cid)
                } else {
                    w.escrow()
                };
                let ix = w.fund_at_ix(key.pubkey(), w.user_funding, escrow, 1);
                self.send_needing(c, ix, &[key], Needs::Never, &label);
            }
        }
    }

    // --------------------------------------------------------------------- the adversary

    /// The key the adversary signs as `key` with: `key`'s own when it holds it, else one of its
    /// own (an impersonation).
    fn as_key(&self, key: &Pubkey) -> &'static Keypair {
        match Role::of(key) {
            Some(role) if self.holds(key) => role.key(),
            _ => Role::Attacker(0).key(),
        }
    }

    /// The most privileged key the adversary holds for an admin verb it cannot sign.
    fn best_key(&self) -> &'static Keypair {
        [
            Role::Guardian,
            Role::Resolver,
            Role::Compliance,
            Role::Member,
            Role::Curator,
            Role::UserSponsor,
        ]
        .into_iter()
        .find(|r| self.held.contains(r))
        .unwrap_or(Role::Attacker(0))
        .key()
    }

    fn needs_key(&self, key: &Pubkey) -> Needs {
        Role::of(key).map_or(Needs::Admin, Needs::Role)
    }

    /// Runs one step; Err with every violation found (and the trace) when an invariant broke.
    pub fn step(&mut self, c: &mut impl Chain, step: Step) -> Result<(), String> {
        match step {
            Step::Wait(secs) => {
                self.react(c);
                self.advance(c, i64::from(secs).clamp(1, MAX_LATENCY), "wait");
            }
            Step::React => self.react(c),
            Step::Tick(secs) => {
                let secs = i64::from(secs).clamp(1, BLIND);
                if c.time() + secs - self.last_react > BLIND {
                    self.react(c);
                }
                self.advance(c, secs, "tick");
            }
            Step::Approach { deadline, before } => {
                self.react(c);
                let e = self.escrow(c);
                let target = [
                    e.challenge_deadline,
                    e.reveal_deadline().unwrap_or(0),
                    e.attest_deadline,
                    e.claim_deadline,
                    e.hard_deadline,
                    e.entries_deadline,
                    e.resolve_deadline,
                ][usize::from(deadline) % 7];
                let before = i64::from(before).clamp(1, BLIND);
                // The escrow clock runs with wall time while nothing stops it; a stop in force
                // only makes the approach land earlier on it.
                let gap = target - before - self.world.escrow_now(c);
                if target != 0 && gap > 0 {
                    self.advance(c, gap.min(MAX_LATENCY), "approach");
                }
            }
            adversary => self.adversary(c, adversary),
        }
        if self.violations.is_empty() {
            Ok(())
        } else {
            Err(self.report())
        }
    }

    /// Wall time moves `secs` and a slot passes.
    fn advance(&mut self, c: &mut impl Chain, secs: i64, what: &str) {
        let t = c.time() + secs;
        c.set_time(t);
        c.next_slot();
        self.trace.push(format!("t={t} {what} {secs}s"));
    }

    pub fn report(&self) -> String {
        let tail = self.trace.len().saturating_sub(40);
        format!(
            "K = {:?} on {:?}\nviolations:\n  {}\ntrace (last {}):\n  {}",
            self.who,
            self.world.panel,
            self.violations.join("\n  "),
            self.trace.len() - tail,
            self.trace[tail..].join("\n  ")
        )
    }

    fn adversary(&mut self, c: &mut impl Chain, step: Step) {
        match step {
            Step::Vote { tree } => {
                for seat in 0..SEATS {
                    let regrader = self.escrow(c).regraders[usize::from(seat)];
                    if self.holds(&regrader) {
                        self.adversary(c, Step::Attest { seat, tree });
                    }
                }
                return;
            }
            Step::Proposal { op } => {
                self.proposal_move(c, op);
                return;
            }
            Step::Sponsor { op, pick } => {
                self.sponsor_move(c, op, pick);
                return;
            }
            Step::WindDown { op } => {
                self.wind_down_move(c, op);
                return;
            }
            Step::Cash { tree } => {
                let t = usize::from(tree) % self.trees.len();
                let cosign = self.holds(&self.escrow(c).compliance);
                for i in 0..self.trees[t].leaves.len() {
                    if !self.holds(&self.trees[t].leaves[i].0) {
                        continue;
                    }
                    let leaf = (t * 2 + i) as u8;
                    if !cosign {
                        self.adversary(c, Step::RequestClaim { leaf });
                    }
                    self.adversary(
                        c,
                        Step::Claim {
                            leaf,
                            amount: 0,
                            cosign,
                        },
                    );
                }
                return;
            }
            _ => {}
        }
        let w = self.world.clone();
        let e = self.escrow(c);
        let before_stop = w.config(c).stop_level(c.time());
        let trees = self.trees.clone();
        let tree = |i: u8| &trees[usize::from(i) % trees.len()];
        let label = format!("{step:?}");
        let (ix, signers, needs): (Instruction, Vec<&'static Keypair>, Needs) = match step {
            Step::Wait(_)
            | Step::React
            | Step::Tick(_)
            | Step::Approach { .. }
            | Step::Vote { .. }
            | Step::Cash { .. }
            | Step::Proposal { .. }
            | Step::Sponsor { .. }
            | Step::WindDown { .. } => {
                unreachable!("the clock's steps and the composite ones")
            }
            Step::Reveal { tree: t, by } => {
                let t = tree(t).clone();
                let key = Role::Attacker(2 + by % 2).key();
                let (hash, salt) = w.commit_of(&key.pubkey(), &t);
                self.challenges.push(t.commitment);
                (
                    w.challenge_reveal_ix(key.pubkey(), hash, salt, &t),
                    vec![key],
                    Needs::Nothing,
                )
            }
            Step::Post { tree: t, total } => {
                let t = tree(t);
                let total = match total % 5 {
                    0 => t.total,
                    1 => TOTAL,
                    2 => c.tokens(&w.vault()),
                    3 => 1,
                    _ => t.total.saturating_sub(1).max(1),
                };
                let key = self.as_key(&e.resolver);
                (
                    w.post_ix(key.pubkey(), t, total),
                    vec![key],
                    self.needs_key(&e.resolver),
                )
            }
            Step::CommitEntries => {
                let key = self.as_key(&e.resolver);
                (
                    w.commit_entries_ix(key.pubkey()),
                    vec![key],
                    self.needs_key(&e.resolver),
                )
            }
            Step::Challenge {
                tree: t,
                by,
                reveal,
            } => {
                let t = tree(t).clone();
                let key = Role::Attacker(2 + by % 2).key();
                let (hash, salt) = w.commit_of(&key.pubkey(), &t);
                self.commits
                    .push((w.commit_pda(&key.pubkey(), &hash), key.pubkey()));
                let commit = w.challenge_commit_ix(key.pubkey(), hash);
                let sent = self.send(c, commit, &[key], &format!("{label} commit"));
                if sent.ok && reveal {
                    c.next_slot();
                    self.challenges.push(t.commitment);
                    let reveal = w.challenge_reveal_ix(key.pubkey(), hash, salt, &t);
                    self.send(c, reveal, &[key], &format!("{label} reveal"));
                }
                return;
            }
            Step::Attest { seat, tree: t } => {
                let seat = usize::from(seat % SEATS);
                let regrader = e.regraders[seat];
                let key = self.as_key(&regrader);
                let commitment = if usize::from(t) % (trees.len() + 1) == trees.len() {
                    e.commitment
                } else {
                    tree(t).commitment
                };
                (
                    w.attest_ix(c, key.pubkey(), commitment),
                    vec![key],
                    self.needs_key(&regrader),
                )
            }
            Step::Settle => (w.settle_ix(&e), vec![], Needs::Nothing),
            Step::Refund => (w.refund_ix(&e), vec![], Needs::Nothing),
            Step::CloseChallenges => {
                self.close_challenges(c, &label);
                return;
            }
            Step::CloseCommits => {
                self.close_commits(c, &label);
                return;
            }
            Step::RequestClaim { leaf } => {
                let (t, i) = self.leaf(leaf);
                let (claimant, amount) = t.leaves[i];
                let key = self.as_key(&claimant);
                (
                    w.request_claim_ix(key.pubkey(), amount, t.proofs[i].clone()),
                    vec![key],
                    Needs::Nothing,
                )
            }
            Step::Claim {
                leaf,
                amount,
                cosign,
            } => {
                let (t, i) = self.leaf(leaf);
                let (claimant, total_amount) = t.leaves[i];
                let key = self.as_key(&claimant);
                let take = match amount % 5 {
                    0 => 0,
                    1 => 1,
                    2 => total_amount / 2,
                    3 => total_amount,
                    _ => total_amount.saturating_add(1),
                };
                let compliance = cosign.then(|| match Role::of(&e.compliance) {
                    Some(role) if self.holds(&e.compliance) => role.key(),
                    _ => Role::Attacker(1).key(),
                });
                let needs = if cosign {
                    self.needs_key(&e.compliance)
                } else {
                    Needs::Nothing
                };
                let mut signers = vec![key];
                signers.extend(compliance);
                (
                    w.claim_ix(
                        key.pubkey(),
                        compliance.map(Keypair::pubkey),
                        total_amount,
                        take,
                        t.proofs[i].clone(),
                    ),
                    signers,
                    needs,
                )
            }
            Step::Hold { claimant } | Step::Release { claimant } => {
                let claimant = claimants()[usize::from(claimant) % 4];
                let key = self.as_key(&e.compliance);
                let ix = if matches!(step, Step::Hold { .. }) {
                    w.hold_ix(key.pubkey(), claimant)
                } else {
                    w.release_ix(key.pubkey(), claimant)
                };
                (ix, vec![key], self.needs_key(&e.compliance))
            }
            Step::Stop { level } => {
                let level = [
                    StopState::Normal,
                    StopState::IntakeStop,
                    StopState::PayoutStop,
                ][usize::from(level % 3)];
                let key = self.as_key(&Role::Guardian.pubkey());
                // The guardian may only raise the level in force; lowering or renewing is the
                // admin's.
                let needs = if level > before_stop {
                    Needs::Role(Role::Guardian)
                } else {
                    Needs::Admin
                };
                (w.set_stop_ix(key.pubkey(), level), vec![key], needs)
            }
            Step::ExtendStop => {
                let key = self.best_key();
                (w.extend_stop_ix(key.pubkey(), DAY), vec![key], Needs::Admin)
            }
            Step::Freeze { on } => {
                let key = self.as_key(&Role::Guardian.pubkey());
                let needs = if on {
                    Needs::Role(Role::Guardian)
                } else {
                    Needs::Admin
                };
                (w.set_freeze_ix(key.pubkey(), on), vec![key], needs)
            }
            Step::ExtendFreeze => {
                let key = self.best_key();
                (
                    w.extend_freeze_ix(key.pubkey(), DAY),
                    vec![key],
                    Needs::Admin,
                )
            }
            Step::Escalate => {
                let key = self.as_key(&Role::Guardian.pubkey());
                (
                    w.escalate_ix(key.pubkey()),
                    vec![key],
                    Needs::Role(Role::Guardian),
                )
            }
            Step::Revoke { target, on } => {
                let targets = [
                    e.resolver,
                    e.compliance,
                    e.regraders[0],
                    e.regraders[1],
                    e.regraders[2],
                    Role::Winner(0).pubkey(),
                    Role::Winner(1).pubkey(),
                    Role::Watcher(0).pubkey(),
                    Role::Arbiter.pubkey(),
                    Role::Admin.pubkey(),
                    Role::Guardian.pubkey(),
                    Role::Attacker(0).pubkey(),
                    Role::Curator.pubkey(),
                ];
                let key = self.as_key(&Role::Guardian.pubkey());
                let needs = if on {
                    Needs::Role(Role::Guardian)
                } else {
                    Needs::Admin
                };
                (
                    w.set_revoked_ix(
                        key.pubkey(),
                        targets[usize::from(target) % targets.len()],
                        on,
                    ),
                    vec![key],
                    needs,
                )
            }
            Step::Arbiter { tree: t } => {
                let key = self.best_key();
                let ix = if usize::from(t) % (trees.len() + 1) == trees.len() {
                    w.arbiter_ix(&e, key.pubkey(), None, e.commitment)
                } else {
                    let t = tree(t);
                    match w.challenge(c, &t.commitment) {
                        Some(ch) => w.arbiter_ix(&e, key.pubkey(), Some(&ch), t.commitment),
                        None => w.arbiter_ix(&e, key.pubkey(), None, t.commitment),
                    }
                };
                (ix, vec![key], Needs::Role(Role::Arbiter))
            }
            Step::Rotate { role } => {
                let key = self.best_key();
                let ix = match role % 3 {
                    0 => w.rotate_ix(
                        key.pubkey(),
                        EscrowRole::Resolver,
                        e.resolver,
                        Role::Attacker(0).pubkey(),
                    ),
                    1 => w.rotate_ix(
                        key.pubkey(),
                        EscrowRole::Compliance,
                        e.compliance,
                        Role::Attacker(1).pubkey(),
                    ),
                    _ => w.rotate_ix(
                        key.pubkey(),
                        EscrowRole::Regrader,
                        e.regraders[usize::from(role / 3 % SEATS)],
                        Role::Regrader(SEATS).pubkey(),
                    ),
                };
                (ix, vec![key], Needs::Admin)
            }
            Step::SetLimits => {
                let key = self.best_key();
                let mut limits = World::limits(w.panel);
                limits.escrow_cap = u64::MAX;
                limits.flow_capacity = u64::MAX;
                limits.max_house_regraders = SEATS;
                (
                    w.set_limits_ix(key.pubkey(), limits),
                    vec![key],
                    Needs::Admin,
                )
            }
            Step::DonateTokens { amount } => {
                let amount = [1, 1_000_000, TOTAL / 10, TOTAL][usize::from(amount % 4)];
                let sent = self.send_donation(c, w.donate_tokens_ix(amount), &label);
                if sent.ok {
                    self.donated_tokens += amount;
                    // The donation is not the adversary's gain: audit again with it counted.
                    let seen = self.seen(c);
                    self.audit(c, seen, &label);
                }
                return;
            }
            Step::DonateLamports => {
                let sent = self.send_donation(c, w.donate_lamports_ix(SOL), &label);
                if sent.ok {
                    self.donated_lamports += SOL;
                    let seen = self.seen(c);
                    self.audit(c, seen, &label);
                }
                return;
            }
        };
        self.send_needing(c, ix, &signers, needs, &label);
    }

    /// A donation: not this program's instruction, so the audit after it runs once the model
    /// counted it.
    fn send_donation(&mut self, c: &mut impl Chain, ix: Instruction, what: &str) -> Sent {
        self.send_other(c, ix, &[Role::Attacker(0).key()], what)
    }

    /// Another program's instruction (the Token or associated token program's), traced; the
    /// caller audits after it where it moved anything the oracle counts.
    fn send_other(
        &mut self,
        c: &mut impl Chain,
        ix: Instruction,
        signers: &[&Keypair],
        what: &str,
    ) -> Sent {
        let sent = self.world.send(c, ix, signers);
        self.trace.push(format!(
            "t={} {what}: {}",
            c.time(),
            if sent.ok { "ok" } else { "failed" }
        ));
        sent
    }

    // --------------------------------------------------------------------- the honest parties

    fn free(&self, c: &impl Chain, key: &Pubkey) -> bool {
        !self.holds(key) && !self.revoked(c, key) && Role::of(key).is_some()
    }

    /// Every honest party acts on what it sees now.
    pub fn react(&mut self, c: &mut impl Chain) {
        self.last_react = c.time();
        let w = self.world.clone();
        let honest = self.honest().clone();

        // The resolver posts the honest result once the entries deadline has passed (the committed
        // root is final then).
        let e = self.escrow(c);
        let now = w.escrow_now(c);
        if e.status == EscrowStatus::Open
            && self.free(c, &e.resolver)
            && e.entries_root != [0; 32]
            && now >= e.entries_deadline
            && now < e.resolve_deadline
        {
            let key = Role::of(&e.resolver).unwrap().key();
            self.send(
                c,
                w.post_ix(key.pubkey(), &honest, TOTAL),
                &[key],
                "honest post",
            );
        }

        // The watcher challenges any other result with the honest one.
        let e = self.escrow(c);
        if matches!(
            e.status,
            EscrowStatus::Challengeable | EscrowStatus::Disputed
        ) && e.commitment != honest.commitment
            && w.challenge(c, &honest.commitment).is_none()
            && w.escrow_now(c) < e.challenge_deadline
        {
            if let Some(watcher) = (0..WATCHERS)
                .map(Role::Watcher)
                .find(|r| !self.revoked(c, &r.pubkey()))
            {
                let key = watcher.key();
                let (hash, salt) = w.commit_of(&key.pubkey(), &honest);
                self.commits
                    .push((w.commit_pda(&key.pubkey(), &hash), key.pubkey()));
                let commit = w.challenge_commit_ix(key.pubkey(), hash);
                if self.send(c, commit, &[key], "watcher commit").ok {
                    c.next_slot();
                    self.challenges.push(honest.commitment);
                    let reveal = w.challenge_reveal_ix(key.pubkey(), hash, salt, &honest);
                    self.send(c, reveal, &[key], "watcher reveal");
                }
            }
        }

        // The free regraders vote the honest side.
        for seat in 0..usize::from(SEATS) {
            let e = self.escrow(c);
            let regrader = e.regraders[seat];
            if e.status != EscrowStatus::Disputed
                || !self.free(c, &regrader)
                || w.escrow_now(c) >= e.attest_deadline
                || w.voted(c, &regrader).is_some()
            {
                continue;
            }
            let commitment = if e.commitment == honest.commitment {
                Some(e.commitment)
            } else {
                w.challenge(c, &honest.commitment)
                    .map(|_| honest.commitment)
            };
            if let Some(commitment) = commitment {
                let key = Role::of(&regrader).unwrap().key();
                let ix = w.attest_ix(c, key.pubkey(), commitment);
                self.send(c, ix, &[key], &format!("honest vote, seat {seat}"));
            }
        }

        // The guardian hands the arbiter an undecided escrow the honest side has no quorum in: at
        // once when the watcher cannot rebuild the posted result or a recorded quorum's, and
        // after the challenge window when any dispute or commit is open (from then on a quorum's
        // votes and settle can land together).
        let e = self.escrow(c);
        let guardian = Role::Guardian.pubkey();
        if matches!(
            e.status,
            EscrowStatus::Challengeable | EscrowStatus::Disputed
        ) && self.free(c, &guardian)
        {
            let honest_quorum = (e.commitment == honest.commitment && e.votes_result >= e.k)
                || (e.challenger != Pubkey::default() && e.alt_commitment == honest.commitment);
            let mismatch = e.commitment != honest.commitment
                || (e.challenger != Pubkey::default() && e.alt_commitment != honest.commitment);
            let open = e.status == EscrowStatus::Disputed || e.pending_commits > 0;
            let late = w.escrow_now(c) >= e.challenge_deadline;
            if !honest_quorum && (mismatch || (late && open)) {
                let key = Role::Guardian.key();
                self.send(c, w.escalate_ix(guardian), &[key], "guardian escalate");
            }
        }

        // The arbiter applies the honest side of a Frozen escrow.
        let e = self.escrow(c);
        let arbiter = w.config(c).arbiter;
        if e.status == EscrowStatus::Frozen && self.free(c, &arbiter) {
            let key = Role::of(&arbiter).unwrap().key();
            if e.commitment == honest.commitment {
                let ix = w.arbiter_ix(&e, key.pubkey(), None, e.commitment);
                self.send(c, ix, &[key], "arbiter: posted");
            } else if let Some(ch) = w.challenge(c, &honest.commitment).filter(|ch| ch.votes > 0) {
                let ix = w.arbiter_ix(&e, key.pubkey(), Some(&ch), honest.commitment);
                self.send(c, ix, &[key], "arbiter: the honest alternative");
            }
        }

        // The compliance key holds every claimant the honest rubric does not pay (fail-closed).
        let e = self.escrow(c);
        if e.status != EscrowStatus::Closed && self.free(c, &e.compliance) {
            let key = Role::of(&e.compliance).unwrap().key();
            for (claimant, _, receipt) in self.accounts.clone() {
                if claimant == Role::Sponsor {
                    continue;
                }
                let pubkey = claimant.pubkey();
                let Some(receipt) = c.anchor::<ClaimReceipt>(&receipt) else {
                    continue;
                };
                let honest_leaf = matches!(claimant, Role::Winner(i)
                    if receipt.total_amount == PRIZES[usize::from(i)]);
                if !receipt.is_held() && receipt.total_amount > 0 && !honest_leaf {
                    let ix = w.hold_ix(key.pubkey(), pubkey);
                    self.send(c, ix, &[key], &format!("compliance holds {claimant:?}"));
                }
            }
        }

        // The winners claim their honest leaves.
        for i in 0..2u8 {
            let winner = Role::Winner(i);
            let e = self.escrow(c);
            let now = w.escrow_now(c);
            let (prize, pubkey) = (PRIZES[usize::from(i)], winner.pubkey());
            let leaf = self.tree_with_root(&e.payout_root).and_then(|t| {
                t.leaves
                    .iter()
                    .position(|l| *l == (pubkey, prize))
                    .map(|j| t.proofs[j].clone())
            });
            let receipt = w.receipt_state(c, &pubkey);
            if e.status != EscrowStatus::Claimable
                || now > e.claim_deadline
                || self.revoked(c, &pubkey)
                || receipt
                    .as_ref()
                    .is_some_and(|r| r.is_held() || r.amount_claimed >= prize)
            {
                continue;
            }
            let Some(proof) = leaf else { continue };
            let key = winner.key();
            if self.free(c, &e.compliance) {
                let compliance = Role::of(&e.compliance).unwrap().key();
                let ix = w.claim_ix(pubkey, Some(compliance.pubkey()), prize, 0, proof);
                self.send(
                    c,
                    ix,
                    &[key, compliance],
                    &format!("{winner:?} claims, co-signed"),
                );
            } else if receipt.as_ref().is_none_or(|r| r.requested_at == 0) {
                let ix = w.request_claim_ix(pubkey, prize, proof);
                self.send(c, ix, &[key], &format!("{winner:?} requests"));
            } else if receipt
                .as_ref()
                .is_some_and(|r| now >= r.requested_at + e.hold_window)
            {
                let ix = w.claim_ix(pubkey, None, prize, 0, proof);
                self.send(c, ix, &[key], &format!("{winner:?} claims on the lapse"));
            }
        }

        // The crank: settle, refund, close what is over.
        let e = self.escrow(c);
        let now = w.escrow_now(c);
        if matches!(
            e.status,
            EscrowStatus::Challengeable | EscrowStatus::Disputed
        ) && now >= e.challenge_deadline
        {
            self.send(c, w.settle_ix(&e), &[], "crank settle");
        }
        let e = self.escrow(c);
        let now = w.escrow_now(c);
        let refundable = match e.status {
            EscrowStatus::Closed => false,
            EscrowStatus::Claimable => now > e.claim_deadline,
            EscrowStatus::Open => now >= e.resolve_deadline,
            _ => now > e.hard_deadline,
        };
        if refundable {
            self.send(c, w.refund_ix(&e), &[], "crank refund");
        }
        self.close_commits(c, "crank close_commit");
        self.close_challenges(c, "crank close_challenge");
        self.close_attestations(c, "crank close_attestation");

        // The user sponsor's proposals: the honest curator approves the world's (the house's
        // terms) a day into its review and rejects any other at its first look; the crank returns
        // each once its review_deadline has passed undecided, and refunds the escrow the world's
        // opened once it is due. Each return goes to a token account the user sponsor owns
        // (user_destination).
        if let Some(p) = w.proposal.clone() {
            let sponsor = p.sponsor;
            let now = c.time();
            let curator = w.config(c).curator;
            if w.proposal_state(c, &sponsor, &p.cid).is_some()
                && self.free(c, &curator)
                && now >= p.submitted_at + DAY
                && now <= p.review_deadline
            {
                let key = Role::of(&curator).unwrap().key();
                let ix = w.approve_proposal_ix(key.pubkey(), sponsor, p.cid);
                self.send(c, ix, &[key], "curator approves");
            }
            if w.proposal_state(c, &sponsor, &USER_CID).is_some() && self.free(c, &curator) {
                let key = Role::of(&curator).unwrap().key();
                let destination = self.user_destination(c);
                let ix =
                    w.close_proposal_to_ix(key.pubkey(), sponsor, USER_CID, REASON, destination);
                self.send(c, ix, &[key], "curator rejects the sponsor's own terms");
            }
            for (cid, review_deadline) in [
                (p.cid, p.review_deadline),
                (
                    USER_CID,
                    self.user_proposal
                        .as_ref()
                        .map_or(i64::MAX, |u| u.review_deadline),
                ),
            ] {
                if w.proposal_state(c, &sponsor, &cid).is_some() && now > review_deadline {
                    let key = Role::Payer.key();
                    let destination = self.user_destination(c);
                    let ix =
                        w.close_proposal_to_ix(key.pubkey(), sponsor, cid, [0; 32], destination);
                    self.send(c, ix, &[key], "crank expires a proposal");
                }
            }
            let address = w.escrow_at(&sponsor, &p.cid);
            if let Some(e) = w.escrow_state_at(c, &sponsor, &p.cid) {
                let escrow_now = prize_escrow::escrow_now(&e, &w.config(c), now);
                let due = match e.status {
                    EscrowStatus::Closed => false,
                    EscrowStatus::Claimable => escrow_now > e.claim_deadline,
                    EscrowStatus::Open => escrow_now >= e.resolve_deadline,
                    _ => escrow_now > e.hard_deadline,
                };
                if due {
                    let destination = self.user_destination(c);
                    let ix = w.refund_at_ix(address, &e, destination);
                    self.send(c, ix, &[], "crank refunds the proposal's escrow");
                }
            }
        }
    }

    /// Whether the user sponsor's proposals (if any) are out (approved or returned) and the
    /// escrow the world's opened, if it did, refunded: nothing they held still counts against
    /// pending_value or open_value.
    fn proposal_settled(&self, c: &impl Chain) -> bool {
        self.world.proposal.as_ref().is_none_or(|p| {
            let w = &self.world;
            w.proposal_state(c, &p.sponsor, &p.cid).is_none()
                && w.proposal_state(c, &p.sponsor, &USER_CID).is_none()
                && w.escrow_state_at(c, &p.sponsor, &p.cid)
                    .is_none_or(|e| e.status == EscrowStatus::Closed)
        })
    }

    /// Closes every vote of the escrow's panel once it is Closed (close_attestation): its rent goes
    /// back to its regrader. Only a panel key votes, and a seat that voted never rotates.
    fn close_attestations(&mut self, c: &mut impl Chain, what: &str) {
        let w = self.world.clone();
        let e = self.escrow(c);
        if e.status != EscrowStatus::Closed {
            return;
        }
        for regrader in e.regraders[..usize::from(e.n)].iter().copied() {
            if w.voted(c, &regrader).is_some() {
                self.send(c, w.close_attestation_ix(regrader), &[], what);
            }
        }
    }

    fn close_commits(&mut self, c: &mut impl Chain, what: &str) {
        let w = self.world.clone();
        if !matches!(
            self.escrow(c).status,
            EscrowStatus::Claimable | EscrowStatus::Closed
        ) {
            return;
        }
        for (commit, challenger) in self.commits.clone() {
            if c.anchor::<CommitRecord>(&commit).is_some() {
                self.send(c, w.close_commit_ix(&commit, challenger), &[], what);
            }
        }
    }

    fn close_challenges(&mut self, c: &mut impl Chain, what: &str) {
        let w = self.world.clone();
        if !matches!(
            self.escrow(c).status,
            EscrowStatus::Claimable | EscrowStatus::Closed
        ) {
            return;
        }
        for commitment in self.challenges.clone() {
            if let Some(ch) = w.challenge(c, &commitment) {
                self.send(c, w.close_challenge_ix(&ch), &[], what);
            }
        }
    }

    /// Runs the honest parties alone until the escrow is Closed and every commit, challenge and
    /// attestation account is closed (or `rounds` waits pass), then asserts the end state: Closed,
    /// every bond back, the vault swept, every vote closed, and (when nobody who could grief them is
    /// compromised) the winners paid in full.
    pub fn drain(&mut self, c: &mut impl Chain, rounds: usize) -> Result<(), String> {
        for _ in 0..rounds {
            if self.settled(c) {
                break;
            }
            self.step(c, Step::Wait(MAX_LATENCY as u32))?;
            self.step(c, Step::React)?;
        }
        let w = self.world.clone();
        let e = self.escrow(c);
        let mut end = Vec::new();
        if e.status != EscrowStatus::Closed {
            end.push(format!(
                "the escrow never closed: {:?} after the drain",
                e.status
            ));
        }
        if e.resolver_bond + e.challenger_bond + e.commit_bond != 0 {
            end.push(format!(
                "bonds still held after the drain: resolver {}, challengers {}, commits {}",
                e.resolver_bond, e.challenger_bond, e.commit_bond
            ));
        }
        if c.tokens(&w.vault()) != 0 {
            end.push("the vault still holds tokens".to_string());
        }
        for regrader in &e.regraders[..usize::from(e.n)] {
            if w.voted(c, regrader).is_some() {
                end.push(format!(
                    "{:?}'s Attestation is still open after the drain",
                    Role::of(regrader)
                ));
            }
        }
        if !self.proposal_settled(c) {
            end.push(
                "a proposal was neither approved nor returned, or the escrow an approval opened was never refunded: pending_value or open_value pinned"
                    .to_string(),
            );
        }
        if self.who.winners_paid() {
            for i in 0..2u8 {
                let got = c.tokens(&w.ata(&Role::Winner(i).pubkey()));
                if got != PRIZES[usize::from(i)] {
                    end.push(format!(
                        "Winner({i}) received {got}, not its prize {}",
                        PRIZES[usize::from(i)]
                    ));
                }
            }
        }
        if end.is_empty() {
            Ok(())
        } else {
            self.violations.extend(end);
            Err(self.report())
        }
    }

    fn settled(&self, c: &impl Chain) -> bool {
        let w = &self.world;
        let e = self.escrow(c);
        e.status == EscrowStatus::Closed
            && self.proposal_settled(c)
            && self
                .commits
                .iter()
                .all(|(commit, _)| c.anchor::<CommitRecord>(commit).is_none())
            && self
                .challenges
                .iter()
                .all(|commitment| w.challenge(c, commitment).is_none())
            && e.regraders[..usize::from(e.n)]
                .iter()
                .all(|regrader| w.voted(c, regrader).is_none())
    }
}

/// The owner of the token account at `address`, or None when there is none.
fn token_owner(c: &impl Chain, address: &Pubkey) -> Option<Pubkey> {
    c.account(address)
        .filter(|a| a.lamports > 0 && a.data.len() == spl_token::state::Account::LEN)
        .and_then(|a| spl_token::state::Account::unpack(&a.data).ok())
        .map(|t| t.owner)
}

/// The claimants hold and release target: the winners and the adversary's two.
fn claimants() -> [Pubkey; 4] {
    [
        Role::Winner(0).pubkey(),
        Role::Winner(1).pubkey(),
        Role::Attacker(0).pubkey(),
        Role::Attacker(1).pubkey(),
    ]
}

/// The lifecycle's edges (lib.rs, state::EscrowStatus): Closed has none.
pub fn edge(from: EscrowStatus, to: EscrowStatus) -> bool {
    use EscrowStatus::*;
    matches!(
        (from, to),
        (Open, Challengeable | Closed)
            | (Challengeable, Disputed | Claimable | Frozen | Closed)
            | (Disputed, Claimable | Frozen | Closed)
            | (Frozen, Claimable | Closed)
            | (Claimable, Closed)
    )
}
