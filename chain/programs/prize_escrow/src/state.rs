use anchor_lang::prelude::*;

use crate::{
    constants::{
        ARBITER_SLACK, BOND_FLOOR_RENTS, CHALLENGE_SEED, COMMIT_SEED, ESCROW_SEED, HOLD_NONE,
        MAX_REGRADERS, MAX_WINDOW, MIN_ATTEST_WINDOW, MIN_CHALLENGE_WINDOW, MIN_CLAIM_WINDOW,
        MIN_HOLD_WINDOW, RESULT_COMMITMENT_DOMAIN,
    },
    error::EscrowError,
};

/// What a posted, challenged or arbiter-set result commits to:
/// `sha256(RESULT_COMMITMENT_DOMAIN || result_sha256 || payout_root || u64le(total))`. The payout
/// root and the total are in it, so a result whose document hash is honest but whose root (or
/// total) is not is a different result: anyone who rebuilds the honest root can challenge it, and
/// regraders vote on what they rebuild, root included. server/chain/result.ts resultCommitment is
/// the same function; tests/fixtures/chain/commitment-vectors.json holds vectors both check.
pub fn result_commitment(result_sha256: &[u8; 32], payout_root: &[u8; 32], total: u64) -> [u8; 32] {
    solana_sha256_hasher::hashv(&[
        RESULT_COMMITMENT_DOMAIN,
        result_sha256,
        payout_root,
        &total.to_le_bytes(),
    ])
    .to_bytes()
}

/// The smallest bond_lamports open_escrow accepts under `rent`: BOND_FLOOR_RENTS times the
/// rent-exempt minimum of an empty account (saturating; no rent comes near u64::MAX).
pub fn bond_floor(rent: &Rent) -> u64 {
    rent.minimum_balance(0).saturating_mul(BOND_FLOOR_RENTS)
}

/// Where an escrow is in its life. Every instruction names the statuses it accepts.
///
/// post_result moves Open to Challengeable. From there settle (no challenge) makes it Claimable,
/// or the first challenge makes it Disputed (later ones, each a distinct alternative, join the
/// dispute), which settle ends as Claimable (the side a quorum of regraders backed applies) or
/// Frozen (no quorum). arbiter_resolve moves Frozen to Claimable on the side it chooses, and
/// refund moves any status to Closed.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq, InitSpace)]
pub enum EscrowStatus {
    /// Funded at open; the entries root and then the result are still to come.
    Open,
    /// A result is posted with the resolver's bond; anyone may challenge it until
    /// challenge_deadline. Once the window is over unchallenged (Escrow::challenge_window_over)
    /// the result binds: settle makes it Claimable, and escalate refuses it.
    Challengeable,
    /// Challenged with one or more bonded alternative results (each its own Challenge PDA, more
    /// may join until challenge_deadline); the named regraders attest until attest_deadline
    /// (challenge_deadline + attest_window), and nothing settles before challenge_deadline.
    Disputed,
    /// The payout root stands (the posted one, or a challenge's alternative a quorum or the
    /// arbiter applied): winners claim until claim_deadline, and refund waits until after it
    /// whatever hard_deadline says.
    Claimable,
    /// No side reached the quorum by attest_deadline: only the arbiter (choosing the posted result
    /// or a challenge's alternative a named regrader voted for) or a refund after hard_deadline
    /// moves it on.
    Frozen,
    /// Refunded. The account stays as the replay marker, so the competition id cannot be
    /// opened again.
    Closed,
}

/// Which result an attestation backs.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq, InitSpace)]
pub enum AttestSide {
    /// The posted result: its commitment.
    Result,
    /// A challenge's alternative: that Challenge's alt_commitment.
    Alt,
}

/// Which result arbiter_resolve applies to a Frozen escrow: the arbiter picks a side, it never
/// writes a result of its own.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArbiterChoice {
    /// The resolver's posted result (commitment): every challenger's bond goes to the resolver.
    Posted,
    /// One challenge's alternative (the Challenge PDA passed in): the resolver's bond and every
    /// other challenger's go to its challenger.
    Alternative,
}

/// One side of a dispute, as the escrow stores it: what applying that side makes the result in
/// force (claims verify against payout_root, capped by total).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResultSide {
    pub result_sha256: [u8; 32],
    pub payout_root: [u8; 32],
    pub total: u64,
    /// result_commitment(result_sha256, payout_root, total).
    pub commitment: [u8; 32],
}

/// The terms open_escrow fixes for the escrow's whole life (the competition id is its own
/// argument, because it seeds the PDA with the sponsor).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct EscrowTerms {
    /// The prize pot in mint base units, moved into the vault at open.
    pub total: u64,
    /// sha256 of the competition's published rules.
    pub rules_sha256: [u8; 32],
    /// Commits the entries root and posts the result.
    pub resolver: Pubkey,
    /// Co-signs claims and places holds; Pubkey::default() means no compliance gate.
    pub compliance: Pubkey,
    /// Resolves a Frozen escrow (a Squads v4 vault PDA, which can only sign through the
    /// multisig's CPI).
    pub arbiter: Pubkey,
    /// Receives refunds (the vault's leftovers and its rent). A forfeited bond goes to the side
    /// that won, never here.
    pub refund_to: Pubkey,
    /// The pre-named regraders, 1 to MAX_REGRADERS distinct keys; n is their count.
    pub regraders: Vec<Pubkey>,
    /// Attestations needed to settle a dispute: 1 <= k <= n and 2k > n.
    pub k: u8,
    /// The SOL bond (lamports) the resolver posts with a result and a challenger posts with a
    /// challenge; at least bond_floor (BOND_FLOOR_RENTS rent-exempt minimums of an empty account).
    pub bond_lamports: u64,
    /// Unix seconds: commit_entries must land before it (the final phase's start).
    pub entries_deadline: i64,
    /// Unix seconds: the final phase's end. post_result lands at or after it, never on a
    /// competition still running.
    pub final_end: i64,
    /// Unix seconds: post_result must land before it, or the pot can be refunded in full.
    pub resolve_deadline: i64,
    /// Seconds a posted result stays challengeable (at least MIN_CHALLENGE_WINDOW).
    pub challenge_window: i64,
    /// Seconds regraders have to attest once the challenge window has closed (at least
    /// MIN_ATTEST_WINDOW): attest_deadline is challenge_deadline + attest_window, set by the first
    /// challenge however early in the challenge window it lands. Regraders may vote from that
    /// challenge on, until attest_deadline.
    pub attest_window: i64,
    /// Seconds after request_claim before an unheld claim clears without the compliance
    /// co-signature (at least MIN_HOLD_WINDOW).
    pub hold_window: i64,
    /// Seconds winners have to claim once the escrow is Claimable: at least MIN_CLAIM_WINDOW, and
    /// longer than hold_window when a compliance key is set.
    pub claim_window: i64,
    /// Unix seconds after which anyone may refund an escrow that is not Claimable, whatever its
    /// status (a Claimable one refunds only after its claim_deadline).
    pub hard_deadline: i64,
}

impl EscrowTerms {
    /// The bounds open_escrow holds the terms to, at unix time `now` and with `min_bond` the bond
    /// floor (bond_floor of the cluster's rent; the server's competition_escrow CHECK constraints
    /// mirror the ones a row can hold):
    /// - `total` > 0 and `bond_lamports` > 0 (InvalidAmount: an unbonded result or challenge costs
    ///   nothing), and `bond_lamports` >= `min_bond` (BondBelowFloor);
    /// - 1 to MAX_REGRADERS distinct, non-default regraders, and 1 <= k <= n with 2k > n;
    /// - each window at least its minimum (MIN_CHALLENGE_WINDOW, MIN_ATTEST_WINDOW,
    ///   MIN_HOLD_WINDOW, MIN_CLAIM_WINDOW) and at most MAX_WINDOW (InvalidWindow);
    /// - with a compliance key, claim_window > hold_window (ClaimWindowTooShort), so a request at
    ///   the start of the claim window clears without the co-signature before the window ends;
    /// - now < entries_deadline <= final_end < resolve_deadline (InvalidDeadlines);
    /// - hard_deadline >= resolve_deadline + challenge_window + attest_window + hold_window +
    ///   claim_window + ARBITER_SLACK (HardDeadlineTooEarly).
    pub fn validate(&self, now: i64, min_bond: u64) -> Result<()> {
        require!(
            self.total > 0 && self.bond_lamports > 0,
            EscrowError::InvalidAmount
        );
        require!(self.bond_lamports >= min_bond, EscrowError::BondBelowFloor);

        let n = self.regraders.len();
        require!(
            (1..=usize::from(MAX_REGRADERS)).contains(&n),
            EscrowError::InvalidRegraderSet
        );
        // n <= MAX_REGRADERS, so it fits a u8.
        require!(
            Escrow::quorum_ok(self.k, n as u8),
            EscrowError::InvalidRegraderSet
        );
        for (i, regrader) in self.regraders.iter().enumerate() {
            require!(
                *regrader != Pubkey::default() && !self.regraders[..i].contains(regrader),
                EscrowError::InvalidRegraderSet
            );
        }

        for (window, min) in [
            (self.challenge_window, MIN_CHALLENGE_WINDOW),
            (self.attest_window, MIN_ATTEST_WINDOW),
            (self.hold_window, MIN_HOLD_WINDOW),
            (self.claim_window, MIN_CLAIM_WINDOW),
        ] {
            require!(
                (min..=MAX_WINDOW).contains(&window),
                EscrowError::InvalidWindow
            );
        }

        if self.compliance != Pubkey::default() {
            require!(
                self.claim_window > self.hold_window,
                EscrowError::ClaimWindowTooShort
            );
        }

        require!(
            now < self.entries_deadline
                && self.entries_deadline <= self.final_end
                && self.final_end < self.resolve_deadline,
            EscrowError::InvalidDeadlines
        );
        // Each window is at most MAX_WINDOW (i32::MAX), so only a resolve_deadline near i64::MAX
        // can overflow, and no hard_deadline could follow it.
        let earliest_hard = [
            self.challenge_window,
            self.attest_window,
            self.hold_window,
            self.claim_window,
            ARBITER_SLACK,
        ]
        .into_iter()
        .try_fold(self.resolve_deadline, i64::checked_add);
        require!(
            earliest_hard.is_some_and(|earliest| self.hard_deadline >= earliest),
            EscrowError::HardDeadlineTooEarly
        );
        Ok(())
    }
}

/// One competition's prize escrow. PDA: `["escrow", sponsor, competition_id]`. Its vault is the
/// associated token account of (this account, mint) under the classic Token program.
#[account]
#[derive(InitSpace, Debug, PartialEq, Eq)]
pub struct Escrow {
    pub bump: u8,
    pub decimals: u8,
    pub status: EscrowStatus,
    /// Attestations needed to settle a dispute.
    pub k: u8,
    /// How many of `regraders` are set.
    pub n: u8,
    /// The competition's 16-byte UUID, a PDA seed after the sponsor.
    pub competition_id: [u8; 16],

    /// Opened and funded the escrow; a PDA seed.
    pub sponsor: Pubkey,
    pub resolver: Pubkey,
    /// Pubkey::default() when there is no compliance gate.
    pub compliance: Pubkey,
    // The Config's arbiter when the escrow opened (open_escrow refuses any other:
    // ArbiterNotConfig), kept as the record of it (EscrowOpened carries it too). Nothing reads it
    // after open: arbiter_resolve answers to Config.arbiter, so a set_config_role rotation moves
    // every escrow at once, and the server's arbiterResolveIx reads Config.arbiter as well (#756).
    pub arbiter: Pubkey,
    pub refund_to: Pubkey,
    pub mint: Pubkey,
    /// The challenger whose alternative won: attest records it when the regraders' votes for its
    /// commitment reach k, arbiter_resolve when the arbiter chooses it. Pubkey::default() until
    /// one does, and again once the arbiter keeps the posted result over a recorded one
    /// (Escrow::clear_alternative): it never names a losing alternative's challenger (every
    /// challenge's own challenger is in its Challenge PDA).
    pub challenger: Pubkey,

    pub rules_sha256: [u8; 32],
    pub entries_root: [u8; 32],
    /// The root claims verify against: the posted one, or the winning alternative's once a quorum
    /// (settle) or the arbiter (arbiter_resolve) applied it.
    pub payout_root: [u8; 32],
    pub result_sha256: [u8; 32],
    /// The posted regrade kit's hash; applying an alternative leaves it as posted.
    pub kit_sha256: [u8; 32],
    /// result_commitment(result_sha256, payout_root, total) of the result in force (the posted
    /// one, or the applied alternative's); while Disputed, attest votes Result on it.
    pub commitment: [u8; 32],
    /// The winning challenge's alternative (the `challenger`'s): its document hash, payout root
    /// and commitment, copied from its Challenge PDA when its votes reach k or the arbiter
    /// chooses it; all zero until then, and zeroed again with `challenger` when the arbiter keeps
    /// the posted result instead. attest votes Alt on a Challenge's alt_commitment.
    pub alt_result_sha256: [u8; 32],
    pub alt_payout_root: [u8; 32],
    pub alt_commitment: [u8; 32],

    pub entries_count: u32,
    /// Challenges opened, each its own Challenge PDA (Challenge.index counts from 0).
    pub challenge_count: u32,
    /// The pot in mint base units: the opened deposit until post_result, then the posted (or the
    /// applied alternative's) total, at most the vault balance, which caps what all claims take
    /// together.
    pub total: u64,
    pub total_claimed: u64,
    /// The winning challenge's alternative total; 0 until one wins (and again once the arbiter
    /// keeps the posted result over it).
    pub alt_total: u64,
    /// The bond, in lamports, a result or a challenge must post.
    pub bond_lamports: u64,
    /// Lamports of the resolver's bond held in this account.
    pub resolver_bond: u64,
    /// Lamports of every challenger's bond held in this account (bond_lamports per challenge): all
    /// of them go to the winning side when settle or the arbiter decides the dispute; a refund
    /// that decided nothing leaves them for close_challenge to return, each to its payer.
    pub challenger_bond: u64,

    pub entries_deadline: i64,
    /// The final phase's end: post_result lands at or after it.
    pub final_end: i64,
    pub resolve_deadline: i64,
    pub challenge_window: i64,
    pub attest_window: i64,
    pub hold_window: i64,
    pub claim_window: i64,
    pub challenge_deadline: i64,
    pub attest_deadline: i64,
    pub claim_deadline: i64,
    pub hard_deadline: i64,

    /// Regraders who voted the posted commitment.
    pub votes_result: u8,
    /// Regraders who voted a challenge's commitment, every challenge together (each Challenge
    /// counts its own).
    pub votes_alt: u8,
    /// The first `n` slots are the regraders; the rest are Pubkey::default().
    pub regraders: [Pubkey; 5],

    /// What open_escrow and fund moved into the vault: held to Config.escrow_cap, and what refund
    /// takes back off Config.open_value.
    pub deposited: u64,
    /// Config's global stopped seconds (G) when the escrow opened: only a PayoutStop after it
    /// stops this escrow's clock (config::escrow_now).
    pub stop_base: i64,
    /// The global clock (Γ) when the guardian's freeze in force began; 0 with none.
    pub freeze_since: i64,
    /// The global clock (Γ) at which that freeze lapses; 0 with no freeze on record.
    pub freeze_until: i64,
    /// Seconds (on the global clock) of every freeze that has ended.
    pub frozen_secs: i64,
    /// Seconds after challenge_deadline a committed challenge may still be revealed (Config's
    /// reveal_grace at open).
    pub reveal_grace: i64,
    /// Lamports of the bonds of commits not yet revealed, held in this account apart from the
    /// challenge bonds: close_commit returns each to its own challenger.
    pub commit_bond: u64,
    /// Commits not yet revealed or closed: settle waits for challenge_deadline + reveal_grace
    /// while any could still be revealed.
    pub pending_commits: u32,
    /// Zeroed room for later fields.
    pub reserved: [u8; 64],
}

const _: () = assert!(
    MAX_REGRADERS as usize == 5,
    "Escrow.regraders has MAX_REGRADERS slots"
);

impl Escrow {
    /// Account size: the 8-byte discriminator plus the fields.
    pub const SPACE: usize = 8 + Self::INIT_SPACE;

    /// Whether k-of-n is a valid quorum: 1 <= k <= n <= MAX_REGRADERS and 2k > n, so no two
    /// commitments (the posted one, or any challenge's) can both reach k.
    pub fn quorum_ok(k: u8, n: u8) -> bool {
        k >= 1 && k <= n && n <= MAX_REGRADERS && 2 * u16::from(k) > u16::from(n)
    }

    /// Whether `key` is one of the escrow's `n` regraders.
    pub fn is_regrader(&self, key: &Pubkey) -> bool {
        self.regraders
            .get(..usize::from(self.n))
            .is_some_and(|set| set.contains(key))
    }

    /// Whether claims need the compliance key (co-signature or a lapsed request).
    pub fn has_compliance(&self) -> bool {
        self.compliance != Pubkey::default()
    }

    /// Whether a challenge's alternative has won (its votes reached k, or the arbiter chose it):
    /// the escrow then holds it in `challenger` and the alt_* fields.
    pub fn has_challenger(&self) -> bool {
        self.challenger != Pubkey::default()
    }

    /// Whether a Disputed escrow's vote is decided: k votes for the posted commitment, or a
    /// challenge whose votes reached k (attest recorded it as the winning alternative: only that
    /// writes `challenger` while Disputed). Since 2k > n, at most one side can reach k.
    pub fn quorum_recorded(&self) -> bool {
        self.votes_result >= self.k || self.has_challenger()
    }

    /// When, on the escrow clock, settle may first apply the recorded quorum (None with none):
    /// challenge_deadline for k votes upholding the posted result, attest_deadline for a
    /// challenge's alternative at k, which overturns it (settle's OverturnWindowOpen before). From
    /// then on the vote binds: escalate refuses it (QuorumRecorded), as refund always does. An
    /// unchallenged result binds the same way once its challenge window is over
    /// (challenge_window_over; escalate's UnchallengedResultBinds).
    pub fn quorum_settles_at(&self) -> Option<i64> {
        if self.votes_result >= self.k {
            Some(self.challenge_deadline)
        } else if self.has_challenger() {
            Some(self.attest_deadline)
        } else {
            None
        }
    }

    /// Whether the challenge window is over at escrow clock `now`, as settle's
    /// require_window_over reads it: at or past challenge_deadline, and past the reveal grace
    /// too (challenge_deadline + reveal_grace) while a commit is pending, which may still be
    /// revealed into a dispute until then. A Challengeable escrow whose window is over binds its
    /// posted result: nothing can challenge it any more and settle makes it Claimable.
    pub fn challenge_window_over(&self, now: i64) -> Result<bool> {
        if now < self.challenge_deadline {
            return Ok(false);
        }
        Ok(self.pending_commits == 0 || now >= self.reveal_deadline()?)
    }

    /// Records `challenge` as the winning alternative (`challenger` and the alt_* fields), which
    /// apply(Alternative) then puts in force.
    pub fn record_alternative(&mut self, challenge: &ChallengeRecord) {
        self.challenger = challenge.challenger;
        self.alt_result_sha256 = challenge.alt_result_sha256;
        self.alt_payout_root = challenge.alt_payout_root;
        self.alt_total = challenge.alt_total;
        self.alt_commitment = challenge.alt_commitment;
    }

    /// Clears a recorded alternative (`challenger` and the alt_* fields back to zero): the
    /// arbiter kept the posted result over it, so the escrow never names a losing alternative as
    /// the one that won. Its Challenge PDA keeps its record until close_challenge.
    pub fn clear_alternative(&mut self) {
        self.challenger = Pubkey::default();
        self.alt_result_sha256 = [0; 32];
        self.alt_payout_root = [0; 32];
        self.alt_total = 0;
        self.alt_commitment = [0; 32];
    }

    /// The result `choice` names as the escrow stores it: the posted one (result_sha256,
    /// payout_root, total, commitment) or the winning challenge's alternative (the alt_* fields).
    pub fn side(&self, choice: ArbiterChoice) -> ResultSide {
        match choice {
            ArbiterChoice::Posted => ResultSide {
                result_sha256: self.result_sha256,
                payout_root: self.payout_root,
                total: self.total,
                commitment: self.commitment,
            },
            ArbiterChoice::Alternative => ResultSide {
                result_sha256: self.alt_result_sha256,
                payout_root: self.alt_payout_root,
                total: self.alt_total,
                commitment: self.alt_commitment,
            },
        }
    }

    /// Makes `choice`'s side the result in force (a no-op for Posted): the root claims verify
    /// against, its document hash, the total that caps claims and their commitment. The alt_*
    /// fields keep the applied alternative as challenged.
    pub fn apply(&mut self, choice: ArbiterChoice) {
        let side = self.side(choice);
        self.result_sha256 = side.result_sha256;
        self.payout_root = side.payout_root;
        self.total = side.total;
        self.commitment = side.commitment;
    }

    /// The lamports each side gets when `winner`'s side wins the dispute, as (to the resolver, to
    /// the winning challenger): every bond held, its own back and every losing side's forfeited
    /// one (the resolver's when an alternative wins, each other challenger's always).
    pub fn bonds_to_winner(&self, winner: ArbiterChoice) -> Result<(u64, u64)> {
        let both = self
            .resolver_bond
            .checked_add(self.challenger_bond)
            .ok_or(EscrowError::MathOverflow)?;
        Ok(match winner {
            ArbiterChoice::Posted => (both, 0),
            ArbiterChoice::Alternative => (0, both),
        })
    }

    /// Every bond the escrow account holds as it tracks them: the resolver's, every challenger's
    /// and every pending commit's. The rest of its lamports (its rent as funded at open, and any
    /// lamports sent to it) is no bond: pay_bond never takes the account below it.
    pub fn tracked_bonds(&self) -> Result<u64> {
        Ok(self
            .resolver_bond
            .checked_add(self.challenger_bond)
            .and_then(|bonds| bonds.checked_add(self.commit_bond))
            .ok_or(EscrowError::MathOverflow)?)
    }

    /// Whether the guardian's freeze is in force at global clock `global_now` (one on record
    /// lapses at freeze_until).
    pub fn is_frozen(&self, global_now: i64) -> bool {
        self.freeze_until != 0 && global_now < self.freeze_until
    }

    /// Every frozen second up to global clock `global_now`: frozen_secs plus the part of the
    /// freeze on record that has elapsed (up to its lapse).
    pub fn frozen_secs_at(&self, global_now: i64) -> i64 {
        let running = if self.freeze_until != 0 {
            global_now
                .min(self.freeze_until)
                .saturating_sub(self.freeze_since)
                .max(0)
        } else {
            0
        };
        self.frozen_secs.saturating_add(running)
    }

    /// Folds the freeze on record (in force or lapsed) into frozen_secs at global clock
    /// `global_now` and clears it.
    pub fn end_freeze(&mut self, global_now: i64) {
        self.frozen_secs = self.frozen_secs_at(global_now);
        self.freeze_since = 0;
        self.freeze_until = 0;
    }

    /// Starts a freeze at global clock `global_now` lasting `duration` seconds of it (a lapsed
    /// one on record is folded first).
    pub fn start_freeze(&mut self, global_now: i64, duration: i64) -> Result<()> {
        self.end_freeze(global_now);
        self.freeze_since = global_now;
        self.freeze_until = global_now
            .checked_add(duration)
            .ok_or(EscrowError::MathOverflow)?;
        Ok(())
    }

    /// When a committed challenge may last be revealed: challenge_deadline + reveal_grace.
    pub fn reveal_deadline(&self) -> Result<i64> {
        Ok(self
            .challenge_deadline
            .checked_add(self.reveal_grace)
            .ok_or(EscrowError::MathOverflow)?)
    }

    /// The seeds the escrow PDA signs with (the vault's authority), bump included:
    /// `["escrow", sponsor, competition_id, bump]`.
    pub fn signer_seeds(&self) -> [&[u8]; 4] {
        [
            ESCROW_SEED,
            self.sponsor.as_ref(),
            &self.competition_id,
            core::slice::from_ref(&self.bump),
        ]
    }
}

/// One claimant's progress against one escrow. PDA: `["claim", escrow, claimant]`.
#[account]
#[derive(InitSpace, Debug, PartialEq, Eq)]
pub struct ClaimReceipt {
    pub claimant: Pubkey,
    /// The leaf amount the claimant proved.
    pub total_amount: u64,
    pub amount_claimed: u64,
    /// Unix seconds of request_claim; 0 when never requested.
    pub requested_at: i64,
    /// HOLD_NONE, or the HOLD_* reason of the hold in force.
    pub hold_reason: u8,
    /// Unix seconds the hold in force was placed; 0 when none.
    pub held_at: i64,
    pub bump: u8,
}

impl ClaimReceipt {
    /// Account size: the 8-byte discriminator plus the fields.
    pub const SPACE: usize = 8 + Self::INIT_SPACE;

    /// Whether a compliance hold is in force.
    pub fn is_held(&self) -> bool {
        self.hold_reason != HOLD_NONE
    }

    /// What is left to claim against `total_amount` (None if amount_claimed ever exceeds it).
    pub fn remaining(&self) -> Option<u64> {
        self.total_amount.checked_sub(self.amount_claimed)
    }
}

/// One regrader's vote in a dispute. PDA: `["attestation", escrow, regrader]`, so each regrader
/// votes once per escrow. The regrader pays its rent; close_attestation returns it to the
/// regrader once the escrow is Closed, when no instruction reads a vote any more.
#[account]
#[derive(InitSpace, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// The regrader who voted and paid the rent (a PDA seed): close_attestation's rent goes to it.
    pub regrader: Pubkey,
    /// The result commitment the regrader rebuilt (document hash, payout root and total): the
    /// posted one (Result) or one challenge's (Alt).
    pub commitment: [u8; 32],
    pub side: AttestSide,
    pub bump: u8,
}

impl Attestation {
    /// Account size: the 8-byte discriminator plus the fields.
    pub const SPACE: usize = 8 + Self::INIT_SPACE;
}

/// One challenge of an escrow: a bonded alternative result (document hash, payout root and
/// total). PDA: `["challenge", escrow, alt_commitment]`, so an escrow takes one challenge per
/// distinct alternative, and a junk challenge never keeps another alternative out. Its bond sits
/// in the escrow account with the others (Escrow.challenger_bond); this account holds its rent,
/// which close_challenge returns to `challenger` once the dispute is over.
#[account]
#[derive(InitSpace, Debug, PartialEq, Eq)]
pub struct ChallengeRecord {
    pub escrow: Pubkey,
    /// Signed the challenge and paid its bond and this account's rent.
    pub challenger: Pubkey,
    pub alt_result_sha256: [u8; 32],
    pub alt_payout_root: [u8; 32],
    /// result_commitment(alt_result_sha256, alt_payout_root, alt_total): the PDA's seed.
    pub alt_commitment: [u8; 32],
    pub alt_total: u64,
    /// The lamports of bond it paid (the escrow's bond_lamports).
    pub bond: u64,
    /// Unix seconds it landed.
    pub opened_at: i64,
    /// Its place among the escrow's challenges, from 0 (the one that opened the dispute).
    pub index: u32,
    /// Regraders who voted its commitment.
    pub votes: u8,
    pub bump: u8,
}

impl ChallengeRecord {
    /// Account size: the 8-byte discriminator plus the fields.
    pub const SPACE: usize = 8 + Self::INIT_SPACE;

    /// Its address: `["challenge", escrow, alt_commitment]` under the program.
    pub fn pda(escrow: &Pubkey, alt_commitment: &[u8; 32]) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[CHALLENGE_SEED, escrow.as_ref(), alt_commitment.as_ref()],
            &crate::ID,
        )
    }

    /// Whether `address` is this record's own PDA, `["challenge", escrow, alt_commitment]` with
    /// its stored bump: the address challenge_reveal's `init` created it at. attest and
    /// arbiter_resolve pin the challenge account they are passed to it in their account
    /// constraints, with its escrow and its commitment.
    pub fn is_at(&self, address: &Pubkey) -> bool {
        Pubkey::create_program_address(
            &[
                CHALLENGE_SEED,
                self.escrow.as_ref(),
                self.alt_commitment.as_ref(),
                &[self.bump],
            ],
            &crate::ID,
        )
        .is_ok_and(|pda| pda == *address)
    }
}

/// What a challenge commits to before it is revealed: `sha256(alt_commitment || challenger ||
/// salt)`. Nobody can read the alternative off a commit, and a commit names its challenger, so a
/// copy of someone else's commit can never be revealed by the copier.
pub fn commit_hash(alt_commitment: &[u8; 32], challenger: &Pubkey, salt: &[u8; 32]) -> [u8; 32] {
    solana_sha256_hasher::hashv(&[alt_commitment, challenger.as_ref(), salt]).to_bytes()
}

/// A committed challenge, not yet revealed. PDA: `["commit", escrow, challenger, hash]`. Its bond
/// sits in the escrow account (Escrow.commit_bond); this account holds its rent. challenge_reveal
/// closes it into a ChallengeRecord (its rent back to the challenger); one never revealed is
/// closed by close_commit once the escrow has decided, its bond and rent back to its own
/// challenger.
#[account]
#[derive(InitSpace, Debug, PartialEq, Eq)]
pub struct CommitRecord {
    pub escrow: Pubkey,
    /// Signed the commit and paid its bond and this account's rent.
    pub challenger: Pubkey,
    /// commit_hash(alt_commitment, challenger, salt).
    pub hash: [u8; 32],
    /// The slot it landed in: a reveal must land in a later one.
    pub slot: u64,
    /// The escrow clock when it landed.
    pub committed_at: i64,
    /// The lamports of bond it paid (the escrow's bond_lamports).
    pub bond: u64,
    pub bump: u8,
}

impl CommitRecord {
    /// Account size: the 8-byte discriminator plus the fields.
    pub const SPACE: usize = 8 + Self::INIT_SPACE;

    /// Its address: `["commit", escrow, challenger, hash]` under the program.
    pub fn pda(escrow: &Pubkey, challenger: &Pubkey, hash: &[u8; 32]) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[
                COMMIT_SEED,
                escrow.as_ref(),
                challenger.as_ref(),
                hash.as_ref(),
            ],
            &crate::ID,
        )
    }
}
