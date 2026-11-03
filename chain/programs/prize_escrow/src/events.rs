//! The program's events. Every instruction emits its one event with `emit_cpi!`: a self-CPI
//! signed by the event authority PDA (`["__event_authority"]`), whose instruction data is
//! `EVENT_IX_TAG_LE || the event's discriminator || its Borsh body`. The runtime records that
//! inner instruction in the transaction's metadata whatever the log holds, so a caller that floods
//! the log until the validator truncates it cannot hide an event (a `Program data:` log line,
//! `emit!`, can be cut that way). Only the program can sign as the event authority, so no other
//! program can forge one.

use anchor_lang::prelude::*;

use crate::{
    config::{AllowList, EscrowRole, StopState},
    state::{ArbiterChoice, AttestSide, EscrowStatus},
};

/// How settle ended a challenge window or a dispute.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettleOutcome {
    /// No challenge landed before challenge_deadline: Claimable, the resolver's bond returned.
    Undisputed,
    /// The posted result reached k attestations: Claimable on it; the resolver takes its bond
    /// back and every challenger's forfeited one.
    ResultUpheld,
    /// One challenge's alternative reached k attestations: the vote is binding, so its
    /// result_sha256, payout_root, total and commitment become the result in force and the
    /// escrow is Claimable on them; its challenger takes its bond back, the resolver's and every
    /// other challenger's forfeited one.
    AltApplied,
    /// No side reached k by attest_deadline: Frozen, every bond held for arbiter_resolve.
    NoQuorum,
}

/// open_escrow: the escrow exists and its vault holds `total`.
#[event]
pub struct EscrowOpened {
    pub escrow: Pubkey,
    pub competition_id: [u8; 16],
    pub sponsor: Pubkey,
    pub resolver: Pubkey,
    pub compliance: Pubkey,
    pub arbiter: Pubkey,
    pub refund_to: Pubkey,
    pub mint: Pubkey,
    pub decimals: u8,
    pub total: u64,
    pub rules_sha256: [u8; 32],
    pub regraders: Vec<Pubkey>,
    pub k: u8,
    pub bond_lamports: u64,
    pub entries_deadline: i64,
    pub final_end: i64,
    pub resolve_deadline: i64,
    pub challenge_window: i64,
    pub attest_window: i64,
    pub hold_window: i64,
    pub claim_window: i64,
    pub hard_deadline: i64,
}

/// fund: the sponsor topped up the vault.
#[event]
pub struct EscrowFunded {
    pub escrow: Pubkey,
    pub sponsor: Pubkey,
    pub amount: u64,
    pub vault_balance: u64,
}

/// commit_entries: the entries root is fixed.
#[event]
pub struct EntriesCommitted {
    pub escrow: Pubkey,
    pub entries_root: [u8; 32],
    pub entries_count: u32,
}

/// post_result: the resolver posted the result with its bond.
#[event]
pub struct ResultPosted {
    pub escrow: Pubkey,
    pub resolver: Pubkey,
    pub payout_root: [u8; 32],
    pub result_sha256: [u8; 32],
    pub kit_sha256: [u8; 32],
    pub total: u64,
    /// result_commitment(result_sha256, payout_root, total).
    pub commitment: [u8; 32],
    pub resolver_bond: u64,
    pub challenge_deadline: i64,
}

/// challenge_commit: a challenger bonded a commit to an alternative it reveals later.
#[event]
pub struct ChallengeCommitted {
    pub escrow: Pubkey,
    /// The CommitRecord PDA, ["commit", escrow, challenger, hash].
    pub commit: Pubkey,
    pub challenger: Pubkey,
    /// sha256(alt_commitment || challenger || salt).
    pub hash: [u8; 32],
    /// The slot it landed in: its reveal must land in a later one.
    pub slot: u64,
    /// The escrow clock when it landed.
    pub committed_at: i64,
    pub bond: u64,
    /// The escrow's commits not yet revealed or closed, this one included.
    pub pending_commits: u32,
}

/// challenge_reveal: a revealed commit's bonded alternative result (document hash, payout root
/// and total) opened its Challenge PDA, and the dispute (the first) or joined it (a later one).
#[event]
pub struct Challenged {
    pub escrow: Pubkey,
    /// The CommitRecord PDA revealed (and closed).
    pub commit: Pubkey,
    /// The Challenge PDA, ["challenge", escrow, alt_commitment].
    pub challenge: Pubkey,
    pub challenger: Pubkey,
    /// The posted result's commitment.
    pub commitment: [u8; 32],
    pub alt_result_sha256: [u8; 32],
    pub alt_payout_root: [u8; 32],
    pub alt_total: u64,
    /// result_commitment(alt_result_sha256, alt_payout_root, alt_total).
    pub alt_commitment: [u8; 32],
    /// This challenge's bond.
    pub challenger_bond: u64,
    /// Its Challenge.index: 0 for the one that opened the dispute.
    pub index: u32,
    /// The escrow's challenge_count after it.
    pub challenge_count: u32,
    /// challenge_deadline + attest_window, set by the first challenge; a later one leaves it.
    pub attest_deadline: i64,
}

/// attest: a regrader voted.
#[event]
pub struct Attested {
    pub escrow: Pubkey,
    pub regrader: Pubkey,
    /// The commitment the regrader backed: the posted one (Result) or one challenge's (Alt).
    pub commitment: [u8; 32],
    pub side: AttestSide,
    /// The Challenge PDA whose commitment it backed; Pubkey::default() for the posted result.
    pub challenge: Pubkey,
    /// The votes its commitment holds now.
    pub votes: u8,
    /// Whether this vote took its commitment to k: the side that wins, which settle applies.
    pub quorum: bool,
    pub votes_result: u8,
    /// Votes for every challenge's commitment together.
    pub votes_alt: u8,
}

/// settle: the challenge window or the dispute ended.
#[event]
pub struct Settled {
    pub escrow: Pubkey,
    pub outcome: SettleOutcome,
    pub status: EscrowStatus,
    pub votes_result: u8,
    pub votes_alt: u8,
    /// Set when the escrow became Claimable; 0 otherwise.
    pub claim_deadline: i64,
    /// The result in force after settle, its commitment the winning one: the posted result, or
    /// the winning challenge's alternative after AltApplied (still the posted one after NoQuorum,
    /// which no side won, until the arbiter chooses).
    pub result_sha256: [u8; 32],
    pub payout_root: [u8; 32],
    pub total: u64,
    pub commitment: [u8; 32],
    /// The winning challenge's challenger after AltApplied; Pubkey::default() otherwise.
    pub challenger: Pubkey,
    /// Lamports paid to the resolver (its bond, plus every challenger's after ResultUpheld).
    pub resolver_paid: u64,
    /// Lamports paid to the winning challenger (every bond after AltApplied; 0 otherwise).
    pub challenger_paid: u64,
}

/// arbiter_resolve: the arbiter chose which result of a Frozen escrow applies, the posted one or
/// one challenge's.
#[event]
pub struct ArbiterResolved {
    pub escrow: Pubkey,
    pub arbiter: Pubkey,
    pub choice: ArbiterChoice,
    /// The chosen side's result, now in force.
    pub payout_root: [u8; 32],
    pub result_sha256: [u8; 32],
    pub total: u64,
    /// result_commitment(result_sha256, payout_root, total): the chosen (winning) commitment.
    pub commitment: [u8; 32],
    /// The chosen Challenge PDA; Pubkey::default() when the posted result was chosen.
    pub challenge: Pubkey,
    /// Its challenger; Pubkey::default() when the posted result was chosen.
    pub challenger: Pubkey,
    pub claim_deadline: i64,
    /// Lamports paid to the resolver (every bond when the posted result was chosen; 0 otherwise).
    pub resolver_paid: u64,
    /// Lamports paid to the chosen challenger (every bond when it was chosen; 0 otherwise).
    pub challenger_paid: u64,
}

/// request_claim: the claimant proved a leaf and started the hold window.
#[event]
pub struct ClaimRequested {
    pub escrow: Pubkey,
    pub claimant: Pubkey,
    pub total_amount: u64,
    pub requested_at: i64,
    /// requested_at + hold_window: when the claim clears if no hold is placed.
    pub clears_at: i64,
}

/// claim: tokens moved from the vault to the claimant.
#[event]
pub struct Claimed {
    pub escrow: Pubkey,
    pub claimant: Pubkey,
    pub amount: u64,
    pub amount_claimed: u64,
    pub total_amount: u64,
    /// Whether the compliance key co-signed (false: the claim cleared by a lapsed request, or
    /// the escrow has no compliance gate).
    pub cosigned: bool,
}

/// hold: the compliance key held a claimant's claim.
#[event]
pub struct HoldPlaced {
    pub escrow: Pubkey,
    pub claimant: Pubkey,
    pub reason: u8,
    pub held_at: i64,
}

/// release_hold: the compliance key released a hold.
#[event]
pub struct HoldReleased {
    pub escrow: Pubkey,
    pub claimant: Pubkey,
    /// The reason of the hold that was released.
    pub reason: u8,
}

/// refund: the vault was swept to refund_to and the escrow is Closed.
#[event]
pub struct Refunded {
    pub escrow: Pubkey,
    pub refund_to: Pubkey,
    pub amount: u64,
    /// The status the escrow was refunded from.
    pub from_status: EscrowStatus,
    /// Lamports of the resolver's bond returned to it (a bond no settle or arbiter paid out).
    pub resolver_paid: u64,
    /// Lamports of challengers' bonds left in the escrow for close_challenge to return, each to
    /// its payer (no side was proven); 0 once a side won.
    pub challenger_bonds_held: u64,
}

/// close_challenge: a Challenge PDA of a decided or refunded escrow was closed, its rent (and,
/// after a refund that decided nothing, its bond) returned to its challenger.
#[event]
pub struct ChallengeClosed {
    pub escrow: Pubkey,
    pub challenge: Pubkey,
    pub challenger: Pubkey,
    pub alt_commitment: [u8; 32],
    /// Lamports of its bond returned: only after a refund that decided nothing (once a side
    /// wins, settle or arbiter_resolve pays every bond to it).
    pub bond_returned: u64,
    /// Lamports of the account's rent returned.
    pub rent_returned: u64,
}

/// close_receipt: a claimant reclaimed a receipt's rent after the escrow closed.
#[event]
pub struct ReceiptClosed {
    pub escrow: Pubkey,
    pub claimant: Pubkey,
    pub amount_claimed: u64,
}

/// close_commit: a commit never revealed was closed once its escrow decided, its bond and rent
/// returned to its own challenger.
#[event]
pub struct CommitClosed {
    pub escrow: Pubkey,
    pub commit: Pubkey,
    pub challenger: Pubkey,
    pub hash: [u8; 32],
    pub bond_returned: u64,
    pub rent_returned: u64,
    /// The escrow's commits still pending after it.
    pub pending_commits: u32,
}

/// close_attestation: a vote's Attestation was closed once its escrow was Closed, its rent
/// returned to its regrader.
#[event]
pub struct AttestationClosed {
    pub escrow: Pubkey,
    pub attestation: Pubkey,
    pub regrader: Pubkey,
    /// The commitment the vote named, and its side.
    pub commitment: [u8; 32],
    pub side: AttestSide,
    pub rent_returned: u64,
}

/// What a ConfigChanged event records.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigChange {
    /// initialize_config created the Config.
    Initialized,
    /// propose_admin named `key` as the next admin.
    AdminProposed,
    /// accept_admin made `key` the admin.
    AdminAccepted,
    /// set_config_role made `key` the guardian.
    GuardianSet,
    /// set_config_role made `key` the arbiter.
    ArbiterSet,
    /// set_limits wrote the caps, the bucket, min_bond and max_house_regraders.
    LimitsSet,
    /// set_floors wrote the window floors and the reveal grace.
    FloorsSet,
    /// set_allowed added `key` to `list` (with `house` for a regrader).
    Allowed,
    /// set_allowed took `key` off `list`.
    Disallowed,
    /// set_min_regraders wrote the panel floor (min_regraders).
    MinRegradersSet,
    /// set_proposal_policy made `key` the curator (Pubkey::default(): proposals off) and set the
    /// pending cap (the event's curator and pending_cap).
    ProposalPolicySet,
}

/// Every Config change but the stop and the revocations (StopChanged, RevocationChanged): what
/// changed, the key it names, and Config's settings after it.
#[event]
pub struct ConfigChanged {
    pub config: Pubkey,
    pub change: ConfigChange,
    /// The signer: the upgrade authority (Initialized), the proposed admin (AdminAccepted), or the
    /// admin.
    pub by: Pubkey,
    /// The key the change names (the new admin, guardian or arbiter, the listed key);
    /// Pubkey::default() otherwise.
    pub key: Pubkey,
    /// The list it edits (Allowed, Disallowed); None otherwise.
    pub list: Option<AllowList>,
    /// The regrader's house flag (Allowed of a regrader); false otherwise.
    pub house: bool,
    pub admin: Pubkey,
    pub pending_admin: Pubkey,
    pub guardian: Pubkey,
    pub arbiter: Pubkey,
    pub escrow_cap: u64,
    pub global_cap: u64,
    pub open_value: u64,
    pub flow_capacity: u64,
    pub flow_period: i64,
    pub min_bond: u64,
    pub max_house_regraders: u8,
    pub min_challenge_window: i64,
    pub min_attest_window: i64,
    pub min_hold_window: i64,
    pub min_claim_window: i64,
    pub reveal_grace: i64,
    /// The panel floor open_escrow holds escrows to (0 on a Config written before the field: it
    /// refuses no panel, as 1 does).
    pub min_regraders: u8,
    /// The proposal policy (set_proposal_policy): the curator (Pubkey::default(): proposals off)
    /// and the pending cap, and what proposals awaiting review hold (Config.pending_value), as
    /// open_value is what open escrows hold. Appended after min_regraders, so a ConfigChanged from
    /// before proposals ends where they start.
    pub curator: Pubkey,
    pub pending_value: u64,
    pub pending_cap: u64,
}

/// set_stop or extend_stop: the breaker level changed or its lapse moved.
#[event]
pub struct StopChanged {
    /// The guardian (escalating) or the admin.
    pub by: Pubkey,
    /// The level in force before.
    pub from: StopState,
    pub stop: StopState,
    pub stop_since: i64,
    pub stop_expires_at: i64,
    /// Seconds of every PayoutStop that has ended.
    pub stopped_secs: i64,
}

/// set_freeze or extend_freeze: the guardian froze an escrow, the admin unfroze it, or the admin
/// moved the freeze's lapse.
#[event]
pub struct FreezeChanged {
    pub escrow: Pubkey,
    pub by: Pubkey,
    pub frozen: bool,
    /// On the global clock: when the freeze in force began and lapses (0 when unfrozen).
    pub freeze_since: i64,
    pub freeze_until: i64,
    /// Seconds of every freeze that has ended.
    pub frozen_secs: i64,
    /// The escrow clock now.
    pub escrow_now: i64,
}

/// escalate: the guardian (or the admin) handed an undecided escrow to the arbiter, Frozen.
#[event]
pub struct Escalated {
    pub escrow: Pubkey,
    pub by: Pubkey,
    /// Challengeable (inside its challenge window) or Disputed (before a recorded quorum binds).
    pub from_status: EscrowStatus,
}

/// set_revoked: a key's signature is refused everywhere (revoked), or accepted again.
#[event]
pub struct RevocationChanged {
    pub key: Pubkey,
    pub by: Pubkey,
    pub revoked: bool,
    /// How many keys are revoked after it.
    pub revoked_count: u32,
}

/// rotate_role: the admin replaced one of an escrow's keys.
#[event]
pub struct RoleRotated {
    pub escrow: Pubkey,
    pub by: Pubkey,
    pub role: EscrowRole,
    pub old: Pubkey,
    pub new: Pubkey,
}

/// Why close_proposal returned a proposal's deposit to its sponsor.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalCloseKind {
    /// The sponsor took its proposal back (no reason), by its review_deadline.
    Withdrawn,
    /// The curator rejected it, naming the sha256 of its reason document.
    Rejected,
    /// Its review_deadline passed undecided, and someone returned it naming no reason: anyone,
    /// the sponsor and the curator (revoked or not) included.
    Expired,
}

/// submit_proposal: the sponsor's deposit is in the proposal vault, its terms and schedule fixed,
/// awaiting the curator's review until review_deadline.
#[event]
pub struct ProposalSubmitted {
    pub proposal: Pubkey,
    /// The escrow PDA approve_proposal opens: ["escrow", sponsor, competition_id].
    pub escrow: Pubkey,
    pub competition_id: [u8; 16],
    pub sponsor: Pubkey,
    /// The curator who co-signed the submit.
    pub curator: Pubkey,
    pub mint: Pubkey,
    pub decimals: u8,
    pub total: u64,
    pub rules_sha256: [u8; 32],
    pub resolver: Pubkey,
    pub compliance: Pubkey,
    pub arbiter: Pubkey,
    pub refund_to: Pubkey,
    pub regraders: Vec<Pubkey>,
    pub k: u8,
    pub bond_lamports: u64,
    pub entries_deadline: i64,
    pub final_end: i64,
    pub resolve_deadline: i64,
    pub challenge_window: i64,
    pub attest_window: i64,
    pub hold_window: i64,
    pub claim_window: i64,
    pub hard_deadline: i64,
    /// When the competition opens: review_deadline <= opens_at < entries_deadline.
    pub opens_at: i64,
    /// The last second approve_proposal may land; after it anyone may return the deposit.
    pub review_deadline: i64,
    pub submitted_at: i64,
    /// Config.pending_value after it (this deposit included).
    pub pending_value: u64,
}

/// approve_proposal: the curator approved a proposal as submitted. Its escrow is open (an
/// EscrowOpened event follows), the deposit moved into the escrow vault, the proposal and its
/// vault closed (their rent to the sponsor).
#[event]
pub struct ProposalApproved {
    pub proposal: Pubkey,
    pub escrow: Pubkey,
    pub competition_id: [u8; 16],
    pub sponsor: Pubkey,
    pub curator: Pubkey,
    /// terms.total: moved into the escrow vault, and from Config.pending_value to open_value.
    pub amount: u64,
    /// What the proposal vault held beyond it (tokens anyone sent there), swept into the escrow
    /// vault too, so the vault could close.
    pub swept: u64,
    /// Config.pending_value and open_value after it.
    pub pending_value: u64,
    pub open_value: u64,
}

/// close_proposal: the proposal vault was swept to the sponsor's associated token account, and
/// the vault and the proposal closed (their rent to the sponsor).
#[event]
pub struct ProposalClosed {
    pub proposal: Pubkey,
    pub sponsor: Pubkey,
    /// The tokens returned: the whole vault.
    pub amount: u64,
    pub kind: ProposalCloseKind,
    /// The sha256 of the rejection document (Rejected); all zero otherwise.
    pub reason_sha256: [u8; 32],
    /// The signer: the sponsor (Withdrawn), the curator (Rejected), anyone past review_deadline
    /// (Expired).
    pub by: Pubkey,
}

/// retire: the admin retired the Config, for good. Intake refuses from here on (Retired); every
/// payout, settle, refund and close stays open, and close_escrow and close_config may follow.
#[event]
pub struct ConfigRetired {
    pub config: Pubkey,
    /// The admin.
    pub by: Pubkey,
    /// Config.open_value, pending_value and live_escrows when it retired: what is left to wind down.
    pub open_value: u64,
    pub pending_value: u64,
    pub live_escrows: u32,
}

/// close_escrow: the admin closed a retired Config's Closed escrow, its vault already closed
/// (refund, or the last claim's sweep) and no bond left in it; every lamport it held went to its
/// refund_to.
#[event]
pub struct EscrowClosed {
    pub escrow: Pubkey,
    pub competition_id: [u8; 16],
    pub sponsor: Pubkey,
    /// Who got the lamports: the escrow's refund_to.
    pub refund_to: Pubkey,
    /// The lamports the escrow account held: its rent and anything donated to it.
    pub lamports: u64,
    /// Config.live_escrows after it.
    pub live_escrows: u32,
}

/// close_config: the admin, as the program's upgrade authority, closed the retired Config with
/// nothing left under it; its rent went to the recipient. initialize_config may create a fresh one.
#[event]
pub struct ConfigClosed {
    pub config: Pubkey,
    /// The admin and upgrade authority.
    pub by: Pubkey,
    /// Who got the Config's lamports.
    pub recipient: Pubkey,
    pub lamports: u64,
}
