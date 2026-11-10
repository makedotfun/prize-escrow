//! make.fun prize escrow.
//!
//! One escrow per (sponsor, competition) holds the prize pot in a vault from open. The named
//! resolver commits the entries root, then, once the final phase has ended, posts the payout root,
//! the result hash and the total with a SOL bond: the escrow stores their commitment. Anyone may
//! challenge with a bonded alternative result (hash, root and total) inside the challenge window,
//! in two steps (a commit, then its reveal in a later slot, so a watcher cannot copy a challenge
//! in flight), each distinct alternative its own Challenge PDA, so a junk first challenge never
//! keeps the honest one out; k-of-n pre-named regraders vote on commitments (the posted one or any
//! challenge's), and the vote binds: the side that reaches k is the result winners claim against,
//! and every losing side's bond goes to the winning side (an overturn of the posted result only
//! once the attest window has ended). Only a dispute with no quorum (or an escrow the guardian
//! escalated before its unchallenged result or its recorded quorum could settle) reaches the
//! arbiter, which chooses the posted result or one challenge's and can write none of its own. Winners self-claim their merkle leaf with their
//! own signature (a separate payer may pay), behind a compliance co-signature with an on-chain
//! hold and a time-boxed lapse, inside a claim window of at least MIN_CLAIM_WINDOW. Refunds are
//! permissionless once their deadline passes. Every instruction emits its event through a
//! self-CPI (emit_cpi!), which a truncated log cannot hide.
//!
//! The safeguards (config.rs): one Config, created by the upgrade authority, holds the open
//! policy (mint, sponsor and regrader allowlists, the house-regrader allowance, the minimum bond
//! and the window floors), the per-escrow and global caps, a flow bucket on claims, the breaker
//! (IntakeStop, PayoutStop) and the revoked keys. The guardian, a key never on the server, may
//! only escalate: stop, freeze one escrow, hand an undecided escrow to the arbiter, revoke a key.
//! Every deadline is read on a clock that stands still while the escrow is stopped or frozen. No
//! breaker stops a program upgrade.
//!
//! The proposals (proposal.rs): a sponsor who is not on the allowlist deposits its prize with its
//! terms and schedule fixed, co-signed by the Config's curator (a key of its own, off by default),
//! and the curator either approves it into the escrow those terms open, or the deposit returns to
//! the sponsor (withdrawn, rejected with the sha256 of a reason, or expired at review_deadline).

pub mod config;
pub mod constants;
pub mod error;
pub mod events;
pub mod instructions;
pub mod merkle;
pub mod proposal;
pub mod state;

use anchor_lang::prelude::*;

pub use config::*;
pub use constants::*;
pub use error::*;
pub use events::*;
pub use instructions::*;
pub use proposal::*;
pub use state::*;

declare_id!("sHC7T46CaBxEdRZjZCVX5D1o9cyomsr4oUA1bHH2MDd");

// Where a security researcher reports a vulnerability (https://github.com/neodyme-labs/solana-security-txt).
// The policy is inline: there is no public security page. source_code is the repository
// scripts/chain/publish-source.ts exports chain/ into. The build stamps the source revision
// (build.rs reads SOURCE_REVISION or GITHUB_SHA), a commit of the platform repository; every
// commit publish-source makes names it in a Source-Revision trailer.
#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "make.fun prize escrow",
    project_url: "https://make.fun",
    contacts: "email:security@make.fun",
    policy: "Report vulnerabilities privately to security@make.fun, never in a public issue or post.",
    source_code: "https://github.com/makedotfun/prize-escrow",
    source_revision: env!("PRIZE_ESCROW_SOURCE_REVISION")
}

#[program]
pub mod prize_escrow {
    use super::*;

    // ------------------------------------------------------------------ the Config

    /// The program's upgrade authority creates the Config at ["config"], once.
    pub fn initialize_config(ctx: Context<InitializeConfig>, init: ConfigInit) -> Result<()> {
        instructions::config_admin::handle_initialize_config(ctx, init)
    }

    /// The admin names its successor (accept_admin completes the move).
    pub fn propose_admin(ctx: Context<AdminConfig>, new_admin: Pubkey) -> Result<()> {
        instructions::config_admin::handle_propose_admin(ctx, new_admin)
    }

    /// The proposed admin takes the Config, unless its key is revoked.
    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        instructions::config_admin::handle_accept_admin(ctx)
    }

    /// The admin replaces the guardian or the arbiter with a key that is not revoked.
    pub fn set_config_role(ctx: Context<AdminConfig>, role: ConfigRole, key: Pubkey) -> Result<()> {
        instructions::config_admin::handle_set_config_role(ctx, role, key)
    }

    /// The admin sets the caps, the flow bucket, min_bond and max_house_regraders.
    pub fn set_limits(ctx: Context<AdminConfig>, limits: Limits) -> Result<()> {
        instructions::config_admin::handle_set_limits(ctx, limits)
    }

    /// The admin sets the window floors and the reveal grace.
    pub fn set_floors(ctx: Context<AdminConfig>, floors: Floors) -> Result<()> {
        instructions::config_admin::handle_set_floors(ctx, floors)
    }

    /// The admin sets the panel floor: the fewest regraders (1 to MAX_REGRADERS) an escrow opened
    /// after it may name.
    pub fn set_min_regraders(ctx: Context<AdminConfig>, min_regraders: u8) -> Result<()> {
        instructions::config_admin::handle_set_min_regraders(ctx, min_regraders)
    }

    /// The admin adds a key to an allowlist (mints, sponsors, the regrader registry) or takes it
    /// off. `house` marks a house regrader, or a house sponsor, whose escrows may open with any
    /// challenge window from 0; on a sponsor already listed, `allowed` sets its mark alone.
    pub fn set_allowed(
        ctx: Context<AdminConfig>,
        list: AllowList,
        key: Pubkey,
        allowed: bool,
        house: bool,
    ) -> Result<()> {
        instructions::config_admin::handle_set_allowed(ctx, list, key, allowed, house)
    }

    /// The admin names the curator (Pubkey::default(): proposals off) and the pending cap. The
    /// curator is never revoked, nor the admin, the guardian or the arbiter.
    pub fn set_proposal_policy(
        ctx: Context<AdminConfig>,
        curator: Pubkey,
        pending_cap: u64,
    ) -> Result<()> {
        instructions::config_admin::handle_set_proposal_policy(ctx, curator, pending_cap)
    }

    // ------------------------------------------------------------------ the breakers

    /// The guardian raises the stop (Normal, IntakeStop, PayoutStop), for 7 days, or until the
    /// later lapse of the stop in force; the admin sets any level, Normal included.
    pub fn set_stop(ctx: Context<SetStop>, level: StopState) -> Result<()> {
        instructions::breakers::handle_set_stop(ctx, level)
    }

    /// The admin moves the lapse of the stop in force later.
    pub fn extend_stop(ctx: Context<ExtendStop>, extra: i64) -> Result<()> {
        instructions::breakers::handle_extend_stop(ctx, extra)
    }

    /// The guardian freezes one escrow, for 7 days of the global clock; the admin unfreezes it.
    pub fn set_freeze(ctx: Context<GuardEscrow>, frozen: bool) -> Result<()> {
        instructions::breakers::handle_set_freeze(ctx, frozen)
    }

    /// The admin moves the lapse of an escrow's freeze later.
    pub fn extend_freeze(ctx: Context<GuardEscrow>, extra: i64) -> Result<()> {
        instructions::breakers::handle_extend_freeze(ctx, extra)
    }

    /// The guardian hands an undecided (Challengeable or Disputed) escrow to the arbiter: Frozen.
    /// A recorded quorum binds once settle may apply it, and is refused from then on
    /// (QuorumRecorded): at challenge_deadline for the posted result, at attest_deadline for a
    /// challenge's alternative. An unchallenged result binds once its challenge window is over
    /// (challenge_deadline, or the reveal grace's end while a commit is pending), and is refused
    /// from then on too (UnchallengedResultBinds).
    pub fn escalate(ctx: Context<GuardEscrow>) -> Result<()> {
        instructions::breakers::handle_escalate(ctx)
    }

    /// The guardian revokes a key (refused everywhere after); the admin unrevokes it.
    pub fn set_revoked(ctx: Context<SetStop>, key: Pubkey, revoked: bool) -> Result<()> {
        instructions::breakers::handle_set_revoked(ctx, key, revoked)
    }

    /// The admin replaces an escrow's resolver, compliance key or one regrader.
    pub fn rotate_role(
        ctx: Context<RotateRole>,
        role: EscrowRole,
        old: Pubkey,
        new: Pubkey,
    ) -> Result<()> {
        instructions::breakers::handle_rotate_role(ctx, role, old, new)
    }

    // ------------------------------------------------------------------ the escrow

    /// Create the escrow for `competition_id` at the PDA ["escrow", sponsor, competition_id], pin
    /// the mint and its decimals, store the terms (held to EscrowTerms::validate's bounds, the
    /// bond to bond_floor of the cluster's rent, and to the Config's open policy and caps) and
    /// rules_sha256, and move `terms.total` from the sponsor into the vault (the vault must grow
    /// by exactly that much). Classic Token program only.
    pub fn open_escrow(
        ctx: Context<OpenEscrow>,
        competition_id: [u8; 16],
        terms: EscrowTerms,
    ) -> Result<()> {
        instructions::open_escrow::handle_open_escrow(ctx, competition_id, terms)
    }

    /// The sponsor adds `amount` to the vault while the escrow is Open, within the caps, as long as
    /// it is on the sponsor allowlist (a sponsor whose escrow a proposal opened adds nothing).
    pub fn fund(ctx: Context<Fund>, amount: u64) -> Result<()> {
        instructions::fund::handle_fund(ctx, amount)
    }

    // ------------------------------------------------------------------ the proposals

    /// A sponsor, co-signed by the Config's curator, deposits `terms.total` into the proposal
    /// vault at the PDA ["proposal", sponsor, competition_id] for review until `review_deadline`
    /// (now < review_deadline <= opens_at < entries_deadline, at most MAX_REVIEW_WINDOW away),
    /// held to EscrowTerms::validate and the open policy (the sponsor allowlist waived), the
    /// proposal's own bounds (the sponsor not the curator, neither the resolver nor the compliance
    /// key the sponsor or the curator, a resolve window of at least MIN_RESOLVE_WINDOW, a bond of
    /// at most MAX_PROPOSAL_BOND), the per-escrow cap, the pending cap and the global cap. No
    /// escrow may exist at the id. `terms.rules_sha256` may be all zero: the curator then sets it
    /// with set_proposal_rules before approving.
    pub fn submit_proposal(
        ctx: Context<SubmitProposal>,
        competition_id: [u8; 16],
        terms: EscrowTerms,
        opens_at: i64,
        review_deadline: i64,
    ) -> Result<()> {
        instructions::submit_proposal::handle_submit_proposal(
            ctx,
            competition_id,
            terms,
            opens_at,
            review_deadline,
        )
    }

    /// The curator, by review_deadline, writes the rules hash of a proposal submitted with an
    /// all-zero one into its stored terms, once and non-zero. Nothing else changes.
    pub fn set_proposal_rules(
        ctx: Context<SetProposalRules>,
        rules_sha256: [u8; 32],
    ) -> Result<()> {
        instructions::set_proposal_rules::handle_set_proposal_rules(ctx, rules_sha256)
    }

    /// The curator, by review_deadline, opens the proposal's escrow with its stored terms (no
    /// arguments: only set_proposal_rules writes them, once) through open_escrow's own init, moves
    /// the deposit into the escrow vault (any extra tokens swept after it), and closes the proposal
    /// and its vault, their rent to the sponsor. The terms are held to today's Config again, the
    /// escrow to today's per-escrow cap; an all-zero rules hash is refused (RulesNotSet).
    pub fn approve_proposal(ctx: Context<ApproveProposal>) -> Result<()> {
        instructions::approve_proposal::handle_approve_proposal(ctx)
    }

    /// The one way back: the whole proposal vault returns to a token account the sponsor owns
    /// (its associated one, or the optional `destination`) and the proposal closes, signed by the
    /// sponsor (Withdrawn, no reason), the curator (Rejected, the reason's sha256) or, after
    /// review_deadline with no reason, anyone (Expired). Refused while a PayoutStop holds, and for
    /// a revoked sponsor (SponsorRevoked: held).
    pub fn close_proposal(ctx: Context<CloseProposal>, reason_sha256: [u8; 32]) -> Result<()> {
        instructions::close_proposal::handle_close_proposal(ctx, reason_sha256)
    }

    /// The resolver fixes the entries root of at least one entry, once, before entries_deadline,
    /// while Open.
    pub fn commit_entries(
        ctx: Context<CommitEntries>,
        entries_root: [u8; 32],
        entries_count: u32,
    ) -> Result<()> {
        instructions::commit_entries::handle_commit_entries(ctx, entries_root, entries_count)
    }

    /// The resolver posts the payout root, the result and kit hashes and the total with its SOL
    /// bond, at or after final_end and before resolve_deadline, once the entries root is
    /// committed; 0 < `total` <= the vault balance. Stores the result commitment and opens the
    /// challenge window (Challengeable).
    pub fn post_result(
        ctx: Context<PostResult>,
        payout_root: [u8; 32],
        result_sha256: [u8; 32],
        kit_sha256: [u8; 32],
        total: u64,
    ) -> Result<()> {
        instructions::post_result::handle_post_result(
            ctx,
            payout_root,
            result_sha256,
            kit_sha256,
            total,
        )
    }

    /// A challenge's first step: anyone bonds a commit to sha256(alt_commitment || challenger ||
    /// salt) before challenge_deadline, at the PDA ["commit", escrow, challenger, hash].
    pub fn challenge_commit(ctx: Context<ChallengeCommit>, hash: [u8; 32]) -> Result<()> {
        instructions::challenge_commit::handle_challenge_commit(ctx, hash)
    }

    /// A challenge's second step: the commit's challenger reveals `salt` and the alternative
    /// result (document hash, payout root and total, the total at most the vault balance) whose
    /// commitment (`alt_commitment`, its result_commitment) differs from the posted one and from
    /// every earlier challenge's, in a slot after the commit's and before challenge_deadline +
    /// reveal_grace, into its own Challenge PDA ["challenge", escrow, alt_commitment]. The first
    /// makes the escrow Disputed and opens the attestation window; a later one joins the dispute.
    pub fn challenge_reveal(
        ctx: Context<ChallengeReveal>,
        salt: [u8; 32],
        alt_result_sha256: [u8; 32],
        alt_payout_root: [u8; 32],
        alt_total: u64,
        alt_commitment: [u8; 32],
    ) -> Result<()> {
        instructions::challenge_reveal::handle_challenge_reveal(
            ctx,
            salt,
            alt_result_sha256,
            alt_payout_root,
            alt_total,
            alt_commitment,
        )
    }

    /// A named regrader backs the posted result or one challenge's (its Challenge PDA passed in)
    /// by its commitment, once, before attest_deadline. Counts the vote, and records the
    /// challenge whose votes reach k as the winning alternative; the status is settle's to change.
    pub fn attest(ctx: Context<Attest>, commitment: [u8; 32]) -> Result<()> {
        instructions::attest::handle_attest(ctx, commitment)
    }

    /// Permissionless, never before challenge_deadline (nor before the reveal grace ends while a
    /// commit is pending): ends an unchallenged window (Claimable) or a dispute: Claimable on the
    /// posted result's quorum, Claimable on the winning challenge's alternative (applied) on its
    /// quorum once attest_deadline (challenge_deadline + attest_window) is reached, Frozen on no
    /// quorum by attest_deadline. The winning side takes every bond.
    pub fn settle(ctx: Context<Settle>) -> Result<()> {
        instructions::settle::handle_settle(ctx)
    }

    /// The Config's arbiter chooses which result of a Frozen escrow applies, the posted one or a
    /// challenge's alternative at least one named regrader voted for (its Challenge PDA passed
    /// in), as stored, naming its commitment; the chosen side takes every bond, and the escrow is
    /// Claimable on its result. Keeping the posted result clears an alternative a quorum recorded.
    pub fn arbiter_resolve(
        ctx: Context<ArbiterResolve>,
        choice: ArbiterChoice,
        commitment: [u8; 32],
    ) -> Result<()> {
        instructions::arbiter_resolve::handle_arbiter_resolve(ctx, choice, commitment)
    }

    /// The claimant proves its leaf and starts the hold window: with no hold placed before it
    /// passes, the claim clears without the compliance co-signature. Refused, as claim is, while
    /// a PayoutStop or the guardian's freeze of the escrow is in force.
    pub fn request_claim(
        ctx: Context<RequestClaim>,
        total_amount: u64,
        proof: Vec<[u8; 32]>,
    ) -> Result<()> {
        instructions::request_claim::handle_request_claim(ctx, total_amount, proof)
    }

    /// The claimant takes `amount` (0 = all that is left) of its leaf's `total_amount` from
    /// the vault into its own token account, while Claimable and before claim_deadline, within
    /// the flow bucket. It needs the compliance key's co-signature or a cleared request.
    pub fn claim(
        ctx: Context<Claim>,
        total_amount: u64,
        amount: u64,
        proof: Vec<[u8; 32]>,
    ) -> Result<()> {
        instructions::claim::handle_claim(ctx, total_amount, amount, proof)
    }

    /// The compliance key holds `claimant`'s claim with a HOLD_* reason, creating the receipt
    /// if needed.
    pub fn hold(ctx: Context<Hold>, claimant: Pubkey, reason: u8) -> Result<()> {
        instructions::hold::handle_hold(ctx, claimant, reason)
    }

    /// The compliance key releases `claimant`'s hold.
    pub fn release_hold(ctx: Context<ReleaseHold>, claimant: Pubkey) -> Result<()> {
        instructions::release_hold::handle_release_hold(ctx, claimant)
    }

    /// Permissionless: sweeps the vault to a token account refund_to owns (its associated one, or
    /// the optional `destination`) and closes it, leaving the escrow Closed and
    /// the resolver's bond (if still held) returned; challengers' bonds still held wait for
    /// close_challenge. Allowed when Claimable past claim_deadline (whatever hard_deadline says),
    /// Open past resolve_deadline, or any other status past hard_deadline, except a Disputed
    /// escrow whose quorum is recorded (QuorumRecorded): settle applies it, past hard_deadline too.
    pub fn refund(ctx: Context<Refund>) -> Result<()> {
        instructions::refund::handle_refund(ctx)
    }

    /// Permissionless: closes a claimant's receipt once its escrow is Closed, its rent back to the
    /// claimant.
    pub fn close_receipt(ctx: Context<CloseReceipt>) -> Result<()> {
        instructions::close_receipt::handle_close_receipt(ctx)
    }

    /// Permissionless: closes a Challenge PDA once its dispute is over (Claimable or Closed), its
    /// rent back to its challenger, and its bond too after a refund that decided nothing.
    pub fn close_challenge(ctx: Context<CloseChallenge>) -> Result<()> {
        instructions::close_challenge::handle_close_challenge(ctx)
    }

    /// Permissionless: closes a commit never revealed once its escrow decided (Claimable or
    /// Closed), its bond and rent back to its own challenger.
    pub fn close_commit(ctx: Context<CloseCommit>) -> Result<()> {
        instructions::close_commit::handle_close_commit(ctx)
    }

    /// Permissionless: closes a regrader's Attestation once its escrow is Closed, its rent back
    /// to the regrader.
    pub fn close_attestation(ctx: Context<CloseAttestation>) -> Result<()> {
        instructions::close_attestation::handle_close_attestation(ctx)
    }

    /// Admin: retires the Config for good. Intake (open_escrow, fund, submit_proposal,
    /// approve_proposal) refuses from here on; every payout and close stays open.
    pub fn retire(ctx: Context<Retire>) -> Result<()> {
        instructions::wind_down::handle_retire(ctx)
    }

    /// Admin, once the Config is retired: closes a Closed escrow with no bond left in it (its
    /// receipts, challenges, commits and attestations closed first), every lamport to refund_to.
    pub fn close_escrow(ctx: Context<CloseEscrow>) -> Result<()> {
        instructions::wind_down::handle_close_escrow(ctx)
    }

    /// Admin and upgrade authority, once the Config is retired with no value or escrow left under
    /// it: closes the Config. initialize_config may then create a fresh one.
    pub fn close_config(ctx: Context<CloseConfig>) -> Result<()> {
        instructions::wind_down::handle_close_config(ctx)
    }
}
