use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, Token, TokenAccount};

use crate::{
    config::{clocks, Config},
    constants::{CHALLENGE_SEED, COMMIT_SEED, CONFIG_SEED},
    error::EscrowError,
    events::Challenged,
    state::{commit_hash, result_commitment, ChallengeRecord, CommitRecord, Escrow, EscrowStatus},
};

#[event_cpi]
#[derive(Accounts)]
#[instruction(salt: [u8; 32], alt_result_sha256: [u8; 32], alt_payout_root: [u8; 32], alt_total: u64, alt_commitment: [u8; 32])]
pub struct ChallengeReveal<'info> {
    /// The commit's challenger: pays the Challenge PDA's rent and takes the commit's back.
    #[account(mut)]
    pub challenger: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(mut, has_one = mint @ EscrowError::MintMismatch)]
    pub escrow: Account<'info, Escrow>,

    pub mint: Account<'info, Mint>,

    /// Read for its balance: the alternative's total must not exceed it, so a quorum for the
    /// alternative can always apply it.
    #[account(
        associated_token::mint = mint,
        associated_token::authority = escrow,
        associated_token::token_program = token_program,
    )]
    pub vault: Account<'info, TokenAccount>,

    /// The challenger's commit, closed here (its rent back to the challenger).
    #[account(
        mut,
        seeds = [COMMIT_SEED, escrow.key().as_ref(), challenger.key().as_ref(), commit.hash.as_ref()],
        bump = commit.bump,
        has_one = escrow @ EscrowError::CommitMismatch,
        has_one = challenger @ EscrowError::CommitMismatch,
        close = challenger,
    )]
    pub commit: Account<'info, CommitRecord>,

    /// One per distinct alternative: `init` refuses a commitment already challenged.
    #[account(
        init,
        payer = challenger,
        space = ChallengeRecord::SPACE,
        seeds = [CHALLENGE_SEED, escrow.key().as_ref(), alt_commitment.as_ref()],
        bump,
    )]
    pub challenge: Account<'info, ChallengeRecord>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

/// The second step: the commit's own challenger reveals `salt` and the alternative, in a slot
/// strictly later than the commit's (RevealTooEarly), and before challenge_deadline +
/// reveal_grace (RevealWindowClosed). sha256(alt_commitment || challenger || salt) must be the
/// commit's hash (CommitMismatch), and the commit names its challenger, so nobody else can reveal
/// it. A copier who reads a reveal in flight can only commit the alternative under its own key,
/// in that slot at the earliest, and reveal it a slot later: a reveal that lands in the slot it
/// was seen in keeps its alternative's Challenge PDA. A reveal seen but not landed then (delayed
/// or dropped) has still disclosed its salt and alternative, though: the copier's commit and
/// reveal can take that Challenge PDA first, and with it the challenge's bond rewards should the
/// alternative win, while the original commit can no longer be revealed (its alternative is
/// challenged already) and close_commit returns its bond once the escrow decides. The pot is never
/// at stake: the alternative applied is the same whoever challenged it. So a watcher resends a
/// reveal that has not landed at once.
///
/// Then, as one challenge: any number while the window is open, one per distinct
/// alternative commitment, each its own Challenge PDA, seeded by the escrow and the commitment, so
/// a second challenge of a commitment finds its account already in use, and a junk first challenge
/// never keeps the honest alternative out. The first moves the escrow from Challengeable to
/// Disputed and sets attest_deadline to challenge_deadline + attest_window, so every challenge, one
/// revealed in the grace too, gets the attest window, and the dispute resolves by that fixed
/// deadline however many challenges join; no commit or reveal moves it. A later one (while
/// Disputed) joins the dispute.
///
/// The alternative is a whole result: its document hash, payout root and total, non-zero each
/// (InvalidResultHash for a zero hash, InvalidAmount for a zero total), the total at most the
/// vault balance (TotalMismatch, as post_result holds the posted total), because a quorum for it
/// applies it as it stands (settle's AltApplied) and the arbiter may choose it. `alt_commitment`
/// must be its result_commitment (the PDA's seed; InvalidResultHash otherwise) and differ from the
/// posted one (InvalidResultHash). The commit's bond becomes this challenge's (from
/// Escrow.commit_bond to Escrow.challenger_bond). A revoked challenger is refused (KeyRevoked); a
/// stop or a freeze never refuses it.
pub fn handle_challenge_reveal(
    ctx: Context<ChallengeReveal>,
    salt: [u8; 32],
    alt_result_sha256: [u8; 32],
    alt_payout_root: [u8; 32],
    alt_total: u64,
    alt_commitment: [u8; 32],
) -> Result<()> {
    let (_, now) = clocks(&ctx.accounts.escrow, &ctx.accounts.config)?;
    let slot = Clock::get()?.slot;
    let challenger = ctx.accounts.challenger.key();
    ctx.accounts.config.require_not_revoked(&challenger)?;
    let commit = &ctx.accounts.commit;
    require!(
        commit_hash(&alt_commitment, &challenger, &salt) == commit.hash,
        EscrowError::CommitMismatch
    );
    require!(slot > commit.slot, EscrowError::RevealTooEarly);
    let escrow = &ctx.accounts.escrow;
    require!(
        escrow.status != EscrowStatus::Closed,
        EscrowError::EscrowClosed
    );
    require!(
        escrow.status == EscrowStatus::Challengeable || escrow.status == EscrowStatus::Disputed,
        EscrowError::InvalidStatus
    );
    require!(
        now < escrow.reveal_deadline()?,
        EscrowError::RevealWindowClosed
    );
    require!(
        alt_result_sha256 != [0; 32] && alt_payout_root != [0; 32],
        EscrowError::InvalidResultHash
    );
    require!(alt_total > 0, EscrowError::InvalidAmount);
    require!(
        alt_total <= ctx.accounts.vault.amount,
        EscrowError::TotalMismatch
    );
    require!(
        alt_commitment == result_commitment(&alt_result_sha256, &alt_payout_root, alt_total),
        EscrowError::InvalidResultHash
    );
    require!(
        alt_commitment != escrow.commitment,
        EscrowError::InvalidResultHash
    );
    let bond = commit.bond;
    // The attest window runs a whole attest_window past the challenge window: a challenge
    // revealed in the grace still gets the regraders' window less the grace, and the escrow
    // resolves by that deadline however many challenges join.
    let attest_deadline = if escrow.status == EscrowStatus::Challengeable {
        escrow
            .challenge_deadline
            .checked_add(escrow.attest_window)
            .ok_or(EscrowError::MathOverflow)?
    } else {
        escrow.attest_deadline
    };
    let index = escrow.challenge_count;
    let challenge_count = index.checked_add(1).ok_or(EscrowError::MathOverflow)?;
    let challenger_bond = escrow
        .challenger_bond
        .checked_add(bond)
        .ok_or(EscrowError::MathOverflow)?;
    let commit_bond = escrow
        .commit_bond
        .checked_sub(bond)
        .ok_or(EscrowError::MathOverflow)?;
    let pending_commits = escrow
        .pending_commits
        .checked_sub(1)
        .ok_or(EscrowError::MathOverflow)?;
    let commit_key = commit.key();

    let challenge = ctx.accounts.challenge.key();
    ctx.accounts.challenge.set_inner(ChallengeRecord {
        escrow: ctx.accounts.escrow.key(),
        challenger,
        alt_result_sha256,
        alt_payout_root,
        alt_commitment,
        alt_total,
        bond,
        opened_at: now,
        index,
        votes: 0,
        bump: ctx.bumps.challenge,
    });

    let escrow = &mut ctx.accounts.escrow;
    escrow.challenge_count = challenge_count;
    escrow.challenger_bond = challenger_bond;
    escrow.commit_bond = commit_bond;
    escrow.pending_commits = pending_commits;
    escrow.attest_deadline = attest_deadline;
    escrow.status = EscrowStatus::Disputed;

    emit_cpi!(Challenged {
        escrow: escrow.key(),
        commit: commit_key,
        challenge,
        challenger,
        commitment: escrow.commitment,
        alt_result_sha256,
        alt_payout_root,
        alt_total,
        alt_commitment,
        challenger_bond: bond,
        index,
        challenge_count,
        attest_deadline,
    });
    Ok(())
}
