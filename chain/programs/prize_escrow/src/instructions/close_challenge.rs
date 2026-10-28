use anchor_lang::prelude::*;

use crate::{
    error::EscrowError,
    events::ChallengeClosed,
    instructions::settle::{pay_bond, unbonded_floor},
    state::{ChallengeRecord, Escrow, EscrowStatus},
};

/// Permissionless: any fee payer may close a challenge once its dispute is over.
#[event_cpi]
#[derive(Accounts)]
pub struct CloseChallenge<'info> {
    /// Pays back a bond a refund left held.
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,

    #[account(
        mut,
        has_one = escrow @ EscrowError::ChallengeMismatch,
        has_one = challenger @ EscrowError::ChallengeMismatch,
        close = challenger,
    )]
    pub challenge: Account<'info, ChallengeRecord>,

    /// CHECK: only receives lamports; pinned by has_one on the challenge.
    /// Its rent back, and its bond after a refund that decided nothing.
    #[account(mut)]
    pub challenger: UncheckedAccount<'info>,
}

/// Closes one Challenge PDA once the dispute is over, the escrow Claimable (a side won: settle or
/// arbiter_resolve already paid every bond to it) or Closed (InvalidStatus while the challenge
/// may still win, Disputed or Frozen): its rent goes back to its challenger, who paid it. After
/// a refund that decided nothing (Disputed or Frozen past hard_deadline), its bond, still held in
/// the escrow account (Escrow.challenger_bond), goes back to it too: no side was proven.
///
/// It reads no Config, so no breaker refuses it: not a PayoutStop, not the guardian's freeze of
/// the escrow, not a revoked challenger (nobody signs it). That is on purpose: it moves no token,
/// only lamports the challenger itself paid (the rent, and its own bond once a refund decided
/// nothing) and only to that challenger (has_one), and only once the escrow is Claimable or
/// Closed, when nothing a stop holds back can still depend on it.
pub fn handle_close_challenge(ctx: Context<CloseChallenge>) -> Result<()> {
    let escrow = &ctx.accounts.escrow;
    require!(
        escrow.status == EscrowStatus::Claimable || escrow.status == EscrowStatus::Closed,
        EscrowError::InvalidStatus
    );
    let challenge = &ctx.accounts.challenge;
    let bond_returned = if escrow.status == EscrowStatus::Closed && escrow.challenger_bond > 0 {
        challenge.bond
    } else {
        0
    };
    let left = escrow
        .challenger_bond
        .checked_sub(bond_returned)
        .ok_or(EscrowError::MathOverflow)?;
    let escrow_info = escrow.to_account_info();
    let floor = unbonded_floor(&escrow_info, escrow)?;
    pay_bond(
        &escrow_info,
        &ctx.accounts.challenger.to_account_info(),
        bond_returned,
        floor,
    )?;
    let rent_returned = challenge.to_account_info().lamports();
    let (challenge_key, challenger, alt_commitment) = (
        challenge.key(),
        challenge.challenger,
        challenge.alt_commitment,
    );

    let escrow = &mut ctx.accounts.escrow;
    escrow.challenger_bond = left;

    emit_cpi!(ChallengeClosed {
        escrow: escrow.key(),
        challenge: challenge_key,
        challenger,
        alt_commitment,
        bond_returned,
        rent_returned,
    });
    Ok(())
}
