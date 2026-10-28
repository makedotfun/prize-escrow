use anchor_lang::prelude::*;

use crate::{
    error::EscrowError,
    events::CommitClosed,
    instructions::settle::{pay_bond, unbonded_floor},
    state::{CommitRecord, Escrow, EscrowStatus},
};

/// Permissionless: any fee payer may close a commit never revealed once its escrow decided.
#[event_cpi]
#[derive(Accounts)]
pub struct CloseCommit<'info> {
    /// Pays the commit's bond back.
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,

    #[account(
        mut,
        has_one = escrow @ EscrowError::CommitMismatch,
        has_one = challenger @ EscrowError::CommitMismatch,
        close = challenger,
    )]
    pub commit: Account<'info, CommitRecord>,

    /// CHECK: only receives lamports; pinned by has_one on the commit.
    #[account(mut)]
    pub challenger: UncheckedAccount<'info>,
}

/// Closes a commit nobody revealed once the escrow has decided, Claimable or Closed (InvalidStatus
/// before: it might still be revealed, or the arbiter has yet to choose): its bond (held in the
/// escrow account, Escrow.commit_bond) and its rent go back to its own challenger, never to the
/// house or the winner. A revealed commit is already closed (challenge_reveal closes it).
///
/// It reads no Config, so no breaker refuses it: not a PayoutStop, not the guardian's freeze of
/// the escrow, not a revoked challenger (nobody signs it). That is on purpose: it moves no token,
/// only the lamports the challenger itself paid (its bond and the commit's rent) and only back to
/// that challenger (has_one), and only once the escrow is Claimable or Closed, when the commit
/// can no longer be revealed into the dispute.
pub fn handle_close_commit(ctx: Context<CloseCommit>) -> Result<()> {
    let escrow = &ctx.accounts.escrow;
    require!(
        escrow.status == EscrowStatus::Claimable || escrow.status == EscrowStatus::Closed,
        EscrowError::InvalidStatus
    );
    let commit = &ctx.accounts.commit;
    let bond_returned = commit.bond;
    let commit_bond = escrow
        .commit_bond
        .checked_sub(bond_returned)
        .ok_or(EscrowError::MathOverflow)?;
    let pending_commits = escrow
        .pending_commits
        .checked_sub(1)
        .ok_or(EscrowError::MathOverflow)?;
    let escrow_info = escrow.to_account_info();
    let floor = unbonded_floor(&escrow_info, escrow)?;
    pay_bond(
        &escrow_info,
        &ctx.accounts.challenger.to_account_info(),
        bond_returned,
        floor,
    )?;
    let rent_returned = commit.to_account_info().lamports();
    let (commit_key, challenger, hash) = (commit.key(), commit.challenger, commit.hash);

    let escrow = &mut ctx.accounts.escrow;
    escrow.commit_bond = commit_bond;
    escrow.pending_commits = pending_commits;

    emit_cpi!(CommitClosed {
        escrow: escrow.key(),
        commit: commit_key,
        challenger,
        hash,
        bond_returned,
        rent_returned,
        pending_commits,
    });
    Ok(())
}
