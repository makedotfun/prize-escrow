use anchor_lang::{
    prelude::*,
    system_program::{transfer, Transfer},
};

use crate::{
    config::{clocks, Config},
    constants::{COMMIT_SEED, CONFIG_SEED},
    error::EscrowError,
    events::ChallengeCommitted,
    state::{CommitRecord, Escrow, EscrowStatus},
};

#[event_cpi]
#[derive(Accounts)]
#[instruction(hash: [u8; 32])]
pub struct ChallengeCommit<'info> {
    /// Anyone: pays the SOL bond into the escrow account and the commit's rent.
    #[account(mut)]
    pub challenger: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub escrow: Account<'info, Escrow>,

    /// One per (escrow, challenger, hash): the challenger in the seeds keeps a copied hash at
    /// another address.
    #[account(
        init,
        payer = challenger,
        space = CommitRecord::SPACE,
        seeds = [COMMIT_SEED, escrow.key().as_ref(), challenger.key().as_ref(), hash.as_ref()],
        bump,
    )]
    pub commit: Account<'info, CommitRecord>,

    pub system_program: Program<'info, System>,
}

/// The first of a challenge's two steps (front-running): the challenger bonds a commit to
/// `hash` = sha256(alt_commitment || challenger || salt) while the escrow is Challengeable or
/// Disputed and before challenge_deadline (ChallengeWindowClosed), recording the hash, its
/// challenger and the slot. Nobody can read the alternative off it, and only its challenger can
/// reveal it (challenge_reveal), in a later slot. It changes no deadline and no status: settle
/// waits for the reveal grace while a commit is pending, and the bond (bond_lamports) sits in the
/// escrow account apart from the challenge bonds (Escrow.commit_bond) until the reveal makes it a
/// challenge's, or close_commit returns it to its own challenger once the escrow decided. A
/// revoked challenger is refused (KeyRevoked); a stop or a freeze never refuses it.
pub fn handle_challenge_commit(ctx: Context<ChallengeCommit>, hash: [u8; 32]) -> Result<()> {
    let (_, now) = clocks(&ctx.accounts.escrow, &ctx.accounts.config)?;
    let challenger = ctx.accounts.challenger.key();
    ctx.accounts.config.require_not_revoked(&challenger)?;
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
        now < escrow.challenge_deadline,
        EscrowError::ChallengeWindowClosed
    );
    require!(hash != [0; 32], EscrowError::InvalidResultHash);
    let bond = escrow.bond_lamports;
    let commit_bond = escrow
        .commit_bond
        .checked_add(bond)
        .ok_or(EscrowError::MathOverflow)?;
    let pending_commits = escrow
        .pending_commits
        .checked_add(1)
        .ok_or(EscrowError::MathOverflow)?;

    transfer(
        CpiContext::new(
            ctx.accounts.system_program.key(),
            Transfer {
                from: ctx.accounts.challenger.to_account_info(),
                to: ctx.accounts.escrow.to_account_info(),
            },
        ),
        bond,
    )?;

    let slot = Clock::get()?.slot;
    let commit = ctx.accounts.commit.key();
    ctx.accounts.commit.set_inner(CommitRecord {
        escrow: ctx.accounts.escrow.key(),
        challenger,
        hash,
        slot,
        committed_at: now,
        bond,
        bump: ctx.bumps.commit,
    });

    let escrow = &mut ctx.accounts.escrow;
    escrow.commit_bond = commit_bond;
    escrow.pending_commits = pending_commits;

    emit_cpi!(ChallengeCommitted {
        escrow: escrow.key(),
        commit,
        challenger,
        hash,
        slot,
        committed_at: now,
        bond,
        pending_commits,
    });
    Ok(())
}
