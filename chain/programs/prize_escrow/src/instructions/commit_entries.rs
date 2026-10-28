use anchor_lang::prelude::*;

use crate::{
    config::{clocks, Config},
    constants::CONFIG_SEED,
    error::EscrowError,
    events::EntriesCommitted,
    state::{Escrow, EscrowStatus},
};

#[event_cpi]
#[derive(Accounts)]
pub struct CommitEntries<'info> {
    pub resolver: Signer<'info>,

    #[account(mut, has_one = resolver @ EscrowError::UnauthorizedResolver)]
    pub escrow: Account<'info, Escrow>,

    /// The stop clock and the revoked keys.
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// The all-zero root is the "not committed" marker, so it is never accepted as a root
/// (InvalidResultHash), and a root commits at least one entry (NoEntries for entries_count 0, as
/// the server never commits an empty list): a competition nobody entered has no root to commit,
/// and its pot refunds at resolve_deadline. The entries deadline is read on the escrow clock; a
/// revoked resolver is refused (KeyRevoked).
pub fn handle_commit_entries(
    ctx: Context<CommitEntries>,
    entries_root: [u8; 32],
    entries_count: u32,
) -> Result<()> {
    let (_, now) = clocks(&ctx.accounts.escrow, &ctx.accounts.config)?;
    ctx.accounts
        .config
        .require_not_revoked(&ctx.accounts.resolver.key())?;
    let escrow = &mut ctx.accounts.escrow;
    require!(
        escrow.status != EscrowStatus::Closed,
        EscrowError::EscrowClosed
    );
    require!(
        escrow.status == EscrowStatus::Open,
        EscrowError::InvalidStatus
    );
    require!(
        escrow.entries_root == [0; 32],
        EscrowError::EntriesAlreadyCommitted
    );
    require!(
        now < escrow.entries_deadline,
        EscrowError::EntriesWindowClosed
    );
    require!(entries_root != [0; 32], EscrowError::InvalidResultHash);
    require!(entries_count > 0, EscrowError::NoEntries);

    escrow.entries_root = entries_root;
    escrow.entries_count = entries_count;

    emit_cpi!(EntriesCommitted {
        escrow: escrow.key(),
        entries_root,
        entries_count,
    });
    Ok(())
}
