use anchor_lang::prelude::*;

use crate::{
    config::{clocks, Config},
    constants::{is_hold_reason, CLAIM_SEED, CONFIG_SEED},
    error::EscrowError,
    events::HoldPlaced,
    state::{ClaimReceipt, Escrow, EscrowStatus},
};

#[event_cpi]
#[derive(Accounts)]
#[instruction(claimant: Pubkey)]
pub struct Hold<'info> {
    /// escrow.compliance; pays the receipt's rent when the claimant has none yet.
    #[account(mut, address = escrow.compliance @ EscrowError::UnauthorizedCompliance)]
    pub compliance: Signer<'info>,

    pub escrow: Account<'info, Escrow>,

    #[account(
        init_if_needed,
        payer = compliance,
        space = ClaimReceipt::SPACE,
        seeds = [CLAIM_SEED, escrow.key().as_ref(), claimant.as_ref()],
        bump,
    )]
    pub receipt: Account<'info, ClaimReceipt>,

    pub system_program: Program<'info, System>,

    /// The stop clock and the revoked keys.
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// Holds `claimant`'s claim with `reason` (HOLD_SANCTIONS, HOLD_GEO, HOLD_TAX_FORM_REQUIRED or
/// HOLD_REVIEW) at any status before Closed, so compliance can screen a winner as soon as the
/// result is posted. A receipt it creates holds no leaf yet (total_amount 0; the claimant's first
/// request_claim or claim proves one). Holding a held receipt replaces the reason and held_at. An
/// escrow without a compliance key (the default key, which nobody can sign for) can never be held.
/// held_at is the escrow clock. A stop or a freeze never refuses a hold; a revoked compliance key
/// is refused (KeyRevoked).
pub fn handle_hold(ctx: Context<Hold>, claimant: Pubkey, reason: u8) -> Result<()> {
    let (_, now) = clocks(&ctx.accounts.escrow, &ctx.accounts.config)?;
    ctx.accounts
        .config
        .require_not_revoked(&ctx.accounts.compliance.key())?;
    let escrow = &ctx.accounts.escrow;
    require!(
        escrow.status != EscrowStatus::Closed,
        EscrowError::EscrowClosed
    );
    require!(is_hold_reason(reason), EscrowError::InvalidHoldReason);

    let receipt = &mut ctx.accounts.receipt;
    receipt.claimant = claimant;
    receipt.bump = ctx.bumps.receipt;
    receipt.hold_reason = reason;
    receipt.held_at = now;

    emit_cpi!(HoldPlaced {
        escrow: escrow.key(),
        claimant,
        reason,
        held_at: now,
    });
    Ok(())
}
