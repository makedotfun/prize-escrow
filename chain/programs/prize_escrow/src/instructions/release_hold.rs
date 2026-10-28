use anchor_lang::prelude::*;

use crate::{
    config::Config,
    constants::{CLAIM_SEED, CONFIG_SEED, HOLD_NONE},
    error::EscrowError,
    events::HoldReleased,
    state::{ClaimReceipt, Escrow, EscrowStatus},
};

#[event_cpi]
#[derive(Accounts)]
#[instruction(claimant: Pubkey)]
pub struct ReleaseHold<'info> {
    #[account(address = escrow.compliance @ EscrowError::UnauthorizedCompliance)]
    pub compliance: Signer<'info>,

    pub escrow: Account<'info, Escrow>,

    #[account(
        mut,
        seeds = [CLAIM_SEED, escrow.key().as_ref(), claimant.as_ref()],
        bump = receipt.bump,
    )]
    pub receipt: Account<'info, ClaimReceipt>,

    /// The revoked keys.
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// Clears the hold in force (NotHeld when there is none) before the escrow is Closed. The claim
/// then clears as without a hold: the co-signature, or a request whose hold window has passed (a
/// request made before the hold keeps its requested_at; request_claim refuses a held receipt). A
/// stop or a freeze never refuses a release; a revoked compliance key is refused (KeyRevoked).
pub fn handle_release_hold(ctx: Context<ReleaseHold>, claimant: Pubkey) -> Result<()> {
    ctx.accounts
        .config
        .require_not_revoked(&ctx.accounts.compliance.key())?;
    let escrow = &ctx.accounts.escrow;
    require!(
        escrow.status != EscrowStatus::Closed,
        EscrowError::EscrowClosed
    );
    let receipt = &mut ctx.accounts.receipt;
    require!(receipt.is_held(), EscrowError::NotHeld);
    let reason = receipt.hold_reason;
    receipt.hold_reason = HOLD_NONE;
    receipt.held_at = 0;

    emit_cpi!(HoldReleased {
        escrow: escrow.key(),
        claimant,
        reason,
    });
    Ok(())
}
