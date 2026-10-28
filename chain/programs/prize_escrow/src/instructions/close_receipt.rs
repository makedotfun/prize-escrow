use anchor_lang::prelude::*;

use crate::{
    constants::CLAIM_SEED,
    error::EscrowError,
    events::ReceiptClosed,
    state::{ClaimReceipt, Escrow, EscrowStatus},
};

#[event_cpi]
#[derive(Accounts)]
pub struct CloseReceipt<'info> {
    /// The receipt's claimant; gets the rent back.
    #[account(mut)]
    pub claimant: Signer<'info>,

    pub escrow: Account<'info, Escrow>,

    #[account(
        mut,
        close = claimant,
        has_one = claimant,
        seeds = [CLAIM_SEED, escrow.key().as_ref(), claimant.key().as_ref()],
        bump = receipt.bump,
    )]
    pub receipt: Account<'info, ClaimReceipt>,
}

/// Only once the escrow is Closed (InvalidStatus before): until then the receipt is what stops a
/// second claim of the same leaf, and no instruction can create a receipt on a Closed escrow
/// again. The rent goes to the claimant, whoever paid it.
///
/// No breaker refuses it, a revoked claimant included: unlike every other signer site it reads no
/// Config (no PayoutStop, freeze or revocation), on purpose. It moves only the receipt's rent back
/// to the claimant, never a token or a bond, and the escrow is already Closed; adding the Config
/// account to refuse it would change the instruction's accounts for nothing of value.
pub fn handle_close_receipt(ctx: Context<CloseReceipt>) -> Result<()> {
    require!(
        ctx.accounts.escrow.status == EscrowStatus::Closed,
        EscrowError::InvalidStatus
    );
    emit_cpi!(ReceiptClosed {
        escrow: ctx.accounts.escrow.key(),
        claimant: ctx.accounts.claimant.key(),
        amount_claimed: ctx.accounts.receipt.amount_claimed,
    });
    Ok(())
}
