use anchor_lang::prelude::*;

use crate::{
    constants::CLAIM_SEED,
    error::EscrowError,
    events::ReceiptClosed,
    state::{ClaimReceipt, Escrow, EscrowStatus},
};

/// Permissionless: any fee payer may close a receipt once its escrow is Closed.
#[event_cpi]
#[derive(Accounts)]
pub struct CloseReceipt<'info> {
    /// The receipt's claimant; gets the rent back.
    /// CHECK: only receives lamports; pinned by has_one and the seeds on the receipt.
    #[account(mut)]
    pub claimant: UncheckedAccount<'info>,

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
/// again. The rent goes to the claimant (has_one), whoever paid it and whoever sends this, as
/// close_challenge, close_commit and close_attestation send theirs: the wind-down tooling closes
/// every receipt before close_escrow without the claimants' keys.
///
/// No breaker refuses it, a revoked claimant included: it reads no Config (no PayoutStop, freeze
/// or revocation), on purpose. It moves only the receipt's rent back to the claimant, never a
/// token or a bond, and the escrow is already Closed; adding the Config account to refuse it would
/// change the instruction's accounts for nothing of value.
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
