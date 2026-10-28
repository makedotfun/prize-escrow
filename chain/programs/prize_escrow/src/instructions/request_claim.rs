use anchor_lang::prelude::*;

use crate::{
    config::{clocks, Config},
    constants::{CLAIM_SEED, CONFIG_SEED},
    error::EscrowError,
    events::ClaimRequested,
    instructions::claim::{bind_receipt, prove_leaf, require_claimable},
    state::{ClaimReceipt, Escrow},
};

#[event_cpi]
#[derive(Accounts)]
pub struct RequestClaim<'info> {
    pub claimant: Signer<'info>,

    /// Pays the receipt's rent; may differ from the claimant.
    #[account(mut)]
    pub payer: Signer<'info>,

    pub escrow: Account<'info, Escrow>,

    #[account(
        init_if_needed,
        payer = payer,
        space = ClaimReceipt::SPACE,
        seeds = [CLAIM_SEED, escrow.key().as_ref(), claimant.key().as_ref()],
        bump,
    )]
    pub receipt: Account<'info, ClaimReceipt>,

    pub system_program: Program<'info, System>,

    /// The stop clock and the revoked keys.
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// Same window and leaf checks as claim (Claimable, at or before claim_deadline, the leaf in the
/// payout tree), then on the receipt: not held (HeldForCompliance), not claimed in full
/// (AlreadyClaimed), and requested once (AlreadyRequested). Records requested_at = now; with no
/// hold placed by requested_at + hold_window, claim then clears without the compliance
/// co-signature. A request too close to claim_deadline lapses after it, when only a co-signed
/// claim is left (ClaimRequested carries clears_at to compare). requested_at and clears_at are on
/// the escrow clock, so a stop holds the hold window back too. As claim does, it refuses first
/// while a PayoutStop or the guardian's freeze of the escrow is in force (PayoutStopped,
/// EscrowFrozen): a request is the first step of the payout path that needs no co-signature, so
/// no hold window starts while the payouts are held. A revoked claimant is refused (KeyRevoked).
pub fn handle_request_claim(
    ctx: Context<RequestClaim>,
    total_amount: u64,
    proof: Vec<[u8; 32]>,
) -> Result<()> {
    let (wall, now) = clocks(&ctx.accounts.escrow, &ctx.accounts.config)?;
    let claimant = ctx.accounts.claimant.key();
    ctx.accounts
        .config
        .require_payouts(&ctx.accounts.escrow, wall)?;
    ctx.accounts.config.require_not_revoked(&claimant)?;
    let escrow = &ctx.accounts.escrow;
    require_claimable(escrow, now)?;
    prove_leaf(escrow, &claimant, total_amount, &proof)?;

    let receipt = &mut ctx.accounts.receipt;
    bind_receipt(receipt, claimant, total_amount, ctx.bumps.receipt)?;
    require!(!receipt.is_held(), EscrowError::HeldForCompliance);
    require!(
        receipt.remaining().ok_or(EscrowError::MathOverflow)? > 0,
        EscrowError::AlreadyClaimed
    );
    require!(receipt.requested_at == 0, EscrowError::AlreadyRequested);
    let clears_at = now
        .checked_add(escrow.hold_window)
        .ok_or(EscrowError::MathOverflow)?;
    receipt.requested_at = now;

    emit_cpi!(ClaimRequested {
        escrow: escrow.key(),
        claimant,
        total_amount,
        requested_at: now,
        clears_at,
    });
    Ok(())
}
