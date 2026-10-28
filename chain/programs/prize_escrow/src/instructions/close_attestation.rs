use anchor_lang::prelude::*;

use crate::{
    constants::ATTESTATION_SEED,
    error::EscrowError,
    events::AttestationClosed,
    state::{Attestation, Escrow, EscrowStatus},
};

/// Permissionless: any fee payer may close a vote once its escrow is Closed.
#[event_cpi]
#[derive(Accounts)]
pub struct CloseAttestation<'info> {
    pub escrow: Account<'info, Escrow>,

    /// The vote, at its own PDA ["attestation", escrow, regrader] (so this escrow's, and the
    /// regrader account's: ConstraintSeeds for any other), closed into its regrader.
    #[account(
        mut,
        has_one = regrader,
        seeds = [ATTESTATION_SEED, escrow.key().as_ref(), regrader.key().as_ref()],
        bump = attestation.bump,
        close = regrader,
    )]
    pub attestation: Account<'info, Attestation>,

    /// CHECK: only receives lamports; pinned by has_one on the attestation and its seeds.
    /// The regrader who voted and paid the rent: the rent goes back to it.
    #[account(mut)]
    pub regrader: UncheckedAccount<'info>,
}

/// Closes one Attestation once the escrow is Closed (InvalidStatus before), its rent back to the
/// regrader who voted and paid it. Until then the Attestation is the once-per-regrader guard of
/// attest and what rotate_role reads to keep a voted seat from rotating; once the escrow is Closed
/// neither runs again (both refuse a Closed escrow, and Closed is final), so the vote is a record
/// only, and the Attested event keeps it.
///
/// It reads no Config, so no breaker refuses it: not a PayoutStop, not the guardian's freeze of
/// the escrow, not a revoked regrader (nobody signs it). As with close_receipt, close_challenge
/// and close_commit that is on purpose: it moves no token and no bond, only the rent the regrader
/// itself paid, and only back to that regrader (has_one and the PDA's seeds), on an escrow that is
/// already Closed.
pub fn handle_close_attestation(ctx: Context<CloseAttestation>) -> Result<()> {
    require!(
        ctx.accounts.escrow.status == EscrowStatus::Closed,
        EscrowError::InvalidStatus
    );
    let attestation = &ctx.accounts.attestation;
    emit_cpi!(AttestationClosed {
        escrow: ctx.accounts.escrow.key(),
        attestation: attestation.key(),
        regrader: attestation.regrader,
        commitment: attestation.commitment,
        side: attestation.side,
        rent_returned: attestation.to_account_info().lamports(),
    });
    Ok(())
}
