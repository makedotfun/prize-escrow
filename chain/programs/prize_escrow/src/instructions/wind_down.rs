//! Winding a deployment down to zero program-owned accounts: retire stops intake for good, the
//! permissionless closes (close_receipt, close_challenge, close_commit, close_attestation) empty
//! each Closed escrow of its children, close_escrow closes the escrow itself, and close_config the
//! Config last. initialize_config may then create a fresh Config at the same program id.

use anchor_lang::{prelude::*, solana_program::bpf_loader_upgradeable};

use crate::{
    config::Config,
    constants::CONFIG_SEED,
    error::EscrowError,
    events::{ConfigClosed, ConfigRetired, EscrowClosed},
    state::{Escrow, EscrowStatus},
};

#[event_cpi]
#[derive(Accounts)]
pub struct Retire<'info> {
    #[account(address = config.admin @ EscrowError::UnauthorizedAdmin)]
    pub admin: Signer<'info>,

    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// Admin: retires the Config, one way (Retired once it is). From here on open_escrow, fund,
/// submit_proposal and approve_proposal refuse (Config::require_intake: Retired); everything that
/// pays out or winds down stays as it was: post_result, the challenges and votes, settle,
/// arbiter_resolve, claims, holds, refunds, close_proposal and every close. No stop or breaker
/// lifts it; a retired Config ends only by close_config.
pub fn handle_retire(ctx: Context<Retire>) -> Result<()> {
    let config = &mut ctx.accounts.config;
    require!(!config.retired, EscrowError::Retired);
    config.retired = true;
    emit_cpi!(ConfigRetired {
        config: config.key(),
        by: ctx.accounts.admin.key(),
        open_value: config.open_value,
        pending_value: config.pending_value,
        live_escrows: config.live_escrows,
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct CloseEscrow<'info> {
    #[account(address = config.admin @ EscrowError::UnauthorizedAdmin)]
    pub admin: Signer<'info>,

    /// Retired; its live_escrows count goes down by one.
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(mut, has_one = refund_to, close = refund_to)]
    pub escrow: Account<'info, Escrow>,

    /// Gets every lamport the escrow holds.
    /// CHECK: only receives lamports; pinned by has_one on the escrow.
    #[account(mut)]
    pub refund_to: UncheckedAccount<'info>,
}

/// Admin, once the Config is retired (NotRetired before): closes a Closed escrow (InvalidStatus
/// before: refund, the only way to Closed, has swept and closed its vault, paid its resolver bond
/// out and taken its deposit off open_value), with every lamport it holds (its rent and anything
/// donated to it) to its refund_to, the sponsor. The sponsor paid that rent at open_escrow; for an
/// escrow a proposal opened the curator did at the approval, and it ends with the sponsor as the
/// vault's rent does (refund).
///
/// No bond may be left in it: a challenge not closed holds challenger_bond
/// (ChallengesOutstanding), a commit not closed commit_bond and pending_commits
/// (CommitsOutstanding), so no challenger's bond ever goes to the sponsor. The children
/// (ClaimReceipt, Challenge, CommitRecord, Attestation) each read this escrow to close, so they
/// close first: the wind-down tooling sends close_receipt, close_challenge, close_commit and
/// close_attestation (all permissionless once the escrow is Closed) before this. It is the admin's
/// alone because a child left behind can no longer close once this has (its rent strands, nothing
/// else), so only the tooling that closed them sends it.
pub fn handle_close_escrow(ctx: Context<CloseEscrow>) -> Result<()> {
    require!(ctx.accounts.config.retired, EscrowError::NotRetired);
    let escrow = &ctx.accounts.escrow;
    require!(
        escrow.status == EscrowStatus::Closed,
        EscrowError::InvalidStatus
    );
    require!(
        escrow.challenger_bond == 0,
        EscrowError::ChallengesOutstanding
    );
    require!(
        escrow.commit_bond == 0 && escrow.pending_commits == 0,
        EscrowError::CommitsOutstanding
    );
    let lamports = escrow.to_account_info().lamports();
    let (escrow_key, competition_id, sponsor, refund_to) = (
        escrow.key(),
        escrow.competition_id,
        escrow.sponsor,
        escrow.refund_to,
    );
    let config = &mut ctx.accounts.config;
    config.live_escrows = config.live_escrows.saturating_sub(1);
    emit_cpi!(EscrowClosed {
        escrow: escrow_key,
        competition_id,
        sponsor,
        refund_to,
        lamports,
        live_escrows: config.live_escrows,
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct CloseConfig<'info> {
    /// The Config's admin, and the program's upgrade authority (program_data).
    #[account(address = config.admin @ EscrowError::UnauthorizedAdmin)]
    pub admin: Signer<'info>,

    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, close = recipient)]
    pub config: Account<'info, Config>,

    /// This program's ProgramData account, ["<program id>"] under the upgradeable loader: the
    /// admin must be its upgrade authority, as initialize_config's signer must.
    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = bpf_loader_upgradeable::ID,
        constraint = program_data.upgrade_authority_address == Some(admin.key())
            @ EscrowError::NotUpgradeAuthority,
    )]
    pub program_data: Account<'info, ProgramData>,

    /// Gets the Config's lamports.
    /// CHECK: only receives lamports; the admin names it.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
}

/// Admin and upgrade authority both (one key signs as both, or the admin is not the upgrade
/// authority: NotUpgradeAuthority), once the Config is retired (NotRetired) with nothing left
/// under it: no value in an open escrow or a pending proposal (ValueOutstanding: open_value and
/// pending_value at 0) and no escrow not closed (EscrowsOutstanding: live_escrows at 0). Closes
/// the Config, its rent to the recipient. initialize_config, the upgrade authority's, may then
/// create a fresh Config at the same PDA: the deployment starts over without a new program id.
pub fn handle_close_config(ctx: Context<CloseConfig>) -> Result<()> {
    let config = &ctx.accounts.config;
    require!(config.retired, EscrowError::NotRetired);
    require!(
        config.open_value == 0 && config.pending_value == 0,
        EscrowError::ValueOutstanding
    );
    require!(config.live_escrows == 0, EscrowError::EscrowsOutstanding);
    emit_cpi!(ConfigClosed {
        config: config.key(),
        by: ctx.accounts.admin.key(),
        recipient: ctx.accounts.recipient.key(),
        lamports: config.to_account_info().lamports(),
    });
    Ok(())
}
