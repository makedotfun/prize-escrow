use anchor_lang::prelude::*;
use anchor_spl::token::{transfer_checked, Mint, Token, TokenAccount, TransferChecked};

use crate::{
    config::Config,
    constants::CONFIG_SEED,
    error::EscrowError,
    events::EscrowFunded,
    instructions::open_escrow::check_deposit,
    state::{Escrow, EscrowStatus},
};

#[event_cpi]
#[derive(Accounts)]
pub struct Fund<'info> {
    pub sponsor: Signer<'info>,

    #[account(
        mut,
        has_one = sponsor @ EscrowError::UnauthorizedSponsor,
        has_one = mint @ EscrowError::MintMismatch,
    )]
    pub escrow: Account<'info, Escrow>,

    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        token::mint = mint,
        token::authority = sponsor,
        token::token_program = token_program,
    )]
    pub sponsor_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = escrow,
        associated_token::token_program = token_program,
    )]
    pub vault: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,

    /// The caps (open_value grows by the deposit) and the stop.
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// Adds to the vault only: Escrow.total stays the opened amount until post_result, whose total
/// may be at most the vault balance, fixes it. Refused while intake is stopped (IntakeStopped) or
/// the sponsor is revoked (KeyRevoked); the escrow's deposits stay within the per-escrow cap C_e
/// and open_value within the global cap C_g (EscrowCapExceeded, GlobalCapExceeded); a frozen
/// sponsor or vault token account is refused by name (SponsorAccountFrozen, VaultFrozen).
pub fn handle_fund(ctx: Context<Fund>, amount: u64) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let status = ctx.accounts.escrow.status;
    require!(status != EscrowStatus::Closed, EscrowError::EscrowClosed);
    require!(status == EscrowStatus::Open, EscrowError::InvalidStatus);
    require!(amount > 0, EscrowError::InvalidAmount);
    let config = &mut ctx.accounts.config;
    config.require_intake(now)?;
    config.require_not_revoked(&ctx.accounts.sponsor.key())?;
    let deposited = config.deposit(ctx.accounts.escrow.deposited, amount)?;
    require!(
        !ctx.accounts.sponsor_token_account.is_frozen(),
        EscrowError::SponsorAccountFrozen
    );
    require!(!ctx.accounts.vault.is_frozen(), EscrowError::VaultFrozen);

    let before = ctx.accounts.vault.amount;
    transfer_checked(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            TransferChecked {
                from: ctx.accounts.sponsor_token_account.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
                authority: ctx.accounts.sponsor.to_account_info(),
            },
        ),
        amount,
        ctx.accounts.escrow.decimals,
    )?;
    ctx.accounts.vault.reload()?;
    let vault_balance = ctx.accounts.vault.amount;
    check_deposit(before, vault_balance, amount)?;
    ctx.accounts.escrow.deposited = deposited;

    emit_cpi!(EscrowFunded {
        escrow: ctx.accounts.escrow.key(),
        sponsor: ctx.accounts.sponsor.key(),
        amount,
        vault_balance,
    });
    Ok(())
}
