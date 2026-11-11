use anchor_lang::{
    prelude::*,
    system_program::{transfer, Transfer},
};
use anchor_spl::token::{Mint, Token, TokenAccount};

use crate::{
    config::{clocks, Config},
    constants::CONFIG_SEED,
    error::EscrowError,
    events::ResultPosted,
    state::{result_commitment, Escrow, EscrowStatus},
};

#[event_cpi]
#[derive(Accounts)]
pub struct PostResult<'info> {
    /// Posts the result and pays the SOL bond into the escrow account.
    #[account(mut)]
    pub resolver: Signer<'info>,

    #[account(
        mut,
        has_one = resolver @ EscrowError::UnauthorizedResolver,
        has_one = mint @ EscrowError::MintMismatch,
    )]
    pub escrow: Account<'info, Escrow>,

    pub mint: Account<'info, Mint>,

    /// Read for its balance: the posted total must not exceed it.
    #[account(
        associated_token::mint = mint,
        associated_token::authority = escrow,
        associated_token::token_program = token_program,
    )]
    pub vault: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,

    /// The stop clock and the revoked keys.
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// In order, each failing with its own error: the resolver is not revoked (KeyRevoked); the
/// escrow is Open; the entries deadline has passed (now >= entries_deadline, EntriesWindowOpen)
/// and resolve_deadline has not (ResolveWindowClosed); the entries root is committed
/// (EntriesNotCommitted); the payout root and result hash are non-zero
/// (InvalidResultHash); and 0 < total <= the vault balance (TotalMismatch).
///
/// The total may be less than the vault: anyone can transfer tokens into the vault's token
/// account, so a donation never blocks a post. Claims are capped by the posted total, and refund
/// after claim_deadline sends whatever the vault still holds (leftovers and donations) to
/// refund_to.
///
/// Every deadline is read on the escrow clock (config::escrow_now), and challenge_deadline is set
/// on it.
///
/// Stores commitment = result_commitment(result_sha256, payout_root, total): a challenge must
/// differ from it, and attest votes on it. The bond moves on top of the escrow account's
/// rent-exempt balance and is tracked in resolver_bond, so paying it out later never touches the
/// rent (settle::pay_bond pays bonds out of the tracked ones only).
pub fn handle_post_result(
    ctx: Context<PostResult>,
    payout_root: [u8; 32],
    result_sha256: [u8; 32],
    kit_sha256: [u8; 32],
    total: u64,
) -> Result<()> {
    let (_, now) = clocks(&ctx.accounts.escrow, &ctx.accounts.config)?;
    ctx.accounts
        .config
        .require_not_revoked(&ctx.accounts.resolver.key())?;
    let escrow = &ctx.accounts.escrow;
    require!(
        escrow.status != EscrowStatus::Closed,
        EscrowError::EscrowClosed
    );
    require!(
        escrow.status == EscrowStatus::Open,
        EscrowError::InvalidStatus
    );
    require!(
        now >= escrow.entries_deadline,
        EscrowError::EntriesWindowOpen
    );
    require!(
        now < escrow.resolve_deadline,
        EscrowError::ResolveWindowClosed
    );
    require!(
        escrow.entries_root != [0; 32],
        EscrowError::EntriesNotCommitted
    );
    // An all-zero hash is the "unset" value of every hash field.
    require!(
        payout_root != [0; 32] && result_sha256 != [0; 32],
        EscrowError::InvalidResultHash
    );
    require!(
        total > 0 && total <= ctx.accounts.vault.amount,
        EscrowError::TotalMismatch
    );
    let commitment = result_commitment(&result_sha256, &payout_root, total);
    let bond = escrow.bond_lamports;
    let challenge_deadline = now
        .checked_add(escrow.challenge_window)
        .ok_or(EscrowError::MathOverflow)?;

    transfer(
        CpiContext::new(
            ctx.accounts.system_program.key(),
            Transfer {
                from: ctx.accounts.resolver.to_account_info(),
                to: ctx.accounts.escrow.to_account_info(),
            },
        ),
        bond,
    )?;

    let escrow = &mut ctx.accounts.escrow;
    escrow.payout_root = payout_root;
    escrow.result_sha256 = result_sha256;
    escrow.kit_sha256 = kit_sha256;
    escrow.total = total;
    escrow.commitment = commitment;
    escrow.resolver_bond = bond;
    escrow.challenge_deadline = challenge_deadline;
    escrow.status = EscrowStatus::Challengeable;

    emit_cpi!(ResultPosted {
        escrow: escrow.key(),
        resolver: ctx.accounts.resolver.key(),
        payout_root,
        result_sha256,
        kit_sha256,
        total,
        commitment,
        resolver_bond: bond,
        challenge_deadline,
    });
    Ok(())
}
