use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{close_account, CloseAccount, Mint, Token, TokenAccount},
};

use crate::{
    config::{Config, StopState},
    constants::{CONFIG_SEED, PROPOSAL_SEED},
    error::EscrowError,
    events::{ProposalCloseKind, ProposalClosed},
    instructions::{approve_proposal::transfer_from_pda, refund::sweep_destination},
    proposal::Proposal,
};

#[event_cpi]
#[derive(Accounts)]
pub struct CloseProposal<'info> {
    /// The sponsor (Withdrawn), the curator (Rejected) or, after review_deadline, anyone
    /// (Expired); pays the rent of the sponsor's associated token account when it is created here.
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Closed, its rent to the sponsor.
    #[account(
        mut,
        close = sponsor,
        has_one = sponsor @ EscrowError::UnauthorizedSponsor,
        has_one = mint @ EscrowError::MintMismatch,
        seeds = [PROPOSAL_SEED, proposal.sponsor.as_ref(), proposal.competition_id.as_ref()],
        bump = proposal.bump,
    )]
    pub proposal: Account<'info, Proposal>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = proposal,
        associated_token::token_program = token_program,
    )]
    pub proposal_vault: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,

    /// CHECK: receives the proposal's and its vault's rent; pinned by has_one on the proposal.
    #[account(mut)]
    pub sponsor: UncheckedAccount<'info>,

    /// The sponsor's associated token account of the mint, its address held by the seeds (the
    /// client derives it): where the deposit returns unless `destination` names another account
    /// of the sponsor's, created when absent and refused unless the sponsor still owns it
    /// (sweep_destination). The deposit returns only to an account the sponsor owns, so no caller
    /// can send it anywhere else.
    /// CHECK: the seeds hold its address; sweep_destination reads or creates the account.
    #[account(
        mut,
        seeds = [sponsor.key().as_ref(), token_program.key().as_ref(), mint.key().as_ref()],
        seeds::program = anchor_spl::associated_token::ID,
        bump,
    )]
    pub sponsor_token_account: UncheckedAccount<'info>,

    /// The curator, the stop, and the pending counter (the deposit comes off pending_value).
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,

    /// Optional: any token account of the mint the sponsor owns, where the deposit returns
    /// instead of sponsor_token_account, so a sponsor that reassigned its associated account's
    /// owner cannot pin its proposal (and pending_value) by it.
    #[account(
        mut,
        token::mint = mint,
        token::authority = sponsor,
        token::token_program = token_program,
    )]
    pub destination: Option<Account<'info, TokenAccount>>,
}

/// The one way back: the whole proposal vault (the deposit and anything sent there) returns to a
/// token account the sponsor owns (its associated one, or the `destination` named:
/// sweep_destination), the vault and the proposal close (their rent to the sponsor), and the
/// deposit comes off pending_value (Config::release_pending, never refused for the counter's
/// sake). When and who signs decide the kind:
/// - after review_deadline with no reason (`reason_sha256` zero): Expired, whoever signs (the
///   sponsor, the curator, a replaced or revoked curator, anyone);
/// - the sponsor: Withdrawn, any time; `reason_sha256` must be zero (InvalidCloseReason);
/// - the Config's curator: Rejected, any time; `reason_sha256` is the sha256 of the rejection
///   document and must not be zero (InvalidCloseReason), the curator's key not revoked
///   (KeyRevoked);
/// - anyone else: Expired, only after review_deadline (DeadlineNotReached), with no reason
///   (InvalidCloseReason).
///
/// Refused while a PayoutStop is in force (PayoutStopped, as refund is) but not an IntakeStop, for
/// a revoked sponsor whatever the kind (SponsorRevoked: the guardian's set_revoked is the OFAC
/// "blocked property" hold, and a deposit it holds is held, never returned, until the admin
/// unrevokes the key), and for a frozen vault or sponsor token account (VaultFrozen,
/// SponsorAccountFrozen).
pub fn handle_close_proposal(ctx: Context<CloseProposal>, reason_sha256: [u8; 32]) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let by = ctx.accounts.authority.key();
    let proposal = &ctx.accounts.proposal;
    let (sponsor, competition_id, bump, deposited, review_deadline) = (
        proposal.sponsor,
        proposal.competition_id,
        proposal.bump,
        proposal.deposited,
        proposal.review_deadline,
    );
    let config = &ctx.accounts.config;
    require!(
        config.stop_level(now) != StopState::PayoutStop,
        EscrowError::PayoutStopped
    );
    require!(!config.is_revoked(&sponsor), EscrowError::SponsorRevoked);
    let no_reason = reason_sha256 == [0; 32];
    // Past review_deadline a return naming no reason is an expiry whoever signs it: a revoked
    // curator, which can reject nothing, still returns the deposit as anyone may (the #852
    // audit's P3-4).
    let kind = if now > review_deadline && no_reason {
        ProposalCloseKind::Expired
    } else if by == sponsor {
        ProposalCloseKind::Withdrawn
    } else if config.is_curator(&by) {
        ProposalCloseKind::Rejected
    } else {
        ProposalCloseKind::Expired
    };
    match kind {
        ProposalCloseKind::Withdrawn => {
            require!(no_reason, EscrowError::InvalidCloseReason);
        }
        ProposalCloseKind::Rejected => {
            config.require_not_revoked(&by)?;
            require!(!no_reason, EscrowError::InvalidCloseReason);
        }
        ProposalCloseKind::Expired => {
            require!(now > review_deadline, EscrowError::DeadlineNotReached);
            require!(no_reason, EscrowError::InvalidCloseReason);
        }
    }
    require!(
        !ctx.accounts.proposal_vault.is_frozen(),
        EscrowError::VaultFrozen
    );
    let (to, to_state) = sweep_destination(
        ctx.accounts.destination.as_ref(),
        ctx.accounts.sponsor_token_account.to_account_info(),
        ctx.accounts.sponsor.to_account_info(),
        ctx.accounts.mint.to_account_info(),
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_program.to_account_info(),
        ctx.accounts.associated_token_program.to_account_info(),
        ctx.accounts.system_program.to_account_info(),
    )?;
    require!(!to_state.is_frozen(), EscrowError::SponsorAccountFrozen);

    let seeds: [&[u8]; 4] = [
        PROPOSAL_SEED,
        sponsor.as_ref(),
        &competition_id,
        core::slice::from_ref(&bump),
    ];
    let signer: &[&[&[u8]]] = &[&seeds];
    let amount = ctx.accounts.proposal_vault.amount;
    if amount > 0 {
        transfer_from_pda(
            &ctx.accounts.token_program,
            &ctx.accounts.proposal_vault,
            &ctx.accounts.mint,
            to,
            ctx.accounts.proposal.to_account_info(),
            signer,
            amount,
        )?;
    }
    close_account(CpiContext::new_with_signer(
        ctx.accounts.token_program.key(),
        CloseAccount {
            account: ctx.accounts.proposal_vault.to_account_info(),
            destination: ctx.accounts.sponsor.to_account_info(),
            authority: ctx.accounts.proposal.to_account_info(),
        },
        signer,
    ))?;
    ctx.accounts.config.release_pending(deposited);

    emit_cpi!(ProposalClosed {
        proposal: ctx.accounts.proposal.key(),
        sponsor,
        amount,
        kind,
        reason_sha256,
        by,
    });
    Ok(())
}
