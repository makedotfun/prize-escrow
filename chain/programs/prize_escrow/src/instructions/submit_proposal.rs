use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{transfer_checked, Mint, Token, TokenAccount, TransferChecked},
};

use crate::{
    config::Config,
    constants::{CONFIG_SEED, ESCROW_SEED, MAX_REVIEW_WINDOW, PROPOSAL_SEED},
    error::EscrowError,
    events::ProposalSubmitted,
    instructions::open_escrow::check_deposit,
    proposal::Proposal,
    state::{bond_floor, EscrowTerms},
};

#[event_cpi]
#[derive(Accounts)]
#[instruction(competition_id: [u8; 16])]
pub struct SubmitProposal<'info> {
    /// Funds the proposal vault from `sponsor_token_account` and pays the proposal's and the
    /// vault's rent (every exit returns both to it).
    #[account(mut)]
    pub sponsor: Signer<'info>,

    /// The Config's curator, co-signing once the house screened the sponsor (checked in the
    /// handler: ProposalsDisabled, UnauthorizedCurator, KeyRevoked).
    pub curator: Signer<'info>,

    /// PDA ["proposal", sponsor, competition_id]: one sponsor cannot submit (squat) another's.
    #[account(
        init,
        payer = sponsor,
        space = Proposal::SPACE,
        seeds = [PROPOSAL_SEED, sponsor.key().as_ref(), competition_id.as_ref()],
        bump,
    )]
    pub proposal: Account<'info, Proposal>,

    /// The prize mint, owned by the classic Token program (no Token-2022, so no transfer hook).
    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        token::mint = mint,
        token::authority = sponsor,
        token::token_program = token_program,
    )]
    pub sponsor_token_account: Account<'info, TokenAccount>,

    /// The proposal's associated token account. init_if_needed, so a vault someone created ahead
    /// of time cannot block the submit.
    #[account(
        init_if_needed,
        payer = sponsor,
        associated_token::mint = mint,
        associated_token::authority = proposal,
        associated_token::token_program = token_program,
    )]
    pub proposal_vault: Account<'info, TokenAccount>,

    /// CHECK: the escrow PDA ["escrow", sponsor, competition_id] an approval opens: it must hold
    /// no data (EscrowExists, read in the handler), so the competition id is not one already
    /// opened, or refunded and kept as a Closed replay marker.
    #[account(
        seeds = [ESCROW_SEED, sponsor.key().as_ref(), competition_id.as_ref()],
        bump,
    )]
    pub escrow: UncheckedAccount<'info>,

    /// The curator, the open policy, the caps (pending_value grows by the deposit) and the stop.
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

/// The sponsor deposits `terms.total` for review, its terms and schedule fixed, refused unless:
/// - the Config's curator co-signs (ProposalsDisabled when none is named, UnauthorizedCurator for
///   another key, KeyRevoked for a revoked curator), and no escrow exists at the competition id
///   (EscrowExists);
/// - intake runs (IntakeStopped), the terms pass EscrowTerms::validate (the bond to bond_floor of
///   the cluster's rent), and the schedule holds: now < review_deadline <= opens_at <
///   entries_deadline and review_deadline <= now + MAX_REVIEW_WINDOW (ReviewWindowInvalid);
/// - Config::check_terms_policy accepts the terms for the escrow they would open, with the sponsor
///   allowlist waived (the curator's co-signature stands in for it) and nothing else;
/// - Config::check_proposal_terms holds the terms the sponsor chose: the sponsor is not the curator
///   (SponsorIsCurator), neither the resolver nor the compliance key is the sponsor or the curator
///   (ProposalRoleNotIndependent), the resolve window is at least MIN_RESOLVE_WINDOW
///   (ResolveWindowTooShort) and the bond at most MAX_PROPOSAL_BOND (ProposalBondTooHigh);
/// - the caps hold (Config::reserve_pending): total <= C_e (EscrowCapExceeded), pending_value +
///   total <= pending_cap (PendingCapExceeded), open_value + pending_value + total <= C_g
///   (GlobalCapExceeded);
/// - neither token account is frozen (SponsorAccountFrozen, VaultFrozen), and the vault grows by
///   exactly the total (check_deposit: Underfunded, Overfunded).
pub fn handle_submit_proposal(
    ctx: Context<SubmitProposal>,
    competition_id: [u8; 16],
    terms: EscrowTerms,
    opens_at: i64,
    review_deadline: i64,
) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let sponsor = ctx.accounts.sponsor.key();
    let curator = ctx.accounts.curator.key();
    let mint = ctx.accounts.mint.key();
    let escrow = ctx.accounts.escrow.key();
    let config = &mut ctx.accounts.config;
    config.require_curator(&curator)?;
    require!(
        ctx.accounts.escrow.data_is_empty(),
        EscrowError::EscrowExists
    );

    config.require_intake(now)?;
    terms.validate(now, bond_floor(&Rent::get()?))?;
    require!(
        now < review_deadline
            && review_deadline <= opens_at
            && opens_at < terms.entries_deadline
            && now
                .checked_add(MAX_REVIEW_WINDOW)
                .is_some_and(|latest| review_deadline <= latest),
        EscrowError::ReviewWindowInvalid
    );
    config.check_terms_policy(&sponsor, &mint, &escrow, &terms, false)?;
    config.check_proposal_terms(&sponsor, &terms)?;
    config.reserve_pending(terms.total)?;
    let pending_value = config.pending_value;
    require!(
        !ctx.accounts.sponsor_token_account.is_frozen(),
        EscrowError::SponsorAccountFrozen
    );
    require!(
        !ctx.accounts.proposal_vault.is_frozen(),
        EscrowError::VaultFrozen
    );

    let decimals = ctx.accounts.mint.decimals;
    let before = ctx.accounts.proposal_vault.amount;
    transfer_checked(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            TransferChecked {
                from: ctx.accounts.sponsor_token_account.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.proposal_vault.to_account_info(),
                authority: ctx.accounts.sponsor.to_account_info(),
            },
        ),
        terms.total,
        decimals,
    )?;
    ctx.accounts.proposal_vault.reload()?;
    check_deposit(before, ctx.accounts.proposal_vault.amount, terms.total)?;

    let event = ProposalSubmitted {
        proposal: ctx.accounts.proposal.key(),
        escrow,
        competition_id,
        sponsor,
        curator,
        mint,
        decimals,
        total: terms.total,
        rules_sha256: terms.rules_sha256,
        resolver: terms.resolver,
        compliance: terms.compliance,
        arbiter: terms.arbiter,
        refund_to: terms.refund_to,
        regraders: terms.regraders.clone(),
        k: terms.k,
        bond_lamports: terms.bond_lamports,
        entries_deadline: terms.entries_deadline,
        final_end: terms.final_end,
        resolve_deadline: terms.resolve_deadline,
        challenge_window: terms.challenge_window,
        attest_window: terms.attest_window,
        hold_window: terms.hold_window,
        claim_window: terms.claim_window,
        hard_deadline: terms.hard_deadline,
        opens_at,
        review_deadline,
        submitted_at: now,
        pending_value,
    };
    let deposited = terms.total;
    ctx.accounts.proposal.set_inner(Proposal {
        bump: ctx.bumps.proposal,
        decimals,
        competition_id,
        sponsor,
        mint,
        terms,
        opens_at,
        review_deadline,
        submitted_at: now,
        deposited,
        reserved: [0; 32],
    });
    emit_cpi!(event);
    Ok(())
}
