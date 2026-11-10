use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{
        close_account, transfer_checked, CloseAccount, Mint, Token, TokenAccount, TransferChecked,
    },
};

use crate::{
    config::Config,
    constants::{CONFIG_SEED, ESCROW_SEED, PROPOSAL_SEED},
    error::EscrowError,
    events::ProposalApproved,
    instructions::open_escrow::{check_deposit, init_escrow, NewEscrow},
    proposal::Proposal,
    state::{bond_floor, Escrow},
};

#[event_cpi]
#[derive(Accounts)]
pub struct ApproveProposal<'info> {
    /// The Config's curator (checked in the handler); pays the escrow's and its vault's rent.
    #[account(mut)]
    pub curator: Signer<'info>,

    /// Closed into the escrow, its rent to the sponsor.
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

    /// The escrow the proposal opens: PDA ["escrow", sponsor, competition_id], as open_escrow's.
    #[account(
        init,
        payer = curator,
        space = Escrow::SPACE,
        seeds = [ESCROW_SEED, proposal.sponsor.as_ref(), proposal.competition_id.as_ref()],
        bump,
    )]
    pub escrow: Account<'info, Escrow>,

    /// The escrow's associated token account. init_if_needed, so a vault someone created ahead
    /// of time cannot block the approval.
    #[account(
        init_if_needed,
        payer = curator,
        associated_token::mint = mint,
        associated_token::authority = escrow,
        associated_token::token_program = token_program,
    )]
    pub escrow_vault: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,

    /// CHECK: receives the proposal's and its vault's rent; pinned by has_one on the proposal.
    #[account(mut)]
    pub sponsor: UncheckedAccount<'info>,

    /// The curator, the open policy, the caps (the deposit moves from pending_value to
    /// open_value) and the stop.
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

/// The curator approves the proposal as submitted: it takes no arguments, so no term can change
/// on the way (set_proposal_rules alone writes the stored terms: an all-zero rules hash, once).
/// Refused unless the signer is the Config's curator today (ProposalsDisabled,
/// UnauthorizedCurator, KeyRevoked: a replaced or revoked curator approves nothing), the review
/// deadline has not passed (ReviewWindowClosed), intake runs (IntakeStopped), the sponsor is not
/// revoked (SponsorRevoked: the hold), the rules hash is set (RulesNotSet: a deposit submitted
/// without one lists only after set_proposal_rules), and the stored terms still pass
/// EscrowTerms::validate, Config::check_terms_policy (the sponsor allowlist waived) and
/// Config::check_proposal_terms against today's Config: a Config that drifted since the submit (a
/// mint, a regrader or the arbiter changed, a floor raised, the sponsor or one of its roles named
/// the curator) refuses the approval, and the curator rejects instead. The escrow it opens is held
/// to today's per-escrow cap C_e (EscrowCapExceeded, Config::approve_pending), as every escrow
/// opened is; C_g is not read again, since the deposit's room under it was taken at the submit.
///
/// The escrow opens through init_escrow, the helper open_escrow uses, so it is field for field
/// the escrow open_escrow would have opened with the same terms at the same moment, Open. Exactly
/// terms.total moves from the proposal vault into the escrow vault (check_deposit: the escrow
/// vault grows by exactly it), then whatever else the proposal vault holds (tokens anyone sent
/// there) is swept after it, so the vault is empty when it closes: the Token program refuses to
/// close a non-empty account, and one donated unit would otherwise block every approval. The
/// vault and the proposal close, their rent to the sponsor. Emits ProposalApproved, then
/// EscrowOpened.
pub fn handle_approve_proposal(ctx: Context<ApproveProposal>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let curator = ctx.accounts.curator.key();
    let proposal_key = ctx.accounts.proposal.key();
    let escrow_key = ctx.accounts.escrow.key();
    let proposal = &ctx.accounts.proposal;
    let (sponsor, mint, competition_id, bump, decimals) = (
        proposal.sponsor,
        proposal.mint,
        proposal.competition_id,
        proposal.bump,
        proposal.decimals,
    );
    let terms = proposal.terms.clone();
    let total = terms.total;
    let review_deadline = proposal.review_deadline;
    let config = &mut ctx.accounts.config;
    config.require_curator(&curator)?;
    require!(now <= review_deadline, EscrowError::ReviewWindowClosed);
    config.require_intake(now)?;
    require!(!config.is_revoked(&sponsor), EscrowError::SponsorRevoked);
    require!(terms.rules_sha256 != [0; 32], EscrowError::RulesNotSet);
    terms.validate(now, bond_floor(&Rent::get()?))?;
    config.check_terms_policy(&sponsor, &mint, &escrow_key, &terms, false)?;
    config.check_proposal_terms(&sponsor, &terms)?;
    // The counters move before any token does, so a cap the escrow would break refuses first.
    config.approve_pending(total)?;
    config.escrow_opened()?;
    require!(
        ctx.accounts.mint.decimals == decimals,
        EscrowError::DecimalsMismatch
    );
    require!(
        !ctx.accounts.proposal_vault.is_frozen(),
        EscrowError::VaultFrozen
    );
    require!(
        !ctx.accounts.escrow_vault.is_frozen(),
        EscrowError::VaultFrozen
    );

    let seeds: [&[u8]; 4] = [
        PROPOSAL_SEED,
        sponsor.as_ref(),
        &competition_id,
        core::slice::from_ref(&bump),
    ];
    let signer: &[&[&[u8]]] = &[&seeds];
    let token_program = ctx.accounts.token_program.key();

    let before = ctx.accounts.escrow_vault.amount;
    transfer_from_pda(
        &ctx.accounts.token_program,
        &ctx.accounts.proposal_vault,
        &ctx.accounts.mint,
        ctx.accounts.escrow_vault.to_account_info(),
        ctx.accounts.proposal.to_account_info(),
        signer,
        total,
    )?;
    ctx.accounts.escrow_vault.reload()?;
    check_deposit(before, ctx.accounts.escrow_vault.amount, total)?;

    ctx.accounts.proposal_vault.reload()?;
    let swept = ctx.accounts.proposal_vault.amount;
    if swept > 0 {
        transfer_from_pda(
            &ctx.accounts.token_program,
            &ctx.accounts.proposal_vault,
            &ctx.accounts.mint,
            ctx.accounts.escrow_vault.to_account_info(),
            ctx.accounts.proposal.to_account_info(),
            signer,
            swept,
        )?;
        ctx.accounts.proposal_vault.reload()?;
    }
    require!(
        ctx.accounts.proposal_vault.amount == 0,
        EscrowError::Overfunded
    );
    close_account(CpiContext::new_with_signer(
        token_program,
        CloseAccount {
            account: ctx.accounts.proposal_vault.to_account_info(),
            destination: ctx.accounts.sponsor.to_account_info(),
            authority: ctx.accounts.proposal.to_account_info(),
        },
        signer,
    ))?;

    let opened = init_escrow(
        &mut ctx.accounts.escrow,
        NewEscrow {
            bump: ctx.bumps.escrow,
            decimals,
            competition_id,
            sponsor,
            mint,
            deposited: total,
        },
        terms,
        &ctx.accounts.config,
        now,
    );
    let approved = ProposalApproved {
        proposal: proposal_key,
        escrow: escrow_key,
        competition_id,
        sponsor,
        curator,
        amount: total,
        swept,
        pending_value: ctx.accounts.config.pending_value,
        open_value: ctx.accounts.config.open_value,
    };
    emit_cpi!(approved);
    emit_cpi!(opened);
    Ok(())
}

/// Moves `amount` out of `from`, a token account of `mint` whose owner is the PDA `authority`,
/// into the token account `to`, the PDA signing with `signer` (approve_proposal into the escrow
/// vault, close_proposal back to an account the sponsor owns).
pub(crate) fn transfer_from_pda<'info>(
    token_program: &Program<'info, Token>,
    from: &Account<'info, TokenAccount>,
    mint: &Account<'info, Mint>,
    to: AccountInfo<'info>,
    authority: AccountInfo<'info>,
    signer: &[&[&[u8]]],
    amount: u64,
) -> Result<()> {
    transfer_checked(
        CpiContext::new_with_signer(
            token_program.key(),
            TransferChecked {
                from: from.to_account_info(),
                mint: mint.to_account_info(),
                to,
                authority,
            },
            signer,
        ),
        amount,
        mint.decimals,
    )
}
