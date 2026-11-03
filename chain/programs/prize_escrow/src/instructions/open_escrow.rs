use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{transfer_checked, Mint, Token, TokenAccount, TransferChecked},
};

use crate::{
    config::Config,
    constants::{CONFIG_SEED, ESCROW_SEED, MAX_REGRADERS},
    error::EscrowError,
    events::EscrowOpened,
    state::{bond_floor, Escrow, EscrowStatus, EscrowTerms},
};

#[event_cpi]
#[derive(Accounts)]
#[instruction(competition_id: [u8; 16])]
pub struct OpenEscrow<'info> {
    /// Funds the vault from `sponsor_token_account` and pays the rent.
    #[account(mut)]
    pub sponsor: Signer<'info>,

    /// PDA ["escrow", sponsor, competition_id]: one sponsor cannot open (squat) another's address.
    #[account(
        init,
        payer = sponsor,
        space = Escrow::SPACE,
        seeds = [ESCROW_SEED, sponsor.key().as_ref(), competition_id.as_ref()],
        bump,
    )]
    pub escrow: Account<'info, Escrow>,

    /// The prize mint, owned by the classic Token program (no Token-2022, so no transfer hook).
    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        token::mint = mint,
        token::authority = sponsor,
        token::token_program = token_program,
    )]
    pub sponsor_token_account: Account<'info, TokenAccount>,

    /// The escrow's associated token account. init_if_needed, so a vault someone created ahead
    /// of time cannot block the open.
    #[account(
        init_if_needed,
        payer = sponsor,
        associated_token::mint = mint,
        associated_token::authority = escrow,
        associated_token::token_program = token_program,
    )]
    pub vault: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,

    /// The open policy, the caps (open_value grows by the deposit) and the stop.
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// After EscrowTerms::validate, Config holds the open to its policy (Config::check_terms_policy
/// with the sponsor allowlist, which also refuses the escrow's own address as the resolver or the
/// compliance key: RoleIsEscrow), refuses it while intake is stopped (IntakeStopped), and holds
/// the deposit to the per-escrow cap C_e and open_value, with what pending proposals hold, to the
/// global cap C_g (EscrowCapExceeded, GlobalCapExceeded).
/// A frozen sponsor or vault token account is refused by name (SponsorAccountFrozen,
/// VaultFrozen). The escrow keeps Config's global stopped seconds (its clock counts only stops
/// after it opened) and reveal grace (always shorter than its attest window: MAX_REVEAL_GRACE <
/// MIN_ATTEST_WINDOW).
pub fn handle_open_escrow(
    ctx: Context<OpenEscrow>,
    competition_id: [u8; 16],
    terms: EscrowTerms,
) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    terms.validate(now, bond_floor(&Rent::get()?))?;
    let sponsor = ctx.accounts.sponsor.key();
    let mint = ctx.accounts.mint.key();
    let escrow_key = ctx.accounts.escrow.key();
    let config = &mut ctx.accounts.config;
    config.require_intake(now)?;
    config.check_terms_policy(&sponsor, &mint, &escrow_key, &terms, true)?;
    let deposited = config.deposit(0, terms.total)?;
    config.escrow_opened()?;
    require!(
        !ctx.accounts.sponsor_token_account.is_frozen(),
        EscrowError::SponsorAccountFrozen
    );
    require!(!ctx.accounts.vault.is_frozen(), EscrowError::VaultFrozen);

    let decimals = ctx.accounts.mint.decimals;
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
        terms.total,
        decimals,
    )?;
    ctx.accounts.vault.reload()?;
    check_deposit(before, ctx.accounts.vault.amount, terms.total)?;

    let opened = init_escrow(
        &mut ctx.accounts.escrow,
        NewEscrow {
            bump: ctx.bumps.escrow,
            decimals,
            competition_id,
            sponsor,
            mint,
            deposited,
        },
        terms,
        &ctx.accounts.config,
        now,
    );
    emit_cpi!(opened);
    Ok(())
}

/// What an escrow opens with beyond its terms: its PDA's bump, the mint's decimals, the
/// competition id and the sponsor (its seeds), the mint, and what Config::deposit counted for it.
pub(crate) struct NewEscrow {
    pub bump: u8,
    pub decimals: u8,
    pub competition_id: [u8; 16],
    pub sponsor: Pubkey,
    pub mint: Pubkey,
    pub deposited: u64,
}

/// Writes a freshly created escrow account, Open, from `terms` (already held to
/// EscrowTerms::validate and Config::check_terms_policy, the deposit already in its vault and
/// counted by Config::deposit or Config::approve_pending), and returns the EscrowOpened event its
/// instruction emits. The one place an escrow is born: open_escrow and approve_proposal both
/// call it, so an escrow a proposal opens is field for field the one open_escrow would have
/// opened with the same terms at the same moment. The escrow keeps Config's global stopped
/// seconds at `now` (its clock counts only stops after it opened) and Config's reveal grace.
pub(crate) fn init_escrow(
    escrow: &mut Account<Escrow>,
    new: NewEscrow,
    terms: EscrowTerms,
    config: &Config,
    now: i64,
) -> EscrowOpened {
    let escrow_key = escrow.key();
    // validate() bounded the set to 1..=MAX_REGRADERS keys, so n fits a u8 and the slots.
    let n = terms.regraders.len();
    let mut regraders = [Pubkey::default(); MAX_REGRADERS as usize];
    regraders[..n].copy_from_slice(&terms.regraders);

    escrow.set_inner(Escrow {
        bump: new.bump,
        decimals: new.decimals,
        status: EscrowStatus::Open,
        k: terms.k,
        n: n as u8,
        competition_id: new.competition_id,
        sponsor: new.sponsor,
        resolver: terms.resolver,
        compliance: terms.compliance,
        arbiter: terms.arbiter,
        refund_to: terms.refund_to,
        mint: new.mint,
        challenger: Pubkey::default(),
        rules_sha256: terms.rules_sha256,
        entries_root: [0; 32],
        payout_root: [0; 32],
        result_sha256: [0; 32],
        kit_sha256: [0; 32],
        commitment: [0; 32],
        alt_result_sha256: [0; 32],
        alt_payout_root: [0; 32],
        alt_commitment: [0; 32],
        entries_count: 0,
        challenge_count: 0,
        total: terms.total,
        total_claimed: 0,
        alt_total: 0,
        bond_lamports: terms.bond_lamports,
        resolver_bond: 0,
        challenger_bond: 0,
        entries_deadline: terms.entries_deadline,
        final_end: terms.final_end,
        resolve_deadline: terms.resolve_deadline,
        challenge_window: terms.challenge_window,
        attest_window: terms.attest_window,
        hold_window: terms.hold_window,
        claim_window: terms.claim_window,
        challenge_deadline: 0,
        attest_deadline: 0,
        claim_deadline: 0,
        hard_deadline: terms.hard_deadline,
        votes_result: 0,
        votes_alt: 0,
        regraders,
        deposited: new.deposited,
        stop_base: config.global_stopped(now),
        freeze_since: 0,
        freeze_until: 0,
        frozen_secs: 0,
        reveal_grace: config.reveal_grace,
        commit_bond: 0,
        pending_commits: 0,
        reserved: [0; 64],
    });

    EscrowOpened {
        escrow: escrow_key,
        competition_id: new.competition_id,
        sponsor: new.sponsor,
        resolver: terms.resolver,
        compliance: terms.compliance,
        arbiter: terms.arbiter,
        refund_to: terms.refund_to,
        mint: new.mint,
        decimals: new.decimals,
        total: terms.total,
        rules_sha256: terms.rules_sha256,
        regraders: terms.regraders,
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
    }
}

/// The underfunding check open_escrow and fund make after their transfer: the vault, measured
/// before and after, must have grown by exactly `amount`. The classic Token program moves what it
/// is asked to, but the vault balance caps what post_result and arbiter_resolve may set as the
/// total, so it is measured rather than trusted.
pub(crate) fn check_deposit(before: u64, after: u64, amount: u64) -> Result<()> {
    let grown = after
        .checked_sub(before)
        .ok_or(error!(EscrowError::Underfunded))?;
    require!(grown >= amount, EscrowError::Underfunded);
    require!(grown == amount, EscrowError::Overfunded);
    Ok(())
}
