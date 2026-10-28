use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, Token, TokenAccount};

use crate::{
    config::{clocks, Config},
    constants::CONFIG_SEED,
    error::EscrowError,
    events::ArbiterResolved,
    instructions::settle::{pay_bond, unbonded_floor},
    state::{ArbiterChoice, ChallengeRecord, Escrow, EscrowStatus},
};

#[event_cpi]
#[derive(Accounts)]
#[instruction(_choice: ArbiterChoice, commitment: [u8; 32])]
pub struct ArbiterResolve<'info> {
    /// Config.arbiter (every escrow names it at open; a Config rotate moves every escrow to the new
    /// one): a Squads v4 vault PDA, which can only sign through the multisig's CPI, or a key.
    #[account(address = config.arbiter @ EscrowError::UnauthorizedArbiter)]
    pub arbiter: Signer<'info>,

    #[account(mut, has_one = mint @ EscrowError::MintMismatch)]
    pub escrow: Account<'info, Escrow>,

    pub mint: Account<'info, Mint>,

    /// Read for its balance: the chosen side's total must not exceed it.
    #[account(
        associated_token::mint = mint,
        associated_token::authority = escrow,
        associated_token::token_program = token_program,
    )]
    pub vault: Account<'info, TokenAccount>,

    /// CHECK: only receives lamports; pinned to escrow.resolver.
    /// Every bond when the posted result is chosen.
    #[account(mut, address = escrow.resolver @ EscrowError::UnauthorizedResolver)]
    pub resolver: UncheckedAccount<'info>,

    /// The chosen Challenge PDA (choice Alternative): its escrow this one, its alt_commitment the
    /// instruction's `commitment`. Omitted when the posted result is chosen.
    // Pinned here, before the handler runs: this escrow's challenge (ChallengeMismatch), of the
    // named commitment (InvalidResultHash, which also refuses one passed with the posted result:
    // no challenge commits to it), at its own PDA ["challenge", escrow, alt_commitment]
    // (ChallengeRecord::is_at; ChallengeMismatch).
    #[account(
        has_one = escrow @ EscrowError::ChallengeMismatch,
        constraint = challenge.alt_commitment == commitment @ EscrowError::InvalidResultHash,
        constraint = challenge.is_at(&challenge.key()) @ EscrowError::ChallengeMismatch,
    )]
    pub challenge: Option<Account<'info, ChallengeRecord>>,

    /// CHECK: only receives lamports; the chosen challenge's challenger (a constraint, not the
    /// handler). Every bond when its alternative is chosen; omitted with the challenge.
    // A challenger account needs the challenge it is the challenger of (ChallengeMismatch).
    #[account(
        mut,
        constraint = challenge.as_ref().is_some_and(|ch| ch.challenger == challenger.key())
            @ EscrowError::ChallengeMismatch,
    )]
    pub challenger: Option<UncheckedAccount<'info>>,

    pub token_program: Program<'info, Token>,

    /// The arbiter, the stop clock, the PayoutStop, the guardian's freeze and the revoked keys.
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// The signer check is the `address = config.arbiter` constraint on a `Signer`: the arbiter is a
/// Squads v4 vault PDA, which carries the signer flag only inside the multisig program's CPI, so
/// no transaction outside an executed Squads proposal can pass it (or, until the vault replaces
/// it, the owner's key). A revoked arbiter is refused (KeyRevoked), and nothing is resolved while
/// a PayoutStop or the guardian's freeze of the escrow is in force (PayoutStopped, EscrowFrozen).
///
/// Only a Frozen escrow reaches the arbiter: no quorum by attest_deadline, or the guardian
/// escalated it before its unchallenged result or a recorded quorum could settle
/// (breakers::handle_escalate).
///
/// The arbiter only chooses among its results, naming the chosen one's `commitment` too
/// (InvalidResultHash when it is not the chosen side's): `choice` Posted keeps the posted result
/// (commitment the escrow's; no challenge account), and clears an alternative a quorum had
/// recorded (Escrow::clear_alternative: `challenger` and the alt_* fields back to zero, so the
/// escrow never names the side that lost as the winner); Alternative applies one challenge's, its
/// Challenge PDA passed in with its challenger (the account constraints refuse, as
/// ChallengeMismatch, a challenge of another escrow or not at its own PDA, and a challenger
/// account that is not its challenger or comes without it; AccountNotEnoughKeys without them):
/// the challenge is recorded in the escrow (Escrow::record_alternative) and its stored
/// alt_result_sha256, alt_payout_root, alt_total and alt_commitment put in force
/// (Escrow::apply). The chosen challenge must have at least one named regrader's vote
/// (AlternativeUnbacked otherwise): the arbiter picks between results the regraders reproduced,
/// the first challenge or a later one, never a vote-less alternative anyone could have bonded, so
/// controlling the arbiter and bonding a junk challenge cannot put an arbitrary root in force. It
/// cannot write a root, a document hash or a total of its own. The chosen side's total must still
/// fit the vault (TotalMismatch; post_result and challenge held each side to it, and nothing
/// takes from the vault while Frozen).
///
/// Every side that lost forfeits its bond to the side that won: every bond goes to the resolver
/// when the posted result is chosen, to the chosen challenger when its alternative is.
/// claim_deadline is now + claim_window on the escrow clock, even past hard_deadline: refund of a
/// Claimable escrow waits for it.
pub fn handle_arbiter_resolve(
    ctx: Context<ArbiterResolve>,
    choice: ArbiterChoice,
    commitment: [u8; 32],
) -> Result<()> {
    let (wall, now) = clocks(&ctx.accounts.escrow, &ctx.accounts.config)?;
    let config = &ctx.accounts.config;
    config.require_not_revoked(&ctx.accounts.arbiter.key())?;
    let escrow_key = ctx.accounts.escrow.key();
    let escrow = &ctx.accounts.escrow;
    require!(
        escrow.status != EscrowStatus::Closed,
        EscrowError::EscrowClosed
    );
    config.require_payouts(escrow, wall)?;
    require!(
        escrow.status == EscrowStatus::Frozen,
        EscrowError::InvalidStatus
    );
    let (challenge_key, challenger_key) = match choice {
        ArbiterChoice::Posted => {
            require!(
                commitment == escrow.commitment,
                EscrowError::InvalidResultHash
            );
            (Pubkey::default(), Pubkey::default())
        }
        ArbiterChoice::Alternative => {
            // The constraints pinned both accounts, when passed, to this escrow's challenge of
            // `commitment` and its challenger.
            let challenge = ctx
                .accounts
                .challenge
                .as_ref()
                .ok_or(error!(anchor_lang::error::ErrorCode::AccountNotEnoughKeys))?;
            require!(
                ctx.accounts.challenger.is_some(),
                anchor_lang::error::ErrorCode::AccountNotEnoughKeys
            );
            require!(challenge.votes > 0, EscrowError::AlternativeUnbacked);
            (challenge.key(), challenge.challenger)
        }
    };
    let claim_deadline = now
        .checked_add(escrow.claim_window)
        .ok_or(EscrowError::MathOverflow)?;
    let (resolver_paid, challenger_paid) = escrow.bonds_to_winner(choice)?;

    let escrow = &mut ctx.accounts.escrow;
    match (choice, ctx.accounts.challenge.as_ref()) {
        (ArbiterChoice::Alternative, Some(challenge)) => escrow.record_alternative(challenge),
        // An alternative a quorum recorded (the guardian escalated it inside the attest window)
        // lost: the escrow no longer names it as the one that won.
        (ArbiterChoice::Posted, _) => escrow.clear_alternative(),
        // Refused above (AccountNotEnoughKeys).
        (ArbiterChoice::Alternative, None) => {}
    }
    let side = escrow.side(choice);
    require!(
        side.total > 0 && side.total <= ctx.accounts.vault.amount,
        EscrowError::TotalMismatch
    );

    let escrow_info = escrow.to_account_info();
    let floor = unbonded_floor(&escrow_info, escrow)?;
    pay_bond(
        &escrow_info,
        &ctx.accounts.resolver.to_account_info(),
        resolver_paid,
        floor,
    )?;
    if challenger_paid > 0 {
        let challenger = ctx
            .accounts
            .challenger
            .as_ref()
            .ok_or(error!(anchor_lang::error::ErrorCode::AccountNotEnoughKeys))?;
        pay_bond(
            &escrow_info,
            &challenger.to_account_info(),
            challenger_paid,
            floor,
        )?;
    }

    escrow.apply(choice);
    escrow.resolver_bond = 0;
    escrow.challenger_bond = 0;
    escrow.claim_deadline = claim_deadline;
    escrow.status = EscrowStatus::Claimable;

    emit_cpi!(ArbiterResolved {
        escrow: escrow_key,
        arbiter: ctx.accounts.arbiter.key(),
        choice,
        payout_root: side.payout_root,
        result_sha256: side.result_sha256,
        total: side.total,
        commitment: side.commitment,
        challenge: challenge_key,
        challenger: challenger_key,
        claim_deadline,
        resolver_paid,
        challenger_paid,
    });
    Ok(())
}
