use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, Token, TokenAccount};

use crate::{
    config::{clocks, Config},
    constants::CONFIG_SEED,
    error::EscrowError,
    events::{SettleOutcome, Settled},
    state::{ArbiterChoice, Escrow, EscrowStatus},
};

/// Permissionless: any fee payer may settle once the window it waits for has ended.
#[event_cpi]
#[derive(Accounts)]
pub struct Settle<'info> {
    #[account(mut, has_one = mint @ EscrowError::MintMismatch)]
    pub escrow: Account<'info, Escrow>,

    pub mint: Account<'info, Mint>,

    /// Read for its balance: an alternative a quorum applies must not total more than it holds.
    #[account(
        associated_token::mint = mint,
        associated_token::authority = escrow,
        associated_token::token_program = token_program,
    )]
    pub vault: Account<'info, TokenAccount>,

    /// CHECK: only receives lamports; pinned to escrow.resolver.
    /// Its bond back, and every challenger's too when the posted result stands.
    #[account(mut, address = escrow.resolver @ EscrowError::UnauthorizedResolver)]
    pub resolver: UncheckedAccount<'info>,

    /// CHECK: only receives lamports; pinned to escrow.challenger, the challenger whose alternative
    /// the regraders' quorum backed (attest recorded it). Every bond when that alternative is
    /// applied; omitted when no alternative won, and may be whenever nothing is paid to it.
    #[account(mut, address = escrow.challenger)]
    pub challenger: Option<UncheckedAccount<'info>>,

    pub token_program: Program<'info, Token>,

    /// The stop clock, the PayoutStop and the guardian's freeze.
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// Ends the challenge window or the dispute (attest counted the votes by commitment, so the side
/// that wins is a whole result: document hash, payout root and total). Nothing settles before
/// challenge_deadline (DeadlineNotReached), whatever the votes: the challenge window always runs
/// whole, so a quorum formed early (a junk self-challenge the regraders answered at once) cannot
/// cut it short for a later challenger.
/// - Challengeable at or past challenge_deadline: Undisputed, Claimable, the resolver's bond back.
/// - Disputed with k votes for the posted commitment: ResultUpheld, Claimable on the posted
///   result; the resolver takes its bond back and every challenger's.
/// - Disputed with k votes for one challenge's commitment (attest recorded that challenge in the
///   escrow as it reached k: `challenger` and the alt_* fields), at or past attest_deadline
///   (OverturnWindowOpen before it): AltApplied. The vote is binding: the alternative's
///   result_sha256, payout_root, total and commitment become the result in force
///   (Escrow::apply) and the escrow is Claimable on them; its challenger takes its bond back, the
///   resolver's and every other challenger's. The vault must hold the alternative's total
///   (TotalMismatch; challenge already refused one over the vault, and nothing takes from the
///   vault while Disputed).
/// - Disputed at or past attest_deadline with no commitment at k: NoQuorum, Frozen, every bond
///   held for arbiter_resolve (or refund after hard_deadline).
///
/// An overturn waits for the whole attest window, however early its quorum formed: attest_deadline
/// (challenge_deadline + attest_window, at least MIN_ATTEST_WINDOW, fixed by the first challenge)
/// is the watcher's and the guardian's time to see a quorum overturn the posted result and
/// escalate it to the arbiter (breakers::handle_escalate takes a recorded alternative until
/// then). Without it, on a panel the house holds a quorum of (owner decision #541), the house's
/// keys could commit a challenge on the challenge window's last second, reveal it in the reveal
/// grace, vote it to k and settle it at challenge_deadline, before anyone outside the server could
/// react. Upholding the posted result keeps its timing: challenge_deadline, as an unchallenged
/// result does, the guardian having had the whole challenge window to escalate a false one.
///
/// Since 2k > n and each regrader votes once, at most one commitment reaches k, and a quorum can
/// only form before attest_deadline (= challenge_deadline + attest_window): the outcome does not
/// depend on when settle runs, and the winning challenge is in the escrow, so no account left out
/// can freeze a dispute a quorum won.
/// While a challenge committed before challenge_deadline may still be revealed (pending_commits,
/// before challenge_deadline + reveal_grace), nothing settles (CommitsPendingReveal), so a commit
/// on the window's last second keeps its reveal; once the grace passes a commit never revealed no
/// longer holds the escrow back (close_commit returns its bond once the escrow decided).
///
/// Every deadline is read on the escrow clock, and nothing settles while a PayoutStop or the
/// guardian's freeze of the escrow is in force (PayoutStopped, EscrowFrozen).
///
/// claim_deadline is set only when the escrow becomes Claimable; a Frozen escrow keeps it 0. The
/// challenger's account is needed only when it is paid (AltApplied; AccountNotEnoughKeys
/// without it). The Challenge PDAs stay open until close_challenge returns their rent.
pub fn handle_settle(ctx: Context<Settle>) -> Result<()> {
    let (wall, now) = clocks(&ctx.accounts.escrow, &ctx.accounts.config)?;
    let escrow = &ctx.accounts.escrow;
    require!(
        escrow.status != EscrowStatus::Closed,
        EscrowError::EscrowClosed
    );
    ctx.accounts.config.require_payouts(escrow, wall)?;
    let outcome = match escrow.status {
        EscrowStatus::Challengeable => {
            require_window_over(escrow, now)?;
            SettleOutcome::Undisputed
        }
        EscrowStatus::Disputed => {
            // The challenge window runs whole whatever the votes: a quorum formed early (say, on a
            // junk self-challenge) never cuts it short, so every challenger keeps the full window.
            require_window_over(escrow, now)?;
            if escrow.votes_result >= escrow.k {
                SettleOutcome::ResultUpheld
            } else if escrow.has_challenger() {
                // An overturn waits for attest_deadline: the guardian's time to escalate it.
                require!(
                    now >= escrow.attest_deadline,
                    EscrowError::OverturnWindowOpen
                );
                SettleOutcome::AltApplied
            } else {
                require!(now >= escrow.attest_deadline, EscrowError::AttestWindowOpen);
                SettleOutcome::NoQuorum
            }
        }
        EscrowStatus::Closed => return err!(EscrowError::EscrowClosed),
        _ => return err!(EscrowError::InvalidStatus),
    };

    let (resolver_paid, challenger_paid) = match outcome {
        SettleOutcome::Undisputed => (escrow.resolver_bond, 0),
        SettleOutcome::ResultUpheld => escrow.bonds_to_winner(ArbiterChoice::Posted)?,
        SettleOutcome::AltApplied => {
            require!(
                escrow.alt_total <= ctx.accounts.vault.amount,
                EscrowError::TotalMismatch
            );
            escrow.bonds_to_winner(ArbiterChoice::Alternative)?
        }
        SettleOutcome::NoQuorum => (0, 0),
    };

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

    let escrow = &mut ctx.accounts.escrow;
    let status = if outcome == SettleOutcome::NoQuorum {
        EscrowStatus::Frozen
    } else {
        escrow.resolver_bond = 0;
        escrow.challenger_bond = 0;
        escrow.claim_deadline = now
            .checked_add(escrow.claim_window)
            .ok_or(EscrowError::MathOverflow)?;
        EscrowStatus::Claimable
    };
    if outcome == SettleOutcome::AltApplied {
        escrow.apply(ArbiterChoice::Alternative);
    }
    escrow.status = status;

    emit_cpi!(Settled {
        escrow: escrow.key(),
        outcome,
        status,
        votes_result: escrow.votes_result,
        votes_alt: escrow.votes_alt,
        claim_deadline: escrow.claim_deadline,
        result_sha256: escrow.result_sha256,
        payout_root: escrow.payout_root,
        total: escrow.total,
        commitment: escrow.commitment,
        challenger: if outcome == SettleOutcome::AltApplied {
            escrow.challenger
        } else {
            Pubkey::default()
        },
        resolver_paid,
        challenger_paid,
    });
    Ok(())
}

/// The challenge window is over at escrow clock `now`: past challenge_deadline
/// (DeadlineNotReached), and past the reveal grace too while a commit is pending
/// (CommitsPendingReveal).
fn require_window_over(escrow: &Escrow, now: i64) -> Result<()> {
    require!(
        now >= escrow.challenge_deadline,
        EscrowError::DeadlineNotReached
    );
    if escrow.pending_commits > 0 {
        require!(
            now >= escrow.reveal_deadline()?,
            EscrowError::CommitsPendingReveal
        );
    }
    Ok(())
}

/// The lamports the escrow account (`info`, holding `escrow`) keeps whatever bonds it pays: all it
/// holds less every bond it tracks (Escrow::tracked_bonds), so its rent as funded at open and any
/// lamports sent to it since. Read once per instruction, before the first pay_bond, and passed to
/// each: the bonds it pays then come out of the tracked ones only (MathOverflow, an accounting
/// fault, if the account ever held less than it tracks).
pub(crate) fn unbonded_floor(info: &AccountInfo, escrow: &Escrow) -> Result<u64> {
    Ok(info
        .lamports()
        .checked_sub(escrow.tracked_bonds()?)
        .ok_or(EscrowError::MathOverflow)?)
}

/// Moves `amount` lamports of a bond held in the escrow account to `to`, refusing (MathOverflow,
/// an accounting fault) to take the account below `floor` (unbonded_floor, read before this
/// instruction paid any bond). A zero amount moves nothing.
///
/// The floor is the escrow's own bookkeeping, not the Rent sysvar of the day: the escrow's rent
/// was funded at open and the bonds sit on top of it, so paying every bond it tracks leaves the
/// rent it was funded with (and whatever else was sent to it). Should the cluster's rent rise
/// after open, that rent may fall short of the new rent-exempt minimum: the runtime then refuses
/// the payout itself (InsufficientFundsForRent; with SIMD-0392, active on mainnet, whenever the
/// balance drops below the new minimum) until someone sends the escrow PDA the shortfall, which
/// this floor then keeps out of every payout. The program adds no refusal of its own on a
/// changed Rent sysvar.
pub(crate) fn pay_bond<'info>(
    escrow: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    amount: u64,
    floor: u64,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let left = escrow
        .lamports()
        .checked_sub(amount)
        .filter(|left| *left >= floor)
        .ok_or(EscrowError::MathOverflow)?;
    **escrow.try_borrow_mut_lamports()? = left;
    let credited = to
        .lamports()
        .checked_add(amount)
        .ok_or(EscrowError::MathOverflow)?;
    **to.try_borrow_mut_lamports()? = credited;
    Ok(())
}
