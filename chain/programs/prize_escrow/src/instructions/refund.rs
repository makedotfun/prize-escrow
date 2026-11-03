use anchor_lang::{error::ErrorCode as AnchorError, prelude::*, system_program};
use anchor_spl::{
    associated_token::{self, AssociatedToken},
    token::{
        close_account, transfer_checked, CloseAccount, Mint, Token, TokenAccount, TransferChecked,
    },
};

use crate::{
    config::{clocks, Config},
    constants::CONFIG_SEED,
    error::EscrowError,
    events::Refunded,
    instructions::settle::{pay_bond, unbonded_floor},
    state::{Escrow, EscrowStatus},
};

/// Where a sweep to `owner` lands (refund's to refund_to, close_proposal's to the sponsor), with
/// its token account state: `named`, the account the caller passed as `destination` (its
/// constraints held it to a token account of the mint that `owner` owns, `token::authority`), or
/// else `ata`, `owner`'s associated token account of the mint (its address held by its seeds),
/// created here when nothing is there yet (`payer` paying its rent, as init_if_needed did) and
/// refused unless `owner` still owns it (ConstraintTokenOwner).
///
/// The choice is what keeps the way back open (the #852 audit's P2-2): a classic Token account's
/// owner can be reassigned (SetAuthority AccountOwner), and an associated account reassigned away
/// from `owner` stays at its address, so a sweep pinned to that address would be refused for good,
/// and with it the release of open_value or pending_value. Anyone may create a token account
/// `owner` owns (InitializeAccount3 takes no signature of the owner's) and name it.
#[allow(
    clippy::too_many_arguments,
    reason = "one per account the create of the associated account needs"
)]
pub(crate) fn sweep_destination<'info>(
    named: Option<&Account<'info, TokenAccount>>,
    ata: AccountInfo<'info>,
    owner: AccountInfo<'info>,
    mint: AccountInfo<'info>,
    payer: AccountInfo<'info>,
    token_program: AccountInfo<'info>,
    associated_token_program: AccountInfo<'info>,
    system_program: AccountInfo<'info>,
) -> Result<(AccountInfo<'info>, TokenAccount)> {
    if let Some(named) = named {
        return Ok((named.to_account_info(), TokenAccount::clone(named)));
    }
    if ata.owner == &system_program::ID {
        associated_token::create(CpiContext::new(
            associated_token_program.key(),
            associated_token::Create {
                payer,
                associated_token: ata.clone(),
                authority: owner.clone(),
                mint: mint.clone(),
                system_program,
                token_program,
            },
        ))?;
    }
    require_keys_eq!(
        *ata.owner,
        anchor_spl::token::ID,
        AnchorError::AccountOwnedByWrongProgram
    );
    let state = TokenAccount::try_deserialize(&mut &ata.try_borrow_data()?[..])?;
    require_keys_eq!(state.mint, mint.key(), AnchorError::ConstraintTokenMint);
    require_keys_eq!(state.owner, owner.key(), AnchorError::ConstraintTokenOwner);
    Ok((ata, state))
}

/// Permissionless: once a refund condition holds, anyone may sweep the vault to refund_to.
#[event_cpi]
#[derive(Accounts)]
pub struct Refund<'info> {
    /// Pays the fees and, if needed, the rent of refund_to's associated token account.
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        mut,
        has_one = mint @ EscrowError::MintMismatch,
        has_one = refund_to,
    )]
    pub escrow: Account<'info, Escrow>,

    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = escrow,
        associated_token::token_program = token_program,
    )]
    pub vault: Account<'info, TokenAccount>,

    /// CHECK: receives the vault's rent when it is closed; pinned by has_one on the escrow.
    #[account(mut)]
    pub refund_to: UncheckedAccount<'info>,

    /// refund_to's associated token account of the mint, its address held by the seeds (the client
    /// derives it): where the vault goes unless `destination` names another account of
    /// refund_to's, created when absent and refused unless refund_to still owns it
    /// (sweep_destination).
    /// CHECK: the seeds hold its address; sweep_destination reads or creates the account.
    #[account(
        mut,
        seeds = [refund_to.key().as_ref(), token_program.key().as_ref(), mint.key().as_ref()],
        seeds::program = anchor_spl::associated_token::ID,
        bump,
    )]
    pub refund_to_token_account: UncheckedAccount<'info>,

    /// CHECK: only receives a bond still held (e.g. a Frozen escrow); pinned to escrow.resolver.
    #[account(mut, address = escrow.resolver @ EscrowError::UnauthorizedResolver)]
    pub resolver: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,

    /// The stop clock, the PayoutStop, the guardian's freeze, and the global cap's counter
    /// (written: the escrow's deposit comes off open_value).
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    /// Optional: any token account of the mint refund_to owns, where the vault goes instead of
    /// refund_to_token_account, so a refund_to that reassigned its associated account's owner
    /// cannot pin the escrow (and open_value) by it.
    #[account(
        mut,
        token::mint = mint,
        token::authority = refund_to,
        token::token_program = token_program,
    )]
    pub destination: Option<Account<'info, TokenAccount>>,
}

/// Every deadline is read on the escrow clock, so a stop or a freeze never lets claim_deadline lapse
/// into a refund; nothing refunds while a PayoutStop or the guardian's freeze of the escrow is in
/// force (PayoutStopped, EscrowFrozen), and a vault or refund_to token account the mint froze is
/// refused by name (VaultFrozen, RefundAccountFrozen). The refund is exempt from the flow bucket:
/// whoever sends it, it pays only refund_to, which open_escrow and submit_proposal hold to the
/// escrow's own sponsor (RefundToNotSponsor), into a token account refund_to owns (its associated
/// one, or the `destination` it owns: sweep_destination), so no caller can turn it into an outflow
/// to anyone else, an allowlisted sponsor's or a proposal's. It takes the escrow's deposit off
/// Config.open_value.
///
/// Allowed when one of these holds ("past" a deadline means after the last second the step it
/// closes may still run):
/// - Claimable after claim_deadline (claims run up to and including it), whatever hard_deadline
///   says: a late arbiter_resolve can set a claim_deadline past hard_deadline, and those claims
///   are live until it.
/// - Open at or past resolve_deadline: no result came, the whole pot goes back.
/// - Open, Challengeable, Frozen, or Disputed with no quorum recorded, after hard_deadline: the
///   backstop for a window nobody settled, a dispute no side won and an arbiter that never acted.
///
/// A Disputed escrow whose quorum is recorded is refused at any time (QuorumRecorded): k votes for
/// the posted commitment (votes_result), or a challenge whose votes reached k, which attest
/// recorded as the winning alternative (Escrow::has_challenger). The vote binds, and a refund
/// would hand the pot to refund_to and every bond back as if no side had won. settle applies the
/// quorum instead, and stays callable past hard_deadline: it reads no hard_deadline, the
/// challenge deadline, the reveal grace and (for an overturn) the attest deadline it waits for
/// all fall before hard_deadline (the grace is shorter than every attest window open_escrow
/// accepts, and hard_deadline is every window past resolve_deadline), and nothing takes from the
/// vault while Disputed, so an applied alternative's total still fits it. It refuses only what
/// refund refuses too, a PayoutStop or the guardian's freeze. Once settled the escrow is
/// Claimable, and it refunds after its claim_deadline.
///
/// A Frozen escrow refunds after hard_deadline, however it froze: settle's NoQuorum, or the
/// guardian's escalate (breakers::handle_escalate), which takes a dispute only before a recorded
/// quorum may settle (Escrow::quorum_settles_at: challenge_deadline for the posted side,
/// attest_deadline for an alternative), and an unchallenged result only inside its challenge
/// window (Escrow::challenge_window_over), so an escalation never turns a result that bound into
/// a refund. An escrow escalated inside that window with its votes
/// already at k is the arbiter's to resolve like any other, and is refunded past hard_deadline
/// if the arbiter never does: a quorum binds only from quorum_settles_at. A Frozen escrow has no
/// claim_deadline (settle sets one only on Claimable), so it waits for the arbiter until
/// hard_deadline: refunding it once "past claim_deadline" (0) would let anyone pre-empt the
/// arbiter the moment a dispute froze.
///
/// Sweeps the whole vault (an empty one too, so a fully claimed escrow still closes; the
/// unclaimed leaves, the unawarded rest and any donation alike) to refund_to's token account,
/// closes the vault with its rent to refund_to (for an escrow a proposal opened, the curator paid
/// that rent at the approval, one 165-byte token account's, 1,488,440 lamports under the rent the
/// tests pin, and it ends with the sponsor: accepted, a cost of the approval like the Escrow
/// account's own rent, which stays as the Closed replay marker), returns the resolver's bond if
/// still held, and
/// leaves the escrow account alive as Closed: its PDA cannot be opened again, and every
/// instruction but close_challenge refuses a Closed escrow. A refund decides nothing: the
/// challengers' bonds still held (a dispute no side won: Disputed with no quorum recorded, or
/// Frozen, past hard_deadline) stay in the escrow account (challenger_bond), and close_challenge
/// returns each to its payer as it closes that Challenge PDA; once a side won, settle or
/// arbiter_resolve paid them out.
pub fn handle_refund(ctx: Context<Refund>) -> Result<()> {
    let (wall, now) = clocks(&ctx.accounts.escrow, &ctx.accounts.config)?;
    let escrow = &ctx.accounts.escrow;
    let from_status = escrow.status;
    require!(
        from_status != EscrowStatus::Closed,
        EscrowError::EscrowClosed
    );
    ctx.accounts.config.require_payouts(escrow, wall)?;
    match from_status {
        EscrowStatus::Closed => return err!(EscrowError::EscrowClosed),
        EscrowStatus::Claimable => require!(
            now > escrow.claim_deadline,
            EscrowError::ClaimWindowNotElapsed
        ),
        // Before the hard_deadline arm: a recorded quorum is settle's to apply, past it too.
        EscrowStatus::Disputed if escrow.quorum_recorded() => {
            return err!(EscrowError::QuorumRecorded)
        }
        _ if now > escrow.hard_deadline => {}
        EscrowStatus::Open => require!(
            now >= escrow.resolve_deadline,
            EscrowError::DeadlineNotReached
        ),
        EscrowStatus::Challengeable | EscrowStatus::Disputed | EscrowStatus::Frozen => {
            return err!(EscrowError::DeadlineNotReached)
        }
    }
    require!(!ctx.accounts.vault.is_frozen(), EscrowError::VaultFrozen);
    let (to, to_state) = sweep_destination(
        ctx.accounts.destination.as_ref(),
        ctx.accounts.refund_to_token_account.to_account_info(),
        ctx.accounts.refund_to.to_account_info(),
        ctx.accounts.mint.to_account_info(),
        ctx.accounts.payer.to_account_info(),
        ctx.accounts.token_program.to_account_info(),
        ctx.accounts.associated_token_program.to_account_info(),
        ctx.accounts.system_program.to_account_info(),
    )?;
    require!(!to_state.is_frozen(), EscrowError::RefundAccountFrozen);

    let escrow = &ctx.accounts.escrow;
    let amount = ctx.accounts.vault.amount;
    let seeds = escrow.signer_seeds();
    let signer: &[&[&[u8]]] = &[&seeds];
    let token_program = ctx.accounts.token_program.key();
    if amount > 0 {
        transfer_checked(
            CpiContext::new_with_signer(
                token_program,
                TransferChecked {
                    from: ctx.accounts.vault.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to,
                    authority: escrow.to_account_info(),
                },
                signer,
            ),
            amount,
            ctx.accounts.mint.decimals,
        )?;
    }
    close_account(CpiContext::new_with_signer(
        token_program,
        CloseAccount {
            account: ctx.accounts.vault.to_account_info(),
            destination: ctx.accounts.refund_to.to_account_info(),
            authority: escrow.to_account_info(),
        },
        signer,
    ))?;

    let escrow_info = escrow.to_account_info();
    let resolver_paid = escrow.resolver_bond;
    let floor = unbonded_floor(&escrow_info, escrow)?;
    pay_bond(
        &escrow_info,
        &ctx.accounts.resolver.to_account_info(),
        resolver_paid,
        floor,
    )?;

    // The global cap's counter falls here and nowhere else: an escrow its winners claimed in full
    // keeps counting against global_cap until this refund closes it after its claim_deadline
    // (the server's refund job sends it then, server/chain/jobs/refund.ts), so open_value counts
    // every escrow not yet refunded, Claimable ones included.
    ctx.accounts.config.release(escrow.deposited);
    let escrow = &mut ctx.accounts.escrow;
    escrow.resolver_bond = 0;
    escrow.status = EscrowStatus::Closed;

    emit_cpi!(Refunded {
        escrow: escrow.key(),
        refund_to: escrow.refund_to,
        amount,
        from_status,
        resolver_paid,
        challenger_bonds_held: escrow.challenger_bond,
    });
    Ok(())
}
