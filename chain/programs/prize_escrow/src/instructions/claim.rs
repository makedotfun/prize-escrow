use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{transfer_checked, Mint, Token, TokenAccount, TransferChecked},
};

use crate::{
    config::{escrow_now, Config},
    constants::{CLAIM_SEED, CONFIG_SEED, MAX_PROOF_LEN},
    error::EscrowError,
    events::Claimed,
    merkle::{compute_leaf_hash, verify_proof_or_error},
    state::{ClaimReceipt, Escrow, EscrowStatus},
};

#[event_cpi]
#[derive(Accounts)]
pub struct Claim<'info> {
    /// The winner: signs for its own leaf.
    pub claimant: Signer<'info>,

    /// Pays the fees and any rent; separate from the claimant, so a claim can be gasless.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// escrow.compliance co-signing a screened claim. Omitted on the lapse path (a request whose
    /// hold window passed with no hold) and when the escrow has no compliance gate.
    #[account(address = escrow.compliance @ EscrowError::UnauthorizedCompliance)]
    pub compliance: Option<Signer<'info>>,

    #[account(mut, has_one = mint @ EscrowError::MintMismatch)]
    pub escrow: Account<'info, Escrow>,

    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = escrow,
        associated_token::token_program = token_program,
    )]
    pub vault: Account<'info, TokenAccount>,

    /// The claimant's own associated token account (the destination owner pin).
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = claimant,
        associated_token::token_program = token_program,
    )]
    pub claimant_token_account: Account<'info, TokenAccount>,

    #[account(
        init_if_needed,
        payer = payer,
        space = ClaimReceipt::SPACE,
        seeds = [CLAIM_SEED, escrow.key().as_ref(), claimant.key().as_ref()],
        bump,
    )]
    pub receipt: Account<'info, ClaimReceipt>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,

    /// The stop clock, the PayoutStop, the guardian's freeze, the revoked keys and the flow
    /// bucket (written: the claim takes from it).
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// In order, each failing with its own error:
/// - no PayoutStop and no guardian freeze of the escrow is in force (PayoutStopped,
///   EscrowFrozen), and neither the claimant nor a co-signing compliance key is revoked
///   (KeyRevoked);
/// - neither the vault nor the claimant's token account is frozen by the mint (VaultFrozen,
///   ClaimantAccountFrozen), named rather than left to the token program's raw error;
/// - the escrow is Claimable and the escrow clock is at or before claim_deadline;
/// - the leaf (escrow, claimant, total_amount) is non-zero, its proof at most MAX_PROOF_LEN deep,
///   and it verifies against payout_root; a receipt that already holds a leaf takes only that
///   one's total_amount;
/// - the receipt is not held (HeldForCompliance, even with the compliance co-signature);
/// - with a compliance key set: its co-signature, or a request (request_claim) whose hold window
///   has passed (NotCleared with no request, HoldWindowOpen before it passes);
/// - `amount` (0 = all that is left) fits what is left of the leaf, and the escrow's total;
/// - the flow bucket holds `amount` (FlowLimitExceeded): checked just before the transfer, the
///   only place the program pays an address of the claimant's choosing.
///
/// Then the vault pays the claimant's own associated token account, the escrow PDA signing.
pub fn handle_claim(
    ctx: Context<Claim>,
    total_amount: u64,
    amount: u64,
    proof: Vec<[u8; 32]>,
) -> Result<()> {
    let wall = Clock::get()?.unix_timestamp;
    let claimant = ctx.accounts.claimant.key();
    let escrow = &ctx.accounts.escrow;
    let config = &ctx.accounts.config;
    let now = escrow_now(escrow, config, wall);
    config.require_payouts(escrow, wall)?;
    config.require_not_revoked(&claimant)?;
    if let Some(compliance) = ctx.accounts.compliance.as_ref() {
        config.require_not_revoked(&compliance.key())?;
    }
    require!(!ctx.accounts.vault.is_frozen(), EscrowError::VaultFrozen);
    require!(
        !ctx.accounts.claimant_token_account.is_frozen(),
        EscrowError::ClaimantAccountFrozen
    );
    require_claimable(escrow, now)?;
    prove_leaf(escrow, &claimant, total_amount, &proof)?;

    let receipt = &mut ctx.accounts.receipt;
    bind_receipt(receipt, claimant, total_amount, ctx.bumps.receipt)?;
    require!(!receipt.is_held(), EscrowError::HeldForCompliance);
    let cosigned = ctx.accounts.compliance.is_some();
    if escrow.has_compliance() && !cosigned {
        require!(receipt.requested_at > 0, EscrowError::NotCleared);
        let clears_at = receipt
            .requested_at
            .checked_add(escrow.hold_window)
            .ok_or(EscrowError::MathOverflow)?;
        require!(now >= clears_at, EscrowError::HoldWindowOpen);
    }

    let remaining = receipt.remaining().ok_or(EscrowError::MathOverflow)?;
    require!(remaining > 0, EscrowError::AlreadyClaimed);
    let take = if amount == 0 {
        remaining
    } else {
        require!(amount <= remaining, EscrowError::ExceedsAllocation);
        amount
    };
    // The payout tree is the resolver's; the posted total still caps what all leaves can take.
    let total_claimed = escrow
        .total_claimed
        .checked_add(take)
        .filter(|claimed| *claimed <= escrow.total)
        .ok_or(EscrowError::ExceedsAllocation)?;
    receipt.amount_claimed = receipt
        .amount_claimed
        .checked_add(take)
        .ok_or(EscrowError::MathOverflow)?;
    let amount_claimed = receipt.amount_claimed;
    ctx.accounts.config.take_flow(take, wall)?;

    let seeds = escrow.signer_seeds();
    let signer: &[&[&[u8]]] = &[&seeds];
    transfer_checked(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.key(),
            TransferChecked {
                from: ctx.accounts.vault.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.claimant_token_account.to_account_info(),
                authority: escrow.to_account_info(),
            },
            signer,
        ),
        take,
        ctx.accounts.mint.decimals,
    )?;

    let escrow = &mut ctx.accounts.escrow;
    escrow.total_claimed = total_claimed;

    emit_cpi!(Claimed {
        escrow: escrow.key(),
        claimant,
        amount: take,
        amount_claimed,
        total_amount,
        cosigned,
    });
    Ok(())
}

/// claim and request_claim run while the escrow is Claimable, up to and including
/// claim_deadline (refund waits until after it).
pub(crate) fn require_claimable(escrow: &Escrow, now: i64) -> Result<()> {
    require!(
        escrow.status != EscrowStatus::Closed,
        EscrowError::EscrowClosed
    );
    require!(
        escrow.status == EscrowStatus::Claimable,
        EscrowError::InvalidStatus
    );
    require!(now <= escrow.claim_deadline, EscrowError::ClaimWindowClosed);
    Ok(())
}

/// The claimant's leaf is in the escrow's payout tree: a positive total_amount (the off-chain
/// builder never writes a zero leaf), a proof of at most MAX_PROOF_LEN siblings, and
/// `keccak256(0x00 || keccak256(escrow || claimant || u64le(total_amount)))` folding up to
/// payout_root. The escrow address in the leaf keeps one escrow's proofs off every other root.
pub(crate) fn prove_leaf(
    escrow: &Account<Escrow>,
    claimant: &Pubkey,
    total_amount: u64,
    proof: &[[u8; 32]],
) -> Result<()> {
    require!(total_amount > 0, EscrowError::NothingToClaim);
    require!(
        proof.len() <= usize::from(MAX_PROOF_LEN),
        EscrowError::ProofTooDeep
    );
    let leaf = compute_leaf_hash(&escrow.key(), claimant, total_amount);
    verify_proof_or_error(proof, &escrow.payout_root, &leaf)
}

/// Records the claimant, its PDA bump and the proven leaf on the receipt. A receipt holds one
/// leaf: the first proven total_amount (hold creates receipts with none yet) stays, and any other
/// is refused like a leaf outside the tree (the payout tree has one leaf per claimant, and
/// payout_root cannot change once the escrow is Claimable).
pub(crate) fn bind_receipt(
    receipt: &mut ClaimReceipt,
    claimant: Pubkey,
    total_amount: u64,
    bump: u8,
) -> Result<()> {
    if receipt.total_amount == 0 {
        receipt.total_amount = total_amount;
    }
    require!(
        receipt.total_amount == total_amount,
        EscrowError::InvalidMerkleProof
    );
    receipt.claimant = claimant;
    receipt.bump = bump;
    Ok(())
}
