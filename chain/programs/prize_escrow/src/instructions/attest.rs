use anchor_lang::prelude::*;

use crate::{
    config::{clocks, Config},
    constants::{ATTESTATION_SEED, CONFIG_SEED},
    error::EscrowError,
    events::Attested,
    state::{AttestSide, Attestation, ChallengeRecord, Escrow, EscrowStatus},
};

#[event_cpi]
#[derive(Accounts)]
#[instruction(commitment: [u8; 32])]
pub struct Attest<'info> {
    /// One of the escrow's named regraders; pays the attestation's rent.
    #[account(mut)]
    pub regrader: Signer<'info>,

    #[account(mut)]
    pub escrow: Account<'info, Escrow>,

    /// One per regrader per escrow, so a regrader votes once.
    #[account(
        init,
        payer = regrader,
        space = Attestation::SPACE,
        seeds = [ATTESTATION_SEED, escrow.key().as_ref(), regrader.key().as_ref()],
        bump,
    )]
    pub attestation: Account<'info, Attestation>,

    /// The Challenge PDA whose commitment the vote names; omitted for a vote on the posted result.
    // Pinned here, before the handler runs (ChallengeMismatch otherwise): this escrow's challenge,
    // of the vote's commitment, at its own PDA ["challenge", escrow, alt_commitment]
    // (ChallengeRecord::is_at). A vote on the posted commitment takes none: no challenge commits
    // to it (challenge_reveal refuses one), so any account passed with it is refused.
    #[account(
        mut,
        has_one = escrow @ EscrowError::ChallengeMismatch,
        constraint = challenge.alt_commitment == commitment @ EscrowError::ChallengeMismatch,
        constraint = challenge.is_at(&challenge.key()) @ EscrowError::ChallengeMismatch,
    )]
    pub challenge: Option<Account<'info, ChallengeRecord>>,

    pub system_program: Program<'info, System>,

    /// The stop clock and the revoked keys.
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// A regrader votes on a result commitment (state::result_commitment of the document hash, payout
/// root and total it rebuilt): the posted commitment counts for Result, with no challenge account;
/// a challenge's, with that Challenge PDA passed in (its escrow this one, its alt_commitment the
/// vote's, at its own PDA: the account constraints pin all three), counts for Alt on that
/// challenge (Challenge.votes, and Escrow.votes_alt for every challenge together); anything else
/// is refused (InvalidResultHash with no challenge account, ChallengeMismatch for a challenge
/// account that is not this escrow's challenge of that commitment at its PDA), so a regrader who
/// rebuilds no side cannot vote. The Attestation PDA's `init` is the once-per-regrader guard: a
/// second vote finds the account already in use.
///
/// The vote that takes a challenge's commitment to k records that challenge in the escrow as the
/// winning alternative (Escrow::record_alternative: `challenger` and the alt_* fields), which
/// settle applies; since 2k > n, no other commitment can reach k after it.
///
/// attest_deadline is read on the escrow clock; a stop or a freeze never refuses a vote, a revoked
/// regrader is refused (KeyRevoked).
pub fn handle_attest(ctx: Context<Attest>, commitment: [u8; 32]) -> Result<()> {
    let (_, now) = clocks(&ctx.accounts.escrow, &ctx.accounts.config)?;
    let regrader = ctx.accounts.regrader.key();
    ctx.accounts.config.require_not_revoked(&regrader)?;
    let escrow_key = ctx.accounts.escrow.key();
    let escrow = &mut ctx.accounts.escrow;
    require!(
        escrow.status != EscrowStatus::Closed,
        EscrowError::EscrowClosed
    );
    require!(
        escrow.status == EscrowStatus::Disputed,
        EscrowError::InvalidStatus
    );
    require!(
        now < escrow.attest_deadline,
        EscrowError::AttestWindowClosed
    );
    require!(escrow.is_regrader(&regrader), EscrowError::NotARegrader);
    require!(commitment != [0; 32], EscrowError::InvalidResultHash);

    // challenge refused an alternative committing to the posted result, so a commitment names one
    // side at most.
    let (side, challenge_key, votes) = if commitment == escrow.commitment {
        escrow.votes_result = escrow
            .votes_result
            .checked_add(1)
            .ok_or(EscrowError::MathOverflow)?;
        (AttestSide::Result, Pubkey::default(), escrow.votes_result)
    } else {
        // The constraints pinned a challenge account passed in to this escrow and this commitment.
        let challenge = ctx
            .accounts
            .challenge
            .as_mut()
            .ok_or(error!(EscrowError::InvalidResultHash))?;
        challenge.votes = challenge
            .votes
            .checked_add(1)
            .ok_or(EscrowError::MathOverflow)?;
        escrow.votes_alt = escrow
            .votes_alt
            .checked_add(1)
            .ok_or(EscrowError::MathOverflow)?;
        (AttestSide::Alt, challenge.key(), challenge.votes)
    };
    let quorum = votes == escrow.k;
    if quorum && side == AttestSide::Alt {
        if let Some(challenge) = ctx.accounts.challenge.as_ref() {
            escrow.record_alternative(challenge);
        }
    }

    ctx.accounts.attestation.set_inner(Attestation {
        regrader,
        commitment,
        side,
        bump: ctx.bumps.attestation,
    });

    emit_cpi!(Attested {
        escrow: escrow_key,
        regrader,
        commitment,
        side,
        challenge: challenge_key,
        votes,
        quorum,
        votes_result: escrow.votes_result,
        votes_alt: escrow.votes_alt,
    });
    Ok(())
}
