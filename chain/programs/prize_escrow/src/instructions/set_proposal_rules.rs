use anchor_lang::prelude::*;

use crate::{
    config::Config,
    constants::{CONFIG_SEED, PROPOSAL_SEED},
    error::EscrowError,
    events::ProposalRulesSet,
    proposal::Proposal,
};

#[event_cpi]
#[derive(Accounts)]
pub struct SetProposalRules<'info> {
    /// The Config's curator (checked in the handler).
    pub curator: Signer<'info>,

    /// Its terms.rules_sha256 is written; nothing else changes.
    #[account(
        mut,
        seeds = [PROPOSAL_SEED, proposal.sponsor.as_ref(), proposal.competition_id.as_ref()],
        bump = proposal.bump,
    )]
    pub proposal: Account<'info, Proposal>,

    /// The curator, the stop and the revocation list.
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// The curator fixes the rules a proposal was submitted without: the sha256 of the rules document,
/// written into its stored terms once. Refused unless the signer is the Config's curator today
/// (ProposalsDisabled, UnauthorizedCurator, KeyRevoked), the review deadline has not passed
/// (ReviewWindowClosed), intake runs (IntakeStopped, Retired) and the sponsor is not revoked
/// (SponsorRevoked): the gates approve_proposal holds it to. The stored hash must still be all
/// zero (RulesAlreadySet: a hash the sponsor submitted, or one set before, never changes) and the
/// new one must not be (RulesNotSet). approve_proposal refuses a proposal whose hash is all zero,
/// so a deposit submitted before its rules were written lists only after this. Emits
/// ProposalRulesSet.
pub fn handle_set_proposal_rules(
    ctx: Context<SetProposalRules>,
    rules_sha256: [u8; 32],
) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let curator = ctx.accounts.curator.key();
    let proposal_key = ctx.accounts.proposal.key();
    let config = &ctx.accounts.config;
    let proposal = &mut ctx.accounts.proposal;
    config.require_curator(&curator)?;
    require!(
        now <= proposal.review_deadline,
        EscrowError::ReviewWindowClosed
    );
    config.require_intake(now)?;
    require!(
        !config.is_revoked(&proposal.sponsor),
        EscrowError::SponsorRevoked
    );
    require!(
        proposal.terms.rules_sha256 == [0; 32],
        EscrowError::RulesAlreadySet
    );
    require!(rules_sha256 != [0; 32], EscrowError::RulesNotSet);
    proposal.terms.rules_sha256 = rules_sha256;
    let set = ProposalRulesSet {
        proposal: proposal_key,
        sponsor: proposal.sponsor,
        competition_id: proposal.competition_id,
        rules_sha256,
    };
    emit_cpi!(set);
    Ok(())
}
