//! A sponsor's proposal: a competition the house has not yet listed, its prize already deposited.
//!
//! submit_proposal (the sponsor signs, the Config's curator co-signs once the house screened the
//! sponsor) moves `terms.total` into the proposal vault and fixes the terms and the schedule for
//! good. From there a proposal has exactly two ways out, and every one of them ends with the
//! proposal and its vault closed:
//! - approve_proposal (the curator): the escrow ["escrow", sponsor, competition_id] opens with the
//!   stored terms (approve takes no arguments, so no term can change on the way) and the deposit
//!   moves into its vault;
//! - close_proposal: the whole vault returns to a token account the sponsor owns (its associated
//!   one, or another it owns the caller names, so a sponsor that reassigned its associated
//!   account's owner cannot pin the deposit), by the sponsor (Withdrawn), the curator (Rejected,
//!   naming the sha256 of its reason) or, once review_deadline has passed, anyone naming no reason
//!   (Expired).
//!
//! The schedule is absolute and the sponsor signs it: review_deadline <= opens_at <
//! entries_deadline, and review_deadline <= the submit + MAX_REVIEW_WINDOW, so a slow review never
//! eats the entry window: the proposal expires instead. The sponsor chose the terms, so beyond the
//! open policy they are held to Config::check_proposal_terms at the submit and the approval: the
//! sponsor is not the curator, neither the resolver nor the compliance key is the sponsor or the
//! curator, the resolve window is at least MIN_RESOLVE_WINDOW and the bond at most
//! MAX_PROPOSAL_BOND. The escrow an approval opens is the sponsor's last deposit: fund refuses a
//! sponsor off the allowlist. A sponsor the guardian revoked (the OFAC "blocked property" hold) can
//! be neither approved nor returned: its deposit is held until the admin unrevokes it.

use anchor_lang::prelude::*;

use crate::{constants::PROPOSAL_SEED, state::EscrowTerms};

/// One sponsor's proposal of one competition. PDA: `["proposal", sponsor, competition_id]`. Its
/// vault is the associated token account of (this account, mint) under the classic Token program.
#[account]
#[derive(InitSpace, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub bump: u8,
    /// The mint's decimals at the submit.
    pub decimals: u8,
    /// The competition's 16-byte UUID, a PDA seed after the sponsor (and the escrow's, once
    /// approved).
    pub competition_id: [u8; 16],
    /// Submitted and funded the proposal; a PDA seed. Every exit returns the deposit to its
    /// associated token account, and both rents to it.
    pub sponsor: Pubkey,
    pub mint: Pubkey,
    /// The escrow's terms, stored whole: approve_proposal opens the escrow with exactly these.
    pub terms: EscrowTerms,
    /// Unix seconds the competition opens: review_deadline <= opens_at < terms.entries_deadline.
    pub opens_at: i64,
    /// The last second approve_proposal may land (unix seconds, wall time); after it anyone may
    /// return the deposit (close_proposal, Expired).
    pub review_deadline: i64,
    /// Unix seconds of the submit.
    pub submitted_at: i64,
    /// What submit_proposal moved into the vault (terms.total), held in Config.pending_value.
    pub deposited: u64,
    /// Zeroed room for later fields.
    pub reserved: [u8; 32],
}

impl Proposal {
    /// Account size: the 8-byte discriminator plus the fields at their longest.
    pub const SPACE: usize = 8 + Self::INIT_SPACE;

    /// Its address: `["proposal", sponsor, competition_id]` under the program.
    pub fn pda(sponsor: &Pubkey, competition_id: &[u8; 16]) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[PROPOSAL_SEED, sponsor.as_ref(), competition_id.as_ref()],
            &crate::ID,
        )
    }

    /// The seeds the proposal PDA signs with (its vault's authority), bump included:
    /// `["proposal", sponsor, competition_id, bump]`.
    pub fn signer_seeds(&self) -> [&[u8]; 4] {
        [
            PROPOSAL_SEED,
            self.sponsor.as_ref(),
            &self.competition_id,
            core::slice::from_ref(&self.bump),
        ]
    }
}
