//! The safeguards release on the release build (`node scripts/chain/build.ts release` first): the
//! Config only the upgrade authority creates; the open policy (mints, sponsors, refund_to, the
//! arbiter, the compliance key, the minimum bond, the window floors, the regrader registry, the
//! house allowance, independence, revoked keys); the per-escrow and global caps and the claim
//! flow bucket; the stoppable escrow clock (a PayoutStop holds claim_deadline, stops lapse after 7
//! days unless the admin extends them, the guardian only escalates); revoke and rotate; the
//! guardian's freeze and escalate against a house majority; the named errors for token accounts
//! the mint froze; and the two-step challenge (commit, then reveal in a later slot). And the
//! regressions of #535's verify: a revoked key never becomes the admin, an escalation never
//! shortens the admin's stop, and lamports sent to an unvoted seat's Attestation PDA never block
//! its rotation (the refund of a dispute whose quorum is recorded is in tests/lifecycle.rs).
//!
//! Time moves by rewriting LiteSVM's Clock sysvar, so the real 72 h, 48 h and 7-day windows run.

mod common;
mod mainnet;
mod program_so;

use {
    anchor_lang::{
        error::ErrorCode as AnchorErrorCode,
        event::EVENT_IX_TAG_LE,
        prelude::{Clock, Pubkey},
        solana_program::{
            instruction::{error::InstructionError, Instruction},
            program_option::COption,
            program_pack::Pack,
            system_program,
        },
        AccountDeserialize, AnchorDeserialize, Discriminator, InstructionData, ToAccountMetas,
    },
    anchor_spl::{
        associated_token::{self, get_associated_token_address},
        token::{self, spl_token},
    },
    common::{
        config_init, config_pda, initialize_config_ix, next_slot, open_floors, open_limits,
        program_data_pda, salt_for, set_upgrade_authority,
    },
    litesvm::{
        types::{TransactionMetadata, TransactionResult},
        LiteSVM,
    },
    prize_escrow::{
        accounts as accts, commit_hash, instruction as ixs,
        merkle::{compute_leaf_hash, hash_pair},
        result_commitment, AllowList, ArbiterChoice, ChallengeCommitted, ChallengeRecord,
        Challenged, CommitClosed, CommitRecord, Config, ConfigChange, ConfigChanged, ConfigInit,
        Escalated, Escrow, EscrowError, EscrowRole, EscrowStatus, EscrowTerms, Floors,
        FreezeChanged, Limits, RevocationChanged, RoleRotated, SettleOutcome, Settled, StopChanged,
        StopState, ATTESTATION_SEED, CHALLENGE_SEED, ESCROW_SEED, EVENT_AUTHORITY_AND_BUMP,
        HOLD_REVIEW, MIN_ATTEST_WINDOW, MIN_CHALLENGE_WINDOW, MIN_HOLD_WINDOW, MIN_REVEAL_GRACE,
        STOP_DURATION,
    },
    solana_account::Account,
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
    solana_transaction_error::TransactionError,
};

const EVENT_AUTHORITY: Pubkey = EVENT_AUTHORITY_AND_BUMP.0;

const DECIMALS: u8 = 6;
const TOTAL: u64 = 5_000_000_000;
/// The two winners' leaves (together TOTAL).
const PRIZES: [u64; 2] = [3_000_000_000, 2_000_000_000];
const BOND: u64 = 100_000_001;
const SOL: u64 = 1_000_000_000;

const HOUR: i64 = 3_600;
const DAY: i64 = 24 * HOUR;
const NOW: i64 = 1_800_000_000;
const ENTRIES_DEADLINE: i64 = NOW + DAY;
const FINAL_END: i64 = NOW + 2 * DAY;
const RESOLVE_DEADLINE: i64 = NOW + 7 * DAY;
const CLAIM_WINDOW: i64 = 30 * DAY;
const HARD_DEADLINE: i64 = NOW + 365 * DAY;
const POST_AT: i64 = FINAL_END;
const CHALLENGE_AT: i64 = POST_AT + HOUR;
const CHALLENGE_DEADLINE: i64 = POST_AT + MIN_CHALLENGE_WINDOW;
const CLAIM_DEADLINE: i64 = CHALLENGE_DEADLINE + CLAIM_WINDOW;

const CID: [u8; 16] = [0x34; 16];
const ENTRIES_ROOT: [u8; 32] = [0xe5; 32];
const RESULT: [u8; 32] = [0xb2; 32];
const KIT: [u8; 32] = [0xc3; 32];
const RULES: [u8; 32] = [0xf6; 32];
/// The honest alternative a challenger reveals: its document hash and root.
const ALT: [u8; 32] = [0xd4; 32];
const ALT_ROOT: [u8; 32] = [0xa7; 32];
/// A junk alternative its committer never reveals in time.
const JUNK: [u8; 32] = [0x6e; 32];
const JUNK_ROOT: [u8; 32] = [0x6f; 32];

// --------------------------------------------------------------------------------- the world

/// Every key, a classic-Token mint, the sponsor's funding token account (not its associated one,
/// where refunds land) and a Config the admin (the fee payer, also the upgrade authority) created.
struct S {
    svm: LiteSVM,
    admin: Keypair,
    guardian: Keypair,
    arbiter: Keypair,
    sponsor: Keypair,
    resolver: Keypair,
    compliance: Keypair,
    regraders: [Keypair; 3],
    challenger: Keypair,
    copier: Keypair,
    stranger: Keypair,
    winners: [Keypair; 2],
    mint: Pubkey,
    funding: Pubkey,
    cid: [u8; 16],
    terms: EscrowTerms,
}

impl S {
    /// The world before the Config exists.
    fn bare() -> Self {
        let mut svm = mainnet::svm();
        svm.add_program(prize_escrow::ID, program_so::bytes())
            .unwrap();
        set_time(&mut svm, NOW);
        let admin = Keypair::new();
        let guardian = Keypair::new();
        let arbiter = Keypair::new();
        let sponsor = Keypair::new();
        let resolver = Keypair::new();
        let compliance = Keypair::new();
        let regraders = [Keypair::new(), Keypair::new(), Keypair::new()];
        let challenger = Keypair::new();
        let copier = Keypair::new();
        let stranger = Keypair::new();
        let winners = [Keypair::new(), Keypair::new()];
        for kp in [
            &admin,
            &guardian,
            &arbiter,
            &sponsor,
            &resolver,
            &compliance,
            &challenger,
            &copier,
            &stranger,
        ]
        .into_iter()
        .chain(regraders.iter())
        {
            svm.airdrop(&kp.pubkey(), 10 * SOL).unwrap();
        }
        let mint = Pubkey::new_unique();
        set_mint(&mut svm, mint);
        let funding = Pubkey::new_unique();
        set_token_account(&mut svm, funding, mint, sponsor.pubkey(), 4 * TOTAL, false);
        let terms = EscrowTerms {
            total: TOTAL,
            rules_sha256: RULES,
            resolver: resolver.pubkey(),
            compliance: compliance.pubkey(),
            arbiter: arbiter.pubkey(),
            refund_to: sponsor.pubkey(),
            regraders: regraders.iter().map(Signer::pubkey).collect(),
            k: 2,
            bond_lamports: BOND,
            entries_deadline: ENTRIES_DEADLINE,
            final_end: FINAL_END,
            resolve_deadline: RESOLVE_DEADLINE,
            challenge_window: MIN_CHALLENGE_WINDOW,
            attest_window: MIN_ATTEST_WINDOW,
            hold_window: MIN_HOLD_WINDOW,
            claim_window: CLAIM_WINDOW,
            hard_deadline: HARD_DEADLINE,
        };
        S {
            svm,
            admin,
            guardian,
            arbiter,
            sponsor,
            resolver,
            compliance,
            regraders,
            challenger,
            copier,
            stranger,
            winners,
            mint,
            funding,
            cid: CID,
            terms,
        }
    }

    fn init(&self) -> ConfigInit {
        let mut init = config_init(
            self.admin.pubkey(),
            self.guardian.pubkey(),
            self.arbiter.pubkey(),
            &[self.mint],
            &[self.sponsor.pubkey()],
            &self.terms.regraders,
        );
        // The regraders are the house's (owner decision #541: the house may hold the panel for
        // now), which max_house_regraders = MAX_REGRADERS allows.
        for entry in &mut init.regraders {
            entry.house = true;
        }
        init
    }

    /// The world with its Config, created by the upgrade authority.
    fn new() -> Self {
        let mut s = S::bare();
        set_upgrade_authority(&mut s.svm, Some(s.admin.pubkey()));
        let ix = initialize_config_ix(s.admin.pubkey(), s.init());
        ok(send(&mut s.svm, &s.admin, ix, &[]), "initialize_config");
        s
    }

    /// Opened at NOW with the default terms, the entries root committed.
    fn committed() -> Self {
        let mut s = S::new();
        ok(s.open(&s.terms.clone()), "open_escrow");
        ok(s.commit_entries(), "commit_entries");
        s
    }

    /// Committed, and the winners' leaves posted at POST_AT (Challengeable).
    fn posted() -> Self {
        let mut s = S::committed();
        s.at(POST_AT);
        let resolver = s.resolver.insecure_clone();
        ok(s.post(&resolver), "post_result");
        s
    }

    /// Posted and settled undisputed at CHALLENGE_DEADLINE: Claimable until CLAIM_DEADLINE.
    fn claimable() -> Self {
        let mut s = S::posted();
        s.at(CHALLENGE_DEADLINE);
        ok(s.settle(), "settle");
        assert_eq!(s.state().claim_deadline, CLAIM_DEADLINE);
        s
    }

    // ------------------------------------------------------------------------ plumbing

    fn at(&mut self, unix_timestamp: i64) {
        set_time(&mut self.svm, unix_timestamp);
    }

    fn escrow(&self) -> Pubkey {
        Pubkey::find_program_address(
            &[ESCROW_SEED, self.sponsor.pubkey().as_ref(), &self.cid],
            &prize_escrow::ID,
        )
        .0
    }

    fn vault(&self) -> Pubkey {
        get_associated_token_address(&self.escrow(), &self.mint)
    }

    fn state(&self) -> Escrow {
        let account = self.svm.get_account(&self.escrow()).expect("the escrow");
        Escrow::try_deserialize(&mut account.data.as_slice()).unwrap()
    }

    fn config(&self) -> Config {
        let account = self.svm.get_account(&config_pda()).expect("the Config");
        Config::try_deserialize(&mut account.data.as_slice()).unwrap()
    }

    fn lamports(&self, address: &Pubkey) -> u64 {
        self.svm.get_account(address).map_or(0, |a| a.lamports)
    }

    fn tokens(&self, address: &Pubkey) -> u64 {
        let account = self.svm.get_account(address).expect("the token account");
        spl_token::state::Account::unpack(&account.data)
            .unwrap()
            .amount
    }

    /// Freezes (or thaws) a token account in place, as the mint's freeze authority would.
    fn set_frozen(&mut self, address: Pubkey, frozen: bool) {
        let mut account = self.svm.get_account(&address).expect("the token account");
        let mut state = spl_token::state::Account::unpack(&account.data).unwrap();
        state.state = if frozen {
            spl_token::state::AccountState::Frozen
        } else {
            spl_token::state::AccountState::Initialized
        };
        state.pack_into_slice(&mut account.data);
        self.svm.set_account(address, account).unwrap();
    }

    fn winner(&self, w: usize) -> Pubkey {
        self.winners[w].pubkey()
    }

    fn payout_root(&self) -> [u8; 32] {
        hash_pair(&self.leaf(0), &self.leaf(1))
    }

    fn leaf(&self, w: usize) -> [u8; 32] {
        compute_leaf_hash(&self.escrow(), &self.winner(w), PRIZES[w])
    }

    fn posted_commitment(&self) -> [u8; 32] {
        result_commitment(&RESULT, &self.payout_root(), TOTAL)
    }

    fn challenge_pda(&self, alt_commitment: &[u8; 32]) -> Pubkey {
        Pubkey::find_program_address(
            &[CHALLENGE_SEED, self.escrow().as_ref(), alt_commitment],
            &prize_escrow::ID,
        )
        .0
    }

    fn commit_pda(&self, challenger: &Pubkey, hash: &[u8; 32]) -> Pubkey {
        CommitRecord::pda(&self.escrow(), challenger, hash).0
    }

    // ------------------------------------------------------------------- the escrow

    fn open_ix(
        &self,
        sponsor: Pubkey,
        funding: Pubkey,
        mint: Pubkey,
        terms: &EscrowTerms,
    ) -> Instruction {
        let escrow = Pubkey::find_program_address(
            &[ESCROW_SEED, sponsor.as_ref(), &self.cid],
            &prize_escrow::ID,
        )
        .0;
        instruction(
            accts::OpenEscrow {
                sponsor,
                escrow,
                mint,
                sponsor_token_account: funding,
                vault: get_associated_token_address(&escrow, &mint),
                token_program: token::ID,
                associated_token_program: associated_token::ID,
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::OpenEscrow {
                competition_id: self.cid,
                terms: terms.clone(),
            },
        )
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn open(&mut self, terms: &EscrowTerms) -> TransactionResult {
        let ix = self.open_ix(self.sponsor.pubkey(), self.funding, self.mint, terms);
        send(&mut self.svm, &self.admin, ix, &[&self.sponsor])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn fund(&mut self, amount: u64) -> TransactionResult {
        let ix = instruction(
            accts::Fund {
                sponsor: self.sponsor.pubkey(),
                escrow: self.escrow(),
                mint: self.mint,
                sponsor_token_account: self.funding,
                vault: self.vault(),
                token_program: token::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Fund { amount },
        );
        send(&mut self.svm, &self.admin, ix, &[&self.sponsor])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn commit_entries(&mut self) -> TransactionResult {
        let ix = instruction(
            accts::CommitEntries {
                resolver: self.resolver.pubkey(),
                escrow: self.escrow(),
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::CommitEntries {
                entries_root: ENTRIES_ROOT,
                entries_count: 2,
            },
        );
        send(&mut self.svm, &self.admin, ix, &[&self.resolver])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn post(&mut self, resolver: &Keypair) -> TransactionResult {
        let ix = instruction(
            accts::PostResult {
                resolver: resolver.pubkey(),
                escrow: self.escrow(),
                mint: self.mint,
                vault: self.vault(),
                token_program: token::ID,
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::PostResult {
                payout_root: self.payout_root(),
                result_sha256: RESULT,
                kit_sha256: KIT,
                total: TOTAL,
            },
        );
        send(&mut self.svm, &self.admin, ix, &[resolver])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn commit(&mut self, challenger: &Keypair, hash: [u8; 32]) -> TransactionResult {
        let ix = instruction(
            accts::ChallengeCommit {
                challenger: challenger.pubkey(),
                config: config_pda(),
                escrow: self.escrow(),
                commit: self.commit_pda(&challenger.pubkey(), &hash),
                system_program: system_program::ID,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ChallengeCommit { hash },
        );
        send(&mut self.svm, &self.admin, ix, &[challenger])
    }

    /// challenge_reveal by `challenger` of the commit at `commit`.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn reveal_at(
        &mut self,
        challenger: &Keypair,
        commit: Pubkey,
        salt: [u8; 32],
        alt: ([u8; 32], [u8; 32]),
    ) -> TransactionResult {
        let alt_commitment = result_commitment(&alt.0, &alt.1, TOTAL);
        let ix = instruction(
            accts::ChallengeReveal {
                challenger: challenger.pubkey(),
                config: config_pda(),
                escrow: self.escrow(),
                mint: self.mint,
                vault: self.vault(),
                commit,
                challenge: self.challenge_pda(&alt_commitment),
                token_program: token::ID,
                system_program: system_program::ID,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ChallengeReveal {
                salt,
                alt_result_sha256: alt.0,
                alt_payout_root: alt.1,
                alt_total: TOTAL,
                alt_commitment,
            },
        );
        send(&mut self.svm, &self.admin, ix, &[challenger])
    }

    /// The hash and salt `challenger` commits `alt` with.
    fn hash_of(&self, challenger: &Pubkey, alt: ([u8; 32], [u8; 32])) -> ([u8; 32], [u8; 32]) {
        let alt_commitment = result_commitment(&alt.0, &alt.1, TOTAL);
        let salt = salt_for(challenger, &alt_commitment);
        (commit_hash(&alt_commitment, challenger, &salt), salt)
    }

    /// Both steps: commit, then reveal in the next slot.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn challenge(&mut self, challenger: &Keypair, alt: ([u8; 32], [u8; 32])) -> TransactionResult {
        let (hash, salt) = self.hash_of(&challenger.pubkey(), alt);
        ok(self.commit(challenger, hash), "challenge_commit");
        next_slot(&mut self.svm);
        let commit = self.commit_pda(&challenger.pubkey(), &hash);
        self.reveal_at(challenger, commit, salt, alt)
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn attest(&mut self, r: usize, commitment: [u8; 32]) -> TransactionResult {
        let challenge_pda = self.challenge_pda(&commitment);
        let challenge = self.svm.get_account(&challenge_pda).map(|_| challenge_pda);
        let regrader = self.regraders[r].insecure_clone();
        let ix = instruction(
            accts::Attest {
                regrader: regrader.pubkey(),
                escrow: self.escrow(),
                attestation: attestation_pda(&self.escrow(), &regrader.pubkey()),
                challenge,
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Attest { commitment },
        );
        send(&mut self.svm, &self.admin, ix, &[&regrader])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn settle(&mut self) -> TransactionResult {
        let recorded = self.state().challenger;
        let ix = instruction(
            accts::Settle {
                escrow: self.escrow(),
                mint: self.mint,
                vault: self.vault(),
                resolver: self.state().resolver,
                challenger: (recorded != Pubkey::default()).then_some(recorded),
                token_program: token::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Settle {},
        );
        send(&mut self.svm, &self.admin, ix, &[])
    }

    /// The arbiter applies the challenge of `alt` (its challenger `challenger`).
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn arbiter_resolve_alt(
        &mut self,
        alt: ([u8; 32], [u8; 32]),
        challenger: Pubkey,
    ) -> TransactionResult {
        let commitment = result_commitment(&alt.0, &alt.1, TOTAL);
        let ix = instruction(
            accts::ArbiterResolve {
                arbiter: self.arbiter.pubkey(),
                escrow: self.escrow(),
                mint: self.mint,
                vault: self.vault(),
                resolver: self.state().resolver,
                challenge: Some(self.challenge_pda(&commitment)),
                challenger: Some(challenger),
                token_program: token::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ArbiterResolve {
                choice: ArbiterChoice::Alternative,
                commitment,
            },
        );
        send(&mut self.svm, &self.admin, ix, &[&self.arbiter])
    }

    fn claim_ix(&self, w: usize, amount: u64, compliance: &Keypair) -> Instruction {
        let claimant = self.winner(w);
        instruction(
            accts::Claim {
                claimant,
                payer: self.admin.pubkey(),
                compliance: Some(compliance.pubkey()),
                escrow: self.escrow(),
                mint: self.mint,
                vault: self.vault(),
                claimant_token_account: get_associated_token_address(&claimant, &self.mint),
                receipt: receipt_pda(&self.escrow(), &claimant),
                token_program: token::ID,
                associated_token_program: associated_token::ID,
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Claim {
                total_amount: PRIZES[w],
                amount,
                proof: vec![self.leaf(1 - w)],
            },
        )
    }

    /// Winner `w` claims `amount` (0 = all that is left), the compliance key co-signing.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn claim(&mut self, w: usize, amount: u64) -> TransactionResult {
        let compliance = self.compliance.insecure_clone();
        self.claim_cosigned(w, amount, &compliance)
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn claim_cosigned(&mut self, w: usize, amount: u64, compliance: &Keypair) -> TransactionResult {
        let ix = self.claim_ix(w, amount, compliance);
        let winner = self.winners[w].insecure_clone();
        send(&mut self.svm, &self.admin, ix, &[&winner, compliance])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn hold(&mut self, compliance: &Keypair, claimant: Pubkey) -> TransactionResult {
        let ix = instruction(
            accts::Hold {
                compliance: compliance.pubkey(),
                escrow: self.escrow(),
                receipt: receipt_pda(&self.escrow(), &claimant),
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Hold {
                claimant,
                reason: HOLD_REVIEW,
            },
        );
        send(&mut self.svm, &self.admin, ix, &[compliance])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn refund(&mut self) -> TransactionResult {
        let refund_to = self.sponsor.pubkey();
        let ix = instruction(
            accts::Refund {
                payer: self.admin.pubkey(),
                escrow: self.escrow(),
                mint: self.mint,
                vault: self.vault(),
                refund_to,
                refund_to_token_account: get_associated_token_address(&refund_to, &self.mint),
                resolver: self.state().resolver,
                token_program: token::ID,
                associated_token_program: associated_token::ID,
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Refund {},
        );
        send(&mut self.svm, &self.admin, ix, &[])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn close_commit(&mut self, challenger: Pubkey, hash: [u8; 32]) -> TransactionResult {
        let ix = instruction(
            accts::CloseCommit {
                escrow: self.escrow(),
                commit: self.commit_pda(&challenger, &hash),
                challenger,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::CloseCommit {},
        );
        send(&mut self.svm, &self.admin, ix, &[])
    }

    // ------------------------------------------------------------------- the breakers

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn set_stop(&mut self, by: &Keypair, level: StopState) -> TransactionResult {
        let ix = instruction(
            accts::SetStop {
                authority: by.pubkey(),
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::SetStop { level },
        );
        send(&mut self.svm, &self.admin, ix, &[by])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn extend_stop(&mut self, by: &Keypair, extra: i64) -> TransactionResult {
        let ix = instruction(
            accts::ExtendStop {
                admin: by.pubkey(),
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ExtendStop { extra },
        );
        send(&mut self.svm, &self.admin, ix, &[by])
    }

    fn guard_escrow(&self, by: &Keypair) -> accts::GuardEscrow {
        accts::GuardEscrow {
            authority: by.pubkey(),
            config: config_pda(),
            escrow: self.escrow(),
            event_authority: EVENT_AUTHORITY,
            program: prize_escrow::ID,
        }
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn set_freeze(&mut self, by: &Keypair, frozen: bool) -> TransactionResult {
        let ix = instruction(self.guard_escrow(by), ixs::SetFreeze { frozen });
        send(&mut self.svm, &self.admin, ix, &[by])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn extend_freeze(&mut self, by: &Keypair, extra: i64) -> TransactionResult {
        let ix = instruction(self.guard_escrow(by), ixs::ExtendFreeze { extra });
        send(&mut self.svm, &self.admin, ix, &[by])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn escalate(&mut self, by: &Keypair) -> TransactionResult {
        let ix = instruction(self.guard_escrow(by), ixs::Escalate {});
        send(&mut self.svm, &self.admin, ix, &[by])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn set_revoked(&mut self, by: &Keypair, key: Pubkey, revoked: bool) -> TransactionResult {
        let ix = instruction(
            accts::SetStop {
                authority: by.pubkey(),
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::SetRevoked { key, revoked },
        );
        send(&mut self.svm, &self.admin, ix, &[by])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn rotate_role(&mut self, role: EscrowRole, old: Pubkey, new: Pubkey) -> TransactionResult {
        let ix = instruction(
            accts::RotateRole {
                admin: self.admin.pubkey(),
                config: config_pda(),
                escrow: self.escrow(),
                old_attestation: (role == EscrowRole::Regrader)
                    .then(|| attestation_pda(&self.escrow(), &old)),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::RotateRole { role, old, new },
        );
        send(&mut self.svm, &self.admin, ix, &[])
    }

    fn admin_config(&self) -> accts::AdminConfig {
        accts::AdminConfig {
            admin: self.admin.pubkey(),
            config: config_pda(),
            event_authority: EVENT_AUTHORITY,
            program: prize_escrow::ID,
        }
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn set_limits(&mut self, limits: Limits) -> TransactionResult {
        let ix = instruction(self.admin_config(), ixs::SetLimits { limits });
        send(&mut self.svm, &self.admin, ix, &[])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn set_floors(&mut self, floors: Floors) -> TransactionResult {
        let ix = instruction(self.admin_config(), ixs::SetFloors { floors });
        send(&mut self.svm, &self.admin, ix, &[])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn set_allowed(
        &mut self,
        list: AllowList,
        key: Pubkey,
        allowed: bool,
        house: bool,
    ) -> TransactionResult {
        let ix = instruction(
            self.admin_config(),
            ixs::SetAllowed {
                list,
                key,
                allowed,
                house,
            },
        );
        send(&mut self.svm, &self.admin, ix, &[])
    }
}

// ------------------------------------------------------------------------------- the Config

#[test]
fn only_the_upgrade_authority_creates_the_config_and_only_once() {
    let mut s = S::bare();
    let init = s.init();

    // LiteSVM deploys with no upgrade authority, as an immutable program would have: nobody.
    let ix = initialize_config_ix(s.admin.pubkey(), init.clone());
    assert_refused(
        send(&mut s.svm, &s.admin, ix, &[]),
        EscrowError::NotUpgradeAuthority,
        "an immutable program's config",
    );
    set_upgrade_authority(&mut s.svm, Some(s.admin.pubkey()));
    let ix = initialize_config_ix(s.stranger.pubkey(), init.clone());
    assert_refused(
        send(&mut s.svm, &s.admin, ix, &[&s.stranger]),
        EscrowError::NotUpgradeAuthority,
        "a config signed by anyone but the upgrade authority",
    );
    // The builder names this program's ProgramData, ["<program id>"] under the upgradeable loader.
    assert_eq!(
        initialize_config_ix(s.admin.pubkey(), init.clone()).accounts[2].pubkey,
        program_data_pda()
    );

    // Out-of-bounds values are refused.
    let mut bad = init.clone();
    bad.guardian = Pubkey::default();
    let ix = initialize_config_ix(s.admin.pubkey(), bad);
    assert_refused(
        send(&mut s.svm, &s.admin, ix, &[]),
        EscrowError::InvalidConfig,
        "no guardian",
    );
    let mut bad = init.clone();
    bad.floors.reveal_grace = MIN_REVEAL_GRACE - 1;
    let ix = initialize_config_ix(s.admin.pubkey(), bad);
    assert_refused(
        send(&mut s.svm, &s.admin, ix, &[]),
        EscrowError::InvalidConfig,
        "a reveal grace under the minimum",
    );
    let mut bad = init.clone();
    bad.limits.flow_period = 0;
    let ix = initialize_config_ix(s.admin.pubkey(), bad);
    assert_refused(
        send(&mut s.svm, &s.admin, ix, &[]),
        EscrowError::InvalidConfig,
        "a flow bucket that never refills",
    );

    let ix = initialize_config_ix(s.admin.pubkey(), init.clone());
    let meta = ok(send(&mut s.svm, &s.admin, ix, &[]), "initialize_config");
    let changed = event::<ConfigChanged>(&meta);
    assert_eq!(changed.change, ConfigChange::Initialized);
    assert_eq!(
        (changed.by, changed.admin, changed.guardian, changed.arbiter),
        (
            s.admin.pubkey(),
            s.admin.pubkey(),
            s.guardian.pubkey(),
            s.arbiter.pubkey()
        )
    );
    let config = s.config();
    assert_eq!(config.stop, StopState::Normal);
    assert_eq!(
        (config.mints.clone(), config.sponsors.clone()),
        (vec![s.mint], vec![s.sponsor.pubkey()])
    );
    assert_eq!(config.regraders, init.regraders);
    assert_eq!(
        config.flow_level, config.flow_capacity,
        "the bucket starts full"
    );
    assert_eq!(
        (config.open_value, config.stopped_secs, config.revoked.len()),
        (0, 0, 0)
    );
    assert_eq!(config.reserved, [0; 63]);
    // The panel floor starts at the default (#541: a one-regrader panel is allowed).
    assert_eq!(
        (config.min_regraders, changed.min_regraders),
        (prize_escrow::DEFAULT_MIN_REGRADERS, 1)
    );
    assert_eq!(
        s.svm.get_account(&config_pda()).unwrap().data.len(),
        Config::SPACE
    );

    // Once: the PDA is in use.
    let ix = initialize_config_ix(s.admin.pubkey(), init);
    assert_refused(send(&mut s.svm, &s.admin, ix, &[]), 0u32, "a second config");
}

#[test]
fn the_admin_moves_in_two_steps_and_only_the_admin_sets_the_config() {
    let mut s = S::new();
    let next = Keypair::new();
    // Only the admin proposes; only the proposed key accepts.
    let ix = instruction(
        accts::AdminConfig {
            admin: s.guardian.pubkey(),
            config: config_pda(),
            event_authority: EVENT_AUTHORITY,
            program: prize_escrow::ID,
        },
        ixs::ProposeAdmin {
            new_admin: next.pubkey(),
        },
    );
    assert_refused(
        send(&mut s.svm, &s.admin, ix, &[&s.guardian]),
        EscrowError::UnauthorizedAdmin,
        "the guardian proposes an admin",
    );
    let ix = instruction(
        s.admin_config(),
        ixs::ProposeAdmin {
            new_admin: next.pubkey(),
        },
    );
    ok(send(&mut s.svm, &s.admin, ix, &[]), "propose_admin");
    let accept = |by: &Keypair| {
        instruction(
            accts::AcceptAdmin {
                new_admin: by.pubkey(),
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::AcceptAdmin {},
        )
    };
    assert_refused(
        send(&mut s.svm, &s.admin, accept(&s.stranger), &[&s.stranger]),
        EscrowError::NotPendingAdmin,
        "a stranger accepts",
    );
    let meta = ok(
        send(&mut s.svm, &s.admin, accept(&next), &[&next]),
        "accept_admin",
    );
    assert_eq!(
        event::<ConfigChanged>(&meta).change,
        ConfigChange::AdminAccepted
    );
    assert_eq!(
        (s.config().admin, s.config().pending_admin),
        (next.pubkey(), Pubkey::default())
    );
    // The old admin is no admin any more.
    assert_refused(
        s.set_limits(open_limits()),
        EscrowError::UnauthorizedAdmin,
        "set_limits by the old admin",
    );

    // The new admin replaces the arbiter (every escrow answers to Config's) and edits the lists.
    let new_arbiter = Pubkey::new_unique();
    let ix = instruction(
        accts::AdminConfig {
            admin: next.pubkey(),
            config: config_pda(),
            event_authority: EVENT_AUTHORITY,
            program: prize_escrow::ID,
        },
        ixs::SetConfigRole {
            role: prize_escrow::ConfigRole::Arbiter,
            key: new_arbiter,
        },
    );
    let meta = ok(send(&mut s.svm, &s.admin, ix, &[&next]), "set_config_role");
    assert_eq!(
        (event::<ConfigChanged>(&meta).change, s.config().arbiter),
        (ConfigChange::ArbiterSet, new_arbiter)
    );
    let ix = instruction(
        accts::AdminConfig {
            admin: next.pubkey(),
            config: config_pda(),
            event_authority: EVENT_AUTHORITY,
            program: prize_escrow::ID,
        },
        ixs::SetAllowed {
            list: AllowList::Mint,
            key: s.mint,
            allowed: true,
            house: false,
        },
    );
    assert_refused(
        send(&mut s.svm, &s.admin, ix, &[&next]),
        EscrowError::AlreadyListed,
        "a mint listed twice",
    );
}

#[test]
fn a_revoked_key_never_becomes_the_admin() {
    // #535's verify: accept_admin read no revocation, so a key the guardian had revoked could
    // take the Config, and the admin's key, which set_revoked never revokes, became a revoked one.
    let mut s = S::new();
    let (guardian, admin) = (s.guardian.insecure_clone(), s.admin.insecure_clone());
    let next = Keypair::new();
    let ix = instruction(
        s.admin_config(),
        ixs::ProposeAdmin {
            new_admin: next.pubkey(),
        },
    );
    ok(send(&mut s.svm, &s.admin, ix, &[]), "propose_admin");
    ok(
        s.set_revoked(&guardian, next.pubkey(), true),
        "the guardian revokes the proposed key",
    );
    let accept = instruction(
        accts::AcceptAdmin {
            new_admin: next.pubkey(),
            config: config_pda(),
            event_authority: EVENT_AUTHORITY,
            program: prize_escrow::ID,
        },
        ixs::AcceptAdmin {},
    );
    assert_refused(
        send(&mut s.svm, &s.admin, accept.clone(), &[&next]),
        EscrowError::KeyRevoked,
        "a revoked key accepts the admin",
    );
    let config = s.config();
    assert_eq!(
        (config.admin, config.pending_admin),
        (admin.pubkey(), next.pubkey()),
        "the admin stays, the proposal stays pending"
    );

    // Unrevoked by the admin, the key takes the Config.
    ok(
        s.set_revoked(&admin, next.pubkey(), false),
        "the admin unrevokes it",
    );
    let meta = ok(send(&mut s.svm, &s.admin, accept, &[&next]), "accept_admin");
    assert_eq!(
        event::<ConfigChanged>(&meta).change,
        ConfigChange::AdminAccepted
    );
    let config = s.config();
    assert_eq!(
        (config.admin, config.pending_admin),
        (next.pubkey(), Pubkey::default())
    );
    assert!(
        !config.is_revoked(&next.pubkey()),
        "the admin is never revoked"
    );
}

// --------------------------------------------------------------------------- the open policy

#[test]
fn open_escrow_holds_the_terms_to_the_config_policy() {
    let mut s = S::new();
    let good = s.terms.clone();
    let check = |s: &mut S, terms: EscrowTerms, want: EscrowError, what: &str| {
        let r = s.open(&terms);
        assert_refused(r, want, what);
        assert!(
            s.svm.get_account(&s.escrow()).is_none(),
            "{what}: no escrow"
        );
    };

    let mut t = good.clone();
    t.refund_to = Pubkey::new_unique();
    check(
        &mut s,
        t,
        EscrowError::RefundToNotSponsor,
        "refunds to anyone but the sponsor",
    );
    let mut t = good.clone();
    t.arbiter = Pubkey::new_unique();
    check(
        &mut s,
        t,
        EscrowError::ArbiterNotConfig,
        "an arbiter other than the config's",
    );
    let mut t = good.clone();
    t.compliance = Pubkey::default();
    check(
        &mut s,
        t,
        EscrowError::ComplianceRequired,
        "no compliance key",
    );
    let mut t = good.clone();
    t.regraders[2] = Pubkey::new_unique();
    check(
        &mut s,
        t,
        EscrowError::RegraderNotRegistered,
        "a regrader not in the registry",
    );

    // Independence: the resolver (registered as a regrader for the test) cannot sit on the panel.
    ok(
        s.set_allowed(AllowList::Regrader, s.resolver.pubkey(), true, false),
        "register the resolver",
    );
    let mut t = good.clone();
    t.regraders[2] = s.resolver.pubkey();
    check(
        &mut s,
        t,
        EscrowError::RegraderNotIndependent,
        "the resolver among the regraders",
    );
    ok(
        s.set_allowed(AllowList::Regrader, s.compliance.pubkey(), true, false),
        "register the compliance key",
    );
    let mut t = good.clone();
    t.regraders[0] = s.compliance.pubkey();
    check(
        &mut s,
        t,
        EscrowError::RegraderNotIndependent,
        "the compliance key among the regraders",
    );

    // The minimum bond and the window floors are the config's, above the compiled minimums.
    let mut limits = open_limits();
    limits.min_bond = BOND + 1;
    ok(s.set_limits(limits), "min_bond");
    check(
        &mut s,
        good.clone(),
        EscrowError::BondBelowMin,
        "a bond under the config's minimum",
    );
    ok(s.set_limits(open_limits()), "min_bond back");
    let mut floors = open_floors();
    floors.min_claim_window = CLAIM_WINDOW + 1;
    ok(s.set_floors(floors), "a claim-window floor");
    check(
        &mut s,
        good.clone(),
        EscrowError::WindowBelowFloor,
        "a claim window under the floor",
    );
    ok(s.set_floors(open_floors()), "floors back");

    // The house allowance: tightened below the panel's house count, it refuses.
    let mut limits = open_limits();
    limits.max_house_regraders = 1;
    ok(s.set_limits(limits), "max_house_regraders = 1");
    check(
        &mut s,
        good.clone(),
        EscrowError::TooManyHouseRegraders,
        "an all-house panel over the allowance",
    );
    ok(
        s.set_limits(open_limits()),
        "max_house_regraders = MAX_REGRADERS",
    );

    // The mint and the sponsor allowlists.
    ok(
        s.set_allowed(AllowList::Mint, s.mint, false, false),
        "disallow the mint",
    );
    check(
        &mut s,
        good.clone(),
        EscrowError::MintNotAllowed,
        "a mint off the allowlist",
    );
    ok(
        s.set_allowed(AllowList::Mint, s.mint, true, false),
        "allow the mint",
    );
    ok(
        s.set_allowed(AllowList::Sponsor, s.sponsor.pubkey(), false, false),
        "disallow the sponsor",
    );
    check(
        &mut s,
        good.clone(),
        EscrowError::SponsorNotAllowed,
        "a sponsor off the allowlist",
    );
    ok(
        s.set_allowed(AllowList::Sponsor, s.sponsor.pubkey(), true, false),
        "allow the sponsor",
    );

    // A revoked key, and intake stopped.
    let guardian = s.guardian.insecure_clone();
    ok(
        s.set_revoked(&guardian, s.regraders[1].pubkey(), true),
        "revoke a regrader",
    );
    check(
        &mut s,
        good.clone(),
        EscrowError::KeyRevoked,
        "a revoked regrader named",
    );
    let admin = s.admin.insecure_clone();
    ok(
        s.set_revoked(&admin, s.regraders[1].pubkey(), false),
        "unrevoke it",
    );
    ok(s.set_stop(&guardian, StopState::IntakeStop), "IntakeStop");
    check(
        &mut s,
        good.clone(),
        EscrowError::IntakeStopped,
        "an open while intake is stopped",
    );
    ok(s.set_stop(&admin, StopState::Normal), "unstop");

    // An all-house panel at the permissive setting opens (owner decision #541).
    let meta = ok(s.open(&good), "open_escrow with an all-house panel");
    let _ = meta;
    let state = s.state();
    assert_eq!(state.status, EscrowStatus::Open);
    assert_eq!(
        (state.deposited, state.stop_base, state.reveal_grace),
        (TOTAL, 0, MIN_REVEAL_GRACE)
    );
    assert_eq!(s.config().house_count(&good.regraders), 3);
    assert_eq!(s.config().open_value, TOTAL);
}

// ---------------------------------------------------------------------- caps and the bucket

#[test]
fn caps_bound_open_and_fund_and_the_flow_bucket_bounds_claims() {
    let mut s = S::new();
    let limits = Limits {
        escrow_cap: TOTAL + 10,
        global_cap: 2 * TOTAL,
        flow_capacity: TOTAL / 2,
        flow_period: DAY,
        min_bond: 0,
        max_house_regraders: 3,
    };
    ok(s.set_limits(limits.clone()), "set_limits");

    let mut over = s.terms.clone();
    over.total = TOTAL + 11;
    assert_refused(
        s.open(&over),
        EscrowError::EscrowCapExceeded,
        "an open over C_e",
    );
    ok(s.open(&s.terms.clone()), "open_escrow");
    assert_refused(
        s.fund(11),
        EscrowError::EscrowCapExceeded,
        "a fund past C_e",
    );
    ok(s.fund(10), "fund up to C_e");
    assert_eq!(
        (s.state().deposited, s.config().open_value),
        (TOTAL + 10, TOTAL + 10)
    );

    // A second escrow would take open_value past C_g.
    s.cid = [0x35; 16];
    assert_refused(
        s.open(&s.terms.clone()),
        EscrowError::GlobalCapExceeded,
        "an open past C_g",
    );
    let mut fits = s.terms.clone();
    fits.total = TOTAL - 10;
    ok(s.open(&fits), "an open up to C_g");
    assert_eq!(s.config().open_value, 2 * TOTAL);
    s.cid = CID;

    // The first escrow runs its course; claims meet the bucket (TOTAL / 2, refilled per day).
    ok(s.commit_entries(), "commit_entries");
    s.at(POST_AT);
    let resolver = s.resolver.insecure_clone();
    ok(s.post(&resolver), "post_result");
    s.at(CHALLENGE_DEADLINE);
    ok(s.settle(), "settle");
    // The bucket has been full since set_limits; a whole 3/5 leaf is over it.
    assert_refused(
        s.claim(0, 0),
        EscrowError::FlowLimitExceeded,
        "a claim over the bucket",
    );
    ok(s.claim(0, TOTAL / 2), "a claim of the whole bucket");
    assert_eq!(s.config().flow_level, 0);
    assert_refused(
        s.claim(1, 0),
        EscrowError::FlowLimitExceeded,
        "a claim of an empty bucket",
    );
    // Half a day refills a quarter: still short of the second leaf (2/5).
    s.at(CHALLENGE_DEADLINE + DAY / 2);
    assert_refused(
        s.claim(1, 0),
        EscrowError::FlowLimitExceeded,
        "a claim of a quarter-full bucket",
    );
    s.at(CHALLENGE_DEADLINE + DAY);
    ok(s.claim(1, 0), "the second leaf once the bucket refilled");
    ok(s.claim(0, 0), "the rest of the first leaf");
    let winner0 = get_associated_token_address(&s.winner(0), &s.mint);
    assert_eq!(s.tokens(&winner0), PRIZES[0]);

    // Refund is exempt from the bucket (its destination is pinned) and gives the deposit back to C_g.
    s.at(CLAIM_DEADLINE + 1);
    ok(s.refund(), "refund");
    assert_eq!(
        s.config().open_value,
        TOTAL - 10,
        "only the second escrow is open"
    );
}

// ------------------------------------------------------------------------- the stop clock

#[test]
fn a_three_day_payout_stop_does_not_let_the_claim_deadline_lapse_into_a_refund() {
    let mut s = S::claimable();
    let (guardian, admin) = (s.guardian.insecure_clone(), s.admin.insecure_clone());
    let stop_at = CLAIM_DEADLINE - DAY;
    s.at(stop_at);
    let meta = ok(
        s.set_stop(&guardian, StopState::PayoutStop),
        "the guardian's PayoutStop",
    );
    let stopped = event::<StopChanged>(&meta);
    assert_eq!(
        (stopped.by, stopped.from, stopped.stop),
        (guardian.pubkey(), StopState::Normal, StopState::PayoutStop)
    );
    assert_eq!(
        (stopped.stop_since, stopped.stop_expires_at),
        (stop_at, stop_at + STOP_DURATION)
    );
    assert_refused(
        s.claim(0, 0),
        EscrowError::PayoutStopped,
        "a claim during the stop",
    );
    // The guardian only escalates: it can neither lower nor lift the stop, nor renew it.
    for level in [
        StopState::Normal,
        StopState::IntakeStop,
        StopState::PayoutStop,
    ] {
        assert_refused(
            s.set_stop(&guardian, level),
            EscrowError::NotAnEscalation,
            "the guardian lowers the stop",
        );
    }
    assert_refused(
        s.extend_stop(&guardian, DAY),
        EscrowError::UnauthorizedAdmin,
        "the guardian extends the stop",
    );

    // Three days on, past the claim deadline in wall time: still stopped, nothing refunds.
    s.at(stop_at + 3 * DAY);
    assert_refused(
        s.refund(),
        EscrowError::PayoutStopped,
        "a refund during the stop",
    );
    let meta = ok(s.set_stop(&admin, StopState::Normal), "the admin's unstop");
    assert_eq!(event::<StopChanged>(&meta).stopped_secs, 3 * DAY);
    // The escrow clock stood still for those three days: a day of the claim window is left.
    assert_refused(
        s.refund(),
        EscrowError::ClaimWindowNotElapsed,
        "a refund inside the claim window",
    );
    ok(s.claim(0, 0), "a claim after the stop");
    s.at(CLAIM_DEADLINE + 3 * DAY);
    ok(s.claim(1, 0), "a claim on the shifted claim deadline");
    s.at(CLAIM_DEADLINE + 3 * DAY + 1);
    ok(s.refund(), "a refund after the shifted claim deadline");
}

#[test]
fn a_stop_lapses_after_seven_days_unless_the_admin_extends_it() {
    let mut s = S::claimable();
    let (guardian, admin) = (s.guardian.insecure_clone(), s.admin.insecure_clone());
    let at = CHALLENGE_DEADLINE + DAY;
    s.at(at);
    ok(s.set_stop(&guardian, StopState::PayoutStop), "PayoutStop");
    s.at(at + STOP_DURATION - 1);
    assert_refused(
        s.claim(0, 0),
        EscrowError::PayoutStopped,
        "a claim on the stop's last second",
    );
    s.at(at + STOP_DURATION);
    ok(s.claim(0, 0), "a claim once the stop lapsed by itself");
    assert_refused(
        s.extend_stop(&admin, DAY),
        EscrowError::NotStopped,
        "extending a lapsed stop",
    );
    assert_eq!(
        s.config().global_stopped(at + STOP_DURATION + 5),
        STOP_DURATION,
        "seven days stopped, no more"
    );

    // A new stop, extended by the admin, outlasts seven days.
    let again = at + STOP_DURATION;
    ok(s.set_stop(&guardian, StopState::IntakeStop), "IntakeStop");
    ok(
        s.set_stop(&guardian, StopState::PayoutStop),
        "escalated to PayoutStop",
    );
    ok(s.extend_stop(&admin, DAY), "the admin extends it a day");
    s.at(again + STOP_DURATION);
    assert_refused(
        s.claim(1, 0),
        EscrowError::PayoutStopped,
        "a claim past seven days of an extended stop",
    );
    s.at(again + STOP_DURATION + DAY);
    ok(s.claim(1, 0), "a claim once the extended stop lapsed");
    assert_eq!(
        s.config().global_stopped(again + STOP_DURATION + DAY),
        2 * STOP_DURATION + DAY
    );
}

#[test]
fn the_guardians_escalation_never_shortens_the_admins_stop() {
    // #535's verify: escalating to PayoutStop set the lapse to now + 7 days whatever the stop in
    // force said, so the guardian could end an IntakeStop the admin had extended before the
    // admin's lapse. An escalation keeps the later lapse.
    let mut s = S::claimable();
    let (guardian, admin) = (s.guardian.insecure_clone(), s.admin.insecure_clone());
    let t = CHALLENGE_DEADLINE + DAY;
    s.at(t);
    ok(s.set_stop(&guardian, StopState::IntakeStop), "IntakeStop");
    ok(
        s.extend_stop(&admin, 20 * DAY),
        "the admin extends it 20 days",
    );
    let lapse = t + STOP_DURATION + 20 * DAY;
    assert_eq!(s.config().stop_expires_at, lapse);

    s.at(t + DAY);
    let meta = ok(
        s.set_stop(&guardian, StopState::PayoutStop),
        "the guardian escalates to PayoutStop",
    );
    let changed = event::<StopChanged>(&meta);
    assert_eq!(
        (
            changed.from,
            changed.stop,
            changed.stop_since,
            changed.stop_expires_at
        ),
        (StopState::IntakeStop, StopState::PayoutStop, t + DAY, lapse),
        "the admin's lapse, not seven days from the escalation"
    );
    // Where the escalation used to lapse, and on the admin's lapse's last second: still stopped.
    for at in [t + DAY + STOP_DURATION, lapse - 1] {
        s.at(at);
        assert_eq!(s.config().stop_level(at), StopState::PayoutStop);
        assert_refused(
            s.claim(0, 0),
            EscrowError::PayoutStopped,
            "a claim before the admin's lapse",
        );
    }
    s.at(lapse);
    assert_eq!(s.config().stop_level(lapse), StopState::Normal);
    ok(s.claim(0, 0), "a claim once the admin's lapse passed");
    assert_eq!(
        s.config().global_stopped(lapse + 5),
        lapse - (t + DAY),
        "the PayoutStop held the clocks from the escalation to the lapse"
    );

    // A stop in force that lapses sooner than seven days from the escalation: seven days from it.
    let u = lapse + DAY;
    s.at(u);
    ok(s.set_stop(&guardian, StopState::IntakeStop), "IntakeStop");
    s.at(u + 6 * DAY);
    let meta = ok(
        s.set_stop(&guardian, StopState::PayoutStop),
        "PayoutStop a day before the IntakeStop lapses",
    );
    assert_eq!(
        event::<StopChanged>(&meta).stop_expires_at,
        u + 6 * DAY + STOP_DURATION
    );
    // The admin still sets any level and lapse: lowering it runs seven days from now.
    s.at(u + 7 * DAY);
    let meta = ok(
        s.set_stop(&admin, StopState::IntakeStop),
        "the admin lowers it to IntakeStop",
    );
    assert_eq!(
        event::<StopChanged>(&meta).stop_expires_at,
        u + 7 * DAY + STOP_DURATION
    );
}

// ------------------------------------------------------------------------ revoke and rotate

#[test]
fn a_revoked_key_is_refused_everywhere_until_the_admin_rotates_it_out() {
    let mut s = S::committed();
    let (guardian, admin) = (s.guardian.insecure_clone(), s.admin.insecure_clone());
    s.at(POST_AT);
    let meta = ok(
        s.set_revoked(&guardian, s.resolver.pubkey(), true),
        "revoke the resolver",
    );
    let revoked = event::<RevocationChanged>(&meta);
    assert_eq!(
        (revoked.key, revoked.revoked, revoked.revoked_count),
        (s.resolver.pubkey(), true, 1)
    );
    let resolver = s.resolver.insecure_clone();
    assert_refused(
        s.post(&resolver),
        EscrowError::KeyRevoked,
        "a revoked resolver's post",
    );
    assert_refused(
        s.set_revoked(&guardian, s.resolver.pubkey(), false),
        EscrowError::UnauthorizedAdmin,
        "the guardian unrevokes",
    );
    assert_refused(
        s.set_revoked(&guardian, admin.pubkey(), true),
        EscrowError::CannotRevokeAdmin,
        "revoking the admin",
    );
    assert_refused(
        s.set_revoked(&guardian, s.resolver.pubkey(), true),
        EscrowError::AlreadyRevoked,
        "revoking twice",
    );

    // The admin rotates the resolver: the new key posts.
    let new_resolver = Keypair::new();
    s.svm.airdrop(&new_resolver.pubkey(), 10 * SOL).unwrap();
    assert_refused(
        s.rotate_role(
            EscrowRole::Resolver,
            Pubkey::new_unique(),
            new_resolver.pubkey(),
        ),
        EscrowError::RoleMismatch,
        "rotating a key that holds no role",
    );
    assert_refused(
        s.rotate_role(
            EscrowRole::Resolver,
            resolver.pubkey(),
            s.regraders[0].pubkey(),
        ),
        EscrowError::RegraderNotIndependent,
        "a regrader as the resolver",
    );
    let meta = ok(
        s.rotate_role(
            EscrowRole::Resolver,
            resolver.pubkey(),
            new_resolver.pubkey(),
        ),
        "rotate the resolver",
    );
    let rotated = event::<RoleRotated>(&meta);
    assert_eq!(
        (rotated.role, rotated.old, rotated.new),
        (
            EscrowRole::Resolver,
            resolver.pubkey(),
            new_resolver.pubkey()
        )
    );
    ok(s.post(&new_resolver), "the new resolver posts");
    assert_eq!(s.state().resolver_bond, BOND);

    // At claims: a revoked compliance key co-signs nothing and holds nothing.
    s.at(CHALLENGE_DEADLINE);
    ok(s.settle(), "settle");
    ok(
        s.set_revoked(&guardian, s.compliance.pubkey(), true),
        "revoke the compliance key",
    );
    assert_refused(
        s.claim(0, 0),
        EscrowError::KeyRevoked,
        "a revoked compliance key's co-signature",
    );
    let compliance = s.compliance.insecure_clone();
    assert_refused(
        s.hold(&compliance, s.winner(1)),
        EscrowError::KeyRevoked,
        "a revoked compliance key's hold",
    );
    let new_compliance = Keypair::new();
    s.svm.airdrop(&new_compliance.pubkey(), SOL).unwrap();
    ok(
        s.rotate_role(
            EscrowRole::Compliance,
            compliance.pubkey(),
            new_compliance.pubkey(),
        ),
        "rotate the compliance key",
    );
    ok(
        s.claim_cosigned(0, 0, &new_compliance),
        "the new compliance key co-signs",
    );
    // A revoked claimant is refused too, until the admin unrevokes it.
    ok(
        s.set_revoked(&guardian, s.winner(1), true),
        "revoke a winner",
    );
    assert_refused(
        s.claim_cosigned(1, 0, &new_compliance),
        EscrowError::KeyRevoked,
        "a revoked claimant",
    );
    ok(s.set_revoked(&admin, s.winner(1), false), "unrevoke it");
    ok(s.claim_cosigned(1, 0, &new_compliance), "the winner claims");

    // A revoked guardian loses its verbs.
    ok(
        s.set_revoked(&admin, guardian.pubkey(), true),
        "revoke the guardian",
    );
    assert_refused(
        s.set_stop(&guardian, StopState::PayoutStop),
        EscrowError::KeyRevoked,
        "a revoked guardian's stop",
    );
    assert_refused(
        s.set_stop(&s.stranger.insecure_clone(), StopState::PayoutStop),
        EscrowError::UnauthorizedGuardian,
        "a stranger's stop",
    );
}

#[test]
fn lamports_sent_to_an_unvoted_seats_attestation_never_block_its_rotation() {
    // #535's verify: rotate_role read a seat as voted when its Attestation PDA held any lamports,
    // so anyone could pin a seat by sending lamports there. A seat has voted only when attest
    // created its Attestation: an account at the PDA this program owns.
    let mut s = S::posted();
    s.at(CHALLENGE_AT);
    let challenger = s.challenger.insecure_clone();
    ok(s.challenge(&challenger, (ALT, ALT_ROOT)), "challenge");
    let (seat0, seat1) = (s.regraders[0].pubkey(), s.regraders[1].pubkey());
    let unvoted = attestation_pda(&s.escrow(), &seat0);
    s.svm.airdrop(&unvoted, 2 * SOL / 1_000).unwrap();
    let account = s.svm.get_account(&unvoted).expect("the funded PDA");
    assert_eq!((account.owner, account.data.len()), (system_program::ID, 0));

    let fresh = Keypair::new();
    s.svm.airdrop(&fresh.pubkey(), SOL).unwrap();
    ok(
        s.set_allowed(AllowList::Regrader, fresh.pubkey(), true, false),
        "register a fresh regrader",
    );
    let meta = ok(
        s.rotate_role(EscrowRole::Regrader, seat0, fresh.pubkey()),
        "rotate an unvoted seat whose PDA holds lamports",
    );
    assert_eq!(
        (event::<RoleRotated>(&meta).old, s.state().regraders[0]),
        (seat0, fresh.pubkey())
    );
    assert_refused(
        s.attest(0, s.posted_commitment()),
        EscrowError::NotARegrader,
        "the rotated-out key votes",
    );
    let ix = instruction(
        accts::Attest {
            regrader: fresh.pubkey(),
            escrow: s.escrow(),
            attestation: attestation_pda(&s.escrow(), &fresh.pubkey()),
            challenge: None,
            system_program: system_program::ID,
            config: config_pda(),
            event_authority: EVENT_AUTHORITY,
            program: prize_escrow::ID,
        },
        ixs::Attest {
            commitment: s.posted_commitment(),
        },
    );
    ok(
        send(&mut s.svm, &s.admin, ix, &[&fresh]),
        "the new key votes from the seat",
    );
    assert_eq!(s.state().votes_result, 1);

    // Lamports at a seat's PDA do not keep it from voting either; once it voted, its seat stays.
    let voted = attestation_pda(&s.escrow(), &seat1);
    s.svm.airdrop(&voted, 2 * SOL / 1_000).unwrap();
    ok(
        s.attest(1, s.posted_commitment()),
        "a vote into a PDA that held lamports",
    );
    assert_eq!(
        s.svm.get_account(&voted).expect("the Attestation").owner,
        prize_escrow::ID
    );
    let other = Pubkey::new_unique();
    ok(
        s.set_allowed(AllowList::Regrader, other, true, false),
        "register another regrader",
    );
    assert_refused(
        s.rotate_role(EscrowRole::Regrader, seat1, other),
        EscrowError::RegraderAlreadyVoted,
        "rotating a seat that voted",
    );
}

// ------------------------------------------------------------------------ freeze and escalate

#[test]
fn a_guardian_freeze_inside_the_challenge_window_stops_a_house_majority_settle() {
    // The house holds every regrader key (owner decision #541): a compromised server posts a
    // false root and its two house regraders back it. The honest challenger's alternative has the
    // third regrader's vote. The guardian freezes the escrow inside the challenge window and
    // escalates it; the arbiter applies the honest alternative.
    let mut s = S::posted();
    let (guardian, admin) = (s.guardian.insecure_clone(), s.admin.insecure_clone());
    s.at(CHALLENGE_AT);
    let challenger = s.challenger.insecure_clone();
    ok(
        s.challenge(&challenger, (ALT, ALT_ROOT)),
        "the honest challenge",
    );
    let alt = result_commitment(&ALT, &ALT_ROOT, TOTAL);
    let posted = s.posted_commitment();
    ok(s.attest(0, posted), "house regrader 0 backs the false root");
    ok(s.attest(1, posted), "house regrader 1 backs it: a quorum");
    ok(s.attest(2, alt), "regrader 2 backs the honest root");
    // A seat that has voted cannot be rotated (it would vote twice).
    assert_refused(
        s.rotate_role(
            EscrowRole::Regrader,
            s.regraders[0].pubkey(),
            Pubkey::new_unique(),
        ),
        EscrowError::RegraderNotRegistered,
        "rotating to an unregistered key",
    );
    let fresh = Pubkey::new_unique();
    ok(
        s.set_allowed(AllowList::Regrader, fresh, true, false),
        "register a fresh regrader",
    );
    assert_refused(
        s.rotate_role(EscrowRole::Regrader, s.regraders[0].pubkey(), fresh),
        EscrowError::RegraderAlreadyVoted,
        "rotating a seat that voted",
    );

    s.at(CHALLENGE_AT + HOUR);
    assert_refused(
        s.escalate(&s.stranger.insecure_clone()),
        EscrowError::UnauthorizedGuardian,
        "a stranger escalates",
    );
    let meta = ok(s.set_freeze(&guardian, true), "the guardian's freeze");
    let frozen = event::<FreezeChanged>(&meta);
    assert!(frozen.frozen);
    assert_eq!(frozen.escrow_now, CHALLENGE_AT + HOUR);
    assert_refused(
        s.set_freeze(&guardian, true),
        EscrowError::AlreadyFrozen,
        "freezing twice",
    );
    assert_refused(
        s.set_freeze(&guardian, false),
        EscrowError::UnauthorizedAdmin,
        "the guardian unfreezes",
    );
    assert_refused(
        s.extend_freeze(&guardian, DAY),
        EscrowError::UnauthorizedAdmin,
        "the guardian extends its freeze",
    );

    // Wall time past the challenge deadline: the house majority's settle is refused.
    s.at(CHALLENGE_DEADLINE + DAY);
    assert_refused(
        s.settle(),
        EscrowError::EscrowFrozen,
        "the house majority's settle while frozen",
    );
    // The escalation hands it to the arbiter.
    let meta = ok(s.escalate(&guardian), "escalate");
    assert_eq!(
        event::<Escalated>(&meta).from_status,
        EscrowStatus::Disputed
    );
    assert_eq!(s.state().status, EscrowStatus::Frozen);
    assert_refused(
        s.escalate(&guardian),
        EscrowError::InvalidStatus,
        "escalating twice",
    );
    let challenger_key = challenger.pubkey();
    assert_refused(
        s.arbiter_resolve_alt((ALT, ALT_ROOT), challenger_key),
        EscrowError::EscrowFrozen,
        "the arbiter while the freeze is in force",
    );
    ok(s.set_freeze(&admin, false), "the admin unfreezes");
    assert_refused(
        s.settle(),
        EscrowError::InvalidStatus,
        "settle of an escalated escrow",
    );
    let before = s.lamports(&challenger_key);
    ok(
        s.arbiter_resolve_alt((ALT, ALT_ROOT), challenger_key),
        "the arbiter applies the honest alternative",
    );
    let state = s.state();
    assert_eq!(
        (state.status, state.payout_root, state.commitment),
        (EscrowStatus::Claimable, ALT_ROOT, alt)
    );
    assert_eq!(
        s.lamports(&challenger_key),
        before + 2 * BOND,
        "the challenger takes every bond"
    );
}

#[test]
fn a_freeze_stops_the_escrow_clock_and_a_global_stop_inside_it_counts_once() {
    let mut s = S::posted();
    let (guardian, admin) = (s.guardian.insecure_clone(), s.admin.insecure_clone());
    s.at(CHALLENGE_AT);
    ok(s.set_freeze(&guardian, true), "freeze inside the window");
    s.at(CHALLENGE_AT + DAY);
    ok(s.set_freeze(&admin, false), "unfreeze a day later");
    assert_eq!(s.state().frozen_secs, DAY);
    s.at(CHALLENGE_DEADLINE);
    assert_refused(
        s.settle(),
        EscrowError::DeadlineNotReached,
        "settle on the old deadline",
    );
    s.at(CHALLENGE_DEADLINE + DAY);
    let meta = ok(s.settle(), "settle a day late");
    assert_eq!(event::<Settled>(&meta).outcome, SettleOutcome::Undisputed);
    assert_eq!(
        s.state().claim_deadline,
        CLAIM_DEADLINE,
        "the claim window on the escrow clock"
    );

    // A freeze of the Claimable escrow, with a day's PayoutStop inside it: the freeze lapses after
    // seven days of the global clock, eight in wall time, and the escrow clock counts the stop
    // once (eight days stopped, not nine).
    let x = CHALLENGE_DEADLINE + 2 * DAY;
    s.at(x);
    ok(s.set_freeze(&guardian, true), "freeze");
    s.at(x + DAY);
    ok(
        s.set_stop(&guardian, StopState::PayoutStop),
        "PayoutStop inside the freeze",
    );
    s.at(x + 2 * DAY);
    ok(s.set_stop(&admin, StopState::Normal), "unstop");
    s.at(x + 8 * DAY - 1);
    assert_refused(
        s.claim(0, 0),
        EscrowError::EscrowFrozen,
        "a claim on the freeze's last second",
    );
    s.at(x + 8 * DAY);
    ok(s.claim(0, 0), "a claim once the freeze lapsed");
    // Stopped for 1 day (the first freeze) + 8 days (freeze and stop together): the claim
    // deadline sits 9 days later in wall time.
    let shifted = CLAIM_DEADLINE + DAY + 8 * DAY;
    s.at(shifted);
    ok(s.claim(1, 0), "a claim on the shifted claim deadline");
    s.at(shifted + 1);
    ok(s.refund(), "a refund a second after it");

    // The admin extends a freeze in force; a lapsed one cannot be extended.
    assert_refused(
        s.extend_freeze(&admin, DAY),
        EscrowError::NotFrozen,
        "extending with no freeze",
    );
}

#[test]
fn the_admin_extends_a_freeze_and_escalate_takes_only_an_undecided_escrow() {
    let mut s = S::committed();
    let (guardian, admin) = (s.guardian.insecure_clone(), s.admin.insecure_clone());
    assert_refused(
        s.escalate(&guardian),
        EscrowError::InvalidStatus,
        "escalating an Open escrow",
    );
    s.at(POST_AT);
    let resolver = s.resolver.insecure_clone();
    ok(s.post(&resolver), "post_result");
    ok(s.set_freeze(&guardian, true), "freeze at the post");
    ok(s.extend_freeze(&admin, DAY), "the admin extends it a day");
    s.at(POST_AT + STOP_DURATION + DAY - 1);
    assert_eq!(s.state().freeze_until, POST_AT + STOP_DURATION + DAY);
    s.at(POST_AT + STOP_DURATION + DAY + CHALLENGE_DEADLINE - POST_AT);
    ok(
        s.settle(),
        "settle once the extended freeze lapsed and the window ran",
    );
    assert_refused(
        s.escalate(&guardian),
        EscrowError::InvalidStatus,
        "escalating a decided escrow",
    );
}

// ------------------------------------------------------------------- frozen token accounts

#[test]
fn token_accounts_the_mint_froze_are_refused_by_name() {
    let mut s = S::claimable();
    // The vault.
    let vault = s.vault();
    s.set_frozen(vault, true);
    assert_refused(
        s.claim(0, 0),
        EscrowError::VaultFrozen,
        "a claim from a frozen vault",
    );
    s.set_frozen(vault, false);
    // The claimant's own account.
    let ata = get_associated_token_address(&s.winner(0), &s.mint);
    let (mint, winner0) = (s.mint, s.winner(0));
    set_token_account(&mut s.svm, ata, mint, winner0, 0, true);
    assert_refused(
        s.claim(0, 0),
        EscrowError::ClaimantAccountFrozen,
        "a claim into a frozen account",
    );
    s.set_frozen(ata, false);
    ok(s.claim(0, 0), "the claim once thawed");

    // While a mint freeze lasts, the guardian's freeze holds the claim deadline.
    let guardian = s.guardian.insecure_clone();
    let admin = s.admin.insecure_clone();
    let ata1 = get_associated_token_address(&s.winner(1), &s.mint);
    let winner1 = s.winner(1);
    set_token_account(&mut s.svm, ata1, mint, winner1, 0, true);
    s.at(CLAIM_DEADLINE - DAY);
    ok(
        s.set_freeze(&guardian, true),
        "the guardian freezes the escrow",
    );
    s.at(CLAIM_DEADLINE + 3 * DAY);
    ok(
        s.set_freeze(&admin, false),
        "the admin unfreezes it once the mint thawed",
    );
    s.set_frozen(ata1, false);
    ok(s.claim(1, 0), "the second winner still claims");

    // refund_to's account, and the vault at refund.
    s.at(CLAIM_DEADLINE + 4 * DAY + 1);
    let refund_ata = get_associated_token_address(&s.sponsor.pubkey(), &s.mint);
    set_token_account(&mut s.svm, refund_ata, s.mint, s.sponsor.pubkey(), 0, true);
    assert_refused(
        s.refund(),
        EscrowError::RefundAccountFrozen,
        "a refund into a frozen account",
    );
    s.set_frozen(refund_ata, false);
    s.set_frozen(vault, true);
    assert_refused(
        s.refund(),
        EscrowError::VaultFrozen,
        "a refund from a frozen vault",
    );
    s.set_frozen(vault, false);
    ok(s.refund(), "the refund once thawed");
}

#[test]
fn a_frozen_sponsor_account_is_refused_by_name() {
    let mut s = S::new();
    let funding = s.funding;
    s.set_frozen(funding, true);
    assert_refused(
        s.open(&s.terms.clone()),
        EscrowError::SponsorAccountFrozen,
        "an open from a frozen account",
    );
    s.set_frozen(funding, false);
    ok(s.open(&s.terms.clone()), "open_escrow");
    s.set_frozen(funding, true);
    assert_refused(
        s.fund(1),
        EscrowError::SponsorAccountFrozen,
        "a fund from a frozen account",
    );
}

// ---------------------------------------------------------------------------- commit-reveal

#[test]
fn a_challenge_commits_then_reveals_in_a_later_slot_and_a_copier_cannot_take_it() {
    let mut s = S::posted();
    let challenger = s.challenger.insecure_clone();
    let copier = s.copier.insecure_clone();
    let stranger = s.stranger.insecure_clone();
    s.at(CHALLENGE_AT);
    let before = s.state();
    let honest = (ALT, ALT_ROOT);
    let alt = result_commitment(&ALT, &ALT_ROOT, TOTAL);
    let (hash, salt) = s.hash_of(&challenger.pubkey(), honest);
    let meta = ok(s.commit(&challenger, hash), "the honest commit");
    let committed = event::<ChallengeCommitted>(&meta);
    let commit = s.commit_pda(&challenger.pubkey(), &hash);
    assert_eq!(
        (
            committed.commit,
            committed.challenger,
            committed.hash,
            committed.bond,
            committed.pending_commits
        ),
        (commit, challenger.pubkey(), hash, BOND, 1)
    );
    // A commit moves no deadline and no status; its bond is held apart.
    let after = s.state();
    assert_eq!(
        (
            after.status,
            after.challenge_deadline,
            after.attest_deadline,
            after.claim_deadline
        ),
        (
            before.status,
            before.challenge_deadline,
            before.attest_deadline,
            before.claim_deadline
        )
    );
    assert_eq!(
        (
            after.commit_bond,
            after.challenger_bond,
            after.pending_commits
        ),
        (BOND, 0, 1)
    );

    // A reveal in the commit's own slot is refused.
    assert_refused(
        s.reveal_at(&challenger, commit, salt, honest),
        EscrowError::RevealTooEarly,
        "a reveal in the commit's slot",
    );
    // A copier cannot reveal the honest commit as its own: the commit's seeds name its
    // challenger.
    assert_refused(
        s.reveal_at(&copier, commit, salt, honest),
        AnchorErrorCode::ConstraintSeeds,
        "a copier revealing the honest commit",
    );
    // A copy of the hash under the copier's key lands at the copier's own address and can never
    // be revealed: the hash names the honest challenger.
    ok(s.commit(&copier, hash), "the copier's copy of the hash");
    let copied = s.commit_pda(&copier.pubkey(), &hash);
    assert_ne!(copied, commit);
    // A junk commit nobody will reveal in time.
    let junk = (JUNK, JUNK_ROOT);
    let (junk_hash, junk_salt) = s.hash_of(&stranger.pubkey(), junk);
    ok(s.commit(&stranger, junk_hash), "a junk commit");

    next_slot(&mut s.svm);
    assert_refused(
        s.reveal_at(&copier, copied, salt, honest),
        EscrowError::CommitMismatch,
        "the copier revealing its copied hash",
    );
    let wrong_salt = [0x11; 32];
    assert_refused(
        s.reveal_at(&challenger, commit, wrong_salt, honest),
        EscrowError::CommitMismatch,
        "a reveal with another salt",
    );
    let meta = ok(
        s.reveal_at(&challenger, commit, salt, honest),
        "the honest reveal",
    );
    let challenged = event::<Challenged>(&meta);
    assert_eq!(
        (
            challenged.commit,
            challenged.alt_commitment,
            challenged.index
        ),
        (commit, alt, 0)
    );
    assert!(
        s.svm.get_account(&commit).is_none_or(|a| a.lamports == 0),
        "the reveal closed the commit"
    );
    let state = s.state();
    assert_eq!(state.status, EscrowStatus::Disputed);
    assert_eq!(
        state.attest_deadline,
        CHALLENGE_DEADLINE + MIN_ATTEST_WINDOW,
        "fixed by the challenge deadline, not the reveal"
    );
    assert_eq!(
        (
            state.commit_bond,
            state.challenger_bond,
            state.pending_commits
        ),
        (2 * BOND, BOND, 2)
    );

    // A front-runner who saw the reveal commits the same alternative under its own key and
    // reveals a slot later: the alternative's Challenge PDA is the honest challenger's already.
    let (copy_hash, copy_salt) = s.hash_of(&copier.pubkey(), honest);
    ok(
        s.commit(&copier, copy_hash),
        "the front-runner's own commit",
    );
    next_slot(&mut s.svm);
    let copy_commit = s.commit_pda(&copier.pubkey(), &copy_hash);
    assert_refused(
        s.reveal_at(&copier, copy_commit, copy_salt, honest),
        0u32,
        "the front-run copy of a revealed alternative",
    );
    let record = s.svm.get_account(&s.challenge_pda(&alt)).unwrap();
    let record = ChallengeRecord::try_deserialize(&mut record.data.as_slice()).unwrap();
    assert_eq!(record.challenger, challenger.pubkey());

    // Nothing is closed before the escrow decides.
    assert_refused(
        s.close_commit(stranger.pubkey(), junk_hash),
        EscrowError::InvalidStatus,
        "close_commit while undecided",
    );

    // The regraders back the alternative; settle waits for the reveal grace while commits pend.
    ok(s.attest(0, alt), "regrader 0");
    ok(s.attest(1, alt), "regrader 1: a quorum");
    s.at(CHALLENGE_DEADLINE);
    assert_refused(
        s.commit(&stranger, [0x78; 32]),
        EscrowError::ChallengeWindowClosed,
        "a commit at the challenge deadline",
    );
    assert_refused(
        s.settle(),
        EscrowError::CommitsPendingReveal,
        "settle inside the reveal grace",
    );
    s.at(CHALLENGE_DEADLINE + MIN_REVEAL_GRACE);
    let junk_commit = s.commit_pda(&stranger.pubkey(), &junk_hash);
    assert_refused(
        s.reveal_at(&stranger, junk_commit, junk_salt, junk),
        EscrowError::RevealWindowClosed,
        "a reveal after the grace",
    );
    // Past the grace the commits hold nothing back; the overturn itself waits for attest_deadline.
    assert_refused(
        s.settle(),
        EscrowError::OverturnWindowOpen,
        "the overturn after the grace",
    );
    let attest_deadline = s.state().attest_deadline;
    assert_eq!(attest_deadline, CHALLENGE_DEADLINE + MIN_ATTEST_WINDOW);
    s.at(attest_deadline);
    let resolver_before = s.lamports(&s.resolver.pubkey());
    let challenger_before = s.lamports(&challenger.pubkey());
    let meta = ok(s.settle(), "settle at the attest deadline");
    let settled = event::<Settled>(&meta);
    assert_eq!(settled.outcome, SettleOutcome::AltApplied);
    // The winner takes the resolver's bond and its own, never an unrevealed commit's.
    assert_eq!(
        s.lamports(&challenger.pubkey()),
        challenger_before + 2 * BOND
    );
    assert_eq!(s.lamports(&s.resolver.pubkey()), resolver_before);
    assert_eq!(
        s.state().commit_bond,
        3 * BOND,
        "the three unrevealed commits' bonds stay held"
    );

    // Each unrevealed commit's bond and rent go back to its own challenger.
    let stranger_before = s.lamports(&stranger.pubkey());
    let rent = s.lamports(&junk_commit);
    let meta = ok(
        s.close_commit(stranger.pubkey(), junk_hash),
        "close the junk commit",
    );
    let closed = event::<CommitClosed>(&meta);
    assert_eq!(
        (
            closed.bond_returned,
            closed.rent_returned,
            closed.pending_commits
        ),
        (BOND, rent, 2)
    );
    assert_eq!(
        s.lamports(&stranger.pubkey()),
        stranger_before + BOND + rent
    );
    assert_refused(
        s.close_commit(stranger.pubkey(), junk_hash),
        AnchorErrorCode::AccountNotInitialized,
        "closing twice",
    );
    ok(
        s.close_commit(copier.pubkey(), hash),
        "close the copied hash",
    );
    ok(
        s.close_commit(copier.pubkey(), copy_hash),
        "close the front-runner's commit",
    );
    let state = s.state();
    assert_eq!((state.commit_bond, state.pending_commits), (0, 0));
    assert_eq!(
        s.lamports(&s.escrow()),
        s.svm.minimum_balance_for_rent_exemption(Escrow::SPACE)
    );
}

// --------------------------------------------------------------------------------- helpers

fn attestation_pda(escrow: &Pubkey, regrader: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[ATTESTATION_SEED, escrow.as_ref(), regrader.as_ref()],
        &prize_escrow::ID,
    )
    .0
}

fn receipt_pda(escrow: &Pubkey, claimant: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[prize_escrow::CLAIM_SEED, escrow.as_ref(), claimant.as_ref()],
        &prize_escrow::ID,
    )
    .0
}

/// Sends `ix` with `payer` paying the fee and `signers` signing too.
#[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
fn send(
    svm: &mut LiteSVM,
    payer: &Keypair,
    ix: Instruction,
    signers: &[&Keypair],
) -> TransactionResult {
    svm.expire_blockhash();
    let msg = Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &svm.latest_blockhash());
    // The payer (the admin) may sign as a role too: each key signs once.
    let mut all = vec![payer];
    for signer in signers {
        if all.iter().all(|kp| kp.pubkey() != signer.pubkey()) {
            all.push(signer);
        }
    }
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &all).unwrap();
    svm.send_transaction(tx)
}

fn set_time(svm: &mut LiteSVM, unix_timestamp: i64) {
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = unix_timestamp;
    svm.set_sysvar::<Clock>(&clock);
}

fn set_mint(svm: &mut LiteSVM, address: Pubkey) {
    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint {
        mint_authority: COption::Some(Pubkey::new_unique()),
        supply: 100 * TOTAL,
        decimals: DECIMALS,
        is_initialized: true,
        freeze_authority: COption::Some(Pubkey::new_unique()),
    }
    .pack_into_slice(&mut data);
    let lamports = svm.minimum_balance_for_rent_exemption(data.len());
    svm.set_account(
        address,
        Account {
            lamports,
            data,
            owner: token::ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn set_token_account(
    svm: &mut LiteSVM,
    address: Pubkey,
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    frozen: bool,
) {
    let mut data = vec![0u8; spl_token::state::Account::LEN];
    spl_token::state::Account {
        mint,
        owner,
        amount,
        delegate: COption::None,
        state: if frozen {
            spl_token::state::AccountState::Frozen
        } else {
            spl_token::state::AccountState::Initialized
        },
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    let lamports = svm.minimum_balance_for_rent_exemption(data.len());
    svm.set_account(
        address,
        Account {
            lamports,
            data,
            owner: token::ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn instruction(accounts: impl ToAccountMetas, data: impl InstructionData) -> Instruction {
    Instruction::new_with_bytes(
        prize_escrow::ID,
        &data.data(),
        accounts.to_account_metas(None),
    )
}

fn logs(result: &TransactionResult) -> String {
    match result {
        Ok(meta) => meta.pretty_logs(),
        Err(failed) => format!("{:?}\n{}", failed.err, failed.meta.pretty_logs()),
    }
}

/// The transaction succeeded; its metadata.
fn ok(result: TransactionResult, what: &str) -> TransactionMetadata {
    match result {
        Ok(meta) => meta,
        Err(_) => panic!("{what} failed: {}", logs(&result)),
    }
}

/// The transaction failed with exactly `code` (0: the system program's AccountAlreadyInUse).
fn assert_refused(result: TransactionResult, code: impl Into<u32>, what: &str) {
    let code = code.into();
    let got = match &result {
        Err(failed) => match &failed.err {
            TransactionError::InstructionError(0, InstructionError::Custom(code)) => Some(*code),
            _ => None,
        },
        Ok(_) => None,
    };
    assert_eq!(
        got,
        Some(code),
        "{what}: expected error {code}, got {}",
        logs(&result)
    );
}

/// The one `E` event the transaction emitted through the program's self-CPI.
fn event<E: Discriminator + AnchorDeserialize>(meta: &TransactionMetadata) -> E {
    let mut found: Vec<E> = meta
        .inner_instructions
        .iter()
        .flatten()
        .filter_map(|inner| {
            let data = inner.instruction.data.strip_prefix(EVENT_IX_TAG_LE)?;
            data.strip_prefix(E::DISCRIMINATOR)
        })
        .map(|body| E::try_from_slice(body).unwrap())
        .collect();
    assert_eq!(found.len(), 1, "one event: {}", meta.pretty_logs());
    found.remove(0)
}
