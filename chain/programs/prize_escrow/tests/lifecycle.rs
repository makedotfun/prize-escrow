//! The prize_escrow lifecycle on the release build (`node scripts/chain/build.ts release` writes
//! the canonical SBPF v2 target/deploy/prize_escrow.so; run it first): open_escrow, fund,
//! commit_entries, post_result, challenge, attest, settle, arbiter_resolve and refund, through
//! every outcome and both sides of every deadline.
//!
//! Time moves by rewriting LiteSVM's Clock sysvar, so the real windows are exercised: the 24 h
//! challenge window and the 24 h attestation window of the release constants, never the 60 s of
//! the test-windows feature. Each test checks the escrow account, the token and lamport balances,
//! and the event the instruction emits.
//!
//! Run review 3's regressions live here too: two sponsors opening one competition id each at
//! its own address, post_result waiting for final_end and the entries root, a donation into the
//! vault never blocking post_result or arbiter_resolve, and the terms' hard-deadline and
//! claim-versus-hold bounds (the commitment and the late-arbiter refund are in tests/claims.rs).
//!
//! And run review 4's: a quorum for the alternative applies it (settle's AltApplied, Claimable on
//! the alternative's root, total and commitment) instead of freezing the escrow for the arbiter;
//! arbiter_resolve only chooses the posted or the alternative result, as stored; the side that
//! lost forfeits its whole bond to the side that won (nothing goes to refund_to); open_escrow
//! holds the claim window to MIN_CLAIM_WINDOW and the bond to its floor; and every event rides a
//! self-CPI (emit_cpi!), never a `Program data:` log line (the `event` helper checks both).
//!
//! And run review 5's: an escrow takes one challenge per distinct alternative commitment, each its
//! own Challenge PDA, so a junk first challenge never keeps the honest alternative out: the
//! regraders' majority for a later challenge applies it, the arbiter may choose any challenge of a
//! Frozen escrow, every losing side's bond goes to the side that won, a refund that decided
//! nothing returns every bond to its payer, and close_challenge returns each PDA's rent.

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
        config_init, config_pda, initialize_config_ix, next_slot, salt_for, set_upgrade_authority,
    },
    litesvm::{
        types::{TransactionMetadata, TransactionResult},
        LiteSVM,
    },
    prize_escrow::{
        accounts as accts, commit_hash, instruction as ixs, result_commitment, ArbiterChoice,
        ArbiterResolved, AttestSide, Attestation, Attested, ChallengeClosed, ChallengeRecord,
        Challenged, CommitRecord, EntriesCommitted, Escrow, EscrowError, EscrowFunded,
        EscrowOpened, EscrowStatus, EscrowTerms, Refunded, ResultPosted, SettleOutcome, Settled,
        ARBITER_SLACK, ATTESTATION_SEED, BOND_FLOOR_RENTS, CHALLENGE_SEED, ESCROW_SEED,
        EVENT_AUTHORITY_AND_BUMP, MIN_ATTEST_WINDOW, MIN_CHALLENGE_WINDOW, MIN_CLAIM_WINDOW,
        MIN_HOLD_WINDOW, MIN_REVEAL_GRACE,
    },
    solana_account::Account,
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
    solana_transaction_error::TransactionError,
};

/// The PDA ["__event_authority"] that signs the program's event self-CPIs.
const EVENT_AUTHORITY: Pubkey = EVENT_AUTHORITY_AND_BUMP.0;

const CID: [u8; 16] = [0x5a; 16];
const DECIMALS: u8 = 6;
/// 5,000 tokens of a 6-decimal mint.
const TOTAL: u64 = 5_000_000_000;
/// Odd, so a payout that split a bond would show (a forfeited bond goes to the winner whole).
const BOND: u64 = 100_000_001;
const SOL: u64 = 1_000_000_000;

const HOUR: i64 = 3_600;
const DAY: i64 = 24 * HOUR;
/// 2027-01-15T08:00:00Z: when every test opens its escrow.
const NOW: i64 = 1_800_000_000;
const ENTRIES_DEADLINE: i64 = NOW + DAY;
/// The final phase ends a day after it starts: post_result waits for it.
const FINAL_END: i64 = NOW + 2 * DAY;
const RESOLVE_DEADLINE: i64 = NOW + 7 * DAY;
const CLAIM_WINDOW: i64 = 30 * DAY;
const HARD_DEADLINE: i64 = NOW + 365 * DAY;
/// When the scenario helpers post the result (the final end itself), and then challenge it.
const POST_AT: i64 = FINAL_END;
const CHALLENGE_AT: i64 = POST_AT + HOUR;
/// The challenge deadline of the result posted at POST_AT (the 24 h window): nothing settles before it.
const CHALLENGE_DEADLINE: i64 = POST_AT + 24 * HOUR;
/// The attest deadline once challenged: a whole 24 h attest window past the challenge deadline,
/// whenever the first challenge landed.
const ATTEST_DEADLINE: i64 = CHALLENGE_DEADLINE + 24 * HOUR;

const ENTRIES_ROOT: [u8; 32] = [0xe5; 32];
const PAYOUT_ROOT: [u8; 32] = [0xa1; 32];
const RESULT: [u8; 32] = [0xb2; 32];
const KIT: [u8; 32] = [0xc3; 32];
/// The challenger's alternative: its document hash, payout root and total.
const ALT: [u8; 32] = [0xd4; 32];
const ALT_ROOT: [u8; 32] = [0xa7; 32];
const RULES: [u8; 32] = [0xf6; 32];

/// What post_result stores for the scenario's result (RESULT, PAYOUT_ROOT, TOTAL).
fn posted_commitment() -> [u8; 32] {
    result_commitment(&RESULT, &PAYOUT_ROOT, TOTAL)
}

/// What challenge stores for the scenario's alternative (ALT, ALT_ROOT, TOTAL).
fn alt_commitment() -> [u8; 32] {
    result_commitment(&ALT, &ALT_ROOT, TOTAL)
}

/// A junk alternative nobody reproduces (JUNK, JUNK_ROOT, TOTAL): the multi-challenge tests open
/// it first, before the honest one.
const JUNK: [u8; 32] = [0x6e; 32];
const JUNK_ROOT: [u8; 32] = [0x6f; 32];

fn junk_commitment() -> [u8; 32] {
    result_commitment(&JUNK, &JUNK_ROOT, TOTAL)
}

// --------------------------------------------------------------------------------- the world

/// Who signs an instruction (besides the fee payer, who signs every transaction).
#[derive(Clone, Copy, Debug)]
enum Who {
    Sponsor,
    Resolver,
    Arbiter,
    Challenger,
    /// A second challenger, who opens a junk alternative.
    Junk,
    Stranger,
    Regrader(usize),
}

struct Keys {
    payer: Keypair,
    sponsor: Keypair,
    resolver: Keypair,
    arbiter: Keypair,
    challenger: Keypair,
    junk: Keypair,
    stranger: Keypair,
    regraders: [Keypair; 3],
}

impl Keys {
    fn get(&self, who: Who) -> &Keypair {
        match who {
            Who::Sponsor => &self.sponsor,
            Who::Resolver => &self.resolver,
            Who::Arbiter => &self.arbiter,
            Who::Challenger => &self.challenger,
            Who::Junk => &self.junk,
            Who::Stranger => &self.stranger,
            Who::Regrader(i) => &self.regraders[i],
        }
    }

    fn key(&self, who: Who) -> Pubkey {
        self.get(who).pubkey()
    }
}

/// A LiteSVM with the release program, every role funded with SOL, a classic-Token mint, the
/// sponsor's associated token account holding 4 x TOTAL, and the escrow's terms. The escrow itself
/// is opened by the real open_escrow (`Lc::opened`).
struct Lc {
    svm: LiteSVM,
    keys: Keys,
    compliance: Pubkey,
    /// The sponsor (the open policy pins refund_to to it). Its associated token account, where
    /// refunds land, starts with no account at all: the sponsor funds from another token account
    /// it owns (sponsor_ata), so a refund's tokens are all that account ever holds.
    refund_to: Pubkey,
    /// refund_to's lamports once the escrow opened: refund_to_gain measures from it.
    refund_to_base: u64,
    mint: Pubkey,
    /// The sponsor's funding token account (not its associated one, which refunds go to).
    sponsor_ata: Pubkey,
    escrow: Pubkey,
    vault: Pubkey,
    terms: EscrowTerms,
}

impl Lc {
    fn new() -> Self {
        let mut svm = mainnet::svm();
        svm.add_program(prize_escrow::ID, program_so::bytes())
            .unwrap();
        set_time(&mut svm, NOW);

        let keys = Keys {
            payer: Keypair::new(),
            sponsor: Keypair::new(),
            resolver: Keypair::new(),
            arbiter: Keypair::new(),
            challenger: Keypair::new(),
            junk: Keypair::new(),
            stranger: Keypair::new(),
            regraders: [Keypair::new(), Keypair::new(), Keypair::new()],
        };
        for kp in [
            &keys.payer,
            &keys.sponsor,
            &keys.resolver,
            &keys.arbiter,
            &keys.challenger,
            &keys.junk,
            &keys.stranger,
        ]
        .into_iter()
        .chain(keys.regraders.iter())
        {
            svm.airdrop(&kp.pubkey(), 10 * SOL).unwrap();
        }

        let mint = Pubkey::new_unique();
        set_mint(&mut svm, mint, token::ID);
        let sponsor_ata = Pubkey::new_unique();
        set_token_account(
            &mut svm,
            sponsor_ata,
            mint,
            keys.sponsor.pubkey(),
            4 * TOTAL,
        );

        let escrow = escrow_pda(&keys.sponsor.pubkey(), &CID);
        let vault = get_associated_token_address(&escrow, &mint);
        let compliance = Pubkey::new_unique();
        let refund_to = keys.sponsor.pubkey();
        let terms = EscrowTerms {
            total: TOTAL,
            rules_sha256: RULES,
            resolver: keys.resolver.pubkey(),
            compliance,
            arbiter: keys.arbiter.pubkey(),
            refund_to,
            regraders: keys.regraders.iter().map(Signer::pubkey).collect(),
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

        // The Config every instruction reads, created by the program's upgrade authority (the
        // payer here): the arbiter, the mint, the sponsor and the regraders allowed, no caps or
        // floors in the way, and the shortest reveal grace.
        set_upgrade_authority(&mut svm, Some(keys.payer.pubkey()));
        let init = config_init(
            keys.payer.pubkey(),
            keys.payer.pubkey(),
            keys.arbiter.pubkey(),
            &[mint],
            &[keys.sponsor.pubkey(), keys.stranger.pubkey()],
            &terms.regraders,
        );
        let mut lc = Lc {
            svm,
            keys,
            compliance,
            refund_to,
            refund_to_base: 0,
            mint,
            sponsor_ata,
            escrow,
            vault,
            terms,
        };
        let ix = initialize_config_ix(lc.keys.payer.pubkey(), init);
        ok(lc.send(ix, &[]), "initialize_config");
        lc
    }

    /// Opened at NOW with the default terms.
    fn opened() -> Self {
        let mut lc = Lc::new();
        let r = lc.open();
        ok(r, "open_escrow");
        lc
    }

    /// Opened, and the entries root committed at NOW (still Open).
    fn committed() -> Self {
        let mut lc = Lc::opened();
        let r = lc.commit(Who::Resolver, ENTRIES_ROOT, 12);
        ok(r, "commit_entries");
        lc
    }

    /// Committed, and the result posted at POST_AT (Challengeable).
    fn posted() -> Self {
        let mut lc = Lc::committed();
        lc.at(POST_AT);
        let r = lc.post(Who::Resolver, TOTAL);
        ok(r, "post_result");
        lc
    }

    /// Posted, then challenged with (ALT, ALT_ROOT, TOTAL) at CHALLENGE_AT (Disputed).
    fn disputed() -> Self {
        let mut lc = Lc::posted();
        lc.at(CHALLENGE_AT);
        let r = lc.challenge(Who::Challenger, ALT);
        ok(r, "challenge");
        lc
    }

    // ------------------------------------------------------------------------ plumbing

    fn at(&mut self, unix_timestamp: i64) {
        set_time(&mut self.svm, unix_timestamp);
    }

    /// Send `ix` with the payer paying the fee and `signers` signing too.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn send(&mut self, ix: Instruction, signers: &[Who]) -> TransactionResult {
        self.svm.expire_blockhash();
        let msg = Message::new_with_blockhash(
            &[ix],
            Some(&self.keys.payer.pubkey()),
            &self.svm.latest_blockhash(),
        );
        let mut all = vec![&self.keys.payer];
        all.extend(signers.iter().map(|who| self.keys.get(*who)));
        let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &all).unwrap();
        self.svm.send_transaction(tx)
    }

    fn state(&self) -> Escrow {
        let account = self
            .svm
            .get_account(&self.escrow)
            .expect("the escrow account exists");
        Escrow::try_deserialize(&mut account.data.as_slice()).unwrap()
    }

    fn lamports(&self, address: &Pubkey) -> u64 {
        self.svm.get_account(address).map_or(0, |a| a.lamports)
    }

    fn tokens(&self, address: &Pubkey) -> u64 {
        let account = self
            .svm
            .get_account(address)
            .expect("the token account exists");
        assert_eq!(account.owner, token::ID);
        spl_token::state::Account::unpack(&account.data)
            .unwrap()
            .amount
    }

    /// The escrow account's rent-exempt minimum: what it holds when no bond is held.
    fn escrow_rent(&self) -> u64 {
        self.svm.minimum_balance_for_rent_exemption(Escrow::SPACE)
    }

    fn refund_to_ata(&self) -> Pubkey {
        get_associated_token_address(&self.refund_to, &self.mint)
    }

    /// The escrow's Challenge PDA of `alt_commitment`.
    fn challenge_pda(&self, alt_commitment: &[u8; 32]) -> Pubkey {
        challenge_pda(&self.escrow, alt_commitment)
    }

    /// The Challenge account of `alt_commitment`, or None when it does not exist (never opened,
    /// or closed).
    fn challenge_state(&self, alt_commitment: &[u8; 32]) -> Option<ChallengeRecord> {
        let account = self.svm.get_account(&self.challenge_pda(alt_commitment))?;
        if account.lamports == 0 {
            return None;
        }
        Some(ChallengeRecord::try_deserialize(&mut account.data.as_slice()).unwrap())
    }

    /// A Challenge account's rent-exempt minimum: what its challenger pays and gets back.
    fn challenge_rent(&self) -> u64 {
        self.svm
            .minimum_balance_for_rent_exemption(ChallengeRecord::SPACE)
    }

    // -------------------------------------------------------------------- instructions

    fn open_ix(&self, terms: &EscrowTerms) -> Instruction {
        instruction(
            accts::OpenEscrow {
                sponsor: self.keys.key(Who::Sponsor),
                escrow: self.escrow,
                mint: self.mint,
                sponsor_token_account: self.sponsor_ata,
                vault: self.vault,
                token_program: token::ID,
                associated_token_program: associated_token::ID,
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::OpenEscrow {
                competition_id: CID,
                terms: terms.clone(),
            },
        )
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn open(&mut self) -> TransactionResult {
        let ix = self.open_ix(&self.terms);
        let result = self.send(ix, &[Who::Sponsor]);
        if result.is_ok() {
            self.refund_to_base = self.lamports(&self.refund_to);
        }
        result
    }

    /// The lamports refund_to (the sponsor) gained since the escrow opened: the vault's rent
    /// after a refund, nothing before (no bond ever goes to it).
    fn refund_to_gain(&self) -> u64 {
        self.lamports(&self.refund_to) - self.refund_to_base
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn fund(&mut self, who: Who, amount: u64) -> TransactionResult {
        let ix = instruction(
            accts::Fund {
                sponsor: self.keys.key(who),
                escrow: self.escrow,
                mint: self.mint,
                sponsor_token_account: self.sponsor_ata,
                vault: self.vault,
                token_program: token::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Fund { amount },
        );
        self.send(ix, &[who])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn commit(
        &mut self,
        who: Who,
        entries_root: [u8; 32],
        entries_count: u32,
    ) -> TransactionResult {
        let ix = instruction(
            accts::CommitEntries {
                resolver: self.keys.key(who),
                escrow: self.escrow,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::CommitEntries {
                entries_root,
                entries_count,
            },
        );
        self.send(ix, &[who])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn post(&mut self, who: Who, total: u64) -> TransactionResult {
        self.post_with(who, PAYOUT_ROOT, RESULT, total)
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn post_with(
        &mut self,
        who: Who,
        payout_root: [u8; 32],
        result_sha256: [u8; 32],
        total: u64,
    ) -> TransactionResult {
        let ix = instruction(
            accts::PostResult {
                resolver: self.keys.key(who),
                escrow: self.escrow,
                mint: self.mint,
                vault: self.vault,
                token_program: token::ID,
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::PostResult {
                payout_root,
                result_sha256,
                kit_sha256: KIT,
                total,
            },
        );
        self.send(ix, &[who])
    }

    /// A challenge with `alt_result_sha256`, ALT_ROOT and TOTAL.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn challenge(&mut self, who: Who, alt_result_sha256: [u8; 32]) -> TransactionResult {
        self.challenge_with(who, alt_result_sha256, ALT_ROOT, TOTAL)
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn challenge_with(
        &mut self,
        who: Who,
        alt_result_sha256: [u8; 32],
        alt_payout_root: [u8; 32],
        alt_total: u64,
    ) -> TransactionResult {
        let alt_commitment = result_commitment(&alt_result_sha256, &alt_payout_root, alt_total);
        self.challenge_committing(
            who,
            alt_result_sha256,
            alt_payout_root,
            alt_total,
            alt_commitment,
        )
    }

    /// A challenge naming `alt_commitment` (its PDA's seed) whatever the alternative commits to.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn challenge_committing(
        &mut self,
        who: Who,
        alt_result_sha256: [u8; 32],
        alt_payout_root: [u8; 32],
        alt_total: u64,
        alt_commitment: [u8; 32],
    ) -> TransactionResult {
        let challenger = self.keys.key(who);
        let salt = salt_for(&challenger, &alt_commitment);
        let hash = commit_hash(&alt_commitment, &challenger, &salt);
        self.commit_challenge(who, hash)?;
        next_slot(&mut self.svm);
        self.reveal(
            who,
            hash,
            salt,
            alt_result_sha256,
            alt_payout_root,
            alt_total,
            alt_commitment,
        )
    }

    /// challenge_commit of `hash` by `who`.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn commit_challenge(&mut self, who: Who, hash: [u8; 32]) -> TransactionResult {
        let challenger = self.keys.key(who);
        let ix = instruction(
            accts::ChallengeCommit {
                challenger,
                config: config_pda(),
                escrow: self.escrow,
                commit: CommitRecord::pda(&self.escrow, &challenger, &hash).0,
                system_program: system_program::ID,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ChallengeCommit { hash },
        );
        self.send(ix, &[who])
    }

    /// challenge_reveal by `who` of its commit of `hash`.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    #[allow(clippy::too_many_arguments, reason = "the instruction's own arguments")]
    fn reveal(
        &mut self,
        who: Who,
        hash: [u8; 32],
        salt: [u8; 32],
        alt_result_sha256: [u8; 32],
        alt_payout_root: [u8; 32],
        alt_total: u64,
        alt_commitment: [u8; 32],
    ) -> TransactionResult {
        let challenger = self.keys.key(who);
        let ix = instruction(
            accts::ChallengeReveal {
                challenger,
                config: config_pda(),
                escrow: self.escrow,
                mint: self.mint,
                vault: self.vault,
                commit: CommitRecord::pda(&self.escrow, &challenger, &hash).0,
                challenge: self.challenge_pda(&alt_commitment),
                token_program: token::ID,
                system_program: system_program::ID,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ChallengeReveal {
                salt,
                alt_result_sha256,
                alt_payout_root,
                alt_total,
                alt_commitment,
            },
        );
        self.send(ix, &[who])
    }

    /// A vote for `commitment` (posted_commitment(), or a challenge's: its Challenge PDA rides
    /// along when it exists).
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn attest(&mut self, who: Who, commitment: [u8; 32]) -> TransactionResult {
        let challenge = self
            .challenge_state(&commitment)
            .map(|_| self.challenge_pda(&commitment));
        self.attest_with(who, commitment, challenge)
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn attest_with(
        &mut self,
        who: Who,
        commitment: [u8; 32],
        challenge: Option<Pubkey>,
    ) -> TransactionResult {
        let regrader = self.keys.key(who);
        let ix = instruction(
            accts::Attest {
                regrader,
                escrow: self.escrow,
                attestation: attestation_pda(&self.escrow, &regrader),
                challenge,
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Attest { commitment },
        );
        self.send(ix, &[who])
    }

    /// Permissionless: only the fee payer signs. With `with_challenger`, the account of the
    /// challenger the escrow records as winning rides along (none while no alternative won: the
    /// account is pinned to escrow.challenger).
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn settle(&mut self, with_challenger: bool) -> TransactionResult {
        let recorded = self.state().challenger;
        let challenger = (recorded != Pubkey::default()).then_some(recorded);
        let ix = instruction(
            accts::Settle {
                escrow: self.escrow,
                mint: self.mint,
                vault: self.vault,
                resolver: self.keys.key(Who::Resolver),
                challenger: challenger.filter(|_| with_challenger),
                token_program: token::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Settle {},
        );
        self.send(ix, &[])
    }

    /// arbiter_resolve(choice) on the scenario's sides: Posted names the escrow's commitment;
    /// Alternative names the scenario's alternative (alt_commitment()), its Challenge PDA and
    /// Who::Challenger.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn arbiter_resolve(&mut self, who: Who, choice: ArbiterChoice) -> TransactionResult {
        let ix = self.arbiter_resolve_ix(who, choice);
        self.send(ix, &[who])
    }

    fn arbiter_resolve_ix(&self, who: Who, choice: ArbiterChoice) -> Instruction {
        match choice {
            ArbiterChoice::Posted => {
                self.arbiter_resolve_with_ix(who, choice, self.state().commitment, None)
            }
            ArbiterChoice::Alternative => self.arbiter_resolve_with_ix(
                who,
                choice,
                alt_commitment(),
                Some((
                    self.challenge_pda(&alt_commitment()),
                    self.keys.key(Who::Challenger),
                )),
            ),
        }
    }

    /// arbiter_resolve(choice, commitment) with `challenge` (its PDA and the challenger account
    /// passed) riding along.
    fn arbiter_resolve_with_ix(
        &self,
        who: Who,
        choice: ArbiterChoice,
        commitment: [u8; 32],
        challenge: Option<(Pubkey, Pubkey)>,
    ) -> Instruction {
        instruction(
            accts::ArbiterResolve {
                arbiter: self.keys.key(who),
                escrow: self.escrow,
                mint: self.mint,
                vault: self.vault,
                resolver: self.keys.key(Who::Resolver),
                challenge: challenge.map(|(pda, _)| pda),
                challenger: challenge.map(|(_, challenger)| challenger),
                token_program: token::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ArbiterResolve { choice, commitment },
        )
    }

    /// Permissionless: closes the Challenge PDA of `alt_commitment`, paying `challenger`.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn close_challenge(
        &mut self,
        alt_commitment: [u8; 32],
        challenger: Pubkey,
    ) -> TransactionResult {
        let ix = instruction(
            accts::CloseChallenge {
                escrow: self.escrow,
                challenge: self.challenge_pda(&alt_commitment),
                challenger,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::CloseChallenge {},
        );
        self.send(ix, &[])
    }

    /// A stranger sends `amount` of the mint straight into the vault's token account with a plain
    /// SPL transfer, which nobody can stop.
    fn donate(&mut self, amount: u64) {
        let stranger = self.keys.key(Who::Stranger);
        let from = get_associated_token_address(&stranger, &self.mint);
        if self.svm.get_account(&from).is_none() {
            set_token_account(&mut self.svm, from, self.mint, stranger, TOTAL);
        }
        let ix = spl_token::instruction::transfer(
            &token::ID,
            &from,
            &self.vault,
            &stranger,
            &[],
            amount,
        )
        .unwrap();
        ok(self.send(ix, &[Who::Stranger]), "a donation into the vault");
    }

    /// Permissionless: only the fee payer signs (and pays refund_to's token account rent).
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn refund(&mut self) -> TransactionResult {
        let ix = instruction(
            accts::Refund {
                payer: self.keys.payer.pubkey(),
                escrow: self.escrow,
                mint: self.mint,
                vault: self.vault,
                refund_to: self.refund_to,
                refund_to_token_account: self.refund_to_ata(),
                resolver: self.keys.key(Who::Resolver),
                token_program: token::ID,
                associated_token_program: associated_token::ID,
                system_program: system_program::ID,
                config: config_pda(),
                destination: None,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Refund {},
        );
        self.send(ix, &[])
    }
}

// ------------------------------------------------------------------------------ open_escrow

#[test]
fn open_escrow_funds_the_vault_and_stores_the_terms() {
    let mut lc = Lc::new();
    let meta = ok(lc.open(), "open_escrow");

    assert_eq!(lc.tokens(&lc.vault), TOTAL);
    assert_eq!(lc.tokens(&lc.sponsor_ata), 3 * TOTAL);

    let (escrow, escrow_bump) = escrow_pda_and_bump(&lc.keys.key(Who::Sponsor), &CID);
    assert_eq!(escrow, lc.escrow);
    let mut regraders = [Pubkey::default(); 5];
    for (slot, kp) in regraders.iter_mut().zip(&lc.keys.regraders) {
        *slot = kp.pubkey();
    }
    assert_eq!(
        lc.state(),
        Escrow {
            bump: escrow_bump,
            decimals: DECIMALS,
            status: EscrowStatus::Open,
            k: 2,
            n: 3,
            competition_id: CID,
            sponsor: lc.keys.key(Who::Sponsor),
            resolver: lc.keys.key(Who::Resolver),
            compliance: lc.compliance,
            arbiter: lc.keys.key(Who::Arbiter),
            refund_to: lc.refund_to,
            mint: lc.mint,
            challenger: Pubkey::default(),
            rules_sha256: RULES,
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
            total: TOTAL,
            total_claimed: 0,
            alt_total: 0,
            bond_lamports: BOND,
            resolver_bond: 0,
            challenger_bond: 0,
            entries_deadline: ENTRIES_DEADLINE,
            final_end: FINAL_END,
            resolve_deadline: RESOLVE_DEADLINE,
            challenge_window: MIN_CHALLENGE_WINDOW,
            attest_window: MIN_ATTEST_WINDOW,
            hold_window: MIN_HOLD_WINDOW,
            claim_window: CLAIM_WINDOW,
            challenge_deadline: 0,
            attest_deadline: 0,
            claim_deadline: 0,
            hard_deadline: HARD_DEADLINE,
            votes_result: 0,
            votes_alt: 0,
            regraders,
            deposited: TOTAL,
            stop_base: 0,
            freeze_since: 0,
            freeze_until: 0,
            frozen_secs: 0,
            reveal_grace: prize_escrow::MIN_REVEAL_GRACE,
            commit_bond: 0,
            pending_commits: 0,
            reserved: [0; 64],
        }
    );
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent());

    let opened = event::<EscrowOpened>(&meta);
    assert_eq!(opened.escrow, lc.escrow);
    assert_eq!(opened.competition_id, CID);
    assert_eq!(opened.sponsor, lc.keys.key(Who::Sponsor));
    assert_eq!(opened.mint, lc.mint);
    assert_eq!(opened.decimals, DECIMALS);
    assert_eq!(opened.total, TOTAL);
    assert_eq!(opened.rules_sha256, RULES);
    assert_eq!(opened.regraders, lc.terms.regraders);
    assert_eq!((opened.k, opened.bond_lamports), (2, BOND));
    assert_eq!(opened.challenge_window, 24 * HOUR);
    assert_eq!(
        (
            opened.entries_deadline,
            opened.final_end,
            opened.resolve_deadline
        ),
        (ENTRIES_DEADLINE, FINAL_END, RESOLVE_DEADLINE)
    );
    assert_eq!(opened.hard_deadline, HARD_DEADLINE);

    // The replay marker: the competition id's PDA exists for good, so it cannot be opened again.
    let before = lc.state();
    let again = lc.open();
    assert_refused(
        again,
        0u32,
        "a second open_escrow of the same competition id",
    );
    assert_eq!(lc.state(), before);
    assert_eq!(lc.tokens(&lc.vault), TOTAL);
}

#[test]
fn open_escrow_refuses_terms_outside_the_bounds() {
    type Edit = fn(&mut EscrowTerms);
    // The bond floor is BOND_FLOOR_RENTS rent-exempt minimums of an empty account, read from
    // the cluster's Rent sysvar: 2 x 650,240 lamports at mainnet's rent (tests/mainnet/
    // features.json: 5,080 lamports a byte since SIMD-0437's set_lamports_per_byte_to_5080; the
    // 6,960 before it made 2 x 890,880).
    const FLOOR: u64 = 2 * 650_240;
    let mut lc = Lc::new();
    let floor = BOND_FLOOR_RENTS * lc.svm.minimum_balance_for_rent_exemption(0);
    assert_eq!(
        floor, FLOOR,
        "mainnet's rent moved (tests/mainnet/features.json): restate FLOOR"
    );
    let cases: [(&str, Edit, EscrowError); 11] = [
        (
            "an entries deadline that is not in the future",
            |t| t.entries_deadline = NOW,
            EscrowError::InvalidDeadlines,
        ),
        (
            "a final end before the entries deadline",
            |t| t.final_end = t.entries_deadline - 1,
            EscrowError::InvalidDeadlines,
        ),
        (
            "a final end at the resolve deadline",
            |t| t.final_end = t.resolve_deadline,
            EscrowError::InvalidDeadlines,
        ),
        (
            "a hard deadline before the resolve deadline",
            |t| t.hard_deadline = t.resolve_deadline - 1,
            EscrowError::HardDeadlineTooEarly,
        ),
        (
            "a hard deadline a second short of every window and the arbiter slack",
            |t| {
                t.hard_deadline = t.resolve_deadline
                    + t.challenge_window
                    + t.attest_window
                    + t.hold_window
                    + t.claim_window
                    + ARBITER_SLACK
                    - 1;
            },
            EscrowError::HardDeadlineTooEarly,
        ),
        (
            "with a compliance key, a hold window as long as the claim window",
            |t| t.hold_window = t.claim_window,
            EscrowError::ClaimWindowTooShort,
        ),
        (
            "1-of-3, where 2k > n fails",
            |t| t.k = 1,
            EscrowError::InvalidRegraderSet,
        ),
        (
            "a challenge window one second short of 24 h",
            |t| t.challenge_window = 24 * HOUR - 1,
            EscrowError::InvalidWindow,
        ),
        ("a zero total", |t| t.total = 0, EscrowError::InvalidAmount),
        // Run review 4: a 1 s claim window was accepted, so refund could sweep the prizes a
        // second after the result became claimable.
        (
            "a claim window one second short of 7 days",
            |t| t.claim_window = 7 * DAY - 1,
            EscrowError::InvalidWindow,
        ),
        // Run review 4: any bond above zero was accepted, so a lamport bought a challenge.
        (
            "a bond a lamport under twice the rent-exempt minimum of an empty account",
            |t| t.bond_lamports = FLOOR - 1,
            EscrowError::BondBelowFloor,
        ),
    ];
    for (what, edit, want) in cases {
        let mut terms = lc.terms.clone();
        edit(&mut terms);
        let ix = lc.open_ix(&terms);
        let r = lc.send(ix, &[Who::Sponsor]);
        assert_refused(r, want, what);
        assert!(
            lc.svm.get_account(&lc.escrow).is_none(),
            "{what}: no escrow"
        );
    }
    assert_eq!(lc.tokens(&lc.sponsor_ata), 4 * TOTAL);

    // The edges hold: final_end may equal the entries deadline (an escrow for a single-phase
    // competition), the hard deadline may be exactly the minimum, the claim window exactly
    // MIN_CLAIM_WINDOW, the hold window one second shorter (a compliance key is required, so the
    // claim window outlasts it) and the bond exactly the floor.
    let mut edge = lc.terms.clone();
    edge.final_end = edge.entries_deadline;
    edge.claim_window = MIN_CLAIM_WINDOW;
    edge.hold_window = MIN_CLAIM_WINDOW - 1;
    edge.bond_lamports = floor;
    edge.hard_deadline = edge.resolve_deadline
        + edge.challenge_window
        + edge.attest_window
        + edge.hold_window
        + edge.claim_window
        + ARBITER_SLACK;
    let ix = lc.open_ix(&edge);
    ok(lc.send(ix, &[Who::Sponsor]), "open_escrow on the edges");
    let state = lc.state();
    assert_eq!(
        (state.final_end, state.hard_deadline, state.claim_window),
        (edge.final_end, edge.hard_deadline, 7 * DAY)
    );
    assert_eq!(state.bond_lamports, floor);
}

#[test]
fn two_sponsors_open_the_same_competition_id_each_at_its_own_address() {
    // Finding 4 of run review 3: with ["escrow", competition_id] alone, whoever opened first owned
    // the competition's address. The sponsor is in the seeds now, so a squatter's open for the
    // same id lands at the squatter's own address and leaves the sponsor's free.
    let mut lc = Lc::new();
    let squatter = lc.keys.key(Who::Stranger);
    let squat = escrow_pda(&squatter, &CID);
    assert_ne!(squat, lc.escrow);
    let squatter_ata = get_associated_token_address(&squatter, &lc.mint);
    set_token_account(&mut lc.svm, squatter_ata, lc.mint, squatter, TOTAL);
    // The squatter is an allowed sponsor too, its refunds its own (the open policy).
    let mut squatter_terms = lc.terms.clone();
    squatter_terms.refund_to = squatter;
    let mut ix = lc.open_ix(&squatter_terms);
    ix.accounts[0].pubkey = squatter;
    ix.accounts[1].pubkey = squat;
    ix.accounts[3].pubkey = squatter_ata;
    ix.accounts[4].pubkey = get_associated_token_address(&squat, &lc.mint);
    ok(lc.send(ix, &[Who::Stranger]), "the squatter's open");
    assert!(lc.svm.get_account(&lc.escrow).is_none());

    // The sponsor opens its own; a PDA of another sponsor (or the old seeds) is refused.
    let mut ix = lc.open_ix(&lc.terms);
    ix.accounts[1].pubkey = squat;
    ix.accounts[4].pubkey = get_associated_token_address(&squat, &lc.mint);
    let r = lc.send(ix, &[Who::Sponsor]);
    assert_refused(
        r,
        AnchorErrorCode::ConstraintSeeds,
        "open_escrow at the squatter's address",
    );
    let old_seeds = Pubkey::find_program_address(&[ESCROW_SEED, &CID], &prize_escrow::ID).0;
    let mut ix = lc.open_ix(&lc.terms);
    ix.accounts[1].pubkey = old_seeds;
    ix.accounts[4].pubkey = get_associated_token_address(&old_seeds, &lc.mint);
    let r = lc.send(ix, &[Who::Sponsor]);
    assert_refused(
        r,
        AnchorErrorCode::ConstraintSeeds,
        "open_escrow at [\"escrow\", competition_id]",
    );
    ok(
        lc.open(),
        "the sponsor's own open of the same competition id",
    );
    let state = lc.state();
    assert_eq!(
        (state.sponsor, state.competition_id),
        (lc.keys.key(Who::Sponsor), CID)
    );
    assert_eq!(lc.tokens(&lc.vault), TOTAL);
}

#[test]
fn open_escrow_takes_the_classic_token_program_only() {
    let token_2022: Pubkey = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        .parse()
        .unwrap();
    let mut lc = Lc::new();

    // A Token-2022 mint (the only kind that can carry a transfer hook or a transfer fee).
    let hooked_mint = Pubkey::new_unique();
    set_mint(&mut lc.svm, hooked_mint, token_2022);
    let mut ix = lc.open_ix(&lc.terms);
    ix.accounts[2].pubkey = hooked_mint;
    let r = lc.send(ix, &[Who::Sponsor]);
    assert_refused(
        r,
        AnchorErrorCode::AccountOwnedByWrongProgram,
        "open_escrow with a Token-2022 mint",
    );

    // The Token-2022 program in the token program slot.
    let mut ix = lc.open_ix(&lc.terms);
    ix.accounts[5].pubkey = token_2022;
    let r = lc.send(ix, &[Who::Sponsor]);
    assert_refused(
        r,
        AnchorErrorCode::InvalidProgramId,
        "open_escrow through the Token-2022 program",
    );

    assert!(lc.svm.get_account(&lc.escrow).is_none());
    assert_eq!(lc.tokens(&lc.sponsor_ata), 4 * TOTAL);
}

#[test]
fn open_escrow_accepts_a_vault_created_ahead_and_post_result_takes_up_to_what_it_holds() {
    let mut lc = Lc::new();
    // Anyone can create the escrow's associated token account first (here holding a 7-unit
    // donation); init_if_needed means it cannot block the open.
    set_token_account(&mut lc.svm, lc.vault, lc.mint, lc.escrow, 7);
    ok(lc.open(), "open_escrow over an existing vault");
    assert_eq!(lc.tokens(&lc.vault), TOTAL + 7);
    assert_eq!(lc.state().total, TOTAL, "the opened total is the deposit");
    ok(lc.commit(Who::Resolver, ENTRIES_ROOT, 12), "commit_entries");

    lc.at(POST_AT);
    let r = lc.post(Who::Resolver, TOTAL + 8);
    assert_refused(
        r,
        EscrowError::TotalMismatch,
        "post_result of more than the vault holds",
    );
    let r = lc.post(Who::Resolver, 0);
    assert_refused(r, EscrowError::TotalMismatch, "post_result of a zero total");
    ok(
        lc.post(Who::Resolver, TOTAL + 7),
        "post_result of the whole vault",
    );
    assert_eq!(lc.state().total, TOTAL + 7);
}

#[test]
fn a_donation_into_the_vault_never_blocks_post_result_or_arbiter_resolve() {
    // Finding 2 of run review 3: post_result and arbiter_resolve required total == vault, and
    // anyone can transfer into the vault's token account, so one unit sent there made every post
    // fail and broke a pending arbiter proposal. Now 0 < total <= vault (for the posted result and
    // the alternative alike), claims stay capped by the total, and the refund after the claim
    // deadline sweeps leftovers and donations alike.
    let mut lc = Lc::committed();
    lc.donate(1);
    assert_eq!(lc.tokens(&lc.vault), TOTAL + 1);
    lc.at(POST_AT);
    ok(
        lc.post(Who::Resolver, TOTAL),
        "post_result of the pot after a donation",
    );
    assert_eq!(lc.state().total, TOTAL);

    // An alternative may take the whole vault, donation included, never more: a quorum for it
    // applies it as it stands, so the vault must cover it from the challenge on.
    lc.at(CHALLENGE_AT);
    let r = lc.challenge_with(Who::Challenger, ALT, ALT_ROOT, TOTAL + 2);
    assert_refused(
        r,
        EscrowError::TotalMismatch,
        "an alternative of more than the vault holds",
    );
    ok(
        lc.challenge_with(Who::Challenger, ALT, ALT_ROOT, TOTAL + 1),
        "an alternative of the whole vault",
    );

    // No quorum, so Frozen; the arbiter's proposal (the alternative) then meets a second
    // donation before it executes.
    ok(
        lc.attest(Who::Regrader(0), posted_commitment()),
        "a vote for the result",
    );
    ok(
        lc.attest(
            Who::Regrader(1),
            result_commitment(&ALT, &ALT_ROOT, TOTAL + 1),
        ),
        "a vote for the alternative",
    );
    lc.at(ATTEST_DEADLINE);
    ok(lc.settle(true), "settle with no quorum");
    assert_eq!(lc.state().status, EscrowStatus::Frozen);
    lc.donate(1);
    let resolve_at = ATTEST_DEADLINE + DAY;
    lc.at(resolve_at);
    let whole_vault = result_commitment(&ALT, &ALT_ROOT, TOTAL + 1);
    let ix = lc.arbiter_resolve_with_ix(
        Who::Arbiter,
        ArbiterChoice::Alternative,
        whole_vault,
        Some((lc.challenge_pda(&whole_vault), lc.keys.key(Who::Challenger))),
    );
    ok(
        lc.send(ix, &[Who::Arbiter]),
        "arbiter_resolve after a donation",
    );
    let state = lc.state();
    assert_eq!(state.status, EscrowStatus::Claimable);
    assert_eq!(state.total, TOTAL + 1);

    // Nobody claims; after the claim deadline the whole vault (the pot and both donations) goes
    // to refund_to.
    lc.at(resolve_at + CLAIM_WINDOW + 1);
    let meta = ok(lc.refund(), "refund after the claim deadline");
    assert_eq!(lc.tokens(&lc.refund_to_ata()), TOTAL + 2);
    assert_eq!(event::<Refunded>(&meta).amount, TOTAL + 2);
}

// ------------------------------------------------------------------------------------- fund

#[test]
fn fund_tops_up_the_vault_while_open_and_only_from_the_sponsor() {
    let mut lc = Lc::committed();

    let meta = ok(lc.fund(Who::Sponsor, 1_250_000), "fund");
    assert_eq!(lc.tokens(&lc.vault), TOTAL + 1_250_000);
    assert_eq!(lc.tokens(&lc.sponsor_ata), 3 * TOTAL - 1_250_000);
    assert_eq!(
        lc.state().total,
        TOTAL,
        "post_result, not fund, fixes the total"
    );
    let funded = event::<EscrowFunded>(&meta);
    assert_eq!(
        (
            funded.escrow,
            funded.sponsor,
            funded.amount,
            funded.vault_balance
        ),
        (
            lc.escrow,
            lc.keys.key(Who::Sponsor),
            1_250_000,
            TOTAL + 1_250_000
        )
    );

    let r = lc.fund(Who::Sponsor, 0);
    assert_refused(r, EscrowError::InvalidAmount, "fund of zero");
    let r = lc.fund(Who::Stranger, 1);
    assert_refused(r, EscrowError::UnauthorizedSponsor, "fund by a stranger");

    lc.at(POST_AT);
    ok(lc.post(Who::Resolver, TOTAL + 1_250_000), "post_result");
    let r = lc.fund(Who::Sponsor, 1);
    assert_refused(r, EscrowError::InvalidStatus, "fund after the result");
    assert_eq!(lc.tokens(&lc.vault), TOTAL + 1_250_000);
}

// --------------------------------------------------------------------------- commit_entries

#[test]
fn commit_entries_lands_once_before_the_entries_deadline() {
    let mut lc = Lc::opened();

    let r = lc.commit(Who::Stranger, ENTRIES_ROOT, 12);
    assert_refused(r, EscrowError::UnauthorizedResolver, "commit by a stranger");
    let r = lc.commit(Who::Resolver, [0; 32], 12);
    assert_refused(
        r,
        EscrowError::InvalidResultHash,
        "commit of an all-zero root",
    );

    lc.at(ENTRIES_DEADLINE - 1);
    let meta = ok(lc.commit(Who::Resolver, ENTRIES_ROOT, 12), "commit_entries");
    let state = lc.state();
    assert_eq!(
        (state.entries_root, state.entries_count),
        (ENTRIES_ROOT, 12)
    );
    assert_eq!(state.status, EscrowStatus::Open);
    let committed = event::<EntriesCommitted>(&meta);
    assert_eq!(
        (
            committed.escrow,
            committed.entries_root,
            committed.entries_count
        ),
        (lc.escrow, ENTRIES_ROOT, 12)
    );

    let r = lc.commit(Who::Resolver, [0x77; 32], 13);
    assert_refused(r, EscrowError::EntriesAlreadyCommitted, "a second commit");
    assert_eq!(lc.state().entries_root, ENTRIES_ROOT);

    // Once the result is posted the escrow is no longer Open.
    lc.at(POST_AT);
    ok(lc.post(Who::Resolver, TOTAL), "post_result");
    lc.at(ENTRIES_DEADLINE - 1);
    let r = lc.commit(Who::Resolver, [0x77; 32], 12);
    assert_refused(r, EscrowError::InvalidStatus, "commit after the result");

    // At the deadline, on an escrow that never committed.
    let mut late = Lc::opened();
    late.at(ENTRIES_DEADLINE);
    let r = late.commit(Who::Resolver, ENTRIES_ROOT, 12);
    assert_refused(
        r,
        EscrowError::EntriesWindowClosed,
        "commit at the entries deadline",
    );
}

// ------------------------------------------------------------------------------ post_result

#[test]
fn post_result_holds_the_total_to_the_vault_and_takes_the_bond() {
    let mut lc = Lc::committed();
    lc.at(RESOLVE_DEADLINE - 1);

    let r = lc.post(Who::Stranger, TOTAL);
    assert_refused(
        r,
        EscrowError::UnauthorizedResolver,
        "post_result by a stranger",
    );
    for total in [0, TOTAL + 1] {
        let r = lc.post(Who::Resolver, total);
        assert_refused(
            r,
            EscrowError::TotalMismatch,
            "a zero total, or more than the vault holds",
        );
    }
    let r = lc.post_with(Who::Resolver, [0; 32], RESULT, TOTAL);
    assert_refused(r, EscrowError::InvalidResultHash, "an all-zero payout root");
    let r = lc.post_with(Who::Resolver, PAYOUT_ROOT, [0; 32], TOTAL);
    assert_refused(r, EscrowError::InvalidResultHash, "an all-zero result hash");

    let resolver_before = lc.lamports(&lc.keys.key(Who::Resolver));
    let now = RESOLVE_DEADLINE - 1;
    let meta = ok(
        lc.post(Who::Resolver, TOTAL),
        "post_result on the last second",
    );
    assert_eq!(
        lc.lamports(&lc.keys.key(Who::Resolver)),
        resolver_before - BOND,
        "the payer pays the fee; the resolver pays exactly the bond"
    );
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent() + BOND);

    let state = lc.state();
    assert_eq!(state.status, EscrowStatus::Challengeable);
    assert_eq!(
        (state.payout_root, state.result_sha256, state.kit_sha256),
        (PAYOUT_ROOT, RESULT, KIT)
    );
    assert_eq!((state.total, state.resolver_bond), (TOTAL, BOND));
    assert_eq!(state.commitment, posted_commitment());
    assert_eq!(state.challenge_deadline, now + 24 * HOUR);
    assert_eq!(state.entries_root, ENTRIES_ROOT);

    let posted = event::<ResultPosted>(&meta);
    assert_eq!(posted.escrow, lc.escrow);
    assert_eq!(posted.resolver, lc.keys.key(Who::Resolver));
    assert_eq!(
        (posted.payout_root, posted.result_sha256, posted.kit_sha256),
        (PAYOUT_ROOT, RESULT, KIT)
    );
    assert_eq!((posted.total, posted.resolver_bond), (TOTAL, BOND));
    assert_eq!(posted.commitment, posted_commitment());
    assert_eq!(posted.challenge_deadline, now + 24 * HOUR);

    let r = lc.post(Who::Resolver, TOTAL);
    assert_refused(r, EscrowError::InvalidStatus, "a second post_result");

    let mut late = Lc::committed();
    late.at(RESOLVE_DEADLINE);
    let r = late.post(Who::Resolver, TOTAL);
    assert_refused(
        r,
        EscrowError::ResolveWindowClosed,
        "post_result at the resolve deadline",
    );
}

#[test]
fn post_result_waits_for_the_final_end_and_the_entries_root() {
    // Finding 4 of run review 3: post_result took a result before the competition's final
    // phase had ended, and with no entries root committed.
    let mut lc = Lc::committed();
    lc.at(FINAL_END - 1);
    let r = lc.post(Who::Resolver, TOTAL);
    assert_refused(
        r,
        EscrowError::FinalNotEnded,
        "post_result a second before the final end",
    );
    lc.at(FINAL_END);
    ok(
        lc.post(Who::Resolver, TOTAL),
        "post_result at the final end",
    );

    // Never committed: no result can be posted, and once entries closed only the refund at the
    // resolve deadline is left.
    let mut uncommitted = Lc::opened();
    uncommitted.at(FINAL_END);
    let r = uncommitted.post(Who::Resolver, TOTAL);
    assert_refused(
        r,
        EscrowError::EntriesNotCommitted,
        "post_result with no entries root",
    );
    assert_eq!(uncommitted.state().status, EscrowStatus::Open);
    uncommitted.at(RESOLVE_DEADLINE);
    ok(uncommitted.refund(), "the refund at the resolve deadline");
    assert_eq!(uncommitted.tokens(&uncommitted.refund_to_ata()), TOTAL);
}

// ------------------------------------------------------------- settle: the undisputed path

#[test]
fn an_unchallenged_result_becomes_claimable_after_the_24_hour_window() {
    let mut lc = Lc::committed();
    let resolver_before = lc.lamports(&lc.keys.key(Who::Resolver));
    lc.at(POST_AT);
    ok(lc.post(Who::Resolver, TOTAL), "post_result");
    let window_end = POST_AT + 24 * HOUR;
    assert_eq!(lc.state().challenge_deadline, window_end);

    lc.at(window_end - 1);
    let r = lc.settle(false);
    assert_refused(
        r,
        EscrowError::DeadlineNotReached,
        "settle inside the window",
    );
    let r = lc.attest(Who::Regrader(0), posted_commitment());
    assert_refused(r, EscrowError::InvalidStatus, "attest without a dispute");

    lc.at(window_end);
    let r = lc.challenge(Who::Challenger, ALT);
    assert_refused(
        r,
        EscrowError::ChallengeWindowClosed,
        "challenge at the deadline",
    );

    let meta = ok(lc.settle(false), "settle at the deadline");
    assert_eq!(lc.lamports(&lc.keys.key(Who::Resolver)), resolver_before);
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent());
    let state = lc.state();
    assert_eq!(state.status, EscrowStatus::Claimable);
    assert_eq!(state.resolver_bond, 0);
    assert_eq!(state.claim_deadline, window_end + CLAIM_WINDOW);
    assert_eq!(lc.tokens(&lc.vault), TOTAL);

    let settled = event::<Settled>(&meta);
    assert_eq!(settled.escrow, lc.escrow);
    assert_eq!(settled.outcome, SettleOutcome::Undisputed);
    assert_eq!(settled.status, EscrowStatus::Claimable);
    assert_eq!(settled.claim_deadline, window_end + CLAIM_WINDOW);
    assert_eq!(
        (settled.result_sha256, settled.payout_root, settled.total),
        (RESULT, PAYOUT_ROOT, TOTAL)
    );
    assert_eq!(settled.commitment, posted_commitment());
    assert_eq!((settled.resolver_paid, settled.challenger_paid), (BOND, 0));

    let r = lc.settle(false);
    assert_refused(r, EscrowError::InvalidStatus, "a second settle");
    let r = lc.challenge(Who::Challenger, ALT);
    assert_refused(r, EscrowError::InvalidStatus, "challenge once Claimable");
    // Never disputed: choosing the posted result needs no challenge account, and the handler
    // refuses an escrow that is not Frozen.
    let r = lc.arbiter_resolve(Who::Arbiter, ArbiterChoice::Posted);
    assert_refused(
        r,
        EscrowError::InvalidStatus,
        "arbiter_resolve of an escrow never disputed",
    );
}

#[test]
fn settle_refuses_an_open_escrow() {
    let mut lc = Lc::opened();
    lc.at(HARD_DEADLINE + 1);
    let r = lc.settle(false);
    assert_refused(r, EscrowError::InvalidStatus, "settle before any result");
}

// ------------------------------------------------------------------------------- challenge

#[test]
fn challenge_bonds_an_alternative_and_opens_the_24_hour_attestation_window() {
    let mut lc = Lc::posted();
    let last_second = POST_AT + 24 * HOUR - 1;
    lc.at(last_second);

    let r = lc.challenge_committing(Who::Challenger, ALT, ALT_ROOT, TOTAL, junk_commitment());
    assert_refused(
        r,
        EscrowError::InvalidResultHash,
        "a challenge naming another alternative's commitment (its PDA's seed)",
    );
    let r = lc.challenge_with(Who::Challenger, RESULT, PAYOUT_ROOT, TOTAL);
    assert_refused(
        r,
        EscrowError::InvalidResultHash,
        "an alternative committing to the posted result",
    );
    let r = lc.challenge(Who::Challenger, [0; 32]);
    assert_refused(r, EscrowError::InvalidResultHash, "an all-zero alternative");
    let r = lc.challenge_with(Who::Challenger, ALT, [0; 32], TOTAL);
    assert_refused(
        r,
        EscrowError::InvalidResultHash,
        "an alternative with an all-zero root",
    );
    let r = lc.challenge_with(Who::Challenger, ALT, ALT_ROOT, 0);
    assert_refused(
        r,
        EscrowError::InvalidAmount,
        "an alternative with a zero total",
    );
    let r = lc.challenge_with(Who::Challenger, ALT, ALT_ROOT, TOTAL + 1);
    assert_refused(
        r,
        EscrowError::TotalMismatch,
        "an alternative of more than the vault holds (a quorum could not apply it)",
    );

    // Each reveal refused above left its commit: its bond is held apart (commit_bond) for
    // close_commit to return once the escrow decides, never a challenge's.
    let refused = lc.state();
    assert!(refused.pending_commits > 0);
    let held = u64::from(refused.pending_commits) * BOND;
    assert_eq!((refused.commit_bond, refused.challenger_bond), (held, 0));
    let challenger_before = lc.lamports(&lc.keys.key(Who::Challenger));
    let meta = ok(
        lc.challenge(Who::Challenger, ALT),
        "challenge on the last second",
    );
    assert_eq!(
        lc.lamports(&lc.keys.key(Who::Challenger)),
        challenger_before - BOND - lc.challenge_rent(),
        "its bond and its Challenge account's rent (the commit's rent came back at the reveal)"
    );
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent() + 2 * BOND + held);
    let state = lc.state();
    assert_eq!(state.status, EscrowStatus::Disputed);
    assert_eq!(state.challenge_count, 1);
    assert_eq!(
        (state.challenger, state.alt_commitment),
        (Pubkey::default(), [0; 32]),
        "no alternative has won yet"
    );
    assert_eq!(
        state.commitment,
        posted_commitment(),
        "the posted result stands"
    );
    assert_eq!((state.resolver_bond, state.challenger_bond), (BOND, BOND));
    assert_eq!(state.attest_deadline, ATTEST_DEADLINE);
    let challenge = lc
        .challenge_state(&alt_commitment())
        .expect("the Challenge PDA exists");
    let pda = lc.challenge_pda(&alt_commitment());
    assert_eq!(lc.svm.get_account(&pda).unwrap().owner, prize_escrow::ID);
    assert_eq!(
        challenge,
        ChallengeRecord {
            escrow: lc.escrow,
            challenger: lc.keys.key(Who::Challenger),
            alt_result_sha256: ALT,
            alt_payout_root: ALT_ROOT,
            alt_commitment: alt_commitment(),
            alt_total: TOTAL,
            bond: BOND,
            opened_at: last_second,
            index: 0,
            votes: 0,
            bump: Pubkey::find_program_address(
                &[CHALLENGE_SEED, lc.escrow.as_ref(), &alt_commitment()],
                &prize_escrow::ID
            )
            .1,
        }
    );

    let challenged = event::<Challenged>(&meta);
    assert_eq!(challenged.escrow, lc.escrow);
    assert_eq!(challenged.challenge, pda);
    assert_eq!((challenged.index, challenged.challenge_count), (0, 1));
    assert_eq!(challenged.challenger, lc.keys.key(Who::Challenger));
    assert_eq!(
        (challenged.commitment, challenged.alt_commitment),
        (posted_commitment(), alt_commitment())
    );
    assert_eq!(
        (
            challenged.alt_result_sha256,
            challenged.alt_payout_root,
            challenged.alt_total
        ),
        (ALT, ALT_ROOT, TOTAL)
    );
    assert_eq!(challenged.challenger_bond, BOND);
    assert_eq!(challenged.attest_deadline, ATTEST_DEADLINE);

    let r = lc.challenge(Who::Stranger, ALT);
    assert_refused(
        r,
        0u32,
        "a second challenge of the same commitment (its PDA is in use)",
    );
    lc.at(last_second + 1);
    let r = lc.challenge(Who::Stranger, [0x99; 32]);
    assert_refused(
        r,
        EscrowError::ChallengeWindowClosed,
        "a challenge at the challenge deadline",
    );
    // The refused reveals' commits could still be revealed until the grace ends.
    let r = lc.settle(true);
    assert_refused(
        r,
        EscrowError::CommitsPendingReveal,
        "settle inside the reveal grace",
    );
    lc.at(last_second + 1 + MIN_REVEAL_GRACE);
    let r = lc.settle(true);
    assert_refused(
        r,
        EscrowError::AttestWindowOpen,
        "settle with no quorum yet",
    );
    let r = lc.fund(Who::Sponsor, 1);
    assert_refused(r, EscrowError::InvalidStatus, "fund during a dispute");
}

// ---------------------------------------------------------------------------------- attest

#[test]
fn attest_counts_each_named_regrader_once_and_leaves_the_status_to_settle() {
    let mut lc = Lc::disputed();
    let attest_deadline = ATTEST_DEADLINE;
    assert_eq!(lc.state().attest_deadline, attest_deadline);

    let r = lc.attest(Who::Stranger, posted_commitment());
    assert_refused(r, EscrowError::NotARegrader, "attest by someone not named");
    let r = lc.attest(Who::Regrader(0), [0x99; 32]);
    assert_refused(
        r,
        EscrowError::InvalidResultHash,
        "attest to a third commitment",
    );
    let r = lc.attest_with(Who::Regrader(0), alt_commitment(), None);
    assert_refused(
        r,
        EscrowError::InvalidResultHash,
        "attest to a challenge's commitment without its Challenge PDA",
    );

    // Votes name commitments: the bare document hash of either side is neither.
    for hash in [RESULT, ALT] {
        let r = lc.attest(Who::Regrader(0), hash);
        assert_refused(
            r,
            EscrowError::InvalidResultHash,
            "attest to a bare result hash",
        );
    }

    // A vote for the posted result takes no challenge account: the constraints pin one passed in
    // to the vote's commitment, which no challenge commits to (#552).
    let challenge = Some(lc.challenge_pda(&alt_commitment()));
    let r = lc.attest_with(Who::Regrader(0), posted_commitment(), challenge);
    assert_refused(
        r,
        EscrowError::ChallengeMismatch,
        "attest to the result with a challenge account riding along",
    );
    assert_eq!(lc.state().votes_result, 0);
    let meta = ok(
        lc.attest_with(Who::Regrader(0), posted_commitment(), None),
        "attest to the result",
    );
    assert_eq!(lc.challenge_state(&alt_commitment()).unwrap().votes, 0);
    let regrader0 = lc.keys.key(Who::Regrader(0));
    let account = lc
        .svm
        .get_account(&attestation_pda(&lc.escrow, &regrader0))
        .expect("the attestation exists");
    assert_eq!(account.owner, prize_escrow::ID);
    let attestation = Attestation::try_deserialize(&mut account.data.as_slice()).unwrap();
    assert_eq!(
        attestation,
        Attestation {
            regrader: regrader0,
            commitment: posted_commitment(),
            side: AttestSide::Result,
            bump: attestation_bump(&lc.escrow, &regrader0),
        }
    );
    let state = lc.state();
    assert_eq!((state.votes_result, state.votes_alt), (1, 0));
    assert_eq!(state.status, EscrowStatus::Disputed);
    let attested = event::<Attested>(&meta);
    assert_eq!((attested.escrow, attested.regrader), (lc.escrow, regrader0));
    assert_eq!(
        (attested.commitment, attested.side),
        (posted_commitment(), AttestSide::Result)
    );
    assert_eq!((attested.votes_result, attested.votes_alt), (1, 0));
    assert_eq!(
        (attested.challenge, attested.votes, attested.quorum),
        (Pubkey::default(), 1, false)
    );

    // A second vote finds the regrader's attestation account already in use.
    let r = lc.attest(Who::Regrader(0), alt_commitment());
    assert_refused(r, 0u32, "a second vote by the same regrader");
    assert_eq!(lc.state().votes_alt, 0);

    lc.at(attest_deadline - 1);
    let meta = ok(
        lc.attest(Who::Regrader(1), alt_commitment()),
        "attest to the alternative",
    );
    let attested = event::<Attested>(&meta);
    assert_eq!(attested.side, AttestSide::Alt);
    assert_eq!(
        (attested.challenge, attested.votes, attested.quorum),
        (lc.challenge_pda(&alt_commitment()), 1, false)
    );
    let state = lc.state();
    assert_eq!((state.votes_result, state.votes_alt), (1, 1));
    assert_eq!(state.status, EscrowStatus::Disputed);
    assert_eq!(lc.challenge_state(&alt_commitment()).unwrap().votes, 1);

    lc.at(attest_deadline);
    let r = lc.attest(Who::Regrader(2), posted_commitment());
    assert_refused(r, EscrowError::AttestWindowClosed, "attest at the deadline");
}

// ------------------------------------------------------------------- settle: the disputes

#[test]
fn the_posted_results_quorum_makes_it_claimable_and_the_resolver_takes_the_challengers_bond() {
    // Run review 4: a forfeited bond was split with refund_to. The side that won takes it whole.
    let mut lc = Lc::committed();
    let resolver_start = lc.lamports(&lc.keys.key(Who::Resolver));
    let challenger_start = lc.lamports(&lc.keys.key(Who::Challenger));
    lc.at(POST_AT);
    ok(lc.post(Who::Resolver, TOTAL), "post_result");
    lc.at(CHALLENGE_AT);
    ok(lc.challenge(Who::Challenger, ALT), "challenge");

    ok(
        lc.attest(Who::Regrader(0), posted_commitment()),
        "first vote",
    );
    let r = lc.settle(true);
    assert_refused(
        r,
        EscrowError::DeadlineNotReached,
        "settle at 1 of k = 2 inside the challenge window",
    );
    ok(
        lc.attest(Who::Regrader(2), posted_commitment()),
        "second vote",
    );

    // Run review 5 (F1): a quorum inside the challenge window settles nothing yet. A junk
    // self-challenge the regraders answered at once must not cut the 24 h window short for the
    // challenger who has not spoken yet.
    lc.at(CHALLENGE_AT + HOUR);
    let r = lc.settle(false);
    assert_refused(
        r,
        EscrowError::DeadlineNotReached,
        "settle at quorum before the challenge deadline",
    );
    lc.at(CHALLENGE_DEADLINE - 1);
    let r = lc.settle(false);
    assert_refused(
        r,
        EscrowError::DeadlineNotReached,
        "settle at quorum on the window's last second",
    );

    // At the challenge deadline the quorum settles at once: no need to wait for attest_deadline.
    // Nothing is paid to the challenger, so its account may stay out.
    lc.at(CHALLENGE_DEADLINE);
    let meta = ok(lc.settle(false), "settle without the challenger's account");
    assert_eq!(
        lc.lamports(&lc.keys.key(Who::Resolver)),
        resolver_start + BOND,
        "the resolver's bond back and the challenger's whole bond"
    );
    assert_eq!(lc.refund_to_gain(), 0, "nothing goes to refund_to");
    assert_eq!(
        lc.lamports(&lc.keys.key(Who::Challenger)),
        challenger_start - BOND - lc.challenge_rent(),
        "its bond lost; its Challenge account's rent waits for close_challenge"
    );
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent());

    let state = lc.state();
    assert_eq!(state.status, EscrowStatus::Claimable);
    assert_eq!((state.resolver_bond, state.challenger_bond), (0, 0));
    assert_eq!(state.claim_deadline, CHALLENGE_DEADLINE + CLAIM_WINDOW);
    assert_eq!(
        (state.payout_root, state.result_sha256, state.total),
        (PAYOUT_ROOT, RESULT, TOTAL)
    );
    assert_eq!(state.commitment, posted_commitment());
    let settled = event::<Settled>(&meta);
    assert_eq!(settled.outcome, SettleOutcome::ResultUpheld);
    assert_eq!(settled.status, EscrowStatus::Claimable);
    assert_eq!((settled.votes_result, settled.votes_alt), (2, 0));
    assert_eq!(settled.claim_deadline, state.claim_deadline);
    assert_eq!(
        (settled.payout_root, settled.commitment),
        (PAYOUT_ROOT, posted_commitment())
    );
    assert_eq!(
        (settled.resolver_paid, settled.challenger_paid),
        (2 * BOND, 0)
    );
    assert_eq!(settled.challenger, Pubkey::default());
}

#[test]
fn the_alternatives_quorum_applies_it_and_the_challenger_takes_the_resolvers_bond() {
    // Run review 4: a quorum for the alternative only froze the escrow, so every dispute the
    // challenger won still waited for the house's arbiter, which could then set any result. The
    // vote binds now: settle applies the alternative's root, document hash, total and commitment,
    // and the escrow is Claimable on them.
    let mut lc = Lc::committed();
    let resolver_start = lc.lamports(&lc.keys.key(Who::Resolver));
    let challenger_start = lc.lamports(&lc.keys.key(Who::Challenger));
    lc.at(POST_AT);
    ok(lc.post(Who::Resolver, TOTAL), "post_result");
    lc.at(CHALLENGE_AT);
    let alt_total = TOTAL - 1_000_000;
    let alt = result_commitment(&ALT, &ALT_ROOT, alt_total);
    ok(
        lc.challenge_with(Who::Challenger, ALT, ALT_ROOT, alt_total),
        "challenge",
    );
    ok(lc.attest(Who::Regrader(1), alt), "first vote");
    assert_eq!(lc.state().challenger, Pubkey::default(), "1 of k = 2");
    let meta = ok(lc.attest(Who::Regrader(2), alt), "second vote");
    let attested = event::<Attested>(&meta);
    assert_eq!((attested.votes, attested.quorum), (2, true));
    let state = lc.state();
    assert_eq!(
        (
            state.challenger,
            state.alt_result_sha256,
            state.alt_payout_root,
            state.alt_total,
            state.alt_commitment
        ),
        (lc.keys.key(Who::Challenger), ALT, ALT_ROOT, alt_total, alt),
        "the vote that reaches k records the challenge as the winning alternative"
    );
    assert_eq!(state.status, EscrowStatus::Disputed, "settle applies it");
    let r = lc.settle(true);
    assert_refused(
        r,
        EscrowError::DeadlineNotReached,
        "settle at quorum inside the challenge window",
    );

    // An overturn waits for the attest window's end (#749): the guardian's time to escalate it.
    lc.at(CHALLENGE_DEADLINE);
    let r = lc.settle(true);
    assert_refused(
        r,
        EscrowError::OverturnWindowOpen,
        "the overturn's settle at the challenge deadline",
    );
    lc.at(ATTEST_DEADLINE - 1);
    let r = lc.settle(true);
    assert_refused(
        r,
        EscrowError::OverturnWindowOpen,
        "the overturn's settle on the attest window's last second",
    );
    let settle_at = ATTEST_DEADLINE;
    lc.at(settle_at);
    let r = lc.settle(false);
    assert_refused(
        r,
        AnchorErrorCode::AccountNotEnoughKeys,
        "settle that must pay the challenger without its account",
    );
    let r = lc.arbiter_resolve(Who::Arbiter, ArbiterChoice::Posted);
    assert_refused(
        r,
        EscrowError::InvalidStatus,
        "arbiter_resolve of a Disputed escrow",
    );
    let meta = ok(lc.settle(true), "settle");
    assert_eq!(
        lc.lamports(&lc.keys.key(Who::Challenger)),
        challenger_start + BOND - lc.challenge_rent(),
        "the challenger's bond back and the resolver's whole bond (its Challenge account's rent \
         waits for close_challenge)"
    );
    assert_eq!(
        lc.lamports(&lc.keys.key(Who::Resolver)),
        resolver_start - BOND
    );
    assert_eq!(lc.refund_to_gain(), 0, "nothing goes to refund_to");
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent());

    let state = lc.state();
    assert_eq!(state.status, EscrowStatus::Claimable);
    assert_eq!(
        (state.payout_root, state.result_sha256, state.total),
        (ALT_ROOT, ALT, alt_total)
    );
    assert_eq!(state.commitment, alt);
    assert_eq!(state.kit_sha256, KIT, "the kit hash stays as posted");
    assert_eq!(
        (
            state.alt_payout_root,
            state.alt_result_sha256,
            state.alt_total,
            state.alt_commitment
        ),
        (ALT_ROOT, ALT, alt_total, alt),
        "the alternative stays on record"
    );
    assert_eq!((state.resolver_bond, state.challenger_bond), (0, 0));
    assert_eq!(state.claim_deadline, settle_at + CLAIM_WINDOW);
    let settled = event::<Settled>(&meta);
    assert_eq!(settled.outcome, SettleOutcome::AltApplied);
    assert_eq!(settled.status, EscrowStatus::Claimable);
    assert_eq!((settled.votes_result, settled.votes_alt), (0, 2));
    assert_eq!(settled.claim_deadline, settle_at + CLAIM_WINDOW);
    assert_eq!(
        (
            settled.result_sha256,
            settled.payout_root,
            settled.total,
            settled.commitment
        ),
        (ALT, ALT_ROOT, alt_total, alt)
    );
    assert_eq!(
        (settled.resolver_paid, settled.challenger_paid),
        (0, 2 * BOND)
    );
    assert_eq!(settled.challenger, lc.keys.key(Who::Challenger));

    // Claimable on the alternative: nothing is left for settle or the arbiter.
    let r = lc.settle(true);
    assert_refused(r, EscrowError::InvalidStatus, "a second settle");
    let r = lc.arbiter_resolve(Who::Arbiter, ArbiterChoice::Posted);
    assert_refused(
        r,
        EscrowError::InvalidStatus,
        "arbiter_resolve of a Claimable escrow",
    );
}

#[test]
fn no_quorum_by_the_attest_deadline_freezes_with_both_bonds_held_for_the_arbiter() {
    let mut lc = Lc::committed();
    let resolver_start = lc.lamports(&lc.keys.key(Who::Resolver));
    let challenger_start = lc.lamports(&lc.keys.key(Who::Challenger));
    lc.at(POST_AT);
    ok(lc.post(Who::Resolver, TOTAL), "post_result");
    lc.at(CHALLENGE_AT);
    ok(lc.challenge(Who::Challenger, ALT), "challenge");
    ok(
        lc.attest(Who::Regrader(0), posted_commitment()),
        "a vote for the result",
    );
    ok(
        lc.attest(Who::Regrader(1), alt_commitment()),
        "a vote for the alternative",
    );

    let attest_deadline = ATTEST_DEADLINE;
    lc.at(attest_deadline - 1);
    let r = lc.settle(true);
    assert_refused(
        r,
        EscrowError::AttestWindowOpen,
        "settle inside the attest window",
    );

    lc.at(attest_deadline);
    let meta = ok(lc.settle(false), "settle at the attest deadline");
    let state = lc.state();
    assert_eq!(state.status, EscrowStatus::Frozen);
    assert_eq!((state.resolver_bond, state.challenger_bond), (BOND, BOND));
    assert_eq!(state.claim_deadline, 0);
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent() + 2 * BOND);
    assert_eq!(lc.refund_to_gain(), 0);
    let settled = event::<Settled>(&meta);
    assert_eq!(settled.outcome, SettleOutcome::NoQuorum);
    assert_eq!(settled.status, EscrowStatus::Frozen);
    assert_eq!((settled.votes_result, settled.votes_alt), (1, 1));
    assert_eq!(settled.commitment, posted_commitment());
    assert_eq!((settled.resolver_paid, settled.challenger_paid), (0, 0));

    // Frozen waits for the arbiter: refund is not open before hard_deadline.
    let resolve_at = attest_deadline + 2 * CLAIM_WINDOW;
    lc.at(resolve_at);
    let r = lc.refund();
    assert_refused(
        r,
        EscrowError::DeadlineNotReached,
        "refund of a Frozen escrow",
    );

    // The arbiter only.
    let r = lc.arbiter_resolve(Who::Stranger, ArbiterChoice::Posted);
    assert_refused(
        r,
        EscrowError::UnauthorizedArbiter,
        "arbiter_resolve by a stranger",
    );
    let r = lc.arbiter_resolve(Who::Resolver, ArbiterChoice::Posted);
    assert_refused(
        r,
        EscrowError::UnauthorizedArbiter,
        "arbiter_resolve by the resolver",
    );

    // Choosing the posted result keeps it, and its poster takes both bonds.
    let meta = ok(
        lc.arbiter_resolve(Who::Arbiter, ArbiterChoice::Posted),
        "arbiter_resolve to the posted result",
    );
    assert_eq!(
        lc.lamports(&lc.keys.key(Who::Resolver)),
        resolver_start + BOND,
        "the resolver's bond back and the challenger's whole bond"
    );
    assert_eq!(
        lc.lamports(&lc.keys.key(Who::Challenger)),
        challenger_start - BOND - lc.challenge_rent()
    );
    assert_eq!(lc.refund_to_gain(), 0);
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent());
    let state = lc.state();
    assert_eq!(state.status, EscrowStatus::Claimable);
    assert_eq!((state.resolver_bond, state.challenger_bond), (0, 0));
    assert_eq!(
        (state.payout_root, state.result_sha256, state.total),
        (PAYOUT_ROOT, RESULT, TOTAL)
    );
    assert_eq!(state.commitment, posted_commitment());
    assert_eq!(state.claim_deadline, resolve_at + CLAIM_WINDOW);
    let resolved = event::<ArbiterResolved>(&meta);
    assert_eq!(
        (resolved.escrow, resolved.arbiter, resolved.choice),
        (lc.escrow, lc.keys.key(Who::Arbiter), ArbiterChoice::Posted)
    );
    assert_eq!(
        (resolved.payout_root, resolved.result_sha256, resolved.total),
        (PAYOUT_ROOT, RESULT, TOTAL)
    );
    assert_eq!(resolved.commitment, posted_commitment());
    assert_eq!(
        (resolved.challenge, resolved.challenger),
        (Pubkey::default(), Pubkey::default())
    );
    assert_eq!(resolved.claim_deadline, resolve_at + CLAIM_WINDOW);
    assert_eq!(
        (resolved.resolver_paid, resolved.challenger_paid),
        (2 * BOND, 0)
    );

    let r = lc.arbiter_resolve(Who::Arbiter, ArbiterChoice::Alternative);
    assert_refused(r, EscrowError::InvalidStatus, "a second arbiter_resolve");
}

#[test]
fn the_arbiter_only_chooses_a_side_and_applies_the_alternative_as_stored() {
    // Run review 4: arbiter_resolve took any payout root, document hash and total up to the
    // vault, so the house multisig could pay anyone. It takes a choice now, Posted or
    // Alternative, and the escrow applies that side's stored result; nothing else decodes.
    let mut lc = Lc::disputed();
    let resolver_after_post = lc.lamports(&lc.keys.key(Who::Resolver));
    let challenger_after_challenge = lc.lamports(&lc.keys.key(Who::Challenger));
    // One regrader backs the alternative (1 of k = 2): the arbiter may choose only an alternative
    // a named regrader voted for (run review 5, F3).
    ok(
        lc.attest(Who::Regrader(0), alt_commitment()),
        "a vote for the alternative",
    );
    let attest_deadline = ATTEST_DEADLINE;
    lc.at(attest_deadline);
    ok(lc.settle(false), "settle with no quorum");
    assert_eq!(lc.state().status, EscrowStatus::Frozen);

    // The old arguments (a payout root, a document hash and a total) no longer decode: the
    // first byte after the discriminator is the choice, 0 or 1, and nothing may follow it.
    let resolve_at = attest_deadline + DAY;
    lc.at(resolve_at);
    let mut ix = lc.arbiter_resolve_ix(Who::Arbiter, ArbiterChoice::Alternative);
    ix.data[8] = 2;
    let r = lc.send(ix, &[Who::Arbiter]);
    assert_refused(
        r,
        AnchorErrorCode::InstructionDidNotDeserialize,
        "a third choice",
    );
    let mut ix = lc.arbiter_resolve_ix(Who::Arbiter, ArbiterChoice::Alternative);
    ix.data.truncate(8);
    ix.data.extend_from_slice(&[0x88; 32]);
    ix.data.extend_from_slice(&ALT);
    ix.data.extend_from_slice(&TOTAL.to_le_bytes());
    let r = lc.send(ix, &[Who::Arbiter]);
    assert_refused(
        r,
        AnchorErrorCode::InstructionDidNotDeserialize,
        "a free-form root, document hash and total",
    );
    assert_eq!(lc.state().status, EscrowStatus::Frozen);

    let meta = ok(
        lc.arbiter_resolve(Who::Arbiter, ArbiterChoice::Alternative),
        "arbiter_resolve to the alternative",
    );
    assert_eq!(
        lc.lamports(&lc.keys.key(Who::Challenger)),
        challenger_after_challenge + 2 * BOND,
        "the challenger's bond back and the resolver's whole bond"
    );
    assert_eq!(
        lc.lamports(&lc.keys.key(Who::Resolver)),
        resolver_after_post
    );
    assert_eq!(lc.refund_to_gain(), 0);
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent());
    let state = lc.state();
    assert_eq!(state.status, EscrowStatus::Claimable);
    assert_eq!(
        (state.payout_root, state.result_sha256, state.total),
        (ALT_ROOT, ALT, TOTAL)
    );
    assert_eq!(state.commitment, alt_commitment());
    assert_eq!(state.kit_sha256, KIT);
    assert_eq!(state.claim_deadline, resolve_at + CLAIM_WINDOW);
    let resolved = event::<ArbiterResolved>(&meta);
    assert_eq!(resolved.choice, ArbiterChoice::Alternative);
    assert_eq!(
        (resolved.payout_root, resolved.result_sha256, resolved.total),
        (ALT_ROOT, ALT, TOTAL)
    );
    assert_eq!(resolved.commitment, alt_commitment());
    assert_eq!(
        (resolved.challenge, resolved.challenger),
        (
            lc.challenge_pda(&alt_commitment()),
            lc.keys.key(Who::Challenger)
        )
    );
    assert_eq!(
        (resolved.resolver_paid, resolved.challenger_paid),
        (0, 2 * BOND)
    );
    assert_eq!(state.challenger, lc.keys.key(Who::Challenger));
}

// ------------------------------------------------------- several challenges (run review 5)
//
// Run review 5, finding 1: one challenge per escrow let a free junk first challenge, whose
// alternative nobody reproduces, take the only slot. With the posted result wrong too, the
// regraders could not vote for the honest one, and the arbiter could only pick between two wrong
// sides. Each distinct alternative is its own Challenge PDA now.

/// Posted at POST_AT, then challenged at CHALLENGE_AT with the junk alternative (Who::Junk) and an
/// hour later with the honest one (Who::Challenger). Returns the lamports each poster held before
/// the post (resolver) and before its challenge (junk, challenger).
fn junk_then_honest() -> (Lc, [u64; 3]) {
    let mut lc = Lc::committed();
    let resolver_start = lc.lamports(&lc.keys.key(Who::Resolver));
    let junk_start = lc.lamports(&lc.keys.key(Who::Junk));
    let challenger_start = lc.lamports(&lc.keys.key(Who::Challenger));
    lc.at(POST_AT);
    ok(lc.post(Who::Resolver, TOTAL), "post_result");
    lc.at(CHALLENGE_AT);
    ok(
        lc.challenge_with(Who::Junk, JUNK, JUNK_ROOT, TOTAL),
        "the junk challenge",
    );
    lc.at(CHALLENGE_AT + HOUR);
    ok(lc.challenge(Who::Challenger, ALT), "the honest challenge");
    (lc, [resolver_start, junk_start, challenger_start])
}

#[test]
fn every_distinct_alternative_is_its_own_challenge_and_a_duplicate_is_refused() {
    let mut lc = Lc::posted();
    lc.at(CHALLENGE_AT);
    let meta = ok(
        lc.challenge_with(Who::Junk, JUNK, JUNK_ROOT, TOTAL),
        "the junk challenge first",
    );
    let first = event::<Challenged>(&meta);
    let attest_deadline = ATTEST_DEADLINE;
    assert_eq!(first.attest_deadline, attest_deadline);
    assert_eq!((first.index, first.challenge_count), (0, 1));
    let state = lc.state();
    assert_eq!(state.status, EscrowStatus::Disputed);
    assert_eq!(state.attest_deadline, attest_deadline);

    // The honest alternative still has its own slot, inside the challenge window, while Disputed.
    let later = POST_AT + 24 * HOUR - 1;
    lc.at(later);
    let meta = ok(
        lc.challenge(Who::Challenger, ALT),
        "a second challenge of another commitment",
    );
    let second = event::<Challenged>(&meta);
    assert_eq!((second.index, second.challenge_count), (1, 2));
    assert_eq!(
        second.attest_deadline, attest_deadline,
        "a later challenge leaves the attest deadline"
    );
    assert_eq!(second.challenge, lc.challenge_pda(&alt_commitment()));
    let state = lc.state();
    assert_eq!(state.challenge_count, 2);
    assert_eq!(state.attest_deadline, attest_deadline);
    assert_eq!(
        (state.resolver_bond, state.challenger_bond),
        (BOND, 2 * BOND)
    );
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent() + 3 * BOND);
    assert_eq!(
        lc.challenge_state(&alt_commitment()).unwrap().index,
        1,
        "the honest challenge is the second"
    );
    assert_eq!(
        lc.challenge_state(&junk_commitment()).unwrap().challenger,
        lc.keys.key(Who::Junk)
    );

    // One challenge per commitment, whoever sends it; never the posted one.
    let r = lc.challenge_with(Who::Stranger, JUNK, JUNK_ROOT, TOTAL);
    assert_refused(
        r,
        0u32,
        "a duplicate commitment (its Challenge PDA is in use)",
    );
    let r = lc.challenge_with(Who::Stranger, RESULT, PAYOUT_ROOT, TOTAL);
    assert_refused(
        r,
        EscrowError::InvalidResultHash,
        "a challenge committing to the posted result",
    );
    lc.at(POST_AT + 24 * HOUR);
    let r = lc.challenge(Who::Stranger, [0x99; 32]);
    assert_refused(
        r,
        EscrowError::ChallengeWindowClosed,
        "a third challenge at the challenge deadline",
    );
    assert_eq!(lc.state().challenge_count, 2);
}

#[test]
fn votes_split_then_a_majority_for_the_second_challenge_applies_it_and_it_takes_every_bond() {
    // The posted result is wrong, a junk challenge opened first, the honest one second: the
    // regraders' majority for the honest one applies it, with no arbiter.
    let (mut lc, [resolver_start, junk_start, challenger_start]) = junk_then_honest();
    let rent = lc.challenge_rent();

    ok(
        lc.attest(Who::Regrader(0), junk_commitment()),
        "a vote for the junk challenge",
    );
    ok(
        lc.attest(Who::Regrader(1), alt_commitment()),
        "a vote for the honest challenge",
    );
    let state = lc.state();
    assert_eq!((state.votes_result, state.votes_alt), (0, 2));
    assert_eq!(state.challenger, Pubkey::default(), "split: no side at k");
    let r = lc.settle(false);
    assert_refused(
        r,
        EscrowError::DeadlineNotReached,
        "settle on a split vote inside the challenge window",
    );
    let junk = lc.keys.key(Who::Junk);
    let r = lc.close_challenge(junk_commitment(), junk);
    assert_refused(
        r,
        EscrowError::InvalidStatus,
        "close_challenge while Disputed",
    );

    let meta = ok(
        lc.attest(Who::Regrader(2), alt_commitment()),
        "the majority for the honest challenge",
    );
    let attested = event::<Attested>(&meta);
    assert_eq!((attested.votes, attested.quorum), (2, true));
    assert_eq!(
        (
            lc.challenge_state(&junk_commitment()).unwrap().votes,
            lc.challenge_state(&alt_commitment()).unwrap().votes
        ),
        (1, 2)
    );
    let challenger = lc.keys.key(Who::Challenger);
    assert_eq!(lc.state().challenger, challenger);

    let r = lc.settle(true);
    assert_refused(
        r,
        EscrowError::DeadlineNotReached,
        "settle at quorum inside the challenge window",
    );
    lc.at(CHALLENGE_DEADLINE);
    let r = lc.settle(true);
    assert_refused(
        r,
        EscrowError::OverturnWindowOpen,
        "the overturn's settle at the challenge deadline",
    );
    lc.at(ATTEST_DEADLINE);
    let meta = ok(lc.settle(true), "settle at the attest deadline");
    let state = lc.state();
    assert_eq!(state.status, EscrowStatus::Claimable);
    assert_eq!(
        (
            state.result_sha256,
            state.payout_root,
            state.total,
            state.commitment
        ),
        (ALT, ALT_ROOT, TOTAL, alt_commitment())
    );
    assert_eq!((state.resolver_bond, state.challenger_bond), (0, 0));
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent());
    let settled = event::<Settled>(&meta);
    assert_eq!(settled.outcome, SettleOutcome::AltApplied);
    assert_eq!(settled.commitment, alt_commitment());
    assert_eq!(settled.challenger, challenger);
    assert_eq!(
        (settled.resolver_paid, settled.challenger_paid),
        (0, 3 * BOND),
        "the honest challenger takes its bond back, the resolver's and the junk challenger's"
    );
    assert_eq!(lc.lamports(&challenger), challenger_start + 2 * BOND - rent);
    assert_eq!(
        lc.lamports(&lc.keys.key(Who::Resolver)),
        resolver_start - BOND
    );
    assert_eq!(lc.lamports(&junk), junk_start - BOND - rent);
    assert_eq!(lc.refund_to_gain(), 0, "nothing goes to refund_to");

    // Each Challenge PDA closes now, its rent back to its payer, the loser's bond already gone.
    let r = lc.close_challenge(junk_commitment(), challenger);
    assert_refused(
        r,
        EscrowError::ChallengeMismatch,
        "close_challenge paying someone else",
    );
    let meta = ok(
        lc.close_challenge(junk_commitment(), junk),
        "close the junk challenge",
    );
    let closed = event::<ChallengeClosed>(&meta);
    assert_eq!((closed.bond_returned, closed.rent_returned), (0, rent));
    assert_eq!(lc.lamports(&junk), junk_start - BOND);
    ok(
        lc.close_challenge(alt_commitment(), challenger),
        "close the honest challenge",
    );
    assert_eq!(lc.lamports(&challenger), challenger_start + 2 * BOND);
    assert!(lc.challenge_state(&junk_commitment()).is_none());
    assert!(lc.challenge_state(&alt_commitment()).is_none());
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent());
}

#[test]
fn the_posted_results_majority_takes_every_challengers_bond() {
    let (mut lc, [resolver_start, junk_start, challenger_start]) = junk_then_honest();
    let rent = lc.challenge_rent();
    ok(
        lc.attest(Who::Regrader(0), posted_commitment()),
        "a vote for the posted result",
    );
    ok(
        lc.attest(Who::Regrader(1), alt_commitment()),
        "a vote for a challenge",
    );
    ok(
        lc.attest(Who::Regrader(2), posted_commitment()),
        "the majority for the posted result",
    );
    lc.at(CHALLENGE_DEADLINE);
    let meta = ok(lc.settle(false), "settle at the challenge deadline");
    let settled = event::<Settled>(&meta);
    assert_eq!(settled.outcome, SettleOutcome::ResultUpheld);
    assert_eq!(
        (settled.resolver_paid, settled.challenger_paid),
        (3 * BOND, 0)
    );
    assert_eq!(
        lc.lamports(&lc.keys.key(Who::Resolver)),
        resolver_start + 2 * BOND
    );
    let (junk, challenger) = (lc.keys.key(Who::Junk), lc.keys.key(Who::Challenger));
    assert_eq!(lc.lamports(&junk), junk_start - BOND - rent);
    assert_eq!(lc.lamports(&challenger), challenger_start - BOND - rent);
    let state = lc.state();
    assert_eq!(state.commitment, posted_commitment());
    assert_eq!((state.resolver_bond, state.challenger_bond), (0, 0));
    ok(lc.close_challenge(junk_commitment(), junk), "close junk");
    ok(
        lc.close_challenge(alt_commitment(), challenger),
        "close honest",
    );
    assert_eq!(
        (lc.lamports(&junk), lc.lamports(&challenger)),
        (junk_start - BOND, challenger_start - BOND),
        "the rent back, the bonds lost"
    );
}

#[test]
fn the_arbiter_may_choose_the_second_challenge_of_a_frozen_escrow() {
    let (mut lc, [resolver_start, junk_start, challenger_start]) = junk_then_honest();
    let rent = lc.challenge_rent();
    // Two of three regraders vote, on two sides: no commitment reaches k = 2, and nobody backs the
    // junk challenge.
    ok(lc.attest(Who::Regrader(0), posted_commitment()), "posted");
    ok(lc.attest(Who::Regrader(2), alt_commitment()), "honest");
    lc.at(ATTEST_DEADLINE);
    let meta = ok(lc.settle(false), "settle at the attest deadline");
    assert_eq!(event::<Settled>(&meta).outcome, SettleOutcome::NoQuorum);
    let state = lc.state();
    assert_eq!(state.status, EscrowStatus::Frozen);
    assert_eq!(
        (state.resolver_bond, state.challenger_bond),
        (BOND, 2 * BOND)
    );

    let resolve_at = ATTEST_DEADLINE + HOUR;
    lc.at(resolve_at);
    let (junk, challenger) = (lc.keys.key(Who::Junk), lc.keys.key(Who::Challenger));
    let honest_pda = lc.challenge_pda(&alt_commitment());
    let refusals = [
        (
            lc.arbiter_resolve_with_ix(
                Who::Arbiter,
                ArbiterChoice::Alternative,
                alt_commitment(),
                None,
            ),
            u32::from(AnchorErrorCode::AccountNotEnoughKeys),
            "the alternative without its Challenge PDA",
        ),
        (
            lc.arbiter_resolve_with_ix(
                Who::Arbiter,
                ArbiterChoice::Alternative,
                junk_commitment(),
                Some((honest_pda, challenger)),
            ),
            u32::from(EscrowError::InvalidResultHash),
            "a commitment that is not the passed challenge's",
        ),
        (
            lc.arbiter_resolve_with_ix(
                Who::Arbiter,
                ArbiterChoice::Alternative,
                alt_commitment(),
                Some((honest_pda, junk)),
            ),
            u32::from(EscrowError::ChallengeMismatch),
            "the honest challenge paying the junk challenger",
        ),
        (
            lc.arbiter_resolve_with_ix(Who::Arbiter, ArbiterChoice::Posted, alt_commitment(), None),
            u32::from(EscrowError::InvalidResultHash),
            "the posted result named by another commitment",
        ),
        // Run review 5, F3: an arbiter who could pick any challenge could pay anyone, through a
        // junk challenge it (or a friend) bonded. It picks only an alternative a regrader backed.
        (
            lc.arbiter_resolve_with_ix(
                Who::Arbiter,
                ArbiterChoice::Alternative,
                junk_commitment(),
                Some((lc.challenge_pda(&junk_commitment()), junk)),
            ),
            u32::from(EscrowError::AlternativeUnbacked),
            "the junk challenge no regrader voted for",
        ),
    ];
    for (ix, code, what) in refusals {
        let r = lc.send(ix, &[Who::Arbiter]);
        assert_refused(r, code, what);
    }

    let ix = lc.arbiter_resolve_with_ix(
        Who::Arbiter,
        ArbiterChoice::Alternative,
        alt_commitment(),
        Some((honest_pda, challenger)),
    );
    let meta = ok(
        lc.send(ix, &[Who::Arbiter]),
        "the arbiter chooses the second challenge",
    );
    let resolved = event::<ArbiterResolved>(&meta);
    assert_eq!(
        (
            resolved.choice,
            resolved.commitment,
            resolved.challenge,
            resolved.challenger
        ),
        (
            ArbiterChoice::Alternative,
            alt_commitment(),
            honest_pda,
            challenger
        )
    );
    assert_eq!(
        (resolved.resolver_paid, resolved.challenger_paid),
        (0, 3 * BOND)
    );
    let state = lc.state();
    assert_eq!(state.status, EscrowStatus::Claimable);
    assert_eq!(
        (state.payout_root, state.result_sha256, state.commitment),
        (ALT_ROOT, ALT, alt_commitment())
    );
    assert_eq!(state.challenger, challenger);
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent());
    assert_eq!(lc.lamports(&challenger), challenger_start + 2 * BOND - rent);
    assert_eq!(
        lc.lamports(&lc.keys.key(Who::Resolver)),
        resolver_start - BOND
    );
    assert_eq!(lc.lamports(&junk), junk_start - BOND - rent);
    ok(lc.close_challenge(junk_commitment(), junk), "close junk");
    ok(
        lc.close_challenge(alt_commitment(), challenger),
        "close honest",
    );
    assert_eq!(lc.lamports(&challenger), challenger_start + 2 * BOND);
    assert_eq!(lc.lamports(&junk), junk_start - BOND);
}

#[test]
fn a_refund_from_frozen_returns_every_bond_to_its_payer() {
    let (mut lc, [resolver_start, junk_start, challenger_start]) = junk_then_honest();
    lc.at(ATTEST_DEADLINE);
    ok(lc.settle(false), "settle with no votes");
    assert_eq!(lc.state().status, EscrowStatus::Frozen);
    lc.at(HARD_DEADLINE + 1);
    let meta = ok(lc.refund(), "refund after the hard deadline");
    let refunded = event::<Refunded>(&meta);
    assert_eq!(
        (refunded.resolver_paid, refunded.challenger_bonds_held),
        (BOND, 2 * BOND)
    );
    assert_eq!(lc.lamports(&lc.keys.key(Who::Resolver)), resolver_start);
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent() + 2 * BOND);
    let (junk, challenger) = (lc.keys.key(Who::Junk), lc.keys.key(Who::Challenger));
    ok(
        lc.close_challenge(alt_commitment(), challenger),
        "close honest",
    );
    assert_eq!(lc.state().challenger_bond, BOND);
    ok(lc.close_challenge(junk_commitment(), junk), "close junk");
    assert_eq!(
        (lc.lamports(&junk), lc.lamports(&challenger)),
        (junk_start, challenger_start),
        "every bond and every rent back to its payer: no side was proven"
    );
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent());
    let state = lc.state();
    assert_eq!(
        (state.status, state.challenger_bond),
        (EscrowStatus::Closed, 0)
    );
}

#[test]
fn a_challenge_on_the_windows_last_second_gets_the_whole_attest_window() {
    // Run review 5, F2: the attest deadline ran from the first challenge, so it could end before
    // the challenge window did: a later challenge could not be voted on, and a NoQuorum settle
    // could freeze the escrow while the window was still open. It is challenge_deadline +
    // attest_window now, fixed by the first challenge.
    let mut lc = Lc::posted();
    lc.at(CHALLENGE_DEADLINE - 1);
    let meta = ok(
        lc.challenge(Who::Challenger, ALT),
        "a challenge on the window's last second",
    );
    assert_eq!(event::<Challenged>(&meta).attest_deadline, ATTEST_DEADLINE);
    assert_eq!(
        lc.state().attest_deadline,
        CHALLENGE_DEADLINE + MIN_ATTEST_WINDOW
    );

    // A whole attest window to vote; no settle without a quorum before it ends.
    lc.at(ATTEST_DEADLINE - 1);
    let r = lc.settle(false);
    assert_refused(
        r,
        EscrowError::AttestWindowOpen,
        "settle with no quorum inside the attest window",
    );
    ok(
        lc.attest(Who::Regrader(0), alt_commitment()),
        "a vote on the attest window's last second",
    );
    ok(
        lc.attest(Who::Regrader(1), alt_commitment()),
        "the majority, on the same second",
    );
    // The overturn applies at the attest deadline itself, not on the same second (#749).
    let r = lc.settle(true);
    assert_refused(
        r,
        EscrowError::OverturnWindowOpen,
        "the overturn on the attest window's last second",
    );
    lc.at(ATTEST_DEADLINE);
    let meta = ok(lc.settle(true), "settle applies it");
    assert_eq!(event::<Settled>(&meta).outcome, SettleOutcome::AltApplied);
    assert_eq!(lc.state().commitment, alt_commitment());
}

#[test]
fn many_challenges_in_one_window_still_resolve_by_the_attest_deadline() {
    // Bounded resolution: every challenge joins a dispute whose deadlines are fixed (the challenge
    // window from post_result, the attest deadline a whole attest window past it), so no number of
    // challenges, nor one on the window's last second, delays it.
    let mut lc = Lc::posted();
    let opened_at = [
        CHALLENGE_AT,
        CHALLENGE_AT + HOUR,
        POST_AT + 8 * HOUR,
        POST_AT + 16 * HOUR,
        POST_AT + 20 * HOUR,
        POST_AT + 23 * HOUR,
        CHALLENGE_DEADLINE - 60,
        CHALLENGE_DEADLINE - 1,
    ];
    for (i, at) in opened_at.into_iter().enumerate() {
        lc.at(at);
        let who = if i % 2 == 0 { Who::Stranger } else { Who::Junk };
        let alt = [0x10 + u8::try_from(i).unwrap(); 32];
        let meta = ok(lc.challenge(who, alt), "one more challenge");
        let challenged = event::<Challenged>(&meta);
        assert_eq!(
            (challenged.index, challenged.attest_deadline),
            (u32::try_from(i).unwrap(), ATTEST_DEADLINE)
        );
    }
    lc.at(CHALLENGE_DEADLINE);
    let r = lc.challenge(Who::Challenger, ALT);
    assert_refused(
        r,
        EscrowError::ChallengeWindowClosed,
        "a challenge at the challenge deadline",
    );
    let state = lc.state();
    assert_eq!(state.challenge_count, 8);
    assert_eq!(state.attest_deadline, ATTEST_DEADLINE);
    assert_eq!(state.challenger_bond, 8 * BOND);

    lc.at(ATTEST_DEADLINE - 1);
    let r = lc.settle(false);
    assert_refused(
        r,
        EscrowError::AttestWindowOpen,
        "settle before the attest deadline",
    );
    lc.at(ATTEST_DEADLINE);
    let meta = ok(lc.settle(false), "settle at the attest deadline");
    let settled = event::<Settled>(&meta);
    assert_eq!(
        (settled.outcome, settled.status),
        (SettleOutcome::NoQuorum, EscrowStatus::Frozen)
    );
}

// ---------------------------------------------------------------------------------- refund

#[test]
fn refund_returns_the_whole_pot_when_no_result_comes_and_leaves_a_closed_marker() {
    let mut lc = Lc::opened();
    ok(lc.fund(Who::Sponsor, 300), "fund");
    let vault_rent = lc.lamports(&lc.vault);

    lc.at(RESOLVE_DEADLINE - 1);
    let r = lc.refund();
    assert_refused(
        r,
        EscrowError::DeadlineNotReached,
        "refund before the resolve deadline",
    );

    lc.at(RESOLVE_DEADLINE);
    let meta = ok(lc.refund(), "refund at the resolve deadline");
    assert_eq!(lc.tokens(&lc.refund_to_ata()), TOTAL + 300);
    assert_eq!(lc.lamports(&lc.vault), 0, "the vault is closed");
    assert_eq!(
        lc.refund_to_gain(),
        vault_rent,
        "the vault's rent goes to refund_to"
    );
    assert_eq!(
        lc.lamports(&lc.escrow),
        lc.escrow_rent(),
        "the escrow account stays"
    );
    assert_eq!(lc.state().status, EscrowStatus::Closed);
    let refunded = event::<Refunded>(&meta);
    assert_eq!(
        (refunded.escrow, refunded.refund_to, refunded.amount),
        (lc.escrow, lc.refund_to, TOTAL + 300)
    );
    assert_eq!(refunded.from_status, EscrowStatus::Open);

    // The replay marker: the id cannot be opened again.
    let r = lc.open();
    assert_refused(r, 0u32, "open_escrow of a refunded competition id");

    // Anyone can re-create the vault account; a Closed escrow still refuses everything.
    set_token_account(&mut lc.svm, lc.vault, lc.mint, lc.escrow, 0);
    let r = lc.refund();
    assert_refused(r, EscrowError::EscrowClosed, "a second refund");
    let r = lc.fund(Who::Sponsor, 1);
    assert_refused(r, EscrowError::EscrowClosed, "fund of a Closed escrow");
    lc.at(NOW + HOUR);
    let r = lc.commit(Who::Resolver, ENTRIES_ROOT, 12);
    assert_refused(
        r,
        EscrowError::EscrowClosed,
        "commit_entries on a Closed escrow",
    );
    let r = lc.post(Who::Resolver, 0);
    assert_refused(
        r,
        EscrowError::EscrowClosed,
        "post_result on a Closed escrow",
    );
    let r = lc.settle(false);
    assert_refused(r, EscrowError::EscrowClosed, "settle of a Closed escrow");
}

#[test]
fn refund_of_a_claimable_escrow_waits_until_after_the_claim_deadline() {
    let mut lc = Lc::posted();
    let window_end = POST_AT + 24 * HOUR;
    lc.at(window_end);
    ok(lc.settle(false), "settle");
    let claim_deadline = window_end + CLAIM_WINDOW;
    assert_eq!(lc.state().claim_deadline, claim_deadline);
    let resolver_before = lc.lamports(&lc.keys.key(Who::Resolver));

    lc.at(claim_deadline);
    let r = lc.refund();
    assert_refused(
        r,
        EscrowError::ClaimWindowNotElapsed,
        "refund on the claim deadline (claims still run)",
    );

    lc.at(claim_deadline + 1);
    let meta = ok(lc.refund(), "refund after the claim deadline");
    assert_eq!(lc.tokens(&lc.refund_to_ata()), TOTAL);
    assert_eq!(lc.lamports(&lc.vault), 0);
    assert_eq!(lc.state().status, EscrowStatus::Closed);
    assert_eq!(lc.lamports(&lc.keys.key(Who::Resolver)), resolver_before);
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent());
    let refunded = event::<Refunded>(&meta);
    assert_eq!(refunded.amount, TOTAL);
    assert_eq!(refunded.from_status, EscrowStatus::Claimable);
}

#[test]
fn refund_after_the_hard_deadline_returns_the_pot_and_every_bond_still_held() {
    // Frozen with both bonds held (no quorum), the arbiter never acts.
    let mut lc = Lc::committed();
    let resolver_start = lc.lamports(&lc.keys.key(Who::Resolver));
    let challenger_start = lc.lamports(&lc.keys.key(Who::Challenger));
    lc.at(POST_AT);
    ok(lc.post(Who::Resolver, TOTAL), "post_result");
    lc.at(CHALLENGE_AT);
    ok(lc.challenge(Who::Challenger, ALT), "challenge");
    lc.at(ATTEST_DEADLINE);
    ok(lc.settle(true), "settle with no votes");
    assert_eq!(lc.state().status, EscrowStatus::Frozen);

    lc.at(HARD_DEADLINE);
    let r = lc.refund();
    assert_refused(
        r,
        EscrowError::DeadlineNotReached,
        "refund on the hard deadline",
    );

    let challenger = lc.keys.key(Who::Challenger);
    let r = lc.close_challenge(alt_commitment(), challenger);
    assert_refused(
        r,
        EscrowError::InvalidStatus,
        "close_challenge of a Frozen escrow (the arbiter may still choose it)",
    );

    lc.at(HARD_DEADLINE + 1);
    let meta = ok(lc.refund(), "refund after the hard deadline");
    assert_eq!(lc.tokens(&lc.refund_to_ata()), TOTAL);
    assert_eq!(lc.lamports(&lc.vault), 0);
    assert_eq!(lc.lamports(&lc.keys.key(Who::Resolver)), resolver_start);
    assert_eq!(
        lc.lamports(&challenger),
        challenger_start - BOND - lc.challenge_rent(),
        "the challenger's bond waits for close_challenge"
    );
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent() + BOND);
    let state = lc.state();
    assert_eq!(state.status, EscrowStatus::Closed);
    assert_eq!((state.resolver_bond, state.challenger_bond), (0, BOND));
    let refunded = event::<Refunded>(&meta);
    assert_eq!(refunded.from_status, EscrowStatus::Frozen);
    assert_eq!(
        (refunded.resolver_paid, refunded.challenger_bonds_held),
        (BOND, BOND)
    );

    // No side was proven: close_challenge returns the bond with the rent.
    let meta = ok(
        lc.close_challenge(alt_commitment(), challenger),
        "close_challenge after the refund",
    );
    assert_eq!(lc.lamports(&challenger), challenger_start);
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent());
    assert_eq!(lc.state().challenger_bond, 0);
    assert!(lc.challenge_state(&alt_commitment()).is_none());
    let closed = event::<ChallengeClosed>(&meta);
    assert_eq!(
        (closed.escrow, closed.challenge, closed.challenger),
        (lc.escrow, lc.challenge_pda(&alt_commitment()), challenger)
    );
    assert_eq!(closed.alt_commitment, alt_commitment());
    assert_eq!(
        (closed.bond_returned, closed.rent_returned),
        (BOND, lc.challenge_rent())
    );
    let r = lc.close_challenge(alt_commitment(), challenger);
    assert_refused(
        r,
        AnchorErrorCode::AccountNotInitialized,
        "a second close_challenge",
    );

    // Too late for the arbiter, or anyone: with the vault account re-created, the dispute
    // instructions all meet the Closed status.
    set_token_account(&mut lc.svm, lc.vault, lc.mint, lc.escrow, 0);
    let r = lc.arbiter_resolve(Who::Arbiter, ArbiterChoice::Posted);
    assert_refused(
        r,
        EscrowError::EscrowClosed,
        "arbiter_resolve of a Closed escrow",
    );
    let r = lc.settle(true);
    assert_refused(r, EscrowError::EscrowClosed, "settle of a Closed escrow");
    let r = lc.challenge(Who::Stranger, [0x99; 32]);
    assert_refused(r, EscrowError::EscrowClosed, "challenge of a Closed escrow");
    let r = lc.attest(Who::Regrader(2), alt_commitment());
    assert_refused(r, EscrowError::EscrowClosed, "attest on a Closed escrow");
}

#[test]
fn refund_after_the_hard_deadline_reaches_a_stalled_window_or_dispute() {
    // Challengeable: nobody settled; the resolver's bond goes back with the refund.
    let mut lc = Lc::posted();
    let resolver_after_post = lc.lamports(&lc.keys.key(Who::Resolver));
    lc.at(HARD_DEADLINE);
    let r = lc.refund();
    assert_refused(
        r,
        EscrowError::DeadlineNotReached,
        "refund of a Challengeable escrow",
    );
    lc.at(HARD_DEADLINE + 1);
    let meta = ok(lc.refund(), "refund of a stalled Challengeable escrow");
    assert_eq!(
        lc.lamports(&lc.keys.key(Who::Resolver)),
        resolver_after_post + BOND
    );
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent());
    assert_eq!(lc.tokens(&lc.refund_to_ata()), TOTAL);
    let refunded = event::<Refunded>(&meta);
    assert_eq!(refunded.from_status, EscrowStatus::Challengeable);

    // Disputed: nobody settled; both bonds go back.
    let mut lc = Lc::disputed();
    let resolver_after = lc.lamports(&lc.keys.key(Who::Resolver));
    let challenger_after = lc.lamports(&lc.keys.key(Who::Challenger));
    lc.at(HARD_DEADLINE - DAY);
    let r = lc.refund();
    assert_refused(
        r,
        EscrowError::DeadlineNotReached,
        "refund of a Disputed escrow",
    );
    lc.at(HARD_DEADLINE + 1);
    let meta = ok(lc.refund(), "refund of a stalled Disputed escrow");
    assert_eq!(
        lc.lamports(&lc.keys.key(Who::Resolver)),
        resolver_after + BOND
    );
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent() + BOND);
    assert_eq!(lc.state().status, EscrowStatus::Closed);
    let refunded = event::<Refunded>(&meta);
    assert_eq!(refunded.from_status, EscrowStatus::Disputed);
    assert_eq!(refunded.challenger_bonds_held, BOND);
    let challenger = lc.keys.key(Who::Challenger);
    ok(
        lc.close_challenge(alt_commitment(), challenger),
        "close_challenge of a stalled dispute",
    );
    assert_eq!(
        lc.lamports(&challenger),
        challenger_after + BOND + lc.challenge_rent()
    );
    assert_eq!(lc.lamports(&lc.escrow), lc.escrow_rent());

    // Open, between the resolve deadline and the hard deadline, is the full refund already;
    // past the hard deadline it still is.
    let mut lc = Lc::opened();
    lc.at(HARD_DEADLINE + 1);
    ok(
        lc.refund(),
        "refund of an Open escrow after the hard deadline",
    );
    assert_eq!(lc.tokens(&lc.refund_to_ata()), TOTAL);
}

#[test]
fn a_dispute_whose_quorum_is_recorded_never_refunds_and_settle_applies_it_past_the_hard_deadline() {
    // #478's rule, still missed at #535's verify: refund took every Disputed escrow past
    // hard_deadline, so a dispute the regraders had decided but nobody settled refunded as if no
    // side had won (the pot to refund_to, every bond back). The vote binds: refund refuses it
    // (QuorumRecorded), settle applies it past hard_deadline too, and the refund waits for the
    // claim window that follows.

    // The posted result's quorum, a commit never revealed still pending.
    let mut lc = Lc::disputed();
    let resolver = lc.keys.key(Who::Resolver);
    let stranger = lc.keys.key(Who::Stranger);
    let junk = junk_commitment();
    let salt = salt_for(&stranger, &junk);
    ok(
        lc.commit_challenge(Who::Stranger, commit_hash(&junk, &stranger, &salt)),
        "a commit its challenger never reveals",
    );
    ok(
        lc.attest(Who::Regrader(0), posted_commitment()),
        "first vote",
    );
    ok(
        lc.attest(Who::Regrader(1), posted_commitment()),
        "second vote: the posted result's quorum",
    );
    for at in [
        ATTEST_DEADLINE,
        HARD_DEADLINE,
        HARD_DEADLINE + 1,
        HARD_DEADLINE + 90 * DAY,
    ] {
        lc.at(at);
        let r = lc.refund();
        assert_refused(
            r,
            EscrowError::QuorumRecorded,
            "refund of a dispute the posted result won",
        );
    }
    let state = lc.state();
    assert_eq!(
        (state.status, state.pending_commits),
        (EscrowStatus::Disputed, 1)
    );
    let resolver_before = lc.lamports(&resolver);
    let settled_at = HARD_DEADLINE + 90 * DAY;
    let meta = ok(lc.settle(false), "settle far past the hard deadline");
    let settled = event::<Settled>(&meta);
    assert_eq!(
        (settled.outcome, settled.status),
        (SettleOutcome::ResultUpheld, EscrowStatus::Claimable)
    );
    assert_eq!(
        lc.lamports(&resolver),
        resolver_before + 2 * BOND,
        "the resolver takes its bond back and the challenger's"
    );
    let claim_deadline = settled_at + CLAIM_WINDOW;
    assert_eq!(lc.state().claim_deadline, claim_deadline);
    lc.at(claim_deadline);
    let r = lc.refund();
    assert_refused(
        r,
        EscrowError::ClaimWindowNotElapsed,
        "refund inside the claim window settle opened",
    );
    lc.at(claim_deadline + 1);
    let meta = ok(lc.refund(), "refund after that claim window");
    let refunded = event::<Refunded>(&meta);
    assert_eq!(
        (
            refunded.from_status,
            refunded.resolver_paid,
            refunded.challenger_bonds_held
        ),
        (EscrowStatus::Claimable, 0, 0)
    );
    assert_eq!(lc.tokens(&lc.refund_to_ata()), TOTAL);

    // The alternative's quorum (attest recorded its challenger as the winner).
    let mut lc = Lc::disputed();
    let challenger = lc.keys.key(Who::Challenger);
    ok(lc.attest(Who::Regrader(1), alt_commitment()), "first vote");
    ok(
        lc.attest(Who::Regrader(2), alt_commitment()),
        "second vote: the alternative's quorum",
    );
    assert_eq!(lc.state().votes_result, 0);
    assert_eq!(lc.state().challenger, challenger);
    lc.at(HARD_DEADLINE + 1);
    let r = lc.refund();
    assert_refused(
        r,
        EscrowError::QuorumRecorded,
        "refund of a dispute the alternative won",
    );
    let challenger_before = lc.lamports(&challenger);
    let meta = ok(lc.settle(true), "settle applies the alternative");
    assert_eq!(event::<Settled>(&meta).outcome, SettleOutcome::AltApplied);
    assert_eq!(lc.lamports(&challenger), challenger_before + 2 * BOND);
    assert_eq!(lc.refund_to_gain(), 0, "nothing goes to refund_to");
    let state = lc.state();
    assert_eq!(
        (state.status, state.payout_root, state.commitment),
        (EscrowStatus::Claimable, ALT_ROOT, alt_commitment())
    );
    assert_eq!(state.claim_deadline, HARD_DEADLINE + 1 + CLAIM_WINDOW);

    // One vote short of k on each side: no side won, and the backstop refunds it.
    let mut lc = Lc::disputed();
    ok(
        lc.attest(Who::Regrader(0), posted_commitment()),
        "a vote for the posted result",
    );
    ok(
        lc.attest(Who::Regrader(1), alt_commitment()),
        "a vote for the alternative",
    );
    lc.at(HARD_DEADLINE);
    let r = lc.refund();
    assert_refused(
        r,
        EscrowError::DeadlineNotReached,
        "refund of an undecided dispute on the hard deadline",
    );
    lc.at(HARD_DEADLINE + 1);
    let meta = ok(lc.refund(), "refund of an undecided dispute");
    let refunded = event::<Refunded>(&meta);
    assert_eq!(
        (refunded.from_status, refunded.challenger_bonds_held),
        (EscrowStatus::Disputed, BOND)
    );

    // The guardian's escalate sets a recorded quorum aside for the arbiter only before settle may
    // apply it (#749): inside the challenge window for the posted result's quorum. Frozen, it
    // refunds after the hard deadline as any Frozen escrow does if the arbiter never resolves it
    // (the payer is this Config's admin and its guardian). From the challenge deadline on the
    // vote binds: escalate refuses it (QuorumRecorded), and settle upholds it.
    let posted_quorum = || {
        let mut lc = Lc::disputed();
        ok(
            lc.attest(Who::Regrader(0), posted_commitment()),
            "first vote",
        );
        ok(
            lc.attest(Who::Regrader(1), posted_commitment()),
            "second vote: the posted result's quorum",
        );
        lc
    };
    let escalate = |lc: &Lc| {
        instruction(
            accts::GuardEscrow {
                authority: lc.keys.payer.pubkey(),
                config: config_pda(),
                escrow: lc.escrow,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Escalate {},
        )
    };
    let mut lc = posted_quorum();
    lc.at(CHALLENGE_DEADLINE - 1);
    let ix = escalate(&lc);
    ok(
        lc.send(ix, &[]),
        "escalate on the challenge window's last second",
    );
    assert_eq!(lc.state().status, EscrowStatus::Frozen);
    lc.at(HARD_DEADLINE + 1);
    let meta = ok(lc.refund(), "refund of an escalated escrow");
    assert_eq!(event::<Refunded>(&meta).from_status, EscrowStatus::Frozen);

    let mut lc = posted_quorum();
    lc.at(CHALLENGE_DEADLINE);
    let ix = escalate(&lc);
    let r = lc.send(ix, &[]);
    assert_refused(
        r,
        EscrowError::QuorumRecorded,
        "escalate of a quorum settle may uphold",
    );
    lc.at(HARD_DEADLINE + 1);
    let r = lc.refund();
    assert_refused(
        r,
        EscrowError::QuorumRecorded,
        "its refund, past hard_deadline",
    );
    let meta = ok(
        lc.settle(false),
        "settle upholds it, past hard_deadline too",
    );
    assert_eq!(event::<Settled>(&meta).outcome, SettleOutcome::ResultUpheld);
}

// --------------------------------------------------------------------------------- helpers

fn escrow_pda(sponsor: &Pubkey, competition_id: &[u8; 16]) -> Pubkey {
    escrow_pda_and_bump(sponsor, competition_id).0
}

fn escrow_pda_and_bump(sponsor: &Pubkey, competition_id: &[u8; 16]) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[ESCROW_SEED, sponsor.as_ref(), competition_id],
        &prize_escrow::ID,
    )
}

fn attestation_pda(escrow: &Pubkey, regrader: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[ATTESTATION_SEED, escrow.as_ref(), regrader.as_ref()],
        &prize_escrow::ID,
    )
    .0
}

fn challenge_pda(escrow: &Pubkey, alt_commitment: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(
        &[CHALLENGE_SEED, escrow.as_ref(), alt_commitment.as_ref()],
        &prize_escrow::ID,
    )
    .0
}

fn attestation_bump(escrow: &Pubkey, regrader: &Pubkey) -> u8 {
    Pubkey::find_program_address(
        &[ATTESTATION_SEED, escrow.as_ref(), regrader.as_ref()],
        &prize_escrow::ID,
    )
    .1
}

fn set_time(svm: &mut LiteSVM, unix_timestamp: i64) {
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = unix_timestamp;
    svm.set_sysvar::<Clock>(&clock);
}

fn set_mint(svm: &mut LiteSVM, address: Pubkey, owner: Pubkey) {
    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint {
        mint_authority: COption::Some(Pubkey::new_unique()),
        supply: 100 * TOTAL,
        decimals: DECIMALS,
        is_initialized: true,
        freeze_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    let lamports = svm.minimum_balance_for_rent_exemption(data.len());
    svm.set_account(
        address,
        Account {
            lamports,
            data,
            owner,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn set_token_account(svm: &mut LiteSVM, address: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64) {
    let mut data = vec![0u8; spl_token::state::Account::LEN];
    spl_token::state::Account {
        mint,
        owner,
        amount,
        delegate: COption::None,
        state: spl_token::state::AccountState::Initialized,
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
    if std::env::var_os("PRIZE_ESCROW_SHOW_LOGS").is_some() {
        eprintln!("{what}:\n{}", logs(&result));
    }
    match result {
        Ok(meta) => meta,
        Err(_) => panic!("{what} failed: {}", logs(&result)),
    }
}

/// The transaction failed with exactly `code`: an EscrowError, an Anchor ErrorCode, or a raw
/// custom code (0 is the system program's AccountAlreadyInUse).
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

/// The one `E` event the transaction emitted. Events ride a self-CPI (emit_cpi!): an inner
/// instruction whose data is EVENT_IX_TAG_LE, the event's discriminator and its Borsh body, at
/// stack height 2 (the program invoking itself). No event is a `Program data:` log line (emit!)
/// any more: a caller that floods the log until it is truncated cannot hide one.
fn event<E: Discriminator + AnchorDeserialize>(meta: &TransactionMetadata) -> E {
    assert!(
        !meta
            .logs
            .iter()
            .any(|line| line.starts_with("Program data: ")),
        "an event in the log: {}",
        meta.pretty_logs()
    );
    let mut found: Vec<E> = meta
        .inner_instructions
        .iter()
        .flatten()
        .filter_map(|inner| {
            let data = inner.instruction.data.strip_prefix(EVENT_IX_TAG_LE)?;
            assert_eq!(inner.stack_height, 2, "an event CPI from the top level");
            data.strip_prefix(E::DISCRIMINATOR)
        })
        .map(|body| E::try_from_slice(body).unwrap())
        .collect();
    assert_eq!(found.len(), 1, "one event: {}", meta.pretty_logs());
    found.remove(0)
}
