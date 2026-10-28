//! A world for the escrow program that any LiteSVM front end can drive: the release build's
//! Config, one competition's escrow and every key the safeguard tests name, with an instruction
//! builder per instruction and a reader per account. tests/drill_regressions.rs and
//! tests/blast_radius.rs run it on a bare LiteSVM; chain/fuzz/prize_escrow runs the same file
//! (by `#[path]`) on crucible's TestContext, through the `Chain` trait.
//!
//! Every key is derived from its role (`Role::keypair`), so a world, a failing step sequence and
//! its repro print the same addresses on every run.

#![allow(
    dead_code,
    reason = "each test file and the crucible harness use their own subset"
)]

pub mod model;

use {
    anchor_lang::{
        event::EVENT_IX_TAG_LE,
        prelude::{Clock, Pubkey},
        solana_program::{
            bpf_loader_upgradeable,
            instruction::{AccountMeta, Instruction},
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
    prize_escrow::{
        accounts as accts, commit_hash, instruction as ixs,
        merkle::{compute_leaf_hash, hash_pair},
        result_commitment, AllowList, ArbiterChoice, Attestation, ChallengeRecord, ClaimReceipt,
        CommitRecord, Config, ConfigInit, ConfigRole, Escrow, EscrowRole, EscrowTerms, Floors,
        Limits, RegraderEntry, StopState, ARBITER_SLACK, ATTESTATION_SEED, CLAIM_SEED, ESCROW_SEED,
        EVENT_AUTHORITY_AND_BUMP, HOLD_REVIEW, MIN_ATTEST_WINDOW, MIN_CHALLENGE_WINDOW,
        MIN_CLAIM_WINDOW, MIN_HOLD_WINDOW, MIN_REVEAL_GRACE,
    },
    solana_account::Account,
    solana_keypair::Keypair,
    solana_signer::Signer,
};

// ------------------------------------------------------------------------------- the terms

pub const DECIMALS: u8 = 6;
/// The prize pot: 5,000 USDC.
pub const TOTAL: u64 = 5_000_000_000;
/// The honest result's two leaves (together TOTAL).
pub const PRIZES: [u64; 2] = [3_000_000_000, 2_000_000_000];
/// The SOL bond a result or a challenge posts.
pub const BOND: u64 = 100_000_001;
/// Config.min_bond: a production-like floor above the rent floor.
pub const MIN_BOND: u64 = 50_000_000;
pub const SOL: u64 = 1_000_000_000;
/// What the sponsor's funding account holds, and the attacker's (donations into the vault).
pub const SPONSOR_FUNDS: u64 = 4 * TOTAL;
pub const ATTACKER_FUNDS: u64 = TOTAL;

pub const HOUR: i64 = 3_600;
pub const DAY: i64 = 24 * HOUR;
pub const NOW: i64 = 1_800_000_000;
pub const ENTRIES_DEADLINE: i64 = NOW + DAY;
pub const FINAL_END: i64 = NOW + 2 * DAY;
pub const RESOLVE_DEADLINE: i64 = NOW + 7 * DAY;
/// The release minimums: 72 h to challenge, 48 h to attest, 72 h on hold, 7 days to claim.
pub const CHALLENGE_WINDOW: i64 = MIN_CHALLENGE_WINDOW;
pub const ATTEST_WINDOW: i64 = MIN_ATTEST_WINDOW;
pub const HOLD_WINDOW: i64 = MIN_HOLD_WINDOW;
pub const CLAIM_WINDOW: i64 = MIN_CLAIM_WINDOW;
/// The earliest hard deadline open_escrow accepts (EscrowTerms::validate).
pub const HARD_DEADLINE: i64 = RESOLVE_DEADLINE
    + CHALLENGE_WINDOW
    + ATTEST_WINDOW
    + HOLD_WINDOW
    + CLAIM_WINDOW
    + ARBITER_SLACK;

pub const CID: [u8; 16] = [0x53; 16];
pub const RULES: [u8; 32] = [0xf6; 32];
pub const KIT: [u8; 32] = [0xc3; 32];
pub const ENTRIES_ROOT: [u8; 32] = [0xe5; 32];
/// The honest result's document hash.
pub const RESULT: [u8; 32] = [0xb2; 32];

/// How many seats the panel has, and the quorum.
pub const SEATS: u8 = 3;
pub const K: u8 = 2;
/// Registered regraders beyond the panel, for rotations (Role::Regrader(SEATS..)).
pub const SPARES: u8 = 2;
/// The honest watcher's keys: one more than Config.revoked holds, so a guardian revoking keys
/// never runs it out of them.
pub const WATCHERS: u8 = prize_escrow::MAX_REVOKED as u8 + 1;

// ------------------------------------------------------------------------------- the keys

/// Every key a test or the oracle signs with. The first SEATS regraders are the panel at open; the
/// rest are registered spares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    Admin,
    Guardian,
    Arbiter,
    Sponsor,
    Resolver,
    Compliance,
    Regrader(u8),
    /// The honest result's winners.
    Winner(u8),
    /// Keys the adversary makes for itself: claimants in its trees (0, 1), challengers (2, 3).
    Attacker(u8),
    /// One member of the Squads multisig that will hold the arbiter (and the admin): a key with no
    /// role the program knows, since only the multisig's vault PDA signs for it.
    Member,
    /// The honest watcher's challenge keys (the next one when one is revoked).
    Watcher(u8),
    /// Pays the fees of every transaction, and the honest crank's.
    Payer,
    /// A compliance key the admin rotates in (F4), and a resolver one (F5).
    Spare(u8),
}

impl Role {
    /// This role's key, derived once per process.
    pub fn key(self) -> &'static Keypair {
        static TABLE: std::sync::OnceLock<Vec<(Role, Keypair)>> = std::sync::OnceLock::new();
        TABLE
            .get_or_init(|| Role::all().into_iter().map(|r| (r, r.derive())).collect())
            .iter()
            .find(|(role, _)| *role == self)
            .map(|(_, key)| key)
            .unwrap_or_else(|| panic!("{self:?} is not among Role::all()"))
    }

    /// An owned copy of this role's key.
    pub fn keypair(self) -> Keypair {
        self.key().insecure_clone()
    }

    fn derive(self) -> Keypair {
        let (tag, index) = match self {
            Role::Admin => (0u8, 0u8),
            Role::Guardian => (1, 0),
            Role::Arbiter => (2, 0),
            Role::Sponsor => (3, 0),
            Role::Resolver => (4, 0),
            Role::Compliance => (5, 0),
            Role::Regrader(i) => (6, i),
            Role::Winner(i) => (7, i),
            Role::Attacker(i) => (8, i),
            Role::Member => (9, 0),
            Role::Watcher(i) => (10, i),
            Role::Payer => (11, 0),
            Role::Spare(i) => (12, i),
        };
        Keypair::new_from_array(
            solana_sha256_hasher::hashv(&[b"prize-escrow/safeguard-tests", &[tag, index]])
                .to_bytes(),
        )
    }

    pub fn pubkey(self) -> Pubkey {
        self.key().pubkey()
    }

    /// Every role a world airdrops SOL to.
    pub fn all() -> Vec<Role> {
        let mut roles = vec![
            Role::Admin,
            Role::Guardian,
            Role::Arbiter,
            Role::Sponsor,
            Role::Resolver,
            Role::Compliance,
            Role::Member,
            Role::Payer,
        ];
        roles.extend((0..SEATS + SPARES).map(Role::Regrader));
        roles.extend((0..2).map(Role::Winner));
        roles.extend((0..4).map(Role::Attacker));
        roles.extend((0..WATCHERS).map(Role::Watcher));
        roles.extend((0..2).map(Role::Spare));
        roles
    }

    /// The role whose key is `key`, if any.
    pub fn of(key: &Pubkey) -> Option<Role> {
        Role::all().into_iter().find(|r| r.pubkey() == *key)
    }
}

/// Whether each panel seat is the house's: today's single-key setup lets the house hold every seat
/// (owner decision #541); the target is a majority of independent regraders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Panel {
    /// Every seat is a house key (max_house_regraders = SEATS).
    HouseMajority,
    /// Seat 0 is the house's, seats 1 and 2 independent (max_house_regraders = 1).
    IndependentMajority,
}

impl Panel {
    pub fn house(self, seat: u8) -> bool {
        match self {
            Panel::HouseMajority => seat < SEATS,
            Panel::IndependentMajority => seat == 0,
        }
    }

    pub fn max_house(self) -> u8 {
        (0..SEATS).filter(|s| self.house(*s)).count() as u8
    }
}

// ------------------------------------------------------------------------------- the chain

/// What a sent transaction did.
#[derive(Clone, Debug)]
pub struct Sent {
    pub ok: bool,
    /// The custom error code the failing instruction returned, if it returned one.
    pub code: Option<u32>,
    /// The transaction error, as text.
    pub error: String,
    pub logs: String,
    /// Each event the program emitted through its self-CPI: discriminator then body.
    pub events: Vec<Vec<u8>>,
}

impl Sent {
    /// A transaction that could not be signed (a signer missing).
    pub fn unsigned(error: String) -> Sent {
        Sent {
            ok: false,
            code: None,
            error,
            logs: String::new(),
            events: Vec::new(),
        }
    }

    /// Every `E` event in the transaction.
    pub fn events<E: Discriminator + AnchorDeserialize>(&self) -> Vec<E> {
        self.events
            .iter()
            .filter_map(|payload| payload.strip_prefix(E::DISCRIMINATOR))
            .map(|body| E::try_from_slice(body).expect("an event body"))
            .collect()
    }

    /// The one `E` event the transaction emitted.
    pub fn event<E: Discriminator + AnchorDeserialize>(&self) -> E {
        let mut found = self.events::<E>();
        assert_eq!(found.len(), 1, "one event: {}", self.logs);
        found.remove(0)
    }

    /// The event payload of an inner instruction's data, if it is an event self-CPI.
    pub fn event_payload(data: &[u8]) -> Option<Vec<u8>> {
        data.strip_prefix(EVENT_IX_TAG_LE).map(<[u8]>::to_vec)
    }
}

/// The few things a world needs from a LiteSVM front end.
pub trait Chain {
    /// Sends `ixs` in one transaction, `payer` paying, each of `signers` signing too, with a fresh
    /// blockhash.
    fn send(&mut self, ixs: &[Instruction], payer: &Keypair, signers: &[&Keypair]) -> Sent;
    fn account(&self, address: &Pubkey) -> Option<Account>;
    fn put_account(&mut self, address: Pubkey, account: Account);
    fn clock(&self) -> Clock;
    fn set_clock(&mut self, clock: &Clock);
    fn airdrop(&mut self, to: &Pubkey, lamports: u64);
    fn rent_exempt(&self, len: usize) -> u64;

    fn time(&self) -> i64 {
        self.clock().unix_timestamp
    }

    fn set_time(&mut self, unix_timestamp: i64) {
        let mut clock = self.clock();
        clock.unix_timestamp = unix_timestamp;
        self.set_clock(&clock);
    }

    /// The next slot at the same unix time (a reveal must land after its commit's slot).
    fn next_slot(&mut self);

    fn lamports(&self, address: &Pubkey) -> u64 {
        self.account(address).map_or(0, |a| a.lamports)
    }

    /// A token account's balance; 0 when it does not exist (or was closed).
    fn tokens(&self, address: &Pubkey) -> u64 {
        match self.account(address) {
            Some(a) if a.data.len() == spl_token::state::Account::LEN && a.lamports > 0 => {
                spl_token::state::Account::unpack(&a.data).map_or(0, |t| t.amount)
            }
            _ => 0,
        }
    }

    fn anchor<T: AccountDeserialize>(&self, address: &Pubkey) -> Option<T> {
        let account = self.account(address)?;
        if account.lamports == 0 || account.owner != prize_escrow::ID {
            return None;
        }
        T::try_deserialize(&mut account.data.as_slice()).ok()
    }
}

/// LiteSVM itself, as the integration tests drive it.
impl Chain for litesvm::LiteSVM {
    fn send(&mut self, ixs: &[Instruction], payer: &Keypair, signers: &[&Keypair]) -> Sent {
        use {
            solana_message::{Message, VersionedMessage},
            solana_transaction::versioned::VersionedTransaction,
            solana_transaction_error::TransactionError,
        };
        self.expire_blockhash();
        let msg = Message::new_with_blockhash(ixs, Some(&payer.pubkey()), &self.latest_blockhash());
        let mut all = vec![payer];
        for signer in signers {
            if all.iter().all(|kp| kp.pubkey() != signer.pubkey()) {
                all.push(signer);
            }
        }
        let tx = match VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &all) {
            Ok(tx) => tx,
            Err(e) => return Sent::unsigned(e.to_string()),
        };
        let collect = |inner: &litesvm::types::TransactionMetadata| -> Vec<Vec<u8>> {
            inner
                .inner_instructions
                .iter()
                .flatten()
                .filter_map(|i| Sent::event_payload(&i.instruction.data))
                .collect()
        };
        match self.send_transaction(tx) {
            Ok(meta) => Sent {
                ok: true,
                code: None,
                error: String::new(),
                logs: meta.pretty_logs(),
                events: collect(&meta),
            },
            Err(failed) => Sent {
                ok: false,
                code: match &failed.err {
                    TransactionError::InstructionError(
                        _,
                        anchor_lang::solana_program::instruction::error::InstructionError::Custom(
                            code,
                        ),
                    ) => Some(*code),
                    _ => None,
                },
                error: format!("{:?}", failed.err),
                logs: failed.meta.pretty_logs(),
                events: Vec::new(),
            },
        }
    }

    fn account(&self, address: &Pubkey) -> Option<Account> {
        self.get_account(address)
    }

    fn put_account(&mut self, address: Pubkey, account: Account) {
        self.set_account(address, account).expect("set_account");
    }

    fn clock(&self) -> Clock {
        self.get_sysvar::<Clock>()
    }

    fn set_clock(&mut self, clock: &Clock) {
        self.set_sysvar::<Clock>(clock);
    }

    fn next_slot(&mut self) {
        let clock = self.get_sysvar::<Clock>();
        self.warp_to_slot(clock.slot + 1);
        // warp_to_slot keeps the unix timestamp; restate it in case a version moves it.
        let mut moved = self.get_sysvar::<Clock>();
        moved.unix_timestamp = clock.unix_timestamp;
        self.set_sysvar::<Clock>(&moved);
    }

    fn airdrop(&mut self, to: &Pubkey, lamports: u64) {
        litesvm::LiteSVM::airdrop(self, to, lamports).expect("airdrop");
    }

    fn rent_exempt(&self, len: usize) -> u64 {
        self.minimum_balance_for_rent_exemption(len)
    }
}

// ------------------------------------------------------------------------------- trees

/// A payout tree: a result document, its leaves, the total posted with it, and what the program
/// derives from them.
#[derive(Clone, Debug)]
pub struct Tree {
    pub name: &'static str,
    pub doc: [u8; 32],
    pub leaves: Vec<(Pubkey, u64)>,
    pub total: u64,
    pub root: [u8; 32],
    pub proofs: Vec<Vec<[u8; 32]>>,
    pub commitment: [u8; 32],
}

impl Tree {
    pub fn new(
        name: &'static str,
        escrow: &Pubkey,
        doc: [u8; 32],
        leaves: Vec<(Pubkey, u64)>,
        total: u64,
    ) -> Tree {
        let hashes: Vec<[u8; 32]> = leaves
            .iter()
            .map(|(claimant, amount)| compute_leaf_hash(escrow, claimant, *amount))
            .collect();
        let (root, proofs) = merkle_tree(&hashes);
        Tree {
            name,
            doc,
            leaves,
            total,
            root,
            proofs,
            commitment: result_commitment(&doc, &root, total),
        }
    }

    /// The leaf index `claimant` holds, if any.
    pub fn leaf_of(&self, claimant: &Pubkey) -> Option<usize> {
        self.leaves.iter().position(|(c, _)| c == claimant)
    }
}

/// A sorted-pair merkle tree over `leaves` (the off-chain builder's shape: an odd node moves up a
/// level unpaired): the root and each leaf's proof, leaf to root.
pub fn merkle_tree(leaves: &[[u8; 32]]) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
    let mut proofs = vec![Vec::new(); leaves.len()];
    let mut level: Vec<([u8; 32], Vec<usize>)> = leaves
        .iter()
        .enumerate()
        .map(|(i, leaf)| (*leaf, vec![i]))
        .collect();
    level.sort_by_key(|a| a.0);
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            match pair {
                [left, right] => {
                    for &i in &left.1 {
                        proofs[i].push(right.0);
                    }
                    for &i in &right.1 {
                        proofs[i].push(left.0);
                    }
                    let members = left.1.iter().chain(&right.1).copied().collect();
                    next.push((hash_pair(&left.0, &right.0), members));
                }
                [odd] => next.push(odd.clone()),
                _ => unreachable!("chunks of two"),
            }
        }
        level = next;
    }
    (level.first().map_or([0; 32], |node| node.0), proofs)
}

/// The salt a challenger commits `alt_commitment` with.
pub fn salt_for(challenger: &Pubkey, alt_commitment: &[u8; 32]) -> [u8; 32] {
    solana_sha256_hasher::hashv(&[b"blast-salt", challenger.as_ref(), alt_commitment]).to_bytes()
}

// ------------------------------------------------------------------------------- the world

pub const EVENT_AUTHORITY: Pubkey = EVENT_AUTHORITY_AND_BUMP.0;

/// One Config and one escrow, opened with `terms` by the sponsor and its entries root committed.
#[derive(Clone, Debug)]
pub struct World {
    pub panel: Panel,
    pub mint: Pubkey,
    /// The sponsor's funding account (not its associated one, where refunds land).
    pub funding: Pubkey,
    /// The attacker's token account it donates into the vault from.
    pub attacker_funding: Pubkey,
    pub cid: [u8; 16],
    pub terms: EscrowTerms,
    /// The escrow PDA (the sponsor's, at `cid`) and its vault, derived once.
    escrow_key: Pubkey,
    vault_key: Pubkey,
}

impl World {
    /// The Config every world opens under: the mint and the sponsor allowed, the panel and the
    /// spares registered (house flags from `panel`), production-like floors and a minimum bond,
    /// caps and a bucket above the pot.
    pub fn config_init(panel: Panel, mint: Pubkey) -> ConfigInit {
        let mut regraders: Vec<RegraderEntry> = (0..SEATS)
            .map(|s| RegraderEntry {
                key: Role::Regrader(s).pubkey(),
                house: panel.house(s),
            })
            .collect();
        regraders.extend((SEATS..SEATS + SPARES).map(|s| RegraderEntry {
            key: Role::Regrader(s).pubkey(),
            house: false,
        }));
        ConfigInit {
            admin: Role::Admin.pubkey(),
            guardian: Role::Guardian.pubkey(),
            arbiter: Role::Arbiter.pubkey(),
            limits: Self::limits(panel),
            floors: Floors {
                min_challenge_window: MIN_CHALLENGE_WINDOW,
                min_attest_window: MIN_ATTEST_WINDOW,
                min_hold_window: MIN_HOLD_WINDOW,
                min_claim_window: MIN_CLAIM_WINDOW,
                reveal_grace: MIN_REVEAL_GRACE,
            },
            mints: vec![mint],
            sponsors: vec![Role::Sponsor.pubkey()],
            regraders,
        }
    }

    pub fn limits(panel: Panel) -> Limits {
        Limits {
            escrow_cap: 10 * TOTAL,
            global_cap: 100 * TOTAL,
            flow_capacity: 10 * TOTAL,
            flow_period: DAY,
            min_bond: MIN_BOND,
            max_house_regraders: panel.max_house(),
        }
    }

    /// The terms the sponsor opens with.
    pub fn default_terms() -> EscrowTerms {
        EscrowTerms {
            total: TOTAL,
            rules_sha256: RULES,
            resolver: Role::Resolver.pubkey(),
            compliance: Role::Compliance.pubkey(),
            arbiter: Role::Arbiter.pubkey(),
            refund_to: Role::Sponsor.pubkey(),
            regraders: (0..SEATS).map(|s| Role::Regrader(s).pubkey()).collect(),
            k: K,
            bond_lamports: BOND,
            entries_deadline: ENTRIES_DEADLINE,
            final_end: FINAL_END,
            resolve_deadline: RESOLVE_DEADLINE,
            challenge_window: CHALLENGE_WINDOW,
            attest_window: ATTEST_WINDOW,
            hold_window: HOLD_WINDOW,
            claim_window: CLAIM_WINDOW,
            hard_deadline: HARD_DEADLINE,
        }
    }

    /// The program must already be loaded at prize_escrow::ID (each front end loads the release
    /// build its own way). Funds every key, creates the mint and the funding accounts, names the
    /// admin the upgrade authority, creates the Config, and (with `open`) opens the escrow at NOW
    /// and commits its entries root.
    pub fn create(c: &mut impl Chain, panel: Panel, open: bool) -> World {
        c.set_time(NOW);
        for role in Role::all() {
            c.airdrop(&role.pubkey(), 1_000 * SOL);
        }
        let mint = Role::Admin.pubkey_derived(b"mint");
        let funding = Role::Sponsor.pubkey_derived(b"funding");
        let attacker_funding = Role::Attacker(0).pubkey_derived(b"funding");
        put_mint(c, mint, SPONSOR_FUNDS + ATTACKER_FUNDS);
        put_token_account(
            c,
            funding,
            mint,
            Role::Sponsor.pubkey(),
            SPONSOR_FUNDS,
            false,
        );
        put_token_account(
            c,
            attacker_funding,
            mint,
            Role::Attacker(0).pubkey(),
            ATTACKER_FUNDS,
            false,
        );
        set_upgrade_authority(c, Some(Role::Admin.pubkey()));
        let escrow_key = escrow_pda(&Role::Sponsor.pubkey(), &CID);
        let world = World {
            panel,
            mint,
            funding,
            attacker_funding,
            cid: CID,
            terms: Self::default_terms(),
            escrow_key,
            vault_key: get_associated_token_address(&escrow_key, &mint),
        };
        let init = world.initialize_config_ix(Role::Admin.pubkey(), Self::config_init(panel, mint));
        expect_ok(
            world.send(c, init, &[&Role::Admin.keypair()]),
            "initialize_config",
        );
        if open {
            let open = world.open_ix(&world.terms);
            expect_ok(
                world.send(c, open, &[&Role::Sponsor.keypair()]),
                "open_escrow",
            );
            let commit = world.commit_entries_ix(Role::Resolver.pubkey());
            expect_ok(
                world.send(c, commit, &[&Role::Resolver.keypair()]),
                "commit_entries",
            );
        }
        world
    }

    /// Sends `ix`, the Payer paying the fee, `signers` signing.
    pub fn send(&self, c: &mut impl Chain, ix: Instruction, signers: &[&Keypair]) -> Sent {
        c.send(&[ix], &Role::Payer.keypair(), signers)
    }

    // --------------------------------------------------------------------- addresses

    pub fn escrow(&self) -> Pubkey {
        self.escrow_key
    }

    pub fn vault(&self) -> Pubkey {
        self.vault_key
    }

    pub fn ata(&self, owner: &Pubkey) -> Pubkey {
        get_associated_token_address(owner, &self.mint)
    }

    pub fn receipt(&self, claimant: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(
            &[CLAIM_SEED, self.escrow().as_ref(), claimant.as_ref()],
            &prize_escrow::ID,
        )
        .0
    }

    pub fn attestation(&self, regrader: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(
            &[ATTESTATION_SEED, self.escrow().as_ref(), regrader.as_ref()],
            &prize_escrow::ID,
        )
        .0
    }

    pub fn challenge_pda(&self, alt_commitment: &[u8; 32]) -> Pubkey {
        ChallengeRecord::pda(&self.escrow(), alt_commitment).0
    }

    pub fn commit_pda(&self, challenger: &Pubkey, hash: &[u8; 32]) -> Pubkey {
        CommitRecord::pda(&self.escrow(), challenger, hash).0
    }

    // --------------------------------------------------------------------- readers

    pub fn state(&self, c: &impl Chain) -> Option<Escrow> {
        c.anchor(&self.escrow())
    }

    pub fn config(&self, c: &impl Chain) -> Config {
        c.anchor(&Config::pda().0).expect("the Config")
    }

    pub fn challenge(&self, c: &impl Chain, alt_commitment: &[u8; 32]) -> Option<ChallengeRecord> {
        c.anchor(&self.challenge_pda(alt_commitment))
    }

    pub fn receipt_state(&self, c: &impl Chain, claimant: &Pubkey) -> Option<ClaimReceipt> {
        c.anchor(&self.receipt(claimant))
    }

    pub fn voted(&self, c: &impl Chain, regrader: &Pubkey) -> Option<Attestation> {
        c.anchor(&self.attestation(regrader))
    }

    /// The escrow clock now (config::escrow_now).
    pub fn escrow_now(&self, c: &impl Chain) -> i64 {
        let escrow = self.state(c).expect("the escrow");
        prize_escrow::escrow_now(&escrow, &self.config(c), c.time())
    }

    /// The trees the oracle and the drill tests post, challenge and claim with: the honest one,
    /// then four the adversary may bond (a root of its own claimants, the honest document over a
    /// root that pays an attacker, an over-paying root, and the honest root at a lower total).
    pub fn trees(&self) -> Vec<Tree> {
        let e = self.escrow();
        let (w0, w1) = (Role::Winner(0).pubkey(), Role::Winner(1).pubkey());
        let (x0, x1) = (Role::Attacker(0).pubkey(), Role::Attacker(1).pubkey());
        vec![
            Tree::new(
                "honest",
                &e,
                RESULT,
                vec![(w0, PRIZES[0]), (w1, PRIZES[1])],
                TOTAL,
            ),
            Tree::new(
                "steal",
                &e,
                [0x5e; 32],
                vec![(x0, TOTAL - 1), (x1, 1)],
                TOTAL,
            ),
            Tree::new(
                "honest-doc-evil-root",
                &e,
                RESULT,
                vec![(w0, PRIZES[0]), (x0, PRIZES[1])],
                TOTAL,
            ),
            Tree::new(
                "overpay",
                &e,
                [0x0f; 32],
                vec![(w0, TOTAL), (x1, PRIZES[1])],
                TOTAL,
            ),
            Tree::new(
                "honest-root-low-total",
                &e,
                RESULT,
                vec![(w0, PRIZES[0]), (w1, PRIZES[1])],
                TOTAL / 2,
            ),
        ]
    }

    // --------------------------------------------------------------------- instructions

    pub fn initialize_config_ix(&self, authority: Pubkey, init: ConfigInit) -> Instruction {
        instruction(
            accts::InitializeConfig {
                authority,
                config: Config::pda().0,
                program_data: program_data_pda(),
                system_program: system_program::ID,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::InitializeConfig { init },
        )
    }

    /// open_escrow by the sponsor from its funding account, with this world's mint and cid.
    pub fn open_ix(&self, terms: &EscrowTerms) -> Instruction {
        self.open_ix_as(Role::Sponsor.pubkey(), self.funding, self.mint, terms)
    }

    pub fn open_ix_as(
        &self,
        sponsor: Pubkey,
        funding: Pubkey,
        mint: Pubkey,
        terms: &EscrowTerms,
    ) -> Instruction {
        let escrow = escrow_pda(&sponsor, &self.cid);
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
                config: Config::pda().0,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::OpenEscrow {
                competition_id: self.cid,
                terms: terms.clone(),
            },
        )
    }

    pub fn fund_ix(&self, sponsor: Pubkey, amount: u64) -> Instruction {
        instruction(
            accts::Fund {
                sponsor,
                escrow: self.escrow(),
                mint: self.mint,
                sponsor_token_account: self.funding,
                vault: self.vault(),
                token_program: token::ID,
                config: Config::pda().0,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Fund { amount },
        )
    }

    pub fn commit_entries_ix(&self, resolver: Pubkey) -> Instruction {
        self.commit_entries_with_ix(resolver, ENTRIES_ROOT, 2)
    }

    /// commit_entries by `resolver` with any root and count.
    pub fn commit_entries_with_ix(
        &self,
        resolver: Pubkey,
        entries_root: [u8; 32],
        entries_count: u32,
    ) -> Instruction {
        instruction(
            accts::CommitEntries {
                resolver,
                escrow: self.escrow(),
                config: Config::pda().0,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::CommitEntries {
                entries_root,
                entries_count,
            },
        )
    }

    pub fn post_ix(&self, resolver: Pubkey, tree: &Tree, total: u64) -> Instruction {
        instruction(
            accts::PostResult {
                resolver,
                escrow: self.escrow(),
                mint: self.mint,
                vault: self.vault(),
                token_program: token::ID,
                system_program: system_program::ID,
                config: Config::pda().0,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::PostResult {
                payout_root: tree.root,
                result_sha256: tree.doc,
                kit_sha256: KIT,
                total,
            },
        )
    }

    /// The commit hash and salt `challenger` bonds `tree` with.
    pub fn commit_of(&self, challenger: &Pubkey, tree: &Tree) -> ([u8; 32], [u8; 32]) {
        let salt = salt_for(challenger, &tree.commitment);
        (commit_hash(&tree.commitment, challenger, &salt), salt)
    }

    pub fn challenge_commit_ix(&self, challenger: Pubkey, hash: [u8; 32]) -> Instruction {
        instruction(
            accts::ChallengeCommit {
                challenger,
                config: Config::pda().0,
                escrow: self.escrow(),
                commit: self.commit_pda(&challenger, &hash),
                system_program: system_program::ID,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ChallengeCommit { hash },
        )
    }

    pub fn challenge_reveal_ix(
        &self,
        challenger: Pubkey,
        hash: [u8; 32],
        salt: [u8; 32],
        tree: &Tree,
    ) -> Instruction {
        instruction(
            accts::ChallengeReveal {
                challenger,
                config: Config::pda().0,
                escrow: self.escrow(),
                mint: self.mint,
                vault: self.vault(),
                commit: self.commit_pda(&challenger, &hash),
                challenge: self.challenge_pda(&tree.commitment),
                token_program: token::ID,
                system_program: system_program::ID,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ChallengeReveal {
                salt,
                alt_result_sha256: tree.doc,
                alt_payout_root: tree.root,
                alt_total: tree.total,
                alt_commitment: tree.commitment,
            },
        )
    }

    /// Both steps of a challenge by `challenger` (its key) with `tree`: the commit, a slot, the
    /// reveal. The commit's result when it fails, else the reveal's.
    pub fn challenge_with(&self, c: &mut impl Chain, challenger: &Keypair, tree: &Tree) -> Sent {
        let (hash, salt) = self.commit_of(&challenger.pubkey(), tree);
        let commit = self.send(
            c,
            self.challenge_commit_ix(challenger.pubkey(), hash),
            &[challenger],
        );
        if !commit.ok {
            return commit;
        }
        c.next_slot();
        let reveal = self.challenge_reveal_ix(challenger.pubkey(), hash, salt, tree);
        self.send(c, reveal, &[challenger])
    }

    /// attest by `regrader` on `commitment`, the Challenge PDA of that commitment passed in when
    /// it exists.
    pub fn attest_ix(&self, c: &impl Chain, regrader: Pubkey, commitment: [u8; 32]) -> Instruction {
        let pda = self.challenge_pda(&commitment);
        let challenge = c.account(&pda).filter(|a| a.lamports > 0).map(|_| pda);
        self.attest_with_ix(regrader, commitment, challenge)
    }

    /// attest by `regrader` on `commitment` with any challenge account (or none).
    pub fn attest_with_ix(
        &self,
        regrader: Pubkey,
        commitment: [u8; 32],
        challenge: Option<Pubkey>,
    ) -> Instruction {
        instruction(
            accts::Attest {
                regrader,
                escrow: self.escrow(),
                attestation: self.attestation(&regrader),
                challenge,
                system_program: system_program::ID,
                config: Config::pda().0,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Attest { commitment },
        )
    }

    /// settle, the recorded challenger passed in when there is one.
    pub fn settle_ix(&self, escrow: &Escrow) -> Instruction {
        instruction(
            accts::Settle {
                escrow: self.escrow(),
                mint: self.mint,
                vault: self.vault(),
                resolver: escrow.resolver,
                challenger: (escrow.challenger != Pubkey::default()).then_some(escrow.challenger),
                token_program: token::ID,
                config: Config::pda().0,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Settle {},
        )
    }

    /// arbiter_resolve by `arbiter`: Posted, or the challenge of `alt` (its challenger as stored).
    pub fn arbiter_ix(
        &self,
        escrow: &Escrow,
        arbiter: Pubkey,
        alt: Option<&ChallengeRecord>,
        commitment: [u8; 32],
    ) -> Instruction {
        let choice = if alt.is_some() {
            ArbiterChoice::Alternative
        } else {
            ArbiterChoice::Posted
        };
        self.arbiter_with_ix(
            escrow,
            arbiter,
            choice,
            commitment,
            alt.map(|ch| self.challenge_pda(&ch.alt_commitment)),
            alt.map(|ch| ch.challenger),
        )
    }

    /// arbiter_resolve by `arbiter` with any choice, commitment, challenge and challenger accounts.
    pub fn arbiter_with_ix(
        &self,
        escrow: &Escrow,
        arbiter: Pubkey,
        choice: ArbiterChoice,
        commitment: [u8; 32],
        challenge: Option<Pubkey>,
        challenger: Option<Pubkey>,
    ) -> Instruction {
        instruction(
            accts::ArbiterResolve {
                arbiter,
                escrow: self.escrow(),
                mint: self.mint,
                vault: self.vault(),
                resolver: escrow.resolver,
                challenge,
                challenger,
                token_program: token::ID,
                config: Config::pda().0,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ArbiterResolve { choice, commitment },
        )
    }

    pub fn request_claim_ix(
        &self,
        claimant: Pubkey,
        total_amount: u64,
        proof: Vec<[u8; 32]>,
    ) -> Instruction {
        instruction(
            accts::RequestClaim {
                claimant,
                payer: Role::Payer.pubkey(),
                escrow: self.escrow(),
                receipt: self.receipt(&claimant),
                system_program: system_program::ID,
                config: Config::pda().0,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::RequestClaim {
                total_amount,
                proof,
            },
        )
    }

    pub fn claim_ix(
        &self,
        claimant: Pubkey,
        compliance: Option<Pubkey>,
        total_amount: u64,
        amount: u64,
        proof: Vec<[u8; 32]>,
    ) -> Instruction {
        instruction(
            accts::Claim {
                claimant,
                payer: Role::Payer.pubkey(),
                compliance,
                escrow: self.escrow(),
                mint: self.mint,
                vault: self.vault(),
                claimant_token_account: self.ata(&claimant),
                receipt: self.receipt(&claimant),
                token_program: token::ID,
                associated_token_program: associated_token::ID,
                system_program: system_program::ID,
                config: Config::pda().0,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Claim {
                total_amount,
                amount,
                proof,
            },
        )
    }

    pub fn hold_ix(&self, compliance: Pubkey, claimant: Pubkey) -> Instruction {
        instruction(
            accts::Hold {
                compliance,
                escrow: self.escrow(),
                receipt: self.receipt(&claimant),
                system_program: system_program::ID,
                config: Config::pda().0,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Hold {
                claimant,
                reason: HOLD_REVIEW,
            },
        )
    }

    pub fn release_ix(&self, compliance: Pubkey, claimant: Pubkey) -> Instruction {
        instruction(
            accts::ReleaseHold {
                compliance,
                escrow: self.escrow(),
                receipt: self.receipt(&claimant),
                config: Config::pda().0,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ReleaseHold { claimant },
        )
    }

    pub fn refund_ix(&self, escrow: &Escrow) -> Instruction {
        let refund_to = escrow.refund_to;
        instruction(
            accts::Refund {
                payer: Role::Payer.pubkey(),
                escrow: self.escrow(),
                mint: self.mint,
                vault: self.vault(),
                refund_to,
                refund_to_token_account: self.ata(&refund_to),
                resolver: escrow.resolver,
                token_program: token::ID,
                associated_token_program: associated_token::ID,
                system_program: system_program::ID,
                config: Config::pda().0,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Refund {},
        )
    }

    pub fn close_challenge_ix(&self, challenge: &ChallengeRecord) -> Instruction {
        instruction(
            accts::CloseChallenge {
                escrow: self.escrow(),
                challenge: self.challenge_pda(&challenge.alt_commitment),
                challenger: challenge.challenger,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::CloseChallenge {},
        )
    }

    pub fn close_commit_ix(&self, commit: &Pubkey, challenger: Pubkey) -> Instruction {
        instruction(
            accts::CloseCommit {
                escrow: self.escrow(),
                commit: *commit,
                challenger,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::CloseCommit {},
        )
    }

    /// close_attestation of `regrader`'s vote, its rent back to `regrader`.
    pub fn close_attestation_ix(&self, regrader: Pubkey) -> Instruction {
        instruction(
            accts::CloseAttestation {
                escrow: self.escrow(),
                attestation: self.attestation(&regrader),
                regrader,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::CloseAttestation {},
        )
    }

    pub fn set_stop_ix(&self, authority: Pubkey, level: StopState) -> Instruction {
        instruction(
            accts::SetStop {
                authority,
                config: Config::pda().0,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::SetStop { level },
        )
    }

    pub fn extend_stop_ix(&self, admin: Pubkey, extra: i64) -> Instruction {
        instruction(
            accts::ExtendStop {
                admin,
                config: Config::pda().0,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ExtendStop { extra },
        )
    }

    fn guard(&self, authority: Pubkey) -> accts::GuardEscrow {
        accts::GuardEscrow {
            authority,
            config: Config::pda().0,
            escrow: self.escrow(),
            event_authority: EVENT_AUTHORITY,
            program: prize_escrow::ID,
        }
    }

    pub fn set_freeze_ix(&self, authority: Pubkey, frozen: bool) -> Instruction {
        instruction(self.guard(authority), ixs::SetFreeze { frozen })
    }

    pub fn extend_freeze_ix(&self, authority: Pubkey, extra: i64) -> Instruction {
        instruction(self.guard(authority), ixs::ExtendFreeze { extra })
    }

    pub fn escalate_ix(&self, authority: Pubkey) -> Instruction {
        instruction(self.guard(authority), ixs::Escalate {})
    }

    pub fn set_revoked_ix(&self, authority: Pubkey, key: Pubkey, revoked: bool) -> Instruction {
        instruction(
            accts::SetStop {
                authority,
                config: Config::pda().0,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::SetRevoked { key, revoked },
        )
    }

    pub fn rotate_ix(
        &self,
        admin: Pubkey,
        role: EscrowRole,
        old: Pubkey,
        new: Pubkey,
    ) -> Instruction {
        instruction(
            accts::RotateRole {
                admin,
                config: Config::pda().0,
                escrow: self.escrow(),
                old_attestation: (role == EscrowRole::Regrader).then(|| self.attestation(&old)),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::RotateRole { role, old, new },
        )
    }

    fn admin_config(&self, admin: Pubkey) -> accts::AdminConfig {
        accts::AdminConfig {
            admin,
            config: Config::pda().0,
            event_authority: EVENT_AUTHORITY,
            program: prize_escrow::ID,
        }
    }

    pub fn set_limits_ix(&self, admin: Pubkey, limits: Limits) -> Instruction {
        instruction(self.admin_config(admin), ixs::SetLimits { limits })
    }

    pub fn set_floors_ix(&self, admin: Pubkey, floors: Floors) -> Instruction {
        instruction(self.admin_config(admin), ixs::SetFloors { floors })
    }

    pub fn set_min_regraders_ix(&self, admin: Pubkey, min_regraders: u8) -> Instruction {
        instruction(
            self.admin_config(admin),
            ixs::SetMinRegraders { min_regraders },
        )
    }

    pub fn set_allowed_ix(
        &self,
        admin: Pubkey,
        list: AllowList,
        key: Pubkey,
        allowed: bool,
        house: bool,
    ) -> Instruction {
        instruction(
            self.admin_config(admin),
            ixs::SetAllowed {
                list,
                key,
                allowed,
                house,
            },
        )
    }

    pub fn set_config_role_ix(&self, admin: Pubkey, role: ConfigRole, key: Pubkey) -> Instruction {
        instruction(self.admin_config(admin), ixs::SetConfigRole { role, key })
    }

    /// A classic Token transfer of `amount` from the attacker's funding account into the vault
    /// (a donation: anyone may send tokens to a token account).
    pub fn donate_tokens_ix(&self, amount: u64) -> Instruction {
        let mut data = vec![3u8];
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: token::ID,
            accounts: vec![
                AccountMeta::new(self.attacker_funding, false),
                AccountMeta::new(self.vault(), false),
                AccountMeta::new_readonly(Role::Attacker(0).pubkey(), true),
            ],
            data,
        }
    }

    /// A system transfer of `lamports` from the attacker to the escrow account.
    pub fn donate_lamports_ix(&self, lamports: u64) -> Instruction {
        let mut data = 2u32.to_le_bytes().to_vec();
        data.extend_from_slice(&lamports.to_le_bytes());
        Instruction {
            program_id: system_program::ID,
            accounts: vec![
                AccountMeta::new(Role::Attacker(0).pubkey(), true),
                AccountMeta::new(self.escrow(), false),
            ],
            data,
        }
    }
}

impl Role {
    /// An address derived from this role and `what`, for accounts that are not keys.
    pub fn pubkey_derived(self, what: &[u8]) -> Pubkey {
        Pubkey::new_from_array(
            solana_sha256_hasher::hashv(&[b"derived", self.pubkey().as_ref(), what]).to_bytes(),
        )
    }
}

// ------------------------------------------------------------------------------- helpers

pub fn escrow_pda(sponsor: &Pubkey, cid: &[u8; 16]) -> Pubkey {
    Pubkey::find_program_address(&[ESCROW_SEED, sponsor.as_ref(), cid], &prize_escrow::ID).0
}

pub fn program_data_pda() -> Pubkey {
    Pubkey::find_program_address(&[prize_escrow::ID.as_ref()], &bpf_loader_upgradeable::ID).0
}

/// Rewrites the ProgramData header the front end's add_program wrote (no upgrade authority) to
/// name `authority`, as a deployed program's would.
pub fn set_upgrade_authority(c: &mut impl Chain, authority: Option<Pubkey>) {
    let address = program_data_pda();
    let mut account = c.account(&address).expect("the ProgramData account");
    // UpgradeableLoaderState::ProgramData: u32 tag 3, u64 slot, then Option<Pubkey>.
    assert_eq!(account.data[..4], [3, 0, 0, 0]);
    match authority {
        Some(key) => {
            account.data[12] = 1;
            account.data[13..45].copy_from_slice(key.as_ref());
        }
        None => {
            account.data[12] = 0;
            account.data[13..45].fill(0);
        }
    }
    c.put_account(address, account);
}

pub fn instruction(accounts: impl ToAccountMetas, data: impl InstructionData) -> Instruction {
    Instruction::new_with_bytes(
        prize_escrow::ID,
        &data.data(),
        accounts.to_account_metas(None),
    )
}

pub fn put_mint(c: &mut impl Chain, address: Pubkey, supply: u64) {
    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint {
        mint_authority: COption::Some(Role::Admin.pubkey_derived(b"mint-authority")),
        supply,
        decimals: DECIMALS,
        is_initialized: true,
        freeze_authority: COption::Some(Role::Admin.pubkey_derived(b"freeze-authority")),
    }
    .pack_into_slice(&mut data);
    let lamports = c.rent_exempt(data.len());
    c.put_account(
        address,
        Account {
            lamports,
            data,
            owner: token::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
}

pub fn put_token_account(
    c: &mut impl Chain,
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
    let lamports = c.rent_exempt(data.len());
    c.put_account(
        address,
        Account {
            lamports,
            data,
            owner: token::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
}

/// The transaction succeeded.
#[track_caller]
pub fn expect_ok(sent: Sent, what: &str) -> Sent {
    assert!(sent.ok, "{what} failed: {}\n{}", sent.error, sent.logs);
    sent
}

/// The transaction failed with exactly `code`.
#[track_caller]
pub fn expect_refused(sent: Sent, code: impl Into<u32>, what: &str) {
    let code = code.into();
    assert_eq!(
        sent.code,
        Some(code),
        "{what}: expected error {code}, got {} {}\n{}",
        if sent.ok { "success" } else { "failure" },
        sent.error,
        sent.logs
    );
}
