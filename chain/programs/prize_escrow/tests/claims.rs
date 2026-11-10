//! Claims on the release build (`node scripts/chain/build.ts release` writes the canonical SBPF v2
//! target/deploy/prize_escrow.so; run it first): request_claim, claim, hold, release_hold and
//! close_receipt, and the merkle vectors the server's tree builder writes
//! (tests/fixtures/chain/merkle-vectors.json).
//!
//! Every vector is checked against the program's own merkle code (src/merkle.rs, the code the
//! release build runs), and this file's tree builder must reproduce every fixture root and proof
//! before the LiteSVM tests post its roots: the claimants there are fixed keys nobody holds, so
//! the on-chain claims sign with keypairs over trees built the server's way.
//!
//! The LiteSVM escrows go through the real open_escrow, commit_entries, post_result and settle
//! (no state is written by hand), so each claim runs against a Claimable escrow at the release
//! constants' 24 h challenge and hold windows. Time moves by rewriting the Clock sysvar. Winners
//! hold no SOL at all: a separate payer (or the compliance key) pays every fee and rent.
//!
//! Two of run review 3's regressions end in claims, so they live here: a self-paying payout root
//! posted with the honest document hash is challenged by its commitment and the honest root is
//! what claims pay, and a late arbiter_resolve keeps its claims live past hard_deadline. Run
//! review 4's binding vote ends in claims too: the regraders' quorum for the honest root applies
//! it with no arbiter, and its claims pay at once.

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
        accounts as accts, commit_hash, instruction as ixs,
        merkle::{compute_leaf_hash, hash_pair, verify_proof},
        result_commitment, ArbiterChoice, ArbiterResolved, ChallengeRecord, ClaimReceipt,
        ClaimRequested, Claimed, CommitRecord, Escrow, EscrowError, EscrowStatus, EscrowTerms,
        HoldPlaced, HoldReleased, ReceiptClosed, Refunded, SettleOutcome, Settled,
        ATTESTATION_SEED, CHALLENGE_SEED, CLAIM_SEED, ESCROW_SEED, EVENT_AUTHORITY_AND_BUMP,
        HOLD_GEO, HOLD_NONE, HOLD_REVIEW, HOLD_SANCTIONS, HOLD_TAX_FORM_REQUIRED, MAX_PROOF_LEN,
        MIN_ATTEST_WINDOW, MIN_CHALLENGE_WINDOW, MIN_HOLD_WINDOW, MIN_REVEAL_GRACE,
    },
    serde_json::Value,
    solana_account::Account,
    solana_keccak_hasher::hashv,
    solana_keypair::Keypair,
    solana_message::{v0, AddressLookupTableAccount, Message, VersionedMessage},
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
    solana_transaction_error::TransactionError,
};

/// The PDA ["__event_authority"] that signs the program's event self-CPIs.
const EVENT_AUTHORITY: Pubkey = EVENT_AUTHORITY_AND_BUMP.0;
const VECTORS_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/chain/merkle-vectors.json"
));

/// The most bytes a transaction may take on the wire (the 1,280-byte IPv6 minimum MTU less 48
/// bytes of headers).
const PACKET_DATA_SIZE: usize = 1_232;
const ADDRESS_LOOKUP_TABLE_PROGRAM: &str = "AddressLookupTab1e1111111111111111111111111";

const CID: [u8; 16] = [0xc1; 16];
const DECIMALS: u8 = 6;
/// 5,000 tokens of a 6-decimal mint.
const TOTAL: u64 = 5_000_000_000;
const BOND: u64 = 100_000_001;
const SOL: u64 = 1_000_000_000;
/// The four winners' leaves: 4,900 tokens awarded, 100 left to refund after the claim deadline.
const PRIZES: [u64; 4] = [2_500_000_000, 1_500_000_000, 750_000_000, 150_000_000];
const AWARDED: u64 = 4_900_000_000;

const HOUR: i64 = 3_600;
const DAY: i64 = 24 * HOUR;
/// 2027-01-15T08:00:00Z: when every test opens its escrow.
const NOW: i64 = 1_800_000_000;
const ENTRIES_DEADLINE: i64 = NOW + DAY;
const FINAL_END: i64 = NOW + 2 * DAY;
const RESOLVE_DEADLINE: i64 = NOW + 7 * DAY;
const CLAIM_WINDOW: i64 = 30 * DAY;
const HARD_DEADLINE: i64 = NOW + 365 * DAY;
/// post_result runs as the final phase ends.
const POST_AT: i64 = FINAL_END;
/// settle runs as the 24 h challenge window ends: the escrow is Claimable from here.
const CLAIMABLE_AT: i64 = POST_AT + 24 * HOUR;
const CLAIM_DEADLINE: i64 = CLAIMABLE_AT + CLAIM_WINDOW;

const ENTRIES_ROOT: [u8; 32] = [0xe5; 32];
const RESULT: [u8; 32] = [0xb2; 32];
const KIT: [u8; 32] = [0xc3; 32];
const RULES: [u8; 32] = [0xf6; 32];
const ALT: [u8; 32] = [0xd4; 32];

// ------------------------------------------------------------------------ the merkle vectors

fn vectors() -> Value {
    let v: Value =
        serde_json::from_str(VECTORS_JSON).expect("tests/fixtures/chain/merkle-vectors.json");
    assert_eq!(v["schema"], "agent-fun/merkle-vectors/v1");
    v
}

fn hex(text: &Value) -> Vec<u8> {
    let text = text.as_str().expect("a hex string");
    assert!(text.len().is_multiple_of(2), "odd hex: {text}");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex32(text: &Value) -> [u8; 32] {
    hex(text).try_into().expect("32 bytes")
}

fn nodes(list: &Value) -> Vec<[u8; 32]> {
    list.as_array()
        .expect("a node list")
        .iter()
        .map(hex32)
        .collect()
}

/// A base58 key, checked against its `*_hex` twin.
fn key_of(v: &Value, field: &str) -> Pubkey {
    let key: Pubkey = v[field].as_str().unwrap().parse().unwrap();
    assert_eq!(
        key.to_bytes(),
        hex32(&v[format!("{field}_hex")]),
        "{field} base58 and hex"
    );
    key
}

fn amount_of(v: &Value) -> u64 {
    v["amount"]
        .as_str()
        .expect("a decimal string")
        .parse()
        .unwrap()
}

/// The server's tree (server/chain/merkle.ts buildMerkleTree, from solana-foundation/rewards): the
/// leaves sorted by hash, paired left to right level by level, an odd last node moving up
/// unpaired. Returns the root (all zero for no leaves) and each leaf's proof, in input order.
fn merkle_tree(leaves: &[[u8; 32]]) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
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

/// The entries-tree leaf: keccak256(0x01 || keccak256(submission_id || wallet ||
/// transcripts_sha256 || sha256(entry_signature))).
fn entry_leaf(
    submission_id: &[u8],
    wallet: &Pubkey,
    transcripts: &[u8],
    sig_sha256: &[u8],
) -> [u8; 32] {
    let inner = hashv(&[submission_id, wallet.as_ref(), transcripts, sig_sha256]).to_bytes();
    hashv(&[&[0x01u8][..], &inner[..]]).to_bytes()
}

#[test]
fn every_payout_vector_verifies_with_the_programs_merkle_code() {
    let v = vectors();
    let sets = v["payout"].as_array().unwrap();
    let mut leaf_count = 0;
    for set in sets {
        let name = set["name"].as_str().unwrap();
        let escrow = key_of(set, "escrow");
        let root = hex32(&set["root"]);
        let mut leaves = Vec::new();
        let mut proofs = Vec::new();
        for leaf in set["leaves"].as_array().unwrap() {
            let claimant = key_of(leaf, "claimant");
            let hash = compute_leaf_hash(&escrow, &claimant, amount_of(leaf));
            assert_eq!(hash, hex32(&leaf["leaf"]), "{name}: {claimant}'s leaf");
            let proof = nodes(&leaf["proof"]);
            assert!(proof.len() <= usize::from(MAX_PROOF_LEN), "{name}");
            assert!(
                verify_proof(&proof, &root, &hash),
                "{name}: {claimant}'s proof"
            );
            leaves.push(hash);
            proofs.push(proof);
        }
        assert_eq!(
            merkle_tree(&leaves),
            (root, proofs),
            "{name}: the Rust tree"
        );
        leaf_count += leaves.len();
    }
    assert_eq!((sets.len(), leaf_count), (7, 34));
    assert_eq!(merkle_tree(&[]).0, [0; 32], "no leaves: the zero root");
}

#[test]
fn no_invalid_payout_vector_verifies() {
    let v = vectors();
    let cases = v["payout_invalid"].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let leaf = compute_leaf_hash(
            &key_of(case, "escrow"),
            &key_of(case, "claimant"),
            amount_of(case),
        );
        assert_eq!(leaf, hex32(&case["leaf"]), "{name}: leaf");
        assert!(
            !verify_proof(&nodes(&case["proof"]), &hex32(&case["root"]), &leaf),
            "{name} verified"
        );
    }
    assert_eq!(cases.len(), 6);
}

#[test]
fn every_entries_vector_verifies_and_matches_the_rust_tree() {
    let v = vectors();
    let sets = v["entries"].as_array().unwrap();
    let mut leaf_count = 0;
    for set in sets {
        let name = set["name"].as_str().unwrap();
        let root = hex32(&set["root"]);
        let mut leaves = Vec::new();
        let mut proofs = Vec::new();
        for entry in set["leaves"].as_array().unwrap() {
            let submission_id = hex(&entry["submission_id_hex"]);
            assert_eq!(submission_id.len(), 16, "{name}: a 16-byte UUID");
            assert_eq!(
                entry["submission_id"].as_str().unwrap().replace('-', ""),
                entry["submission_id_hex"].as_str().unwrap(),
                "{name}: the UUID's bytes"
            );
            let leaf = entry_leaf(
                &submission_id,
                &key_of(entry, "wallet"),
                &hex32(&entry["transcripts_sha256"]),
                &hex32(&entry["entry_signature_sha256"]),
            );
            assert_eq!(leaf, hex32(&entry["leaf"]), "{name}: leaf");
            let proof = nodes(&entry["proof"]);
            assert!(verify_proof(&proof, &root, &leaf), "{name}: proof");
            leaves.push(leaf);
            proofs.push(proof);
        }
        assert_eq!(
            merkle_tree(&leaves),
            (root, proofs),
            "{name}: the Rust tree"
        );
        leaf_count += leaves.len();
    }
    assert_eq!((sets.len(), leaf_count), (4, 12));
}

// --------------------------------------------------------------------------------- the world

/// Who signs an instruction or pays a transaction's fee.
#[derive(Clone, Copy, Debug)]
enum Who {
    Payer,
    Sponsor,
    Resolver,
    Compliance,
    Stranger,
    Challenger,
    Arbiter,
    Regrader(usize),
    Winner(usize),
}

/// A LiteSVM with the release program, a classic-Token mint, and one escrow opened by the real
/// open_escrow with its entries root committed; `Cl::claimable` also posts the winners' payout
/// root and settles it. The payer, sponsor, resolver, compliance key, stranger, challenger,
/// arbiter and regraders hold SOL; the winners hold none.
struct Cl {
    svm: LiteSVM,
    payer: Keypair,
    sponsor: Keypair,
    resolver: Keypair,
    compliance: Keypair,
    stranger: Keypair,
    challenger: Keypair,
    arbiter: Keypair,
    regraders: [Keypair; 3],
    winners: [Keypair; 4],
    refund_to: Pubkey,
    mint: Pubkey,
    escrow: Pubkey,
    vault: Pubkey,
    /// Each winner's leaf, (total_amount, proof), once a payout root is posted.
    leaves: Vec<(u64, Vec<[u8; 32]>)>,
}

impl Cl {
    /// Opened at NOW with a compliance key (the open policy requires one; `gate` must be true).
    ///
    /// Every key is fixed, so each run derives the same addresses: the compute a claim uses
    /// depends on how many bumps its on-chain PDA and associated-account searches try.
    fn open(gate: bool) -> Self {
        assert!(gate, "the open policy requires a compliance key");
        let mut svm = mainnet::svm();
        svm.add_program(prize_escrow::ID, program_so::bytes())
            .unwrap();
        set_time(&mut svm, NOW);

        let keypair = |n: u8| Keypair::new_from_array([n; 32]);
        let address = |n: u8| Pubkey::new_from_array([n; 32]);
        let payer = keypair(0x01);
        let sponsor = keypair(0x02);
        let resolver = keypair(0x03);
        let compliance = keypair(0x04);
        let stranger = keypair(0x05);
        let challenger = keypair(0x06);
        let arbiter = keypair(0x41);
        let regraders = [keypair(0x21), keypair(0x22), keypair(0x23)];
        for kp in [
            &payer,
            &sponsor,
            &resolver,
            &compliance,
            &stranger,
            &challenger,
            &arbiter,
        ]
        .into_iter()
        .chain(regraders.iter())
        {
            svm.airdrop(&kp.pubkey(), 10 * SOL).unwrap();
        }
        let winners = [keypair(0x11), keypair(0x12), keypair(0x13), keypair(0x14)];

        let mint = address(0x4d);
        set_mint(&mut svm, mint);
        // The sponsor funds from a token account it owns other than its associated one, which is
        // refund_to's (the open policy pins refund_to to the sponsor): refunds land there alone.
        let sponsor_ata = address(0x53);
        set_token_account(&mut svm, sponsor_ata, mint, sponsor.pubkey(), TOTAL);

        let escrow = Pubkey::find_program_address(
            &[ESCROW_SEED, sponsor.pubkey().as_ref(), &CID],
            &prize_escrow::ID,
        )
        .0;
        let vault = get_associated_token_address(&escrow, &mint);
        let refund_to = sponsor.pubkey();
        let terms = EscrowTerms {
            total: TOTAL,
            rules_sha256: RULES,
            resolver: resolver.pubkey(),
            compliance: compliance.pubkey(),
            arbiter: arbiter.pubkey(),
            refund_to,
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

        let mut cl = Cl {
            svm,
            payer,
            sponsor,
            resolver,
            compliance,
            stranger,
            challenger,
            arbiter,
            regraders,
            winners,
            refund_to,
            mint,
            escrow,
            vault,
            leaves: Vec::new(),
        };
        // The Config, created by the upgrade authority (the payer): the arbiter, the mint, the
        // sponsor and the regraders allowed, nothing capped.
        set_upgrade_authority(&mut cl.svm, Some(cl.payer.pubkey()));
        let init = config_init(
            cl.payer.pubkey(),
            cl.payer.pubkey(),
            cl.arbiter.pubkey(),
            &[mint],
            &[cl.sponsor.pubkey()],
            &cl.regraders.iter().map(Signer::pubkey).collect::<Vec<_>>(),
        );
        ok(
            cl.send(initialize_config_ix(cl.payer.pubkey(), init), &[]),
            "initialize_config",
        );
        let ix = instruction(
            accts::OpenEscrow {
                sponsor: cl.key(Who::Sponsor),
                escrow,
                mint,
                sponsor_token_account: sponsor_ata,
                vault,
                token_program: token::ID,
                associated_token_program: associated_token::ID,
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::OpenEscrow {
                competition_id: CID,
                terms,
            },
        );
        ok(cl.send(ix, &[Who::Sponsor]), "open_escrow");
        let ix = instruction(
            accts::CommitEntries {
                resolver: cl.key(Who::Resolver),
                escrow,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::CommitEntries {
                entries_root: ENTRIES_ROOT,
                entries_count: 4,
            },
        );
        ok(cl.send(ix, &[Who::Resolver]), "commit_entries");
        cl
    }

    /// Opened, the winners' PRIZES posted as the payout root, and settled: Claimable from
    /// CLAIMABLE_AT until CLAIM_DEADLINE.
    fn claimable(gate: bool) -> Self {
        let mut cl = Cl::open(gate);
        let leaves: Vec<(Pubkey, u64)> = (0..4).map(|w| (cl.winner(w), PRIZES[w])).collect();
        let root = cl.post_tree(&leaves);
        cl.settle_at(root);
        cl
    }

    /// Builds the payout tree over `(claimant, total_amount)` leaves, keeps them (in order) as
    /// the winners' leaves, and returns the root.
    fn post_tree(&mut self, leaves: &[(Pubkey, u64)]) -> [u8; 32] {
        let hashes: Vec<[u8; 32]> = leaves
            .iter()
            .map(|(claimant, amount)| compute_leaf_hash(&self.escrow, claimant, *amount))
            .collect();
        let (root, proofs) = merkle_tree(&hashes);
        self.leaves = leaves.iter().map(|l| l.1).zip(proofs).collect();
        root
    }

    /// post_result of (RESULT, `payout_root`, TOTAL) at POST_AT (Challengeable).
    fn post(&mut self, payout_root: [u8; 32]) {
        self.at(POST_AT);
        let ix = instruction(
            accts::PostResult {
                resolver: self.key(Who::Resolver),
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
                result_sha256: RESULT,
                kit_sha256: KIT,
                total: TOTAL,
            },
        );
        ok(self.send(ix, &[Who::Resolver]), "post_result");
    }

    /// post_result, then settle at CLAIMABLE_AT (Claimable).
    fn settle_at(&mut self, payout_root: [u8; 32]) {
        self.post(payout_root);
        self.at(CLAIMABLE_AT);
        let ix = instruction(
            accts::Settle {
                escrow: self.escrow,
                mint: self.mint,
                vault: self.vault,
                resolver: self.key(Who::Resolver),
                challenger: None,
                token_program: token::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Settle {},
        );
        ok(self.send(ix, &[]), "settle");
        let state = self.state();
        assert_eq!(state.status, EscrowStatus::Claimable);
        assert_eq!(state.claim_deadline, CLAIM_DEADLINE);
    }

    // ------------------------------------------------------------------------ plumbing

    fn get(&self, who: Who) -> &Keypair {
        match who {
            Who::Payer => &self.payer,
            Who::Sponsor => &self.sponsor,
            Who::Resolver => &self.resolver,
            Who::Compliance => &self.compliance,
            Who::Stranger => &self.stranger,
            Who::Challenger => &self.challenger,
            Who::Arbiter => &self.arbiter,
            Who::Regrader(i) => &self.regraders[i],
            Who::Winner(w) => &self.winners[w],
        }
    }

    fn key(&self, who: Who) -> Pubkey {
        self.get(who).pubkey()
    }

    fn winner(&self, w: usize) -> Pubkey {
        self.key(Who::Winner(w))
    }

    fn at(&mut self, unix_timestamp: i64) {
        set_time(&mut self.svm, unix_timestamp);
    }

    /// Signs `message` by `fee_payer` and `signers` (each key once).
    fn sign(
        &self,
        message: VersionedMessage,
        fee_payer: Who,
        signers: &[Who],
    ) -> VersionedTransaction {
        let mut keys = vec![self.get(fee_payer)];
        for who in signers {
            let kp = self.get(*who);
            if keys.iter().all(|k| k.pubkey() != kp.pubkey()) {
                keys.push(kp);
            }
        }
        VersionedTransaction::try_new(message, &keys).unwrap()
    }

    fn legacy_tx(
        &mut self,
        fee_payer: Who,
        ix: Instruction,
        signers: &[Who],
    ) -> VersionedTransaction {
        self.svm.expire_blockhash();
        let message = Message::new_with_blockhash(
            &[ix],
            Some(&self.key(fee_payer)),
            &self.svm.latest_blockhash(),
        );
        self.sign(VersionedMessage::Legacy(message), fee_payer, signers)
    }

    fn v0_tx(
        &mut self,
        fee_payer: Who,
        ix: Instruction,
        signers: &[Who],
        table: &AddressLookupTableAccount,
    ) -> VersionedTransaction {
        self.svm.expire_blockhash();
        let message = v0::Message::try_compile(
            &self.key(fee_payer),
            &[ix],
            std::slice::from_ref(table),
            self.svm.latest_blockhash(),
        )
        .unwrap();
        self.sign(VersionedMessage::V0(message), fee_payer, signers)
    }

    /// Send `ix` with the payer paying the fee and `signers` signing too.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn send(&mut self, ix: Instruction, signers: &[Who]) -> TransactionResult {
        self.send_from(Who::Payer, ix, signers)
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn send_from(&mut self, fee_payer: Who, ix: Instruction, signers: &[Who]) -> TransactionResult {
        let tx = self.legacy_tx(fee_payer, ix, signers);
        self.svm.send_transaction(tx)
    }

    fn state(&self) -> Escrow {
        let account = self.svm.get_account(&self.escrow).expect("the escrow");
        Escrow::try_deserialize(&mut account.data.as_slice()).unwrap()
    }

    /// The claimant's receipt, if it exists.
    fn receipt(&self, claimant: &Pubkey) -> Option<ClaimReceipt> {
        self.svm
            .get_account(&receipt_pda(&self.escrow, claimant))
            .filter(|a| a.lamports > 0 && a.owner == prize_escrow::ID)
            .map(|a| ClaimReceipt::try_deserialize(&mut a.data.as_slice()).unwrap())
    }

    fn lamports(&self, address: &Pubkey) -> u64 {
        self.svm.get_account(address).map_or(0, |a| a.lamports)
    }

    /// A token account's balance; 0 when it does not exist.
    fn tokens(&self, address: &Pubkey) -> u64 {
        self.svm.get_account(address).map_or(0, |account| {
            assert_eq!(account.owner, token::ID);
            spl_token::state::Account::unpack(&account.data)
                .unwrap()
                .amount
        })
    }

    fn ata(&self, owner: &Pubkey) -> Pubkey {
        get_associated_token_address(owner, &self.mint)
    }

    fn rent(&self, len: usize) -> u64 {
        self.svm.minimum_balance_for_rent_exemption(len)
    }

    // -------------------------------------------------------------------- instructions

    fn request_ix(&self, claimant: Pubkey, total_amount: u64, proof: Vec<[u8; 32]>) -> Instruction {
        instruction(
            accts::RequestClaim {
                claimant,
                payer: self.payer.pubkey(),
                escrow: self.escrow,
                receipt: receipt_pda(&self.escrow, &claimant),
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::RequestClaim {
                total_amount,
                proof,
            },
        )
    }

    /// claim into the claimant's own associated token account; `payer` pays fees and rent.
    fn claim_ix(
        &self,
        claimant: Pubkey,
        payer: Pubkey,
        cosign: bool,
        total_amount: u64,
        amount: u64,
        proof: Vec<[u8; 32]>,
    ) -> Instruction {
        instruction(
            accts::Claim {
                claimant,
                payer,
                compliance: cosign.then(|| self.compliance.pubkey()),
                escrow: self.escrow,
                mint: self.mint,
                vault: self.vault,
                claimant_token_account: self.ata(&claimant),
                receipt: receipt_pda(&self.escrow, &claimant),
                token_program: token::ID,
                associated_token_program: associated_token::ID,
                system_program: system_program::ID,
                config: config_pda(),
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

    /// Winner `w` requests its own leaf.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn request(&mut self, w: usize) -> TransactionResult {
        let (total, proof) = self.leaves[w].clone();
        let ix = self.request_ix(self.winner(w), total, proof);
        self.send(ix, &[Who::Winner(w)])
    }

    /// Winner `w` claims `amount` (0 = the rest) of its own leaf, the payer paying, co-signed by
    /// the compliance key when `cosign`.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn claim(&mut self, w: usize, amount: u64, cosign: bool) -> TransactionResult {
        let (total, proof) = self.leaves[w].clone();
        self.claim_with(w, total, amount, proof, cosign)
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn claim_with(
        &mut self,
        w: usize,
        total_amount: u64,
        amount: u64,
        proof: Vec<[u8; 32]>,
        cosign: bool,
    ) -> TransactionResult {
        let ix = self.claim_ix(
            self.winner(w),
            self.payer.pubkey(),
            cosign,
            total_amount,
            amount,
            proof,
        );
        let signers: &[Who] = if cosign {
            &[Who::Winner(w), Who::Compliance]
        } else {
            &[Who::Winner(w)]
        };
        self.send(ix, signers)
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn hold(&mut self, who: Who, claimant: Pubkey, reason: u8) -> TransactionResult {
        let ix = instruction(
            accts::Hold {
                compliance: self.key(who),
                escrow: self.escrow,
                receipt: receipt_pda(&self.escrow, &claimant),
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Hold { claimant, reason },
        );
        self.send(ix, &[who])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn release(&mut self, who: Who, claimant: Pubkey) -> TransactionResult {
        let ix = instruction(
            accts::ReleaseHold {
                compliance: self.key(who),
                escrow: self.escrow,
                receipt: receipt_pda(&self.escrow, &claimant),
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ReleaseHold { claimant },
        );
        self.send(ix, &[who])
    }

    /// The receipt of `of` closed with `who` named as the claimant its rent goes to (`of` itself,
    /// unless a test says otherwise). Nobody signs for the claimant: the payer sends it.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn close_receipt(&mut self, who: Who, of: Pubkey) -> TransactionResult {
        let ix = instruction(
            accts::CloseReceipt {
                claimant: self.key(who),
                escrow: self.escrow,
                receipt: receipt_pda(&self.escrow, &of),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::CloseReceipt {},
        );
        self.send(ix, &[])
    }

    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn challenge(
        &mut self,
        alt_result_sha256: [u8; 32],
        alt_payout_root: [u8; 32],
        alt_total: u64,
    ) -> TransactionResult {
        let alt_commitment = result_commitment(&alt_result_sha256, &alt_payout_root, alt_total);
        // The two steps: a commit, then its reveal in the next slot.
        let challenger = self.key(Who::Challenger);
        let salt = salt_for(&challenger, &alt_commitment);
        let hash = commit_hash(&alt_commitment, &challenger, &salt);
        let commit = CommitRecord::pda(&self.escrow, &challenger, &hash).0;
        let ix = instruction(
            accts::ChallengeCommit {
                challenger,
                config: config_pda(),
                escrow: self.escrow,
                commit,
                system_program: system_program::ID,
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ChallengeCommit { hash },
        );
        self.send(ix, &[Who::Challenger])?;
        next_slot(&mut self.svm);
        let ix = instruction(
            accts::ChallengeReveal {
                challenger,
                config: config_pda(),
                escrow: self.escrow,
                mint: self.mint,
                vault: self.vault,
                commit,
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
        self.send(ix, &[Who::Challenger])
    }

    /// The escrow's Challenge PDA of `alt_commitment`.
    fn challenge_pda(&self, alt_commitment: &[u8; 32]) -> Pubkey {
        Pubkey::find_program_address(
            &[
                CHALLENGE_SEED,
                self.escrow.as_ref(),
                alt_commitment.as_ref(),
            ],
            &prize_escrow::ID,
        )
        .0
    }

    /// A vote for `commitment`: the posted one, or a challenge's (its Challenge PDA rides along
    /// when it exists).
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn attest(&mut self, regrader: usize, commitment: [u8; 32]) -> TransactionResult {
        let key = self.key(Who::Regrader(regrader));
        let pda = self.challenge_pda(&commitment);
        let challenge = self.svm.get_account(&pda).map(|_| pda);
        let ix = instruction(
            accts::Attest {
                regrader: key,
                escrow: self.escrow,
                attestation: Pubkey::find_program_address(
                    &[ATTESTATION_SEED, self.escrow.as_ref(), key.as_ref()],
                    &prize_escrow::ID,
                )
                .0,
                challenge,
                system_program: system_program::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Attest { commitment },
        );
        self.send(ix, &[Who::Regrader(regrader)])
    }

    /// Permissionless: only the fee payer signs. The winning challenger's account rides along
    /// once the escrow records one (a quorum for its alternative: settle pays it).
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn settle_disputed(&mut self) -> TransactionResult {
        let recorded = self.state().challenger;
        let ix = instruction(
            accts::Settle {
                escrow: self.escrow,
                mint: self.mint,
                vault: self.vault,
                resolver: self.key(Who::Resolver),
                challenger: (recorded != Pubkey::default()).then_some(recorded),
                token_program: token::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::Settle {},
        );
        self.send(ix, &[])
    }

    /// arbiter_resolve choosing the posted result (`commitment` the escrow's), or the
    /// alternative of `commitment` (its Challenge PDA and Who::Challenger riding along).
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn arbiter_resolve(
        &mut self,
        choice: ArbiterChoice,
        commitment: [u8; 32],
    ) -> TransactionResult {
        let alternative = choice == ArbiterChoice::Alternative;
        let ix = instruction(
            accts::ArbiterResolve {
                arbiter: self.key(Who::Arbiter),
                escrow: self.escrow,
                mint: self.mint,
                vault: self.vault,
                resolver: self.key(Who::Resolver),
                challenge: alternative.then(|| self.challenge_pda(&commitment)),
                challenger: alternative.then(|| self.key(Who::Challenger)),
                token_program: token::ID,
                config: config_pda(),
                event_authority: EVENT_AUTHORITY,
                program: prize_escrow::ID,
            },
            ixs::ArbiterResolve { choice, commitment },
        );
        self.send(ix, &[Who::Arbiter])
    }

    /// Permissionless: only the fee payer signs.
    #[allow(clippy::result_large_err, reason = "LiteSVM's own result type")]
    fn refund(&mut self) -> TransactionResult {
        let ix = instruction(
            accts::Refund {
                payer: self.payer.pubkey(),
                escrow: self.escrow,
                mint: self.mint,
                vault: self.vault,
                refund_to: self.refund_to,
                refund_to_token_account: self.ata(&self.refund_to),
                resolver: self.key(Who::Resolver),
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

// --------------------------------------------------------------------------- co-signed claims

#[test]
fn a_cosigned_claim_pays_the_whole_leaf_into_the_winners_own_account_once() {
    let mut cl = Cl::claimable(true);
    let w0 = cl.winner(0);
    let payer_before = cl.lamports(&cl.payer.pubkey());
    cl.at(CLAIMABLE_AT + HOUR);

    let meta = ok(cl.claim(0, 0, true), "a co-signed claim of all of it");
    assert_eq!(cl.tokens(&cl.ata(&w0)), PRIZES[0]);
    assert_eq!(cl.tokens(&cl.vault), TOTAL - PRIZES[0]);
    assert_eq!(cl.lamports(&w0), 0, "the winner paid nothing");
    assert_eq!(
        payer_before - cl.lamports(&cl.payer.pubkey()),
        meta.fee + cl.rent(ClaimReceipt::SPACE) + cl.rent(spl_token::state::Account::LEN),
        "the payer pays the fee, the receipt and the winner's token account"
    );
    assert_eq!(
        cl.receipt(&w0),
        Some(ClaimReceipt {
            claimant: w0,
            total_amount: PRIZES[0],
            amount_claimed: PRIZES[0],
            requested_at: 0,
            hold_reason: HOLD_NONE,
            held_at: 0,
            bump: receipt_bump(&cl.escrow, &w0),
        })
    );
    assert_eq!(cl.state().total_claimed, PRIZES[0]);
    let claimed = event::<Claimed>(&meta);
    assert_eq!(
        (
            claimed.escrow,
            claimed.claimant,
            claimed.amount,
            claimed.amount_claimed,
            claimed.total_amount,
            claimed.cosigned
        ),
        (cl.escrow, w0, PRIZES[0], PRIZES[0], PRIZES[0], true)
    );

    // The double claim: the receipt remembers the leaf is spent, whatever the amount asked.
    for amount in [0, 1] {
        let r = cl.claim(0, amount, true);
        assert_refused(r, EscrowError::AlreadyClaimed, "a second co-signed claim");
    }
    cl.at(CLAIMABLE_AT + MIN_HOLD_WINDOW + DAY);
    let r = cl.request(0);
    assert_refused(
        r,
        EscrowError::AlreadyClaimed,
        "a request after the full claim",
    );
    assert_eq!(cl.tokens(&cl.ata(&w0)), PRIZES[0]);
    assert_eq!(cl.state().total_claimed, PRIZES[0]);
}

#[test]
fn the_compliance_key_can_pay_for_the_claim_it_cosigns() {
    let mut cl = Cl::claimable(true);
    let w1 = cl.winner(1);
    let payer_before = cl.lamports(&cl.payer.pubkey());
    let compliance_before = cl.lamports(&cl.compliance.pubkey());
    let (total, proof) = cl.leaves[1].clone();
    let ix = cl.claim_ix(w1, cl.compliance.pubkey(), true, total, 0, proof);
    let tx = cl.legacy_tx(Who::Compliance, ix, &[Who::Winner(1), Who::Compliance]);
    assert_eq!(tx.signatures.len(), 2, "the winner and the compliance key");
    let meta = ok(
        cl.svm.send_transaction(tx),
        "a claim the compliance key pays for",
    );

    assert_eq!(cl.tokens(&cl.ata(&w1)), PRIZES[1]);
    assert_eq!(cl.lamports(&cl.payer.pubkey()), payer_before);
    assert_eq!(
        compliance_before - cl.lamports(&cl.compliance.pubkey()),
        meta.fee + cl.rent(ClaimReceipt::SPACE) + cl.rent(spl_token::state::Account::LEN)
    );
    assert!(event::<Claimed>(&meta).cosigned);
}

#[test]
fn partial_claims_add_up_to_the_leaf_and_never_past_it() {
    let mut cl = Cl::claimable(true);
    let w0 = cl.winner(0);

    let meta = ok(cl.claim(0, 1_000_000_000, true), "a first part");
    let claimed = event::<Claimed>(&meta);
    assert_eq!(
        (claimed.amount, claimed.amount_claimed, claimed.total_amount),
        (1_000_000_000, 1_000_000_000, PRIZES[0])
    );
    let r = cl.claim(0, 1_500_000_001, true);
    assert_refused(
        r,
        EscrowError::ExceedsAllocation,
        "one base unit more than is left",
    );
    ok(cl.claim(0, 1, true), "one base unit");
    let meta = ok(cl.claim(0, 0, true), "the rest");
    let claimed = event::<Claimed>(&meta);
    assert_eq!(
        (claimed.amount, claimed.amount_claimed),
        (1_499_999_999, PRIZES[0])
    );
    let r = cl.claim(0, 0, true);
    assert_refused(r, EscrowError::AlreadyClaimed, "a claim once all is paid");

    assert_eq!(cl.tokens(&cl.ata(&w0)), PRIZES[0]);
    assert_eq!(cl.receipt(&w0).unwrap().amount_claimed, PRIZES[0]);
    assert_eq!(cl.state().total_claimed, PRIZES[0]);

    // Every winner takes its leaf: the vault keeps the unawarded rest.
    for (w, prize) in PRIZES.iter().enumerate().skip(1) {
        ok(cl.claim(w, 0, true), "another winner");
        assert_eq!(cl.tokens(&cl.ata(&cl.winner(w))), *prize);
    }
    assert_eq!(cl.state().total_claimed, AWARDED);
    assert_eq!(cl.tokens(&cl.vault), TOTAL - AWARDED);
}

// ------------------------------------------------------------------- what a claim refuses

#[test]
fn claims_refuse_a_leaf_outside_the_tree_a_deep_proof_and_another_mint() {
    let mut cl = Cl::claimable(true);
    let w0 = cl.winner(0);
    let (total, proof) = cl.leaves[0].clone();
    let (total1, proof1) = cl.leaves[1].clone();

    let cases: [(&str, u64, Vec<[u8; 32]>, EscrowError); 6] = [
        (
            "the amount raised by one",
            total + 1,
            proof.clone(),
            EscrowError::InvalidMerkleProof,
        ),
        (
            "another winner's leaf",
            total1,
            proof1.clone(),
            EscrowError::InvalidMerkleProof,
        ),
        (
            "an empty proof",
            total,
            Vec::new(),
            EscrowError::InvalidMerkleProof,
        ),
        (
            "a sibling flipped",
            total,
            {
                let mut p = proof.clone();
                p[0][0] ^= 1;
                p
            },
            EscrowError::InvalidMerkleProof,
        ),
        (
            "a proof one deeper than MAX_PROOF_LEN",
            total,
            vec![[7; 32]; usize::from(MAX_PROOF_LEN) + 1],
            EscrowError::ProofTooDeep,
        ),
        ("a zero leaf", 0, proof.clone(), EscrowError::NothingToClaim),
    ];
    for (what, total_amount, proof, want) in cases {
        let want = u32::from(want);
        let r = cl.claim_with(0, total_amount, 0, proof.clone(), true);
        assert_refused(r, want, &format!("claim: {what}"));
        let ix = cl.request_ix(w0, total_amount, proof);
        let r = cl.send(ix, &[Who::Winner(0)]);
        assert_refused(r, want, &format!("request_claim: {what}"));
    }

    // A stranger with a winner's leaf and proof: the leaf names the claimant.
    let ix = cl.claim_ix(
        cl.key(Who::Stranger),
        cl.payer.pubkey(),
        true,
        total,
        0,
        proof.clone(),
    );
    let r = cl.send(ix, &[Who::Stranger, Who::Compliance]);
    assert_refused(r, EscrowError::InvalidMerkleProof, "a stranger's claim");

    // The same claim against a vault of another mint: the escrow's mint pin refuses it.
    let other_mint = Pubkey::new_unique();
    set_mint(&mut cl.svm, other_mint);
    let other_vault = get_associated_token_address(&cl.escrow, &other_mint);
    set_token_account(&mut cl.svm, other_vault, other_mint, cl.escrow, TOTAL);
    let mut ix = cl.claim_ix(w0, cl.payer.pubkey(), true, total, 0, proof);
    ix.accounts[4].pubkey = other_mint;
    ix.accounts[5].pubkey = other_vault;
    ix.accounts[6].pubkey = get_associated_token_address(&w0, &other_mint);
    let r = cl.send(ix, &[Who::Winner(0), Who::Compliance]);
    assert_refused(r, EscrowError::MintMismatch, "a claim against another mint");
    assert_eq!(cl.tokens(&other_vault), TOTAL);

    assert_eq!(cl.receipt(&w0), None, "every refusal rolled back");
    assert_eq!(cl.receipt(&cl.key(Who::Stranger)), None);
    assert_eq!(cl.tokens(&cl.vault), TOTAL);
    assert_eq!(cl.state().total_claimed, 0);
}

#[test]
fn claims_pay_only_the_winners_own_associated_token_account() {
    let mut cl = Cl::claimable(true);
    let w0 = cl.winner(0);
    let (total, proof) = cl.leaves[0].clone();

    // Someone else's existing account.
    let stranger = cl.key(Who::Stranger);
    let foreign = cl.ata(&stranger);
    set_token_account(&mut cl.svm, foreign, cl.mint, stranger, 0);
    let mut ix = cl.claim_ix(w0, cl.payer.pubkey(), true, total, 0, proof.clone());
    ix.accounts[6].pubkey = foreign;
    let r = cl.send(ix, &[Who::Winner(0), Who::Compliance]);
    assert_refused(
        r,
        AnchorErrorCode::ConstraintTokenOwner,
        "a claim into the stranger's token account",
    );

    // A token account the winner owns that is not its associated one.
    let side = Pubkey::new_unique();
    set_token_account(&mut cl.svm, side, cl.mint, w0, 0);
    let mut ix = cl.claim_ix(w0, cl.payer.pubkey(), true, total, 0, proof);
    ix.accounts[6].pubkey = side;
    let r = cl.send(ix, &[Who::Winner(0), Who::Compliance]);
    assert_refused(
        r,
        AnchorErrorCode::AccountNotAssociatedTokenAccount,
        "a claim into a side account",
    );
    assert_eq!((cl.tokens(&foreign), cl.tokens(&side)), (0, 0));

    // An associated account that already exists is paid as is.
    let (own, mint) = (cl.ata(&w0), cl.mint);
    set_token_account(&mut cl.svm, own, mint, w0, 7);
    ok(cl.claim(0, 0, true), "a claim into an existing account");
    assert_eq!(cl.tokens(&cl.ata(&w0)), 7 + PRIZES[0]);
}

#[test]
fn claims_run_while_claimable_up_to_and_including_the_claim_deadline() {
    // Before settle: the root can still be challenged.
    let mut cl = Cl::open(true);
    let leaves: Vec<(Pubkey, u64)> = (0..4).map(|w| (cl.winner(w), PRIZES[w])).collect();
    let root = cl.post_tree(&leaves);
    cl.post(root);
    let r = cl.claim(0, 0, true);
    assert_refused(r, EscrowError::InvalidStatus, "a claim while Challengeable");
    let r = cl.request(0);
    assert_refused(
        r,
        EscrowError::InvalidStatus,
        "a request while Challengeable",
    );

    let mut cl = Cl::claimable(true);
    cl.at(CLAIM_DEADLINE);
    ok(
        cl.claim(0, 0, true),
        "a claim on the deadline's last second",
    );
    let meta = ok(cl.request(1), "a request on the deadline's last second");
    assert_eq!(
        event::<ClaimRequested>(&meta).clears_at,
        CLAIM_DEADLINE + MIN_HOLD_WINDOW,
        "it lapses after the deadline: only a co-signed claim is left"
    );

    cl.at(CLAIM_DEADLINE + 1);
    for w in 1..3 {
        let r = cl.claim(w, 0, true);
        assert_refused(
            r,
            EscrowError::ClaimWindowClosed,
            "a claim after the deadline",
        );
    }
    let r = cl.request(2);
    assert_refused(
        r,
        EscrowError::ClaimWindowClosed,
        "a request after the deadline",
    );

    ok(cl.refund(), "refund after the deadline");
    // refund closed the vault, so account validation refuses first; recreated by anyone (it is
    // an associated token account), the handler's own status check still refuses.
    let r = cl.claim(1, 0, true);
    assert_refused(
        r,
        AnchorErrorCode::AccountNotInitialized,
        "a claim once the vault is closed",
    );
    let (vault, mint, escrow) = (cl.vault, cl.mint, cl.escrow);
    set_token_account(&mut cl.svm, vault, mint, escrow, 0);
    let r = cl.claim(1, 0, true);
    assert_refused(r, EscrowError::EscrowClosed, "a claim once refunded");
    let r = cl.request(2);
    assert_refused(r, EscrowError::EscrowClosed, "a request once refunded");
    assert_eq!(cl.tokens(&cl.ata(&cl.winner(1))), 0);
    assert_eq!(cl.tokens(&cl.ata(&cl.refund_to)), TOTAL - PRIZES[0]);
}

#[test]
fn a_receipt_keeps_the_first_leaf_its_claimant_proves() {
    // A malformed tree (the server sums a claimant's awards into one leaf) with two leaves for
    // winner 0: the receipt is per claimant, so only one of them can ever pay.
    let mut cl = Cl::open(true);
    let w0 = cl.winner(0);
    let root = cl.post_tree(&[(w0, 1_000_000_000), (w0, 2_000_000_000)]);
    cl.settle_at(root);
    let (small, small_proof) = cl.leaves[0].clone();
    let (large, large_proof) = cl.leaves[1].clone();

    ok(
        cl.claim_with(0, small, 400_000_000, small_proof.clone(), true),
        "part of one leaf",
    );
    let r = cl.claim_with(0, large, 0, large_proof.clone(), true);
    assert_refused(r, EscrowError::InvalidMerkleProof, "the other leaf");
    let ix = cl.request_ix(w0, large, large_proof);
    let r = cl.send(ix, &[Who::Winner(0)]);
    assert_refused(
        r,
        EscrowError::InvalidMerkleProof,
        "a request for the other leaf",
    );
    ok(
        cl.claim_with(0, small, 0, small_proof, true),
        "the rest of the first leaf",
    );
    assert_eq!(cl.tokens(&cl.ata(&w0)), small);
    let receipt = cl.receipt(&w0).unwrap();
    assert_eq!(
        (receipt.total_amount, receipt.amount_claimed),
        (small, small)
    );
}

#[test]
fn the_posted_total_caps_what_all_leaves_together_take() {
    // A tree awarding one base unit more than the posted total, and a donation that would cover
    // it: the escrow pays out its total and no more; the donation refunds with the rest.
    let mut cl = Cl::open(true);
    let (w0, w1) = (cl.winner(0), cl.winner(1));
    let root = cl.post_tree(&[(w0, TOTAL - 1), (w1, 2)]);
    cl.settle_at(root);
    let (vault, mint, escrow) = (cl.vault, cl.mint, cl.escrow);
    set_token_account(&mut cl.svm, vault, mint, escrow, TOTAL + 1);

    ok(cl.claim(0, 0, true), "the first leaf");
    let r = cl.claim(1, 0, true);
    assert_refused(r, EscrowError::ExceedsAllocation, "past the posted total");
    ok(cl.claim(1, 1, true), "what is left of the total");
    let r = cl.claim(1, 1, true);
    assert_refused(r, EscrowError::ExceedsAllocation, "the leaf's last unit");
    assert_eq!(cl.state().total_claimed, TOTAL);
    assert_eq!(cl.tokens(&cl.vault), 1);
}

// ------------------------------------------------------------- disputes that end in claims

#[test]
fn a_self_paying_root_posted_with_the_honest_document_is_challenged_and_the_honest_root_pays() {
    // Finding 1 of run review 3: challenge, attest and settle compared result_sha256 only, and the
    // payout root is outside the hashed document, so a resolver key could post the honest
    // document's hash with a root paying itself, nobody could challenge it with the same hash, and
    // regraders re-running the document upheld it. The escrow commits to (document, root, total)
    // now: the honest root is a different commitment, which a challenger can post and regraders
    // can back.
    let mut cl = Cl::open(true);
    let resolver = cl.key(Who::Resolver);
    let winners: Vec<(Pubkey, u64)> = (0..4).map(|w| (cl.winner(w), PRIZES[w])).collect();
    let honest_root = cl.post_tree(&winners);
    let honest_leaves = cl.leaves.clone();
    let self_paying = compute_leaf_hash(&cl.escrow, &resolver, TOTAL);
    cl.post(self_paying);
    let posted = result_commitment(&RESULT, &self_paying, TOTAL);
    let honest = result_commitment(&RESULT, &honest_root, TOTAL);
    assert_eq!(cl.state().commitment, posted);

    // The same document with the posted root is no alternative; with the honest root it is.
    cl.at(POST_AT + HOUR);
    let r = cl.challenge(RESULT, self_paying, TOTAL);
    assert_refused(
        r,
        EscrowError::InvalidResultHash,
        "a challenge committing to the posted result",
    );
    ok(
        cl.challenge(RESULT, honest_root, TOTAL),
        "a challenge with the posted document hash and the honest root",
    );
    assert_eq!(cl.state().status, EscrowStatus::Disputed);
    let pda = cl.challenge_pda(&honest);
    let challenge =
        ChallengeRecord::try_deserialize(&mut cl.svm.get_account(&pda).unwrap().data.as_slice())
            .unwrap();
    assert_eq!(
        (
            challenge.alt_result_sha256,
            challenge.alt_payout_root,
            challenge.alt_total,
            challenge.alt_commitment
        ),
        (RESULT, honest_root, TOTAL, honest)
    );

    // Regraders rebuild the document and its root: they back the honest commitment, and their
    // quorum applies it (run review 4: it used to freeze the escrow for the arbiter). The
    // challenger takes the resolver's bond.
    ok(cl.attest(0, honest), "a regrader backs the honest root");
    ok(cl.attest(2, honest), "a second regrader backs it");
    let state = cl.state();
    assert_eq!(
        (
            state.alt_result_sha256,
            state.alt_payout_root,
            state.alt_total,
            state.alt_commitment
        ),
        (RESULT, honest_root, TOTAL, honest),
        "the quorum records the honest challenge as the winning alternative"
    );
    let challenger_before = cl.lamports(&cl.key(Who::Challenger));
    // Nothing settles before the challenge deadline, a quorum or not (run review 5, F1).
    let r = cl.settle_disputed();
    assert_refused(
        r,
        EscrowError::DeadlineNotReached,
        "settle at quorum inside the challenge window",
    );
    // The refused reveal (it committed to the posted result) left its commit pending: settle
    // waits out the reveal grace after the challenge deadline, then the commit holds nothing back.
    cl.at(CLAIMABLE_AT);
    let r = cl.settle_disputed();
    assert_refused(
        r,
        EscrowError::CommitsPendingReveal,
        "settle while a commit may still be revealed",
    );
    cl.at(CLAIMABLE_AT + MIN_REVEAL_GRACE);
    // Past the grace the commit holds nothing back, but an overturn of the posted result applies
    // only at attest_deadline (#749): the guardian's window to escalate it.
    let r = cl.settle_disputed();
    assert_refused(
        r,
        EscrowError::OverturnWindowOpen,
        "the overturn once the reveal grace passed",
    );
    let attest_deadline = cl.state().attest_deadline;
    cl.at(attest_deadline);
    let meta = ok(cl.settle_disputed(), "settle at the attest deadline");
    let settled = event::<Settled>(&meta);
    assert_eq!(settled.outcome, SettleOutcome::AltApplied);
    assert_eq!(settled.commitment, honest);
    assert_eq!(
        cl.lamports(&cl.key(Who::Challenger)),
        challenger_before + 2 * BOND
    );
    let state = cl.state();
    assert_eq!(state.status, EscrowStatus::Claimable);
    assert_eq!(
        (state.payout_root, state.total, state.commitment),
        (honest_root, TOTAL, honest)
    );

    cl.leaves = honest_leaves;
    ok(cl.claim(0, 0, true), "the first winner's honest leaf");
    assert_eq!(cl.tokens(&cl.ata(&cl.winner(0))), PRIZES[0]);
    let ix = cl.claim_ix(resolver, cl.payer.pubkey(), true, TOTAL, 0, Vec::new());
    let r = cl.send(ix, &[Who::Resolver, Who::Compliance]);
    assert_refused(
        r,
        EscrowError::InvalidMerkleProof,
        "the resolver's self-paying leaf",
    );
    assert_eq!(cl.tokens(&cl.vault), TOTAL - PRIZES[0]);
}

#[test]
fn a_late_arbiter_resolve_keeps_its_claims_live_past_the_hard_deadline() {
    // Finding 3 of run review 3: refund matched `now > hard_deadline` before the Claimable arm, and
    // arbiter_resolve sets claim_deadline = now + claim_window with no clamp, so an arbiter acting
    // late opened a claim window past hard_deadline that anyone could sweep by refunding. A
    // Claimable escrow now refunds only after its claim_deadline.
    let mut cl = Cl::open(true);
    let winners: Vec<(Pubkey, u64)> = (0..4).map(|w| (cl.winner(w), PRIZES[w])).collect();
    let root = cl.post_tree(&winners);
    cl.post(root);
    cl.at(POST_AT + HOUR);
    ok(cl.challenge(ALT, [0xa7; 32], TOTAL), "challenge");
    // The attest deadline: a whole 24 h attest window past the 24 h challenge window.
    cl.at(CLAIMABLE_AT + 24 * HOUR);
    ok(cl.settle_disputed(), "settle with no votes");
    assert_eq!(cl.state().status, EscrowStatus::Frozen);

    // The arbiter's proposal lands ten days before hard_deadline.
    let resolve_at = HARD_DEADLINE - 10 * DAY;
    cl.at(resolve_at);
    let meta = ok(
        cl.arbiter_resolve(ArbiterChoice::Posted, cl.state().commitment),
        "a late arbiter_resolve",
    );
    assert_eq!(
        event::<ArbiterResolved>(&meta).payout_root,
        root,
        "the posted root, as chosen"
    );
    let claim_deadline = resolve_at + CLAIM_WINDOW;
    assert_eq!(cl.state().claim_deadline, claim_deadline);
    assert!(claim_deadline > HARD_DEADLINE);

    // Past hard_deadline the claims are live and the refund waits.
    cl.at(HARD_DEADLINE + 1);
    let r = cl.refund();
    assert_refused(
        r,
        EscrowError::ClaimWindowNotElapsed,
        "refund past hard_deadline while claims run",
    );
    ok(cl.claim(0, 0, true), "a claim past hard_deadline");
    cl.at(claim_deadline);
    ok(cl.claim(1, 0, true), "a claim on the claim deadline");
    let r = cl.refund();
    assert_refused(
        r,
        EscrowError::ClaimWindowNotElapsed,
        "refund on the claim deadline",
    );

    cl.at(claim_deadline + 1);
    let r = cl.claim(2, 0, true);
    assert_refused(r, EscrowError::ClaimWindowClosed, "a claim after it");
    let meta = ok(cl.refund(), "refund after the claim deadline");
    let rest = TOTAL - PRIZES[0] - PRIZES[1];
    assert_eq!(cl.tokens(&cl.ata(&cl.refund_to)), rest);
    let refunded = event::<Refunded>(&meta);
    assert_eq!(
        (refunded.amount, refunded.from_status),
        (rest, EscrowStatus::Claimable)
    );
}

// ----------------------------------------------------------------------- the lapse path

#[test]
fn without_the_cosignature_a_claim_waits_out_the_hold_window_after_a_request() {
    let mut cl = Cl::claimable(true);
    let w0 = cl.winner(0);

    let r = cl.claim(0, 0, false);
    assert_refused(r, EscrowError::NotCleared, "a bare claim with no request");
    assert_eq!(cl.receipt(&w0), None);

    let requested_at = CLAIMABLE_AT + HOUR;
    cl.at(requested_at);
    let meta = ok(cl.request(0), "request_claim");
    assert_eq!(cl.lamports(&w0), 0, "the payer paid the receipt");
    assert_eq!(
        cl.receipt(&w0),
        Some(ClaimReceipt {
            claimant: w0,
            total_amount: PRIZES[0],
            amount_claimed: 0,
            requested_at,
            hold_reason: HOLD_NONE,
            held_at: 0,
            bump: receipt_bump(&cl.escrow, &w0),
        })
    );
    let requested = event::<ClaimRequested>(&meta);
    let clears_at = requested_at + 24 * HOUR;
    assert_eq!(
        (
            requested.escrow,
            requested.claimant,
            requested.total_amount,
            requested.requested_at,
            requested.clears_at
        ),
        (cl.escrow, w0, PRIZES[0], requested_at, clears_at)
    );
    let r = cl.request(0);
    assert_refused(r, EscrowError::AlreadyRequested, "a second request");

    cl.at(clears_at - 1);
    let r = cl.claim(0, 0, false);
    assert_refused(
        r,
        EscrowError::HoldWindowOpen,
        "a bare claim one second before the window passes",
    );
    let r = cl.request(0);
    assert_refused(r, EscrowError::AlreadyRequested, "a request to restart it");

    cl.at(clears_at);
    let meta = ok(
        cl.claim(0, 0, false),
        "the bare claim once the window passed",
    );
    assert!(!event::<Claimed>(&meta).cosigned);
    assert_eq!(cl.tokens(&cl.ata(&w0)), PRIZES[0]);
    assert_eq!(cl.receipt(&w0).unwrap().amount_claimed, PRIZES[0]);
    let r = cl.claim(0, 0, false);
    assert_refused(r, EscrowError::AlreadyClaimed, "a second bare claim");

    // A co-signed claim needs no request, and a request never stops one.
    ok(cl.request(1), "another winner's request");
    ok(
        cl.claim(1, 0, true),
        "its co-signed claim inside the window",
    );
}

// ------------------------------------------------------------------------------- holds

#[test]
fn a_held_receipt_is_refused_until_compliance_releases_it() {
    let mut cl = Cl::claimable(true);
    let (w0, w1) = (cl.winner(0), cl.winner(1));

    // A hold before any request: the compliance key creates the receipt and pays its rent.
    let compliance_before = cl.lamports(&cl.compliance.pubkey());
    let held_at = CLAIMABLE_AT + HOUR;
    cl.at(held_at);
    ok(cl.hold(Who::Compliance, w0, HOLD_SANCTIONS), "hold");
    assert_eq!(
        compliance_before - cl.lamports(&cl.compliance.pubkey()),
        cl.rent(ClaimReceipt::SPACE)
    );
    assert_eq!(
        cl.receipt(&w0),
        Some(ClaimReceipt {
            claimant: w0,
            total_amount: 0,
            amount_claimed: 0,
            requested_at: 0,
            hold_reason: HOLD_SANCTIONS,
            held_at,
            bump: receipt_bump(&cl.escrow, &w0),
        })
    );
    let r = cl.request(0);
    assert_refused(r, EscrowError::HeldForCompliance, "a request while held");
    let r = cl.claim(0, 0, true);
    assert_refused(
        r,
        EscrowError::HeldForCompliance,
        "a co-signed claim while held",
    );
    let r = cl.claim(0, 0, false);
    assert_refused(r, EscrowError::HeldForCompliance, "a bare claim while held");

    // A hold inside a request's window blocks the lapse, at and after its end too.
    let requested_at = CLAIMABLE_AT + 2 * HOUR;
    cl.at(requested_at);
    ok(cl.request(1), "a request");
    cl.at(requested_at + DAY);
    ok(
        cl.hold(Who::Compliance, w1, HOLD_REVIEW),
        "a hold inside the window",
    );
    for at in [requested_at + MIN_HOLD_WINDOW, requested_at + 20 * DAY] {
        cl.at(at);
        let r = cl.claim(1, 0, false);
        assert_refused(
            r,
            EscrowError::HeldForCompliance,
            "a bare claim after the window, held",
        );
        let r = cl.claim(1, 0, true);
        assert_refused(
            r,
            EscrowError::HeldForCompliance,
            "a co-signed claim after the window, held",
        );
    }
    assert_eq!(cl.tokens(&cl.vault), TOTAL);

    // Released, the request's own window (long passed) clears the bare claim.
    let meta = ok(cl.release(Who::Compliance, w1), "release");
    assert_eq!(event::<HoldReleased>(&meta).reason, HOLD_REVIEW);
    let meta = ok(cl.claim(1, 0, false), "the bare claim once released");
    assert!(!event::<Claimed>(&meta).cosigned);
    assert_eq!(cl.tokens(&cl.ata(&w1)), PRIZES[1]);

    // Released, the receipt the hold created takes the leaf on the first claim.
    ok(cl.release(Who::Compliance, w0), "release");
    ok(cl.claim(0, 0, true), "the co-signed claim once released");
    let receipt = cl.receipt(&w0).unwrap();
    assert_eq!(
        (
            receipt.total_amount,
            receipt.amount_claimed,
            receipt.hold_reason,
            receipt.held_at
        ),
        (PRIZES[0], PRIZES[0], HOLD_NONE, 0)
    );
    assert_eq!(cl.state().total_claimed, PRIZES[0] + PRIZES[1]);
}

#[test]
fn hold_and_release_take_the_compliance_key_and_a_known_reason() {
    // Compliance can screen a winner as soon as the result is posted.
    let mut cl = Cl::open(true);
    let leaves: Vec<(Pubkey, u64)> = (0..4).map(|w| (cl.winner(w), PRIZES[w])).collect();
    let root = cl.post_tree(&leaves);
    cl.post(root);
    let w2 = cl.winner(2);

    let r = cl.hold(Who::Stranger, w2, HOLD_GEO);
    assert_refused(
        r,
        EscrowError::UnauthorizedCompliance,
        "a hold by a stranger",
    );
    for reason in [HOLD_NONE, HOLD_REVIEW + 1, u8::MAX] {
        let r = cl.hold(Who::Compliance, w2, reason);
        assert_refused(r, EscrowError::InvalidHoldReason, "an unknown reason");
    }
    assert_eq!(cl.receipt(&w2), None);

    // Each reason in turn: a hold on a held receipt replaces the reason and the time.
    for (i, reason) in [
        HOLD_GEO,
        HOLD_TAX_FORM_REQUIRED,
        HOLD_SANCTIONS,
        HOLD_REVIEW,
    ]
    .into_iter()
    .enumerate()
    {
        let at = POST_AT + HOUR * (i as i64 + 1);
        cl.at(at);
        let meta = ok(cl.hold(Who::Compliance, w2, reason), "hold");
        let placed = event::<HoldPlaced>(&meta);
        assert_eq!(
            (
                placed.escrow,
                placed.claimant,
                placed.reason,
                placed.held_at
            ),
            (cl.escrow, w2, reason, at)
        );
        let receipt = cl.receipt(&w2).unwrap();
        assert_eq!((receipt.hold_reason, receipt.held_at), (reason, at));
    }

    let r = cl.release(Who::Stranger, w2);
    assert_refused(
        r,
        EscrowError::UnauthorizedCompliance,
        "a release by a stranger",
    );
    let meta = ok(cl.release(Who::Compliance, w2), "release");
    let released = event::<HoldReleased>(&meta);
    assert_eq!(
        (released.escrow, released.claimant, released.reason),
        (cl.escrow, w2, HOLD_REVIEW)
    );
    let receipt = cl.receipt(&w2).unwrap();
    assert_eq!((receipt.hold_reason, receipt.held_at), (HOLD_NONE, 0));
    let r = cl.release(Who::Compliance, w2);
    assert_refused(r, EscrowError::NotHeld, "a second release");
    let r = cl.release(Who::Compliance, cl.winner(3));
    assert_refused(
        r,
        AnchorErrorCode::AccountNotInitialized,
        "a release with no receipt",
    );
}

// ------------------------------------------------------------------------- close_receipt

#[test]
fn receipts_close_once_the_escrow_is_refunded_and_return_the_rent_to_the_winner() {
    let mut cl = Cl::claimable(true);
    let (w0, w3) = (cl.winner(0), cl.winner(3));
    ok(cl.claim(0, 1_000_000_000, true), "a partial claim");
    ok(
        cl.hold(Who::Compliance, w3, HOLD_TAX_FORM_REQUIRED),
        "a hold",
    );

    let r = cl.close_receipt(Who::Winner(0), w0);
    assert_refused(r, EscrowError::InvalidStatus, "a close while Claimable");

    cl.at(CLAIM_DEADLINE + 1);
    ok(cl.refund(), "refund");
    assert_eq!(cl.state().status, EscrowStatus::Closed);
    assert_eq!(cl.tokens(&cl.ata(&cl.refund_to)), TOTAL - 1_000_000_000);

    // Closed: nothing reopens a receipt or a hold.
    let r = cl.hold(Who::Compliance, cl.winner(1), HOLD_REVIEW);
    assert_refused(r, EscrowError::EscrowClosed, "a hold once refunded");
    let r = cl.release(Who::Compliance, w3);
    assert_refused(r, EscrowError::EscrowClosed, "a release once refunded");

    let r = cl.close_receipt(Who::Stranger, w0);
    assert!(
        matches!(
            custom_code(&r),
            Some(c) if c == u32::from(AnchorErrorCode::ConstraintHasOne)
                || c == u32::from(AnchorErrorCode::ConstraintSeeds)
        ),
        "a close of the winner's receipt paying its rent to a stranger: {}",
        logs(&r)
    );

    let rent = cl.lamports(&receipt_pda(&cl.escrow, &w0));
    assert_eq!(rent, cl.rent(ClaimReceipt::SPACE));
    let meta = ok(cl.close_receipt(Who::Winner(0), w0), "close_receipt");
    assert_eq!(cl.receipt(&w0), None);
    assert_eq!(
        cl.lamports(&w0),
        rent,
        "the winner takes the rent the payer paid"
    );
    let closed = event::<ReceiptClosed>(&meta);
    assert_eq!(
        (closed.escrow, closed.claimant, closed.amount_claimed),
        (cl.escrow, w0, 1_000_000_000)
    );
    let r = cl.close_receipt(Who::Winner(0), w0);
    assert_refused(r, AnchorErrorCode::AccountNotInitialized, "a second close");

    // The receipt the compliance key paid for goes back to its winner too.
    ok(
        cl.close_receipt(Who::Winner(3), w3),
        "close the held receipt",
    );
    assert_eq!(cl.lamports(&w3), rent);
}

// ------------------------------------------------------------------- deep proofs: CU and size

/// A Claimable escrow whose payout tree holds winners 0 and 1 as sibling leaves `depth` levels
/// down (the other subtrees opaque), like a tree of 2^depth leaves.
fn deep(depth: usize) -> Cl {
    let mut cl = Cl::open(true);
    let leaf0 = compute_leaf_hash(&cl.escrow, &cl.winner(0), PRIZES[0]);
    let leaf1 = compute_leaf_hash(&cl.escrow, &cl.winner(1), PRIZES[1]);
    let opaque: Vec<[u8; 32]> = (1..depth)
        .map(|i| hashv(&[b"opaque subtree".as_slice(), &(i as u64).to_le_bytes()]).to_bytes())
        .collect();
    let root = opaque
        .iter()
        .fold(hash_pair(&leaf0, &leaf1), |node, sibling| {
            hash_pair(&node, sibling)
        });
    let proof = |sibling: [u8; 32]| [vec![sibling], opaque.clone()].concat();
    cl.leaves = vec![(PRIZES[0], proof(leaf1)), (PRIZES[1], proof(leaf0))];
    assert_eq!(cl.leaves[0].1.len(), depth);
    cl.settle_at(root);
    cl
}

/// The claim's non-signer accounts in an address lookup table: everything but the signers and
/// the program itself (which the instruction invokes, so it stays a static key), the event
/// authority included.
fn claim_table(cl: &mut Cl, claimant: &Pubkey) -> AddressLookupTableAccount {
    let table = AddressLookupTableAccount {
        key: Pubkey::new_unique(),
        addresses: vec![
            cl.escrow,
            cl.mint,
            cl.vault,
            cl.ata(claimant),
            receipt_pda(&cl.escrow, claimant),
            token::ID,
            associated_token::ID,
            system_program::ID,
            config_pda(),
            EVENT_AUTHORITY,
        ],
    };
    set_lookup_table(&mut cl.svm, &table);
    table
}

/// Bytes on the wire: the compact-u16 signature count (one byte below 128), the signatures and
/// the message.
fn wire_size(tx: &VersionedTransaction) -> usize {
    assert!(tx.signatures.len() < 128);
    1 + 64 * tx.signatures.len() + tx.message.serialize().len()
}

#[test]
fn proofs_16_and_24_deep_fit_one_transaction_and_their_compute_is_measured() {
    let mut cl = deep(1);
    let w0 = cl.winner(0);

    // How deep a proof a legacy transaction carries, by who signs it: 81 + 64 x signatures + 32 x
    // keys + 32 x depth bytes, so each extra signer (64 bytes + its key) costs three levels. The
    // event-CPI accounts (#[event_cpi]: the event authority's key, and an index each for it and
    // the program) cost 34 bytes, one level in every shape, and so does the Config every claim
    // reads (its flow bucket, the stop, the guardian's freeze and the revoked keys). The
    // compliance key paying (the server's gasless claim) or the lapse path takes depth 18; beyond
    // it, an address lookup table holding the ten non-signer accounts carries the full
    // MAX_PROOF_LEN in every shape.
    let shapes: [(&str, Who, bool, usize, usize); 4] = [
        (
            "payer, winner and compliance key",
            Who::Payer,
            true,
            15,
            1_218,
        ),
        ("the compliance key pays", Who::Compliance, true, 18, 1_122),
        (
            "lapse, a payer and the winner",
            Who::Payer,
            false,
            18,
            1_122,
        ),
        ("lapse, the winner pays", Who::Winner(0), false, 21, 1_026),
    ];
    let table = claim_table(&mut cl, &w0);
    for (what, fee_payer, cosign, deepest, alt_size_24) in shapes {
        let mut signers = vec![Who::Winner(0)];
        if cosign {
            signers.push(Who::Compliance);
        }
        let mut legacy = Vec::new();
        for depth in 0..=usize::from(MAX_PROOF_LEN) {
            let ix = cl.claim_ix(
                w0,
                cl.key(fee_payer),
                cosign,
                PRIZES[0],
                0,
                vec![[9; 32]; depth],
            );
            legacy.push(wire_size(&cl.legacy_tx(fee_payer, ix, &signers)));
        }
        let fits = legacy
            .iter()
            .filter(|size| **size <= PACKET_DATA_SIZE)
            .count();
        assert_eq!(
            fits - 1,
            deepest,
            "{what}: the deepest legacy proof ({legacy:?})"
        );
        assert!(legacy.windows(2).all(|w| w[1] > w[0]), "{what}: {legacy:?}");
        assert!(
            legacy[15] <= PACKET_DATA_SIZE,
            "{what}: depth 15 needs no table"
        );

        let ix = cl.claim_ix(
            w0,
            cl.key(fee_payer),
            cosign,
            PRIZES[0],
            0,
            vec![[9; 32]; usize::from(MAX_PROOF_LEN)],
        );
        let size = wire_size(&cl.v0_tx(fee_payer, ix, &signers, &table));
        assert_eq!(
            size, alt_size_24,
            "{what}: depth 24 through the lookup table"
        );
        assert!(size <= PACKET_DATA_SIZE);
        eprintln!(
            "claim, {what}: legacy fits a proof up to {deepest} deep (depth 15: {} bytes); depth 24 with the lookup table: {size} bytes",
            legacy[15]
        );
    }

    // The worst case runs: the first claim creates the receipt and the winner's token account.
    let mut used = Vec::new();
    for depth in [16, 24] {
        let mut cl = deep(depth);
        let (w0, w1) = (cl.winner(0), cl.winner(1));
        let signers = [Who::Winner(0), Who::Compliance];
        let (total, proof) = cl.leaves[0].clone();
        let ix = cl.claim_ix(w0, cl.payer.pubkey(), true, total, 0, proof);
        let tx = if depth <= 15 {
            cl.legacy_tx(Who::Payer, ix, &signers)
        } else {
            let table = claim_table(&mut cl, &w0);
            let tx = cl.v0_tx(Who::Payer, ix, &signers, &table);
            assert!(matches!(tx.message, VersionedMessage::V0(_)));
            tx
        };
        let size = wire_size(&tx);
        assert!(size <= PACKET_DATA_SIZE, "depth {depth}: {size} bytes");
        let claim = ok(cl.svm.send_transaction(tx), "a deep co-signed claim");
        assert_eq!(cl.tokens(&cl.ata(&w0)), PRIZES[0]);

        let (total, proof) = cl.leaves[1].clone();
        let ix = cl.request_ix(w1, total, proof);
        let tx = cl.legacy_tx(Who::Payer, ix, &[Who::Winner(1)]);
        let request_size = wire_size(&tx);
        assert!(request_size <= PACKET_DATA_SIZE);
        let request = ok(cl.svm.send_transaction(tx), "a deep request");

        eprintln!(
            "depth {depth}: claim {} CU in {size} bytes, request_claim {} CU in {request_size} bytes",
            claim.compute_units_consumed, request.compute_units_consumed
        );
        used.push((claim.compute_units_consumed, request.compute_units_consumed));
    }
    // Measured on the release build (SBPF v2, the sponsor-seeded escrow) with Cl::open's fixed
    // keys, under mainnet's feature set (tests/mainnet): depth 16, claim 59,826 CU and
    // request_claim 20,018; depth 24, 61,530 and 21,722
    // (about 213 CU a level; most of a first claim is creating the receipt and the token
    // account, the event's self-CPI adds about 2,880 to each, and reading the Config about 3,200,
    // plus about 2,900 for the claim's flow bucket and its checks). Other keys move both by 1,500 CU for
    // each extra bump an on-chain PDA or associated-account search tries (random keys measured
    // up to 77,131 for a depth-16 claim), all far inside the 200,000 CU an instruction gets
    // without a compute-budget request. The ceilings leave room for toolchain drift, not for a
    // new cost.
    let [(claim16, request16), (claim24, request24)] = used[..] else {
        unreachable!()
    };
    assert!(claim24 > claim16 && request24 > request16, "{used:?}");
    assert!(claim24 <= 70_000 && request24 <= 25_000, "{used:?}");
}

// --------------------------------------------------------------------------------- helpers

fn receipt_pda(escrow: &Pubkey, claimant: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[CLAIM_SEED, escrow.as_ref(), claimant.as_ref()],
        &prize_escrow::ID,
    )
    .0
}

fn receipt_bump(escrow: &Pubkey, claimant: &Pubkey) -> u8 {
    Pubkey::find_program_address(
        &[CLAIM_SEED, escrow.as_ref(), claimant.as_ref()],
        &prize_escrow::ID,
    )
    .1
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
        freeze_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    set_raw(svm, address, data, token::ID);
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
    set_raw(svm, address, data, token::ID);
}

/// An active, frozen address lookup table: the ProgramState::LookupTable tag, then the 52-byte
/// LookupTableMeta (deactivation_slot u64::MAX, last_extended_slot 0, a start index covering
/// every address so they resolve in slot 0 too, no authority), padded to 56 bytes, then the
/// addresses.
fn set_lookup_table(svm: &mut LiteSVM, table: &AddressLookupTableAccount) {
    let mut data = vec![0u8; 56];
    data[..4].copy_from_slice(&1u32.to_le_bytes());
    data[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
    data[20] = u8::try_from(table.addresses.len()).unwrap();
    for address in &table.addresses {
        data.extend_from_slice(address.as_ref());
    }
    let owner: Pubkey = ADDRESS_LOOKUP_TABLE_PROGRAM.parse().unwrap();
    set_raw(svm, table.key, data, owner);
}

fn set_raw(svm: &mut LiteSVM, address: Pubkey, data: Vec<u8>, owner: Pubkey) {
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

fn custom_code(result: &TransactionResult) -> Option<u32> {
    match result {
        Err(failed) => match &failed.err {
            TransactionError::InstructionError(0, InstructionError::Custom(code)) => Some(*code),
            _ => None,
        },
        Ok(_) => None,
    }
}

/// The transaction failed with exactly `code`: an EscrowError or an Anchor ErrorCode.
fn assert_refused(result: TransactionResult, code: impl Into<u32>, what: &str) {
    let code = code.into();
    assert_eq!(
        custom_code(&result),
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
