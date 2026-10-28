//! What every LiteSVM test file shares: the Config every instruction reads, created the way a
//! cluster creates it (initialize_config, signed by the program's upgrade authority), and the
//! slot and upgrade-authority plumbing it needs.

#![allow(dead_code, reason = "each test file uses its own subset")]

use {
    anchor_lang::{
        prelude::{Clock, Pubkey},
        solana_program::{bpf_loader_upgradeable, instruction::Instruction, system_program},
        InstructionData, ToAccountMetas,
    },
    litesvm::LiteSVM,
    prize_escrow::{
        accounts as accts, instruction as ixs, ConfigInit, Floors, Limits, RegraderEntry,
        EVENT_AUTHORITY_AND_BUMP, MAX_REGRADERS, MIN_REVEAL_GRACE,
    },
};

/// The Config PDA, ["config"].
pub fn config_pda() -> Pubkey {
    prize_escrow::Config::pda().0
}

/// The program's ProgramData account, ["<program id>"] under the upgradeable loader.
pub fn program_data_pda() -> Pubkey {
    Pubkey::find_program_address(&[prize_escrow::ID.as_ref()], &bpf_loader_upgradeable::ID).0
}

/// Rewrites the ProgramData header LiteSVM's add_program wrote (no upgrade authority) to name
/// `authority`, or none, as a deployed program's would.
pub fn set_upgrade_authority(svm: &mut LiteSVM, authority: Option<Pubkey>) {
    let address = program_data_pda();
    let mut account = svm.get_account(&address).expect("the ProgramData account");
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
    svm.set_account(address, account).unwrap();
}

/// Moves LiteSVM to the next slot (a reveal must land after its commit's slot).
pub fn next_slot(svm: &mut LiteSVM) {
    let clock = svm.get_sysvar::<Clock>();
    svm.warp_to_slot(clock.slot + 1);
    // warp_to_slot keeps the unix timestamp; restate it in case a version moves it.
    let mut moved = svm.get_sysvar::<Clock>();
    moved.unix_timestamp = clock.unix_timestamp;
    svm.set_sysvar::<Clock>(&moved);
}

/// Limits that let every test escrow through: caps and a bucket far above any test total, no
/// minimum bond, and an all-house panel allowed.
pub fn open_limits() -> Limits {
    Limits {
        escrow_cap: u64::MAX / 4,
        global_cap: u64::MAX / 2,
        flow_capacity: u64::MAX / 4,
        flow_period: 24 * 60 * 60,
        min_bond: 0,
        max_house_regraders: MAX_REGRADERS,
    }
}

/// No floors above the compiled minimums, and the shortest reveal grace.
pub fn open_floors() -> Floors {
    Floors {
        min_challenge_window: 0,
        min_attest_window: 0,
        min_hold_window: 0,
        min_claim_window: 0,
        reveal_grace: MIN_REVEAL_GRACE,
    }
}

/// A ConfigInit allowing `mints`, `sponsors` and `regraders` (none of them the house's), with
/// open_limits and open_floors.
pub fn config_init(
    admin: Pubkey,
    guardian: Pubkey,
    arbiter: Pubkey,
    mints: &[Pubkey],
    sponsors: &[Pubkey],
    regraders: &[Pubkey],
) -> ConfigInit {
    ConfigInit {
        admin,
        guardian,
        arbiter,
        limits: open_limits(),
        floors: open_floors(),
        mints: mints.to_vec(),
        sponsors: sponsors.to_vec(),
        regraders: regraders
            .iter()
            .map(|key| RegraderEntry {
                key: *key,
                house: false,
            })
            .collect(),
    }
}

/// initialize_config signed by `authority`.
pub fn initialize_config_ix(authority: Pubkey, init: ConfigInit) -> Instruction {
    Instruction {
        program_id: prize_escrow::ID,
        accounts: accts::InitializeConfig {
            authority,
            config: config_pda(),
            program_data: program_data_pda(),
            system_program: system_program::ID,
            event_authority: EVENT_AUTHORITY_AND_BUMP.0,
            program: prize_escrow::ID,
        }
        .to_account_metas(None),
        data: ixs::InitializeConfig { init }.data(),
    }
}

/// The salt the tests commit challenges with: one per challenger and alternative, so two
/// challengers committing the same alternative hold different hashes.
pub fn salt_for(challenger: &Pubkey, alt_commitment: &[u8; 32]) -> [u8; 32] {
    solana_sha256_hasher::hashv(&[b"test-salt", challenger.as_ref(), alt_commitment]).to_bytes()
}
