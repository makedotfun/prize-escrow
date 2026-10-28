//! The program tests run under the feature set mainnet has active (tests/mainnet/features.json,
//! read from the cluster by scripts/chain/feature-set.ts), and LiteSVM honours it: exactly those
//! features are on, its agave runtime knows every one the cluster's release still gates on, and
//! what LiteSVM derives from them is the cluster's: the feature accounts, the Rent sysvar byte for
//! byte (so the bond floor the program enforces is mainnet's) and the SPL Token build.

mod mainnet;

use {
    anchor_lang::prelude::Rent,
    prize_escrow::{state::bond_floor, Config, Escrow, BOND_FLOOR_RENTS},
    std::collections::{BTreeMap, HashSet},
};

/// The feature-gate program, which owns every feature account.
const FEATURE_PROGRAM: &str = "Feature111111111111111111111111111111111111";
const RENT_SYSVAR: &str = "SysvarRent111111111111111111111111111111111";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// SIMD-0266's gate: SPL Token's address runs p-token, an upgradeable-loader program.
const P_TOKEN_GATE: &str = "ptokFjwyJtrwCa9Kgo9xoDS59V4QccBGEaRFnRPnSdP";
const UPGRADEABLE_LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const LOADER_V2: &str = "BPFLoader2111111111111111111111111111111111";

/// The first four bytes, little-endian, of agave-feature-set's ID: the feature-set id getVersion
/// reports for a node running the same feature list as LiteSVM's runtime.
fn runtime_feature_set_id() -> u32 {
    let id: &[u8] = agave_feature_set::ID.as_ref();
    u32::from_le_bytes(id[..4].try_into().expect("a 32-byte hash"))
}

fn pinned() -> BTreeMap<String, u64> {
    mainnet::pin()
        .active
        .iter()
        .map(|f| (f.id.clone(), f.slot))
        .collect()
}

#[test]
fn the_pin_is_mainnets() {
    let pin = mainnet::pin();
    assert_eq!(
        pin.cluster, "mainnet",
        "tests/mainnet/features.json pins another cluster"
    );
    assert!(pin.slot > 0 && !pin.read_at.is_empty());
    let mut ids = HashSet::new();
    for f in &pin.active {
        assert!(ids.insert(f.id.as_str()), "{} is pinned twice", f.id);
        assert!(
            f.slot <= pin.slot,
            "{} activates after the slot the pin was read at",
            f.id
        );
        assert!(
            f.retired || f.name.is_some(),
            "{} is neither named nor retired",
            f.id
        );
    }
    for id in &pin.pending {
        assert!(
            !ids.contains(id.as_str()),
            "{id} is both active and pending"
        );
    }
}

#[test]
fn the_feature_set_is_exactly_the_pinned_one() {
    let set = mainnet::feature_set();
    let pinned = pinned();
    let active: BTreeMap<String, u64> = set
        .active()
        .iter()
        .map(|(id, slot)| (id.to_string(), *slot))
        .collect();
    assert_eq!(active, pinned);
    // Every feature the runtime knows and mainnet has not activated (the pending ones too) is off.
    for id in agave_feature_set::FEATURE_NAMES.keys() {
        if !pinned.contains_key(&id.to_string()) {
            assert!(!set.is_active(id), "{id} is on but not on mainnet");
        }
    }
    for id in &mainnet::pin().pending {
        assert!(!active.contains_key(id), "pending {id} is on");
    }
}

#[test]
fn litesvm_runs_the_pinned_features() {
    // LiteSVM writes a feature-gate account for each feature its set holds, activated at its slot
    // (bincode Feature { activated_at: Some(slot) }), as the cluster holds them: so its feature
    // accounts are its active set.
    let svm = mainnet::svm();
    let owner = FEATURE_PROGRAM.parse().expect("an address");
    let accounts: BTreeMap<String, u64> = svm
        .get_program_accounts(&owner)
        .into_iter()
        .map(|(address, account)| {
            assert_eq!(account.data.len(), 9, "{address}'s feature account");
            assert_eq!(account.data[0], 1, "{address} is not activated");
            let slot = u64::from_le_bytes(account.data[1..9].try_into().expect("8 bytes"));
            (address.to_string(), slot)
        })
        .collect();
    assert_eq!(
        accounts,
        pinned(),
        "LiteSVM's feature accounts are not the pinned set"
    );

    // The default programs follow the set too: SPL Token's address holds p-token (an
    // upgradeable-loader program) where SIMD-0266's gate is on, SPL Token 3.5 (loader v2) where
    // it is off.
    let token = svm
        .get_account(&TOKEN_PROGRAM.parse().expect("an address"))
        .expect("the SPL Token program");
    let want = if pinned().contains_key(P_TOKEN_GATE) {
        UPGRADEABLE_LOADER
    } else {
        LOADER_V2
    };
    assert_eq!(token.owner.to_string(), want, "SPL Token's loader");
}

#[test]
fn litesvm_runtime_knows_every_feature_mainnet_gates_on() {
    let pin = mainnet::pin();
    let known: HashSet<String> = agave_feature_set::FEATURE_NAMES
        .keys()
        .map(ToString::to_string)
        .collect();
    let missing: Vec<String> = pin
        .active
        .iter()
        .filter(|f| !f.retired && !known.contains(&f.id))
        .map(|f| {
            format!(
                "{} {} (slot {})",
                f.name.as_deref().unwrap_or("?"),
                f.id,
                f.slot
            )
        })
        .collect();
    assert!(
        missing.is_empty(),
        "mainnet (Agave {}, feature-set {}) has {} feature(s) active that LiteSVM's agave runtime \
         (feature-set {}) does not know, so the tests would run without them:\n  {}\nBump litesvm \
         in chain/programs/prize_escrow/Cargo.toml to a release built on Agave {} or later.",
        pin.solana_core,
        pin.feature_set_id,
        missing.len(),
        runtime_feature_set_id(),
        missing.join("\n  "),
        pin.solana_core,
    );
}

#[test]
fn rent_is_the_clusters() {
    let pin = mainnet::pin();
    let svm = mainnet::svm();
    let sysvar = svm
        .get_account(&RENT_SYSVAR.parse().expect("an address"))
        .expect("the Rent sysvar");
    assert_eq!(
        sysvar.data, pin.rent.data,
        "LiteSVM derives another Rent sysvar from the pinned features than mainnet holds \
         ({} lamports a byte, threshold {}, burn {}%)",
        pin.rent.lamports_per_byte, pin.rent.exemption_threshold, pin.rent.burn_percent
    );

    // The program reads the same 17 bytes (Rent::get), so the bond floor it enforces is
    // BOND_FLOOR_RENTS rent-exempt minimums of an empty account at mainnet's rent, and the
    // runtime's own rent-exempt minimum agrees with the program's arithmetic.
    #[allow(
        deprecated,
        reason = "the program's solana-rent 3 Rent has only these fields"
    )]
    let rent = Rent {
        lamports_per_byte_year: pin.rent.lamports_per_byte,
        exemption_threshold: pin.rent.exemption_threshold,
        burn_percent: pin.rent.burn_percent,
    };
    let empty = svm.minimum_balance_for_rent_exemption(0);
    assert_eq!(rent.minimum_balance(0), empty);
    assert_eq!(bond_floor(&rent), BOND_FLOOR_RENTS * empty);
    for len in [0, 165, Escrow::SPACE, Config::SPACE] {
        assert_eq!(
            rent.minimum_balance(len),
            svm.minimum_balance_for_rent_exemption(len),
            "the rent-exempt minimum of {len} bytes"
        );
    }
}
