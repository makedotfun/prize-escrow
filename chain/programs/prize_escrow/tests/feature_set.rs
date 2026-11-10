//! The program tests run under the feature set mainnet has active (tests/mainnet/features.json,
//! read from the cluster by scripts/chain/feature-set.ts), and LiteSVM honours it: exactly those
//! features are on, its agave runtime knows every one the cluster's release still gates on, and
//! what LiteSVM derives from them is the cluster's: the feature accounts, the Rent sysvar byte for
//! byte (so the bond floor the program enforces is mainnet's) and the SPL Token build.

mod mainnet;

use {
    anchor_lang::prelude::Rent,
    prize_escrow::{state::bond_floor, Config, Escrow, BOND_FLOOR_RENTS},
    std::{
        collections::{BTreeMap, HashSet},
        io::Write,
    },
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

/// A feature mainnet has active that LiteSVM's agave runtime does not know, accepted by name: the
/// tests run without it, and this records why that does not bear on the program. Every other such
/// feature still fails `litesvm_runtime_knows_every_feature_mainnet_gates_on`, and an entry whose
/// feature the runtime knows, or that mainnet does not have active, fails it as stale.
struct Exception {
    id: &'static str,
    /// Its module path in the cluster release's agave-feature-set.
    name: &'static str,
    /// The slot it activated at on mainnet, and when that was.
    slot: u64,
    since: &'static str,
    /// What the feature changes in the runtime.
    changes: &'static str,
    /// Why running the tests without it does not bear on the program.
    why: &'static str,
    /// Who accepted it, and when.
    decided: &'static str,
    /// When the entry goes.
    remove_when: &'static str,
}

const ACCEPTED: &[Exception] = &[Exception {
    id: "8whkDenELnfwYLirBc4Wb4H2Z1z5K7tiykpdxJS7cWg1",
    name: "loaderv3_programdata_size_floor",
    slot: 466_128_000,
    since: "2026-11-06T13:34:20Z",
    changes: "when a transaction invokes an upgradeable-loader program without listing that \
              program's ProgramData account, the loaded-data-size charge for the ProgramData \
              becomes 64 + max(its length, 45 bytes) and is charged even when the account does \
              not exist; the bank also stops adding implicit read locks on ProgramData \
              (scheduling only) (Agave svm/src/account_loader.rs and runtime/src/bank.rs at \
              v4.4.1; backport PR #16775 of master #16769)",
    why: "prize_escrow's ProgramData and the SPL Token program's both exist and are far over 45 \
          bytes, so the charge for them is what it was; nothing in this repository sets \
          SetLoadedAccountsDataSizeLimit, so the default limit applies and our transactions sit \
          far under it; token transfers, CPI, account reallocation, the loader's extend and \
          upgrade, compute budget, sysvars and syscalls are untouched",
    decided: "the program's owner, 2026-11-10: upgrade now, with this exception recorded",
    remove_when: "LiteSVM's runtime knows the feature (a litesvm built on Agave 4.4.1 or later): \
                  the test then fails on this entry until it is deleted",
}];

/// What the rule finds in the pin, against the features the runtime knows and the exceptions.
struct Verdict<'a> {
    /// Active features the release gates on (not retired) that the runtime does not know and
    /// that no exception names: each one fails the test.
    missing: Vec<String>,
    /// Exceptions that no longer hold (the runtime knows the feature, or mainnet does not have it
    /// active as the entry says): each one fails the test.
    stale: Vec<String>,
    /// Exceptions that hold: an active, gated feature the runtime does not know.
    accepted: Vec<&'a Exception>,
}

fn describe(f: &mainnet::Feature) -> String {
    format!(
        "{} {} (slot {})",
        f.name.as_deref().unwrap_or("?"),
        f.id,
        f.slot
    )
}

/// The rule `litesvm_runtime_knows_every_feature_mainnet_gates_on` enforces, pure: every active
/// feature the release gates on is one the runtime knows, or one an exception names; and every
/// exception names a feature that is active, gated, at the entry's slot, and unknown to the
/// runtime.
fn judge<'a>(
    active: &[mainnet::Feature],
    known: &HashSet<String>,
    exceptions: &'a [Exception],
) -> Verdict<'a> {
    let excepted = |id: &str| exceptions.iter().any(|e| e.id == id);
    let missing = active
        .iter()
        .filter(|f| !f.retired && !known.contains(&f.id) && !excepted(&f.id))
        .map(describe)
        .collect();
    let mut stale = Vec::new();
    let mut accepted = Vec::new();
    for e in exceptions {
        let entry = format!("{} {}", e.name, e.id);
        match active.iter().find(|f| f.id == e.id) {
            _ if known.contains(e.id) => stale.push(format!(
                "{entry}: LiteSVM's runtime knows it now, so the tests run with it; delete the \
                 entry"
            )),
            None => stale.push(format!(
                "{entry}: not active in the pin, so there is nothing to accept; delete the entry"
            )),
            Some(f) if f.retired => stale.push(format!(
                "{entry}: retired in the pin (its behaviour is unconditional), so there is \
                 nothing to accept; delete the entry"
            )),
            Some(f) if f.slot != e.slot || f.name.as_deref() != Some(e.name) => {
                stale.push(format!(
                    "{entry}: the pin has it as {}, not as the entry says (slot {}); the entry \
                     describes another activation, so review it",
                    describe(f),
                    e.slot
                ))
            }
            Some(_) => accepted.push(e),
        }
    }
    Verdict {
        missing,
        stale,
        accepted,
    }
}

#[test]
fn litesvm_runtime_knows_every_feature_mainnet_gates_on() {
    let pin = mainnet::pin();
    let known: HashSet<String> = agave_feature_set::FEATURE_NAMES
        .keys()
        .map(ToString::to_string)
        .collect();
    let Verdict {
        missing,
        stale,
        accepted,
    } = judge(&pin.active, &known, ACCEPTED);
    // The release whose feature list the cluster runs: a later patch than the node's version string
    // when its build is ahead of it (the pin's featureList).
    let list = pin.feature_list.as_deref().unwrap_or(&pin.solana_core);
    assert!(
        stale.is_empty(),
        "{} stale exception(s) in tests/feature_set.rs ACCEPTED:\n  {}",
        stale.len(),
        stale.join("\n  "),
    );
    for e in &accepted {
        // Straight to the process's stderr: libtest captures eprintln! of a passing test, and the
        // exception belongs in every run's log.
        let _ = writeln!(
            std::io::stderr(),
            "feature_set: accepted exception {} {} (active since slot {}, {}), which LiteSVM's \
             agave runtime (feature-set {}) does not know: {}. Decided by {}. Remove when {}.",
            e.name,
            e.id,
            e.slot,
            e.since,
            runtime_feature_set_id(),
            e.why,
            e.decided,
            e.remove_when,
        );
    }
    assert!(
        missing.is_empty(),
        "mainnet (Agave {}, feature-set {}, agave-feature-set {}'s list) has {} feature(s) active \
         that LiteSVM's agave runtime (feature-set {}) does not know, so the tests would run \
         without them:\n  {}\nBump litesvm in chain/programs/prize_escrow/Cargo.toml to a release \
         built on agave-feature-set {} or later.",
        pin.solana_core,
        pin.feature_set_id,
        list,
        missing.len(),
        runtime_feature_set_id(),
        missing.join("\n  "),
        list,
    );
}

/// Every exception says, whole, what it accepts and why: a real address, and no blank field.
#[test]
fn every_exception_is_written_whole() {
    for e in ACCEPTED {
        assert!(
            e.id.parse::<anchor_lang::prelude::Pubkey>().is_ok(),
            "{} is not an address",
            e.id
        );
        for (field, text) in [
            ("name", e.name),
            ("since", e.since),
            ("changes", e.changes),
            ("why", e.why),
            ("decided", e.decided),
            ("remove_when", e.remove_when),
        ] {
            assert!(!text.trim().is_empty(), "{}'s {field} is blank", e.id);
        }
        assert!(e.slot > 0, "{}'s slot", e.id);
    }
}

/// The rule's cases, on made-up ids: a runtime that knows `Known1`, an exception for `New1`.
fn feature(id: &str, slot: u64) -> mainnet::Feature {
    mainnet::Feature {
        id: id.to_owned(),
        slot,
        name: Some(format!("name_of_{id}")),
        retired: false,
    }
}

const NEW1: Exception = Exception {
    id: "New1",
    name: "name_of_New1",
    slot: 20,
    since: "a made-up date",
    changes: "a made-up change",
    why: "a made-up reason",
    decided: "a made-up decision",
    remove_when: "a made-up condition",
};

fn knows(ids: &[&str]) -> HashSet<String> {
    ids.iter().map(|id| (*id).to_owned()).collect()
}

#[test]
fn rule_fails_an_unknown_feature_no_exception_names() {
    let active = [
        feature("Known1", 10),
        feature("New1", 20),
        feature("New2", 30),
    ];
    let v = judge(&active, &knows(&["Known1"]), &[NEW1]);
    assert_eq!(v.missing, ["name_of_New2 New2 (slot 30)"]);
    assert!(v.stale.is_empty());
    assert_eq!(v.accepted.len(), 1);
    // With no exception at all, both unknown features fail.
    let v = judge(&active, &knows(&["Known1"]), &[]);
    assert_eq!(
        v.missing,
        ["name_of_New1 New1 (slot 20)", "name_of_New2 New2 (slot 30)"]
    );
}

#[test]
fn rule_fails_an_exception_the_runtime_knows_as_stale() {
    let active = [feature("Known1", 10), feature("New1", 20)];
    let v = judge(&active, &knows(&["Known1", "New1"]), &[NEW1]);
    assert!(v.missing.is_empty());
    assert_eq!(v.stale.len(), 1);
    assert!(
        v.stale[0].starts_with("name_of_New1 New1: LiteSVM's runtime knows it now"),
        "{}",
        v.stale[0]
    );
    assert!(v.accepted.is_empty());
}

#[test]
fn rule_fails_an_exception_not_active_in_the_pin_as_stale() {
    let v = judge(&[feature("Known1", 10)], &knows(&["Known1"]), &[NEW1]);
    assert!(v.missing.is_empty());
    assert_eq!(v.stale.len(), 1);
    assert!(
        v.stale[0].starts_with("name_of_New1 New1: not active in the pin"),
        "{}",
        v.stale[0]
    );
    assert!(v.accepted.is_empty());

    // Active but retired, or active at another slot than the entry says: stale as well.
    let mut retired = feature("New1", 20);
    retired.retired = true;
    let v = judge(&[retired], &knows(&[]), &[NEW1]);
    assert!(v.missing.is_empty() && v.accepted.is_empty());
    assert!(v.stale[0].contains("retired in the pin"), "{}", v.stale[0]);
    let v = judge(&[feature("New1", 21)], &knows(&[]), &[NEW1]);
    assert!(v.missing.is_empty() && v.accepted.is_empty());
    assert!(
        v.stale[0].contains("not as the entry says"),
        "{}",
        v.stale[0]
    );
}

#[test]
fn rule_passes_only_the_listed_active_unknown_feature() {
    let active = [feature("Known1", 10), feature("New1", 20)];
    let v = judge(&active, &knows(&["Known1"]), &[NEW1]);
    assert!(v.missing.is_empty(), "{:?}", v.missing);
    assert!(v.stale.is_empty(), "{:?}", v.stale);
    let ids: Vec<&str> = v.accepted.iter().map(|e| e.id).collect();
    assert_eq!(ids, ["New1"]);
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
