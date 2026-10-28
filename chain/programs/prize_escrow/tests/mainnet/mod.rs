//! The feature set mainnet has active, and the LiteSVM every program test drives under it.
//!
//! scripts/chain/feature-set.ts reads it from the cluster (every account the feature-gate program
//! owns, the Rent sysvar, and the feature list of the Agave release its validators run) and pins it
//! in features.json beside this file. `svm()` is `LiteSVM::new()` with exactly that set in place of
//! the snapshot litesvm compiled in: the builtins, the default programs (the SPL Token build the
//! p-token gate picks), the sysvars (the Rent the SIMD-0194 and SIMD-0437 gates set) and the
//! feature accounts all follow it. tests/feature_set.rs checks that LiteSVM honours the pin.
//!
//! Refresh the pin with `node scripts/chain/feature-set.ts`; before a deploy,
//! `node scripts/chain/feature-set.ts --check` says whether mainnet has moved since.

#![allow(dead_code, reason = "each test file uses its own subset")]

use {agave_feature_set::FeatureSet, litesvm::LiteSVM, serde_json::Value, std::sync::OnceLock};

const PIN_JSON: &str = include_str!("features.json");

/// What `LiteSVM::new()` funds its airdrop account with: a million SOL.
const AIRDROP_LAMPORTS: u64 = 1_000_000 * 1_000_000_000;

/// A feature active on the cluster.
pub struct Feature {
    pub id: String,
    /// The slot it activated at.
    pub slot: u64,
    /// Its module path in the release's agave-feature-set; None when the release no longer
    /// lists it.
    pub name: Option<String>,
    /// Active, and no longer in the release's feature list: cleaned up, its behaviour
    /// unconditional.
    pub retired: bool,
}

/// The cluster's Rent sysvar.
pub struct Rent {
    pub lamports_per_byte: u64,
    pub exemption_threshold: f64,
    pub burn_percent: u8,
    /// The sysvar account's 17 bytes, as the cluster holds them.
    pub data: Vec<u8>,
}

/// features.json.
pub struct Pin {
    pub cluster: String,
    pub read_at: String,
    pub slot: u64,
    /// The Agave release the RPC node ran, and its feature-set id (getVersion).
    pub solana_core: String,
    pub feature_set_id: u32,
    pub rent: Rent,
    pub active: Vec<Feature>,
    /// Queued for the next epoch boundary when the pin was read: not active, so not in `svm()`.
    pub pending: Vec<String>,
}

fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key)
        .unwrap_or_else(|| panic!("tests/mainnet/features.json: no {key:?} in {v}"))
}

fn u64_of(v: &Value, key: &str) -> u64 {
    field(v, key)
        .as_u64()
        .unwrap_or_else(|| panic!("tests/mainnet/features.json: {key:?} is not a u64 in {v}"))
}

fn str_of(v: &Value, key: &str) -> String {
    field(v, key)
        .as_str()
        .unwrap_or_else(|| panic!("tests/mainnet/features.json: {key:?} is not a string in {v}"))
        .to_owned()
}

fn hex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "tests/mainnet/features.json: odd hex {s:?}"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("tests/mainnet/features.json: hex"))
        .collect()
}

/// The pin, parsed once.
pub fn pin() -> &'static Pin {
    static PIN: OnceLock<Pin> = OnceLock::new();
    PIN.get_or_init(|| {
        let v: Value =
            serde_json::from_str(PIN_JSON).expect("tests/mainnet/features.json is not JSON");
        let release = field(&v, "release");
        let rent = field(&v, "rent");
        let active = field(&v, "active")
            .as_array()
            .expect("tests/mainnet/features.json: active is not an array")
            .iter()
            .map(|f| Feature {
                id: str_of(f, "id"),
                slot: u64_of(f, "slot"),
                name: f.get("name").and_then(Value::as_str).map(str::to_owned),
                retired: f.get("retired").and_then(Value::as_bool).unwrap_or(false),
            })
            .collect::<Vec<_>>();
        assert!(
            !active.is_empty(),
            "tests/mainnet/features.json: no active feature"
        );
        Pin {
            cluster: str_of(&v, "cluster"),
            read_at: str_of(&v, "readAt"),
            slot: u64_of(&v, "slot"),
            solana_core: str_of(release, "solanaCore"),
            feature_set_id: u32::try_from(u64_of(release, "featureSet"))
                .expect("tests/mainnet/features.json: featureSet is not a u32"),
            rent: Rent {
                lamports_per_byte: u64_of(rent, "lamportsPerByte"),
                exemption_threshold: field(rent, "exemptionThreshold")
                    .as_f64()
                    .expect("tests/mainnet/features.json: exemptionThreshold"),
                burn_percent: u8::try_from(u64_of(rent, "burnPercent"))
                    .expect("tests/mainnet/features.json: burnPercent"),
                data: hex(&str_of(rent, "data")),
            },
            active,
            pending: field(&v, "pending")
                .as_array()
                .expect("tests/mainnet/features.json: pending is not an array")
                .iter()
                .map(|f| str_of(f, "id"))
                .collect(),
        }
    })
}

/// Exactly the pinned active features, each at its activation slot; every other feature off.
pub fn feature_set() -> FeatureSet {
    let mut set = FeatureSet::default();
    for f in &pin().active {
        let id = f
            .id
            .parse()
            .unwrap_or_else(|_| panic!("tests/mainnet/features.json: {} is not an address", f.id));
        set.activate(&id, f.slot);
    }
    set
}

/// `LiteSVM::new()` under mainnet's feature set: the same steps in the same order
/// (litesvm's `into_basic`), with the pinned set where it puts its compiled-in snapshot.
pub fn svm() -> LiteSVM {
    LiteSVM::default()
        .with_feature_set(feature_set())
        .with_builtins()
        .with_lamports(AIRDROP_LAMPORTS)
        .with_sysvars()
        .with_feature_accounts()
        .with_default_programs()
        .with_sigverify(true)
        .with_blockhash_check(true)
}
