use anchor_lang::prelude::*;

/// Seed of the Escrow PDA: `["escrow", sponsor, competition_id]`, competition_id being the
/// competition's 16-byte UUID. The sponsor in the seeds means nobody else can open a sponsor's
/// competition first and squat its address.
#[constant]
pub const ESCROW_SEED: &[u8] = b"escrow";

/// Domain of the result commitment post_result stores, each challenge seeds its PDA with, and
/// attest and arbiter_resolve compare:
/// `sha256(RESULT_COMMITMENT_DOMAIN || result_sha256 || payout_root || u64le(total))`
/// (state::result_commitment; server/chain/result.ts resultCommitment).
#[constant]
pub const RESULT_COMMITMENT_DOMAIN: &[u8] = b"agent-fun/result-commitment/v1";

/// Seed of a ClaimReceipt PDA: `["claim", escrow, claimant]`.
#[constant]
pub const CLAIM_SEED: &[u8] = b"claim";

/// Seed of an Attestation PDA: `["attestation", escrow, regrader]`.
#[constant]
pub const ATTESTATION_SEED: &[u8] = b"attestation";

/// Seed of a Challenge PDA: `["challenge", escrow, alt_commitment]`, so an escrow holds one
/// challenge per distinct alternative commitment.
#[constant]
pub const CHALLENGE_SEED: &[u8] = b"challenge";

const HOUR: i64 = 60 * 60;

/// The shortest challenge window open_escrow accepts, in seconds: 72 h. The `test-windows`
/// feature (localnet and devnet builds only) lowers it to 60 s.
#[constant]
pub const MIN_CHALLENGE_WINDOW: i64 = if cfg!(feature = "test-windows") {
    60
} else {
    72 * HOUR
};

/// The shortest attestation window open_escrow accepts, in seconds: 48 h (60 s under
/// `test-windows`).
#[constant]
pub const MIN_ATTEST_WINDOW: i64 = if cfg!(feature = "test-windows") {
    60
} else {
    48 * HOUR
};

/// The shortest compliance hold window open_escrow accepts, in seconds: 72 h (60 s under
/// `test-windows`). A requested claim with no on-chain hold clears once it passes.
#[constant]
pub const MIN_HOLD_WINDOW: i64 = if cfg!(feature = "test-windows") {
    60
} else {
    72 * HOUR
};

/// The shortest claim window open_escrow accepts, in seconds: 7 days, so winners always get a
/// week to claim before refund may sweep their prizes. The `test-windows` feature lowers it to
/// 90 s, still longer than that build's 60 s hold window.
#[constant]
pub const MIN_CLAIM_WINDOW: i64 = if cfg!(feature = "test-windows") {
    90
} else {
    7 * 24 * HOUR
};

// A claim requested as the shortest claim window opens can clear without the co-signature (the
// shortest hold window) inside it, in both builds.
const _: () = assert!(
    MIN_CLAIM_WINDOW > MIN_HOLD_WINDOW,
    "MIN_CLAIM_WINDOW outlasts MIN_HOLD_WINDOW"
);

/// The bond floor, in rent-exempt minimums of an empty account: open_escrow takes a bond_lamports
/// of at least BOND_FLOOR_RENTS x Rent::minimum_balance(0) (state::bond_floor), read from the Rent
/// sysvar, so the floor follows the cluster's rent. A bond that size is never dust, and any one
/// bond paid out leaves its recipient rent-exempt even if it held nothing before.
#[constant]
pub const BOND_FLOOR_RENTS: u64 = 2;

/// What open_escrow adds after every window to find the earliest hard_deadline it accepts, in
/// seconds: 7 days for a delayed arbiter_resolve (a Squads proposal and its time lock). With
/// hard_deadline >= resolve_deadline + challenge + attest + hold + claim windows + this slack, an
/// escrow that runs its course on time is Claimable well inside hard_deadline; a later arbiter
/// still leaves its claims a whole claim window (refund waits for claim_deadline).
#[constant]
pub const ARBITER_SLACK: i64 = 7 * 24 * HOUR;

/// The longest window open_escrow accepts, in seconds (i32::MAX, about 68 years): deadline
/// arithmetic on any accepted window cannot overflow, and every window fits the server's 32-bit
/// *_window_seconds columns.
#[constant]
pub const MAX_WINDOW: i64 = i32::MAX as i64;

/// The longest merkle proof claim and request_claim accept (2^24 leaves).
#[constant]
pub const MAX_PROOF_LEN: u8 = 24;

/// The most regraders an escrow names; Escrow.regraders holds this many slots.
#[constant]
pub const MAX_REGRADERS: u8 = 5;

/// The panel floor a new Config starts with (Config.min_regraders): 1, the smallest panel
/// EscrowTerms::validate accepts anyway (owner decision #541: single keys for now). The admin
/// raises it with set_min_regraders, up to MAX_REGRADERS, without an upgrade.
#[constant]
pub const DEFAULT_MIN_REGRADERS: u8 = 1;

/// ClaimReceipt.hold_reason: no hold.
#[constant]
pub const HOLD_NONE: u8 = 0;

/// ClaimReceipt.hold_reason: a sanctions-list match.
#[constant]
pub const HOLD_SANCTIONS: u8 = 1;

/// ClaimReceipt.hold_reason: a blocked geography.
#[constant]
pub const HOLD_GEO: u8 = 2;

/// ClaimReceipt.hold_reason: a tax form (W-9) is required before payment.
#[constant]
pub const HOLD_TAX_FORM_REQUIRED: u8 = 3;

/// ClaimReceipt.hold_reason: a manual review.
#[constant]
pub const HOLD_REVIEW: u8 = 4;

/// Whether `reason` is a reason hold accepts (HOLD_SANCTIONS through HOLD_REVIEW).
pub fn is_hold_reason(reason: u8) -> bool {
    (HOLD_SANCTIONS..=HOLD_REVIEW).contains(&reason)
}

/// Seed of the Config PDA: `["config"]`, one per program, created once by the program's upgrade
/// authority (initialize_config).
#[constant]
pub const CONFIG_SEED: &[u8] = b"config";

/// Seed of a CommitRecord PDA: `["commit", escrow, challenger, hash]`, hash being
/// `sha256(alt_commitment || challenger || salt)`. The challenger is in the seeds, so a copy of
/// someone else's hash lands at another address and never blocks the original.
#[constant]
pub const COMMIT_SEED: &[u8] = b"commit";

/// How long one stop (Config's IntakeStop or PayoutStop) or one guardian freeze of an escrow lasts
/// before it lapses on its own, in seconds: 7 days. Only the admin extends one in force
/// (extend_stop, extend_freeze), but the length is per raise, not a ceiling: once one lapses the
/// guardian may raise it again, and so hold the program (or one escrow) for as long as it keeps
/// renewing, until the admin replaces or revokes the guardian's key (breakers.rs).
#[constant]
pub const STOP_DURATION: i64 = 7 * 24 * HOUR;

/// The shortest reveal grace Config accepts, in seconds: how long after challenge_deadline a
/// challenge committed before it may still be revealed. 5 minutes (5 s under `test-windows`).
#[constant]
pub const MIN_REVEAL_GRACE: i64 = if cfg!(feature = "test-windows") {
    5
} else {
    5 * 60
};

/// The longest reveal grace Config accepts, in seconds: 6 h (30 s under `test-windows`). It stays
/// below every attest window open_escrow accepts, so a reveal on the grace's last second still
/// leaves the regraders time to vote before attest_deadline.
#[constant]
pub const MAX_REVEAL_GRACE: i64 = if cfg!(feature = "test-windows") {
    30
} else {
    6 * HOUR
};

const _: () = assert!(
    MAX_REVEAL_GRACE < MIN_ATTEST_WINDOW,
    "a reveal on the grace's last second leaves time to attest"
);

/// The most mints Config.mints allows.
pub const MAX_MINTS: usize = 4;

/// The most sponsors Config.sponsors allows (room for every sponsor of the competitions running at
/// once; one removed after its open leaves its escrow as it is).
pub const MAX_SPONSORS: usize = 32;

/// The most keys the regrader registry (Config.regraders) holds.
pub const MAX_REGISTRY: usize = 16;

/// The most keys Config.revoked holds.
pub const MAX_REVOKED: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reveal_grace_bounds_follow_the_test_windows_feature() {
        if cfg!(feature = "test-windows") {
            assert_eq!((MIN_REVEAL_GRACE, MAX_REVEAL_GRACE), (5, 30));
        } else {
            assert_eq!((MIN_REVEAL_GRACE, MAX_REVEAL_GRACE), (5 * 60, 6 * HOUR));
        }
        assert_eq!(STOP_DURATION, 7 * 24 * HOUR);
    }

    #[test]
    fn minimum_windows_follow_the_test_windows_feature() {
        let windows = [
            MIN_CHALLENGE_WINDOW,
            MIN_ATTEST_WINDOW,
            MIN_HOLD_WINDOW,
            MIN_CLAIM_WINDOW,
        ];
        if cfg!(feature = "test-windows") {
            assert_eq!(windows, [60, 60, 60, 90]);
        } else {
            assert_eq!(windows, [72 * HOUR, 48 * HOUR, 72 * HOUR, 7 * 24 * HOUR]);
        }
    }
}
