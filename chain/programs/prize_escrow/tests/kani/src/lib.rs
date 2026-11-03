//! Kani proofs of prize_escrow's pure functions, the bounded-model-checking half of
//! tests/properties.rs (whose proptest properties sample the same functions):
//!
//! - merkle.rs: compute_leaf_hash, hash_pair and verify_proof, under the keccak oracle;
//! - commitment.rs: result_commitment and commit_hash, under the sha256 oracle;
//! - clock.rs: escrow_now and the global clock, the stop breaker and its escalation, the freeze;
//! - bucket.rs: the claim flow bucket, Config::refill and take_flow;
//! - deposit.rs: open_escrow.rs's check_deposit;
//! - bonds.rs: Escrow::bonds_to_winner and tracked_bonds, settle.rs's unbonded_floor and pay_bond
//!   (the floor every bond payout keeps);
//! - window.rs: Escrow::challenge_window_over (escalate's UnchallengedResultBinds) against
//!   settle.rs's require_window_over;
//! - panel.rs: Config::min_regraders, check_terms_policy's PanelTooSmall and set_min_regraders;
//! - alternative.rs: Escrow::record_alternative and clear_alternative (arbiter_resolve keeping the
//!   posted result).
//!
//! oracle.rs is the hash model: what the hashing proofs assume of keccak256 and sha256 (no
//! collision among the inputs a harness queries) and nothing more.
//!
//! Run them in Docker (the host never gets Kani's toolchain): `node run.mjs` in this directory
//! builds the image (Dockerfile) and verifies every harness, logs under the worktree's
//! .tmp/kani/. Nothing here builds outside `cargo kani`, which sets cfg(kani).

#[cfg(kani)]
mod alternative;
#[cfg(kani)]
mod bonds;
#[cfg(kani)]
mod bucket;
#[cfg(kani)]
mod clock;
#[cfg(kani)]
mod commitment;
#[cfg(kani)]
mod deposit;
#[cfg(kani)]
mod merkle;
#[cfg(kani)]
mod oracle;
#[cfg(kani)]
mod panel;
#[cfg(kani)]
mod window;

// open_escrow.rs reaches the program's modules, its ID and its event authority through `crate::`.
#[cfg(kani)]
#[allow(unused_imports)]
use prize_escrow::{config, constants, error, events, state, EVENT_AUTHORITY_AND_BUMP, ID};

/// The program's open_escrow.rs, compiled into this crate for its pub(crate) check_deposit.
#[cfg(kani)]
#[allow(dead_code, unused_imports)]
#[path = "../../../src/instructions/open_escrow.rs"]
mod open_escrow_src;

/// The program's settle.rs, compiled into this crate for its pub(crate) unbonded_floor and pay_bond
/// and its private require_window_over: include! rather than #[path], so this module's own item
/// can name require_window_over, the program's text unchanged.
#[cfg(kani)]
#[allow(dead_code, unused_imports)]
mod settle_src {
    include!("../../../src/instructions/settle.rs");

    /// settle.rs's require_window_over, as handle_settle calls it, under a name the harnesses
    /// reach.
    pub(crate) fn settle_requires_window_over(escrow: &Escrow, now: i64) -> Result<()> {
        require_window_over(escrow, now)
    }
}

/// Stands in for `EscrowError::name` (#[kani::stub]): the proofs compare error codes, never
/// names, and formatting a name is most of the code a symbolic path through an error would walk
/// (a harness that only reached start_freeze's MathOverflow ran out of memory in core::fmt).
#[cfg(kani)]
#[allow(dead_code, reason = "only #[kani::stub] reaches it")]
fn no_name(_: &prize_escrow::EscrowError) -> String {
    String::new()
}

/// Stands in for EscrowError's `Display::fmt` (#[kani::stub]), which `to_string()` calls for
/// AnchorError.error_msg: as no_name.
#[cfg(kani)]
#[allow(dead_code, reason = "only #[kani::stub] reaches it")]
fn no_message(
    _: &prize_escrow::EscrowError,
    _: &mut core::fmt::Formatter<'_>,
) -> core::fmt::Result {
    Ok(())
}

// What a harness that reaches the program's errors uses: their codes stay, their texts go.
#[cfg(kani)]
kani::stub_set!(
    pub quiet_errors,
    stub(prize_escrow::EscrowError::name, crate::no_name),
    stub(<prize_escrow::EscrowError as core::fmt::Display>::fmt, crate::no_message),
);

/// An account of type `T` with every byte zero (a fresh `init` account's data, past the
/// discriminator), decoded as the program decodes it. The harnesses then set only the fields they
/// reason about, so a field added to Config or Escrow later decodes as zero here and changes
/// nothing they prove.
#[cfg(kani)]
fn zeroed<T: anchor_lang::AnchorDeserialize>() -> T {
    const ZEROS: [u8; 2048] = [0; 2048];
    T::deserialize(&mut &ZEROS[..]).expect("an all-zero account decodes")
}

/// The error code a result carries: None for Ok, u32::MAX for a ProgramError.
#[cfg(kani)]
fn code<T>(result: &anchor_lang::Result<T>) -> Option<u32> {
    match result {
        Ok(_) => None,
        Err(anchor_lang::error::Error::AnchorError(e)) => Some(e.error_code_number),
        Err(anchor_lang::error::Error::ProgramError(_)) => Some(u32::MAX),
    }
}

/// The code of an EscrowError.
#[cfg(kani)]
fn escrow_error(e: prize_escrow::EscrowError) -> Option<u32> {
    Some(u32::from(e))
}
