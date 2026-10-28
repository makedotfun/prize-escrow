//! config.rs: the claim flow bucket, Config::refill and Config::take_flow (claim.rs takes each
//! payout from it at wall time), on a Config whose bucket fields are symbolic.

use {crate::zeroed, prize_escrow::Config};

fn bucket(capacity: u64, period: i64, level: u64, updated_at: i64) -> Config {
    let mut config: Config = zeroed();
    config.flow_capacity = capacity;
    config.flow_period = period;
    config.flow_level = level;
    config.flow_updated_at = updated_at;
    config
}

/// At full width (any capacity, any period, Limits' 1..=MAX_WINDOW or not, any level up to the
/// capacity, any two wall times): a refill never fails (so the bucket never refuses a claim with
/// MathOverflow), never empties or overfills the bucket, never moves flow_updated_at back, and a
/// clock behind flow_updated_at (Solana's stake-weighted clock may read earlier) adds nothing
/// (#536's concern: refill(900) after a drain at 1000, then refill(1000), filled the bucket).
#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn a_refill_never_fails_overfills_or_runs_backward() {
    let (capacity, level): (u64, u64) = kani::any();
    kani::assume(level <= capacity);
    let (period, updated_at, now): (i64, i64, i64) = kani::any();
    let mut config = bucket(capacity, period, level, updated_at);
    assert!(config.refill(now).is_ok());
    kani::cover!(config.flow_level > level, "a refill credits");
    assert!(level <= config.flow_level && config.flow_level <= capacity);
    assert_eq!(config.flow_updated_at, updated_at.max(now));
    if now <= updated_at {
        assert_eq!(config.flow_level, level);
    }
}

/// At full width: take_flow pays exactly what the refilled bucket holds. After a refill to `now`,
/// a take at the same instant succeeds exactly when it is at most the level, and leaves the level
/// less the take; a refused take changes nothing.
#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn a_take_pays_exactly_what_the_bucket_holds() {
    let (capacity, level, want): (u64, u64, u64) = kani::any();
    kani::assume(level <= capacity);
    let (period, updated_at, now): (i64, i64, i64) = kani::any();
    let mut config = bucket(capacity, period, level, updated_at);
    assert!(config.refill(now).is_ok());
    let (held, at) = (config.flow_level, config.flow_updated_at);
    let paid = config.take_flow(want, now).is_ok();
    kani::cover!(paid, "a take is paid");
    kani::cover!(!paid, "a take is refused");
    assert_eq!(paid, want <= held);
    assert_eq!(config.flow_level, if paid { held - want } else { held });
    assert_eq!(config.flow_updated_at, at);
}

// Not proven here: the rate bound over a run of claims (the bucket pays at most its capacity
// plus capacity per period of the time elapsed, and two refills credit no more than one over the
// same span). Both turn on refill's floor division, capacity * elapsed / period in u128, and the
// solver has to relate two such divisions through their 128-bit multiply and divide circuits:
// CaDiCaL ran past 20 minutes on each with capacity, period, level and wall times all bytes
// (2026-10-28), and CBMC's SMT backend (z3) aborted on the program ("map::at").
// tests/properties.rs keeps both under proptest (the_bucket_pays_at_most_its_capacity_and_its_rate,
// a_refill_never_overfills_or_runs_backward); the proofs above cover what they need of refill and
// take_flow at full width.
