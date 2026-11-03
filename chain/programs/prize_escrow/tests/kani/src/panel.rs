//! config.rs: Config::min_regraders, the panel floor check_terms_policy holds every escrow to
//! (PanelTooSmall), and Config::set_min_regraders, which the admin raises it with.

use {
    crate::{code, escrow_error, zeroed},
    anchor_lang::prelude::Pubkey,
    prize_escrow::{Config, EscrowError, EscrowTerms, RegraderEntry, MAX_REGRADERS},
};

fn key(byte: u8) -> Pubkey {
    Pubkey::new_from_array([byte; 32])
}

/// For every floor (all of u8), a panel of LEN regraders (all registered, or its last one outside
/// the registry), each of them the house's or not, and every house allowance (all of u8), on terms
/// that pass every check before the panel's: check_terms_policy (open_escrow's call, the sponsor
/// allowlist held) refuses PanelTooSmall exactly when LEN is below the floor, and otherwise
/// answers as it would with no floor at all: the
/// registry's RegraderNotRegistered, the allowance's TooManyHouseRegraders, or Ok. So floor 0,
/// what a Config written before min_regraders reads in its first reserved byte, refuses no panel,
/// not even an empty one, and refuses the same panels as floor 1 among the 1 to MAX_REGRADERS
/// that EscrowTerms::validate lets through: none. Returns whether the panel, at a floor it
/// meets, was refused for another reason (what an empty panel never is).
///
/// What keeps it in CBMC's reach: every key and the panel's length are concrete (one harness per
/// length, below), so each slice loop stops where its Vec ends, and one policy call per harness;
/// the revoked list is empty, because the policy's revocation loop
/// ([sponsor, resolver, compliance].chain(regraders)) is one CBMC cannot bound by its length, and
/// with a revoked key it unrolled to the unwind bound with a 32-byte memcmp in every pass (2.4
/// million assignments on an empty panel; over every length at once, past 6 GB). Pubkey's
/// PartialEq cannot be stubbed loop-free: Kani 0.68 resolves `core::cmp::PartialEq` in a stub path
/// to the derive macro.
fn the_floor_refuses_exactly_the_panels_below_it<const LEN: usize>() -> bool {
    let (sponsor, mint, escrow, resolver, compliance, arbiter) =
        (key(1), key(2), key(3), key(4), key(5), key(6));
    // MAX_REGRADERS distinct keys, none of them one of the six above, and one more outside the
    // registry.
    let panel: [Pubkey; MAX_REGRADERS as usize] = core::array::from_fn(|i| key(11 + i as u8));
    let outsider = key(30);

    let houses: [bool; MAX_REGRADERS as usize] = kani::any();
    let (floor, allowance): (u8, u8) = kani::any();
    let mut config: Config = zeroed();
    config.mints = vec![mint];
    config.sponsors = vec![sponsor];
    config.arbiter = arbiter;
    config.max_house_regraders = allowance;
    config.regraders = panel
        .iter()
        .zip(houses)
        .map(|(&key, house)| RegraderEntry { key, house })
        .collect();
    config.min_regraders = floor;

    let mut terms: EscrowTerms = zeroed();
    terms.refund_to = sponsor;
    terms.arbiter = arbiter;
    terms.resolver = resolver;
    terms.compliance = compliance;
    terms.regraders = panel[..LEN].to_vec();
    let unregistered = LEN > 0 && kani::any();
    if unregistered {
        terms.regraders[LEN - 1] = outsider;
    }

    // The policy past the panel's floor, on these terms: the registry, then the allowance
    // (resolver and compliance are none of the panel's, and nothing is revoked).
    let house = houses[..LEN].iter().filter(|&&h| h).count();
    let unfloored = if unregistered {
        escrow_error(EscrowError::RegraderNotRegistered)
    } else if house > usize::from(allowance) {
        escrow_error(EscrowError::TooManyHouseRegraders)
    } else {
        None
    };
    let below = LEN < usize::from(floor);
    let want = if below {
        escrow_error(EscrowError::PanelTooSmall)
    } else {
        unfloored
    };
    let got = code(&config.check_terms_policy(&sponsor, &mint, &escrow, &terms, true));
    assert_eq!(got, want);

    kani::cover!(below, "a panel under the floor is refused");
    kani::cover!(floor == 0 && got.is_none(), "floor 0 lets the panel open");
    kani::cover!(
        usize::from(floor) == LEN && got.is_none(),
        "a panel at the floor opens"
    );
    !below && got.is_some()
}

#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn the_floor_refuses_exactly_the_panels_below_it_of_0() {
    the_floor_refuses_exactly_the_panels_below_it::<0>();
}

#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn the_floor_refuses_exactly_the_panels_below_it_of_1() {
    let other = the_floor_refuses_exactly_the_panels_below_it::<1>();
    kani::cover!(other, "a panel the floor allows is refused for another reason");
}

#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn the_floor_refuses_exactly_the_panels_below_it_of_2() {
    let other = the_floor_refuses_exactly_the_panels_below_it::<2>();
    kani::cover!(other, "a panel the floor allows is refused for another reason");
}

#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn the_floor_refuses_exactly_the_panels_below_it_of_3() {
    let other = the_floor_refuses_exactly_the_panels_below_it::<3>();
    kani::cover!(other, "a panel the floor allows is refused for another reason");
}

#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn the_floor_refuses_exactly_the_panels_below_it_of_4() {
    let other = the_floor_refuses_exactly_the_panels_below_it::<4>();
    kani::cover!(other, "a panel the floor allows is refused for another reason");
}

#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn the_floor_refuses_exactly_the_panels_below_it_of_5() {
    let other = the_floor_refuses_exactly_the_panels_below_it::<5>();
    kani::cover!(other, "a panel the floor allows is refused for another reason");
}

/// For every floor written and every floor in force (all of u8): set_min_regraders writes the
/// floor exactly when it is 1 to MAX_REGRADERS, and refuses any other with InvalidConfig, the floor
/// in force unchanged. So no admin writes floor 0 (only a Config from before the field reads it),
/// nor one past a full panel, which would refuse every escrow (EscrowTerms::validate caps a panel
/// at MAX_REGRADERS).
#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn set_min_regraders_writes_only_a_floor_a_panel_can_meet() {
    let mut config: Config = zeroed();
    let (was, want): (u8, u8) = kani::any();
    config.min_regraders = was;
    let written = config.set_min_regraders(want);
    if (1..=MAX_REGRADERS).contains(&want) {
        kani::cover!(want != was, "a floor written");
        assert!(written.is_ok());
        assert_eq!(config.min_regraders, want);
    } else {
        kani::cover!(want == 0, "floor 0 refused");
        kani::cover!(want > MAX_REGRADERS, "a floor past a full panel refused");
        assert_eq!(code(&written), escrow_error(EscrowError::InvalidConfig));
        assert_eq!(config.min_regraders, was);
    }
}
