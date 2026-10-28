//! state.rs: Escrow::bonds_to_winner, what settle and arbiter_resolve pay the bonds by.

use {
    crate::zeroed,
    anchor_lang::error::Error,
    prize_escrow::{ArbiterChoice, Escrow, EscrowError},
};

/// For every pair of bonds held (all of u64): the side that wins takes every bond, its own and the
/// loser's, and the loser nothing; a sum past u64 is MathOverflow for either side, never a
/// wrapped payment.
#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn the_winner_takes_every_bond_or_the_sum_overflows() {
    let mut escrow: Escrow = zeroed();
    escrow.resolver_bond = kani::any();
    escrow.challenger_bond = kani::any();
    let winner = if kani::any() {
        ArbiterChoice::Posted
    } else {
        ArbiterChoice::Alternative
    };
    let paid = escrow.bonds_to_winner(winner);
    match escrow.resolver_bond.checked_add(escrow.challenger_bond) {
        Some(all) => {
            kani::cover!(true, "the bonds add up");
            let want = match winner {
                ArbiterChoice::Posted => (all, 0),
                ArbiterChoice::Alternative => (0, all),
            };
            assert!(paid.is_ok_and(|got| got == want));
        }
        None => {
            kani::cover!(true, "the bonds overflow");
            assert!(matches!(
                paid,
                Err(Error::AnchorError(e))
                    if e.error_code_number == u32::from(EscrowError::MathOverflow)
            ));
        }
    }
}
