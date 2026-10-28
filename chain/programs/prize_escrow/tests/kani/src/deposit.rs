//! open_escrow.rs: check_deposit, the vault measurement open_escrow and fund make after their
//! transfer (compiled into this crate from the program's source, where it is pub(crate)).

use {crate::open_escrow_src::check_deposit, anchor_lang::error::Error, prize_escrow::EscrowError};

fn code(result: anchor_lang::Result<()>) -> Option<u32> {
    match result {
        Ok(()) => None,
        Err(Error::AnchorError(e)) => Some(e.error_code_number),
        Err(Error::ProgramError(_)) => Some(u32::MAX),
    }
}

/// For every vault balance before and after and every amount (all of u64): check_deposit passes
/// exactly when the vault grew by the amount, is Underfunded when it shrank or grew by less, and
/// Overfunded when it grew by more. No balance pair wraps it into a pass.
#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn check_deposit_passes_exactly_the_amount() {
    let (before, after, amount): (u64, u64, u64) = kani::any();
    let want = if after < before || after - before < amount {
        Some(u32::from(EscrowError::Underfunded))
    } else if after - before > amount {
        Some(u32::from(EscrowError::Overfunded))
    } else {
        None
    };
    kani::cover!(want.is_none(), "an exact deposit");
    kani::cover!(
        want == Some(u32::from(EscrowError::Underfunded)),
        "an underfunded deposit"
    );
    kani::cover!(
        want == Some(u32::from(EscrowError::Overfunded)),
        "an overfunded deposit"
    );
    assert_eq!(code(check_deposit(before, after, amount)), want);
}
