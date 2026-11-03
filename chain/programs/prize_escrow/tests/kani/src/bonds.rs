//! state.rs: Escrow::bonds_to_winner, what settle and arbiter_resolve pay the bonds by, and
//! Escrow::tracked_bonds; settle.rs: unbonded_floor and pay_bond, the floor every bond payout
//! keeps (settle, arbiter_resolve, refund, close_commit and close_challenge read it once and pay
//! against it), on AccountInfos whose balances are symbolic at full width.

use {
    crate::{
        code, escrow_error,
        settle_src::{pay_bond, unbonded_floor},
        zeroed,
    },
    anchor_lang::{
        error::Error,
        prelude::{AccountInfo, Pubkey},
    },
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

/// An escrow whose three tracked bonds (resolver_bond, challenger_bond, commit_bond) are any u64,
/// every other field zero: nothing else is read by tracked_bonds or unbonded_floor.
fn bonded() -> Escrow {
    let mut escrow: Escrow = zeroed();
    escrow.resolver_bond = kani::any();
    escrow.challenger_bond = kani::any();
    escrow.commit_bond = kani::any();
    escrow
}

/// The three bonds' sum, wide enough that it never wraps.
fn tracked(escrow: &Escrow) -> u128 {
    u128::from(escrow.resolver_bond)
        + u128::from(escrow.challenger_bond)
        + u128::from(escrow.commit_bond)
}

/// For every balance and every three bonds (all of u64): tracked_bonds is the bonds' sum, and the
/// floor unbonded_floor reads is the balance less that sum, exactly. So it never exceeds what the
/// account holds beyond its bonds (no payout against it can reach a tracked bond's lamports and
/// stop short of the rent, nor take rent as a bond), and it never underflows or wraps: an account
/// holding less than it tracks, or bonds past u64, read as MathOverflow (an accounting fault that
/// refuses every payout), never as a floor.
#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn the_floor_is_the_balance_less_every_tracked_bond() {
    let escrow = bonded();
    let balance: u64 = kani::any();
    let (key, owner) = (Pubkey::new_from_array([1; 32]), prize_escrow::ID);
    let (mut lamports, mut data) = (balance, [0u8; 0]);
    let info = AccountInfo::new(&key, false, true, &mut lamports, &mut data, &owner, false);

    let all = tracked(&escrow);
    let sum = escrow.tracked_bonds();
    if all <= u128::from(u64::MAX) {
        assert!(sum.is_ok_and(|s| u128::from(s) == all));
    } else {
        kani::cover!(true, "the bonds overflow u64");
        assert_eq!(code(&sum), escrow_error(EscrowError::MathOverflow));
    }

    let floor = unbonded_floor(&info, &escrow);
    match floor {
        Ok(floor) => {
            kani::cover!(all > 0, "a floor under bonds");
            assert!(all <= u128::from(balance));
            assert_eq!(u128::from(floor) + all, u128::from(balance));
        }
        Err(_) => {
            kani::cover!(
                all <= u128::from(u64::MAX),
                "an account holding less than it tracks"
            );
            assert!(all > u128::from(balance));
            assert_eq!(code(&floor), escrow_error(EscrowError::MathOverflow));
        }
    }
    // unbonded_floor only reads the balance.
    assert_eq!(info.lamports(), balance);
}

/// For every escrow balance, recipient balance, amount and floor (all of u64): pay_bond moves
/// exactly `amount` from the escrow to the recipient, and refuses (MathOverflow) exactly when that
/// would take the escrow below the floor (or below zero) or the recipient past u64; a zero amount
/// moves nothing, whatever the floor. A refusal never credits the recipient, and one for the floor
/// leaves the escrow as it was (one for the recipient's overflow has debited the escrow's
/// in-memory balance already, which the failed instruction's rollback discards).
#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn pay_bond_moves_the_amount_and_never_below_the_floor() {
    let (from, to, amount, floor): (u64, u64, u64, u64) = kani::any();
    let (escrow_key, to_key, owner) = (
        Pubkey::new_from_array([1; 32]),
        Pubkey::new_from_array([2; 32]),
        prize_escrow::ID,
    );
    let (mut escrow_lamports, mut to_lamports) = (from, to);
    let (mut escrow_data, mut to_data) = ([0u8; 0], [0u8; 0]);
    let escrow = AccountInfo::new(
        &escrow_key,
        false,
        true,
        &mut escrow_lamports,
        &mut escrow_data,
        &owner,
        false,
    );
    let recipient = AccountInfo::new(&to_key, false, true, &mut to_lamports, &mut to_data, &owner, false);

    let paid = pay_bond(&escrow, &recipient, amount, floor);
    let above_floor = amount <= from && from - amount >= floor;
    let room = to.checked_add(amount).is_some();
    assert_eq!(paid.is_ok(), amount == 0 || (above_floor && room));
    if paid.is_ok() {
        kani::cover!(amount > 0, "a bond paid");
        kani::cover!(amount == 0 && from < floor, "nothing paid under the floor");
        assert_eq!(escrow.lamports(), from - amount);
        assert!(amount == 0 || escrow.lamports() >= floor);
        assert_eq!(recipient.lamports(), to + amount);
    } else {
        kani::cover!(!above_floor, "refused for the floor");
        kani::cover!(above_floor && !room, "refused for the recipient's balance");
        assert_eq!(code(&paid), escrow_error(EscrowError::MathOverflow));
        assert_eq!(recipient.lamports(), to);
        if !above_floor {
            assert_eq!(escrow.lamports(), from);
        }
    }
}

/// What settle and arbiter_resolve do with the bonds (refund, close_commit and close_challenge pay
/// one the same way): read unbonded_floor once, then pay two amounts out of the escrow in turn,
/// each pay_bond against that one floor. For every balance holding at least the bonds the escrow
/// tracks, every three bonds and any two amounts (all of u64), to two recipients that can take
/// them: the floor reads, and both payments land exactly when together they are at most the
/// tracked bonds, leaving the escrow at the floor plus the tracked bonds not paid. So no run of
/// payouts in one instruction takes the rent (or any lamports sent to the escrow) as a bond, and
/// no tracked bond is ever refused for it: bonds_to_winner's split pays resolver_bond plus
/// challenger_bond, at most what it tracks, and leaves the commits' bonds behind for close_commit.
#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn the_floor_lets_out_exactly_the_tracked_bonds() {
    let escrow = bonded();
    let all = tracked(&escrow);
    let balance: u64 = kani::any();
    kani::assume(all <= u128::from(balance));
    let (first, second): (u64, u64) = kani::any();

    let (escrow_key, owner) = (Pubkey::new_from_array([1; 32]), prize_escrow::ID);
    let (one_key, two_key) = (Pubkey::new_from_array([2; 32]), Pubkey::new_from_array([3; 32]));
    let (mut escrow_lamports, mut one_lamports, mut two_lamports) = (balance, 0u64, 0u64);
    let (mut escrow_data, mut one_data, mut two_data) = ([0u8; 0], [0u8; 0], [0u8; 0]);
    let info = AccountInfo::new(
        &escrow_key,
        false,
        true,
        &mut escrow_lamports,
        &mut escrow_data,
        &owner,
        false,
    );
    let one = AccountInfo::new(&one_key, false, true, &mut one_lamports, &mut one_data, &owner, false);
    let two = AccountInfo::new(&two_key, false, true, &mut two_lamports, &mut two_data, &owner, false);

    let floor = unbonded_floor(&info, &escrow);
    assert!(floor.is_ok());
    let floor = floor.unwrap();
    let both = pay_bond(&info, &one, first, floor).is_ok() && pay_bond(&info, &two, second, floor).is_ok();
    let out = u128::from(first) + u128::from(second);
    assert_eq!(both, out <= all);
    kani::cover!(both && out == all && all > 0, "every tracked bond paid out");
    kani::cover!(!both, "a payout past the tracked bonds refused");
    if both {
        assert_eq!(u128::from(info.lamports()), u128::from(floor) + all - out);
        assert_eq!((one.lamports(), two.lamports()), (first, second));
    }
}
