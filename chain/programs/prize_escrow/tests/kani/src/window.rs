//! state.rs: Escrow::challenge_window_over, which handle_escalate refuses a Challengeable escrow
//! by once it holds (UnchallengedResultBinds), against settle.rs's require_window_over, which
//! handle_settle waits for, on an Escrow whose window fields (challenge_deadline, reveal_grace,
//! pending_commits) are symbolic at full width. Nothing else is read by either.

use {
    crate::{code, escrow_error, settle_src::settle_requires_window_over, zeroed},
    prize_escrow::{Escrow, EscrowError},
};

fn window() -> Escrow {
    let mut escrow: Escrow = zeroed();
    escrow.challenge_deadline = kani::any();
    escrow.reveal_grace = kani::any();
    escrow.pending_commits = kani::any();
    escrow
}

/// At every escrow clock reading, every challenge_deadline and reveal_grace (all of i64) and every
/// count of pending commits (all of u32): the window escalate reads is over exactly when settle's
/// is, at or past challenge_deadline and, while a commit is pending, past the reveal grace's end
/// too. So no instant lets the guardian escalate an unchallenged result that settle could make
/// Claimable, and none leaves an unsettleable result that escalate refuses: settle refuses with
/// DeadlineNotReached before the deadline and CommitsPendingReveal inside the grace, exactly where
/// escalate may still act. Both refuse with MathOverflow, together, only where the grace's end is
/// past i64 (open_escrow's MAX_WINDOW and MAX_REVEAL_GRACE keep every escrow far inside it).
#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn the_window_is_over_for_escalate_exactly_when_settle_may_settle() {
    let escrow = window();
    let now: i64 = kani::any();
    let over = escrow.challenge_window_over(now);
    let settles = settle_requires_window_over(&escrow, now);

    let (deadline, pending) = (escrow.challenge_deadline, escrow.pending_commits > 0);
    // What both should read, at full width: None where the grace's end overflows.
    let want = if now < deadline {
        Some(false)
    } else if !pending {
        Some(true)
    } else {
        deadline
            .checked_add(escrow.reveal_grace)
            .map(|grace_end| now >= grace_end)
    };
    match want {
        Some(true) => {
            kani::cover!(!pending, "over, with no commit pending");
            kani::cover!(pending, "over, past the reveal grace");
            assert!(matches!(over, Ok(true)));
            assert!(settles.is_ok());
        }
        Some(false) => {
            kani::cover!(now < deadline, "before the deadline");
            kani::cover!(now >= deadline, "inside the reveal grace");
            assert!(matches!(over, Ok(false)));
            let refusal = if now < deadline {
                EscrowError::DeadlineNotReached
            } else {
                EscrowError::CommitsPendingReveal
            };
            assert_eq!(code(&settles), escrow_error(refusal));
        }
        None => {
            kani::cover!(true, "the grace's end overflows");
            assert_eq!(code(&over), escrow_error(EscrowError::MathOverflow));
            assert_eq!(code(&settles), escrow_error(EscrowError::MathOverflow));
        }
    }
}

/// A window once over stays over: at a later escrow clock reading (the escrow clock never runs
/// backward, clock.rs), with no more commits pending than before (challenge_commit lands only
/// before challenge_deadline, so once the window is over a reveal or close_commit only lowers the
/// count), challenge_window_over still holds. An unchallenged result that bound never becomes
/// escalatable again.
#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn a_window_once_over_stays_over() {
    let mut escrow = window();
    let (t1, t2): (i64, i64) = kani::any();
    kani::assume(t1 <= t2);
    let was_over = matches!(escrow.challenge_window_over(t1), Ok(true));
    let before = escrow.pending_commits;
    escrow.pending_commits = kani::any();
    kani::assume(escrow.pending_commits <= before);
    kani::cover!(
        was_over && before > 0 && t1 < t2,
        "time passes past the grace with a commit pending"
    );
    if was_over {
        assert!(matches!(escrow.challenge_window_over(t2), Ok(true)));
    }
}
