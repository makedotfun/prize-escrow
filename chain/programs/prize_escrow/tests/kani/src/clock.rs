//! config.rs and state.rs: escrow_now and what it reads (Config::global_stopped, global_now,
//! stop_level; Escrow::frozen_secs_at, is_frozen), the stop breaker (Config::set_stop, as
//! handle_set_stop and handle_extend_stop call it) and the escrow's freeze (start_freeze,
//! end_freeze, extend_freeze's lapse), on a Config and an Escrow whose every clock field is
//! symbolic. No other field is read by these functions.

use {
    crate::zeroed,
    prize_escrow::{escrow_now, Config, Escrow, StopState, MAX_WINDOW, STOP_DURATION},
};

/// Any instant or span of the proofs that need a range: 0 to u32::MAX s (the year 2106, and
/// durations up to 136 years). Every sum the clocks form then stays far inside an i64, so no
/// saturating operation saturates; the upper half of each i64 is zero, which keeps the solver's
/// adders 33 bits wide (at 64 bits, two-instant properties ran past 15 minutes).
fn instant() -> i64 {
    i64::from(kani::any::<u32>())
}

fn level() -> StopState {
    match kani::any::<u8>() {
        0 => StopState::Normal,
        1 => StopState::IntakeStop,
        _ => StopState::PayoutStop,
    }
}

/// A Config and an Escrow with every clock field symbolic: an instant() when `in_span`, any i64
/// otherwise. The fields need not be consistent with each other (a stop that lapses before it was
/// set, a freeze on record that ended before it began): the proofs hold for those too.
fn clocks(in_span: bool) -> (Config, Escrow) {
    let t = || if in_span { instant() } else { kani::any() };
    let mut config: Config = zeroed();
    config.stop = level();
    config.stop_since = t();
    config.stop_expires_at = t();
    config.stopped_secs = t();
    let mut escrow: Escrow = zeroed();
    escrow.stop_base = t();
    escrow.freeze_since = t();
    escrow.freeze_until = t();
    escrow.frozen_secs = t();
    (config, escrow)
}

/// No Config, Escrow or wall time, however corrupt, makes a clock panic or overflow: every
/// instruction reads escrow_now first, so a panic there would brick the escrow.
#[kani::proof]
#[kani::unwind(70)]
fn the_clocks_never_overflow() {
    let (config, escrow) = clocks(false);
    let now: i64 = kani::any();
    let global = config.global_now(now);
    let _ = (config.stop_level(now), escrow.is_frozen(global));
    let _ = escrow_now(&escrow, &config, now);
    kani::cover!(true, "every clock was read");
}

// The escrow clock never runs backward, nor faster than wall time: deadlines on it never come
// closer than in wall time, and a stop and a freeze in force together hold it once (counted
// twice, it would run backward). Proven in three steps, the next three harnesses, because in one
// (both clocks between two instants) CaDiCaL ran past 25 minutes: the global clock never runs
// backward or faster than wall time; the escrow's own layer over it (the global clock less the
// escrow's frozen seconds) never runs backward or faster than the global clock; and escrow_now
// is exactly that layer over the global clock. Both properties survive composition.

/// Wall time running forward never runs the global clock backward, nor faster than itself.
#[kani::proof]
#[kani::unwind(70)]
fn the_global_clock_never_runs_backward_or_faster_than_wall_time() {
    let (config, _) = clocks(true);
    let (t1, t2) = (instant(), instant());
    kani::assume(t1 <= t2);
    kani::cover!(
        t1 < t2 && config.stop == StopState::PayoutStop,
        "time passes with a PayoutStop on record"
    );
    let (g1, g2) = (config.global_now(t1), config.global_now(t2));
    assert!(g1 <= g2 && g2 - g1 <= t2 - t1);
}

/// Any global clock reading: global_now(t) for an instant() t lies in [-2^33, 2^32] (t less up to
/// two u32 spans of stopped seconds).
fn global_instant() -> i64 {
    i64::from(kani::any::<u32>()) - 2 * i64::from(kani::any::<u32>())
}

/// The escrow's own layer over the global clock, as escrow_now applies it at global clock `global`.
fn escrow_layer(escrow: &Escrow, global: i64) -> i64 {
    global
        .saturating_add(escrow.stop_base)
        .saturating_sub(escrow.frozen_secs_at(global))
}

/// The global clock running forward never runs the escrow's layer over it backward, nor faster
/// than itself, whatever freeze is on record.
#[kani::proof]
#[kani::unwind(70)]
fn the_escrow_clock_never_runs_backward_or_faster_than_the_global_clock() {
    let (_, escrow) = clocks(true);
    let (g1, g2) = (global_instant(), global_instant());
    kani::assume(g1 <= g2);
    kani::cover!(
        g1 < g2 && escrow.freeze_until != 0,
        "global time passes with a freeze on record"
    );
    let (e1, e2) = (escrow_layer(&escrow, g1), escrow_layer(&escrow, g2));
    assert!(e1 <= e2 && e2 - e1 <= g2 - g1);
}

/// escrow_now is the escrow's layer over the global clock, at every instant, so the two harnesses
/// above compose into escrow_now's: never backward, never faster than wall time.
#[kani::proof]
#[kani::unwind(70)]
fn escrow_now_is_the_escrow_layer_over_the_global_clock() {
    let (config, escrow) = clocks(true);
    let now = instant();
    let global = config.global_now(now);
    kani::cover!(
        global < now && escrow.freeze_until != 0,
        "a stopped global clock and a freeze on record"
    );
    assert!((-(1i64 << 33)..=1i64 << 32).contains(&global));
    assert_eq!(
        escrow_now(&escrow, &config, now),
        escrow_layer(&escrow, global)
    );
}

/// A PayoutStop in force holds the global clock and every escrow's clock still.
#[kani::proof]
#[kani::unwind(70)]
fn a_payout_stop_holds_every_clock() {
    let (mut config, escrow) = clocks(true);
    config.stop = StopState::PayoutStop;
    let (t1, t2) = (instant(), instant());
    kani::assume(config.stop_since <= t1 && t1 <= t2 && t2 <= config.stop_expires_at);
    kani::cover!(t1 < t2, "time passes under the stop");
    assert_eq!(config.global_now(t1), config.global_now(t2));
    assert_eq!(
        escrow_now(&escrow, &config, t1),
        escrow_now(&escrow, &config, t2)
    );
}

/// A freeze in force holds its escrow's clock still, whatever the global clock does.
#[kani::proof]
#[kani::unwind(70)]
fn a_freeze_holds_its_escrow_clock() {
    let (config, escrow) = clocks(true);
    let (t1, t2) = (instant(), instant());
    kani::assume(t1 <= t2);
    let (g1, g2) = (config.global_now(t1), config.global_now(t2));
    kani::assume(escrow.freeze_until != 0);
    kani::assume(escrow.freeze_since <= g1 && g2 <= escrow.freeze_until);
    kani::cover!(g1 < g2, "global time passes under the freeze");
    assert_eq!(
        escrow_now(&escrow, &config, t1),
        escrow_now(&escrow, &config, t2)
    );
}

/// With no PayoutStop over [t1, t2) the global clock runs at wall speed, and with no freeze over
/// its span either, so does the escrow clock: nothing else slows a deadline.
#[kani::proof]
#[kani::unwind(70)]
fn with_no_stop_or_freeze_in_force_the_clocks_run_at_wall_speed() {
    let (config, escrow) = clocks(true);
    let (t1, t2) = (instant(), instant());
    kani::assume(t1 <= t2);
    let (since, lapse) = (config.stop_since, config.stop_expires_at);
    kani::assume(
        config.stop != StopState::PayoutStop || lapse <= since || lapse <= t1 || t2 <= since,
    );
    let (g1, g2) = (config.global_now(t1), config.global_now(t2));
    assert_eq!(g2 - g1, t2 - t1);
    let (since, until) = (escrow.freeze_since, escrow.freeze_until);
    kani::assume(until == 0 || until <= since || until <= g1 || g2 <= since);
    kani::cover!(t1 < t2, "time passes with nothing in force");
    assert_eq!(
        escrow_now(&escrow, &config, t2) - escrow_now(&escrow, &config, t1),
        t2 - t1
    );
}

/// No breaker moves a clock at the instant it lands (it changes only how the clocks run from
/// then on): set_stop at any level (an escalation or not), extend_stop on a stop in force,
/// set_freeze on and off, and extend_freeze, each behind its handler's guard (breakers.rs).
#[kani::proof]
#[kani::use_stub_set(crate::quiet_errors)]
#[kani::unwind(70)]
fn a_breaker_moves_no_clock_at_the_instant_it_lands() {
    let (mut config, mut escrow) = clocks(true);
    let now = instant();
    let global = config.global_now(now);
    let clock = escrow_now(&escrow, &config, now);
    // What extension() lets extend_stop and extend_freeze add.
    let extra = instant();
    kani::assume((1..=MAX_WINDOW).contains(&extra));
    match kani::any::<u8>() {
        0 => {
            config.set_stop(level(), now, kani::any());
            kani::cover!(true, "set_stop");
        }
        1 => {
            kani::assume(config.stop_level(now) != StopState::Normal);
            config.stop_expires_at += extra;
            kani::cover!(true, "extend_stop");
        }
        2 => {
            kani::assume(!escrow.is_frozen(global));
            assert!(escrow.start_freeze(global, STOP_DURATION).is_ok());
            kani::cover!(true, "set_freeze on");
        }
        3 => {
            kani::assume(escrow.is_frozen(global));
            escrow.end_freeze(global);
            kani::cover!(true, "set_freeze off");
        }
        _ => {
            kani::assume(escrow.is_frozen(global));
            escrow.freeze_until += extra;
            kani::cover!(true, "extend_freeze");
        }
    }
    assert_eq!(config.global_now(now), global);
    assert_eq!(escrow_now(&escrow, &config, now), clock);
}

/// set_stop as handle_set_stop calls it (an escalation keeps a later lapse): a stop set holds
/// from now until its lapse, at least STOP_DURATION away, and then lapses to Normal; an escalation
/// of a stop in force never brings its lapse closer (#535's finding 2), and anything else lasts
/// exactly STOP_DURATION; a PayoutStop holds the global clock from now to its lapse and no
/// longer; lifting the stop (Normal) holds nothing from now on and keeps every second already
/// held.
#[kani::proof]
#[kani::unwind(70)]
fn a_stop_holds_until_its_lapse_and_an_escalation_never_shortens_it() {
    let (mut config, _) = clocks(true);
    let now = instant();
    let from = config.stop_level(now);
    let (lapse, held) = (config.stop_expires_at, config.global_stopped(now));
    let level = level();
    let escalation = level > from;
    config.set_stop(level, now, escalation);
    let until = config.stop_expires_at;
    let t = instant();
    kani::assume(t >= now);
    if level == StopState::Normal {
        assert_eq!(config.stop_level(t), StopState::Normal);
        assert_eq!(config.global_stopped(t), held);
    } else {
        assert!(until >= now + STOP_DURATION);
        if escalation && from != StopState::Normal {
            kani::cover!(
                lapse > now + STOP_DURATION,
                "an escalation keeps a later lapse"
            );
            assert!(until >= lapse);
            assert_eq!(until, (now + STOP_DURATION).max(lapse));
        } else {
            assert_eq!(until, now + STOP_DURATION);
        }
        let want = if t < until { level } else { StopState::Normal };
        assert_eq!(config.stop_level(t), want);
        let running = if level == StopState::PayoutStop {
            t.min(until) - now
        } else {
            0
        };
        assert_eq!(config.global_stopped(t), held + running);
    }
}
