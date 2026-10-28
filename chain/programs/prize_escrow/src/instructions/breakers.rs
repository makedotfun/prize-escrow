//! The breakers. The guardian may only escalate: raise the stop (set_stop), freeze one escrow
//! (set_freeze on), hand an undecided escrow to the arbiter (escalate), and revoke a key
//! (set_revoked on). Only the admin lowers or lifts any of them (set_stop down, set_freeze off,
//! set_revoked off), extends a stop or a freeze past its 7 days, or rotates an escrow's key
//! (rotate_role); the admin may use the guardian's verbs too. No breaker stops a program
//! upgrade.
//!
//! Seven days (STOP_DURATION) is the length of one raise, not a ceiling: once a stop or a freeze
//! lapses the guardian may raise it again (a lapsed stop reads as Normal, a lapsed freeze as not
//! frozen), and a stop in force may be raised a level (IntakeStop to PayoutStop) for seven more
//! days, so a guardian key can hold intake, payouts or one escrow indefinitely by renewing. Only
//! the admin ends that: it lifts the stop or the freeze, and it replaces the guardian
//! (set_config_role) or revokes its key (guard_role refuses a revoked guardian: KeyRevoked).

use anchor_lang::prelude::*;

use crate::{
    config::{escrow_now, Config, EscrowRole, StopState},
    constants::{ATTESTATION_SEED, CONFIG_SEED, MAX_REVOKED, MAX_WINDOW, STOP_DURATION},
    error::EscrowError,
    events::{Escalated, FreezeChanged, RevocationChanged, RoleRotated, StopChanged},
    state::{Escrow, EscrowStatus},
};

/// Whether `authority` acts as the admin (true) or as the guardian (false); refuses anyone else
/// (UnauthorizedGuardian) and a revoked guardian (KeyRevoked).
fn guard_role(config: &Config, authority: &Pubkey) -> Result<bool> {
    if *authority == config.admin {
        return Ok(true);
    }
    require!(
        *authority == config.guardian,
        EscrowError::UnauthorizedGuardian
    );
    config.require_not_revoked(authority)?;
    Ok(false)
}

/// A seconds count an extension accepts: 1 to MAX_WINDOW.
fn extension(extra: i64) -> Result<i64> {
    require!(
        (1..=MAX_WINDOW).contains(&extra),
        EscrowError::InvalidConfig
    );
    Ok(extra)
}

// ------------------------------------------------------------------------ the global stop

/// set_stop: the guardian or the admin, on the Config.
#[event_cpi]
#[derive(Accounts)]
pub struct SetStop<'info> {
    pub authority: Signer<'info>,

    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// Sets the breaker level from now, for STOP_DURATION (Normal: for good). The guardian may only
/// raise the level in force (NotAnEscalation: never lower it, never renew one in force); the
/// admin may set any level, Normal (the unstop) included. An escalation, by either, keeps the
/// lapse of the stop in force when that is later (the admin extended it: Config::set_stop), so
/// the guardian can never shorten a stop the admin set or extended. A PayoutStop ended folds its
/// seconds into Config.stopped_secs, so every escrow's clock keeps them. Once a stop lapses the
/// level in force is Normal again, and the guardian may raise a new one: the seven days are per
/// raise (see the module header).
pub fn handle_set_stop(ctx: Context<SetStop>, level: StopState) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let by = ctx.accounts.authority.key();
    let config = &mut ctx.accounts.config;
    let is_admin = guard_role(config, &by)?;
    let from = config.stop_level(now);
    if !is_admin {
        require!(level > from, EscrowError::NotAnEscalation);
    }
    config.set_stop(level, now, level > from);
    emit_cpi!(StopChanged {
        by,
        from,
        stop: config.stop,
        stop_since: config.stop_since,
        stop_expires_at: config.stop_expires_at,
        stopped_secs: config.stopped_secs,
    });
    Ok(())
}

/// extend_stop: the admin, on the Config.
#[event_cpi]
#[derive(Accounts)]
pub struct ExtendStop<'info> {
    #[account(address = config.admin @ EscrowError::UnauthorizedAdmin)]
    pub admin: Signer<'info>,

    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// Moves the lapse of the stop in force `extra` seconds later (NotStopped when none is in force:
/// a lapsed stop is never brought back, which would stop clocks retroactively).
pub fn handle_extend_stop(ctx: Context<ExtendStop>, extra: i64) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let extra = extension(extra)?;
    let config = &mut ctx.accounts.config;
    let level = config.stop_level(now);
    require!(level != StopState::Normal, EscrowError::NotStopped);
    config.stop_expires_at = config
        .stop_expires_at
        .checked_add(extra)
        .ok_or(EscrowError::MathOverflow)?;
    emit_cpi!(StopChanged {
        by: ctx.accounts.admin.key(),
        from: level,
        stop: config.stop,
        stop_since: config.stop_since,
        stop_expires_at: config.stop_expires_at,
        stopped_secs: config.stopped_secs,
    });
    Ok(())
}

// ------------------------------------------------------------------------ one escrow

/// set_freeze, extend_freeze and escalate: the guardian or the admin, on one escrow.
#[event_cpi]
#[derive(Accounts)]
pub struct GuardEscrow<'info> {
    pub authority: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub escrow: Account<'info, Escrow>,
}

/// `frozen`: the guardian (or the admin) freezes the escrow for STOP_DURATION of the global clock
/// (AlreadyFrozen while a freeze is in force): its clock stands still, and claim, refund, settle
/// and arbiter_resolve are refused, until the admin unfreezes it or the freeze lapses. Not
/// `frozen`: only the admin unfreezes (UnauthorizedAdmin for the guardian; NotFrozen with no
/// freeze in force), folding its seconds into the escrow's frozen_secs. Any status but Closed.
/// Once a freeze lapses the guardian may freeze the escrow again: the seven days are per freeze
/// (see the module header).
pub fn handle_set_freeze(ctx: Context<GuardEscrow>, frozen: bool) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let by = ctx.accounts.authority.key();
    let config = &ctx.accounts.config;
    let is_admin = guard_role(config, &by)?;
    let global_now = config.global_now(now);
    let escrow = &mut ctx.accounts.escrow;
    require!(
        escrow.status != EscrowStatus::Closed,
        EscrowError::EscrowClosed
    );
    if frozen {
        require!(!escrow.is_frozen(global_now), EscrowError::AlreadyFrozen);
        escrow.start_freeze(global_now, STOP_DURATION)?;
    } else {
        require!(is_admin, EscrowError::UnauthorizedAdmin);
        require!(escrow.is_frozen(global_now), EscrowError::NotFrozen);
        escrow.end_freeze(global_now);
    }
    emit_cpi!(FreezeChanged {
        escrow: escrow.key(),
        by,
        frozen,
        freeze_since: escrow.freeze_since,
        freeze_until: escrow.freeze_until,
        frozen_secs: escrow.frozen_secs,
        escrow_now: escrow_now(escrow, config, now),
    });
    Ok(())
}

/// The admin moves the lapse of the escrow's freeze in force `extra` seconds (of the global
/// clock) later (UnauthorizedAdmin for the guardian; NotFrozen with none in force).
pub fn handle_extend_freeze(ctx: Context<GuardEscrow>, extra: i64) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let extra = extension(extra)?;
    let by = ctx.accounts.authority.key();
    let config = &ctx.accounts.config;
    require!(guard_role(config, &by)?, EscrowError::UnauthorizedAdmin);
    let global_now = config.global_now(now);
    let escrow = &mut ctx.accounts.escrow;
    require!(escrow.is_frozen(global_now), EscrowError::NotFrozen);
    escrow.freeze_until = escrow
        .freeze_until
        .checked_add(extra)
        .ok_or(EscrowError::MathOverflow)?;
    emit_cpi!(FreezeChanged {
        escrow: escrow.key(),
        by,
        frozen: true,
        freeze_since: escrow.freeze_since,
        freeze_until: escrow.freeze_until,
        frozen_secs: escrow.frozen_secs,
        escrow_now: escrow_now(escrow, config, now),
    });
    Ok(())
}

/// The guardian (or the admin) hands an undecided escrow, Challengeable or Disputed
/// (InvalidStatus otherwise; EscrowClosed when Closed), to the arbiter: it becomes Frozen, as if
/// no quorum had formed, so a house majority cannot settle it. The arbiter then chooses the
/// posted result or a challenge's alternative a regrader voted for, as arbiter_resolve always
/// does, or, if it never does, the escrow refunds after hard_deadline as any Frozen escrow does.
/// Every bond stays held for the side the arbiter picks; commits not yet revealed stay for
/// close_commit.
///
/// A recorded quorum binds from the moment settle may apply it (Escrow::quorum_settles_at, on the
/// escrow clock), and from then on escalate refuses the dispute (QuorumRecorded), so the
/// guardian never turns a decided vote into a Frozen escrow that refunds: k votes for the posted
/// result from challenge_deadline on, a challenge's alternative at k from attest_deadline on
/// (settle applies an overturn only from there). Before that the dispute may still be escalated,
/// whatever the votes: on a panel the house holds a quorum of (owner decision #541), the house's
/// keys can post a false result, self-challenge it and vote it to k within seconds, or overturn
/// an honest result with a challenge revealed in the reveal grace, and the challenge window (for
/// the posted side) and the attest window (for an alternative) are the guardian's time to see it
/// and hand it to the arbiter. A freeze holds the escrow clock, so a dispute frozen before its
/// quorum may settle can still be escalated once the guardian has looked.
///
/// An unchallenged result binds by the same rule: once its challenge window is over
/// (Escrow::challenge_window_over, the moment settle's require_window_over passes:
/// challenge_deadline, or the end of the reveal grace while a commit is pending) escalate refuses
/// a Challengeable escrow (UnchallengedResultBinds), as settle may then make it Claimable. The
/// challenge window is the guardian's time to escalate a false posted result, and a commit still
/// pending in the grace may yet open a dispute, so until then it may. Without the rule a guardian
/// key alone could take any honest result nobody challenged past its window to the arbiter, and
/// with an idle arbiter refund it in full after hard_deadline.
pub fn handle_escalate(ctx: Context<GuardEscrow>) -> Result<()> {
    let wall = Clock::get()?.unix_timestamp;
    let by = ctx.accounts.authority.key();
    let config = &ctx.accounts.config;
    guard_role(config, &by)?;
    let now = escrow_now(&ctx.accounts.escrow, config, wall);
    let escrow = &mut ctx.accounts.escrow;
    let from_status = escrow.status;
    require!(
        from_status != EscrowStatus::Closed,
        EscrowError::EscrowClosed
    );
    require!(
        from_status == EscrowStatus::Challengeable || from_status == EscrowStatus::Disputed,
        EscrowError::InvalidStatus
    );
    if from_status == EscrowStatus::Challengeable {
        require!(
            !escrow.challenge_window_over(now)?,
            EscrowError::UnchallengedResultBinds
        );
    }
    if let Some(settles_at) = escrow.quorum_settles_at() {
        require!(now < settles_at, EscrowError::QuorumRecorded);
    }
    escrow.status = EscrowStatus::Frozen;
    emit_cpi!(Escalated {
        escrow: escrow.key(),
        by,
        from_status,
    });
    Ok(())
}

// ------------------------------------------------------------------------ revocation

/// `revoked`: the guardian (or the admin) revokes `key`, whose signature every instruction then
/// refuses (KeyRevoked) in every role it holds: sponsor, resolver, compliance (its co-signature
/// too), regrader, arbiter, claimant, challenger and guardian. The admin's key cannot be revoked
/// (CannotRevokeAdmin); at most MAX_REVOKED keys are (ListFull). Not `revoked`: only the admin
/// unrevokes (UnauthorizedAdmin for the guardian).
pub fn handle_set_revoked(ctx: Context<SetStop>, key: Pubkey, revoked: bool) -> Result<()> {
    let by = ctx.accounts.authority.key();
    let config = &mut ctx.accounts.config;
    let is_admin = guard_role(config, &by)?;
    if revoked {
        require!(key != Pubkey::default(), EscrowError::InvalidConfig);
        require!(key != config.admin, EscrowError::CannotRevokeAdmin);
        require!(!config.is_revoked(&key), EscrowError::AlreadyRevoked);
        require!(config.revoked.len() < MAX_REVOKED, EscrowError::ListFull);
        config.revoked.push(key);
    } else {
        require!(is_admin, EscrowError::UnauthorizedAdmin);
        require!(config.is_revoked(&key), EscrowError::NotRevoked);
        config.revoked.retain(|k| *k != key);
    }
    emit_cpi!(RevocationChanged {
        key,
        by,
        revoked,
        revoked_count: config.revoked.len() as u32,
    });
    Ok(())
}

// ------------------------------------------------------------------------ rotate_role

#[event_cpi]
#[derive(Accounts)]
pub struct RotateRole<'info> {
    #[account(address = config.admin @ EscrowError::UnauthorizedAdmin)]
    pub admin: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub escrow: Account<'info, Escrow>,

    /// CHECK: the old regrader's Attestation PDA ["attestation", escrow, old] (checked in the
    /// handler): a regrader seat rotates only while it has not voted. Omitted for the resolver
    /// and the compliance key.
    pub old_attestation: Option<UncheckedAccount<'info>>,
}

/// The admin replaces one of the escrow's keys (any status but Closed), typically after the
/// guardian revoked it: the resolver, the compliance key, or one regrader `old` (RoleMismatch when
/// `old` does not hold that role). `new` must be set and not revoked (InvalidConfig, KeyRevoked),
/// a new resolver or compliance key not the escrow's own address, which never signs (RoleIsEscrow,
/// as open_escrow refuses it), and the panel stays independent: no regrader may be the resolver
/// or the compliance key (RegraderNotIndependent). A new regrader must be registered
/// (RegraderNotRegistered), not already on the panel (InvalidRegraderSet), keep the house count
/// within max_house_regraders (TooManyHouseRegraders), and take a seat that has not voted
/// (RegraderAlreadyVoted: its Attestation exists, the account at its PDA owned by this program),
/// so a seat never votes twice; lamports anyone sends to that PDA do not block the rotation. The
/// resolver's bond, if held, now goes to the new resolver.
pub fn handle_rotate_role(
    ctx: Context<RotateRole>,
    role: EscrowRole,
    old: Pubkey,
    new: Pubkey,
) -> Result<()> {
    let config = &ctx.accounts.config;
    let escrow_key = ctx.accounts.escrow.key();
    let escrow = &mut ctx.accounts.escrow;
    require!(
        escrow.status != EscrowStatus::Closed,
        EscrowError::EscrowClosed
    );
    require!(new != Pubkey::default(), EscrowError::InvalidConfig);
    config.require_not_revoked(&new)?;
    let n = usize::from(escrow.n);
    match role {
        EscrowRole::Resolver => {
            require!(escrow.resolver == old, EscrowError::RoleMismatch);
            require!(new != escrow_key, EscrowError::RoleIsEscrow);
            require!(
                !escrow.is_regrader(&new),
                EscrowError::RegraderNotIndependent
            );
            escrow.resolver = new;
        }
        EscrowRole::Compliance => {
            require!(escrow.compliance == old, EscrowError::RoleMismatch);
            require!(new != escrow_key, EscrowError::RoleIsEscrow);
            require!(
                !escrow.is_regrader(&new),
                EscrowError::RegraderNotIndependent
            );
            escrow.compliance = new;
        }
        EscrowRole::Regrader => {
            let seat = escrow.regraders[..n]
                .iter()
                .position(|k| *k == old)
                .ok_or(EscrowError::RoleMismatch)?;
            require!(
                config.regrader(&new).is_some(),
                EscrowError::RegraderNotRegistered
            );
            require!(!escrow.is_regrader(&new), EscrowError::InvalidRegraderSet);
            require!(
                new != escrow.resolver && new != escrow.compliance,
                EscrowError::RegraderNotIndependent
            );
            let attestation = ctx
                .accounts
                .old_attestation
                .as_ref()
                .ok_or(error!(anchor_lang::error::ErrorCode::AccountNotEnoughKeys))?;
            let (expected, _) = Pubkey::find_program_address(
                &[ATTESTATION_SEED, escrow_key.as_ref(), old.as_ref()],
                &crate::ID,
            );
            require_keys_eq!(
                attestation.key(),
                expected,
                anchor_lang::error::ErrorCode::ConstraintSeeds
            );
            // The seat voted iff attest's `init` created its Attestation: only this program can
            // own an account at its own PDA. Lamports alone prove nothing (anyone may send them).
            require!(
                *attestation.owner != crate::ID,
                EscrowError::RegraderAlreadyVoted
            );
            let mut panel = escrow.regraders;
            panel[seat] = new;
            require!(
                config.house_count(&panel[..n]) <= config.max_house_regraders,
                EscrowError::TooManyHouseRegraders
            );
            escrow.regraders = panel;
        }
    }
    emit_cpi!(RoleRotated {
        escrow: escrow_key,
        by: ctx.accounts.admin.key(),
        role,
        old,
        new,
    });
    Ok(())
}
