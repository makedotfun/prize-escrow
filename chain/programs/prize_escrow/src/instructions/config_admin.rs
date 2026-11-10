//! Creating the Config and the admin's setters: the admin (two steps), the guardian and the
//! arbiter, the limits, the panel floor, the window floors, the allowlists and the proposal
//! policy (the curator and the pending cap). Each emits ConfigChanged with Config's settings
//! after it.

use anchor_lang::{prelude::*, solana_program::bpf_loader_upgradeable};

use crate::{
    config::{AllowList, Config, ConfigInit, ConfigRole, Floors, Limits},
    constants::CONFIG_SEED,
    error::EscrowError,
    events::{ConfigChange, ConfigChanged},
};

/// The ConfigChanged event for `config` (at `config_key`) after `change`.
pub(crate) fn config_changed(
    config_key: Pubkey,
    config: &Config,
    change: ConfigChange,
    by: Pubkey,
    key: Pubkey,
    list: Option<AllowList>,
    house: bool,
) -> ConfigChanged {
    ConfigChanged {
        config: config_key,
        change,
        by,
        key,
        list,
        house,
        admin: config.admin,
        pending_admin: config.pending_admin,
        guardian: config.guardian,
        arbiter: config.arbiter,
        escrow_cap: config.escrow_cap,
        global_cap: config.global_cap,
        open_value: config.open_value,
        flow_capacity: config.flow_capacity,
        flow_period: config.flow_period,
        min_bond: config.min_bond,
        max_house_regraders: config.max_house_regraders,
        min_challenge_window: config.min_challenge_window,
        min_attest_window: config.min_attest_window,
        min_hold_window: config.min_hold_window,
        min_claim_window: config.min_claim_window,
        reveal_grace: config.reveal_grace,
        min_regraders: config.min_regraders,
        curator: config.curator,
        pending_value: config.pending_value,
        pending_cap: config.pending_cap,
    }
}

// ------------------------------------------------------------------------ initialize_config

#[event_cpi]
#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    /// The program's upgrade authority (its ProgramData's upgrade_authority_address); pays the
    /// rent.
    #[account(mut)]
    pub authority: Signer<'info>,

    /// PDA ["config"]: `init`, so it is created once.
    #[account(
        init,
        payer = authority,
        space = Config::SPACE,
        seeds = [CONFIG_SEED],
        bump,
    )]
    pub config: Account<'info, Config>,

    /// This program's ProgramData account, ["<program id>"] under the upgradeable loader.
    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = bpf_loader_upgradeable::ID,
        constraint = program_data.upgrade_authority_address == Some(authority.key())
            @ EscrowError::NotUpgradeAuthority,
    )]
    pub program_data: Account<'info, ProgramData>,

    pub system_program: Program<'info, System>,
}

/// Only the program's upgrade authority, and only once (the PDA's `init`): an immutable program
/// (no upgrade authority) or any other signer is refused (NotUpgradeAuthority). The keys must be
/// set, the limits and floors in bounds (InvalidConfig) and the lists within their lengths.
pub fn handle_initialize_config(ctx: Context<InitializeConfig>, init: ConfigInit) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let config = Config::new(init, ctx.bumps.config, now)?;
    ctx.accounts.config.set_inner(config);
    let event = config_changed(
        ctx.accounts.config.key(),
        &ctx.accounts.config,
        ConfigChange::Initialized,
        ctx.accounts.authority.key(),
        Pubkey::default(),
        None,
        false,
    );
    emit_cpi!(event);
    Ok(())
}

// ------------------------------------------------------------------------ the admin's setters

/// Every admin setter: the admin signs and the Config is written.
#[event_cpi]
#[derive(Accounts)]
pub struct AdminConfig<'info> {
    #[account(address = config.admin @ EscrowError::UnauthorizedAdmin)]
    pub admin: Signer<'info>,

    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// The admin names its successor; accept_admin, signed by that key, completes the move, so a
/// mistyped key never takes the Config. Pubkey::default() withdraws a proposal.
pub fn handle_propose_admin(ctx: Context<AdminConfig>, new_admin: Pubkey) -> Result<()> {
    let config = &mut ctx.accounts.config;
    config.pending_admin = new_admin;
    let event = config_changed(
        config.key(),
        config,
        ConfigChange::AdminProposed,
        ctx.accounts.admin.key(),
        new_admin,
        None,
        false,
    );
    emit_cpi!(event);
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    pub new_admin: Signer<'info>,

    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
        constraint = config.pending_admin == new_admin.key() @ EscrowError::NotPendingAdmin,
    )]
    pub config: Account<'info, Config>,
}

/// The key propose_admin named becomes the admin (NotPendingAdmin for any other signer), unless it
/// is revoked (KeyRevoked, as at every other signer site): the admin's key can never be revoked
/// (set_revoked's CannotRevokeAdmin), so a revoked key never becomes it. The proposal stays
/// pending; the key takes the Config once the admin unrevokes it. Nor does the curator's key ever
/// become it (CuratorNotIndependent): the curator is a key of its own.
pub fn handle_accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
    let new_admin = ctx.accounts.new_admin.key();
    require!(new_admin != Pubkey::default(), EscrowError::NotPendingAdmin);
    let config = &mut ctx.accounts.config;
    config.require_not_revoked(&new_admin)?;
    require!(
        !config.is_curator(&new_admin),
        EscrowError::CuratorNotIndependent
    );
    config.admin = new_admin;
    config.pending_admin = Pubkey::default();
    let event = config_changed(
        config.key(),
        config,
        ConfigChange::AdminAccepted,
        new_admin,
        new_admin,
        None,
        false,
    );
    emit_cpi!(event);
    Ok(())
}

/// Replaces the guardian or the arbiter (InvalidConfig for the default key). A revoked key is
/// refused (KeyRevoked), as accept_admin refuses it for the admin and rotate_role for an escrow's
/// keys: it could sign nothing in that role anyway (guard_role and arbiter_resolve refuse a
/// revoked signer), so naming it would leave the Config with no working guardian or arbiter until
/// the admin unrevoked it. A new arbiter answers for every escrow at once: arbiter_resolve checks
/// Config's. The curator's key is refused (CuratorNotIndependent), as set_proposal_policy refuses
/// the guardian's or the arbiter's as the curator.
pub fn handle_set_config_role(
    ctx: Context<AdminConfig>,
    role: ConfigRole,
    key: Pubkey,
) -> Result<()> {
    require!(key != Pubkey::default(), EscrowError::InvalidConfig);
    let config = &mut ctx.accounts.config;
    config.require_not_revoked(&key)?;
    require!(!config.is_curator(&key), EscrowError::CuratorNotIndependent);
    let change = match role {
        ConfigRole::Guardian => {
            config.guardian = key;
            ConfigChange::GuardianSet
        }
        ConfigRole::Arbiter => {
            config.arbiter = key;
            ConfigChange::ArbiterSet
        }
    };
    let event = config_changed(
        config.key(),
        config,
        change,
        ctx.accounts.admin.key(),
        key,
        None,
        false,
    );
    emit_cpi!(event);
    Ok(())
}

/// Writes the caps, the flow bucket, min_bond and max_house_regraders (InvalidConfig out of
/// bounds). Lowering a cap below what is open already refuses only new deposits.
pub fn handle_set_limits(ctx: Context<AdminConfig>, limits: Limits) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let config = &mut ctx.accounts.config;
    config.set_limits(&limits, now)?;
    let event = config_changed(
        config.key(),
        config,
        ConfigChange::LimitsSet,
        ctx.accounts.admin.key(),
        Pubkey::default(),
        None,
        false,
    );
    emit_cpi!(event);
    Ok(())
}

/// Writes the panel floor, the fewest regraders open_escrow lets an escrow name (1 to
/// MAX_REGRADERS; InvalidConfig otherwise), so the admin can refuse small panels, whose one or
/// two votes decide a dispute, without an upgrade. Escrows already open keep their panel.
pub fn handle_set_min_regraders(ctx: Context<AdminConfig>, min_regraders: u8) -> Result<()> {
    let config = &mut ctx.accounts.config;
    config.set_min_regraders(min_regraders)?;
    let event = config_changed(
        config.key(),
        config,
        ConfigChange::MinRegradersSet,
        ctx.accounts.admin.key(),
        Pubkey::default(),
        None,
        false,
    );
    emit_cpi!(event);
    Ok(())
}

/// Writes the window floors and the reveal grace (InvalidConfig out of bounds); escrows already
/// open keep their windows and grace.
pub fn handle_set_floors(ctx: Context<AdminConfig>, floors: Floors) -> Result<()> {
    let config = &mut ctx.accounts.config;
    config.set_floors(&floors)?;
    let event = config_changed(
        config.key(),
        config,
        ConfigChange::FloorsSet,
        ctx.accounts.admin.key(),
        Pubkey::default(),
        None,
        false,
    );
    emit_cpi!(event);
    Ok(())
}

/// Names the curator (Pubkey::default(): proposals off on chain) and the pending cap
/// (Config::set_proposal_policy: never a revoked key, KeyRevoked, nor the admin's, the guardian's
/// or the arbiter's, CuratorNotIndependent). The Limits and ConfigInit wire formats are
/// untouched: initialize_config and set_limits leave both as they are. Proposals already
/// submitted stay: the new curator reviews them (a replaced one is refused,
/// UnauthorizedCurator), and their deposits stay in pending_value whatever the new cap.
pub fn handle_set_proposal_policy(
    ctx: Context<AdminConfig>,
    curator: Pubkey,
    pending_cap: u64,
) -> Result<()> {
    let config = &mut ctx.accounts.config;
    config.set_proposal_policy(curator, pending_cap)?;
    let event = config_changed(
        config.key(),
        config,
        ConfigChange::ProposalPolicySet,
        ctx.accounts.admin.key(),
        curator,
        None,
        false,
    );
    emit_cpi!(event);
    Ok(())
}

/// Adds `key` to `list` (`house` marks a house regrader or a house sponsor) or takes it off;
/// escrows already open keep what they named. A sponsor already listed is not refused: `allowed`
/// with `house` marks it a house sponsor, without unmarks it, and nothing else changes
/// (Config::allow_or_mark); a mint or a regrader listed twice is still AlreadyListed.
pub fn handle_set_allowed(
    ctx: Context<AdminConfig>,
    list: AllowList,
    key: Pubkey,
    allowed: bool,
    house: bool,
) -> Result<()> {
    let config = &mut ctx.accounts.config;
    let change = if allowed {
        config.allow_or_mark(list, key, house)?;
        ConfigChange::Allowed
    } else {
        config.disallow(list, key)?;
        ConfigChange::Disallowed
    };
    let event = config_changed(
        config.key(),
        config,
        change,
        ctx.accounts.admin.key(),
        key,
        Some(list),
        allowed && house && list != AllowList::Mint,
    );
    emit_cpi!(event);
    Ok(())
}
