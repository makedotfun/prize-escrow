//! The program's one Config account and the safeguards it carries: the open policy (allowlists,
//! the regrader registry, floors), the caps and the claim flow bucket, the stop state and the
//! revoked keys, and the stoppable escrow clock every deadline check reads.
//!
//! The clock. `escrow_now(escrow, config)` is wall time minus the seconds this escrow has been
//! stopped, by a global PayoutStop or its own guardian freeze, counted once when both overlap:
//! - G(t), the global stopped seconds up to wall time t: Config.stopped_secs (every PayoutStop
//!   that ended) plus the part of the PayoutStop in force that has elapsed by t (a stop lapses at
//!   stop_expires_at). Only PayoutStop stops the clock; IntakeStop refuses only the deposits
//!   (open_escrow, fund, submit_proposal), set_proposal_rules and approve_proposal.
//! - Γ(t) = t - G(t), the global clock: it stands still while a PayoutStop is in force.
//! - A freeze is measured on Γ: it began at Γ = freeze_since and lapses at Γ = freeze_until, so a
//!   PayoutStop during a freeze also holds the freeze's own lapse back, and the escrow's frozen
//!   seconds never count a second the global stop already counted.
//! - escrow_now(t) = t - (G(t) - escrow.stop_base) - F(t), where stop_base is G at open and F is
//!   Escrow.frozen_secs plus the part of the freeze in force that has elapsed on Γ.
//!
//! So the escrow clock never runs backwards and never runs faster than wall time: a stop of d
//! seconds moves every deadline d seconds later in wall time (the deadlines themselves are stored
//! as they were set, on the escrow clock), and never shortens a window. Nothing needs an
//! instruction to land when a stop or a freeze lapses: each is read against wall time.
//!
//! No breaker stops a program upgrade: the upgrade authority (today the owner's key, later the
//! multisig vault) can always deploy new bytes, and neither the guardian nor the admin of this
//! Config can refuse it.

use anchor_lang::prelude::*;

use crate::{
    constants::{
        CONFIG_SEED, DEFAULT_MIN_REGRADERS, MAX_MINTS, MAX_PROPOSAL_BOND, MAX_REGISTRY,
        MAX_REGRADERS, MAX_REVEAL_GRACE, MAX_REVOKED, MAX_SPONSORS, MAX_WINDOW, MIN_RESOLVE_WINDOW,
        MIN_REVEAL_GRACE, STOP_DURATION,
    },
    error::EscrowError,
    state::{Escrow, EscrowTerms},
};

/// The breaker level Config holds. The levels are ordered: PayoutStop includes IntakeStop, so the
/// guardian, who may only escalate, moves Normal -> IntakeStop -> PayoutStop and never back.
#[derive(
    AnchorSerialize,
    AnchorDeserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    InitSpace,
)]
pub enum StopState {
    /// Nothing is stopped.
    Normal,
    /// open_escrow, fund, submit_proposal, set_proposal_rules and approve_proposal are refused
    /// (close_proposal is not: a deposit always has its way back).
    IntakeStop,
    /// open_escrow, fund, submit_proposal, set_proposal_rules and approve_proposal, and every
    /// payout (claim, refund, settle, arbiter_resolve and close_proposal), are refused, and every
    /// escrow's clock stands still.
    PayoutStop,
}

/// One key of the regrader registry: `house` marks a key the house holds (open_escrow counts them
/// against Config.max_house_regraders).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq, InitSpace)]
pub struct RegraderEntry {
    pub key: Pubkey,
    pub house: bool,
}

/// Which allowlist set_allowed edits.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowList {
    /// Config.mints: the mints an escrow may hold.
    Mint,
    /// Config.sponsors: who may open an escrow.
    Sponsor,
    /// Config.regraders: the keys an escrow may name as regraders, each with its house flag.
    Regrader,
}

/// Which Config key set_config_role replaces (the admin moves by propose_admin and accept_admin).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigRole {
    Guardian,
    Arbiter,
}

/// Which of an escrow's keys rotate_role replaces.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum EscrowRole {
    Resolver,
    Compliance,
    Regrader,
}

/// The caps, the flow bucket, the bond minimum and the house-regrader allowance (set_limits).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// C_e: the most one escrow may hold (what open_escrow and fund deposited), in mint base units.
    pub escrow_cap: u64,
    /// C_g: the most every escrow not yet refunded may hold together (Config.open_value).
    pub global_cap: u64,
    /// The flow bucket's capacity: the most claims may pay out in a burst.
    pub flow_capacity: u64,
    /// Seconds the bucket takes to refill from empty to flow_capacity.
    pub flow_period: i64,
    /// The smallest bond_lamports open_escrow accepts (on top of the rent floor).
    pub min_bond: u64,
    /// The most house regraders one escrow may name (MAX_REGRADERS allows an all-house panel).
    pub max_house_regraders: u8,
}

impl Limits {
    pub fn validate(&self) -> Result<()> {
        require!(
            self.escrow_cap > 0
                && self.global_cap > 0
                && self.flow_capacity > 0
                && (1..=MAX_WINDOW).contains(&self.flow_period)
                && self.max_house_regraders <= MAX_REGRADERS,
            EscrowError::InvalidConfig
        );
        Ok(())
    }
}

/// The window floors open_escrow holds the terms to, on top of the compiled minimums, and the
/// reveal grace every escrow opened after it takes (set_floors).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Floors {
    pub min_challenge_window: i64,
    pub min_attest_window: i64,
    pub min_hold_window: i64,
    pub min_claim_window: i64,
    /// Seconds after challenge_deadline a challenge committed before it may still be revealed:
    /// MIN_REVEAL_GRACE to MAX_REVEAL_GRACE.
    pub reveal_grace: i64,
}

impl Floors {
    pub fn validate(&self) -> Result<()> {
        for floor in [
            self.min_challenge_window,
            self.min_attest_window,
            self.min_hold_window,
            self.min_claim_window,
        ] {
            require!(
                (0..=MAX_WINDOW).contains(&floor),
                EscrowError::InvalidConfig
            );
        }
        require!(
            (MIN_REVEAL_GRACE..=MAX_REVEAL_GRACE).contains(&self.reveal_grace),
            EscrowError::InvalidConfig
        );
        Ok(())
    }
}

/// What initialize_config writes: the keys, the limits, the floors and the starting lists.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ConfigInit {
    pub admin: Pubkey,
    pub guardian: Pubkey,
    pub arbiter: Pubkey,
    pub limits: Limits,
    pub floors: Floors,
    pub mints: Vec<Pubkey>,
    pub sponsors: Vec<Pubkey>,
    pub regraders: Vec<RegraderEntry>,
}

/// The program's Config. PDA: `["config"]`. Created once by the upgrade authority; every setter
/// is the admin's, except the guardian's escalation verbs (set_stop up, set_freeze on, escalate,
/// set_revoked on), which the admin may use too.
#[account]
#[derive(InitSpace, Debug, PartialEq, Eq)]
pub struct Config {
    pub bump: u8,
    /// The breaker level as last set; it lapses to Normal at stop_expires_at (stop_level reads it).
    pub stop: StopState,
    /// The most house regraders one escrow may name.
    pub max_house_regraders: u8,
    /// Sets everything; today the owner's key, later the upgrade multisig vault.
    pub admin: Pubkey,
    /// The key propose_admin named, which accept_admin makes the admin; Pubkey::default() when
    /// none is pending.
    pub pending_admin: Pubkey,
    /// The guardian: a separate key, never on the server, that may only escalate.
    pub guardian: Pubkey,
    /// The arbiter every escrow names and arbiter_resolve answers to; today the owner's key, later
    /// the multisig vault.
    pub arbiter: Pubkey,
    /// C_e, in mint base units.
    pub escrow_cap: u64,
    /// C_g, in mint base units.
    pub global_cap: u64,
    /// What every escrow not yet refunded deposited (open_escrow and fund add, refund takes away).
    pub open_value: u64,
    pub flow_capacity: u64,
    pub flow_period: i64,
    /// The bucket as of flow_updated_at (wall time); claim refills it, then takes from it.
    pub flow_level: u64,
    pub flow_updated_at: i64,
    pub min_bond: u64,
    pub min_challenge_window: i64,
    pub min_attest_window: i64,
    pub min_hold_window: i64,
    pub min_claim_window: i64,
    pub reveal_grace: i64,
    /// Wall time the stop in force was set (meaningful while `stop` is not Normal).
    pub stop_since: i64,
    /// Wall time the stop in force lapses.
    pub stop_expires_at: i64,
    /// Seconds of every PayoutStop that has ended: G before the one in force.
    pub stopped_secs: i64,
    #[max_len(MAX_MINTS)]
    pub mints: Vec<Pubkey>,
    #[max_len(MAX_SPONSORS)]
    pub sponsors: Vec<Pubkey>,
    #[max_len(MAX_REGISTRY)]
    pub regraders: Vec<RegraderEntry>,
    #[max_len(MAX_REVOKED)]
    pub revoked: Vec<Pubkey>,
    /// The fewest regraders an escrow may name (open_escrow's PanelTooSmall): DEFAULT_MIN_REGRADERS
    /// at initialize_config, 1 to MAX_REGRADERS by set_min_regraders. It takes the first of the
    /// bytes `reserved` held, so a Config written before it reads 0 here, which refuses no panel
    /// (every panel names at least one regrader), as 1 does.
    pub min_regraders: u8,
    /// The key that co-signs a sponsor's submit_proposal (after the house screened the sponsor)
    /// and approves the proposal as submitted (setting its rules hash first if the submit left it
    /// all zero) or rejects it back to the sponsor, and nothing else: it never sponsors a proposal,
    /// nor is a proposal's resolver or compliance key (Config::check_proposal_terms).
    /// Pubkey::default() (what Config::new writes, and what a Config created before the field
    /// existed reads, its reserved bytes zero) turns proposals off: submit_proposal,
    /// set_proposal_rules and approve_proposal refuse (ProposalsDisabled); the sponsor's and
    /// anyone's exits stay open.
    pub curator: Pubkey,
    /// What every proposal not yet approved or closed deposited (submit_proposal adds,
    /// approve_proposal moves it to open_value, close_proposal takes it away). It counts against
    /// global_cap with open_value, so a direct open never takes room a proposal holds.
    pub pending_value: u64,
    /// The most pending_value may reach (set_proposal_policy).
    pub pending_cap: u64,
    /// Set once by retire, never cleared: the deployment winds down. Intake refuses for good
    /// (Config::require_intake: Retired); every payout, settle, refund and close stays open, and
    /// close_escrow and close_config need it. A Config created before the field existed reads
    /// false (its reserved bytes zero).
    pub retired: bool,
    /// The escrows opened under this Config and not yet closed: open_escrow and approve_proposal
    /// add one, close_escrow takes one away (saturating, as a Config created before the field
    /// existed reads 0 with escrows already open). close_config needs it at 0.
    pub live_escrows: u32,
    /// The house sponsors: bit i set marks sponsors[i] as the house's own (MAX_SPONSORS is 32, one
    /// bit each; every bit at or above sponsors.len() is clear). An escrow a house sponsor opens
    /// may take any challenge window from 0 (open_escrow; Config::is_house_sponsor): neither
    /// MIN_CHALLENGE_WINDOW nor min_challenge_window holds it, and every other bound does. The
    /// admin marks and unmarks a listed sponsor with set_allowed(Sponsor, key, true, house), and
    /// taking a sponsor off the list moves the bits above it down with it
    /// (Config::without_bit). A Config written before the field reads 0 (its reserved bytes
    /// zero): no house sponsor.
    pub house_sponsors: u32,
    /// Zeroed room for later fields. min_regraders took the first of the 64 bytes this held,
    /// curator, pending_value and pending_cap the next 48, retired and live_escrows the next 5,
    /// and house_sponsors the next 4, so every offset before it and Config::SPACE stayed as they
    /// were.
    pub reserved: [u8; 6],
}

impl Config {
    /// Account size: the 8-byte discriminator plus the fields at their longest.
    pub const SPACE: usize = 8 + Self::INIT_SPACE;

    /// Its address: `["config"]` under the program.
    pub fn pda() -> (Pubkey, u8) {
        Pubkey::find_program_address(&[CONFIG_SEED], &crate::ID)
    }

    /// A fresh Config from `init`, the bucket full, nothing stopped or revoked, no curator
    /// (proposals off until set_proposal_policy names one).
    pub fn new(init: ConfigInit, bump: u8, now: i64) -> Result<Self> {
        require!(
            init.admin != Pubkey::default()
                && init.guardian != Pubkey::default()
                && init.arbiter != Pubkey::default(),
            EscrowError::InvalidConfig
        );
        init.limits.validate()?;
        init.floors.validate()?;
        require!(
            init.mints.len() <= MAX_MINTS
                && init.sponsors.len() <= MAX_SPONSORS
                && init.regraders.len() <= MAX_REGISTRY,
            EscrowError::ListFull
        );
        let mut config = Config {
            bump,
            stop: StopState::Normal,
            max_house_regraders: 0,
            admin: init.admin,
            pending_admin: Pubkey::default(),
            guardian: init.guardian,
            arbiter: init.arbiter,
            escrow_cap: 0,
            global_cap: 0,
            open_value: 0,
            flow_capacity: 0,
            flow_period: 0,
            flow_level: 0,
            flow_updated_at: now,
            min_bond: 0,
            min_challenge_window: 0,
            min_attest_window: 0,
            min_hold_window: 0,
            min_claim_window: 0,
            reveal_grace: 0,
            stop_since: 0,
            stop_expires_at: 0,
            stopped_secs: 0,
            mints: Vec::new(),
            sponsors: Vec::new(),
            regraders: Vec::new(),
            revoked: Vec::new(),
            min_regraders: DEFAULT_MIN_REGRADERS,
            curator: Pubkey::default(),
            pending_value: 0,
            pending_cap: 0,
            retired: false,
            live_escrows: 0,
            house_sponsors: 0,
            reserved: [0; 6],
        };
        config.set_limits(&init.limits, now)?;
        config.flow_level = config.flow_capacity;
        config.set_floors(&init.floors)?;
        for mint in init.mints {
            config.allow(AllowList::Mint, mint, false)?;
        }
        for sponsor in init.sponsors {
            config.allow(AllowList::Sponsor, sponsor, false)?;
        }
        for entry in init.regraders {
            config.allow(AllowList::Regrader, entry.key, entry.house)?;
        }
        Ok(config)
    }

    /// Writes `limits` (validated). The bucket keeps what it holds, refilled to `now` and capped
    /// at the new capacity; flow_updated_at never moves back (Config::refill).
    pub fn set_limits(&mut self, limits: &Limits, now: i64) -> Result<()> {
        limits.validate()?;
        if self.flow_period > 0 {
            self.refill(now)?;
        }
        self.escrow_cap = limits.escrow_cap;
        self.global_cap = limits.global_cap;
        self.flow_capacity = limits.flow_capacity;
        self.flow_period = limits.flow_period;
        self.flow_level = self.flow_level.min(limits.flow_capacity);
        self.flow_updated_at = self.flow_updated_at.max(now);
        self.min_bond = limits.min_bond;
        self.max_house_regraders = limits.max_house_regraders;
        Ok(())
    }

    /// Writes the panel floor open_escrow holds every escrow to: 1 to MAX_REGRADERS
    /// (InvalidConfig otherwise). Escrows already open keep the panel they named.
    pub fn set_min_regraders(&mut self, min_regraders: u8) -> Result<()> {
        require!(
            (1..=MAX_REGRADERS).contains(&min_regraders),
            EscrowError::InvalidConfig
        );
        self.min_regraders = min_regraders;
        Ok(())
    }

    /// Writes `floors` (validated). Escrows already open keep the reveal grace they opened with.
    pub fn set_floors(&mut self, floors: &Floors) -> Result<()> {
        floors.validate()?;
        self.min_challenge_window = floors.min_challenge_window;
        self.min_attest_window = floors.min_attest_window;
        self.min_hold_window = floors.min_hold_window;
        self.min_claim_window = floors.min_claim_window;
        self.reveal_grace = floors.reveal_grace;
        Ok(())
    }

    /// Adds `key` to `list` (AlreadyListed, ListFull, InvalidConfig for the default key). `house`
    /// marks a house regrader, or a house sponsor (its bit of house_sponsors); a mint has none.
    pub fn allow(&mut self, list: AllowList, key: Pubkey, house: bool) -> Result<()> {
        require!(key != Pubkey::default(), EscrowError::InvalidConfig);
        require!(!self.is_listed(list, &key), EscrowError::AlreadyListed);
        match list {
            AllowList::Mint => {
                require!(self.mints.len() < MAX_MINTS, EscrowError::ListFull);
                self.mints.push(key);
            }
            AllowList::Sponsor => {
                require!(self.sponsors.len() < MAX_SPONSORS, EscrowError::ListFull);
                self.sponsors.push(key);
                self.set_house_bit(self.sponsors.len() - 1, house);
            }
            AllowList::Regrader => {
                require!(self.regraders.len() < MAX_REGISTRY, EscrowError::ListFull);
                self.regraders.push(RegraderEntry { key, house });
            }
        }
        Ok(())
    }

    /// set_allowed's add: Config::allow, except for a sponsor already listed, which is not
    /// refused: its house bit becomes `house` and nothing else changes (its place on the list,
    /// every other sponsor's bit). A mint or a regrader already listed is still AlreadyListed.
    pub fn allow_or_mark(&mut self, list: AllowList, key: Pubkey, house: bool) -> Result<()> {
        if list == AllowList::Sponsor {
            if let Some(index) = self.sponsor_index(&key) {
                self.set_house_bit(index, house);
                return Ok(());
            }
        }
        self.allow(list, key, house)
    }

    /// Takes `key` off `list` (NotListed). Escrows already open keep what they named. A sponsor
    /// taken off takes its house bit with it, and every sponsor after it keeps its own
    /// (Config::without_bit: the list keeps its order, so each moves down one place, bit and all).
    pub fn disallow(&mut self, list: AllowList, key: Pubkey) -> Result<()> {
        require!(self.is_listed(list, &key), EscrowError::NotListed);
        match list {
            AllowList::Mint => self.mints.retain(|k| *k != key),
            AllowList::Sponsor => {
                let index = self.sponsor_index(&key).ok_or(EscrowError::NotListed)?;
                self.sponsors.remove(index);
                self.house_sponsors = Self::without_bit(self.house_sponsors, index);
            }
            AllowList::Regrader => self.regraders.retain(|e| e.key != key),
        }
        Ok(())
    }

    /// Whether `key` is a listed sponsor the admin marked as the house's own: open_escrow then
    /// waives the challenge window's minimums (EscrowTerms::validate_for_sponsor,
    /// Config::check_terms_policy). Never true for a key off the sponsor list.
    pub fn is_house_sponsor(&self, key: &Pubkey) -> bool {
        self.sponsor_index(key)
            .and_then(|index| u32::try_from(index).ok())
            .and_then(|index| self.house_sponsors.checked_shr(index))
            .is_some_and(|bits| bits & 1 == 1)
    }

    /// Where `key` sits on the sponsor list.
    fn sponsor_index(&self, key: &Pubkey) -> Option<usize> {
        self.sponsors.iter().position(|k| k == key)
    }

    /// Sets sponsors[index]'s house bit to `house` (an index past the 32 bits sets nothing:
    /// MAX_SPONSORS never lets the list reach one).
    fn set_house_bit(&mut self, index: usize, house: bool) {
        let Some(bit) = u32::try_from(index)
            .ok()
            .and_then(|index| 1u32.checked_shl(index))
        else {
            return;
        };
        if house {
            self.house_sponsors |= bit;
        } else {
            self.house_sponsors &= !bit;
        }
    }

    /// `bits` with bit `index` taken out: the bits below it stay, every bit above it moves down
    /// one place, and the top bit is clear (what disallow does to house_sponsors as the sponsor
    /// list closes up behind the one it takes off). An index past 31 changes nothing.
    pub fn without_bit(bits: u32, index: usize) -> u32 {
        let Ok(index) = u32::try_from(index) else {
            return bits;
        };
        if index >= u32::BITS {
            return bits;
        }
        let below = bits & ((1u32 << index) - 1);
        let above = bits.checked_shr(index + 1).unwrap_or(0) << index;
        below | above
    }

    pub fn is_listed(&self, list: AllowList, key: &Pubkey) -> bool {
        match list {
            AllowList::Mint => self.mints.contains(key),
            AllowList::Sponsor => self.sponsors.contains(key),
            AllowList::Regrader => self.regrader(key).is_some(),
        }
    }

    /// The registry entry of `key`, if it is a registered regrader.
    pub fn regrader(&self, key: &Pubkey) -> Option<&RegraderEntry> {
        self.regraders.iter().find(|e| e.key == *key)
    }

    // ------------------------------------------------------------------- revocation

    pub fn is_revoked(&self, key: &Pubkey) -> bool {
        self.revoked.contains(key)
    }

    /// Refuses a revoked signer (KeyRevoked).
    pub fn require_not_revoked(&self, key: &Pubkey) -> Result<()> {
        require!(!self.is_revoked(key), EscrowError::KeyRevoked);
        Ok(())
    }

    // ------------------------------------------------------------------- the stop clock

    /// The stop in force at wall time `now`: the level last set, or Normal once it lapsed.
    pub fn stop_level(&self, now: i64) -> StopState {
        if self.stop != StopState::Normal && now < self.stop_expires_at {
            self.stop
        } else {
            StopState::Normal
        }
    }

    /// G(now): every second a PayoutStop has held the clocks, up to wall time `now`.
    pub fn global_stopped(&self, now: i64) -> i64 {
        let running = if self.stop == StopState::PayoutStop {
            now.min(self.stop_expires_at)
                .saturating_sub(self.stop_since)
                .max(0)
        } else {
            0
        };
        self.stopped_secs.saturating_add(running)
    }

    /// Γ(now) = now - G(now): the global clock, still while a PayoutStop is in force.
    pub fn global_now(&self, now: i64) -> i64 {
        now.saturating_sub(self.global_stopped(now))
    }

    /// Ends the stop in force at `now` (folding its elapsed PayoutStop seconds into
    /// stopped_secs) and sets `level` from `now`: for good when Normal, else for STOP_DURATION.
    /// With `keep_later` (an escalation) a stop in force that lapses later than that keeps its
    /// lapse, so raising the level never brings the lapse closer: an IntakeStop the admin extended
    /// past seven days, escalated to PayoutStop, still holds intake until the admin's lapse (the
    /// PayoutStop then lasts as long; only the admin lowers or lifts it).
    pub fn set_stop(&mut self, level: StopState, now: i64, keep_later: bool) {
        let in_force = self.stop_level(now) != StopState::Normal;
        let lapse = self.stop_expires_at;
        self.stopped_secs = self.global_stopped(now);
        self.stop = level;
        self.stop_since = now;
        self.stop_expires_at = if level == StopState::Normal {
            now
        } else if keep_later && in_force {
            now.saturating_add(STOP_DURATION).max(lapse)
        } else {
            now.saturating_add(STOP_DURATION)
        };
    }

    /// Refuses open_escrow, fund, submit_proposal, set_proposal_rules and approve_proposal while
    /// IntakeStop or PayoutStop is in force, and for good once the Config is retired.
    pub fn require_intake(&self, now: i64) -> Result<()> {
        require!(!self.retired, EscrowError::Retired);
        require!(
            self.stop_level(now) == StopState::Normal,
            EscrowError::IntakeStopped
        );
        Ok(())
    }

    /// One more escrow opened under this Config (open_escrow, approve_proposal).
    pub fn escrow_opened(&mut self) -> Result<()> {
        self.live_escrows = self
            .live_escrows
            .checked_add(1)
            .ok_or(EscrowError::MathOverflow)?;
        Ok(())
    }

    /// Refuses a payout step (claim, refund, settle, arbiter_resolve) while a PayoutStop is in
    /// force (PayoutStopped) or the guardian's freeze of `escrow` is (EscrowFrozen).
    pub fn require_payouts(&self, escrow: &Escrow, now: i64) -> Result<()> {
        require!(
            self.stop_level(now) != StopState::PayoutStop,
            EscrowError::PayoutStopped
        );
        require!(
            !escrow.is_frozen(self.global_now(now)),
            EscrowError::EscrowFrozen
        );
        Ok(())
    }

    // ------------------------------------------------------------------- the flow bucket

    /// Refills the bucket to wall time `now`: flow_capacity per flow_period, never past capacity.
    /// A `now` behind flow_updated_at (the cluster's stake-weighted clock may read earlier than it
    /// did) adds nothing and leaves flow_updated_at where it is: moving it back would let the next
    /// refill credit the same seconds a second time.
    pub fn refill(&mut self, now: i64) -> Result<()> {
        let elapsed = now.saturating_sub(self.flow_updated_at).max(0);
        let period =
            u128::try_from(self.flow_period.max(1)).map_err(|_| EscrowError::MathOverflow)?;
        let added = u128::from(self.flow_capacity)
            .checked_mul(u128::try_from(elapsed).map_err(|_| EscrowError::MathOverflow)?)
            .ok_or(EscrowError::MathOverflow)?
            / period;
        let level = u128::from(self.flow_level)
            .saturating_add(added)
            .min(u128::from(self.flow_capacity));
        self.flow_level = u64::try_from(level).map_err(|_| EscrowError::MathOverflow)?;
        self.flow_updated_at = self.flow_updated_at.max(now);
        Ok(())
    }

    /// Takes `amount` from the bucket, refilled to `now` first (FlowLimitExceeded when it holds
    /// less).
    ///
    /// The bucket refills on wall time, while claim_deadline runs on the escrow clock, and neither
    /// knows the other: a bucket that cannot pay the claims due in one claim window (it pays
    /// flow_capacity at once, then flow_capacity per flow_period) turns claimants away until their
    /// claim_deadline passes and their prizes lapse into refund, so ops size it at or above the
    /// claims due in one claim window (the README's incident runbook).
    pub fn take_flow(&mut self, amount: u64, now: i64) -> Result<()> {
        self.refill(now)?;
        self.flow_level = self
            .flow_level
            .checked_sub(amount)
            .ok_or(EscrowError::FlowLimitExceeded)?;
        Ok(())
    }

    // ------------------------------------------------------------------- caps

    /// Adds `amount` to what one escrow holds (`deposited` before it) and to open_value, held to
    /// C_e (EscrowCapExceeded) and, with what proposals awaiting review hold, to C_g:
    /// open_value + pending_value + amount <= global_cap (GlobalCapExceeded), so a direct open or
    /// a fund never takes the room a pending proposal holds. Returns the escrow's new deposited.
    pub fn deposit(&mut self, deposited: u64, amount: u64) -> Result<u64> {
        let escrow_total = deposited
            .checked_add(amount)
            .filter(|total| *total <= self.escrow_cap)
            .ok_or(EscrowError::EscrowCapExceeded)?;
        let open_value = self
            .open_value
            .checked_add(amount)
            .filter(|open| {
                open.checked_add(self.pending_value)
                    .is_some_and(|held| held <= self.global_cap)
            })
            .ok_or(EscrowError::GlobalCapExceeded)?;
        self.open_value = open_value;
        Ok(escrow_total)
    }

    /// Takes a refunded escrow's deposit off open_value (never below zero: a refund is never
    /// refused for the counter's sake). Only refund calls it: an escrow paid out in full still
    /// counts against global_cap until its refund runs after claim_deadline (the server's refund
    /// job sends it then).
    pub fn release(&mut self, deposited: u64) {
        self.open_value = self.open_value.saturating_sub(deposited);
    }

    /// Adds a submitted proposal's deposit `amount` to pending_value: the one escrow it would open
    /// within C_e (EscrowCapExceeded), the proposals awaiting review within pending_cap
    /// (PendingCapExceeded), and open_value + pending_value + amount within C_g
    /// (GlobalCapExceeded).
    pub fn reserve_pending(&mut self, amount: u64) -> Result<()> {
        require!(amount <= self.escrow_cap, EscrowError::EscrowCapExceeded);
        let pending_value = self
            .pending_value
            .checked_add(amount)
            .filter(|pending| *pending <= self.pending_cap)
            .ok_or(EscrowError::PendingCapExceeded)?;
        require!(
            pending_value
                .checked_add(self.open_value)
                .is_some_and(|held| held <= self.global_cap),
            EscrowError::GlobalCapExceeded
        );
        self.pending_value = pending_value;
        Ok(())
    }

    /// Moves an approved proposal's deposit `amount` from pending_value to open_value, the one
    /// escrow it opens held to today's C_e (EscrowCapExceeded): the approval opens an escrow, and
    /// no escrow opens over the per-escrow cap in force, however it was submitted (the curator
    /// rejects instead). Its room under C_g was taken at submit (reserve_pending), so
    /// open_value + pending_value does not move and C_g is not read again: a C_g lowered since
    /// refuses only new deposits, as it does for open escrows. pending_value always holds the
    /// amount (only reserve_pending adds to it), so the subtraction never saturates (MathOverflow
    /// if it ever could not).
    pub fn approve_pending(&mut self, amount: u64) -> Result<()> {
        require!(amount <= self.escrow_cap, EscrowError::EscrowCapExceeded);
        self.pending_value = self
            .pending_value
            .checked_sub(amount)
            .ok_or(EscrowError::MathOverflow)?;
        self.open_value = self
            .open_value
            .checked_add(amount)
            .ok_or(EscrowError::MathOverflow)?;
        Ok(())
    }

    /// Takes a returned proposal's deposit `amount` off pending_value (never below zero, as
    /// release: a return to the sponsor is never refused for the counter's sake).
    pub fn release_pending(&mut self, amount: u64) {
        self.pending_value = self.pending_value.saturating_sub(amount);
    }

    // ------------------------------------------------------------------- the proposal policy

    /// Names `curator` (Pubkey::default(): proposals off) and the pending cap. A curator is a key
    /// of its own: never the admin, the guardian or the arbiter (CuratorNotIndependent), and never
    /// a revoked key (KeyRevoked), which could sign nothing in the role. Proposals already
    /// submitted stay as they are: the new curator reviews them, the old one no longer can.
    pub fn set_proposal_policy(&mut self, curator: Pubkey, pending_cap: u64) -> Result<()> {
        if curator != Pubkey::default() {
            self.require_not_revoked(&curator)?;
            require!(
                curator != self.admin && curator != self.guardian && curator != self.arbiter,
                EscrowError::CuratorNotIndependent
            );
        }
        self.curator = curator;
        self.pending_cap = pending_cap;
        Ok(())
    }

    /// Refuses `signer` unless it is the curator: none named (ProposalsDisabled), another key
    /// (UnauthorizedCurator), or the curator's key revoked (KeyRevoked).
    pub fn require_curator(&self, signer: &Pubkey) -> Result<()> {
        require!(
            self.curator != Pubkey::default(),
            EscrowError::ProposalsDisabled
        );
        require!(*signer == self.curator, EscrowError::UnauthorizedCurator);
        self.require_not_revoked(signer)
    }

    /// Whether `key` is the curator (a key is: Pubkey::default() never is).
    pub fn is_curator(&self, key: &Pubkey) -> bool {
        self.curator != Pubkey::default() && *key == self.curator
    }

    /// What a proposal's terms are held to on top of check_terms_policy, at the submit and again at
    /// the approval against today's curator, since its sponsor (off the allowlist) chose them and
    /// the program cannot read whose key a resolver is (the #852 audit's P2-1 and P3-1; the house's
    /// own check, that the terms are exactly the ones it composes for the competition, is the
    /// server's):
    /// - the sponsor is not the curator (SponsorIsCurator): one signature would submit and approve;
    /// - neither the resolver nor the compliance key is the sponsor or the curator
    ///   (ProposalRoleNotIndependent): a sponsor as its own resolver posts what it likes, as its own
    ///   compliance key holds every winner until the pot refunds to it, and the curator as either
    ///   would hold a role in an escrow it approved;
    /// - resolve_deadline - final_end is at least MIN_RESOLVE_WINDOW (ResolveWindowTooShort): past
    ///   resolve_deadline no result can be posted and the whole pot refunds to the sponsor;
    /// - bond_lamports is at most MAX_PROPOSAL_BOND (ProposalBondTooHigh): a bond the resolver
    ///   cannot post is the same refund, and one no entrant can afford leaves a result unchallenged.
    ///
    /// The terms passed EscrowTerms::validate first, so final_end < resolve_deadline and the
    /// subtraction cannot overflow (MathOverflow if it ever could).
    pub fn check_proposal_terms(&self, sponsor: &Pubkey, terms: &EscrowTerms) -> Result<()> {
        require!(!self.is_curator(sponsor), EscrowError::SponsorIsCurator);
        for role in [&terms.resolver, &terms.compliance] {
            require!(
                role != sponsor && !self.is_curator(role),
                EscrowError::ProposalRoleNotIndependent
            );
        }
        let window = terms
            .resolve_deadline
            .checked_sub(terms.final_end)
            .ok_or(EscrowError::MathOverflow)?;
        require!(
            window >= MIN_RESOLVE_WINDOW,
            EscrowError::ResolveWindowTooShort
        );
        require!(
            terms.bond_lamports <= MAX_PROPOSAL_BOND,
            EscrowError::ProposalBondTooHigh
        );
        Ok(())
    }

    // ------------------------------------------------------------------- the open policy

    /// What open_escrow (and submit_proposal and approve_proposal, for the escrow a proposal
    /// opens) holds `terms` to on top of EscrowTerms::validate, each its own error: the mint on
    /// the allowlist (MintNotAllowed), the sponsor too when `sponsor_allowlisted`
    /// (SponsorNotAllowed: open_escrow passes true; a proposal passes false, since the curator's
    /// co-signature, given after the house screened the sponsor, stands in for the sponsor
    /// allowlist, and waives nothing else), refund_to
    /// the sponsor (RefundToNotSponsor), the arbiter Config's (ArbiterNotConfig), a compliance key
    /// (ComplianceRequired), neither the resolver nor the compliance key the address of the
    /// `escrow` being opened (RoleIsEscrow: a PDA of this program that it never signs for, so
    /// post_result, holds and co-signatures could never land and every claim would clear unheld
    /// on the lapse path), the bond at least min_bond (BondBelowMin), each window at least its
    /// floor (WindowBelowFloor; the challenge window's floor is waived when `sponsor_allowlisted`
    /// and the sponsor is a house sponsor, Config::is_house_sponsor: open_escrow's house path,
    /// which a proposal never takes), at least min_regraders regraders (PanelTooSmall), every regrader
    /// registered (RegraderNotRegistered), at most max_house_regraders of them the house's
    /// (TooManyHouseRegraders), no resolver or compliance key among them
    /// (RegraderNotIndependent), and no key revoked (KeyRevoked).
    ///
    /// max_house_regraders is the admin's: bootstrap sets it to the panel's size (an all-house
    /// panel, owner decision #541), so today the allowance refuses nothing, the house's keys hold
    /// every panel's quorum, and the guardian's escalation inside the challenge and attest windows
    /// (breakers::handle_escalate) is what stands between a server compromise and the pot. A later
    /// Config lowers it below a majority (set_limits). min_regraders is the admin's too: 1 by
    /// default (#541), so a one-regrader panel, whose one vote decides a dispute, is allowed until
    /// the admin raises the floor (set_min_regraders), with no upgrade.
    pub fn check_terms_policy(
        &self,
        sponsor: &Pubkey,
        mint: &Pubkey,
        escrow: &Pubkey,
        terms: &EscrowTerms,
        sponsor_allowlisted: bool,
    ) -> Result<()> {
        require!(self.mints.contains(mint), EscrowError::MintNotAllowed);
        require!(
            !sponsor_allowlisted || self.sponsors.contains(sponsor),
            EscrowError::SponsorNotAllowed
        );
        require!(terms.refund_to == *sponsor, EscrowError::RefundToNotSponsor);
        require!(terms.arbiter == self.arbiter, EscrowError::ArbiterNotConfig);
        require!(
            terms.compliance != Pubkey::default(),
            EscrowError::ComplianceRequired
        );
        require!(
            terms.resolver != *escrow && terms.compliance != *escrow,
            EscrowError::RoleIsEscrow
        );
        require!(
            terms.bond_lamports >= self.min_bond,
            EscrowError::BondBelowMin
        );
        let challenge_floor = if sponsor_allowlisted && self.is_house_sponsor(sponsor) {
            0
        } else {
            self.min_challenge_window
        };
        for (window, floor) in [
            (terms.challenge_window, challenge_floor),
            (terms.attest_window, self.min_attest_window),
            (terms.hold_window, self.min_hold_window),
            (terms.claim_window, self.min_claim_window),
        ] {
            require!(window >= floor, EscrowError::WindowBelowFloor);
        }
        require!(
            terms.regraders.len() >= usize::from(self.min_regraders),
            EscrowError::PanelTooSmall
        );
        let mut house = 0u8;
        for regrader in &terms.regraders {
            let entry = self
                .regrader(regrader)
                .ok_or(EscrowError::RegraderNotRegistered)?;
            house = house.saturating_add(u8::from(entry.house));
        }
        require!(
            house <= self.max_house_regraders,
            EscrowError::TooManyHouseRegraders
        );
        require!(
            !terms.regraders.contains(&terms.resolver)
                && !terms.regraders.contains(&terms.compliance),
            EscrowError::RegraderNotIndependent
        );
        for key in [sponsor, &terms.resolver, &terms.compliance]
            .into_iter()
            .chain(terms.regraders.iter())
        {
            self.require_not_revoked(key)?;
        }
        Ok(())
    }

    /// How many of `regraders` the registry marks as the house's.
    pub fn house_count(&self, regraders: &[Pubkey]) -> u8 {
        regraders
            .iter()
            .filter(|key| self.regrader(key).is_some_and(|e| e.house))
            .count()
            .try_into()
            .unwrap_or(u8::MAX)
    }
}

/// The escrow clock at wall time `now`: wall time minus the seconds `escrow` has been stopped (by
/// a global PayoutStop since it opened, or its own guardian freeze), counted once when both
/// overlap. Every deadline comparison goes through it.
pub fn escrow_now(escrow: &Escrow, config: &Config, now: i64) -> i64 {
    let global_now = config.global_now(now);
    global_now
        .saturating_add(escrow.stop_base)
        .saturating_sub(escrow.frozen_secs_at(global_now))
}

/// The wall clock, for the stop and the bucket, and the escrow clock, for every deadline.
pub fn clocks(escrow: &Escrow, config: &Config) -> Result<(i64, i64)> {
    let wall = Clock::get()?.unix_timestamp;
    Ok((wall, escrow_now(escrow, config, wall)))
}

const _: () = assert!(MAX_REVOKED > 0 && MAX_REGISTRY >= MAX_REGRADERS as usize);
const _: () = assert!(
    MAX_SPONSORS <= u32::BITS as usize,
    "Config.house_sponsors holds one bit per sponsor"
);
