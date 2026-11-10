use anchor_lang::prelude::*;

/// Every error the program returns. Codes start at 6000 in declaration order and are part of the
/// wire interface (the generated client and the server read them): append, never reorder.
#[error_code]
pub enum EscrowError {
    #[msg("The signer is not this escrow's resolver")]
    UnauthorizedResolver,
    #[msg("The signer is not this escrow's arbiter")]
    UnauthorizedArbiter,
    #[msg("The signer is not one of this escrow's regraders")]
    NotARegrader,
    #[msg("The escrow's status does not allow this instruction")]
    InvalidStatus,
    #[msg("The challenge window has closed")]
    ChallengeWindowClosed,
    #[msg("The claim window has closed")]
    ClaimWindowClosed,
    #[msg("The claim window has not elapsed yet")]
    ClaimWindowNotElapsed,
    #[msg("The deadline this instruction waits for has not been reached")]
    DeadlineNotReached,
    #[msg("The attestation window is still open")]
    AttestWindowOpen,
    #[msg("The attestation window has closed")]
    AttestWindowClosed,
    #[msg("The vault holds less than the escrow total")]
    Underfunded,
    #[msg("The vault holds more than the escrow total")]
    Overfunded,
    #[msg("The total is zero or more than the vault holds")]
    TotalMismatch,
    #[msg("The merkle proof does not verify against the payout root")]
    InvalidMerkleProof,
    #[msg("The merkle proof is longer than MAX_PROOF_LEN")]
    ProofTooDeep,
    #[msg("This allocation has already been claimed in full")]
    AlreadyClaimed,
    #[msg("The amount exceeds what is left of this allocation")]
    ExceedsAllocation,
    #[msg("Nothing is left to claim")]
    NothingToClaim,
    #[msg("The mint is not this escrow's mint")]
    MintMismatch,
    #[msg("The mint's decimals do not match the escrow's")]
    DecimalsMismatch,
    #[msg("Only the classic SPL Token program is supported")]
    UnsupportedTokenProgram,
    #[msg("The bond is not the escrow's bond amount")]
    BondMismatch,
    #[msg("The result hash is not one this instruction accepts")]
    InvalidResultHash,
    #[msg("The regrader set is invalid: it needs 1 <= k <= n <= 5, 2k > n and distinct keys")]
    InvalidRegraderSet,
    #[msg("Neither result has reached the quorum")]
    NoQuorum,
    #[msg("Arithmetic overflow")]
    MathOverflow,
    #[msg("The escrow is closed")]
    EscrowClosed,
    #[msg("The vault is empty: nothing to refund")]
    NothingToRefund,
    #[msg("This claim is held for compliance")]
    HeldForCompliance,
    #[msg("The claim is not cleared: it needs the compliance co-signature, or a request whose hold window has passed")]
    NotCleared,
    #[msg("The hold window after the claim request has not passed yet")]
    HoldWindowOpen,
    #[msg("The entries root has already been committed")]
    EntriesAlreadyCommitted,
    #[msg("The signer is not this escrow's sponsor")]
    UnauthorizedSponsor,
    #[msg("The signer is not this escrow's compliance key")]
    UnauthorizedCompliance,
    #[msg("The deadlines must be in the future and in order: entries deadline <= final end < resolve deadline")]
    InvalidDeadlines,
    #[msg("A window is below its minimum or above MAX_WINDOW")]
    InvalidWindow,
    #[msg("The amount must be greater than zero")]
    InvalidAmount,
    #[msg("The hold reason is not one of sanctions, geo, tax form required or review")]
    InvalidHoldReason,
    #[msg("The entries deadline has passed")]
    EntriesWindowClosed,
    #[msg("The resolve deadline has passed")]
    ResolveWindowClosed,
    #[msg("This claim is not held")]
    NotHeld,
    #[msg("This claim has already been requested")]
    AlreadyRequested,
    #[msg("The competition's final phase has not ended yet")]
    FinalNotEnded,
    #[msg("The entries root has not been committed")]
    EntriesNotCommitted,
    #[msg("With a compliance key, the claim window must be longer than the hold window")]
    ClaimWindowTooShort,
    #[msg("The hard deadline must be at least every window and ARBITER_SLACK after the resolve deadline")]
    HardDeadlineTooEarly,
    #[msg("The bond is below the floor: BOND_FLOOR_RENTS times the rent-exempt minimum of an empty account")]
    BondBelowFloor,
    #[msg("The challenge account is not this escrow's challenge of that commitment, or its challenger account is not its challenger")]
    ChallengeMismatch,
    #[msg("No named regrader voted for this alternative: the arbiter chooses the posted result or an alternative a regrader backed")]
    AlternativeUnbacked,
    #[msg("Only the program's upgrade authority can initialise the config")]
    NotUpgradeAuthority,
    #[msg("The signer is not the config's admin")]
    UnauthorizedAdmin,
    #[msg("The signer is neither the config's guardian nor its admin")]
    UnauthorizedGuardian,
    #[msg("The signer is not the admin the config's admin proposed")]
    NotPendingAdmin,
    #[msg("A config value is out of bounds")]
    InvalidConfig,
    #[msg("This key is revoked: its signature is refused everywhere until the admin unrevokes it")]
    KeyRevoked,
    #[msg("The admin's key cannot be revoked")]
    CannotRevokeAdmin,
    #[msg("This key is already revoked")]
    AlreadyRevoked,
    #[msg("This key is not revoked")]
    NotRevoked,
    #[msg("The list is full")]
    ListFull,
    #[msg("The key is already on the list")]
    AlreadyListed,
    #[msg("The key is not on the list")]
    NotListed,
    #[msg(
        "Intake is stopped: open_escrow and fund are refused until the stop is lifted or lapses"
    )]
    IntakeStopped,
    #[msg("Payouts are stopped: claim, refund, settle and arbiter_resolve are refused until the stop is lifted or lapses")]
    PayoutStopped,
    #[msg("The guardian has frozen this escrow: claim, refund, settle and arbiter_resolve are refused until the admin unfreezes it or the freeze lapses")]
    EscrowFrozen,
    #[msg("The guardian may only raise the stop level")]
    NotAnEscalation,
    #[msg("No stop is in force")]
    NotStopped,
    #[msg("This escrow is already frozen")]
    AlreadyFrozen,
    #[msg("This escrow is not frozen")]
    NotFrozen,
    #[msg("The mint is not on the config's mint allowlist")]
    MintNotAllowed,
    #[msg("The sponsor is not on the config's sponsor allowlist")]
    SponsorNotAllowed,
    #[msg("refund_to must be the sponsor")]
    RefundToNotSponsor,
    #[msg("The arbiter must be the config's arbiter")]
    ArbiterNotConfig,
    #[msg("A compliance key is required")]
    ComplianceRequired,
    #[msg("The bond is below the config's minimum bond")]
    BondBelowMin,
    #[msg("A window is below the config's floor for it")]
    WindowBelowFloor,
    #[msg("A regrader is not in the config's regrader registry")]
    RegraderNotRegistered,
    #[msg("More house regraders than the config allows")]
    TooManyHouseRegraders,
    #[msg("The resolver and the compliance key cannot be regraders")]
    RegraderNotIndependent,
    #[msg("The escrow would hold more than the config's per-escrow cap")]
    EscrowCapExceeded,
    #[msg("Open escrows would hold more than the config's global cap")]
    GlobalCapExceeded,
    #[msg("The claim is over what the flow limit allows now: claim less, or wait for the bucket to refill")]
    FlowLimitExceeded,
    #[msg("The escrow's vault token account is frozen by the mint's freeze authority")]
    VaultFrozen,
    #[msg("The claimant's token account is frozen by the mint's freeze authority")]
    ClaimantAccountFrozen,
    #[msg("refund_to's token account is frozen by the mint's freeze authority")]
    RefundAccountFrozen,
    #[msg("The sponsor's token account is frozen by the mint's freeze authority")]
    SponsorAccountFrozen,
    #[msg("The reveal does not match the commit: sha256(alt_commitment || challenger || salt) differs")]
    CommitMismatch,
    #[msg("A reveal must land in a slot after its commit's")]
    RevealTooEarly,
    #[msg("The reveal window (challenge_deadline + reveal_grace) has closed")]
    RevealWindowClosed,
    #[msg("A committed challenge may still be revealed: settle waits for challenge_deadline + reveal_grace")]
    CommitsPendingReveal,
    #[msg("The key is not this escrow's holder of that role")]
    RoleMismatch,
    #[msg("This regrader has already voted: its seat cannot be rotated")]
    RegraderAlreadyVoted,
    #[msg("The dispute's quorum is recorded and binds: settle applies it, so the escrow is never refunded from Disputed, nor escalated once settle may apply it")]
    QuorumRecorded,
    #[msg("An alternative a quorum backed overturns the posted result only once the attest window has ended (attest_deadline): until then the guardian may escalate it to the arbiter")]
    OverturnWindowOpen,
    #[msg(
        "The resolver and the compliance key cannot be the escrow's own address, which never signs"
    )]
    RoleIsEscrow,
    #[msg("An entries root commits at least one entry: entries_count is zero")]
    NoEntries,
    #[msg("The posted result's challenge window is over with no challenge: the result binds (settle makes it Claimable), so it is no longer escalated")]
    UnchallengedResultBinds,
    #[msg("The escrow names fewer regraders than the config's min_regraders")]
    PanelTooSmall,
    #[msg("Proposals are off: the config names no curator")]
    ProposalsDisabled,
    #[msg("The signer is not the config's curator")]
    UnauthorizedCurator,
    #[msg("Proposals awaiting review would hold more than the config's pending cap")]
    PendingCapExceeded,
    #[msg("The review deadline must be in the future, at most MAX_REVIEW_WINDOW after the submit, and no later than opens_at, which is before the entries deadline")]
    ReviewWindowInvalid,
    #[msg("The review deadline has passed: the proposal can only be returned")]
    ReviewWindowClosed,
    #[msg("The sponsor is revoked: its proposal is held, neither approved nor returned, until the admin unrevokes it")]
    SponsorRevoked,
    #[msg("An escrow already exists at this sponsor's competition id")]
    EscrowExists,
    #[msg("The curator must be a key of its own: not the admin, the guardian or the arbiter")]
    CuratorNotIndependent,
    #[msg("A rejection names the sha256 of its reason; a withdrawal or an expiry names none")]
    InvalidCloseReason,
    #[msg("The curator cannot sponsor a proposal: it would approve its own")]
    SponsorIsCurator,
    #[msg("A proposal's resolver and compliance key must be neither its sponsor nor the curator")]
    ProposalRoleNotIndependent,
    #[msg("A proposal's resolve window (resolve_deadline - final_end) is shorter than MIN_RESOLVE_WINDOW")]
    ResolveWindowTooShort,
    #[msg("A proposal's bond is over MAX_PROPOSAL_BOND")]
    ProposalBondTooHigh,
    #[msg("The config is retired: no escrow opens, is funded or is proposed under it again")]
    Retired,
    #[msg("Only a retired config's escrows and the config itself are closed")]
    NotRetired,
    #[msg("A challenge still holds its bond in the escrow: close every challenge first")]
    ChallengesOutstanding,
    #[msg("A commit still holds its bond in the escrow: close every commit first")]
    CommitsOutstanding,
    #[msg("The config still counts value in open escrows or pending proposals")]
    ValueOutstanding,
    #[msg("The config still counts an escrow not closed")]
    EscrowsOutstanding,
    #[msg("The proposal's rules hash is all zero: the curator sets it before approving")]
    RulesNotSet,
    #[msg("The proposal's rules hash is already set: it is written once")]
    RulesAlreadySet,
}
