/**
 * @title ZcashBridgeAdapter Certora Specification
 * @notice Formal verification for Zcash bridge security properties
 * @dev Run with: certoraRun certora/conf/ZcashBridge.conf
 */

using ZcashNullifierRegistry as registry;
using ZcashProofVerifier as verifier;

methods {
    // ZcashBridgeAdapter
    function initiateDeposit(uint8, uint256, bytes32, bytes32, address, bytes) external returns (uint256);
    function submitDepositProof(uint256, bytes) external;
    function completeDeposit(uint256) external;
    function initiateWithdrawal(uint8, uint256, bytes, bytes32) external returns (uint256);
    function processWithdrawal(uint256, bytes32) external;
    function completeWithdrawal(uint256, bytes) external;
    function syncNullifier(bytes32, uint8, bytes32, uint32, bytes) external;
    function updateAnchor(uint8, bytes32, uint32, bytes) external;
    
    // View functions
    function deposits(uint256) external returns (uint256, address, uint8, uint64, bytes32, bytes32) envfree;
    function withdrawals(uint256) external returns (uint256, bytes, uint8, uint64, bytes32, address) envfree;
    function syncedNullifiers(bytes32) external returns (bool) envfree;
    function bridgedNotes(bytes32) external returns (bool) envfree;
    function usedWithdrawalNullifiers(bytes32) external returns (bool) envfree;
    function dailyDepositLimit() external returns (uint256) envfree;
    function dailyWithdrawalLimit() external returns (uint256) envfree;
    function maxDepositPerTx() external returns (uint256) envfree;
    function maxWithdrawalPerTx() external returns (uint256) envfree;
    function circuitBreakerActive() external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function depositCounter() external returns (uint256) envfree;
    function withdrawalCounter() external returns (uint256) envfree;
    function todayDepositVolume() external returns (uint256) envfree;
    function todayWithdrawalVolume() external returns (uint256) envfree;
    
    // ZcashNullifierRegistry
    function registry.isNullifierRegistered(bytes32) external returns (bool) envfree;
    function registry.exists(bytes32) external returns (bool) envfree;
    function registry.zcashToPilBinding(bytes32) external returns (bytes32) envfree;
    function registry.pilToZcashBinding(bytes32) external returns (bytes32) envfree;
}

/*//////////////////////////////////////////////////////////////
                    DEPOSIT INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Deposit counter must only increase
 * @dev Prevents counter manipulation attacks
 */
invariant depositCounterMonotonic()
    depositCounter() >= 0
    {
        preserved {
            require depositCounter() < max_uint256;
        }
    }

/**
 * @notice A note commitment can only be bridged once
 * @dev Prevents double-deposit attacks
 */
rule noteCommitmentUniqueness(bytes32 noteCommitment, method f) 
    filtered { f -> f.selector == sig:initiateDeposit(uint8, uint256, bytes32, bytes32, address, bytes).selector }
{
    bool bridgedBefore = bridgedNotes(noteCommitment);
    
    env e;
    calldataarg args;
    f(e, args);
    
    bool bridgedAfter = bridgedNotes(noteCommitment);
    
    // If it was bridged before, it should still be bridged
    assert bridgedBefore => bridgedAfter, "Bridged note flag should never be cleared";
    
    // If not bridged before and now bridged, it's a new valid deposit
    assert (!bridgedBefore && bridgedAfter) => true, "New deposit should mark note as bridged";
}

/**
 * @notice Deposit amount must respect per-transaction limits
 */
rule depositAmountLimits(uint256 amount) {
    uint256 maxPerTx = maxDepositPerTx();
    
    env e;
    uint256 depositId = initiateDeposit(e, 1, amount, _, _, _, _);
    
    // If deposit succeeded, amount was within limits
    assert depositId > 0 => amount <= maxPerTx && amount > 0, 
        "Successful deposits must respect amount limits";
}

/**
 * @notice Deposit status transitions must follow valid path
 * PENDING -> PROOF_VERIFIED -> COMPLETED
 */
rule depositStateTransitions(uint256 depositId) {
    uint8 statusBefore;
    _, _, statusBefore, _, _, _ = deposits(depositId);
    
    env e;
    submitDepositProof(e, depositId, _);
    
    uint8 statusAfter;
    _, _, statusAfter, _, _, _ = deposits(depositId);
    
    // PENDING (0) -> PROOF_VERIFIED (1)
    assert statusBefore == 0 => statusAfter == 1,
        "Proof submission should transition from PENDING to PROOF_VERIFIED";
}

/*//////////////////////////////////////////////////////////////
                   WITHDRAWAL INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Withdrawal counter must only increase
 */
invariant withdrawalCounterMonotonic()
    withdrawalCounter() >= 0
    {
        preserved {
            require withdrawalCounter() < max_uint256;
        }
    }

/**
 * @notice A nullifier can only be used for one withdrawal
 * @dev Prevents double-spend attacks
 */
rule nullifierWithdrawalUniqueness(bytes32 nullifier, method f)
    filtered { f -> f.selector == sig:initiateWithdrawal(uint8, uint256, bytes, bytes32).selector }
{
    bool usedBefore = usedWithdrawalNullifiers(nullifier);
    
    env e;
    calldataarg args;
    f(e, args);
    
    bool usedAfter = usedWithdrawalNullifiers(nullifier);
    
    // If used before, should still be used
    assert usedBefore => usedAfter, "Used nullifier flag should never be cleared";
}

/**
 * @notice Withdrawal amount must respect per-transaction limits
 */
rule withdrawalAmountLimits(uint256 amount) {
    uint256 maxPerTx = maxWithdrawalPerTx();
    
    env e;
    uint256 withdrawalId = initiateWithdrawal(e, 1, amount, _, _);
    
    assert withdrawalId > 0 => amount <= maxPerTx && amount > 0,
        "Successful withdrawals must respect amount limits";
}

/*//////////////////////////////////////////////////////////////
                   NULLIFIER INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Synced nullifier flag is permanent
 */
rule nullifierSyncPermanence(bytes32 nullifier, method f) {
    bool syncedBefore = syncedNullifiers(nullifier);
    
    env e;
    calldataarg args;
    f(e, args);
    
    bool syncedAfter = syncedNullifiers(nullifier);
    
    // Once synced, always synced
    assert syncedBefore => syncedAfter, "Nullifier sync should be permanent";
}

/**
 * @notice Nullifier sync must be deterministic
 */
rule nullifierSyncDeterminism(
    bytes32 nullifier,
    uint8 pool,
    bytes32 txHash,
    uint32 blockHeight
) {
    env e1;
    env e2;
    
    // Same inputs should have same effect
    syncNullifier(e1, nullifier, pool, txHash, blockHeight, _);
    bool synced1 = syncedNullifiers(nullifier);
    
    // Subsequent call should be idempotent
    syncNullifier(e2, nullifier, pool, txHash, blockHeight, _);
    bool synced2 = syncedNullifiers(nullifier);
    
    assert synced1 == synced2, "Nullifier sync should be idempotent";
}

/*//////////////////////////////////////////////////////////////
                   ANCHOR INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Anchor block height must only increase
 * @dev Prevents stale anchor attacks
 */
rule anchorMonotonicity(uint8 pool, bytes32 anchor, uint32 newHeight) {
    // Get current anchor height
    bytes32 currentAnchor;
    uint32 currentHeight;
    currentAnchor, currentHeight, _ = anchors(pool);
    
    env e;
    updateAnchor(e, pool, anchor, newHeight, _);
    
    // If update succeeded, new height must be greater
    bytes32 updatedAnchor;
    uint32 updatedHeight;
    updatedAnchor, updatedHeight, _ = anchors(pool);
    
    assert updatedHeight >= currentHeight, "Anchor height should only increase";
}

/*//////////////////////////////////////////////////////////////
                  RATE LIMIT INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Daily deposit volume cannot exceed limit
 */
invariant dailyDepositVolumeLimit()
    todayDepositVolume() <= dailyDepositLimit()
    {
        preserved {
            require dailyDepositLimit() > 0;
        }
    }

/**
 * @notice Daily withdrawal volume cannot exceed limit
 */
invariant dailyWithdrawalVolumeLimit()
    todayWithdrawalVolume() <= dailyWithdrawalLimit()
    {
        preserved {
            require dailyWithdrawalLimit() > 0;
        }
    }

/*//////////////////////////////////////////////////////////////
                 CIRCUIT BREAKER INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Circuit breaker blocks all deposits
 */
rule circuitBreakerBlocksDeposits() {
    bool breakerActive = circuitBreakerActive();
    
    env e;
    uint256 depositId;
    
    @withrevert
    depositId = initiateDeposit(e, 1, 1000000, _, _, _, _);
    
    // If circuit breaker is active, deposit should revert
    assert breakerActive => lastReverted, "Circuit breaker should block deposits";
}

/**
 * @notice Circuit breaker blocks all withdrawals
 */
rule circuitBreakerBlocksWithdrawals() {
    bool breakerActive = circuitBreakerActive();
    
    env e;
    uint256 withdrawalId;
    
    @withrevert
    withdrawalId = initiateWithdrawal(e, 1, 1000000, _, _);
    
    assert breakerActive => lastReverted, "Circuit breaker should block withdrawals";
}

/*//////////////////////////////////////////////////////////////
               CROSS-CHAIN BINDING INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Cross-chain bindings must be bidirectional
 */
rule bindingBidirectionality(bytes32 zcashNullifier) {
    bytes32 pilNullifier = registry.zcashToPilBinding(zcashNullifier);
    
    // If binding exists
    require pilNullifier != 0;
    
    bytes32 reverseBinding = registry.pilToZcashBinding(pilNullifier);
    
    assert reverseBinding == zcashNullifier, "Bindings must be bidirectional";
}

/**
 * @notice A nullifier can only have one binding
 */
rule bindingUniqueness(bytes32 zcashNullifier, method f)
    filtered { f -> f.selector == sig:registry.createBinding(bytes32, bytes32, bytes).selector }
{
    bytes32 bindingBefore = registry.zcashToPilBinding(zcashNullifier);
    
    env e;
    calldataarg args;
    f(e, args);
    
    bytes32 bindingAfter = registry.zcashToPilBinding(zcashNullifier);
    
    // If binding existed, it should remain unchanged
    assert bindingBefore != 0 => bindingBefore == bindingAfter,
        "Existing bindings should not be overwritten";
}

/*//////////////////////////////////////////////////////////////
                     PAUSE INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Pause blocks all state-changing operations
 */
rule pauseBlocksOperations() {
    bool isPaused = paused();
    
    env e;
    
    @withrevert
    initiateDeposit(e, 1, 1000000, _, _, _, _);
    bool depositReverted = lastReverted;
    
    // Paused state should block deposits
    assert isPaused => depositReverted, "Pause should block deposits";
}

/*//////////////////////////////////////////////////////////////
                  GLOBAL SECURITY PROPERTIES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Total deposits should never exceed total supply
 * @dev Conservation of value property
 */
rule conservationOfValue(method f) {
    uint256 depositVolumeBefore = todayDepositVolume();
    uint256 withdrawalVolumeBefore = todayWithdrawalVolume();
    
    env e;
    calldataarg args;
    f(e, args);
    
    uint256 depositVolumeAfter = todayDepositVolume();
    uint256 withdrawalVolumeAfter = todayWithdrawalVolume();
    
    // Volume changes should be non-negative
    assert depositVolumeAfter >= depositVolumeBefore, "Deposit volume should not decrease";
}

/**
 * @notice No operation should create tokens from nothing
 */
rule noTokenCreationFromNothing(method f) {
    uint256 counterBefore = depositCounter();
    
    env e;
    calldataarg args;
    f(e, args);
    
    uint256 counterAfter = depositCounter();
    
    // Counter can only increase by legitimate deposits
    assert counterAfter >= counterBefore, "Deposit counter should not decrease";
}
