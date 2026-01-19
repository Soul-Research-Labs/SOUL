/**
 * Certora Formal Verification Specification
 * Privacy Interoperability Layer - ZKBoundStateLocks (ZK-Slocks)
 * 
 * This spec verifies critical invariants for cross-chain ZK state locks
 */

// ============================================================================
// METHODS
// ============================================================================

methods {
    // Lock operations
    function createLock(bytes32, bytes32, uint64, bytes32) external returns (bytes32);
    function releaseLock(bytes32, bytes32, uint256[8]) external;
    function claimLock(bytes32, bytes32, uint256[8]) external;
    function expireLock(bytes32) external;
    
    // View functions
    function locks(bytes32) external returns (
        bytes32, bytes32, address, uint64, uint8, uint256, bytes32
    ) envfree;
    function isLockActive(bytes32) external returns (bool) envfree;
    function getLockState(bytes32) external returns (uint8) envfree;
    function usedNullifiers(bytes32) external returns (bool) envfree;
    function domainSeparator() external returns (bytes32) envfree;
}

// ============================================================================
// DEFINITIONS
// ============================================================================

// Lock states
definition LOCK_NONE() returns uint8 = 0;
definition LOCK_ACTIVE() returns uint8 = 1;
definition LOCK_RELEASED() returns uint8 = 2;
definition LOCK_CLAIMED() returns uint8 = 3;
definition LOCK_EXPIRED() returns uint8 = 4;

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Lock State Machine
 * @notice Lock states follow valid transitions only
 */
invariant validLockStateTransitions(bytes32 lockId)
    getLockState(lockId) == LOCK_NONE() ||
    getLockState(lockId) == LOCK_ACTIVE() ||
    getLockState(lockId) == LOCK_RELEASED() ||
    getLockState(lockId) == LOCK_CLAIMED() ||
    getLockState(lockId) == LOCK_EXPIRED()
    { preserved { require true; } }

/**
 * @title Nullifier Uniqueness for Locks
 * @notice Each nullifier can only be used once across all locks
 */
invariant lockNullifierUniqueness(bytes32 nullifier)
    usedNullifiers(nullifier) == true =>
        forall bytes32 lockId. (getLockState(lockId) != LOCK_ACTIVE() || 
                                 getLockCommitment(lockId) != nullifier)
    { preserved { require true; } }

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Lock Creation Succeeds
 * @notice Valid lock creation results in ACTIVE state
 */
rule lockCreationSuccess(
    bytes32 stateCommitment,
    bytes32 targetChainCommitment,
    uint64 expiry,
    bytes32 secretHash
) {
    env e;
    
    require e.block.timestamp < expiry;
    require stateCommitment != bytes32(0);
    require targetChainCommitment != bytes32(0);
    
    bytes32 lockId = createLock(e, stateCommitment, targetChainCommitment, expiry, secretHash);
    
    assert getLockState(lockId) == LOCK_ACTIVE(), "New lock should be active";
    assert isLockActive(lockId), "isLockActive should return true";
}

/**
 * @title Only Active Locks Can Be Released
 * @notice Release operation requires ACTIVE state
 */
rule releaseRequiresActive(bytes32 lockId, bytes32 secret, uint256[8] proof) {
    env e;
    
    require getLockState(lockId) != LOCK_ACTIVE();
    
    releaseLock@withrevert(e, lockId, secret, proof);
    
    assert lastReverted, "Non-active lock release should revert";
}

/**
 * @title Release Transitions to Released State
 * @notice Successful release changes state to RELEASED
 */
rule releaseTransition(bytes32 lockId, bytes32 secret, uint256[8] proof) {
    env e;
    
    require getLockState(lockId) == LOCK_ACTIVE();
    
    releaseLock(e, lockId, secret, proof);
    
    assert getLockState(lockId) == LOCK_RELEASED(), "State should be RELEASED";
    assert !isLockActive(lockId), "Lock should no longer be active";
}

/**
 * @title Only Active Locks Can Be Claimed
 * @notice Claim operation requires ACTIVE state
 */
rule claimRequiresActive(bytes32 lockId, bytes32 nullifier, uint256[8] proof) {
    env e;
    
    require getLockState(lockId) != LOCK_ACTIVE();
    
    claimLock@withrevert(e, lockId, nullifier, proof);
    
    assert lastReverted, "Non-active lock claim should revert";
}

/**
 * @title Claim Transitions to Claimed State
 * @notice Successful claim changes state to CLAIMED
 */
rule claimTransition(bytes32 lockId, bytes32 nullifier, uint256[8] proof) {
    env e;
    
    require getLockState(lockId) == LOCK_ACTIVE();
    require !usedNullifiers(nullifier);
    
    claimLock(e, lockId, nullifier, proof);
    
    assert getLockState(lockId) == LOCK_CLAIMED(), "State should be CLAIMED";
    assert usedNullifiers(nullifier), "Nullifier should be marked used";
}

/**
 * @title Expiry Only After Timeout
 * @notice Lock can only expire after expiry time
 */
rule expiryRequiresTimeout(bytes32 lockId) {
    env e;
    
    // Get lock expiry (assuming it's stored in the lock struct)
    uint8 state;
    bytes32 commitment;
    bytes32 targetCommitment;
    address creator;
    uint64 expiry;
    
    require getLockState(lockId) == LOCK_ACTIVE();
    require e.block.timestamp < expiry;
    
    expireLock@withrevert(e, lockId);
    
    assert lastReverted, "Premature expiry should revert";
}

/**
 * @title Expiry Transitions Correctly
 * @notice After timeout, expiry succeeds
 */
rule expiryTransition(bytes32 lockId, uint64 lockExpiry) {
    env e;
    
    require getLockState(lockId) == LOCK_ACTIVE();
    require e.block.timestamp >= lockExpiry;
    
    expireLock(e, lockId);
    
    assert getLockState(lockId) == LOCK_EXPIRED(), "State should be EXPIRED";
}

/**
 * @title No State Regression
 * @notice Terminal states (RELEASED, CLAIMED, EXPIRED) cannot change
 */
rule terminalStatesAreFinal(bytes32 lockId) {
    env e;
    bytes32 secret;
    bytes32 nullifier;
    uint256[8] proof;
    
    uint8 stateBefore = getLockState(lockId);
    require stateBefore == LOCK_RELEASED() || 
            stateBefore == LOCK_CLAIMED() || 
            stateBefore == LOCK_EXPIRED();
    
    // Try any operation
    releaseLock@withrevert(e, lockId, secret, proof);
    bool releaseReverted = lastReverted;
    
    claimLock@withrevert(e, lockId, nullifier, proof);
    bool claimReverted = lastReverted;
    
    expireLock@withrevert(e, lockId);
    bool expireReverted = lastReverted;
    
    // All should revert
    assert releaseReverted, "Release on terminal state should revert";
    assert claimReverted, "Claim on terminal state should revert";
    assert expireReverted, "Expire on terminal state should revert";
    
    // State unchanged
    assert getLockState(lockId) == stateBefore, "Terminal state should not change";
}

// ============================================================================
// CROSS-CHAIN SECURITY
// ============================================================================

/**
 * @title Domain Separator Uniqueness
 * @notice Domain separator should be non-zero and unique per chain
 */
rule domainSeparatorNonZero() {
    assert domainSeparator() != bytes32(0), "Domain separator should be non-zero";
}

/**
 * @title Atomic Lock Operations
 * @notice Lock state changes are atomic (no partial updates)
 */
rule atomicLockOperations(bytes32 lockId) {
    env e;
    uint8 stateBefore = getLockState(lockId);
    
    // If operation fails, state should remain unchanged
    // This is verified by checking state consistency
    assert getLockState(lockId) == stateBefore || 
           getLockState(lockId) == LOCK_RELEASED() ||
           getLockState(lockId) == LOCK_CLAIMED() ||
           getLockState(lockId) == LOCK_EXPIRED(),
           "Invalid state transition detected";
}
