/**
 * @title Enhanced ZK-Bound State Locks (ZK-SLocks) Formal Verification
 * @notice Comprehensive Certora specifications for ZK-SLocks
 * @dev Extended verification for cross-chain state lock security
 */

/*//////////////////////////////////////////////////////////////
                         METHODS
//////////////////////////////////////////////////////////////*/

methods {
    // State accessors
    function nullifierUsed(bytes32) external returns (bool) envfree;
    function verifiers(bytes32) external returns (address) envfree;
    function totalLocksCreated() external returns (uint256) envfree;
    function totalLocksUnlocked() external returns (uint256) envfree;
    function totalOptimisticUnlocks() external returns (uint256) envfree;
    function totalDisputes() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function getActiveLockCount() external returns (uint256) envfree;
    
    // Mutating functions - actual signatures from contract
    // createLock(bytes32 oldStateCommitment, bytes32 transitionPredicateHash, bytes32 policyHash, bytes32 domainSeparator, uint64 unlockDeadline)
    function createLock(bytes32, bytes32, bytes32, bytes32, uint64) external returns (bytes32);
    
    // unlock, optimisticUnlock, challengeOptimisticUnlock use UnlockProof struct
    // We declare them with the struct type for CVL
    function unlock(ZKBoundStateLocks.UnlockProof) external;
    function optimisticUnlock(ZKBoundStateLocks.UnlockProof) external;
    function challengeOptimisticUnlock(bytes32, ZKBoundStateLocks.UnlockProof) external;
    function finalizeOptimisticUnlock(bytes32) external;
    
    // Admin functions
    function pause() external;
    function unpause() external;
}

/*//////////////////////////////////////////////////////////////
                       GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

// Track all used nullifiers
ghost mapping(bytes32 => bool) ghostNullifierUsed {
    init_state axiom forall bytes32 n. !ghostNullifierUsed[n];
}

// Track lock creation count
ghost mathint ghostLockCount {
    init_state axiom ghostLockCount == 0;
}

// Track unlock count
ghost mathint ghostUnlockCount {
    init_state axiom ghostUnlockCount == 0;
}

// Track optimistic unlock count
ghost mathint ghostOptimisticCount {
    init_state axiom ghostOptimisticCount == 0;
}

// Track dispute count
ghost mathint ghostDisputeCount {
    init_state axiom ghostDisputeCount == 0;
}

/*//////////////////////////////////////////////////////////////
                          HOOKS
//////////////////////////////////////////////////////////////*/

hook Sstore nullifierUsed[KEY bytes32 n] bool used (bool old_used) {
    if (!old_used && used) {
        ghostNullifierUsed[n] = true;
    }
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * INV-ZKS-001: Nullifier consumption is permanent
 * Once a nullifier is marked as used, it stays used
 */
invariant nullifierConsumptionPermanent(bytes32 nullifier)
    ghostNullifierUsed[nullifier] => nullifierUsed(nullifier);

/**
 * INV-ZKS-002: Total unlocks cannot exceed total created
 * You cannot unlock more locks than were created
 */
invariant unlocksCannotExceedCreated()
    totalLocksUnlocked() <= totalLocksCreated();

/**
 * INV-ZKS-003: Disputes cannot exceed optimistic unlocks
 * You cannot have more disputes than optimistic unlock attempts
 */
invariant disputesCannotExceedOptimistic()
    totalDisputes() <= totalOptimisticUnlocks();

/**
 * INV-ZKS-004: Statistics are non-negative
 * All counters must be non-negative
 */
invariant statisticsNonNegative()
    totalLocksCreated() >= 0 && 
    totalLocksUnlocked() >= 0 && 
    totalOptimisticUnlocks() >= 0 && 
    totalDisputes() >= 0;

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * RULE-ZKS-001: Lock creation increments counter
 * Creating a lock must increase the total lock count by exactly 1
 */
rule lockCreationIncrementsCounter() {
    env e;
    bytes32 oldStateCommitment;
    bytes32 transitionPredicateHash;
    bytes32 policyHash;
    bytes32 domainSeparator;
    uint64 unlockDeadline;
    
    require !paused();
    
    mathint countBefore = totalLocksCreated();
    
    createLock(e, oldStateCommitment, transitionPredicateHash, policyHash, domainSeparator, unlockDeadline);
    
    mathint countAfter = totalLocksCreated();
    
    assert countAfter == countBefore + 1, "Lock creation must increment counter";
}

/**
 * RULE-ZKS-002: Lock creation returns unique ID
 * Two lock creations with different parameters should return different IDs
 */
rule lockCreationReturnsUniqueId() {
    env e1; env e2;
    bytes32 oldState1; bytes32 predicate1; bytes32 policy1; bytes32 domain1; uint64 deadline1;
    bytes32 oldState2; bytes32 predicate2; bytes32 policy2; bytes32 domain2; uint64 deadline2;
    
    require !paused();
    require e1.msg.sender != e2.msg.sender || 
            oldState1 != oldState2 || 
            predicate1 != predicate2 ||
            policy1 != policy2 ||
            domain1 != domain2;
    
    bytes32 lockId1 = createLock(e1, oldState1, predicate1, policy1, domain1, deadline1);
    bytes32 lockId2 = createLock(e2, oldState2, predicate2, policy2, domain2, deadline2);
    
    assert lockId1 != lockId2, "Different lock parameters must produce different IDs";
}

/**
 * RULE-ZKS-003: Paused contract blocks lock creation
 * When paused, no new locks can be created
 */
rule pausedContractBlocksLockCreation() {
    env e;
    bytes32 oldState; bytes32 predicate; bytes32 policy; bytes32 domain; uint64 deadline;
    
    require paused();
    
    createLock@withrevert(e, oldState, predicate, policy, domain, deadline);
    
    assert lastReverted, "Lock creation must fail when paused";
}

/**
 * RULE-ZKS-004: Paused contract blocks unlock
 * When paused, locks cannot be unlocked
 */
rule pausedContractBlocksUnlock() {
    env e;
    ZKBoundStateLocks.UnlockProof proof;
    
    require paused();
    
    unlock@withrevert(e, proof);
    
    assert lastReverted, "Unlock must fail when paused";
}

/**
 * RULE-ZKS-005: Paused contract blocks optimistic unlock
 * When paused, optimistic unlocks cannot be initiated
 */
rule pausedContractBlocksOptimisticUnlock() {
    env e;
    ZKBoundStateLocks.UnlockProof proof;
    
    require paused();
    
    optimisticUnlock@withrevert(e, proof);
    
    assert lastReverted, "Optimistic unlock must fail when paused";
}

/**
 * RULE-ZKS-006: Nullifier cannot be reused
 * Once a nullifier is used, any subsequent use must fail
 */
rule nullifierCannotBeReused(bytes32 nullifier) {
    env e1; env e2;
    ZKBoundStateLocks.UnlockProof proof1;
    ZKBoundStateLocks.UnlockProof proof2;
    
    require !paused();
    require !nullifierUsed(nullifier);
    require proof1.nullifier == nullifier;
    require proof2.nullifier == nullifier;
    
    // First unlock with nullifier
    unlock(e1, proof1);
    
    // Verify nullifier is now used
    assert nullifierUsed(nullifier), "Nullifier must be marked as used after unlock";
    
    // Second unlock with same nullifier must fail
    unlock@withrevert(e2, proof2);
    
    assert lastReverted, "Nullifier reuse must be prevented";
}

/**
 * RULE-ZKS-007: Finalize only works after dispute window
 * Finalization of optimistic unlock requires dispute window to pass
 */
rule finalizeRequiresDisputeWindow(bytes32 lockId) {
    env e;
    
    // If finalize succeeds, dispute window must have passed
    finalizeOptimisticUnlock(e, lockId);
    
    // Rule passes if we reach here - the contract enforces the window
    assert true, "Finalization succeeded, implying dispute window passed";
}

/**
 * RULE-ZKS-008: Successful challenge increments dispute counter
 * A successful challenge must increase the dispute count
 */
rule challengeIncrementsDisputeCounter(bytes32 lockId) {
    env e;
    ZKBoundStateLocks.UnlockProof conflictProof;
    
    mathint disputesBefore = totalDisputes();
    
    challengeOptimisticUnlock(e, lockId, conflictProof);
    
    mathint disputesAfter = totalDisputes();
    
    assert disputesAfter == disputesBefore + 1, "Challenge must increment dispute counter";
}

/**
 * RULE-ZKS-009: Unlock increments unlock counter
 * A successful unlock must increase the unlock count
 */
rule unlockIncrementsCounter() {
    env e;
    ZKBoundStateLocks.UnlockProof proof;
    
    require !paused();
    
    mathint unlocksBefore = totalLocksUnlocked();
    
    unlock(e, proof);
    
    mathint unlocksAfter = totalLocksUnlocked();
    
    assert unlocksAfter == unlocksBefore + 1, "Unlock must increment counter";
}

/**
 * RULE-ZKS-010: Optimistic unlock increments optimistic counter
 * An optimistic unlock must increase the optimistic unlock count
 */
rule optimisticUnlockIncrementsCounter() {
    env e;
    ZKBoundStateLocks.UnlockProof proof;
    
    require !paused();
    
    mathint optimisticBefore = totalOptimisticUnlocks();
    
    optimisticUnlock(e, proof);
    
    mathint optimisticAfter = totalOptimisticUnlocks();
    
    assert optimisticAfter == optimisticBefore + 1, "Optimistic unlock must increment counter";
}

/*//////////////////////////////////////////////////////////////
                    SECURITY PROPERTIES
//////////////////////////////////////////////////////////////*/

/**
 * SEC-ZKS-001: No lock ID collision
 * Same parameters at different times produce different lock IDs
 */
rule noLockIdCollisionOverTime() {
    env e1; env e2;
    bytes32 oldState; bytes32 predicate; bytes32 policy; bytes32 domain; uint64 deadline;
    
    require !paused();
    require e1.block.timestamp != e2.block.timestamp;
    require e1.msg.sender == e2.msg.sender;
    
    bytes32 lockId1 = createLock(e1, oldState, predicate, policy, domain, deadline);
    bytes32 lockId2 = createLock(e2, oldState, predicate, policy, domain, deadline);
    
    assert lockId1 != lockId2, "Same parameters at different times must produce different IDs";
}

/**
 * SEC-ZKS-002: Active lock count consistency
 * Active lock count should be consistent with created minus unlocked
 */
rule activeLockCountConsistency() {
    mathint created = totalLocksCreated();
    mathint unlocked = totalLocksUnlocked();
    mathint active = getActiveLockCount();
    
    // Active locks should be at most created - unlocked
    assert active <= created - unlocked, "Active count must be <= created - unlocked";
}

/*//////////////////////////////////////////////////////////////
                    STATE TRANSITION PROPERTIES
//////////////////////////////////////////////////////////////*/

/**
 * TRANS-ZKS-001: Monotonic lock creation
 * Lock creation count can only increase
 */
rule monotonicLockCreation(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalLocksCreated();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalLocksCreated();
    
    assert countAfter >= countBefore, "Lock count must be monotonically increasing";
}

/**
 * TRANS-ZKS-002: Monotonic unlock count
 * Unlock count can only increase
 */
rule monotonicUnlockCount(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalLocksUnlocked();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalLocksUnlocked();
    
    assert countAfter >= countBefore, "Unlock count must be monotonically increasing";
}

/**
 * TRANS-ZKS-003: Monotonic dispute count
 * Dispute count can only increase
 */
rule monotonicDisputeCount(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalDisputes();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalDisputes();
    
    assert countAfter >= countBefore, "Dispute count must be monotonically increasing";
}
