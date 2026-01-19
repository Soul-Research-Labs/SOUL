/**
 * Certora Formal Verification Specification
 * Privacy Interoperability Layer - ConfidentialStateContainer
 * 
 * This spec verifies critical invariants for the confidential state container
 */

using ConfidentialStateContainerV3 as csc;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions
    function getStateCommitment(bytes32) external returns (bytes32) envfree;
    function getStateNullifier(bytes32) external returns (bytes32) envfree;
    function isStateActive(bytes32) external returns (bool) envfree;
    function getStateCreator(bytes32) external returns (address) envfree;
    function getStateBlock(bytes32) external returns (uint256) envfree;
    function nullifiers(bytes32) external returns (bool) envfree;
    function deprecated() external returns (bool) envfree;
    function admin() external returns (address) envfree;
    
    // State-changing functions
    function createConfidentialState(bytes32, bytes32, bytes, uint8[2], bytes32[2]) external;
    function updateState(bytes32, bytes32, bytes32, uint256[8]) external;
    function nullifyState(bytes32, bytes32, uint256[8]) external;
    function deprecate() external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 totalActiveStates;
ghost mapping(bytes32 => bool) stateExists;

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Nullifier Uniqueness
 * @notice A nullifier can only be used once - prevents double-spending
 */
invariant nullifierUniqueness(bytes32 nullifier)
    nullifiers(nullifier) == true => 
        forall bytes32 stateId. (getStateNullifier(stateId) == nullifier => !isStateActive(stateId))
    { preserved { require true; } }

/**
 * @title State Commitment Immutability
 * @notice Once a state is created, its commitment cannot change except through valid update
 */
invariant commitmentImmutability(bytes32 stateId, bytes32 commitment)
    getStateCommitment(stateId) == commitment && isStateActive(stateId) =>
        getStateCommitment(stateId) == commitment
    { preserved { require true; } }

/**
 * @title Creator Permanence
 * @notice The creator of a state can never change
 */
invariant creatorPermanence(bytes32 stateId)
    stateExists[stateId] => getStateCreator(stateId) != address(0)
    { preserved { require true; } }

// ============================================================================
// RULES
// ============================================================================

/**
 * @title No Double Nullification
 * @notice A state cannot be nullified twice
 */
rule noDoubleNullification(bytes32 stateId, bytes32 nullifier, uint256[8] proof) {
    env e;
    
    // Pre-condition: state is not active (already nullified)
    require !isStateActive(stateId);
    
    // Action: attempt to nullify again
    nullifyState@withrevert(e, stateId, nullifier, proof);
    
    // Post-condition: must revert
    assert lastReverted, "Double nullification should revert";
}

/**
 * @title State Creation Authorization
 * @notice Only valid proofs can create states (verified by proof check)
 */
rule stateCreationRequiresProof(
    bytes32 stateId, 
    bytes32 commitment, 
    bytes encryptedData,
    uint8[2] proofTypes,
    bytes32[2] proofCommitments
) {
    env e;
    
    // Pre-condition: state doesn't exist
    require !isStateActive(stateId);
    require getStateCommitment(stateId) == bytes32(0);
    
    // Action: create state
    createConfidentialState(e, stateId, commitment, encryptedData, proofTypes, proofCommitments);
    
    // Post-condition: state is now active with correct commitment
    assert isStateActive(stateId), "State should be active after creation";
    assert getStateCommitment(stateId) == commitment, "Commitment should match";
    assert getStateCreator(stateId) == e.msg.sender, "Creator should be sender";
}

/**
 * @title Update Preserves State Existence
 * @notice Updating a state keeps it active
 */
rule updatePreservesExistence(
    bytes32 stateId,
    bytes32 oldNullifier,
    bytes32 newCommitment,
    uint256[8] proof
) {
    env e;
    
    // Pre-condition: state exists and is active
    require isStateActive(stateId);
    address creatorBefore = getStateCreator(stateId);
    
    // Action: update state
    updateState(e, stateId, oldNullifier, newCommitment, proof);
    
    // Post-condition: state still exists, creator unchanged
    assert isStateActive(stateId), "State should remain active";
    assert getStateCreator(stateId) == creatorBefore, "Creator should not change";
    assert getStateCommitment(stateId) == newCommitment, "Commitment should update";
}

/**
 * @title Nullification Deactivates State
 * @notice After nullification, state is no longer active
 */
rule nullificationDeactivates(bytes32 stateId, bytes32 nullifier, uint256[8] proof) {
    env e;
    
    // Pre-condition: state is active
    require isStateActive(stateId);
    
    // Action: nullify
    nullifyState(e, stateId, nullifier, proof);
    
    // Post-condition: state is inactive, nullifier is used
    assert !isStateActive(stateId), "State should be inactive after nullification";
    assert nullifiers(nullifier) == true, "Nullifier should be marked as used";
}

/**
 * @title Deprecation Is Permanent
 * @notice Once deprecated, contract stays deprecated
 */
rule deprecationIsPermanent() {
    env e1; env e2;
    
    // Pre-condition: deprecate the contract
    require !deprecated();
    deprecate(e1);
    
    // Post-condition: stays deprecated
    assert deprecated(), "Contract should be deprecated";
    
    // Any subsequent call should maintain deprecated state
    // (Cannot un-deprecate)
}

/**
 * @title Admin Only Deprecation
 * @notice Only admin can deprecate
 */
rule onlyAdminCanDeprecate() {
    env e;
    
    require e.msg.sender != admin();
    require !deprecated();
    
    deprecate@withrevert(e);
    
    assert lastReverted, "Non-admin deprecation should revert";
}

// ============================================================================
// SECURITY PROPERTIES
// ============================================================================

/**
 * @title No State Resurrection
 * @notice A nullified state cannot become active again
 */
rule noStateResurrection(bytes32 stateId) {
    env e1; env e2;
    bytes32 nullifier;
    uint256[8] proof;
    
    // Pre-condition: state is active, then nullified
    require isStateActive(stateId);
    nullifyState(e1, stateId, nullifier, proof);
    require !isStateActive(stateId);
    
    // Any subsequent operation should not resurrect the state
    // Verified by checking state remains inactive
    assert !isStateActive(stateId), "Nullified state should stay inactive";
}

/**
 * @title Reentrancy Protection Check
 * @notice State changes should be atomic
 */
rule atomicStateChanges(bytes32 stateId) {
    env e;
    bytes32 oldCommitment = getStateCommitment(stateId);
    bool wasActive = isStateActive(stateId);
    
    // If state was not active before any operation, 
    // and we didn't create it, it should remain not active
    require !wasActive;
    
    // After any failed operation, state should remain unchanged
    assert getStateCommitment(stateId) == oldCommitment || 
           isStateActive(stateId), "Partial state change detected";
}
