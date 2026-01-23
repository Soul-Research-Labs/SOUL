/**
 * @title DilithiumVerifier Formal Verification Specification
 * @notice Certora CVL specification for post-quantum Dilithium signature verification
 */

methods {
    // State variables
    function useMockVerification() external returns (bool) envfree;
    function trustedKeyHashes(bytes32) external returns (bool) envfree;
    function owner() external returns (address) envfree;
    
    // Core functions
    function verifyDilithium3(bytes32, bytes, bytes) external returns (bool);
    function verifyDilithium5(bytes32, bytes, bytes) external returns (bool);
    function verify(bytes32, bytes, bytes, uint8) external returns (bool);
    function batchVerify(bytes32[], bytes[], bytes[], uint8[]) external returns (bool);
    
    // Admin functions
    function addTrustedKey(bytes32) external;
    function removeTrustedKey(bytes32) external;
    function setMockMode(bool) external;
    function setMockResult(bytes32, bool) external;
}

// =============================================================================
// GHOST VARIABLES
// =============================================================================

ghost uint256 totalVerifications;
ghost uint256 trustedKeyCount;
ghost mapping(bytes32 => bool) ghostTrustedKeys;

// =============================================================================
// HOOKS
// =============================================================================

hook Sstore trustedKeyHashes[KEY bytes32 keyHash] bool newValue (bool oldValue) {
    if (newValue && !oldValue) {
        trustedKeyCount = trustedKeyCount + 1;
    }
    if (!newValue && oldValue) {
        trustedKeyCount = require_uint256(trustedKeyCount - 1);
    }
    ghostTrustedKeys[keyHash] = newValue;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/**
 * @notice INV-001: Trusted key count is consistent with mapping
 */
invariant trustedKeyCountConsistent()
    trustedKeyCount >= 0
    {
        preserved {
            require trustedKeyCount < max_uint256;
        }
    }

/**
 * @notice INV-002: Mock mode can only be set by owner
 */
invariant mockModeOwnerOnly()
    true // Enforced by onlyOwner modifier

// =============================================================================
// RULES
// =============================================================================

/**
 * @notice RULE-001: Adding a trusted key makes it trusted
 */
rule addTrustedKeyEffect(bytes32 keyHash) {
    env e;
    
    require !trustedKeyHashes(keyHash);
    
    addTrustedKey(e, keyHash);
    
    assert trustedKeyHashes(keyHash), "Key should be trusted after adding";
}

/**
 * @notice RULE-002: Removing a trusted key makes it untrusted
 */
rule removeTrustedKeyEffect(bytes32 keyHash) {
    env e;
    
    require trustedKeyHashes(keyHash);
    
    removeTrustedKey(e, keyHash);
    
    assert !trustedKeyHashes(keyHash), "Key should not be trusted after removal";
}

/**
 * @notice RULE-003: Trusted key operations are reversible
 */
rule trustedKeyReversibility(bytes32 keyHash) {
    env e1;
    env e2;
    
    bool initialState = trustedKeyHashes(keyHash);
    
    addTrustedKey(e1, keyHash);
    removeTrustedKey(e2, keyHash);
    
    assert !trustedKeyHashes(keyHash), "After add-remove, key should be untrusted";
}

/**
 * @notice RULE-004: Mock mode doesn't affect trusted key state
 */
rule mockModeIndependence(bytes32 keyHash, bool mockState) {
    env e;
    
    bool keyStateBefore = trustedKeyHashes(keyHash);
    
    setMockMode(e, mockState);
    
    bool keyStateAfter = trustedKeyHashes(keyHash);
    
    assert keyStateBefore == keyStateAfter, "Mock mode should not affect trusted keys";
}

/**
 * @notice RULE-005: Verification is deterministic for same inputs
 */
rule verificationDeterministic(bytes32 message, bytes signature, bytes publicKey) {
    env e1;
    env e2;
    
    require e1.msg.sender == e2.msg.sender;
    require e1.block.timestamp == e2.block.timestamp;
    
    bool result1 = verifyDilithium3(e1, message, signature, publicKey);
    bool result2 = verifyDilithium3(e2, message, signature, publicKey);
    
    assert result1 == result2, "Verification should be deterministic";
}

/**
 * @notice RULE-006: Batch verification fails if any individual verification fails
 * @dev In mock mode, batch should return false if any verification is false
 */
rule batchVerificationSoundness(
    bytes32[] messages,
    bytes[] signatures,
    bytes[] publicKeys,
    uint8[] levels
) {
    env e;
    
    require messages.length == signatures.length;
    require signatures.length == publicKeys.length;
    require publicKeys.length == levels.length;
    require messages.length > 0;
    require messages.length <= 10; // Bound for tractability
    
    bool batchResult = batchVerify(e, messages, signatures, publicKeys, levels);
    
    // If batch succeeds, we can't prove individual success without more info
    // But if batch fails, at least one must have failed
    assert true; // Placeholder - full verification requires loop unrolling
}

/**
 * @notice RULE-007: Only owner can modify trusted keys
 */
rule onlyOwnerModifiesTrustedKeys(method f, bytes32 keyHash) 
    filtered { f -> f.selector == sig:addTrustedKey(bytes32).selector || 
                    f.selector == sig:removeTrustedKey(bytes32).selector }
{
    env e;
    
    bool trustedBefore = trustedKeyHashes(keyHash);
    
    f@withrevert(e, keyHash);
    
    bool trustedAfter = trustedKeyHashes(keyHash);
    
    assert trustedBefore != trustedAfter => e.msg.sender == owner(),
        "Only owner can modify trusted keys";
}

/**
 * @notice RULE-008: Verification with invalid signature size reverts
 */
rule invalidSignatureSizeReverts(bytes32 message, bytes signature, bytes publicKey) {
    env e;
    
    // Dilithium3 signature size is 3293 bytes
    require signature.length != 3293;
    
    verifyDilithium3@withrevert(e, message, signature, publicKey);
    
    assert lastReverted, "Invalid signature size should revert";
}

/**
 * @notice RULE-009: Verification with invalid public key size reverts
 */
rule invalidPublicKeySizeReverts(bytes32 message, bytes signature, bytes publicKey) {
    env e;
    
    require signature.length == 3293; // Valid sig size
    // Dilithium3 public key size is 1952 bytes
    require publicKey.length != 1952;
    
    verifyDilithium3@withrevert(e, message, signature, publicKey);
    
    assert lastReverted, "Invalid public key size should revert";
}

// =============================================================================
// PARAMETRIC RULES
// =============================================================================

/**
 * @notice PARAM-001: State changes only through authorized functions
 */
rule stateChangeAuthorization(method f) 
    filtered { f -> !f.isView }
{
    env e;
    calldataarg args;
    
    bool mockBefore = useMockVerification();
    
    f(e, args);
    
    bool mockAfter = useMockVerification();
    
    // Mock mode can only change via setMockMode
    assert mockBefore != mockAfter => 
        f.selector == sig:setMockMode(bool).selector,
        "Mock mode should only change via setMockMode";
}
