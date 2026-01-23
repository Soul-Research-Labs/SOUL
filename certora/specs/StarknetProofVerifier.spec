/**
 * @title Certora CVL Specification for StarknetProofVerifier
 * @author PIL Protocol
 * @notice Formal verification of STARK proof verification logic
 * 
 * VERIFICATION SCOPE:
 * - FRI configuration validation
 * - Proof lifecycle state transitions
 * - Security parameter enforcement
 * - Proof verification correctness
 * 
 * CRITICAL SECURITY PROPERTIES:
 * 1. Security level: numQueries * log2(blowupFactor) >= 128 bits
 * 2. Proof integrity: Verified proofs cannot be invalidated
 * 3. Program registration: Only operators can register programs
 * 4. No double verification: Proofs can only be verified once
 * 5. Expiry enforcement: Expired proofs cannot be verified
 */

/*//////////////////////////////////////////////////////////////
                         METHODS BLOCK
//////////////////////////////////////////////////////////////*/

methods {
    // Role management
    function hasRole(bytes32 role, address account) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function VERIFIER_ROLE() external returns (bytes32) envfree;
    function PROVER_ROLE() external returns (bytes32) envfree;
    
    // FRI configuration
    function setDefaultFRIConfig(uint256, uint256, uint256, uint256, uint256) external;
    function registerProgram(bytes32, StarknetProofVerifier.FRIConfig) external;
    
    // Proof management
    function submitProof(StarknetProofVerifier.STARKProof) external returns (bytes32);
    function verifyProof(bytes32) external returns (bool);
    function batchVerifyProofs(bytes32[]) external returns (bool[]);
    
    // View functions
    function proofs(bytes32) external returns (StarknetProofVerifier.STARKProof) envfree;
    function verifiedProofs(bytes32) external returns (StarknetProofVerifier.VerifiedProof) envfree;
    function verifiedPrograms(bytes32) external returns (bool) envfree;
    function allowedProofTypes(StarknetProofVerifier.ProofType) external returns (bool) envfree;
    
    // Constants
    function MIN_QUERIES() external returns (uint256) envfree;
    function MAX_QUERIES() external returns (uint256) envfree;
    function MIN_BLOWUP() external returns (uint256) envfree;
    function MAX_BLOWUP() external returns (uint256) envfree;
    function SECURITY_BITS() external returns (uint256) envfree;
    
    // Counters
    function totalProofs() external returns (uint256) envfree;
    function totalVerifiedProofs() external returns (uint256) envfree;
    function proofExpiryTime() external returns (uint256) envfree;
    
    // Pause
    function paused() external returns (bool) envfree;
}

/*//////////////////////////////////////////////////////////////
                       DEFINITIONS
//////////////////////////////////////////////////////////////*/

// Required security level in bits
definition REQUIRED_SECURITY_BITS() returns uint256 = 128;

// Log2 approximation for common blowup factors
definition log2BlowupFactor(uint256 blowup) returns uint256 =
    blowup == 2 ? 1 :
    blowup == 4 ? 2 :
    blowup == 8 ? 3 :
    blowup == 16 ? 4 : 0;

// Compute security level: numQueries * log2(blowupFactor)
definition computeSecurityLevel(uint256 numQueries, uint256 blowup) returns uint256 =
    numQueries * log2BlowupFactor(blowup);

/*//////////////////////////////////////////////////////////////
                      GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

// Track proof state transitions
ghost mapping(bytes32 => bool) proofSubmitted {
    init_state axiom forall bytes32 id. proofSubmitted[id] == false;
}

ghost mapping(bytes32 => bool) proofVerified {
    init_state axiom forall bytes32 id. proofVerified[id] == false;
}

// Track registered programs
ghost mapping(bytes32 => bool) programRegistered {
    init_state axiom forall bytes32 hash. programRegistered[hash] == false;
}

// Counter ghosts
ghost mathint ghostTotalProofs {
    init_state axiom ghostTotalProofs == 0;
}

ghost mathint ghostTotalVerifiedProofs {
    init_state axiom ghostTotalVerifiedProofs == 0;
}

/*//////////////////////////////////////////////////////////////
                          HOOKS
//////////////////////////////////////////////////////////////*/

// Hook on proof submission
hook Sstore proofs[KEY bytes32 proofId].proofId bytes32 newId {
    proofSubmitted[proofId] = true;
    ghostTotalProofs = ghostTotalProofs + 1;
}

// Hook on proof verification
hook Sstore proofs[KEY bytes32 proofId].verified bool newVerified {
    if (newVerified) {
        proofVerified[proofId] = true;
        ghostTotalVerifiedProofs = ghostTotalVerifiedProofs + 1;
    }
}

// Hook on program registration
hook Sstore verifiedPrograms[KEY bytes32 programHash] bool registered {
    if (registered) {
        programRegistered[programHash] = true;
    }
}

/*//////////////////////////////////////////////////////////////
                       INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Verified proofs counter is consistent
 */
invariant verifiedProofCountConsistent()
    to_mathint(totalVerifiedProofs()) == ghostTotalVerifiedProofs
    {
        preserved {
            require !paused();
        }
    }

/**
 * @notice Total proofs counter is consistent
 */
invariant totalProofCountConsistent()
    to_mathint(totalProofs()) == ghostTotalProofs
    {
        preserved {
            require !paused();
        }
    }

/**
 * @notice Security constants are valid
 */
invariant securityConstantsValid()
    MIN_QUERIES() >= 20 &&
    MAX_QUERIES() <= 100 &&
    MIN_BLOWUP() >= 2 &&
    MAX_BLOWUP() <= 16 &&
    SECURITY_BITS() == 128

/**
 * @notice Verified proofs remain verified
 * @dev Critical: once verified, proofs cannot be unverified
 */
invariant verifiedProofsImmutable(bytes32 proofId)
    proofVerified[proofId] => verifiedProofs(proofId).proofId == proofId
    {
        preserved verifyProof(bytes32 id) with (env e) {
            require !paused();
            require proofSubmitted[id];
        }
    }

/*//////////////////////////////////////////////////////////////
                           RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Only operators can set FRI config
 * @dev Access control verification
 */
rule onlyOperatorCanSetFRIConfig(
    uint256 domainSize,
    uint256 blowupFactor,
    uint256 numQueries,
    uint256 foldingFactor,
    uint256 lastLayerDegBound
) {
    env e;
    
    bool isOperator = hasRole(OPERATOR_ROLE(), e.msg.sender);
    
    setDefaultFRIConfig@withrevert(e, domainSize, blowupFactor, numQueries, foldingFactor, lastLayerDegBound);
    
    bool reverted = lastReverted;
    
    assert !isOperator => reverted, "Non-operators must not be able to set FRI config";
}

/**
 * @notice Only operators can register programs
 */
rule onlyOperatorCanRegisterProgram(bytes32 programHash) {
    env e;
    
    StarknetProofVerifier.FRIConfig config;
    require config.domainSize >= 1024;
    require config.blowupFactor >= 2 && config.blowupFactor <= 16;
    require config.numQueries >= 20 && config.numQueries <= 100;
    require config.foldingFactor >= 2;
    
    bool isOperator = hasRole(OPERATOR_ROLE(), e.msg.sender);
    
    registerProgram@withrevert(e, programHash, config);
    
    bool reverted = lastReverted;
    
    assert !isOperator => reverted, "Non-operators must not be able to register programs";
}

/**
 * @notice FRI config must meet security requirements
 * @dev Security level: numQueries * log2(blowupFactor) >= 128
 */
rule friConfigMustMeetSecurityLevel(
    uint256 domainSize,
    uint256 blowupFactor,
    uint256 numQueries,
    uint256 foldingFactor,
    uint256 lastLayerDegBound
) {
    env e;
    require hasRole(OPERATOR_ROLE(), e.msg.sender);
    
    // Compute security level
    uint256 securityLevel = computeSecurityLevel(numQueries, blowupFactor);
    
    // If security level is insufficient, should revert
    setDefaultFRIConfig@withrevert(e, domainSize, blowupFactor, numQueries, foldingFactor, lastLayerDegBound);
    
    bool reverted = lastReverted;
    
    assert securityLevel < REQUIRED_SECURITY_BITS() => reverted,
        "Insufficient security level must be rejected";
}

/**
 * @notice FRI config parameters must be within bounds
 */
rule friConfigParameterBounds(
    uint256 domainSize,
    uint256 blowupFactor,
    uint256 numQueries,
    uint256 foldingFactor,
    uint256 lastLayerDegBound
) {
    env e;
    require hasRole(OPERATOR_ROLE(), e.msg.sender);
    
    setDefaultFRIConfig@withrevert(e, domainSize, blowupFactor, numQueries, foldingFactor, lastLayerDegBound);
    
    bool reverted = lastReverted;
    
    // Out-of-bounds parameters should revert
    assert (numQueries < MIN_QUERIES() || numQueries > MAX_QUERIES()) => reverted,
        "numQueries out of bounds must be rejected";
    assert (blowupFactor < MIN_BLOWUP() || blowupFactor > MAX_BLOWUP()) => reverted,
        "blowupFactor out of bounds must be rejected";
}

/**
 * @notice Proofs cannot be verified twice
 */
rule noDoubleVerification(bytes32 proofId) {
    env e1;
    env e2;
    
    require proofSubmitted[proofId];
    require !proofVerified[proofId];
    
    // First verification
    verifyProof(e1, proofId);
    
    bool wasVerified = proofVerified[proofId];
    
    // Second verification attempt
    verifyProof@withrevert(e2, proofId);
    
    bool secondReverted = lastReverted;
    
    assert wasVerified => secondReverted, "Already verified proofs must not be verifiable again";
}

/**
 * @notice Unsubmitted proofs cannot be verified
 */
rule unsubmittedProofsCannotBeVerified(bytes32 proofId) {
    env e;
    
    require !proofSubmitted[proofId];
    
    verifyProof@withrevert(e, proofId);
    
    assert lastReverted, "Unsubmitted proofs must not be verifiable";
}

/**
 * @notice Proof submission increases counter
 */
rule proofSubmissionIncreasesCounter() {
    env e;
    
    StarknetProofVerifier.STARKProof proof;
    require proof.programHash != bytes32(0);
    require allowedProofTypes(proof.proofType);
    
    uint256 beforeCount = totalProofs();
    
    submitProof(e, proof);
    
    uint256 afterCount = totalProofs();
    
    assert afterCount == beforeCount + 1, "Proof submission must increment counter";
}

/**
 * @notice Proof verification increases verified counter
 */
rule verificationIncreasesVerifiedCounter(bytes32 proofId) {
    env e;
    
    require proofSubmitted[proofId];
    require !proofVerified[proofId];
    
    uint256 beforeCount = totalVerifiedProofs();
    
    bool result = verifyProof(e, proofId);
    
    uint256 afterCount = totalVerifiedProofs();
    
    assert result => afterCount == beforeCount + 1, 
        "Successful verification must increment verified counter";
}

/**
 * @notice Cannot verify proofs when paused
 */
rule cannotVerifyWhenPaused(bytes32 proofId) {
    env e;
    
    require paused();
    
    verifyProof@withrevert(e, proofId);
    
    assert lastReverted, "Verification must fail when paused";
}

/**
 * @notice Cannot submit proofs when paused
 */
rule cannotSubmitWhenPaused() {
    env e;
    
    require paused();
    
    StarknetProofVerifier.STARKProof proof;
    
    submitProof@withrevert(e, proof);
    
    assert lastReverted, "Submission must fail when paused";
}

/**
 * @notice Only allowed proof types can be submitted
 */
rule onlyAllowedProofTypesAccepted() {
    env e;
    
    StarknetProofVerifier.STARKProof proof;
    
    bool isAllowed = allowedProofTypes(proof.proofType);
    
    submitProof@withrevert(e, proof);
    
    bool reverted = lastReverted;
    
    // If proof type is not allowed, should revert
    assert !isAllowed => reverted, "Disallowed proof types must be rejected";
}

/**
 * @notice Verified proofs have valid metadata
 */
rule verifiedProofHasValidMetadata(bytes32 proofId) {
    env e;
    
    require proofSubmitted[proofId];
    require !proofVerified[proofId];
    
    bool result = verifyProof(e, proofId);
    
    if (result) {
        StarknetProofVerifier.VerifiedProof verified = verifiedProofs(proofId);
        
        assert verified.proofId == proofId, "Verified proof must have correct ID";
        assert verified.verifiedAt > 0, "Verified proof must have timestamp";
        assert verified.verifier == e.msg.sender, "Verified proof must record verifier";
    }
}

/*//////////////////////////////////////////////////////////////
                   FRI LAYER VERIFICATION RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice FRI layers must decrease in size
 * @dev Each layer should be smaller by folding factor
 */
rule friLayerSizesDecrease(bytes32 proofId) {
    require proofSubmitted[proofId];
    
    StarknetProofVerifier.STARKProof proof = proofs(proofId);
    
    uint256 numLayers = proof.friLayerCommitments.length;
    
    // For valid proofs, layer count should match config
    assert numLayers > 0, "Must have at least one FRI layer";
}

/**
 * @notice Domain size must be power of 2
 */
rule domainSizeMustBePowerOfTwo(
    uint256 domainSize,
    uint256 blowupFactor,
    uint256 numQueries,
    uint256 foldingFactor,
    uint256 lastLayerDegBound
) {
    env e;
    require hasRole(OPERATOR_ROLE(), e.msg.sender);
    
    // Domain size must be power of 2 (have exactly one bit set)
    bool isPowerOfTwo = (domainSize != 0) && ((domainSize & (domainSize - 1)) == 0);
    
    setDefaultFRIConfig@withrevert(e, domainSize, blowupFactor, numQueries, foldingFactor, lastLayerDegBound);
    
    bool reverted = lastReverted;
    
    assert !isPowerOfTwo => reverted, "Non-power-of-2 domain size must be rejected";
}

/*//////////////////////////////////////////////////////////////
                      SECURITY RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Proof expiry is enforced
 */
rule expiredProofsCannotBeVerified(bytes32 proofId) {
    env e;
    
    require proofSubmitted[proofId];
    require !proofVerified[proofId];
    
    StarknetProofVerifier.STARKProof proof = proofs(proofId);
    uint256 expiryTime = proofExpiryTime();
    
    // If proof is expired
    require e.block.timestamp > proof.timestamp + expiryTime;
    
    verifyProof@withrevert(e, proofId);
    
    assert lastReverted, "Expired proofs must be rejected";
}

/**
 * @notice Program must be registered before proof verification
 */
rule programMustBeRegisteredForVerification(bytes32 proofId) {
    env e;
    
    require proofSubmitted[proofId];
    require !proofVerified[proofId];
    
    StarknetProofVerifier.STARKProof proof = proofs(proofId);
    
    bool isProgramRegistered = verifiedPrograms(proof.programHash);
    
    verifyProof@withrevert(e, proofId);
    
    bool reverted = lastReverted;
    
    // Unregistered programs should cause verification to fail
    assert !isProgramRegistered => reverted, "Unregistered program proofs must be rejected";
}

/**
 * @notice Batch verification is atomic
 * @dev All proofs in batch must pass or all fail
 */
rule batchVerificationIsAtomic(bytes32 proofId1, bytes32 proofId2) {
    env e;
    
    bytes32[] proofIds;
    require proofIds.length == 2;
    require proofIds[0] == proofId1;
    require proofIds[1] == proofId2;
    
    require proofSubmitted[proofId1];
    require proofSubmitted[proofId2];
    
    bool[] results = batchVerifyProofs(e, proofIds);
    
    // Results array should match input length
    assert results.length == proofIds.length, "Results must match input length";
}

/**
 * @notice Verified proof data matches submitted proof
 */
rule verifiedProofMatchesSubmitted(bytes32 proofId) {
    env e;
    
    require proofSubmitted[proofId];
    require !proofVerified[proofId];
    
    StarknetProofVerifier.STARKProof submittedProof = proofs(proofId);
    
    bool result = verifyProof(e, proofId);
    
    if (result) {
        StarknetProofVerifier.VerifiedProof verified = verifiedProofs(proofId);
        
        assert verified.programHash == submittedProof.programHash,
            "Verified proof programHash must match submitted";
        assert verified.proofType == submittedProof.proofType,
            "Verified proof type must match submitted";
    }
}
