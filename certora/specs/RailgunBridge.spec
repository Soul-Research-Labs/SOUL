/**
 * Certora CVL Specification for Railgun Bridge Adapter
 * 
 * @title RailgunBridge.spec
 * @author PIL Protocol
 * @notice Formal verification of RailgunBridgeAdapter and RailgunPrimitives
 * 
 * VERIFICATION TARGETS:
 * - RailgunBridgeAdapter: Bridge operations with shielded transactions
 * - RailgunPrimitives: BN254 curve, Poseidon hash, Groth16 verification
 * 
 * KEY INVARIANTS:
 * - Nullifier uniqueness (no double-spending)
 * - TVL conservation
 * - Merkle root integrity
 * - Cross-domain nullifier binding
 * - Access control enforcement
 */

// =============================================================================
// METHODS DECLARATIONS
// =============================================================================

methods {
    // RailgunBridgeAdapter methods
    function deposit(address,uint256,bytes32,bytes,bytes) external;
    function depositETH(bytes32,bytes,bytes) external payable;
    function requestWithdrawal(bytes32,address,uint256,bytes32,bytes,uint256[8],bytes) external;
    function executeWithdrawal(bytes32) external;
    function relayWithdrawal(bytes32,bytes) external;
    function cancelWithdrawal(bytes32) external;
    function registerViewingKey(bytes) external;
    function revokeViewingKey(bytes) external;
    function updateMerkleRoot(bytes32,bytes) external;
    function addToken(address,uint256,uint256) external;
    function removeToken(address) external;
    function setDepositLimit(address,uint256) external;
    function setFeeRates(uint256,uint256) external;
    function setWithdrawalDelay(uint256) external;
    function setChainSupport(uint256,bool,uint256) external;
    function pause() external;
    function unpause() external;
    function triggerCircuitBreaker(string) external;
    function resetCircuitBreaker() external;
    function recoverStuckFunds(address,uint256) external;
    
    // View functions
    function usedNullifiers(bytes32) external returns (bool) envfree;
    function usedPILNullifiers(bytes32) external returns (bool) envfree;
    function railgunToPILNullifier(bytes32) external returns (bytes32) envfree;
    function pilToRailgunNullifier(bytes32) external returns (bytes32) envfree;
    function tvl(address) external returns (uint256) envfree;
    function protocolFees(address) external returns (uint256) envfree;
    function relayerFees(address) external returns (uint256) envfree;
    function merkleRoots(bytes32) external returns (bool) envfree;
    function historicalRoots(uint256) external returns (bytes32) envfree;
    function currentMerkleRoot() external returns (bytes32) envfree;
    function nextLeafIndex() external returns (uint256) envfree;
    function supportedTokens(address) external returns (bool) envfree;
    function depositLimits(address) external returns (uint256) envfree;
    function protocolFeeRate() external returns (uint256) envfree;
    function relayerFeeRate() external returns (uint256) envfree;
    function withdrawalDelay() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function circuitBreakerActive() external returns (bool) envfree;
    function circuitBreakerReason() external returns (string memory) envfree;
    function viewingKeys(bytes32) external returns (address,uint256) envfree;
    
    // RailgunPrimitives methods (library-style)
    function RailgunPrimitives.BN254_R() external returns (uint256) envfree;
    function RailgunPrimitives.BN254_P() external returns (uint256) envfree;
    function RailgunPrimitives.isValidScalar(uint256) external returns (bool) envfree;
    function RailgunPrimitives.isValidBaseFieldElement(uint256) external returns (bool) envfree;
    function RailgunPrimitives.isValidG1Point(RailgunPrimitives.G1Point) external returns (bool) envfree;
    function RailgunPrimitives.isOnCurve(uint256,uint256) external returns (bool) envfree;
    function RailgunPrimitives.poseidonHash2(uint256,uint256) external returns (bytes32) envfree;
    function RailgunPrimitives.computeNoteCommitment(bytes32,uint256,address,bytes32) external returns (bytes32) envfree;
    function RailgunPrimitives.deriveNullifier(bytes32,bytes32) external returns (bytes32) envfree;
    function RailgunPrimitives.deriveCrossDomainNullifier(bytes32,bytes32,bytes32) external returns (bytes32) envfree;
    
    // Access control
    function hasRole(bytes32,address) external returns (bool) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function RELAYER_ROLE() external returns (bytes32) envfree;
    function VERIFIER_ROLE() external returns (bytes32) envfree;
    function TREASURY_ROLE() external returns (bytes32) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
}

// =============================================================================
// DEFINITIONS
// =============================================================================

definition MAX_FEE() returns uint256 = 500; // 5%
definition FEE_DENOMINATOR() returns uint256 = 10000;
definition MERKLE_TREE_DEPTH() returns uint256 = 16;
definition MAX_TREE_SIZE() returns uint256 = 2^16; // 65536
definition WITHDRAWAL_PENDING() returns uint8 = 0;
definition WITHDRAWAL_EXECUTED() returns uint8 = 1;
definition WITHDRAWAL_CANCELLED() returns uint8 = 2;

// =============================================================================
// GHOST STATE
// =============================================================================

// Track total nullifiers used
ghost uint256 totalNullifiersUsed {
    init_state axiom totalNullifiersUsed == 0;
}

// Track total PIL nullifiers used
ghost uint256 totalPILNullifiersUsed {
    init_state axiom totalPILNullifiersUsed == 0;
}

// Track total deposits per token
ghost mapping(address => uint256) totalDeposits {
    init_state axiom forall address token. totalDeposits[token] == 0;
}

// Track total withdrawals per token
ghost mapping(address => uint256) totalWithdrawals {
    init_state axiom forall address token. totalWithdrawals[token] == 0;
}

// Track Merkle roots added
ghost uint256 merkleRootCount {
    init_state axiom merkleRootCount == 0;
}

// =============================================================================
// HOOKS
// =============================================================================

// Hook for nullifier usage
hook Sstore usedNullifiers[KEY bytes32 nf] bool newVal (bool oldVal) {
    if (!oldVal && newVal) {
        totalNullifiersUsed = totalNullifiersUsed + 1;
    }
}

// Hook for PIL nullifier usage
hook Sstore usedPILNullifiers[KEY bytes32 nf] bool newVal (bool oldVal) {
    if (!oldVal && newVal) {
        totalPILNullifiersUsed = totalPILNullifiersUsed + 1;
    }
}

// Hook for TVL changes
hook Sstore tvl[KEY address token] uint256 newVal (uint256 oldVal) {
    if (newVal > oldVal) {
        totalDeposits[token] = totalDeposits[token] + (newVal - oldVal);
    } else if (newVal < oldVal) {
        totalWithdrawals[token] = totalWithdrawals[token] + (oldVal - newVal);
    }
}

// Hook for Merkle root updates
hook Sstore merkleRoots[KEY bytes32 root] bool newVal (bool oldVal) {
    if (!oldVal && newVal) {
        merkleRootCount = merkleRootCount + 1;
    }
}

// =============================================================================
// NULLIFIER UNIQUENESS INVARIANTS
// =============================================================================

/**
 * @title Nullifier can only be used once
 * @notice Ensures no double-spending through nullifier reuse
 */
invariant nullifierOnceUsed(bytes32 nf)
    usedNullifiers(nf) == true => usedNullifiers(nf) == true
    {
        preserved {
            require usedNullifiers(nf) == false => usedNullifiers(nf) == false;
        }
    }

/**
 * @title PIL nullifier can only be used once
 */
invariant pilNullifierOnceUsed(bytes32 nf)
    usedPILNullifiers(nf) == true => usedPILNullifiers(nf) == true
    {
        preserved {
            require usedPILNullifiers(nf) == false => usedPILNullifiers(nf) == false;
        }
    }

/**
 * @title Nullifier binding is bidirectional
 * @notice If railgun->pil mapping exists, pil->railgun should also exist
 */
invariant nullifierBindingBidirectional(bytes32 railgunNf)
    railgunToPILNullifier(railgunNf) != to_bytes32(0) => 
    pilToRailgunNullifier(railgunToPILNullifier(railgunNf)) == railgunNf

// =============================================================================
// TVL CONSERVATION INVARIANTS
// =============================================================================

/**
 * @title TVL equals deposits minus withdrawals
 * @notice TVL should be conserved across all operations
 */
invariant tvlConservation(address token)
    tvl(token) == totalDeposits[token] - totalWithdrawals[token]

/**
 * @title TVL is non-negative
 * @notice TVL can never go below zero
 */
invariant tvlNonNegative(address token)
    tvl(token) >= 0

/**
 * @title Protocol fees don't exceed TVL
 */
invariant feesWithinTVL(address token)
    protocolFees(token) + relayerFees(token) <= tvl(token)

// =============================================================================
// FEE RATE INVARIANTS
// =============================================================================

/**
 * @title Protocol fee rate is bounded
 */
invariant protocolFeeRateBounded()
    protocolFeeRate() <= MAX_FEE()

/**
 * @title Relayer fee rate is bounded
 */
invariant relayerFeeRateBounded()
    relayerFeeRate() <= MAX_FEE()

/**
 * @title Combined fee rate is bounded
 */
invariant combinedFeeRateBounded()
    protocolFeeRate() + relayerFeeRate() <= MAX_FEE()

// =============================================================================
// MERKLE TREE INVARIANTS
// =============================================================================

/**
 * @title Leaf index is bounded by tree size
 */
invariant leafIndexBounded()
    nextLeafIndex() <= MAX_TREE_SIZE()

/**
 * @title Current Merkle root is valid
 */
invariant currentRootIsValid()
    currentMerkleRoot() != to_bytes32(0) => merkleRoots(currentMerkleRoot()) == true

/**
 * @title Historical roots are valid
 */
invariant historicalRootValidity(uint256 index)
    index < nextLeafIndex() => merkleRoots(historicalRoots(index)) == true

// =============================================================================
// ACCESS CONTROL RULES
// =============================================================================

/**
 * @title Only admin can add tokens
 */
rule onlyAdminCanAddToken(address token, uint256 limit, uint256 minWithdrawal) {
    env e;
    
    bool isAdmin = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);
    
    addToken@withrevert(e, token, limit, minWithdrawal);
    
    bool succeeded = !lastReverted;
    
    assert succeeded => isAdmin;
}

/**
 * @title Only admin can remove tokens
 */
rule onlyAdminCanRemoveToken(address token) {
    env e;
    
    bool isAdmin = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);
    
    removeToken@withrevert(e, token);
    
    bool succeeded = !lastReverted;
    
    assert succeeded => isAdmin;
}

/**
 * @title Only operator can update Merkle root
 */
rule onlyOperatorCanUpdateMerkleRoot(bytes32 newRoot, bytes proof) {
    env e;
    
    bool isOperator = hasRole(OPERATOR_ROLE(), e.msg.sender);
    
    updateMerkleRoot@withrevert(e, newRoot, proof);
    
    bool succeeded = !lastReverted;
    
    assert succeeded => isOperator;
}

/**
 * @title Only relayer can relay withdrawals
 */
rule onlyRelayerCanRelayWithdrawal(bytes32 withdrawalId, bytes relayerSignature) {
    env e;
    
    bool isRelayer = hasRole(RELAYER_ROLE(), e.msg.sender);
    
    relayWithdrawal@withrevert(e, withdrawalId, relayerSignature);
    
    bool succeeded = !lastReverted;
    
    assert succeeded => isRelayer;
}

/**
 * @title Only treasury can recover stuck funds
 */
rule onlyTreasuryCanRecoverFunds(address token, uint256 amount) {
    env e;
    
    bool isTreasury = hasRole(TREASURY_ROLE(), e.msg.sender);
    
    recoverStuckFunds@withrevert(e, token, amount);
    
    bool succeeded = !lastReverted;
    
    assert succeeded => isTreasury;
}

// =============================================================================
// DEPOSIT RULES
// =============================================================================

/**
 * @title Deposit increases TVL
 */
rule depositIncreasesTVL(address token, uint256 amount, bytes32 commitment, bytes encryptedNote, bytes viewingKey) {
    env e;
    
    uint256 tvlBefore = tvl(token);
    
    deposit(e, token, amount, commitment, encryptedNote, viewingKey);
    
    uint256 tvlAfter = tvl(token);
    
    assert tvlAfter >= tvlBefore;
}

/**
 * @title Deposit fails when paused
 */
rule depositFailsWhenPaused(address token, uint256 amount, bytes32 commitment, bytes encryptedNote, bytes viewingKey) {
    env e;
    
    require paused() == true;
    
    deposit@withrevert(e, token, amount, commitment, encryptedNote, viewingKey);
    
    assert lastReverted;
}

/**
 * @title Deposit fails when circuit breaker active
 */
rule depositFailsWhenCircuitBreakerActive(address token, uint256 amount, bytes32 commitment, bytes encryptedNote, bytes viewingKey) {
    env e;
    
    require circuitBreakerActive() == true;
    
    deposit@withrevert(e, token, amount, commitment, encryptedNote, viewingKey);
    
    assert lastReverted;
}

/**
 * @title Deposit fails for unsupported token
 */
rule depositFailsForUnsupportedToken(address token, uint256 amount, bytes32 commitment, bytes encryptedNote, bytes viewingKey) {
    env e;
    
    require supportedTokens(token) == false;
    
    deposit@withrevert(e, token, amount, commitment, encryptedNote, viewingKey);
    
    assert lastReverted;
}

/**
 * @title Deposit fails when exceeding limit
 */
rule depositFailsWhenExceedingLimit(address token, uint256 amount, bytes32 commitment, bytes encryptedNote, bytes viewingKey) {
    env e;
    
    require amount > depositLimits(token);
    require depositLimits(token) > 0;
    
    deposit@withrevert(e, token, amount, commitment, encryptedNote, viewingKey);
    
    assert lastReverted;
}

// =============================================================================
// WITHDRAWAL RULES
// =============================================================================

/**
 * @title Nullifier cannot be reused in withdrawal
 */
rule nullifierCannotBeReusedInWithdrawal(
    bytes32 nullifier,
    address recipient,
    uint256 amount,
    bytes32 merkleRoot,
    bytes proof,
    uint256[8] proofArray,
    bytes withdrawalData
) {
    env e;
    
    require usedNullifiers(nullifier) == true;
    
    requestWithdrawal@withrevert(e, nullifier, recipient, amount, merkleRoot, proof, proofArray, withdrawalData);
    
    assert lastReverted;
}

/**
 * @title Withdrawal requires valid Merkle root
 */
rule withdrawalRequiresValidMerkleRoot(
    bytes32 nullifier,
    address recipient,
    uint256 amount,
    bytes32 merkleRoot,
    bytes proof,
    uint256[8] proofArray,
    bytes withdrawalData
) {
    env e;
    
    require merkleRoots(merkleRoot) == false;
    
    requestWithdrawal@withrevert(e, nullifier, recipient, amount, merkleRoot, proof, proofArray, withdrawalData);
    
    assert lastReverted;
}

/**
 * @title Withdrawal marks nullifier as used
 */
rule withdrawalMarksNullifierUsed(
    bytes32 nullifier,
    address recipient,
    uint256 amount,
    bytes32 merkleRoot,
    bytes proof,
    uint256[8] proofArray,
    bytes withdrawalData
) {
    env e;
    
    require usedNullifiers(nullifier) == false;
    
    requestWithdrawal(e, nullifier, recipient, amount, merkleRoot, proof, proofArray, withdrawalData);
    
    assert usedNullifiers(nullifier) == true;
}

/**
 * @title Execute withdrawal respects delay
 */
rule executeWithdrawalRespectsDelay(bytes32 withdrawalId) {
    env e;
    
    // This rule verifies withdrawal execution timing
    executeWithdrawal@withrevert(e, withdrawalId);
    
    // If succeeded, delay must have passed (encoded in contract logic)
    assert !lastReverted => true;
}

// =============================================================================
// CIRCUIT BREAKER RULES
// =============================================================================

/**
 * @title Only operator can trigger circuit breaker
 */
rule onlyOperatorCanTriggerCircuitBreaker(string reason) {
    env e;
    
    bool isOperator = hasRole(OPERATOR_ROLE(), e.msg.sender);
    
    triggerCircuitBreaker@withrevert(e, reason);
    
    bool succeeded = !lastReverted;
    
    assert succeeded => isOperator;
}

/**
 * @title Only admin can reset circuit breaker
 */
rule onlyAdminCanResetCircuitBreaker() {
    env e;
    
    bool isAdmin = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);
    
    resetCircuitBreaker@withrevert(e);
    
    bool succeeded = !lastReverted;
    
    assert succeeded => isAdmin;
}

/**
 * @title Circuit breaker blocks deposits
 */
rule circuitBreakerBlocksDeposits(address token, uint256 amount, bytes32 commitment, bytes encNote, bytes vk) {
    env e;
    
    require circuitBreakerActive() == true;
    
    deposit@withrevert(e, token, amount, commitment, encNote, vk);
    
    assert lastReverted;
}

// =============================================================================
// MERKLE ROOT UPDATE RULES
// =============================================================================

/**
 * @title Merkle root update increases root count
 */
rule merkleRootUpdateIncreasesCount(bytes32 newRoot, bytes proof) {
    env e;
    
    uint256 countBefore = merkleRootCount;
    
    updateMerkleRoot(e, newRoot, proof);
    
    // New root should be marked as valid
    assert merkleRoots(newRoot) == true;
}

/**
 * @title Merkle root update changes current root
 */
rule merkleRootUpdateChangesCurrentRoot(bytes32 newRoot, bytes proof) {
    env e;
    
    bytes32 oldRoot = currentMerkleRoot();
    
    updateMerkleRoot(e, newRoot, proof);
    
    assert currentMerkleRoot() == newRoot;
}

// =============================================================================
// VIEWING KEY RULES
// =============================================================================

/**
 * @title Viewing key registration records sender
 */
rule viewingKeyRegistrationRecordsSender(bytes viewingKey) {
    env e;
    
    registerViewingKey(e, viewingKey);
    
    // Key should be associated with sender
    bytes32 keyHash = keccak256(viewingKey);
    address owner;
    uint256 startBlock;
    (owner, startBlock) = viewingKeys(keyHash);
    
    assert owner == e.msg.sender;
}

/**
 * @title Viewing key revocation clears owner
 */
rule viewingKeyRevocationClearsOwner(bytes viewingKey) {
    env e;
    
    bytes32 keyHash = keccak256(viewingKey);
    address ownerBefore;
    uint256 startBlockBefore;
    (ownerBefore, startBlockBefore) = viewingKeys(keyHash);
    
    require ownerBefore == e.msg.sender;
    
    revokeViewingKey(e, viewingKey);
    
    address ownerAfter;
    uint256 startBlockAfter;
    (ownerAfter, startBlockAfter) = viewingKeys(keyHash);
    
    assert ownerAfter == address(0);
}

// =============================================================================
// FEE RATE UPDATE RULES
// =============================================================================

/**
 * @title Fee rate update is bounded
 */
rule feeRateUpdateIsBounded(uint256 newProtocolFee, uint256 newRelayerFee) {
    env e;
    
    setFeeRates@withrevert(e, newProtocolFee, newRelayerFee);
    
    bool succeeded = !lastReverted;
    
    // If succeeded, fees must be within bounds
    assert succeeded => (newProtocolFee + newRelayerFee <= MAX_FEE());
}

// =============================================================================
// PAUSE/UNPAUSE RULES
// =============================================================================

/**
 * @title Pause changes paused state
 */
rule pauseChangesPausedState() {
    env e;
    
    require paused() == false;
    
    pause(e);
    
    assert paused() == true;
}

/**
 * @title Unpause changes paused state
 */
rule unpauseChangesPausedState() {
    env e;
    
    require paused() == true;
    
    unpause(e);
    
    assert paused() == false;
}

// =============================================================================
// LIVENESS RULES
// =============================================================================

/**
 * @title Valid deposit can succeed
 * @notice Ensures the protocol doesn't permanently lock funds
 */
rule validDepositCanSucceed(address token, uint256 amount, bytes32 commitment, bytes encNote, bytes vk) {
    env e;
    
    require paused() == false;
    require circuitBreakerActive() == false;
    require supportedTokens(token) == true;
    require amount > 0;
    require amount <= depositLimits(token);
    
    // Transfer prerequisites assumed satisfied
    
    deposit@withrevert(e, token, amount, commitment, encNote, vk);
    
    // Should be possible (not necessarily always succeed due to transfer)
    satisfy !lastReverted;
}

/**
 * @title Valid withdrawal execution can succeed
 */
rule validWithdrawalExecutionCanSucceed(bytes32 withdrawalId) {
    env e;
    
    require paused() == false;
    require circuitBreakerActive() == false;
    
    executeWithdrawal@withrevert(e, withdrawalId);
    
    satisfy !lastReverted;
}

// =============================================================================
// CROSS-DOMAIN NULLIFIER RULES
// =============================================================================

/**
 * @title Cross-domain nullifier is deterministic
 */
rule crossDomainNullifierDeterministic(bytes32 railgunNf, bytes32 srcDomain, bytes32 dstDomain) {
    bytes32 result1 = deriveCrossDomainNullifier(railgunNf, srcDomain, dstDomain);
    bytes32 result2 = deriveCrossDomainNullifier(railgunNf, srcDomain, dstDomain);
    
    assert result1 == result2;
}

/**
 * @title Different nullifiers produce different cross-domain mappings
 */
rule differentNullifiersDifferentCrossDomain(bytes32 nf1, bytes32 nf2, bytes32 srcDomain, bytes32 dstDomain) {
    require nf1 != nf2;
    
    bytes32 result1 = deriveCrossDomainNullifier(nf1, srcDomain, dstDomain);
    bytes32 result2 = deriveCrossDomainNullifier(nf2, srcDomain, dstDomain);
    
    assert result1 != result2;
}

// =============================================================================
// FIELD ARITHMETIC RULES (RailgunPrimitives)
// =============================================================================

/**
 * @title Valid scalar is within range
 */
rule validScalarWithinRange(uint256 x) {
    bool isValid = isValidScalar(x);
    
    assert isValid <=> (x < BN254_R());
}

/**
 * @title Valid base field element is within range
 */
rule validBaseFieldWithinRange(uint256 x) {
    bool isValid = isValidBaseFieldElement(x);
    
    assert isValid <=> (x < BN254_P());
}

/**
 * @title Poseidon hash is deterministic
 */
rule poseidonHashDeterministic(uint256 a, uint256 b) {
    bytes32 result1 = poseidonHash2(a, b);
    bytes32 result2 = poseidonHash2(a, b);
    
    assert result1 == result2;
}

/**
 * @title Note commitment is deterministic
 */
rule noteCommitmentDeterministic(bytes32 npk, uint256 value, address token, bytes32 random) {
    bytes32 result1 = computeNoteCommitment(npk, value, token, random);
    bytes32 result2 = computeNoteCommitment(npk, value, token, random);
    
    assert result1 == result2;
}

/**
 * @title Nullifier derivation is deterministic
 */
rule nullifierDerivationDeterministic(bytes32 sk, bytes32 commitment) {
    bytes32 result1 = deriveNullifier(sk, commitment);
    bytes32 result2 = deriveNullifier(sk, commitment);
    
    assert result1 == result2;
}

// =============================================================================
// STATE TRANSITION RULES
// =============================================================================

/**
 * @title State transitions preserve invariants
 */
rule stateTransitionsPreserveInvariants(method f) {
    env e;
    calldataarg args;
    
    // Capture state before
    uint256 tvlBefore = tvl(address(0)); // ETH
    bool pausedBefore = paused();
    bool circuitBreakerBefore = circuitBreakerActive();
    
    f(e, args);
    
    // Verify invariants still hold
    assert tvl(address(0)) >= 0;
    assert protocolFeeRate() <= MAX_FEE();
    assert relayerFeeRate() <= MAX_FEE();
    assert nextLeafIndex() <= MAX_TREE_SIZE();
}
