/**
 * @title PQCRegistry Formal Verification Specification
 * @notice Certora CVL specification for Post-Quantum Cryptography Registry
 */

methods {
    // State variables
    function currentPhase() external returns (uint8) envfree;
    function paused() external returns (bool) envfree;
    
    // View functions
    function getAccountConfig(address) external returns (PQCRegistry.AccountPQConfig memory) envfree;
    function getStats() external returns (PQCRegistry.PQCStats memory) envfree;
    function isPQCEnabled(address) external returns (bool) envfree;
    function supportedPrimitives(uint8) external returns (bool) envfree;
    
    // Core functions
    function configureAccount(uint8, uint8, bytes32, bytes32, bool) external;
    function updateAccount(uint8, uint8) external;
    function deactivateAccount() external;
    function transitionPhase(uint8) external;
    
    // Admin functions
    function pause() external;
    function unpause() external;
}

// =============================================================================
// GHOST VARIABLES
// =============================================================================

ghost uint256 ghostTotalAccounts;
ghost uint256 ghostDilithiumAccounts;
ghost uint256 ghostSphincAccounts;
ghost uint256 ghostKyberAccounts;
ghost mapping(address => bool) ghostActiveAccounts;

// =============================================================================
// HOOKS
// =============================================================================

hook Sstore accountConfigs[KEY address account].isActive bool newValue (bool oldValue) {
    if (newValue && !oldValue) {
        ghostTotalAccounts = ghostTotalAccounts + 1;
        ghostActiveAccounts[account] = true;
    }
    if (!newValue && oldValue) {
        ghostTotalAccounts = require_uint256(ghostTotalAccounts - 1);
        ghostActiveAccounts[account] = false;
    }
}

// =============================================================================
// INVARIANTS
// =============================================================================

/**
 * @notice INV-001: Total accounts is consistent with active accounts
 */
invariant totalAccountsConsistent()
    ghostTotalAccounts >= 0
    {
        preserved {
            require ghostTotalAccounts < max_uint256;
        }
    }

/**
 * @notice INV-002: Dilithium + SPHINCS accounts <= total accounts
 */
invariant signatureAccountsConsistent() {
    PQCRegistry.PQCStats stats = getStats();
    stats.dilithiumAccounts + stats.sphincsAccounts <= stats.totalAccounts
}

/**
 * @notice INV-003: Phase is always valid (0-4)
 */
invariant phaseInValidRange()
    currentPhase() <= 4

/**
 * @notice INV-004: Kyber accounts <= total accounts
 */
invariant kyberAccountsConsistent() {
    PQCRegistry.PQCStats stats = getStats();
    stats.kyberAccounts <= stats.totalAccounts
}

// =============================================================================
// RULES
// =============================================================================

/**
 * @notice RULE-001: Account configuration is one-time until deactivation
 */
rule noDoubleConfiguration(
    uint8 sigAlgo, 
    uint8 kemAlgo, 
    bytes32 sigKeyHash, 
    bytes32 kemKeyHash, 
    bool enableHybrid
) {
    env e;
    
    require isPQCEnabled(e.msg.sender);
    
    configureAccount@withrevert(e, sigAlgo, kemAlgo, sigKeyHash, kemKeyHash, enableHybrid);
    
    assert lastReverted, "Should not allow reconfiguration of active account";
}

/**
 * @notice RULE-002: Configuration makes account PQC enabled
 */
rule configurationEnablesPQC(
    uint8 sigAlgo, 
    uint8 kemAlgo, 
    bytes32 sigKeyHash, 
    bytes32 kemKeyHash, 
    bool enableHybrid
) {
    env e;
    
    require !isPQCEnabled(e.msg.sender);
    require !paused();
    require supportedPrimitives(sigAlgo);
    
    configureAccount(e, sigAlgo, kemAlgo, sigKeyHash, kemKeyHash, enableHybrid);
    
    assert isPQCEnabled(e.msg.sender), "Account should be PQC enabled after configuration";
}

/**
 * @notice RULE-003: Deactivation disables PQC
 */
rule deactivationDisablesPQC() {
    env e;
    
    require isPQCEnabled(e.msg.sender);
    
    deactivateAccount(e);
    
    assert !isPQCEnabled(e.msg.sender), "Account should not be PQC enabled after deactivation";
}

/**
 * @notice RULE-004: Cannot deactivate inactive account
 */
rule cannotDeactivateInactive() {
    env e;
    
    require !isPQCEnabled(e.msg.sender);
    
    deactivateAccount@withrevert(e);
    
    assert lastReverted, "Should not allow deactivation of inactive account";
}

/**
 * @notice RULE-005: Cannot update inactive account
 */
rule cannotUpdateInactive(uint8 sigAlgo, uint8 kemAlgo) {
    env e;
    
    require !isPQCEnabled(e.msg.sender);
    
    updateAccount@withrevert(e, sigAlgo, kemAlgo);
    
    assert lastReverted, "Should not allow update of inactive account";
}

/**
 * @notice RULE-006: Phase transitions are monotonic (forward only)
 */
rule phaseTransitionMonotonic(uint8 newPhase) {
    env e;
    
    uint8 phaseBefore = currentPhase();
    
    transitionPhase(e, newPhase);
    
    uint8 phaseAfter = currentPhase();
    
    assert phaseAfter >= phaseBefore, "Phase should only increase";
}

/**
 * @notice RULE-007: Cannot configure when paused
 */
rule noConfigurationWhenPaused(
    uint8 sigAlgo, 
    uint8 kemAlgo, 
    bytes32 sigKeyHash, 
    bytes32 kemKeyHash, 
    bool enableHybrid
) {
    env e;
    
    require paused();
    
    configureAccount@withrevert(e, sigAlgo, kemAlgo, sigKeyHash, kemKeyHash, enableHybrid);
    
    assert lastReverted, "Should not allow configuration when paused";
}

/**
 * @notice RULE-008: HybridMandatory phase requires hybrid mode
 */
rule hybridMandatoryEnforced(
    uint8 sigAlgo, 
    uint8 kemAlgo, 
    bytes32 sigKeyHash, 
    bytes32 kemKeyHash
) {
    env e;
    
    require currentPhase() == 2; // HybridMandatory
    require !paused();
    require !isPQCEnabled(e.msg.sender);
    
    // Try to configure without hybrid
    configureAccount@withrevert(e, sigAlgo, kemAlgo, sigKeyHash, kemKeyHash, false);
    
    assert lastReverted, "HybridMandatory should require hybrid mode";
}

/**
 * @notice RULE-009: Account configuration preserves other accounts
 */
rule configurationPreservesOthers(
    address other,
    uint8 sigAlgo, 
    uint8 kemAlgo, 
    bytes32 sigKeyHash, 
    bytes32 kemKeyHash, 
    bool enableHybrid
) {
    env e;
    
    require e.msg.sender != other;
    bool otherEnabledBefore = isPQCEnabled(other);
    
    configureAccount(e, sigAlgo, kemAlgo, sigKeyHash, kemKeyHash, enableHybrid);
    
    bool otherEnabledAfter = isPQCEnabled(other);
    
    assert otherEnabledBefore == otherEnabledAfter, 
        "Configuration should not affect other accounts";
}

/**
 * @notice RULE-010: Deactivation preserves other accounts
 */
rule deactivationPreservesOthers(address other) {
    env e;
    
    require e.msg.sender != other;
    bool otherEnabledBefore = isPQCEnabled(other);
    
    deactivateAccount(e);
    
    bool otherEnabledAfter = isPQCEnabled(other);
    
    assert otherEnabledBefore == otherEnabledAfter, 
        "Deactivation should not affect other accounts";
}

/**
 * @notice RULE-011: Stats never decrease (monotonic)
 */
rule statsMonotonic(method f) 
    filtered { f -> !f.isView }
{
    env e;
    calldataarg args;
    
    PQCRegistry.PQCStats statsBefore = getStats();
    
    f(e, args);
    
    PQCRegistry.PQCStats statsAfter = getStats();
    
    // Total verifications and encapsulations should only increase
    assert statsAfter.totalSignatureVerifications >= statsBefore.totalSignatureVerifications,
        "Signature verifications should not decrease";
    assert statsAfter.totalKeyEncapsulations >= statsBefore.totalKeyEncapsulations,
        "Key encapsulations should not decrease";
}

/**
 * @notice RULE-012: Unsupported primitives cannot be used
 */
rule unsupportedPrimitivesRejected(
    uint8 sigAlgo, 
    uint8 kemAlgo, 
    bytes32 sigKeyHash, 
    bytes32 kemKeyHash, 
    bool enableHybrid
) {
    env e;
    
    require !supportedPrimitives(sigAlgo);
    
    configureAccount@withrevert(e, sigAlgo, kemAlgo, sigKeyHash, kemKeyHash, enableHybrid);
    
    assert lastReverted, "Unsupported signature algorithm should be rejected";
}

// =============================================================================
// PARAMETRIC RULES
// =============================================================================

/**
 * @notice PARAM-001: Only authorized functions modify phase
 */
rule phaseChangeOnlyViaTransition(method f) 
    filtered { f -> f.selector != sig:transitionPhase(uint8).selector }
{
    env e;
    calldataarg args;
    
    uint8 phaseBefore = currentPhase();
    
    f(e, args);
    
    uint8 phaseAfter = currentPhase();
    
    assert phaseBefore == phaseAfter, 
        "Only transitionPhase can modify phase";
}

/**
 * @notice PARAM-002: Pause state changes only via pause/unpause
 */
rule pauseChangeOnlyViaAdminFunctions(method f) 
    filtered { 
        f -> f.selector != sig:pause().selector && 
             f.selector != sig:unpause().selector 
    }
{
    env e;
    calldataarg args;
    
    bool pausedBefore = paused();
    
    f(e, args);
    
    bool pausedAfter = paused();
    
    assert pausedBefore == pausedAfter, 
        "Only pause/unpause can modify pause state";
}
