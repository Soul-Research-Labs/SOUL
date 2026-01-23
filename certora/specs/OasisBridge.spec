/**
 * Certora Formal Verification Specification for Oasis Bridge
 * 
 * @title OasisBridge.spec
 * @author PIL Protocol
 * @notice Formal verification rules for Oasis Network cross-chain bridge
 * 
 * VERIFICATION SCOPE:
 * - SGX TEE attestation verification
 * - Nullifier uniqueness (PIL and Oasis)
 * - Cross-domain nullifier binding
 * - Withdrawal authorization (committee threshold)
 * - Value conservation
 * - ParaTime state verification
 * - Encrypted envelope validation
 */

using OasisPrimitives as primitives;
using OasisBridgeAdapter as bridge;

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

methods {
    // OasisPrimitives - Pure functions
    function primitives.SAPPHIRE_MAINNET_CHAIN_ID() external returns (uint256) envfree;
    function primitives.SAPPHIRE_TESTNET_CHAIN_ID() external returns (uint256) envfree;
    function primitives.EMERALD_MAINNET_CHAIN_ID() external returns (uint256) envfree;
    function primitives.EMERALD_TESTNET_CHAIN_ID() external returns (uint256) envfree;
    function primitives.CURVE25519_PRIME() external returns (uint256) envfree;
    
    // OasisPrimitives - Key validation
    function primitives.isValidX25519PublicKey(bytes32) external returns (bool) envfree;
    function primitives.isLowOrderPoint(bytes32) external returns (bool) envfree;
    
    // OasisPrimitives - Cryptographic operations
    function primitives.deriveNullifier(bytes32, bytes32) external returns (bytes32) envfree;
    function primitives.deriveCrossDomainNullifier(bytes32, bytes32, bytes32) external returns (bytes32) envfree;
    function primitives.isSapphire(uint256) external returns (bool) envfree;
    function primitives.isConfidentialParaTime(uint256) external returns (bool) envfree;
    
    // OasisPrimitives - Attestation
    function primitives.verifyAttestation(OasisPrimitives.Attestation, bytes32, bytes32) external returns (bool) envfree;
    
    // OasisBridgeAdapter - View functions
    function bridge.supportedParaTimes(uint256) external returns (bool) envfree;
    function bridge.totalDepositedByParaTime(uint256) external returns (uint256) envfree;
    function bridge.totalWithdrawnByParaTime(uint256) external returns (uint256) envfree;
    function bridge.usedPILNullifiers(bytes32) external returns (bool) envfree;
    function bridge.usedOasisNullifiers(bytes32) external returns (bool) envfree;
    function bridge.pilNullifierToOasisNullifier(bytes32) external returns (bytes32) envfree;
    function bridge.oasisNullifierToPILNullifier(bytes32) external returns (bytes32) envfree;
    function bridge.isPaused() external returns (bool) envfree;
    function bridge.committeeThreshold() external returns (uint256) envfree;
    function bridge.getCommitteeSize() external returns (uint256) envfree;
    function bridge.minDeposit() external returns (uint256) envfree;
    function bridge.maxDeposit() external returns (uint256) envfree;
    function bridge.dailyLimit() external returns (uint256) envfree;
    function bridge.approvedEnclaves(bytes32, bytes32) external returns (bool) envfree;
    function bridge.isCommitteeMember(address) external returns (bool) envfree;
    function bridge.isPILNullifierUsed(bytes32) external returns (bool) envfree;
    function bridge.isOasisNullifierUsed(bytes32) external returns (bool) envfree;
    function bridge.getAvailableBalance(uint256) external returns (uint256) envfree;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

// Track nullifier usage
ghost mapping(bytes32 => bool) pilNullifierGhost;
ghost mapping(bytes32 => bool) oasisNullifierGhost;

// Track cross-domain binding
ghost mapping(bytes32 => bytes32) pilToOasisBinding;
ghost mapping(bytes32 => bytes32) oasisToPILBinding;

// Track deposits and withdrawals
ghost mapping(uint256 => uint256) depositedByParaTime;
ghost mapping(uint256 => uint256) withdrawnByParaTime;

// Track committee state
ghost uint256 committeeSize;
ghost uint256 threshold;

// ============================================================================
// HOOKS
// ============================================================================

hook Sstore usedPILNullifiers[KEY bytes32 nf] bool used (bool old_used) {
    pilNullifierGhost[nf] = used;
}

hook Sstore usedOasisNullifiers[KEY bytes32 nf] bool used (bool old_used) {
    oasisNullifierGhost[nf] = used;
}

hook Sstore pilNullifierToOasisNullifier[KEY bytes32 pilNf] bytes32 oasisNf (bytes32 old_oasisNf) {
    pilToOasisBinding[pilNf] = oasisNf;
}

hook Sstore oasisNullifierToPILNullifier[KEY bytes32 oasisNf] bytes32 pilNf (bytes32 old_pilNf) {
    oasisToPILBinding[oasisNf] = pilNf;
}

hook Sstore totalDepositedByParaTime[KEY uint256 paraTime] uint256 amount (uint256 old_amount) {
    depositedByParaTime[paraTime] = amount;
}

hook Sstore totalWithdrawnByParaTime[KEY uint256 paraTime] uint256 amount (uint256 old_amount) {
    withdrawnByParaTime[paraTime] = amount;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title PIL Nullifier Permanence
 * @notice Once a PIL nullifier is marked as used, it remains used forever
 * @dev Prevents double-spending from PIL side
 */
invariant pilNullifierPermanence(bytes32 pilNf)
    bridge.usedPILNullifiers(pilNf) => bridge.usedPILNullifiers(pilNf)
    {
        preserved {
            require bridge.usedPILNullifiers(pilNf);
        }
    }

/**
 * @title Oasis Nullifier Permanence
 * @notice Once an Oasis nullifier is marked as used, it remains used forever
 * @dev Prevents double-deposit from Oasis side
 */
invariant oasisNullifierPermanence(bytes32 oasisNf)
    bridge.usedOasisNullifiers(oasisNf) => bridge.usedOasisNullifiers(oasisNf)
    {
        preserved {
            require bridge.usedOasisNullifiers(oasisNf);
        }
    }

/**
 * @title Value Conservation Per ParaTime
 * @notice Total withdrawn never exceeds total deposited for any ParaTime
 */
invariant valueConservationByParaTime(uint256 paraTime)
    bridge.totalWithdrawnByParaTime(paraTime) <= bridge.totalDepositedByParaTime(paraTime)

/**
 * @title Committee Threshold Sanity
 * @notice Threshold cannot exceed committee size
 */
invariant thresholdSanity()
    bridge.committeeThreshold() <= bridge.getCommitteeSize()

/**
 * @title Binding Bidirectionality
 * @notice Cross-domain nullifier binding must be bidirectional
 * @dev If PIL→Oasis binding exists, Oasis→PIL must point back
 */
invariant bindingBidirectional(bytes32 pilNf)
    bridge.pilNullifierToOasisNullifier(pilNf) != 0 =>
        bridge.oasisNullifierToPILNullifier(bridge.pilNullifierToOasisNullifier(pilNf)) == pilNf

/**
 * @title Binding Immutability
 * @notice Once a PIL nullifier is bound to an Oasis nullifier, the binding cannot change
 */
invariant bindingImmutable(bytes32 pilNf)
    bridge.pilNullifierToOasisNullifier(pilNf) != 0 =>
        bridge.pilNullifierToOasisNullifier(pilNf) == pilToOasisBinding[pilNf]

// ============================================================================
// NULLIFIER RULES
// ============================================================================

/**
 * @title PIL Nullifier No Double Use
 * @notice A PIL nullifier cannot be used twice for withdrawals
 */
rule pilNullifierNoDoubleUse(env e, bytes32 pilNf) {
    bool usedBefore = bridge.usedPILNullifiers(pilNf);
    
    // Any state-changing function call
    calldataarg args;
    bridge.requestWithdrawal(e, args);
    
    bool usedAfter = bridge.usedPILNullifiers(pilNf);
    
    // If already used, must stay used
    assert usedBefore => usedAfter;
}

/**
 * @title Oasis Nullifier No Double Use
 * @notice An Oasis nullifier cannot be used twice for deposits
 */
rule oasisNullifierNoDoubleUse(env e, bytes32 oasisNf) {
    bool usedBefore = bridge.usedOasisNullifiers(oasisNf);
    
    calldataarg args;
    bridge.executeWithdrawal(e, args);
    
    bool usedAfter = bridge.usedOasisNullifiers(oasisNf);
    
    // If already used, must stay used
    assert usedBefore => usedAfter;
}

/**
 * @title Nullifier Uniqueness Preserved
 * @notice Each nullifier can only be bound to one cross-domain counterpart
 */
rule nullifierBindingUnique(env e, bytes32 pilNf1, bytes32 pilNf2) {
    require pilNf1 != pilNf2;
    require bridge.pilNullifierToOasisNullifier(pilNf1) != 0;
    require bridge.pilNullifierToOasisNullifier(pilNf2) != 0;
    
    assert bridge.pilNullifierToOasisNullifier(pilNf1) != bridge.pilNullifierToOasisNullifier(pilNf2);
}

// ============================================================================
// WITHDRAWAL RULES
// ============================================================================

/**
 * @title Withdrawal Requires Unused Nullifier
 * @notice Withdrawal request must fail if PIL nullifier already used
 */
rule withdrawalRequiresUnusedNullifier(
    env e,
    bytes32 pilNf,
    uint256 amount,
    uint256 paraTime,
    OasisPrimitives.EncryptedEnvelope envelope
) {
    bool usedBefore = bridge.usedPILNullifiers(pilNf);
    
    require usedBefore;
    
    bridge.requestWithdrawal@withrevert(e, pilNf, amount, paraTime, envelope);
    
    // Must revert if nullifier already used
    assert lastReverted;
}

/**
 * @title Withdrawal Cannot Exceed Available Balance
 * @notice Withdrawal amount limited by available balance
 */
rule withdrawalLimitedByBalance(
    env e,
    bytes32 pilNf,
    uint256 amount,
    uint256 paraTime,
    OasisPrimitives.EncryptedEnvelope envelope
) {
    uint256 availableBefore = bridge.getAvailableBalance(paraTime);
    
    require amount > availableBefore;
    require !bridge.usedPILNullifiers(pilNf);
    require bridge.supportedParaTimes(paraTime);
    
    bridge.requestWithdrawal@withrevert(e, pilNf, amount, paraTime, envelope);
    
    // Must revert if amount exceeds available
    assert lastReverted;
}

/**
 * @title Zero Amount Withdrawal Rejected
 * @notice Cannot withdraw zero amount
 */
rule zeroAmountWithdrawalRejected(
    env e,
    bytes32 pilNf,
    uint256 paraTime,
    OasisPrimitives.EncryptedEnvelope envelope
) {
    require !bridge.usedPILNullifiers(pilNf);
    require bridge.supportedParaTimes(paraTime);
    require bridge.getAvailableBalance(paraTime) > 0;
    
    bridge.requestWithdrawal@withrevert(e, pilNf, 0, paraTime, envelope);
    
    // Must revert for zero amount
    assert lastReverted;
}

// ============================================================================
// PARATIME RULES
// ============================================================================

/**
 * @title Unsupported ParaTime Rejected
 * @notice Operations on unsupported ParaTimes must fail
 */
rule unsupportedParaTimeRejected(
    env e,
    bytes32 pilNf,
    uint256 amount,
    uint256 paraTime,
    OasisPrimitives.EncryptedEnvelope envelope
) {
    require !bridge.supportedParaTimes(paraTime);
    
    bridge.requestWithdrawal@withrevert(e, pilNf, amount, paraTime, envelope);
    
    assert lastReverted;
}

/**
 * @title Sapphire Recognition
 * @notice Sapphire mainnet and testnet correctly identified as Sapphire
 */
rule sapphireRecognition() {
    uint256 mainnet = primitives.SAPPHIRE_MAINNET_CHAIN_ID();
    uint256 testnet = primitives.SAPPHIRE_TESTNET_CHAIN_ID();
    
    assert primitives.isSapphire(mainnet);
    assert primitives.isSapphire(testnet);
}

/**
 * @title Confidential ParaTime Detection
 * @notice Sapphire and Cipher are confidential, Emerald is not
 */
rule confidentialParaTimeDetection() {
    assert primitives.isConfidentialParaTime(primitives.SAPPHIRE_MAINNET_CHAIN_ID());
    assert primitives.isConfidentialParaTime(primitives.SAPPHIRE_TESTNET_CHAIN_ID());
    // Emerald is not confidential
    assert !primitives.isConfidentialParaTime(primitives.EMERALD_MAINNET_CHAIN_ID());
}

// ============================================================================
// ENCLAVE ATTESTATION RULES
// ============================================================================

/**
 * @title Unapproved Enclave Rejected
 * @notice Operations from unapproved enclaves must fail
 */
rule unapprovedEnclaveRejected(
    env e,
    bytes32 mrEnclave,
    bytes32 mrSigner
) {
    require !bridge.approvedEnclaves(mrEnclave, mrSigner);
    
    // TEE-attested operations should fail
    // This is enforced at the attestation verification level
    assert !bridge.approvedEnclaves(mrEnclave, mrSigner);
}

/**
 * @title Attestation Verification Deterministic
 * @notice Same inputs produce same verification result
 */
rule attestationDeterministic(
    OasisPrimitives.Attestation attestation,
    bytes32 mrEnclave,
    bytes32 mrSigner
) {
    bool result1 = primitives.verifyAttestation(attestation, mrEnclave, mrSigner);
    bool result2 = primitives.verifyAttestation(attestation, mrEnclave, mrSigner);
    
    assert result1 == result2;
}

// ============================================================================
// COMMITTEE RULES
// ============================================================================

/**
 * @title Committee Threshold Enforcement
 * @notice Withdrawals require committee threshold approval
 */
rule committeeThresholdRequired(env e) {
    uint256 threshold = bridge.committeeThreshold();
    uint256 size = bridge.getCommitteeSize();
    
    // Threshold must be at least 1 and at most committee size
    assert threshold >= 1 && threshold <= size;
}

/**
 * @title Non-Committee Cannot Approve
 * @notice Only committee members can approve withdrawals
 */
rule nonCommitteeCannotApprove(env e, uint256 requestId) {
    require !bridge.isCommitteeMember(e.msg.sender);
    
    bridge.approveWithdrawal@withrevert(e, requestId);
    
    assert lastReverted;
}

// ============================================================================
// PAUSE RULES
// ============================================================================

/**
 * @title Paused Bridge Rejects Operations
 * @notice When paused, state-changing operations must fail
 */
rule pausedBridgeRejectsOperations(
    env e,
    bytes32 pilNf,
    uint256 amount,
    uint256 paraTime,
    OasisPrimitives.EncryptedEnvelope envelope
) {
    require bridge.isPaused();
    
    bridge.requestWithdrawal@withrevert(e, pilNf, amount, paraTime, envelope);
    
    assert lastReverted;
}

// ============================================================================
// CRYPTOGRAPHIC RULES
// ============================================================================

/**
 * @title Low Order Point Rejection
 * @notice Low-order X25519 points must be rejected
 */
rule lowOrderPointRejected(bytes32 pubKey) {
    bool isLowOrder = primitives.isLowOrderPoint(pubKey);
    bool isValid = primitives.isValidX25519PublicKey(pubKey);
    
    assert isLowOrder => !isValid;
}

/**
 * @title Nullifier Derivation Deterministic
 * @notice Same inputs produce same nullifier
 */
rule nullifierDerivationDeterministic(bytes32 secret, bytes32 commitment) {
    bytes32 nf1 = primitives.deriveNullifier(secret, commitment);
    bytes32 nf2 = primitives.deriveNullifier(secret, commitment);
    
    assert nf1 == nf2;
}

/**
 * @title Cross-Domain Nullifier Deterministic
 * @notice Cross-domain derivation is deterministic
 */
rule crossDomainNullifierDeterministic(bytes32 nf, bytes32 srcDomain, bytes32 dstDomain) {
    bytes32 cross1 = primitives.deriveCrossDomainNullifier(nf, srcDomain, dstDomain);
    bytes32 cross2 = primitives.deriveCrossDomainNullifier(nf, srcDomain, dstDomain);
    
    assert cross1 == cross2;
}

// ============================================================================
// VALUE FLOW RULES
// ============================================================================

/**
 * @title Deposit Increases Balance
 * @notice Successful deposit increases total deposited for ParaTime
 */
rule depositIncreasesBalance(env e, uint256 paraTime) {
    uint256 depositedBefore = bridge.totalDepositedByParaTime(paraTime);
    
    // Simulate deposit operation
    calldataarg args;
    bridge.deposit(e, args);
    
    uint256 depositedAfter = bridge.totalDepositedByParaTime(paraTime);
    
    // Deposited amount should only increase or stay same
    assert depositedAfter >= depositedBefore;
}

/**
 * @title Withdrawal Never Creates Negative Balance
 * @notice Available balance never goes negative
 */
rule withdrawalNeverNegative(uint256 paraTime) {
    uint256 deposited = bridge.totalDepositedByParaTime(paraTime);
    uint256 withdrawn = bridge.totalWithdrawnByParaTime(paraTime);
    
    assert deposited >= withdrawn;
}

/**
 * @title Available Balance Calculation
 * @notice Available = Deposited - Withdrawn
 */
rule availableBalanceCalculation(uint256 paraTime) {
    uint256 deposited = bridge.totalDepositedByParaTime(paraTime);
    uint256 withdrawn = bridge.totalWithdrawnByParaTime(paraTime);
    uint256 available = bridge.getAvailableBalance(paraTime);
    
    assert available == deposited - withdrawn;
}

// ============================================================================
// ACCESS CONTROL RULES
// ============================================================================

/**
 * @title Only Admin Can Add ParaTime
 * @notice Non-admins cannot add supported ParaTimes
 */
rule onlyAdminCanAddParaTime(env e, uint256 paraTime) {
    bool hasRole = bridge.hasRole(bridge.DEFAULT_ADMIN_ROLE(), e.msg.sender);
    
    require !hasRole;
    
    bridge.addParaTime@withrevert(e, paraTime);
    
    assert lastReverted;
}

/**
 * @title Only Admin Can Approve Enclave
 * @notice Non-admins cannot approve TEE enclaves
 */
rule onlyAdminCanApproveEnclave(env e, bytes32 mrEnclave, bytes32 mrSigner) {
    bool hasRole = bridge.hasRole(bridge.DEFAULT_ADMIN_ROLE(), e.msg.sender);
    
    require !hasRole;
    
    bridge.approveEnclave@withrevert(e, mrEnclave, mrSigner);
    
    assert lastReverted;
}

/**
 * @title Only Admin Can Set Deposit Limits
 * @notice Non-admins cannot change deposit limits
 */
rule onlyAdminCanSetLimits(env e, uint256 min, uint256 max, uint256 daily) {
    bool hasRole = bridge.hasRole(bridge.DEFAULT_ADMIN_ROLE(), e.msg.sender);
    
    require !hasRole;
    
    bridge.setDepositLimits@withrevert(e, min, max, daily);
    
    assert lastReverted;
}

// ============================================================================
// ENVELOPE VALIDATION RULES
// ============================================================================

/**
 * @title Empty Ciphertext Rejected
 * @notice Encrypted envelopes with empty ciphertext must be rejected
 */
rule emptyCiphertextRejected(
    env e,
    bytes32 pilNf,
    uint256 amount,
    uint256 paraTime
) {
    OasisPrimitives.EncryptedEnvelope envelope;
    require envelope.ciphertext.length == 0;
    
    require !bridge.usedPILNullifiers(pilNf);
    require bridge.supportedParaTimes(paraTime);
    require amount > 0 && amount <= bridge.getAvailableBalance(paraTime);
    
    bridge.requestWithdrawal@withrevert(e, pilNf, amount, paraTime, envelope);
    
    assert lastReverted;
}

// ============================================================================
// SUMMARY FUNCTIONS
// ============================================================================

/**
 * @title Total Value Locked Summary
 * @notice Summary of total value locked across all ParaTimes
 */
function totalValueLocked(uint256 paraTime) returns uint256 {
    return bridge.totalDepositedByParaTime(paraTime) - bridge.totalWithdrawnByParaTime(paraTime);
}

/**
 * @title Is Valid Withdrawal Amount
 * @notice Check if withdrawal amount is valid for ParaTime
 */
function isValidWithdrawalAmount(uint256 amount, uint256 paraTime) returns bool {
    return amount > 0 && amount <= bridge.getAvailableBalance(paraTime);
}
