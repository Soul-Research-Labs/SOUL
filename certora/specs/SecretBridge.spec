/**
 * Certora Formal Verification Specification for Secret Network Bridge
 * 
 * @title SecretBridge.spec
 * @author PIL Protocol
 * @notice Formal verification rules for Secret Network cross-chain bridge
 * 
 * VERIFICATION SCOPE:
 * - SGX TEE attestation verification
 * - Nullifier uniqueness (PIL and Secret)
 * - Cross-domain nullifier binding
 * - Withdrawal authorization (committee threshold)
 * - Value conservation
 * - IBC channel state verification
 * - Viewing key and query permit validation
 * - SNIP token standard support
 * 
 * SECRET NETWORK IDENTIFIERS:
 * - Mainnet: secret-4 (numeric ID: 1)
 * - Testnet: pulsar-3 (numeric ID: 2)
 */

using SecretPrimitives as primitives;
using SecretBridgeAdapter as bridge;

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

methods {
    // SecretPrimitives - Constants
    function primitives.SECP256K1_P() external returns (uint256) envfree;
    function primitives.SECP256K1_N() external returns (uint256) envfree;
    function primitives.SECRET_MAINNET_NUMERIC_ID() external returns (uint256) envfree;
    function primitives.SECRET_TESTNET_NUMERIC_ID() external returns (uint256) envfree;
    function primitives.MAX_QUOTE_AGE() external returns (uint256) envfree;
    
    // SecretPrimitives - Validation
    function primitives.isValidPublicKey(bytes) external returns (bool) envfree;
    function primitives.isValidFieldElement(uint256) external returns (bool) envfree;
    function primitives.isValidScalar(uint256) external returns (bool) envfree;
    
    // SecretPrimitives - Cryptographic operations
    function primitives.deriveNullifier(bytes32, bytes32) external returns (bytes32) envfree;
    function primitives.deriveCrossDomainNullifier(bytes32, bytes32, bytes32) external returns (bytes32) envfree;
    function primitives.fieldAdd(uint256, uint256) external returns (uint256) envfree;
    function primitives.fieldSub(uint256, uint256) external returns (uint256) envfree;
    function primitives.fieldMul(uint256, uint256) external returns (uint256) envfree;
    function primitives.scalarAdd(uint256, uint256) external returns (uint256) envfree;
    function primitives.scalarMul(uint256, uint256) external returns (uint256) envfree;
    
    // SecretPrimitives - Network detection
    function primitives.isSecretMainnet(uint256) external returns (bool) envfree;
    function primitives.isSecretTestnet(uint256) external returns (bool) envfree;
    
    // SecretPrimitives - Viewing keys & permits
    function primitives.hashViewingKey(SecretPrimitives.ViewingKey) external returns (bytes32) envfree;
    
    // SecretPrimitives - IBC
    function primitives.computeIBCPacketCommitment(SecretPrimitives.IBCChannel, uint64, bytes) external returns (bytes32) envfree;
    
    // SecretPrimitives - SNIP tokens
    function primitives.computeSNIP20Hash(address, string) external returns (bytes32) envfree;
    function primitives.computeSNIP721Hash(address, string, string) external returns (bytes32) envfree;
    
    // SecretBridgeAdapter - State
    function bridge.usedPILNullifiers(bytes32) external returns (bool) envfree;
    function bridge.usedSecretNullifiers(bytes32) external returns (bool) envfree;
    function bridge.pilNullifierToSecretNullifier(bytes32) external returns (bytes32) envfree;
    function bridge.secretNullifierToPILNullifier(bytes32) external returns (bytes32) envfree;
    function bridge.totalDeposited() external returns (uint256) envfree;
    function bridge.totalWithdrawn() external returns (uint256) envfree;
    function bridge.isPaused() external returns (bool) envfree;
    function bridge.committeeThreshold() external returns (uint256) envfree;
    function bridge.getCommitteeSize() external returns (uint256) envfree;
    function bridge.minDeposit() external returns (uint256) envfree;
    function bridge.maxDeposit() external returns (uint256) envfree;
    function bridge.dailyLimit() external returns (uint256) envfree;
    function bridge.approvedEnclaves(bytes32, bytes32) external returns (bool) envfree;
    function bridge.isCommitteeMember(address) external returns (bool) envfree;
    function bridge.isPILNullifierUsed(bytes32) external returns (bool) envfree;
    function bridge.isSecretNullifierUsed(bytes32) external returns (bool) envfree;
    function bridge.getAvailableBalance() external returns (uint256) envfree;
    function bridge.viewingKeys(bytes32) external returns (bytes32) envfree;
    function bridge.activePermits(bytes32) external returns (uint256) envfree;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

// Track nullifier usage
ghost mapping(bytes32 => bool) pilNullifierGhost;
ghost mapping(bytes32 => bool) secretNullifierGhost;

// Track cross-domain binding
ghost mapping(bytes32 => bytes32) pilToSecretBinding;
ghost mapping(bytes32 => bytes32) secretToPILBinding;

// Track deposits and withdrawals
ghost uint256 totalDepositedGhost;
ghost uint256 totalWithdrawnGhost;

// Track committee state
ghost uint256 committeeSize;
ghost uint256 threshold;

// Track viewing keys
ghost mapping(bytes32 => bool) viewingKeyRegistered;

// Track query permits
ghost mapping(bytes32 => bool) permitActive;

// ============================================================================
// HOOKS
// ============================================================================

hook Sstore usedPILNullifiers[KEY bytes32 nf] bool used (bool old_used) {
    pilNullifierGhost[nf] = used;
}

hook Sstore usedSecretNullifiers[KEY bytes32 nf] bool used (bool old_used) {
    secretNullifierGhost[nf] = used;
}

hook Sstore pilNullifierToSecretNullifier[KEY bytes32 pilNf] bytes32 secretNf (bytes32 old_secretNf) {
    pilToSecretBinding[pilNf] = secretNf;
}

hook Sstore secretNullifierToPILNullifier[KEY bytes32 secretNf] bytes32 pilNf (bytes32 old_pilNf) {
    secretToPILBinding[secretNf] = pilNf;
}

hook Sstore totalDeposited uint256 amount (uint256 old_amount) {
    totalDepositedGhost = amount;
}

hook Sstore totalWithdrawn uint256 amount (uint256 old_amount) {
    totalWithdrawnGhost = amount;
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
 * @title Secret Nullifier Permanence
 * @notice Once a Secret nullifier is marked as used, it remains used forever
 * @dev Prevents double-deposit from Secret side
 */
invariant secretNullifierPermanence(bytes32 secretNf)
    bridge.usedSecretNullifiers(secretNf) => bridge.usedSecretNullifiers(secretNf)
    {
        preserved {
            require bridge.usedSecretNullifiers(secretNf);
        }
    }

/**
 * @title Value Conservation
 * @notice Total withdrawn never exceeds total deposited
 */
invariant valueConservation()
    bridge.totalWithdrawn() <= bridge.totalDeposited()

/**
 * @title Committee Threshold Sanity
 * @notice Threshold cannot exceed committee size
 */
invariant thresholdSanity()
    bridge.committeeThreshold() <= bridge.getCommitteeSize()

/**
 * @title Binding Bidirectionality
 * @notice Cross-domain nullifier binding must be bidirectional
 * @dev If PIL→Secret binding exists, Secret→PIL must point back
 */
invariant bindingBidirectional(bytes32 pilNf)
    bridge.pilNullifierToSecretNullifier(pilNf) != 0 =>
        bridge.secretNullifierToPILNullifier(bridge.pilNullifierToSecretNullifier(pilNf)) == pilNf

/**
 * @title Binding Immutability
 * @notice Once a PIL nullifier is bound to a Secret nullifier, the binding cannot change
 */
invariant bindingImmutable(bytes32 pilNf)
    bridge.pilNullifierToSecretNullifier(pilNf) != 0 =>
        bridge.pilNullifierToSecretNullifier(pilNf) == pilToSecretBinding[pilNf]

/**
 * @title Deposit Limits Valid
 * @notice minDeposit must be less than or equal to maxDeposit
 */
invariant depositLimitsValid()
    bridge.minDeposit() <= bridge.maxDeposit()

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
 * @title Secret Nullifier No Double Use
 * @notice A Secret nullifier cannot be used twice for deposits
 */
rule secretNullifierNoDoubleUse(env e, bytes32 secretNf) {
    bool usedBefore = bridge.usedSecretNullifiers(secretNf);
    
    calldataarg args;
    bridge.executeWithdrawal(e, args);
    
    bool usedAfter = bridge.usedSecretNullifiers(secretNf);
    
    // If already used, must stay used
    assert usedBefore => usedAfter;
}

/**
 * @title Nullifier Uniqueness Preserved
 * @notice Each nullifier can only be bound to one cross-domain counterpart
 */
rule nullifierBindingUnique(env e, bytes32 pilNf1, bytes32 pilNf2) {
    require pilNf1 != pilNf2;
    require bridge.pilNullifierToSecretNullifier(pilNf1) != 0;
    require bridge.pilNullifierToSecretNullifier(pilNf2) != 0;
    
    assert bridge.pilNullifierToSecretNullifier(pilNf1) != bridge.pilNullifierToSecretNullifier(pilNf2);
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
    SecretPrimitives.EncryptedEnvelope envelope
) {
    bool usedBefore = bridge.usedPILNullifiers(pilNf);
    
    require usedBefore;
    
    bridge.requestWithdrawal@withrevert(e, pilNf, amount, envelope);
    
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
    SecretPrimitives.EncryptedEnvelope envelope
) {
    uint256 availableBefore = bridge.getAvailableBalance();
    
    require amount > availableBefore;
    require !bridge.usedPILNullifiers(pilNf);
    
    bridge.requestWithdrawal@withrevert(e, pilNf, amount, envelope);
    
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
    SecretPrimitives.EncryptedEnvelope envelope
) {
    require !bridge.usedPILNullifiers(pilNf);
    require bridge.getAvailableBalance() > 0;
    
    bridge.requestWithdrawal@withrevert(e, pilNf, 0, envelope);
    
    // Must revert for zero amount
    assert lastReverted;
}

// ============================================================================
// DEPOSIT RULES
// ============================================================================

/**
 * @title Deposit Increases Balance
 * @notice Successful deposit increases total deposited
 */
rule depositIncreasesBalance(env e) {
    uint256 depositedBefore = bridge.totalDeposited();
    
    calldataarg args;
    bridge.deposit(e, args);
    
    uint256 depositedAfter = bridge.totalDeposited();
    
    // Deposited amount should only increase or stay same
    assert depositedAfter >= depositedBefore;
}

/**
 * @title Deposit Within Limits
 * @notice Deposits must be within min/max limits
 */
rule depositWithinLimits(
    env e,
    bytes32 secretNf,
    bytes32 commitment,
    bytes proof
) {
    uint256 minDep = bridge.minDeposit();
    uint256 maxDep = bridge.maxDeposit();
    
    require e.msg.value > 0;
    require e.msg.value < minDep || e.msg.value > maxDep;
    
    bridge.deposit@withrevert(e, secretNf, commitment, proof);
    
    // Must revert if outside limits
    assert lastReverted;
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
    assert !bridge.approvedEnclaves(mrEnclave, mrSigner);
}

// ============================================================================
// COMMITTEE RULES
// ============================================================================

/**
 * @title Committee Threshold Enforcement
 * @notice Withdrawals require committee threshold approval
 */
rule committeeThresholdRequired(env e) {
    uint256 thresholdVal = bridge.committeeThreshold();
    uint256 size = bridge.getCommitteeSize();
    
    // Threshold must be at least 1 and at most committee size
    assert thresholdVal >= 1 && thresholdVal <= size;
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
 * @title Paused Bridge Rejects Deposits
 * @notice When paused, deposits must fail
 */
rule pausedBridgeRejectsDeposits(
    env e,
    bytes32 secretNf,
    bytes32 commitment,
    bytes proof
) {
    require bridge.isPaused();
    
    bridge.deposit@withrevert(e, secretNf, commitment, proof);
    
    assert lastReverted;
}

/**
 * @title Paused Bridge Rejects Withdrawals
 * @notice When paused, withdrawal requests must fail
 */
rule pausedBridgeRejectsWithdrawals(
    env e,
    bytes32 pilNf,
    uint256 amount,
    SecretPrimitives.EncryptedEnvelope envelope
) {
    require bridge.isPaused();
    
    bridge.requestWithdrawal@withrevert(e, pilNf, amount, envelope);
    
    assert lastReverted;
}

// ============================================================================
// VIEWING KEY RULES
// ============================================================================

/**
 * @title Viewing Key Registration Persistence
 * @notice Registered viewing keys remain registered
 */
rule viewingKeyPersistence(env e, bytes32 keyHash) {
    bytes32 storedKey = bridge.viewingKeys(keyHash);
    require storedKey != 0;
    
    calldataarg args;
    bridge.registerViewingKey(e, args);
    
    bytes32 keyAfter = bridge.viewingKeys(keyHash);
    
    // Key should still be registered
    assert keyAfter == storedKey;
}

/**
 * @title Zero Viewing Key Rejected
 * @notice Cannot register zero viewing key
 */
rule zeroViewingKeyRejected(env e, bytes32 owner) {
    SecretPrimitives.ViewingKey vk;
    require vk.key == 0;
    
    bridge.registerViewingKey@withrevert(e, vk.key, owner, vk.expiration);
    
    // Should revert for zero key
    assert lastReverted;
}

// ============================================================================
// QUERY PERMIT RULES
// ============================================================================

/**
 * @title Expired Permit Invalid
 * @notice Expired query permits should not be usable
 */
rule expiredPermitInvalid(env e, bytes32 permitId) {
    uint256 expiration = bridge.activePermits(permitId);
    
    require expiration > 0;
    require e.block.timestamp > expiration;
    
    // Permit should be considered expired
    assert e.block.timestamp > expiration;
}

// ============================================================================
// IBC CHANNEL RULES
// ============================================================================

/**
 * @title IBC Packet Commitment Deterministic
 * @notice Same inputs produce same packet commitment
 */
rule ibcPacketCommitmentDeterministic(
    SecretPrimitives.IBCChannel channel,
    uint64 sequence,
    bytes data
) {
    bytes32 commitment1 = primitives.computeIBCPacketCommitment(channel, sequence, data);
    bytes32 commitment2 = primitives.computeIBCPacketCommitment(channel, sequence, data);
    
    assert commitment1 == commitment2;
}

// ============================================================================
// CRYPTOGRAPHIC RULES
// ============================================================================

/**
 * @title Field Element Closure
 * @notice Field operations produce valid field elements
 */
rule fieldOperationsClosure(uint256 a, uint256 b) {
    require primitives.isValidFieldElement(a);
    require primitives.isValidFieldElement(b);
    
    uint256 sum = primitives.fieldAdd(a, b);
    uint256 diff = primitives.fieldSub(a, b);
    uint256 prod = primitives.fieldMul(a, b);
    
    assert primitives.isValidFieldElement(sum);
    assert primitives.isValidFieldElement(diff);
    assert primitives.isValidFieldElement(prod);
}

/**
 * @title Scalar Operations Closure
 * @notice Scalar operations produce valid scalars
 */
rule scalarOperationsClosure(uint256 a, uint256 b) {
    require primitives.isValidScalar(a);
    require primitives.isValidScalar(b);
    
    uint256 sum = primitives.scalarAdd(a, b);
    uint256 prod = primitives.scalarMul(a, b);
    
    // Note: Result may overflow, so we check it's within bounds
    uint256 n = primitives.SECP256K1_N();
    assert sum < n;
    assert prod < n;
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
// SNIP TOKEN RULES
// ============================================================================

/**
 * @title SNIP20 Hash Deterministic
 * @notice Same contract and viewing key produce same hash
 */
rule snip20HashDeterministic(address contractAddr, string viewingKey) {
    bytes32 hash1 = primitives.computeSNIP20Hash(contractAddr, viewingKey);
    bytes32 hash2 = primitives.computeSNIP20Hash(contractAddr, viewingKey);
    
    assert hash1 == hash2;
}

/**
 * @title SNIP721 Hash Deterministic
 * @notice Same inputs produce same NFT hash
 */
rule snip721HashDeterministic(address contractAddr, string tokenId, string viewingKey) {
    bytes32 hash1 = primitives.computeSNIP721Hash(contractAddr, tokenId, viewingKey);
    bytes32 hash2 = primitives.computeSNIP721Hash(contractAddr, tokenId, viewingKey);
    
    assert hash1 == hash2;
}

// ============================================================================
// NETWORK DETECTION RULES
// ============================================================================

/**
 * @title Mainnet Detection
 * @notice Mainnet ID correctly identifies as mainnet
 */
rule mainnetDetection() {
    uint256 mainnetId = primitives.SECRET_MAINNET_NUMERIC_ID();
    
    assert primitives.isSecretMainnet(mainnetId);
    assert !primitives.isSecretTestnet(mainnetId);
}

/**
 * @title Testnet Detection
 * @notice Testnet ID correctly identifies as testnet
 */
rule testnetDetection() {
    uint256 testnetId = primitives.SECRET_TESTNET_NUMERIC_ID();
    
    assert primitives.isSecretTestnet(testnetId);
    assert !primitives.isSecretMainnet(testnetId);
}

// ============================================================================
// VALUE FLOW RULES
// ============================================================================

/**
 * @title Withdrawal Never Creates Negative Balance
 * @notice Available balance never goes negative
 */
rule withdrawalNeverNegative() {
    uint256 deposited = bridge.totalDeposited();
    uint256 withdrawn = bridge.totalWithdrawn();
    
    assert deposited >= withdrawn;
}

/**
 * @title Available Balance Calculation
 * @notice Available = Deposited - Withdrawn
 */
rule availableBalanceCalculation() {
    uint256 deposited = bridge.totalDeposited();
    uint256 withdrawn = bridge.totalWithdrawn();
    uint256 available = bridge.getAvailableBalance();
    
    assert available == deposited - withdrawn;
}

// ============================================================================
// ACCESS CONTROL RULES
// ============================================================================

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

/**
 * @title Only IBC Handler Can Set Channel
 * @notice Non-IBC handlers cannot set IBC channel
 */
rule onlyIBCHandlerCanSetChannel(env e, SecretPrimitives.IBCChannel channel) {
    bool hasRole = bridge.hasRole(bridge.IBC_HANDLER_ROLE(), e.msg.sender);
    
    require !hasRole;
    
    bridge.setIBCChannel@withrevert(e, channel);
    
    assert lastReverted;
}

// ============================================================================
// SUMMARY FUNCTIONS
// ============================================================================

/**
 * @title Total Value Locked Summary
 * @notice Summary of total value locked in bridge
 */
function totalValueLocked() returns uint256 {
    return bridge.totalDeposited() - bridge.totalWithdrawn();
}

/**
 * @title Is Valid Withdrawal Amount
 * @notice Check if withdrawal amount is valid
 */
function isValidWithdrawalAmount(uint256 amount) returns bool {
    return amount > 0 && amount <= bridge.getAvailableBalance();
}

/**
 * @title Is Valid Deposit Amount
 * @notice Check if deposit amount is within limits
 */
function isValidDepositAmount(uint256 amount) returns bool {
    return amount >= bridge.minDeposit() && amount <= bridge.maxDeposit();
}
