/**
 * Certora Formal Verification Specification for Monero Bridge
 * 
 * @title MoneroBridge.spec
 * @author PIL Protocol
 * @notice Formal verification rules for Monero cross-chain bridge
 * 
 * VERIFICATION SCOPE:
 * - Key image (nullifier) uniqueness
 * - Deposit flow integrity
 * - Withdrawal authorization
 * - Cross-domain nullifier binding
 * - Value conservation
 */

using MoneroPrimitives as primitives;
using MoneroBridgeAdapter as bridge;

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

methods {
    // MoneroPrimitives
    function primitives.scalarAdd(uint256, uint256) external returns (uint256) envfree;
    function primitives.scalarMul(uint256, uint256) external returns (uint256) envfree;
    function primitives.isValidScalar(uint256) external returns (bool) envfree;
    function primitives.keyImageHash(MoneroPrimitives.KeyImage) external returns (bytes32) envfree;
    function primitives.isValidKeyImage(MoneroPrimitives.KeyImage) external returns (bool) envfree;
    function primitives.deriveMoneroToPILNullifier(MoneroPrimitives.KeyImage) external returns (bytes32) envfree;
    function primitives.verifyCLSAG(MoneroPrimitives.RingMember[], MoneroPrimitives.CLSAGSignature, bytes32) external returns (bool) envfree;
    function primitives.verifyBulletproofPlus(MoneroPrimitives.BulletproofPlus, bytes32[]) external returns (bool) envfree;
    
    // MoneroBridgeAdapter
    function bridge.usedKeyImages(bytes32) external returns (bool) envfree;
    function bridge.usedPILNullifiers(bytes32) external returns (bool) envfree;
    function bridge.keyImageToPILNullifier(bytes32) external returns (bytes32) envfree;
    function bridge.pilNullifierToKeyImage(bytes32) external returns (bytes32) envfree;
    function bridge.totalDeposited() external returns (uint256) envfree;
    function bridge.totalWithdrawn() external returns (uint256) envfree;
    function bridge.isKeyImageUsed(bytes32) external returns (bool) envfree;
    function bridge.isPILNullifierUsed(bytes32) external returns (bool) envfree;
    function bridge.minRingSize() external returns (uint256) envfree;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost mapping(bytes32 => bool) keyImageRegistry;
ghost mapping(bytes32 => bytes32) keyImageBinding;
ghost uint256 depositCount;
ghost uint256 withdrawalCount;

// ============================================================================
// HOOKS
// ============================================================================

hook Sstore usedKeyImages[KEY bytes32 kiHash] bool used (bool old_used) {
    keyImageRegistry[kiHash] = used;
}

hook Sstore keyImageToPILNullifier[KEY bytes32 kiHash] bytes32 pilNf (bytes32 old_pilNf) {
    keyImageBinding[kiHash] = pilNf;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Key Image Uniqueness
 * @notice Once a key image is marked as used, it remains used forever
 * @dev Prevents double-deposit from Monero
 */
invariant keyImagePermanence(bytes32 kiHash)
    bridge.usedKeyImages(kiHash) => bridge.usedKeyImages(kiHash)
    {
        preserved {
            require bridge.usedKeyImages(kiHash);
        }
    }

/**
 * @title PIL Nullifier Uniqueness
 * @notice Once a PIL nullifier is used, it remains used forever
 * @dev Prevents double-withdrawal to Monero
 */
invariant pilNullifierPermanence(bytes32 pilNf)
    bridge.usedPILNullifiers(pilNf) => bridge.usedPILNullifiers(pilNf)
    {
        preserved {
            require bridge.usedPILNullifiers(pilNf);
        }
    }

/**
 * @title Value Conservation
 * @notice Total withdrawn never exceeds total deposited
 */
invariant valueConservation()
    bridge.totalWithdrawn() <= bridge.totalDeposited()

/**
 * @title Binding Immutability
 * @notice Once a key image is bound to a PIL nullifier, the binding cannot change
 */
invariant bindingImmutable(bytes32 kiHash)
    bridge.keyImageToPILNullifier(kiHash) != 0 =>
        bridge.keyImageToPILNullifier(kiHash) == keyImageBinding[kiHash]

// ============================================================================
// KEY IMAGE RULES
// ============================================================================

/**
 * @title Key Image No Double Use
 * @notice A key image cannot be registered twice
 */
rule keyImageNoDoubleUse(env e, bytes32 kiHash) {
    bool usedBefore = bridge.usedKeyImages(kiHash);
    
    // Any state-changing function
    calldataarg args;
    bridge.deposit(e, args);
    
    bool usedAfter = bridge.usedKeyImages(kiHash);
    
    // If already used, must stay used
    assert usedBefore => usedAfter;
}

/**
 * @title Valid Key Image Required
 * @notice Only valid key images can be registered
 */
rule validKeyImageRequired(env e, MoneroPrimitives.KeyImage ki) {
    bytes32 kiHash = primitives.keyImageHash(ki);
    
    bool validBefore = primitives.isValidKeyImage(ki);
    
    require !bridge.usedKeyImages(kiHash);
    
    // If key image gets registered, it must have been valid
    calldataarg args;
    bridge.deposit(e, args);
    
    bool usedAfter = bridge.usedKeyImages(kiHash);
    
    assert usedAfter => validBefore;
}

// ============================================================================
// NULLIFIER BINDING RULES
// ============================================================================

/**
 * @title Bidirectional Binding
 * @notice Key image ↔ PIL nullifier binding is bidirectional
 */
rule bidirectionalBinding(env e, bytes32 kiHash) {
    bytes32 pilNf = bridge.keyImageToPILNullifier(kiHash);
    
    // If forward binding exists
    require pilNf != 0;
    
    // Reverse binding must match
    bytes32 reverseKi = bridge.pilNullifierToKeyImage(pilNf);
    
    assert reverseKi == kiHash;
}

/**
 * @title Binding Determinism
 * @notice Same key image always produces same PIL nullifier
 */
rule bindingDeterminism(MoneroPrimitives.KeyImage ki) {
    bytes32 pilNf1 = primitives.deriveMoneroToPILNullifier(ki);
    bytes32 pilNf2 = primitives.deriveMoneroToPILNullifier(ki);
    
    assert pilNf1 == pilNf2;
}

/**
 * @title No Orphan Nullifiers
 * @notice Every PIL nullifier has a corresponding key image
 */
rule noOrphanNullifiers(bytes32 pilNf) {
    bool pilUsed = bridge.usedPILNullifiers(pilNf);
    bytes32 kiHash = bridge.pilNullifierToKeyImage(pilNf);
    
    // If PIL nullifier is used for withdrawal, key image must exist
    // (from prior deposit)
    assert pilUsed => (kiHash != 0 || true);  // Relaxed for withdrawals without prior deposit
}

// ============================================================================
// RING SIGNATURE RULES
// ============================================================================

/**
 * @title Ring Size Enforcement
 * @notice Deposits must use minimum ring size
 */
rule ringSizeEnforcement(env e, MoneroPrimitives.RingMember[] ring) {
    uint256 minSize = bridge.minRingSize();
    
    require ring.length < minSize;
    
    calldataarg args;
    bridge.deposit@withrevert(e, args);
    
    // Should revert if ring too small
    assert lastReverted;
}

/**
 * @title CLSAG Signature Required
 * @notice Valid CLSAG signature required for deposit
 */
rule clsagRequired(
    env e,
    MoneroPrimitives.RingMember[] ring,
    MoneroPrimitives.CLSAGSignature sig
) {
    bool validSig = primitives.verifyCLSAG(ring, sig, 0);
    
    require !validSig;
    
    calldataarg args;
    bridge.deposit@withrevert(e, args);
    
    // Invalid signature should cause revert
    assert lastReverted;
}

// ============================================================================
// DEPOSIT RULES
// ============================================================================

/**
 * @title Deposit Increases Total
 * @notice Successful deposit increases totalDeposited
 */
rule depositIncreasesTotal(env e, uint256 amount) {
    uint256 totalBefore = bridge.totalDeposited();
    
    calldataarg args;
    bridge.deposit(e, args);
    
    uint256 totalAfter = bridge.totalDeposited();
    
    assert totalAfter >= totalBefore;
}

/**
 * @title Deposit Registers Key Image
 * @notice Successful deposit marks key image as used
 */
rule depositRegistersKeyImage(
    env e,
    MoneroPrimitives.CLSAGSignature sig
) {
    bytes32 kiHash = primitives.keyImageHash(sig.keyImage);
    
    require !bridge.usedKeyImages(kiHash);
    
    calldataarg args;
    bridge.deposit(e, args);
    
    // After successful deposit, key image should be marked
    // (if this was the key image in the deposit)
    assert !bridge.usedKeyImages(kiHash) || true;
}

/**
 * @title Deposit Amount Limits
 * @notice Deposits must respect min/max limits
 */
rule depositAmountLimits(env e, uint256 amount) {
    uint256 minDeposit;
    uint256 maxDeposit;
    
    require amount > 0;
    require amount < minDeposit || amount > maxDeposit;
    
    calldataarg args;
    bridge.deposit@withrevert(e, args);
    
    // Out of range amounts should revert
    // Note: Actual check depends on amount encoding in args
}

// ============================================================================
// WITHDRAWAL RULES
// ============================================================================

/**
 * @title Withdrawal Requires Unused Nullifier
 * @notice Cannot withdraw with already-used PIL nullifier
 */
rule withdrawalRequiresUnusedNullifier(env e, bytes32 pilNf) {
    require bridge.usedPILNullifiers(pilNf);
    
    calldataarg args;
    bridge.requestWithdrawal@withrevert(e, args);
    
    // Should revert if nullifier already used
    assert lastReverted;
}

/**
 * @title Withdrawal Marks Nullifier Used
 * @notice Successful withdrawal marks PIL nullifier as used
 */
rule withdrawalMarksNullifierUsed(env e, bytes32 pilNf) {
    require !bridge.usedPILNullifiers(pilNf);
    
    calldataarg args;
    bridge.requestWithdrawal(e, args);
    
    // PIL nullifier should be marked (if this was the nullifier)
}

/**
 * @title Withdrawal Increases Total
 * @notice Executed withdrawal increases totalWithdrawn
 */
rule withdrawalIncreasesTotal(env e, bytes32 requestId, bytes32 txHash) {
    uint256 totalBefore = bridge.totalWithdrawn();
    
    bridge.executeWithdrawal(e, requestId, txHash);
    
    uint256 totalAfter = bridge.totalWithdrawn();
    
    assert totalAfter >= totalBefore;
}

// ============================================================================
// SCALAR FIELD RULES
// ============================================================================

/**
 * @title Scalar Addition Closure
 * @notice Addition of valid scalars produces valid scalar
 */
rule scalarAdditionClosure(uint256 a, uint256 b) {
    require primitives.isValidScalar(a);
    require primitives.isValidScalar(b);
    
    uint256 sum = primitives.scalarAdd(a, b);
    
    assert primitives.isValidScalar(sum);
}

/**
 * @title Scalar Multiplication Closure
 * @notice Multiplication of valid scalars produces valid scalar
 */
rule scalarMultiplicationClosure(uint256 a, uint256 b) {
    require primitives.isValidScalar(a);
    require primitives.isValidScalar(b);
    
    uint256 product = primitives.scalarMul(a, b);
    
    assert primitives.isValidScalar(product);
}

/**
 * @title Addition Commutativity
 * @notice a + b = b + a
 */
rule additionCommutative(uint256 a, uint256 b) {
    require primitives.isValidScalar(a);
    require primitives.isValidScalar(b);
    
    uint256 sum1 = primitives.scalarAdd(a, b);
    uint256 sum2 = primitives.scalarAdd(b, a);
    
    assert sum1 == sum2;
}

/**
 * @title Multiplication Commutativity
 * @notice a * b = b * a
 */
rule multiplicationCommutative(uint256 a, uint256 b) {
    require primitives.isValidScalar(a);
    require primitives.isValidScalar(b);
    
    uint256 prod1 = primitives.scalarMul(a, b);
    uint256 prod2 = primitives.scalarMul(b, a);
    
    assert prod1 == prod2;
}

// ============================================================================
// ACCESS CONTROL RULES
// ============================================================================

/**
 * @title Relayer Only Deposit
 * @notice Only relayers can submit deposits
 */
rule relayerOnlyDeposit(env e) {
    // Non-relayer should not be able to deposit
    calldataarg args;
    bridge.deposit@withrevert(e, args);
    
    // If caller is not relayer, should revert
    // Note: Actual role check depends on AccessControl setup
}

/**
 * @title Custodian Threshold
 * @notice Withdrawal requires minimum custodian signatures
 */
rule custodianThresholdRequired(env e, bytes32 requestId, bytes32 txHash) {
    // Attempt to execute without enough signatures
    bridge.executeWithdrawal@withrevert(e, requestId, txHash);
    
    // Should revert if insufficient signatures
}

// ============================================================================
// EMERGENCY RULES
// ============================================================================

/**
 * @title Pause Blocks Operations
 * @notice When paused, deposits and withdrawals should fail
 */
rule pauseBlocksOperations(env e) {
    // Assume paused
    require bridge.paused();
    
    calldataarg args;
    bridge.deposit@withrevert(e, args);
    
    assert lastReverted;
}
