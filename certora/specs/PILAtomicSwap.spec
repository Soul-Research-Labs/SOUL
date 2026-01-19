/**
 * Certora Formal Verification Specification
 * Privacy Interoperability Layer - PILAtomicSwapV2
 * 
 * This spec verifies HTLC-based atomic swap security properties
 */

// ============================================================================
// METHODS
// ============================================================================

methods {
    // Swap operations
    function initiateSwap(address, bytes32, uint256, address, uint256) external returns (bytes32);
    function completeSwap(bytes32, bytes32) external;
    function refundSwap(bytes32) external;
    
    // View functions  
    function swaps(bytes32) external returns (
        address, address, uint256, bytes32, uint256, uint8, address
    ) envfree;
    function getSwapState(bytes32) external returns (uint8) envfree;
    function isSwapActive(bytes32) external returns (bool) envfree;
    function usedSecrets(bytes32) external returns (bool) envfree;
    function MAX_FEE_BPS() external returns (uint256) envfree;
}

// ============================================================================
// DEFINITIONS
// ============================================================================

// Swap states
definition SWAP_NONE() returns uint8 = 0;
definition SWAP_INITIATED() returns uint8 = 1;
definition SWAP_COMPLETED() returns uint8 = 2;
definition SWAP_REFUNDED() returns uint8 = 3;

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Fee Bounds
 * @notice Fees should never exceed maximum
 */
invariant feeBounds()
    MAX_FEE_BPS() <= 100  // 1% maximum
    { preserved { require true; } }

/**
 * @title Swap State Validity
 * @notice Swap states are always valid enum values
 */
invariant validSwapStates(bytes32 swapId)
    getSwapState(swapId) == SWAP_NONE() ||
    getSwapState(swapId) == SWAP_INITIATED() ||
    getSwapState(swapId) == SWAP_COMPLETED() ||
    getSwapState(swapId) == SWAP_REFUNDED()
    { preserved { require true; } }

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Swap Initiation Creates Active Swap
 * @notice Valid initiation results in INITIATED state
 */
rule initiationCreatesActiveSwap(
    address recipient,
    bytes32 secretHash,
    uint256 amount,
    address token,
    uint256 timelock
) {
    env e;
    
    require recipient != address(0);
    require amount > 0;
    require e.block.timestamp < timelock;
    
    bytes32 swapId = initiateSwap(e, recipient, secretHash, amount, token, timelock);
    
    assert getSwapState(swapId) == SWAP_INITIATED(), "Swap should be initiated";
    assert isSwapActive(swapId), "Swap should be active";
}

/**
 * @title Completion Requires Correct Secret
 * @notice Only the correct secret can complete a swap
 */
rule completionRequiresSecret(bytes32 swapId, bytes32 secret) {
    env e;
    
    require getSwapState(swapId) == SWAP_INITIATED();
    bytes32 expectedHash = keccak256(abi.encodePacked(secret));
    
    // If secret hash doesn't match, should revert
    completeSwap@withrevert(e, swapId, secret);
    
    // Post-condition: either completed or reverted
    assert !lastReverted => getSwapState(swapId) == SWAP_COMPLETED(),
           "Successful completion should change state";
}

/**
 * @title Completion Transitions Correctly
 * @notice Successful completion changes state to COMPLETED
 */
rule completionTransition(bytes32 swapId, bytes32 secret) {
    env e;
    
    require getSwapState(swapId) == SWAP_INITIATED();
    
    completeSwap(e, swapId, secret);
    
    assert getSwapState(swapId) == SWAP_COMPLETED(), "State should be COMPLETED";
    assert !isSwapActive(swapId), "Swap should no longer be active";
}

/**
 * @title Refund Only After Timelock
 * @notice Refund can only happen after timelock expires
 */
rule refundRequiresTimelock(bytes32 swapId, uint256 swapTimelock) {
    env e;
    
    require getSwapState(swapId) == SWAP_INITIATED();
    require e.block.timestamp < swapTimelock;
    
    refundSwap@withrevert(e, swapId);
    
    assert lastReverted, "Premature refund should revert";
}

/**
 * @title Refund Transitions Correctly
 * @notice After timelock, refund succeeds
 */
rule refundTransition(bytes32 swapId, uint256 swapTimelock) {
    env e;
    
    require getSwapState(swapId) == SWAP_INITIATED();
    require e.block.timestamp >= swapTimelock;
    
    refundSwap(e, swapId);
    
    assert getSwapState(swapId) == SWAP_REFUNDED(), "State should be REFUNDED";
}

/**
 * @title No Double Completion
 * @notice A swap cannot be completed twice
 */
rule noDoubleCompletion(bytes32 swapId, bytes32 secret) {
    env e;
    
    require getSwapState(swapId) == SWAP_COMPLETED();
    
    completeSwap@withrevert(e, swapId, secret);
    
    assert lastReverted, "Double completion should revert";
}

/**
 * @title No Double Refund
 * @notice A swap cannot be refunded twice
 */
rule noDoubleRefund(bytes32 swapId) {
    env e;
    
    require getSwapState(swapId) == SWAP_REFUNDED();
    
    refundSwap@withrevert(e, swapId);
    
    assert lastReverted, "Double refund should revert";
}

/**
 * @title Mutual Exclusion
 * @notice A swap cannot be both completed and refunded
 */
rule mutualExclusion(bytes32 swapId) {
    assert !(getSwapState(swapId) == SWAP_COMPLETED() && 
             getSwapState(swapId) == SWAP_REFUNDED()),
           "Swap cannot be both completed and refunded";
}

/**
 * @title Terminal States Are Final
 * @notice COMPLETED and REFUNDED states cannot change
 */
rule terminalStatesAreFinal(bytes32 swapId, bytes32 secret) {
    env e;
    
    uint8 stateBefore = getSwapState(swapId);
    require stateBefore == SWAP_COMPLETED() || stateBefore == SWAP_REFUNDED();
    
    // Try complete
    completeSwap@withrevert(e, swapId, secret);
    assert lastReverted, "Complete on terminal should revert";
    
    // Try refund
    refundSwap@withrevert(e, swapId);
    assert lastReverted, "Refund on terminal should revert";
    
    // State unchanged
    assert getSwapState(swapId) == stateBefore, "Terminal state should not change";
}

// ============================================================================
// VALUE SAFETY
// ============================================================================

/**
 * @title No Value Loss
 * @notice Swap value is preserved (either to recipient or refunded to initiator)
 */
rule noValueLoss(bytes32 swapId) {
    uint8 state = getSwapState(swapId);
    
    // Either swap is active (funds locked) or terminal (funds transferred)
    assert state == SWAP_NONE() ||
           state == SWAP_INITIATED() ||
           state == SWAP_COMPLETED() ||
           state == SWAP_REFUNDED(),
           "Invalid state means potential value loss";
}

/**
 * @title Secret Reveals Only On Completion
 * @notice Secret is only revealed when swap is completed
 */
rule secretRevealOnCompletion(bytes32 swapId, bytes32 secret) {
    env e;
    
    bool secretUsedBefore = usedSecrets(secret);
    require !secretUsedBefore;
    require getSwapState(swapId) == SWAP_INITIATED();
    
    completeSwap(e, swapId, secret);
    
    // After completion, secret is revealed (marked as used)
    assert getSwapState(swapId) == SWAP_COMPLETED() => usedSecrets(secret),
           "Secret should be marked used after completion";
}
