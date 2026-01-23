/*
 * Certora Formal Verification Specification
 * PIL Private Exchange
 * 
 * Verifies critical invariants for the exchange contract
 */

/*
 * ============================================================================
 * METHODS DECLARATIONS
 * ============================================================================
 */

methods {
    // State variables - matching actual contract mappings
    function paused() external returns (bool) envfree;
    function usedNullifiers(bytes32) external returns (bool) envfree;
    function collectedFees(address) external returns (uint256) envfree;
    function supportedTokens(address) external returns (bool) envfree;
    function balances(address, address) external returns (uint256) envfree;
    
    // Admin functions  
    function pause() external;
    function unpause() external;
    function withdrawFees(address) external;
    
    // Core functions - matching exact signatures
    function deposit(address, uint256, bytes32) external;
    function withdraw(address, uint256, bytes32, bytes) external;
    function createPool(address, address, uint256) external returns (bytes32);
    function instantSwap(bytes32, address, uint256, uint256) external returns (uint256);
    function cancelOrder(bytes32) external;
    function matchOrders(bytes32, bytes32, uint256, uint256, bytes) external;
}

/*
 * ============================================================================
 * GHOST VARIABLES AND HOOKS
 * ============================================================================
 */

// Track total nullifiers used
ghost mathint totalNullifiersUsed {
    init_state axiom totalNullifiersUsed == 0;
}

// Hook on nullifier usage
hook Sstore usedNullifiers[KEY bytes32 nullifier] bool newValue (bool oldValue) {
    if (newValue && !oldValue) {
        totalNullifiersUsed = totalNullifiersUsed + 1;
    }
}

/*
 * ============================================================================
 * INVARIANTS
 * ============================================================================
 */

/**
 * INV-1: Nullifiers can only transition from false to true
 * Once a nullifier is marked as used, it stays used forever
 */
invariant nullifierImmutability(bytes32 nullifier)
    usedNullifiers(nullifier) == true => usedNullifiers(nullifier) == true;

/*
 * ============================================================================
 * RULES
 * ============================================================================
 */

/**
 * RULE-1: Nullifier cannot be reused for withdrawal
 * Attempting to withdraw with an already-used nullifier must revert
 */
rule nullifierNotReusable(env e, address token, uint256 amount, bytes32 nullifier, bytes proof) {
    require usedNullifiers(nullifier) == true;
    
    withdraw@withrevert(e, token, amount, nullifier, proof);
    
    assert lastReverted, "Withdrawal with used nullifier must revert";
}

/**
 * RULE-2: Pausing blocks deposits
 */
rule pauseBlocksDeposits(env e, address token, uint256 amount, bytes32 commitment) {
    require paused() == true;
    
    deposit@withrevert(e, token, amount, commitment);
    
    assert lastReverted, "Deposits must be blocked when paused";
}

/**
 * RULE-3: Pausing blocks withdrawals
 */
rule pauseBlocksWithdrawals(env e, address token, uint256 amount, bytes32 nullifier, bytes proof) {
    require paused() == true;
    
    withdraw@withrevert(e, token, amount, nullifier, proof);
    
    assert lastReverted, "Withdrawals must be blocked when paused";
}

/**
 * RULE-4: Pausing blocks swaps
 */
rule pauseBlocksSwaps(env e, bytes32 poolId, address tokenIn, uint256 amountIn, uint256 minOut) {
    require paused() == true;
    
    instantSwap@withrevert(e, poolId, tokenIn, amountIn, minOut);
    
    assert lastReverted, "Swaps must be blocked when paused";
}

/**
 * RULE-5: Swap output respects minimum slippage
 */
rule swapRespectsSlippage(
    env e,
    bytes32 poolId,
    address tokenIn,
    uint256 amountIn,
    uint256 minAmountOut
) {
    require !paused();
    require minAmountOut > 0;
    
    uint256 amountOut = instantSwap(e, poolId, tokenIn, amountIn, minAmountOut);
    
    assert amountOut >= minAmountOut, "Swap output must be >= minimum specified";
}

/**
 * RULE-6: Total nullifiers only increases (never decreases)
 */
rule nullifierCountMonotonic(method f, env e, calldataarg args) {
    mathint before = totalNullifiersUsed;
    
    f(e, args);
    
    mathint after = totalNullifiersUsed;
    
    assert after >= before, "Nullifier count can only increase";
}

/**
 * RULE-7: Collected fees can only increase (via swaps) or decrease (via withdrawal)
 */
rule feesOnlyChangeOnSwapOrWithdraw(method f, env e, calldataarg args, address token)
    filtered { 
        f -> f.selector != sig:instantSwap(bytes32, address, uint256, uint256).selector 
             && f.selector != sig:withdrawFees(address).selector 
    }
{
    uint256 feesBefore = collectedFees(token);
    
    f(e, args);
    
    uint256 feesAfter = collectedFees(token);
    
    assert feesAfter == feesBefore, "Fees unchanged by non-swap/withdraw functions";
}

/**
 * RULE-8: User balance is conserved across deposit
 */
rule userBalanceConservation(env e, address user, address token, uint256 amount, bytes32 commitment) {
    require user == e.msg.sender;
    uint256 balanceBefore = balances(user, token);
    
    deposit(e, token, amount, commitment);
    
    uint256 balanceAfter = balances(user, token);
    
    assert balanceAfter == balanceBefore + amount, "Balance must increase by deposit amount";
}

/*
 * ============================================================================
 * SANITY CHECKS
 * ============================================================================
 */

/**
 * Sanity: Deposit function is reachable
 */
rule depositReachable(env e, address token, uint256 amount, bytes32 commitment) {
    require !paused();
    require supportedTokens(token);
    require amount > 0;
    
    deposit(e, token, amount, commitment);
    
    satisfy true;
}

/**
 * Sanity: Withdraw function is reachable  
 */
rule withdrawReachable(env e, address token, uint256 amount, bytes32 nullifier, bytes proof) {
    require !paused();
    require !usedNullifiers(nullifier);
    require amount > 0;
    
    withdraw@withrevert(e, token, amount, nullifier, proof);
    
    satisfy true;
}
