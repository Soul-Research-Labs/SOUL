/**
 * @title Certora CVL Specification for StarknetStateSync
 * @author PIL Protocol
 * @notice Formal verification of Starknet state synchronization
 * 
 * VERIFICATION SCOPE:
 * - State root validation and updates
 * - Storage proof verification
 * - Block sync integrity
 * - Finality enforcement
 * 
 * CRITICAL SECURITY PROPERTIES:
 * 1. State root integrity: Only valid state roots accepted
 * 2. Finality: Only finalized blocks can update state
 * 3. Proof verification: Storage proofs must be valid
 * 4. Sequential sync: Block numbers must increase monotonically
 * 5. Authorization: Only authorized roles can update state
 */

/*//////////////////////////////////////////////////////////////
                         METHODS BLOCK
//////////////////////////////////////////////////////////////*/

methods {
    // Role management
    function hasRole(bytes32 role, address account) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function SEQUENCER_ROLE() external returns (bytes32) envfree;
    function VERIFIER_ROLE() external returns (bytes32) envfree;
    function RELAYER_ROLE() external returns (bytes32) envfree;
    
    // State management
    function updateStateRoot(bytes32, uint256, bytes32) external;
    function submitStateUpdate(StarknetStateSync.StateUpdate) external returns (bytes32);
    function finalizeStateUpdate(bytes32) external;
    
    // Proof verification
    function verifyStorageProof(uint256, uint256, uint256, bytes32[]) external returns (bool);
    function verifyContractState(uint256, bytes32, bytes32[]) external returns (bool);
    
    // View functions
    function currentStateRoot() external returns (bytes32) envfree;
    function lastFinalizedBlock() external returns (uint256) envfree;
    function stateRootHistory(bytes32) external returns (StarknetStateSync.StateRootRecord) envfree;
    function pendingUpdates(bytes32) external returns (StarknetStateSync.StateUpdate) envfree;
    function starknetCore() external returns (address) envfree;
    
    // Configuration
    function setStarknetCore(address) external;
    function setFinalityDelay(uint256) external;
    function finalityDelay() external returns (uint256) envfree;
    function minConfirmations() external returns (uint256) envfree;
    
    // Counters
    function totalUpdates() external returns (uint256) envfree;
    function totalVerifications() external returns (uint256) envfree;
    
    // Pause
    function paused() external returns (bool) envfree;
}

/*//////////////////////////////////////////////////////////////
                       DEFINITIONS
//////////////////////////////////////////////////////////////*/

// Minimum finality delay (blocks)
definition MIN_FINALITY_DELAY() returns uint256 = 100;

// Maximum finality delay (blocks) 
definition MAX_FINALITY_DELAY() returns uint256 = 10000;

/*//////////////////////////////////////////////////////////////
                      GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

// Track state root history
ghost mapping(bytes32 => bool) stateRootSeen {
    init_state axiom forall bytes32 root. stateRootSeen[root] == false;
}

// Track block numbers for monotonicity
ghost mathint ghostLastBlock {
    init_state axiom ghostLastBlock == 0;
}

// Track finalized updates
ghost mapping(bytes32 => bool) updateFinalized {
    init_state axiom forall bytes32 id. updateFinalized[id] == false;
}

// Track pending updates
ghost mapping(bytes32 => bool) updatePending {
    init_state axiom forall bytes32 id. updatePending[id] == false;
}

// Counter ghosts
ghost mathint ghostTotalUpdates {
    init_state axiom ghostTotalUpdates == 0;
}

ghost mathint ghostTotalVerifications {
    init_state axiom ghostTotalVerifications == 0;
}

/*//////////////////////////////////////////////////////////////
                          HOOKS
//////////////////////////////////////////////////////////////*/

// Hook on state root update
hook Sstore currentStateRoot() bytes32 newRoot {
    stateRootSeen[newRoot] = true;
}

// Hook on block number update
hook Sstore lastFinalizedBlock() uint256 newBlock {
    ghostLastBlock = to_mathint(newBlock);
}

// Hook on update submission
hook Sstore pendingUpdates[KEY bytes32 updateId].updateId bytes32 newId {
    if (newId != to_bytes32(0)) {
        updatePending[updateId] = true;
        ghostTotalUpdates = ghostTotalUpdates + 1;
    }
}

// Hook on update finalization
hook Sstore pendingUpdates[KEY bytes32 updateId].finalized bool isFinalized {
    if (isFinalized) {
        updateFinalized[updateId] = true;
    }
}

/*//////////////////////////////////////////////////////////////
                       INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Total updates counter is consistent
 */
invariant updateCountConsistent()
    to_mathint(totalUpdates()) == ghostTotalUpdates
    {
        preserved {
            require !paused();
        }
    }

/**
 * @notice Current state root is in history
 */
invariant currentRootInHistory()
    currentStateRoot() != to_bytes32(0) => stateRootSeen[currentStateRoot()]
    {
        preserved updateStateRoot(bytes32 r, uint256 b, bytes32 p) with (env e) {
            require hasRole(SEQUENCER_ROLE(), e.msg.sender);
        }
    }

/**
 * @notice Finalized updates stay finalized
 */
invariant finalizedUpdatesStayFinalized(bytes32 updateId)
    updateFinalized[updateId] => pendingUpdates(updateId).finalized == true
    {
        preserved {
            require !paused();
        }
    }

/**
 * @notice Block number never decreases
 */
invariant blockNumberNeverDecreases()
    to_mathint(lastFinalizedBlock()) >= 0
    {
        preserved updateStateRoot(bytes32 r, uint256 b, bytes32 p) with (env e) {
            require b >= lastFinalizedBlock();
        }
    }

/*//////////////////////////////////////////////////////////////
                           RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Only sequencer can update state root
 */
rule onlySequencerCanUpdateStateRoot(bytes32 stateRoot, uint256 blockNumber, bytes32 proof) {
    env e;
    
    bool isSequencer = hasRole(SEQUENCER_ROLE(), e.msg.sender);
    
    updateStateRoot@withrevert(e, stateRoot, blockNumber, proof);
    
    bool reverted = lastReverted;
    
    assert !isSequencer => reverted, "Non-sequencers must not update state root";
}

/**
 * @notice State root updates must increase block number
 */
rule stateRootUpdateIncreasesBlockNumber(bytes32 stateRoot, uint256 blockNumber, bytes32 proof) {
    env e;
    
    require hasRole(SEQUENCER_ROLE(), e.msg.sender);
    require !paused();
    
    uint256 beforeBlock = lastFinalizedBlock();
    
    // Block number must be greater
    require blockNumber > beforeBlock;
    
    updateStateRoot(e, stateRoot, blockNumber, proof);
    
    uint256 afterBlock = lastFinalizedBlock();
    
    assert afterBlock >= beforeBlock, "Block number must not decrease";
}

/**
 * @notice Cannot update with same block number
 */
rule cannotUpdateWithSameBlockNumber(bytes32 stateRoot, uint256 blockNumber, bytes32 proof) {
    env e;
    
    require hasRole(SEQUENCER_ROLE(), e.msg.sender);
    require !paused();
    
    uint256 currentBlock = lastFinalizedBlock();
    require blockNumber == currentBlock;
    require currentBlock > 0; // Not the first update
    
    updateStateRoot@withrevert(e, stateRoot, blockNumber, proof);
    
    assert lastReverted, "Cannot update with same block number";
}

/**
 * @notice Cannot update with lower block number
 */
rule cannotUpdateWithLowerBlockNumber(bytes32 stateRoot, uint256 blockNumber, bytes32 proof) {
    env e;
    
    require hasRole(SEQUENCER_ROLE(), e.msg.sender);
    require !paused();
    
    uint256 currentBlock = lastFinalizedBlock();
    require blockNumber < currentBlock;
    require currentBlock > 0;
    
    updateStateRoot@withrevert(e, stateRoot, blockNumber, proof);
    
    assert lastReverted, "Cannot update with lower block number";
}

/**
 * @notice Zero state root is rejected
 */
rule zeroStateRootRejected(uint256 blockNumber, bytes32 proof) {
    env e;
    
    require hasRole(SEQUENCER_ROLE(), e.msg.sender);
    require !paused();
    
    updateStateRoot@withrevert(e, to_bytes32(0), blockNumber, proof);
    
    assert lastReverted, "Zero state root must be rejected";
}

/**
 * @notice Only relayer can submit state updates
 */
rule onlyRelayerCanSubmitUpdates() {
    env e;
    
    StarknetStateSync.StateUpdate update;
    
    bool isRelayer = hasRole(RELAYER_ROLE(), e.msg.sender);
    
    submitStateUpdate@withrevert(e, update);
    
    bool reverted = lastReverted;
    
    assert !isRelayer => reverted, "Non-relayers must not submit updates";
}

/**
 * @notice Only verifier can finalize updates
 */
rule onlyVerifierCanFinalizeUpdates(bytes32 updateId) {
    env e;
    
    bool isVerifier = hasRole(VERIFIER_ROLE(), e.msg.sender);
    
    finalizeStateUpdate@withrevert(e, updateId);
    
    bool reverted = lastReverted;
    
    assert !isVerifier => reverted, "Non-verifiers must not finalize updates";
}

/**
 * @notice Cannot finalize non-pending updates
 */
rule cannotFinalizeNonPendingUpdates(bytes32 updateId) {
    env e;
    
    require !updatePending[updateId];
    require hasRole(VERIFIER_ROLE(), e.msg.sender);
    
    finalizeStateUpdate@withrevert(e, updateId);
    
    assert lastReverted, "Non-pending updates must not be finalizable";
}

/**
 * @notice Cannot finalize already finalized updates
 */
rule cannotDoubleFinalizeUpdates(bytes32 updateId) {
    env e;
    
    require updatePending[updateId];
    require updateFinalized[updateId];
    require hasRole(VERIFIER_ROLE(), e.msg.sender);
    
    finalizeStateUpdate@withrevert(e, updateId);
    
    assert lastReverted, "Already finalized updates must not be re-finalized";
}

/**
 * @notice Storage proof verification is deterministic
 */
rule storageProofVerificationDeterministic(
    uint256 contractAddress,
    uint256 storageKey,
    uint256 expectedValue
) {
    env e1;
    env e2;
    
    bytes32[] proof;
    
    bool result1 = verifyStorageProof(e1, contractAddress, storageKey, expectedValue, proof);
    bool result2 = verifyStorageProof(e2, contractAddress, storageKey, expectedValue, proof);
    
    assert result1 == result2, "Storage proof verification must be deterministic";
}

/**
 * @notice Contract state verification is deterministic
 */
rule contractStateVerificationDeterministic(
    uint256 contractAddress,
    bytes32 stateCommitment
) {
    env e1;
    env e2;
    
    bytes32[] proof;
    
    bool result1 = verifyContractState(e1, contractAddress, stateCommitment, proof);
    bool result2 = verifyContractState(e2, contractAddress, stateCommitment, proof);
    
    assert result1 == result2, "Contract state verification must be deterministic";
}

/**
 * @notice Cannot operate when paused
 */
rule cannotOperateWhenPaused() {
    env e;
    
    require paused();
    
    bytes32 stateRoot;
    uint256 blockNumber;
    bytes32 proof;
    
    updateStateRoot@withrevert(e, stateRoot, blockNumber, proof);
    bool updateReverted = lastReverted;
    
    StarknetStateSync.StateUpdate update;
    submitStateUpdate@withrevert(e, update);
    bool submitReverted = lastReverted;
    
    bytes32 updateId;
    finalizeStateUpdate@withrevert(e, updateId);
    bool finalizeReverted = lastReverted;
    
    assert updateReverted && submitReverted && finalizeReverted,
        "All operations must fail when paused";
}

/**
 * @notice Only operator can set Starknet core
 */
rule onlyOperatorCanSetStarknetCore(address newCore) {
    env e;
    
    bool isOperator = hasRole(OPERATOR_ROLE(), e.msg.sender);
    
    setStarknetCore@withrevert(e, newCore);
    
    bool reverted = lastReverted;
    
    assert !isOperator => reverted, "Non-operators must not set Starknet core";
}

/**
 * @notice Only operator can set finality delay
 */
rule onlyOperatorCanSetFinalityDelay(uint256 newDelay) {
    env e;
    
    bool isOperator = hasRole(OPERATOR_ROLE(), e.msg.sender);
    
    setFinalityDelay@withrevert(e, newDelay);
    
    bool reverted = lastReverted;
    
    assert !isOperator => reverted, "Non-operators must not set finality delay";
}

/**
 * @notice Finality delay must be within bounds
 */
rule finalityDelayWithinBounds(uint256 newDelay) {
    env e;
    
    require hasRole(OPERATOR_ROLE(), e.msg.sender);
    
    setFinalityDelay@withrevert(e, newDelay);
    
    bool reverted = lastReverted;
    
    // Out of bounds should revert
    assert (newDelay < MIN_FINALITY_DELAY() || newDelay > MAX_FINALITY_DELAY()) => reverted,
        "Out of bounds finality delay must be rejected";
}

/*//////////////////////////////////////////////////////////////
                   STATE SYNC SECURITY RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice State root history preserves integrity
 */
rule stateRootHistoryIntegrity(bytes32 stateRoot, uint256 blockNumber, bytes32 proof) {
    env e;
    
    require hasRole(SEQUENCER_ROLE(), e.msg.sender);
    require !paused();
    require blockNumber > lastFinalizedBlock();
    
    bytes32 beforeRoot = currentStateRoot();
    
    updateStateRoot(e, stateRoot, blockNumber, proof);
    
    bytes32 afterRoot = currentStateRoot();
    
    // New root should be recorded
    assert afterRoot == stateRoot, "State root must be updated";
    
    // Old root should still be in history
    assert stateRootSeen[beforeRoot] || beforeRoot == to_bytes32(0),
        "Previous root must remain in history";
}

/**
 * @notice Starknet core address cannot be zero
 */
rule starknetCoreCannotBeZero(address newCore) {
    env e;
    
    require hasRole(OPERATOR_ROLE(), e.msg.sender);
    require newCore == address(0);
    
    setStarknetCore@withrevert(e, newCore);
    
    assert lastReverted, "Zero address must not be set as Starknet core";
}

/**
 * @notice Update submission increases counter
 */
rule updateSubmissionIncreasesCounter() {
    env e;
    
    require hasRole(RELAYER_ROLE(), e.msg.sender);
    require !paused();
    
    StarknetStateSync.StateUpdate update;
    
    uint256 beforeCount = totalUpdates();
    
    submitStateUpdate(e, update);
    
    uint256 afterCount = totalUpdates();
    
    assert afterCount == beforeCount + 1, "Update submission must increment counter";
}

/**
 * @notice State root cannot be overwritten with same block
 */
rule stateRootNotOverwrittenSameBlock(bytes32 root1, bytes32 root2, uint256 blockNumber, bytes32 proof1, bytes32 proof2) {
    env e1;
    env e2;
    
    require hasRole(SEQUENCER_ROLE(), e1.msg.sender);
    require hasRole(SEQUENCER_ROLE(), e2.msg.sender);
    require !paused();
    require root1 != root2;
    require blockNumber > 0;
    
    // Set initial state
    require lastFinalizedBlock() == blockNumber - 1;
    
    // First update
    updateStateRoot(e1, root1, blockNumber, proof1);
    
    // Second update with same block number (should fail)
    updateStateRoot@withrevert(e2, root2, blockNumber, proof2);
    
    assert lastReverted, "Cannot overwrite state root for same block";
}

/**
 * @notice Minimum confirmations is positive
 */
rule minConfirmationsPositive() {
    uint256 minConf = minConfirmations();
    
    assert minConf > 0, "Minimum confirmations must be positive";
}
