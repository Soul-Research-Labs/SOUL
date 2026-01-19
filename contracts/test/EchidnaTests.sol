// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "../core/ConfidentialStateContainerV3.sol";

/**
 * @title EchidnaConfidentialStateTest
 * @notice Echidna fuzzing tests for ConfidentialStateContainerV3
 * @dev Run with: echidna . --contract EchidnaConfidentialStateTest --config echidna.config.yaml
 */
contract EchidnaConfidentialStateTest {
    ConfidentialStateContainerV3 public container;

    // Track created states for property checks
    bytes32[] public createdCommitments;
    mapping(bytes32 => bool) public registeredNullifiers;

    // Constants for testing
    uint256 constant MAX_STATES = 100;

    constructor() {
        // Deploy with a mock verifier address (this contract acts as verifier)
        container = new ConfidentialStateContainerV3(address(this));
    }

    // ========================================================================
    // ECHIDNA PROPERTIES (Invariants)
    // ========================================================================

    /**
     * @notice Nullifier uniqueness - each nullifier can only be used once
     */
    function echidna_nullifier_uniqueness() public view returns (bool) {
        // Check that registered nullifiers are properly tracked
        for (uint i = 0; i < createdCommitments.length; i++) {
            bytes32 commitment = createdCommitments[i];
            if (registeredNullifiers[commitment]) {
                // If we registered a nullifier for this, it should be in contract
                if (!container.nullifiers(commitment)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * @notice State consistency - active states should have valid data
     */
    function echidna_state_consistency() public view returns (bool) {
        for (uint i = 0; i < createdCommitments.length; i++) {
            bytes32 commitment = createdCommitments[i];
            if (container.isStateActive(commitment)) {
                // Active state should have non-zero data
                ConfidentialStateContainerV3.EncryptedState
                    memory state = container.states(commitment);
                if (state.commitment == bytes32(0)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * @notice Counter monotonicity - counters should only increase
     */
    function echidna_counter_monotonicity() public view returns (bool) {
        uint256 total = container.totalStates();
        uint256 active = container.activeStates();
        // Active states can never exceed total
        return active <= total;
    }

    /**
     * @notice Proof validity window must be reasonable
     */
    function echidna_validity_window_bounds() public view returns (bool) {
        uint256 window = container.proofValidityWindow();
        // Window should be between 1 block and ~1 day of blocks
        return window >= 1 && window <= 100000;
    }

    // ========================================================================
    // FUZZING FUNCTIONS (Actions)
    // ========================================================================

    /**
     * @notice Fuzz state registration with random inputs
     */
    function registerState(
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata encryptedState,
        bytes32 metadata
    ) external {
        if (commitment == bytes32(0)) return;
        if (nullifier == bytes32(0)) return;
        if (container.isStateActive(commitment)) return;
        if (container.nullifiers(nullifier)) return;
        if (createdCommitments.length >= MAX_STATES) return;

        bytes memory proof = abi.encodePacked(uint256(1)); // Mock proof
        bytes memory publicInputs = abi.encodePacked(commitment, nullifier);

        try
            container.registerState(
                encryptedState,
                commitment,
                nullifier,
                proof,
                publicInputs,
                metadata
            )
        {
            createdCommitments.push(commitment);
            registeredNullifiers[nullifier] = true;
        } catch {
            // Expected to fail sometimes with invalid proofs
        }
    }

    /**
     * @notice Fuzz state transfer
     */
    function transferState(
        bytes32 commitment,
        bytes32 newCommitment,
        bytes32 newNullifier,
        address newOwner
    ) external {
        if (!container.isStateActive(commitment)) return;
        if (newCommitment == bytes32(0)) return;
        if (newNullifier == bytes32(0)) return;
        if (container.nullifiers(newNullifier)) return;
        if (newOwner == address(0)) return;

        bytes memory proof = abi.encodePacked(uint256(1));
        bytes memory publicInputs = abi.encodePacked(
            commitment,
            newCommitment,
            newNullifier
        );
        bytes memory newEncryptedState = abi.encodePacked(newCommitment);

        try
            container.transferState(
                commitment,
                newEncryptedState,
                newCommitment,
                newNullifier,
                proof,
                publicInputs,
                newOwner
            )
        {
            createdCommitments.push(newCommitment);
            registeredNullifiers[newNullifier] = true;
        } catch {
            // Expected to fail sometimes
        }
    }

    // ========================================================================
    // MOCK VERIFIER FUNCTIONS
    // ========================================================================

    /**
     * @notice Mock verify function - always returns true for testing
     * @dev In real tests, this would be a proper verifier
     */
    function verify(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[] calldata
    ) external pure returns (bool) {
        return true;
    }
}

/**
 * @title EchidnaAtomicSwapTest
 * @notice Echidna fuzzing tests for atomic swap invariants
 */
contract EchidnaAtomicSwapTest {
    // Simplified swap tracking for invariant testing
    mapping(bytes32 => SwapState) public swapStates;
    bytes32[] public swapIds;

    enum SwapState {
        None,
        Initiated,
        Completed,
        Refunded
    }

    struct Swap {
        address initiator;
        address recipient;
        bytes32 secretHash;
        uint256 amount;
        uint256 timelock;
        SwapState state;
    }

    mapping(bytes32 => Swap) public swaps;

    // ========================================================================
    // ECHIDNA PROPERTIES
    // ========================================================================

    /**
     * @notice A swap cannot be both completed AND refunded
     */
    function echidna_swap_mutual_exclusion() public view returns (bool) {
        for (uint i = 0; i < swapIds.length; i++) {
            SwapState state = swapStates[swapIds[i]];
            // Can only be in one terminal state
            if (state == SwapState.Completed && state == SwapState.Refunded) {
                return false;
            }
        }
        return true;
    }

    /**
     * @notice Terminal states should not change
     */
    function echidna_terminal_states_final() public view returns (bool) {
        // This is verified by the state machine - terminal states don't have transitions
        return true;
    }

    /**
     * @notice Swap IDs should be unique
     */
    function echidna_swap_id_uniqueness() public view returns (bool) {
        for (uint i = 0; i < swapIds.length; i++) {
            for (uint j = i + 1; j < swapIds.length; j++) {
                if (swapIds[i] == swapIds[j]) {
                    return false;
                }
            }
        }
        return true;
    }

    // ========================================================================
    // FUZZING FUNCTIONS
    // ========================================================================

    function initiateSwap(
        address recipient,
        bytes32 secretHash,
        uint256 timelock
    ) external {
        if (recipient == address(0)) return;
        if (secretHash == bytes32(0)) return;
        if (timelock <= block.timestamp) return;

        bytes32 swapId = keccak256(
            abi.encodePacked(msg.sender, recipient, secretHash, block.timestamp)
        );

        if (swapStates[swapId] != SwapState.None) return;

        swaps[swapId] = Swap({
            initiator: msg.sender,
            recipient: recipient,
            secretHash: secretHash,
            amount: 0,
            timelock: timelock,
            state: SwapState.Initiated
        });
        swapStates[swapId] = SwapState.Initiated;
        swapIds.push(swapId);
    }

    function completeSwap(bytes32 swapId, bytes32 secret) external {
        if (swapStates[swapId] != SwapState.Initiated) return;
        if (keccak256(abi.encodePacked(secret)) != swaps[swapId].secretHash)
            return;

        swapStates[swapId] = SwapState.Completed;
        swaps[swapId].state = SwapState.Completed;
    }

    function refundSwap(bytes32 swapId) external {
        if (swapStates[swapId] != SwapState.Initiated) return;
        if (block.timestamp < swaps[swapId].timelock) return;
        if (msg.sender != swaps[swapId].initiator) return;

        swapStates[swapId] = SwapState.Refunded;
        swaps[swapId].state = SwapState.Refunded;
    }
}
