// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../core/Groth16VerifierBLS12381.sol";
import "../core/NullifierRegistry.sol";

/// @title ConfidentialStateContainer
/// @author PIL Protocol
/// @notice Registers and transfers confidential state with Groth16 proof verification (BLS12-381)
/// @dev Inherits NullifierRegistry for double-spend prevention, uses OpenZeppelin security patterns
contract ConfidentialStateContainer is
    NullifierRegistry,
    Ownable,
    ReentrancyGuard,
    Pausable
{
    /// @notice The Groth16 verifier contract
    Groth16VerifierBLS12381 public verifier;

    /// @notice Represents an encrypted confidential state
    /// @param encryptedState The AES-256-GCM encrypted state blob
    /// @param commitment Pedersen commitment to the state
    /// @param nullifier Unique nullifier for double-spend prevention
    /// @param owner The address that owns this state
    struct EncryptedState {
        bytes encryptedState;
        bytes32 commitment;
        bytes32 nullifier;
        address owner;
    }

    /// @notice Mapping from commitment to encrypted state
    mapping(bytes32 => EncryptedState) public states;

    /// @notice Emitted when a new state is registered
    /// @param commitment The state commitment
    /// @param owner The state owner
    event StateRegistered(bytes32 indexed commitment, address indexed owner);

    /// @notice Emitted when a state is transferred
    /// @param oldCommitment The previous state commitment
    /// @param newCommitment The new state commitment
    /// @param newOwner The new state owner
    event StateTransferred(
        bytes32 indexed oldCommitment,
        bytes32 indexed newCommitment,
        address indexed newOwner
    );

    /// @notice Emitted when the verifier address is updated
    /// @param oldVerifier The previous verifier address
    /// @param newVerifier The new verifier address
    event VerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

    /// @notice Custom errors for gas-efficient reverts
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidProof();
    error NotStateOwner(address caller, address owner);
    error ZeroAddress();
    error EmptyEncryptedState();
    error CommitmentAlreadyExists(bytes32 commitment);

    /// @notice Initializes the contract with a verifier address
    /// @param _verifier The address of the Groth16VerifierBLS12381 contract
    constructor(address _verifier) Ownable(msg.sender) {
        if (_verifier == address(0)) revert ZeroAddress();
        verifier = Groth16VerifierBLS12381(_verifier);
    }

    /// @notice Registers a new confidential state with proof verification
    /// @param encryptedState The encrypted state data (AES-256-GCM)
    /// @param commitment The Pedersen commitment to the state
    /// @param nullifier The nullifier for double-spend prevention
    /// @param proof The Groth16 proof bytes
    /// @param publicInputs The public inputs for the proof
    /// @dev Validates proof, registers nullifier, and stores state
    function registerState(
        bytes calldata encryptedState,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external nonReentrant whenNotPaused {
        // Input validation
        if (encryptedState.length == 0) revert EmptyEncryptedState();
        if (states[commitment].owner != address(0))
            revert CommitmentAlreadyExists(commitment);
        if (nullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        // Verify proof
        if (!verifier.verifyProof(proof, publicInputs)) revert InvalidProof();

        // Store state
        states[commitment] = EncryptedState({
            encryptedState: encryptedState,
            commitment: commitment,
            nullifier: nullifier,
            owner: msg.sender
        });

        // Register nullifier
        _registerNullifierInternal(nullifier);

        emit StateRegistered(commitment, msg.sender);
    }

    /// @notice Transfers state ownership with proof verification
    /// @param oldCommitment The commitment of the state to transfer
    /// @param newEncryptedState The new encrypted state data
    /// @param newCommitment The new Pedersen commitment
    /// @param newNullifier The new nullifier
    /// @param proof The Groth16 proof bytes
    /// @param publicInputs The public inputs for the proof
    /// @param newOwner The new owner address
    /// @dev Only the current owner can transfer; validates proof and updates state
    function transferState(
        bytes32 oldCommitment,
        bytes calldata newEncryptedState,
        bytes32 newCommitment,
        bytes32 newNullifier,
        bytes calldata proof,
        bytes calldata publicInputs,
        address newOwner
    ) external nonReentrant whenNotPaused {
        // Input validation
        if (newOwner == address(0)) revert ZeroAddress();
        if (newEncryptedState.length == 0) revert EmptyEncryptedState();

        EncryptedState storage oldState = states[oldCommitment];
        if (oldState.owner != msg.sender)
            revert NotStateOwner(msg.sender, oldState.owner);
        if (nullifiers[newNullifier]) revert NullifierAlreadyUsed(newNullifier);

        // Verify proof
        if (!verifier.verifyProof(proof, publicInputs)) revert InvalidProof();

        // Store new state
        states[newCommitment] = EncryptedState({
            encryptedState: newEncryptedState,
            commitment: newCommitment,
            nullifier: newNullifier,
            owner: newOwner
        });

        // Register new nullifier
        _registerNullifierInternal(newNullifier);

        emit StateTransferred(oldCommitment, newCommitment, newOwner);
    }

    /// @notice Updates the verifier contract address
    /// @param _newVerifier The new verifier address
    /// @dev Only callable by owner; emits VerifierUpdated event
    function setVerifier(address _newVerifier) external onlyOwner {
        if (_newVerifier == address(0)) revert ZeroAddress();
        address oldVerifier = address(verifier);
        verifier = Groth16VerifierBLS12381(_newVerifier);
        emit VerifierUpdated(oldVerifier, _newVerifier);
    }

    /// @notice Pauses the contract
    /// @dev Only callable by owner
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses the contract
    /// @dev Only callable by owner
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Checks if a state exists for a given commitment
    /// @param commitment The commitment to check
    /// @return exists True if the state exists
    function stateExists(
        bytes32 commitment
    ) external view returns (bool exists) {
        return states[commitment].owner != address(0);
    }

    /// @notice Returns the owner of a state
    /// @param commitment The commitment to query
    /// @return owner The state owner address
    function getStateOwner(
        bytes32 commitment
    ) external view returns (address owner) {
        return states[commitment].owner;
    }

    /// @notice Internal function to register nullifier (avoids external call overhead)
    /// @param nullifier The nullifier to register
    function _registerNullifierInternal(bytes32 nullifier) internal {
        nullifiers[nullifier] = true;
        emit NullifierRegistered(nullifier);
    }
}
