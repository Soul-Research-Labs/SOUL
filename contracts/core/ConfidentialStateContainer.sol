// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../verifiers/Groth16VerifierBLS12381.sol";

/// @title ConfidentialStateContainer
/// @notice MVP: Register and transfer confidential stablecoin state with Groth16 proof verification (BLS12-381)
/// @dev Legacy contract - see ConfidentialStateContainerV3 for production use
/// @custom:deprecated Use ConfidentialStateContainerV3 instead
contract ConfidentialStateContainer {
    /*//////////////////////////////////////////////////////////////
                             IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifier contract (immutable for gas savings)
    Groth16VerifierBLS12381 public immutable verifier;

    /// @notice Admin address (immutable for gas savings)
    address public immutable admin;

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Nullifier tracking
    mapping(bytes32 => bool) public nullifiers;

    /// @notice Whether this contract is deprecated
    bool public deprecated;

    struct EncryptedState {
        bytes encryptedState;
        bytes32 commitment;
        bytes32 nullifier;
        address owner;
    }

    mapping(bytes32 => EncryptedState) public states;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event StateRegistered(bytes32 indexed commitment, address indexed owner);
    event StateTransferred(
        bytes32 indexed oldCommitment,
        bytes32 indexed newCommitment,
        address indexed newOwner
    );
    event ContractDeprecated(bool status);

    /*//////////////////////////////////////////////////////////////
                           CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error NullifierAlreadyUsed();
    error InvalidProof();
    error NotOwner();
    error NotAdmin();
    error ContractIsDeprecated();
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                              MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier notDeprecated() {
        if (deprecated) revert ContractIsDeprecated();
        _;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _verifier) {
        if (_verifier == address(0)) revert ZeroAddress();
        verifier = Groth16VerifierBLS12381(_verifier);
        admin = msg.sender;
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Mark contract as deprecated
    function setDeprecated(bool _deprecated) external onlyAdmin {
        deprecated = _deprecated;
        emit ContractDeprecated(_deprecated);
    }

    /*//////////////////////////////////////////////////////////////
                         CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function registerState(
        bytes calldata encryptedState,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external notDeprecated {
        if (nullifiers[nullifier]) revert NullifierAlreadyUsed();
        if (!verifier.verifyProof(proof, publicInputs)) revert InvalidProof();

        states[commitment] = EncryptedState({
            encryptedState: encryptedState,
            commitment: commitment,
            nullifier: nullifier,
            owner: msg.sender
        });
        nullifiers[nullifier] = true;

        emit StateRegistered(commitment, msg.sender);
    }

    function transferState(
        bytes32 oldCommitment,
        bytes calldata newEncryptedState,
        bytes32 newCommitment,
        bytes32 newNullifier,
        bytes calldata proof,
        bytes calldata publicInputs,
        address newOwner
    ) external notDeprecated {
        EncryptedState storage oldState = states[oldCommitment];
        if (oldState.owner != msg.sender) revert NotOwner();
        if (nullifiers[newNullifier]) revert NullifierAlreadyUsed();
        if (!verifier.verifyProof(proof, publicInputs)) revert InvalidProof();

        states[newCommitment] = EncryptedState({
            encryptedState: newEncryptedState,
            commitment: newCommitment,
            nullifier: newNullifier,
            owner: newOwner
        });
        nullifiers[newNullifier] = true;

        emit StateTransferred(oldCommitment, newCommitment, newOwner);
    }
}
