// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/// @title NullifierRegistryV2
/// @author PIL Protocol
/// @notice Global nullifier tracking for double-spend prevention with cross-chain support
/// @dev Uses sparse storage pattern for gas efficiency
contract NullifierRegistryV2 is Ownable {
    /// @notice Mapping of nullifier hash to used status
    mapping(bytes32 => bool) public nullifiers;

    /// @notice Mapping of nullifier to registration timestamp (for auditing)
    mapping(bytes32 => uint256) public nullifierTimestamps;

    /// @notice Mapping of nullifier to registering contract (for cross-chain tracking)
    mapping(bytes32 => address) public nullifierSources;

    /// @notice Total count of registered nullifiers
    uint256 public nullifierCount;

    /// @notice Authorized contracts that can register nullifiers
    mapping(address => bool) public authorizedRegistrars;

    /// @notice Emitted when a nullifier is registered
    /// @param nullifier The registered nullifier
    /// @param source The contract that registered it
    /// @param timestamp The registration timestamp
    event NullifierRegistered(
        bytes32 indexed nullifier,
        address indexed source,
        uint256 timestamp
    );

    /// @notice Emitted when a registrar is authorized/deauthorized
    /// @param registrar The registrar address
    /// @param authorized Whether authorized or deauthorized
    event RegistrarUpdated(address indexed registrar, bool authorized);

    /// @notice Custom errors
    error NullifierAlreadyUsed(bytes32 nullifier);
    error NotAuthorizedRegistrar(address caller);
    error ZeroNullifier();

    /// @notice Modifier to restrict to authorized registrars
    modifier onlyAuthorized() {
        if (!authorizedRegistrars[msg.sender] && msg.sender != owner()) {
            revert NotAuthorizedRegistrar(msg.sender);
        }
        _;
    }

    constructor() Ownable(msg.sender) {
        // Owner is automatically authorized
        authorizedRegistrars[msg.sender] = true;
    }

    /// @notice Registers a nullifier (prevents double-spend)
    /// @param nullifier The nullifier to register
    /// @dev Reverts if nullifier already used
    function registerNullifier(bytes32 nullifier) public onlyAuthorized {
        if (nullifier == bytes32(0)) revert ZeroNullifier();
        if (nullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        nullifiers[nullifier] = true;
        nullifierTimestamps[nullifier] = block.timestamp;
        nullifierSources[nullifier] = msg.sender;
        nullifierCount++;

        emit NullifierRegistered(nullifier, msg.sender, block.timestamp);
    }

    /// @notice Batch registers multiple nullifiers (gas efficient)
    /// @param _nullifiers Array of nullifiers to register
    function batchRegisterNullifiers(
        bytes32[] calldata _nullifiers
    ) external onlyAuthorized {
        for (uint256 i = 0; i < _nullifiers.length; i++) {
            registerNullifier(_nullifiers[i]);
        }
    }

    /// @notice Checks if a nullifier has been used
    /// @param nullifier The nullifier to check
    /// @return used True if the nullifier has been used
    function isNullifierUsed(
        bytes32 nullifier
    ) external view returns (bool used) {
        return nullifiers[nullifier];
    }

    /// @notice Batch checks multiple nullifiers
    /// @param _nullifiers Array of nullifiers to check
    /// @return results Array of boolean results
    function batchCheckNullifiers(
        bytes32[] calldata _nullifiers
    ) external view returns (bool[] memory results) {
        results = new bool[](_nullifiers.length);
        for (uint256 i = 0; i < _nullifiers.length; i++) {
            results[i] = nullifiers[_nullifiers[i]];
        }
    }

    /// @notice Gets nullifier registration info
    /// @param nullifier The nullifier to query
    /// @return used Whether the nullifier is used
    /// @return timestamp The registration timestamp
    /// @return source The registering contract
    function getNullifierInfo(
        bytes32 nullifier
    ) external view returns (bool used, uint256 timestamp, address source) {
        return (
            nullifiers[nullifier],
            nullifierTimestamps[nullifier],
            nullifierSources[nullifier]
        );
    }

    /// @notice Authorizes a contract to register nullifiers
    /// @param registrar The contract address to authorize
    function authorizeRegistrar(address registrar) external onlyOwner {
        authorizedRegistrars[registrar] = true;
        emit RegistrarUpdated(registrar, true);
    }

    /// @notice Deauthorizes a contract from registering nullifiers
    /// @param registrar The contract address to deauthorize
    function deauthorizeRegistrar(address registrar) external onlyOwner {
        authorizedRegistrars[registrar] = false;
        emit RegistrarUpdated(registrar, false);
    }
}
