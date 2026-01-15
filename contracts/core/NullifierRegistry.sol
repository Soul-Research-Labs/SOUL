// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title NullifierRegistry
/// @notice Global nullifier tracking for double-spend prevention
contract NullifierRegistry {
    mapping(bytes32 => bool) public nullifiers;

    event NullifierRegistered(bytes32 indexed nullifier);

    function registerNullifier(bytes32 nullifier) public {
        require(!nullifiers[nullifier], "Already used");
        nullifiers[nullifier] = true;
        emit NullifierRegistered(nullifier);
    }

    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }
}
