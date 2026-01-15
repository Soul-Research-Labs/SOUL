// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IPILUpgradeableProxy
/// @notice Interface for upgradeable proxy pattern
interface IPILUpgradeableProxy {
    function upgradeTo(address newImplementation) external;

    function implementation() external view returns (address);
}
