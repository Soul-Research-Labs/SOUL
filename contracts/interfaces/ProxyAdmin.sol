// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ProxyAdmin
/// @notice Governance-controlled proxy admin
import "./TransparentUpgradeableProxy.sol";

contract ProxyAdmin {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function changeProxyAdmin(address proxy, address newAdmin) external {
        require(msg.sender == owner, "Not owner");
        TransparentUpgradeableProxy(payable(proxy)).changeAdmin(newAdmin);
    }
}
