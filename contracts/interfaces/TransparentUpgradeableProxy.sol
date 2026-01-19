// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title TransparentUpgradeableProxy
/// @notice EIP-1967 compliant transparent proxy for upgradeable contracts
/// @dev SECURITY: Uses EIP-1967 storage slots to prevent storage collision with implementation
///      Original implementation stored at slots 0 and 1 which could collide with implementation storage
contract TransparentUpgradeableProxy {
    /// @dev EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
    bytes32 private constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /// @dev EIP-1967 admin slot: keccak256("eip1967.proxy.admin") - 1
    bytes32 private constant _ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    constructor(address _implementation, address _admin) {
        _setImplementation(_implementation);
        _setAdmin(_admin);
    }

    /// @notice Returns the current implementation address
    function implementation() public view returns (address impl) {
        bytes32 slot = _IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    /// @notice Returns the current admin address
    function admin() public view returns (address adm) {
        bytes32 slot = _ADMIN_SLOT;
        assembly {
            adm := sload(slot)
        }
    }

    function upgradeTo(address newImplementation) external {
        require(msg.sender == admin(), "Not admin");
        require(newImplementation != address(0), "Invalid implementation");
        _setImplementation(newImplementation);
    }

    function changeAdmin(address newAdmin) external {
        require(msg.sender == admin(), "Not admin");
        require(newAdmin != address(0), "Invalid admin");
        _setAdmin(newAdmin);
    }

    function _setImplementation(address newImplementation) private {
        bytes32 slot = _IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    function _setAdmin(address newAdmin) private {
        bytes32 slot = _ADMIN_SLOT;
        assembly {
            sstore(slot, newAdmin)
        }
    }

    fallback() external payable {
        address impl = implementation();
        require(impl != address(0), "No implementation");

        // SECURITY: Prevent admin from calling implementation functions
        // to avoid function selector collision attacks
        require(msg.sender != admin(), "Admin cannot call fallback");

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    receive() external payable {}
}
