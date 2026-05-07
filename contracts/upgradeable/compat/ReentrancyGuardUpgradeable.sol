// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @dev Compatibility shim for OpenZeppelin 5.5.0+, where `ReentrancyGuard`
 * uses ERC-7201 namespaced storage and no constructor initialization.
 *
 * Existing upgradeable contracts still call `__ReentrancyGuard_init()` through
 * the historical upgradeable API. This shim preserves that API without
 * modifying vendored OpenZeppelin submodules.
 */
abstract contract ReentrancyGuardUpgradeable is Initializable, ReentrancyGuard {
    function __ReentrancyGuard_init() internal onlyInitializing {
        __ReentrancyGuard_init_unchained();
    }

    function __ReentrancyGuard_init_unchained() internal onlyInitializing {
        // No-op: base ReentrancyGuard owns namespaced storage initialization.
    }
}
