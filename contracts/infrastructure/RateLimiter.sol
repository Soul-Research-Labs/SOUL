// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title RateLimiter
/// @notice Per-user, per-chain, and global rate limiting
contract RateLimiter {
    // ...rate limiting logic...

    function checkRate(
        address user,
        uint256 chainId
    ) external view returns (bool) {
        // ...implementation...
        return true;
    }
}
