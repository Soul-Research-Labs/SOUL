// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockNoirVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}
