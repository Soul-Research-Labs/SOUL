// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./NoirVerifierAdapter.sol";

/**
 * @title PolicyVerifierAdapter
 * @notice Adapter for the Policy Compliance Noir circuit
 */
contract PolicyVerifierAdapter is NoirVerifierAdapter {
    constructor(address _noirVerifier) NoirVerifierAdapter(_noirVerifier) {}

    /**
     * @notice Custom verification for Policy compliance
     * @dev Decodes policy-specific public inputs: policy_hash, user_commitment, merkle_root
     */
    function verify(
        bytes32 /* circuitHash */,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool) {
        // Policy Noir circuit has 3 public inputs:
        // 1. policy_hash
        // 2. user_commitment
        // 3. merkle_root
        
        // Ensure inputs are decoded correctly from the generic bytes blob
        // Usually, the SDK will encode these as an array or a struct
        bytes32[] memory inputs = abi.decode(publicInputs, (bytes32[]));
        
        // Call the generated verifier
        return INoirVerifier(noirVerifier).verify(proof, inputs);
    }
}
