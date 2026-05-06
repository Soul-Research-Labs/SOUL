// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BN254ScalarField
/// @notice Shared scalar-field bounds checks for Noir/UltraHonk public inputs.
/// @dev Generated Barretenberg verifiers reduce `bytes32` inputs modulo this
///      field. Callers that pass semantically public field elements must reject
///      out-of-range values before invoking generated verifier contracts.
library BN254ScalarField {
    /// @notice BN254 scalar field order used by Noir/Barretenberg public inputs.
    uint256 internal constant MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    error FieldElementOutOfRange(uint256 index, bytes32 value);

    function validateCalldata(bytes32[] calldata publicInputs) internal pure {
        uint256 len = publicInputs.length;
        for (uint256 i = 0; i < len; ) {
            if (uint256(publicInputs[i]) >= MODULUS) {
                revert FieldElementOutOfRange(i, publicInputs[i]);
            }
            unchecked {
                ++i;
            }
        }
    }

    function validateMemory(bytes32[] memory publicInputs) internal pure {
        uint256 len = publicInputs.length;
        for (uint256 i = 0; i < len; ) {
            if (uint256(publicInputs[i]) >= MODULUS) {
                revert FieldElementOutOfRange(i, publicInputs[i]);
            }
            unchecked {
                ++i;
            }
        }
    }
}
