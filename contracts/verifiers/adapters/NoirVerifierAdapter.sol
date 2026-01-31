// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title INoirVerifier
 * @notice Minimal interface for auto-generated Noir verifiers
 */
interface INoirVerifier {
    /**
     * @notice Verify a proof
     * @param _proof The proof bytes
     * @param _publicInputs The public inputs array
     * @return Whether the proof is valid
     */
    function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external view returns (bool);
}

/**
 * @title NoirVerifierAdapter
 * @notice Base adapter to bridge SoulUniversalVerifier to auto-generated Noir verifiers
 * @dev Handles decoding of generic bytes public inputs into Noir's expected bytes32[]
 */
abstract contract NoirVerifierAdapter {
    /// @notice The auto-generated Noir verifier contract
    address public immutable noirVerifier;

    error VerificationFailed();

    constructor(address _noirVerifier) {
        noirVerifier = _noirVerifier;
    }

    /**
     * @notice Verify a proof
     * @param circuitHash Hash/ID of the circuit
     * @param proof The proof bytes
     * @param publicInputs Generic encoded public inputs
     * @return Whether the proof is valid
     */
    function verify(
        bytes32 circuitHash,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view virtual returns (bool) {
        // Default implementation decodes publicInputs as bytes32[]
        // Specific adapters can override this if custom decoding is needed
        bytes32[] memory inputs = abi.decode(publicInputs, (bytes32[]));
        return INoirVerifier(noirVerifier).verify(proof, inputs);
    }
}
