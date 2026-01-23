// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Groth16VerifierBLS12381 - Coverage Stub
 * @notice Simplified stub for coverage testing (no assembly)
 * @dev This file replaces the original during coverage runs
 */
contract Groth16VerifierBLS12381 {
    bytes public vkAlpha;
    bytes public vkBeta;
    bytes public vkGamma;
    bytes public vkDelta;
    bytes[] public vkIC;
    bool public initialized;
    address public owner;

    error NotOwner();
    error NotInitialized();
    error AlreadyInitialized();
    error InvalidProofLength();
    error InvalidPublicInputsLength();
    error InvalidPublicInput(uint256 index);
    error PrecompileFailed(address precompile);
    error PairingCheckFailed();
    error EIP2537NotSupported();
    error InvalidPointSize();

    event VerificationKeySet(uint256 icLength);
    event ProofVerified(bytes32 indexed proofHash, bool result);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setVerificationKey(
        bytes calldata _alpha,
        bytes calldata _beta,
        bytes calldata _gamma,
        bytes calldata _delta,
        bytes[] calldata _ic
    ) external onlyOwner {
        if (initialized) revert AlreadyInitialized();
        vkAlpha = _alpha;
        vkBeta = _beta;
        vkGamma = _gamma;
        vkDelta = _delta;
        delete vkIC;
        for (uint256 i = 0; i < _ic.length; i++) {
            vkIC.push(_ic[i]);
        }
        initialized = true;
        emit VerificationKeySet(_ic.length);
    }

    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool valid) {
        if (!initialized) revert NotInitialized();
        if (proof.length != 384) revert InvalidProofLength();
        // Stub: always return true for coverage
        return true;
    }

    function verifyProofParsed(
        bytes calldata, // pA
        bytes calldata, // pB
        bytes calldata, // pC
        uint256[] calldata // publicInputs
    ) external view returns (bool) {
        if (!initialized) revert NotInitialized();
        return true;
    }

    function batchVerifyProofs(
        bytes[] calldata proofs,
        bytes[] calldata publicInputsArray
    ) external view returns (bool[] memory results) {
        if (!initialized) revert NotInitialized();
        results = new bool[](proofs.length);
        for (uint256 i = 0; i < proofs.length; i++) {
            results[i] = true;
        }
    }

    function getICCount() external view returns (uint256) {
        return vkIC.length;
    }

    function isEIP2537Supported() external pure returns (bool) {
        return true;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}
