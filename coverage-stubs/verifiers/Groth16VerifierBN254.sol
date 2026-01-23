// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IProofVerifier.sol";

/**
 * @title Groth16VerifierBN254 - Coverage Stub
 * @notice Simplified stub for coverage testing (no assembly)
 */
contract Groth16VerifierBN254 is IProofVerifier {
    uint256 constant FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant PROOF_SIZE = 256;

    uint256[2] public vkAlpha;
    uint256[4] public vkBeta;
    uint256[4] public vkGamma;
    uint256[4] public vkDelta;
    uint256[2][] public vkIC;
    bool public initialized;
    address public owner;

    error NotOwner();
    error NotInitialized();
    error AlreadyInitialized();
    error InvalidProofSize(uint256 size);
    error InvalidPublicInputCount(uint256 provided, uint256 expected);
    error InvalidPublicInput(uint256 index, uint256 value);
    error PairingCheckFailed();
    error PrecompileFailed();

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
        uint256[2] calldata _alpha,
        uint256[4] calldata _beta,
        uint256[4] calldata _gamma,
        uint256[4] calldata _delta,
        uint256[2][] calldata _ic
    ) external onlyOwner {
        if (initialized) revert AlreadyInitialized();
        require(_ic.length >= 1, "IC must have at least 1 element");
        
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

    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view override returns (bool success) {
        if (!initialized) revert NotInitialized();
        if (proof.length != PROOF_SIZE) revert InvalidProofSize(proof.length);
        
        uint256 expectedInputs = vkIC.length - 1;
        if (publicInputs.length != expectedInputs) {
            revert InvalidPublicInputCount(publicInputs.length, expectedInputs);
        }
        
        for (uint256 i = 0; i < publicInputs.length; i++) {
            if (publicInputs[i] >= FIELD_MODULUS) {
                revert InvalidPublicInput(i, publicInputs[i]);
            }
        }
        
        return true;
    }

    function verifySingle(
        bytes calldata proof,
        uint256 publicInput
    ) external view override returns (bool success) {
        if (!initialized) revert NotInitialized();
        if (proof.length != PROOF_SIZE) revert InvalidProofSize(proof.length);
        if (vkIC.length != 2) revert InvalidPublicInputCount(1, vkIC.length - 1);
        if (publicInput >= FIELD_MODULUS) revert InvalidPublicInput(0, publicInput);
        return true;
    }

    function getPublicInputCount() external view override returns (uint256) {
        if (!initialized) return 0;
        return vkIC.length - 1;
    }

    function isReady() external view override returns (bool) {
        return initialized;
    }

    function _decodeProof(bytes calldata) internal pure returns (uint256[8] memory p) {
        return p;
    }

    function _verifyPairing(
        uint256[2] memory,
        uint256[4] memory,
        uint256[2] memory,
        uint256[2] memory
    ) internal pure returns (bool) {
        return true;
    }

    function _negate(uint256[2] memory p) internal pure returns (uint256[2] memory) {
        return p;
    }

    function _pointAdd(uint256[2] memory, uint256[2] memory) internal pure returns (uint256[2] memory r) {
        return r;
    }

    function _scalarMul(uint256[2] memory, uint256) internal pure returns (uint256[2] memory r) {
        return r;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}
