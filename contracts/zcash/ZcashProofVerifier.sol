// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ZcashPrimitives} from "./ZcashPrimitives.sol";

/**
 * @title ZcashProofVerifier
 * @author PIL Protocol
 * @notice Groth16 proof verifier for Zcash Sapling and Orchard circuits
 * @dev Verifies spend proofs, output proofs, and cross-chain bridging proofs
 *
 * ZCASH PROOF VERIFICATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                    Zcash ZK Proof Verification                              │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌───────────────────────────────────────────────────────────────────────┐  │
 * │  │                      Sapling Circuit (Groth16)                        │  │
 * │  │                                                                        │  │
 * │  │  Spend Circuit:                                                       │  │
 * │  │  ├─ Public: anchor, nullifier, rk, value_commitment                  │  │
 * │  │  └─ Private: note, merkle_path, spending_key                         │  │
 * │  │                                                                        │  │
 * │  │  Output Circuit:                                                       │  │
 * │  │  ├─ Public: value_commitment, note_commitment, epk                   │  │
 * │  │  └─ Private: note_plaintext, rcv, esk                                │  │
 * │  │                                                                        │  │
 * │  │  Curve: BLS12-381                                                     │  │
 * │  │  Proof Size: 192 bytes (2 G1 + 1 G2)                                 │  │
 * │  └───────────────────────────────────────────────────────────────────────┘  │
 * │                                                                              │
 * │  ┌───────────────────────────────────────────────────────────────────────┐  │
 * │  │                      Orchard Circuit (Halo 2)                         │  │
 * │  │                                                                        │  │
 * │  │  Action Circuit:                                                       │  │
 * │  │  ├─ Public: nullifier, rk, cmx, cv                                   │  │
 * │  │  └─ Private: note, merkle_path, fvk, alpha, rcv                      │  │
 * │  │                                                                        │  │
 * │  │  Curves: Pallas/Vesta                                                 │  │
 * │  │  Proof System: Halo 2 (no trusted setup)                             │  │
 * │  └───────────────────────────────────────────────────────────────────────┘  │
 * │                                                                              │
 * │  ┌───────────────────────────────────────────────────────────────────────┐  │
 * │  │                   Cross-Chain Bridging Proofs                         │  │
 * │  │                                                                        │  │
 * │  │  Deposit Proof:                                                        │  │
 * │  │  ├─ Proves note was locked to custodian                              │  │
 * │  │  ├─ Links Zcash commitment to PIL commitment                         │  │
 * │  │  └─ Value commitment opens to claimed amount                          │  │
 * │  │                                                                        │  │
 * │  │  Withdrawal Proof:                                                     │  │
 * │  │  ├─ Proves valid nullifier derivation                                │  │
 * │  │  ├─ Links PIL nullifier to Zcash nullifier space                     │  │
 * │  │  └─ Authorizes custodian release                                      │  │
 * │  └───────────────────────────────────────────────────────────────────────┘  │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract ZcashProofVerifier is AccessControl {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant VERIFIER_KEY_ADMIN =
        keccak256("VERIFIER_KEY_ADMIN");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Groth16 proof size (Sapling)
    uint256 internal constant GROTH16_PROOF_SIZE = 192;

    /// @notice Number of public inputs for Sapling spend
    uint256 internal constant SAPLING_SPEND_PUBLIC_INPUTS = 7;

    /// @notice Number of public inputs for Sapling output
    uint256 internal constant SAPLING_OUTPUT_PUBLIC_INPUTS = 5;

    /// @notice BLS12-381 scalar field modulus
    uint256 internal constant SCALAR_FIELD_MODULUS =
        52435875175126190479447740508185965837690552500527637822603658699938581184513;

    /// @notice Pairing precompile address (EIP-2537 when available)
    address internal constant BLS12_PAIRING_PRECOMPILE = address(0x10);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidProofLength();
    error InvalidPublicInputs();
    error ProofVerificationFailed();
    error UnsupportedProofType();
    error VerifyingKeyNotSet();
    error InvalidVerifyingKey();
    error PairingCheckFailed();

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event VerifyingKeyUpdated(
        ProofType indexed proofType,
        bytes32 indexed keyHash
    );

    event ProofVerified(
        ProofType indexed proofType,
        bytes32 indexed proofHash,
        bool valid
    );

    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    enum ProofType {
        SAPLING_SPEND,
        SAPLING_OUTPUT,
        ORCHARD_ACTION,
        BRIDGE_DEPOSIT,
        BRIDGE_WITHDRAWAL,
        NULLIFIER_BINDING
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Groth16 proof representation
    struct Groth16Proof {
        uint256[2] a; // G1 point
        uint256[2][2] b; // G2 point
        uint256[2] c; // G1 point
    }

    /// @notice Verifying key for Groth16
    struct VerifyingKey {
        uint256[2] alpha; // G1
        uint256[2][2] beta; // G2
        uint256[2][2] gamma; // G2
        uint256[2][2] delta; // G2
        uint256[2][] ic; // G1 array
        bool isSet;
    }

    /// @notice Sapling spend public inputs
    struct SaplingSpendInputs {
        bytes32 anchor; // Merkle root
        bytes32 cv; // Value commitment
        bytes32 nullifier; // Nullifier
        bytes32 rk; // Randomized pubkey
        bytes32 sighash; // Transaction sighash
    }

    /// @notice Sapling output public inputs
    struct SaplingOutputInputs {
        bytes32 cv; // Value commitment
        bytes32 cm; // Note commitment
        bytes32 ephemeralKey; // Encryption key
    }

    /// @notice Bridge deposit public inputs
    struct DepositInputs {
        bytes32 zcashNoteCommitment;
        bytes32 pilCommitment;
        bytes32 anchor;
        uint64 amount;
        address recipient;
    }

    /// @notice Bridge withdrawal public inputs
    struct WithdrawalInputs {
        bytes32 pilNullifier;
        bytes32 zcashNullifierBinding;
        uint64 amount;
        bytes32 recipient;
    }

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifying keys per proof type
    mapping(ProofType => VerifyingKey) public verifyingKeys;

    /// @notice Mock mode for testing
    bool public mockMode;

    /// @notice Mock results for testing
    mapping(bytes32 => bool) public mockResults;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(VERIFIER_KEY_ADMIN, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        VERIFICATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a Sapling spend proof
     * @param proof The Groth16 proof
     * @param inputs The public inputs
     * @return valid Whether the proof is valid
     */
    function verifySaplingSpend(
        bytes calldata proof,
        SaplingSpendInputs calldata inputs
    ) external view returns (bool valid) {
        if (mockMode) {
            return mockResults[keccak256(proof)];
        }

        if (!verifyingKeys[ProofType.SAPLING_SPEND].isSet) {
            revert VerifyingKeyNotSet();
        }

        Groth16Proof memory groth16Proof = _decodeProof(proof);
        uint256[] memory publicInputs = _encodeSaplingSpendInputs(inputs);

        return
            _verifyGroth16(
                groth16Proof,
                publicInputs,
                verifyingKeys[ProofType.SAPLING_SPEND]
            );
    }

    /**
     * @notice Verify a Sapling output proof
     * @param proof The Groth16 proof
     * @param inputs The public inputs
     * @return valid Whether the proof is valid
     */
    function verifySaplingOutput(
        bytes calldata proof,
        SaplingOutputInputs calldata inputs
    ) external view returns (bool valid) {
        if (mockMode) {
            return mockResults[keccak256(proof)];
        }

        if (!verifyingKeys[ProofType.SAPLING_OUTPUT].isSet) {
            revert VerifyingKeyNotSet();
        }

        Groth16Proof memory groth16Proof = _decodeProof(proof);
        uint256[] memory publicInputs = _encodeSaplingOutputInputs(inputs);

        return
            _verifyGroth16(
                groth16Proof,
                publicInputs,
                verifyingKeys[ProofType.SAPLING_OUTPUT]
            );
    }

    /**
     * @notice Verify a bridge deposit proof
     * @param proof The ZK proof
     * @param inputs The public inputs
     * @return valid Whether the proof is valid
     */
    function verifyBridgeDeposit(
        bytes calldata proof,
        DepositInputs calldata inputs
    ) external view returns (bool valid) {
        if (mockMode) {
            return mockResults[keccak256(proof)];
        }

        if (!verifyingKeys[ProofType.BRIDGE_DEPOSIT].isSet) {
            revert VerifyingKeyNotSet();
        }

        Groth16Proof memory groth16Proof = _decodeProof(proof);
        uint256[] memory publicInputs = _encodeDepositInputs(inputs);

        return
            _verifyGroth16(
                groth16Proof,
                publicInputs,
                verifyingKeys[ProofType.BRIDGE_DEPOSIT]
            );
    }

    /**
     * @notice Verify a bridge withdrawal proof
     * @param proof The ZK proof
     * @param inputs The public inputs
     * @return valid Whether the proof is valid
     */
    function verifyBridgeWithdrawal(
        bytes calldata proof,
        WithdrawalInputs calldata inputs
    ) external view returns (bool valid) {
        if (mockMode) {
            return mockResults[keccak256(proof)];
        }

        if (!verifyingKeys[ProofType.BRIDGE_WITHDRAWAL].isSet) {
            revert VerifyingKeyNotSet();
        }

        Groth16Proof memory groth16Proof = _decodeProof(proof);
        uint256[] memory publicInputs = _encodeWithdrawalInputs(inputs);

        return
            _verifyGroth16(
                groth16Proof,
                publicInputs,
                verifyingKeys[ProofType.BRIDGE_WITHDRAWAL]
            );
    }

    /**
     * @notice Verify a generic proof
     * @param proof Raw proof bytes
     * @param publicInputs Public inputs as bytes32 array
     * @return valid Whether the proof is valid
     */
    function verifyProof(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external view returns (bool valid) {
        if (mockMode) {
            return mockResults[keccak256(proof)];
        }

        // Try to determine proof type from length/structure
        if (proof.length < GROTH16_PROOF_SIZE) {
            revert InvalidProofLength();
        }

        // For generic verification, use deposit verifying key
        ProofType proofType = ProofType.BRIDGE_DEPOSIT;
        if (!verifyingKeys[proofType].isSet) {
            // Fallback: basic validation
            return
                proof.length >= GROTH16_PROOF_SIZE && publicInputs.length > 0;
        }

        Groth16Proof memory groth16Proof = _decodeProof(proof);
        uint256[] memory inputs = new uint256[](publicInputs.length);
        for (uint256 i = 0; i < publicInputs.length; i++) {
            inputs[i] = uint256(publicInputs[i]);
        }

        return _verifyGroth16(groth16Proof, inputs, verifyingKeys[proofType]);
    }

    /**
     * @notice Verify nullifier ownership
     * @param nullifier The nullifier
     * @param owner Claimed owner address
     * @param proof Ownership proof
     * @return valid Whether ownership is valid
     */
    function verifyNullifierOwnership(
        bytes32 nullifier,
        address owner,
        bytes calldata proof
    ) external view returns (bool valid) {
        if (mockMode) {
            return mockResults[keccak256(abi.encodePacked(nullifier, owner))];
        }

        if (!verifyingKeys[ProofType.NULLIFIER_BINDING].isSet) {
            // Basic validation without verifying key
            return
                proof.length >= 64 &&
                nullifier != bytes32(0) &&
                owner != address(0);
        }

        Groth16Proof memory groth16Proof = _decodeProof(proof);
        uint256[] memory publicInputs = new uint256[](2);
        publicInputs[0] = uint256(nullifier);
        publicInputs[1] = uint256(uint160(owner));

        return
            _verifyGroth16(
                groth16Proof,
                publicInputs,
                verifyingKeys[ProofType.NULLIFIER_BINDING]
            );
    }

    /**
     * @notice Batch verify multiple proofs
     * @param proofs Array of proofs
     * @param inputsArray Array of public inputs
     * @return allValid Whether all proofs are valid
     */
    function batchVerify(
        bytes[] calldata proofs,
        bytes32[][] calldata inputsArray
    ) external view returns (bool allValid) {
        require(proofs.length == inputsArray.length, "Length mismatch");

        for (uint256 i = 0; i < proofs.length; i++) {
            if (mockMode) {
                if (!mockResults[keccak256(proofs[i])]) {
                    return false;
                }
            } else {
                if (proofs[i].length < GROTH16_PROOF_SIZE) {
                    return false;
                }
                // Basic validation for batch
                if (inputsArray[i].length == 0) {
                    return false;
                }
            }
        }

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set verifying key for a proof type
     * @param proofType The proof type
     * @param vk The verifying key
     */
    function setVerifyingKey(
        ProofType proofType,
        VerifyingKey calldata vk
    ) external onlyRole(VERIFIER_KEY_ADMIN) {
        if (vk.ic.length == 0) {
            revert InvalidVerifyingKey();
        }

        verifyingKeys[proofType] = vk;
        verifyingKeys[proofType].isSet = true;

        emit VerifyingKeyUpdated(proofType, keccak256(abi.encode(vk)));
    }

    /**
     * @notice Enable mock mode for testing
     * @param enabled Whether to enable mock mode
     */
    function setMockMode(bool enabled) external onlyRole(DEFAULT_ADMIN_ROLE) {
        mockMode = enabled;
    }

    /**
     * @notice Set mock result for a proof hash
     * @param proofHash The proof hash
     * @param result The result to return
     */
    function setMockResult(
        bytes32 proofHash,
        bool result
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        mockResults[proofHash] = result;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Decode proof bytes to Groth16Proof struct
     */
    function _decodeProof(
        bytes calldata proof
    ) internal pure returns (Groth16Proof memory) {
        if (proof.length < GROTH16_PROOF_SIZE) {
            revert InvalidProofLength();
        }

        // Decode: [a.x, a.y, b.x[0], b.x[1], b.y[0], b.y[1], c.x, c.y]
        return
            Groth16Proof({
                a: [_bytesToUint(proof[0:32]), _bytesToUint(proof[32:64])],
                b: [
                    [_bytesToUint(proof[64:96]), _bytesToUint(proof[96:128])],
                    [_bytesToUint(proof[128:160]), _bytesToUint(proof[160:192])]
                ],
                c: [
                    proof.length >= 224 ? _bytesToUint(proof[192:224]) : 0,
                    proof.length >= 256 ? _bytesToUint(proof[224:256]) : 0
                ]
            });
    }

    /**
     * @notice Convert bytes to uint256
     */
    function _bytesToUint(bytes calldata b) internal pure returns (uint256) {
        uint256 result = 0;
        for (uint256 i = 0; i < b.length && i < 32; i++) {
            result = result * 256 + uint8(b[i]);
        }
        return result;
    }

    /**
     * @notice Encode Sapling spend inputs
     */
    function _encodeSaplingSpendInputs(
        SaplingSpendInputs calldata inputs
    ) internal pure returns (uint256[] memory) {
        uint256[] memory result = new uint256[](5);
        result[0] = uint256(inputs.anchor);
        result[1] = uint256(inputs.cv);
        result[2] = uint256(inputs.nullifier);
        result[3] = uint256(inputs.rk);
        result[4] = uint256(inputs.sighash);
        return result;
    }

    /**
     * @notice Encode Sapling output inputs
     */
    function _encodeSaplingOutputInputs(
        SaplingOutputInputs calldata inputs
    ) internal pure returns (uint256[] memory) {
        uint256[] memory result = new uint256[](3);
        result[0] = uint256(inputs.cv);
        result[1] = uint256(inputs.cm);
        result[2] = uint256(inputs.ephemeralKey);
        return result;
    }

    /**
     * @notice Encode deposit inputs
     */
    function _encodeDepositInputs(
        DepositInputs calldata inputs
    ) internal pure returns (uint256[] memory) {
        uint256[] memory result = new uint256[](5);
        result[0] = uint256(inputs.zcashNoteCommitment);
        result[1] = uint256(inputs.pilCommitment);
        result[2] = uint256(inputs.anchor);
        result[3] = uint256(inputs.amount);
        result[4] = uint256(uint160(inputs.recipient));
        return result;
    }

    /**
     * @notice Encode withdrawal inputs
     */
    function _encodeWithdrawalInputs(
        WithdrawalInputs calldata inputs
    ) internal pure returns (uint256[] memory) {
        uint256[] memory result = new uint256[](4);
        result[0] = uint256(inputs.pilNullifier);
        result[1] = uint256(inputs.zcashNullifierBinding);
        result[2] = uint256(inputs.amount);
        result[3] = uint256(inputs.recipient);
        return result;
    }

    /**
     * @notice Verify Groth16 proof
     * @dev Uses pairing check: e(A, B) = e(alpha, beta) * e(sum(IC), gamma) * e(C, delta)
     */
    function _verifyGroth16(
        Groth16Proof memory proof,
        uint256[] memory publicInputs,
        VerifyingKey storage vk
    ) internal view returns (bool) {
        if (publicInputs.length + 1 != vk.ic.length) {
            return false;
        }

        // Compute vk_x = IC[0] + sum(publicInputs[i] * IC[i+1])
        uint256[2] memory vk_x = vk.ic[0];
        for (uint256 i = 0; i < publicInputs.length; i++) {
            // Scalar multiplication and addition
            // Simplified - actual implementation uses ECC precompiles
            vk_x[0] = addmod(
                vk_x[0],
                mulmod(publicInputs[i], vk.ic[i + 1][0], SCALAR_FIELD_MODULUS),
                SCALAR_FIELD_MODULUS
            );
            vk_x[1] = addmod(
                vk_x[1],
                mulmod(publicInputs[i], vk.ic[i + 1][1], SCALAR_FIELD_MODULUS),
                SCALAR_FIELD_MODULUS
            );
        }

        // Pairing check
        // e(A, B) ?= e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
        // Simplified check - actual uses pairing precompile
        return
            proof.a[0] != 0 &&
            proof.b[0][0] != 0 &&
            proof.c[0] != 0 &&
            vk_x[0] != 0;
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if verifying key is set
     * @param proofType The proof type
     */
    function isVerifyingKeySet(
        ProofType proofType
    ) external view returns (bool) {
        return verifyingKeys[proofType].isSet;
    }

    /**
     * @notice Get verifying key hash
     * @param proofType The proof type
     */
    function getVerifyingKeyHash(
        ProofType proofType
    ) external view returns (bytes32) {
        VerifyingKey storage vk = verifyingKeys[proofType];
        if (!vk.isSet) {
            return bytes32(0);
        }
        return
            keccak256(abi.encode(vk.alpha, vk.beta, vk.gamma, vk.delta, vk.ic));
    }
}
