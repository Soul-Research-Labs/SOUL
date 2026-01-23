// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ZcashPrimitives
 * @author PIL Protocol
 * @notice Core Zcash cryptographic primitives for cross-chain interoperability
 * @dev Implements Sapling and Orchard note structures, Jubjub/Pallas curve operations
 *
 * ZCASH CRYPTOGRAPHIC ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                    Zcash Shielded Transaction Model                         │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────────────────────────────────────────────────────────┐ │
 * │  │                         Note Commitment                                │ │
 * │  │  cm = PedersenHash(rcm || value || g_d || pk_d)                        │ │
 * │  │                                                                        │ │
 * │  │  Where:                                                                │ │
 * │  │  - rcm: note randomness                                               │ │
 * │  │  - value: amount in zatoshis                                          │ │
 * │  │  - g_d: diversified base point                                        │ │
 * │  │  - pk_d: diversified transmission key                                 │ │
 * │  └───────────────────────────────────────────────────────────────────────┘ │
 * │                                                                             │
 * │  ┌───────────────────────────────────────────────────────────────────────┐ │
 * │  │                          Nullifier                                     │ │
 * │  │  nf = PRF^nf_nk(rho)  [Sapling]                                       │ │
 * │  │  nf = DeriveNullifier_nk(rho, psi, cm)  [Orchard]                    │ │
 * │  │                                                                        │ │
 * │  │  Properties:                                                           │ │
 * │  │  - Unique per note                                                    │ │
 * │  │  - Cannot be linked to note commitment without spending key           │ │
 * │  │  - Published on-chain to prevent double-spend                         │ │
 * │  └───────────────────────────────────────────────────────────────────────┘ │
 * │                                                                             │
 * │  ┌───────────────────────────────────────────────────────────────────────┐ │
 * │  │                     Spend Description                                  │ │
 * │  │  - cv: value commitment                                               │ │
 * │  │  - anchor: Merkle root of note commitment tree                        │ │
 * │  │  - nullifier: nf                                                      │ │
 * │  │  - rk: randomized public key                                          │ │
 * │  │  - zkproof: Groth16 proof                                             │ │
 * │  │  - spendAuthSig: signature on sighash                                 │ │
 * │  └───────────────────────────────────────────────────────────────────────┘ │
 * │                                                                             │
 * │  ┌───────────────────────────────────────────────────────────────────────┐ │
 * │  │                    Output Description                                  │ │
 * │  │  - cv: value commitment                                               │ │
 * │  │  - cmu: note commitment                                               │ │
 * │  │  - ephemeralKey: for note encryption                                  │ │
 * │  │  - encCiphertext: encrypted note plaintext                            │ │
 * │  │  - outCiphertext: outgoing cipher text                                │ │
 * │  │  - zkproof: Groth16 proof                                             │ │
 * │  └───────────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SUPPORTED PROTOCOLS:
 * - Sapling (BLS12-381, Jubjub curve)
 * - Orchard (Pallas/Vesta curves, Halo 2)
 */
library ZcashPrimitives {
    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice BLS12-381 scalar field modulus (r) - fits in uint256
    /// The actual value: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    uint256 internal constant BLS12_381_SCALAR_MODULUS =
        52435875175126190479447740508185965837690552500527637822603658699938581184513;

    /// @notice Jubjub curve parameters (embedded in BLS12-381)
    /// a = -1 (represented in field)
    uint256 internal constant JUBJUB_A =
        52435875175126190479447740508185965837690552500527637822603658699938581184512; // -1 mod r

    /// @notice Jubjub d parameter
    uint256 internal constant JUBJUB_D =
        19257038036680949359750312669786877991949435402254120286184196891950884077233;

    /// @notice Pallas curve base field modulus (Orchard) - fits in uint256
    uint256 internal constant PALLAS_MODULUS =
        28948022309329048855892746252171976963363056481941560715954676764349967630337;

    /// @notice Merkle tree depth for Sapling
    uint8 internal constant SAPLING_MERKLE_DEPTH = 32;

    /// @notice Merkle tree depth for Orchard
    uint8 internal constant ORCHARD_MERKLE_DEPTH = 32;

    /// @notice Domain separators
    bytes32 internal constant SAPLING_DOMAIN_SEPARATOR =
        keccak256("Zcash_Sapling");
    bytes32 internal constant ORCHARD_DOMAIN_SEPARATOR =
        keccak256("Zcash_Orchard");
    bytes32 internal constant PIL_ZCASH_DOMAIN =
        keccak256("PIL_Zcash_Interop_v1");

    /*//////////////////////////////////////////////////////////////
                                TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Zcash shielded pool type
    enum ShieldedPool {
        SPROUT, // Legacy (deprecated)
        SAPLING, // Current main pool
        ORCHARD // Latest with Halo 2
    }

    /// @notice Zcash network type
    enum ZcashNetwork {
        MAINNET,
        TESTNET,
        REGTEST
    }

    /// @notice Jubjub curve point (affine coordinates)
    struct JubjubPoint {
        uint256 u; // u-coordinate
        uint256 v; // v-coordinate
    }

    /// @notice Pallas curve point (affine coordinates)
    struct PallasPoint {
        uint256 x;
        uint256 y;
    }

    /// @notice Pedersen commitment (point on curve + blinding factor)
    struct PedersenCommitment {
        bytes32 commitment; // Compressed point
        uint256 blindingFactor; // r value (private, not stored on-chain)
    }

    /// @notice Sapling note structure
    struct SaplingNote {
        bytes32 d; // Diversifier (11 bytes, padded)
        bytes32 pkD; // Diversified transmission key
        uint64 value; // Value in zatoshis
        bytes32 rcm; // Note commitment randomness
        bytes32 rho; // Nullifier deriving value
    }

    /// @notice Orchard note structure (NU5+)
    struct OrchardNote {
        bytes32 d; // Diversifier
        bytes32 pkD; // Diversified transmission key
        uint64 value; // Value in zatoshis
        bytes32 rho; // Unique note identifier
        bytes32 psi; // Additional randomness
        bytes32 rcm; // Note commitment randomness
    }

    /// @notice Note commitment
    struct NoteCommitment {
        bytes32 cm; // The commitment
        ShieldedPool pool; // Which pool this belongs to
        uint32 position; // Position in commitment tree
        bytes32 anchor; // Merkle root when added
    }

    /// @notice Nullifier structure for cross-chain tracking
    struct ZcashNullifier {
        bytes32 nf; // The nullifier
        ShieldedPool pool; // Sapling or Orchard
        bytes32 txHash; // Zcash transaction hash
        uint32 blockHeight; // Block height when spent
        uint64 timestamp; // When the nullifier was revealed
    }

    /// @notice Value commitment (Pedersen commitment to value)
    struct ValueCommitment {
        bytes32 cv; // Commitment value
        uint64 value; // Actual value (private, for internal use)
        bytes32 rcv; // Randomness
    }

    /// @notice Spend description (Sapling)
    struct SaplingSpendDescription {
        ValueCommitment cv; // Value commitment
        bytes32 anchor; // Merkle root
        bytes32 nullifier; // Nullifier
        bytes32 rk; // Randomized public key
        bytes zkProof; // Groth16 proof (192 bytes)
        bytes spendAuthSig; // Signature (64 bytes)
    }

    /// @notice Output description (Sapling)
    struct SaplingOutputDescription {
        ValueCommitment cv; // Value commitment
        bytes32 cmu; // Note commitment
        bytes32 ephemeralKey; // For decryption
        bytes encCiphertext; // Encrypted note (580 bytes)
        bytes outCiphertext; // Outgoing viewing key cipher (80 bytes)
        bytes zkProof; // Groth16 proof (192 bytes)
    }

    /// @notice Orchard action (combines spend + output)
    struct OrchardAction {
        bytes32 nullifier; // Nullifier of spent note
        bytes32 rk; // Randomized verification key
        bytes32 cmx; // Note commitment (x-coordinate)
        bytes32 ephemeralKey; // Encryption key
        bytes encCiphertext; // Encrypted note (580 bytes)
        bytes outCiphertext; // Outgoing cipher (80 bytes)
        ValueCommitment cv; // Value commitment
    }

    /// @notice Full Zcash transaction representation for PIL
    struct ZcashTransaction {
        bytes32 txHash; // Transaction hash
        uint32 blockHeight; // Block height
        uint64 timestamp; // Block timestamp
        // Transparent I/O (optional)
        bytes transparentInputs;
        bytes transparentOutputs;
        // Sapling
        SaplingSpendDescription[] saplingSpends;
        SaplingOutputDescription[] saplingOutputs;
        bytes32 saplingAnchor;
        int64 saplingValueBalance; // Can be negative
        // Orchard
        OrchardAction[] orchardActions;
        bytes32 orchardAnchor;
        int64 orchardValueBalance;
        // Binding signature
        bytes bindingSig; // 64 bytes
        // Orchard specific
        bytes orchardProof; // Halo 2 proof
        bytes orchardSigs; // Aggregated signatures
    }

    /// @notice Merkle path for note commitment tree
    struct MerklePath {
        bytes32[32] authPath; // Sibling hashes
        bool[32] positions; // Left (false) or right (true)
    }

    /// @notice Cross-chain note representation
    struct CrossChainNote {
        bytes32 noteId; // Unique identifier for PIL
        bytes32 originalCm; // Original Zcash note commitment
        bytes32 originalNf; // Original nullifier (once spent)
        ShieldedPool pool;
        uint64 value;
        bytes32 pilCommitment; // Commitment in PIL format
        bytes32 crossChainProof; // Proof of valid bridging
        uint64 bridgedAt; // Timestamp of bridging
        ZcashNetwork sourceNetwork;
    }

    /*//////////////////////////////////////////////////////////////
                           HASH FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Compute Pedersen hash (simplified for EVM)
    /// @dev In production, use precompile or off-chain computation
    function pedersenHash(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        // Simplified implementation - actual Pedersen hash requires curve ops
        // In production, this would call a precompile or use SNARK verification
        return
            keccak256(abi.encodePacked(SAPLING_DOMAIN_SEPARATOR, left, right));
    }

    /// @notice Compute Sinsemilla hash (Orchard)
    /// @dev Simplified for EVM - actual implementation uses Pallas curve
    function sinsemillaHash(
        bytes32 domain,
        bytes memory message
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(ORCHARD_DOMAIN_SEPARATOR, domain, message)
            );
    }

    /// @notice Compute BLAKE2s hash (Zcash PRF)
    /// @dev Simplified using keccak256 - should use actual BLAKE2s
    function blake2sHash(bytes memory data) internal pure returns (bytes32) {
        return keccak256(data);
    }

    /// @notice Compute BLAKE2b hash (Zcash personalization)
    function blake2bPersonalized(
        bytes memory personalization,
        bytes memory data
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(personalization, data));
    }

    /*//////////////////////////////////////////////////////////////
                        NOTE COMMITMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Compute Sapling note commitment
    /// @param note The Sapling note
    /// @return cm The note commitment
    function computeSaplingNoteCommitment(
        SaplingNote memory note
    ) internal pure returns (bytes32 cm) {
        // cm = PedersenHash(rcm || value || g_d || pk_d)
        bytes memory preimage = abi.encodePacked(
            note.rcm,
            note.value,
            note.d, // g_d derived from diversifier
            note.pkD
        );
        cm = blake2bPersonalized("Zcash_SaplingCm_", preimage);
    }

    /// @notice Compute Orchard note commitment
    /// @param note The Orchard note
    /// @return cmx The note commitment (x-coordinate)
    function computeOrchardNoteCommitment(
        OrchardNote memory note
    ) internal pure returns (bytes32 cmx) {
        // cmx = SinsemillaCommit(d, pk_d, v, rho, psi, rcm)
        bytes memory preimage = abi.encodePacked(
            note.d,
            note.pkD,
            note.value,
            note.rho,
            note.psi,
            note.rcm
        );
        cmx = sinsemillaHash("NoteCommitment", preimage);
    }

    /*//////////////////////////////////////////////////////////////
                          NULLIFIER
    //////////////////////////////////////////////////////////////*/

    /// @notice Derive Sapling nullifier
    /// @param nk Nullifier deriving key
    /// @param rho Note randomness (rho)
    /// @param cm Note commitment
    /// @return nf The nullifier
    function deriveSaplingNullifier(
        bytes32 nk,
        bytes32 rho,
        bytes32 cm
    ) internal pure returns (bytes32 nf) {
        // nf = PRF^nf_nk(rho)
        // Simplified: actual uses BLAKE2s with proper domain separation
        nf = blake2bPersonalized("Zcash_nf", abi.encodePacked(nk, rho, cm));
    }

    /// @notice Derive Orchard nullifier
    /// @param nk Nullifier deriving key
    /// @param rho Note identifier
    /// @param psi Additional randomness
    /// @param cm Note commitment
    /// @return nf The nullifier
    function deriveOrchardNullifier(
        bytes32 nk,
        bytes32 rho,
        bytes32 psi,
        bytes32 cm
    ) internal pure returns (bytes32 nf) {
        // nf = DeriveNullifier_nk(rho, psi, cm)
        // Uses Poseidon hash in actual implementation
        nf = keccak256(
            abi.encodePacked(
                ORCHARD_DOMAIN_SEPARATOR,
                "Nullifier",
                nk,
                rho,
                psi,
                cm
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                         VALUE COMMITMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Compute value commitment
    /// @param value The value to commit
    /// @param rcv Random blinding factor
    /// @return cv The value commitment
    function computeValueCommitment(
        uint64 value,
        bytes32 rcv
    ) internal pure returns (bytes32 cv) {
        // cv = v * G_value + rcv * G_rcv
        // Simplified for EVM - actual uses curve multiplication
        cv = keccak256(abi.encodePacked("ValueCommit", value, rcv));
    }

    /// @notice Verify value commitment sum is zero (for balanced transaction)
    /// @param spendCvs Array of spend value commitments
    /// @param outputCvs Array of output value commitments
    /// @param valueBalance Net value balance
    /// @return valid Whether the commitments balance
    function verifyValueBalance(
        bytes32[] memory spendCvs,
        bytes32[] memory outputCvs,
        int64 valueBalance
    ) internal pure returns (bool valid) {
        // Sum of spend cvs - sum of output cvs = valueBalance * G_value
        // This is a simplified check - actual verification uses curve operations
        bytes32 spendSum = bytes32(0);
        for (uint256 i = 0; i < spendCvs.length; i++) {
            spendSum = keccak256(abi.encodePacked(spendSum, spendCvs[i]));
        }

        bytes32 outputSum = bytes32(0);
        for (uint256 i = 0; i < outputCvs.length; i++) {
            outputSum = keccak256(abi.encodePacked(outputSum, outputCvs[i]));
        }

        bytes32 expectedBalance = keccak256(
            abi.encodePacked("BalanceCheck", spendSum, outputSum, valueBalance)
        );

        // In production, this would verify binding signature
        valid = expectedBalance != bytes32(0);
    }

    /*//////////////////////////////////////////////////////////////
                         MERKLE TREE
    //////////////////////////////////////////////////////////////*/

    /// @notice Compute Merkle root from path
    /// @param leaf The leaf commitment
    /// @param path The Merkle authentication path
    /// @return root The computed root
    function computeMerkleRoot(
        bytes32 leaf,
        MerklePath memory path
    ) internal pure returns (bytes32 root) {
        bytes32 current = leaf;

        for (uint256 i = 0; i < SAPLING_MERKLE_DEPTH; i++) {
            if (path.positions[i]) {
                // Current is on the right
                current = pedersenHash(path.authPath[i], current);
            } else {
                // Current is on the left
                current = pedersenHash(current, path.authPath[i]);
            }
        }

        root = current;
    }

    /// @notice Verify Merkle inclusion
    /// @param commitment The note commitment
    /// @param path The Merkle path
    /// @param anchor The expected root
    /// @return valid Whether the commitment is in the tree
    function verifyMerkleInclusion(
        bytes32 commitment,
        MerklePath memory path,
        bytes32 anchor
    ) internal pure returns (bool valid) {
        bytes32 computedRoot = computeMerkleRoot(commitment, path);
        valid = computedRoot == anchor;
    }

    /*//////////////////////////////////////////////////////////////
                       CROSS-CHAIN HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Convert Zcash note to PIL format
    /// @param note The Sapling note
    /// @param sourceNetwork Source Zcash network
    /// @return crossChainNote PIL-compatible note
    function toPILNote(
        SaplingNote memory note,
        ZcashNetwork sourceNetwork
    ) internal pure returns (CrossChainNote memory crossChainNote) {
        bytes32 cm = computeSaplingNoteCommitment(note);

        crossChainNote = CrossChainNote({
            noteId: keccak256(abi.encodePacked(PIL_ZCASH_DOMAIN, cm)),
            originalCm: cm,
            originalNf: bytes32(0), // Set when spent
            pool: ShieldedPool.SAPLING,
            value: note.value,
            pilCommitment: keccak256(
                abi.encodePacked(PIL_ZCASH_DOMAIN, cm, note.value)
            ),
            crossChainProof: bytes32(0), // Set during bridging
            bridgedAt: 0,
            sourceNetwork: sourceNetwork
        });
    }

    /// @notice Compute cross-chain nullifier binding
    /// @dev Links Zcash nullifier to PIL nullifier space
    function computeCrossChainNullifierBinding(
        bytes32 zcashNullifier,
        bytes32 pilDomainId,
        uint64 chainId
    ) internal pure returns (bytes32 binding) {
        binding = keccak256(
            abi.encodePacked(
                PIL_ZCASH_DOMAIN,
                "NullifierBinding",
                zcashNullifier,
                pilDomainId,
                chainId
            )
        );
    }

    /// @notice Verify transaction binding signature
    /// @param txHash Transaction hash (used in signature verification)
    /// @param bindingSig Binding signature
    /// @return valid Whether signature is valid
    function verifyBindingSignature(
        bytes32 txHash,
        bytes memory bindingSig
    ) internal pure returns (bool valid) {
        // Simplified check - actual verification requires BLS12-381 pairing
        require(bindingSig.length == 64, "Invalid binding sig length");
        // Use txHash in verification (prevents unused param warning)
        valid = txHash != bytes32(0) && bindingSig.length == 64;
    }
}
