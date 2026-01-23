// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title RailgunPrimitives
 * @author PIL Protocol
 * @notice Cryptographic primitives for Railgun privacy system integration
 *
 * @dev Railgun Cryptographic Stack:
 *
 * Curve: BN254 (alt_bn128) for ZK-SNARK proofs
 * Hash: Poseidon for in-circuit efficiency
 * Proofs: Groth16 zero-knowledge proofs
 * Notes: UTXO-based shielded transactions
 *
 * Railgun Architecture:
 * - UTXO model with shielded notes
 * - Poseidon-based Merkle trees
 * - Encrypted note metadata (viewing keys)
 * - Multi-asset support (ERC20/721/1155)
 *
 * BN254 Parameters:
 * - Field Prime (p): 21888242871839275222246405745257275088696311157297823662689037894645226208583
 * - Group Order (r): 21888242871839275222246405745257275088548364400416034343698204186575808495617
 * - Generator G1: (1, 2)
 * - Generator G2: Complex extension field point
 *
 * Privacy Model:
 * - Shielded UTXOs with commitment hiding
 * - Nullifiers prevent double-spending
 * - Viewing keys for balance scanning
 * - Relayer support for gas abstraction
 */
contract RailgunPrimitives {
    // =========================================================================
    // BN254 (alt_bn128) CURVE CONSTANTS
    // =========================================================================

    /// @notice BN254 base field prime (p)
    uint256 public constant BN254_P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /// @notice BN254 scalar field order (r) - also known as the group order
    uint256 public constant BN254_R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice BN254 G1 generator x-coordinate
    uint256 public constant BN254_G1_X = 1;

    /// @notice BN254 G1 generator y-coordinate
    uint256 public constant BN254_G1_Y = 2;

    /// @notice BN254 G2 generator x0 (real part of x)
    uint256 public constant BN254_G2_X0 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;

    /// @notice BN254 G2 generator x1 (imaginary part of x)
    uint256 public constant BN254_G2_X1 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;

    /// @notice BN254 G2 generator y0 (real part of y)
    uint256 public constant BN254_G2_Y0 =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;

    /// @notice BN254 G2 generator y1 (imaginary part of y)
    uint256 public constant BN254_G2_Y1 =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;

    /// @notice BN254 curve b coefficient (y² = x³ + b)
    uint256 public constant BN254_B = 3;

    // =========================================================================
    // POSEIDON HASH CONSTANTS
    // =========================================================================

    /// @notice Number of full rounds in Poseidon
    uint8 public constant POSEIDON_FULL_ROUNDS = 8;

    /// @notice Number of partial rounds in Poseidon
    uint8 public constant POSEIDON_PARTIAL_ROUNDS = 57;

    /// @notice Poseidon state width (t = rate + capacity)
    uint8 public constant POSEIDON_WIDTH = 3;

    /// @notice Poseidon S-box exponent (x^5 for BN254)
    uint8 public constant POSEIDON_ALPHA = 5;

    // =========================================================================
    // RAILGUN PROTOCOL CONSTANTS
    // =========================================================================

    /// @notice Merkle tree depth for note commitments
    uint8 public constant MERKLE_TREE_DEPTH = 16;

    /// @notice Maximum number of inputs per transaction
    uint8 public constant MAX_INPUTS = 13;

    /// @notice Maximum number of outputs per transaction
    uint8 public constant MAX_OUTPUTS = 13;

    /// @notice Domain separator for PIL-Railgun binding
    bytes32 public constant PIL_RAILGUN_DOMAIN =
        keccak256("PIL_Railgun_Interop_v1");

    /// @notice Domain for note commitments
    bytes32 public constant NOTE_COMMITMENT_DOMAIN =
        keccak256("RAILGUN_NOTE_COMMITMENT");

    /// @notice Domain for nullifier derivation
    bytes32 public constant NULLIFIER_DOMAIN = keccak256("RAILGUN_NULLIFIER");

    /// @notice Domain for viewing key derivation
    bytes32 public constant VIEWING_KEY_DOMAIN =
        keccak256("RAILGUN_VIEWING_KEY");

    /// @notice Domain for note encryption
    bytes32 public constant NOTE_ENCRYPTION_DOMAIN =
        keccak256("RAILGUN_NOTE_ENCRYPTION");

    /// @notice Railgun mainnet deployment chain ID (Ethereum)
    uint256 public constant RAILGUN_ETHEREUM_CHAIN_ID = 1;

    /// @notice Railgun Polygon deployment
    uint256 public constant RAILGUN_POLYGON_CHAIN_ID = 137;

    /// @notice Railgun Arbitrum deployment
    uint256 public constant RAILGUN_ARBITRUM_CHAIN_ID = 42161;

    /// @notice Railgun BSC deployment
    uint256 public constant RAILGUN_BSC_CHAIN_ID = 56;

    // =========================================================================
    // GROTH16 VERIFICATION KEY CONSTANTS
    // =========================================================================

    /// @notice Groth16 verification requires 4 G1 points and 2 G2 points minimum
    uint8 public constant GROTH16_VK_ALPHA_G1_SIZE = 64;
    uint8 public constant GROTH16_VK_BETA_G2_SIZE = 128;
    uint8 public constant GROTH16_VK_GAMMA_G2_SIZE = 128;
    uint8 public constant GROTH16_VK_DELTA_G2_SIZE = 128;

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice G1 point on BN254
    struct G1Point {
        uint256 x;
        uint256 y;
    }

    /// @notice G2 point on BN254 (over extension field)
    struct G2Point {
        uint256 x0; // Real part of x
        uint256 x1; // Imaginary part of x
        uint256 y0; // Real part of y
        uint256 y1; // Imaginary part of y
    }

    /// @notice Groth16 proof structure
    struct Groth16Proof {
        G1Point a;
        G2Point b;
        G1Point c;
    }

    /// @notice Groth16 verification key
    struct VerificationKey {
        G1Point alpha;
        G2Point beta;
        G2Point gamma;
        G2Point delta;
        G1Point[] ic; // Input commitment points
    }

    /// @notice Railgun shielded note
    struct ShieldedNote {
        bytes32 commitment; // Poseidon(npk, value, token, random)
        bytes32 nullifier; // Derived from spending key
        uint256 value; // Note value
        address token; // Token contract address
        bytes32 random; // Randomness for commitment
    }

    /// @notice Encrypted note ciphertext
    struct EncryptedNote {
        bytes32 ephemeralPubKey; // For ECDH
        bytes ciphertext; // AES-GCM encrypted note data
        bytes32 mac; // Message authentication code
    }

    /// @notice Railgun transaction bundle
    struct TransactionBundle {
        bytes32[] nullifiers; // Input nullifiers
        bytes32[] commitments; // Output commitments
        Groth16Proof proof; // ZK proof
        bytes32 merkleRoot; // Current tree root
        EncryptedNote[] encryptedOutputs; // Encrypted output notes
    }

    /// @notice Viewing key for balance scanning
    struct ViewingKey {
        bytes32 key; // Derived viewing key
        address owner; // Key owner
        uint256 startBlock; // Block to start scanning from
    }

    /// @notice Note position in Merkle tree
    struct NotePosition {
        uint256 treeIndex; // Which tree
        uint256 leafIndex; // Position in tree
        bytes32[] siblings; // Merkle path
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    event NoteCommitted(bytes32 indexed commitment, uint256 indexed leafIndex);
    event NullifierUsed(bytes32 indexed nullifier);
    event ViewingKeyRegistered(address indexed owner, bytes32 keyHash);
    event ProofVerified(bytes32 indexed txHash, bool success);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidFieldElement();
    error InvalidG1Point();
    error InvalidG2Point();
    error InvalidProof();
    error NullifierAlreadyUsed();
    error InvalidMerkleProof();
    error InvalidNoteCommitment();
    error PairingFailed();
    error InvalidViewingKey();
    error InvalidEncryptedNote();

    // =========================================================================
    // FIELD ARITHMETIC (mod r - scalar field)
    // =========================================================================

    /**
     * @notice Add two field elements modulo r
     * @param a First operand
     * @param b Second operand
     * @return result (a + b) mod r
     */
    function fieldAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return addmod(a, b, BN254_R);
    }

    /**
     * @notice Subtract two field elements modulo r
     * @param a First operand
     * @param b Second operand
     * @return result (a - b) mod r
     */
    function fieldSub(uint256 a, uint256 b) public pure returns (uint256) {
        return addmod(a, BN254_R - (b % BN254_R), BN254_R);
    }

    /**
     * @notice Multiply two field elements modulo r
     * @param a First operand
     * @param b Second operand
     * @return result (a * b) mod r
     */
    function fieldMul(uint256 a, uint256 b) public pure returns (uint256) {
        return mulmod(a, b, BN254_R);
    }

    /**
     * @notice Negate a field element modulo r
     * @param a Operand
     * @return result (-a) mod r
     */
    function fieldNeg(uint256 a) public pure returns (uint256) {
        return BN254_R - (a % BN254_R);
    }

    /**
     * @notice Compute modular inverse using Fermat's little theorem
     * @param a Element to invert
     * @return result a^(-1) mod r
     */
    function fieldInv(uint256 a) public view returns (uint256) {
        require(a != 0, "Cannot invert zero");
        return modExp(a, BN254_R - 2, BN254_R);
    }

    /**
     * @notice Check if value is a valid field element
     * @param x Value to check
     * @return isValid True if x < r
     */
    function isValidFieldElement(uint256 x) public pure returns (bool) {
        return x < BN254_R;
    }

    // =========================================================================
    // BASE FIELD ARITHMETIC (mod p)
    // =========================================================================

    /**
     * @notice Add two base field elements modulo p
     * @param a First operand
     * @param b Second operand
     * @return result (a + b) mod p
     */
    function baseFieldAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return addmod(a, b, BN254_P);
    }

    /**
     * @notice Multiply two base field elements modulo p
     * @param a First operand
     * @param b Second operand
     * @return result (a * b) mod p
     */
    function baseFieldMul(uint256 a, uint256 b) public pure returns (uint256) {
        return mulmod(a, b, BN254_P);
    }

    /**
     * @notice Check if value is a valid base field element
     * @param x Value to check
     * @return isValid True if x < p
     */
    function isValidBaseFieldElement(uint256 x) public pure returns (bool) {
        return x < BN254_P;
    }

    // =========================================================================
    // G1 POINT OPERATIONS
    // =========================================================================

    /**
     * @notice Check if a G1 point is valid (on curve)
     * @param p Point to validate
     * @return isValid True if point is on BN254 G1
     */
    function isValidG1Point(G1Point memory p) public pure returns (bool) {
        if (p.x == 0 && p.y == 0) {
            return true; // Point at infinity
        }
        if (p.x >= BN254_P || p.y >= BN254_P) {
            return false;
        }
        // Check y² = x³ + 3 (mod p)
        uint256 lhs = mulmod(p.y, p.y, BN254_P);
        uint256 rhs = addmod(
            mulmod(mulmod(p.x, p.x, BN254_P), p.x, BN254_P),
            BN254_B,
            BN254_P
        );
        return lhs == rhs;
    }

    /**
     * @notice Negate a G1 point
     * @param p Point to negate
     * @return result -p
     */
    function g1Negate(G1Point memory p) public pure returns (G1Point memory) {
        if (p.x == 0 && p.y == 0) {
            return p; // Negation of infinity is infinity
        }
        return G1Point(p.x, BN254_P - p.y);
    }

    /**
     * @notice Add two G1 points using precompile
     * @param p1 First point
     * @param p2 Second point
     * @return result p1 + p2
     */
    function g1Add(
        G1Point memory p1,
        G1Point memory p2
    ) public view returns (G1Point memory) {
        uint256[4] memory input;
        input[0] = p1.x;
        input[1] = p1.y;
        input[2] = p2.x;
        input[3] = p2.y;

        uint256[2] memory output;
        bool success;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            success := staticcall(gas(), 6, input, 128, output, 64)
        }

        require(success, "G1 addition failed");
        return G1Point(output[0], output[1]);
    }

    /**
     * @notice Scalar multiplication on G1 using precompile
     * @param p Point to multiply
     * @param s Scalar
     * @return result s * p
     */
    function g1ScalarMul(
        G1Point memory p,
        uint256 s
    ) public view returns (G1Point memory) {
        uint256[3] memory input;
        input[0] = p.x;
        input[1] = p.y;
        input[2] = s;

        uint256[2] memory output;
        bool success;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            success := staticcall(gas(), 7, input, 96, output, 64)
        }

        require(success, "G1 scalar mul failed");
        return G1Point(output[0], output[1]);
    }

    /**
     * @notice Get G1 generator point
     * @return generator The generator point G1
     */
    function g1Generator() public pure returns (G1Point memory) {
        return G1Point(BN254_G1_X, BN254_G1_Y);
    }

    // =========================================================================
    // G2 POINT OPERATIONS
    // =========================================================================

    /**
     * @notice Check if G2 point coordinates are valid base field elements
     * @param p Point to validate
     * @return isValid True if coordinates are valid
     */
    function isValidG2Point(G2Point memory p) public pure returns (bool) {
        // Check all coordinates are in base field
        return
            p.x0 < BN254_P &&
            p.x1 < BN254_P &&
            p.y0 < BN254_P &&
            p.y1 < BN254_P;
    }

    /**
     * @notice Get G2 generator point
     * @return generator The generator point G2
     */
    function g2Generator() public pure returns (G2Point memory) {
        return G2Point(BN254_G2_X0, BN254_G2_X1, BN254_G2_Y0, BN254_G2_Y1);
    }

    // =========================================================================
    // PAIRING OPERATIONS
    // =========================================================================

    /**
     * @notice Compute pairing check e(a1, b1) * e(a2, b2) == 1
     * @param a1 First G1 point
     * @param b1 First G2 point
     * @param a2 Second G1 point
     * @param b2 Second G2 point
     * @return success True if pairing equation holds
     */
    function pairingCheck(
        G1Point memory a1,
        G2Point memory b1,
        G1Point memory a2,
        G2Point memory b2
    ) public view returns (bool) {
        uint256[12] memory input;
        input[0] = a1.x;
        input[1] = a1.y;
        input[2] = b1.x1; // Note: G2 coordinates are swapped for precompile
        input[3] = b1.x0;
        input[4] = b1.y1;
        input[5] = b1.y0;
        input[6] = a2.x;
        input[7] = a2.y;
        input[8] = b2.x1;
        input[9] = b2.x0;
        input[10] = b2.y1;
        input[11] = b2.y0;

        uint256[1] memory output;
        bool success;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            success := staticcall(gas(), 8, input, 384, output, 32)
        }

        require(success, "Pairing precompile failed");
        return output[0] == 1;
    }

    // =========================================================================
    // POSEIDON HASH
    // =========================================================================

    /**
     * @notice Compute Poseidon hash of two field elements
     * @dev Simplified Poseidon implementation for demonstration
     * @param left First input
     * @param right Second input
     * @return hash Poseidon hash output
     */
    function poseidonHash2(
        uint256 left,
        uint256 right
    ) public pure returns (uint256) {
        // Simplified Poseidon - in production use optimized implementation
        // This uses domain separation and multiple rounds of mixing
        uint256 state = uint256(
            keccak256(
                abi.encodePacked(
                    NOTE_COMMITMENT_DOMAIN,
                    left % BN254_R,
                    right % BN254_R
                )
            )
        ) % BN254_R;

        // Additional mixing rounds
        for (uint8 i = 0; i < 4; i++) {
            state = uint256(keccak256(abi.encodePacked(state, i))) % BN254_R;
        }

        return state;
    }

    /**
     * @notice Compute Poseidon hash of four field elements
     * @param a First input
     * @param b Second input
     * @param c Third input
     * @param d Fourth input
     * @return hash Poseidon hash output
     */
    function poseidonHash4(
        uint256 a,
        uint256 b,
        uint256 c,
        uint256 d
    ) public pure returns (uint256) {
        uint256 left = poseidonHash2(a, b);
        uint256 right = poseidonHash2(c, d);
        return poseidonHash2(left, right);
    }

    /**
     * @notice Compute Poseidon hash of variable inputs
     * @param inputs Array of field elements
     * @return hash Poseidon hash output
     */
    function poseidonHashN(
        uint256[] memory inputs
    ) public pure returns (uint256) {
        require(inputs.length > 0, "Empty input");

        uint256 result = inputs[0] % BN254_R;
        for (uint256 i = 1; i < inputs.length; i++) {
            result = poseidonHash2(result, inputs[i]);
        }
        return result;
    }

    // =========================================================================
    // NOTE COMMITMENT
    // =========================================================================

    /**
     * @notice Compute note commitment
     * @param npk Note public key (derived from spending key)
     * @param value Note value
     * @param token Token address
     * @param random Randomness
     * @return commitment Note commitment hash
     */
    function computeNoteCommitment(
        bytes32 npk,
        uint256 value,
        address token,
        bytes32 random
    ) public pure returns (bytes32) {
        uint256 commitment = poseidonHash4(
            uint256(npk),
            value,
            uint256(uint160(token)),
            uint256(random)
        );
        return bytes32(commitment);
    }

    /**
     * @notice Verify a note commitment
     * @param note Note to verify
     * @param npk Note public key
     * @return isValid True if commitment matches
     */
    function verifyNoteCommitment(
        ShieldedNote memory note,
        bytes32 npk
    ) public pure returns (bool) {
        bytes32 computed = computeNoteCommitment(
            npk,
            note.value,
            note.token,
            note.random
        );
        return computed == note.commitment;
    }

    // =========================================================================
    // NULLIFIER OPERATIONS
    // =========================================================================

    /**
     * @notice Derive nullifier from spending key and note
     * @param spendingKey Spending key (private)
     * @param commitment Note commitment
     * @return nullifier The derived nullifier
     */
    function deriveNullifier(
        bytes32 spendingKey,
        bytes32 commitment
    ) public pure returns (bytes32) {
        return
            bytes32(
                poseidonHash2(uint256(spendingKey), uint256(commitment)) %
                    BN254_R
            );
    }

    /**
     * @notice Derive cross-domain nullifier for PIL interop
     * @param railgunNullifier Original Railgun nullifier
     * @param srcDomain Source domain identifier
     * @param dstDomain Destination domain identifier
     * @return crossDomainNullifier Derived cross-domain nullifier
     */
    function deriveCrossDomainNullifier(
        bytes32 railgunNullifier,
        bytes32 srcDomain,
        bytes32 dstDomain
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    PIL_RAILGUN_DOMAIN,
                    railgunNullifier,
                    srcDomain,
                    dstDomain
                )
            );
    }

    /**
     * @notice Derive PIL binding for Railgun nullifier
     * @param railgunNullifier Railgun nullifier
     * @return pilBinding PIL-bound nullifier
     */
    function derivePILBinding(
        bytes32 railgunNullifier
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    PIL_RAILGUN_DOMAIN,
                    railgunNullifier,
                    "RAILGUN_TO_PIL"
                )
            );
    }

    // =========================================================================
    // MERKLE TREE OPERATIONS
    // =========================================================================

    /**
     * @notice Compute Merkle root from leaf and path
     * @param leaf Leaf hash
     * @param pathIndices Bit indices (0 = left, 1 = right)
     * @param siblings Sibling hashes
     * @return root Computed Merkle root
     */
    function computeMerkleRoot(
        bytes32 leaf,
        uint256 pathIndices,
        bytes32[] memory siblings
    ) public pure returns (bytes32) {
        require(siblings.length == MERKLE_TREE_DEPTH, "Invalid path length");

        bytes32 current = leaf;
        for (uint256 i = 0; i < MERKLE_TREE_DEPTH; i++) {
            if ((pathIndices >> i) & 1 == 0) {
                // Current is left child
                current = bytes32(
                    poseidonHash2(uint256(current), uint256(siblings[i]))
                );
            } else {
                // Current is right child
                current = bytes32(
                    poseidonHash2(uint256(siblings[i]), uint256(current))
                );
            }
        }
        return current;
    }

    /**
     * @notice Verify Merkle proof for a note commitment
     * @param commitment Note commitment
     * @param merkleRoot Expected root
     * @param position Note position info
     * @return isValid True if proof is valid
     */
    function verifyMerkleProof(
        bytes32 commitment,
        bytes32 merkleRoot,
        NotePosition memory position
    ) public pure returns (bool) {
        bytes32 computed = computeMerkleRoot(
            commitment,
            position.leafIndex,
            position.siblings
        );
        return computed == merkleRoot;
    }

    // =========================================================================
    // GROTH16 VERIFICATION
    // =========================================================================

    /**
     * @notice Verify a Groth16 proof
     * @param proof The proof to verify
     * @param vk Verification key
     * @param publicInputs Public inputs to the circuit
     * @return isValid True if proof is valid
     */
    function verifyGroth16Proof(
        Groth16Proof memory proof,
        VerificationKey memory vk,
        uint256[] memory publicInputs
    ) public view returns (bool) {
        require(publicInputs.length + 1 == vk.ic.length, "Invalid input count");

        // Validate proof points
        if (!isValidG1Point(proof.a) || !isValidG1Point(proof.c)) {
            return false;
        }
        if (!isValidG2Point(proof.b)) {
            return false;
        }

        // Compute linear combination of IC points
        G1Point memory vkX = vk.ic[0];
        for (uint256 i = 0; i < publicInputs.length; i++) {
            require(publicInputs[i] < BN254_R, "Input too large");
            vkX = g1Add(vkX, g1ScalarMul(vk.ic[i + 1], publicInputs[i]));
        }

        // Verify pairing equation:
        // e(A, B) = e(alpha, beta) * e(vkX, gamma) * e(C, delta)
        // Which is equivalent to:
        // e(-A, B) * e(alpha, beta) * e(vkX, gamma) * e(C, delta) = 1

        return
            pairingCheck(g1Negate(proof.a), proof.b, vk.alpha, vk.beta) &&
            pairingCheck(vkX, vk.gamma, proof.c, vk.delta);
    }

    /**
     * @notice Verify a proof with pre-computed public inputs hash
     * @param proof The proof to verify
     * @param vk Verification key
     * @param publicInputsHash Hash of public inputs
     * @return isValid True if proof is valid
     */
    function verifyProofWithHash(
        Groth16Proof memory proof,
        VerificationKey memory vk,
        bytes32 publicInputsHash
    ) public view returns (bool) {
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = uint256(publicInputsHash) % BN254_R;
        return verifyGroth16Proof(proof, vk, inputs);
    }

    // =========================================================================
    // VIEWING KEY OPERATIONS
    // =========================================================================

    /**
     * @notice Derive viewing key from spending key
     * @param spendingKey Master spending key
     * @param salt Derivation salt
     * @return viewingKey Derived viewing key
     */
    function deriveViewingKey(
        bytes32 spendingKey,
        bytes32 salt
    ) public pure returns (bytes32) {
        return
            keccak256(abi.encodePacked(VIEWING_KEY_DOMAIN, spendingKey, salt));
    }

    /**
     * @notice Hash viewing key for storage
     * @param vk Viewing key
     * @return hash Viewing key hash
     */
    function hashViewingKey(
        ViewingKey memory vk
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(vk.key, vk.owner, vk.startBlock));
    }

    /**
     * @notice Validate viewing key
     * @param vk Viewing key to validate
     * @param currentBlock Current block number
     * @return isValid True if viewing key is valid
     */
    function isValidViewingKey(
        ViewingKey memory vk,
        uint256 currentBlock
    ) public pure returns (bool) {
        return
            vk.key != bytes32(0) &&
            vk.owner != address(0) &&
            vk.startBlock <= currentBlock;
    }

    // =========================================================================
    // NOTE ENCRYPTION
    // =========================================================================

    /**
     * @notice Create encrypted note
     * @dev Uses simplified encryption for demonstration
     * @param note Note to encrypt
     * @param recipientPubKey Recipient's public key
     * @param ephemeralPrivKey Ephemeral private key
     * @return encrypted Encrypted note
     */
    function encryptNote(
        ShieldedNote memory note,
        bytes32 recipientPubKey,
        bytes32 ephemeralPrivKey
    ) public view returns (EncryptedNote memory) {
        // Derive shared secret (simplified ECDH)
        bytes32 sharedSecret = keccak256(
            abi.encodePacked(
                NOTE_ENCRYPTION_DOMAIN,
                recipientPubKey,
                ephemeralPrivKey
            )
        );

        // Derive encryption key
        bytes32 encKey = keccak256(
            abi.encodePacked(sharedSecret, "ENCRYPTION")
        );

        // Encrypt note data (simplified - XOR with key stream)
        bytes memory plaintext = abi.encode(
            note.value,
            note.token,
            note.random
        );

        bytes memory ciphertext = new bytes(plaintext.length);
        for (uint256 i = 0; i < plaintext.length; i++) {
            bytes32 keyByte = keccak256(abi.encodePacked(encKey, i));
            ciphertext[i] = bytes1(uint8(plaintext[i]) ^ uint8(keyByte[0]));
        }

        // Compute MAC
        bytes32 mac = keccak256(
            abi.encodePacked(sharedSecret, "MAC", ciphertext)
        );

        // Ephemeral public key (simplified - hash of private key)
        bytes32 ephemeralPubKey = keccak256(
            abi.encodePacked(ephemeralPrivKey, block.timestamp)
        );

        return EncryptedNote(ephemeralPubKey, ciphertext, mac);
    }

    /**
     * @notice Verify encrypted note MAC
     * @param encrypted Encrypted note
     * @param viewingKey Viewing key
     * @return isValid True if MAC is valid
     */
    function verifyEncryptedNote(
        EncryptedNote memory encrypted,
        bytes32 viewingKey
    ) public pure returns (bool) {
        // Derive shared secret from viewing key
        bytes32 sharedSecret = keccak256(
            abi.encodePacked(
                NOTE_ENCRYPTION_DOMAIN,
                viewingKey,
                encrypted.ephemeralPubKey
            )
        );

        // Verify MAC
        bytes32 expectedMac = keccak256(
            abi.encodePacked(sharedSecret, "MAC", encrypted.ciphertext)
        );

        return encrypted.mac == expectedMac;
    }

    // =========================================================================
    // CHAIN DETECTION
    // =========================================================================

    /**
     * @notice Check if chain is Ethereum mainnet
     * @param chainId Chain ID to check
     * @return isEthereum True if Ethereum mainnet
     */
    function isEthereumMainnet(uint256 chainId) public pure returns (bool) {
        return chainId == RAILGUN_ETHEREUM_CHAIN_ID;
    }

    /**
     * @notice Check if chain is Polygon
     * @param chainId Chain ID to check
     * @return isPolygon True if Polygon
     */
    function isPolygon(uint256 chainId) public pure returns (bool) {
        return chainId == RAILGUN_POLYGON_CHAIN_ID;
    }

    /**
     * @notice Check if chain is Arbitrum
     * @param chainId Chain ID to check
     * @return isArbitrum True if Arbitrum
     */
    function isArbitrum(uint256 chainId) public pure returns (bool) {
        return chainId == RAILGUN_ARBITRUM_CHAIN_ID;
    }

    /**
     * @notice Check if chain is BSC
     * @param chainId Chain ID to check
     * @return isBSC True if BSC
     */
    function isBSC(uint256 chainId) public pure returns (bool) {
        return chainId == RAILGUN_BSC_CHAIN_ID;
    }

    /**
     * @notice Check if chain is a supported Railgun deployment
     * @param chainId Chain ID to check
     * @return isSupported True if supported
     */
    function isRailgunChain(uint256 chainId) public pure returns (bool) {
        return
            isEthereumMainnet(chainId) ||
            isPolygon(chainId) ||
            isArbitrum(chainId) ||
            isBSC(chainId);
    }

    // =========================================================================
    // TRANSACTION VALIDATION
    // =========================================================================

    /**
     * @notice Validate transaction bundle structure
     * @param bundle Transaction bundle
     * @return isValid True if bundle is well-formed
     */
    function validateBundleStructure(
        TransactionBundle memory bundle
    ) public pure returns (bool) {
        // Check input/output counts
        if (
            bundle.nullifiers.length == 0 ||
            bundle.nullifiers.length > MAX_INPUTS
        ) {
            return false;
        }
        if (
            bundle.commitments.length == 0 ||
            bundle.commitments.length > MAX_OUTPUTS
        ) {
            return false;
        }

        // Check encrypted outputs match commitments
        if (bundle.encryptedOutputs.length != bundle.commitments.length) {
            return false;
        }

        // Validate proof points
        if (!isValidG1Point(bundle.proof.a)) {
            return false;
        }
        if (!isValidG2Point(bundle.proof.b)) {
            return false;
        }
        if (!isValidG1Point(bundle.proof.c)) {
            return false;
        }

        return true;
    }

    /**
     * @notice Compute public inputs hash for transaction
     * @param bundle Transaction bundle
     * @return hash Public inputs hash
     */
    function computePublicInputsHash(
        TransactionBundle memory bundle
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    bundle.merkleRoot,
                    bundle.nullifiers,
                    bundle.commitments
                )
            );
    }

    // =========================================================================
    // UTILITY FUNCTIONS
    // =========================================================================

    /**
     * @notice Modular exponentiation using precompile
     * @param base Base value
     * @param exponent Exponent
     * @param modulus Modulus
     * @return result base^exponent mod modulus
     */
    function modExp(
        uint256 base,
        uint256 exponent,
        uint256 modulus
    ) public view returns (uint256 result) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // Free memory pointer
            let ptr := mload(0x40)

            // Store parameters for MODEXP precompile (address 0x05)
            mstore(ptr, 32) // Length of base
            mstore(add(ptr, 32), 32) // Length of exponent
            mstore(add(ptr, 64), 32) // Length of modulus
            mstore(add(ptr, 96), base)
            mstore(add(ptr, 128), exponent)
            mstore(add(ptr, 160), modulus)

            // Call the MODEXP precompile
            if iszero(staticcall(gas(), 5, ptr, 192, ptr, 32)) {
                revert(0, 0)
            }

            result := mload(ptr)
        }
    }

    /**
     * @notice Convert bytes to uint256
     * @param data Bytes data
     * @return result Uint256 value
     */
    function bytesToUint256(bytes memory data) public pure returns (uint256) {
        require(data.length == 32, "Invalid length");
        uint256 result;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            result := mload(add(data, 32))
        }
        return result;
    }

    /**
     * @notice Convert uint256 to bytes32
     * @param x Uint256 value
     * @return result Bytes32 value
     */
    function uint256ToBytes32(uint256 x) public pure returns (bytes32) {
        return bytes32(x);
    }
}
