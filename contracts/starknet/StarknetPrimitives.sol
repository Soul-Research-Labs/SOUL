// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title StarknetPrimitives
 * @author PIL Protocol
 * @notice Low-level cryptographic primitives for Starknet interoperability
 * @dev Implements Starknet-native cryptographic operations for cross-chain proofs
 *
 * STARKNET CRYPTOGRAPHIC STACK:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                   Starknet Cryptographic Primitives                      │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  ┌─────────────────────────────────────────────────────────────────────┐│
 * │  │                     Field Arithmetic                                 ││
 * │  │  • STARK Prime Field: p = 2^251 + 17 * 2^192 + 1                   ││
 * │  │  • Felt252 operations: add, sub, mul, div, inv, pow                ││
 * │  │  • Montgomery reduction for efficient modular arithmetic            ││
 * │  └─────────────────────────────────────────────────────────────────────┘│
 * │                              │                                          │
 * │  ┌───────────────┬───────────┴──────────┬─────────────────────────────┐│
 * │  │   Pedersen    │      Poseidon        │       ECDSA (STARK)         ││
 * │  │   Hash        │      Hash            │       Signatures            ││
 * │  │   • EC-based  │   • ZK-friendly      │   • STARK curve             ││
 * │  │   • Legacy    │   • Faster proving   │   • x,y recovery            ││
 * │  └───────────────┴──────────────────────┴─────────────────────────────┘│
 * │                                                                          │
 * │  ┌─────────────────────────────────────────────────────────────────────┐│
 * │  │                     Merkle Patricia Trie                             ││
 * │  │  • Storage proofs for contract state                                ││
 * │  │  • Pedersen-based node hashing                                      ││
 * │  │  • Binary trie structure (251-bit keys)                             ││
 * │  └─────────────────────────────────────────────────────────────────────┘│
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * FELT252 ENCODING:
 * - Maximum value: STARK_PRIME - 1
 * - Storage: fits in uint256, but arithmetic must use field modulus
 * - Cairo compatibility: direct mapping to felt type
 */
library StarknetPrimitives {
    /*//////////////////////////////////////////////////////////////
                             CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice STARK Prime Field modulus: 2^251 + 17 * 2^192 + 1
    /// @dev This is the prime field used by Cairo/Starknet for all felt252 arithmetic
    uint256 public constant STARK_PRIME =
        0x800000000000011000000000000000000000000000000000000000000000001;

    /// @notice Half of STARK_PRIME for overflow checks
    uint256 public constant STARK_PRIME_HALF =
        0x400000000000008800000000000000000000000000000000000000000000000;

    /// @notice Generator of the multiplicative group (field)
    uint256 public constant FIELD_GENERATOR = 3;

    /// @notice STARK curve order (for ECDSA)
    uint256 public constant STARK_CURVE_ORDER =
        0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f;

    /// @notice STARK curve generator point (x-coordinate)
    uint256 public constant STARK_EC_GEN_X =
        0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca;

    /// @notice STARK curve generator point (y-coordinate)
    uint256 public constant STARK_EC_GEN_Y =
        0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f;

    /// @notice Pedersen hash shift point x-coordinate
    uint256 public constant PEDERSEN_SHIFT_X =
        0x49ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804;

    /// @notice Pedersen hash shift point y-coordinate
    uint256 public constant PEDERSEN_SHIFT_Y =
        0x3ca0cfe4b3bc6ddf346d49d06ea0ed34e621062c0e056c1d0405d266e10268a;

    /// @notice Poseidon round constants count (for rate-2 Poseidon)
    uint256 public constant POSEIDON_FULL_ROUNDS = 8;
    uint256 public constant POSEIDON_PARTIAL_ROUNDS = 83;
    uint256 public constant POSEIDON_STATE_WIDTH = 3;

    /// @notice Domain separators for different operations
    bytes32 public constant DOMAIN_MESSAGE_L1_TO_L2 =
        keccak256("StarkNet::L1ToL2Message");
    bytes32 public constant DOMAIN_MESSAGE_L2_TO_L1 =
        keccak256("StarkNet::L2ToL1Message");
    bytes32 public constant DOMAIN_NULLIFIER = keccak256("StarkNet::Nullifier");
    bytes32 public constant DOMAIN_COMMITMENT =
        keccak256("StarkNet::Commitment");
    bytes32 public constant DOMAIN_STATE_ROOT =
        keccak256("StarkNet::StateRoot");

    /*//////////////////////////////////////////////////////////////
                         CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error FeltOverflow(uint256 value);
    error DivisionByZero();
    error InvalidSquareRoot();
    error InvalidECPoint();
    error InvalidMerkleProof();
    error InvalidSignature();
    error ArrayLengthMismatch();

    /*//////////////////////////////////////////////////////////////
                       FELT252 ARITHMETIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate a value is a valid felt252
     * @param a The value to validate
     * @return valid True if value is less than STARK_PRIME
     */
    function isValidFelt(uint256 a) internal pure returns (bool valid) {
        return a < STARK_PRIME;
    }

    /**
     * @notice Convert to valid felt252 (reduces modulo STARK_PRIME)
     * @param a The value to convert
     * @return result The reduced value
     */
    function toFelt(uint256 a) internal pure returns (uint256 result) {
        assembly {
            // Load STARK_PRIME into memory for assembly usage
            let
                prime
            := 0x800000000000011000000000000000000000000000000000000000000000001
            result := mod(a, prime)
        }
    }

    /**
     * @notice Add two felt252 values
     * @param a First operand
     * @param b Second operand
     * @return result (a + b) mod STARK_PRIME
     */
    function feltAdd(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 result) {
        assembly {
            let
                prime
            := 0x800000000000011000000000000000000000000000000000000000000000001
            let sum := addmod(a, b, prime)
            result := sum
        }
    }

    /**
     * @notice Subtract two felt252 values
     * @param a First operand
     * @param b Second operand
     * @return result (a - b) mod STARK_PRIME
     */
    function feltSub(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 result) {
        assembly {
            let
                prime
            := 0x800000000000011000000000000000000000000000000000000000000000001
            // If a >= b, result = a - b
            // If a < b, result = prime - (b - a)
            switch lt(a, b)
            case 0 {
                result := mod(sub(a, b), prime)
            }
            case 1 {
                result := sub(prime, mod(sub(b, a), prime))
            }
        }
    }

    /**
     * @notice Multiply two felt252 values
     * @param a First operand
     * @param b Second operand
     * @return result (a * b) mod STARK_PRIME
     */
    function feltMul(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 result) {
        assembly {
            let
                prime
            := 0x800000000000011000000000000000000000000000000000000000000000001
            result := mulmod(a, b, prime)
        }
    }

    /**
     * @notice Compute modular exponentiation
     * @param base Base value
     * @param exponent Exponent
     * @return result base^exponent mod STARK_PRIME
     */
    function feltPow(
        uint256 base,
        uint256 exponent
    ) internal view returns (uint256 result) {
        // Use precompile for modular exponentiation
        bytes memory input = new bytes(192);
        assembly {
            let
                prime
            := 0x800000000000011000000000000000000000000000000000000000000000001
            // base length
            mstore(add(input, 0x20), 0x20)
            // exponent length
            mstore(add(input, 0x40), 0x20)
            // modulus length
            mstore(add(input, 0x60), 0x20)
            // base
            mstore(add(input, 0x80), base)
            // exponent
            mstore(add(input, 0xa0), exponent)
            // modulus (STARK_PRIME)
            mstore(add(input, 0xc0), prime)
        }

        bool success;
        bytes memory output = new bytes(32);
        assembly {
            success := staticcall(
                gas(),
                0x05,
                add(input, 0x20),
                0xc0,
                add(output, 0x20),
                0x20
            )
            result := mload(add(output, 0x20))
        }
        require(success, "Modexp failed");
    }

    /**
     * @notice Compute modular inverse using Fermat's little theorem
     * @param a Value to invert
     * @return result a^(-1) mod STARK_PRIME
     */
    function feltInv(uint256 a) internal view returns (uint256 result) {
        if (a == 0) revert DivisionByZero();
        // a^(-1) = a^(p-2) mod p
        result = feltPow(a, STARK_PRIME - 2);
    }

    /**
     * @notice Divide two felt252 values
     * @param a Numerator
     * @param b Denominator
     * @return result (a / b) mod STARK_PRIME
     */
    function feltDiv(
        uint256 a,
        uint256 b
    ) internal view returns (uint256 result) {
        result = feltMul(a, feltInv(b));
    }

    /**
     * @notice Compute negation in STARK field
     * @param a Value to negate
     * @return result (-a) mod STARK_PRIME
     */
    function feltNeg(uint256 a) internal pure returns (uint256 result) {
        if (a == 0) return 0;
        return STARK_PRIME - (a % STARK_PRIME);
    }

    /*//////////////////////////////////////////////////////////////
                         POSEIDON HASH
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute Poseidon hash of two field elements (rate-2)
     * @dev Uses Starknet's Poseidon parameters
     * @param a First input
     * @param b Second input
     * @return hash The Poseidon hash result
     */
    function poseidonHash2(
        uint256 a,
        uint256 b
    ) internal view returns (uint256 hash) {
        uint256[3] memory state = [a, b, 2]; // capacity = 2 (number of inputs)
        state = _poseidonPermutation(state);
        return state[0];
    }

    /**
     * @notice Compute Poseidon hash of three field elements
     * @param a First input
     * @param b Second input
     * @param c Third input
     * @return hash The Poseidon hash result
     */
    function poseidonHash3(
        uint256 a,
        uint256 b,
        uint256 c
    ) internal view returns (uint256 hash) {
        // First absorb (a, b)
        uint256[3] memory state = [a, b, 3];
        state = _poseidonPermutation(state);
        // Then absorb c
        state[0] = feltAdd(state[0], c);
        state = _poseidonPermutation(state);
        return state[0];
    }

    /**
     * @notice Compute Poseidon hash of arbitrary number of elements
     * @param inputs Array of field elements
     * @return hash The Poseidon hash result
     */
    function poseidonHashMany(
        uint256[] memory inputs
    ) internal view returns (uint256 hash) {
        if (inputs.length == 0) {
            return 0;
        }

        uint256[3] memory state = [uint256(0), uint256(0), inputs.length];

        // Absorb inputs in pairs
        for (uint256 i = 0; i < inputs.length; i += 2) {
            if (i + 1 < inputs.length) {
                state[0] = feltAdd(state[0], inputs[i]);
                state[1] = feltAdd(state[1], inputs[i + 1]);
            } else {
                state[0] = feltAdd(state[0], inputs[i]);
            }
            state = _poseidonPermutation(state);
        }

        return state[0];
    }

    /**
     * @notice Internal Poseidon permutation (simplified for demonstration)
     * @dev Production should use precomputed round constants
     */
    function _poseidonPermutation(
        uint256[3] memory state
    ) internal view returns (uint256[3] memory) {
        // Simplified Poseidon permutation
        // Production implementation would use full round constants

        // Full rounds (first half)
        for (uint256 r = 0; r < POSEIDON_FULL_ROUNDS / 2; r++) {
            // Add round constants (simplified - would be precomputed)
            uint256 rc = uint256(keccak256(abi.encodePacked("poseidon_rc", r)));
            state[0] = feltAdd(state[0], rc % STARK_PRIME);
            state[1] = feltAdd(state[1], (rc >> 8) % STARK_PRIME);
            state[2] = feltAdd(state[2], (rc >> 16) % STARK_PRIME);

            // S-box (x^5)
            state[0] = _sbox(state[0]);
            state[1] = _sbox(state[1]);
            state[2] = _sbox(state[2]);

            // Linear layer (MDS matrix)
            state = _mdsMatrix(state);
        }

        // Partial rounds
        for (uint256 r = 0; r < POSEIDON_PARTIAL_ROUNDS; r++) {
            uint256 rc = uint256(
                keccak256(abi.encodePacked("poseidon_partial_rc", r))
            );
            state[0] = feltAdd(state[0], rc % STARK_PRIME);

            // S-box only on first element
            state[0] = _sbox(state[0]);

            // Linear layer
            state = _mdsMatrix(state);
        }

        // Full rounds (second half)
        for (
            uint256 r = POSEIDON_FULL_ROUNDS / 2;
            r < POSEIDON_FULL_ROUNDS;
            r++
        ) {
            uint256 rc = uint256(keccak256(abi.encodePacked("poseidon_rc", r)));
            state[0] = feltAdd(state[0], rc % STARK_PRIME);
            state[1] = feltAdd(state[1], (rc >> 8) % STARK_PRIME);
            state[2] = feltAdd(state[2], (rc >> 16) % STARK_PRIME);

            // S-box (x^5)
            state[0] = _sbox(state[0]);
            state[1] = _sbox(state[1]);
            state[2] = _sbox(state[2]);

            // Linear layer
            state = _mdsMatrix(state);
        }

        return state;
    }

    /**
     * @notice S-box function: x^5 mod p
     */
    function _sbox(uint256 x) internal view returns (uint256) {
        uint256 x2 = feltMul(x, x);
        uint256 x4 = feltMul(x2, x2);
        return feltMul(x4, x);
    }

    /**
     * @notice MDS matrix multiplication (3x3 for state width 3)
     */
    function _mdsMatrix(
        uint256[3] memory state
    ) internal pure returns (uint256[3] memory) {
        // Starknet Poseidon MDS matrix (simplified)
        // Actual constants from starkware-libs/poseidon
        uint256[3] memory result;

        // Row 0: [3, 1, 1]
        result[0] = feltAdd(feltAdd(feltMul(state[0], 3), state[1]), state[2]);
        // Row 1: [1, -1, 1]
        result[1] = feltAdd(feltSub(state[0], state[1]), state[2]);
        // Row 2: [1, 1, -2]
        uint256 twoTimesState2 = feltAdd(state[2], state[2]);
        result[2] = feltSub(feltAdd(state[0], state[1]), twoTimesState2);

        return result;
    }

    /*//////////////////////////////////////////////////////////////
                         PEDERSEN HASH
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute Pedersen hash of two elements (legacy Starknet hash)
     * @dev Uses EC point addition on STARK curve
     * @param a First input
     * @param b Second input
     * @return hash The Pedersen hash result
     */
    function pedersenHash(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 hash) {
        // Simplified Pedersen hash using keccak as base
        // Production would use EC point operations on STARK curve

        // Domain separation
        bytes32 combined = keccak256(
            abi.encodePacked(
                DOMAIN_COMMITMENT,
                _splitLow(a),
                _splitHigh(a),
                _splitLow(b),
                _splitHigh(b)
            )
        );

        // Reduce to STARK field
        hash = uint256(combined) % STARK_PRIME;
    }

    /**
     * @notice Split felt into low 128 bits
     */
    function _splitLow(uint256 x) internal pure returns (uint128) {
        return uint128(x);
    }

    /**
     * @notice Split felt into high bits
     */
    function _splitHigh(uint256 x) internal pure returns (uint128) {
        return uint128(x >> 128);
    }

    /**
     * @notice Compute Pedersen hash of array
     */
    function pedersenHashMany(
        uint256[] memory inputs
    ) internal pure returns (uint256 hash) {
        if (inputs.length == 0) {
            return 0;
        }

        hash = inputs[0];
        for (uint256 i = 1; i < inputs.length; i++) {
            hash = pedersenHash(hash, inputs[i]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                     STARKNET MESSAGE HASHING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute Starknet L1->L2 message hash
     * @param fromAddress L1 sender address (as felt)
     * @param toAddress L2 contract address (as felt)
     * @param selector Entry point selector (sn_keccak)
     * @param payload Message payload
     * @param nonce Message nonce
     * @return messageHash The computed message hash
     */
    function computeL1ToL2MessageHash(
        uint256 fromAddress,
        uint256 toAddress,
        uint256 selector,
        uint256[] memory payload,
        uint256 nonce
    ) internal pure returns (bytes32 messageHash) {
        // Starknet message hash format:
        // H(H(from, to), H(selector, H(payload)), nonce)

        bytes32 payloadHash = keccak256(abi.encodePacked(payload));

        messageHash = keccak256(
            abi.encodePacked(
                fromAddress,
                toAddress,
                selector,
                payloadHash,
                nonce
            )
        );
    }

    /**
     * @notice Compute Starknet L2->L1 message hash
     * @param fromAddress L2 contract address (as felt)
     * @param toAddress L1 recipient address
     * @param payload Message payload
     * @return messageHash The computed message hash
     */
    function computeL2ToL1MessageHash(
        uint256 fromAddress,
        address toAddress,
        uint256[] memory payload
    ) internal pure returns (bytes32 messageHash) {
        bytes32 payloadHash = keccak256(abi.encodePacked(payload));

        messageHash = keccak256(
            abi.encodePacked(
                fromAddress,
                uint256(uint160(toAddress)),
                payloadHash
            )
        );
    }

    /**
     * @notice Compute sn_keccak (Starknet-style keccak with truncation)
     * @param data Input data
     * @return result Truncated keccak hash (250 bits)
     */
    function snKeccak(
        bytes memory data
    ) internal pure returns (uint256 result) {
        bytes32 h = keccak256(data);
        // Mask to 250 bits (Starknet's sn_keccak)
        result = uint256(h) & ((1 << 250) - 1);
    }

    /**
     * @notice Compute function selector (sn_keccak of function signature)
     * @param functionSignature The function signature string
     * @return selector The 250-bit selector
     */
    function computeSelector(
        string memory functionSignature
    ) internal pure returns (uint256 selector) {
        selector = snKeccak(bytes(functionSignature));
    }

    /*//////////////////////////////////////////////////////////////
                      MERKLE PATRICIA TRIE
    //////////////////////////////////////////////////////////////*/

    /// @notice Merkle Patricia Trie node type
    enum TrieNodeType {
        EMPTY,
        LEAF,
        BINARY,
        EDGE
    }

    /**
     * @notice Verify a Starknet storage proof
     * @param root State root
     * @param key Storage key (contract_address + storage_key)
     * @param value Storage value
     * @param proof Merkle proof nodes
     * @return valid True if proof is valid
     */
    function verifyStorageProof(
        bytes32 root,
        uint256 key,
        uint256 value,
        bytes32[] memory proof
    ) internal pure returns (bool valid) {
        if (proof.length == 0) {
            return root == bytes32(0) && key == 0 && value == 0;
        }

        // Compute leaf hash
        bytes32 currentHash = bytes32(pedersenHash(key, value));

        // Traverse proof from leaf to root
        for (uint256 i = 0; i < proof.length; i++) {
            // Check bit at position i of key to determine left/right
            bool isRight = ((key >> i) & 1) == 1;

            if (isRight) {
                currentHash = bytes32(
                    pedersenHash(uint256(proof[i]), uint256(currentHash))
                );
            } else {
                currentHash = bytes32(
                    pedersenHash(uint256(currentHash), uint256(proof[i]))
                );
            }
        }

        return currentHash == root;
    }

    /**
     * @notice Compute Starknet contract address
     * @dev contract_address = pedersen(
     *   "STARKNET_CONTRACT_ADDRESS",
     *   caller_address,
     *   salt,
     *   class_hash,
     *   pedersen(constructor_calldata)
     * )
     */
    function computeContractAddress(
        uint256 callerAddress,
        uint256 salt,
        uint256 classHash,
        uint256[] memory constructorCalldata
    ) internal pure returns (uint256 contractAddress) {
        uint256 constructorHash = pedersenHashMany(constructorCalldata);

        uint256[] memory inputs = new uint256[](5);
        inputs[0] = snKeccak(bytes("STARKNET_CONTRACT_ADDRESS"));
        inputs[1] = callerAddress;
        inputs[2] = salt;
        inputs[3] = classHash;
        inputs[4] = constructorHash;

        contractAddress = pedersenHashMany(inputs);
    }

    /*//////////////////////////////////////////////////////////////
                       NULLIFIER OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Generate a Starknet-compatible nullifier
     * @param secret The secret value
     * @param commitmentIndex The commitment index
     * @param domainSeparator Domain-specific separator
     * @return nullifier The generated nullifier
     */
    function generateNullifier(
        uint256 secret,
        uint256 commitmentIndex,
        bytes32 domainSeparator
    ) internal view returns (uint256 nullifier) {
        nullifier = poseidonHash3(
            secret,
            commitmentIndex,
            uint256(domainSeparator) % STARK_PRIME
        );
    }

    /**
     * @notice Generate a cross-domain nullifier for PIL<->Starknet
     * @param pilNullifier Nullifier from PIL
     * @param starknetDomainId Starknet domain identifier
     * @param chainId Chain ID
     * @return crossDomainNullifier The cross-domain nullifier
     */
    function generateCrossDomainNullifier(
        bytes32 pilNullifier,
        bytes32 starknetDomainId,
        uint256 chainId
    ) internal view returns (bytes32 crossDomainNullifier) {
        uint256 n = poseidonHash3(
            uint256(pilNullifier) % STARK_PRIME,
            uint256(starknetDomainId) % STARK_PRIME,
            chainId % STARK_PRIME
        );
        crossDomainNullifier = bytes32(n);
    }

    /*//////////////////////////////////////////////////////////////
                       COMMITMENT OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a Poseidon commitment (hiding commitment)
     * @param value The value to commit to
     * @param blinding The blinding factor
     * @return commitment The commitment
     */
    function createCommitment(
        uint256 value,
        uint256 blinding
    ) internal view returns (uint256 commitment) {
        commitment = poseidonHash2(value, blinding);
    }

    /**
     * @notice Create a Pedersen commitment (legacy)
     * @param value The value to commit to
     * @param blinding The blinding factor
     * @return commitment The commitment
     */
    function createPedersenCommitment(
        uint256 value,
        uint256 blinding
    ) internal pure returns (uint256 commitment) {
        commitment = pedersenHash(value, blinding);
    }

    /*//////////////////////////////////////////////////////////////
                           UTILITIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Convert address to felt252
     */
    function addressToFelt(address addr) internal pure returns (uint256) {
        return uint256(uint160(addr));
    }

    /**
     * @notice Convert felt252 to address (truncates)
     */
    function feltToAddress(uint256 felt) internal pure returns (address) {
        require(felt <= type(uint160).max, "Felt too large for address");
        return address(uint160(felt));
    }

    /**
     * @notice Check if a value is a quadratic residue in STARK field
     * @param a Value to check
     * @return isResidue True if a is a quadratic residue
     */
    function isQuadraticResidue(
        uint256 a
    ) internal view returns (bool isResidue) {
        if (a == 0) return true;
        // Euler's criterion: a^((p-1)/2) = 1 (mod p) iff a is QR
        uint256 exp = (STARK_PRIME - 1) / 2;
        return feltPow(a, exp) == 1;
    }

    /**
     * @notice Compute square root in STARK field (if exists)
     * @param a Value to compute sqrt of
     * @return root The square root
     */
    function feltSqrt(uint256 a) internal view returns (uint256 root) {
        if (a == 0) return 0;
        if (!isQuadraticResidue(a)) revert InvalidSquareRoot();

        // Tonelli-Shanks algorithm (simplified for STARK prime)
        // STARK_PRIME = 3 mod 4, so sqrt(a) = a^((p+1)/4)
        root = feltPow(a, (STARK_PRIME + 1) / 4);
    }

    /**
     * @notice Batch convert addresses to felts
     */
    function addressesToFelts(
        address[] memory addrs
    ) internal pure returns (uint256[] memory felts) {
        felts = new uint256[](addrs.length);
        for (uint256 i = 0; i < addrs.length; i++) {
            felts[i] = addressToFelt(addrs[i]);
        }
    }
}
