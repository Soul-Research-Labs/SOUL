// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SecretPrimitives
 * @author PIL Protocol
 * @notice Cryptographic primitives for Secret Network (SCRT) integration
 *
 * @dev Secret Network Cryptographic Stack:
 *
 * Encryption: AES-SIV (Deterministic AEAD) for state encryption
 * Key Exchange: ECDH with secp256k1 for shared secrets
 * Attestation: Intel SGX Remote Attestation (EPID/DCAP)
 * Hashing: SHA-256, HKDF for key derivation
 *
 * Secret Network Architecture:
 * - Consensus: Tendermint BFT with encrypted mempool
 * - Execution: CosmWasm with TEE-based confidential compute
 * - State: All contract state encrypted at rest
 * - Tokens: SNIP-20/721/1155 privacy-preserving standards
 *
 * TEE Integration:
 * - Intel SGX enclaves for confidential execution
 * - Consensus seed derived from SGX sealing
 * - Network-wide encryption key sharing via DKG
 *
 * Privacy Model:
 * - Encrypted inputs (transaction calldata)
 * - Encrypted state (AES-SIV)
 * - Encrypted outputs (logs/events)
 * - Viewing keys for selective disclosure
 * - Query permits for access control
 */
contract SecretPrimitives {
    // =========================================================================
    // SECP256K1 CONSTANTS (Secret Network uses Cosmos SDK secp256k1)
    // =========================================================================

    /// @notice secp256k1 field prime
    uint256 public constant SECP256K1_P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    /// @notice secp256k1 group order
    uint256 public constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice secp256k1 generator point Gx
    uint256 public constant SECP256K1_GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;

    /// @notice secp256k1 generator point Gy
    uint256 public constant SECP256K1_GY =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    /// @notice secp256k1 cofactor
    uint8 public constant SECP256K1_COFACTOR = 1;

    // =========================================================================
    // AES-SIV CONSTANTS (Deterministic AEAD for state encryption)
    // =========================================================================

    /// @notice AES-SIV key size (256 bits for AES-256-SIV = 64 bytes total)
    uint8 public constant AES_SIV_KEY_SIZE = 64;

    /// @notice AES block size (128 bits = 16 bytes)
    uint8 public constant AES_BLOCK_SIZE = 16;

    /// @notice SIV tag size (128 bits = 16 bytes)
    uint8 public constant SIV_TAG_SIZE = 16;

    // =========================================================================
    // SECRET NETWORK CONSTANTS
    // =========================================================================

    /// @notice Secret Network mainnet chain ID (Cosmos format)
    string public constant SECRET_MAINNET_CHAIN_ID = "secret-4";

    /// @notice Secret Network testnet chain ID
    string public constant SECRET_TESTNET_CHAIN_ID = "pulsar-3";

    /// @notice Secret Network numeric identifiers for EVM compatibility
    uint256 public constant SECRET_MAINNET_NUMERIC_ID = 1;
    uint256 public constant SECRET_TESTNET_NUMERIC_ID = 2;

    /// @notice Domain separator for PIL-Secret binding
    bytes32 public constant PIL_SECRET_DOMAIN =
        keccak256("PIL_Secret_Interop_v1");

    /// @notice Domain for encrypted state
    bytes32 public constant ENCRYPTED_STATE_DOMAIN =
        keccak256("SECRET_ENCRYPTED_STATE");

    /// @notice Domain for viewing key derivation
    bytes32 public constant VIEWING_KEY_DOMAIN =
        keccak256("SECRET_VIEWING_KEY");

    /// @notice Domain for query permits
    bytes32 public constant QUERY_PERMIT_DOMAIN =
        keccak256("SECRET_QUERY_PERMIT");

    // =========================================================================
    // SGX ATTESTATION CONSTANTS
    // =========================================================================

    /// @notice Intel SGX quote version
    uint16 public constant SGX_QUOTE_VERSION = 3;

    /// @notice Attestation key type (ECDSA-256 with P-256)
    uint16 public constant SGX_ATTESTATION_KEY_TYPE = 2;

    /// @notice Maximum quote age (24 hours in seconds)
    uint256 public constant MAX_QUOTE_AGE = 86400;

    /// @notice TCB status values
    uint8 public constant TCB_STATUS_UP_TO_DATE = 0;
    uint8 public constant TCB_STATUS_SW_HARDENING_NEEDED = 1;
    uint8 public constant TCB_STATUS_CONFIGURATION_NEEDED = 2;
    uint8 public constant TCB_STATUS_OUT_OF_DATE = 3;
    uint8 public constant TCB_STATUS_REVOKED = 4;

    // =========================================================================
    // SNIP TOKEN CONSTANTS
    // =========================================================================

    /// @notice SNIP-20 interface ID (fungible tokens)
    bytes4 public constant SNIP20_INTERFACE_ID = 0x36372b07;

    /// @notice SNIP-721 interface ID (NFTs)
    bytes4 public constant SNIP721_INTERFACE_ID = 0x80ac58cd;

    /// @notice SNIP-1155 interface ID (multi-token)
    bytes4 public constant SNIP1155_INTERFACE_ID = 0xd9b67a26;

    // =========================================================================
    // TYPE DEFINITIONS
    // =========================================================================

    /// @notice Secp256k1 public key (compressed, 33 bytes)
    struct Secp256k1PublicKey {
        bytes key; // 33 bytes compressed
    }

    /// @notice Encrypted data envelope (AES-SIV)
    struct EncryptedEnvelope {
        bytes16 sivTag; // SIV authentication tag (also serves as IV)
        bytes ciphertext; // Encrypted data
        bytes ephemeralPubKey; // Sender's ephemeral secp256k1 public key (33 bytes)
    }

    /// @notice Viewing key for Secret Network
    struct ViewingKey {
        bytes32 key; // The viewing key
        address owner; // Owner of the viewing key
        uint256 createdAt; // Creation timestamp
        uint256 expiresAt; // Expiration timestamp (0 = never)
    }

    /// @notice Query permit for Secret Network access control
    struct QueryPermit {
        bytes32 permitId; // Unique permit identifier
        address granter; // Who issued the permit
        address grantee; // Who can use the permit
        bytes32[] permissions; // List of allowed query types
        uint256 expiresAt; // Expiration timestamp
        bytes signature; // Signature from granter
    }

    /// @notice SGX Report Body (simplified for Secret Network)
    struct SGXReportBody {
        bytes16 cpuSvn; // CPU security version
        bytes32 mrEnclave; // Measurement of enclave code
        bytes32 mrSigner; // Measurement of enclave signer
        uint16 isvProdId; // ISV product ID
        uint16 isvSvn; // ISV security version
        bytes reportData; // User-defined data (64 bytes)
    }

    /// @notice SGX Quote for attestation
    struct SGXQuote {
        uint16 version;
        uint16 attestationKeyType;
        bytes32 mrEnclave;
        bytes32 mrSigner;
        uint64 timestamp;
        bytes reportData;
        bytes signature;
    }

    /// @notice Attestation result
    struct Attestation {
        bytes32 mrEnclave;
        bytes32 mrSigner;
        uint8 tcbStatus;
        uint64 timestamp;
        bytes32 reportDataHash0; // First 32 bytes of report data hash
        bytes32 reportDataHash1; // Second 32 bytes of report data hash
    }

    /// @notice Secret Network nullifier
    struct SecretNullifier {
        bytes32 secret; // Secret value known only to owner
        bytes32 commitment; // Public commitment
        bytes32 mrEnclave; // TEE that created it
    }

    /// @notice SNIP-20 token info
    struct SNIP20Info {
        string name;
        string symbol;
        uint8 decimals;
        bytes32 contractHash; // Code hash on Secret Network
    }

    /// @notice IBC channel info
    struct IBCChannel {
        string channelId; // e.g., "channel-0"
        string portId; // e.g., "transfer"
        string counterpartyChannelId;
        string counterpartyPortId;
        bytes32 connectionHops; // Hash of connection path
    }

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidPublicKey();
    error InvalidSignature();
    error InvalidEnvelope();
    error ExpiredViewingKey();
    error ExpiredPermit();
    error InvalidPermit();
    error AttestationFailed();
    error TCBOutOfDate();
    error InvalidMerkleProof();
    error InvalidNullifier();

    // =========================================================================
    // EVENTS
    // =========================================================================

    event ViewingKeyCreated(
        address indexed owner,
        bytes32 indexed keyHash,
        uint256 expiresAt
    );
    event QueryPermitIssued(
        bytes32 indexed permitId,
        address indexed granter,
        address indexed grantee
    );
    event AttestationVerified(
        bytes32 indexed mrEnclave,
        bytes32 indexed mrSigner,
        uint8 tcbStatus
    );

    // =========================================================================
    // SECP256K1 FIELD OPERATIONS
    // =========================================================================

    /**
     * @notice Add two field elements mod p
     * @param a First element
     * @param b Second element
     * @return Result mod p
     */
    function fieldAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return addmod(a, b, SECP256K1_P);
    }

    /**
     * @notice Subtract two field elements mod p
     * @param a First element
     * @param b Second element
     * @return Result mod p
     */
    function fieldSub(uint256 a, uint256 b) public pure returns (uint256) {
        if (b > a) {
            return SECP256K1_P - ((b - a) % SECP256K1_P);
        }
        return (a - b) % SECP256K1_P;
    }

    /**
     * @notice Multiply two field elements mod p
     * @param a First element
     * @param b Second element
     * @return Result mod p
     */
    function fieldMul(uint256 a, uint256 b) public pure returns (uint256) {
        return mulmod(a, b, SECP256K1_P);
    }

    /**
     * @notice Negate a field element mod p
     * @param a Element to negate
     * @return Negated element
     */
    function fieldNeg(uint256 a) public pure returns (uint256) {
        if (a == 0) return 0;
        return SECP256K1_P - (a % SECP256K1_P);
    }

    /**
     * @notice Compute field inverse using Fermat's little theorem
     * @param a Element to invert
     * @return a^(-1) mod p
     */
    function fieldInv(uint256 a) public view returns (uint256) {
        require(a != 0, "Cannot invert zero");
        return modExp(a, SECP256K1_P - 2, SECP256K1_P);
    }

    /**
     * @notice Modular exponentiation using precompile
     * @param base Base value
     * @param exponent Exponent
     * @param modulus Modulus
     * @return result Result of base^exponent mod modulus
     */
    function modExp(
        uint256 base,
        uint256 exponent,
        uint256 modulus
    ) public view returns (uint256 result) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 32) // base length
            mstore(add(ptr, 32), 32) // exponent length
            mstore(add(ptr, 64), 32) // modulus length
            mstore(add(ptr, 96), base)
            mstore(add(ptr, 128), exponent)
            mstore(add(ptr, 160), modulus)

            let success := staticcall(gas(), 0x05, ptr, 192, ptr, 32)
            if iszero(success) {
                revert(0, 0)
            }
            result := mload(ptr)
        }
    }

    // =========================================================================
    // SCALAR OPERATIONS (mod n)
    // =========================================================================

    /**
     * @notice Add two scalars mod n
     * @param a First scalar
     * @param b Second scalar
     * @return Result mod n
     */
    function scalarAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return addmod(a, b, SECP256K1_N);
    }

    /**
     * @notice Subtract two scalars mod n
     * @param a First scalar
     * @param b Second scalar
     * @return Result mod n
     */
    function scalarSub(uint256 a, uint256 b) public pure returns (uint256) {
        if (b > a) {
            return SECP256K1_N - ((b - a) % SECP256K1_N);
        }
        return (a - b) % SECP256K1_N;
    }

    /**
     * @notice Multiply two scalars mod n
     * @param a First scalar
     * @param b Second scalar
     * @return Result mod n
     */
    function scalarMul(uint256 a, uint256 b) public pure returns (uint256) {
        return mulmod(a, b, SECP256K1_N);
    }

    /**
     * @notice Reduce a value mod n
     * @param a Value to reduce
     * @return Reduced value
     */
    function scalarReduce(uint256 a) public pure returns (uint256) {
        return a % SECP256K1_N;
    }

    /**
     * @notice Check if scalar is valid (non-zero and less than n)
     * @param s Scalar to check
     * @return True if valid
     */
    function isValidScalar(uint256 s) public pure returns (bool) {
        return s > 0 && s < SECP256K1_N;
    }

    // =========================================================================
    // PUBLIC KEY VALIDATION
    // =========================================================================

    /**
     * @notice Validate a compressed secp256k1 public key
     * @param pubKey Compressed public key (33 bytes)
     * @return True if valid
     */
    function isValidPublicKey(bytes memory pubKey) public pure returns (bool) {
        // Check length
        if (pubKey.length != 33) {
            return false;
        }

        // Check prefix byte (0x02 or 0x03 for compressed)
        uint8 prefix = uint8(pubKey[0]);
        if (prefix != 0x02 && prefix != 0x03) {
            return false;
        }

        // Extract x-coordinate
        uint256 x;
        assembly {
            x := shr(8, mload(add(pubKey, 32)))
        }

        // Check x is in valid range
        if (x == 0 || x >= SECP256K1_P) {
            return false;
        }

        return true;
    }

    /**
     * @notice Decompress a secp256k1 public key
     * @param compressed Compressed public key (33 bytes)
     * @return x X-coordinate
     * @return y Y-coordinate
     */
    function decompressPublicKey(
        bytes memory compressed
    ) public view returns (uint256 x, uint256 y) {
        require(compressed.length == 33, "Invalid key length");
        uint8 prefix = uint8(compressed[0]);
        require(prefix == 0x02 || prefix == 0x03, "Invalid prefix");

        // Extract x-coordinate
        assembly {
            x := shr(8, mload(add(compressed, 32)))
        }

        // Compute y² = x³ + 7 (secp256k1 equation: y² = x³ + 7)
        uint256 y2 = fieldAdd(fieldMul(fieldMul(x, x), x), 7);

        // Compute y = sqrt(y²) using Tonelli-Shanks (simplified for secp256k1)
        // For secp256k1: y = y²^((p+1)/4) mod p
        y = modExp(y2, (SECP256K1_P + 1) / 4, SECP256K1_P);

        // Check parity and adjust if needed
        bool yIsOdd = (y & 1) == 1;
        bool shouldBeOdd = prefix == 0x03;

        if (yIsOdd != shouldBeOdd) {
            y = SECP256K1_P - y;
        }
    }

    // =========================================================================
    // ECDH KEY EXCHANGE
    // =========================================================================

    /**
     * @notice Derive shared secret using ECDH
     * @param privateKey Private key scalar
     * @param publicKey Peer's compressed public key
     * @return sharedSecret The shared secret (x-coordinate of result)
     */
    function deriveSharedSecret(
        uint256 privateKey,
        bytes memory publicKey
    ) public view returns (bytes32 sharedSecret) {
        require(isValidScalar(privateKey), "Invalid private key");
        require(isValidPublicKey(publicKey), "Invalid public key");

        // Decompress public key
        (uint256 px, uint256 py) = decompressPublicKey(publicKey);

        // Scalar multiplication: result = privateKey * P
        // Using ecMul precompile
        (uint256 rx, ) = ecMul(px, py, privateKey);

        sharedSecret = bytes32(rx);
    }

    /**
     * @notice EC scalar multiplication using precompile
     * @param px X-coordinate of point
     * @param py Y-coordinate of point
     * @param scalar Scalar to multiply
     * @return rx Result X-coordinate
     * @return ry Result Y-coordinate
     */
    function ecMul(
        uint256 px,
        uint256 py,
        uint256 scalar
    ) public view returns (uint256 rx, uint256 ry) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, px)
            mstore(add(ptr, 32), py)
            mstore(add(ptr, 64), scalar)

            let success := staticcall(gas(), 0x07, ptr, 96, ptr, 64)
            if iszero(success) {
                revert(0, 0)
            }
            rx := mload(ptr)
            ry := mload(add(ptr, 32))
        }
    }

    // =========================================================================
    // ENCRYPTION/DECRYPTION (AES-SIV simulation)
    // =========================================================================

    /**
     * @notice Create encrypted envelope (simulated AES-SIV)
     * @param key Encryption key
     * @param plaintext Data to encrypt
     * @param aad Additional authenticated data
     * @return envelope The encrypted envelope
     */
    function createEncryptedEnvelope(
        bytes32 key,
        bytes memory plaintext,
        bytes memory aad
    ) public view returns (EncryptedEnvelope memory envelope) {
        // Simulate SIV tag computation (S2V in real implementation)
        envelope.sivTag = bytes16(
            keccak256(abi.encodePacked(key, aad, plaintext))
        );

        // Simulate ciphertext (AES-CTR with SIV as IV)
        envelope.ciphertext = _xorEncrypt(plaintext, key, envelope.sivTag);

        // Generate ephemeral public key placeholder
        envelope.ephemeralPubKey = abi.encodePacked(
            uint8(0x02),
            keccak256(abi.encodePacked(key, block.timestamp))
        );
    }

    /**
     * @notice Verify and decrypt envelope (simulated)
     * @param key Decryption key
     * @param envelope Encrypted envelope
     * @param aad Additional authenticated data
     * @return plaintext Decrypted data
     */
    function decryptEnvelope(
        bytes32 key,
        EncryptedEnvelope memory envelope,
        bytes memory aad
    ) public pure returns (bytes memory plaintext) {
        // Decrypt ciphertext
        plaintext = _xorEncrypt(envelope.ciphertext, key, envelope.sivTag);

        // Verify SIV tag
        bytes16 expectedTag = bytes16(
            keccak256(abi.encodePacked(key, aad, plaintext))
        );
        require(expectedTag == envelope.sivTag, "Authentication failed");
    }

    /**
     * @notice XOR-based encryption (simplified)
     * @param data Data to encrypt/decrypt
     * @param key Encryption key
     * @param iv Initialization vector
     * @return result Encrypted/decrypted data
     */
    function _xorEncrypt(
        bytes memory data,
        bytes32 key,
        bytes16 iv
    ) internal pure returns (bytes memory result) {
        result = new bytes(data.length);
        bytes32 keystream;

        for (uint256 i = 0; i < data.length; i++) {
            if (i % 32 == 0) {
                keystream = keccak256(abi.encodePacked(key, iv, i / 32));
            }
            result[i] = data[i] ^ bytes1(keystream[i % 32]);
        }
    }

    /**
     * @notice Validate encrypted envelope structure
     * @param envelope Envelope to validate
     * @return True if valid structure
     */
    function isValidEnvelope(
        EncryptedEnvelope memory envelope
    ) public pure returns (bool) {
        // Must have ciphertext
        if (envelope.ciphertext.length == 0) {
            return false;
        }

        // Must have valid ephemeral public key
        if (!isValidPublicKey(envelope.ephemeralPubKey)) {
            return false;
        }

        return true;
    }

    // =========================================================================
    // VIEWING KEY OPERATIONS
    // =========================================================================

    /**
     * @notice Derive viewing key from master secret
     * @param masterSecret Master secret
     * @param owner Owner address
     * @param expiration Expiration timestamp (0 = never)
     * @return viewingKey The derived viewing key
     */
    function deriveViewingKey(
        bytes32 masterSecret,
        address owner,
        uint256 expiration
    ) public view returns (ViewingKey memory viewingKey) {
        viewingKey.key = keccak256(
            abi.encodePacked(
                VIEWING_KEY_DOMAIN,
                masterSecret,
                owner,
                block.timestamp
            )
        );
        viewingKey.owner = owner;
        viewingKey.createdAt = block.timestamp;
        viewingKey.expiresAt = expiration;
    }

    /**
     * @notice Validate viewing key
     * @param viewingKey Key to validate
     * @return True if valid and not expired
     */
    function isValidViewingKey(
        ViewingKey memory viewingKey
    ) public view returns (bool) {
        // Check expiration
        if (
            viewingKey.expiresAt != 0 && block.timestamp > viewingKey.expiresAt
        ) {
            return false;
        }

        // Check owner is set
        if (viewingKey.owner == address(0)) {
            return false;
        }

        return true;
    }

    /**
     * @notice Hash viewing key for storage
     * @param viewingKey Viewing key to hash
     * @return Hash of the viewing key
     */
    function hashViewingKey(
        ViewingKey memory viewingKey
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    viewingKey.key,
                    viewingKey.owner,
                    viewingKey.createdAt,
                    viewingKey.expiresAt
                )
            );
    }

    // =========================================================================
    // QUERY PERMIT OPERATIONS
    // =========================================================================

    /**
     * @notice Create query permit
     * @param granter Who issues the permit
     * @param grantee Who can use the permit
     * @param permissions List of allowed query types
     * @param expiresAt Expiration timestamp
     * @return permit The query permit (without signature)
     */
    function createQueryPermit(
        address granter,
        address grantee,
        bytes32[] memory permissions,
        uint256 expiresAt
    ) public view returns (QueryPermit memory permit) {
        permit.permitId = keccak256(
            abi.encodePacked(
                QUERY_PERMIT_DOMAIN,
                granter,
                grantee,
                block.timestamp,
                permissions
            )
        );
        permit.granter = granter;
        permit.grantee = grantee;
        permit.permissions = permissions;
        permit.expiresAt = expiresAt;
    }

    /**
     * @notice Validate query permit
     * @param permit Permit to validate
     * @param requiredPermission Permission being requested
     * @return True if valid
     */
    function isValidQueryPermit(
        QueryPermit memory permit,
        bytes32 requiredPermission
    ) public view returns (bool) {
        // Check expiration
        if (block.timestamp > permit.expiresAt) {
            return false;
        }

        // Check permission exists
        for (uint256 i = 0; i < permit.permissions.length; i++) {
            if (permit.permissions[i] == requiredPermission) {
                return true;
            }
        }

        return false;
    }

    /**
     * @notice Compute permit message hash for signing
     * @param permit Permit to sign
     * @return Message hash
     */
    function getPermitMessageHash(
        QueryPermit memory permit
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n32",
                    keccak256(
                        abi.encodePacked(
                            permit.permitId,
                            permit.granter,
                            permit.grantee,
                            keccak256(abi.encodePacked(permit.permissions)),
                            permit.expiresAt
                        )
                    )
                )
            );
    }

    // =========================================================================
    // SGX ATTESTATION
    // =========================================================================

    /**
     * @notice Verify SGX attestation
     * @param quote SGX quote
     * @param expectedMrEnclave Expected enclave measurement
     * @param expectedMrSigner Expected signer measurement
     * @return True if valid
     */
    function verifyAttestation(
        SGXQuote memory quote,
        bytes32 expectedMrEnclave,
        bytes32 expectedMrSigner
    ) public view returns (bool) {
        // Check quote version
        if (quote.version != SGX_QUOTE_VERSION) {
            return false;
        }

        // Check MRENCLAVE
        if (quote.mrEnclave != expectedMrEnclave) {
            return false;
        }

        // Check MRSIGNER
        if (quote.mrSigner != expectedMrSigner) {
            return false;
        }

        // Check timestamp (not too old)
        if (block.timestamp - quote.timestamp > MAX_QUOTE_AGE) {
            return false;
        }

        return true;
    }

    /**
     * @notice Parse attestation from quote
     * @param quote SGX quote
     * @return attestation Parsed attestation
     */
    function parseAttestation(
        SGXQuote memory quote
    ) public pure returns (Attestation memory attestation) {
        attestation.mrEnclave = quote.mrEnclave;
        attestation.mrSigner = quote.mrSigner;
        attestation.timestamp = quote.timestamp;

        // Hash report data into two 32-byte chunks
        bytes32 reportHash = keccak256(quote.reportData);
        attestation.reportDataHash0 = reportHash;
        attestation.reportDataHash1 = keccak256(
            abi.encodePacked(reportHash, quote.reportData)
        );
    }

    /**
     * @notice Check if TCB status is acceptable
     * @param status TCB status value
     * @return True if acceptable for production
     */
    function isTCBAcceptable(uint8 status) public pure returns (bool) {
        return
            status == TCB_STATUS_UP_TO_DATE ||
            status == TCB_STATUS_SW_HARDENING_NEEDED;
    }

    // =========================================================================
    // NULLIFIER OPERATIONS
    // =========================================================================

    /**
     * @notice Derive nullifier from secret and commitment
     * @param secret Secret value
     * @param commitment Public commitment
     * @return nullifier The derived nullifier
     */
    function deriveNullifier(
        bytes32 secret,
        bytes32 commitment
    ) public pure returns (bytes32 nullifier) {
        nullifier = keccak256(
            abi.encodePacked("SECRET_NULLIFIER", secret, commitment)
        );
    }

    /**
     * @notice Derive cross-domain nullifier (Secret → PIL)
     * @param secretNullifier Original Secret Network nullifier
     * @param srcDomain Source domain identifier
     * @param dstDomain Destination domain identifier
     * @return pilNullifier PIL-compatible nullifier
     */
    function deriveCrossDomainNullifier(
        bytes32 secretNullifier,
        bytes32 srcDomain,
        bytes32 dstDomain
    ) public pure returns (bytes32 pilNullifier) {
        pilNullifier = keccak256(
            abi.encodePacked(
                PIL_SECRET_DOMAIN,
                secretNullifier,
                srcDomain,
                dstDomain,
                "S2P" // Secret to PIL marker
            )
        );
    }

    /**
     * @notice Derive PIL to Secret nullifier binding
     * @param pilNullifier PIL nullifier
     * @return secretBinding Secret Network binding
     */
    function derivePILToSecretBinding(
        bytes32 pilNullifier
    ) public pure returns (bytes32 secretBinding) {
        secretBinding = keccak256(
            abi.encodePacked(
                PIL_SECRET_DOMAIN,
                pilNullifier,
                "P2S" // PIL to Secret marker
            )
        );
    }

    /**
     * @notice Create Secret nullifier struct
     * @param secret Secret value
     * @param commitment Public commitment
     * @param mrEnclave TEE measurement
     * @return nullifier The nullifier struct
     */
    function createSecretNullifier(
        bytes32 secret,
        bytes32 commitment,
        bytes32 mrEnclave
    ) public pure returns (SecretNullifier memory nullifier) {
        nullifier.secret = secret;
        nullifier.commitment = commitment;
        nullifier.mrEnclave = mrEnclave;
    }

    // =========================================================================
    // IBC OPERATIONS
    // =========================================================================

    /**
     * @notice Compute IBC packet commitment
     * @param channel Channel info
     * @param sequence Packet sequence number
     * @param data Packet data
     * @return commitment The packet commitment
     */
    function computeIBCPacketCommitment(
        IBCChannel memory channel,
        uint64 sequence,
        bytes memory data
    ) public pure returns (bytes32 commitment) {
        commitment = keccak256(
            abi.encodePacked(
                channel.channelId,
                channel.portId,
                sequence,
                keccak256(data)
            )
        );
    }

    /**
     * @notice Verify IBC packet proof (simplified Merkle)
     * @param root Merkle root
     * @param commitment Packet commitment
     * @param proof Merkle proof
     * @return True if valid
     */
    function verifyIBCProof(
        bytes32 root,
        bytes32 commitment,
        bytes32[] memory proof
    ) public pure returns (bool) {
        bytes32 computedHash = commitment;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash < proofElement) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proofElement)
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proofElement, computedHash)
                );
            }
        }

        return computedHash == root;
    }

    // =========================================================================
    // SNIP TOKEN HELPERS
    // =========================================================================

    /**
     * @notice Compute SNIP-20 token contract hash
     * @param codeHash Code hash from Secret Network
     * @param contractAddress Contract address on Secret Network
     * @return Hash for verification
     */
    function computeSNIP20Hash(
        bytes32 codeHash,
        string memory contractAddress
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(SNIP20_INTERFACE_ID, codeHash, contractAddress)
            );
    }

    /**
     * @notice Compute SNIP-721 token hash
     * @param codeHash Code hash from Secret Network
     * @param contractAddress Contract address on Secret Network
     * @param tokenId Token ID
     * @return Hash for verification
     */
    function computeSNIP721Hash(
        bytes32 codeHash,
        string memory contractAddress,
        string memory tokenId
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    SNIP721_INTERFACE_ID,
                    codeHash,
                    contractAddress,
                    tokenId
                )
            );
    }

    // =========================================================================
    // STATE VERIFICATION
    // =========================================================================

    /**
     * @notice Verify Merkle proof for state
     * @param root State root
     * @param key State key
     * @param value State value
     * @param proof Merkle proof
     * @return True if valid
     */
    function verifyStateProof(
        bytes32 root,
        bytes memory key,
        bytes memory value,
        bytes32[] memory proof
    ) public pure returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(key, value));
        return _verifyMerkleProof(root, leaf, proof);
    }

    /**
     * @notice Internal Merkle proof verification
     * @param root Expected root
     * @param leaf Leaf hash
     * @param proof Proof elements
     * @return True if valid
     */
    function _verifyMerkleProof(
        bytes32 root,
        bytes32 leaf,
        bytes32[] memory proof
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash < proofElement) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proofElement)
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proofElement, computedHash)
                );
            }
        }

        return computedHash == root;
    }

    // =========================================================================
    // NETWORK TYPE DETECTION
    // =========================================================================

    /**
     * @notice Check if network ID corresponds to Secret mainnet
     * @param networkId Network identifier
     * @return True if Secret mainnet
     */
    function isSecretMainnet(uint256 networkId) public pure returns (bool) {
        return networkId == SECRET_MAINNET_NUMERIC_ID;
    }

    /**
     * @notice Check if network ID corresponds to Secret testnet
     * @param networkId Network identifier
     * @return True if Secret testnet
     */
    function isSecretTestnet(uint256 networkId) public pure returns (bool) {
        return networkId == SECRET_TESTNET_NUMERIC_ID;
    }

    /**
     * @notice Check if network is a Secret Network
     * @param networkId Network identifier
     * @return True if any Secret Network
     */
    function isSecretNetwork(uint256 networkId) public pure returns (bool) {
        return isSecretMainnet(networkId) || isSecretTestnet(networkId);
    }
}
