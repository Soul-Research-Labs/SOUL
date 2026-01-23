// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title OasisPrimitives
 * @author PIL Protocol
 * @notice Cryptographic primitives for Oasis Network integration
 *
 * @dev Oasis Network Cryptographic Stack:
 *
 * Key Exchange: x25519 (Curve25519 for ECDH)
 * Encryption: Deoxys-II-256-128 (MRAE - Misuse-Resistant Authenticated Encryption)
 * Attestation: Intel SGX Remote Attestation (DCAP/EPID)
 * Hashing: SHA-512/256 for key derivation
 *
 * Oasis Network Architecture:
 * - Consensus Layer: Tendermint-based BFT consensus
 * - ParaTimes: Parallel execution environments
 *   - Sapphire: EVM-compatible confidential smart contracts
 *   - Cipher: WASM-based confidential compute
 *   - Emerald: Non-confidential EVM
 *
 * TEE Integration:
 * - Intel SGX enclaves for confidential execution
 * - Remote attestation proves code integrity
 * - Key management via MRSIGNER/MRENCLAVE
 *
 * Confidentiality Model:
 * - State encryption at rest (Deoxys-II)
 * - Encrypted transaction calldata
 * - View keys for selective disclosure
 */
contract OasisPrimitives {
    // =========================================================================
    // CURVE25519 CONSTANTS (x25519 ECDH)
    // =========================================================================

    /// @notice Curve25519 prime (2^255 - 19)
    uint256 public constant CURVE25519_PRIME =
        57896044618658097711785492504343953926634992332820282019728792003956564819949;

    /// @notice Curve25519 order (for scalar operations)
    uint256 public constant CURVE25519_ORDER =
        7237005577332262213973186563042994240857116359379907606001950938285454250989;

    /// @notice Curve25519 cofactor
    uint8 public constant CURVE25519_COFACTOR = 8;

    /// @notice Curve25519 A parameter (A = 486662)
    uint256 public constant CURVE25519_A = 486662;

    /// @notice Basepoint u-coordinate (9)
    uint256 public constant CURVE25519_BASEPOINT_U = 9;

    // =========================================================================
    // DEOXYS-II CONSTANTS
    // =========================================================================

    /// @notice Deoxys-II block size (128 bits = 16 bytes)
    uint8 public constant DEOXYS_BLOCK_SIZE = 16;

    /// @notice Deoxys-II key size (256 bits = 32 bytes)
    uint8 public constant DEOXYS_KEY_SIZE = 32;

    /// @notice Deoxys-II nonce size (120 bits = 15 bytes)
    uint8 public constant DEOXYS_NONCE_SIZE = 15;

    /// @notice Deoxys-II tag size (128 bits = 16 bytes)
    uint8 public constant DEOXYS_TAG_SIZE = 16;

    // =========================================================================
    // OASIS NETWORK CONSTANTS
    // =========================================================================

    /// @notice Sapphire ParaTime chain ID
    uint256 public constant SAPPHIRE_MAINNET_CHAIN_ID = 23294;
    uint256 public constant SAPPHIRE_TESTNET_CHAIN_ID = 23295;

    /// @notice Emerald ParaTime chain ID
    uint256 public constant EMERALD_MAINNET_CHAIN_ID = 42262;
    uint256 public constant EMERALD_TESTNET_CHAIN_ID = 42261;

    /// @notice Domain separator for PIL-Oasis binding
    bytes32 public constant PIL_OASIS_DOMAIN =
        keccak256("PIL_Oasis_Interop_v1");

    /// @notice Domain for confidential state encryption
    bytes32 public constant CONFIDENTIAL_STATE_DOMAIN =
        keccak256("OASIS_CONFIDENTIAL_STATE");

    /// @notice Domain for view key derivation
    bytes32 public constant VIEW_KEY_DOMAIN = keccak256("OASIS_VIEW_KEY");

    // =========================================================================
    // SGX ATTESTATION CONSTANTS
    // =========================================================================

    /// @notice Intel SGX quote version (DCAP v3)
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
    // TYPE DEFINITIONS
    // =========================================================================

    /// @notice x25519 public key (32 bytes)
    struct X25519PublicKey {
        bytes32 key;
    }

    /// @notice Encrypted data envelope (Deoxys-II)
    struct EncryptedEnvelope {
        bytes15 nonce; // 120-bit nonce
        bytes ciphertext; // Encrypted data
        bytes16 tag; // Authentication tag
        bytes32 ephemeralPubKey; // Sender's ephemeral x25519 public key
    }

    /// @notice SGX Report Body
    struct SGXReportBody {
        bytes16 cpuSvn; // CPU security version
        uint32 miscSelect; // Misc select flags
        bytes28 reserved1;
        bytes16 attributes; // Enclave attributes
        bytes32 mrEnclave; // Measurement of enclave code
        bytes32 reserved2;
        bytes32 mrSigner; // Measurement of enclave signer
        bytes reserved3; // Reserved (96 bytes, variable for gas)
        uint16 isvProdId; // ISV product ID
        uint16 isvSvn; // ISV security version
        bytes reserved4; // Reserved (60 bytes, variable)
        bytes reportData; // User-defined data (64 bytes)
    }

    /// @notice SGX Quote (DCAP attestation)
    struct SGXQuote {
        uint16 version;
        uint16 attestationKeyType;
        bytes4 reserved;
        uint16 qeSvn;
        uint16 pceSvn;
        bytes16 qeVendorId;
        bytes20 userData;
        SGXReportBody reportBody;
        uint32 signatureDataLen;
        bytes signatureData; // ECDSA signature over quote
    }

    /// @notice TEE Attestation Result
    struct AttestationResult {
        bool valid;
        bytes32 mrEnclave;
        bytes32 mrSigner;
        bytes32 reportDataHash;
        uint256 attestationTime;
        uint8 tcbStatus;
    }

    /// @notice Confidential Transaction
    struct ConfidentialTx {
        bytes32 txHash;
        EncryptedEnvelope encryptedCalldata;
        bytes32 stateCommitment; // Commitment to post-execution state
        bytes32 nullifier; // Privacy nullifier
    }

    /// @notice View Key for selective disclosure
    struct ViewKey {
        bytes32 key;
        uint256 validFrom;
        uint256 validUntil;
        bytes32 scope; // What data this key can view
    }

    /// @notice ParaTime State Proof
    struct ParaTimeStateProof {
        uint64 round; // ParaTime round number
        bytes32 stateRoot; // Merkle root of state
        bytes32[] proof; // Merkle proof
        bytes32 ioRoot; // I/O Merkle root
        bytes signature; // Committee signature
    }

    /// @notice Cross-chain message from Oasis
    struct OasisMessage {
        uint256 sourceParaTime; // Source ParaTime ID
        uint256 destinationChain; // Destination chain ID
        bytes32 sender; // Sender address (as bytes32)
        bytes32 recipient; // Recipient address
        bytes payload; // Message payload
        uint64 nonce; // Message nonce
        bytes32 stateProofHash; // Hash of state proof
    }

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidPublicKey();
    error InvalidNonce();
    error InvalidTag();
    error DecryptionFailed();
    error AttestationExpired();
    error InvalidQuote();
    error InvalidMREnclave();
    error InvalidMRSigner();
    error TCBNotUpToDate();
    error InvalidStateProof();
    error InvalidSignature();
    error NullifierAlreadyUsed();
    error InvalidViewKey();

    // =========================================================================
    // EVENTS
    // =========================================================================

    event EncryptionKeyGenerated(
        bytes32 indexed publicKeyHash,
        uint256 timestamp
    );
    event AttestationVerified(
        bytes32 indexed mrEnclave,
        bytes32 indexed mrSigner,
        uint8 tcbStatus
    );
    event ConfidentialTxProcessed(
        bytes32 indexed txHash,
        bytes32 indexed nullifier
    );
    event ViewKeyIssued(
        bytes32 indexed keyHash,
        bytes32 indexed scope,
        uint256 validUntil
    );
    event StateProofVerified(uint64 indexed round, bytes32 stateRoot);

    // =========================================================================
    // X25519 KEY EXCHANGE
    // =========================================================================

    /**
     * @notice Validate x25519 public key
     * @param pubKey The public key to validate
     * @return valid True if key is valid
     */
    function isValidX25519PublicKey(
        bytes32 pubKey
    ) public pure returns (bool valid) {
        // x25519 accepts any 32-byte value, but we check for common invalid values
        // Key should not be zero or low-order points
        if (pubKey == bytes32(0)) {
            return false;
        }

        // Check for low-order points (cofactor clearing handles most cases)
        // These are the small-order points that should be rejected
        // Point at u=0
        if (pubKey == bytes32(uint256(0))) {
            return false;
        }
        // Point at u=1
        if (pubKey == bytes32(uint256(1))) {
            return false;
        }
        // Small order point (order 8)
        if (uint256(pubKey) == 0x80) {
            return false;
        }

        return true;
    }

    /**
     * @notice Derive shared secret using x25519 ECDH
     * @dev In production, this would be done off-chain in a TEE
     * @param privateKey The private scalar
     * @param publicKey The peer's public key
     * @return sharedSecret The derived shared secret
     */
    function x25519DeriveSharedSecret(
        bytes32 privateKey,
        bytes32 publicKey
    ) public pure returns (bytes32 sharedSecret) {
        if (!isValidX25519PublicKey(publicKey)) {
            revert InvalidPublicKey();
        }

        // Montgomery ladder scalar multiplication (simplified)
        // Real implementation would use constant-time operations
        uint256 scalar = uint256(privateKey);
        uint256 u = uint256(publicKey);

        // Clamp scalar per RFC 7748
        scalar &= ~uint256(7); // Clear lowest 3 bits
        scalar &= ~(uint256(128) << 248); // Clear bit 255
        scalar |= uint256(64) << 248; // Set bit 254

        // Simplified scalar multiplication (for demonstration)
        // Production would use proper Montgomery ladder
        sharedSecret = keccak256(abi.encodePacked(scalar, u, "x25519"));
    }

    /**
     * @notice Derive encryption key from shared secret
     * @param sharedSecret The x25519 shared secret
     * @param context Additional context for key derivation
     * @return encryptionKey The derived Deoxys-II key
     */
    function deriveEncryptionKey(
        bytes32 sharedSecret,
        bytes memory context
    ) public pure returns (bytes32 encryptionKey) {
        // HKDF-SHA256 expand (simplified)
        encryptionKey = keccak256(
            abi.encodePacked(sharedSecret, context, CONFIDENTIAL_STATE_DOMAIN)
        );
    }

    // =========================================================================
    // DEOXYS-II ENCRYPTION (MRAE)
    // =========================================================================

    /**
     * @notice Create authenticated encryption envelope
     * @dev Deoxys-II-256-128 is MRAE (Misuse-Resistant Authenticated Encryption)
     * @param key The encryption key
     * @param nonce The nonce (must be unique per key)
     * @param plaintext The data to encrypt
     * @param associatedData Additional authenticated data
     * @return envelope The encrypted envelope
     */
    function createEncryptedEnvelope(
        bytes32 key,
        bytes15 nonce,
        bytes memory plaintext,
        bytes memory associatedData
    ) public pure returns (EncryptedEnvelope memory envelope) {
        // Simplified - actual Deoxys-II would use AES-based tweakable block cipher
        // This is a placeholder for the encryption operation

        envelope.nonce = nonce;

        // Derive ciphertext (XOR with keystream for demo)
        bytes memory ciphertext = new bytes(plaintext.length);
        bytes32 keystream = keccak256(abi.encodePacked(key, nonce, uint256(0)));

        for (uint256 i = 0; i < plaintext.length; i++) {
            if (i > 0 && i % 32 == 0) {
                keystream = keccak256(abi.encodePacked(key, nonce, i / 32));
            }
            ciphertext[i] = plaintext[i] ^ keystream[i % 32];
        }

        envelope.ciphertext = ciphertext;

        // Compute authentication tag
        envelope.tag = bytes16(
            keccak256(abi.encodePacked(key, nonce, associatedData, ciphertext))
        );

        return envelope;
    }

    /**
     * @notice Verify authentication tag
     * @param key The encryption key
     * @param envelope The encrypted envelope
     * @param associatedData Additional authenticated data
     * @return valid True if tag is valid
     */
    function verifyAuthTag(
        bytes32 key,
        EncryptedEnvelope memory envelope,
        bytes memory associatedData
    ) public pure returns (bool valid) {
        bytes16 expectedTag = bytes16(
            keccak256(
                abi.encodePacked(
                    key,
                    envelope.nonce,
                    associatedData,
                    envelope.ciphertext
                )
            )
        );

        return envelope.tag == expectedTag;
    }

    /**
     * @notice Decrypt envelope (requires tag verification first)
     * @param key The encryption key
     * @param envelope The encrypted envelope
     * @return plaintext The decrypted data
     */
    function decryptEnvelope(
        bytes32 key,
        EncryptedEnvelope memory envelope
    ) public pure returns (bytes memory plaintext) {
        plaintext = new bytes(envelope.ciphertext.length);
        bytes32 keystream = keccak256(
            abi.encodePacked(key, envelope.nonce, uint256(0))
        );

        for (uint256 i = 0; i < envelope.ciphertext.length; i++) {
            if (i > 0 && i % 32 == 0) {
                keystream = keccak256(
                    abi.encodePacked(key, envelope.nonce, i / 32)
                );
            }
            plaintext[i] = envelope.ciphertext[i] ^ keystream[i % 32];
        }

        return plaintext;
    }

    // =========================================================================
    // SGX ATTESTATION
    // =========================================================================

    /**
     * @notice Verify SGX quote (DCAP attestation)
     * @param quote The SGX quote to verify
     * @param expectedMREnclave Expected MRENCLAVE value
     * @param expectedMRSigner Expected MRSIGNER value
     * @return result The attestation verification result
     */
    function verifyAttestation(
        SGXQuote memory quote,
        bytes32 expectedMREnclave,
        bytes32 expectedMRSigner
    ) public view returns (AttestationResult memory result) {
        // Verify quote version
        if (quote.version != SGX_QUOTE_VERSION) {
            revert InvalidQuote();
        }

        // Verify MRENCLAVE (code measurement)
        if (
            expectedMREnclave != bytes32(0) &&
            quote.reportBody.mrEnclave != expectedMREnclave
        ) {
            revert InvalidMREnclave();
        }

        // Verify MRSIGNER (signer measurement)
        if (
            expectedMRSigner != bytes32(0) &&
            quote.reportBody.mrSigner != expectedMRSigner
        ) {
            revert InvalidMRSigner();
        }

        // Build result
        result.valid = true;
        result.mrEnclave = quote.reportBody.mrEnclave;
        result.mrSigner = quote.reportBody.mrSigner;
        result.reportDataHash = keccak256(
            abi.encodePacked(quote.reportBody.reportData)
        );
        result.attestationTime = block.timestamp;
        result.tcbStatus = TCB_STATUS_UP_TO_DATE; // Simplified - would check PCK cert chain

        return result;
    }

    /**
     * @notice Hash report data for binding
     * @param data The data to bind to attestation
     * @return hash0 First 32 bytes of report data hash
     * @return hash1 Second 32 bytes of report data hash
     */
    function hashReportData(
        bytes memory data
    ) public pure returns (bytes32 hash0, bytes32 hash1) {
        hash0 = keccak256(data);
        hash1 = keccak256(abi.encodePacked(hash0));
    }

    /**
     * @notice Verify TCB status is acceptable
     * @param status The TCB status to check
     * @return acceptable True if TCB status is acceptable
     */
    function isTCBStatusAcceptable(
        uint8 status
    ) public pure returns (bool acceptable) {
        return
            status == TCB_STATUS_UP_TO_DATE ||
            status == TCB_STATUS_SW_HARDENING_NEEDED;
    }

    // =========================================================================
    // NULLIFIER OPERATIONS
    // =========================================================================

    /**
     * @notice Derive nullifier from confidential state
     * @param stateCommitment The state commitment
     * @param secretKey The secret key (from TEE)
     * @return nullifier The derived nullifier
     */
    function deriveNullifier(
        bytes32 stateCommitment,
        bytes32 secretKey
    ) public pure returns (bytes32 nullifier) {
        nullifier = keccak256(
            abi.encodePacked(
                PIL_OASIS_DOMAIN,
                stateCommitment,
                secretKey,
                "NULLIFIER"
            )
        );
    }

    /**
     * @notice Derive cross-domain nullifier for PIL binding
     * @param oasisNullifier The Oasis-native nullifier
     * @param destinationChainId The target chain ID
     * @return pilNullifier The PIL-compatible nullifier
     */
    function deriveCrossDomainNullifier(
        bytes32 oasisNullifier,
        uint256 destinationChainId
    ) public pure returns (bytes32 pilNullifier) {
        pilNullifier = keccak256(
            abi.encodePacked(
                PIL_OASIS_DOMAIN,
                oasisNullifier,
                destinationChainId,
                "CROSS_DOMAIN"
            )
        );
    }

    // =========================================================================
    // VIEW KEY OPERATIONS
    // =========================================================================

    /**
     * @notice Derive view key for selective disclosure
     * @param masterKey The master secret key
     * @param scope The scope of data this key can view
     * @param validUntil Expiry timestamp
     * @return viewKey The derived view key
     */
    function deriveViewKey(
        bytes32 masterKey,
        bytes32 scope,
        uint256 validUntil
    ) public pure returns (ViewKey memory viewKey) {
        viewKey.key = keccak256(
            abi.encodePacked(VIEW_KEY_DOMAIN, masterKey, scope, validUntil)
        );
        viewKey.validFrom = 0; // Can be set by caller
        viewKey.validUntil = validUntil;
        viewKey.scope = scope;
    }

    /**
     * @notice Verify view key is valid for given scope
     * @param viewKey The view key to verify
     * @param scope The scope to check
     * @param timestamp Current timestamp
     * @return valid True if view key is valid
     */
    function isViewKeyValid(
        ViewKey memory viewKey,
        bytes32 scope,
        uint256 timestamp
    ) public pure returns (bool valid) {
        if (viewKey.scope != scope) {
            return false;
        }
        if (viewKey.validFrom > timestamp) {
            return false;
        }
        if (viewKey.validUntil != 0 && viewKey.validUntil < timestamp) {
            return false;
        }
        return true;
    }

    // =========================================================================
    // PARATIME STATE VERIFICATION
    // =========================================================================

    /**
     * @notice Verify ParaTime state proof
     * @param proof The state proof from Oasis
     * @param key The storage key
     * @param value The expected value
     * @return valid True if proof is valid
     */
    function verifyStateProof(
        ParaTimeStateProof memory proof,
        bytes32 key,
        bytes32 value
    ) public pure returns (bool valid) {
        // Verify Merkle proof
        bytes32 leaf = keccak256(abi.encodePacked(key, value));
        bytes32 computedRoot = leaf;

        for (uint256 i = 0; i < proof.proof.length; i++) {
            bytes32 proofElement = proof.proof[i];
            if (computedRoot <= proofElement) {
                computedRoot = keccak256(
                    abi.encodePacked(computedRoot, proofElement)
                );
            } else {
                computedRoot = keccak256(
                    abi.encodePacked(proofElement, computedRoot)
                );
            }
        }

        return computedRoot == proof.stateRoot;
    }

    /**
     * @notice Compute state commitment
     * @param stateRoot The state Merkle root
     * @param ioRoot The I/O Merkle root
     * @param round The ParaTime round
     * @return commitment The state commitment
     */
    function computeStateCommitment(
        bytes32 stateRoot,
        bytes32 ioRoot,
        uint64 round
    ) public pure returns (bytes32 commitment) {
        commitment = keccak256(abi.encodePacked(stateRoot, ioRoot, round));
    }

    // =========================================================================
    // MESSAGE HASHING
    // =========================================================================

    /**
     * @notice Hash Oasis cross-chain message
     * @param message The message to hash
     * @return messageHash The message hash
     */
    function hashOasisMessage(
        OasisMessage memory message
    ) public pure returns (bytes32 messageHash) {
        messageHash = keccak256(
            abi.encodePacked(
                PIL_OASIS_DOMAIN,
                message.sourceParaTime,
                message.destinationChain,
                message.sender,
                message.recipient,
                keccak256(message.payload),
                message.nonce,
                message.stateProofHash
            )
        );
    }

    /**
     * @notice Verify message signature from ParaTime committee
     * @param messageHash The message hash
     * @param signature The aggregate signature
     * @param committeeThreshold Minimum signatures required
     * @return valid True if signature is valid
     */
    function verifyCommitteeSignature(
        bytes32 messageHash,
        bytes memory signature,
        uint256 committeeThreshold
    ) public pure returns (bool valid) {
        // Simplified - would verify threshold BLS signature
        // Real implementation checks aggregate signature from committee members
        if (signature.length < 64) {
            return false;
        }

        // Placeholder verification
        bytes32 sigHash = keccak256(signature);
        return sigHash != bytes32(0) && committeeThreshold > 0;
    }

    // =========================================================================
    // UTILITY FUNCTIONS
    // =========================================================================

    /**
     * @notice Check if value is valid scalar for Curve25519
     * @param scalar The scalar value to check
     * @return valid True if scalar is in valid range
     */
    function isValidScalar(uint256 scalar) public pure returns (bool valid) {
        return scalar > 0 && scalar < CURVE25519_ORDER;
    }

    /**
     * @notice Reduce scalar modulo curve order
     * @param scalar The scalar to reduce
     * @return reduced The reduced scalar
     */
    function reduceScalar(
        uint256 scalar
    ) public pure returns (uint256 reduced) {
        reduced = scalar % CURVE25519_ORDER;
    }

    /**
     * @notice Clamp scalar per RFC 7748
     * @param scalar The scalar to clamp
     * @return clamped The clamped scalar
     */
    function clampScalar(bytes32 scalar) public pure returns (bytes32 clamped) {
        uint256 s = uint256(scalar);
        s &= ~uint256(7); // Clear lowest 3 bits
        s &= ~(uint256(128) << 248); // Clear bit 255
        s |= uint256(64) << 248; // Set bit 254
        clamped = bytes32(s);
    }

    /**
     * @notice Check if ParaTime is confidential
     * @param chainId The chain ID to check
     * @return confidential True if ParaTime supports confidential contracts
     */
    function isConfidentialParaTime(
        uint256 chainId
    ) public pure returns (bool confidential) {
        return
            chainId == SAPPHIRE_MAINNET_CHAIN_ID ||
            chainId == SAPPHIRE_TESTNET_CHAIN_ID;
    }

    /**
     * @notice Get ParaTime type from chain ID
     * @param chainId The chain ID
     * @return paraTimeType 0 = Unknown, 1 = Sapphire, 2 = Emerald, 3 = Cipher
     */
    function getParaTimeType(
        uint256 chainId
    ) public pure returns (uint8 paraTimeType) {
        if (
            chainId == SAPPHIRE_MAINNET_CHAIN_ID ||
            chainId == SAPPHIRE_TESTNET_CHAIN_ID
        ) {
            return 1; // Sapphire
        } else if (
            chainId == EMERALD_MAINNET_CHAIN_ID ||
            chainId == EMERALD_TESTNET_CHAIN_ID
        ) {
            return 2; // Emerald
        }
        return 0; // Unknown
    }
}
