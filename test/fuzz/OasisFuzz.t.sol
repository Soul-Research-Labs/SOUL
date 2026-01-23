// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/oasis/OasisPrimitives.sol";

/**
 * @title OasisFuzz
 * @author PIL Protocol
 * @notice Fuzz tests for Oasis Network cryptographic primitives
 */
contract OasisFuzz is Test {
    OasisPrimitives public primitives;

    function setUp() public {
        primitives = new OasisPrimitives();
    }

    // =========================================================================
    // X25519 KEY EXCHANGE FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: valid x25519 public keys are accepted
     */
    function testFuzz_ValidX25519PublicKey(bytes32 pubKey) public view {
        // Non-zero, non-low-order keys should be valid
        vm.assume(pubKey != bytes32(0));
        vm.assume(pubKey != bytes32(uint256(1)));
        vm.assume(uint256(pubKey) != 0x80);

        bool valid = primitives.isValidX25519PublicKey(pubKey);
        assertTrue(valid, "Non-trivial key should be valid");
    }

    /**
     * @notice Fuzz test: zero key is rejected
     */
    function testFuzz_ZeroX25519KeyRejected() public view {
        bool valid = primitives.isValidX25519PublicKey(bytes32(0));
        assertFalse(valid, "Zero key should be invalid");
    }

    /**
     * @notice Fuzz test: key at u=1 is rejected
     */
    function testFuzz_LowOrderPointRejected() public view {
        bool valid = primitives.isValidX25519PublicKey(bytes32(uint256(1)));
        assertFalse(valid, "Low order point should be invalid");
    }

    /**
     * @notice Fuzz test: small order point (0x80) is rejected
     */
    function testFuzz_SmallOrderPointRejected() public view {
        bool valid = primitives.isValidX25519PublicKey(bytes32(uint256(0x80)));
        assertFalse(valid, "Small order point should be invalid");
    }

    /**
     * @notice Fuzz test: shared secret derivation is deterministic
     */
    function testFuzz_SharedSecretDeterministic(
        bytes32 privateKey,
        bytes32 publicKey
    ) public view {
        vm.assume(publicKey != bytes32(0));
        vm.assume(publicKey != bytes32(uint256(1)));
        vm.assume(uint256(publicKey) != 0x80);

        bytes32 secret1 = primitives.x25519DeriveSharedSecret(
            privateKey,
            publicKey
        );
        bytes32 secret2 = primitives.x25519DeriveSharedSecret(
            privateKey,
            publicKey
        );

        assertEq(secret1, secret2, "Shared secret should be deterministic");
    }

    /**
     * @notice Fuzz test: different keys produce different secrets
     */
    function testFuzz_DifferentKeysDifferentSecrets(
        bytes32 privateKey,
        bytes32 publicKey1,
        bytes32 publicKey2
    ) public view {
        vm.assume(publicKey1 != bytes32(0));
        vm.assume(publicKey2 != bytes32(0));
        vm.assume(publicKey1 != bytes32(uint256(1)));
        vm.assume(publicKey2 != bytes32(uint256(1)));
        vm.assume(uint256(publicKey1) != 0x80);
        vm.assume(uint256(publicKey2) != 0x80);
        vm.assume(publicKey1 != publicKey2);

        bytes32 secret1 = primitives.x25519DeriveSharedSecret(
            privateKey,
            publicKey1
        );
        bytes32 secret2 = primitives.x25519DeriveSharedSecret(
            privateKey,
            publicKey2
        );

        assertNotEq(
            secret1,
            secret2,
            "Different keys should produce different secrets"
        );
    }

    /**
     * @notice Fuzz test: encryption key derivation is deterministic
     */
    function testFuzz_EncryptionKeyDeterministic(
        bytes32 sharedSecret,
        bytes memory context
    ) public view {
        bytes32 key1 = primitives.deriveEncryptionKey(sharedSecret, context);
        bytes32 key2 = primitives.deriveEncryptionKey(sharedSecret, context);

        assertEq(
            key1,
            key2,
            "Encryption key derivation should be deterministic"
        );
    }

    /**
     * @notice Fuzz test: different contexts produce different keys
     */
    function testFuzz_DifferentContextsDifferentKeys(
        bytes32 sharedSecret,
        bytes memory context1,
        bytes memory context2
    ) public view {
        vm.assume(keccak256(context1) != keccak256(context2));

        bytes32 key1 = primitives.deriveEncryptionKey(sharedSecret, context1);
        bytes32 key2 = primitives.deriveEncryptionKey(sharedSecret, context2);

        assertNotEq(
            key1,
            key2,
            "Different contexts should produce different keys"
        );
    }

    // =========================================================================
    // DEOXYS-II ENCRYPTION FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: encryption-decryption roundtrip
     */
    function testFuzz_EncryptDecryptRoundtrip(
        bytes32 key,
        bytes15 nonce,
        bytes memory plaintext,
        bytes memory associatedData
    ) public view {
        vm.assume(plaintext.length > 0);
        vm.assume(plaintext.length < 1024); // Limit for gas

        OasisPrimitives.EncryptedEnvelope memory envelope = primitives
            .createEncryptedEnvelope(key, nonce, plaintext, associatedData);

        // Verify tag
        bool tagValid = primitives.verifyAuthTag(key, envelope, associatedData);
        assertTrue(tagValid, "Tag should be valid");

        // Decrypt
        bytes memory decrypted = primitives.decryptEnvelope(key, envelope);
        assertEq(decrypted, plaintext, "Decrypted should match plaintext");
    }

    /**
     * @notice Fuzz test: wrong key fails tag verification
     */
    function testFuzz_WrongKeyFailsVerification(
        bytes32 key1,
        bytes32 key2,
        bytes15 nonce,
        bytes memory plaintext,
        bytes memory associatedData
    ) public view {
        vm.assume(key1 != key2);
        vm.assume(plaintext.length > 0);
        vm.assume(plaintext.length < 256);

        OasisPrimitives.EncryptedEnvelope memory envelope = primitives
            .createEncryptedEnvelope(key1, nonce, plaintext, associatedData);

        bool tagValid = primitives.verifyAuthTag(
            key2,
            envelope,
            associatedData
        );
        assertFalse(tagValid, "Wrong key should fail verification");
    }

    /**
     * @notice Fuzz test: modified ciphertext fails verification
     */
    function testFuzz_ModifiedCiphertextFails(
        bytes32 key,
        bytes15 nonce,
        bytes memory plaintext,
        bytes memory associatedData,
        uint8 modIndex
    ) public view {
        vm.assume(plaintext.length > 0);
        vm.assume(plaintext.length < 256);

        OasisPrimitives.EncryptedEnvelope memory envelope = primitives
            .createEncryptedEnvelope(key, nonce, plaintext, associatedData);

        // Modify ciphertext
        uint256 idx = modIndex % envelope.ciphertext.length;
        envelope.ciphertext[idx] = bytes1(
            uint8(envelope.ciphertext[idx]) ^ 0xFF
        );

        bool tagValid = primitives.verifyAuthTag(key, envelope, associatedData);
        assertFalse(tagValid, "Modified ciphertext should fail verification");
    }

    /**
     * @notice Fuzz test: modified associated data fails verification
     */
    function testFuzz_ModifiedAADFails(
        bytes32 key,
        bytes15 nonce,
        bytes memory plaintext,
        bytes memory aad1,
        bytes memory aad2
    ) public view {
        vm.assume(keccak256(aad1) != keccak256(aad2));
        vm.assume(plaintext.length > 0);
        vm.assume(plaintext.length < 256);

        OasisPrimitives.EncryptedEnvelope memory envelope = primitives
            .createEncryptedEnvelope(key, nonce, plaintext, aad1);

        bool tagValid = primitives.verifyAuthTag(key, envelope, aad2);
        assertFalse(tagValid, "Modified AAD should fail verification");
    }

    /**
     * @notice Fuzz test: empty plaintext encryption
     */
    function testFuzz_EmptyPlaintextEncryption(
        bytes32 key,
        bytes15 nonce,
        bytes memory associatedData
    ) public view {
        bytes memory empty = "";

        OasisPrimitives.EncryptedEnvelope memory envelope = primitives
            .createEncryptedEnvelope(key, nonce, empty, associatedData);

        assertEq(
            envelope.ciphertext.length,
            0,
            "Empty plaintext should produce empty ciphertext"
        );

        bool tagValid = primitives.verifyAuthTag(key, envelope, associatedData);
        assertTrue(tagValid, "Empty plaintext should have valid tag");
    }

    // =========================================================================
    // NULLIFIER FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: nullifier derivation is deterministic
     */
    function testFuzz_NullifierDeterministic(
        bytes32 stateCommitment,
        bytes32 secretKey
    ) public view {
        bytes32 nullifier1 = primitives.deriveNullifier(
            stateCommitment,
            secretKey
        );
        bytes32 nullifier2 = primitives.deriveNullifier(
            stateCommitment,
            secretKey
        );

        assertEq(nullifier1, nullifier2, "Nullifier should be deterministic");
    }

    /**
     * @notice Fuzz test: different inputs produce different nullifiers
     */
    function testFuzz_DifferentInputsDifferentNullifiers(
        bytes32 state1,
        bytes32 state2,
        bytes32 secretKey
    ) public view {
        vm.assume(state1 != state2);

        bytes32 nullifier1 = primitives.deriveNullifier(state1, secretKey);
        bytes32 nullifier2 = primitives.deriveNullifier(state2, secretKey);

        assertNotEq(
            nullifier1,
            nullifier2,
            "Different states should produce different nullifiers"
        );
    }

    /**
     * @notice Fuzz test: cross-domain nullifier derivation
     */
    function testFuzz_CrossDomainNullifier(
        bytes32 oasisNullifier,
        uint256 chainId
    ) public view {
        bytes32 pilNullifier = primitives.deriveCrossDomainNullifier(
            oasisNullifier,
            chainId
        );

        // Should be non-zero
        assertNotEq(
            pilNullifier,
            bytes32(0),
            "Cross-domain nullifier should be non-zero"
        );

        // Should be deterministic
        bytes32 pilNullifier2 = primitives.deriveCrossDomainNullifier(
            oasisNullifier,
            chainId
        );
        assertEq(
            pilNullifier,
            pilNullifier2,
            "Cross-domain nullifier should be deterministic"
        );
    }

    /**
     * @notice Fuzz test: different chains produce different nullifiers
     */
    function testFuzz_DifferentChainsDifferentNullifiers(
        bytes32 oasisNullifier,
        uint256 chainId1,
        uint256 chainId2
    ) public view {
        vm.assume(chainId1 != chainId2);

        bytes32 pilNullifier1 = primitives.deriveCrossDomainNullifier(
            oasisNullifier,
            chainId1
        );
        bytes32 pilNullifier2 = primitives.deriveCrossDomainNullifier(
            oasisNullifier,
            chainId2
        );

        assertNotEq(
            pilNullifier1,
            pilNullifier2,
            "Different chains should produce different nullifiers"
        );
    }

    // =========================================================================
    // VIEW KEY FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: view key derivation is deterministic
     */
    function testFuzz_ViewKeyDeterministic(
        bytes32 masterKey,
        bytes32 scope,
        uint256 validUntil
    ) public view {
        OasisPrimitives.ViewKey memory key1 = primitives.deriveViewKey(
            masterKey,
            scope,
            validUntil
        );
        OasisPrimitives.ViewKey memory key2 = primitives.deriveViewKey(
            masterKey,
            scope,
            validUntil
        );

        assertEq(key1.key, key2.key, "View key should be deterministic");
        assertEq(key1.scope, key2.scope, "View key scope should match");
        assertEq(
            key1.validUntil,
            key2.validUntil,
            "View key expiry should match"
        );
    }

    /**
     * @notice Fuzz test: view key valid within time range
     */
    function testFuzz_ViewKeyValidInRange(
        bytes32 masterKey,
        bytes32 scope,
        uint256 validUntil,
        uint256 timestamp
    ) public view {
        vm.assume(timestamp <= validUntil);

        OasisPrimitives.ViewKey memory viewKey = primitives.deriveViewKey(
            masterKey,
            scope,
            validUntil
        );

        bool valid = primitives.isViewKeyValid(viewKey, scope, timestamp);
        assertTrue(valid, "View key should be valid within time range");
    }

    /**
     * @notice Fuzz test: expired view key is invalid
     */
    function testFuzz_ExpiredViewKeyInvalid(
        bytes32 masterKey,
        bytes32 scope,
        uint256 validUntil,
        uint256 timestamp
    ) public view {
        vm.assume(validUntil > 0);
        vm.assume(timestamp > validUntil);

        OasisPrimitives.ViewKey memory viewKey = primitives.deriveViewKey(
            masterKey,
            scope,
            validUntil
        );

        bool valid = primitives.isViewKeyValid(viewKey, scope, timestamp);
        assertFalse(valid, "Expired view key should be invalid");
    }

    /**
     * @notice Fuzz test: wrong scope is invalid
     */
    function testFuzz_WrongScopeInvalid(
        bytes32 masterKey,
        bytes32 scope1,
        bytes32 scope2,
        uint256 validUntil,
        uint256 timestamp
    ) public view {
        vm.assume(scope1 != scope2);
        vm.assume(timestamp <= validUntil);

        OasisPrimitives.ViewKey memory viewKey = primitives.deriveViewKey(
            masterKey,
            scope1,
            validUntil
        );

        bool valid = primitives.isViewKeyValid(viewKey, scope2, timestamp);
        assertFalse(valid, "Wrong scope should be invalid");
    }

    // =========================================================================
    // STATE PROOF FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: state commitment is deterministic
     */
    function testFuzz_StateCommitmentDeterministic(
        bytes32 stateRoot,
        bytes32 ioRoot,
        uint64 round
    ) public view {
        bytes32 commitment1 = primitives.computeStateCommitment(
            stateRoot,
            ioRoot,
            round
        );
        bytes32 commitment2 = primitives.computeStateCommitment(
            stateRoot,
            ioRoot,
            round
        );

        assertEq(
            commitment1,
            commitment2,
            "State commitment should be deterministic"
        );
    }

    /**
     * @notice Fuzz test: different rounds produce different commitments
     */
    function testFuzz_DifferentRoundsDifferentCommitments(
        bytes32 stateRoot,
        bytes32 ioRoot,
        uint64 round1,
        uint64 round2
    ) public view {
        vm.assume(round1 != round2);

        bytes32 commitment1 = primitives.computeStateCommitment(
            stateRoot,
            ioRoot,
            round1
        );
        bytes32 commitment2 = primitives.computeStateCommitment(
            stateRoot,
            ioRoot,
            round2
        );

        assertNotEq(
            commitment1,
            commitment2,
            "Different rounds should produce different commitments"
        );
    }

    /**
     * @notice Fuzz test: valid Merkle proof verification
     */
    function testFuzz_ValidMerkleProof(bytes32 key, bytes32 value) public view {
        // Create a simple 1-level proof
        bytes32 leaf = keccak256(abi.encodePacked(key, value));
        bytes32 sibling = keccak256(abi.encodePacked("sibling"));

        bytes32 stateRoot;
        if (leaf <= sibling) {
            stateRoot = keccak256(abi.encodePacked(leaf, sibling));
        } else {
            stateRoot = keccak256(abi.encodePacked(sibling, leaf));
        }

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        OasisPrimitives.ParaTimeStateProof memory stateProof = OasisPrimitives
            .ParaTimeStateProof({
                round: 1,
                stateRoot: stateRoot,
                proof: proof,
                ioRoot: bytes32(0),
                signature: ""
            });

        bool valid = primitives.verifyStateProof(stateProof, key, value);
        assertTrue(valid, "Valid Merkle proof should verify");
    }

    /**
     * @notice Fuzz test: invalid Merkle proof rejected
     */
    function testFuzz_InvalidMerkleProofRejected(
        bytes32 key,
        bytes32 value,
        bytes32 wrongRoot
    ) public view {
        bytes32 leaf = keccak256(abi.encodePacked(key, value));
        bytes32 sibling = keccak256(abi.encodePacked("sibling"));

        bytes32 correctRoot;
        if (leaf <= sibling) {
            correctRoot = keccak256(abi.encodePacked(leaf, sibling));
        } else {
            correctRoot = keccak256(abi.encodePacked(sibling, leaf));
        }

        vm.assume(wrongRoot != correctRoot);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        OasisPrimitives.ParaTimeStateProof memory stateProof = OasisPrimitives
            .ParaTimeStateProof({
                round: 1,
                stateRoot: wrongRoot,
                proof: proof,
                ioRoot: bytes32(0),
                signature: ""
            });

        bool valid = primitives.verifyStateProof(stateProof, key, value);
        assertFalse(valid, "Invalid Merkle proof should be rejected");
    }

    // =========================================================================
    // SCALAR OPERATIONS FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: scalar reduction stays in range
     */
    function testFuzz_ScalarReductionInRange(uint256 scalar) public view {
        uint256 reduced = primitives.reduceScalar(scalar);
        assertTrue(
            reduced < primitives.CURVE25519_ORDER(),
            "Reduced scalar should be in range"
        );
    }

    /**
     * @notice Fuzz test: valid scalar check
     */
    function testFuzz_ValidScalarCheck(uint256 scalar) public view {
        scalar = bound(scalar, 1, primitives.CURVE25519_ORDER() - 1);
        assertTrue(
            primitives.isValidScalar(scalar),
            "Bounded scalar should be valid"
        );
    }

    /**
     * @notice Fuzz test: zero scalar is invalid
     */
    function testFuzz_ZeroScalarInvalid() public view {
        assertFalse(
            primitives.isValidScalar(0),
            "Zero should be invalid scalar"
        );
    }

    /**
     * @notice Fuzz test: scalar >= order is invalid
     */
    function testFuzz_ScalarAtOrderInvalid(uint256 offset) public view {
        offset = bound(offset, 0, 1000);
        uint256 scalar = primitives.CURVE25519_ORDER() + offset;
        assertFalse(
            primitives.isValidScalar(scalar),
            "Scalar >= order should be invalid"
        );
    }

    /**
     * @notice Fuzz test: scalar clamping is deterministic
     */
    function testFuzz_ScalarClampingDeterministic(bytes32 scalar) public view {
        bytes32 clamped1 = primitives.clampScalar(scalar);
        bytes32 clamped2 = primitives.clampScalar(scalar);
        assertEq(clamped1, clamped2, "Scalar clamping should be deterministic");
    }

    // =========================================================================
    // PARATIME IDENTIFICATION FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: Sapphire mainnet is confidential
     */
    function testFuzz_SapphireMainnetConfidential() public view {
        assertTrue(
            primitives.isConfidentialParaTime(
                primitives.SAPPHIRE_MAINNET_CHAIN_ID()
            ),
            "Sapphire mainnet should be confidential"
        );
    }

    /**
     * @notice Fuzz test: Sapphire testnet is confidential
     */
    function testFuzz_SapphireTestnetConfidential() public view {
        assertTrue(
            primitives.isConfidentialParaTime(
                primitives.SAPPHIRE_TESTNET_CHAIN_ID()
            ),
            "Sapphire testnet should be confidential"
        );
    }

    /**
     * @notice Fuzz test: Emerald is not confidential
     */
    function testFuzz_EmeraldNotConfidential() public view {
        assertFalse(
            primitives.isConfidentialParaTime(
                primitives.EMERALD_MAINNET_CHAIN_ID()
            ),
            "Emerald should not be confidential"
        );
    }

    /**
     * @notice Fuzz test: random chain not confidential
     */
    function testFuzz_RandomChainNotConfidential(uint256 chainId) public view {
        vm.assume(chainId != primitives.SAPPHIRE_MAINNET_CHAIN_ID());
        vm.assume(chainId != primitives.SAPPHIRE_TESTNET_CHAIN_ID());

        assertFalse(
            primitives.isConfidentialParaTime(chainId),
            "Random chain should not be confidential"
        );
    }

    /**
     * @notice Fuzz test: ParaTime type identification
     */
    function testFuzz_ParaTimeTypeIdentification() public view {
        assertEq(
            primitives.getParaTimeType(primitives.SAPPHIRE_MAINNET_CHAIN_ID()),
            1,
            "Sapphire mainnet should be type 1"
        );
        assertEq(
            primitives.getParaTimeType(primitives.SAPPHIRE_TESTNET_CHAIN_ID()),
            1,
            "Sapphire testnet should be type 1"
        );
        assertEq(
            primitives.getParaTimeType(primitives.EMERALD_MAINNET_CHAIN_ID()),
            2,
            "Emerald mainnet should be type 2"
        );
        assertEq(
            primitives.getParaTimeType(primitives.EMERALD_TESTNET_CHAIN_ID()),
            2,
            "Emerald testnet should be type 2"
        );
        assertEq(
            primitives.getParaTimeType(12345),
            0,
            "Unknown chain should be type 0"
        );
    }

    // =========================================================================
    // MESSAGE HASHING FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: message hashing is deterministic
     */
    function testFuzz_MessageHashDeterministic(
        uint256 sourceParaTime,
        uint256 destChain,
        bytes32 sender,
        bytes32 recipient,
        bytes memory payload,
        uint64 nonce,
        bytes32 proofHash
    ) public view {
        OasisPrimitives.OasisMessage memory message = OasisPrimitives
            .OasisMessage({
                sourceParaTime: sourceParaTime,
                destinationChain: destChain,
                sender: sender,
                recipient: recipient,
                payload: payload,
                nonce: nonce,
                stateProofHash: proofHash
            });

        bytes32 hash1 = primitives.hashOasisMessage(message);
        bytes32 hash2 = primitives.hashOasisMessage(message);

        assertEq(hash1, hash2, "Message hash should be deterministic");
    }

    /**
     * @notice Fuzz test: different messages produce different hashes
     */
    function testFuzz_DifferentMessagesDifferentHashes(
        uint256 sourceParaTime,
        uint256 destChain,
        bytes32 sender,
        bytes32 recipient,
        bytes memory payload,
        uint64 nonce1,
        uint64 nonce2,
        bytes32 proofHash
    ) public view {
        vm.assume(nonce1 != nonce2);

        OasisPrimitives.OasisMessage memory message1 = OasisPrimitives
            .OasisMessage({
                sourceParaTime: sourceParaTime,
                destinationChain: destChain,
                sender: sender,
                recipient: recipient,
                payload: payload,
                nonce: nonce1,
                stateProofHash: proofHash
            });

        OasisPrimitives.OasisMessage memory message2 = OasisPrimitives
            .OasisMessage({
                sourceParaTime: sourceParaTime,
                destinationChain: destChain,
                sender: sender,
                recipient: recipient,
                payload: payload,
                nonce: nonce2,
                stateProofHash: proofHash
            });

        bytes32 hash1 = primitives.hashOasisMessage(message1);
        bytes32 hash2 = primitives.hashOasisMessage(message2);

        assertNotEq(
            hash1,
            hash2,
            "Different messages should have different hashes"
        );
    }

    // =========================================================================
    // ATTESTATION FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: TCB status UP_TO_DATE is acceptable
     */
    function testFuzz_TCBUpToDateAcceptable() public view {
        assertTrue(
            primitives.isTCBStatusAcceptable(
                primitives.TCB_STATUS_UP_TO_DATE()
            ),
            "UP_TO_DATE should be acceptable"
        );
    }

    /**
     * @notice Fuzz test: TCB status SW_HARDENING_NEEDED is acceptable
     */
    function testFuzz_TCBSwHardeningAcceptable() public view {
        assertTrue(
            primitives.isTCBStatusAcceptable(
                primitives.TCB_STATUS_SW_HARDENING_NEEDED()
            ),
            "SW_HARDENING_NEEDED should be acceptable"
        );
    }

    /**
     * @notice Fuzz test: TCB status OUT_OF_DATE is not acceptable
     */
    function testFuzz_TCBOutOfDateNotAcceptable() public view {
        assertFalse(
            primitives.isTCBStatusAcceptable(
                primitives.TCB_STATUS_OUT_OF_DATE()
            ),
            "OUT_OF_DATE should not be acceptable"
        );
    }

    /**
     * @notice Fuzz test: TCB status REVOKED is not acceptable
     */
    function testFuzz_TCBRevokedNotAcceptable() public view {
        assertFalse(
            primitives.isTCBStatusAcceptable(primitives.TCB_STATUS_REVOKED()),
            "REVOKED should not be acceptable"
        );
    }

    /**
     * @notice Fuzz test: report data hashing is deterministic
     */
    function testFuzz_ReportDataHashDeterministic(
        bytes memory data
    ) public view {
        (bytes32 hash0a, bytes32 hash1a) = primitives.hashReportData(data);
        (bytes32 hash0b, bytes32 hash1b) = primitives.hashReportData(data);

        assertEq(hash0a, hash0b, "Report data hash0 should be deterministic");
        assertEq(hash1a, hash1b, "Report data hash1 should be deterministic");
    }

    /**
     * @notice Fuzz test: hash1 is derived from hash0
     */
    function testFuzz_ReportDataHash1DerivedFromHash0(
        bytes memory data
    ) public view {
        (bytes32 hash0, bytes32 hash1) = primitives.hashReportData(data);

        bytes32 expectedHash1 = keccak256(abi.encodePacked(hash0));
        assertEq(hash1, expectedHash1, "Hash1 should be keccak256(hash0)");
    }
}
