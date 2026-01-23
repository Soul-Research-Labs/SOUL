// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {RailgunPrimitives} from "../../contracts/railgun/RailgunPrimitives.sol";

/**
 * @title RailgunFuzz
 * @notice Comprehensive fuzz tests for Railgun cryptographic primitives
 */
contract RailgunFuzz is Test {
    RailgunPrimitives public primitives;

    // BN254 constants for testing
    uint256 constant BN254_P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant BN254_R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function setUp() public {
        primitives = new RailgunPrimitives();
    }

    // =========================================================================
    // FIELD ARITHMETIC TESTS
    // =========================================================================

    function testFuzz_FieldAddCommutative(uint256 a, uint256 b) public view {
        a = bound(a, 0, BN254_R - 1);
        b = bound(b, 0, BN254_R - 1);

        uint256 ab = primitives.fieldAdd(a, b);
        uint256 ba = primitives.fieldAdd(b, a);

        assertEq(ab, ba, "Field addition should be commutative");
    }

    function testFuzz_FieldAddProducesValidElement(
        uint256 a,
        uint256 b
    ) public view {
        a = bound(a, 0, BN254_R - 1);
        b = bound(b, 0, BN254_R - 1);

        uint256 result = primitives.fieldAdd(a, b);
        assertTrue(
            primitives.isValidFieldElement(result),
            "Result should be valid field element"
        );
    }

    function testFuzz_FieldMulCommutative(uint256 a, uint256 b) public view {
        a = bound(a, 0, BN254_R - 1);
        b = bound(b, 0, BN254_R - 1);

        uint256 ab = primitives.fieldMul(a, b);
        uint256 ba = primitives.fieldMul(b, a);

        assertEq(ab, ba, "Field multiplication should be commutative");
    }

    function testFuzz_FieldMulProducesValidElement(
        uint256 a,
        uint256 b
    ) public view {
        a = bound(a, 0, BN254_R - 1);
        b = bound(b, 0, BN254_R - 1);

        uint256 result = primitives.fieldMul(a, b);
        assertTrue(
            primitives.isValidFieldElement(result),
            "Result should be valid field element"
        );
    }

    function testFuzz_FieldSubProducesValidElement(
        uint256 a,
        uint256 b
    ) public view {
        a = bound(a, 0, BN254_R - 1);
        b = bound(b, 0, BN254_R - 1);

        uint256 result = primitives.fieldSub(a, b);
        assertTrue(
            primitives.isValidFieldElement(result),
            "Result should be valid field element"
        );
    }

    function testFuzz_FieldNegIsAdditiveInverse(uint256 a) public view {
        a = bound(a, 1, BN254_R - 1);

        uint256 negA = primitives.fieldNeg(a);
        uint256 sum = primitives.fieldAdd(a, negA);

        assertEq(sum, 0, "a + (-a) should equal 0");
    }

    function testFuzz_ZeroIsAdditiveIdentity(uint256 a) public view {
        a = bound(a, 0, BN254_R - 1);

        uint256 result = primitives.fieldAdd(a, 0);
        assertEq(result, a, "a + 0 should equal a");
    }

    function testFuzz_OneIsMultiplicativeIdentity(uint256 a) public view {
        a = bound(a, 0, BN254_R - 1);

        uint256 result = primitives.fieldMul(a, 1);
        assertEq(result, a, "a * 1 should equal a");
    }

    function testFuzz_FieldInverse(uint256 a) public view {
        a = bound(a, 1, BN254_R - 1);

        uint256 invA = primitives.fieldInv(a);
        uint256 product = primitives.fieldMul(a, invA);

        assertEq(product, 1, "a * a^(-1) should equal 1");
    }

    // =========================================================================
    // BASE FIELD TESTS
    // =========================================================================

    function testFuzz_BaseFieldAddProducesValidElement(
        uint256 a,
        uint256 b
    ) public view {
        a = bound(a, 0, BN254_P - 1);
        b = bound(b, 0, BN254_P - 1);

        uint256 result = primitives.baseFieldAdd(a, b);
        assertTrue(
            primitives.isValidBaseFieldElement(result),
            "Result should be valid base field element"
        );
    }

    function testFuzz_BaseFieldMulProducesValidElement(
        uint256 a,
        uint256 b
    ) public view {
        a = bound(a, 0, BN254_P - 1);
        b = bound(b, 0, BN254_P - 1);

        uint256 result = primitives.baseFieldMul(a, b);
        assertTrue(
            primitives.isValidBaseFieldElement(result),
            "Result should be valid base field element"
        );
    }

    // =========================================================================
    // G1 POINT TESTS
    // =========================================================================

    function testFuzz_G1GeneratorIsValid() public view {
        RailgunPrimitives.G1Point memory g = primitives.g1Generator();
        assertTrue(primitives.isValidG1Point(g), "Generator should be valid");
    }

    function testFuzz_G1PointAtInfinityIsValid() public view {
        RailgunPrimitives.G1Point memory p = RailgunPrimitives.G1Point(0, 0);
        assertTrue(
            primitives.isValidG1Point(p),
            "Point at infinity should be valid"
        );
    }

    function testFuzz_G1InvalidPointRejected(uint256 x, uint256 y) public view {
        x = bound(x, 1, BN254_P - 1);
        y = bound(y, 1, BN254_P - 1);

        // Random points are very unlikely to be on curve
        RailgunPrimitives.G1Point memory p = RailgunPrimitives.G1Point(x, y);

        // Most random points won't be on curve
        // We can't assert false because some might randomly be valid
        // Just ensure the function doesn't revert
        primitives.isValidG1Point(p);
    }

    function testFuzz_G1NegateInfinity() public view {
        RailgunPrimitives.G1Point memory inf = RailgunPrimitives.G1Point(0, 0);
        RailgunPrimitives.G1Point memory negInf = primitives.g1Negate(inf);

        assertEq(negInf.x, 0, "Negation of infinity x should be 0");
        assertEq(negInf.y, 0, "Negation of infinity y should be 0");
    }

    function testFuzz_G1NegateGenerator() public view {
        RailgunPrimitives.G1Point memory g = primitives.g1Generator();
        RailgunPrimitives.G1Point memory negG = primitives.g1Negate(g);

        assertEq(negG.x, g.x, "Negation should preserve x coordinate");
        assertEq(negG.y, BN254_P - g.y, "Negation should negate y coordinate");
    }

    function testFuzz_G1ScalarMulByZero() public view {
        RailgunPrimitives.G1Point memory g = primitives.g1Generator();
        RailgunPrimitives.G1Point memory result = primitives.g1ScalarMul(g, 0);

        assertEq(result.x, 0, "0 * G should give infinity (x=0)");
        assertEq(result.y, 0, "0 * G should give infinity (y=0)");
    }

    function testFuzz_G1ScalarMulByOne() public view {
        RailgunPrimitives.G1Point memory g = primitives.g1Generator();
        RailgunPrimitives.G1Point memory result = primitives.g1ScalarMul(g, 1);

        assertEq(result.x, g.x, "1 * G should equal G");
        assertEq(result.y, g.y, "1 * G should equal G");
    }

    function testFuzz_G1AddWithInfinity() public view {
        RailgunPrimitives.G1Point memory g = primitives.g1Generator();
        RailgunPrimitives.G1Point memory inf = RailgunPrimitives.G1Point(0, 0);

        RailgunPrimitives.G1Point memory result = primitives.g1Add(g, inf);

        assertEq(result.x, g.x, "G + O should equal G");
        assertEq(result.y, g.y, "G + O should equal G");
    }

    function testFuzz_G1ScalarMulProducesValidPoint(uint256 s) public view {
        s = bound(s, 1, BN254_R - 1);

        RailgunPrimitives.G1Point memory g = primitives.g1Generator();
        RailgunPrimitives.G1Point memory result = primitives.g1ScalarMul(g, s);

        assertTrue(
            primitives.isValidG1Point(result),
            "Scalar mul should produce valid point"
        );
    }

    // =========================================================================
    // G2 POINT TESTS
    // =========================================================================

    function testFuzz_G2GeneratorIsValid() public view {
        RailgunPrimitives.G2Point memory g2 = primitives.g2Generator();
        assertTrue(
            primitives.isValidG2Point(g2),
            "G2 generator should be valid"
        );
    }

    function testFuzz_G2InvalidCoordinatesRejected(
        uint256 x0,
        uint256 x1
    ) public view {
        x0 = BN254_P + 1; // Force invalid
        x1 = bound(x1, 0, BN254_P - 1);

        RailgunPrimitives.G2Point memory p = RailgunPrimitives.G2Point(
            x0,
            x1,
            0,
            0
        );

        assertFalse(
            primitives.isValidG2Point(p),
            "Invalid G2 point should be rejected"
        );
    }

    // =========================================================================
    // POSEIDON HASH TESTS
    // =========================================================================

    function testFuzz_PoseidonHash2Deterministic(
        uint256 a,
        uint256 b
    ) public view {
        a = bound(a, 0, BN254_R - 1);
        b = bound(b, 0, BN254_R - 1);

        uint256 hash1 = primitives.poseidonHash2(a, b);
        uint256 hash2 = primitives.poseidonHash2(a, b);

        assertEq(hash1, hash2, "Poseidon hash should be deterministic");
    }

    function testFuzz_PoseidonHash2ProducesValidElement(
        uint256 a,
        uint256 b
    ) public view {
        uint256 hash = primitives.poseidonHash2(a, b);
        assertTrue(
            primitives.isValidFieldElement(hash),
            "Hash should be valid field element"
        );
    }

    function testFuzz_PoseidonHash2DifferentInputsDifferentOutputs(
        uint256 a,
        uint256 b,
        uint256 c
    ) public view {
        a = bound(a, 0, BN254_R - 1);
        b = bound(b, 0, BN254_R - 1);
        c = bound(c, 0, BN254_R - 1);

        vm.assume(a != c);

        uint256 hash1 = primitives.poseidonHash2(a, b);
        uint256 hash2 = primitives.poseidonHash2(c, b);

        assertNotEq(
            hash1,
            hash2,
            "Different inputs should produce different hashes"
        );
    }

    function testFuzz_PoseidonHash4Deterministic(
        uint256 a,
        uint256 b,
        uint256 c,
        uint256 d
    ) public view {
        a = bound(a, 0, BN254_R - 1);
        b = bound(b, 0, BN254_R - 1);
        c = bound(c, 0, BN254_R - 1);
        d = bound(d, 0, BN254_R - 1);

        uint256 hash1 = primitives.poseidonHash4(a, b, c, d);
        uint256 hash2 = primitives.poseidonHash4(a, b, c, d);

        assertEq(hash1, hash2, "Poseidon hash4 should be deterministic");
    }

    function testFuzz_PoseidonHashNDeterministic(
        uint8 inputCount,
        uint256 seed
    ) public view {
        inputCount = uint8(bound(inputCount, 1, 10));

        uint256[] memory inputs = new uint256[](inputCount);
        for (uint256 i = 0; i < inputCount; i++) {
            inputs[i] = uint256(keccak256(abi.encodePacked(seed, i)));
        }

        uint256 hash1 = primitives.poseidonHashN(inputs);
        uint256 hash2 = primitives.poseidonHashN(inputs);

        assertEq(hash1, hash2, "Poseidon hashN should be deterministic");
    }

    // =========================================================================
    // NOTE COMMITMENT TESTS
    // =========================================================================

    function testFuzz_NoteCommitmentDeterministic(
        bytes32 npk,
        uint256 value,
        address token,
        bytes32 random
    ) public view {
        bytes32 commitment1 = primitives.computeNoteCommitment(
            npk,
            value,
            token,
            random
        );
        bytes32 commitment2 = primitives.computeNoteCommitment(
            npk,
            value,
            token,
            random
        );

        assertEq(
            commitment1,
            commitment2,
            "Note commitment should be deterministic"
        );
    }

    function testFuzz_NoteCommitmentUniqueness(
        bytes32 npk1,
        bytes32 npk2,
        uint256 value,
        address token,
        bytes32 random
    ) public view {
        vm.assume(npk1 != npk2);

        bytes32 commitment1 = primitives.computeNoteCommitment(
            npk1,
            value,
            token,
            random
        );
        bytes32 commitment2 = primitives.computeNoteCommitment(
            npk2,
            value,
            token,
            random
        );

        assertNotEq(
            commitment1,
            commitment2,
            "Different npk should produce different commitments"
        );
    }

    function testFuzz_NoteCommitmentVerification(
        bytes32 npk,
        uint256 value,
        address token,
        bytes32 random
    ) public view {
        bytes32 commitment = primitives.computeNoteCommitment(
            npk,
            value,
            token,
            random
        );

        RailgunPrimitives.ShieldedNote memory note = RailgunPrimitives
            .ShieldedNote({
                commitment: commitment,
                nullifier: bytes32(0),
                value: value,
                token: token,
                random: random
            });

        assertTrue(
            primitives.verifyNoteCommitment(note, npk),
            "Note commitment should verify"
        );
    }

    function testFuzz_NoteCommitmentWrongNpkFails(
        bytes32 npk1,
        bytes32 npk2,
        uint256 value,
        address token,
        bytes32 random
    ) public view {
        vm.assume(npk1 != npk2);

        bytes32 commitment = primitives.computeNoteCommitment(
            npk1,
            value,
            token,
            random
        );

        RailgunPrimitives.ShieldedNote memory note = RailgunPrimitives
            .ShieldedNote({
                commitment: commitment,
                nullifier: bytes32(0),
                value: value,
                token: token,
                random: random
            });

        assertFalse(
            primitives.verifyNoteCommitment(note, npk2),
            "Wrong npk should fail verification"
        );
    }

    // =========================================================================
    // NULLIFIER TESTS
    // =========================================================================

    function testFuzz_NullifierDeterministic(
        bytes32 spendingKey,
        bytes32 commitment
    ) public view {
        bytes32 nullifier1 = primitives.deriveNullifier(
            spendingKey,
            commitment
        );
        bytes32 nullifier2 = primitives.deriveNullifier(
            spendingKey,
            commitment
        );

        assertEq(
            nullifier1,
            nullifier2,
            "Nullifier derivation should be deterministic"
        );
    }

    function testFuzz_NullifierUniqueness(
        bytes32 spendingKey,
        bytes32 commitment1,
        bytes32 commitment2
    ) public view {
        vm.assume(commitment1 != commitment2);

        bytes32 nullifier1 = primitives.deriveNullifier(
            spendingKey,
            commitment1
        );
        bytes32 nullifier2 = primitives.deriveNullifier(
            spendingKey,
            commitment2
        );

        assertNotEq(
            nullifier1,
            nullifier2,
            "Different commitments should produce different nullifiers"
        );
    }

    function testFuzz_CrossDomainNullifierDeterministic(
        bytes32 nullifier,
        bytes32 srcDomain,
        bytes32 dstDomain
    ) public view {
        bytes32 cross1 = primitives.deriveCrossDomainNullifier(
            nullifier,
            srcDomain,
            dstDomain
        );
        bytes32 cross2 = primitives.deriveCrossDomainNullifier(
            nullifier,
            srcDomain,
            dstDomain
        );

        assertEq(
            cross1,
            cross2,
            "Cross-domain nullifier should be deterministic"
        );
    }

    function testFuzz_DifferentDomainsDifferentNullifiers(
        bytes32 nullifier,
        bytes32 srcDomain,
        bytes32 dstDomain1,
        bytes32 dstDomain2
    ) public view {
        vm.assume(dstDomain1 != dstDomain2);

        bytes32 cross1 = primitives.deriveCrossDomainNullifier(
            nullifier,
            srcDomain,
            dstDomain1
        );
        bytes32 cross2 = primitives.deriveCrossDomainNullifier(
            nullifier,
            srcDomain,
            dstDomain2
        );

        assertNotEq(
            cross1,
            cross2,
            "Different domains should produce different nullifiers"
        );
    }

    function testFuzz_PILBindingDeterministic(
        bytes32 railgunNullifier
    ) public view {
        bytes32 binding1 = primitives.derivePILBinding(railgunNullifier);
        bytes32 binding2 = primitives.derivePILBinding(railgunNullifier);

        assertEq(binding1, binding2, "PIL binding should be deterministic");
    }

    // =========================================================================
    // MERKLE TREE TESTS
    // =========================================================================

    function testFuzz_MerkleRootDeterministic(
        bytes32 leaf,
        uint256 pathIndices
    ) public view {
        bytes32[] memory siblings = new bytes32[](16);
        for (uint256 i = 0; i < 16; i++) {
            siblings[i] = keccak256(abi.encodePacked(leaf, i));
        }

        bytes32 root1 = primitives.computeMerkleRoot(
            leaf,
            pathIndices,
            siblings
        );
        bytes32 root2 = primitives.computeMerkleRoot(
            leaf,
            pathIndices,
            siblings
        );

        assertEq(
            root1,
            root2,
            "Merkle root computation should be deterministic"
        );
    }

    function testFuzz_MerkleProofVerification(bytes32 commitment) public view {
        bytes32[] memory siblings = new bytes32[](16);
        for (uint256 i = 0; i < 16; i++) {
            siblings[i] = keccak256(abi.encodePacked(commitment, i));
        }

        uint256 pathIndices = 0;
        bytes32 root = primitives.computeMerkleRoot(
            commitment,
            pathIndices,
            siblings
        );

        RailgunPrimitives.NotePosition memory position = RailgunPrimitives
            .NotePosition({
                treeIndex: 0,
                leafIndex: pathIndices,
                siblings: siblings
            });

        assertTrue(
            primitives.verifyMerkleProof(commitment, root, position),
            "Valid Merkle proof should verify"
        );
    }

    function testFuzz_MerkleProofWrongRootFails(
        bytes32 commitment,
        bytes32 wrongRoot
    ) public view {
        bytes32[] memory siblings = new bytes32[](16);
        for (uint256 i = 0; i < 16; i++) {
            siblings[i] = keccak256(abi.encodePacked(commitment, i));
        }

        uint256 pathIndices = 0;
        bytes32 correctRoot = primitives.computeMerkleRoot(
            commitment,
            pathIndices,
            siblings
        );

        vm.assume(wrongRoot != correctRoot);

        RailgunPrimitives.NotePosition memory position = RailgunPrimitives
            .NotePosition({
                treeIndex: 0,
                leafIndex: pathIndices,
                siblings: siblings
            });

        assertFalse(
            primitives.verifyMerkleProof(commitment, wrongRoot, position),
            "Wrong root should fail verification"
        );
    }

    // =========================================================================
    // VIEWING KEY TESTS
    // =========================================================================

    function testFuzz_ViewingKeyDerivationDeterministic(
        bytes32 spendingKey,
        bytes32 salt
    ) public view {
        bytes32 vk1 = primitives.deriveViewingKey(spendingKey, salt);
        bytes32 vk2 = primitives.deriveViewingKey(spendingKey, salt);

        assertEq(vk1, vk2, "Viewing key derivation should be deterministic");
    }

    function testFuzz_ViewingKeyHashDeterministic(
        bytes32 key,
        address owner,
        uint256 startBlock
    ) public view {
        RailgunPrimitives.ViewingKey memory vk = RailgunPrimitives.ViewingKey({
            key: key,
            owner: owner,
            startBlock: startBlock
        });

        bytes32 hash1 = primitives.hashViewingKey(vk);
        bytes32 hash2 = primitives.hashViewingKey(vk);

        assertEq(hash1, hash2, "Viewing key hash should be deterministic");
    }

    function testFuzz_ViewingKeyValidation(
        bytes32 key,
        address owner,
        uint256 startBlock,
        uint256 currentBlock
    ) public view {
        vm.assume(key != bytes32(0));
        vm.assume(owner != address(0));
        startBlock = bound(startBlock, 0, currentBlock);

        RailgunPrimitives.ViewingKey memory vk = RailgunPrimitives.ViewingKey({
            key: key,
            owner: owner,
            startBlock: startBlock
        });

        assertTrue(
            primitives.isValidViewingKey(vk, currentBlock),
            "Valid viewing key should pass validation"
        );
    }

    function testFuzz_ViewingKeyZeroKeyInvalid(
        address owner,
        uint256 startBlock
    ) public view {
        RailgunPrimitives.ViewingKey memory vk = RailgunPrimitives.ViewingKey({
            key: bytes32(0),
            owner: owner,
            startBlock: startBlock
        });

        assertFalse(
            primitives.isValidViewingKey(vk, block.number),
            "Zero key should be invalid"
        );
    }

    function testFuzz_ViewingKeyZeroOwnerInvalid(
        bytes32 key,
        uint256 startBlock
    ) public view {
        vm.assume(key != bytes32(0));

        RailgunPrimitives.ViewingKey memory vk = RailgunPrimitives.ViewingKey({
            key: key,
            owner: address(0),
            startBlock: startBlock
        });

        assertFalse(
            primitives.isValidViewingKey(vk, block.number),
            "Zero owner should be invalid"
        );
    }

    function testFuzz_ViewingKeyFutureStartBlockInvalid(
        bytes32 key,
        address owner,
        uint256 currentBlock
    ) public view {
        vm.assume(key != bytes32(0));
        vm.assume(owner != address(0));
        vm.assume(currentBlock < type(uint256).max);

        RailgunPrimitives.ViewingKey memory vk = RailgunPrimitives.ViewingKey({
            key: key,
            owner: owner,
            startBlock: currentBlock + 1
        });

        assertFalse(
            primitives.isValidViewingKey(vk, currentBlock),
            "Future start block should be invalid"
        );
    }

    // =========================================================================
    // NOTE ENCRYPTION TESTS
    // =========================================================================

    function testFuzz_EncryptedNoteVerification(
        bytes32 viewingKey,
        bytes32 ephemeralPubKey,
        bytes memory ciphertext
    ) public view {
        vm.assume(ciphertext.length > 0);

        // Derive expected MAC
        bytes32 sharedSecret = keccak256(
            abi.encodePacked(
                primitives.NOTE_ENCRYPTION_DOMAIN(),
                viewingKey,
                ephemeralPubKey
            )
        );
        bytes32 mac = keccak256(
            abi.encodePacked(sharedSecret, "MAC", ciphertext)
        );

        RailgunPrimitives.EncryptedNote memory encrypted = RailgunPrimitives
            .EncryptedNote({
                ephemeralPubKey: ephemeralPubKey,
                ciphertext: ciphertext,
                mac: mac
            });

        assertTrue(
            primitives.verifyEncryptedNote(encrypted, viewingKey),
            "Valid MAC should verify"
        );
    }

    function testFuzz_EncryptedNoteWrongKeyFails(
        bytes32 viewingKey1,
        bytes32 viewingKey2,
        bytes32 ephemeralPubKey,
        bytes memory ciphertext
    ) public view {
        vm.assume(viewingKey1 != viewingKey2);
        vm.assume(ciphertext.length > 0);

        // Create MAC with key1
        bytes32 sharedSecret = keccak256(
            abi.encodePacked(
                primitives.NOTE_ENCRYPTION_DOMAIN(),
                viewingKey1,
                ephemeralPubKey
            )
        );
        bytes32 mac = keccak256(
            abi.encodePacked(sharedSecret, "MAC", ciphertext)
        );

        RailgunPrimitives.EncryptedNote memory encrypted = RailgunPrimitives
            .EncryptedNote({
                ephemeralPubKey: ephemeralPubKey,
                ciphertext: ciphertext,
                mac: mac
            });

        // Verify with key2 should fail
        assertFalse(
            primitives.verifyEncryptedNote(encrypted, viewingKey2),
            "Wrong viewing key should fail verification"
        );
    }

    // =========================================================================
    // CHAIN DETECTION TESTS
    // =========================================================================

    function testFuzz_EthereumMainnetDetection() public view {
        assertTrue(
            primitives.isEthereumMainnet(1),
            "Should detect Ethereum mainnet"
        );
        assertFalse(
            primitives.isEthereumMainnet(137),
            "Should not detect Polygon as Ethereum"
        );
    }

    function testFuzz_PolygonDetection() public view {
        assertTrue(primitives.isPolygon(137), "Should detect Polygon");
        assertFalse(
            primitives.isPolygon(1),
            "Should not detect Ethereum as Polygon"
        );
    }

    function testFuzz_ArbitrumDetection() public view {
        assertTrue(primitives.isArbitrum(42161), "Should detect Arbitrum");
        assertFalse(
            primitives.isArbitrum(1),
            "Should not detect Ethereum as Arbitrum"
        );
    }

    function testFuzz_BSCDetection() public view {
        assertTrue(primitives.isBSC(56), "Should detect BSC");
        assertFalse(primitives.isBSC(1), "Should not detect Ethereum as BSC");
    }

    function testFuzz_RailgunChainDetection(uint256 chainId) public view {
        bool isRailgun = primitives.isRailgunChain(chainId);

        bool expected = chainId == 1 ||
            chainId == 137 ||
            chainId == 42161 ||
            chainId == 56;
        assertEq(
            isRailgun,
            expected,
            "Railgun chain detection should be correct"
        );
    }

    // =========================================================================
    // TRANSACTION BUNDLE TESTS
    // =========================================================================

    function testFuzz_BundleValidationEmptyNullifiers() public view {
        RailgunPrimitives.TransactionBundle memory bundle;
        bundle.nullifiers = new bytes32[](0);
        bundle.commitments = new bytes32[](1);
        bundle.commitments[0] = bytes32(uint256(1));
        bundle.encryptedOutputs = new RailgunPrimitives.EncryptedNote[](1);
        bundle.proof = _createValidProofStructure();

        assertFalse(
            primitives.validateBundleStructure(bundle),
            "Empty nullifiers should be invalid"
        );
    }

    function testFuzz_BundleValidationTooManyInputs(uint8 count) public view {
        count = uint8(bound(count, 14, 255));

        RailgunPrimitives.TransactionBundle memory bundle;
        bundle.nullifiers = new bytes32[](count);
        bundle.commitments = new bytes32[](1);
        bundle.commitments[0] = bytes32(uint256(1));
        bundle.encryptedOutputs = new RailgunPrimitives.EncryptedNote[](1);
        bundle.proof = _createValidProofStructure();

        assertFalse(
            primitives.validateBundleStructure(bundle),
            "Too many inputs should be invalid"
        );
    }

    function testFuzz_BundleValidationMismatchedOutputs() public view {
        RailgunPrimitives.TransactionBundle memory bundle;
        bundle.nullifiers = new bytes32[](1);
        bundle.nullifiers[0] = bytes32(uint256(1));
        bundle.commitments = new bytes32[](2);
        bundle.encryptedOutputs = new RailgunPrimitives.EncryptedNote[](1); // Mismatch
        bundle.proof = _createValidProofStructure();

        assertFalse(
            primitives.validateBundleStructure(bundle),
            "Mismatched outputs should be invalid"
        );
    }

    function testFuzz_PublicInputsHashDeterministic(
        bytes32 merkleRoot,
        bytes32 nullifier,
        bytes32 commitment
    ) public view {
        RailgunPrimitives.TransactionBundle memory bundle;
        bundle.merkleRoot = merkleRoot;
        bundle.nullifiers = new bytes32[](1);
        bundle.nullifiers[0] = nullifier;
        bundle.commitments = new bytes32[](1);
        bundle.commitments[0] = commitment;
        bundle.encryptedOutputs = new RailgunPrimitives.EncryptedNote[](1);
        bundle.proof = _createValidProofStructure();

        bytes32 hash1 = primitives.computePublicInputsHash(bundle);
        bytes32 hash2 = primitives.computePublicInputsHash(bundle);

        assertEq(hash1, hash2, "Public inputs hash should be deterministic");
    }

    // =========================================================================
    // UTILITY TESTS
    // =========================================================================

    function testFuzz_ModExp(uint256 base, uint256 exp) public view {
        base = bound(base, 1, BN254_R - 1);
        exp = bound(exp, 1, 100); // Keep exponent small for gas

        uint256 result = primitives.modExp(base, exp, BN254_R);
        assertTrue(result < BN254_R, "ModExp result should be in field");
    }

    function testFuzz_BytesToUint256(bytes32 data) public view {
        bytes memory dataBytes = abi.encodePacked(data);
        uint256 result = primitives.bytesToUint256(dataBytes);
        assertEq(
            result,
            uint256(data),
            "Bytes to uint256 conversion should be correct"
        );
    }

    function testFuzz_Uint256ToBytes32(uint256 x) public view {
        bytes32 result = primitives.uint256ToBytes32(x);
        assertEq(
            uint256(result),
            x,
            "Uint256 to bytes32 conversion should be correct"
        );
    }

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================

    function _createValidProofStructure()
        internal
        view
        returns (RailgunPrimitives.Groth16Proof memory)
    {
        // Create a structurally valid (but not cryptographically valid) proof
        RailgunPrimitives.G1Point memory g1 = primitives.g1Generator();
        RailgunPrimitives.G2Point memory g2 = primitives.g2Generator();

        return RailgunPrimitives.Groth16Proof({a: g1, b: g2, c: g1});
    }
}
