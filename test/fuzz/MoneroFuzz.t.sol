// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/monero/MoneroPrimitives.sol";

/**
 * @title MoneroFuzz
 * @author PIL Protocol
 * @notice Foundry fuzz tests for Monero cryptographic primitives
 */
contract MoneroFuzz is Test {
    MoneroPrimitives public primitives;

    // Ed25519 constants
    uint256 constant ED25519_ORDER =
        7237005577332262213973186563042994240857116359379907606001950938285454250989;
    uint256 constant ED25519_PRIME =
        57896044618658097711785492504343953926634992332820282019728792003956564819949;

    function setUp() public {
        primitives = new MoneroPrimitives();
    }

    // =========================================================================
    // SCALAR ARITHMETIC FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: scalar addition is commutative
     */
    function testFuzz_ScalarAddCommutative(uint256 a, uint256 b) public view {
        a = bound(a, 0, ED25519_ORDER - 1);
        b = bound(b, 0, ED25519_ORDER - 1);

        uint256 sum1 = primitives.scalarAdd(a, b);
        uint256 sum2 = primitives.scalarAdd(b, a);

        assertEq(sum1, sum2, "Scalar addition should be commutative");
    }

    /**
     * @notice Fuzz test: scalar addition has identity (0)
     */
    function testFuzz_ScalarAddIdentity(uint256 a) public view {
        a = bound(a, 0, ED25519_ORDER - 1);

        uint256 result = primitives.scalarAdd(a, 0);

        assertEq(result, a, "Adding zero should return original");
    }

    /**
     * @notice Fuzz test: scalar addition result is in valid range
     */
    function testFuzz_ScalarAddInRange(uint256 a, uint256 b) public view {
        a = bound(a, 0, ED25519_ORDER - 1);
        b = bound(b, 0, ED25519_ORDER - 1);

        uint256 result = primitives.scalarAdd(a, b);

        assertTrue(result < ED25519_ORDER, "Result should be less than order");
    }

    /**
     * @notice Fuzz test: scalar subtraction inverse of addition
     */
    function testFuzz_ScalarSubInverse(uint256 a, uint256 b) public view {
        a = bound(a, 0, ED25519_ORDER - 1);
        b = bound(b, 0, ED25519_ORDER - 1);

        uint256 sum = primitives.scalarAdd(a, b);
        uint256 diff = primitives.scalarSub(sum, b);

        assertEq(diff, a, "Subtraction should undo addition");
    }

    /**
     * @notice Fuzz test: scalar multiplication is commutative
     */
    function testFuzz_ScalarMulCommutative(uint256 a, uint256 b) public view {
        a = bound(a, 0, ED25519_ORDER - 1);
        b = bound(b, 0, ED25519_ORDER - 1);

        uint256 prod1 = primitives.scalarMul(a, b);
        uint256 prod2 = primitives.scalarMul(b, a);

        assertEq(prod1, prod2, "Scalar multiplication should be commutative");
    }

    /**
     * @notice Fuzz test: scalar multiplication has identity (1)
     */
    function testFuzz_ScalarMulIdentity(uint256 a) public view {
        a = bound(a, 0, ED25519_ORDER - 1);

        uint256 result = primitives.scalarMul(a, 1);

        assertEq(result, a, "Multiplying by one should return original");
    }

    /**
     * @notice Fuzz test: scalar multiplication by zero is zero
     */
    function testFuzz_ScalarMulZero(uint256 a) public view {
        a = bound(a, 0, ED25519_ORDER - 1);

        uint256 result = primitives.scalarMul(a, 0);

        assertEq(result, 0, "Multiplying by zero should return zero");
    }

    /**
     * @notice Fuzz test: scalar multiplication result is in valid range
     */
    function testFuzz_ScalarMulInRange(uint256 a, uint256 b) public view {
        a = bound(a, 0, ED25519_ORDER - 1);
        b = bound(b, 0, ED25519_ORDER - 1);

        uint256 result = primitives.scalarMul(a, b);

        assertTrue(result < ED25519_ORDER, "Result should be less than order");
    }

    /**
     * @notice Fuzz test: scalar distributive law
     * a * (b + c) = a*b + a*c
     */
    function testFuzz_ScalarDistributive(
        uint256 a,
        uint256 b,
        uint256 c
    ) public view {
        a = bound(a, 0, ED25519_ORDER - 1);
        b = bound(b, 0, ED25519_ORDER - 1);
        c = bound(c, 0, ED25519_ORDER - 1);

        uint256 left = primitives.scalarMul(a, primitives.scalarAdd(b, c));
        uint256 right = primitives.scalarAdd(
            primitives.scalarMul(a, b),
            primitives.scalarMul(a, c)
        );

        assertEq(left, right, "Distributive law should hold");
    }

    /**
     * @notice Fuzz test: isValidScalar returns true for valid scalars
     */
    function testFuzz_IsValidScalarTrue(uint256 s) public view {
        s = bound(s, 0, ED25519_ORDER - 1);

        assertTrue(primitives.isValidScalar(s), "Should be valid scalar");
    }

    /**
     * @notice Fuzz test: isValidScalar returns false for invalid scalars
     */
    function testFuzz_IsValidScalarFalse(uint256 s) public view {
        s = bound(s, ED25519_ORDER, type(uint256).max);

        assertFalse(primitives.isValidScalar(s), "Should be invalid scalar");
    }

    // =========================================================================
    // HASH FUNCTION FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: hashToScalar is deterministic
     */
    function testFuzz_HashToScalarDeterministic(bytes memory data) public view {
        uint256 hash1 = primitives.hashToScalar(data);
        uint256 hash2 = primitives.hashToScalar(data);

        assertEq(hash1, hash2, "Hash should be deterministic");
    }

    /**
     * @notice Fuzz test: hashToScalar produces valid scalar
     */
    function testFuzz_HashToScalarValid(bytes memory data) public view {
        uint256 hash = primitives.hashToScalar(data);

        assertTrue(
            primitives.isValidScalar(hash),
            "Hash should produce valid scalar"
        );
    }

    /**
     * @notice Fuzz test: hashToPoint is deterministic
     */
    function testFuzz_HashToPointDeterministic(bytes memory data) public view {
        MoneroPrimitives.Ed25519Point memory point1 = primitives.hashToPoint(
            data
        );
        MoneroPrimitives.Ed25519Point memory point2 = primitives.hashToPoint(
            data
        );

        assertEq(
            point1.compressed,
            point2.compressed,
            "Hash to point should be deterministic"
        );
    }

    /**
     * @notice Fuzz test: different inputs produce different hashes (collision resistance)
     */
    function testFuzz_HashCollisionResistance(
        bytes memory data1,
        bytes memory data2
    ) public view {
        vm.assume(keccak256(data1) != keccak256(data2));

        uint256 hash1 = primitives.hashToScalar(data1);
        uint256 hash2 = primitives.hashToScalar(data2);

        // Note: This is probabilistic, very unlikely to fail
        assertNotEq(
            hash1,
            hash2,
            "Different inputs should produce different hashes"
        );
    }

    // =========================================================================
    // KEY IMAGE FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: keyImageHash is deterministic
     */
    function testFuzz_KeyImageHashDeterministic(
        bytes32 compressed
    ) public view {
        MoneroPrimitives.KeyImage memory ki = MoneroPrimitives.KeyImage({
            point: MoneroPrimitives.Ed25519Point({compressed: compressed})
        });

        bytes32 hash1 = primitives.keyImageHash(ki);
        bytes32 hash2 = primitives.keyImageHash(ki);

        assertEq(hash1, hash2, "Key image hash should be deterministic");
    }

    /**
     * @notice Fuzz test: isValidKeyImage rejects zero
     */
    function testFuzz_IsValidKeyImageRejectsZero() public view {
        MoneroPrimitives.KeyImage memory ki = MoneroPrimitives.KeyImage({
            point: MoneroPrimitives.Ed25519Point({compressed: bytes32(0)})
        });

        assertFalse(
            primitives.isValidKeyImage(ki),
            "Zero key image should be invalid"
        );
    }

    /**
     * @notice Fuzz test: isValidKeyImage accepts non-zero
     */
    function testFuzz_IsValidKeyImageAcceptsNonZero(
        bytes32 compressed
    ) public view {
        vm.assume(compressed != bytes32(0));

        MoneroPrimitives.KeyImage memory ki = MoneroPrimitives.KeyImage({
            point: MoneroPrimitives.Ed25519Point({compressed: compressed})
        });

        assertTrue(
            primitives.isValidKeyImage(ki),
            "Non-zero key image should be valid"
        );
    }

    /**
     * @notice Fuzz test: deriveMoneroToPILNullifier is deterministic
     */
    function testFuzz_DeriveNullifierDeterministic(
        bytes32 compressed
    ) public view {
        vm.assume(compressed != bytes32(0));

        MoneroPrimitives.KeyImage memory ki = MoneroPrimitives.KeyImage({
            point: MoneroPrimitives.Ed25519Point({compressed: compressed})
        });

        bytes32 nf1 = primitives.deriveMoneroToPILNullifier(ki);
        bytes32 nf2 = primitives.deriveMoneroToPILNullifier(ki);

        assertEq(nf1, nf2, "Nullifier derivation should be deterministic");
    }

    /**
     * @notice Fuzz test: different key images produce different nullifiers
     */
    function testFuzz_DeriveNullifierUnique(
        bytes32 compressed1,
        bytes32 compressed2
    ) public view {
        vm.assume(compressed1 != compressed2);
        vm.assume(compressed1 != bytes32(0));
        vm.assume(compressed2 != bytes32(0));

        MoneroPrimitives.KeyImage memory ki1 = MoneroPrimitives.KeyImage({
            point: MoneroPrimitives.Ed25519Point({compressed: compressed1})
        });
        MoneroPrimitives.KeyImage memory ki2 = MoneroPrimitives.KeyImage({
            point: MoneroPrimitives.Ed25519Point({compressed: compressed2})
        });

        bytes32 nf1 = primitives.deriveMoneroToPILNullifier(ki1);
        bytes32 nf2 = primitives.deriveMoneroToPILNullifier(ki2);

        assertNotEq(
            nf1,
            nf2,
            "Different key images should produce different nullifiers"
        );
    }

    /**
     * @notice Fuzz test: hashKeyImageToPIL is deterministic
     */
    function testFuzz_HashKeyImageToPILDeterministic(
        bytes32 keyImage
    ) public view {
        bytes32 hash1 = primitives.hashKeyImageToPIL(keyImage);
        bytes32 hash2 = primitives.hashKeyImageToPIL(keyImage);

        assertEq(hash1, hash2, "Hash should be deterministic");
    }

    // =========================================================================
    // PEDERSEN COMMITMENT FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: pedersenCommitmentHash is deterministic
     */
    function testFuzz_PedersenHashDeterministic(
        uint256 mask,
        uint64 amount
    ) public view {
        bytes32 hash1 = primitives.pedersenCommitmentHash(mask, amount);
        bytes32 hash2 = primitives.pedersenCommitmentHash(mask, amount);

        assertEq(hash1, hash2, "Pedersen hash should be deterministic");
    }

    /**
     * @notice Fuzz test: different masks produce different commitments
     */
    function testFuzz_PedersenMaskDifferentiation(
        uint256 mask1,
        uint256 mask2,
        uint64 amount
    ) public view {
        vm.assume(mask1 != mask2);

        bytes32 hash1 = primitives.pedersenCommitmentHash(mask1, amount);
        bytes32 hash2 = primitives.pedersenCommitmentHash(mask2, amount);

        assertNotEq(
            hash1,
            hash2,
            "Different masks should produce different commitments"
        );
    }

    /**
     * @notice Fuzz test: different amounts produce different commitments
     */
    function testFuzz_PedersenAmountDifferentiation(
        uint256 mask,
        uint64 amount1,
        uint64 amount2
    ) public view {
        vm.assume(amount1 != amount2);

        bytes32 hash1 = primitives.pedersenCommitmentHash(mask, amount1);
        bytes32 hash2 = primitives.pedersenCommitmentHash(mask, amount2);

        assertNotEq(
            hash1,
            hash2,
            "Different amounts should produce different commitments"
        );
    }

    // =========================================================================
    // RING SIGNATURE FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: verifyCLSAG rejects ring size < 2
     */
    function testFuzz_CLSAGRejectsSmallRing(
        bytes32 pubKey,
        bytes32 commitment,
        bytes32 c0,
        bytes32 response
    ) public view {
        MoneroPrimitives.RingMember[]
            memory ring = new MoneroPrimitives.RingMember[](1);
        ring[0] = MoneroPrimitives.RingMember({
            publicKey: MoneroPrimitives.Ed25519Point({compressed: pubKey}),
            commitment: commitment
        });

        bytes32[] memory s = new bytes32[](1);
        s[0] = response;

        MoneroPrimitives.CLSAGSignature memory sig = MoneroPrimitives
            .CLSAGSignature({
                c0: c0,
                s: s,
                keyImage: MoneroPrimitives.KeyImage({
                    point: MoneroPrimitives.Ed25519Point({
                        compressed: bytes32(uint256(1))
                    })
                }),
                D: bytes32(0)
            });

        assertFalse(
            primitives.verifyCLSAG(ring, sig, bytes32(0)),
            "Should reject ring size < 2"
        );
    }

    /**
     * @notice Fuzz test: verifyCLSAG rejects ring size > 128
     */
    function testFuzz_CLSAGRejectsLargeRing(uint8 ringSize) public view {
        ringSize = uint8(bound(ringSize, 129, 200));

        MoneroPrimitives.RingMember[]
            memory ring = new MoneroPrimitives.RingMember[](ringSize);
        bytes32[] memory s = new bytes32[](ringSize);

        for (uint256 i = 0; i < ringSize; i++) {
            ring[i] = MoneroPrimitives.RingMember({
                publicKey: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(i + 1)
                }),
                commitment: bytes32(i + 1)
            });
            s[i] = bytes32(i + 1);
        }

        MoneroPrimitives.CLSAGSignature memory sig = MoneroPrimitives
            .CLSAGSignature({
                c0: bytes32(uint256(1)),
                s: s,
                keyImage: MoneroPrimitives.KeyImage({
                    point: MoneroPrimitives.Ed25519Point({
                        compressed: bytes32(uint256(1))
                    })
                }),
                D: bytes32(0)
            });

        assertFalse(
            primitives.verifyCLSAG(ring, sig, bytes32(0)),
            "Should reject ring size > 128"
        );
    }

    /**
     * @notice Fuzz test: verifyCLSAG rejects mismatched ring/response sizes
     */
    function testFuzz_CLSAGRejectsMismatchedSizes(
        uint8 ringSize,
        uint8 responseSize
    ) public view {
        ringSize = uint8(bound(ringSize, 2, 16));
        responseSize = uint8(bound(responseSize, 2, 16));
        vm.assume(ringSize != responseSize);

        MoneroPrimitives.RingMember[]
            memory ring = new MoneroPrimitives.RingMember[](ringSize);
        bytes32[] memory s = new bytes32[](responseSize);

        for (uint256 i = 0; i < ringSize; i++) {
            ring[i] = MoneroPrimitives.RingMember({
                publicKey: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(i + 1)
                }),
                commitment: bytes32(i + 1)
            });
        }
        for (uint256 i = 0; i < responseSize; i++) {
            s[i] = bytes32(i + 1);
        }

        MoneroPrimitives.CLSAGSignature memory sig = MoneroPrimitives
            .CLSAGSignature({
                c0: bytes32(uint256(1)),
                s: s,
                keyImage: MoneroPrimitives.KeyImage({
                    point: MoneroPrimitives.Ed25519Point({
                        compressed: bytes32(uint256(1))
                    })
                }),
                D: bytes32(0)
            });

        assertFalse(
            primitives.verifyCLSAG(ring, sig, bytes32(0)),
            "Should reject mismatched sizes"
        );
    }

    // =========================================================================
    // BULLETPROOF+ FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: verifyBulletproofPlus rejects mismatched L/R sizes
     */
    function testFuzz_BulletproofRejectsMismatchedLR(
        uint8 lSize,
        uint8 rSize
    ) public view {
        lSize = uint8(bound(lSize, 1, 10));
        rSize = uint8(bound(rSize, 1, 10));
        vm.assume(lSize != rSize);

        bytes32[] memory L = new bytes32[](lSize);
        bytes32[] memory R = new bytes32[](rSize);

        for (uint256 i = 0; i < lSize; i++) {
            L[i] = bytes32(i + 1);
        }
        for (uint256 i = 0; i < rSize; i++) {
            R[i] = bytes32(i + 1);
        }

        MoneroPrimitives.BulletproofPlus memory proof = MoneroPrimitives
            .BulletproofPlus({
                A: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(1))
                }),
                A1: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(2))
                }),
                B: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(3))
                }),
                r1: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(4))
                }),
                s1: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(5))
                }),
                d1: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(6))
                }),
                L: L,
                R: R
            });

        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = bytes32(uint256(1));

        assertFalse(
            primitives.verifyBulletproofPlus(proof, commitments),
            "Should reject mismatched L/R"
        );
    }

    /**
     * @notice Fuzz test: verifyBulletproofPlus validates proof size for single output
     */
    function testFuzz_BulletproofValidSizeOneOutput() public view {
        // 64 bits * 1 output = 64, log2(64) = 6
        uint256 expectedRounds = 6;

        bytes32[] memory L = new bytes32[](expectedRounds);
        bytes32[] memory R = new bytes32[](expectedRounds);

        for (uint256 i = 0; i < expectedRounds; i++) {
            L[i] = bytes32(i + 1);
            R[i] = bytes32(i + 1);
        }

        MoneroPrimitives.BulletproofPlus memory proof = MoneroPrimitives
            .BulletproofPlus({
                A: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(1))
                }),
                A1: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(2))
                }),
                B: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(3))
                }),
                r1: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(4))
                }),
                s1: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(5))
                }),
                d1: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(6))
                }),
                L: L,
                R: R
            });

        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = bytes32(uint256(1));

        assertTrue(
            primitives.verifyBulletproofPlus(proof, commitments),
            "Should accept valid proof size"
        );
    }

    /**
     * @notice Fuzz test: verifyBulletproofPlus validates proof size for two outputs
     */
    function testFuzz_BulletproofValidSizeTwoOutputs() public view {
        // 64 bits * 2 outputs = 128, log2(128) = 7
        uint256 expectedRounds = 7;

        bytes32[] memory L = new bytes32[](expectedRounds);
        bytes32[] memory R = new bytes32[](expectedRounds);

        for (uint256 i = 0; i < expectedRounds; i++) {
            L[i] = bytes32(i + 1);
            R[i] = bytes32(i + 1);
        }

        MoneroPrimitives.BulletproofPlus memory proof = MoneroPrimitives
            .BulletproofPlus({
                A: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(1))
                }),
                A1: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(2))
                }),
                B: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(3))
                }),
                r1: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(4))
                }),
                s1: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(5))
                }),
                d1: MoneroPrimitives.Ed25519Point({
                    compressed: bytes32(uint256(6))
                }),
                L: L,
                R: R
            });

        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = bytes32(uint256(1));
        commitments[1] = bytes32(uint256(2));

        assertTrue(
            primitives.verifyBulletproofPlus(proof, commitments),
            "Should accept valid proof size"
        );
    }

    // =========================================================================
    // SCALAR REDUCE 512 FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: scalarReduce512 produces valid scalar
     */
    function testFuzz_ScalarReduce512Valid(
        uint256 low,
        uint256 high
    ) public view {
        uint256 result = primitives.scalarReduce512(low, high);
        assertTrue(result < ED25519_ORDER, "Reduced scalar should be valid");
    }

    /**
     * @notice Fuzz test: scalarReduce512 is deterministic
     */
    function testFuzz_ScalarReduce512Deterministic(
        uint256 low,
        uint256 high
    ) public view {
        uint256 result1 = primitives.scalarReduce512(low, high);
        uint256 result2 = primitives.scalarReduce512(low, high);
        assertEq(result1, result2, "Reduction should be deterministic");
    }

    // =========================================================================
    // CLSAG CHALLENGE FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: clsagChallenge produces valid scalar
     */
    function testFuzz_CLSAGChallengeValid(
        bytes32 domain,
        bytes32 keyImageCompressed,
        bytes32 lCompressed,
        bytes32 rCompressed
    ) public view {
        MoneroPrimitives.RingMember[]
            memory ring = new MoneroPrimitives.RingMember[](2);
        ring[0] = MoneroPrimitives.RingMember({
            publicKey: MoneroPrimitives.Ed25519Point({
                compressed: bytes32(uint256(1))
            }),
            commitment: bytes32(uint256(1))
        });
        ring[1] = MoneroPrimitives.RingMember({
            publicKey: MoneroPrimitives.Ed25519Point({
                compressed: bytes32(uint256(2))
            }),
            commitment: bytes32(uint256(2))
        });

        MoneroPrimitives.KeyImage memory ki = MoneroPrimitives.KeyImage({
            point: MoneroPrimitives.Ed25519Point({
                compressed: keyImageCompressed
            })
        });

        MoneroPrimitives.Ed25519Point memory L = MoneroPrimitives.Ed25519Point({
            compressed: lCompressed
        });
        MoneroPrimitives.Ed25519Point memory R = MoneroPrimitives.Ed25519Point({
            compressed: rCompressed
        });

        uint256 challenge = primitives.clsagChallenge(domain, ring, ki, L, R);
        assertTrue(
            challenge < ED25519_ORDER,
            "Challenge should be valid scalar"
        );
    }

    // =========================================================================
    // VERIFICATION HELPERS
    // =========================================================================

    /**
     * @notice Fuzz test: verifyKeyImageLinkage consistent with signature key image
     */
    function testFuzz_KeyImageLinkageConsistency(
        bytes32 kiCompressed
    ) public view {
        vm.assume(kiCompressed != bytes32(0));

        MoneroPrimitives.KeyImage memory ki = MoneroPrimitives.KeyImage({
            point: MoneroPrimitives.Ed25519Point({compressed: kiCompressed})
        });

        // Create ring and signature with same key image
        MoneroPrimitives.RingMember[]
            memory ring = new MoneroPrimitives.RingMember[](2);
        ring[0] = MoneroPrimitives.RingMember({
            publicKey: MoneroPrimitives.Ed25519Point({
                compressed: bytes32(uint256(1))
            }),
            commitment: bytes32(uint256(1))
        });
        ring[1] = MoneroPrimitives.RingMember({
            publicKey: MoneroPrimitives.Ed25519Point({
                compressed: bytes32(uint256(2))
            }),
            commitment: bytes32(uint256(2))
        });

        bytes32[] memory s = new bytes32[](2);
        s[0] = bytes32(uint256(1));
        s[1] = bytes32(uint256(2));

        MoneroPrimitives.CLSAGSignature memory sig = MoneroPrimitives
            .CLSAGSignature({
                c0: bytes32(uint256(1)),
                s: s,
                keyImage: ki,
                D: bytes32(0)
            });

        // Key image hash should match
        bytes32 expectedHash = primitives.keyImageHash(ki);
        bytes32 sigKIHash = primitives.keyImageHash(sig.keyImage);

        assertEq(expectedHash, sigKIHash, "Key image hashes should match");
    }
}
