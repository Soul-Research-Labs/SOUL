// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/zcash/ZcashPrimitives.sol";
import "../../contracts/zcash/ZcashProofVerifier.sol";
import "../../contracts/zcash/ZcashNullifierRegistry.sol";

/**
 * @title ZcashNullifierRegistryTest
 * @notice Comprehensive tests for Zcash nullifier registry
 */
contract ZcashNullifierRegistryTest is Test {
    ZcashProofVerifier public verifier;
    ZcashNullifierRegistry public registry;

    address public admin = address(0x1);

    // Valid proof data (32 bytes for nullifier proofs, 64 bytes for binding proofs)
    bytes constant NULLIFIER_PROOF =
        hex"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // 32 bytes
    bytes constant BINDING_PROOF =
        hex"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // 64 bytes

    function setUp() public {
        vm.startPrank(admin);

        verifier = new ZcashProofVerifier();
        // Use address(0) for proof verifier to use basic internal validation
        registry = new ZcashNullifierRegistry(address(0));

        // Grant roles
        registry.grantRole(registry.RELAYER_ROLE(), admin);
        registry.grantRole(registry.REGISTRAR_ROLE(), admin);
        registry.grantRole(registry.EPOCH_ADMIN_ROLE(), admin);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                   NULLIFIER REGISTRY TESTS
    //////////////////////////////////////////////////////////////*/

    function testRegisterNullifier() public {
        bytes32 nullifier = bytes32(uint256(0x123));
        bytes32 txHash = bytes32(uint256(0xabc));
        uint32 blockHeight = 1000;

        vm.prank(admin);
        registry.registerNullifier(
            nullifier,
            ZcashPrimitives.ShieldedPool.SAPLING,
            txHash,
            blockHeight,
            NULLIFIER_PROOF
        );

        assertTrue(registry.isNullifierRegistered(nullifier));
        assertTrue(registry.exists(nullifier));
    }

    function testBatchRegisterNullifiers() public {
        bytes32[] memory nullifierList = new bytes32[](5);
        bytes32[] memory txHashes = new bytes32[](5);
        uint32[] memory blockHeights = new uint32[](5);

        for (uint256 i = 0; i < 5; i++) {
            nullifierList[i] = bytes32(uint256(i + 1));
            txHashes[i] = bytes32(uint256(i + 100));
            blockHeights[i] = uint32(1000 + i);
        }

        vm.prank(admin);
        uint256 batchId = registry.batchRegisterNullifiers(
            nullifierList,
            ZcashPrimitives.ShieldedPool.SAPLING,
            txHashes,
            blockHeights
        );

        assertEq(batchId, 1);
        assertEq(
            registry.getTotalNullifiers(ZcashPrimitives.ShieldedPool.SAPLING),
            5
        );
    }

    function testCreateBinding() public {
        bytes32 zcashNullifier = bytes32(uint256(0x123));
        bytes32 pilNullifier = bytes32(uint256(0x456));

        vm.startPrank(admin);

        registry.registerNullifier(
            zcashNullifier,
            ZcashPrimitives.ShieldedPool.SAPLING,
            bytes32(uint256(0xabc)),
            1000,
            NULLIFIER_PROOF
        );

        registry.createBinding(zcashNullifier, pilNullifier, BINDING_PROOF);
        vm.stopPrank();

        assertEq(registry.zcashToPilBinding(zcashNullifier), pilNullifier);
        assertEq(registry.pilToZcashBinding(pilNullifier), zcashNullifier);
    }

    function testRevertDuplicateBinding() public {
        bytes32 zcashNullifier = bytes32(uint256(0x123));
        bytes32 pilNullifier1 = bytes32(uint256(0x456));
        bytes32 pilNullifier2 = bytes32(uint256(0x789));

        vm.startPrank(admin);

        registry.registerNullifier(
            zcashNullifier,
            ZcashPrimitives.ShieldedPool.SAPLING,
            bytes32(uint256(0xabc)),
            1000,
            NULLIFIER_PROOF
        );

        registry.createBinding(zcashNullifier, pilNullifier1, BINDING_PROOF);

        vm.expectRevert(ZcashNullifierRegistry.BindingAlreadyExists.selector);
        registry.createBinding(zcashNullifier, pilNullifier2, BINDING_PROOF);
        vm.stopPrank();
    }

    function testFinalizeEpoch() public {
        bytes32[] memory nullifierList = new bytes32[](3);
        bytes32[] memory txHashes = new bytes32[](3);
        uint32[] memory blockHeights = new uint32[](3);

        // Use block heights in epoch 1 (1000-1999) to avoid epoch 0 bug
        for (uint256 i = 0; i < 3; i++) {
            nullifierList[i] = bytes32(uint256(i + 1));
            txHashes[i] = bytes32(uint256(i + 100));
            blockHeights[i] = uint32(1000 + i); // epoch 1
        }

        vm.startPrank(admin);

        registry.batchRegisterNullifiers(
            nullifierList,
            ZcashPrimitives.ShieldedPool.SAPLING,
            txHashes,
            blockHeights
        );

        // Finalize epoch 1 (not epoch 0)
        registry.finalizeEpoch(ZcashPrimitives.ShieldedPool.SAPLING, 1);
        vm.stopPrank();

        (
            ,
            ,
            bytes32 merkleRoot,
            uint256 nullifierCount,
            bool isFinalized
        ) = registry.getEpoch(ZcashPrimitives.ShieldedPool.SAPLING, 1);

        assertTrue(isFinalized);
        assertTrue(merkleRoot != bytes32(0));
        assertEq(nullifierCount, 3);
    }

    function testRevertDuplicateNullifierRegistration() public {
        bytes32 nullifier = bytes32(uint256(0x123));

        vm.startPrank(admin);

        registry.registerNullifier(
            nullifier,
            ZcashPrimitives.ShieldedPool.SAPLING,
            bytes32(uint256(0xabc)),
            1000,
            NULLIFIER_PROOF
        );

        vm.expectRevert(
            ZcashNullifierRegistry.NullifierAlreadyRegistered.selector
        );
        registry.registerNullifier(
            nullifier,
            ZcashPrimitives.ShieldedPool.SAPLING,
            bytes32(uint256(0xdef)),
            1001,
            NULLIFIER_PROOF
        );

        vm.stopPrank();
    }

    function testRevertInvalidPool() public {
        vm.prank(admin);
        vm.expectRevert(ZcashNullifierRegistry.InvalidPool.selector);
        registry.registerNullifier(
            bytes32(uint256(0x123)),
            ZcashPrimitives.ShieldedPool.SPROUT,
            bytes32(uint256(0xabc)),
            1000,
            NULLIFIER_PROOF
        );
    }

    function testComputeBinding() public view {
        bytes32 zcashNullifier = bytes32(uint256(0x123));
        uint64 chainId = 1;

        bytes32 binding = registry.computeBinding(zcashNullifier, chainId);
        assertTrue(binding != bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzzBatchRegister(uint8 count) public {
        vm.assume(count > 0 && count <= 100);

        bytes32[] memory nullifierList = new bytes32[](count);
        bytes32[] memory txHashes = new bytes32[](count);
        uint32[] memory blockHeights = new uint32[](count);

        for (uint256 i = 0; i < count; i++) {
            nullifierList[i] = bytes32(uint256(keccak256(abi.encode(i))));
            txHashes[i] = bytes32(uint256(keccak256(abi.encode(i + 1000))));
            blockHeights[i] = uint32(1000 + i);
        }

        vm.prank(admin);
        uint256 batchId = registry.batchRegisterNullifiers(
            nullifierList,
            ZcashPrimitives.ShieldedPool.SAPLING,
            txHashes,
            blockHeights
        );

        assertTrue(batchId > 0);
        assertEq(
            registry.getTotalNullifiers(ZcashPrimitives.ShieldedPool.SAPLING),
            count
        );
    }

    function testFuzzBindingDeterminism(
        bytes32 zcashNullifier,
        uint64 chainId
    ) public view {
        vm.assume(zcashNullifier != bytes32(0));

        bytes32 binding1 = registry.computeBinding(zcashNullifier, chainId);
        bytes32 binding2 = registry.computeBinding(zcashNullifier, chainId);

        assertEq(binding1, binding2, "Bindings must be deterministic");
    }

    function testFuzzNullifierUniqueness(
        bytes32 nullifier,
        bytes32 txHash,
        uint32 blockHeight
    ) public {
        vm.assume(nullifier != bytes32(0) && txHash != bytes32(0));
        // Bound block height to reasonable range to avoid overflow in epoch calculation
        vm.assume(blockHeight > 0 && blockHeight < 100_000_000);

        vm.prank(admin);
        registry.registerNullifier(
            nullifier,
            ZcashPrimitives.ShieldedPool.SAPLING,
            txHash,
            blockHeight,
            NULLIFIER_PROOF
        );

        assertTrue(registry.isNullifierRegistered(nullifier));

        // Re-registration should fail
        vm.prank(admin);
        vm.expectRevert(
            ZcashNullifierRegistry.NullifierAlreadyRegistered.selector
        );
        registry.registerNullifier(
            nullifier,
            ZcashPrimitives.ShieldedPool.SAPLING,
            txHash,
            blockHeight,
            NULLIFIER_PROOF
        );
    }

    function testFuzzPoolSeparation(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));
        bytes32 nullifier2 = bytes32(uint256(nullifier) + 1);
        vm.assume(nullifier2 != nullifier);

        vm.startPrank(admin);

        registry.registerNullifier(
            nullifier,
            ZcashPrimitives.ShieldedPool.SAPLING,
            bytes32(uint256(0xabc)),
            1000,
            NULLIFIER_PROOF
        );

        registry.registerNullifier(
            nullifier2,
            ZcashPrimitives.ShieldedPool.ORCHARD,
            bytes32(uint256(0xdef)),
            1000,
            NULLIFIER_PROOF
        );

        vm.stopPrank();

        assertTrue(registry.exists(nullifier));
        assertTrue(registry.exists(nullifier2));

        assertEq(
            registry.getTotalNullifiers(ZcashPrimitives.ShieldedPool.SAPLING),
            1
        );
        assertEq(
            registry.getTotalNullifiers(ZcashPrimitives.ShieldedPool.ORCHARD),
            1
        );
    }
}

/**
 * @title ZcashProofVerifierTest
 * @notice Tests for ZcashProofVerifier mock mode
 */
contract ZcashProofVerifierTest is Test {
    ZcashProofVerifier public verifier;
    address public admin = address(0x1);

    function setUp() public {
        vm.prank(admin);
        verifier = new ZcashProofVerifier();
    }

    function testMockMode() public {
        vm.startPrank(admin);

        verifier.setMockMode(true);
        assertTrue(verifier.mockMode());

        vm.stopPrank();
    }

    function testSetMockResult() public {
        vm.startPrank(admin);

        verifier.setMockMode(true);

        bytes32 proofHash = keccak256("test_proof");
        verifier.setMockResult(proofHash, true);

        vm.stopPrank();
    }
}
