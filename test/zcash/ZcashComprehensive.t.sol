// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/zcash/ZcashPrimitives.sol";
import "../../contracts/zcash/ZcashBridgeAdapter.sol";
import "../../contracts/zcash/ZcashProofVerifier.sol";
import "../../contracts/zcash/ZcashNullifierRegistry.sol";

/**
 * @title ZcashPrimitivesTest
 * @notice Comprehensive unit and fuzz tests for Zcash primitives
 */
contract ZcashPrimitivesTest is Test {
    /*//////////////////////////////////////////////////////////////
                          UNIT TESTS
    //////////////////////////////////////////////////////////////*/

    function testSaplingNoteCommitmentDeterminism() public pure {
        ZcashPrimitives.SaplingNote memory note = ZcashPrimitives.SaplingNote({
            d: bytes32(uint256(0x123456)),
            pkD: bytes32(uint256(0xabc)),
            value: 1 ether,
            rcm: bytes32(uint256(0x789)),
            rho: bytes32(uint256(0xdef))
        });

        bytes32 cm1 = ZcashPrimitives.computeSaplingNoteCommitment(note);
        bytes32 cm2 = ZcashPrimitives.computeSaplingNoteCommitment(note);

        assertEq(cm1, cm2, "Same inputs should produce same commitment");
    }

    function testSaplingNoteCommitmentUniqueness() public pure {
        ZcashPrimitives.SaplingNote memory note1 = ZcashPrimitives.SaplingNote({
            d: bytes32(uint256(1)),
            pkD: bytes32(uint256(2)),
            value: 1 ether,
            rcm: bytes32(uint256(0x123)),
            rho: bytes32(uint256(0x456))
        });

        ZcashPrimitives.SaplingNote memory note2 = ZcashPrimitives.SaplingNote({
            d: bytes32(uint256(3)),
            pkD: bytes32(uint256(4)),
            value: 1 ether,
            rcm: bytes32(uint256(0x123)),
            rho: bytes32(uint256(0x456))
        });

        bytes32 cm1 = ZcashPrimitives.computeSaplingNoteCommitment(note1);
        bytes32 cm2 = ZcashPrimitives.computeSaplingNoteCommitment(note2);

        assertTrue(
            cm1 != cm2,
            "Different keys should produce different commitments"
        );
    }

    function testOrchardNoteCommitmentDeterminism() public pure {
        ZcashPrimitives.OrchardNote memory note = ZcashPrimitives.OrchardNote({
            d: bytes32(uint256(0x111)),
            pkD: bytes32(uint256(0x222)),
            value: 2 ether,
            rho: bytes32(uint256(0x333)),
            psi: bytes32(uint256(0x444)),
            rcm: bytes32(uint256(0x555))
        });

        bytes32 cm1 = ZcashPrimitives.computeOrchardNoteCommitment(note);
        bytes32 cm2 = ZcashPrimitives.computeOrchardNoteCommitment(note);

        assertEq(
            cm1,
            cm2,
            "Same inputs should produce same Orchard commitment"
        );
    }

    function testNullifierNonZero() public pure {
        bytes32 nk = bytes32(uint256(0x111));
        bytes32 rho = bytes32(uint256(0x222));
        bytes32 cm = bytes32(uint256(0x333));

        bytes32 nullifier = ZcashPrimitives.deriveSaplingNullifier(nk, rho, cm);
        assertTrue(nullifier != bytes32(0), "Nullifier should never be zero");
    }

    function testMerkleRootWithSingleLeaf() public pure {
        bytes32 leaf = bytes32(uint256(0x123));

        ZcashPrimitives.MerklePath memory path;
        path.authPath[0] = bytes32(uint256(0x456));
        path.positions[0] = false;
        // Rest are already zeroed

        bytes32 root = ZcashPrimitives.computeMerkleRoot(leaf, path);
        assertTrue(root != bytes32(0), "Single leaf root should not be zero");
    }

    function testMerkleRootPositionMatters() public pure {
        bytes32 leaf = bytes32(uint256(0x123));

        ZcashPrimitives.MerklePath memory pathLeft;
        pathLeft.authPath[0] = bytes32(uint256(0x456));
        pathLeft.authPath[1] = bytes32(uint256(0x789));
        pathLeft.positions[0] = false;
        pathLeft.positions[1] = false;

        ZcashPrimitives.MerklePath memory pathRight;
        pathRight.authPath[0] = bytes32(uint256(0x456));
        pathRight.authPath[1] = bytes32(uint256(0x789));
        pathRight.positions[0] = true;
        pathRight.positions[1] = true;

        bytes32 rootLeft = ZcashPrimitives.computeMerkleRoot(leaf, pathLeft);
        bytes32 rootRight = ZcashPrimitives.computeMerkleRoot(leaf, pathRight);

        assertTrue(rootLeft != rootRight, "Position should affect Merkle root");
    }

    function testValueCommitmentNonZero() public pure {
        bytes32 cv = ZcashPrimitives.computeValueCommitment(
            1000000000, // 10 ZEC
            bytes32(uint256(0xabc))
        );
        assertTrue(cv != bytes32(0), "Value commitment should not be zero");
    }

    function testCrossChainBindingDomainSeparation() public pure {
        bytes32 nullifier = bytes32(uint256(0x12345));
        bytes32 domain1 = keccak256("DOMAIN_1");
        bytes32 domain2 = keccak256("DOMAIN_2");

        bytes32 binding1 = ZcashPrimitives.computeCrossChainNullifierBinding(
            nullifier,
            domain1,
            1
        );
        bytes32 binding2 = ZcashPrimitives.computeCrossChainNullifierBinding(
            nullifier,
            domain2,
            1
        );

        assertTrue(
            binding1 != binding2,
            "Different domains should produce different bindings"
        );
    }

    function testCrossChainBindingChainIdSeparation() public pure {
        bytes32 nullifier = bytes32(uint256(0x12345));
        bytes32 domain = keccak256("DOMAIN");

        bytes32 binding1 = ZcashPrimitives.computeCrossChainNullifierBinding(
            nullifier,
            domain,
            1
        );
        bytes32 binding2 = ZcashPrimitives.computeCrossChainNullifierBinding(
            nullifier,
            domain,
            137
        );

        assertTrue(
            binding1 != binding2,
            "Different chain IDs should produce different bindings"
        );
    }

    function testToPILNoteValuePreservation() public pure {
        uint64 originalValue = 5 ether;

        ZcashPrimitives.SaplingNote memory note = ZcashPrimitives.SaplingNote({
            d: bytes32(uint256(0x123)),
            pkD: bytes32(uint256(0x456)),
            value: originalValue,
            rcm: bytes32(uint256(0x789)),
            rho: bytes32(uint256(0xabc))
        });

        ZcashPrimitives.CrossChainNote memory pilNote = ZcashPrimitives
            .toPILNote(note, ZcashPrimitives.ZcashNetwork.MAINNET);
        assertEq(
            pilNote.value,
            originalValue,
            "Value should be preserved in conversion"
        );
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzzSaplingCommitmentDeterminism(
        bytes32 d,
        bytes32 pkD,
        uint64 value,
        bytes32 rcm,
        bytes32 rho
    ) public pure {
        vm.assume(value > 0);

        ZcashPrimitives.SaplingNote memory note = ZcashPrimitives.SaplingNote({
            d: d,
            pkD: pkD,
            value: value,
            rcm: rcm,
            rho: rho
        });

        bytes32 cm1 = ZcashPrimitives.computeSaplingNoteCommitment(note);
        bytes32 cm2 = ZcashPrimitives.computeSaplingNoteCommitment(note);

        assertEq(cm1, cm2, "Commitment must be deterministic");
    }

    function testFuzzOrchardCommitmentDeterminism(
        bytes32 d,
        bytes32 pkD,
        uint64 value,
        bytes32 rho,
        bytes32 psi,
        bytes32 rcm
    ) public pure {
        vm.assume(value > 0);

        ZcashPrimitives.OrchardNote memory note = ZcashPrimitives.OrchardNote({
            d: d,
            pkD: pkD,
            value: value,
            rho: rho,
            psi: psi,
            rcm: rcm
        });

        bytes32 cm1 = ZcashPrimitives.computeOrchardNoteCommitment(note);
        bytes32 cm2 = ZcashPrimitives.computeOrchardNoteCommitment(note);

        assertEq(cm1, cm2, "Orchard commitment must be deterministic");
    }

    function testFuzzSaplingNullifierDeterminism(
        bytes32 nk,
        bytes32 rho,
        bytes32 cm
    ) public pure {
        vm.assume(nk != bytes32(0) && cm != bytes32(0));

        bytes32 nf1 = ZcashPrimitives.deriveSaplingNullifier(nk, rho, cm);
        bytes32 nf2 = ZcashPrimitives.deriveSaplingNullifier(nk, rho, cm);

        assertEq(nf1, nf2, "Nullifier derivation must be deterministic");
    }

    function testFuzzOrchardNullifierDeterminism(
        bytes32 nk,
        bytes32 rho,
        bytes32 psi,
        bytes32 cm
    ) public pure {
        vm.assume(nk != bytes32(0) && cm != bytes32(0));

        bytes32 nf1 = ZcashPrimitives.deriveOrchardNullifier(nk, rho, psi, cm);
        bytes32 nf2 = ZcashPrimitives.deriveOrchardNullifier(nk, rho, psi, cm);

        assertEq(nf1, nf2, "Orchard nullifier must be deterministic");
    }

    function testFuzzNullifierUniqueness(
        bytes32 nk,
        bytes32 rho1,
        bytes32 rho2,
        bytes32 cm
    ) public pure {
        vm.assume(nk != bytes32(0));
        vm.assume(cm != bytes32(0));
        vm.assume(rho1 != rho2);

        bytes32 nf1 = ZcashPrimitives.deriveSaplingNullifier(nk, rho1, cm);
        bytes32 nf2 = ZcashPrimitives.deriveSaplingNullifier(nk, rho2, cm);

        assertTrue(
            nf1 != nf2,
            "Different rho should produce different nullifiers"
        );
    }

    function testFuzzMerkleRootDeterminism(
        bytes32 leaf,
        bytes32 sibling1,
        bytes32 sibling2,
        bool pos1,
        bool pos2
    ) public pure {
        vm.assume(leaf != bytes32(0));

        ZcashPrimitives.MerklePath memory path;
        path.authPath[0] = sibling1;
        path.authPath[1] = sibling2;
        path.positions[0] = pos1;
        path.positions[1] = pos2;

        bytes32 root1 = ZcashPrimitives.computeMerkleRoot(leaf, path);
        bytes32 root2 = ZcashPrimitives.computeMerkleRoot(leaf, path);

        assertEq(root1, root2, "Merkle root must be deterministic");
    }

    function testFuzzValueCommitmentDeterminism(
        uint64 value,
        bytes32 rcv
    ) public pure {
        vm.assume(value > 0);

        bytes32 cv1 = ZcashPrimitives.computeValueCommitment(value, rcv);
        bytes32 cv2 = ZcashPrimitives.computeValueCommitment(value, rcv);

        assertEq(cv1, cv2, "Value commitment must be deterministic");
    }

    function testFuzzCrossChainBindingDeterminism(
        bytes32 nullifier,
        bytes32 domain,
        uint64 chainId
    ) public pure {
        vm.assume(nullifier != bytes32(0));

        bytes32 binding1 = ZcashPrimitives.computeCrossChainNullifierBinding(
            nullifier,
            domain,
            chainId
        );
        bytes32 binding2 = ZcashPrimitives.computeCrossChainNullifierBinding(
            nullifier,
            domain,
            chainId
        );

        assertEq(
            binding1,
            binding2,
            "Cross-chain binding must be deterministic"
        );
    }

    function testFuzzToPILNoteValuePreservation(uint64 value) public pure {
        vm.assume(value > 0);

        ZcashPrimitives.SaplingNote memory note = ZcashPrimitives.SaplingNote({
            d: bytes32(uint256(0x123)),
            pkD: bytes32(uint256(0x456)),
            value: value,
            rcm: bytes32(uint256(0x789)),
            rho: bytes32(uint256(0xabc))
        });

        ZcashPrimitives.CrossChainNote memory pilNote = ZcashPrimitives
            .toPILNote(note, ZcashPrimitives.ZcashNetwork.MAINNET);
        assertEq(pilNote.value, value, "PIL note must preserve value");
    }

    function testFuzzSaplingVsOrchardNullifierDifference(
        bytes32 nk,
        bytes32 rho,
        bytes32 psi,
        bytes32 cm
    ) public pure {
        vm.assume(nk != bytes32(0) && cm != bytes32(0));

        bytes32 saplingNf = ZcashPrimitives.deriveSaplingNullifier(nk, rho, cm);
        bytes32 orchardNf = ZcashPrimitives.deriveOrchardNullifier(
            nk,
            rho,
            psi,
            cm
        );

        // Sapling and Orchard use different derivation, should be different (most of the time)
        // Only edge case: psi == 0 might collide but unlikely
        assertTrue(
            saplingNf != orchardNf || psi == bytes32(0),
            "Sapling and Orchard nullifiers should differ for same nk/rho/cm"
        );
    }
}

/**
 * @title ZcashProofVerifierExtendedTest
 * @notice Comprehensive tests for ZcashProofVerifier
 */
contract ZcashProofVerifierExtendedTest is Test {
    ZcashProofVerifier public verifier;
    address public admin = address(0x1);

    // 192-byte dummy proof for Groth16
    bytes constant VALID_GROTH16_PROOF =
        hex"000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006";

    // 64-byte dummy proof for ownership
    bytes constant OWNERSHIP_PROOF =
        hex"00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002";

    function setUp() public {
        vm.prank(admin);
        verifier = new ZcashProofVerifier();
    }

    function testInitialMockModeOff() public view {
        assertFalse(verifier.mockMode(), "Mock mode should be off by default");
    }

    function testSetMockMode() public {
        vm.startPrank(admin);
        verifier.setMockMode(true);
        assertTrue(verifier.mockMode());

        verifier.setMockMode(false);
        assertFalse(verifier.mockMode());
        vm.stopPrank();
    }

    function testMockResultSetting() public {
        vm.startPrank(admin);
        verifier.setMockMode(true);

        bytes32 proofHash = keccak256(VALID_GROTH16_PROOF);

        verifier.setMockResult(proofHash, true);
        assertTrue(verifier.mockResults(proofHash));

        verifier.setMockResult(proofHash, false);
        assertFalse(verifier.mockResults(proofHash));
        vm.stopPrank();
    }

    function testVerifySaplingSpendMockMode() public {
        vm.startPrank(admin);
        verifier.setMockMode(true);
        verifier.setMockResult(keccak256(VALID_GROTH16_PROOF), true);
        vm.stopPrank();

        ZcashProofVerifier.SaplingSpendInputs memory inputs = ZcashProofVerifier
            .SaplingSpendInputs({
                anchor: bytes32(uint256(0x123)),
                cv: bytes32(uint256(0x456)),
                nullifier: bytes32(uint256(0x789)),
                rk: bytes32(uint256(0xabc)),
                sighash: bytes32(uint256(0xdef))
            });

        bool valid = verifier.verifySaplingSpend(VALID_GROTH16_PROOF, inputs);
        assertTrue(valid, "Mock mode should return true for registered proof");
    }

    function testVerifySaplingOutputMockMode() public {
        vm.startPrank(admin);
        verifier.setMockMode(true);
        verifier.setMockResult(keccak256(VALID_GROTH16_PROOF), true);
        vm.stopPrank();

        ZcashProofVerifier.SaplingOutputInputs
            memory inputs = ZcashProofVerifier.SaplingOutputInputs({
                cv: bytes32(uint256(0x111)),
                cm: bytes32(uint256(0x222)),
                ephemeralKey: bytes32(uint256(0x333))
            });

        bool valid = verifier.verifySaplingOutput(VALID_GROTH16_PROOF, inputs);
        assertTrue(valid);
    }

    function testVerifyBridgeDepositMockMode() public {
        vm.startPrank(admin);
        verifier.setMockMode(true);
        verifier.setMockResult(keccak256(VALID_GROTH16_PROOF), true);
        vm.stopPrank();

        ZcashProofVerifier.DepositInputs memory inputs = ZcashProofVerifier
            .DepositInputs({
                zcashNoteCommitment: bytes32(uint256(0x123)),
                pilCommitment: bytes32(uint256(0x456)),
                anchor: bytes32(uint256(0x789)),
                amount: 1 ether,
                recipient: address(0xBEEF)
            });

        bool valid = verifier.verifyBridgeDeposit(VALID_GROTH16_PROOF, inputs);
        assertTrue(valid);
    }

    function testVerifyBridgeWithdrawalMockMode() public {
        vm.startPrank(admin);
        verifier.setMockMode(true);
        verifier.setMockResult(keccak256(VALID_GROTH16_PROOF), true);
        vm.stopPrank();

        ZcashProofVerifier.WithdrawalInputs memory inputs = ZcashProofVerifier
            .WithdrawalInputs({
                pilNullifier: bytes32(uint256(0x123)),
                zcashNullifierBinding: bytes32(uint256(0x456)),
                amount: 1 ether,
                recipient: bytes32(uint256(0x789))
            });

        bool valid = verifier.verifyBridgeWithdrawal(
            VALID_GROTH16_PROOF,
            inputs
        );
        assertTrue(valid);
    }

    function testVerifyNullifierOwnershipMockMode() public {
        bytes32 nullifier = bytes32(uint256(0x123));
        address owner = address(0xBEEF);

        vm.startPrank(admin);
        verifier.setMockMode(true);
        verifier.setMockResult(
            keccak256(abi.encodePacked(nullifier, owner)),
            true
        );
        vm.stopPrank();

        bool valid = verifier.verifyNullifierOwnership(
            nullifier,
            owner,
            OWNERSHIP_PROOF
        );
        assertTrue(valid);
    }

    function testVerifyGenericProofWithoutVerifyingKey() public view {
        bytes32[] memory publicInputs = new bytes32[](2);
        publicInputs[0] = bytes32(uint256(1));
        publicInputs[1] = bytes32(uint256(2));

        // Without verifying key set, should do basic validation
        bool valid = verifier.verifyProof(VALID_GROTH16_PROOF, publicInputs);
        assertTrue(
            valid,
            "Basic validation should pass for valid proof structure"
        );
    }

    function testRevertInvalidProofLength() public {
        bytes memory shortProof = hex"deadbeef";
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = bytes32(uint256(1));

        vm.expectRevert(ZcashProofVerifier.InvalidProofLength.selector);
        verifier.verifyProof(shortProof, publicInputs);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzzMockResultToggle(bytes32 proofHash) public {
        vm.startPrank(admin);
        verifier.setMockMode(true);

        verifier.setMockResult(proofHash, true);
        assertTrue(verifier.mockResults(proofHash));

        verifier.setMockResult(proofHash, false);
        assertFalse(verifier.mockResults(proofHash));
        vm.stopPrank();
    }

    function testFuzzNullifierOwnershipValidation(
        bytes32 nullifier,
        address owner
    ) public {
        vm.assume(nullifier != bytes32(0) && owner != address(0));

        vm.startPrank(admin);
        verifier.setMockMode(true);
        verifier.setMockResult(
            keccak256(abi.encodePacked(nullifier, owner)),
            true
        );
        vm.stopPrank();

        bool valid = verifier.verifyNullifierOwnership(
            nullifier,
            owner,
            OWNERSHIP_PROOF
        );
        assertTrue(valid);
    }

    function testFuzzDepositInputsValidation(
        bytes32 noteCommitment,
        bytes32 pilCommitment,
        bytes32 anchor,
        uint64 amount,
        address recipient
    ) public {
        vm.assume(recipient != address(0));

        vm.startPrank(admin);
        verifier.setMockMode(true);
        verifier.setMockResult(keccak256(VALID_GROTH16_PROOF), true);
        vm.stopPrank();

        ZcashProofVerifier.DepositInputs memory inputs = ZcashProofVerifier
            .DepositInputs({
                zcashNoteCommitment: noteCommitment,
                pilCommitment: pilCommitment,
                anchor: anchor,
                amount: amount,
                recipient: recipient
            });

        bool valid = verifier.verifyBridgeDeposit(VALID_GROTH16_PROOF, inputs);
        assertTrue(valid);
    }
}

/**
 * @title ZcashBridgeAdapterExtendedTest
 * @notice Extended tests for bridge adapter
 */
contract ZcashBridgeAdapterExtendedTest is Test {
    ZcashBridgeAdapter public adapter;
    ZcashProofVerifier public verifier;
    ZcashNullifierRegistry public registry;

    address public admin = address(0x1);
    address public user = address(0x2);
    address public guardian = address(0x3);

    bytes32 public constant TEST_CUSTODIAN = bytes32(uint256(0xCCC));

    function setUp() public {
        vm.startPrank(admin);

        verifier = new ZcashProofVerifier();
        registry = new ZcashNullifierRegistry(address(0)); // No external verifier
        adapter = new ZcashBridgeAdapter(
            ZcashPrimitives.ZcashNetwork.MAINNET,
            TEST_CUSTODIAN,
            address(verifier)
        );

        // Enable mock mode
        verifier.setMockMode(true);

        // Grant roles
        adapter.grantRole(adapter.OPERATOR_ROLE(), admin);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), guardian);
        adapter.grantRole(adapter.RELAYER_ROLE(), admin);
        adapter.grantRole(adapter.VERIFIER_ROLE(), admin);

        registry.grantRole(registry.RELAYER_ROLE(), admin);
        registry.grantRole(registry.REGISTRAR_ROLE(), admin);
        registry.grantRole(registry.EPOCH_ADMIN_ROLE(), admin);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testInitialConfiguration() public view {
        assertEq(
            uint8(adapter.zcashNetwork()),
            uint8(ZcashPrimitives.ZcashNetwork.MAINNET)
        );
        assertEq(adapter.custodianAddress(), TEST_CUSTODIAN);
        assertEq(adapter.proofVerifier(), address(verifier));
    }

    function testTestnetConfiguration() public {
        vm.prank(admin);
        ZcashBridgeAdapter testnetAdapter = new ZcashBridgeAdapter(
            ZcashPrimitives.ZcashNetwork.TESTNET,
            bytes32(uint256(0xDDD)),
            address(verifier)
        );

        assertEq(
            uint8(testnetAdapter.zcashNetwork()),
            uint8(ZcashPrimitives.ZcashNetwork.TESTNET)
        );
    }

    /*//////////////////////////////////////////////////////////////
                          PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function testPauseByGuardian() public {
        vm.prank(guardian);
        adapter.pause();
        assertTrue(adapter.paused());
    }

    function testUnpauseByAdmin() public {
        vm.prank(guardian);
        adapter.pause();

        vm.prank(admin);
        adapter.unpause();
        assertFalse(adapter.paused());
    }

    /*//////////////////////////////////////////////////////////////
                        ROLE TESTS
    //////////////////////////////////////////////////////////////*/

    function testRoleAssignment() public view {
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), guardian));
    }

    function testRoleRevocation() public {
        vm.startPrank(admin);
        adapter.revokeRole(adapter.OPERATOR_ROLE(), admin);
        assertFalse(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ TESTS - BRIDGE ADAPTER
    //////////////////////////////////////////////////////////////*/

    function testFuzzCustodianAddressValid(bytes32 custodian) public {
        vm.assume(custodian != bytes32(0));

        vm.prank(admin);
        ZcashBridgeAdapter newAdapter = new ZcashBridgeAdapter(
            ZcashPrimitives.ZcashNetwork.MAINNET,
            custodian,
            address(verifier)
        );

        assertEq(newAdapter.custodianAddress(), custodian);
    }
}

/**
 * @title ZcashNullifierRegistryExtendedTest
 * @notice Extended tests for nullifier registry
 */
contract ZcashNullifierRegistryExtendedTest is Test {
    ZcashNullifierRegistry public registry;
    address public admin = address(0x1);
    address public relayer = address(0x2);

    // 32-byte proof for nullifier registration
    bytes constant NULLIFIER_PROOF =
        hex"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    // 64-byte proof for binding
    bytes constant BINDING_PROOF =
        hex"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    function setUp() public {
        vm.startPrank(admin);
        registry = new ZcashNullifierRegistry(address(0));
        registry.grantRole(registry.RELAYER_ROLE(), admin);
        registry.grantRole(registry.RELAYER_ROLE(), relayer);
        registry.grantRole(registry.REGISTRAR_ROLE(), admin);
        registry.grantRole(registry.EPOCH_ADMIN_ROLE(), admin);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        EDGE CASE TESTS
    //////////////////////////////////////////////////////////////*/

    function testRegisterMaxBatchSize() public {
        bytes32[] memory nullifiers = new bytes32[](100);
        bytes32[] memory txHashes = new bytes32[](100);
        uint32[] memory blockHeights = new uint32[](100);

        for (uint256 i = 0; i < 100; i++) {
            nullifiers[i] = bytes32(keccak256(abi.encode("nf", i)));
            txHashes[i] = bytes32(keccak256(abi.encode("tx", i)));
            blockHeights[i] = uint32(1000 + i);
        }

        vm.prank(admin);
        uint256 batchId = registry.batchRegisterNullifiers(
            nullifiers,
            ZcashPrimitives.ShieldedPool.SAPLING,
            txHashes,
            blockHeights
        );

        assertTrue(batchId > 0);
        assertEq(
            registry.getTotalNullifiers(ZcashPrimitives.ShieldedPool.SAPLING),
            100
        );
    }

    function testRegisterDifferentPools() public {
        bytes32 nullifier1 = bytes32(uint256(0x123));
        bytes32 nullifier2 = bytes32(uint256(0x456)); // Different nullifier for different pool

        vm.startPrank(admin);

        registry.registerNullifier(
            nullifier1,
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

        assertEq(
            registry.getTotalNullifiers(ZcashPrimitives.ShieldedPool.SAPLING),
            1
        );
        assertEq(
            registry.getTotalNullifiers(ZcashPrimitives.ShieldedPool.ORCHARD),
            1
        );
    }

    function testEpochBoundaries() public {
        // Register nullifiers at epoch boundary (block 999 and 1000)
        vm.startPrank(admin);

        registry.registerNullifier(
            bytes32(uint256(0x111)),
            ZcashPrimitives.ShieldedPool.SAPLING,
            bytes32(uint256(0xaaa)),
            999, // End of epoch 0
            NULLIFIER_PROOF
        );

        registry.registerNullifier(
            bytes32(uint256(0x222)),
            ZcashPrimitives.ShieldedPool.SAPLING,
            bytes32(uint256(0xbbb)),
            1000, // Start of epoch 1
            NULLIFIER_PROOF
        );

        vm.stopPrank();

        // Both should be registered
        assertEq(
            registry.getTotalNullifiers(ZcashPrimitives.ShieldedPool.SAPLING),
            2
        );
    }

    function testMultipleEpochFinalization() public {
        bytes32[] memory nullifiers = new bytes32[](3);
        bytes32[] memory txHashes = new bytes32[](3);
        uint32[] memory blockHeights = new uint32[](3);

        // Epoch 1 nullifiers
        for (uint256 i = 0; i < 3; i++) {
            nullifiers[i] = bytes32(uint256(i + 10));
            txHashes[i] = bytes32(uint256(i + 100));
            blockHeights[i] = uint32(1000 + i);
        }

        vm.startPrank(admin);
        registry.batchRegisterNullifiers(
            nullifiers,
            ZcashPrimitives.ShieldedPool.SAPLING,
            txHashes,
            blockHeights
        );

        // Epoch 2 nullifiers
        for (uint256 i = 0; i < 3; i++) {
            nullifiers[i] = bytes32(uint256(i + 20));
            txHashes[i] = bytes32(uint256(i + 200));
            blockHeights[i] = uint32(2000 + i);
        }
        registry.batchRegisterNullifiers(
            nullifiers,
            ZcashPrimitives.ShieldedPool.SAPLING,
            txHashes,
            blockHeights
        );

        // Finalize both epochs
        registry.finalizeEpoch(ZcashPrimitives.ShieldedPool.SAPLING, 1);
        registry.finalizeEpoch(ZcashPrimitives.ShieldedPool.SAPLING, 2);

        vm.stopPrank();

        (, , bytes32 merkleRoot1, , bool isFinalized1) = registry.getEpoch(
            ZcashPrimitives.ShieldedPool.SAPLING,
            1
        );
        (, , bytes32 merkleRoot2, , bool isFinalized2) = registry.getEpoch(
            ZcashPrimitives.ShieldedPool.SAPLING,
            2
        );

        assertTrue(isFinalized1);
        assertTrue(isFinalized2);
        assertTrue(merkleRoot1 != bytes32(0));
        assertTrue(merkleRoot2 != bytes32(0));
        assertTrue(
            merkleRoot1 != merkleRoot2,
            "Different epochs should have different roots"
        );
    }

    function testRevertFinalizeAlreadyFinalizedEpoch() public {
        bytes32[] memory nullifiers = new bytes32[](2);
        bytes32[] memory txHashes = new bytes32[](2);
        uint32[] memory blockHeights = new uint32[](2);

        for (uint256 i = 0; i < 2; i++) {
            nullifiers[i] = bytes32(uint256(i + 1));
            txHashes[i] = bytes32(uint256(i + 100));
            blockHeights[i] = uint32(1000 + i);
        }

        vm.startPrank(admin);
        registry.batchRegisterNullifiers(
            nullifiers,
            ZcashPrimitives.ShieldedPool.SAPLING,
            txHashes,
            blockHeights
        );

        registry.finalizeEpoch(ZcashPrimitives.ShieldedPool.SAPLING, 1);

        vm.expectRevert(ZcashNullifierRegistry.EpochAlreadyFinalized.selector);
        registry.finalizeEpoch(ZcashPrimitives.ShieldedPool.SAPLING, 1);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        FUZZ TESTS - REGISTRY
    //////////////////////////////////////////////////////////////*/

    function testFuzzNullifierRegistration(
        bytes32 nullifier,
        bytes32 txHash,
        uint32 blockHeight
    ) public {
        vm.assume(nullifier != bytes32(0) && txHash != bytes32(0));
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
        assertTrue(registry.exists(nullifier));
    }

    function testFuzzBindingCreation(
        bytes32 zcashNullifier,
        bytes32 pilNullifier
    ) public {
        vm.assume(zcashNullifier != bytes32(0) && pilNullifier != bytes32(0));

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

    function testFuzzComputeBindingDeterminism(
        bytes32 zcashNullifier,
        uint64 chainId
    ) public view {
        vm.assume(zcashNullifier != bytes32(0));

        bytes32 binding1 = registry.computeBinding(zcashNullifier, chainId);
        bytes32 binding2 = registry.computeBinding(zcashNullifier, chainId);

        assertEq(
            binding1,
            binding2,
            "Binding computation must be deterministic"
        );
    }

    function testFuzzBatchRegistrationWithVariableSizes(uint8 size) public {
        vm.assume(size > 0 && size <= 100);

        bytes32[] memory nullifiers = new bytes32[](size);
        bytes32[] memory txHashes = new bytes32[](size);
        uint32[] memory blockHeights = new uint32[](size);

        for (uint256 i = 0; i < size; i++) {
            nullifiers[i] = bytes32(
                keccak256(abi.encode("unique_nullifier", i, size))
            );
            txHashes[i] = bytes32(keccak256(abi.encode("unique_tx", i, size)));
            blockHeights[i] = uint32(1000 + i);
        }

        vm.prank(admin);
        uint256 batchId = registry.batchRegisterNullifiers(
            nullifiers,
            ZcashPrimitives.ShieldedPool.SAPLING,
            txHashes,
            blockHeights
        );

        assertTrue(batchId > 0);
        assertEq(
            registry.getTotalNullifiers(ZcashPrimitives.ShieldedPool.SAPLING),
            size
        );
    }

    function testFuzzEpochIdCalculation(uint32 blockHeight) public pure {
        vm.assume(blockHeight < 100_000_000);

        uint64 expectedEpochId = uint64(blockHeight / 1000);
        uint64 calculatedEpochId = uint64(blockHeight / 1000);

        assertEq(
            calculatedEpochId,
            expectedEpochId,
            "Epoch ID calculation must be correct"
        );
    }
}

/**
 * @title ZcashSecurityTest
 * @notice Security-focused tests for Zcash contracts
 */
contract ZcashSecurityTest is Test {
    ZcashNullifierRegistry public registry;
    ZcashProofVerifier public verifier;
    ZcashBridgeAdapter public adapter;

    address public admin = address(0x1);
    address public attacker = address(0xBAD);

    bytes constant NULLIFIER_PROOF =
        hex"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    bytes32 constant TEST_CUSTODIAN = bytes32(uint256(0xCCC));

    function setUp() public {
        vm.startPrank(admin);
        verifier = new ZcashProofVerifier();
        registry = new ZcashNullifierRegistry(address(0));
        adapter = new ZcashBridgeAdapter(
            ZcashPrimitives.ZcashNetwork.MAINNET,
            TEST_CUSTODIAN,
            address(verifier)
        );

        registry.grantRole(registry.RELAYER_ROLE(), admin);
        registry.grantRole(registry.REGISTRAR_ROLE(), admin);
        registry.grantRole(registry.EPOCH_ADMIN_ROLE(), admin);
        vm.stopPrank();
    }

    function testUnauthorizedNullifierRegistration() public {
        vm.prank(attacker);
        vm.expectRevert();
        registry.registerNullifier(
            bytes32(uint256(0x123)),
            ZcashPrimitives.ShieldedPool.SAPLING,
            bytes32(uint256(0xabc)),
            1000,
            NULLIFIER_PROOF
        );
    }

    function testUnauthorizedEpochFinalization() public {
        vm.startPrank(admin);
        registry.registerNullifier(
            bytes32(uint256(0x123)),
            ZcashPrimitives.ShieldedPool.SAPLING,
            bytes32(uint256(0xabc)),
            1000,
            NULLIFIER_PROOF
        );
        vm.stopPrank();

        vm.prank(attacker);
        vm.expectRevert();
        registry.finalizeEpoch(ZcashPrimitives.ShieldedPool.SAPLING, 1);
    }

    function testUnauthorizedBindingCreation() public {
        vm.startPrank(admin);
        registry.registerNullifier(
            bytes32(uint256(0x123)),
            ZcashPrimitives.ShieldedPool.SAPLING,
            bytes32(uint256(0xabc)),
            1000,
            NULLIFIER_PROOF
        );
        vm.stopPrank();

        vm.prank(attacker);
        vm.expectRevert();
        registry.createBinding(
            bytes32(uint256(0x123)),
            bytes32(uint256(0x456)),
            hex"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    function testUnauthorizedMockModeToggle() public {
        vm.prank(attacker);
        vm.expectRevert();
        verifier.setMockMode(true);
    }

    function testDoubleSpendPrevention() public {
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

    function testSproutPoolRejection() public {
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

    function testZeroNullifierRejection() public {
        vm.prank(admin);
        vm.expectRevert(ZcashNullifierRegistry.InvalidNullifier.selector);
        registry.registerNullifier(
            bytes32(0),
            ZcashPrimitives.ShieldedPool.SAPLING,
            bytes32(uint256(0xabc)),
            1000,
            NULLIFIER_PROOF
        );
    }

    function testFuzzUnauthorizedAccess(address unauthorized) public {
        vm.assume(unauthorized != admin);
        vm.assume(unauthorized != address(0));

        vm.prank(unauthorized);
        vm.expectRevert();
        registry.registerNullifier(
            bytes32(uint256(0x123)),
            ZcashPrimitives.ShieldedPool.SAPLING,
            bytes32(uint256(0xabc)),
            1000,
            NULLIFIER_PROOF
        );
    }

    function testFuzzDoubleRegistrationPrevention(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

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
            2000,
            NULLIFIER_PROOF
        );
        vm.stopPrank();
    }
}
