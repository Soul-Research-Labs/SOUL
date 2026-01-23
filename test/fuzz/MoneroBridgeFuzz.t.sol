// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/monero/MoneroPrimitives.sol";
import "../../contracts/crosschain/MoneroBridgeAdapter.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title MoneroBridgeFuzz
 * @author PIL Protocol
 * @notice Foundry fuzz tests for Monero Bridge Adapter
 */
contract MoneroBridgeFuzz is Test {
    MoneroPrimitives public primitives;
    MoneroBridgeAdapter public bridge;

    address public admin;
    address public relayer;
    address public custodian1;
    address public custodian2;
    address public custodian3;
    address public user;

    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant CUSTODIAN_ROLE = keccak256("CUSTODIAN_ROLE");
    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    function setUp() public {
        admin = address(0x1);
        relayer = address(0x2);
        custodian1 = address(0x3);
        custodian2 = address(0x4);
        custodian3 = address(0x5);
        user = address(0x6);

        // Deploy MoneroPrimitives
        primitives = new MoneroPrimitives();

        // Deploy MoneroBridgeAdapter via proxy
        MoneroBridgeAdapter implementation = new MoneroBridgeAdapter();
        bytes memory initData = abi.encodeWithSelector(
            MoneroBridgeAdapter.initialize.selector,
            admin,
            address(primitives),
            1, // PIL chain ID
            2 // Custodian threshold
        );
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );
        bridge = MoneroBridgeAdapter(address(proxy));

        // Setup roles
        vm.startPrank(admin);
        bridge.grantRole(RELAYER_ROLE, relayer);
        bridge.addCustodian(custodian1);
        bridge.addCustodian(custodian2);
        bridge.addCustodian(custodian3);
        vm.stopPrank();

        // Set initial deposited balance for withdrawal tests
        // Storage slot for totalDeposited is slot 81 (after all mappings and state vars)
        _setTotalDeposited(1000 ether);
    }

    /**
     * @notice Helper to set totalDeposited for testing withdrawals
     * @dev Uses vm.store to set storage directly
     */
    function _setTotalDeposited(uint256 amount) internal {
        // totalDeposited is at slot 8 (from `forge inspect MoneroBridgeAdapter storageLayout`)
        bytes32 slot = bytes32(uint256(8));
        vm.store(address(bridge), slot, bytes32(amount));
    }

    // =========================================================================
    // KEY IMAGE TRACKING FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: unused key images return false
     */
    function testFuzz_UnusedKeyImage(bytes32 keyImageHash) public view {
        assertFalse(
            bridge.isKeyImageUsed(keyImageHash),
            "Unused key image should return false"
        );
    }

    /**
     * @notice Fuzz test: unused key images have no PIL nullifier
     */
    function testFuzz_UnusedKeyImageNoPILNullifier(
        bytes32 keyImageHash
    ) public view {
        assertEq(
            bridge.getPILNullifier(keyImageHash),
            bytes32(0),
            "Should have no PIL nullifier"
        );
    }

    /**
     * @notice Fuzz test: unused PIL nullifiers return false
     */
    function testFuzz_UnusedPILNullifier(bytes32 pilNullifier) public view {
        assertFalse(
            bridge.isPILNullifierUsed(pilNullifier),
            "Unused PIL nullifier should return false"
        );
    }

    // =========================================================================
    // WITHDRAWAL REQUEST FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: withdrawal request marks nullifier as used
     */
    function testFuzz_WithdrawalMarksNullifierUsed(
        bytes32 pilNullifier,
        uint256 amount,
        bytes32 viewKey,
        bytes32 spendKey
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        vm.assume(viewKey != bytes32(0));
        vm.assume(spendKey != bytes32(0));
        // Bound amount to available balance (1000 ether set in setUp)
        amount = bound(amount, 1, 500 ether);

        vm.prank(user);
        bridge.requestWithdrawal(pilNullifier, amount, viewKey, spendKey);

        assertTrue(
            bridge.isPILNullifierUsed(pilNullifier),
            "Nullifier should be marked used"
        );
    }

    /**
     * @notice Fuzz test: cannot reuse PIL nullifier
     */
    function testFuzz_CannotReusePILNullifier(
        bytes32 pilNullifier,
        uint256 amount,
        bytes32 viewKey,
        bytes32 spendKey
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        vm.assume(viewKey != bytes32(0));
        vm.assume(spendKey != bytes32(0));
        // Bound amount to available balance
        amount = bound(amount, 1, 500 ether);

        vm.prank(user);
        bridge.requestWithdrawal(pilNullifier, amount, viewKey, spendKey);

        vm.expectRevert(MoneroBridgeAdapter.PILNullifierAlreadyUsed.selector);
        vm.prank(user);
        bridge.requestWithdrawal(pilNullifier, amount, viewKey, spendKey);
    }

    /**
     * @notice Fuzz test: zero amount rejected
     */
    function testFuzz_ZeroAmountRejected(
        bytes32 pilNullifier,
        bytes32 viewKey,
        bytes32 spendKey
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        vm.assume(viewKey != bytes32(0));
        vm.assume(spendKey != bytes32(0));

        vm.expectRevert(MoneroBridgeAdapter.InvalidAmount.selector);
        vm.prank(user);
        bridge.requestWithdrawal(pilNullifier, 0, viewKey, spendKey);
    }

    /**
     * @notice Fuzz test: zero view key rejected
     */
    function testFuzz_ZeroViewKeyRejected(
        bytes32 pilNullifier,
        uint256 amount,
        bytes32 spendKey
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        vm.assume(spendKey != bytes32(0));
        amount = bound(amount, 1, 500 ether);

        vm.expectRevert(MoneroBridgeAdapter.InvalidRecipientKeys.selector);
        vm.prank(user);
        bridge.requestWithdrawal(pilNullifier, amount, bytes32(0), spendKey);
    }

    /**
     * @notice Fuzz test: zero spend key rejected
     */
    function testFuzz_ZeroSpendKeyRejected(
        bytes32 pilNullifier,
        uint256 amount,
        bytes32 viewKey
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        vm.assume(viewKey != bytes32(0));
        amount = bound(amount, 1, 500 ether);

        vm.expectRevert(MoneroBridgeAdapter.InvalidRecipientKeys.selector);
        vm.prank(user);
        bridge.requestWithdrawal(pilNullifier, amount, viewKey, bytes32(0));
    }

    /**
     * @notice Fuzz test: withdrawal request emits event
     */
    function testFuzz_WithdrawalEmitsEvent(
        bytes32 pilNullifier,
        uint256 amount,
        bytes32 viewKey,
        bytes32 spendKey
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        vm.assume(viewKey != bytes32(0));
        vm.assume(spendKey != bytes32(0));
        amount = bound(amount, 1, 500 ether);

        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit MoneroBridgeAdapter.WithdrawalRequested(
            keccak256(
                abi.encodePacked(
                    pilNullifier,
                    amount,
                    viewKey,
                    spendKey,
                    block.timestamp
                )
            ),
            pilNullifier,
            amount,
            viewKey,
            spendKey
        );
        bridge.requestWithdrawal(pilNullifier, amount, viewKey, spendKey);
    }

    // =========================================================================
    // WITHDRAWAL SIGNING FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: custodian can sign withdrawal
     */
    function testFuzz_CustodianCanSign(
        bytes32 pilNullifier,
        uint256 amount,
        bytes32 viewKey,
        bytes32 spendKey
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        vm.assume(viewKey != bytes32(0));
        vm.assume(spendKey != bytes32(0));
        amount = bound(amount, 1, 500 ether);

        // Create withdrawal request
        vm.prank(user);
        bridge.requestWithdrawal(pilNullifier, amount, viewKey, spendKey);

        bytes32 requestId = keccak256(
            abi.encodePacked(
                pilNullifier,
                amount,
                viewKey,
                spendKey,
                block.timestamp
            )
        );

        // Custodian signs
        vm.prank(custodian1);
        vm.expectEmit(true, true, false, true);
        emit MoneroBridgeAdapter.WithdrawalSigned(requestId, custodian1, 1);
        bridge.signWithdrawal(requestId);
    }

    /**
     * @notice Fuzz test: non-custodian cannot sign
     */
    function testFuzz_NonCustodianCannotSign(
        bytes32 pilNullifier,
        uint256 amount,
        bytes32 viewKey,
        bytes32 spendKey
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        vm.assume(viewKey != bytes32(0));
        vm.assume(spendKey != bytes32(0));
        amount = bound(amount, 1, 500 ether);

        // Create withdrawal request
        vm.prank(user);
        bridge.requestWithdrawal(pilNullifier, amount, viewKey, spendKey);

        bytes32 requestId = keccak256(
            abi.encodePacked(
                pilNullifier,
                amount,
                viewKey,
                spendKey,
                block.timestamp
            )
        );

        // Non-custodian tries to sign
        vm.expectRevert();
        vm.prank(user);
        bridge.signWithdrawal(requestId);
    }

    /**
     * @notice Fuzz test: custodian cannot double-sign
     */
    function testFuzz_CustodianCannotDoubleSig(
        bytes32 pilNullifier,
        uint256 amount,
        bytes32 viewKey,
        bytes32 spendKey
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        vm.assume(viewKey != bytes32(0));
        vm.assume(spendKey != bytes32(0));
        amount = bound(amount, 1, 500 ether);

        // Create withdrawal request
        vm.prank(user);
        bridge.requestWithdrawal(pilNullifier, amount, viewKey, spendKey);

        bytes32 requestId = keccak256(
            abi.encodePacked(
                pilNullifier,
                amount,
                viewKey,
                spendKey,
                block.timestamp
            )
        );

        // First signature
        vm.prank(custodian1);
        bridge.signWithdrawal(requestId);

        // Second attempt
        vm.expectRevert(MoneroBridgeAdapter.WithdrawalAlreadySigned.selector);
        vm.prank(custodian1);
        bridge.signWithdrawal(requestId);
    }

    /**
     * @notice Fuzz test: signing non-existent request fails
     */
    function testFuzz_SignNonExistentRequest(bytes32 fakeRequestId) public {
        vm.expectRevert(MoneroBridgeAdapter.WithdrawalNotFound.selector);
        vm.prank(custodian1);
        bridge.signWithdrawal(fakeRequestId);
    }

    // =========================================================================
    // BLOCK HEADER FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: relayer can submit genesis block
     */
    function testFuzz_RelayerSubmitsGenesisBlock(
        bytes32 blockHash,
        bytes32 merkleRoot,
        uint64 timestamp,
        uint64 difficulty
    ) public {
        vm.assume(blockHash != bytes32(0));

        MoneroBridgeAdapter.MoneroBlockHeader
            memory header = MoneroBridgeAdapter.MoneroBlockHeader({
                blockHash: blockHash,
                prevHash: bytes32(0),
                merkleRoot: merkleRoot,
                height: 0,
                timestamp: timestamp,
                difficulty: difficulty,
                verified: false
            });

        vm.prank(relayer);
        vm.expectEmit(true, false, false, true);
        emit MoneroBridgeAdapter.BlockHeaderVerified(blockHash, 0);
        bridge.submitBlockHeader(header);
    }

    /**
     * @notice Fuzz test: non-relayer cannot submit block
     */
    function testFuzz_NonRelayerCannotSubmitBlock(
        bytes32 blockHash,
        bytes32 merkleRoot
    ) public {
        vm.assume(blockHash != bytes32(0));

        MoneroBridgeAdapter.MoneroBlockHeader
            memory header = MoneroBridgeAdapter.MoneroBlockHeader({
                blockHash: blockHash,
                prevHash: bytes32(0),
                merkleRoot: merkleRoot,
                height: 0,
                timestamp: uint64(block.timestamp),
                difficulty: 1000000,
                verified: false
            });

        vm.expectRevert();
        vm.prank(user);
        bridge.submitBlockHeader(header);
    }

    /**
     * @notice Fuzz test: zero block hash rejected
     */
    function testFuzz_ZeroBlockHashRejected(bytes32 merkleRoot) public {
        MoneroBridgeAdapter.MoneroBlockHeader
            memory header = MoneroBridgeAdapter.MoneroBlockHeader({
                blockHash: bytes32(0),
                prevHash: bytes32(0),
                merkleRoot: merkleRoot,
                height: 0,
                timestamp: uint64(block.timestamp),
                difficulty: 1000000,
                verified: false
            });

        vm.expectRevert(MoneroBridgeAdapter.InvalidBlockHeader.selector);
        vm.prank(relayer);
        bridge.submitBlockHeader(header);
    }

    /**
     * @notice Fuzz test: non-genesis requires existing previous
     */
    function testFuzz_NonGenesisRequiresPrevious(
        bytes32 blockHash,
        bytes32 prevHash,
        bytes32 merkleRoot
    ) public {
        vm.assume(blockHash != bytes32(0));
        vm.assume(prevHash != bytes32(0));

        MoneroBridgeAdapter.MoneroBlockHeader
            memory header = MoneroBridgeAdapter.MoneroBlockHeader({
                blockHash: blockHash,
                prevHash: prevHash,
                merkleRoot: merkleRoot,
                height: 1,
                timestamp: uint64(block.timestamp),
                difficulty: 1000000,
                verified: false
            });

        vm.expectRevert(MoneroBridgeAdapter.BlockNotVerified.selector);
        vm.prank(relayer);
        bridge.submitBlockHeader(header);
    }

    // =========================================================================
    // MERKLE PROOF FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: valid merkle proof verifies
     */
    function testFuzz_ValidMerkleProof(
        bytes32 leaf,
        bytes32 sibling
    ) public view {
        bytes32 root = keccak256(abi.encodePacked(leaf, sibling));
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        assertTrue(
            bridge.verifyMerkleProof(proof, root, leaf, 0),
            "Valid proof should verify"
        );
    }

    /**
     * @notice Fuzz test: invalid merkle proof fails
     */
    function testFuzz_InvalidMerkleProof(
        bytes32 leaf,
        bytes32 sibling,
        bytes32 wrongSibling
    ) public view {
        vm.assume(sibling != wrongSibling);

        bytes32 root = keccak256(abi.encodePacked(leaf, sibling));
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = wrongSibling;

        assertFalse(
            bridge.verifyMerkleProof(proof, root, leaf, 0),
            "Invalid proof should fail"
        );
    }

    /**
     * @notice Fuzz test: merkle proof with odd index
     */
    function testFuzz_MerkleProofOddIndex(
        bytes32 leaf,
        bytes32 sibling
    ) public view {
        bytes32 root = keccak256(abi.encodePacked(sibling, leaf));
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        assertTrue(
            bridge.verifyMerkleProof(proof, root, leaf, 1),
            "Odd index proof should verify"
        );
    }

    /**
     * @notice Fuzz test: deeper merkle proof
     */
    function testFuzz_DeepMerkleProof(
        bytes32 leaf,
        bytes32 sib1,
        bytes32 sib2
    ) public view {
        bytes32 node1 = keccak256(abi.encodePacked(leaf, sib1));
        bytes32 root = keccak256(abi.encodePacked(node1, sib2));

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = sib1;
        proof[1] = sib2;

        assertTrue(
            bridge.verifyMerkleProof(proof, root, leaf, 0),
            "Deep proof should verify"
        );
    }

    // =========================================================================
    // ADMIN FUNCTION FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: admin can set deposit limits
     */
    function testFuzz_AdminSetsDepositLimits(
        uint256 minDep,
        uint256 maxDep,
        uint256 dailyLimit
    ) public {
        vm.prank(admin);
        bridge.setDepositLimits(minDep, maxDep, dailyLimit);

        assertEq(bridge.minDeposit(), minDep, "Min deposit should be set");
        assertEq(bridge.maxDeposit(), maxDep, "Max deposit should be set");
        assertEq(
            bridge.dailyDepositLimit(),
            dailyLimit,
            "Daily limit should be set"
        );
    }

    /**
     * @notice Fuzz test: admin can set min ring size
     */
    function testFuzz_AdminSetsMinRingSize(uint256 ringSize) public {
        ringSize = bound(ringSize, 2, 128);

        vm.prank(admin);
        bridge.setMinRingSize(ringSize);

        assertEq(bridge.minRingSize(), ringSize, "Min ring size should be set");
    }

    /**
     * @notice Fuzz test: ring size less than 2 rejected
     */
    function testFuzz_RingSizeLessThan2Rejected(uint256 ringSize) public {
        ringSize = bound(ringSize, 0, 1);

        vm.expectRevert();
        vm.prank(admin);
        bridge.setMinRingSize(ringSize);
    }

    /**
     * @notice Fuzz test: admin can update custodian threshold
     */
    function testFuzz_AdminSetsCustodianThreshold(uint256 threshold) public {
        threshold = bound(threshold, 1, 3); // 3 custodians

        vm.prank(admin);
        bridge.setCustodianThreshold(threshold);

        assertEq(
            bridge.custodianThreshold(),
            threshold,
            "Threshold should be set"
        );
    }

    // =========================================================================
    // PAUSE FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: operations blocked when paused
     */
    function testFuzz_OperationsBlockedWhenPaused(
        bytes32 pilNullifier,
        uint256 amount,
        bytes32 viewKey,
        bytes32 spendKey
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        vm.assume(viewKey != bytes32(0));
        vm.assume(spendKey != bytes32(0));
        amount = bound(amount, 1, 500 ether);

        // Pause
        vm.prank(admin);
        bridge.pause();

        // Try withdrawal request
        vm.expectRevert();
        vm.prank(user);
        bridge.requestWithdrawal(pilNullifier, amount, viewKey, spendKey);
    }

    /**
     * @notice Fuzz test: operations resume after unpause
     */
    function testFuzz_OperationsResumeAfterUnpause(
        bytes32 pilNullifier,
        uint256 amount,
        bytes32 viewKey,
        bytes32 spendKey
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        vm.assume(viewKey != bytes32(0));
        vm.assume(spendKey != bytes32(0));
        amount = bound(amount, 1, 500 ether);

        // Pause then unpause
        vm.prank(admin);
        bridge.pause();
        vm.prank(admin);
        bridge.unpause();

        // Withdrawal request should work
        vm.prank(user);
        bridge.requestWithdrawal(pilNullifier, amount, viewKey, spendKey);

        assertTrue(
            bridge.isPILNullifierUsed(pilNullifier),
            "Request should succeed after unpause"
        );
    }

    // =========================================================================
    // INVARIANT HELPERS
    // =========================================================================

    /**
     * @notice Fuzz test: total withdrawn never exceeds total deposited
     * (invariant check - would need deposits to fully test)
     */
    function testFuzz_WithdrawNeverExceedsDeposit() public view {
        assertLe(
            bridge.totalWithdrawn(),
            bridge.totalDeposited(),
            "Withdrawn <= Deposited"
        );
    }
}
