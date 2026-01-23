// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/oasis/OasisPrimitives.sol";
import "../../contracts/crosschain/OasisBridgeAdapter.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title OasisBridgeFuzz
 * @author PIL Protocol
 * @notice Fuzz tests for Oasis Network bridge adapter
 */
contract OasisBridgeFuzz is Test {
    OasisPrimitives public primitives;
    OasisBridgeAdapter public bridge;
    OasisBridgeAdapter public bridgeImpl;

    address public admin = address(1);
    address public relayer = address(2);
    address public committee1 = address(3);
    address public committee2 = address(4);
    address public teeOperator = address(5);
    address public user = address(6);

    bytes32 public testMREnclave = keccak256("test_enclave");
    bytes32 public testMRSigner = keccak256("test_signer");

    // Store chain IDs to avoid external calls during expectRevert
    uint256 public SAPPHIRE_MAINNET;
    uint256 public SAPPHIRE_TESTNET;

    function setUp() public {
        // Deploy primitives
        primitives = new OasisPrimitives();

        // Cache chain IDs to avoid external calls during expectRevert
        SAPPHIRE_MAINNET = primitives.SAPPHIRE_MAINNET_CHAIN_ID();
        SAPPHIRE_TESTNET = primitives.SAPPHIRE_TESTNET_CHAIN_ID();

        // Deploy bridge implementation
        bridgeImpl = new OasisBridgeAdapter();

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            OasisBridgeAdapter.initialize.selector,
            admin,
            address(primitives),
            1, // PIL chain ID
            2 // Committee threshold
        );

        ERC1967Proxy proxy = new ERC1967Proxy(address(bridgeImpl), initData);
        bridge = OasisBridgeAdapter(address(proxy));

        // Setup roles
        vm.startPrank(admin);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);
        bridge.grantRole(bridge.TEE_OPERATOR_ROLE(), teeOperator);
        bridge.addCommitteeMember(committee1);
        bridge.addCommitteeMember(committee2);
        bridge.approveEnclave(testMREnclave, testMRSigner);
        vm.stopPrank();

        // Set totalDeposited for withdrawal tests (slot 12 from storage layout)
        _setTotalDeposited(SAPPHIRE_MAINNET, 1000 ether);
    }

    /**
     * @notice Helper to set totalDepositedByParaTime for testing withdrawals
     * @dev Uses vm.store to set storage directly
     */
    function _setTotalDeposited(uint256 paraTime, uint256 amount) internal {
        // totalDepositedByParaTime is a mapping at slot 12
        // slot = keccak256(abi.encode(key, slot))
        bytes32 slot = keccak256(abi.encode(paraTime, uint256(12)));
        vm.store(address(bridge), slot, bytes32(amount));
    }

    /**
     * @notice Helper to set totalWithdrawnByParaTime for testing
     * @dev Uses vm.store to set storage directly
     */
    function _setTotalWithdrawn(uint256 paraTime, uint256 amount) internal {
        // totalWithdrawnByParaTime is a mapping at slot 13
        bytes32 slot = keccak256(abi.encode(paraTime, uint256(13)));
        vm.store(address(bridge), slot, bytes32(amount));
    }

    // =========================================================================
    // PARATIME MANAGEMENT FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: admin can add ParaTime
     */
    function testFuzz_AdminAddsParaTime(uint256 chainId) public {
        vm.prank(admin);
        bridge.addParaTime(chainId);

        assertTrue(
            bridge.supportedParaTimes(chainId),
            "ParaTime should be added"
        );
    }

    /**
     * @notice Fuzz test: admin can remove ParaTime
     */
    function testFuzz_AdminRemovesParaTime(uint256 chainId) public {
        vm.prank(admin);
        bridge.addParaTime(chainId);

        vm.prank(admin);
        bridge.removeParaTime(chainId);

        assertFalse(
            bridge.supportedParaTimes(chainId),
            "ParaTime should be removed"
        );
    }

    /**
     * @notice Fuzz test: non-admin cannot add ParaTime
     */
    function testFuzz_NonAdminCannotAddParaTime(uint256 chainId) public {
        vm.expectRevert();
        vm.prank(user);
        bridge.addParaTime(chainId);
    }

    // =========================================================================
    // COMMITTEE MANAGEMENT FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: admin can add committee member
     */
    function testFuzz_AdminAddsCommitteeMember(address member) public {
        vm.assume(member != address(0));
        vm.assume(!bridge.committeeMembers(member));

        uint256 sizeBefore = bridge.committeeSize();

        vm.prank(admin);
        bridge.addCommitteeMember(member);

        assertTrue(bridge.committeeMembers(member), "Member should be added");
        assertEq(
            bridge.committeeSize(),
            sizeBefore + 1,
            "Committee size should increase"
        );
    }

    /**
     * @notice Fuzz test: admin can remove committee member
     */
    function testFuzz_AdminRemovesCommitteeMember() public {
        address member = address(100);

        vm.prank(admin);
        bridge.addCommitteeMember(member);

        uint256 sizeBefore = bridge.committeeSize();

        vm.prank(admin);
        bridge.removeCommitteeMember(member);

        assertFalse(
            bridge.committeeMembers(member),
            "Member should be removed"
        );
        assertEq(
            bridge.committeeSize(),
            sizeBefore - 1,
            "Committee size should decrease"
        );
    }

    /**
     * @notice Fuzz test: admin can set committee threshold
     */
    function testFuzz_AdminSetsThreshold(uint256 threshold) public {
        threshold = bound(threshold, 1, bridge.committeeSize());

        vm.prank(admin);
        bridge.setCommitteeThreshold(threshold);

        assertEq(
            bridge.committeeThreshold(),
            threshold,
            "Threshold should be updated"
        );
    }

    /**
     * @notice Fuzz test: threshold cannot exceed committee size
     */
    function testFuzz_ThresholdCannotExceedSize(uint256 threshold) public {
        threshold = bound(
            threshold,
            bridge.committeeSize() + 1,
            type(uint256).max
        );

        vm.expectRevert("Invalid threshold");
        vm.prank(admin);
        bridge.setCommitteeThreshold(threshold);
    }

    // =========================================================================
    // DEPOSIT LIMIT FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: admin can set deposit limits
     */
    function testFuzz_AdminSetsDepositLimits(
        uint256 minDep,
        uint256 maxDep,
        uint256 dailyLimit
    ) public {
        minDep = bound(minDep, 0, 100 ether);
        maxDep = bound(maxDep, minDep, 1000 ether);
        dailyLimit = bound(dailyLimit, maxDep, 10000 ether);

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
     * @notice Fuzz test: min deposit cannot exceed max
     */
    function testFuzz_MinCannotExceedMax(
        uint256 minDep,
        uint256 maxDep
    ) public {
        minDep = bound(minDep, 1 ether, 100 ether);
        maxDep = bound(maxDep, 0, minDep - 1);

        vm.expectRevert("Invalid limits");
        vm.prank(admin);
        bridge.setDepositLimits(minDep, maxDep, 1000 ether);
    }

    // =========================================================================
    // ENCLAVE MANAGEMENT FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: admin can approve enclave
     */
    function testFuzz_AdminApprovesEnclave(
        bytes32 mrEnclave,
        bytes32 mrSigner
    ) public {
        vm.prank(admin);
        bridge.approveEnclave(mrEnclave, mrSigner);

        assertTrue(
            bridge.approvedEnclaves(mrEnclave),
            "Enclave should be approved"
        );
        if (mrSigner != bytes32(0)) {
            assertTrue(
                bridge.approvedSigners(mrSigner),
                "Signer should be approved"
            );
        }
    }

    /**
     * @notice Fuzz test: admin can revoke enclave
     */
    function testFuzz_AdminRevokesEnclave(bytes32 mrEnclave) public {
        vm.prank(admin);
        bridge.approveEnclave(mrEnclave, bytes32(0));

        vm.prank(admin);
        bridge.revokeEnclave(mrEnclave);

        assertFalse(
            bridge.approvedEnclaves(mrEnclave),
            "Enclave should be revoked"
        );
    }

    /**
     * @notice Fuzz test: non-admin cannot approve enclave
     */
    function testFuzz_NonAdminCannotApproveEnclave(bytes32 mrEnclave) public {
        vm.expectRevert();
        vm.prank(user);
        bridge.approveEnclave(mrEnclave, bytes32(0));
    }

    // =========================================================================
    // WITHDRAWAL REQUEST FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: user can request withdrawal
     */
    function testFuzz_UserRequestsWithdrawal(
        bytes32 pilNullifier,
        uint256 amount,
        bytes memory ciphertext
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        vm.assume(ciphertext.length > 0);
        amount = bound(amount, 1, 500 ether);

        OasisPrimitives.EncryptedEnvelope memory envelope = OasisPrimitives
            .EncryptedEnvelope({
                nonce: bytes15(uint120(123)),
                ciphertext: ciphertext,
                tag: bytes16(uint128(456)),
                ephemeralPubKey: bytes32(uint256(789))
            });

        vm.prank(user);
        bridge.requestWithdrawal(
            pilNullifier,
            amount,
            primitives.SAPPHIRE_MAINNET_CHAIN_ID(),
            envelope
        );

        assertTrue(
            bridge.isPILNullifierUsed(pilNullifier),
            "PIL nullifier should be marked used"
        );
    }

    /**
     * @notice Fuzz test: cannot reuse PIL nullifier
     */
    function testFuzz_CannotReusePILNullifier(
        bytes32 pilNullifier,
        uint256 amount
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        amount = bound(amount, 1, 500 ether);

        OasisPrimitives.EncryptedEnvelope memory envelope = OasisPrimitives
            .EncryptedEnvelope({
                nonce: bytes15(uint120(123)),
                ciphertext: "test",
                tag: bytes16(uint128(456)),
                ephemeralPubKey: bytes32(uint256(789))
            });

        vm.prank(user);
        bridge.requestWithdrawal(
            pilNullifier,
            amount,
            SAPPHIRE_MAINNET,
            envelope
        );

        vm.expectRevert(OasisBridgeAdapter.PILNullifierAlreadyUsed.selector);
        vm.prank(user);
        bridge.requestWithdrawal(
            pilNullifier,
            amount,
            SAPPHIRE_MAINNET,
            envelope
        );
    }

    /**
     * @notice Fuzz test: zero amount rejected
     */
    function testFuzz_ZeroAmountRejected(bytes32 pilNullifier) public {
        vm.assume(pilNullifier != bytes32(0));

        // Ensure we have balance available
        _setTotalDeposited(SAPPHIRE_MAINNET, 1000 ether);

        OasisPrimitives.EncryptedEnvelope memory envelope = OasisPrimitives
            .EncryptedEnvelope({
                nonce: bytes15(uint120(123)),
                ciphertext: "test",
                tag: bytes16(uint128(456)),
                ephemeralPubKey: bytes32(uint256(789))
            });

        vm.expectRevert(OasisBridgeAdapter.InvalidAmount.selector);
        vm.prank(user);
        bridge.requestWithdrawal(
            pilNullifier,
            0, // Zero amount
            SAPPHIRE_MAINNET,
            envelope
        );
    }

    /**
     * @notice Fuzz test: invalid ParaTime rejected
     */
    function testFuzz_InvalidParaTimeRejected(
        bytes32 pilNullifier,
        uint256 amount,
        uint256 chainId
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        vm.assume(!bridge.supportedParaTimes(chainId));
        amount = bound(amount, 1, 100 ether);

        OasisPrimitives.EncryptedEnvelope memory envelope = OasisPrimitives
            .EncryptedEnvelope({
                nonce: bytes15(uint120(123)),
                ciphertext: "test",
                tag: bytes16(uint128(456)),
                ephemeralPubKey: bytes32(uint256(789))
            });

        vm.expectRevert(OasisBridgeAdapter.InvalidParaTime.selector);
        vm.prank(user);
        bridge.requestWithdrawal(pilNullifier, amount, chainId, envelope);
    }

    /**
     * @notice Fuzz test: empty ciphertext rejected
     */
    function testFuzz_EmptyCiphertextRejected(
        bytes32 pilNullifier,
        uint256 amount
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        amount = bound(amount, 1, 500 ether); // Within available balance

        // Ensure we have balance available
        _setTotalDeposited(SAPPHIRE_MAINNET, 1000 ether);

        OasisPrimitives.EncryptedEnvelope memory envelope = OasisPrimitives
            .EncryptedEnvelope({
                nonce: bytes15(uint120(123)),
                ciphertext: "", // Empty
                tag: bytes16(uint128(456)),
                ephemeralPubKey: bytes32(uint256(789))
            });

        vm.expectRevert(OasisBridgeAdapter.InvalidEncryptedData.selector);
        vm.prank(user);
        bridge.requestWithdrawal(
            pilNullifier,
            amount,
            SAPPHIRE_MAINNET,
            envelope
        );
    }

    // =========================================================================
    // NULLIFIER BINDING FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: Oasis nullifier not used initially
     */
    function testFuzz_OasisNullifierNotUsedInitially(
        bytes32 nullifier
    ) public view {
        assertFalse(
            bridge.isOasisNullifierUsed(nullifier),
            "Nullifier should not be used initially"
        );
    }

    /**
     * @notice Fuzz test: PIL nullifier not used initially
     */
    function testFuzz_PILNullifierNotUsedInitially(
        bytes32 nullifier
    ) public view {
        assertFalse(
            bridge.isPILNullifierUsed(nullifier),
            "PIL nullifier should not be used initially"
        );
    }

    /**
     * @notice Fuzz test: nullifier binding returns zero for unused
     */
    function testFuzz_NullifierBindingZeroForUnused(
        bytes32 nullifier
    ) public view {
        assertEq(
            bridge.getPILNullifier(nullifier),
            bytes32(0),
            "Unused Oasis nullifier should map to zero"
        );
        assertEq(
            bridge.getOasisNullifier(nullifier),
            bytes32(0),
            "Unused PIL nullifier should map to zero"
        );
    }

    // =========================================================================
    // BALANCE TRACKING FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: available balance calculation
     */
    function testFuzz_AvailableBalanceCalculation(
        uint256 deposited,
        uint256 withdrawn
    ) public {
        deposited = bound(deposited, 0, 1000 ether);
        withdrawn = bound(withdrawn, 0, deposited);

        uint256 paraTime = primitives.SAPPHIRE_MAINNET_CHAIN_ID();

        // Set deposited
        _setTotalDeposited(paraTime, deposited);

        // Set withdrawn (slot 13)
        _setTotalWithdrawn(paraTime, withdrawn);

        uint256 available = bridge.getAvailableBalance(paraTime);
        assertEq(
            available,
            deposited - withdrawn,
            "Available balance should match"
        );
    }

    /**
     * @notice Fuzz test: withdrawal cannot exceed available
     */
    function testFuzz_WithdrawalCannotExceedAvailable(
        bytes32 pilNullifier,
        uint256 available,
        uint256 amount
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        available = bound(available, 1, 100 ether);
        amount = bound(amount, available + 1, type(uint256).max);

        uint256 paraTime = primitives.SAPPHIRE_MAINNET_CHAIN_ID();
        _setTotalDeposited(paraTime, available);

        OasisPrimitives.EncryptedEnvelope memory envelope = OasisPrimitives
            .EncryptedEnvelope({
                nonce: bytes15(uint120(123)),
                ciphertext: "test",
                tag: bytes16(uint128(456)),
                ephemeralPubKey: bytes32(uint256(789))
            });

        vm.expectRevert(OasisBridgeAdapter.InvalidAmount.selector);
        vm.prank(user);
        bridge.requestWithdrawal(pilNullifier, amount, paraTime, envelope);
    }

    // =========================================================================
    // PAUSE FUNCTIONALITY FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: paused bridge rejects withdrawal
     */
    function testFuzz_PausedBridgeRejectsWithdrawal(
        bytes32 pilNullifier,
        uint256 amount
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        amount = bound(amount, 1, 500 ether);

        vm.prank(admin);
        bridge.pause();

        OasisPrimitives.EncryptedEnvelope memory envelope = OasisPrimitives
            .EncryptedEnvelope({
                nonce: bytes15(uint120(123)),
                ciphertext: "test",
                tag: bytes16(uint128(456)),
                ephemeralPubKey: bytes32(uint256(789))
            });

        vm.expectRevert();
        vm.prank(user);
        bridge.requestWithdrawal(
            pilNullifier,
            amount,
            SAPPHIRE_MAINNET,
            envelope
        );
    }

    /**
     * @notice Fuzz test: operations resume after unpause
     */
    function testFuzz_OperationsResumeAfterUnpause(
        bytes32 pilNullifier,
        uint256 amount
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        amount = bound(amount, 1, 500 ether);

        vm.prank(admin);
        bridge.pause();

        vm.prank(admin);
        bridge.unpause();

        OasisPrimitives.EncryptedEnvelope memory envelope = OasisPrimitives
            .EncryptedEnvelope({
                nonce: bytes15(uint120(123)),
                ciphertext: "test",
                tag: bytes16(uint128(456)),
                ephemeralPubKey: bytes32(uint256(789))
            });

        vm.prank(user);
        bridge.requestWithdrawal(
            pilNullifier,
            amount,
            primitives.SAPPHIRE_MAINNET_CHAIN_ID(),
            envelope
        );

        assertTrue(
            bridge.isPILNullifierUsed(pilNullifier),
            "Withdrawal should succeed after unpause"
        );
    }

    // =========================================================================
    // WITHDRAWAL REQUEST VIEW FUZZ TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: withdrawal request details
     */
    function testFuzz_WithdrawalRequestDetails(
        bytes32 pilNullifier,
        uint256 amount
    ) public {
        vm.assume(pilNullifier != bytes32(0));
        amount = bound(amount, 1, 500 ether);

        uint256 paraTime = primitives.SAPPHIRE_MAINNET_CHAIN_ID();

        OasisPrimitives.EncryptedEnvelope memory envelope = OasisPrimitives
            .EncryptedEnvelope({
                nonce: bytes15(uint120(123)),
                ciphertext: "test_ciphertext",
                tag: bytes16(uint128(456)),
                ephemeralPubKey: bytes32(uint256(789))
            });

        vm.prank(user);
        bridge.requestWithdrawal(pilNullifier, amount, paraTime, envelope);

        // Compute request ID
        bytes32 requestId = keccak256(
            abi.encodePacked(
                pilNullifier,
                amount,
                paraTime,
                keccak256(envelope.ciphertext),
                block.timestamp
            )
        );

        (
            bytes32 retPilNullifier,
            uint256 retAmount,
            uint256 retParaTime,
            OasisBridgeAdapter.WithdrawalStatus retStatus
        ) = bridge.getWithdrawalRequest(requestId);

        assertEq(retPilNullifier, pilNullifier, "PIL nullifier should match");
        assertEq(retAmount, amount, "Amount should match");
        assertEq(retParaTime, paraTime, "ParaTime should match");
        assertEq(
            uint8(retStatus),
            uint8(OasisBridgeAdapter.WithdrawalStatus.Pending),
            "Status should be Pending"
        );
    }

    // =========================================================================
    // INVARIANT: WITHDRAWAL NEVER EXCEEDS DEPOSIT
    // =========================================================================

    /**
     * @notice Invariant test: withdrawal tracking
     */
    function testFuzz_WithdrawNeverExceedsDeposit() public view {
        uint256 paraTime = primitives.SAPPHIRE_MAINNET_CHAIN_ID();
        uint256 available = bridge.getAvailableBalance(paraTime);
        uint256 deposited = bridge.totalDepositedByParaTime(paraTime);
        uint256 withdrawn = bridge.totalWithdrawnByParaTime(paraTime);

        assertTrue(
            withdrawn <= deposited,
            "Withdrawn should never exceed deposited"
        );
        assertEq(
            available,
            deposited - withdrawn,
            "Available should equal deposited minus withdrawn"
        );
    }
}
