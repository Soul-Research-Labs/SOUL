// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RailgunPrimitives} from "../../contracts/railgun/RailgunPrimitives.sol";
import {RailgunBridgeAdapter} from "../../contracts/crosschain/RailgunBridgeAdapter.sol";

/**
 * @title MockERC20
 * @notice Simple ERC20 for testing
 */
contract MockERC20 is IERC20 {
    string public name = "Mock Token";
    string public symbol = "MOCK";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

/**
 * @title RailgunBridgeFuzz
 * @notice Comprehensive fuzz tests for Railgun Bridge Adapter
 */
contract RailgunBridgeFuzz is Test {
    RailgunPrimitives public primitives;
    RailgunBridgeAdapter public bridge;
    MockERC20 public mockToken;

    address public admin;
    address public relayer;
    address public treasury;
    address public user;

    uint256 constant BN254_R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function setUp() public {
        admin = address(this);
        relayer = makeAddr("relayer");
        treasury = makeAddr("treasury");
        user = makeAddr("user");

        // Deploy primitives
        primitives = new RailgunPrimitives();

        // Deploy implementation
        RailgunBridgeAdapter impl = new RailgunBridgeAdapter();

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            RailgunBridgeAdapter.initialize.selector,
            admin,
            address(primitives)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        bridge = RailgunBridgeAdapter(payable(address(proxy)));

        // Deploy mock token
        mockToken = new MockERC20();

        // Setup roles
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);
        bridge.grantRole(bridge.TREASURY_ROLE(), treasury);
        bridge.grantRole(bridge.VERIFIER_ROLE(), admin);

        // Add supported token
        bridge.addToken(address(mockToken), 100 ether);

        // Mint tokens to user
        mockToken.mint(user, 1000 ether);

        // Fund user with ETH
        vm.deal(user, 100 ether);
    }

    // =========================================================================
    // DEPOSIT TESTS
    // =========================================================================

    function testFuzz_DepositToken(uint256 amount, bytes32 commitment) public {
        amount = bound(amount, 1, 100 ether);

        vm.startPrank(user);
        mockToken.approve(address(bridge), amount);

        RailgunPrimitives.EncryptedNote
            memory encryptedNote = _createEncryptedNote();

        bridge.deposit(address(mockToken), amount, commitment, encryptedNote);
        vm.stopPrank();

        // Verify TVL increased
        assertTrue(
            bridge.getTVL(address(mockToken)) > 0,
            "TVL should increase"
        );
    }

    function testFuzz_DepositETH(uint256 amount, bytes32 commitment) public {
        amount = bound(amount, 0.01 ether, 10 ether);

        vm.startPrank(user);

        RailgunPrimitives.EncryptedNote
            memory encryptedNote = _createEncryptedNote();

        bridge.depositETH{value: amount}(commitment, encryptedNote);
        vm.stopPrank();

        // Verify TVL increased
        assertTrue(bridge.getTVL(address(0)) > 0, "ETH TVL should increase");
    }

    function testFuzz_DepositZeroAmountReverts(bytes32 commitment) public {
        vm.startPrank(user);
        mockToken.approve(address(bridge), 1 ether);

        RailgunPrimitives.EncryptedNote
            memory encryptedNote = _createEncryptedNote();

        vm.expectRevert(RailgunBridgeAdapter.InvalidAmount.selector);
        bridge.deposit(address(mockToken), 0, commitment, encryptedNote);
        vm.stopPrank();
    }

    function testFuzz_DepositUnsupportedTokenReverts(
        uint256 amount,
        bytes32 commitment
    ) public {
        amount = bound(amount, 1, 100 ether);
        address unsupportedToken = makeAddr("unsupported");

        vm.startPrank(user);

        RailgunPrimitives.EncryptedNote
            memory encryptedNote = _createEncryptedNote();

        vm.expectRevert(RailgunBridgeAdapter.InvalidToken.selector);
        bridge.deposit(unsupportedToken, amount, commitment, encryptedNote);
        vm.stopPrank();
    }

    function testFuzz_DepositExceedsLimitReverts(bytes32 commitment) public {
        uint256 amount = 101 ether; // Limit is 100 ether

        mockToken.mint(user, amount);

        vm.startPrank(user);
        mockToken.approve(address(bridge), amount);

        RailgunPrimitives.EncryptedNote
            memory encryptedNote = _createEncryptedNote();

        vm.expectRevert(RailgunBridgeAdapter.DepositLimitExceeded.selector);
        bridge.deposit(address(mockToken), amount, commitment, encryptedNote);
        vm.stopPrank();
    }

    // =========================================================================
    // WITHDRAWAL TESTS
    // =========================================================================

    function testFuzz_WithdrawalRequestCreatesRequest(
        bytes32 nullifier,
        uint256 amount
    ) public {
        amount = bound(amount, 0.1 ether, 10 ether);

        // First deposit to have balance
        _depositForTest(amount * 2);

        // Get current root
        bytes32 merkleRoot = bridge.getCurrentRoot();

        // Create valid proof structure
        RailgunPrimitives.Groth16Proof memory proof = _createValidProof();

        vm.prank(user);
        bridge.requestWithdrawal(
            address(mockToken),
            amount,
            nullifier,
            user,
            merkleRoot,
            proof
        );

        // Verify nullifier is used
        assertTrue(
            bridge.isNullifierUsed(nullifier),
            "Nullifier should be used"
        );
    }

    function testFuzz_WithdrawalUsedNullifierReverts(
        bytes32 nullifier,
        uint256 amount
    ) public {
        amount = bound(amount, 0.1 ether, 5 ether);

        // First deposit
        _depositForTest(amount * 3);

        bytes32 merkleRoot = bridge.getCurrentRoot();
        RailgunPrimitives.Groth16Proof memory proof = _createValidProof();

        // First withdrawal
        vm.prank(user);
        bridge.requestWithdrawal(
            address(mockToken),
            amount,
            nullifier,
            user,
            merkleRoot,
            proof
        );

        // Second withdrawal with same nullifier should fail
        vm.prank(user);
        vm.expectRevert(RailgunBridgeAdapter.NullifierAlreadyUsed.selector);
        bridge.requestWithdrawal(
            address(mockToken),
            amount,
            nullifier,
            user,
            merkleRoot,
            proof
        );
    }

    function testFuzz_WithdrawalInvalidRootReverts(
        bytes32 nullifier,
        bytes32 fakeRoot,
        uint256 amount
    ) public {
        amount = bound(amount, 0.1 ether, 5 ether);

        // First deposit
        _depositForTest(amount * 2);

        // Use fake root (not in history)
        vm.assume(!bridge.isValidRoot(fakeRoot));

        RailgunPrimitives.Groth16Proof memory proof = _createValidProof();

        vm.prank(user);
        vm.expectRevert(RailgunBridgeAdapter.InvalidMerkleRoot.selector);
        bridge.requestWithdrawal(
            address(mockToken),
            amount,
            nullifier,
            user,
            fakeRoot,
            proof
        );
    }

    // =========================================================================
    // VIEWING KEY TESTS
    // =========================================================================

    function testFuzz_RegisterViewingKey(
        bytes32 keyHash,
        uint256 startBlock
    ) public {
        vm.assume(keyHash != bytes32(0));

        vm.prank(user);
        bridge.registerViewingKey(keyHash, startBlock);

        RailgunPrimitives.ViewingKey memory vk = bridge.getViewingKey(user);
        assertEq(vk.owner, user, "Viewing key owner should match");
    }

    function testFuzz_RegisterZeroViewingKeyReverts(uint256 startBlock) public {
        vm.prank(user);
        vm.expectRevert(RailgunBridgeAdapter.InvalidViewingKey.selector);
        bridge.registerViewingKey(bytes32(0), startBlock);
    }

    // =========================================================================
    // ADMIN TESTS
    // =========================================================================

    function testFuzz_AdminAddsToken(address token, uint256 limit) public {
        vm.assume(token != address(0));
        vm.assume(token != address(mockToken));

        bridge.addToken(token, limit);
        assertTrue(bridge.isTokenSupported(token), "Token should be supported");
    }

    function testFuzz_AdminRemovesToken() public {
        bridge.removeToken(address(mockToken));
        assertFalse(
            bridge.isTokenSupported(address(mockToken)),
            "Token should not be supported"
        );
    }

    function testFuzz_AdminSetsDepositLimit(uint256 limit) public {
        bridge.setDepositLimit(address(mockToken), limit);
        // Deposit limit should be set (no direct getter, test via behavior)
    }

    function testFuzz_AdminSetsDailyVolumeLimit(uint256 limit) public {
        bridge.setDailyVolumeLimit(limit);
        // Daily volume limit should be set
    }

    function testFuzz_AdminSetsFeeRates(
        uint256 protocolFee,
        uint256 relayerFee
    ) public {
        protocolFee = bound(protocolFee, 0, 250); // Max 2.5%
        relayerFee = bound(relayerFee, 0, 250); // Max 2.5%

        bridge.setFeeRates(protocolFee, relayerFee);
    }

    function testFuzz_AdminSetsFeeRatesTooHighReverts(
        uint256 protocolFee,
        uint256 relayerFee
    ) public {
        protocolFee = bound(protocolFee, 300, 500);
        relayerFee = bound(relayerFee, 300, 500);

        vm.expectRevert("Fee too high");
        bridge.setFeeRates(protocolFee, relayerFee);
    }

    function testFuzz_AdminSetsCircuitBreakerThreshold(
        uint256 threshold
    ) public {
        bridge.setCircuitBreakerThreshold(threshold);
    }

    function testFuzz_AdminSetsChainSupport(
        uint256 chainId,
        bool supported
    ) public {
        bridge.setChainSupport(chainId, supported);
        assertEq(
            bridge.isChainSupported(chainId),
            supported,
            "Chain support should match"
        );
    }

    function testFuzz_NonAdminCannotAddToken(
        address attacker,
        address token
    ) public {
        vm.assume(attacker != admin);
        vm.assume(!bridge.hasRole(bridge.DEFAULT_ADMIN_ROLE(), attacker));

        vm.prank(attacker);
        vm.expectRevert();
        bridge.addToken(token, 100 ether);
    }

    function testFuzz_NonAdminCannotPause(address attacker) public {
        vm.assume(attacker != admin);
        vm.assume(!bridge.hasRole(bridge.DEFAULT_ADMIN_ROLE(), attacker));

        vm.prank(attacker);
        vm.expectRevert();
        bridge.pause();
    }

    // =========================================================================
    // PAUSE TESTS
    // =========================================================================

    function testFuzz_PausedBridgeRejectsDeposits(
        uint256 amount,
        bytes32 commitment
    ) public {
        amount = bound(amount, 1, 100 ether);

        bridge.pause();

        vm.startPrank(user);
        mockToken.approve(address(bridge), amount);

        RailgunPrimitives.EncryptedNote
            memory encryptedNote = _createEncryptedNote();

        vm.expectRevert();
        bridge.deposit(address(mockToken), amount, commitment, encryptedNote);
        vm.stopPrank();
    }

    function testFuzz_UnpausedBridgeAcceptsDeposits(
        uint256 amount,
        bytes32 commitment
    ) public {
        amount = bound(amount, 1, 100 ether);

        bridge.pause();
        bridge.unpause();

        vm.startPrank(user);
        mockToken.approve(address(bridge), amount);

        RailgunPrimitives.EncryptedNote
            memory encryptedNote = _createEncryptedNote();

        bridge.deposit(address(mockToken), amount, commitment, encryptedNote);
        vm.stopPrank();

        assertTrue(
            bridge.getTVL(address(mockToken)) > 0,
            "Deposit should succeed after unpause"
        );
    }

    // =========================================================================
    // NULLIFIER BINDING TESTS
    // =========================================================================

    function testFuzz_NullifierBindingCreated(
        bytes32 nullifier,
        uint256 amount
    ) public {
        amount = bound(amount, 0.1 ether, 5 ether);

        _depositForTest(amount * 2);

        bytes32 merkleRoot = bridge.getCurrentRoot();
        RailgunPrimitives.Groth16Proof memory proof = _createValidProof();

        vm.prank(user);
        bridge.requestWithdrawal(
            address(mockToken),
            amount,
            nullifier,
            user,
            merkleRoot,
            proof
        );

        // Verify PIL binding was created
        bytes32 pilNullifier = bridge.railgunToPILNullifier(nullifier);
        assertTrue(pilNullifier != bytes32(0), "PIL binding should be created");
        assertTrue(
            bridge.isPILNullifierUsed(pilNullifier),
            "PIL nullifier should be used"
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

    function testFuzz_DifferentNullifiersDifferentBindings(
        bytes32 nullifier1,
        bytes32 nullifier2,
        uint256 amount
    ) public {
        vm.assume(nullifier1 != nullifier2);
        amount = bound(amount, 0.1 ether, 3 ether);

        _depositForTest(amount * 5);

        bytes32 merkleRoot = bridge.getCurrentRoot();
        RailgunPrimitives.Groth16Proof memory proof = _createValidProof();

        // First withdrawal
        vm.prank(user);
        bridge.requestWithdrawal(
            address(mockToken),
            amount,
            nullifier1,
            user,
            merkleRoot,
            proof
        );

        // Second withdrawal with different nullifier
        vm.prank(user);
        bridge.requestWithdrawal(
            address(mockToken),
            amount,
            nullifier2,
            user,
            merkleRoot,
            proof
        );

        bytes32 pilNullifier1 = bridge.railgunToPILNullifier(nullifier1);
        bytes32 pilNullifier2 = bridge.railgunToPILNullifier(nullifier2);

        assertNotEq(
            pilNullifier1,
            pilNullifier2,
            "Different nullifiers should have different bindings"
        );
    }

    // =========================================================================
    // CHAIN DETECTION TESTS
    // =========================================================================

    function testFuzz_DefaultSupportedChains() public view {
        assertTrue(bridge.isChainSupported(1), "Ethereum should be supported");
        assertTrue(bridge.isChainSupported(137), "Polygon should be supported");
        assertTrue(
            bridge.isChainSupported(42161),
            "Arbitrum should be supported"
        );
        assertTrue(bridge.isChainSupported(56), "BSC should be supported");
    }

    function testFuzz_ChainDetection(uint256 chainId) public view {
        bool isSupported = bridge.isChainSupported(chainId);

        bool expected = chainId == 1 ||
            chainId == 137 ||
            chainId == 42161 ||
            chainId == 56;
        assertEq(isSupported, expected, "Chain detection should be correct");
    }

    // =========================================================================
    // MERKLE ROOT TESTS
    // =========================================================================

    function testFuzz_MerkleRootUpdatedAfterDeposit(
        bytes32 commitment1,
        bytes32 commitment2
    ) public {
        vm.assume(commitment1 != commitment2);

        vm.startPrank(user);
        mockToken.approve(address(bridge), 20 ether);

        RailgunPrimitives.EncryptedNote
            memory encryptedNote = _createEncryptedNote();

        // First deposit
        bridge.deposit(address(mockToken), 1 ether, commitment1, encryptedNote);
        bytes32 root1 = bridge.getCurrentRoot();

        // Second deposit
        bridge.deposit(address(mockToken), 1 ether, commitment2, encryptedNote);
        bytes32 root2 = bridge.getCurrentRoot();

        vm.stopPrank();

        assertNotEq(root1, root2, "Merkle root should change after deposit");
    }

    function testFuzz_HistoricalRootsValid(bytes32 commitment) public {
        vm.startPrank(user);
        mockToken.approve(address(bridge), 10 ether);

        RailgunPrimitives.EncryptedNote
            memory encryptedNote = _createEncryptedNote();

        bridge.deposit(address(mockToken), 1 ether, commitment, encryptedNote);
        bytes32 root = bridge.getCurrentRoot();

        vm.stopPrank();

        assertTrue(bridge.isValidRoot(root), "Root should be valid");
    }

    // =========================================================================
    // TVL TESTS
    // =========================================================================

    function testFuzz_TVLTracking(uint256 amount) public {
        amount = bound(amount, 0.1 ether, 50 ether);

        uint256 tvlBefore = bridge.getTVL(address(mockToken));

        _depositForTest(amount);

        uint256 tvlAfter = bridge.getTVL(address(mockToken));

        // Account for protocol fee
        assertTrue(tvlAfter > tvlBefore, "TVL should increase after deposit");
    }

    function testFuzz_AvailableBalance(uint256 amount) public {
        amount = bound(amount, 0.1 ether, 50 ether);

        _depositForTest(amount);

        uint256 available = bridge.getAvailableBalance(address(mockToken));
        assertTrue(available > 0, "Available balance should be positive");
    }

    // =========================================================================
    // CIRCUIT BREAKER TESTS
    // =========================================================================

    function testFuzz_CircuitBreakerTriggered() public {
        // Set low threshold
        bridge.setCircuitBreakerThreshold(1 ether);

        // Deposit more than threshold to trigger
        vm.startPrank(user);
        mockToken.approve(address(bridge), 2 ether);

        RailgunPrimitives.EncryptedNote
            memory encryptedNote = _createEncryptedNote();

        bridge.deposit(
            address(mockToken),
            2 ether,
            keccak256("commitment"),
            encryptedNote
        );
        vm.stopPrank();

        assertTrue(
            bridge.circuitBreakerTriggered(),
            "Circuit breaker should be triggered"
        );
    }

    function testFuzz_CircuitBreakerReset() public {
        // Trigger circuit breaker
        bridge.setCircuitBreakerThreshold(1 ether);

        vm.startPrank(user);
        mockToken.approve(address(bridge), 2 ether);

        RailgunPrimitives.EncryptedNote
            memory encryptedNote = _createEncryptedNote();

        bridge.deposit(
            address(mockToken),
            2 ether,
            keccak256("commitment"),
            encryptedNote
        );
        vm.stopPrank();

        // Reset
        bridge.resetCircuitBreaker();

        assertFalse(
            bridge.circuitBreakerTriggered(),
            "Circuit breaker should be reset"
        );
    }

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================

    function _createEncryptedNote()
        internal
        pure
        returns (RailgunPrimitives.EncryptedNote memory)
    {
        return
            RailgunPrimitives.EncryptedNote({
                ephemeralPubKey: keccak256("ephemeral"),
                ciphertext: hex"0011223344556677",
                mac: keccak256("mac")
            });
    }

    function _createValidProof()
        internal
        view
        returns (RailgunPrimitives.Groth16Proof memory)
    {
        RailgunPrimitives.G1Point memory g1 = primitives.g1Generator();
        RailgunPrimitives.G2Point memory g2 = primitives.g2Generator();

        return RailgunPrimitives.Groth16Proof({a: g1, b: g2, c: g1});
    }

    function _depositForTest(uint256 amount) internal {
        vm.startPrank(user);
        mockToken.approve(address(bridge), amount);

        RailgunPrimitives.EncryptedNote
            memory encryptedNote = _createEncryptedNote();

        bridge.deposit(
            address(mockToken),
            amount,
            keccak256(abi.encodePacked("commitment", block.timestamp)),
            encryptedNote
        );
        vm.stopPrank();
    }
}
