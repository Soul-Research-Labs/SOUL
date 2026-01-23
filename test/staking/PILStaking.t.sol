// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../../contracts/staking/PILStaking.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title PILStaking Test Suite
 * @notice Comprehensive tests for PIL staking and relayer system
 */
contract PILStakingTest is Test {
    PILStaking public staking;
    MockPILToken public pilToken;

    address public admin = address(0xAD01);
    address public slasher = address(0xAAA1);
    address public rewardsManager = address(0xBBB1);
    address public user1 = address(0xCCC1);
    address public user2 = address(0xCCC2);
    address public relayer1 = address(0xDDD1);
    address public relayer2 = address(0xDDD2);

    uint256 constant FLEXIBLE_MIN = 100 * 10 ** 18;
    uint256 constant BRONZE_MIN = 1_000 * 10 ** 18;
    uint256 constant SILVER_MIN = 5_000 * 10 ** 18;
    uint256 constant GOLD_MIN = 25_000 * 10 ** 18;
    uint256 constant PLATINUM_MIN = 100_000 * 10 ** 18;
    uint256 constant MIN_RELAYER_STAKE = 50_000 * 10 ** 18;

    event Staked(
        address indexed user,
        uint256 amount,
        PILStaking.StakingTier tier,
        uint256 stakeIndex
    );
    event Unstaked(address indexed user, uint256 amount, uint256 stakeIndex);
    event RewardsClaimed(address indexed user, uint256 amount);
    event RelayerRegistered(address indexed relayer);
    event RelayerDeactivated(address indexed relayer);
    event RelayerSlashed(
        address indexed relayer,
        uint256 amount,
        string reason
    );

    function setUp() public {
        // Deploy mock PIL token
        pilToken = new MockPILToken("PIL Token", "PIL");

        // Deploy staking contract
        vm.prank(admin);
        staking = new PILStaking(address(pilToken));

        // Grant roles
        vm.startPrank(admin);
        staking.grantRole(staking.SLASHER_ROLE(), slasher);
        staking.grantRole(staking.REWARDS_MANAGER(), rewardsManager);
        vm.stopPrank();

        // Mint tokens to users
        pilToken.mint(user1, 500_000 * 10 ** 18);
        pilToken.mint(user2, 500_000 * 10 ** 18);
        pilToken.mint(relayer1, 500_000 * 10 ** 18);
        pilToken.mint(relayer2, 500_000 * 10 ** 18);
        pilToken.mint(rewardsManager, 1_000_000 * 10 ** 18);

        // Approve staking contract
        vm.prank(user1);
        pilToken.approve(address(staking), type(uint256).max);
        vm.prank(user2);
        pilToken.approve(address(staking), type(uint256).max);
        vm.prank(relayer1);
        pilToken.approve(address(staking), type(uint256).max);
        vm.prank(relayer2);
        pilToken.approve(address(staking), type(uint256).max);
        vm.prank(rewardsManager);
        pilToken.approve(address(staking), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_initialState() public view {
        assertEq(
            address(staking.pilToken()),
            address(pilToken),
            "PIL token should match"
        );
        assertEq(staking.totalStaked(), 0, "Initial total staked should be 0");
        assertEq(staking.rewardsPool(), 0, "Initial rewards pool should be 0");
    }

    function test_tierConfigs() public view {
        // Flexible tier
        (uint256 lockDuration, uint256 rewardRate, uint256 minStake) = staking
            .tierConfigs(PILStaking.StakingTier.FLEXIBLE);
        assertEq(lockDuration, 0, "Flexible should have no lock");
        assertEq(rewardRate, 500, "Flexible rate should be 5%");
        assertEq(minStake, FLEXIBLE_MIN, "Flexible min stake should match");

        // Bronze tier
        (lockDuration, rewardRate, minStake) = staking.tierConfigs(
            PILStaking.StakingTier.BRONZE
        );
        assertEq(lockDuration, 30 days, "Bronze lock should be 30 days");
        assertEq(rewardRate, 800, "Bronze rate should be 8%");
        assertEq(minStake, BRONZE_MIN, "Bronze min stake should match");

        // Platinum tier
        (lockDuration, rewardRate, minStake) = staking.tierConfigs(
            PILStaking.StakingTier.PLATINUM
        );
        assertEq(lockDuration, 365 days, "Platinum lock should be 365 days");
        assertEq(rewardRate, 2500, "Platinum rate should be 25%");
        assertEq(minStake, PLATINUM_MIN, "Platinum min stake should match");
    }

    /*//////////////////////////////////////////////////////////////
                             STAKING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_stakeFlexible() public {
        uint256 amount = FLEXIBLE_MIN;
        uint256 balanceBefore = pilToken.balanceOf(user1);

        vm.prank(user1);
        staking.stake(amount, PILStaking.StakingTier.FLEXIBLE);

        assertEq(
            pilToken.balanceOf(user1),
            balanceBefore - amount,
            "User balance should decrease"
        );
        assertEq(staking.totalStaked(), amount, "Total staked should increase");
        assertEq(
            staking.getUserTotalStake(user1),
            amount,
            "User stake should match"
        );
    }

    function test_stakeBronze() public {
        uint256 amount = BRONZE_MIN;

        vm.prank(user1);
        staking.stake(amount, PILStaking.StakingTier.BRONZE);

        assertEq(staking.totalStaked(), amount, "Total staked should match");
    }

    function test_stakePlatinum() public {
        uint256 amount = PLATINUM_MIN;

        vm.prank(user1);
        staking.stake(amount, PILStaking.StakingTier.PLATINUM);

        assertEq(staking.totalStaked(), amount, "Total staked should match");
    }

    function test_stakeBelowMinimumReverts() public {
        uint256 amount = FLEXIBLE_MIN - 1;

        vm.prank(user1);
        vm.expectRevert("Below minimum stake");
        staking.stake(amount, PILStaking.StakingTier.FLEXIBLE);
    }

    function test_multipleStakes() public {
        vm.startPrank(user1);
        staking.stake(FLEXIBLE_MIN, PILStaking.StakingTier.FLEXIBLE);
        staking.stake(BRONZE_MIN, PILStaking.StakingTier.BRONZE);
        staking.stake(SILVER_MIN, PILStaking.StakingTier.SILVER);
        vm.stopPrank();

        uint256 expectedTotal = FLEXIBLE_MIN + BRONZE_MIN + SILVER_MIN;
        assertEq(
            staking.getUserTotalStake(user1),
            expectedTotal,
            "Total stake should match"
        );
    }

    /*//////////////////////////////////////////////////////////////
                            UNSTAKING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_unstakeFlexible() public {
        uint256 amount = FLEXIBLE_MIN;

        vm.prank(user1);
        staking.stake(amount, PILStaking.StakingTier.FLEXIBLE);

        uint256 balanceBefore = pilToken.balanceOf(user1);

        vm.prank(user1);
        staking.unstake(0); // First stake index

        assertEq(
            pilToken.balanceOf(user1),
            balanceBefore + amount,
            "User should receive tokens back"
        );
        assertEq(staking.totalStaked(), 0, "Total staked should be 0");
    }

    function test_unstakeLockedBeforeTimeReverts() public {
        uint256 amount = BRONZE_MIN;

        vm.prank(user1);
        staking.stake(amount, PILStaking.StakingTier.BRONZE);

        // Try to unstake before lock period
        vm.prank(user1);
        vm.expectRevert("Still locked");
        staking.unstake(0);
    }

    function test_unstakeAfterLockPeriod() public {
        uint256 amount = BRONZE_MIN;

        vm.prank(user1);
        staking.stake(amount, PILStaking.StakingTier.BRONZE);

        // Warp past lock period (30 days)
        vm.warp(block.timestamp + 31 days);

        vm.prank(user1);
        staking.unstake(0);

        assertEq(staking.totalStaked(), 0, "Total staked should be 0");
    }

    function test_unstakeInvalidIndexReverts() public {
        vm.prank(user1);
        staking.stake(FLEXIBLE_MIN, PILStaking.StakingTier.FLEXIBLE);

        vm.prank(user1);
        vm.expectRevert("Invalid stake index");
        staking.unstake(999);
    }

    /*//////////////////////////////////////////////////////////////
                            REWARDS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_addRewards() public {
        uint256 rewardAmount = 100_000 * 10 ** 18;

        vm.prank(rewardsManager);
        staking.addRewards(rewardAmount);

        assertEq(
            staking.rewardsPool(),
            rewardAmount,
            "Rewards pool should increase"
        );
    }

    function test_claimRewards() public {
        // Add rewards
        vm.prank(rewardsManager);
        staking.addRewards(100_000 * 10 ** 18);

        // Stake
        vm.prank(user1);
        staking.stake(PLATINUM_MIN, PILStaking.StakingTier.PLATINUM);

        // Wait for rewards to accrue
        vm.warp(block.timestamp + 365 days);

        uint256 pendingRewards = staking.getUserPendingRewards(user1);
        assertTrue(pendingRewards > 0, "Should have pending rewards");

        uint256 balanceBefore = pilToken.balanceOf(user1);

        vm.prank(user1);
        staking.claimRewards();

        assertTrue(
            pilToken.balanceOf(user1) > balanceBefore,
            "Balance should increase"
        );
    }

    /*//////////////////////////////////////////////////////////////
                            RELAYER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_registerRelayer() public {
        // First stake enough to become a relayer
        vm.prank(relayer1);
        staking.stake(MIN_RELAYER_STAKE, PILStaking.StakingTier.GOLD);

        // Register as relayer
        vm.prank(relayer1);
        staking.registerRelayer();

        (bool isActive, uint256 stakedAmount, , , , ) = staking.relayers(
            relayer1
        );
        assertTrue(isActive, "Relayer should be active");
        assertEq(stakedAmount, MIN_RELAYER_STAKE, "Staked amount should match");
    }

    function test_registerRelayerInsufficientStakeReverts() public {
        // Stake less than minimum
        vm.prank(relayer1);
        staking.stake(GOLD_MIN, PILStaking.StakingTier.GOLD);

        // Try to register (should fail)
        vm.prank(relayer1);
        vm.expectRevert(); // Insufficient stake
        staking.registerRelayer();
    }

    function test_deactivateRelayer() public {
        // Setup relayer
        vm.prank(relayer1);
        staking.stake(MIN_RELAYER_STAKE, PILStaking.StakingTier.GOLD);
        vm.prank(relayer1);
        staking.registerRelayer();

        // Deactivate
        vm.prank(relayer1);
        staking.deactivateRelayer();

        (bool isActive, , , , , ) = staking.relayers(relayer1);
        assertFalse(isActive, "Relayer should be inactive");
    }

    function test_slashRelayer() public {
        // Setup relayer
        vm.prank(relayer1);
        staking.stake(MIN_RELAYER_STAKE, PILStaking.StakingTier.GOLD);
        vm.prank(relayer1);
        staking.registerRelayer();

        uint256 stakeBefore = staking.getUserTotalStake(relayer1);

        // Slash relayer
        vm.prank(slasher);
        staking.slashRelayer(relayer1, "Malicious behavior");

        uint256 stakeAfter = staking.getUserTotalStake(relayer1);
        assertTrue(
            stakeAfter < stakeBefore,
            "Stake should decrease after slash"
        );
    }

    function test_slashRelayerByNonSlasherReverts() public {
        // Setup relayer
        vm.prank(relayer1);
        staking.stake(MIN_RELAYER_STAKE, PILStaking.StakingTier.GOLD);
        vm.prank(relayer1);
        staking.registerRelayer();

        // Try to slash without role
        vm.prank(user1);
        vm.expectRevert();
        staking.slashRelayer(relayer1, "Unauthorized");
    }

    function test_recordRelaySuccess() public {
        // Setup relayer
        vm.prank(relayer1);
        staking.stake(MIN_RELAYER_STAKE, PILStaking.StakingTier.GOLD);
        vm.prank(relayer1);
        staking.registerRelayer();

        (, , uint256 totalBefore, uint256 successBefore, , ) = staking.relayers(
            relayer1
        );

        vm.prank(slasher);
        staking.recordRelaySuccess(relayer1);

        (, , uint256 totalAfter, uint256 successAfter, , ) = staking.relayers(
            relayer1
        );
        assertEq(
            totalAfter,
            totalBefore + 1,
            "Total processed should increase"
        );
        assertEq(
            successAfter,
            successBefore + 1,
            "Success count should increase"
        );
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_getUserStakes() public {
        vm.startPrank(user1);
        staking.stake(FLEXIBLE_MIN, PILStaking.StakingTier.FLEXIBLE);
        staking.stake(BRONZE_MIN, PILStaking.StakingTier.BRONZE);
        vm.stopPrank();

        PILStaking.Stake[] memory stakes = staking.getUserStakes(user1);
        assertEq(stakes.length, 2, "Should have 2 stakes");
        assertEq(
            stakes[0].amount,
            FLEXIBLE_MIN,
            "First stake amount should match"
        );
        assertEq(
            stakes[1].amount,
            BRONZE_MIN,
            "Second stake amount should match"
        );
    }

    function test_getActiveRelayers() public {
        // Setup multiple relayers
        vm.prank(relayer1);
        staking.stake(MIN_RELAYER_STAKE, PILStaking.StakingTier.GOLD);
        vm.prank(relayer1);
        staking.registerRelayer();

        vm.prank(relayer2);
        staking.stake(MIN_RELAYER_STAKE, PILStaking.StakingTier.GOLD);
        vm.prank(relayer2);
        staking.registerRelayer();

        address[] memory activeRelayers = staking.getActiveRelayers();
        assertEq(activeRelayers.length, 2, "Should have 2 active relayers");
    }

    function test_getRelayerInfo() public {
        vm.prank(relayer1);
        staking.stake(MIN_RELAYER_STAKE, PILStaking.StakingTier.GOLD);
        vm.prank(relayer1);
        staking.registerRelayer();

        PILStaking.Relayer memory info = staking.getRelayerInfo(relayer1);
        assertTrue(info.isActive, "Should be active");
        assertEq(
            info.stakedAmount,
            MIN_RELAYER_STAKE,
            "Staked amount should match"
        );
    }

    /*//////////////////////////////////////////////////////////////
                             PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_pause() public {
        vm.prank(admin);
        staking.pause();

        assertTrue(staking.paused(), "Contract should be paused");
    }

    function test_stakeWhenPausedReverts() public {
        vm.prank(admin);
        staking.pause();

        vm.prank(user1);
        vm.expectRevert();
        staking.stake(FLEXIBLE_MIN, PILStaking.StakingTier.FLEXIBLE);
    }

    function test_unpause() public {
        vm.prank(admin);
        staking.pause();

        vm.prank(admin);
        staking.unpause();

        assertFalse(staking.paused(), "Contract should be unpaused");
    }

    /*//////////////////////////////////////////////////////////////
                             FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_stakeAmount(uint256 amount) public {
        amount = bound(amount, FLEXIBLE_MIN, 100_000 * 10 ** 18);

        vm.prank(user1);
        staking.stake(amount, PILStaking.StakingTier.FLEXIBLE);

        assertEq(
            staking.getUserTotalStake(user1),
            amount,
            "Stake should match"
        );
    }

    function testFuzz_multipleTierStaking(uint8 tierIndex) public {
        tierIndex = uint8(bound(tierIndex, 0, 4)); // 5 tiers
        PILStaking.StakingTier tier = PILStaking.StakingTier(tierIndex);

        (, , uint256 minStake) = staking.tierConfigs(tier);

        vm.prank(user1);
        staking.stake(minStake, tier);

        assertEq(
            staking.getUserTotalStake(user1),
            minStake,
            "Stake should match min"
        );
    }
}

/**
 * @notice Mock PIL Token for testing
 */
contract MockPILToken is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
