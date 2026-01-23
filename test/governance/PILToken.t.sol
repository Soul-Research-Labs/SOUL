// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/governance/PILToken.sol";

/**
 * @title PILTokenTest
 * @notice Tests for PIL Token contract
 */
contract PILTokenTest is Test {
    PILToken public token;

    address public owner = address(0x1);
    address public user1 = address(0x2);
    address public user2 = address(0x3);
    address public beneficiary = address(0x4);
    address public attacker = address(0xDEAD);

    uint256 constant INITIAL_SUPPLY = 5_000_000e18;
    uint256 constant MAX_SUPPLY = 100_000_000e18;

    function setUp() public {
        vm.prank(owner);
        token = new PILToken(owner);
    }

    function test_initialState() public view {
        assertEq(token.name(), "PIL Token");
        assertEq(token.symbol(), "PIL");
        assertEq(token.decimals(), 18);
        assertEq(token.totalSupply(), INITIAL_SUPPLY);
        assertEq(token.balanceOf(owner), INITIAL_SUPPLY);
        assertEq(token.MAX_SUPPLY(), MAX_SUPPLY);
    }

    function test_transfer() public {
        vm.prank(owner);
        token.transfer(user1, 1000e18);

        assertEq(token.balanceOf(user1), 1000e18);
        assertEq(token.balanceOf(owner), INITIAL_SUPPLY - 1000e18);
    }

    function test_transferFrom() public {
        vm.prank(owner);
        token.approve(user1, 1000e18);

        vm.prank(user1);
        token.transferFrom(owner, user2, 500e18);

        assertEq(token.balanceOf(user2), 500e18);
        assertEq(token.allowance(owner, user1), 500e18);
    }

    function test_approve() public {
        vm.prank(owner);
        token.approve(user1, 1000e18);

        assertEq(token.allowance(owner, user1), 1000e18);
    }

    function test_mint() public {
        vm.prank(owner);
        token.mint(user1, 1_000_000e18);

        assertEq(token.balanceOf(user1), 1_000_000e18);
        assertEq(token.totalSupply(), INITIAL_SUPPLY + 1_000_000e18);
    }

    function test_mint_OnlyOwner() public {
        vm.prank(attacker);
        vm.expectRevert();
        token.mint(attacker, 1000e18);
    }

    function test_mint_ExceedsMaxSupply() public {
        uint256 mintAmount = MAX_SUPPLY - INITIAL_SUPPLY + 1;

        vm.prank(owner);
        vm.expectRevert("Exceeds max supply");
        token.mint(user1, mintAmount);
    }

    function test_delegate() public {
        vm.prank(owner);
        token.transfer(user1, 1000e18);

        vm.prank(user1);
        token.delegate(user1);

        vm.roll(block.number + 1);

        assertEq(token.getVotes(user1), 1000e18);
    }

    function test_delegateToOther() public {
        vm.prank(owner);
        token.transfer(user1, 1000e18);

        vm.prank(user1);
        token.delegate(user2);

        vm.roll(block.number + 1);

        assertEq(token.getVotes(user2), 1000e18);
        assertEq(token.getVotes(user1), 0);
    }

    function test_createVestingSchedule() public {
        uint256 vestingAmount = 10_000_000e18;
        uint256 startTime = block.timestamp;
        uint256 duration = 4 * 365 days;
        uint256 cliff = 365 days;

        vm.prank(owner);
        token.createVestingSchedule(
            beneficiary,
            vestingAmount,
            startTime,
            duration,
            cliff
        );

        (uint256 totalAmount, , , , ) = token.vestingSchedules(beneficiary);
        assertEq(totalAmount, vestingAmount);
    }

    function test_createVestingSchedule_OnlyOwner() public {
        vm.prank(attacker);
        vm.expectRevert();
        token.createVestingSchedule(
            beneficiary,
            1000e18,
            block.timestamp,
            365 days,
            30 days
        );
    }

    function test_createVestingSchedule_AlreadyExists() public {
        vm.startPrank(owner);
        token.createVestingSchedule(
            beneficiary,
            1000e18,
            block.timestamp,
            365 days,
            30 days
        );

        vm.expectRevert("Schedule exists");
        token.createVestingSchedule(
            beneficiary,
            2000e18,
            block.timestamp,
            365 days,
            30 days
        );
        vm.stopPrank();
    }

    function test_releaseVestedTokens_NoSchedule() public {
        vm.prank(user1);
        vm.expectRevert("No vesting schedule");
        token.releaseVestedTokens();
    }

    function testFuzz_transfer(uint256 amount) public {
        amount = bound(amount, 1, INITIAL_SUPPLY);

        vm.prank(owner);
        token.transfer(user1, amount);

        assertEq(token.balanceOf(user1), amount);
    }

    function testFuzz_mint(uint256 amount) public {
        amount = bound(amount, 1, MAX_SUPPLY - INITIAL_SUPPLY);

        vm.prank(owner);
        token.mint(user1, amount);

        assertEq(token.balanceOf(user1), amount);
    }

    function test_invariant_totalSupplyNeverExceedsMax() public {
        vm.prank(owner);
        token.mint(user1, MAX_SUPPLY - INITIAL_SUPPLY - 1);

        assertLe(token.totalSupply(), MAX_SUPPLY);
    }
}
