// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/governance/PILGovernance.sol";
import "../../contracts/governance/PILToken.sol";

/**
 * @title PILGovernanceTest
 * @notice Tests for PIL Governance contract
 */
contract PILGovernanceTest is Test {
    PILGovernance public governance;
    PILToken public token;

    address public admin = address(0x1);
    address public proposer = address(0x2);
    address public executor = address(0x3);
    address public voter1 = address(0x4);
    address public attacker = address(0xDEAD);

    function setUp() public {
        vm.startPrank(admin);

        // Deploy token
        token = new PILToken(admin);

        // Deploy governance
        governance = new PILGovernance(address(token));

        // Grant roles
        governance.grantRole(governance.PROPOSER_ROLE(), proposer);
        governance.grantRole(governance.EXECUTOR_ROLE(), executor);
        governance.grantRole(governance.CANCELLER_ROLE(), admin);

        vm.stopPrank();
    }

    function test_initialState() public view {
        assertEq(governance.proposalCount(), 0);
        assertEq(governance.governanceToken(), address(token));
        assertGt(governance.votingPeriod(), 0);
        assertGt(governance.quorumVotes(), 0);
    }

    function test_createProposal() public {
        vm.startPrank(proposer);

        address[] memory targets = new address[](1);
        targets[0] = address(governance);

        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("setVotingPeriod(uint256)", 100);

        uint256 proposalId = governance.propose(
            targets,
            values,
            calldatas,
            "Test proposal"
        );

        assertGt(proposalId, 0);
        assertEq(governance.proposalCount(), 1);

        vm.stopPrank();
    }

    function test_createProposal_InvalidLength() public {
        vm.startPrank(proposer);

        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](2);
        bytes[] memory calldatas = new bytes[](1);

        vm.expectRevert(PILGovernance.InvalidProposalLength.selector);
        governance.propose(targets, values, calldatas, "Invalid");

        vm.stopPrank();
    }

    function test_castVote() public {
        uint256 proposalId = _createProposal();

        // Move to active
        vm.roll(block.number + governance.votingDelay() + 1);

        vm.prank(voter1);
        governance.castVote(proposalId, 1);

        // Verify vote was recorded
        (bool hasVoted, , ) = governance.proposalVotes(proposalId, voter1);
        assertTrue(hasVoted);
    }

    function test_castVote_DoubleVoting() public {
        uint256 proposalId = _createProposal();
        vm.roll(block.number + governance.votingDelay() + 1);

        vm.startPrank(voter1);
        governance.castVote(proposalId, 1);

        vm.expectRevert(PILGovernance.AlreadyVoted.selector);
        governance.castVote(proposalId, 1);
        vm.stopPrank();
    }

    function test_castVote_InvalidType() public {
        uint256 proposalId = _createProposal();
        vm.roll(block.number + governance.votingDelay() + 1);

        vm.prank(voter1);
        vm.expectRevert(PILGovernance.InvalidVoteType.selector);
        governance.castVote(proposalId, 3);
    }

    function test_castVote_NotActive() public {
        uint256 proposalId = _createProposal();

        vm.prank(voter1);
        vm.expectRevert(PILGovernance.ProposalNotActive.selector);
        governance.castVote(proposalId, 1);
    }

    function test_cancelProposal() public {
        uint256 proposalId = _createProposal();

        vm.prank(admin);
        governance.cancel(proposalId);

        assertEq(
            uint256(governance.state(proposalId)),
            uint256(PILGovernance.ProposalState.Canceled)
        );
    }

    function test_cancelProposal_Unauthorized() public {
        uint256 proposalId = _createProposal();

        vm.prank(attacker);
        vm.expectRevert();
        governance.cancel(proposalId);
    }

    function test_setVotingDelay() public {
        uint256 newDelay = 100;

        vm.prank(admin);
        governance.setVotingDelay(newDelay);

        assertEq(governance.votingDelay(), newDelay);
    }

    function test_setVotingPeriod() public {
        uint256 newPeriod = 50000;

        vm.prank(admin);
        governance.setVotingPeriod(newPeriod);

        assertEq(governance.votingPeriod(), newPeriod);
    }

    function testFuzz_votingDelay(uint256 newDelay) public {
        newDelay = bound(newDelay, 1, 100000);

        vm.prank(admin);
        governance.setVotingDelay(newDelay);

        assertEq(governance.votingDelay(), newDelay);
    }

    function _createProposal() internal returns (uint256) {
        vm.startPrank(proposer);

        address[] memory targets = new address[](1);
        targets[0] = address(governance);

        uint256[] memory values = new uint256[](1);
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature(
            "setVotingPeriod(uint256)",
            100000
        );

        uint256 proposalId = governance.propose(
            targets,
            values,
            calldatas,
            "Test"
        );

        vm.stopPrank();
        return proposalId;
    }
}
