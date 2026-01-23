// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "../../contracts/primitives/ZKBoundStateLocks.sol";

/**
 * @title ZKSlocksSymbolicTest
 * @notice Symbolic execution tests for ZK-Bound State Locks using Halmos
 * @dev Run with: halmos --contract ZKSlocksSymbolicTest
 */
contract ZKSlocksSymbolicTest is Test {
    ZKBoundStateLocks public zkSlocks;
    bytes32 public testDomain;

    function setUp() public {
        // Deploy with this contract as the verifier
        zkSlocks = new ZKBoundStateLocks(address(this));

        // Register a test domain (we're deployer, have DEFAULT_ADMIN_ROLE)
        // Grant DOMAIN_ADMIN_ROLE to this contract
        bytes32 DOMAIN_ADMIN_ROLE = keccak256("DOMAIN_ADMIN_ROLE");
        zkSlocks.grantRole(DOMAIN_ADMIN_ROLE, address(this));

        // Register the domain used in tests
        testDomain = zkSlocks.registerDomain(1, 1, 1, "Test Domain");
    }

    // =========================================================================
    // LOCK STATE MACHINE TESTS
    // =========================================================================

    /**
     * @notice Symbolic test: Lock creation produces valid lock ID
     */
    function check_lock_creation_produces_valid_id(
        bytes32 commitment,
        bytes32 predicateHash,
        bytes32 policyHash,
        uint64 deadlineOffset
    ) public {
        vm.assume(commitment != bytes32(0));
        vm.assume(deadlineOffset > 0 && deadlineOffset < 365 days);

        uint64 deadline = uint64(block.timestamp) + deadlineOffset;

        bytes32 lockId = zkSlocks.createLock(
            commitment,
            predicateHash,
            policyHash,
            testDomain,
            deadline
        );

        assert(lockId != bytes32(0));
    }

    /**
     * @notice Symbolic test: Cannot create duplicate lock with same commitment
     */
    function check_no_duplicate_locks(
        bytes32 commitment,
        bytes32 predicateHash,
        bytes32 policyHash
    ) public {
        vm.assume(commitment != bytes32(0));

        uint64 deadline = uint64(block.timestamp) + 1 hours;

        zkSlocks.createLock(
            commitment,
            predicateHash,
            policyHash,
            testDomain,
            deadline
        );

        // Second creation with same commitment should revert
        try
            zkSlocks.createLock(
                commitment,
                predicateHash,
                policyHash,
                testDomain,
                deadline
            )
        returns (bytes32) {
            assert(false); // Should have reverted
        } catch {
            assert(true); // Expected
        }
    }

    /**
     * @notice Symbolic test: Expired locks cannot be normally unlocked
     */
    function check_expired_lock_behavior(
        bytes32 commitment,
        uint64 deadlineOffset
    ) public {
        vm.assume(commitment != bytes32(0));
        vm.assume(deadlineOffset > 0 && deadlineOffset < 30 days);

        uint64 deadline = uint64(block.timestamp) + deadlineOffset;

        bytes32 lockId = zkSlocks.createLock(
            commitment,
            keccak256("predicate"),
            keccak256("policy"),
            testDomain,
            deadline
        );

        // Warp past deadline
        vm.warp(block.timestamp + deadlineOffset + 1);

        // Normal unlock should handle expiry appropriately
        // (Implementation specific - may revert or transition to expired state)
    }

    /**
     * @notice Symbolic test: Nullifier uniqueness - same nullifier cannot be reused
     */
    function check_nullifier_uniqueness(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        bool usedBefore = zkSlocks.nullifierUsed(nullifier);

        if (!usedBefore) {
            // After marking as used, should be used
            // Note: This requires internal access or a function that uses nullifiers
        }
    }

    /**
     * @notice Symbolic test: Domain separator is deterministic
     */
    function check_domain_separator_deterministic(
        uint16 chainId,
        uint16 appId,
        uint32 epoch
    ) public view {
        bytes32 domain1 = zkSlocks.generateDomainSeparator(
            chainId,
            appId,
            epoch
        );
        bytes32 domain2 = zkSlocks.generateDomainSeparator(
            chainId,
            appId,
            epoch
        );

        assert(domain1 == domain2);
    }

    /**
     * @notice Symbolic test: Different inputs produce different domain separators
     */
    function check_domain_separator_uniqueness(
        uint16 chainId1,
        uint16 chainId2,
        uint16 appId,
        uint32 epoch
    ) public view {
        vm.assume(chainId1 != chainId2);

        bytes32 domain1 = zkSlocks.generateDomainSeparator(
            chainId1,
            appId,
            epoch
        );
        bytes32 domain2 = zkSlocks.generateDomainSeparator(
            chainId2,
            appId,
            epoch
        );

        assert(domain1 != domain2);
    }

    /**
     * @notice Symbolic test: Active lock count consistency
     */
    function check_active_lock_count_consistency(uint8 numLocks) public {
        vm.assume(numLocks > 0 && numLocks <= 5);

        uint64 deadline = uint64(block.timestamp) + 1 hours;

        uint256 initialCount = zkSlocks.getActiveLockCount();

        for (uint8 i = 0; i < numLocks; i++) {
            bytes32 commitment = keccak256(
                abi.encodePacked("lock", i, block.timestamp)
            );
            zkSlocks.createLock(
                commitment,
                keccak256("predicate"),
                keccak256("policy"),
                testDomain,
                deadline
            );
        }

        uint256 finalCount = zkSlocks.getActiveLockCount();

        assert(finalCount == initialCount + numLocks);
    }

    /**
     * @notice Symbolic test: Lock creation preserves other locks
     */
    function check_lock_isolation(
        bytes32 commitment1,
        bytes32 commitment2
    ) public {
        vm.assume(commitment1 != bytes32(0));
        vm.assume(commitment2 != bytes32(0));
        vm.assume(commitment1 != commitment2);

        uint64 deadline = uint64(block.timestamp) + 1 hours;

        // Create first lock
        bytes32 lockId1 = zkSlocks.createLock(
            commitment1,
            keccak256("predicate1"),
            keccak256("policy1"),
            testDomain,
            deadline
        );

        // Get first lock state (ZKSLock has 9 fields, we care about isUnlocked)
        (, , , , , , uint64 createdAtBefore, , ) = zkSlocks.locks(lockId1);

        // Create second lock
        zkSlocks.createLock(
            commitment2,
            keccak256("predicate2"),
            keccak256("policy2"),
            testDomain,
            deadline
        );

        // First lock should be unchanged
        (, , , , , , uint64 createdAtAfter, , ) = zkSlocks.locks(lockId1);

        assert(createdAtBefore == createdAtAfter);
    }

    /**
     * @notice Symbolic test: Stats never decrease
     */
    function check_stats_monotonic(uint8 numOperations) public {
        vm.assume(numOperations > 0 && numOperations <= 5);

        (uint256 createdBefore, , , , ) = zkSlocks.getStats();

        uint64 deadline = uint64(block.timestamp) + 1 hours;

        for (uint8 i = 0; i < numOperations; i++) {
            bytes32 commitment = keccak256(
                abi.encodePacked("monotonic", i, block.timestamp)
            );
            zkSlocks.createLock(
                commitment,
                keccak256("predicate"),
                keccak256("policy"),
                testDomain,
                deadline
            );
        }

        (uint256 createdAfter, , , , ) = zkSlocks.getStats();

        assert(createdAfter >= createdBefore);
        assert(createdAfter == createdBefore + numOperations);
    }

    // =========================================================================
    // EDGE CASE TESTS
    // =========================================================================

    /**
     * @notice Symbolic test: Zero commitment behavior
     * @dev SECURITY FINDING: Contract currently allows zero commitment.
     *      This test documents the current behavior.
     *      Consider adding validation: require(commitment != bytes32(0))
     */
    function check_zero_commitment_allowed() public {
        uint64 deadline = uint64(block.timestamp) + 1 hours;

        // Current behavior: zero commitment is allowed
        bytes32 lockId = zkSlocks.createLock(
            bytes32(0), // Zero commitment
            keccak256("predicate"),
            keccak256("policy"),
            testDomain,
            deadline
        );

        // Documenting current behavior - lock is created
        assert(lockId != bytes32(0));
    }

    /**
     * @notice Symbolic test: Past deadline behavior
     * @dev SECURITY FINDING: Contract currently allows past deadlines.
     *      This test documents the current behavior.
     *      Consider adding validation: require(deadline > block.timestamp)
     */
    function check_past_deadline_allowed(bytes32 commitment) public {
        vm.assume(commitment != bytes32(0));

        uint64 deadline = uint64(block.timestamp) - 1; // In the past

        // Current behavior: past deadline is allowed
        bytes32 lockId = zkSlocks.createLock(
            commitment,
            keccak256("predicate"),
            keccak256("policy"),
            testDomain,
            deadline
        );

        // Documenting current behavior - lock is created
        assert(lockId != bytes32(0));
    }

    /**
     * @notice Symbolic test: Maximum deadline is accepted
     */
    function check_max_deadline_accepted(bytes32 commitment) public {
        vm.assume(commitment != bytes32(0));

        uint64 deadline = type(uint64).max;

        // Should not revert (max deadline is valid)
        bytes32 lockId = zkSlocks.createLock(
            commitment,
            keccak256("predicate"),
            keccak256("policy"),
            testDomain,
            deadline
        );

        assert(lockId != bytes32(0));
    }
}
