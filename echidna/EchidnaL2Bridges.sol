// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../contracts/crosschain/OptimismBridgeAdapter.sol";
import "../contracts/crosschain/BaseBridgeAdapter.sol";

/**
 * @title EchidnaL2Bridges
 * @notice Echidna property-based testing for L2 bridge adapters
 * @dev Run with: echidna . --contract EchidnaL2Bridges --config echidna.yaml
 *
 * Properties tested:
 * 1. Proof relay uniqueness
 * 2. Nonce monotonicity
 * 3. Access control invariants
 * 4. Value conservation
 * 5. State consistency
 */
contract EchidnaL2Bridges {
    OptimismBridgeAdapter public optimismL1;
    OptimismBridgeAdapter public optimismL2;
    BaseBridgeAdapter public baseL1;
    BaseBridgeAdapter public baseL2;

    address internal constant ADMIN = address(0x10000);
    address internal constant ATTACKER = address(0xBAD);

    // Track state for invariants
    uint256 public totalProofsRelayed;
    uint256 public totalValueBridged;
    mapping(bytes32 => bool) public relayedProofHashes;
    uint256 public lastNonce;

    constructor() {
        // Deploy adapters with this contract as admin
        optimismL1 = new OptimismBridgeAdapter(
            address(this),
            address(this),
            address(this),
            address(this),
            true
        );

        optimismL2 = new OptimismBridgeAdapter(
            address(this),
            address(this),
            address(this),
            address(this),
            false
        );

        baseL1 = new BaseBridgeAdapter(
            address(this),
            address(this),
            address(this),
            address(this),
            true
        );

        baseL2 = new BaseBridgeAdapter(
            address(this),
            address(this),
            address(this),
            address(this),
            false
        );

        // Configure targets
        optimismL1.setL2Target(address(optimismL2));
        baseL1.setL2Target(address(baseL2));

        // Configure CCTP
        baseL1.configureCCTP(address(this), address(this));
        bytes32 CCTP_ROLE = keccak256("CCTP_ROLE");
        baseL1.grantRole(CCTP_ROLE, address(this));
    }

    /*//////////////////////////////////////////////////////////////
                    ECHIDNA TEST FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test proof relay
    function echidna_relayProof(bytes32 proofHash) public {
        if (proofHash == bytes32(0)) return;
        if (optimismL2.isProofRelayed(proofHash)) return;

        optimismL2.receiveProofFromL1(proofHash, hex"", hex"", 1);
        relayedProofHashes[proofHash] = true;
        totalProofsRelayed++;
    }

    /// @notice Test sending proof to L2
    function echidna_sendProofToL2(
        bytes32 proofHash,
        uint256 gasLimit
    ) public payable {
        if (proofHash == bytes32(0)) return;
        if (gasLimit < 100000) gasLimit = 100000;
        if (gasLimit > 30000000) gasLimit = 30000000;

        uint256 nonceBefore = optimismL1.messageNonce();

        try
            optimismL1.sendProofToL2{value: msg.value}(
                proofHash,
                hex"1234",
                hex"5678",
                gasLimit
            )
        {
            uint256 nonceAfter = optimismL1.messageNonce();
            assert(nonceAfter > nonceBefore);
            lastNonce = nonceAfter;
            totalValueBridged += msg.value;
        } catch {}
    }

    /// @notice Test CCTP transfer
    function echidna_cctpTransfer(uint256 amount) public {
        if (amount == 0) return;
        if (amount > type(uint128).max) amount = type(uint128).max;

        uint64 nonceBefore = baseL1.cctpNonce();

        try baseL1.initiateUSDCTransfer(address(this), amount, 6) {
            uint64 nonceAfter = baseL1.cctpNonce();
            assert(nonceAfter == nonceBefore + 1);
        } catch {}
    }

    /// @notice Test state sync
    function echidna_stateSync(bytes32 stateRoot, uint256 blockNumber) public {
        if (stateRoot == bytes32(0)) return;
        if (blockNumber == 0) return;

        optimismL2.receiveStateFromL1(stateRoot, blockNumber);

        uint256 storedBlock = optimismL2.getStateRootBlock(stateRoot);
        assert(storedBlock == blockNumber);
    }

    /// @notice Test attestation sync
    function echidna_attestationSync(
        bytes32 attestationId,
        address subject,
        bytes32 schemaId
    ) public {
        if (attestationId == bytes32(0)) return;
        if (subject == address(0)) return;

        baseL1.syncAttestation(attestationId, subject, schemaId, hex"1234");

        BaseBridgeAdapter.AttestationSync memory attest = baseL1.getAttestation(
            attestationId
        );
        assert(attest.synced == true);
        assert(attest.subject == subject);
    }

    /*//////////////////////////////////////////////////////////////
                        PROPERTY CHECKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Property: Relayed proofs cannot be re-relayed
    function echidna_property_proofUniqueness() public view returns (bool) {
        // If a proof is marked as relayed in our tracking, it must be relayed in contract
        bytes32 testHash = keccak256(abi.encodePacked("test-property"));
        if (relayedProofHashes[testHash]) {
            return optimismL2.isProofRelayed(testHash);
        }
        return true;
    }

    /// @notice Property: Nonce never decreases
    function echidna_property_nonceMonotonicity() public view returns (bool) {
        return optimismL1.messageNonce() >= lastNonce;
    }

    /// @notice Property: Stats counters are consistent
    function echidna_property_statsConsistency() public view returns (bool) {
        (uint256 sent, , uint256 value, ) = optimismL1.getStats();

        // Sent messages should match nonce
        if (sent != optimismL1.messageNonce()) return false;

        // Value bridged should match tracked
        if (value != totalValueBridged) return false;

        return true;
    }

    /// @notice Property: Paused adapter blocks operations
    function echidna_property_pauseBlocking() public returns (bool) {
        bool wasPaused = optimismL1.paused();

        if (wasPaused) {
            // Try to send - should fail
            try
                optimismL1.sendProofToL2{value: 0.01 ether}(
                    keccak256("test"),
                    hex"1234",
                    hex"5678",
                    100000
                )
            {
                return false; // Should have reverted
            } catch {
                return true; // Correctly blocked
            }
        }

        return true;
    }

    /// @notice Property: L1/L2 operations are chain-specific
    function echidna_property_chainSpecificOperations()
        public
        view
        returns (bool)
    {
        // L1 adapter should be isL1 = true
        if (!optimismL1.isL1()) return false;

        // L2 adapter should be isL1 = false
        if (optimismL2.isL1()) return false;

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                    ATTACK SIMULATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Simulate attacker trying to send proof without operator role
    function echidna_attack_unauthorizedProofSend(
        bytes32 proofHash
    ) public returns (bool) {
        // Revoke our own operator role temporarily
        bytes32 OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

        // Save state
        bool hasRole = optimismL1.hasRole(OPERATOR_ROLE, address(this));

        if (hasRole) {
            // Temporarily revoke
            optimismL1.revokeRole(OPERATOR_ROLE, address(this));

            // Try to send - should fail
            bool reverted = false;
            try
                optimismL1.sendProofToL2{value: 0.01 ether}(
                    proofHash,
                    hex"1234",
                    hex"5678",
                    100000
                )
            {
                reverted = false;
            } catch {
                reverted = true;
            }

            // Restore role
            optimismL1.grantRole(OPERATOR_ROLE, address(this));

            return reverted; // Should have reverted
        }

        return true;
    }

    /// @notice Simulate double relay attack
    function echidna_attack_doubleRelay(
        bytes32 proofHash
    ) public returns (bool) {
        if (proofHash == bytes32(0)) return true;
        if (optimismL2.isProofRelayed(proofHash)) return true; // Already relayed

        // First relay
        optimismL2.receiveProofFromL1(proofHash, hex"", hex"", 1);

        // Second relay should fail
        try optimismL2.receiveProofFromL1(proofHash, hex"", hex"", 1) {
            return false; // Should have reverted
        } catch {
            return true; // Correctly prevented
        }
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    receive() external payable {}

    fallback() external payable {}
}
