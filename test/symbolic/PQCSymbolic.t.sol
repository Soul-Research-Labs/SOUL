// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "../../contracts/pqc/DilithiumVerifier.sol";
import "../../contracts/pqc/KyberKEM.sol";
import "../../contracts/pqc/PQCRegistry.sol";

/**
 * @title PQCSymbolicTest
 * @notice Symbolic execution tests for PQC contracts using Halmos
 * @dev Run with: halmos --contract PQCSymbolicTest
 */
contract PQCSymbolicTest is Test {
    DilithiumVerifier public dilithiumVerifier;
    KyberKEM public kyberKEM;
    PQCRegistry public pqcRegistry;

    function setUp() public {
        dilithiumVerifier = new DilithiumVerifier();
        kyberKEM = new KyberKEM();
        pqcRegistry = new PQCRegistry(
            address(dilithiumVerifier),
            address(0), // SPHINCS verifier
            address(kyberKEM)
        );
    }

    // =========================================================================
    // DILITHIUM VERIFIER SYMBOLIC TESTS
    // =========================================================================

    /**
     * @notice Symbolic test: Invalid signature size always reverts
     * @dev Uses try/catch pattern for Halmos compatibility
     */
    function check_dilithium3_invalid_sig_size_reverts(
        bytes32 message,
        bytes memory signature,
        bytes memory publicKey
    ) public {
        // Dilithium3 signature size is 3293
        vm.assume(signature.length != 3293);
        vm.assume(signature.length < 10000); // Bound for tractability

        try
            dilithiumVerifier.verifyDilithium3(message, signature, publicKey)
        returns (bool) {
            // Should not succeed with invalid sig size
            assert(false);
        } catch {
            // Expected to revert
            assert(true);
        }
    }

    /**
     * @notice Symbolic test: Invalid public key size always reverts
     * @dev Uses try/catch pattern for Halmos compatibility
     */
    function check_dilithium3_invalid_pk_size_reverts(
        bytes32 message,
        bytes memory publicKey
    ) public {
        bytes memory signature = new bytes(3293); // Valid sig size

        // Dilithium3 public key size is 1952
        vm.assume(publicKey.length != 1952);
        vm.assume(publicKey.length < 5000); // Bound for tractability

        try
            dilithiumVerifier.verifyDilithium3(message, signature, publicKey)
        returns (bool) {
            // Should not succeed with invalid pk size
            assert(false);
        } catch {
            // Expected to revert
            assert(true);
        }
    }

    /**
     * @notice Symbolic test: Verification is deterministic
     */
    function check_dilithium_verification_deterministic(
        bytes32 message
    ) public {
        bytes memory signature = new bytes(3293);
        bytes memory publicKey = new bytes(1952);

        // Fill with deterministic data
        for (uint256 i = 0; i < signature.length; i++) {
            signature[i] = bytes1(uint8(i % 256));
        }
        for (uint256 i = 0; i < publicKey.length; i++) {
            publicKey[i] = bytes1(uint8((i * 7) % 256));
        }

        bool result1 = dilithiumVerifier.verifyDilithium3(
            message,
            signature,
            publicKey
        );
        bool result2 = dilithiumVerifier.verifyDilithium3(
            message,
            signature,
            publicKey
        );

        assert(result1 == result2);
    }

    /**
     * @notice Symbolic test: Trusted key addition is effective
     */
    function check_trusted_key_addition(bytes32 keyHash) public {
        vm.assume(keyHash != bytes32(0));

        bool trustedBefore = dilithiumVerifier.trustedKeyHashes(keyHash);

        dilithiumVerifier.addTrustedKey(keyHash);

        bool trustedAfter = dilithiumVerifier.trustedKeyHashes(keyHash);

        // If it wasn't trusted before, it should be trusted after
        assert(!trustedBefore || trustedAfter);
        assert(trustedAfter);
    }

    /**
     * @notice Symbolic test: Trusted key removal is effective
     */
    function check_trusted_key_removal(bytes32 keyHash) public {
        vm.assume(keyHash != bytes32(0));

        // First add, then remove
        dilithiumVerifier.addTrustedKey(keyHash);
        dilithiumVerifier.removeTrustedKey(keyHash);

        bool trustedAfter = dilithiumVerifier.trustedKeyHashes(keyHash);

        assert(!trustedAfter);
    }

    // =========================================================================
    // KYBER KEM SYMBOLIC TESTS
    // =========================================================================

    /**
     * @notice Symbolic test: Cannot register with invalid key size
     * @dev Uses try/catch pattern for Halmos compatibility
     */
    function check_kyber_invalid_key_size_reverts(
        bytes memory publicKey,
        uint8 variant
    ) public {
        // Kyber768 key size is 1184
        vm.assume(
            publicKey.length != 1184 &&
                publicKey.length != 800 &&
                publicKey.length != 1568
        );
        vm.assume(publicKey.length < 5000); // Bound
        vm.assume(variant <= 2); // Valid variants

        try
            kyberKEM.registerPublicKey(
                publicKey,
                KyberKEM.KyberVariant(variant)
            )
        {
            assert(false); // Should have reverted
        } catch {
            assert(true); // Expected
        }
    }

    /**
     * @notice Symbolic test: Cannot double register
     * @dev Uses try/catch pattern for Halmos compatibility
     */
    function check_kyber_no_double_registration() public {
        bytes memory publicKey = new bytes(1184);

        kyberKEM.registerPublicKey(publicKey, KyberKEM.KyberVariant.Kyber768);

        try
            kyberKEM.registerPublicKey(
                publicKey,
                KyberKEM.KyberVariant.Kyber768
            )
        {
            assert(false); // Should have reverted
        } catch {
            assert(true); // Expected
        }
    }

    /**
     * @notice Symbolic test: Key registration makes hasActiveKey true
     */
    function check_kyber_registration_activates_key() public {
        bytes memory publicKey = new bytes(1184);
        address user = address(0x1234);

        vm.prank(user);
        kyberKEM.registerPublicKey(publicKey, KyberKEM.KyberVariant.Kyber768);

        (, , , bool isActive) = kyberKEM.registeredKeys(user);
        assert(isActive);
    }

    /**
     * @notice Symbolic test: Key revocation deactivates key
     */
    function check_kyber_revocation_deactivates_key() public {
        bytes memory publicKey = new bytes(1184);
        address user = address(0x1234);

        vm.startPrank(user);
        kyberKEM.registerPublicKey(publicKey, KyberKEM.KyberVariant.Kyber768);
        kyberKEM.revokeKey();
        vm.stopPrank();

        (, , , bool isActive) = kyberKEM.registeredKeys(user);
        assert(!isActive);
    }

    /**
     * @notice Symbolic test: Exchange completion is terminal
     */
    function check_kyber_exchange_completion_terminal(
        bytes32 exchangeId
    ) public {
        // Setup: Complete an exchange
        bytes memory publicKey = new bytes(1184);
        address sender = address(0x1);
        address recipient = address(0x2);

        vm.prank(recipient);
        kyberKEM.registerPublicKey(publicKey, KyberKEM.KyberVariant.Kyber768);

        vm.prank(sender);
        (bytes32 id, , bytes32 sharedSecretHash) = kyberKEM.encapsulate(
            recipient,
            keccak256("randomness")
        );

        vm.prank(recipient);
        kyberKEM.confirmDecapsulation(id, sharedSecretHash);

        // Verify it's completed
        assert(kyberKEM.isExchangeCompleted(id));

        // Try to complete again - should revert
        vm.prank(recipient);
        try kyberKEM.confirmDecapsulation(id, sharedSecretHash) {
            assert(false); // Should have reverted
        } catch {
            assert(true); // Expected - already completed
        }
    }

    // =========================================================================
    // PQC REGISTRY SYMBOLIC TESTS
    // =========================================================================

    /**
     * @notice Symbolic test: Account configuration is one-time
     */
    function check_pqc_no_double_configuration() public {
        bytes32 sigKeyHash = keccak256("sigKey");
        bytes32 kemKeyHash = keccak256("kemKey");

        address user = address(0x1234);

        vm.startPrank(user);
        pqcRegistry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.Kyber768,
            sigKeyHash,
            kemKeyHash,
            true
        );

        // Second configuration should revert
        try
            pqcRegistry.configureAccount(
                PQCRegistry.PQCPrimitive.Dilithium3,
                PQCRegistry.PQCPrimitive.Kyber768,
                sigKeyHash,
                kemKeyHash,
                true
            )
        {
            assert(false); // Should have reverted
        } catch {
            assert(true); // Expected
        }
        vm.stopPrank();
    }

    /**
     * @notice Symbolic test: Configuration enables PQC
     */
    function check_pqc_configuration_enables_account() public {
        bytes32 sigKeyHash = keccak256("sigKey");
        bytes32 kemKeyHash = keccak256("kemKey");
        address user = address(0x1234);

        assert(!pqcRegistry.isPQCEnabled(user));

        vm.prank(user);
        pqcRegistry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.Kyber768,
            sigKeyHash,
            kemKeyHash,
            true
        );

        assert(pqcRegistry.isPQCEnabled(user));
    }

    /**
     * @notice Symbolic test: Deactivation disables PQC
     */
    function check_pqc_deactivation_disables_account() public {
        bytes32 sigKeyHash = keccak256("sigKey");
        bytes32 kemKeyHash = keccak256("kemKey");
        address user = address(0x1234);

        vm.startPrank(user);
        pqcRegistry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.Kyber768,
            sigKeyHash,
            kemKeyHash,
            true
        );

        pqcRegistry.deactivateAccount();
        vm.stopPrank();

        assert(!pqcRegistry.isPQCEnabled(user));
    }

    /**
     * @notice Symbolic test: Stats are monotonically increasing
     */
    function check_pqc_stats_monotonic(uint8 numAccounts) public {
        vm.assume(numAccounts > 0 && numAccounts <= 5);

        PQCRegistry.PQCStats memory statsBefore = pqcRegistry.getStats();

        for (uint8 i = 0; i < numAccounts; i++) {
            address user = address(uint160(0x1000 + i));
            vm.prank(user);
            pqcRegistry.configureAccount(
                PQCRegistry.PQCPrimitive.Dilithium3,
                PQCRegistry.PQCPrimitive.None,
                keccak256(abi.encodePacked("sigKey", i)),
                bytes32(0),
                false
            );
        }

        PQCRegistry.PQCStats memory statsAfter = pqcRegistry.getStats();

        assert(statsAfter.totalAccounts >= statsBefore.totalAccounts);
        assert(statsAfter.dilithiumAccounts >= statsBefore.dilithiumAccounts);
    }

    /**
     * @notice Symbolic test: Account configuration preserves other accounts
     */
    function check_pqc_configuration_isolation(address other) public {
        vm.assume(other != address(0x1234));
        vm.assume(other != address(0));

        bytes32 sigKeyHash = keccak256("sigKey");
        bytes32 kemKeyHash = keccak256("kemKey");
        address user = address(0x1234);

        // Setup other account
        vm.prank(other);
        pqcRegistry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.None,
            keccak256("otherSigKey"),
            bytes32(0),
            false
        );

        bool otherEnabledBefore = pqcRegistry.isPQCEnabled(other);

        // Configure user account
        vm.prank(user);
        pqcRegistry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.Kyber768,
            sigKeyHash,
            kemKeyHash,
            true
        );

        bool otherEnabledAfter = pqcRegistry.isPQCEnabled(other);

        assert(otherEnabledBefore == otherEnabledAfter);
    }
}
