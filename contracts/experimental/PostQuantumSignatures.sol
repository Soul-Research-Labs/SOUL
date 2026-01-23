// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

/**
 * @title PostQuantumSignatures
 * @author PIL Protocol
 * @notice Experimental implementation of hybrid classical/post-quantum signature verification
 * @dev This contract provides a framework for transitioning to post-quantum cryptography
 *      while maintaining backwards compatibility with existing ECDSA-based accounts.
 *
 * WARNING: This is experimental code for research purposes. Do not use in production
 * until post-quantum precompiles are available on Ethereum mainnet.
 */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title IPQVerifier
 * @notice Interface for external post-quantum signature verifier
 */
interface IPQVerifier {
    /**
     * @notice Verify a Dilithium signature
     * @param message The message that was signed
     * @param signature The Dilithium signature
     * @param publicKey The Dilithium public key
     * @return valid True if signature is valid
     */
    function verifyDilithium(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey
    ) external view returns (bool valid);

    /**
     * @notice Verify a SPHINCS+ signature
     * @param message The message that was signed
     * @param signature The SPHINCS+ signature
     * @param publicKey The SPHINCS+ public key
     * @return valid True if signature is valid
     */
    function verifySPHINCSPlus(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey
    ) external view returns (bool valid);
}

/**
 * @title PostQuantumSignatures
 * @notice Main contract for hybrid signature management
 */
contract PostQuantumSignatures is AccessControl, Pausable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // =============================================================================
    // CONSTANTS
    // =============================================================================

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Domain separator for EIP-712 signatures
    bytes32 public immutable DOMAIN_SEPARATOR;

    /// @notice Typehash for PQ account registration
    bytes32 public constant REGISTER_TYPEHASH =
        keccak256(
            "RegisterPQAccount(address classicalAddress,bytes32 pqPublicKeyHash,uint256 nonce,uint256 deadline)"
        );

    /// @notice Typehash for hybrid verification
    bytes32 public constant VERIFY_TYPEHASH =
        keccak256(
            "HybridVerify(bytes32 messageHash,uint256 nonce,uint256 deadline)"
        );

    // =============================================================================
    // ENUMS & STRUCTS
    // =============================================================================

    /**
     * @notice Supported post-quantum signature algorithms
     */
    enum PQAlgorithm {
        None, // No PQ algorithm (classical only)
        Dilithium3, // NIST ML-DSA Level 3
        Dilithium5, // NIST ML-DSA Level 5
        SPHINCSPlus128, // SPHINCS+ 128-bit security
        SPHINCSPlus256 // SPHINCS+ 256-bit security
    }

    /**
     * @notice Verification mode for signature checks
     */
    enum VerificationMode {
        ClassicalOnly, // Only verify ECDSA (legacy mode)
        Hybrid, // Verify both ECDSA and PQ (recommended)
        PQOnly // Only verify PQ signature (future mode)
    }

    /**
     * @notice Post-quantum account registration
     */
    struct PQAccount {
        bytes32 pqPublicKeyHash; // Keccak256 hash of PQ public key
        PQAlgorithm algorithm; // Which PQ algorithm is used
        uint64 registeredAt; // When the account was registered
        uint64 lastVerifiedAt; // Last successful verification
        bool isActive; // Whether PQ verification is enabled
        uint256 verificationCount; // Number of successful verifications
    }

    /**
     * @notice Hybrid signature structure
     */
    struct HybridSignature {
        bytes classicalSig; // ECDSA signature (65 bytes)
        bytes pqSignature; // Post-quantum signature
        bytes pqPublicKey; // Post-quantum public key (for verification)
        PQAlgorithm algorithm; // Algorithm used
    }

    // =============================================================================
    // STATE VARIABLES
    // =============================================================================

    /// @notice External PQ verifier contract (placeholder until precompiles exist)
    IPQVerifier public pqVerifier;

    /// @notice Mapping of classical addresses to PQ accounts
    mapping(address => PQAccount) public pqAccounts;

    /// @notice Nonces for replay protection
    mapping(address => uint256) public nonces;

    /// @notice Global verification mode
    VerificationMode public globalMode;

    /// @notice Whether hybrid verification is mandatory
    bool public hybridMandatory;

    /// @notice Statistics
    uint256 public totalRegistrations;
    uint256 public totalHybridVerifications;
    uint256 public totalPQOnlyVerifications;

    // =============================================================================
    // EVENTS
    // =============================================================================

    event PQAccountRegistered(
        address indexed classicalAddress,
        bytes32 indexed pqPublicKeyHash,
        PQAlgorithm algorithm,
        uint256 timestamp
    );

    event PQAccountUpdated(
        address indexed classicalAddress,
        bytes32 indexed oldKeyHash,
        bytes32 indexed newKeyHash,
        PQAlgorithm algorithm
    );

    event PQAccountDeactivated(
        address indexed classicalAddress,
        uint256 timestamp
    );

    event HybridVerificationSuccess(
        address indexed signer,
        bytes32 indexed messageHash,
        PQAlgorithm algorithm
    );

    event VerificationModeChanged(
        VerificationMode oldMode,
        VerificationMode newMode
    );

    event PQVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

    // =============================================================================
    // ERRORS
    // =============================================================================

    error InvalidClassicalSignature();
    error InvalidPQSignature();
    error PQAccountNotRegistered();
    error PQAccountAlreadyRegistered();
    error PQAccountNotActive();
    error InvalidPQPublicKey();
    error SignatureExpired();
    error InvalidNonce();
    error PQVerifierNotSet();
    error UnsupportedAlgorithm();
    error HybridVerificationRequired();

    // =============================================================================
    // CONSTRUCTOR
    // =============================================================================

    constructor(address _pqVerifier) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);

        if (_pqVerifier != address(0)) {
            pqVerifier = IPQVerifier(_pqVerifier);
        }

        globalMode = VerificationMode.ClassicalOnly;
        hybridMandatory = false;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("PILPostQuantum"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    // =============================================================================
    // ACCOUNT REGISTRATION
    // =============================================================================

    /**
     * @notice Register a post-quantum public key for an address
     * @param pqPublicKey The full post-quantum public key
     * @param algorithm The PQ algorithm used
     * @param classicalSignature ECDSA signature proving ownership
     * @param deadline Signature expiration timestamp
     */
    function registerPQAccount(
        bytes calldata pqPublicKey,
        PQAlgorithm algorithm,
        bytes calldata classicalSignature,
        uint256 deadline
    ) external whenNotPaused {
        if (block.timestamp > deadline) revert SignatureExpired();
        if (algorithm == PQAlgorithm.None) revert UnsupportedAlgorithm();
        if (pqAccounts[msg.sender].isActive)
            revert PQAccountAlreadyRegistered();

        // Validate PQ public key size based on algorithm
        _validatePQPublicKeySize(pqPublicKey, algorithm);

        bytes32 pqKeyHash = keccak256(pqPublicKey);

        // Verify classical signature
        bytes32 structHash = keccak256(
            abi.encode(
                REGISTER_TYPEHASH,
                msg.sender,
                pqKeyHash,
                nonces[msg.sender]++,
                deadline
            )
        );

        bytes32 digest = MessageHashUtils.toTypedDataHash(
            DOMAIN_SEPARATOR,
            structHash
        );
        address recovered = digest.recover(classicalSignature);

        if (recovered != msg.sender) revert InvalidClassicalSignature();

        // Register the account
        pqAccounts[msg.sender] = PQAccount({
            pqPublicKeyHash: pqKeyHash,
            algorithm: algorithm,
            registeredAt: uint64(block.timestamp),
            lastVerifiedAt: 0,
            isActive: true,
            verificationCount: 0
        });

        totalRegistrations++;

        emit PQAccountRegistered(
            msg.sender,
            pqKeyHash,
            algorithm,
            block.timestamp
        );
    }

    /**
     * @notice Update the PQ public key for an existing account
     * @param newPQPublicKey The new post-quantum public key
     * @param algorithm The PQ algorithm used
     * @param classicalSignature ECDSA signature proving ownership
     * @param pqSignature PQ signature with old key (proves key ownership)
     * @param deadline Signature expiration timestamp
     */
    function updatePQKey(
        bytes calldata newPQPublicKey,
        PQAlgorithm algorithm,
        bytes calldata classicalSignature,
        bytes calldata pqSignature,
        bytes calldata oldPQPublicKey,
        uint256 deadline
    ) external whenNotPaused {
        if (block.timestamp > deadline) revert SignatureExpired();
        if (!pqAccounts[msg.sender].isActive) revert PQAccountNotActive();

        _validatePQPublicKeySize(newPQPublicKey, algorithm);

        bytes32 oldKeyHash = pqAccounts[msg.sender].pqPublicKeyHash;
        bytes32 newKeyHash = keccak256(newPQPublicKey);

        // Verify old PQ public key matches
        if (keccak256(oldPQPublicKey) != oldKeyHash)
            revert InvalidPQPublicKey();

        // Verify classical signature
        bytes32 updateHash = keccak256(
            abi.encode(
                "UpdatePQKey",
                msg.sender,
                oldKeyHash,
                newKeyHash,
                nonces[msg.sender]++,
                deadline
            )
        );

        bytes32 digest = MessageHashUtils.toTypedDataHash(
            DOMAIN_SEPARATOR,
            updateHash
        );
        address recovered = digest.recover(classicalSignature);
        if (recovered != msg.sender) revert InvalidClassicalSignature();

        // Verify PQ signature with old key
        if (
            !_verifyPQSignature(
                digest,
                pqSignature,
                oldPQPublicKey,
                pqAccounts[msg.sender].algorithm
            )
        ) revert InvalidPQSignature();

        // Update the account
        pqAccounts[msg.sender].pqPublicKeyHash = newKeyHash;
        pqAccounts[msg.sender].algorithm = algorithm;

        emit PQAccountUpdated(msg.sender, oldKeyHash, newKeyHash, algorithm);
    }

    /**
     * @notice Deactivate PQ verification for an account
     * @param classicalSignature ECDSA signature proving ownership
     * @param deadline Signature expiration timestamp
     */
    function deactivatePQAccount(
        bytes calldata classicalSignature,
        uint256 deadline
    ) external {
        if (block.timestamp > deadline) revert SignatureExpired();
        if (!pqAccounts[msg.sender].isActive) revert PQAccountNotActive();

        bytes32 deactivateHash = keccak256(
            abi.encode(
                "DeactivatePQ",
                msg.sender,
                nonces[msg.sender]++,
                deadline
            )
        );

        bytes32 digest = MessageHashUtils.toTypedDataHash(
            DOMAIN_SEPARATOR,
            deactivateHash
        );
        address recovered = digest.recover(classicalSignature);
        if (recovered != msg.sender) revert InvalidClassicalSignature();

        pqAccounts[msg.sender].isActive = false;

        emit PQAccountDeactivated(msg.sender, block.timestamp);
    }

    // =============================================================================
    // HYBRID VERIFICATION
    // =============================================================================

    /**
     * @notice Verify a hybrid signature (ECDSA + PQ)
     * @param signer The expected signer address
     * @param messageHash The message hash that was signed
     * @param hybridSig The hybrid signature structure
     * @return valid True if both signatures are valid
     */
    function verifyHybridSignature(
        address signer,
        bytes32 messageHash,
        HybridSignature calldata hybridSig
    ) public view returns (bool valid) {
        // Check if account has PQ registered
        PQAccount storage account = pqAccounts[signer];

        if (globalMode == VerificationMode.ClassicalOnly || !account.isActive) {
            // Classical-only verification
            return
                _verifyClassicalSignature(
                    signer,
                    messageHash,
                    hybridSig.classicalSig
                );
        }

        if (globalMode == VerificationMode.PQOnly) {
            // PQ-only verification
            if (!account.isActive) revert PQAccountNotRegistered();
            return
                _verifyPQSignature(
                    messageHash,
                    hybridSig.pqSignature,
                    hybridSig.pqPublicKey,
                    hybridSig.algorithm
                );
        }

        // Hybrid verification (both must pass)
        bool classicalValid = _verifyClassicalSignature(
            signer,
            messageHash,
            hybridSig.classicalSig
        );
        if (!classicalValid) return false;

        if (account.isActive) {
            // Verify PQ public key matches registered hash
            if (keccak256(hybridSig.pqPublicKey) != account.pqPublicKeyHash) {
                return false;
            }

            bool pqValid = _verifyPQSignature(
                messageHash,
                hybridSig.pqSignature,
                hybridSig.pqPublicKey,
                hybridSig.algorithm
            );

            if (hybridMandatory && !pqValid) {
                return false;
            }

            return pqValid;
        }

        return classicalValid;
    }

    /**
     * @notice Execute a function with hybrid signature verification
     * @param signer The signer address
     * @param messageHash The action message hash
     * @param hybridSig The hybrid signature
     */
    function executeWithHybridVerification(
        address signer,
        bytes32 messageHash,
        HybridSignature calldata hybridSig
    ) external whenNotPaused returns (bool success) {
        if (!verifyHybridSignature(signer, messageHash, hybridSig)) {
            if (globalMode == VerificationMode.Hybrid && hybridMandatory) {
                revert HybridVerificationRequired();
            }
            return false;
        }

        // Update account statistics
        PQAccount storage account = pqAccounts[signer];
        if (account.isActive) {
            account.lastVerifiedAt = uint64(block.timestamp);
            account.verificationCount++;
            totalHybridVerifications++;
        }

        emit HybridVerificationSuccess(
            signer,
            messageHash,
            hybridSig.algorithm
        );

        return true;
    }

    // =============================================================================
    // INTERNAL VERIFICATION HELPERS
    // =============================================================================

    /**
     * @dev Verify classical ECDSA signature
     */
    function _verifyClassicalSignature(
        address signer,
        bytes32 messageHash,
        bytes calldata signature
    ) internal pure returns (bool) {
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(
            messageHash
        );
        address recovered = ethSignedHash.recover(signature);
        return recovered == signer;
    }

    /**
     * @dev Verify post-quantum signature using external verifier
     */
    function _verifyPQSignature(
        bytes32 messageHash,
        bytes calldata signature,
        bytes calldata publicKey,
        PQAlgorithm algorithm
    ) internal view returns (bool) {
        if (address(pqVerifier) == address(0)) revert PQVerifierNotSet();

        if (
            algorithm == PQAlgorithm.Dilithium3 ||
            algorithm == PQAlgorithm.Dilithium5
        ) {
            return
                pqVerifier.verifyDilithium(messageHash, signature, publicKey);
        } else if (
            algorithm == PQAlgorithm.SPHINCSPlus128 ||
            algorithm == PQAlgorithm.SPHINCSPlus256
        ) {
            return
                pqVerifier.verifySPHINCSPlus(messageHash, signature, publicKey);
        }

        revert UnsupportedAlgorithm();
    }

    /**
     * @dev Validate PQ public key size based on algorithm
     */
    function _validatePQPublicKeySize(
        bytes calldata publicKey,
        PQAlgorithm algorithm
    ) internal pure {
        uint256 expectedSize;

        if (algorithm == PQAlgorithm.Dilithium3) {
            expectedSize = 1952; // Dilithium3 public key size
        } else if (algorithm == PQAlgorithm.Dilithium5) {
            expectedSize = 2592; // Dilithium5 public key size
        } else if (algorithm == PQAlgorithm.SPHINCSPlus128) {
            expectedSize = 32; // SPHINCS+ 128 public key
        } else if (algorithm == PQAlgorithm.SPHINCSPlus256) {
            expectedSize = 64; // SPHINCS+ 256 public key
        } else {
            revert UnsupportedAlgorithm();
        }

        if (publicKey.length != expectedSize) revert InvalidPQPublicKey();
    }

    // =============================================================================
    // ADMIN FUNCTIONS
    // =============================================================================

    /**
     * @notice Update the PQ verifier contract
     * @param newVerifier Address of new verifier contract
     */
    function setPQVerifier(address newVerifier) external onlyRole(ADMIN_ROLE) {
        address old = address(pqVerifier);
        pqVerifier = IPQVerifier(newVerifier);
        emit PQVerifierUpdated(old, newVerifier);
    }

    /**
     * @notice Update global verification mode
     * @param newMode New verification mode
     */
    function setVerificationMode(
        VerificationMode newMode
    ) external onlyRole(ADMIN_ROLE) {
        VerificationMode old = globalMode;
        globalMode = newMode;
        emit VerificationModeChanged(old, newMode);
    }

    /**
     * @notice Set whether hybrid verification is mandatory
     * @param mandatory True to require both signatures
     */
    function setHybridMandatory(bool mandatory) external onlyRole(ADMIN_ROLE) {
        hybridMandatory = mandatory;
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    // =============================================================================
    // VIEW FUNCTIONS
    // =============================================================================

    /**
     * @notice Get account information
     * @param account The address to query
     * @return info The PQ account information
     */
    function getAccountInfo(
        address account
    ) external view returns (PQAccount memory info) {
        return pqAccounts[account];
    }

    /**
     * @notice Check if an address has active PQ registration
     * @param account The address to check
     * @return active True if PQ is active
     */
    function isPQActive(address account) external view returns (bool active) {
        return pqAccounts[account].isActive;
    }

    /**
     * @notice Get current nonce for an address
     * @param account The address to query
     * @return Current nonce value
     */
    function getNonce(address account) external view returns (uint256) {
        return nonces[account];
    }

    /**
     * @notice Get protocol statistics
     * @return registrations Total number of PQ registrations
     * @return hybridVerifications Total hybrid verifications
     * @return pqOnlyVerifications Total PQ-only verifications
     */
    function getStats()
        external
        view
        returns (
            uint256 registrations,
            uint256 hybridVerifications,
            uint256 pqOnlyVerifications
        )
    {
        return (
            totalRegistrations,
            totalHybridVerifications,
            totalPQOnlyVerifications
        );
    }
}
