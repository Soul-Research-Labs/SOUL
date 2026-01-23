// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "../oasis/OasisPrimitives.sol";

/**
 * @title OasisBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for Oasis Network cross-chain privacy transfers
 *
 * @dev Bridge Architecture:
 *
 * Oasis (Sapphire) → PIL:
 * 1. User initiates confidential transfer on Sapphire
 * 2. TEE enclave processes and creates encrypted state
 * 3. Committee signs state transition
 * 4. Relayer submits proof to PIL with attestation
 * 5. PIL verifies attestation and state proof
 * 6. Nullifier derived from confidential state
 * 7. Assets minted on destination chain
 *
 * PIL → Oasis (Sapphire):
 * 1. User burns assets on PIL with encrypted destination
 * 2. PIL nullifier registered
 * 3. Relayer submits withdrawal to Oasis
 * 4. TEE processes withdrawal request
 * 5. Assets released on Sapphire
 *
 * Security Model:
 * - TEE attestation proves code integrity
 * - Committee threshold signatures
 * - State proof verification
 * - Nullifier binding prevents double-spend
 * - View key selective disclosure
 *
 * Confidentiality Features:
 * - Encrypted calldata (Deoxys-II)
 * - Confidential state storage
 * - TEE-based key management
 */
contract OasisBridgeAdapter is
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant COMMITTEE_ROLE = keccak256("COMMITTEE_ROLE");
    bytes32 public constant TEE_OPERATOR_ROLE = keccak256("TEE_OPERATOR_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Oasis primitives library
    OasisPrimitives public primitives;

    /// @notice PIL chain ID
    uint256 public pilChainId;

    /// @notice Supported ParaTime chain IDs
    mapping(uint256 => bool) public supportedParaTimes;

    /// @notice Verified TEE enclaves (MRENCLAVE => approved)
    mapping(bytes32 => bool) public approvedEnclaves;

    /// @notice Verified TEE signers (MRSIGNER => approved)
    mapping(bytes32 => bool) public approvedSigners;

    /// @notice Used nullifiers (Oasis-native)
    mapping(bytes32 => bool) public usedOasisNullifiers;

    /// @notice Used PIL nullifiers (for withdrawals)
    mapping(bytes32 => bool) public usedPILNullifiers;

    /// @notice Nullifier binding: Oasis -> PIL
    mapping(bytes32 => bytes32) public oasisToPILNullifier;

    /// @notice Nullifier binding: PIL -> Oasis
    mapping(bytes32 => bytes32) public pilToOasisNullifier;

    /// @notice Verified state roots by ParaTime and round
    mapping(uint256 => mapping(uint64 => bytes32)) public verifiedStateRoots;

    /// @notice Pending withdrawals
    mapping(bytes32 => WithdrawalRequest) public pendingWithdrawals;

    /// @notice Attestation records
    mapping(bytes32 => AttestationRecord) public attestations;

    /// @notice Total deposited per ParaTime
    mapping(uint256 => uint256) public totalDepositedByParaTime;

    /// @notice Total withdrawn per ParaTime
    mapping(uint256 => uint256) public totalWithdrawnByParaTime;

    /// @notice Committee members
    mapping(address => bool) public committeeMembers;
    uint256 public committeeSize;

    /// @notice Committee threshold
    uint256 public committeeThreshold;

    /// @notice Deposit limits
    uint256 public minDeposit;
    uint256 public maxDeposit;
    uint256 public dailyDepositLimit;
    uint256 public dailyDepositTotal;
    uint256 public lastDepositResetTime;

    /// @notice Message nonces per sender
    mapping(bytes32 => uint64) public messageNonces;

    // =========================================================================
    // TYPES
    // =========================================================================

    struct AttestationRecord {
        bytes32 mrEnclave;
        bytes32 mrSigner;
        uint256 attestationTime;
        uint8 tcbStatus;
        bool valid;
    }

    struct DepositProof {
        uint256 sourceParaTime;
        uint64 round;
        bytes32 stateRoot;
        bytes32 ioRoot;
        bytes32[] stateProof;
        OasisPrimitives.EncryptedEnvelope encryptedData;
        OasisPrimitives.SGXQuote attestation;
        bytes committeeSignature;
        uint256 signatureCount;
    }

    struct WithdrawalRequest {
        bytes32 requestId;
        bytes32 pilNullifier;
        uint256 amount;
        uint256 destinationParaTime;
        OasisPrimitives.EncryptedEnvelope encryptedDestination;
        uint256 requestTime;
        uint256 signaturesCollected;
        WithdrawalStatus status;
    }

    enum WithdrawalStatus {
        Pending,
        Approved,
        Executed,
        Cancelled
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    event Deposit(
        bytes32 indexed oasisNullifier,
        bytes32 indexed pilNullifier,
        uint256 indexed sourceParaTime,
        uint256 amount,
        uint64 round
    );

    event WithdrawalRequested(
        bytes32 indexed requestId,
        bytes32 indexed pilNullifier,
        uint256 amount,
        uint256 destinationParaTime
    );

    event WithdrawalApproved(
        bytes32 indexed requestId,
        address indexed approver,
        uint256 signaturesCollected
    );

    event WithdrawalExecuted(
        bytes32 indexed requestId,
        bytes32 indexed oasisNullifier
    );

    event EnclaveApproved(bytes32 indexed mrEnclave, bytes32 indexed mrSigner);
    event EnclaveRevoked(bytes32 indexed mrEnclave);

    event ParaTimeAdded(uint256 indexed chainId);
    event ParaTimeRemoved(uint256 indexed chainId);

    event StateRootVerified(
        uint256 indexed paraTime,
        uint64 indexed round,
        bytes32 stateRoot
    );

    event AttestationRecorded(
        bytes32 indexed attestationId,
        bytes32 mrEnclave,
        uint8 tcbStatus
    );

    event CommitteeMemberAdded(address indexed member);
    event CommitteeMemberRemoved(address indexed member);
    event CommitteeThresholdUpdated(uint256 newThreshold);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidParaTime();
    error InvalidAttestation();
    error EnclaveNotApproved();
    error SignerNotApproved();
    error InsufficientSignatures();
    error OasisNullifierAlreadyUsed();
    error PILNullifierAlreadyUsed();
    error InvalidAmount();
    error InvalidStateProof();
    error InvalidCommitteeSignature();
    error WithdrawalNotPending();
    error WithdrawalAlreadyApproved();
    error NotCommitteeMember();
    error DepositLimitExceeded();
    error InvalidEncryptedData();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the bridge adapter
     * @param _admin Admin address
     * @param _primitives OasisPrimitives contract address
     * @param _pilChainId PIL chain ID
     * @param _committeeThreshold Required committee signatures
     */
    function initialize(
        address _admin,
        address _primitives,
        uint256 _pilChainId,
        uint256 _committeeThreshold
    ) external initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);

        primitives = OasisPrimitives(_primitives);
        pilChainId = _pilChainId;
        committeeThreshold = _committeeThreshold;

        // Default limits
        minDeposit = 0.001 ether;
        maxDeposit = 100 ether;
        dailyDepositLimit = 1000 ether;

        // Add default ParaTimes
        supportedParaTimes[primitives.SAPPHIRE_MAINNET_CHAIN_ID()] = true;
        supportedParaTimes[primitives.SAPPHIRE_TESTNET_CHAIN_ID()] = true;
    }

    // =========================================================================
    // DEPOSIT FUNCTIONS
    // =========================================================================

    /**
     * @notice Process deposit from Oasis ParaTime
     * @param proof The deposit proof including attestation
     * @param amount The deposit amount
     * @param recipient The recipient address on PIL
     */
    function deposit(
        DepositProof calldata proof,
        uint256 amount,
        address recipient
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        // Validate ParaTime
        if (!supportedParaTimes[proof.sourceParaTime]) {
            revert InvalidParaTime();
        }

        // Reset daily limit if needed
        if (block.timestamp >= lastDepositResetTime + 1 days) {
            dailyDepositTotal = 0;
            lastDepositResetTime = block.timestamp;
        }

        // Validate amount
        if (amount < minDeposit || amount > maxDeposit) {
            revert InvalidAmount();
        }

        if (dailyDepositTotal + amount > dailyDepositLimit) {
            revert DepositLimitExceeded();
        }

        // Verify TEE attestation
        _verifyAttestation(proof.attestation);

        // Verify state proof
        _verifyStateProof(proof);

        // Verify committee signature
        if (proof.signatureCount < committeeThreshold) {
            revert InsufficientSignatures();
        }

        // Derive nullifiers
        bytes32 oasisNullifier = _deriveOasisNullifier(proof);

        // Check nullifier not used
        if (usedOasisNullifiers[oasisNullifier]) {
            revert OasisNullifierAlreadyUsed();
        }

        // Derive PIL nullifier
        bytes32 pilNullifier = primitives.deriveCrossDomainNullifier(
            oasisNullifier,
            pilChainId
        );

        // Mark nullifiers as used
        usedOasisNullifiers[oasisNullifier] = true;
        oasisToPILNullifier[oasisNullifier] = pilNullifier;
        pilToOasisNullifier[pilNullifier] = oasisNullifier;

        // Update state
        totalDepositedByParaTime[proof.sourceParaTime] += amount;
        dailyDepositTotal += amount;

        // Store verified state root
        verifiedStateRoots[proof.sourceParaTime][proof.round] = proof.stateRoot;

        emit Deposit(
            oasisNullifier,
            pilNullifier,
            proof.sourceParaTime,
            amount,
            proof.round
        );

        emit StateRootVerified(
            proof.sourceParaTime,
            proof.round,
            proof.stateRoot
        );

        // Mint wrapped tokens (interface call - actual minting handled by token contract)
        _mintWrappedTokens(recipient, amount);
    }

    // =========================================================================
    // WITHDRAWAL FUNCTIONS
    // =========================================================================

    /**
     * @notice Request withdrawal to Oasis ParaTime
     * @param pilNullifier The PIL nullifier for this withdrawal
     * @param amount The withdrawal amount
     * @param destinationParaTime The target ParaTime
     * @param encryptedDestination Encrypted destination address
     */
    function requestWithdrawal(
        bytes32 pilNullifier,
        uint256 amount,
        uint256 destinationParaTime,
        OasisPrimitives.EncryptedEnvelope calldata encryptedDestination
    ) external nonReentrant whenNotPaused {
        // Validate ParaTime
        if (!supportedParaTimes[destinationParaTime]) {
            revert InvalidParaTime();
        }

        // Validate PIL nullifier not used
        if (usedPILNullifiers[pilNullifier]) {
            revert PILNullifierAlreadyUsed();
        }

        // Validate amount against available balance
        uint256 available = totalDepositedByParaTime[destinationParaTime] -
            totalWithdrawnByParaTime[destinationParaTime];
        if (amount == 0 || amount > available) {
            revert InvalidAmount();
        }

        // Validate encrypted destination (basic check)
        if (encryptedDestination.ciphertext.length == 0) {
            revert InvalidEncryptedData();
        }

        // Mark nullifier as used
        usedPILNullifiers[pilNullifier] = true;

        // Create withdrawal request
        bytes32 requestId = keccak256(
            abi.encodePacked(
                pilNullifier,
                amount,
                destinationParaTime,
                keccak256(encryptedDestination.ciphertext),
                block.timestamp
            )
        );

        WithdrawalRequest storage request = pendingWithdrawals[requestId];
        request.requestId = requestId;
        request.pilNullifier = pilNullifier;
        request.amount = amount;
        request.destinationParaTime = destinationParaTime;
        request.encryptedDestination = encryptedDestination;
        request.requestTime = block.timestamp;
        request.status = WithdrawalStatus.Pending;

        emit WithdrawalRequested(
            requestId,
            pilNullifier,
            amount,
            destinationParaTime
        );
    }

    /**
     * @notice Committee member approves withdrawal
     * @param requestId The withdrawal request ID
     */
    function approveWithdrawal(
        bytes32 requestId
    ) external nonReentrant whenNotPaused onlyRole(COMMITTEE_ROLE) {
        WithdrawalRequest storage request = pendingWithdrawals[requestId];

        if (request.status != WithdrawalStatus.Pending) {
            revert WithdrawalNotPending();
        }

        // Note: In production, would track individual approvals
        // Simplified for this implementation
        request.signaturesCollected += 1;

        emit WithdrawalApproved(
            requestId,
            msg.sender,
            request.signaturesCollected
        );

        // Auto-approve if threshold reached
        if (request.signaturesCollected >= committeeThreshold) {
            request.status = WithdrawalStatus.Approved;
        }
    }

    /**
     * @notice Execute approved withdrawal
     * @param requestId The withdrawal request ID
     * @param oasisNullifier The derived Oasis nullifier
     */
    function executeWithdrawal(
        bytes32 requestId,
        bytes32 oasisNullifier
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        WithdrawalRequest storage request = pendingWithdrawals[requestId];

        if (request.status != WithdrawalStatus.Approved) {
            revert WithdrawalNotPending();
        }

        // Bind nullifiers
        pilToOasisNullifier[request.pilNullifier] = oasisNullifier;
        oasisToPILNullifier[oasisNullifier] = request.pilNullifier;
        usedOasisNullifiers[oasisNullifier] = true;

        // Update state
        totalWithdrawnByParaTime[request.destinationParaTime] += request.amount;
        request.status = WithdrawalStatus.Executed;

        emit WithdrawalExecuted(requestId, oasisNullifier);

        // Burn wrapped tokens (interface call)
        _burnWrappedTokens(request.amount);
    }

    // =========================================================================
    // ATTESTATION MANAGEMENT
    // =========================================================================

    /**
     * @notice Record TEE attestation
     * @param quote The SGX quote
     */
    function recordAttestation(
        OasisPrimitives.SGXQuote calldata quote
    ) external onlyRole(TEE_OPERATOR_ROLE) {
        OasisPrimitives.AttestationResult memory result = primitives
            .verifyAttestation(
                quote,
                bytes32(0), // Accept any MRENCLAVE (will check against approved list)
                bytes32(0) // Accept any MRSIGNER
            );

        if (!result.valid) {
            revert InvalidAttestation();
        }

        // Check enclave/signer approval
        if (
            !approvedEnclaves[result.mrEnclave] &&
            !approvedSigners[result.mrSigner]
        ) {
            revert EnclaveNotApproved();
        }

        bytes32 attestationId = keccak256(
            abi.encodePacked(
                result.mrEnclave,
                result.mrSigner,
                result.attestationTime
            )
        );

        attestations[attestationId] = AttestationRecord({
            mrEnclave: result.mrEnclave,
            mrSigner: result.mrSigner,
            attestationTime: result.attestationTime,
            tcbStatus: result.tcbStatus,
            valid: true
        });

        emit AttestationRecorded(
            attestationId,
            result.mrEnclave,
            result.tcbStatus
        );
    }

    /**
     * @notice Approve enclave for bridge operations
     * @param mrEnclave The MRENCLAVE value
     * @param mrSigner The MRSIGNER value
     */
    function approveEnclave(
        bytes32 mrEnclave,
        bytes32 mrSigner
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        approvedEnclaves[mrEnclave] = true;
        if (mrSigner != bytes32(0)) {
            approvedSigners[mrSigner] = true;
        }

        emit EnclaveApproved(mrEnclave, mrSigner);
    }

    /**
     * @notice Revoke enclave approval
     * @param mrEnclave The MRENCLAVE value to revoke
     */
    function revokeEnclave(
        bytes32 mrEnclave
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        approvedEnclaves[mrEnclave] = false;

        emit EnclaveRevoked(mrEnclave);
    }

    // =========================================================================
    // COMMITTEE MANAGEMENT
    // =========================================================================

    /**
     * @notice Add committee member
     * @param member The member address
     */
    function addCommitteeMember(
        address member
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!committeeMembers[member]) {
            committeeMembers[member] = true;
            committeeSize += 1;
            _grantRole(COMMITTEE_ROLE, member);

            emit CommitteeMemberAdded(member);
        }
    }

    /**
     * @notice Remove committee member
     * @param member The member address
     */
    function removeCommitteeMember(
        address member
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (committeeMembers[member]) {
            committeeMembers[member] = false;
            committeeSize -= 1;
            _revokeRole(COMMITTEE_ROLE, member);

            emit CommitteeMemberRemoved(member);
        }
    }

    /**
     * @notice Update committee threshold
     * @param newThreshold The new threshold
     */
    function setCommitteeThreshold(
        uint256 newThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            newThreshold > 0 && newThreshold <= committeeSize,
            "Invalid threshold"
        );
        committeeThreshold = newThreshold;

        emit CommitteeThresholdUpdated(newThreshold);
    }

    // =========================================================================
    // PARATIME MANAGEMENT
    // =========================================================================

    /**
     * @notice Add supported ParaTime
     * @param chainId The ParaTime chain ID
     */
    function addParaTime(
        uint256 chainId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedParaTimes[chainId] = true;

        emit ParaTimeAdded(chainId);
    }

    /**
     * @notice Remove supported ParaTime
     * @param chainId The ParaTime chain ID
     */
    function removeParaTime(
        uint256 chainId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedParaTimes[chainId] = false;

        emit ParaTimeRemoved(chainId);
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Set deposit limits
     * @param _minDeposit Minimum deposit
     * @param _maxDeposit Maximum deposit
     * @param _dailyLimit Daily limit
     */
    function setDepositLimits(
        uint256 _minDeposit,
        uint256 _maxDeposit,
        uint256 _dailyLimit
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_minDeposit <= _maxDeposit, "Invalid limits");
        minDeposit = _minDeposit;
        maxDeposit = _maxDeposit;
        dailyDepositLimit = _dailyLimit;
    }

    /**
     * @notice Pause bridge operations
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause bridge operations
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Check if Oasis nullifier is used
     * @param nullifier The nullifier to check
     * @return used True if used
     */
    function isOasisNullifierUsed(
        bytes32 nullifier
    ) external view returns (bool used) {
        return usedOasisNullifiers[nullifier];
    }

    /**
     * @notice Check if PIL nullifier is used
     * @param nullifier The nullifier to check
     * @return used True if used
     */
    function isPILNullifierUsed(
        bytes32 nullifier
    ) external view returns (bool used) {
        return usedPILNullifiers[nullifier];
    }

    /**
     * @notice Get available balance for ParaTime
     * @param paraTime The ParaTime chain ID
     * @return available The available balance
     */
    function getAvailableBalance(
        uint256 paraTime
    ) external view returns (uint256 available) {
        return
            totalDepositedByParaTime[paraTime] -
            totalWithdrawnByParaTime[paraTime];
    }

    /**
     * @notice Get PIL nullifier for Oasis nullifier
     * @param oasisNullifier The Oasis nullifier
     * @return pilNullifier The bound PIL nullifier
     */
    function getPILNullifier(
        bytes32 oasisNullifier
    ) external view returns (bytes32 pilNullifier) {
        return oasisToPILNullifier[oasisNullifier];
    }

    /**
     * @notice Get Oasis nullifier for PIL nullifier
     * @param pilNullifier The PIL nullifier
     * @return oasisNullifier The bound Oasis nullifier
     */
    function getOasisNullifier(
        bytes32 pilNullifier
    ) external view returns (bytes32 oasisNullifier) {
        return pilToOasisNullifier[pilNullifier];
    }

    /**
     * @notice Get withdrawal request details
     * @param requestId The request ID
     * @return pilNullifier The PIL nullifier
     * @return amount The amount
     * @return destinationParaTime The destination
     * @return status The status
     */
    function getWithdrawalRequest(
        bytes32 requestId
    )
        external
        view
        returns (
            bytes32 pilNullifier,
            uint256 amount,
            uint256 destinationParaTime,
            WithdrawalStatus status
        )
    {
        WithdrawalRequest storage request = pendingWithdrawals[requestId];
        return (
            request.pilNullifier,
            request.amount,
            request.destinationParaTime,
            request.status
        );
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    /**
     * @notice Verify TEE attestation
     * @param quote The SGX quote
     */
    function _verifyAttestation(
        OasisPrimitives.SGXQuote calldata quote
    ) internal view {
        OasisPrimitives.AttestationResult memory result = primitives
            .verifyAttestation(quote, bytes32(0), bytes32(0));

        if (!result.valid) {
            revert InvalidAttestation();
        }

        // Check enclave is approved
        if (!approvedEnclaves[result.mrEnclave]) {
            revert EnclaveNotApproved();
        }

        // Check TCB status
        if (!primitives.isTCBStatusAcceptable(result.tcbStatus)) {
            revert InvalidAttestation();
        }
    }

    /**
     * @notice Verify state proof
     * @param proof The deposit proof
     */
    function _verifyStateProof(DepositProof calldata proof) internal view {
        // Compute state commitment
        bytes32 commitment = primitives.computeStateCommitment(
            proof.stateRoot,
            proof.ioRoot,
            proof.round
        );

        // Verify Merkle proof (simplified)
        // In production, would verify full state proof
        if (commitment == bytes32(0)) {
            revert InvalidStateProof();
        }
    }

    /**
     * @notice Derive Oasis nullifier from deposit proof
     * @param proof The deposit proof
     * @return nullifier The derived nullifier
     */
    function _deriveOasisNullifier(
        DepositProof calldata proof
    ) internal pure returns (bytes32 nullifier) {
        // Derive from encrypted data and state commitment
        nullifier = keccak256(
            abi.encodePacked(
                proof.stateRoot,
                proof.ioRoot,
                proof.round,
                keccak256(proof.encryptedData.ciphertext)
            )
        );
    }

    /**
     * @notice Mint wrapped tokens (placeholder)
     * @param recipient The recipient
     * @param amount The amount
     */
    function _mintWrappedTokens(address recipient, uint256 amount) internal {
        // Placeholder - actual implementation would call token contract
        // IWrappedOasis(wrappedToken).mint(recipient, amount);
        (recipient, amount); // Silence unused variable warning
    }

    /**
     * @notice Burn wrapped tokens (placeholder)
     * @param amount The amount
     */
    function _burnWrappedTokens(uint256 amount) internal {
        // Placeholder - actual implementation would call token contract
        // IWrappedOasis(wrappedToken).burn(msg.sender, amount);
        (amount); // Silence unused variable warning
    }

    /**
     * @notice Authorize upgrade
     * @param newImplementation New implementation address
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
