// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "../secret/SecretPrimitives.sol";

/**
 * @title SecretBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for Secret Network (SCRT) cross-chain privacy transfers
 *
 * @dev Bridge Architecture:
 *
 * Secret Network → PIL:
 * 1. User initiates private transfer on Secret Network
 * 2. CosmWasm contract with TEE processes transfer
 * 3. IBC packet created with encrypted payload
 * 4. Relayer submits proof to PIL with attestation
 * 5. PIL verifies attestation and IBC proof
 * 6. Nullifier derived from Secret Network state
 * 7. Assets minted on destination chain
 *
 * PIL → Secret Network:
 * 1. User burns assets on PIL with viewing key
 * 2. PIL nullifier registered
 * 3. IBC relayer submits withdrawal to Secret
 * 4. TEE processes withdrawal request
 * 5. Assets released on Secret Network
 *
 * Security Model:
 * - TEE attestation proves code integrity
 * - IBC light client verification
 * - Committee threshold signatures
 * - State proof verification
 * - Nullifier binding prevents double-spend
 * - Viewing keys for selective disclosure
 *
 * Privacy Features:
 * - Encrypted calldata (AES-SIV)
 * - Confidential contract state
 * - Private viewing keys
 * - Query permits for access control
 */
contract SecretBridgeAdapter is
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
    bytes32 public constant IBC_HANDLER_ROLE = keccak256("IBC_HANDLER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Secret Network primitives library
    SecretPrimitives public primitives;

    /// @notice PIL chain ID
    uint256 public pilChainId;

    /// @notice IBC channel for Secret Network
    SecretPrimitives.IBCChannel public ibcChannel;

    /// @notice Verified TEE enclaves (MRENCLAVE => approved)
    mapping(bytes32 => bool) public approvedEnclaves;

    /// @notice Verified TEE signers (MRSIGNER => approved)
    mapping(bytes32 => bool) public approvedSigners;

    /// @notice Used nullifiers (Secret-native)
    mapping(bytes32 => bool) public usedSecretNullifiers;

    /// @notice Used PIL nullifiers (for withdrawals)
    mapping(bytes32 => bool) public usedPILNullifiers;

    /// @notice Nullifier binding: Secret -> PIL
    mapping(bytes32 => bytes32) public secretToPILNullifier;

    /// @notice Nullifier binding: PIL -> Secret
    mapping(bytes32 => bytes32) public pilToSecretNullifier;

    /// @notice Verified IBC packet commitments
    mapping(bytes32 => bool) public verifiedPackets;

    /// @notice Pending withdrawals
    mapping(bytes32 => WithdrawalRequest) public pendingWithdrawals;

    /// @notice Attestation records
    mapping(bytes32 => AttestationRecord) public attestations;

    /// @notice Total deposited
    uint256 public totalDeposited;

    /// @notice Total withdrawn
    uint256 public totalWithdrawn;

    /// @notice Committee members
    mapping(address => bool) public committeeMembers;
    address[] public committeeMemberList;
    uint256 public committeeSize;

    /// @notice Committee threshold
    uint256 public committeeThreshold;

    /// @notice Deposit limits
    uint256 public minDeposit;
    uint256 public maxDeposit;
    uint256 public dailyDepositLimit;
    uint256 public dailyDepositTotal;
    uint256 public lastDepositResetTime;

    /// @notice IBC sequence numbers
    uint64 public nextSendSequence;
    uint64 public lastReceivedSequence;

    /// @notice Viewing key registry
    mapping(bytes32 => SecretPrimitives.ViewingKey) public viewingKeys;

    /// @notice Active query permits
    mapping(bytes32 => bool) public activePermits;

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
        bytes32 packetCommitment;
        uint64 sequence;
        bytes32 stateRoot;
        bytes32[] merkleProof;
        SecretPrimitives.EncryptedEnvelope encryptedData;
        SecretPrimitives.SGXQuote attestation;
        bytes committeeSignature;
        uint256 signatureCount;
    }

    struct WithdrawalRequest {
        bytes32 requestId;
        bytes32 pilNullifier;
        uint256 amount;
        string secretRecipient; // Secret Network address (bech32)
        SecretPrimitives.EncryptedEnvelope encryptedDestination;
        uint256 requestTime;
        uint256 signaturesCollected;
        mapping(address => bool) approvals;
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
        bytes32 indexed secretNullifier,
        bytes32 indexed pilNullifier,
        uint256 amount,
        uint64 sequence
    );

    event WithdrawalRequested(
        bytes32 indexed requestId,
        bytes32 indexed pilNullifier,
        uint256 amount,
        string secretRecipient
    );

    event WithdrawalApproved(
        bytes32 indexed requestId,
        address indexed approver,
        uint256 signaturesCollected
    );

    event WithdrawalExecuted(
        bytes32 indexed requestId,
        bytes32 indexed secretNullifier,
        uint64 sequence
    );

    event EnclaveApproved(bytes32 indexed mrEnclave, bytes32 indexed mrSigner);
    event EnclaveRevoked(bytes32 indexed mrEnclave);

    event IBCChannelUpdated(
        string channelId,
        string portId,
        string counterpartyChannelId
    );

    event CommitteeMemberAdded(address indexed member);
    event CommitteeMemberRemoved(address indexed member);

    event ViewingKeyRegistered(bytes32 indexed keyHash, address indexed owner);

    event QueryPermitIssued(
        bytes32 indexed permitId,
        address indexed granter,
        address indexed grantee
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidAmount();
    error InvalidProof();
    error InvalidAttestation();
    error SecretNullifierAlreadyUsed();
    error PILNullifierAlreadyUsed();
    error InvalidEnvelope();
    error InvalidCommitteeSignature();
    error InsufficientSignatures();
    error WithdrawalNotFound();
    error WithdrawalAlreadyApproved();
    error WithdrawalNotApproved();
    error NotCommitteeMember();
    error ExceedsDepositLimit();
    error InvalidIBCProof();
    error InvalidViewingKey();
    error InvalidPermit();
    error InvalidEncryptedData();

    // =========================================================================
    // MODIFIERS
    // =========================================================================

    modifier onlyCommitteeMember() {
        if (!committeeMembers[msg.sender]) revert NotCommitteeMember();
        _;
    }

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the bridge adapter
     * @param admin Admin address
     * @param _primitives Secret Network primitives library
     * @param _pilChainId PIL chain ID
     * @param _threshold Committee threshold
     */
    function initialize(
        address admin,
        address _primitives,
        uint256 _pilChainId,
        uint256 _threshold
    ) external initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        primitives = SecretPrimitives(_primitives);
        pilChainId = _pilChainId;
        committeeThreshold = _threshold;

        // Set default deposit limits
        minDeposit = 0.001 ether;
        maxDeposit = 100 ether;
        dailyDepositLimit = 1000 ether;
        lastDepositResetTime = block.timestamp;
    }

    // =========================================================================
    // DEPOSIT (Secret → PIL)
    // =========================================================================

    /**
     * @notice Process deposit from Secret Network
     * @param proof Deposit proof with IBC and attestation data
     * @param amount Amount to deposit
     */
    function deposit(
        DepositProof calldata proof,
        uint256 amount
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        // Validate amount
        if (amount == 0 || amount < minDeposit || amount > maxDeposit) {
            revert InvalidAmount();
        }

        // Check daily limit
        _checkAndUpdateDailyLimit(amount);

        // Verify attestation
        if (
            !primitives.verifyAttestation(
                proof.attestation,
                proof.attestation.mrEnclave,
                proof.attestation.mrSigner
            )
        ) {
            revert InvalidAttestation();
        }

        // Verify enclave is approved
        if (!approvedEnclaves[proof.attestation.mrEnclave]) {
            revert InvalidAttestation();
        }

        // Verify IBC packet commitment
        bytes32 commitment = primitives.computeIBCPacketCommitment(
            ibcChannel,
            proof.sequence,
            abi.encode(proof.encryptedData)
        );

        if (
            !primitives.verifyIBCProof(
                proof.stateRoot,
                commitment,
                proof.merkleProof
            )
        ) {
            revert InvalidIBCProof();
        }

        // Mark packet as processed
        if (verifiedPackets[proof.packetCommitment]) {
            revert SecretNullifierAlreadyUsed();
        }
        verifiedPackets[proof.packetCommitment] = true;

        // Derive nullifiers
        bytes32 secretNullifier = keccak256(
            abi.encodePacked(
                proof.packetCommitment,
                proof.sequence,
                proof.attestation.mrEnclave
            )
        );

        bytes32 pilNullifier = primitives.deriveCrossDomainNullifier(
            secretNullifier,
            primitives.PIL_SECRET_DOMAIN(),
            bytes32(pilChainId)
        );

        // Check Secret nullifier not already used
        if (usedSecretNullifiers[secretNullifier]) {
            revert SecretNullifierAlreadyUsed();
        }

        // Register nullifiers
        usedSecretNullifiers[secretNullifier] = true;
        secretToPILNullifier[secretNullifier] = pilNullifier;
        pilToSecretNullifier[pilNullifier] = secretNullifier;

        // Update totals
        totalDeposited += amount;
        lastReceivedSequence = proof.sequence;

        // Mint wrapped tokens (placeholder)
        _mintWrappedTokens(msg.sender, amount);

        emit Deposit(secretNullifier, pilNullifier, amount, proof.sequence);
    }

    // =========================================================================
    // WITHDRAWAL (PIL → Secret)
    // =========================================================================

    /**
     * @notice Request withdrawal to Secret Network
     * @param pilNullifier PIL nullifier to consume
     * @param amount Amount to withdraw
     * @param secretRecipient Recipient address on Secret Network
     * @param envelope Encrypted withdrawal data
     */
    function requestWithdrawal(
        bytes32 pilNullifier,
        uint256 amount,
        string calldata secretRecipient,
        SecretPrimitives.EncryptedEnvelope calldata envelope
    ) external nonReentrant whenNotPaused {
        // Validate amount
        uint256 available = totalDeposited - totalWithdrawn;
        if (amount == 0 || amount > available) {
            revert InvalidAmount();
        }

        // Check PIL nullifier not already used
        if (usedPILNullifiers[pilNullifier]) {
            revert PILNullifierAlreadyUsed();
        }

        // Validate envelope
        if (envelope.ciphertext.length == 0) {
            revert InvalidEncryptedData();
        }

        // Create withdrawal request
        bytes32 requestId = keccak256(
            abi.encodePacked(
                pilNullifier,
                amount,
                secretRecipient,
                block.timestamp,
                msg.sender
            )
        );

        WithdrawalRequest storage request = pendingWithdrawals[requestId];
        request.requestId = requestId;
        request.pilNullifier = pilNullifier;
        request.amount = amount;
        request.secretRecipient = secretRecipient;
        request.encryptedDestination = envelope;
        request.requestTime = block.timestamp;
        request.status = WithdrawalStatus.Pending;

        // Mark PIL nullifier as used
        usedPILNullifiers[pilNullifier] = true;

        emit WithdrawalRequested(
            requestId,
            pilNullifier,
            amount,
            secretRecipient
        );
    }

    /**
     * @notice Approve withdrawal request (committee member)
     * @param requestId Request to approve
     */
    function approveWithdrawal(bytes32 requestId) external onlyCommitteeMember {
        WithdrawalRequest storage request = pendingWithdrawals[requestId];

        if (request.requestId == bytes32(0)) {
            revert WithdrawalNotFound();
        }

        if (request.status != WithdrawalStatus.Pending) {
            revert WithdrawalAlreadyApproved();
        }

        if (request.approvals[msg.sender]) {
            revert WithdrawalAlreadyApproved();
        }

        request.approvals[msg.sender] = true;
        request.signaturesCollected++;

        emit WithdrawalApproved(
            requestId,
            msg.sender,
            request.signaturesCollected
        );

        // Check if threshold met
        if (request.signaturesCollected >= committeeThreshold) {
            request.status = WithdrawalStatus.Approved;
        }
    }

    /**
     * @notice Execute approved withdrawal
     * @param requestId Request to execute
     */
    function executeWithdrawal(
        bytes32 requestId
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        WithdrawalRequest storage request = pendingWithdrawals[requestId];

        if (request.requestId == bytes32(0)) {
            revert WithdrawalNotFound();
        }

        if (request.status != WithdrawalStatus.Approved) {
            revert WithdrawalNotApproved();
        }

        // Derive Secret nullifier binding
        bytes32 secretNullifier = primitives.derivePILToSecretBinding(
            request.pilNullifier
        );

        // Update totals
        totalWithdrawn += request.amount;

        // Update status
        request.status = WithdrawalStatus.Executed;

        // Burn wrapped tokens (placeholder)
        _burnWrappedTokens(request.amount);

        // Get next sequence
        uint64 sequence = nextSendSequence++;

        emit WithdrawalExecuted(requestId, secretNullifier, sequence);
    }

    // =========================================================================
    // VIEWING KEY MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a viewing key
     * @param viewingKey The viewing key to register
     */
    function registerViewingKey(
        SecretPrimitives.ViewingKey calldata viewingKey
    ) external {
        if (viewingKey.owner != msg.sender) {
            revert InvalidViewingKey();
        }

        if (!primitives.isValidViewingKey(viewingKey)) {
            revert InvalidViewingKey();
        }

        bytes32 keyHash = primitives.hashViewingKey(viewingKey);
        viewingKeys[keyHash] = viewingKey;

        emit ViewingKeyRegistered(keyHash, msg.sender);
    }

    /**
     * @notice Validate a viewing key
     * @param keyHash Hash of the viewing key
     * @return True if valid
     */
    function isViewingKeyValid(bytes32 keyHash) external view returns (bool) {
        SecretPrimitives.ViewingKey storage vk = viewingKeys[keyHash];
        return primitives.isValidViewingKey(vk);
    }

    // =========================================================================
    // QUERY PERMIT MANAGEMENT
    // =========================================================================

    /**
     * @notice Issue a query permit
     * @param grantee Who can use the permit
     * @param permissions Allowed query types
     * @param expiresAt Expiration timestamp
     * @return permitId The permit ID
     */
    function issueQueryPermit(
        address grantee,
        bytes32[] calldata permissions,
        uint256 expiresAt
    ) external returns (bytes32 permitId) {
        SecretPrimitives.QueryPermit memory permit = primitives
            .createQueryPermit(msg.sender, grantee, permissions, expiresAt);

        permitId = permit.permitId;
        activePermits[permitId] = true;

        emit QueryPermitIssued(permitId, msg.sender, grantee);
    }

    /**
     * @notice Revoke a query permit
     * @param permitId Permit to revoke
     */
    function revokeQueryPermit(bytes32 permitId) external {
        activePermits[permitId] = false;
    }

    // =========================================================================
    // IBC CHANNEL MANAGEMENT
    // =========================================================================

    /**
     * @notice Set IBC channel
     * @param channelId Channel ID
     * @param portId Port ID
     * @param counterpartyChannelId Counterparty channel ID
     * @param counterpartyPortId Counterparty port ID
     */
    function setIBCChannel(
        string calldata channelId,
        string calldata portId,
        string calldata counterpartyChannelId,
        string calldata counterpartyPortId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        ibcChannel.channelId = channelId;
        ibcChannel.portId = portId;
        ibcChannel.counterpartyChannelId = counterpartyChannelId;
        ibcChannel.counterpartyPortId = counterpartyPortId;

        emit IBCChannelUpdated(channelId, portId, counterpartyChannelId);
    }

    // =========================================================================
    // COMMITTEE MANAGEMENT
    // =========================================================================

    /**
     * @notice Add committee member
     * @param member Address to add
     */
    function addCommitteeMember(
        address member
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!committeeMembers[member]) {
            committeeMembers[member] = true;
            committeeMemberList.push(member);
            committeeSize++;
            _grantRole(COMMITTEE_ROLE, member);
            emit CommitteeMemberAdded(member);
        }
    }

    /**
     * @notice Remove committee member
     * @param member Address to remove
     */
    function removeCommitteeMember(
        address member
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (committeeMembers[member]) {
            committeeMembers[member] = false;
            committeeSize--;
            _revokeRole(COMMITTEE_ROLE, member);

            // Remove from list
            for (uint256 i = 0; i < committeeMemberList.length; i++) {
                if (committeeMemberList[i] == member) {
                    committeeMemberList[i] = committeeMemberList[
                        committeeMemberList.length - 1
                    ];
                    committeeMemberList.pop();
                    break;
                }
            }

            emit CommitteeMemberRemoved(member);
        }
    }

    /**
     * @notice Set committee threshold
     * @param threshold New threshold
     */
    function setCommitteeThreshold(
        uint256 threshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            threshold > 0 && threshold <= committeeSize,
            "Invalid threshold"
        );
        committeeThreshold = threshold;
    }

    /**
     * @notice Get committee size
     * @return Size of committee
     */
    function getCommitteeSize() external view returns (uint256) {
        return committeeSize;
    }

    /**
     * @notice Check if address is committee member
     * @param member Address to check
     * @return True if member
     */
    function isCommitteeMember(address member) external view returns (bool) {
        return committeeMembers[member];
    }

    // =========================================================================
    // ENCLAVE MANAGEMENT
    // =========================================================================

    /**
     * @notice Approve TEE enclave
     * @param mrEnclave Enclave measurement
     * @param mrSigner Signer measurement
     */
    function approveEnclave(
        bytes32 mrEnclave,
        bytes32 mrSigner
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        approvedEnclaves[mrEnclave] = true;
        approvedSigners[mrSigner] = true;
        emit EnclaveApproved(mrEnclave, mrSigner);
    }

    /**
     * @notice Revoke TEE enclave
     * @param mrEnclave Enclave measurement
     */
    function revokeEnclave(
        bytes32 mrEnclave
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        approvedEnclaves[mrEnclave] = false;
        emit EnclaveRevoked(mrEnclave);
    }

    // =========================================================================
    // DEPOSIT LIMITS
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
     * @notice Check and update daily deposit limit
     * @param amount Amount to deposit
     */
    function _checkAndUpdateDailyLimit(uint256 amount) internal {
        // Reset daily counter if new day
        if (block.timestamp - lastDepositResetTime >= 1 days) {
            dailyDepositTotal = 0;
            lastDepositResetTime = block.timestamp;
        }

        // Check limit
        if (dailyDepositTotal + amount > dailyDepositLimit) {
            revert ExceedsDepositLimit();
        }

        dailyDepositTotal += amount;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Check if Secret nullifier is used
     * @param nullifier Nullifier to check
     * @return True if used
     */
    function isSecretNullifierUsed(
        bytes32 nullifier
    ) external view returns (bool) {
        return usedSecretNullifiers[nullifier];
    }

    /**
     * @notice Check if PIL nullifier is used
     * @param nullifier Nullifier to check
     * @return True if used
     */
    function isPILNullifierUsed(
        bytes32 nullifier
    ) external view returns (bool) {
        return usedPILNullifiers[nullifier];
    }

    /**
     * @notice Get available balance
     * @return Available balance for withdrawals
     */
    function getAvailableBalance() external view returns (uint256) {
        return totalDeposited - totalWithdrawn;
    }

    /**
     * @notice Get withdrawal status
     * @param requestId Request ID
     * @return status Withdrawal status
     */
    function getWithdrawalStatus(
        bytes32 requestId
    ) external view returns (WithdrawalStatus) {
        return pendingWithdrawals[requestId].status;
    }

    /**
     * @notice Check if address has approved withdrawal
     * @param requestId Request ID
     * @param approver Approver address
     * @return True if approved
     */
    function hasApproved(
        bytes32 requestId,
        address approver
    ) external view returns (bool) {
        return pendingWithdrawals[requestId].approvals[approver];
    }

    // =========================================================================
    // PAUSE
    // =========================================================================

    /**
     * @notice Pause the bridge
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the bridge
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Check if bridge is paused
     * @return True if paused
     */
    function isPaused() external view returns (bool) {
        return paused();
    }

    // =========================================================================
    // UUPS UPGRADE
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    // =========================================================================
    // INTERNAL HELPERS
    // =========================================================================

    /**
     * @notice Mint wrapped tokens (placeholder)
     * @param recipient Token recipient
     * @param amount Amount to mint
     */
    function _mintWrappedTokens(address recipient, uint256 amount) internal {
        // Placeholder for wrapped token minting
        // In production, this would interact with a wrapped SCRT token
        (recipient, amount); // Silence unused warnings
    }

    /**
     * @notice Burn wrapped tokens (placeholder)
     * @param amount Amount to burn
     */
    function _burnWrappedTokens(uint256 amount) internal {
        // Placeholder for wrapped token burning
        // In production, this would interact with a wrapped SCRT token
        (amount); // Silence unused warning
    }
}
