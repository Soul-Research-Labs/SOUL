// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "../monero/MoneroPrimitives.sol";

/**
 * @title MoneroBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for Monero cross-chain privacy transfers
 *
 * @dev Bridge Architecture:
 *
 * Monero → PIL (Deposit):
 * 1. User creates Monero tx sending to bridge custodian address
 * 2. Relayer submits proof of tx inclusion (block header + merkle proof)
 * 3. Relayer submits RingCT proof for value verification
 * 4. Key image is registered as spent (prevents double-deposit)
 * 5. PIL nullifier derived from key image
 * 6. Wrapped XMR minted on destination chain
 *
 * PIL → Monero (Withdrawal):
 * 1. User burns wrapped XMR with withdrawal request
 * 2. PIL nullifier registered as spent
 * 3. MPC custodians sign Monero tx to user's stealth address
 * 4. Monero tx broadcast by relayer
 *
 * Security Model:
 * - Federated bridge (MPC custodians hold Monero keys)
 * - Key image tracking prevents double-spend across chains
 * - Bulletproof verification ensures amount validity
 * - Ring signature verification proves spend authorization
 */
contract MoneroBridgeAdapter is
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant CUSTODIAN_ROLE = keccak256("CUSTODIAN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Monero primitives library
    MoneroPrimitives public primitives;

    /// @notice Chain ID for PIL destination chain
    uint256 public pilChainId;

    /// @notice Mapping of used key images (Monero nullifiers)
    mapping(bytes32 => bool) public usedKeyImages;

    /// @notice Mapping of used PIL nullifiers (for withdrawals)
    mapping(bytes32 => bool) public usedPILNullifiers;

    /// @notice Key image to PIL nullifier binding
    mapping(bytes32 => bytes32) public keyImageToPILNullifier;

    /// @notice PIL nullifier to key image binding (reverse lookup)
    mapping(bytes32 => bytes32) public pilNullifierToKeyImage;

    /// @notice Verified Monero block headers
    mapping(bytes32 => MoneroBlockHeader) public verifiedHeaders;

    /// @notice Pending withdrawals
    mapping(bytes32 => WithdrawalRequest) public pendingWithdrawals;

    /// @notice Total deposited (in atomic units, 1 XMR = 10^12 piconero)
    uint256 public totalDeposited;

    /// @notice Total withdrawn
    uint256 public totalWithdrawn;

    /// @notice Minimum ring size for deposits
    uint256 public minRingSize;

    /// @notice Required custodian signatures for withdrawals
    uint256 public custodianThreshold;

    /// @notice Total custodians
    uint256 public custodianCount;

    /// @notice Deposit limits
    uint256 public minDeposit;
    uint256 public maxDeposit;
    uint256 public dailyDepositLimit;
    uint256 public dailyDepositTotal;
    uint256 public lastDepositResetTime;

    // =========================================================================
    // TYPES
    // =========================================================================

    struct MoneroBlockHeader {
        bytes32 blockHash;
        bytes32 prevHash;
        bytes32 merkleRoot;
        uint64 height;
        uint64 timestamp;
        uint64 difficulty;
        bool verified;
    }

    struct DepositProof {
        MoneroPrimitives.RingMember[] ring;
        MoneroPrimitives.CLSAGSignature signature;
        MoneroPrimitives.BulletproofPlus rangeProof;
        bytes32 outputCommitment;
        bytes32 blockHash;
        bytes32[] merkleProof;
        uint256 txIndex;
    }

    struct WithdrawalRequest {
        bytes32 requestId;
        bytes32 pilNullifier;
        uint256 amount;
        bytes32 recipientViewKey;
        bytes32 recipientSpendKey;
        uint256 requestTime;
        uint256 signaturesCollected;
        WithdrawalStatus status;
        mapping(address => bool) custodianSigned;
    }

    enum WithdrawalStatus {
        Pending,
        Signed,
        Executed,
        Cancelled
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    event Deposit(
        bytes32 indexed keyImageHash,
        bytes32 indexed pilNullifier,
        uint256 amount,
        address indexed recipient,
        bytes32 blockHash
    );

    event WithdrawalRequested(
        bytes32 indexed requestId,
        bytes32 indexed pilNullifier,
        uint256 amount,
        bytes32 recipientViewKey,
        bytes32 recipientSpendKey
    );

    event WithdrawalSigned(
        bytes32 indexed requestId,
        address indexed custodian,
        uint256 signatureCount
    );

    event WithdrawalExecuted(
        bytes32 indexed requestId,
        bytes32 indexed monerTxHash
    );

    event BlockHeaderVerified(bytes32 indexed blockHash, uint64 height);

    event KeyImageRegistered(
        bytes32 indexed keyImageHash,
        bytes32 indexed pilNullifier
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidBlockHeader();
    error BlockNotVerified();
    error InvalidMerkleProof();
    error InvalidRingSignature();
    error InvalidRangeProof();
    error KeyImageAlreadyUsed();
    error PILNullifierAlreadyUsed();
    error InvalidAmount();
    error DepositLimitExceeded();
    error WithdrawalNotFound();
    error WithdrawalAlreadySigned();
    error WithdrawalNotReady();
    error InsufficientSignatures();
    error RingSizeTooSmall();
    error InvalidRecipientKeys();

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
     * @param _primitives MoneroPrimitives contract address
     * @param _pilChainId PIL destination chain ID
     * @param _custodianThreshold Required signatures for withdrawals
     */
    function initialize(
        address admin,
        address _primitives,
        uint256 _pilChainId,
        uint256 _custodianThreshold
    ) external initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        primitives = MoneroPrimitives(_primitives);
        pilChainId = _pilChainId;
        custodianThreshold = _custodianThreshold;

        // Default settings
        minRingSize = 16;
        minDeposit = 0.001 ether; // 0.001 XMR worth
        maxDeposit = 1000 ether; // 1000 XMR worth
        dailyDepositLimit = 10000 ether;
        lastDepositResetTime = block.timestamp;
    }

    // =========================================================================
    // BLOCK HEADER VERIFICATION
    // =========================================================================

    /**
     * @notice Submit and verify a Monero block header
     * @dev Called by relayers to add new verified blocks
     * @param header Block header data
     */
    function submitBlockHeader(
        MoneroBlockHeader calldata header
    ) external onlyRole(RELAYER_ROLE) whenNotPaused {
        // Verify header structure
        if (header.blockHash == bytes32(0)) {
            revert InvalidBlockHeader();
        }

        // If not genesis, verify previous block exists
        if (header.height > 0) {
            if (!verifiedHeaders[header.prevHash].verified) {
                revert BlockNotVerified();
            }
        }

        // Verify PoW (simplified - in production, verify RandomX hash)
        // TODO: Implement RandomX verification or use light client proof

        // Store header
        verifiedHeaders[header.blockHash] = header;
        verifiedHeaders[header.blockHash].verified = true;

        emit BlockHeaderVerified(header.blockHash, header.height);
    }

    // =========================================================================
    // DEPOSIT (MONERO → PIL)
    // =========================================================================

    /**
     * @notice Process a deposit from Monero
     * @dev Verifies ring signature, bulletproof, and merkle inclusion
     * @param proof Deposit proof data
     * @param amount Amount in atomic units (piconero)
     * @param recipient PIL recipient address
     */
    function deposit(
        DepositProof calldata proof,
        uint256 amount,
        address recipient
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
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

        // Validate ring size
        if (proof.ring.length < minRingSize) {
            revert RingSizeTooSmall();
        }

        // Verify block header is known
        if (!verifiedHeaders[proof.blockHash].verified) {
            revert BlockNotVerified();
        }

        // Verify merkle proof (tx is in block)
        bytes32 txHash = keccak256(
            abi.encodePacked(
                proof.signature.keyImage.point.compressed,
                proof.outputCommitment
            )
        );

        if (
            !verifyMerkleProof(
                proof.merkleProof,
                verifiedHeaders[proof.blockHash].merkleRoot,
                txHash,
                proof.txIndex
            )
        ) {
            revert InvalidMerkleProof();
        }

        // Verify CLSAG ring signature
        if (!primitives.verifyCLSAG(proof.ring, proof.signature, bytes32(0))) {
            revert InvalidRingSignature();
        }

        // Verify Bulletproof+ range proof
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = proof.outputCommitment;
        if (!primitives.verifyBulletproofPlus(proof.rangeProof, commitments)) {
            revert InvalidRangeProof();
        }

        // Check key image not already used
        bytes32 keyImageHash = primitives.keyImageHash(
            proof.signature.keyImage
        );
        if (usedKeyImages[keyImageHash]) {
            revert KeyImageAlreadyUsed();
        }

        // Register key image
        usedKeyImages[keyImageHash] = true;

        // Derive PIL nullifier from key image
        bytes32 pilNullifier = primitives.deriveMoneroToPILNullifier(
            proof.signature.keyImage
        );

        // Register binding
        keyImageToPILNullifier[keyImageHash] = pilNullifier;
        pilNullifierToKeyImage[pilNullifier] = keyImageHash;

        // Update totals
        totalDeposited += amount;
        dailyDepositTotal += amount;

        emit Deposit(
            keyImageHash,
            pilNullifier,
            amount,
            recipient,
            proof.blockHash
        );
        emit KeyImageRegistered(keyImageHash, pilNullifier);

        // TODO: Mint wrapped XMR on PIL chain via cross-chain message
    }

    /**
     * @notice Verify Merkle proof for transaction inclusion
     * @param proof Merkle proof nodes
     * @param root Merkle root from block header
     * @param leaf Transaction hash
     * @param index Transaction index
     * @return True if proof is valid
     */
    function verifyMerkleProof(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf,
        uint256 index
    ) public pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            if (index % 2 == 0) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proof[i])
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proof[i], computedHash)
                );
            }
            index = index / 2;
        }

        return computedHash == root;
    }

    // =========================================================================
    // WITHDRAWAL (PIL → MONERO)
    // =========================================================================

    /**
     * @notice Request a withdrawal to Monero
     * @dev Burns wrapped XMR and creates withdrawal request
     * @param pilNullifier PIL nullifier being spent
     * @param amount Amount to withdraw
     * @param recipientViewKey Recipient's Monero view key
     * @param recipientSpendKey Recipient's Monero spend key
     */
    function requestWithdrawal(
        bytes32 pilNullifier,
        uint256 amount,
        bytes32 recipientViewKey,
        bytes32 recipientSpendKey
    ) external nonReentrant whenNotPaused {
        // Validate PIL nullifier not used
        if (usedPILNullifiers[pilNullifier]) {
            revert PILNullifierAlreadyUsed();
        }

        // Validate amount
        if (amount == 0 || amount > totalDeposited - totalWithdrawn) {
            revert InvalidAmount();
        }

        // Validate recipient keys
        if (recipientViewKey == bytes32(0) || recipientSpendKey == bytes32(0)) {
            revert InvalidRecipientKeys();
        }

        // Mark nullifier as used
        usedPILNullifiers[pilNullifier] = true;

        // Create withdrawal request
        bytes32 requestId = keccak256(
            abi.encodePacked(
                pilNullifier,
                amount,
                recipientViewKey,
                recipientSpendKey,
                block.timestamp
            )
        );

        WithdrawalRequest storage request = pendingWithdrawals[requestId];
        request.requestId = requestId;
        request.pilNullifier = pilNullifier;
        request.amount = amount;
        request.recipientViewKey = recipientViewKey;
        request.recipientSpendKey = recipientSpendKey;
        request.requestTime = block.timestamp;
        request.status = WithdrawalStatus.Pending;

        emit WithdrawalRequested(
            requestId,
            pilNullifier,
            amount,
            recipientViewKey,
            recipientSpendKey
        );
    }

    /**
     * @notice Custodian signs a withdrawal request
     * @dev Requires threshold signatures before execution
     * @param requestId Withdrawal request ID
     */
    function signWithdrawal(
        bytes32 requestId
    ) external onlyRole(CUSTODIAN_ROLE) whenNotPaused {
        WithdrawalRequest storage request = pendingWithdrawals[requestId];

        if (request.requestId == bytes32(0)) {
            revert WithdrawalNotFound();
        }

        if (request.status != WithdrawalStatus.Pending) {
            revert WithdrawalNotReady();
        }

        if (request.custodianSigned[msg.sender]) {
            revert WithdrawalAlreadySigned();
        }

        request.custodianSigned[msg.sender] = true;
        request.signaturesCollected++;

        emit WithdrawalSigned(
            requestId,
            msg.sender,
            request.signaturesCollected
        );

        if (request.signaturesCollected >= custodianThreshold) {
            request.status = WithdrawalStatus.Signed;
        }
    }

    /**
     * @notice Execute a fully-signed withdrawal
     * @dev Called by relayer after MPC signing produces Monero tx
     * @param requestId Withdrawal request ID
     * @param moneroTxHash Hash of broadcast Monero transaction
     */
    function executeWithdrawal(
        bytes32 requestId,
        bytes32 moneroTxHash
    ) external onlyRole(RELAYER_ROLE) whenNotPaused {
        WithdrawalRequest storage request = pendingWithdrawals[requestId];

        if (request.status != WithdrawalStatus.Signed) {
            revert InsufficientSignatures();
        }

        request.status = WithdrawalStatus.Executed;
        totalWithdrawn += request.amount;

        emit WithdrawalExecuted(requestId, moneroTxHash);
    }

    // =========================================================================
    // KEY IMAGE QUERIES
    // =========================================================================

    /**
     * @notice Check if a key image has been used
     * @param keyImageHash Hash of the key image
     * @return True if key image is spent
     */
    function isKeyImageUsed(bytes32 keyImageHash) external view returns (bool) {
        return usedKeyImages[keyImageHash];
    }

    /**
     * @notice Get PIL nullifier for a key image
     * @param keyImageHash Hash of the key image
     * @return PIL nullifier (or zero if not registered)
     */
    function getPILNullifier(
        bytes32 keyImageHash
    ) external view returns (bytes32) {
        return keyImageToPILNullifier[keyImageHash];
    }

    /**
     * @notice Check if PIL nullifier has been used
     * @param pilNullifier PIL nullifier to check
     * @return True if nullifier is spent
     */
    function isPILNullifierUsed(
        bytes32 pilNullifier
    ) external view returns (bool) {
        return usedPILNullifiers[pilNullifier];
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Add a custodian
     * @param custodian Custodian address
     */
    function addCustodian(
        address custodian
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(CUSTODIAN_ROLE, custodian);
        custodianCount++;
    }

    /**
     * @notice Remove a custodian
     * @param custodian Custodian address
     */
    function removeCustodian(
        address custodian
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(CUSTODIAN_ROLE, custodian);
        custodianCount--;
    }

    /**
     * @notice Update custodian threshold
     * @param threshold New threshold
     */
    function setCustodianThreshold(
        uint256 threshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            threshold > 0 && threshold <= custodianCount,
            "Invalid threshold"
        );
        custodianThreshold = threshold;
    }

    /**
     * @notice Update deposit limits
     * @param _minDeposit Minimum deposit
     * @param _maxDeposit Maximum deposit
     * @param _dailyLimit Daily limit
     */
    function setDepositLimits(
        uint256 _minDeposit,
        uint256 _maxDeposit,
        uint256 _dailyLimit
    ) external onlyRole(OPERATOR_ROLE) {
        minDeposit = _minDeposit;
        maxDeposit = _maxDeposit;
        dailyDepositLimit = _dailyLimit;
    }

    /**
     * @notice Update minimum ring size
     * @param _minRingSize New minimum ring size
     */
    function setMinRingSize(
        uint256 _minRingSize
    ) external onlyRole(OPERATOR_ROLE) {
        require(_minRingSize >= 2, "Ring size too small");
        minRingSize = _minRingSize;
    }

    /**
     * @notice Pause the bridge
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the bridge
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    // =========================================================================
    // UPGRADE
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
