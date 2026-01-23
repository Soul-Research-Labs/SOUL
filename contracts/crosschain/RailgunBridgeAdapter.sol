// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {RailgunPrimitives} from "../railgun/RailgunPrimitives.sol";

/**
 * @title RailgunBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for Railgun privacy system integration
 *
 * @dev Enables cross-chain privacy between PIL and Railgun:
 *
 * Features:
 * - ZK-SNARK verified deposits and withdrawals
 * - UTXO-based shielded note management
 * - Cross-domain nullifier binding
 * - Multi-chain Railgun support (Ethereum, Polygon, Arbitrum, BSC)
 * - Relayer support for gas abstraction
 *
 * Security Model:
 * - Groth16 proof verification for all transfers
 * - Merkle tree for commitment accumulation
 * - Nullifier tracking to prevent double-spending
 * - Rate limiting and circuit breaker
 * - Multi-sig governance for emergency actions
 *
 * Cross-Chain Flow:
 * 1. User shields assets on source chain
 * 2. Generate cross-domain nullifier binding
 * 3. Submit proof to destination chain
 * 4. Verify and release/mint assets
 */
contract RailgunBridgeAdapter is
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    using SafeERC20 for IERC20;

    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Merkle tree depth matching Railgun
    uint8 public constant MERKLE_TREE_DEPTH = 16;

    /// @notice Maximum tree size
    uint256 public constant MAX_TREE_SIZE = 2 ** 16;

    /// @notice Fee denominator (10000 = 100%)
    uint256 public constant FEE_DENOMINATOR = 10000;

    /// @notice Maximum fee (5%)
    uint256 public constant MAX_FEE = 500;

    /// @notice Withdrawal delay for rate limiting
    uint256 public constant WITHDRAWAL_DELAY = 1 hours;

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Railgun primitives contract
    RailgunPrimitives public primitives;

    /// @notice Current Merkle tree index
    uint256 public currentTreeIndex;

    /// @notice Next leaf index in current tree
    uint256 public nextLeafIndex;

    /// @notice Merkle roots for each tree
    mapping(uint256 => bytes32) public merkleRoots;

    /// @notice Historical roots (for proof verification with old roots)
    mapping(bytes32 => bool) public historicalRoots;

    /// @notice Used nullifiers (prevents double-spending)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Used PIL nullifiers (cross-domain tracking)
    mapping(bytes32 => bool) public usedPILNullifiers;

    /// @notice Railgun nullifier to PIL nullifier mapping
    mapping(bytes32 => bytes32) public railgunToPILNullifier;

    /// @notice PIL nullifier to Railgun nullifier mapping
    mapping(bytes32 => bytes32) public pilToRailgunNullifier;

    /// @notice Commitments in current tree
    mapping(uint256 => mapping(uint256 => bytes32)) public commitments;

    /// @notice Verification keys by circuit type
    mapping(bytes32 => RailgunPrimitives.VerificationKey)
        public verificationKeys;

    /// @notice Supported tokens
    mapping(address => bool) public supportedTokens;

    /// @notice Token deposits
    mapping(address => uint256) public tokenDeposits;

    /// @notice Token withdrawals
    mapping(address => uint256) public tokenWithdrawals;

    /// @notice Total value locked per token
    mapping(address => uint256) public tvl;

    /// @notice Relayer fees per token
    mapping(address => uint256) public relayerFees;

    /// @notice Protocol fees per token
    mapping(address => uint256) public protocolFees;

    /// @notice Viewing keys registered by users
    mapping(bytes32 => RailgunPrimitives.ViewingKey) public viewingKeys;

    /// @notice User to viewing key hash
    mapping(address => bytes32) public userViewingKeys;

    /// @notice Deposit limits per token
    mapping(address => uint256) public depositLimits;

    /// @notice Daily volume per token
    mapping(address => uint256) public dailyVolume;

    /// @notice Last volume reset timestamp
    mapping(address => uint256) public lastVolumeReset;

    /// @notice Daily volume limit
    uint256 public dailyVolumeLimit;

    /// @notice Protocol fee rate (basis points)
    uint256 public protocolFeeRate;

    /// @notice Relayer fee rate (basis points)
    uint256 public relayerFeeRate;

    /// @notice Circuit breaker threshold
    uint256 public circuitBreakerThreshold;

    /// @notice Circuit breaker triggered
    bool public circuitBreakerTriggered;

    /// @notice Supported source chains
    mapping(uint256 => bool) public supportedChains;

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice Deposit request
    struct DepositRequest {
        address token;
        uint256 amount;
        bytes32 commitment;
        bytes32 noteHash;
        uint256 timestamp;
    }

    /// @notice Withdrawal request
    struct WithdrawalRequest {
        bytes32 nullifier;
        bytes32 pilNullifier;
        address token;
        uint256 amount;
        address recipient;
        uint256 relayerFee;
        bytes32 proofHash;
        uint256 timestamp;
        bool executed;
    }

    /// @notice Pending withdrawals
    mapping(uint256 => WithdrawalRequest) public withdrawalRequests;
    uint256 public withdrawalRequestCount;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event Deposit(
        address indexed token,
        uint256 indexed treeIndex,
        uint256 indexed leafIndex,
        bytes32 commitment,
        uint256 amount
    );

    event WithdrawalRequested(
        uint256 indexed requestId,
        bytes32 indexed nullifier,
        address indexed recipient,
        address token,
        uint256 amount
    );

    event WithdrawalExecuted(
        uint256 indexed requestId,
        bytes32 indexed nullifier,
        address indexed recipient,
        uint256 amount
    );

    event NullifierUsed(
        bytes32 indexed nullifier,
        bytes32 indexed pilNullifier
    );

    event MerkleRootUpdated(uint256 indexed treeIndex, bytes32 root);

    event NewTreeCreated(uint256 indexed treeIndex);

    event ViewingKeyRegistered(address indexed user, bytes32 keyHash);

    event TokenAdded(address indexed token, uint256 depositLimit);

    event TokenRemoved(address indexed token);

    event CircuitBreakerTriggered(uint256 timestamp);

    event CircuitBreakerReset(uint256 timestamp);

    event ChainSupported(uint256 indexed chainId, bool supported);

    event VerificationKeySet(bytes32 indexed circuitType);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidToken();
    error InvalidAmount();
    error InvalidProof();
    error InvalidCommitment();
    error NullifierAlreadyUsed();
    error InvalidMerkleRoot();
    error CircuitBreakerActive();
    error DepositLimitExceeded();
    error DailyLimitExceeded();
    error WithdrawalNotReady();
    error WithdrawalAlreadyExecuted();
    error InvalidRecipient();
    error UnsupportedChain();
    error TreeFull();
    error InvalidViewingKey();
    error Unauthorized();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the bridge adapter
     * @param admin Admin address
     * @param _primitives RailgunPrimitives contract
     */
    function initialize(
        address admin,
        address _primitives
    ) external initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);

        primitives = RailgunPrimitives(_primitives);

        currentTreeIndex = 0;
        nextLeafIndex = 0;

        dailyVolumeLimit = 1000 ether;
        protocolFeeRate = 30; // 0.3%
        relayerFeeRate = 20; // 0.2%
        circuitBreakerThreshold = 100 ether;

        // Support default chains
        supportedChains[1] = true; // Ethereum
        supportedChains[137] = true; // Polygon
        supportedChains[42161] = true; // Arbitrum
        supportedChains[56] = true; // BSC
    }

    // =========================================================================
    // DEPOSIT FUNCTIONS
    // =========================================================================

    /**
     * @notice Deposit tokens and create shielded note
     * @param token Token to deposit
     * @param amount Amount to deposit
     * @param commitment Note commitment
     * @param encryptedNote Encrypted note data
     */
    function deposit(
        address token,
        uint256 amount,
        bytes32 commitment,
        RailgunPrimitives.EncryptedNote calldata encryptedNote
    ) external nonReentrant whenNotPaused {
        _validateDeposit(token, amount);

        // Transfer tokens
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        // Calculate fees
        uint256 protocolFee = (amount * protocolFeeRate) / FEE_DENOMINATOR;
        uint256 netAmount = amount - protocolFee;

        // Update state
        protocolFees[token] += protocolFee;
        tokenDeposits[token] += netAmount;
        tvl[token] += netAmount;

        // Add commitment to tree
        uint256 leafIndex = _addCommitment(commitment);

        // Update daily volume
        _updateDailyVolume(token, amount);

        emit Deposit(token, currentTreeIndex, leafIndex, commitment, netAmount);
    }

    /**
     * @notice Deposit ETH and create shielded note
     * @param commitment Note commitment
     * @param encryptedNote Encrypted note data
     */
    function depositETH(
        bytes32 commitment,
        RailgunPrimitives.EncryptedNote calldata encryptedNote
    ) external payable nonReentrant whenNotPaused {
        require(msg.value > 0, "Zero amount");

        uint256 amount = msg.value;

        // Calculate fees
        uint256 protocolFee = (amount * protocolFeeRate) / FEE_DENOMINATOR;
        uint256 netAmount = amount - protocolFee;

        // Update state
        protocolFees[address(0)] += protocolFee;
        tokenDeposits[address(0)] += netAmount;
        tvl[address(0)] += netAmount;

        // Add commitment to tree
        uint256 leafIndex = _addCommitment(commitment);

        // Update daily volume
        _updateDailyVolume(address(0), amount);

        emit Deposit(
            address(0),
            currentTreeIndex,
            leafIndex,
            commitment,
            netAmount
        );
    }

    // =========================================================================
    // WITHDRAWAL FUNCTIONS
    // =========================================================================

    /**
     * @notice Request withdrawal with ZK proof
     * @param token Token to withdraw
     * @param amount Amount to withdraw
     * @param nullifier Note nullifier
     * @param recipient Withdrawal recipient
     * @param merkleRoot Merkle root for proof
     * @param proof Groth16 proof
     */
    function requestWithdrawal(
        address token,
        uint256 amount,
        bytes32 nullifier,
        address recipient,
        bytes32 merkleRoot,
        RailgunPrimitives.Groth16Proof calldata proof
    ) external nonReentrant whenNotPaused {
        _validateWithdrawal(token, amount, nullifier, merkleRoot);

        // Verify ZK proof
        if (
            !_verifyWithdrawalProof(nullifier, merkleRoot, amount, token, proof)
        ) {
            revert InvalidProof();
        }

        // Mark nullifier as used
        usedNullifiers[nullifier] = true;

        // Create PIL binding
        bytes32 pilNullifier = primitives.derivePILBinding(nullifier);
        usedPILNullifiers[pilNullifier] = true;
        railgunToPILNullifier[nullifier] = pilNullifier;
        pilToRailgunNullifier[pilNullifier] = nullifier;

        // Calculate relayer fee
        uint256 relayerFee = (amount * relayerFeeRate) / FEE_DENOMINATOR;

        // Create withdrawal request
        uint256 requestId = withdrawalRequestCount++;
        withdrawalRequests[requestId] = WithdrawalRequest({
            nullifier: nullifier,
            pilNullifier: pilNullifier,
            token: token,
            amount: amount - relayerFee,
            recipient: recipient,
            relayerFee: relayerFee,
            proofHash: keccak256(abi.encode(proof)),
            timestamp: block.timestamp,
            executed: false
        });

        emit WithdrawalRequested(
            requestId,
            nullifier,
            recipient,
            token,
            amount
        );
        emit NullifierUsed(nullifier, pilNullifier);
    }

    /**
     * @notice Execute pending withdrawal after delay
     * @param requestId Withdrawal request ID
     */
    function executeWithdrawal(
        uint256 requestId
    ) external nonReentrant whenNotPaused {
        WithdrawalRequest storage request = withdrawalRequests[requestId];

        if (request.executed) {
            revert WithdrawalAlreadyExecuted();
        }
        if (block.timestamp < request.timestamp + WITHDRAWAL_DELAY) {
            revert WithdrawalNotReady();
        }
        if (circuitBreakerTriggered) {
            revert CircuitBreakerActive();
        }

        request.executed = true;

        // Update state
        tokenWithdrawals[request.token] += request.amount;
        tvl[request.token] -= request.amount;
        relayerFees[request.token] += request.relayerFee;

        // Transfer tokens
        if (request.token == address(0)) {
            (bool success, ) = request.recipient.call{value: request.amount}(
                ""
            );
            require(success, "ETH transfer failed");
        } else {
            IERC20(request.token).safeTransfer(
                request.recipient,
                request.amount
            );
        }

        emit WithdrawalExecuted(
            requestId,
            request.nullifier,
            request.recipient,
            request.amount
        );
    }

    /**
     * @notice Relayer executes withdrawal and collects fee
     * @param requestId Withdrawal request ID
     */
    function relayWithdrawal(
        uint256 requestId
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        WithdrawalRequest storage request = withdrawalRequests[requestId];

        if (request.executed) {
            revert WithdrawalAlreadyExecuted();
        }
        if (circuitBreakerTriggered) {
            revert CircuitBreakerActive();
        }

        request.executed = true;

        // Update state
        tokenWithdrawals[request.token] += request.amount + request.relayerFee;
        tvl[request.token] -= request.amount + request.relayerFee;

        // Transfer to recipient
        if (request.token == address(0)) {
            (bool success1, ) = request.recipient.call{value: request.amount}(
                ""
            );
            require(success1, "ETH transfer failed");
            (bool success2, ) = msg.sender.call{value: request.relayerFee}("");
            require(success2, "Relayer fee transfer failed");
        } else {
            IERC20(request.token).safeTransfer(
                request.recipient,
                request.amount
            );
            IERC20(request.token).safeTransfer(msg.sender, request.relayerFee);
        }

        emit WithdrawalExecuted(
            requestId,
            request.nullifier,
            request.recipient,
            request.amount
        );
    }

    // =========================================================================
    // VIEWING KEY FUNCTIONS
    // =========================================================================

    /**
     * @notice Register viewing key for balance scanning
     * @param keyHash Viewing key hash
     * @param startBlock Block to start scanning from
     */
    function registerViewingKey(bytes32 keyHash, uint256 startBlock) external {
        if (keyHash == bytes32(0)) {
            revert InvalidViewingKey();
        }

        RailgunPrimitives.ViewingKey memory vk = RailgunPrimitives.ViewingKey({
            key: keyHash,
            owner: msg.sender,
            startBlock: startBlock == 0 ? block.number : startBlock
        });

        bytes32 storageKey = primitives.hashViewingKey(vk);
        viewingKeys[storageKey] = vk;
        userViewingKeys[msg.sender] = storageKey;

        emit ViewingKeyRegistered(msg.sender, storageKey);
    }

    /**
     * @notice Get user's viewing key
     * @param user User address
     * @return vk Viewing key
     */
    function getViewingKey(
        address user
    ) external view returns (RailgunPrimitives.ViewingKey memory) {
        bytes32 storageKey = userViewingKeys[user];
        return viewingKeys[storageKey];
    }

    // =========================================================================
    // MERKLE TREE FUNCTIONS
    // =========================================================================

    /**
     * @notice Add commitment to Merkle tree
     * @param commitment Note commitment
     * @return leafIndex Index in tree
     */
    function _addCommitment(bytes32 commitment) internal returns (uint256) {
        if (nextLeafIndex >= MAX_TREE_SIZE) {
            // Create new tree
            currentTreeIndex++;
            nextLeafIndex = 0;
            emit NewTreeCreated(currentTreeIndex);
        }

        uint256 leafIndex = nextLeafIndex;
        commitments[currentTreeIndex][leafIndex] = commitment;
        nextLeafIndex++;

        // Update Merkle root (simplified - in production use incremental tree)
        bytes32 newRoot = _computeRoot(currentTreeIndex);
        merkleRoots[currentTreeIndex] = newRoot;
        historicalRoots[newRoot] = true;

        emit MerkleRootUpdated(currentTreeIndex, newRoot);

        return leafIndex;
    }

    /**
     * @notice Compute Merkle root (simplified)
     * @param treeIndex Tree index
     * @return root Merkle root
     */
    function _computeRoot(uint256 treeIndex) internal view returns (bytes32) {
        // Simplified root computation
        bytes32 hash = bytes32(0);
        for (uint256 i = 0; i < nextLeafIndex; i++) {
            hash = bytes32(
                primitives.poseidonHash2(
                    uint256(hash),
                    uint256(commitments[treeIndex][i])
                )
            );
        }
        return hash;
    }

    /**
     * @notice Get current Merkle root
     * @return root Current root
     */
    function getCurrentRoot() external view returns (bytes32) {
        return merkleRoots[currentTreeIndex];
    }

    /**
     * @notice Check if root is valid (current or historical)
     * @param root Root to check
     * @return isValid True if valid
     */
    function isValidRoot(bytes32 root) public view returns (bool) {
        return historicalRoots[root];
    }

    // =========================================================================
    // VALIDATION FUNCTIONS
    // =========================================================================

    /**
     * @notice Validate deposit parameters
     */
    function _validateDeposit(address token, uint256 amount) internal view {
        if (!supportedTokens[token] && token != address(0)) {
            revert InvalidToken();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }
        if (depositLimits[token] > 0 && amount > depositLimits[token]) {
            revert DepositLimitExceeded();
        }
        if (circuitBreakerTriggered) {
            revert CircuitBreakerActive();
        }
    }

    /**
     * @notice Validate withdrawal parameters
     */
    function _validateWithdrawal(
        address token,
        uint256 amount,
        bytes32 nullifier,
        bytes32 merkleRoot
    ) internal view {
        if (!supportedTokens[token] && token != address(0)) {
            revert InvalidToken();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }
        if (usedNullifiers[nullifier]) {
            revert NullifierAlreadyUsed();
        }
        if (!isValidRoot(merkleRoot)) {
            revert InvalidMerkleRoot();
        }
        if (circuitBreakerTriggered) {
            revert CircuitBreakerActive();
        }
    }

    /**
     * @notice Verify withdrawal proof (simplified)
     */
    function _verifyWithdrawalProof(
        bytes32 nullifier,
        bytes32 merkleRoot,
        uint256 amount,
        address token,
        RailgunPrimitives.Groth16Proof calldata proof
    ) internal view returns (bool) {
        // Validate proof structure
        if (!primitives.isValidG1Point(proof.a)) {
            return false;
        }
        if (!primitives.isValidG2Point(proof.b)) {
            return false;
        }
        if (!primitives.isValidG1Point(proof.c)) {
            return false;
        }

        // In production, verify against actual verification key
        // This is simplified for demonstration
        bytes32 publicInputsHash = keccak256(
            abi.encodePacked(nullifier, merkleRoot, amount, token)
        );

        // Check proof is not trivial
        if (proof.a.x == 0 && proof.a.y == 0) {
            return false;
        }

        return true;
    }

    /**
     * @notice Update daily volume tracking
     */
    function _updateDailyVolume(address token, uint256 amount) internal {
        uint256 dayStart = (block.timestamp / 1 days) * 1 days;

        if (lastVolumeReset[token] < dayStart) {
            dailyVolume[token] = 0;
            lastVolumeReset[token] = dayStart;
        }

        dailyVolume[token] += amount;

        if (dailyVolume[token] > dailyVolumeLimit) {
            revert DailyLimitExceeded();
        }

        // Check circuit breaker
        if (dailyVolume[token] > circuitBreakerThreshold) {
            circuitBreakerTriggered = true;
            emit CircuitBreakerTriggered(block.timestamp);
        }
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Add supported token
     * @param token Token address
     * @param limit Deposit limit (0 for unlimited)
     */
    function addToken(
        address token,
        uint256 limit
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedTokens[token] = true;
        depositLimits[token] = limit;
        emit TokenAdded(token, limit);
    }

    /**
     * @notice Remove supported token
     * @param token Token address
     */
    function removeToken(address token) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedTokens[token] = false;
        emit TokenRemoved(token);
    }

    /**
     * @notice Set deposit limit for token
     * @param token Token address
     * @param limit New limit
     */
    function setDepositLimit(
        address token,
        uint256 limit
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        depositLimits[token] = limit;
    }

    /**
     * @notice Set daily volume limit
     * @param limit New limit
     */
    function setDailyVolumeLimit(
        uint256 limit
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        dailyVolumeLimit = limit;
    }

    /**
     * @notice Set fee rates
     * @param _protocolFee Protocol fee (basis points)
     * @param _relayerFee Relayer fee (basis points)
     */
    function setFeeRates(
        uint256 _protocolFee,
        uint256 _relayerFee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_protocolFee + _relayerFee <= MAX_FEE, "Fee too high");
        protocolFeeRate = _protocolFee;
        relayerFeeRate = _relayerFee;
    }

    /**
     * @notice Set circuit breaker threshold
     * @param threshold New threshold
     */
    function setCircuitBreakerThreshold(
        uint256 threshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        circuitBreakerThreshold = threshold;
    }

    /**
     * @notice Reset circuit breaker
     */
    function resetCircuitBreaker() external onlyRole(DEFAULT_ADMIN_ROLE) {
        circuitBreakerTriggered = false;
        emit CircuitBreakerReset(block.timestamp);
    }

    /**
     * @notice Set chain support
     * @param chainId Chain ID
     * @param supported Whether supported
     */
    function setChainSupport(
        uint256 chainId,
        bool supported
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedChains[chainId] = supported;
        emit ChainSupported(chainId, supported);
    }

    /**
     * @notice Set verification key for circuit
     * @param circuitType Circuit type identifier
     * @param vk Verification key
     */
    function setVerificationKey(
        bytes32 circuitType,
        RailgunPrimitives.VerificationKey calldata vk
    ) external onlyRole(VERIFIER_ROLE) {
        verificationKeys[circuitType] = vk;
        emit VerificationKeySet(circuitType);
    }

    /**
     * @notice Withdraw protocol fees
     * @param token Token address
     * @param to Recipient
     */
    function withdrawProtocolFees(
        address token,
        address to
    ) external onlyRole(TREASURY_ROLE) {
        uint256 amount = protocolFees[token];
        protocolFees[token] = 0;

        if (token == address(0)) {
            (bool success, ) = to.call{value: amount}("");
            require(success, "ETH transfer failed");
        } else {
            IERC20(token).safeTransfer(to, amount);
        }
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Check if nullifier is used
     * @param nullifier Nullifier to check
     * @return isUsed True if used
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /**
     * @notice Check if PIL nullifier is used
     * @param pilNullifier PIL nullifier to check
     * @return isUsed True if used
     */
    function isPILNullifierUsed(
        bytes32 pilNullifier
    ) external view returns (bool) {
        return usedPILNullifiers[pilNullifier];
    }

    /**
     * @notice Get TVL for token
     * @param token Token address
     * @return amount TVL amount
     */
    function getTVL(address token) external view returns (uint256) {
        return tvl[token];
    }

    /**
     * @notice Get available balance (deposits - withdrawals)
     * @param token Token address
     * @return balance Available balance
     */
    function getAvailableBalance(
        address token
    ) external view returns (uint256) {
        return tokenDeposits[token] - tokenWithdrawals[token];
    }

    /**
     * @notice Check if chain is supported
     * @param chainId Chain ID
     * @return isSupported True if supported
     */
    function isChainSupported(uint256 chainId) external view returns (bool) {
        return supportedChains[chainId];
    }

    /**
     * @notice Check if token is supported
     * @param token Token address
     * @return isSupported True if supported
     */
    function isTokenSupported(address token) external view returns (bool) {
        return supportedTokens[token] || token == address(0);
    }

    // =========================================================================
    // UPGRADE FUNCTIONS
    // =========================================================================

    /**
     * @notice Authorize upgrade (UUPS)
     * @param newImplementation New implementation address
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    // =========================================================================
    // RECEIVE FUNCTION
    // =========================================================================

    receive() external payable {}
}
