// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title ScrollBridgeAdapter
 * @notice PIL bridge adapter for Scroll zkEVM (bytecode-compatible zkRollup)
 * @dev Integrates with Scroll's native bridge and zk-proof finality
 * @author PIL Protocol Team
 * @custom:security-contact security@pil.network
 */
contract ScrollBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    // ============ Constants ============

    bytes32 public constant BRIDGE_OPERATOR_ROLE =
        keccak256("BRIDGE_OPERATOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    /// @notice Scroll chain ID
    uint256 public constant SCROLL_MAINNET_CHAIN_ID = 534352;
    uint256 public constant SCROLL_SEPOLIA_CHAIN_ID = 534351;

    /// @notice Message types
    uint8 public constant MESSAGE_TYPE_PROOF = 1;
    uint8 public constant MESSAGE_TYPE_STATE_UPDATE = 2;
    uint8 public constant MESSAGE_TYPE_WITHDRAWAL = 3;

    /// @notice Finality blocks (zk-proof finality)
    uint256 public constant FINALITY_BLOCKS = 1; // Near-instant with ZK proofs

    // ============ Immutable State ============

    /// @notice Scroll L1 Messenger
    address public immutable scrollMessenger;

    /// @notice Scroll L1 Gateway Router
    address public immutable gatewayRouter;

    /// @notice Scroll Rollup Contract
    address public immutable rollupContract;

    // ============ Mutable State ============

    /// @notice PIL Hub on Scroll L2
    address public pilHubL2;

    /// @notice L1 Proof Registry
    address public proofRegistry;

    /// @notice Bridge configuration
    BridgeConfig public config;

    /// @notice Message nonce
    uint256 public nonce;

    /// @notice Pending L1 -> L2 messages
    mapping(bytes32 => L1ToL2Message) public pendingL1Messages;

    /// @notice Finalized L2 -> L1 messages
    mapping(bytes32 => bool) public finalizedL2Messages;

    /// @notice Batch proofs awaiting finality
    mapping(uint256 => BatchInfo) public pendingBatches;

    /// @notice Cross-chain proof status
    mapping(bytes32 => ProofStatus) public proofStatus;

    // ============ Structs ============

    struct BridgeConfig {
        uint256 minAmount;
        uint256 maxAmount;
        uint256 dailyLimit;
        uint256 dailyUsed;
        uint256 lastResetDay;
        uint256 gasLimit;
    }

    struct L1ToL2Message {
        address sender;
        bytes32 proofHash;
        uint256 amount;
        uint256 timestamp;
        uint256 gasLimit;
        bool executed;
        bool refunded;
    }

    struct BatchInfo {
        bytes32 batchHash;
        uint256 timestamp;
        uint256 blockNumber;
        bool finalized;
        bytes32[] proofHashes;
    }

    struct ProofStatus {
        bool bridged;
        bool finalized;
        uint256 sourceChain;
        uint256 destChain;
        address sender;
        uint256 timestamp;
    }

    struct ScrollMessage {
        uint8 messageType;
        bytes32 proofHash;
        bytes proofData;
        bytes publicInputs;
        address sender;
        address recipient;
        uint256 value;
    }

    // ============ Events ============

    event ProofSentToScroll(
        bytes32 indexed messageId,
        bytes32 indexed proofHash,
        address indexed sender,
        address recipient,
        uint256 value
    );

    event ProofReceivedFromScroll(
        bytes32 indexed messageId,
        bytes32 indexed proofHash,
        address indexed sender,
        uint256 batchNumber
    );

    event BatchFinalized(
        uint256 indexed batchNumber,
        bytes32 batchHash,
        uint256 proofCount
    );

    event MessageFailed(bytes32 indexed messageId, bytes reason);

    event RefundClaimed(
        bytes32 indexed messageId,
        address indexed recipient,
        uint256 amount
    );

    event ConfigUpdated(string param, uint256 value);

    // ============ Errors ============

    error InvalidAddress();
    error InvalidAmount();
    error InvalidMessageType();
    error MessageAlreadyProcessed();
    error MessageNotFound();
    error BatchNotFinalized();
    error DailyLimitExceeded();
    error InsufficientGas();
    error UnauthorizedMessenger();
    error ProofVerificationFailed();
    error RefundFailed();
    error InvalidBatch();

    // ============ Modifiers ============

    modifier onlyScrollMessenger() {
        if (msg.sender != scrollMessenger) {
            revert UnauthorizedMessenger();
        }
        _;
    }

    // ============ Constructor ============

    /**
     * @notice Initialize Scroll bridge adapter
     * @param _scrollMessenger Scroll L1 Messenger address
     * @param _gatewayRouter Scroll Gateway Router address
     * @param _rollupContract Scroll Rollup contract address
     * @param _admin Admin address
     */
    constructor(
        address _scrollMessenger,
        address _gatewayRouter,
        address _rollupContract,
        address _admin
    ) {
        if (
            _scrollMessenger == address(0) ||
            _gatewayRouter == address(0) ||
            _rollupContract == address(0) ||
            _admin == address(0)
        ) {
            revert InvalidAddress();
        }

        scrollMessenger = _scrollMessenger;
        gatewayRouter = _gatewayRouter;
        rollupContract = _rollupContract;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(BRIDGE_OPERATOR_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);
        _grantRole(RELAYER_ROLE, _admin);

        config = BridgeConfig({
            minAmount: 0.001 ether,
            maxAmount: 100 ether,
            dailyLimit: 1000 ether,
            dailyUsed: 0,
            lastResetDay: block.timestamp / 1 days,
            gasLimit: 1000000
        });
    }

    // ============ External Functions ============

    /**
     * @notice Bridge proof to Scroll L2
     * @param proofHash Hash of the ZK proof
     * @param proofData Serialized proof data
     * @param publicInputs Public inputs for verification
     * @param recipient Recipient address on Scroll
     * @return messageId Unique message identifier
     */
    function bridgeProofToScroll(
        bytes32 proofHash,
        bytes calldata proofData,
        bytes calldata publicInputs,
        address recipient
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (recipient == address(0)) revert InvalidAddress();
        if (msg.value < config.minAmount || msg.value > config.maxAmount) {
            revert InvalidAmount();
        }

        _checkDailyLimit(msg.value);

        messageId = keccak256(
            abi.encodePacked(
                block.chainid,
                SCROLL_MAINNET_CHAIN_ID,
                msg.sender,
                proofHash,
                nonce++
            )
        );

        // Encode message for Scroll
        bytes memory message = abi.encode(
            ScrollMessage({
                messageType: MESSAGE_TYPE_PROOF,
                proofHash: proofHash,
                proofData: proofData,
                publicInputs: publicInputs,
                sender: msg.sender,
                recipient: recipient,
                value: msg.value
            })
        );

        // Send via Scroll Messenger
        _sendMessageToL2(pilHubL2, msg.value, message, config.gasLimit);

        pendingL1Messages[messageId] = L1ToL2Message({
            sender: msg.sender,
            proofHash: proofHash,
            amount: msg.value,
            timestamp: block.timestamp,
            gasLimit: config.gasLimit,
            executed: false,
            refunded: false
        });

        proofStatus[proofHash] = ProofStatus({
            bridged: true,
            finalized: false,
            sourceChain: block.chainid,
            destChain: SCROLL_MAINNET_CHAIN_ID,
            sender: msg.sender,
            timestamp: block.timestamp
        });

        emit ProofSentToScroll(
            messageId,
            proofHash,
            msg.sender,
            recipient,
            msg.value
        );
    }

    /**
     * @notice Receive finalized proof from Scroll L2
     * @param batchNumber Scroll batch number
     * @param message Encoded message from L2
     * @param batchProof Batch inclusion proof
     */
    function receiveProofFromScroll(
        uint256 batchNumber,
        bytes calldata message,
        bytes calldata batchProof
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        // Verify batch is finalized
        if (!_isBatchFinalized(batchNumber)) {
            revert BatchNotFinalized();
        }

        // Verify message inclusion in batch
        if (!_verifyBatchInclusion(batchNumber, message, batchProof)) {
            revert ProofVerificationFailed();
        }

        // Decode message
        ScrollMessage memory scrollMsg = abi.decode(message, (ScrollMessage));

        bytes32 messageId = keccak256(
            abi.encodePacked(
                SCROLL_MAINNET_CHAIN_ID,
                block.chainid,
                scrollMsg.sender,
                scrollMsg.proofHash,
                batchNumber
            )
        );

        if (finalizedL2Messages[messageId]) {
            revert MessageAlreadyProcessed();
        }

        finalizedL2Messages[messageId] = true;

        // Update proof status
        proofStatus[scrollMsg.proofHash].finalized = true;

        emit ProofReceivedFromScroll(
            messageId,
            scrollMsg.proofHash,
            scrollMsg.sender,
            batchNumber
        );

        // Notify proof registry
        if (proofRegistry != address(0)) {
            _notifyRegistry(
                scrollMsg.proofHash,
                scrollMsg.sender,
                scrollMsg.value
            );
        }

        // Transfer value to recipient
        if (scrollMsg.value > 0 && scrollMsg.recipient != address(0)) {
            (bool success, ) = scrollMsg.recipient.call{value: scrollMsg.value}(
                ""
            );
            if (!success) revert RefundFailed();
        }
    }

    /**
     * @notice Finalize a batch of proofs
     * @param batchNumber Batch number to finalize
     * @param batchHash Hash of the batch
     * @param zkProof ZK proof of batch validity
     */
    function finalizeBatch(
        uint256 batchNumber,
        bytes32 batchHash,
        bytes calldata zkProof
    ) external onlyRole(RELAYER_ROLE) {
        BatchInfo storage batch = pendingBatches[batchNumber];

        if (batch.finalized) revert InvalidBatch();

        // Verify ZK proof against Scroll rollup
        if (!_verifyScrollProof(batchNumber, batchHash, zkProof)) {
            revert ProofVerificationFailed();
        }

        batch.finalized = true;
        batch.batchHash = batchHash;

        emit BatchFinalized(batchNumber, batchHash, batch.proofHashes.length);
    }

    /**
     * @notice Claim refund for failed L1->L2 message
     * @param messageId Message ID to refund
     */
    function claimRefund(bytes32 messageId) external nonReentrant {
        L1ToL2Message storage message = pendingL1Messages[messageId];

        if (message.sender == address(0)) revert MessageNotFound();
        if (message.executed || message.refunded)
            revert MessageAlreadyProcessed();
        if (message.sender != msg.sender) revert InvalidAddress();

        // Check message expiry (7 days without execution)
        if (block.timestamp < message.timestamp + 7 days) {
            revert InvalidAmount(); // Not yet expired
        }

        message.refunded = true;

        (bool success, ) = message.sender.call{value: message.amount}("");
        if (!success) revert RefundFailed();

        emit RefundClaimed(messageId, message.sender, message.amount);
    }

    // ============ View Functions ============

    /**
     * @notice Get proof bridging status
     * @param proofHash Hash of the proof
     * @return status Proof status struct
     */
    function getProofStatus(
        bytes32 proofHash
    ) external view returns (ProofStatus memory) {
        return proofStatus[proofHash];
    }

    /**
     * @notice Check if proof is finalized
     * @param proofHash Hash of the proof
     * @return True if finalized
     */
    function isProofFinalized(bytes32 proofHash) external view returns (bool) {
        return proofStatus[proofHash].finalized;
    }

    /**
     * @notice Get remaining daily limit
     * @return remaining Amount remaining in daily limit
     */
    function getRemainingDailyLimit()
        external
        view
        returns (uint256 remaining)
    {
        uint256 currentDay = block.timestamp / 1 days;
        if (currentDay > config.lastResetDay) {
            return config.dailyLimit;
        }
        return config.dailyLimit - config.dailyUsed;
    }

    // ============ Admin Functions ============

    function setPilHubL2(
        address _pilHubL2
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_pilHubL2 == address(0)) revert InvalidAddress();
        pilHubL2 = _pilHubL2;
    }

    function setProofRegistry(
        address _proofRegistry
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        proofRegistry = _proofRegistry;
    }

    function updateConfig(
        uint256 _minAmount,
        uint256 _maxAmount,
        uint256 _dailyLimit,
        uint256 _gasLimit
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_minAmount >= _maxAmount) revert InvalidAmount();

        config.minAmount = _minAmount;
        config.maxAmount = _maxAmount;
        config.dailyLimit = _dailyLimit;
        config.gasLimit = _gasLimit;

        emit ConfigUpdated("config", block.timestamp);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // ============ Internal Functions ============

    function _checkDailyLimit(uint256 amount) internal {
        uint256 currentDay = block.timestamp / 1 days;

        if (currentDay > config.lastResetDay) {
            config.dailyUsed = 0;
            config.lastResetDay = currentDay;
        }

        if (config.dailyUsed + amount > config.dailyLimit) {
            revert DailyLimitExceeded();
        }

        config.dailyUsed += amount;
    }

    function _sendMessageToL2(
        address target,
        uint256 value,
        bytes memory message,
        uint256 gasLimit
    ) internal {
        // Call Scroll Messenger's sendMessage
        (bool success, ) = scrollMessenger.call{value: value}(
            abi.encodeWithSignature(
                "sendMessage(address,uint256,bytes,uint256)",
                target,
                value,
                message,
                gasLimit
            )
        );

        if (!success) revert InvalidAmount();
    }

    function _isBatchFinalized(
        uint256 batchNumber
    ) internal view returns (bool) {
        // Query Scroll rollup contract for batch finality
        (bool success, bytes memory result) = rollupContract.staticcall(
            abi.encodeWithSignature("isBatchFinalized(uint256)", batchNumber)
        );

        if (!success) return false;
        return abi.decode(result, (bool));
    }

    function _verifyBatchInclusion(
        uint256 batchNumber,
        bytes calldata message,
        bytes calldata proof
    ) internal view returns (bool) {
        // Verify message is included in batch via Merkle proof
        (bool success, bytes memory result) = rollupContract.staticcall(
            abi.encodeWithSignature(
                "verifyMessageInBatch(uint256,bytes,bytes)",
                batchNumber,
                message,
                proof
            )
        );

        if (!success) return false;
        return abi.decode(result, (bool));
    }

    function _verifyScrollProof(
        uint256 batchNumber,
        bytes32 batchHash,
        bytes calldata zkProof
    ) internal view returns (bool) {
        // Verify ZK proof of batch against rollup
        (bool success, bytes memory result) = rollupContract.staticcall(
            abi.encodeWithSignature(
                "verifyBatchProof(uint256,bytes32,bytes)",
                batchNumber,
                batchHash,
                zkProof
            )
        );

        if (!success) return false;
        return abi.decode(result, (bool));
    }

    function _notifyRegistry(
        bytes32 proofHash,
        address sender,
        uint256 value
    ) internal {
        (bool success, ) = proofRegistry.call(
            abi.encodeWithSignature(
                "recordFinalizedProof(bytes32,address,uint256,uint256)",
                proofHash,
                sender,
                value,
                SCROLL_MAINNET_CHAIN_ID
            )
        );
        // Non-critical, continue even on failure
        success;
    }

    receive() external payable {}
}
