// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/// @title CrossChainProofHubV2
/// @author PIL Protocol
/// @notice Aggregates, batches, and relays proofs between chains with security hardening
/// @dev Implements proof batching for gas optimization and relayer incentives
contract CrossChainProofHubV2 is Ownable, ReentrancyGuard, Pausable {
    /// @notice Represents a cross-chain proof message (optimized: stores hashes instead of full bytes)
    /// @param id Unique message identifier
    /// @param sourceChain Source chain ID
    /// @param destChain Destination chain ID
    /// @param proofHash Keccak256 hash of proof bytes (gas optimization)
    /// @param publicInputsHash Keccak256 hash of public inputs (gas optimization)
    /// @param sender The original sender
    /// @param timestamp Submission timestamp
    /// @param status Message status
    struct ProofMessage {
        bytes32 id;
        uint256 sourceChain;
        uint256 destChain;
        bytes32 proofHash;
        bytes32 publicInputsHash;
        address sender;
        uint256 timestamp;
        MessageStatus status;
    }

    /// @notice Message status enum
    enum MessageStatus {
        Pending,
        Batched,
        Relayed,
        Confirmed,
        Failed
    }

    /// @notice Represents a batch of proofs
    /// @param id Batch identifier
    /// @param messageIds Array of message IDs in this batch
    /// @param merkleRoot Merkle root of all proofs
    /// @param relayer Assigned relayer
    /// @param timestamp Batch creation timestamp
    /// @param status Batch status
    struct ProofBatch {
        bytes32 id;
        bytes32[] messageIds;
        bytes32 merkleRoot;
        address relayer;
        uint256 timestamp;
        BatchStatus status;
    }

    /// @notice Batch status enum
    enum BatchStatus {
        Open,
        Sealed,
        Relaying,
        Confirmed,
        Failed
    }

    /// @notice Mapping of message ID to message
    mapping(bytes32 => ProofMessage) public messages;

    /// @notice Mapping of batch ID to batch
    mapping(bytes32 => ProofBatch) public batches;

    /// @notice Current open batch ID
    bytes32 public currentBatchId;

    /// @notice Array of message IDs in current batch
    bytes32[] public currentBatchMessages;

    /// @notice Maximum messages per batch
    uint256 public maxBatchSize;

    /// @notice Batch timeout in seconds
    uint256 public batchTimeout;

    /// @notice Current batch start timestamp
    uint256 public currentBatchStart;

    /// @notice Message nonce for unique IDs
    uint256 public messageNonce;

    /// @notice Registered relayers
    mapping(address => bool) public registeredRelayers;

    /// @notice Relayer stakes
    mapping(address => uint256) public relayerStakes;

    /// @notice Minimum stake required for relayers
    uint256 public minRelayerStake;

    /// @notice Events
    event ProofSubmitted(
        bytes32 indexed messageId,
        uint256 indexed destChain,
        address indexed sender,
        bytes32 proofHash,
        bytes32 publicInputsHash
    );

    /// @notice Emitted with full proof data for off-chain retrieval (indexed by messageId)
    event ProofDataStored(
        bytes32 indexed messageId,
        bytes proof,
        bytes publicInputs
    );
    event BatchSealed(
        bytes32 indexed batchId,
        uint256 messageCount,
        bytes32 merkleRoot
    );
    event BatchRelayed(bytes32 indexed batchId, address indexed relayer);
    event BatchConfirmed(bytes32 indexed batchId);
    event RelayerRegistered(address indexed relayer, uint256 stake);
    event RelayerSlashed(
        address indexed relayer,
        uint256 amount,
        string reason
    );

    /// @notice Custom errors
    error InvalidDestChain();
    error EmptyProof();
    error RelayerNotRegistered();
    error InsufficientStake();
    error BatchNotReady();
    error BatchAlreadySealed();
    error MessageNotFound();
    error InvalidBatchStatus();

    constructor(
        uint256 _maxBatchSize,
        uint256 _batchTimeout,
        uint256 _minRelayerStake
    ) Ownable(msg.sender) {
        maxBatchSize = _maxBatchSize;
        batchTimeout = _batchTimeout;
        minRelayerStake = _minRelayerStake;
        _startNewBatch();
    }

    /// @notice Submits a proof for cross-chain relay (gas optimized: stores hashes, emits full data)
    /// @param destChain Destination chain ID
    /// @param proof The proof bytes
    /// @param publicInputs Public inputs for verification
    /// @return messageId The unique message ID
    function submitProof(
        uint256 destChain,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (destChain == block.chainid) revert InvalidDestChain();
        if (proof.length == 0) revert EmptyProof();

        // Compute hashes for gas-efficient storage
        bytes32 proofHash = keccak256(proof);
        bytes32 publicInputsHash = keccak256(publicInputs);

        messageId = keccak256(
            abi.encodePacked(
                block.chainid,
                destChain,
                msg.sender,
                messageNonce++
            )
        );

        // Store only hashes (saves ~70% gas vs storing full bytes)
        messages[messageId] = ProofMessage({
            id: messageId,
            sourceChain: block.chainid,
            destChain: destChain,
            proofHash: proofHash,
            publicInputsHash: publicInputsHash,
            sender: msg.sender,
            timestamp: block.timestamp,
            status: MessageStatus.Pending
        });

        currentBatchMessages.push(messageId);
        messages[messageId].status = MessageStatus.Batched;

        // Emit full proof data for off-chain indexing (calldata is cheaper than storage)
        emit ProofDataStored(messageId, proof, publicInputs);
        emit ProofSubmitted(
            messageId,
            destChain,
            msg.sender,
            proofHash,
            publicInputsHash
        );

        // Auto-seal batch if full
        if (currentBatchMessages.length >= maxBatchSize) {
            _sealBatch();
        }

        return messageId;
    }

    /// @notice Seals the current batch (can be called by anyone after timeout)
    function sealBatch() external whenNotPaused {
        if (currentBatchMessages.length == 0) revert BatchNotReady();
        if (
            block.timestamp < currentBatchStart + batchTimeout &&
            currentBatchMessages.length < maxBatchSize
        ) {
            revert BatchNotReady();
        }
        _sealBatch();
    }

    /// @notice Internal function to seal batch
    function _sealBatch() internal {
        bytes32 merkleRoot = _computeMerkleRoot(currentBatchMessages);

        batches[currentBatchId] = ProofBatch({
            id: currentBatchId,
            messageIds: currentBatchMessages,
            merkleRoot: merkleRoot,
            relayer: address(0),
            timestamp: block.timestamp,
            status: BatchStatus.Sealed
        });

        emit BatchSealed(
            currentBatchId,
            currentBatchMessages.length,
            merkleRoot
        );

        _startNewBatch();
    }

    /// @notice Starts a new batch
    function _startNewBatch() internal {
        currentBatchId = keccak256(
            abi.encodePacked(block.chainid, block.timestamp, messageNonce)
        );
        delete currentBatchMessages;
        currentBatchStart = block.timestamp;
    }

    /// @notice Computes merkle root of message IDs
    /// @param messageIds Array of message IDs
    /// @return root The merkle root
    function _computeMerkleRoot(
        bytes32[] memory messageIds
    ) internal pure returns (bytes32 root) {
        if (messageIds.length == 0) return bytes32(0);
        if (messageIds.length == 1) return messageIds[0];

        uint256 n = messageIds.length;
        while (n > 1) {
            for (uint256 i = 0; i < n / 2; i++) {
                messageIds[i] = keccak256(
                    abi.encodePacked(messageIds[2 * i], messageIds[2 * i + 1])
                );
            }
            if (n % 2 == 1) {
                messageIds[n / 2] = messageIds[n - 1];
                n = n / 2 + 1;
            } else {
                n = n / 2;
            }
        }
        return messageIds[0];
    }

    /// @notice Registers as a relayer with stake
    function registerRelayer() external payable {
        if (msg.value < minRelayerStake) revert InsufficientStake();
        registeredRelayers[msg.sender] = true;
        relayerStakes[msg.sender] += msg.value;
        emit RelayerRegistered(msg.sender, msg.value);
    }

    /// @notice Claims a batch for relaying
    /// @param batchId The batch to claim
    function claimBatch(bytes32 batchId) external {
        if (!registeredRelayers[msg.sender]) revert RelayerNotRegistered();
        ProofBatch storage batch = batches[batchId];
        if (batch.status != BatchStatus.Sealed) revert InvalidBatchStatus();

        batch.relayer = msg.sender;
        batch.status = BatchStatus.Relaying;
        emit BatchRelayed(batchId, msg.sender);
    }

    /// @notice Confirms batch delivery (called by destination chain oracle)
    /// @param batchId The batch to confirm
    function confirmBatch(bytes32 batchId) external onlyOwner {
        ProofBatch storage batch = batches[batchId];
        if (batch.status != BatchStatus.Relaying) revert InvalidBatchStatus();

        batch.status = BatchStatus.Confirmed;

        // Update all message statuses
        for (uint256 i = 0; i < batch.messageIds.length; i++) {
            messages[batch.messageIds[i]].status = MessageStatus.Confirmed;
        }

        emit BatchConfirmed(batchId);
    }

    /// @notice Slashes a relayer for misbehavior
    /// @param relayer The relayer to slash
    /// @param amount The amount to slash
    /// @param reason The reason for slashing
    function slashRelayer(
        address relayer,
        uint256 amount,
        string calldata reason
    ) external onlyOwner {
        uint256 stake = relayerStakes[relayer];
        uint256 slashAmount = amount > stake ? stake : amount;
        relayerStakes[relayer] -= slashAmount;

        if (relayerStakes[relayer] < minRelayerStake) {
            registeredRelayers[relayer] = false;
        }

        emit RelayerSlashed(relayer, slashAmount, reason);
    }

    /// @notice Gets the current batch message count
    /// @return count Number of messages in current batch
    function getCurrentBatchSize() external view returns (uint256 count) {
        return currentBatchMessages.length;
    }

    /// @notice Gets message details
    /// @param messageId The message ID
    /// @return message The proof message
    function getMessage(
        bytes32 messageId
    ) external view returns (ProofMessage memory message) {
        return messages[messageId];
    }

    /// @notice Verifies proof data matches stored hash (for off-chain verification)
    /// @param messageId The message ID
    /// @param proof The original proof bytes
    /// @param publicInputs The original public inputs
    /// @return valid True if hashes match
    function verifyProofIntegrity(
        bytes32 messageId,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool valid) {
        ProofMessage storage msg_ = messages[messageId];
        return
            msg_.proofHash == keccak256(proof) &&
            msg_.publicInputsHash == keccak256(publicInputs);
    }

    /// @notice Pause the contract
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpause the contract
    function unpause() external onlyOwner {
        _unpause();
    }
}
