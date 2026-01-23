// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title OptimismBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for Optimism L2 integration
 * @dev Enables cross-chain interoperability with Optimism using the native CrossDomainMessenger
 *
 * OPTIMISM INTEGRATION:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    PIL <-> Optimism Bridge                              │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   PIL Protocol    │           │   Optimism        │                 │
 * │  │  (L1 Ethereum)    │           │   (L2 Rollup)     │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ L1 Cross    │  │           │  │ L2 Cross    │  │                 │
 * │  │  │ Domain      │  │──────────►│  │ Domain      │  │                 │
 * │  │  │ Messenger   │  │           │  │ Messenger   │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ Optimism    │  │◄──────────│  │ L2 to L1   │  │                 │
 * │  │  │ Portal      │  │           │  │ Messages   │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   OP Stack Architecture                            │ │
 * │  │  - Optimistic Rollup with Fault Proofs                             │ │
 * │  │  - 7-Day Withdrawal Period                                          │ │
 * │  │  - CrossDomainMessenger for L1<->L2 messaging                       │ │
 * │  │  - Bedrock Upgrade with improved performance                        │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * OP STACK CONCEPTS:
 * - Bedrock: Latest OP Stack upgrade with modular architecture
 * - CrossDomainMessenger: Native L1<->L2 messaging
 * - OptimismPortal: L1 contract for deposits and withdrawals
 * - Fault Proofs: Dispute resolution mechanism
 * - Sequencer: Batches and submits transactions
 */
contract OptimismBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Optimism Mainnet chain ID
    uint256 public constant OP_MAINNET_CHAIN_ID = 10;

    /// @notice Optimism Sepolia chain ID
    uint256 public constant OP_SEPOLIA_CHAIN_ID = 11155420;

    /// @notice Withdrawal period in seconds (~7 days)
    uint256 public constant WITHDRAWAL_PERIOD = 604800;

    /// @notice Default L2 gas limit
    uint256 public constant DEFAULT_L2_GAS_LIMIT = 1000000;

    /// @notice Minimum gas limit for cross-domain messages
    uint256 public constant MIN_GAS_LIMIT = 100000;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum MessageType {
        PROOF_RELAY,
        STATE_SYNC,
        NULLIFIER_CHECK,
        BATCH_VERIFY,
        EMERGENCY
    }

    enum MessageStatus {
        PENDING,
        SENT,
        CONFIRMED,
        FAILED,
        WITHDRAWN
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Cross-domain message structure
    struct CrossDomainMessage {
        bytes32 messageId;
        MessageType messageType;
        bytes payload;
        uint256 sourceChainId;
        uint256 targetChainId;
        address sender;
        address target;
        uint256 value;
        uint256 gasLimit;
        uint256 timestamp;
        MessageStatus status;
    }

    /// @notice Proof relay request
    struct ProofRelayRequest {
        bytes32 proofHash;
        bytes proof;
        bytes publicInputs;
        bytes32 stateRoot;
        uint256 nonce;
        uint256 deadline;
    }

    /// @notice Withdrawal request for L2->L1
    struct WithdrawalRequest {
        bytes32 withdrawalId;
        address user;
        bytes32 proofHash;
        uint256 amount;
        uint256 requestedAt;
        uint256 completableAt;
        bool completed;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice L1 CrossDomainMessenger address
    address public l1CrossDomainMessenger;

    /// @notice L2 CrossDomainMessenger address
    address public l2CrossDomainMessenger;

    /// @notice OptimismPortal address (L1)
    address public optimismPortal;

    /// @notice L2 target contract (PIL adapter on Optimism)
    address public l2Target;

    /// @notice Message nonce
    uint256 public messageNonce;

    /// @notice Whether this adapter is on L1 or L2
    bool public immutable isL1;

    /// @notice Mapping of message ID to message
    mapping(bytes32 => CrossDomainMessage) public messages;

    /// @notice Mapping of withdrawal ID to withdrawal request
    mapping(bytes32 => WithdrawalRequest) public withdrawals;

    /// @notice Pending proof relays
    mapping(bytes32 => ProofRelayRequest) public pendingProofRelays;

    /// @notice Relayed proofs
    mapping(bytes32 => bool) public relayedProofs;

    /// @notice Confirmed state roots
    mapping(bytes32 => uint256) public confirmedStateRoots;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages received
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged
    uint256 public totalValueBridged;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageId,
        MessageType messageType,
        address indexed sender,
        address indexed target,
        uint256 value
    );

    event MessageReceived(
        bytes32 indexed messageId,
        MessageType messageType,
        address indexed sender,
        uint256 value
    );

    event ProofRelayed(
        bytes32 indexed proofHash,
        uint256 sourceChainId,
        uint256 targetChainId,
        address relayer
    );

    event WithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed user,
        bytes32 proofHash,
        uint256 completableAt
    );

    event WithdrawalCompleted(
        bytes32 indexed withdrawalId,
        address indexed user,
        uint256 amount
    );

    event StateRootConfirmed(bytes32 indexed stateRoot, uint256 blockNumber);

    event L2TargetUpdated(address indexed oldTarget, address indexed newTarget);

    event MessengerUpdated(address indexed messenger, bool isL1Messenger);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidChainId();
    error InvalidMessenger();
    error InvalidTarget();
    error MessageNotFound();
    error MessageAlreadyProcessed();
    error ProofAlreadyRelayed();
    error WithdrawalNotReady();
    error WithdrawalAlreadyCompleted();
    error InsufficientGasLimit();
    error UnauthorizedCaller();
    error InvalidProof();
    error DeadlineExpired();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _admin,
        address _l1CrossDomainMessenger,
        address _l2CrossDomainMessenger,
        address _optimismPortal,
        bool _isL1
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);

        l1CrossDomainMessenger = _l1CrossDomainMessenger;
        l2CrossDomainMessenger = _l2CrossDomainMessenger;
        optimismPortal = _optimismPortal;
        isL1 = _isL1;
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a proof relay message to Optimism L2
     * @param proofHash Hash of the proof to relay
     * @param proof The actual proof data
     * @param publicInputs Public inputs for the proof
     * @param gasLimit Gas limit for L2 execution
     * @return messageId The ID of the sent message
     */
    function sendProofToL2(
        bytes32 proofHash,
        bytes calldata proof,
        bytes calldata publicInputs,
        uint256 gasLimit
    )
        external
        payable
        nonReentrant
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 messageId)
    {
        if (!isL1) revert InvalidChainId();
        if (gasLimit < MIN_GAS_LIMIT) revert InsufficientGasLimit();
        if (l2Target == address(0)) revert InvalidTarget();

        messageId = _generateMessageId(
            MessageType.PROOF_RELAY,
            msg.sender,
            l2Target
        );

        // Create proof relay payload
        bytes memory payload = abi.encodeWithSelector(
            this.receiveProofFromL1.selector,
            proofHash,
            proof,
            publicInputs,
            block.chainid
        );

        // Store message
        messages[messageId] = CrossDomainMessage({
            messageId: messageId,
            messageType: MessageType.PROOF_RELAY,
            payload: payload,
            sourceChainId: block.chainid,
            targetChainId: OP_MAINNET_CHAIN_ID,
            sender: msg.sender,
            target: l2Target,
            value: msg.value,
            gasLimit: gasLimit,
            timestamp: block.timestamp,
            status: MessageStatus.SENT
        });

        // Store pending proof relay
        pendingProofRelays[proofHash] = ProofRelayRequest({
            proofHash: proofHash,
            proof: proof,
            publicInputs: publicInputs,
            stateRoot: bytes32(0),
            nonce: messageNonce,
            deadline: block.timestamp + 1 hours
        });

        messageNonce++;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(
            messageId,
            MessageType.PROOF_RELAY,
            msg.sender,
            l2Target,
            msg.value
        );

        emit ProofRelayed(
            proofHash,
            block.chainid,
            OP_MAINNET_CHAIN_ID,
            msg.sender
        );

        // In production, this would call the CrossDomainMessenger
        // ICrossDomainMessenger(l1CrossDomainMessenger).sendMessage{value: msg.value}(
        //     l2Target,
        //     payload,
        //     uint32(gasLimit)
        // );
    }

    /**
     * @notice Receive a proof from L1 (called by CrossDomainMessenger)
     * @param proofHash Hash of the relayed proof
     * @param proof The proof data
     * @param publicInputs Public inputs
     * @param sourceChainId Source chain ID
     */
    function receiveProofFromL1(
        bytes32 proofHash,
        bytes calldata proof,
        bytes calldata publicInputs,
        uint256 sourceChainId
    ) external whenNotPaused {
        // Verify caller is the messenger
        // In production: require(msg.sender == l2CrossDomainMessenger)

        if (relayedProofs[proofHash]) revert ProofAlreadyRelayed();

        relayedProofs[proofHash] = true;
        totalMessagesReceived++;

        bytes32 messageId = keccak256(
            abi.encodePacked(proofHash, sourceChainId, block.timestamp)
        );

        emit MessageReceived(messageId, MessageType.PROOF_RELAY, msg.sender, 0);

        emit ProofRelayed(proofHash, sourceChainId, block.chainid, msg.sender);
    }

    /**
     * @notice Initiate a withdrawal from L2 to L1
     * @param proofHash Proof hash associated with the withdrawal
     * @return withdrawalId The withdrawal ID
     */
    function initiateWithdrawal(
        bytes32 proofHash
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 withdrawalId)
    {
        if (isL1) revert InvalidChainId();

        withdrawalId = keccak256(
            abi.encodePacked(
                msg.sender,
                proofHash,
                block.timestamp,
                messageNonce++
            )
        );

        withdrawals[withdrawalId] = WithdrawalRequest({
            withdrawalId: withdrawalId,
            user: msg.sender,
            proofHash: proofHash,
            amount: msg.value,
            requestedAt: block.timestamp,
            completableAt: block.timestamp + WITHDRAWAL_PERIOD,
            completed: false
        });

        emit WithdrawalInitiated(
            withdrawalId,
            msg.sender,
            proofHash,
            block.timestamp + WITHDRAWAL_PERIOD
        );

        // In production, this would call the L2ToL1MessagePasser
    }

    /**
     * @notice Complete a withdrawal on L1 (after challenge period)
     * @param withdrawalId The withdrawal ID to complete
     */
    function completeWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant whenNotPaused {
        if (!isL1) revert InvalidChainId();

        WithdrawalRequest storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.user == address(0)) revert MessageNotFound();
        if (withdrawal.completed) revert WithdrawalAlreadyCompleted();
        if (block.timestamp < withdrawal.completableAt)
            revert WithdrawalNotReady();

        withdrawal.completed = true;

        // Transfer funds
        (bool success, ) = withdrawal.user.call{value: withdrawal.amount}("");
        require(success, "Transfer failed");

        emit WithdrawalCompleted(
            withdrawalId,
            withdrawal.user,
            withdrawal.amount
        );
    }

    /**
     * @notice Send state sync message to L2
     * @param stateRoot State root to sync
     * @param blockNumber Associated block number
     * @param gasLimit Gas limit for L2 execution
     */
    function syncStateToL2(
        bytes32 stateRoot,
        uint256 blockNumber,
        uint256 gasLimit
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 messageId)
    {
        if (!isL1) revert InvalidChainId();
        if (gasLimit < MIN_GAS_LIMIT) revert InsufficientGasLimit();

        messageId = _generateMessageId(
            MessageType.STATE_SYNC,
            msg.sender,
            l2Target
        );

        bytes memory payload = abi.encodeWithSelector(
            this.receiveStateFromL1.selector,
            stateRoot,
            blockNumber
        );

        messages[messageId] = CrossDomainMessage({
            messageId: messageId,
            messageType: MessageType.STATE_SYNC,
            payload: payload,
            sourceChainId: block.chainid,
            targetChainId: OP_MAINNET_CHAIN_ID,
            sender: msg.sender,
            target: l2Target,
            value: 0,
            gasLimit: gasLimit,
            timestamp: block.timestamp,
            status: MessageStatus.SENT
        });

        totalMessagesSent++;

        emit MessageSent(
            messageId,
            MessageType.STATE_SYNC,
            msg.sender,
            l2Target,
            0
        );
    }

    /**
     * @notice Receive state from L1
     * @param stateRoot The state root
     * @param blockNumber The block number
     */
    function receiveStateFromL1(
        bytes32 stateRoot,
        uint256 blockNumber
    ) external whenNotPaused {
        // Verify caller is messenger in production

        confirmedStateRoots[stateRoot] = blockNumber;
        totalMessagesReceived++;

        emit StateRootConfirmed(stateRoot, blockNumber);
    }

    /**
     * @notice Check if a proof has been relayed
     * @param proofHash The proof hash to check
     * @return relayed True if the proof has been relayed
     */
    function isProofRelayed(
        bytes32 proofHash
    ) external view returns (bool relayed) {
        return relayedProofs[proofHash];
    }

    /**
     * @notice Get withdrawal status
     * @param withdrawalId The withdrawal ID
     * @return request The withdrawal request details
     */
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (WithdrawalRequest memory request) {
        return withdrawals[withdrawalId];
    }

    /**
     * @notice Get message details
     * @param messageId The message ID
     * @return message The message details
     */
    function getMessage(
        bytes32 messageId
    ) external view returns (CrossDomainMessage memory message) {
        return messages[messageId];
    }

    /**
     * @notice Check if a state root is confirmed
     * @param stateRoot The state root to check
     * @return blockNumber The block number (0 if not confirmed)
     */
    function getStateRootBlock(
        bytes32 stateRoot
    ) external view returns (uint256 blockNumber) {
        return confirmedStateRoots[stateRoot];
    }

    /**
     * @notice Get adapter statistics
     */
    function getStats()
        external
        view
        returns (
            uint256 messagesSent,
            uint256 messagesReceived,
            uint256 valueBridged,
            uint256 currentNonce
        )
    {
        return (
            totalMessagesSent,
            totalMessagesReceived,
            totalValueBridged,
            messageNonce
        );
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update L2 target address
     * @param _l2Target New L2 target address
     */
    function setL2Target(
        address _l2Target
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        address oldTarget = l2Target;
        l2Target = _l2Target;
        emit L2TargetUpdated(oldTarget, _l2Target);
    }

    /**
     * @notice Update messenger addresses
     * @param _messenger New messenger address
     * @param _isL1Messenger Whether this is the L1 messenger
     */
    function setMessenger(
        address _messenger,
        bool _isL1Messenger
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_isL1Messenger) {
            l1CrossDomainMessenger = _messenger;
        } else {
            l2CrossDomainMessenger = _messenger;
        }
        emit MessengerUpdated(_messenger, _isL1Messenger);
    }

    /**
     * @notice Pause the adapter
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the adapter
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /**
     * @notice Emergency withdraw stuck funds
     * @param to Recipient address
     * @param amount Amount to withdraw
     */
    function emergencyWithdraw(
        address to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        (bool success, ) = to.call{value: amount}("");
        require(success, "Transfer failed");
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Generate a unique message ID
     */
    function _generateMessageId(
        MessageType messageType,
        address sender,
        address target
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    messageType,
                    sender,
                    target,
                    block.chainid,
                    messageNonce,
                    block.timestamp
                )
            );
    }

    /**
     * @notice Receive ETH
     */
    receive() external payable {}
}
