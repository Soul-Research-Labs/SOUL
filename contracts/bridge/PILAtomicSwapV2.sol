// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title PILAtomicSwapV2
/// @author PIL Protocol
/// @notice Atomic cross-chain swaps with HTLC, privacy features, and security hardening
/// @dev Implements hash time-locked contracts with stealth address support
contract PILAtomicSwapV2 is Ownable, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /// @notice Swap status enum
    enum SwapStatus {
        Invalid,
        Created,
        Claimed,
        Refunded,
        Expired
    }

    /// @notice Represents an atomic swap
    /// @param id Unique swap identifier
    /// @param initiator The swap initiator
    /// @param recipient The intended recipient
    /// @param token The token address (address(0) for ETH)
    /// @param amount The swap amount
    /// @param hashLock The hash lock (keccak256 of secret)
    /// @param timeLock The time lock expiry timestamp
    /// @param status Current swap status
    /// @param commitment Privacy commitment for stealth transfer
    struct Swap {
        bytes32 id;
        address initiator;
        address recipient;
        address token;
        uint256 amount;
        bytes32 hashLock;
        uint256 timeLock;
        SwapStatus status;
        bytes32 commitment;
    }

    /// @notice Mapping of swap ID to swap details
    mapping(bytes32 => Swap) public swaps;

    /// @notice Mapping of hash lock to swap ID (for lookup)
    mapping(bytes32 => bytes32) public hashLockToSwap;

    /// @notice Minimum time lock duration (1 hour)
    uint256 public constant MIN_TIMELOCK = 1 hours;

    /// @notice Maximum time lock duration (7 days)
    uint256 public constant MAX_TIMELOCK = 7 days;

    /// @notice Protocol fee in basis points (0.1%)
    uint256 public protocolFeeBps = 10;

    /// @notice Fee recipient address
    address public feeRecipient;

    /// @notice Total fees collected per token
    mapping(address => uint256) public collectedFees;

    /// @notice Events
    event SwapCreated(
        bytes32 indexed swapId,
        address indexed initiator,
        address indexed recipient,
        address token,
        uint256 amount,
        bytes32 hashLock,
        uint256 timeLock
    );
    event SwapClaimed(
        bytes32 indexed swapId,
        address indexed claimer,
        bytes32 secret
    );
    event SwapRefunded(bytes32 indexed swapId, address indexed initiator);
    event FeeUpdated(uint256 oldFee, uint256 newFee);
    event FeeRecipientUpdated(address oldRecipient, address newRecipient);

    /// @notice Custom errors
    error InvalidRecipient();
    error InvalidAmount();
    error InvalidTimeLock();
    error InvalidHashLock();
    error SwapAlreadyExists();
    error SwapNotFound();
    error SwapNotPending();
    error InvalidSecret();
    error SwapNotExpired();
    error SwapExpired();
    error NotInitiator();
    error TransferFailed();

    constructor(address _feeRecipient) Ownable(msg.sender) {
        feeRecipient = _feeRecipient;
    }

    /// @notice Creates a new atomic swap (ETH)
    /// @param recipient The intended recipient
    /// @param hashLock The hash lock (keccak256 of secret)
    /// @param timeLock The time lock duration in seconds
    /// @param commitment Privacy commitment for stealth transfer
    /// @return swapId The unique swap identifier
    function createSwapETH(
        address recipient,
        bytes32 hashLock,
        uint256 timeLock,
        bytes32 commitment
    ) external payable nonReentrant whenNotPaused returns (bytes32 swapId) {
        return
            _createSwap(
                recipient,
                address(0),
                msg.value,
                hashLock,
                timeLock,
                commitment
            );
    }

    /// @notice Creates a new atomic swap (ERC20)
    /// @param recipient The intended recipient
    /// @param token The ERC20 token address
    /// @param amount The swap amount
    /// @param hashLock The hash lock (keccak256 of secret)
    /// @param timeLock The time lock duration in seconds
    /// @param commitment Privacy commitment for stealth transfer
    /// @return swapId The unique swap identifier
    function createSwapToken(
        address recipient,
        address token,
        uint256 amount,
        bytes32 hashLock,
        uint256 timeLock,
        bytes32 commitment
    ) external nonReentrant whenNotPaused returns (bytes32 swapId) {
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        return
            _createSwap(
                recipient,
                token,
                amount,
                hashLock,
                timeLock,
                commitment
            );
    }

    /// @notice Internal function to create swap
    function _createSwap(
        address recipient,
        address token,
        uint256 amount,
        bytes32 hashLock,
        uint256 timeLock,
        bytes32 commitment
    ) internal returns (bytes32 swapId) {
        // Validations
        if (recipient == address(0)) revert InvalidRecipient();
        if (amount == 0) revert InvalidAmount();
        if (timeLock < MIN_TIMELOCK || timeLock > MAX_TIMELOCK)
            revert InvalidTimeLock();
        if (hashLock == bytes32(0)) revert InvalidHashLock();
        if (hashLockToSwap[hashLock] != bytes32(0)) revert SwapAlreadyExists();

        // Generate swap ID
        swapId = keccak256(
            abi.encodePacked(
                msg.sender,
                recipient,
                token,
                amount,
                hashLock,
                block.timestamp
            )
        );

        // Calculate fee
        uint256 fee = (amount * protocolFeeBps) / 10000;
        uint256 netAmount = amount - fee;
        collectedFees[token] += fee;

        // Create swap
        swaps[swapId] = Swap({
            id: swapId,
            initiator: msg.sender,
            recipient: recipient,
            token: token,
            amount: netAmount,
            hashLock: hashLock,
            timeLock: block.timestamp + timeLock,
            status: SwapStatus.Created,
            commitment: commitment
        });

        hashLockToSwap[hashLock] = swapId;

        emit SwapCreated(
            swapId,
            msg.sender,
            recipient,
            token,
            netAmount,
            hashLock,
            block.timestamp + timeLock
        );
    }

    /// @notice Claims a swap by revealing the secret
    /// @param swapId The swap identifier
    /// @param secret The secret that hashes to hashLock
    function claim(
        bytes32 swapId,
        bytes32 secret
    ) external nonReentrant whenNotPaused {
        Swap storage swap = swaps[swapId];

        if (swap.status != SwapStatus.Created) revert SwapNotPending();
        if (block.timestamp >= swap.timeLock) revert SwapExpired();
        if (keccak256(abi.encodePacked(secret)) != swap.hashLock)
            revert InvalidSecret();

        swap.status = SwapStatus.Claimed;

        // Transfer to recipient
        if (swap.token == address(0)) {
            (bool success, ) = swap.recipient.call{value: swap.amount}("");
            if (!success) revert TransferFailed();
        } else {
            IERC20(swap.token).safeTransfer(swap.recipient, swap.amount);
        }

        emit SwapClaimed(swapId, msg.sender, secret);
    }

    /// @notice Refunds an expired swap to the initiator
    /// @param swapId The swap identifier
    function refund(bytes32 swapId) external nonReentrant {
        Swap storage swap = swaps[swapId];

        if (swap.status != SwapStatus.Created) revert SwapNotPending();
        if (block.timestamp < swap.timeLock) revert SwapNotExpired();

        swap.status = SwapStatus.Refunded;

        // Refund to initiator
        if (swap.token == address(0)) {
            (bool success, ) = swap.initiator.call{value: swap.amount}("");
            if (!success) revert TransferFailed();
        } else {
            IERC20(swap.token).safeTransfer(swap.initiator, swap.amount);
        }

        emit SwapRefunded(swapId, swap.initiator);
    }

    /// @notice Gets swap details by hash lock
    /// @param hashLock The hash lock to lookup
    /// @return swap The swap details
    function getSwapByHashLock(
        bytes32 hashLock
    ) external view returns (Swap memory swap) {
        bytes32 swapId = hashLockToSwap[hashLock];
        return swaps[swapId];
    }

    /// @notice Checks if a swap is claimable
    /// @param swapId The swap identifier
    /// @return claimable True if claimable
    function isClaimable(
        bytes32 swapId
    ) external view returns (bool claimable) {
        Swap storage swap = swaps[swapId];
        return
            swap.status == SwapStatus.Created &&
            block.timestamp < swap.timeLock;
    }

    /// @notice Checks if a swap is refundable
    /// @param swapId The swap identifier
    /// @return refundable True if refundable
    function isRefundable(
        bytes32 swapId
    ) external view returns (bool refundable) {
        Swap storage swap = swaps[swapId];
        return
            swap.status == SwapStatus.Created &&
            block.timestamp >= swap.timeLock;
    }

    /// @notice Updates the protocol fee
    /// @param newFeeBps New fee in basis points
    function setProtocolFee(uint256 newFeeBps) external onlyOwner {
        require(newFeeBps <= 100, "Fee too high"); // Max 1%
        uint256 oldFee = protocolFeeBps;
        protocolFeeBps = newFeeBps;
        emit FeeUpdated(oldFee, newFeeBps);
    }

    /// @notice Updates the fee recipient
    /// @param newRecipient New fee recipient address
    function setFeeRecipient(address newRecipient) external onlyOwner {
        require(newRecipient != address(0), "Invalid recipient");
        address oldRecipient = feeRecipient;
        feeRecipient = newRecipient;
        emit FeeRecipientUpdated(oldRecipient, newRecipient);
    }

    /// @notice Withdraws collected fees
    /// @param token Token address (address(0) for ETH)
    function withdrawFees(address token) external onlyOwner {
        uint256 amount = collectedFees[token];
        collectedFees[token] = 0;

        if (token == address(0)) {
            (bool success, ) = feeRecipient.call{value: amount}("");
            require(success, "Transfer failed");
        } else {
            IERC20(token).safeTransfer(feeRecipient, amount);
        }
    }

    /// @notice Pause the contract
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpause the contract
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Receive ETH
    receive() external payable {}
}
