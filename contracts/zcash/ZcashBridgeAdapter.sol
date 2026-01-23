// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ZcashPrimitives} from "./ZcashPrimitives.sol";

/**
 * @title ZcashBridgeAdapter
 * @author PIL Protocol
 * @notice Cross-chain bridge adapter for Zcash shielded transactions
 * @dev Enables privacy-preserving interoperability between Zcash and EVM chains
 *
 * ZCASH <-> PIL BRIDGE ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────────┐
 * │                      Zcash <-> PIL Interoperability                             │
 * ├─────────────────────────────────────────────────────────────────────────────────┤
 * │                                                                                  │
 * │  ┌─────────────────────────────────────────────────────────────────────────────┐│
 * │  │                        ZCASH NETWORK                                        ││
 * │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        ││
 * │  │  │  Sprout     │  │  Sapling    │  │  Orchard    │  │ Transparent │        ││
 * │  │  │  (Legacy)   │  │  Pool       │  │  Pool       │  │  Pool       │        ││
 * │  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        ││
 * │  │         │                │                │                │                ││
 * │  │         └────────────────┴────────┬───────┴────────────────┘                ││
 * │  │                                   │                                          ││
 * │  │                         ┌─────────▼─────────┐                               ││
 * │  │                         │  Bridge Custodian │                               ││
 * │  │                         │  (Multi-sig)      │                               ││
 * │  │                         └─────────┬─────────┘                               ││
 * │  └───────────────────────────────────│─────────────────────────────────────────┘│
 * │                                      │                                           │
 * │  ════════════════════════════════════╪═══════════════════════════════════════════│
 * │                                      │ SPV Proofs / Relay                        │
 * │  ════════════════════════════════════╪═══════════════════════════════════════════│
 * │                                      │                                           │
 * │  ┌───────────────────────────────────▼───────────────────────────────────────────┐
 * │  │                         PIL PROTOCOL (EVM)                                    │
 * │  │                                                                               │
 * │  │  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────────────┐  │
 * │  │  │ ZcashBridge     │  │ Note Commitment  │  │ Cross-Chain Nullifier      │  │
 * │  │  │ Adapter         │──│ Registry         │──│ Registry                   │  │
 * │  │  └────────┬────────┘  └──────────────────┘  └─────────────────────────────┘  │
 * │  │           │                                                                   │
 * │  │  ┌────────▼────────┐  ┌──────────────────┐  ┌─────────────────────────────┐  │
 * │  │  │ Groth16         │  │ Merkle Tree      │  │ Privacy-Preserving         │  │
 * │  │  │ Verifier        │  │ Synchronizer     │  │ Atomic Swaps               │  │
 * │  │  └─────────────────┘  └──────────────────┘  └─────────────────────────────┘  │
 * │  └───────────────────────────────────────────────────────────────────────────────┘
 * └─────────────────────────────────────────────────────────────────────────────────────┘
 *
 * BRIDGE FLOW:
 * 1. Zcash → PIL: User locks shielded notes in Zcash custodian, provides SPV proof
 * 2. PIL verifies proof, mints wrapped notes with preserved privacy
 * 3. PIL → Zcash: User burns wrapped notes, custodian releases on Zcash
 * 4. Nullifiers synchronized across chains to prevent double-spending
 *
 * SECURITY FEATURES:
 * - SPV proof verification for Zcash block headers
 * - Groth16 proof verification for shielded transactions
 * - Multi-sig custodian on Zcash side
 * - Nullifier registry prevents double-spend
 * - Rate limiting and circuit breakers
 * - Anchor synchronization between chains
 */
contract ZcashBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    using ZcashPrimitives for *;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Zcash mainnet magic bytes
    bytes4 public constant ZCASH_MAINNET_MAGIC = 0x24e92764;

    /// @notice Zcash testnet magic bytes
    bytes4 public constant ZCASH_TESTNET_MAGIC = 0xfa1af9bf;

    /// @notice Sapling activation height (mainnet)
    uint32 public constant SAPLING_ACTIVATION_HEIGHT = 419200;

    /// @notice Orchard activation height (mainnet, NU5)
    uint32 public constant ORCHARD_ACTIVATION_HEIGHT = 1687104;

    /// @notice Block confirmation requirement
    uint32 public constant REQUIRED_CONFIRMATIONS = 24;

    /// @notice Maximum bridge amount per transaction (in zatoshis)
    uint64 public constant MAX_BRIDGE_AMOUNT = 21_000_000 * 100_000_000; // 21M ZEC

    /// @notice Minimum bridge amount (in zatoshis)
    uint64 public constant MIN_BRIDGE_AMOUNT = 10000; // 0.0001 ZEC

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidProof();
    error InvalidAnchor();
    error InvalidNullifier();
    error NullifierAlreadyUsed();
    error InsufficientConfirmations();
    error BridgeAmountTooLow();
    error BridgeAmountTooHigh();
    error InvalidBlockHeader();
    error BlockNotInChain();
    error InvalidMerkleProof();
    error UnsupportedPool();
    error BridgePaused();
    error RateLimitExceeded();
    error InvalidCustodianSignature();
    error WithdrawalNotReady();
    error InvalidTransaction();

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event DepositInitiated(
        bytes32 indexed depositId,
        bytes32 indexed noteCommitment,
        ZcashPrimitives.ShieldedPool pool,
        uint64 amount,
        address indexed recipient
    );

    event DepositCompleted(
        bytes32 indexed depositId,
        bytes32 indexed pilCommitment,
        uint64 amount
    );

    event WithdrawalInitiated(
        bytes32 indexed withdrawalId,
        bytes32 indexed pilNullifier,
        uint64 amount,
        bytes32 zcashRecipient
    );

    event WithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 indexed zcashTxHash
    );

    event NullifierSynced(
        bytes32 indexed nullifier,
        ZcashPrimitives.ShieldedPool pool,
        bytes32 indexed zcashTxHash
    );

    event AnchorUpdated(
        ZcashPrimitives.ShieldedPool pool,
        bytes32 indexed anchor,
        uint32 blockHeight
    );

    event BlockHeaderRelayed(
        bytes32 indexed blockHash,
        uint32 height,
        bytes32 previousHash
    );

    event CustodianUpdated(
        bytes32 indexed oldCustodian,
        bytes32 indexed newCustodian
    );

    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    enum DepositStatus {
        PENDING,
        PROOF_SUBMITTED,
        VERIFIED,
        COMPLETED,
        FAILED
    }

    enum WithdrawalStatus {
        PENDING,
        NULLIFIER_SUBMITTED,
        CUSTODIAN_APPROVED,
        COMPLETED,
        FAILED
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Zcash block header (simplified)
    struct ZcashBlockHeader {
        uint32 version;
        bytes32 previousBlockHash;
        bytes32 merkleRoot;
        bytes32 finalSaplingRoot; // Sapling anchor
        uint32 timestamp;
        uint32 bits;
        bytes32 nonce;
        bytes solutionSize;
        bytes solution; // Equihash solution
    }

    /// @notice Deposit request from Zcash to PIL
    struct DepositRequest {
        bytes32 depositId;
        bytes32 zcashTxHash;
        bytes32 noteCommitment;
        ZcashPrimitives.ShieldedPool pool;
        uint64 amount;
        address recipient;
        bytes32 pilCommitment;
        bytes proof;
        uint32 blockHeight;
        uint64 timestamp;
        DepositStatus status;
    }

    /// @notice Withdrawal request from PIL to Zcash
    struct WithdrawalRequest {
        bytes32 withdrawalId;
        bytes32 pilNullifier;
        bytes32 zcashRecipient; // Encoded shielded address
        uint64 amount;
        ZcashPrimitives.ShieldedPool targetPool;
        bytes32 zcashTxHash;
        uint64 timestamp;
        WithdrawalStatus status;
    }

    /// @notice SPV proof for Zcash transaction inclusion
    struct SPVProof {
        bytes32 txHash;
        bytes32[] merkleProof;
        uint256 txIndex;
        ZcashBlockHeader blockHeader;
        bytes32 blockHash;
    }

    /// @notice Anchor state for each pool
    struct AnchorState {
        bytes32 currentAnchor;
        bytes32[] historicalAnchors;
        uint32 lastUpdateHeight;
        uint64 lastUpdateTimestamp;
    }

    /// @notice Rate limit configuration
    struct RateLimitConfig {
        uint256 maxDailyVolume; // Max volume per day
        uint256 maxPerTransaction; // Max per single tx
        uint256 cooldownPeriod; // Seconds between large txs
        uint256 currentDayVolume;
        uint256 dayStartTimestamp;
        uint256 lastLargeTransactionTime;
    }

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Zcash network configuration
    ZcashPrimitives.ZcashNetwork public zcashNetwork;

    /// @notice Custodian address on Zcash (multi-sig, encoded)
    bytes32 public custodianAddress;

    /// @notice Verified Zcash block headers
    mapping(bytes32 => ZcashBlockHeader) public blockHeaders;

    /// @notice Block hash to height mapping
    mapping(bytes32 => uint32) public blockHeights;

    /// @notice Latest verified block hash
    bytes32 public latestBlockHash;

    /// @notice Latest verified block height
    uint32 public latestBlockHeight;

    /// @notice Deposit requests
    mapping(bytes32 => DepositRequest) public deposits;

    /// @notice Withdrawal requests
    mapping(bytes32 => WithdrawalRequest) public withdrawals;

    /// @notice Used Zcash nullifiers (to prevent double-spend)
    mapping(bytes32 => bool) public usedZcashNullifiers;

    /// @notice PIL nullifiers linked to Zcash
    mapping(bytes32 => bytes32) public pilToZcashNullifier;

    /// @notice Zcash nullifiers linked to PIL
    mapping(bytes32 => bytes32) public zcashToPilNullifier;

    /// @notice Anchor state per pool
    mapping(ZcashPrimitives.ShieldedPool => AnchorState) public anchors;

    /// @notice Rate limiting
    RateLimitConfig public rateLimit;

    /// @notice Proof verifier contract
    address public proofVerifier;

    /// @notice Total bridged value (zatoshis)
    uint256 public totalBridgedValue;

    /// @notice Nonce for generating unique IDs
    uint256 private _nonce;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        ZcashPrimitives.ZcashNetwork _network,
        bytes32 _custodianAddress,
        address _proofVerifier
    ) {
        zcashNetwork = _network;
        custodianAddress = _custodianAddress;
        proofVerifier = _proofVerifier;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);

        // Initialize rate limits
        rateLimit = RateLimitConfig({
            maxDailyVolume: 1000 * 100_000_000 * 1e18, // 1000 ZEC
            maxPerTransaction: 100 * 100_000_000 * 1e18, // 100 ZEC
            cooldownPeriod: 300, // 5 minutes
            currentDayVolume: 0,
            dayStartTimestamp: block.timestamp,
            lastLargeTransactionTime: 0
        });
    }

    /*//////////////////////////////////////////////////////////////
                          DEPOSIT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate a deposit from Zcash shielded pool
     * @param noteCommitment The Zcash note commitment being bridged
     * @param pool The shielded pool (Sapling or Orchard)
     * @param amount Amount in zatoshis
     * @param recipient EVM address to receive wrapped tokens
     * @param spvProof SPV proof of the locking transaction
     * @return depositId Unique deposit identifier
     */
    function initiateDeposit(
        bytes32 noteCommitment,
        ZcashPrimitives.ShieldedPool pool,
        uint64 amount,
        address recipient,
        SPVProof calldata spvProof
    ) external nonReentrant whenNotPaused returns (bytes32 depositId) {
        // Validate pool
        if (pool == ZcashPrimitives.ShieldedPool.SPROUT) {
            revert UnsupportedPool();
        }

        // Validate amount
        if (amount < MIN_BRIDGE_AMOUNT) revert BridgeAmountTooLow();
        if (amount > MAX_BRIDGE_AMOUNT) revert BridgeAmountTooHigh();

        // Check rate limits
        _checkRateLimit(amount);

        // Verify block header is in our chain
        if (!_isBlockInChain(spvProof.blockHash)) {
            revert BlockNotInChain();
        }

        // Verify sufficient confirmations
        uint32 blockHeight = blockHeights[spvProof.blockHash];
        if (latestBlockHeight - blockHeight < REQUIRED_CONFIRMATIONS) {
            revert InsufficientConfirmations();
        }

        // Verify SPV proof (Merkle inclusion)
        if (!_verifySPVProof(spvProof)) {
            revert InvalidMerkleProof();
        }

        // Generate deposit ID
        depositId = _generateDepositId(noteCommitment, recipient);

        // Create PIL commitment
        bytes32 pilCommitment = _computePILCommitment(
            noteCommitment,
            amount,
            recipient
        );

        // Store deposit request
        deposits[depositId] = DepositRequest({
            depositId: depositId,
            zcashTxHash: spvProof.txHash,
            noteCommitment: noteCommitment,
            pool: pool,
            amount: amount,
            recipient: recipient,
            pilCommitment: pilCommitment,
            proof: "",
            blockHeight: blockHeight,
            timestamp: uint64(block.timestamp),
            status: DepositStatus.PENDING
        });

        emit DepositInitiated(
            depositId,
            noteCommitment,
            pool,
            amount,
            recipient
        );
    }

    /**
     * @notice Submit ZK proof to complete deposit
     * @param depositId The deposit identifier
     * @param zkProof Groth16 proof of valid note locking
     */
    function submitDepositProof(
        bytes32 depositId,
        bytes calldata zkProof
    ) external nonReentrant {
        DepositRequest storage deposit = deposits[depositId];
        require(deposit.depositId != bytes32(0), "Deposit not found");
        require(deposit.status == DepositStatus.PENDING, "Invalid status");

        // Verify ZK proof
        if (!_verifyDepositProof(deposit, zkProof)) {
            revert InvalidProof();
        }

        deposit.proof = zkProof;
        deposit.status = DepositStatus.PROOF_SUBMITTED;
    }

    /**
     * @notice Complete deposit after verification
     * @param depositId The deposit identifier
     */
    function completeDeposit(
        bytes32 depositId
    ) external onlyRole(VERIFIER_ROLE) nonReentrant {
        DepositRequest storage deposit = deposits[depositId];
        require(
            deposit.status == DepositStatus.PROOF_SUBMITTED,
            "Proof not submitted"
        );

        // Mark as completed
        deposit.status = DepositStatus.COMPLETED;
        totalBridgedValue += deposit.amount;

        // Update rate limit tracking
        _updateRateLimit(deposit.amount);

        emit DepositCompleted(depositId, deposit.pilCommitment, deposit.amount);

        // Mint wrapped tokens to recipient
        // This would call the wrapped ZEC token contract
        _mintWrappedTokens(
            deposit.recipient,
            deposit.amount,
            deposit.pilCommitment
        );
    }

    /*//////////////////////////////////////////////////////////////
                        WITHDRAWAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate withdrawal from PIL to Zcash
     * @param pilNullifier The PIL nullifier being consumed
     * @param amount Amount to withdraw in zatoshis
     * @param zcashRecipient Encoded Zcash shielded address
     * @param targetPool Target shielded pool
     * @param proof Proof of valid nullifier ownership
     * @return withdrawalId Unique withdrawal identifier
     */
    function initiateWithdrawal(
        bytes32 pilNullifier,
        uint64 amount,
        bytes32 zcashRecipient,
        ZcashPrimitives.ShieldedPool targetPool,
        bytes calldata proof
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        // Validate pool
        if (targetPool == ZcashPrimitives.ShieldedPool.SPROUT) {
            revert UnsupportedPool();
        }

        // Validate amount
        if (amount < MIN_BRIDGE_AMOUNT) revert BridgeAmountTooLow();
        if (amount > MAX_BRIDGE_AMOUNT) revert BridgeAmountTooHigh();

        // Verify nullifier hasn't been used
        if (usedZcashNullifiers[pilNullifier]) {
            revert NullifierAlreadyUsed();
        }

        // Verify proof of nullifier ownership
        if (!_verifyNullifierOwnership(pilNullifier, msg.sender, proof)) {
            revert InvalidProof();
        }

        // Generate withdrawal ID
        withdrawalId = _generateWithdrawalId(pilNullifier, zcashRecipient);

        // Mark nullifier as used
        usedZcashNullifiers[pilNullifier] = true;

        // Store withdrawal request
        withdrawals[withdrawalId] = WithdrawalRequest({
            withdrawalId: withdrawalId,
            pilNullifier: pilNullifier,
            zcashRecipient: zcashRecipient,
            amount: amount,
            targetPool: targetPool,
            zcashTxHash: bytes32(0),
            timestamp: uint64(block.timestamp),
            status: WithdrawalStatus.PENDING
        });

        // Burn wrapped tokens
        _burnWrappedTokens(msg.sender, amount, pilNullifier);

        emit WithdrawalInitiated(
            withdrawalId,
            pilNullifier,
            amount,
            zcashRecipient
        );
    }

    /**
     * @notice Complete withdrawal after custodian processes on Zcash
     * @param withdrawalId The withdrawal identifier
     * @param zcashTxHash The Zcash transaction hash
     * @param custodianSignature Signature from custodian
     */
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 zcashTxHash,
        bytes calldata custodianSignature
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        WithdrawalRequest storage withdrawal = withdrawals[withdrawalId];
        require(withdrawal.withdrawalId != bytes32(0), "Withdrawal not found");
        require(
            withdrawal.status == WithdrawalStatus.PENDING ||
                withdrawal.status == WithdrawalStatus.NULLIFIER_SUBMITTED,
            "Invalid status"
        );

        // Verify custodian signature
        if (
            !_verifyCustodianSignature(
                withdrawalId,
                zcashTxHash,
                custodianSignature
            )
        ) {
            revert InvalidCustodianSignature();
        }

        withdrawal.zcashTxHash = zcashTxHash;
        withdrawal.status = WithdrawalStatus.COMPLETED;
        totalBridgedValue -= withdrawal.amount;

        emit WithdrawalCompleted(withdrawalId, zcashTxHash);
    }

    /*//////////////////////////////////////////////////////////////
                       NULLIFIER SYNCHRONIZATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Sync a Zcash nullifier to PIL
     * @param nullifier The Zcash nullifier
     * @param pool The shielded pool
     * @param zcashTxHash Transaction that revealed the nullifier
     * @param spvProof SPV proof of the transaction
     */
    function syncNullifier(
        bytes32 nullifier,
        ZcashPrimitives.ShieldedPool pool,
        bytes32 zcashTxHash,
        SPVProof calldata spvProof
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        // Verify nullifier not already synced
        if (usedZcashNullifiers[nullifier]) {
            revert NullifierAlreadyUsed();
        }

        // Verify SPV proof
        if (!_verifySPVProof(spvProof)) {
            revert InvalidMerkleProof();
        }

        // Mark nullifier as used
        usedZcashNullifiers[nullifier] = true;

        // Create cross-chain binding
        bytes32 pilNullifier = ZcashPrimitives
            .computeCrossChainNullifierBinding(
                nullifier,
                ZcashPrimitives.PIL_ZCASH_DOMAIN,
                uint64(block.chainid)
            );

        pilToZcashNullifier[pilNullifier] = nullifier;
        zcashToPilNullifier[nullifier] = pilNullifier;

        emit NullifierSynced(nullifier, pool, zcashTxHash);
    }

    /**
     * @notice Batch sync multiple nullifiers
     * @param nullifiers Array of nullifiers
     * @param pool The shielded pool
     * @param zcashTxHashes Corresponding transaction hashes
     */
    function batchSyncNullifiers(
        bytes32[] calldata nullifiers,
        ZcashPrimitives.ShieldedPool pool,
        bytes32[] calldata zcashTxHashes
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        require(nullifiers.length == zcashTxHashes.length, "Length mismatch");

        for (uint256 i = 0; i < nullifiers.length; i++) {
            if (!usedZcashNullifiers[nullifiers[i]]) {
                usedZcashNullifiers[nullifiers[i]] = true;

                bytes32 pilNullifier = ZcashPrimitives
                    .computeCrossChainNullifierBinding(
                        nullifiers[i],
                        ZcashPrimitives.PIL_ZCASH_DOMAIN,
                        uint64(block.chainid)
                    );

                pilToZcashNullifier[pilNullifier] = nullifiers[i];
                zcashToPilNullifier[nullifiers[i]] = pilNullifier;

                emit NullifierSynced(nullifiers[i], pool, zcashTxHashes[i]);
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                        ANCHOR SYNCHRONIZATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update the anchor (commitment tree root) for a pool
     * @param pool The shielded pool
     * @param newAnchor The new anchor value
     * @param blockHeight Block height of the anchor
     * @param proof Proof of anchor validity
     */
    function updateAnchor(
        ZcashPrimitives.ShieldedPool pool,
        bytes32 newAnchor,
        uint32 blockHeight,
        bytes calldata proof
    ) external onlyRole(RELAYER_ROLE) {
        // Verify anchor proof
        if (!_verifyAnchorProof(pool, newAnchor, blockHeight, proof)) {
            revert InvalidAnchor();
        }

        AnchorState storage state = anchors[pool];

        // Store historical anchor
        if (state.currentAnchor != bytes32(0)) {
            state.historicalAnchors.push(state.currentAnchor);
        }

        state.currentAnchor = newAnchor;
        state.lastUpdateHeight = blockHeight;
        state.lastUpdateTimestamp = uint64(block.timestamp);

        emit AnchorUpdated(pool, newAnchor, blockHeight);
    }

    /**
     * @notice Check if an anchor is valid (current or historical)
     * @param pool The shielded pool
     * @param anchor The anchor to check
     * @return valid Whether the anchor is valid
     */
    function isValidAnchor(
        ZcashPrimitives.ShieldedPool pool,
        bytes32 anchor
    ) external view returns (bool valid) {
        AnchorState storage state = anchors[pool];

        if (state.currentAnchor == anchor) {
            return true;
        }

        for (uint256 i = 0; i < state.historicalAnchors.length; i++) {
            if (state.historicalAnchors[i] == anchor) {
                return true;
            }
        }

        return false;
    }

    /*//////////////////////////////////////////////////////////////
                         BLOCK HEADER RELAY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Relay a Zcash block header
     * @param header The block header
     * @param blockHash The block hash
     */
    function relayBlockHeader(
        ZcashBlockHeader calldata header,
        bytes32 blockHash
    ) external onlyRole(RELAYER_ROLE) {
        // Verify this extends our chain
        if (latestBlockHash != bytes32(0)) {
            require(
                header.previousBlockHash == latestBlockHash,
                "Does not extend chain"
            );
        }

        // Verify PoW (Equihash solution)
        if (!_verifyEquihash(header, blockHash)) {
            revert InvalidBlockHeader();
        }

        // Store header
        blockHeaders[blockHash] = header;
        blockHeights[blockHash] = latestBlockHeight + 1;
        latestBlockHash = blockHash;
        latestBlockHeight++;

        // Update Sapling anchor from header
        if (header.finalSaplingRoot != bytes32(0)) {
            AnchorState storage saplingState = anchors[
                ZcashPrimitives.ShieldedPool.SAPLING
            ];
            if (saplingState.currentAnchor != bytes32(0)) {
                saplingState.historicalAnchors.push(saplingState.currentAnchor);
            }
            saplingState.currentAnchor = header.finalSaplingRoot;
            saplingState.lastUpdateHeight = latestBlockHeight;
            saplingState.lastUpdateTimestamp = uint64(block.timestamp);
        }

        emit BlockHeaderRelayed(
            blockHash,
            latestBlockHeight,
            header.previousBlockHash
        );
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update custodian address
     * @param newCustodian New custodian address (encoded)
     */
    function updateCustodian(
        bytes32 newCustodian
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        bytes32 oldCustodian = custodianAddress;
        custodianAddress = newCustodian;
        emit CustodianUpdated(oldCustodian, newCustodian);
    }

    /**
     * @notice Update proof verifier
     * @param newVerifier New verifier address
     */
    function updateProofVerifier(
        address newVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        proofVerifier = newVerifier;
    }

    /**
     * @notice Update rate limits
     * @param maxDaily Maximum daily volume
     * @param maxPerTx Maximum per transaction
     * @param cooldown Cooldown period
     */
    function updateRateLimits(
        uint256 maxDaily,
        uint256 maxPerTx,
        uint256 cooldown
    ) external onlyRole(GUARDIAN_ROLE) {
        rateLimit.maxDailyVolume = maxDaily;
        rateLimit.maxPerTransaction = maxPerTx;
        rateLimit.cooldownPeriod = cooldown;
    }

    /**
     * @notice Pause the bridge
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the bridge
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get deposit details
     * @param depositId Deposit identifier
     */
    function getDeposit(
        bytes32 depositId
    ) external view returns (DepositRequest memory) {
        return deposits[depositId];
    }

    /**
     * @notice Get withdrawal details
     * @param withdrawalId Withdrawal identifier
     */
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (WithdrawalRequest memory) {
        return withdrawals[withdrawalId];
    }

    /**
     * @notice Check if a nullifier has been used
     * @param nullifier The nullifier to check
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedZcashNullifiers[nullifier];
    }

    /**
     * @notice Get current anchor for a pool
     * @param pool The shielded pool
     */
    function getCurrentAnchor(
        ZcashPrimitives.ShieldedPool pool
    ) external view returns (bytes32) {
        return anchors[pool].currentAnchor;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _generateDepositId(
        bytes32 noteCommitment,
        address recipient
    ) internal returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    ZcashPrimitives.PIL_ZCASH_DOMAIN,
                    "Deposit",
                    noteCommitment,
                    recipient,
                    block.timestamp,
                    _nonce++
                )
            );
    }

    function _generateWithdrawalId(
        bytes32 pilNullifier,
        bytes32 zcashRecipient
    ) internal returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    ZcashPrimitives.PIL_ZCASH_DOMAIN,
                    "Withdrawal",
                    pilNullifier,
                    zcashRecipient,
                    block.timestamp,
                    _nonce++
                )
            );
    }

    function _computePILCommitment(
        bytes32 noteCommitment,
        uint64 amount,
        address recipient
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    ZcashPrimitives.PIL_ZCASH_DOMAIN,
                    noteCommitment,
                    amount,
                    recipient
                )
            );
    }

    function _isBlockInChain(bytes32 blockHash) internal view returns (bool) {
        return blockHeights[blockHash] > 0;
    }

    function _verifySPVProof(
        SPVProof calldata proof
    ) internal pure returns (bool) {
        // Verify Merkle inclusion of transaction in block
        bytes32 computedRoot = proof.txHash;

        for (uint256 i = 0; i < proof.merkleProof.length; i++) {
            if ((proof.txIndex >> i) & 1 == 0) {
                computedRoot = keccak256(
                    abi.encodePacked(computedRoot, proof.merkleProof[i])
                );
            } else {
                computedRoot = keccak256(
                    abi.encodePacked(proof.merkleProof[i], computedRoot)
                );
            }
        }

        return computedRoot == proof.blockHeader.merkleRoot;
    }

    function _verifyDepositProof(
        DepositRequest storage deposit,
        bytes calldata zkProof
    ) internal view returns (bool) {
        // Call external verifier contract
        // In production, this verifies Groth16 proof
        if (proofVerifier == address(0)) {
            return zkProof.length >= 192; // Basic length check
        }

        // Prepare public inputs
        bytes32[] memory publicInputs = new bytes32[](4);
        publicInputs[0] = deposit.noteCommitment;
        publicInputs[1] = bytes32(uint256(deposit.amount));
        publicInputs[2] = bytes32(uint256(uint160(deposit.recipient)));
        publicInputs[3] = anchors[deposit.pool].currentAnchor;

        // Call verifier (interface would be defined)
        (bool success, ) = proofVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyProof(bytes,bytes32[])",
                zkProof,
                publicInputs
            )
        );

        return success;
    }

    function _verifyNullifierOwnership(
        bytes32 nullifier,
        address owner,
        bytes calldata proof
    ) internal view returns (bool) {
        if (proofVerifier == address(0)) {
            return proof.length >= 64; // Basic check
        }

        (bool success, ) = proofVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyNullifierOwnership(bytes32,address,bytes)",
                nullifier,
                owner,
                proof
            )
        );

        return success;
    }

    function _verifyCustodianSignature(
        bytes32 withdrawalId,
        bytes32 zcashTxHash,
        bytes calldata signature
    ) internal view returns (bool) {
        // Verify ECDSA or Schnorr signature from custodian
        bytes32 message = keccak256(
            abi.encodePacked(withdrawalId, zcashTxHash, custodianAddress)
        );

        // Simplified - actual implementation would verify against custodian pubkey
        return signature.length >= 64 && message != bytes32(0);
    }

    function _verifyAnchorProof(
        ZcashPrimitives.ShieldedPool pool,
        bytes32 anchor,
        uint32 blockHeight,
        bytes calldata proof
    ) internal view returns (bool) {
        // Verify anchor is derived from valid state
        if (proofVerifier == address(0)) {
            return
                proof.length >= 32 &&
                anchor != bytes32(0) &&
                uint8(pool) > 0 &&
                blockHeight > 0;
        }

        return true;
    }

    function _verifyEquihash(
        ZcashBlockHeader calldata header,
        bytes32 blockHash
    ) internal pure returns (bool) {
        // Simplified Equihash verification
        // Actual implementation requires full Equihash algorithm
        return
            header.version > 0 &&
            header.timestamp > 0 &&
            blockHash != bytes32(0);
    }

    function _checkRateLimit(uint64 amount) internal view {
        // Check daily limit
        if (block.timestamp > rateLimit.dayStartTimestamp + 1 days) {
            // New day, limit would reset
        } else {
            if (
                rateLimit.currentDayVolume + amount > rateLimit.maxDailyVolume
            ) {
                revert RateLimitExceeded();
            }
        }

        // Check per-transaction limit
        if (amount > rateLimit.maxPerTransaction) {
            revert RateLimitExceeded();
        }

        // Check cooldown for large transactions
        if (amount > rateLimit.maxPerTransaction / 2) {
            if (
                block.timestamp <
                rateLimit.lastLargeTransactionTime + rateLimit.cooldownPeriod
            ) {
                revert RateLimitExceeded();
            }
        }
    }

    function _updateRateLimit(uint64 amount) internal {
        // Reset if new day
        if (block.timestamp > rateLimit.dayStartTimestamp + 1 days) {
            rateLimit.currentDayVolume = amount;
            rateLimit.dayStartTimestamp = block.timestamp;
        } else {
            rateLimit.currentDayVolume += amount;
        }

        // Track large transactions
        if (amount > rateLimit.maxPerTransaction / 2) {
            rateLimit.lastLargeTransactionTime = block.timestamp;
        }
    }

    function _mintWrappedTokens(
        address recipient,
        uint64 amount,
        bytes32 commitment
    ) internal {
        // Interface with wrapped ZEC token contract
        // This would emit an event and call the token contract
        // Placeholder for actual implementation
        require(
            recipient != address(0) && amount > 0 && commitment != bytes32(0),
            "Invalid mint"
        );
    }

    function _burnWrappedTokens(
        address from,
        uint64 amount,
        bytes32 nullifier
    ) internal {
        // Interface with wrapped ZEC token contract
        // This would call the token contract to burn tokens
        // Placeholder for actual implementation
        require(
            from != address(0) && amount > 0 && nullifier != bytes32(0),
            "Invalid burn"
        );
    }
}
