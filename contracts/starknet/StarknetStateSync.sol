// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./StarknetPrimitives.sol";

/**
 * @title StarknetStateSync
 * @author PIL Protocol
 * @notice State synchronization between Ethereum L1 and Starknet L2
 * @dev Enables verification of Starknet state on L1 for cross-chain operations
 *
 * STATE SYNCHRONIZATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                   Starknet State Sync Pipeline                           │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  ┌──────────────────────────────────────────────────────────────────┐   │
 * │  │                    STARKNET L2                                    │   │
 * │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │   │
 * │  │  │   Block     │─►│   State     │─►│   STARK     │              │   │
 * │  │  │   Producer  │  │   Root      │  │   Proof     │              │   │
 * │  │  └─────────────┘  └─────────────┘  └─────────────┘              │   │
 * │  └──────────────────────────────────────────────────────────────────┘   │
 * │                              │                                          │
 * │                              ▼                                          │
 * │  ┌──────────────────────────────────────────────────────────────────┐   │
 * │  │                    STARKNET CORE (L1)                            │   │
 * │  │  • State commitment via STARK proof                              │   │
 * │  │  • Block hash verification                                        │   │
 * │  │  • State diff publication                                         │   │
 * │  └──────────────────────────────────────────────────────────────────┘   │
 * │                              │                                          │
 * │                              ▼                                          │
 * │  ┌──────────────────────────────────────────────────────────────────┐   │
 * │  │                    PIL STATE SYNC                                 │   │
 * │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │   │
 * │  │  │   State     │─►│   Storage   │─►│   Contract  │              │   │
 * │  │  │   Root      │  │   Proof     │  │   State     │              │   │
 * │  │  │   Cache     │  │   Verify    │  │   Query     │              │   │
 * │  │  └─────────────┘  └─────────────┘  └─────────────┘              │   │
 * │  └──────────────────────────────────────────────────────────────────┘   │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * STARKNET STATE STRUCTURE:
 * - Global state root = commitment(contract_states, class_hashes, compiled_classes)
 * - Contract state = commitment(class_hash, storage_root, nonce)
 * - Storage = Patricia-Merkle trie with Pedersen nodes
 *
 * STORAGE PROOF VERIFICATION:
 * 1. Verify block is finalized on L1 (via Starknet Core)
 * 2. Verify state root matches block commitment
 * 3. Verify contract state in global trie
 * 4. Verify storage value in contract trie
 */
contract StarknetStateSync is AccessControl, ReentrancyGuard, Pausable {
    using StarknetPrimitives for uint256;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant SEQUENCER_ROLE = keccak256("SEQUENCER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Block status
    enum BlockStatus {
        UNKNOWN,
        PENDING,
        ACCEPTED_ON_L2,
        ACCEPTED_ON_L1,
        REJECTED
    }

    /// @notice Starknet block header
    struct BlockHeader {
        uint256 blockNumber;
        bytes32 blockHash;
        bytes32 parentBlockHash;
        bytes32 stateRoot;
        bytes32 transactionsRoot;
        bytes32 receiptsRoot;
        bytes32 sequencerAddress; // As felt
        uint256 timestamp;
        uint256 gasPrice;
        BlockStatus status;
        uint256 provenAt; // When proven on L1
    }

    /// @notice Contract state commitment
    struct ContractState {
        uint256 contractAddress; // Starknet address as felt
        bytes32 classHash;
        bytes32 storageRoot;
        uint256 nonce;
        bool verified;
        uint256 verifiedAt;
    }

    /// @notice Storage proof
    struct StorageProof {
        uint256 contractAddress;
        uint256 storageKey;
        uint256 storageValue;
        bytes32[] proof; // Patricia-Merkle proof nodes
        uint256 proofHeight; // Trie height
        bool verified;
    }

    /// @notice State update batch
    struct StateUpdate {
        bytes32 updateId;
        uint256 blockNumber;
        bytes32 blockHash;
        bytes32 newStateRoot;
        bytes32 oldStateRoot;
        uint256[] contractsUpdated;
        bytes32[] storageUpdates; // Hashed storage diffs
        uint256 timestamp;
        bool verified;
    }

    /// @notice Sync checkpoint
    struct SyncCheckpoint {
        uint256 l1BlockNumber;
        uint256 l2BlockNumber;
        bytes32 stateRoot;
        bytes32 checkpointHash;
        uint256 timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Starknet Core contract address
    address public starknetCore;

    /// @notice Cached block headers by block number
    mapping(uint256 => BlockHeader) public blockHeaders;
    uint256 public latestBlockNumber;

    /// @notice Cached block headers by hash
    mapping(bytes32 => uint256) public blockHashToNumber;

    /// @notice Contract states
    mapping(uint256 => ContractState) public contractStates;

    /// @notice Verified storage values
    mapping(bytes32 => uint256) public verifiedStorage; // key = keccak(contract, slot)

    /// @notice State updates
    mapping(bytes32 => StateUpdate) public stateUpdates;
    uint256 public totalStateUpdates;

    /// @notice Sync checkpoints
    mapping(uint256 => SyncCheckpoint) public checkpoints;
    uint256 public latestCheckpointIndex;

    /// @notice Finality delay (blocks before state is considered final)
    uint256 public finalityDelay = 64;

    /// @notice Maximum proof verification gas
    uint256 public maxProofVerificationGas = 500000;

    /// @notice State root cache TTL
    uint256 public stateRootTTL = 1 hours;

    /// @notice Last verified state root
    bytes32 public lastVerifiedStateRoot;
    uint256 public lastVerifiedBlockNumber;
    uint256 public lastVerifiedTimestamp;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event BlockHeaderCached(
        uint256 indexed blockNumber,
        bytes32 indexed blockHash,
        bytes32 stateRoot
    );

    event StateUpdateSubmitted(
        bytes32 indexed updateId,
        uint256 indexed blockNumber,
        bytes32 newStateRoot
    );

    event StateUpdateVerified(
        bytes32 indexed updateId,
        uint256 indexed blockNumber,
        bool valid
    );

    event StorageProofVerified(
        uint256 indexed contractAddress,
        uint256 indexed storageKey,
        uint256 storageValue,
        bool valid
    );

    event ContractStateVerified(
        uint256 indexed contractAddress,
        bytes32 classHash,
        bytes32 storageRoot
    );

    event CheckpointCreated(
        uint256 indexed checkpointIndex,
        uint256 l2BlockNumber,
        bytes32 stateRoot
    );

    event StarknetCoreUpdated(address indexed newCore);

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidStarknetCore();
    error BlockNotFound(uint256 blockNumber);
    error BlockNotFinalized(uint256 blockNumber);
    error InvalidStateRoot();
    error InvalidStorageProof();
    error InvalidContractProof();
    error StateRootExpired();
    error ProofTooLarge();
    error UpdateNotFound(bytes32 updateId);
    error UpdateAlreadyVerified();
    error ZeroAddress();
    error InvalidBlockHash();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set Starknet Core contract address
     */
    function setStarknetCore(
        address _starknetCore
    ) external onlyRole(OPERATOR_ROLE) {
        if (_starknetCore == address(0)) revert ZeroAddress();
        starknetCore = _starknetCore;
        emit StarknetCoreUpdated(_starknetCore);
    }

    /**
     * @notice Set finality delay
     */
    function setFinalityDelay(uint256 _delay) external onlyRole(OPERATOR_ROLE) {
        require(_delay >= 1 && _delay <= 1000, "Invalid delay");
        finalityDelay = _delay;
    }

    /**
     * @notice Set state root TTL
     */
    function setStateRootTTL(uint256 _ttl) external onlyRole(OPERATOR_ROLE) {
        require(_ttl >= 10 minutes && _ttl <= 24 hours, "Invalid TTL");
        stateRootTTL = _ttl;
    }

    /*//////////////////////////////////////////////////////////////
                       BLOCK HEADER SYNC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Cache a Starknet block header
     */
    function cacheBlockHeader(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentBlockHash,
        bytes32 stateRoot,
        bytes32 transactionsRoot,
        bytes32 receiptsRoot,
        bytes32 sequencerAddress,
        uint256 timestamp,
        uint256 gasPrice
    ) external onlyRole(SEQUENCER_ROLE) {
        blockHeaders[blockNumber] = BlockHeader({
            blockNumber: blockNumber,
            blockHash: blockHash,
            parentBlockHash: parentBlockHash,
            stateRoot: stateRoot,
            transactionsRoot: transactionsRoot,
            receiptsRoot: receiptsRoot,
            sequencerAddress: sequencerAddress,
            timestamp: timestamp,
            gasPrice: gasPrice,
            status: BlockStatus.ACCEPTED_ON_L2,
            provenAt: 0
        });

        blockHashToNumber[blockHash] = blockNumber;

        if (blockNumber > latestBlockNumber) {
            latestBlockNumber = blockNumber;
        }

        emit BlockHeaderCached(blockNumber, blockHash, stateRoot);
    }

    /**
     * @notice Mark block as proven on L1
     */
    function markBlockProven(
        uint256 blockNumber,
        bytes calldata starkProof
    ) external onlyRole(VERIFIER_ROLE) {
        BlockHeader storage header = blockHeaders[blockNumber];
        if (header.blockNumber == 0) revert BlockNotFound(blockNumber);

        // Verify STARK proof against Starknet Core (simplified)
        if (!_verifyBlockProof(header, starkProof)) {
            header.status = BlockStatus.REJECTED;
            return;
        }

        header.status = BlockStatus.ACCEPTED_ON_L1;
        header.provenAt = block.timestamp;

        // Update last verified state root
        lastVerifiedStateRoot = header.stateRoot;
        lastVerifiedBlockNumber = blockNumber;
        lastVerifiedTimestamp = block.timestamp;
    }

    /**
     * @notice Get block header
     */
    function getBlockHeader(
        uint256 blockNumber
    ) external view returns (BlockHeader memory) {
        return blockHeaders[blockNumber];
    }

    /**
     * @notice Check if block is finalized
     */
    function isBlockFinalized(uint256 blockNumber) public view returns (bool) {
        BlockHeader storage header = blockHeaders[blockNumber];
        if (header.blockNumber == 0) return false;
        if (header.status != BlockStatus.ACCEPTED_ON_L1) return false;
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                       STATE UPDATE SYNC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a state update from Starknet
     */
    function submitStateUpdate(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 newStateRoot,
        bytes32 oldStateRoot,
        uint256[] calldata contractsUpdated,
        bytes32[] calldata storageUpdates
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 updateId)
    {
        // Verify block exists
        BlockHeader storage header = blockHeaders[blockNumber];
        if (header.blockNumber == 0) revert BlockNotFound(blockNumber);
        if (header.blockHash != blockHash) revert InvalidBlockHash();

        updateId = keccak256(
            abi.encodePacked(
                blockNumber,
                blockHash,
                newStateRoot,
                msg.sender,
                block.timestamp
            )
        );

        stateUpdates[updateId] = StateUpdate({
            updateId: updateId,
            blockNumber: blockNumber,
            blockHash: blockHash,
            newStateRoot: newStateRoot,
            oldStateRoot: oldStateRoot,
            contractsUpdated: contractsUpdated,
            storageUpdates: storageUpdates,
            timestamp: block.timestamp,
            verified: false
        });

        totalStateUpdates++;

        emit StateUpdateSubmitted(updateId, blockNumber, newStateRoot);
    }

    /**
     * @notice Verify a state update with STARK proof
     */
    function verifyStateUpdate(
        bytes32 updateId,
        bytes calldata stateTransitionProof
    ) external nonReentrant onlyRole(VERIFIER_ROLE) {
        StateUpdate storage update = stateUpdates[updateId];
        if (update.updateId == bytes32(0)) revert UpdateNotFound(updateId);
        if (update.verified) revert UpdateAlreadyVerified();

        // Verify the state transition proof
        bool valid = _verifyStateTransition(
            update.oldStateRoot,
            update.newStateRoot,
            update.contractsUpdated,
            stateTransitionProof
        );

        update.verified = valid;

        if (valid) {
            // Update cached state roots
            BlockHeader storage header = blockHeaders[update.blockNumber];
            if (header.stateRoot == bytes32(0)) {
                header.stateRoot = update.newStateRoot;
            }
        }

        emit StateUpdateVerified(updateId, update.blockNumber, valid);
    }

    /*//////////////////////////////////////////////////////////////
                       STORAGE PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a storage proof and cache the value
     * @param contractAddress Starknet contract address (as felt)
     * @param storageKey Storage key (as felt)
     * @param storageValue Expected storage value (as felt)
     * @param stateRoot State root to verify against
     * @param contractProof Proof for contract in global trie
     * @param storageProof Proof for storage in contract trie
     */
    function verifyAndCacheStorageValue(
        uint256 contractAddress,
        uint256 storageKey,
        uint256 storageValue,
        bytes32 stateRoot,
        bytes32[] calldata contractProof,
        bytes32[] calldata storageProof
    ) external nonReentrant whenNotPaused returns (bool valid) {
        // Verify state root is current or recent
        if (!_isValidStateRoot(stateRoot)) revert InvalidStateRoot();

        // Verify contract state in global trie
        ContractState memory cs = _verifyContractInGlobalTrie(
            contractAddress,
            stateRoot,
            contractProof
        );

        if (!cs.verified) revert InvalidContractProof();

        // Verify storage value in contract's storage trie
        valid = _verifyStorageValue(
            storageKey,
            storageValue,
            cs.storageRoot,
            storageProof
        );

        if (valid) {
            // Cache the verified storage value
            bytes32 cacheKey = keccak256(
                abi.encodePacked(contractAddress, storageKey)
            );
            verifiedStorage[cacheKey] = storageValue;

            // Update contract state cache
            contractStates[contractAddress] = cs;

            emit StorageProofVerified(
                contractAddress,
                storageKey,
                storageValue,
                true
            );
        } else {
            emit StorageProofVerified(
                contractAddress,
                storageKey,
                storageValue,
                false
            );
            revert InvalidStorageProof();
        }
    }

    /**
     * @notice Get cached storage value
     */
    function getCachedStorageValue(
        uint256 contractAddress,
        uint256 storageKey
    ) external view returns (uint256 value, bool exists) {
        bytes32 cacheKey = keccak256(
            abi.encodePacked(contractAddress, storageKey)
        );
        value = verifiedStorage[cacheKey];
        exists = value != 0; // Note: zero values are indistinguishable from not-found
    }

    /**
     * @notice Verify contract state without caching
     */
    function verifyContractState(
        uint256 contractAddress,
        bytes32 stateRoot,
        bytes32[] calldata contractProof
    ) external view returns (ContractState memory) {
        if (!_isValidStateRoot(stateRoot)) revert InvalidStateRoot();
        return
            _verifyContractInGlobalTrie(
                contractAddress,
                stateRoot,
                contractProof
            );
    }

    /*//////////////////////////////////////////////////////////////
                       CHECKPOINT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a sync checkpoint
     */
    function createCheckpoint(
        uint256 l2BlockNumber
    ) external onlyRole(OPERATOR_ROLE) returns (uint256 checkpointIndex) {
        if (!isBlockFinalized(l2BlockNumber))
            revert BlockNotFinalized(l2BlockNumber);

        BlockHeader storage header = blockHeaders[l2BlockNumber];

        checkpointIndex = ++latestCheckpointIndex;

        bytes32 checkpointHash = keccak256(
            abi.encodePacked(
                block.number,
                l2BlockNumber,
                header.stateRoot,
                block.timestamp
            )
        );

        checkpoints[checkpointIndex] = SyncCheckpoint({
            l1BlockNumber: block.number,
            l2BlockNumber: l2BlockNumber,
            stateRoot: header.stateRoot,
            checkpointHash: checkpointHash,
            timestamp: block.timestamp
        });

        emit CheckpointCreated(
            checkpointIndex,
            l2BlockNumber,
            header.stateRoot
        );
    }

    /**
     * @notice Get checkpoint
     */
    function getCheckpoint(
        uint256 index
    ) external view returns (SyncCheckpoint memory) {
        return checkpoints[index];
    }

    /**
     * @notice Verify checkpoint validity
     */
    function isCheckpointValid(uint256 index) external view returns (bool) {
        SyncCheckpoint storage cp = checkpoints[index];
        if (cp.l2BlockNumber == 0) return false;

        // Check if the block is still finalized
        BlockHeader storage header = blockHeaders[cp.l2BlockNumber];
        if (header.status != BlockStatus.ACCEPTED_ON_L1) return false;

        // Verify state root matches
        return header.stateRoot == cp.stateRoot;
    }

    /*//////////////////////////////////////////////////////////////
                       INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if state root is valid (current or recent)
     */
    function _isValidStateRoot(bytes32 stateRoot) internal view returns (bool) {
        // Check if it's the last verified root
        if (stateRoot == lastVerifiedStateRoot) {
            return block.timestamp <= lastVerifiedTimestamp + stateRootTTL;
        }

        // Check recent blocks for matching state root
        for (uint256 i = 0; i < finalityDelay && latestBlockNumber >= i; i++) {
            BlockHeader storage header = blockHeaders[latestBlockNumber - i];
            if (
                header.stateRoot == stateRoot &&
                header.status == BlockStatus.ACCEPTED_ON_L1
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * @notice Verify block proof (simplified)
     */
    function _verifyBlockProof(
        BlockHeader storage header,
        bytes calldata proof
    ) internal view returns (bool) {
        if (proof.length < 32) return false;

        // Production: Verify against Starknet Core contract
        // IStarknetCore(starknetCore).verifyStateTransition(...)

        // Verify block hash computation
        bytes32 computedHash = keccak256(
            abi.encodePacked(
                header.blockNumber,
                header.parentBlockHash,
                header.stateRoot,
                header.transactionsRoot,
                header.sequencerAddress,
                header.timestamp
            )
        );

        // Simplified verification
        return computedHash != bytes32(0);
    }

    /**
     * @notice Verify state transition (simplified)
     */
    function _verifyStateTransition(
        bytes32 oldStateRoot,
        bytes32 newStateRoot,
        uint256[] memory contractsUpdated,
        bytes calldata proof
    ) internal pure returns (bool) {
        if (proof.length < 32) return false;
        if (oldStateRoot == bytes32(0) || newStateRoot == bytes32(0))
            return false;
        if (contractsUpdated.length == 0) return false;

        // Production: Full STARK proof verification of state transition
        return true;
    }

    /**
     * @notice Verify contract in global state trie
     */
    function _verifyContractInGlobalTrie(
        uint256 contractAddress,
        bytes32 stateRoot,
        bytes32[] calldata proof
    ) internal view returns (ContractState memory cs) {
        if (proof.length == 0) {
            cs.verified = false;
            return cs;
        }

        // Extract contract state from proof
        // Starknet contract state = H(H(class_hash, storage_root), nonce)

        // Verify Merkle proof path
        bytes32 current = proof[0]; // Leaf value

        for (uint256 i = 1; i < proof.length; i++) {
            uint256 pathBit = (contractAddress >> (proof.length - 1 - i)) & 1;

            if (pathBit == 0) {
                current = bytes32(
                    StarknetPrimitives.pedersenHash(
                        uint256(current),
                        uint256(proof[i])
                    )
                );
            } else {
                current = bytes32(
                    StarknetPrimitives.pedersenHash(
                        uint256(proof[i]),
                        uint256(current)
                    )
                );
            }
        }

        cs.verified = current == stateRoot;
        cs.contractAddress = contractAddress;
        cs.verifiedAt = block.timestamp;

        // Decode contract state from leaf (simplified)
        if (cs.verified && proof.length > 0) {
            // Extract class_hash, storage_root, nonce from proof[0]
            cs.classHash = bytes32(uint256(proof[0]) >> 128);
            cs.storageRoot = bytes32(uint256(proof[0]) & type(uint128).max);
            cs.nonce = 0; // Would be extracted from proof
        }

        return cs;
    }

    /**
     * @notice Verify storage value in contract's storage trie
     */
    function _verifyStorageValue(
        uint256 storageKey,
        uint256 storageValue,
        bytes32 storageRoot,
        bytes32[] calldata proof
    ) internal pure returns (bool) {
        if (proof.length == 0) return false;

        // Compute expected leaf
        bytes32 expectedLeaf = bytes32(
            StarknetPrimitives.pedersenHash(storageKey, storageValue)
        );

        // Verify leaf is in proof
        if (proof[0] != expectedLeaf) return false;

        // Verify Merkle path to storage root
        bytes32 current = proof[0];

        for (uint256 i = 1; i < proof.length; i++) {
            uint256 pathBit = (storageKey >> (proof.length - 1 - i)) & 1;

            if (pathBit == 0) {
                current = bytes32(
                    StarknetPrimitives.pedersenHash(
                        uint256(current),
                        uint256(proof[i])
                    )
                );
            } else {
                current = bytes32(
                    StarknetPrimitives.pedersenHash(
                        uint256(proof[i]),
                        uint256(current)
                    )
                );
            }
        }

        return current == storageRoot;
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get latest verified state root
     */
    function getLatestVerifiedState()
        external
        view
        returns (bytes32 stateRoot, uint256 blockNumber, uint256 timestamp)
    {
        return (
            lastVerifiedStateRoot,
            lastVerifiedBlockNumber,
            lastVerifiedTimestamp
        );
    }

    /**
     * @notice Get contract state
     */
    function getContractState(
        uint256 contractAddress
    ) external view returns (ContractState memory) {
        return contractStates[contractAddress];
    }

    /**
     * @notice Get state update
     */
    function getStateUpdate(
        bytes32 updateId
    ) external view returns (StateUpdate memory) {
        return stateUpdates[updateId];
    }

    /**
     * @notice Get sync statistics
     */
    function getStats()
        external
        view
        returns (
            uint256 _latestBlockNumber,
            uint256 _totalStateUpdates,
            uint256 _latestCheckpoint,
            bytes32 _lastVerifiedRoot
        )
    {
        return (
            latestBlockNumber,
            totalStateUpdates,
            latestCheckpointIndex,
            lastVerifiedStateRoot
        );
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Emergency clear cached state
     */
    function clearCachedState(
        uint256 contractAddress
    ) external onlyRole(OPERATOR_ROLE) {
        delete contractStates[contractAddress];
    }

    /**
     * @notice Pause syncing
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause syncing
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }
}
