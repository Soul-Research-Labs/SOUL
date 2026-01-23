// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ZcashPrimitives} from "./ZcashPrimitives.sol";

/**
 * @title ZcashNullifierRegistry
 * @author PIL Protocol
 * @notice Cross-chain nullifier registry for Zcash interoperability
 * @dev Synchronizes nullifiers between Zcash shielded pools and PIL protocol
 *
 * NULLIFIER SYNCHRONIZATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                  Zcash <-> PIL Nullifier Synchronization                    │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌─────────────────────────────────────────────────────────────────────────┐│
 * │  │                         ZCASH NETWORK                                   ││
 * │  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         ││
 * │  │  │  Sapling Pool   │  │  Orchard Pool   │  │  Sprout Pool    │         ││
 * │  │  │  (BLS12-381)    │  │  (Pallas/Vesta) │  │  (deprecated)   │         ││
 * │  │  │                 │  │                 │  │                 │         ││
 * │  │  │ ┌─────────────┐ │  │ ┌─────────────┐ │  │                 │         ││
 * │  │  │ │ Nullifiers  │ │  │ │ Nullifiers  │ │  │                 │         ││
 * │  │  │ │ (revealed   │ │  │ │ (revealed   │ │  │                 │         ││
 * │  │  │ │  on spend)  │ │  │ │  on spend)  │ │  │                 │         ││
 * │  │  │ └──────┬──────┘ │  │ └──────┬──────┘ │  │                 │         ││
 * │  │  └────────│────────┘  └────────│────────┘  └─────────────────┘         ││
 * │  │           │                    │                                        ││
 * │  │           └────────────┬───────┘                                        ││
 * │  │                        │                                                ││
 * │  │              ┌─────────▼─────────┐                                      ││
 * │  │              │  Relayer Network  │                                      ││
 * │  │              │  (SPV Proofs)     │                                      ││
 * │  │              └─────────┬─────────┘                                      ││
 * │  └────────────────────────│────────────────────────────────────────────────┘│
 * │                           │                                                  │
 * │  ═════════════════════════╪══════════════════════════════════════════════════│
 * │                           │ Cross-Chain Synchronization                      │
 * │  ═════════════════════════╪══════════════════════════════════════════════════│
 * │                           │                                                  │
 * │  ┌────────────────────────▼────────────────────────────────────────────────┐ │
 * │  │                      PIL PROTOCOL (EVM)                                 │ │
 * │  │                                                                         │ │
 * │  │  ┌─────────────────────────────────────────────────────────────────┐   │ │
 * │  │  │              ZcashNullifierRegistry                              │   │ │
 * │  │  │                                                                  │   │ │
 * │  │  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐     │   │ │
 * │  │  │  │ Sapling        │  │ Orchard        │  │ Cross-Chain    │     │   │ │
 * │  │  │  │ Nullifiers     │  │ Nullifiers     │  │ Bindings       │     │   │ │
 * │  │  │  │                │  │                │  │                │     │   │ │
 * │  │  │  │ nf → metadata  │  │ nf → metadata  │  │ zcash → pil    │     │   │ │
 * │  │  │  │                │  │                │  │ pil → zcash    │     │   │ │
 * │  │  │  └────────────────┘  └────────────────┘  └────────────────┘     │   │ │
 * │  │  │                                                                  │   │ │
 * │  │  │  ┌───────────────────────────────────────────────────────────┐  │   │ │
 * │  │  │  │                   Epoch Management                        │  │   │ │
 * │  │  │  │  - Nullifiers organized by epoch (Zcash block ranges)    │  │   │ │
 * │  │  │  │  - Merkle roots for efficient verification               │  │   │ │
 * │  │  │  │  - Finalization for immutable audit trail                │  │   │ │
 * │  │  │  └───────────────────────────────────────────────────────────┘  │   │ │
 * │  │  └─────────────────────────────────────────────────────────────────┘   │ │
 * │  └────────────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * KEY PROPERTIES:
 * - Nullifier uniqueness: Each nullifier can only be registered once
 * - Domain separation: Sapling and Orchard nullifiers are kept separate
 * - Cross-chain binding: Links Zcash nullifiers to PIL nullifier space
 * - Epoch finalization: Creates immutable snapshots for verification
 * - Double-spend prevention: Prevents spending bridged notes twice
 */
contract ZcashNullifierRegistry is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant EPOCH_ADMIN_ROLE = keccak256("EPOCH_ADMIN_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Domain separator for cross-chain bindings
    bytes32 public constant BINDING_DOMAIN =
        keccak256("PIL_Zcash_NullifierBinding_v1");

    /// @notice Epoch duration in Zcash blocks
    uint32 public constant EPOCH_BLOCK_DURATION = 1000;

    /// @notice Maximum nullifiers per batch registration
    uint256 public constant MAX_BATCH_SIZE = 100;

    /// @notice Historical epoch retention limit
    uint256 public constant MAX_HISTORICAL_EPOCHS = 100;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error NullifierAlreadyRegistered();
    error InvalidNullifier();
    error InvalidEpoch();
    error EpochNotFinalized();
    error EpochAlreadyFinalized();
    error BatchTooLarge();
    error InvalidProof();
    error InvalidPool();
    error NullifierNotFound();
    error BindingAlreadyExists();
    error UnauthorizedBinding();

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event NullifierRegistered(
        bytes32 indexed nullifier,
        ZcashPrimitives.ShieldedPool indexed pool,
        bytes32 indexed txHash,
        uint64 epochId,
        uint32 blockHeight
    );

    event NullifierBound(
        bytes32 indexed zcashNullifier,
        bytes32 indexed pilNullifier,
        uint64 timestamp
    );

    event EpochFinalized(
        uint64 indexed epochId,
        bytes32 indexed merkleRoot,
        uint256 nullifierCount,
        ZcashPrimitives.ShieldedPool pool
    );

    event BatchRegistered(
        uint256 indexed batchId,
        uint256 count,
        ZcashPrimitives.ShieldedPool pool
    );

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Nullifier metadata
    struct NullifierMetadata {
        bytes32 nullifier;
        ZcashPrimitives.ShieldedPool pool;
        bytes32 txHash; // Zcash tx that revealed it
        uint32 blockHeight; // Zcash block height
        uint64 epochId; // Epoch this belongs to
        uint64 registeredAt; // PIL registration timestamp
        bytes32 pilBinding; // Cross-chain binding (if any)
        bool isBridged; // Whether this nullifier was used for bridging
    }

    /// @notice Epoch data
    struct Epoch {
        uint64 epochId;
        ZcashPrimitives.ShieldedPool pool;
        uint32 startBlock;
        uint32 endBlock;
        bytes32 merkleRoot;
        uint256 nullifierCount;
        bytes32[] nullifiers; // Only for non-finalized epochs
        bool isFinalized;
        uint64 finalizedAt;
    }

    /// @notice Cross-chain nullifier binding
    struct NullifierBinding {
        bytes32 zcashNullifier;
        bytes32 pilNullifier;
        ZcashPrimitives.ShieldedPool pool;
        uint64 createdAt;
        address creator;
        bytes32 proofHash; // Hash of binding proof
    }

    /// @notice Batch registration receipt
    struct BatchReceipt {
        uint256 batchId;
        uint256 count;
        bytes32[] nullifiers;
        ZcashPrimitives.ShieldedPool pool;
        uint64 timestamp;
        bytes32 batchHash;
    }

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Registered nullifiers
    mapping(bytes32 => NullifierMetadata) public nullifiers;

    /// @notice Quick lookup for nullifier existence
    mapping(bytes32 => bool) public isNullifierRegistered;

    /// @notice Epochs per pool
    mapping(ZcashPrimitives.ShieldedPool => mapping(uint64 => Epoch))
        public epochs;

    /// @notice Current epoch per pool
    mapping(ZcashPrimitives.ShieldedPool => uint64) public currentEpoch;

    /// @notice Cross-chain bindings (Zcash → PIL)
    mapping(bytes32 => bytes32) public zcashToPilBinding;

    /// @notice Cross-chain bindings (PIL → Zcash)
    mapping(bytes32 => bytes32) public pilToZcashBinding;

    /// @notice Full binding metadata
    mapping(bytes32 => NullifierBinding) public bindings;

    /// @notice Batch registration counter
    uint256 public batchCounter;

    /// @notice Batch receipts
    mapping(uint256 => BatchReceipt) public batchReceipts;

    /// @notice Total nullifiers per pool
    mapping(ZcashPrimitives.ShieldedPool => uint256)
        public totalNullifiersPerPool;

    /// @notice Proof verifier contract
    address public proofVerifier;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _proofVerifier) {
        proofVerifier = _proofVerifier;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRAR_ROLE, msg.sender);
        _grantRole(RELAYER_ROLE, msg.sender);
        _grantRole(EPOCH_ADMIN_ROLE, msg.sender);

        // Initialize epochs for each pool
        _initializeEpoch(ZcashPrimitives.ShieldedPool.SAPLING, 0);
        _initializeEpoch(ZcashPrimitives.ShieldedPool.ORCHARD, 0);
    }

    /*//////////////////////////////////////////////////////////////
                     NULLIFIER REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a single Zcash nullifier
     * @param nullifier The nullifier value
     * @param pool The shielded pool
     * @param txHash Zcash transaction hash
     * @param blockHeight Zcash block height
     * @param proof SPV proof of transaction inclusion
     */
    function registerNullifier(
        bytes32 nullifier,
        ZcashPrimitives.ShieldedPool pool,
        bytes32 txHash,
        uint32 blockHeight,
        bytes calldata proof
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenNotPaused {
        _validatePool(pool);
        _validateNullifier(nullifier);

        if (isNullifierRegistered[nullifier]) {
            revert NullifierAlreadyRegistered();
        }

        // Verify SPV proof
        if (!_verifyNullifierProof(nullifier, txHash, blockHeight, proof)) {
            revert InvalidProof();
        }

        // Determine epoch
        uint64 epochId = _getEpochForBlock(pool, blockHeight);

        // Ensure epoch exists
        if (epochs[pool][epochId].epochId == 0) {
            _initializeEpoch(pool, epochId);
        }

        // Store nullifier
        nullifiers[nullifier] = NullifierMetadata({
            nullifier: nullifier,
            pool: pool,
            txHash: txHash,
            blockHeight: blockHeight,
            epochId: epochId,
            registeredAt: uint64(block.timestamp),
            pilBinding: bytes32(0),
            isBridged: false
        });

        isNullifierRegistered[nullifier] = true;
        totalNullifiersPerPool[pool]++;

        // Add to epoch (if not finalized)
        Epoch storage epoch = epochs[pool][epochId];
        if (!epoch.isFinalized) {
            epoch.nullifiers.push(nullifier);
            epoch.nullifierCount++;
        }

        emit NullifierRegistered(nullifier, pool, txHash, epochId, blockHeight);
    }

    /**
     * @notice Batch register multiple nullifiers
     * @param nullifierList Array of nullifiers
     * @param pool The shielded pool
     * @param txHashes Corresponding transaction hashes
     * @param blockHeights Corresponding block heights
     * @return batchId The batch registration ID
     */
    function batchRegisterNullifiers(
        bytes32[] calldata nullifierList,
        ZcashPrimitives.ShieldedPool pool,
        bytes32[] calldata txHashes,
        uint32[] calldata blockHeights
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (uint256 batchId)
    {
        if (nullifierList.length > MAX_BATCH_SIZE) {
            revert BatchTooLarge();
        }
        require(
            nullifierList.length == txHashes.length &&
                nullifierList.length == blockHeights.length,
            "Length mismatch"
        );

        _validatePool(pool);

        batchId = ++batchCounter;
        bytes32[] memory registered = new bytes32[](nullifierList.length);
        uint256 registeredCount = 0;

        for (uint256 i = 0; i < nullifierList.length; i++) {
            bytes32 nf = nullifierList[i];

            if (nf == bytes32(0) || isNullifierRegistered[nf]) {
                continue;
            }

            uint64 epochId = _getEpochForBlock(pool, blockHeights[i]);

            if (epochs[pool][epochId].epochId == 0) {
                _initializeEpoch(pool, epochId);
            }

            nullifiers[nf] = NullifierMetadata({
                nullifier: nf,
                pool: pool,
                txHash: txHashes[i],
                blockHeight: blockHeights[i],
                epochId: epochId,
                registeredAt: uint64(block.timestamp),
                pilBinding: bytes32(0),
                isBridged: false
            });

            isNullifierRegistered[nf] = true;
            totalNullifiersPerPool[pool]++;
            registered[registeredCount++] = nf;

            Epoch storage epoch = epochs[pool][epochId];
            if (!epoch.isFinalized) {
                epoch.nullifiers.push(nf);
                epoch.nullifierCount++;
            }

            emit NullifierRegistered(
                nf,
                pool,
                txHashes[i],
                epochId,
                blockHeights[i]
            );
        }

        // Resize registered array
        bytes32[] memory finalRegistered = new bytes32[](registeredCount);
        for (uint256 i = 0; i < registeredCount; i++) {
            finalRegistered[i] = registered[i];
        }

        // Store batch receipt
        batchReceipts[batchId] = BatchReceipt({
            batchId: batchId,
            count: registeredCount,
            nullifiers: finalRegistered,
            pool: pool,
            timestamp: uint64(block.timestamp),
            batchHash: keccak256(abi.encodePacked(finalRegistered))
        });

        emit BatchRegistered(batchId, registeredCount, pool);
    }

    /*//////////////////////////////////////////////////////////////
                       CROSS-CHAIN BINDING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a cross-chain nullifier binding
     * @param zcashNullifier The Zcash nullifier
     * @param pilNullifier The corresponding PIL nullifier
     * @param proof Proof of valid binding
     */
    function createBinding(
        bytes32 zcashNullifier,
        bytes32 pilNullifier,
        bytes calldata proof
    ) external onlyRole(REGISTRAR_ROLE) nonReentrant {
        if (!isNullifierRegistered[zcashNullifier]) {
            revert NullifierNotFound();
        }

        if (zcashToPilBinding[zcashNullifier] != bytes32(0)) {
            revert BindingAlreadyExists();
        }

        if (pilToZcashBinding[pilNullifier] != bytes32(0)) {
            revert BindingAlreadyExists();
        }

        // Verify binding proof
        if (!_verifyBindingProof(zcashNullifier, pilNullifier, proof)) {
            revert InvalidProof();
        }

        // Create binding
        zcashToPilBinding[zcashNullifier] = pilNullifier;
        pilToZcashBinding[pilNullifier] = zcashNullifier;

        bindings[zcashNullifier] = NullifierBinding({
            zcashNullifier: zcashNullifier,
            pilNullifier: pilNullifier,
            pool: nullifiers[zcashNullifier].pool,
            createdAt: uint64(block.timestamp),
            creator: msg.sender,
            proofHash: keccak256(proof)
        });

        // Update nullifier metadata
        nullifiers[zcashNullifier].pilBinding = pilNullifier;

        emit NullifierBound(
            zcashNullifier,
            pilNullifier,
            uint64(block.timestamp)
        );
    }

    /**
     * @notice Compute cross-chain nullifier binding (no storage)
     * @param zcashNullifier The Zcash nullifier
     * @param chainId Target chain ID
     * @return binding The computed binding
     */
    function computeBinding(
        bytes32 zcashNullifier,
        uint64 chainId
    ) external pure returns (bytes32 binding) {
        return
            ZcashPrimitives.computeCrossChainNullifierBinding(
                zcashNullifier,
                BINDING_DOMAIN,
                chainId
            );
    }

    /*//////////////////////////////////////////////////////////////
                        EPOCH MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Finalize an epoch with Merkle root
     * @param pool The shielded pool
     * @param epochId The epoch to finalize
     */
    function finalizeEpoch(
        ZcashPrimitives.ShieldedPool pool,
        uint64 epochId
    ) external onlyRole(EPOCH_ADMIN_ROLE) {
        Epoch storage epoch = epochs[pool][epochId];

        if (epoch.epochId == 0) {
            revert InvalidEpoch();
        }

        if (epoch.isFinalized) {
            revert EpochAlreadyFinalized();
        }

        // Compute Merkle root of nullifiers
        bytes32 merkleRoot = _computeEpochMerkleRoot(epoch.nullifiers);

        epoch.merkleRoot = merkleRoot;
        epoch.isFinalized = true;
        epoch.finalizedAt = uint64(block.timestamp);

        // Clear nullifier array to save gas (root is stored)
        delete epoch.nullifiers;

        // Advance current epoch if needed
        if (currentEpoch[pool] == epochId) {
            currentEpoch[pool] = epochId + 1;
            _initializeEpoch(pool, epochId + 1);
        }

        emit EpochFinalized(epochId, merkleRoot, epoch.nullifierCount, pool);
    }

    /**
     * @notice Verify nullifier is in a finalized epoch
     * @param nullifier The nullifier to verify
     * @param epochId The claimed epoch
     * @param merkleProof Merkle proof
     * @return valid Whether the proof is valid
     */
    function verifyNullifierInEpoch(
        bytes32 nullifier,
        ZcashPrimitives.ShieldedPool pool,
        uint64 epochId,
        bytes32[] calldata merkleProof
    ) external view returns (bool valid) {
        Epoch storage epoch = epochs[pool][epochId];

        if (!epoch.isFinalized) {
            revert EpochNotFinalized();
        }

        // Verify Merkle inclusion
        return _verifyMerkleProof(nullifier, merkleProof, epoch.merkleRoot);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get nullifier metadata
     * @param nullifier The nullifier
     */
    function getNullifier(
        bytes32 nullifier
    ) external view returns (NullifierMetadata memory) {
        return nullifiers[nullifier];
    }

    /**
     * @notice Check if nullifier exists
     * @param nullifier The nullifier
     */
    function exists(bytes32 nullifier) external view returns (bool) {
        return isNullifierRegistered[nullifier];
    }

    /**
     * @notice Get epoch data
     * @param pool The shielded pool
     * @param epochId The epoch ID
     */
    function getEpoch(
        ZcashPrimitives.ShieldedPool pool,
        uint64 epochId
    )
        external
        view
        returns (
            uint32 startBlock,
            uint32 endBlock,
            bytes32 merkleRoot,
            uint256 nullifierCount,
            bool isFinalized
        )
    {
        Epoch storage epoch = epochs[pool][epochId];
        return (
            epoch.startBlock,
            epoch.endBlock,
            epoch.merkleRoot,
            epoch.nullifierCount,
            epoch.isFinalized
        );
    }

    /**
     * @notice Get binding for a Zcash nullifier
     * @param zcashNullifier The Zcash nullifier
     */
    function getBinding(
        bytes32 zcashNullifier
    ) external view returns (NullifierBinding memory) {
        return bindings[zcashNullifier];
    }

    /**
     * @notice Get PIL nullifier for Zcash nullifier
     * @param zcashNullifier The Zcash nullifier
     */
    function getPilNullifier(
        bytes32 zcashNullifier
    ) external view returns (bytes32) {
        return zcashToPilBinding[zcashNullifier];
    }

    /**
     * @notice Get Zcash nullifier for PIL nullifier
     * @param pilNullifier The PIL nullifier
     */
    function getZcashNullifier(
        bytes32 pilNullifier
    ) external view returns (bytes32) {
        return pilToZcashBinding[pilNullifier];
    }

    /**
     * @notice Get batch receipt
     * @param batchId The batch ID
     */
    function getBatchReceipt(
        uint256 batchId
    ) external view returns (BatchReceipt memory) {
        return batchReceipts[batchId];
    }

    /**
     * @notice Get current epoch for a pool
     * @param pool The shielded pool
     */
    function getCurrentEpochId(
        ZcashPrimitives.ShieldedPool pool
    ) external view returns (uint64) {
        return currentEpoch[pool];
    }

    /**
     * @notice Get total nullifiers for a pool
     * @param pool The shielded pool
     */
    function getTotalNullifiers(
        ZcashPrimitives.ShieldedPool pool
    ) external view returns (uint256) {
        return totalNullifiersPerPool[pool];
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _validatePool(ZcashPrimitives.ShieldedPool pool) internal pure {
        if (pool == ZcashPrimitives.ShieldedPool.SPROUT) {
            revert InvalidPool();
        }
    }

    function _validateNullifier(bytes32 nullifier) internal pure {
        if (nullifier == bytes32(0)) {
            revert InvalidNullifier();
        }
    }

    function _getEpochForBlock(
        ZcashPrimitives.ShieldedPool,
        uint32 blockHeight
    ) internal pure returns (uint64) {
        return uint64(blockHeight / EPOCH_BLOCK_DURATION);
    }

    function _initializeEpoch(
        ZcashPrimitives.ShieldedPool pool,
        uint64 epochId
    ) internal {
        uint32 startBlock = uint32(epochId * EPOCH_BLOCK_DURATION);
        uint32 endBlock = startBlock + EPOCH_BLOCK_DURATION - 1;

        epochs[pool][epochId] = Epoch({
            epochId: epochId,
            pool: pool,
            startBlock: startBlock,
            endBlock: endBlock,
            merkleRoot: bytes32(0),
            nullifierCount: 0,
            nullifiers: new bytes32[](0),
            isFinalized: false,
            finalizedAt: 0
        });

        if (currentEpoch[pool] < epochId + 1) {
            currentEpoch[pool] = epochId;
        }
    }

    function _verifyNullifierProof(
        bytes32 nullifier,
        bytes32 txHash,
        uint32 blockHeight,
        bytes calldata proof
    ) internal view returns (bool) {
        if (proofVerifier == address(0)) {
            // Basic validation without external verifier
            return
                nullifier != bytes32(0) &&
                txHash != bytes32(0) &&
                blockHeight > 0 &&
                proof.length >= 32;
        }

        // Call external verifier
        (bool success, ) = proofVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyNullifierInclusion(bytes32,bytes32,uint32,bytes)",
                nullifier,
                txHash,
                blockHeight,
                proof
            )
        );
        return success;
    }

    function _verifyBindingProof(
        bytes32 zcashNullifier,
        bytes32 pilNullifier,
        bytes calldata proof
    ) internal view returns (bool) {
        if (proofVerifier == address(0)) {
            // Basic validation
            return
                zcashNullifier != bytes32(0) &&
                pilNullifier != bytes32(0) &&
                proof.length >= 64;
        }

        // Call external verifier
        (bool success, ) = proofVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyNullifierBinding(bytes32,bytes32,bytes)",
                zcashNullifier,
                pilNullifier,
                proof
            )
        );
        return success;
    }

    function _computeEpochMerkleRoot(
        bytes32[] memory items
    ) internal pure returns (bytes32) {
        if (items.length == 0) {
            return bytes32(0);
        }
        if (items.length == 1) {
            return items[0];
        }

        // Simple binary Merkle tree
        uint256 n = items.length;
        bytes32[] memory layer = items;

        while (n > 1) {
            uint256 nextN = (n + 1) / 2;
            bytes32[] memory nextLayer = new bytes32[](nextN);

            for (uint256 i = 0; i < n / 2; i++) {
                nextLayer[i] = keccak256(
                    abi.encodePacked(layer[2 * i], layer[2 * i + 1])
                );
            }
            if (n % 2 == 1) {
                nextLayer[nextN - 1] = layer[n - 1];
            }

            layer = nextLayer;
            n = nextN;
        }

        return layer[0];
    }

    function _verifyMerkleProof(
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes32 root
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proofElement)
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proofElement, computedHash)
                );
            }
        }

        return computedHash == root;
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

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
     * @notice Pause the registry
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the registry
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
