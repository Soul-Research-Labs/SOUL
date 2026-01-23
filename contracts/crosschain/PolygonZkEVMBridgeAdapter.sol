// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title PolygonZkEVMBridgeAdapter
 * @notice PIL bridge adapter for Polygon zkEVM (Type 2 zkEVM)
 * @dev Integrates with Polygon zkEVM Bridge and LxLy Bridge
 * @author PIL Protocol Team
 * @custom:security-contact security@pil.network
 */
contract PolygonZkEVMBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    // ============ Constants ============

    bytes32 public constant BRIDGE_OPERATOR_ROLE =
        keccak256("BRIDGE_OPERATOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant CLAIMER_ROLE = keccak256("CLAIMER_ROLE");

    /// @notice Polygon zkEVM chain IDs
    uint256 public constant POLYGON_ZKEVM_MAINNET = 1101;
    uint256 public constant POLYGON_ZKEVM_TESTNET = 1442;

    /// @notice Network IDs for LxLy Bridge
    uint32 public constant NETWORK_ID_MAINNET = 0;
    uint32 public constant NETWORK_ID_ZKEVM = 1;

    /// @notice Destination network for proofs
    uint32 public constant DESTINATION_NETWORK = 1; // zkEVM

    /// @notice Leaf type constants
    uint8 public constant LEAF_TYPE_ASSET = 0;
    uint8 public constant LEAF_TYPE_MESSAGE = 1;

    // ============ Immutable State ============

    /// @notice Polygon zkEVM Bridge contract
    address public immutable polygonZkEVMBridge;

    /// @notice Global Exit Root Manager
    address public immutable globalExitRootManager;

    /// @notice Polygon zkEVM contract (for state verification)
    address public immutable polygonZkEVM;

    // ============ State Variables ============

    /// @notice PIL Hub on Polygon zkEVM
    address public pilHubL2;

    /// @notice L1 Proof Registry
    address public proofRegistry;

    /// @notice Network ID for this chain
    uint32 public networkId;

    /// @notice Bridge configuration
    BridgeConfig public config;

    /// @notice Message nonce
    uint256 public messageNonce;

    /// @notice Deposit count for exit tree
    uint32 public depositCount;

    /// @notice Outgoing bridge deposits
    mapping(uint256 => BridgeDeposit) public deposits;

    /// @notice Claimed messages by global index
    mapping(uint256 => bool) public claimedGlobalIndex;

    /// @notice Proof bridging status
    mapping(bytes32 => ProofBridgeStatus) public proofBridgeStatus;

    // ============ Structs ============

    struct BridgeConfig {
        uint256 minAmount;
        uint256 maxAmount;
        uint256 dailyLimit;
        uint256 dailyUsed;
        uint256 lastResetDay;
        bool forceUpdateGlobalExitRoot;
    }

    struct BridgeDeposit {
        uint8 leafType;
        uint32 originNetwork;
        address originAddress;
        uint32 destinationNetwork;
        address destinationAddress;
        uint256 amount;
        bytes32 proofHash;
        bytes metadata;
        uint256 timestamp;
        bool claimed;
    }

    struct ProofBridgeStatus {
        bool initiated;
        bool claimed;
        uint32 originNetwork;
        uint32 destNetwork;
        uint256 depositCount;
        uint256 globalIndex;
        address sender;
        uint256 timestamp;
    }

    struct ClaimParams {
        bytes32[32] smtProofLocalExitRoot;
        bytes32[32] smtProofRollupExitRoot;
        uint256 globalIndex;
        bytes32 mainnetExitRoot;
        bytes32 rollupExitRoot;
        uint32 originNetwork;
        address originAddress;
        uint32 destinationNetwork;
        address destinationAddress;
        uint256 amount;
        bytes metadata;
    }

    // ============ Events ============

    event ProofBridgedToZkEVM(
        uint256 indexed depositCount,
        bytes32 indexed proofHash,
        address indexed sender,
        address destinationAddress,
        uint256 amount
    );

    event ProofClaimedFromZkEVM(
        uint256 indexed globalIndex,
        bytes32 indexed proofHash,
        address indexed recipient,
        uint256 amount
    );

    event BridgeAssetDeposited(
        uint8 leafType,
        uint32 originNetwork,
        address originAddress,
        uint32 destinationNetwork,
        address destinationAddress,
        uint256 amount,
        bytes metadata
    );

    event GlobalExitRootUpdated(
        bytes32 mainnetExitRoot,
        bytes32 rollupExitRoot
    );

    event ConfigUpdated(string param, uint256 value);

    // ============ Errors ============

    error InvalidAddress();
    error InvalidAmount();
    error InvalidNetwork();
    error InvalidProof();
    error DepositNotFound();
    error AlreadyClaimed();
    error DailyLimitExceeded();
    error InvalidLeafType();
    error ClaimFailed();
    error BridgeFailed();
    error ExitRootNotFound();

    // ============ Constructor ============

    /**
     * @notice Initialize Polygon zkEVM bridge adapter
     * @param _bridge Polygon zkEVM Bridge address
     * @param _globalExitRootManager Global Exit Root Manager address
     * @param _polygonZkEVM Polygon zkEVM contract address
     * @param _networkId Network ID for this chain
     * @param _admin Admin address
     */
    constructor(
        address _bridge,
        address _globalExitRootManager,
        address _polygonZkEVM,
        uint32 _networkId,
        address _admin
    ) {
        if (
            _bridge == address(0) ||
            _globalExitRootManager == address(0) ||
            _polygonZkEVM == address(0) ||
            _admin == address(0)
        ) {
            revert InvalidAddress();
        }

        polygonZkEVMBridge = _bridge;
        globalExitRootManager = _globalExitRootManager;
        polygonZkEVM = _polygonZkEVM;
        networkId = _networkId;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(BRIDGE_OPERATOR_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);
        _grantRole(CLAIMER_ROLE, _admin);

        config = BridgeConfig({
            minAmount: 0.001 ether,
            maxAmount: 100 ether,
            dailyLimit: 1000 ether,
            dailyUsed: 0,
            lastResetDay: block.timestamp / 1 days,
            forceUpdateGlobalExitRoot: true
        });
    }

    // ============ External Functions ============

    /**
     * @notice Bridge proof to Polygon zkEVM
     * @param proofHash Hash of the ZK proof
     * @param proofData Serialized proof data
     * @param publicInputs Public inputs for verification
     * @param destinationAddress Recipient address on zkEVM
     * @return depositIndex Deposit count for tracking
     */
    function bridgeProofToZkEVM(
        bytes32 proofHash,
        bytes calldata proofData,
        bytes calldata publicInputs,
        address destinationAddress
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (uint256 depositIndex)
    {
        if (destinationAddress == address(0)) revert InvalidAddress();
        if (msg.value < config.minAmount || msg.value > config.maxAmount) {
            revert InvalidAmount();
        }

        _checkDailyLimit(msg.value);

        depositIndex = depositCount++;

        // Encode metadata for L2
        bytes memory metadata = abi.encode(
            proofHash,
            proofData,
            publicInputs,
            msg.sender
        );

        // Bridge message to zkEVM
        _bridgeMessage(
            DESTINATION_NETWORK,
            pilHubL2,
            config.forceUpdateGlobalExitRoot,
            metadata
        );

        deposits[depositIndex] = BridgeDeposit({
            leafType: LEAF_TYPE_MESSAGE,
            originNetwork: networkId,
            originAddress: address(this),
            destinationNetwork: DESTINATION_NETWORK,
            destinationAddress: pilHubL2,
            amount: msg.value,
            proofHash: proofHash,
            metadata: metadata,
            timestamp: block.timestamp,
            claimed: false
        });

        proofBridgeStatus[proofHash] = ProofBridgeStatus({
            initiated: true,
            claimed: false,
            originNetwork: networkId,
            destNetwork: DESTINATION_NETWORK,
            depositCount: depositIndex,
            globalIndex: 0, // Set when claimed
            sender: msg.sender,
            timestamp: block.timestamp
        });

        emit ProofBridgedToZkEVM(
            depositIndex,
            proofHash,
            msg.sender,
            destinationAddress,
            msg.value
        );
        emit BridgeAssetDeposited(
            LEAF_TYPE_MESSAGE,
            networkId,
            address(this),
            DESTINATION_NETWORK,
            pilHubL2,
            msg.value,
            metadata
        );
    }

    /**
     * @notice Claim bridged proof from zkEVM
     * @param params Claim parameters including Merkle proofs
     */
    function claimProofFromZkEVM(
        ClaimParams calldata params
    ) external nonReentrant whenNotPaused {
        if (claimedGlobalIndex[params.globalIndex]) {
            revert AlreadyClaimed();
        }

        // Verify the SMT proofs
        if (!_verifyClaim(params)) {
            revert InvalidProof();
        }

        claimedGlobalIndex[params.globalIndex] = true;

        // Decode metadata
        (bytes32 proofHash, , , address originalSender) = abi.decode(
            params.metadata,
            (bytes32, bytes, bytes, address)
        );

        // Update bridge status
        proofBridgeStatus[proofHash].claimed = true;
        proofBridgeStatus[proofHash].globalIndex = params.globalIndex;

        emit ProofClaimedFromZkEVM(
            params.globalIndex,
            proofHash,
            params.destinationAddress,
            params.amount
        );

        // Notify proof registry
        if (proofRegistry != address(0)) {
            _notifyRegistry(proofHash, originalSender, params.amount);
        }

        // Transfer value to destination
        if (params.amount > 0 && params.destinationAddress != address(0)) {
            (bool success, ) = params.destinationAddress.call{
                value: params.amount
            }("");
            if (!success) revert ClaimFailed();
        }
    }

    /**
     * @notice Bridge asset (ETH/token) to zkEVM
     * @param destinationAddress Recipient on zkEVM
     * @param token Token address (address(0) for ETH)
     * @param amount Amount to bridge
     * @param permitData Optional permit data for ERC20
     */
    function bridgeAsset(
        address destinationAddress,
        address token,
        uint256 amount,
        bytes calldata permitData
    ) external payable nonReentrant whenNotPaused {
        if (destinationAddress == address(0)) revert InvalidAddress();

        uint256 bridgeValue = token == address(0) ? msg.value : 0;

        if (bridgeValue < config.minAmount || bridgeValue > config.maxAmount) {
            revert InvalidAmount();
        }

        _checkDailyLimit(bridgeValue);

        // Call Polygon zkEVM Bridge
        _bridgeAsset(
            DESTINATION_NETWORK,
            destinationAddress,
            bridgeValue,
            token,
            config.forceUpdateGlobalExitRoot,
            permitData
        );
    }

    /**
     * @notice Get the current global exit root
     * @return mainnetExitRoot L1 exit root
     * @return rollupExitRoot L2 rollup exit root
     */
    function getGlobalExitRoot()
        external
        view
        returns (bytes32 mainnetExitRoot, bytes32 rollupExitRoot)
    {
        (bool success, bytes memory data) = globalExitRootManager.staticcall(
            abi.encodeWithSignature("getLastGlobalExitRoot()")
        );

        if (success && data.length >= 64) {
            (mainnetExitRoot, rollupExitRoot) = abi.decode(
                data,
                (bytes32, bytes32)
            );
        }
    }

    /**
     * @notice Verify if a deposit is claimable
     * @param depositIndex Deposit index
     * @return True if claimable
     */
    function isClaimable(uint256 depositIndex) external view returns (bool) {
        BridgeDeposit storage deposit = deposits[depositIndex];
        return deposit.timestamp > 0 && !deposit.claimed;
    }

    // ============ View Functions ============

    /**
     * @notice Get proof bridge status
     * @param proofHash Hash of the proof
     * @return status Bridge status struct
     */
    function getProofStatus(
        bytes32 proofHash
    ) external view returns (ProofBridgeStatus memory) {
        return proofBridgeStatus[proofHash];
    }

    /**
     * @notice Get deposit info
     * @param depositIndex Deposit index
     * @return deposit Deposit struct
     */
    function getDeposit(
        uint256 depositIndex
    ) external view returns (BridgeDeposit memory) {
        return deposits[depositIndex];
    }

    /**
     * @notice Get remaining daily limit
     */
    function getRemainingDailyLimit() external view returns (uint256) {
        uint256 currentDay = block.timestamp / 1 days;
        if (currentDay > config.lastResetDay) {
            return config.dailyLimit;
        }
        return
            config.dailyLimit > config.dailyUsed
                ? config.dailyLimit - config.dailyUsed
                : 0;
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
        bool _forceUpdateGlobalExitRoot
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_minAmount >= _maxAmount) revert InvalidAmount();

        config.minAmount = _minAmount;
        config.maxAmount = _maxAmount;
        config.dailyLimit = _dailyLimit;
        config.forceUpdateGlobalExitRoot = _forceUpdateGlobalExitRoot;

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

    function _bridgeMessage(
        uint32 destinationNetwork,
        address destinationAddress,
        bool forceUpdateGlobalExitRoot,
        bytes memory metadata
    ) internal {
        (bool success, ) = polygonZkEVMBridge.call{value: msg.value}(
            abi.encodeWithSignature(
                "bridgeMessage(uint32,address,bool,bytes)",
                destinationNetwork,
                destinationAddress,
                forceUpdateGlobalExitRoot,
                metadata
            )
        );

        if (!success) revert BridgeFailed();
    }

    function _bridgeAsset(
        uint32 destinationNetwork,
        address destinationAddress,
        uint256 amount,
        address token,
        bool forceUpdateGlobalExitRoot,
        bytes calldata permitData
    ) internal {
        (bool success, ) = polygonZkEVMBridge.call{value: amount}(
            abi.encodeWithSignature(
                "bridgeAsset(uint32,address,uint256,address,bool,bytes)",
                destinationNetwork,
                destinationAddress,
                amount,
                token,
                forceUpdateGlobalExitRoot,
                permitData
            )
        );

        if (!success) revert BridgeFailed();
    }

    function _verifyClaim(
        ClaimParams calldata params
    ) internal view returns (bool) {
        // Verify Merkle proofs against Polygon zkEVM Bridge
        bytes memory callData = abi.encodeWithSignature(
            "verifyMerkleProof(bytes32,bytes32[32],bytes32[32],uint256,bytes32,bytes32)",
            keccak256(
                abi.encodePacked(
                    params.originNetwork,
                    params.originAddress,
                    params.destinationNetwork,
                    params.destinationAddress,
                    params.amount,
                    keccak256(params.metadata)
                )
            ),
            params.smtProofLocalExitRoot,
            params.smtProofRollupExitRoot,
            params.globalIndex,
            params.mainnetExitRoot,
            params.rollupExitRoot
        );

        (bool success, bytes memory result) = polygonZkEVMBridge.staticcall(
            callData
        );

        if (!success) return false;

        // If the call succeeds without returning data, proof is valid
        if (result.length == 0) return true;

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
                POLYGON_ZKEVM_MAINNET
            )
        );
        success; // Silence warning
    }

    receive() external payable {}
}
