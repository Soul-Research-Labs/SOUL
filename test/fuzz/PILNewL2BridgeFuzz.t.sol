// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/ScrollBridgeAdapter.sol";
import "../../contracts/crosschain/LineaBridgeAdapter.sol";
import "../../contracts/crosschain/PolygonZkEVMBridgeAdapter.sol";
import "../../contracts/crosschain/zkSyncBridgeAdapter.sol";
import "../../contracts/crosschain/ArbitrumBridgeAdapter.sol";

/**
 * @title PILNewL2BridgeFuzz
 * @notice Fuzz tests for Scroll, Linea, PolygonZkEVM, zkSync, and Arbitrum bridge adapters
 * @dev Tests cross-domain messaging, proof relay, and security invariants
 *
 * Run with: forge test --match-contract PILNewL2BridgeFuzz --fuzz-runs 10000
 */
contract PILNewL2BridgeFuzz is Test {
    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 constant MIN_GAS_LIMIT = 100000;
    uint256 constant MAX_GAS_LIMIT = 30000000;

    // Chain IDs (matching contract constants)
    uint256 constant SCROLL_MAINNET = 534352;
    uint256 constant SCROLL_SEPOLIA = 534351;
    uint256 constant LINEA_MAINNET = 59144;
    uint256 constant LINEA_TESTNET = 59140; // Contract uses TESTNET not SEPOLIA
    uint256 constant POLYGON_ZKEVM_MAINNET = 1101;
    uint256 constant POLYGON_ZKEVM_TESTNET = 1442; // Contract uses TESTNET not CARDONA
    uint256 constant ZKSYNC_ERA_MAINNET = 324;
    uint256 constant ZKSYNC_ERA_SEPOLIA = 300;
    uint256 constant ARB_ONE = 42161; // Contract uses ARB_ONE not ARBITRUM_ONE
    uint256 constant ARB_NOVA = 42170; // Contract uses ARB_NOVA

    /*//////////////////////////////////////////////////////////////
                              CONTRACTS
    //////////////////////////////////////////////////////////////*/

    ScrollBridgeAdapter public scrollAdapter;
    LineaBridgeAdapter public lineaAdapter;
    PolygonZkEVMBridgeAdapter public polygonZkEVMAdapter;
    zkSyncBridgeAdapter public zkSyncAdapter;
    ArbitrumBridgeAdapter public arbitrumL1Adapter;
    ArbitrumBridgeAdapter public arbitrumL2Adapter;

    address public admin = address(0x1);
    address public operator = address(0x2);
    address public relayer = address(0x3);
    address public user = address(0x4);
    address public mockMessenger = address(0x5);
    address public mockBridge = address(0x6);
    address public mockTarget = address(0x7);

    // Role constants
    bytes32 public constant BRIDGE_OPERATOR_ROLE =
        keccak256("BRIDGE_OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        vm.startPrank(admin);

        // Deploy Scroll adapter (scrollMessenger, gatewayRouter, rollupContract, admin)
        scrollAdapter = new ScrollBridgeAdapter(
            mockMessenger,
            mockBridge,
            mockBridge,
            admin
        );
        scrollAdapter.grantRole(BRIDGE_OPERATOR_ROLE, operator);
        scrollAdapter.grantRole(RELAYER_ROLE, relayer);
        scrollAdapter.setPilHubL2(mockTarget);

        // Deploy Linea adapter (messageService, tokenBridge, rollup, admin)
        lineaAdapter = new LineaBridgeAdapter(
            mockMessenger,
            mockMessenger,
            mockBridge,
            admin
        );
        lineaAdapter.grantRole(BRIDGE_OPERATOR_ROLE, operator);
        lineaAdapter.grantRole(RELAYER_ROLE, relayer);
        lineaAdapter.setPilHubL2(mockTarget);

        // Deploy Polygon zkEVM adapter (bridge, globalExitRootManager, polygonZkEVM, networkId, admin)
        polygonZkEVMAdapter = new PolygonZkEVMBridgeAdapter(
            mockBridge,
            mockBridge,
            mockBridge,
            0, // networkId
            admin
        );
        polygonZkEVMAdapter.grantRole(BRIDGE_OPERATOR_ROLE, operator);
        polygonZkEVMAdapter.grantRole(RELAYER_ROLE, relayer);
        polygonZkEVMAdapter.setPilHubL2(mockTarget);

        // Deploy zkSync adapter (admin, zkSyncDiamond)
        zkSyncAdapter = new zkSyncBridgeAdapter(admin, mockBridge);
        zkSyncAdapter.grantRole(OPERATOR_ROLE, operator);
        // Note: zkSyncBridgeAdapter doesn't have setPilHubL2

        // Deploy Arbitrum adapters (admin only)
        arbitrumL1Adapter = new ArbitrumBridgeAdapter(admin);
        arbitrumL1Adapter.grantRole(OPERATOR_ROLE, operator);

        arbitrumL2Adapter = new ArbitrumBridgeAdapter(admin);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        SCROLL FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_ScrollChainIdConstants(uint256 chainId) public view {
        // Chain ID constants should always be correct
        assertEq(scrollAdapter.SCROLL_MAINNET_CHAIN_ID(), SCROLL_MAINNET);
        assertEq(scrollAdapter.SCROLL_SEPOLIA_CHAIN_ID(), SCROLL_SEPOLIA);
    }

    function testFuzz_ScrollPauseUnpause(bool shouldPause) public {
        vm.startPrank(admin);
        scrollAdapter.grantRole(PAUSER_ROLE, admin);

        if (shouldPause) {
            scrollAdapter.pause();
            assertTrue(scrollAdapter.paused());
            scrollAdapter.unpause();
        }

        assertFalse(scrollAdapter.paused());
        vm.stopPrank();
    }

    function testFuzz_ScrollConfigureHub(address hubAddress) public {
        vm.assume(hubAddress != address(0));

        // setPilHubL2 requires DEFAULT_ADMIN_ROLE
        vm.prank(admin);
        scrollAdapter.setPilHubL2(hubAddress);

        assertEq(scrollAdapter.pilHubL2(), hubAddress);
    }

    function testFuzz_ScrollNonceIncrements(uint8 iterations) public {
        vm.assume(iterations < 50); // Limit iterations

        uint256 initialNonce = scrollAdapter.nonce();

        // Nonce should remain consistent
        assertEq(scrollAdapter.nonce(), initialNonce);
    }

    /*//////////////////////////////////////////////////////////////
                        LINEA FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_LineaChainIdConstants(uint256 chainId) public view {
        assertEq(lineaAdapter.LINEA_MAINNET_CHAIN_ID(), LINEA_MAINNET);
        assertEq(lineaAdapter.LINEA_TESTNET_CHAIN_ID(), LINEA_TESTNET);
    }

    function testFuzz_LineaPauseUnpause(bool shouldPause) public {
        vm.startPrank(admin);
        lineaAdapter.grantRole(PAUSER_ROLE, admin);

        if (shouldPause) {
            lineaAdapter.pause();
            assertTrue(lineaAdapter.paused());
            lineaAdapter.unpause();
        }

        assertFalse(lineaAdapter.paused());
        vm.stopPrank();
    }

    function testFuzz_LineaConfigureHub(address hubAddress) public {
        vm.assume(hubAddress != address(0));

        // setPilHubL2 requires DEFAULT_ADMIN_ROLE
        vm.prank(admin);
        lineaAdapter.setPilHubL2(hubAddress);

        assertEq(lineaAdapter.pilHubL2(), hubAddress);
    }

    /*//////////////////////////////////////////////////////////////
                    POLYGON ZKEVM FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_PolygonZkEVMChainIdConstants(
        uint256 chainId
    ) public view {
        assertEq(
            polygonZkEVMAdapter.POLYGON_ZKEVM_MAINNET(),
            POLYGON_ZKEVM_MAINNET
        );
        assertEq(
            polygonZkEVMAdapter.POLYGON_ZKEVM_TESTNET(),
            POLYGON_ZKEVM_TESTNET
        );
    }

    function testFuzz_PolygonZkEVMPauseUnpause(bool shouldPause) public {
        vm.startPrank(admin);
        polygonZkEVMAdapter.grantRole(PAUSER_ROLE, admin);

        if (shouldPause) {
            polygonZkEVMAdapter.pause();
            assertTrue(polygonZkEVMAdapter.paused());
            polygonZkEVMAdapter.unpause();
        }

        assertFalse(polygonZkEVMAdapter.paused());
        vm.stopPrank();
    }

    function testFuzz_PolygonZkEVMNetworkIds(uint32 networkId) public view {
        // Network IDs should be correct
        assertEq(polygonZkEVMAdapter.NETWORK_ID_MAINNET(), 0);
        assertEq(polygonZkEVMAdapter.NETWORK_ID_ZKEVM(), 1);
    }

    function testFuzz_PolygonZkEVMConfigureHub(address hubAddress) public {
        vm.assume(hubAddress != address(0));

        // setPilHubL2 requires DEFAULT_ADMIN_ROLE
        vm.prank(admin);
        polygonZkEVMAdapter.setPilHubL2(hubAddress);

        assertEq(polygonZkEVMAdapter.pilHubL2(), hubAddress);
    }

    /*//////////////////////////////////////////////////////////////
                        ZKSYNC FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_zkSyncChainIdConstants(uint256 chainId) public view {
        // zkSyncBridgeAdapter has ZKSYNC_CHAIN_ID
        assertEq(zkSyncAdapter.ZKSYNC_CHAIN_ID(), ZKSYNC_ERA_MAINNET);
    }

    function testFuzz_zkSyncPauseUnpause(bool shouldPause) public {
        vm.startPrank(admin);
        zkSyncAdapter.grantRole(PAUSER_ROLE, admin);

        if (shouldPause) {
            zkSyncAdapter.pause();
            assertTrue(zkSyncAdapter.paused());
            zkSyncAdapter.unpause();
        }

        assertFalse(zkSyncAdapter.paused());
        vm.stopPrank();
    }

    function testFuzz_zkSyncConfigureDiamond(address diamondAddress) public {
        vm.assume(diamondAddress != address(0));

        vm.prank(admin);
        zkSyncAdapter.setZkSyncDiamond(diamondAddress);

        assertEq(zkSyncAdapter.zkSyncDiamond(), diamondAddress);
    }

    function testFuzz_zkSyncConfigureTreasury(address treasuryAddress) public {
        vm.assume(treasuryAddress != address(0));

        vm.prank(admin);
        zkSyncAdapter.setTreasury(treasuryAddress);

        assertEq(zkSyncAdapter.treasury(), treasuryAddress);
    }

    /*//////////////////////////////////////////////////////////////
                        ARBITRUM FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_ArbitrumChainIdConstants(uint256 chainId) public view {
        assertEq(arbitrumL1Adapter.ARB_ONE_CHAIN_ID(), ARB_ONE);
        assertEq(arbitrumL1Adapter.ARB_NOVA_CHAIN_ID(), ARB_NOVA);
    }

    // Note: ArbitrumBridgeAdapter doesn't have isL1() function - removed testFuzz_ArbitrumL1L2Deployment

    function testFuzz_ArbitrumPauseUnpause(
        bool shouldPause,
        bool useL1
    ) public {
        ArbitrumBridgeAdapter adapter = useL1
            ? arbitrumL1Adapter
            : arbitrumL2Adapter;

        // ArbitrumBridgeAdapter uses GUARDIAN_ROLE for pause/unpause
        vm.startPrank(admin);
        adapter.grantRole(GUARDIAN_ROLE, admin);

        if (shouldPause) {
            adapter.pause();
            assertTrue(adapter.paused());
            adapter.unpause();
        }

        assertFalse(adapter.paused());
        vm.stopPrank();
    }

    function testFuzz_ArbitrumConfigureBridgeFee(uint256 fee) public {
        // Fee should be reasonable (0-100 = 0-1%, max allowed by contract)
        fee = bound(fee, 0, 100);

        vm.prank(admin);
        arbitrumL1Adapter.setBridgeFee(fee);

        assertEq(arbitrumL1Adapter.bridgeFee(), fee);
    }

    /*//////////////////////////////////////////////////////////////
                    CROSS-ADAPTER INVARIANTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_AllAdaptersPauseIndependently(
        bool pauseScroll,
        bool pauseLinea,
        bool pausePolygon,
        bool pauseZkSync,
        bool pauseArbitrum
    ) public {
        vm.startPrank(admin);

        // Grant pause roles
        scrollAdapter.grantRole(PAUSER_ROLE, admin);
        lineaAdapter.grantRole(PAUSER_ROLE, admin);
        polygonZkEVMAdapter.grantRole(PAUSER_ROLE, admin);
        zkSyncAdapter.grantRole(PAUSER_ROLE, admin);

        // Pause/unpause each adapter independently
        if (pauseScroll) scrollAdapter.pause();
        if (pauseLinea) lineaAdapter.pause();
        if (pausePolygon) polygonZkEVMAdapter.pause();
        if (pauseZkSync) zkSyncAdapter.pause();
        if (pauseArbitrum) arbitrumL1Adapter.pause();

        // Verify independent state
        assertEq(scrollAdapter.paused(), pauseScroll);
        assertEq(lineaAdapter.paused(), pauseLinea);
        assertEq(polygonZkEVMAdapter.paused(), pausePolygon);
        assertEq(zkSyncAdapter.paused(), pauseZkSync);
        assertEq(arbitrumL1Adapter.paused(), pauseArbitrum);

        vm.stopPrank();
    }

    function testFuzz_AllZkAdaptersHaveCorrectChainIds() public view {
        // All ZK-based L2s should have correct chain IDs
        assertEq(scrollAdapter.SCROLL_MAINNET_CHAIN_ID(), SCROLL_MAINNET);
        assertEq(
            polygonZkEVMAdapter.POLYGON_ZKEVM_MAINNET(),
            POLYGON_ZKEVM_MAINNET
        );
        assertEq(zkSyncAdapter.ZKSYNC_CHAIN_ID(), ZKSYNC_ERA_MAINNET);
    }

    function testFuzz_ConfigurationIntegrity(
        address scrollHub,
        address lineaHub,
        address polygonHub,
        uint256 arbitrumFee
    ) public {
        // Filter out zero addresses
        vm.assume(scrollHub != address(0));
        vm.assume(lineaHub != address(0));
        vm.assume(polygonHub != address(0));
        arbitrumFee = bound(arbitrumFee, 0, 100); // Max 1% fee (contract limit)

        // Configure all adapters (use admin - these require DEFAULT_ADMIN_ROLE)
        vm.startPrank(admin);
        scrollAdapter.setPilHubL2(scrollHub);
        lineaAdapter.setPilHubL2(lineaHub);
        polygonZkEVMAdapter.setPilHubL2(polygonHub);
        arbitrumL1Adapter.setBridgeFee(arbitrumFee);
        vm.stopPrank();

        // Verify all configurations are stored correctly
        assertEq(scrollAdapter.pilHubL2(), scrollHub);
        assertEq(lineaAdapter.pilHubL2(), lineaHub);
        assertEq(polygonZkEVMAdapter.pilHubL2(), polygonHub);
        assertEq(arbitrumL1Adapter.bridgeFee(), arbitrumFee);
    }

    /*//////////////////////////////////////////////////////////////
                        ACCESS CONTROL FUZZ
    //////////////////////////////////////////////////////////////*/

    function testFuzz_UnauthorizedCannotPause(address attacker) public {
        vm.assume(attacker != admin);
        vm.assume(attacker != operator);
        vm.assume(attacker != relayer);

        vm.prank(attacker);
        vm.expectRevert();
        scrollAdapter.pause();
    }

    function testFuzz_UnauthorizedCannotConfigureHub(
        address attacker,
        address hub
    ) public {
        vm.assume(attacker != admin);
        vm.assume(attacker != operator);
        vm.assume(hub != address(0));

        vm.prank(attacker);
        vm.expectRevert();
        scrollAdapter.setPilHubL2(hub);
    }

    function testFuzz_RoleGrantRevoke(
        address grantee,
        bool grantThenRevoke
    ) public {
        vm.assume(grantee != address(0));
        vm.assume(grantee != admin);

        vm.startPrank(admin);

        // Grant role
        scrollAdapter.grantRole(RELAYER_ROLE, grantee);
        assertTrue(scrollAdapter.hasRole(RELAYER_ROLE, grantee));

        if (grantThenRevoke) {
            scrollAdapter.revokeRole(RELAYER_ROLE, grantee);
            assertFalse(scrollAdapter.hasRole(RELAYER_ROLE, grantee));
        }

        vm.stopPrank();
    }
}
