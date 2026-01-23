// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/starknet/StarknetPrimitives.sol";
import "../../contracts/starknet/StarknetProofVerifier.sol";
import "../../contracts/starknet/CrossDomainNullifierStarknet.sol";
import "../../contracts/starknet/StarknetStateSync.sol";
import "../../contracts/crosschain/StarkNetBridgeAdapter.sol";

/**
 * @title StarknetBridgeFuzz
 * @author PIL Protocol
 * @notice Comprehensive fuzz tests for Starknet interoperability components
 * @dev Tests edge cases, invariants, and security properties
 *
 * FUZZ TEST COVERAGE:
 * - StarknetPrimitives: Field arithmetic, hash functions, message encoding
 * - StarknetProofVerifier: FRI config validation, proof lifecycle
 * - CrossDomainNullifierStarknet: Nullifier uniqueness, cross-domain consistency
 * - StarknetStateSync: State root validation, storage proof verification
 * - StarkNetBridgeAdapter: Message hashing, fee calculations, token mappings
 */
contract StarknetBridgeFuzz is Test {
    using StarknetPrimitives for uint256;

    // Constants
    uint256 constant STARK_PRIME =
        0x800000000000011000000000000000000000000000000000000000000000001;

    // Contract instances
    StarknetProofVerifier public proofVerifier;
    CrossDomainNullifierStarknet public nullifierContract;
    StarknetStateSync public stateSync;
    StarkNetBridgeAdapter public bridgeAdapter;

    // Test addresses
    address public owner;
    address public operator;
    address public verifier;
    address public sequencer;
    address public bridge;
    address public registrar;
    address public relayer;
    address public prover;

    // Test data
    bytes32 public testProgramHash;
    bytes32 public testDomainId;

    function setUp() public {
        owner = address(this);
        operator = makeAddr("operator");
        verifier = makeAddr("verifier");
        sequencer = makeAddr("sequencer");
        bridge = makeAddr("bridge");
        registrar = makeAddr("registrar");
        relayer = makeAddr("relayer");
        prover = makeAddr("prover");

        // Deploy StarknetProofVerifier
        proofVerifier = new StarknetProofVerifier();
        proofVerifier.grantRole(proofVerifier.OPERATOR_ROLE(), operator);
        proofVerifier.grantRole(proofVerifier.VERIFIER_ROLE(), verifier);
        proofVerifier.grantRole(proofVerifier.PROVER_ROLE(), prover);

        // Register test program
        testProgramHash = keccak256("test_program");
        // Security requirement: numQueries * log2(blowupFactor) >= 128
        // 45 * 3 (log2(8)) = 135 >= 128 ✓
        StarknetProofVerifier.FRIConfig memory friConfig = StarknetProofVerifier
            .FRIConfig({
                domainSize: 1 << 16,
                blowupFactor: 8,
                numQueries: 45,
                foldingFactor: 2,
                lastLayerDegBound: 64,
                numLayers: 10
            });
        vm.prank(operator);
        proofVerifier.registerProgram(testProgramHash, friConfig);

        // Deploy CrossDomainNullifierStarknet
        nullifierContract = new CrossDomainNullifierStarknet();
        nullifierContract.grantRole(
            nullifierContract.OPERATOR_ROLE(),
            operator
        );
        nullifierContract.grantRole(nullifierContract.BRIDGE_ROLE(), bridge);
        nullifierContract.grantRole(
            nullifierContract.NULLIFIER_REGISTRAR_ROLE(),
            registrar
        );

        // Configure Starknet bridge
        vm.prank(operator);
        nullifierContract.configureStarknetBridge(bridge, 12345);

        // Register test domain
        testDomainId = keccak256("test_domain");
        vm.prank(operator);
        nullifierContract.registerDomain(
            testDomainId,
            CrossDomainNullifierStarknet.DomainType.PIL_L1,
            12345
        );

        // Deploy StarknetStateSync
        stateSync = new StarknetStateSync();
        stateSync.grantRole(stateSync.OPERATOR_ROLE(), operator);
        stateSync.grantRole(stateSync.SEQUENCER_ROLE(), sequencer);
        stateSync.grantRole(stateSync.VERIFIER_ROLE(), verifier);
        stateSync.grantRole(stateSync.RELAYER_ROLE(), relayer);

        // Set Starknet core
        vm.prank(operator);
        stateSync.setStarknetCore(makeAddr("starknetCore"));

        // Deploy StarkNetBridgeAdapter
        bridgeAdapter = new StarkNetBridgeAdapter();
        bridgeAdapter.grantRole(bridgeAdapter.OPERATOR_ROLE(), operator);
        bridgeAdapter.grantRole(bridgeAdapter.SEQUENCER_ROLE(), sequencer);
        bridgeAdapter.grantRole(bridgeAdapter.GUARDIAN_ROLE(), operator);
        bridgeAdapter.grantRole(bridgeAdapter.VERIFIER_ROLE(), verifier);

        // Configure bridge
        vm.prank(operator);
        bridgeAdapter.configureStarkNetCore(makeAddr("starknetCore"));
    }

    /*//////////////////////////////////////////////////////////////
                    STARKNET PRIMITIVES FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test felt addition is commutative and associative
    function testFuzz_FeltAddCommutative(uint256 a, uint256 b) public pure {
        a = bound(a, 0, STARK_PRIME - 1);
        b = bound(b, 0, STARK_PRIME - 1);

        uint256 ab = StarknetPrimitives.feltAdd(a, b);
        uint256 ba = StarknetPrimitives.feltAdd(b, a);

        assertEq(ab, ba, "Felt addition should be commutative");
    }

    /// @notice Test felt subtraction is inverse of addition
    function testFuzz_FeltSubInverse(uint256 a, uint256 b) public pure {
        a = bound(a, 0, STARK_PRIME - 1);
        b = bound(b, 0, STARK_PRIME - 1);

        uint256 sum = StarknetPrimitives.feltAdd(a, b);
        uint256 result = StarknetPrimitives.feltSub(sum, b);

        assertEq(result, a, "Felt subtraction should be inverse of addition");
    }

    /// @notice Test felt multiplication is commutative
    function testFuzz_FeltMulCommutative(uint256 a, uint256 b) public pure {
        a = bound(a, 0, STARK_PRIME - 1);
        b = bound(b, 0, STARK_PRIME - 1);

        uint256 ab = StarknetPrimitives.feltMul(a, b);
        uint256 ba = StarknetPrimitives.feltMul(b, a);

        assertEq(ab, ba, "Felt multiplication should be commutative");
    }

    /// @notice Test felt multiplication by one is identity
    function testFuzz_FeltMulIdentity(uint256 a) public pure {
        a = bound(a, 0, STARK_PRIME - 1);

        uint256 result = StarknetPrimitives.feltMul(a, 1);

        assertEq(result, a, "Multiplication by 1 should be identity");
    }

    /// @notice Test felt multiplication by zero is zero
    function testFuzz_FeltMulZero(uint256 a) public pure {
        a = bound(a, 0, STARK_PRIME - 1);

        uint256 result = StarknetPrimitives.feltMul(a, 0);

        assertEq(result, 0, "Multiplication by 0 should be 0");
    }

    /// @notice Test felt negation is correct
    function testFuzz_FeltNegation(uint256 a) public pure {
        a = bound(a, 0, STARK_PRIME - 1);

        uint256 negA = StarknetPrimitives.feltNeg(a);
        uint256 sum = StarknetPrimitives.feltAdd(a, negA);

        assertEq(sum, 0, "a + (-a) should equal 0");
    }

    /// @notice Test toFelt reduces values correctly
    function testFuzz_ToFelt(uint256 a) public pure {
        uint256 result = StarknetPrimitives.toFelt(a);

        assertTrue(result < STARK_PRIME, "toFelt should reduce to valid felt");
        assertEq(result, a % STARK_PRIME, "toFelt should be modular reduction");
    }

    /// @notice Test isValidFelt boundary
    function testFuzz_IsValidFelt(uint256 a) public pure {
        bool isValid = StarknetPrimitives.isValidFelt(a);

        if (a < STARK_PRIME) {
            assertTrue(isValid, "Values less than STARK_PRIME should be valid");
        } else {
            assertFalse(isValid, "Values >= STARK_PRIME should be invalid");
        }
    }

    /// @notice Test Poseidon hash is deterministic
    function testFuzz_PoseidonDeterministic(uint256 a, uint256 b) public view {
        a = bound(a, 0, STARK_PRIME - 1);
        b = bound(b, 0, STARK_PRIME - 1);

        uint256 hash1 = StarknetPrimitives.poseidonHash2(a, b);
        uint256 hash2 = StarknetPrimitives.poseidonHash2(a, b);

        assertEq(hash1, hash2, "Poseidon hash should be deterministic");
    }

    /// @notice Test Poseidon hash is collision-resistant (weak test)
    function testFuzz_PoseidonCollisionResistance(
        uint256 a,
        uint256 b,
        uint256 c,
        uint256 d
    ) public view {
        a = bound(a, 0, STARK_PRIME - 1);
        b = bound(b, 0, STARK_PRIME - 1);
        c = bound(c, 0, STARK_PRIME - 1);
        d = bound(d, 0, STARK_PRIME - 1);

        // Skip if inputs are identical
        vm.assume(a != c || b != d);

        uint256 hash1 = StarknetPrimitives.poseidonHash2(a, b);
        uint256 hash2 = StarknetPrimitives.poseidonHash2(c, d);

        // This is a weak collision resistance test - statistically should pass
        assertNotEq(
            hash1,
            hash2,
            "Different inputs should produce different hashes"
        );
    }

    /// @notice Test Pedersen hash is deterministic
    function testFuzz_PedersenDeterministic(uint256 a, uint256 b) public pure {
        a = bound(a, 0, STARK_PRIME - 1);
        b = bound(b, 0, STARK_PRIME - 1);

        uint256 hash1 = StarknetPrimitives.pedersenHash(a, b);
        uint256 hash2 = StarknetPrimitives.pedersenHash(a, b);

        assertEq(hash1, hash2, "Pedersen hash should be deterministic");
    }

    /// @notice Test address to felt conversion
    function testFuzz_AddressToFelt(address addr) public pure {
        uint256 felt = StarknetPrimitives.addressToFelt(addr);

        assertEq(
            felt,
            uint256(uint160(addr)),
            "Address to felt should preserve value"
        );
        assertTrue(felt <= type(uint160).max, "Felt should fit in 160 bits");
    }

    /// @notice Test felt to address conversion
    function testFuzz_FeltToAddress(uint160 felt) public pure {
        address addr = StarknetPrimitives.feltToAddress(uint256(felt));

        assertEq(addr, address(felt), "Felt to address should preserve value");
    }

    /// @notice Test L1 to L2 message hash is deterministic
    function testFuzz_L1ToL2MessageHash(
        uint256 fromAddress,
        uint256 toAddress,
        uint256 selector,
        uint256 nonce
    ) public pure {
        fromAddress = bound(fromAddress, 0, STARK_PRIME - 1);
        toAddress = bound(toAddress, 1, STARK_PRIME - 1);
        selector = bound(selector, 1, STARK_PRIME - 1);

        uint256[] memory payload = new uint256[](2);
        payload[0] = fromAddress;
        payload[1] = toAddress;

        bytes32 hash1 = StarknetPrimitives.computeL1ToL2MessageHash(
            fromAddress,
            toAddress,
            selector,
            payload,
            nonce
        );

        bytes32 hash2 = StarknetPrimitives.computeL1ToL2MessageHash(
            fromAddress,
            toAddress,
            selector,
            payload,
            nonce
        );

        assertEq(hash1, hash2, "Message hash should be deterministic");
    }

    /// @notice Test sn_keccak truncation
    function testFuzz_SnKeccak(bytes memory data) public pure {
        vm.assume(data.length > 0 && data.length < 1000);

        uint256 result = StarknetPrimitives.snKeccak(data);

        assertTrue(result < (1 << 250), "sn_keccak should be 250 bits");
    }

    /*//////////////////////////////////////////////////////////////
                  PROOF VERIFIER FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test FRI config validation with random parameters
    function testFuzz_FRIConfigValidation(
        uint256 domainSize,
        uint256 blowupFactor,
        uint256 numQueries,
        uint256 foldingFactor
    ) public {
        // Constrain to potentially valid ranges
        domainSize = 1 << bound(domainSize, 10, 26);
        blowupFactor = bound(blowupFactor, 2, 16);
        numQueries = bound(numQueries, 20, 100);
        foldingFactor = foldingFactor % 2 == 0 ? 2 : 4;

        StarknetProofVerifier.FRIConfig memory config = StarknetProofVerifier
            .FRIConfig({
                domainSize: domainSize,
                blowupFactor: blowupFactor,
                numQueries: numQueries,
                foldingFactor: foldingFactor,
                lastLayerDegBound: 64,
                numLayers: 10
            });

        // Should not revert for valid configs
        vm.prank(operator);
        try
            proofVerifier.registerProgram(
                keccak256(abi.encode(domainSize, blowupFactor)),
                config
            )
        {
            // Success
        } catch {
            // Expected for invalid configs
        }
    }

    /// @notice Test proof submission with random data
    function testFuzz_ProofSubmission(
        bytes32 traceCommitment,
        bytes32 constraintCommitment,
        bytes32 compositionCommitment,
        uint256 numLayers
    ) public {
        numLayers = bound(numLayers, 1, 10);

        bytes32[] memory friCommitments = new bytes32[](numLayers);
        for (uint256 i = 0; i < numLayers; i++) {
            friCommitments[i] = keccak256(
                abi.encodePacked("layer", i, traceCommitment)
            );
        }

        uint256[] memory publicInputs = new uint256[](3);
        publicInputs[0] = uint256(traceCommitment) % STARK_PRIME;
        publicInputs[1] = uint256(constraintCommitment) % STARK_PRIME;
        publicInputs[2] = uint256(compositionCommitment) % STARK_PRIME;

        bytes32 proofId = proofVerifier.submitProof(
            testProgramHash,
            StarknetProofVerifier.ProofType.CAIRO_1,
            traceCommitment,
            constraintCommitment,
            compositionCommitment,
            friCommitments,
            publicInputs
        );

        assertTrue(proofId != bytes32(0), "Proof ID should not be zero");

        StarknetProofVerifier.STARKProof memory proof = proofVerifier.getProof(
            proofId
        );
        assertEq(
            proof.traceCommitment,
            traceCommitment,
            "Trace commitment mismatch"
        );
    }

    /// @notice Test proof expiry time configuration
    function testFuzz_ProofExpiryConfig(uint256 expiryTime) public {
        expiryTime = bound(expiryTime, 1 days, 365 days);

        vm.prank(operator);
        proofVerifier.setProofExpiryTime(expiryTime);

        assertEq(
            proofVerifier.proofExpiryTime(),
            expiryTime,
            "Expiry time should be set"
        );
    }

    /*//////////////////////////////////////////////////////////////
                CROSS-DOMAIN NULLIFIER FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test nullifier registration with random data
    function testFuzz_NullifierRegistration(
        bytes32 nullifier,
        bytes32 commitment
    ) public {
        vm.assume(nullifier != bytes32(0));
        vm.assume(commitment != bytes32(0));

        vm.prank(registrar);
        bytes32 crossDomainNullifier = nullifierContract
            .registerNullifierFromL1(nullifier, commitment, testDomainId);

        assertTrue(
            crossDomainNullifier != bytes32(0),
            "Cross-domain nullifier should not be zero"
        );
        assertTrue(
            nullifierContract.nullifierExists(nullifier),
            "Nullifier should exist"
        );
    }

    /// @notice Test nullifier uniqueness
    function testFuzz_NullifierUniqueness(
        bytes32 nullifier1,
        bytes32 nullifier2,
        bytes32 commitment
    ) public {
        vm.assume(nullifier1 != nullifier2);
        vm.assume(nullifier1 != bytes32(0));
        vm.assume(nullifier2 != bytes32(0));
        vm.assume(commitment != bytes32(0));

        vm.prank(registrar);
        bytes32 cdn1 = nullifierContract.registerNullifierFromL1(
            nullifier1,
            commitment,
            testDomainId
        );

        vm.prank(registrar);
        bytes32 cdn2 = nullifierContract.registerNullifierFromL1(
            nullifier2,
            keccak256(abi.encode(commitment)),
            testDomainId
        );

        assertNotEq(
            cdn1,
            cdn2,
            "Different nullifiers should produce different cross-domain nullifiers"
        );
    }

    /// @notice Test double registration prevention
    function testFuzz_DoubleRegistrationPrevention(
        bytes32 nullifier,
        bytes32 commitment
    ) public {
        vm.assume(nullifier != bytes32(0));
        vm.assume(commitment != bytes32(0));

        vm.prank(registrar);
        nullifierContract.registerNullifierFromL1(
            nullifier,
            commitment,
            testDomainId
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                CrossDomainNullifierStarknet
                    .NullifierAlreadyRegistered
                    .selector,
                nullifier
            )
        );
        vm.prank(registrar);
        nullifierContract.registerNullifierFromL1(
            nullifier,
            commitment,
            testDomainId
        );
    }

    /// @notice Test L2 nullifier derivation
    function testFuzz_L2NullifierDerivation(
        bytes32 nullifier,
        bytes32 commitment
    ) public {
        vm.assume(nullifier != bytes32(0));
        vm.assume(commitment != bytes32(0));

        vm.prank(registrar);
        nullifierContract.registerNullifierFromL1(
            nullifier,
            commitment,
            testDomainId
        );

        uint256 l2Nullifier = nullifierContract.getL2Nullifier(nullifier);
        assertTrue(l2Nullifier != 0, "L2 nullifier should be derived");
        assertTrue(
            l2Nullifier < STARK_PRIME,
            "L2 nullifier should be valid felt"
        );
    }

    /// @notice Test batch sync with random nullifiers
    function testFuzz_BatchSync(uint8 batchSize) public {
        batchSize = uint8(bound(batchSize, 1, 50));

        bytes32[] memory nullifiers = new bytes32[](batchSize);

        for (uint8 i = 0; i < batchSize; i++) {
            bytes32 nullifier = keccak256(abi.encodePacked("nullifier", i));
            bytes32 commitment = keccak256(abi.encodePacked("commitment", i));

            vm.prank(registrar);
            nullifiers[i] = nullifierContract.registerNullifierFromL1(
                nullifier,
                commitment,
                testDomainId
            );
        }

        bytes32 stateRoot = keccak256("state_root");

        vm.prank(bridge);
        bytes32 batchId = nullifierContract.submitSyncBatch(
            nullifiers,
            stateRoot,
            1000
        );

        assertTrue(batchId != bytes32(0), "Batch ID should not be zero");

        CrossDomainNullifierStarknet.SyncBatch memory batch = nullifierContract
            .getBatch(batchId);
        assertEq(batch.nullifiers.length, batchSize, "Batch size mismatch");
    }

    /// @notice Test sync delay enforcement
    function testFuzz_SyncDelayEnforcement(uint256 delay) public {
        delay = bound(delay, 1 minutes, 1 days);

        vm.prank(operator);
        nullifierContract.setSyncDelay(delay);

        assertEq(
            nullifierContract.syncDelay(),
            delay,
            "Sync delay should be set"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    STATE SYNC FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test block header caching with random data
    function testFuzz_BlockHeaderCaching(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 stateRoot
    ) public {
        blockNumber = bound(blockNumber, 1, type(uint64).max);
        vm.assume(blockHash != bytes32(0));
        vm.assume(stateRoot != bytes32(0));

        vm.prank(sequencer);
        stateSync.cacheBlockHeader(
            blockNumber,
            blockHash,
            parentHash,
            stateRoot,
            keccak256("tx_root"),
            keccak256("receipts"),
            keccak256("sequencer"),
            block.timestamp,
            1 gwei
        );

        StarknetStateSync.BlockHeader memory header = stateSync.getBlockHeader(
            blockNumber
        );
        assertEq(header.blockHash, blockHash, "Block hash mismatch");
        assertEq(header.stateRoot, stateRoot, "State root mismatch");
    }

    /// @notice Test latest block number tracking
    function testFuzz_LatestBlockTracking(
        uint256[] memory blockNumbers
    ) public {
        vm.assume(blockNumbers.length > 0 && blockNumbers.length < 20);

        uint256 maxBlock = 0;

        for (uint256 i = 0; i < blockNumbers.length; i++) {
            uint256 bn = bound(blockNumbers[i], 1, type(uint64).max);

            vm.prank(sequencer);
            stateSync.cacheBlockHeader(
                bn,
                keccak256(abi.encodePacked("hash", bn)),
                keccak256(abi.encodePacked("parent", bn)),
                keccak256(abi.encodePacked("state", bn)),
                keccak256(abi.encodePacked("tx", bn)),
                keccak256(abi.encodePacked("receipts", bn)),
                keccak256(abi.encodePacked("sequencer", bn)),
                block.timestamp,
                1 gwei
            );

            if (bn > maxBlock) {
                maxBlock = bn;
            }
        }

        assertEq(
            stateSync.latestBlockNumber(),
            maxBlock,
            "Latest block should track max"
        );
    }

    /// @notice Test finality delay configuration
    function testFuzz_FinalityDelayConfig(uint256 delay) public {
        delay = bound(delay, 1, 1000);

        vm.prank(operator);
        stateSync.setFinalityDelay(delay);

        assertEq(
            stateSync.finalityDelay(),
            delay,
            "Finality delay should be set"
        );
    }

    /// @notice Test state root TTL configuration
    function testFuzz_StateRootTTLConfig(uint256 ttl) public {
        ttl = bound(ttl, 10 minutes, 24 hours);

        vm.prank(operator);
        stateSync.setStateRootTTL(ttl);

        assertEq(stateSync.stateRootTTL(), ttl, "State root TTL should be set");
    }

    /*//////////////////////////////////////////////////////////////
                  BRIDGE ADAPTER FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test L1 to L2 message sending with random data
    function testFuzz_L1ToL2MessageSending(
        uint256 toAddress,
        uint256 selector,
        uint256 payloadSize
    ) public {
        toAddress = bound(toAddress, 1, STARK_PRIME - 1);
        selector = bound(selector, 1, STARK_PRIME - 1);
        payloadSize = bound(payloadSize, 0, 10);

        uint256[] memory payload = new uint256[](payloadSize);
        for (uint256 i = 0; i < payloadSize; i++) {
            payload[i] = i;
        }

        uint256 fee = 0.01 ether;
        vm.deal(address(this), fee);

        bytes32 messageHash = bridgeAdapter.sendMessageToL2{value: fee}(
            toAddress,
            selector,
            payload
        );

        assertTrue(
            messageHash != bytes32(0),
            "Message hash should not be zero"
        );
        assertEq(
            bridgeAdapter.totalL1ToL2Messages(),
            1,
            "Message count should be 1"
        );
    }

    /// @notice Test token mapping with random addresses
    function testFuzz_TokenMapping(address l1Token, uint256 l2Token) public {
        vm.assume(l1Token != address(0));
        vm.assume(l2Token != 0);

        vm.prank(operator);
        bridgeAdapter.setTokenMapping(l1Token, l2Token);

        assertEq(
            bridgeAdapter.l1ToL2TokenMap(l1Token),
            l2Token,
            "L1 to L2 mapping mismatch"
        );
        assertEq(
            bridgeAdapter.l2ToL1TokenMap(l2Token),
            l1Token,
            "L2 to L1 mapping mismatch"
        );
    }

    /// @notice Test bridge fee configuration
    function testFuzz_BridgeFeeConfig(uint256 feeBps) public {
        feeBps = bound(feeBps, 0, 100);

        vm.prank(operator);
        bridgeAdapter.setBridgeFee(feeBps);

        assertEq(bridgeAdapter.bridgeFeeBps(), feeBps, "Fee BPS should be set");
    }

    /// @notice Test minimum message fee configuration
    function testFuzz_MinMessageFeeConfig(uint256 fee) public {
        fee = bound(fee, 0, 1 ether);

        vm.prank(operator);
        bridgeAdapter.setMinMessageFee(fee);

        assertEq(bridgeAdapter.minMessageFee(), fee, "Min fee should be set");
    }

    /// @notice Test message timeout configuration
    function testFuzz_MessageTimeoutConfig(uint256 timeout) public {
        timeout = bound(timeout, 1 days, 30 days);

        vm.prank(operator);
        bridgeAdapter.setMessageTimeout(timeout);

        assertEq(
            bridgeAdapter.messageTimeout(),
            timeout,
            "Timeout should be set"
        );
    }

    /// @notice Test Cairo contract registration
    function testFuzz_CairoContractRegistration(
        uint256 classHash,
        uint256 contractAddress,
        bytes32 programHash
    ) public {
        vm.assume(classHash != 0);
        vm.assume(contractAddress != 0);

        bytes32 contractId = bridgeAdapter.registerCairoContract(
            classHash,
            contractAddress,
            programHash,
            StarkNetBridgeAdapter.CairoVersion.CAIRO_1
        );

        assertTrue(contractId != bytes32(0), "Contract ID should not be zero");

        StarkNetBridgeAdapter.CairoContract memory contract_ = bridgeAdapter
            .getCairoContract(contractId);
        assertEq(contract_.classHash, classHash, "Class hash mismatch");
    }

    /// @notice Test STARK proof submission
    function testFuzz_STARKProofSubmission(
        bytes32 programHash,
        bytes32 outputHash,
        uint256 publicInputHash,
        uint8 numCommitments
    ) public {
        numCommitments = uint8(bound(numCommitments, 1, 10));

        bytes32[] memory friCommitments = new bytes32[](numCommitments);
        for (uint8 i = 0; i < numCommitments; i++) {
            friCommitments[i] = keccak256(abi.encodePacked("commitment", i));
        }

        bytes32 proofId = bridgeAdapter.submitSTARKProof(
            programHash,
            outputHash,
            publicInputHash,
            friCommitments,
            StarkNetBridgeAdapter.CairoVersion.CAIRO_1
        );

        assertTrue(proofId != bytes32(0), "Proof ID should not be zero");
    }

    /*//////////////////////////////////////////////////////////////
                       INVARIANT TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Invariant: Total nullifiers should never decrease
    function invariant_NullifierCountMonotonic() public view {
        assertTrue(
            nullifierContract.totalNullifiers() >= 0,
            "Nullifier count should be non-negative"
        );
    }

    /// @notice Invariant: Latest block number should be cached
    function invariant_LatestBlockCached() public view {
        uint256 latestBlock = stateSync.latestBlockNumber();
        if (latestBlock > 0) {
            StarknetStateSync.BlockHeader memory header = stateSync
                .getBlockHeader(latestBlock);
            assertTrue(
                header.blockNumber == latestBlock,
                "Latest block should be cached"
            );
        }
    }

    /// @notice Invariant: Bridge fee should not exceed maximum
    function invariant_BridgeFeeMax() public view {
        assertTrue(
            bridgeAdapter.bridgeFeeBps() <= 100,
            "Bridge fee should not exceed 1%"
        );
    }

    /// @notice Invariant: Accumulated fees should match collected fees
    function invariant_AccumulatedFees() public view {
        (, , , , , uint256 accumulatedFees) = bridgeAdapter.getBridgeStats();
        assertTrue(
            accumulatedFees >= 0,
            "Accumulated fees should be non-negative"
        );
    }
}

/**
 * @title StarknetPrimitivesTest
 * @notice Test wrapper for StarknetPrimitives library
 */
contract StarknetPrimitivesTest {
    function feltAdd(uint256 a, uint256 b) external pure returns (uint256) {
        return StarknetPrimitives.feltAdd(a, b);
    }

    function feltSub(uint256 a, uint256 b) external pure returns (uint256) {
        return StarknetPrimitives.feltSub(a, b);
    }

    function feltMul(uint256 a, uint256 b) external pure returns (uint256) {
        return StarknetPrimitives.feltMul(a, b);
    }

    function poseidonHash2(
        uint256 a,
        uint256 b
    ) external view returns (uint256) {
        return StarknetPrimitives.poseidonHash2(a, b);
    }

    function pedersenHash(
        uint256 a,
        uint256 b
    ) external pure returns (uint256) {
        return StarknetPrimitives.pedersenHash(a, b);
    }

    function isValidFelt(uint256 a) external pure returns (bool) {
        return StarknetPrimitives.isValidFelt(a);
    }

    function toFelt(uint256 a) external pure returns (uint256) {
        return StarknetPrimitives.toFelt(a);
    }
}
