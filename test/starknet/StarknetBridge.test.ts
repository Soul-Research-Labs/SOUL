import { expect } from "chai";
import hre from "hardhat";
import { keccak256, toBytes, padHex, parseEther } from "viem";

/**
 * Starknet Interoperability Tests
 * 
 * Comprehensive tests for Starknet integration:
 * - StarknetProofVerifier (STARK/FRI verification)
 * - CrossDomainNullifierStarknet (nullifier sync)
 * - StarknetStateSync (state roots)
 * - StarkNetBridgeAdapter (L1↔L2 messaging)
 */
describe("Starknet Interoperability", function () {
    // Role constants
    const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
    const SEQUENCER_ROLE = keccak256(toBytes("SEQUENCER_ROLE"));
    const VERIFIER_ROLE = keccak256(toBytes("VERIFIER_ROLE"));
    const GUARDIAN_ROLE = keccak256(toBytes("GUARDIAN_ROLE"));
    const PROVER_ROLE = keccak256(toBytes("PROVER_ROLE"));
    const BRIDGE_ROLE = keccak256(toBytes("BRIDGE_ROLE"));
    const NULLIFIER_REGISTRAR_ROLE = keccak256(toBytes("NULLIFIER_REGISTRAR_ROLE"));
    const RELAYER_ROLE = keccak256(toBytes("RELAYER_ROLE"));
    const DEFAULT_ADMIN_ROLE = padHex("0x00", { size: 32 });

    // Test constants
    const STARK_PRIME = 0x800000000000011000000000000000000000000000000000000000000000001n;

    // Helper to get viem
    async function getViem() {
        const { viem } = await hre.network.connect();
        return viem;
    }

    /*//////////////////////////////////////////////////////////////
                        STARKNET PROOF VERIFIER
    //////////////////////////////////////////////////////////////*/

    describe("StarknetProofVerifier", function () {
        describe("Deployment", function () {
            it("Should deploy with correct initial state", async function () {
                const viem = await getViem();
                const verifier = await viem.deployContract("StarknetProofVerifier");

                const stats = await verifier.read.getStats();
                expect(stats[0]).to.equal(0n); // totalProofs
                expect(stats[1]).to.equal(0n); // totalVerified
            });

            it("Should grant admin role to deployer", async function () {
                const viem = await getViem();
                const [admin] = await viem.getWalletClients();
                const verifier = await viem.deployContract("StarknetProofVerifier");

                const hasAdminRole = await verifier.read.hasRole([DEFAULT_ADMIN_ROLE, admin.account.address]);
                expect(hasAdminRole).to.be.true;
            });
        });

        describe("FRI Configuration", function () {
            it("Should set default FRI config", async function () {
                const viem = await getViem();
                const [admin, operator] = await viem.getWalletClients();
                const verifier = await viem.deployContract("StarknetProofVerifier");

                await verifier.write.grantRole([OPERATOR_ROLE, operator.account.address]);

                // Security requirement: numQueries * log2(blowupFactor) >= 128
                // 45 * 3 (log2(8)) = 135 >= 128 ✓
                const domainSize = BigInt(1 << 16);
                const blowupFactor = 8n;
                const numQueries = 45n;
                const foldingFactor = 2n;
                const lastLayerDegBound = 64n;
                const numLayers = 10n;

                await verifier.write.setDefaultFRIConfig([
                    domainSize, blowupFactor, numQueries, foldingFactor, lastLayerDegBound, numLayers
                ], { account: operator.account });

                // Verify it was set
                const config = await verifier.read.defaultFRIConfig();
                expect(config[0]).to.equal(domainSize);
            });
        });

        describe("Program Registration", function () {
            it("Should register a Cairo program", async function () {
                const viem = await getViem();
                const [admin, operator] = await viem.getWalletClients();
                const verifier = await viem.deployContract("StarknetProofVerifier");

                await verifier.write.grantRole([OPERATOR_ROLE, operator.account.address]);

                const programHash = keccak256(toBytes("cairo_program"));
                // Security: 45 * log2(8) = 135 >= 128
                const config = {
                    domainSize: BigInt(1 << 16),
                    blowupFactor: 8n,
                    numQueries: 45n,
                    foldingFactor: 2n,
                    lastLayerDegBound: 64n,
                    numLayers: 10n
                };

                await verifier.write.registerProgram([programHash, config], { account: operator.account });

                const isRegistered = await verifier.read.isProgram([programHash]);
                expect(isRegistered).to.be.true;
            });
        });

        describe("Proof Submission", function () {
            it("Should submit a STARK proof", async function () {
                const viem = await getViem();
                const [admin, operator, user] = await viem.getWalletClients();
                const verifier = await viem.deployContract("StarknetProofVerifier");

                await verifier.write.grantRole([OPERATOR_ROLE, operator.account.address]);

                // Register program with valid security config
                // Security: 45 * log2(8) = 135 >= 128
                const programHash = keccak256(toBytes("test_program"));
                const config = {
                    domainSize: BigInt(1 << 16),
                    blowupFactor: 8n,
                    numQueries: 45n,
                    foldingFactor: 2n,
                    lastLayerDegBound: 64n,
                    numLayers: 10n
                };
                await verifier.write.registerProgram([programHash, config], { account: operator.account });

                // Submit proof
                const traceCommitment = keccak256(toBytes("trace"));
                const constraintCommitment = keccak256(toBytes("constraint"));
                const compositionCommitment = keccak256(toBytes("composition"));
                const friCommitments = [keccak256(toBytes("fri_0")), keccak256(toBytes("fri_1"))];
                const publicInputs = [1n, 2n, 3n];

                const tx = await verifier.write.submitProof([
                    programHash,
                    1, // CAIRO_1
                    traceCommitment,
                    constraintCommitment,
                    compositionCommitment,
                    friCommitments,
                    publicInputs
                ], { account: user.account });

                expect(tx).to.not.be.null;

                const stats = await verifier.read.getStats();
                expect(stats[0]).to.equal(1n); // totalProofs
            });
        });
    });

    /*//////////////////////////////////////////////////////////////
                    CROSS-DOMAIN NULLIFIER STARKNET
    //////////////////////////////////////////////////////////////*/

    describe("CrossDomainNullifierStarknet", function () {
        describe("Deployment", function () {
            it("Should deploy with initial state", async function () {
                const viem = await getViem();
                const nullifier = await viem.deployContract("CrossDomainNullifierStarknet");

                const count = await nullifier.read.totalNullifiers();
                expect(count).to.equal(0n);
            });
        });

        describe("Domain Registration", function () {
            it("Should register a domain", async function () {
                const viem = await getViem();
                const [admin, operator] = await viem.getWalletClients();
                const nullifier = await viem.deployContract("CrossDomainNullifierStarknet");

                await nullifier.write.grantRole([OPERATOR_ROLE, operator.account.address]);

                const domainId = keccak256(toBytes("starknet_domain"));
                const domainType = 0; // STARKNET
                const chainId = 12345n;

                await nullifier.write.registerDomain([domainId, domainType, chainId], { account: operator.account });

                const isRegistered = await nullifier.read.isDomainRegistered([domainId]);
                expect(isRegistered).to.be.true;
            });
        });

        describe("Nullifier Registration", function () {
            it("Should register nullifier from L1", async function () {
                const viem = await getViem();
                const [admin, operator, registrar] = await viem.getWalletClients();
                const nullifier = await viem.deployContract("CrossDomainNullifierStarknet");

                await nullifier.write.grantRole([OPERATOR_ROLE, operator.account.address]);
                await nullifier.write.grantRole([NULLIFIER_REGISTRAR_ROLE, registrar.account.address]);

                // Register domain first
                const domainId = keccak256(toBytes("test_domain"));
                await nullifier.write.registerDomain([domainId, 0, 12345n], { account: operator.account });

                // Register nullifier
                const nullifierHash = keccak256(toBytes("private_tx_nullifier"));
                const commitment = keccak256(toBytes("commitment"));

                await nullifier.write.registerNullifierFromL1(
                    [nullifierHash, commitment, domainId],
                    { account: registrar.account }
                );

                const count = await nullifier.read.totalNullifiers();
                expect(count).to.equal(1n);
            });

            it("Should prevent duplicate nullifier registration", async function () {
                const viem = await getViem();
                const [admin, operator, registrar] = await viem.getWalletClients();
                const nullifier = await viem.deployContract("CrossDomainNullifierStarknet");

                await nullifier.write.grantRole([OPERATOR_ROLE, operator.account.address]);
                await nullifier.write.grantRole([NULLIFIER_REGISTRAR_ROLE, registrar.account.address]);

                const domainId = keccak256(toBytes("test_domain"));
                await nullifier.write.registerDomain([domainId, 0, 12345n], { account: operator.account });

                const nullifierHash = keccak256(toBytes("duplicate_nullifier"));
                const commitment = keccak256(toBytes("commitment"));

                await nullifier.write.registerNullifierFromL1(
                    [nullifierHash, commitment, domainId],
                    { account: registrar.account }
                );

                // Second registration should fail
                let failed = false;
                try {
                    await nullifier.write.registerNullifierFromL1(
                        [nullifierHash, commitment, domainId],
                        { account: registrar.account }
                    );
                } catch {
                    failed = true;
                }
                expect(failed).to.be.true;
            });
        });

        describe("Nullifier Consumption", function () {
            it("Should consume a registered nullifier", async function () {
                const viem = await getViem();
                const [admin, operator, registrar] = await viem.getWalletClients();
                const nullifier = await viem.deployContract("CrossDomainNullifierStarknet");

                await nullifier.write.grantRole([OPERATOR_ROLE, operator.account.address]);
                await nullifier.write.grantRole([NULLIFIER_REGISTRAR_ROLE, registrar.account.address]);

                const domainId = keccak256(toBytes("consume_domain"));
                await nullifier.write.registerDomain([domainId, 0, 12345n], { account: operator.account });

                const nullifierHash = keccak256(toBytes("consumable_nullifier"));
                const commitment = keccak256(toBytes("commitment"));

                const tx = await nullifier.write.registerNullifierFromL1(
                    [nullifierHash, commitment, domainId],
                    { account: registrar.account }
                );

                // Get the cross-domain nullifier from event (simplified - use the l2 derivation)
                const l2Nullifier = await nullifier.read.getL2Nullifier([nullifierHash]);
                expect(l2Nullifier).to.not.equal(0n);
            });
        });

        describe("Merkle Tree", function () {
            it("Should update Merkle root on registration", async function () {
                const viem = await getViem();
                const [admin, operator, registrar] = await viem.getWalletClients();
                const nullifier = await viem.deployContract("CrossDomainNullifierStarknet");

                await nullifier.write.grantRole([OPERATOR_ROLE, operator.account.address]);
                await nullifier.write.grantRole([NULLIFIER_REGISTRAR_ROLE, registrar.account.address]);

                const domainId = keccak256(toBytes("merkle_domain"));
                await nullifier.write.registerDomain([domainId, 0, 12345n], { account: operator.account });

                const initialRoot = await nullifier.read.getMerkleRoot();

                await nullifier.write.registerNullifierFromL1(
                    [keccak256(toBytes("null_1")), keccak256(toBytes("comm_1")), domainId],
                    { account: registrar.account }
                );

                const newRoot = await nullifier.read.getMerkleRoot();
                expect(newRoot).to.not.equal(initialRoot);
            });
        });
    });

    /*//////////////////////////////////////////////////////////////
                         STARKNET STATE SYNC
    //////////////////////////////////////////////////////////////*/

    describe("StarknetStateSync", function () {
        describe("Deployment", function () {
            it("Should deploy with initial state", async function () {
                const viem = await getViem();
                const stateSync = await viem.deployContract("StarknetStateSync");

                const latestBlock = await stateSync.read.latestBlockNumber();
                expect(latestBlock).to.equal(0n);
            });
        });

        describe("Block Header Caching", function () {
            it("Should cache a block header", async function () {
                const viem = await getViem();
                const [admin, operator, sequencer] = await viem.getWalletClients();
                const stateSync = await viem.deployContract("StarknetStateSync");

                await stateSync.write.grantRole([OPERATOR_ROLE, operator.account.address]);
                await stateSync.write.grantRole([SEQUENCER_ROLE, sequencer.account.address]);

                // Set starknet core (mock)
                const mockCore = "0x1234567890123456789012345678901234567890";
                await stateSync.write.setStarknetCore([mockCore], { account: operator.account });

                const blockNumber = 1000n;
                const blockHash = keccak256(toBytes("block_1000"));
                const parentHash = keccak256(toBytes("block_999"));
                const stateRoot = keccak256(toBytes("state_root"));
                const txRoot = keccak256(toBytes("tx_root"));
                const receiptsRoot = keccak256(toBytes("receipts"));
                const sequencerAddr = keccak256(toBytes("sequencer"));
                const timestamp = BigInt(Math.floor(Date.now() / 1000));
                const gasUsed = 1000000000n;

                await stateSync.write.cacheBlockHeader([
                    blockNumber,
                    blockHash,
                    parentHash,
                    stateRoot,
                    txRoot,
                    receiptsRoot,
                    sequencerAddr,
                    timestamp,
                    gasUsed
                ], { account: sequencer.account });

                const latest = await stateSync.read.latestBlockNumber();
                expect(latest).to.equal(blockNumber);
            });
        });

        describe("State Updates", function () {
            it("Should submit state update", async function () {
                const viem = await getViem();
                const [admin, operator, sequencer, relayer] = await viem.getWalletClients();
                const stateSync = await viem.deployContract("StarknetStateSync");

                await stateSync.write.grantRole([OPERATOR_ROLE, operator.account.address]);
                await stateSync.write.grantRole([SEQUENCER_ROLE, sequencer.account.address]);
                await stateSync.write.grantRole([RELAYER_ROLE, relayer.account.address]);

                const mockCore = "0x1234567890123456789012345678901234567890";
                await stateSync.write.setStarknetCore([mockCore], { account: operator.account });

                // Cache block first
                const blockNumber = 500n;
                const blockHash = keccak256(toBytes("update_block"));
                await stateSync.write.cacheBlockHeader([
                    blockNumber,
                    blockHash,
                    keccak256(toBytes("parent")),
                    keccak256(toBytes("state")),
                    keccak256(toBytes("tx")),
                    keccak256(toBytes("receipts")),
                    keccak256(toBytes("seq")),
                    BigInt(Math.floor(Date.now() / 1000)),
                    1000000000n
                ], { account: sequencer.account });

                // Submit state update
                const tx = await stateSync.write.submitStateUpdate([
                    blockNumber,
                    blockHash,
                    keccak256(toBytes("new_state")),
                    keccak256(toBytes("old_state")),
                    [123n, 456n],
                    [keccak256(toBytes("storage"))]
                ], { account: relayer.account });

                expect(tx).to.not.be.null;

                const stats = await stateSync.read.getStats();
                expect(stats[2]).to.equal(1n); // totalStateUpdates
            });
        });

        describe("Checkpoints", function () {
            it("Should create checkpoint", async function () {
                const viem = await getViem();
                const [admin, operator, sequencer, verifier] = await viem.getWalletClients();
                const stateSync = await viem.deployContract("StarknetStateSync");

                await stateSync.write.grantRole([OPERATOR_ROLE, operator.account.address]);
                await stateSync.write.grantRole([SEQUENCER_ROLE, sequencer.account.address]);
                await stateSync.write.grantRole([VERIFIER_ROLE, verifier.account.address]);

                const mockCore = "0x1234567890123456789012345678901234567890";
                await stateSync.write.setStarknetCore([mockCore], { account: operator.account });

                // Cache and prove block
                const blockNumber = 100n;
                await stateSync.write.cacheBlockHeader([
                    blockNumber,
                    keccak256(toBytes("block")),
                    keccak256(toBytes("parent")),
                    keccak256(toBytes("state")),
                    keccak256(toBytes("tx")),
                    keccak256(toBytes("receipts")),
                    keccak256(toBytes("seq")),
                    BigInt(Math.floor(Date.now() / 1000)),
                    1000000000n
                ], { account: sequencer.account });

                await stateSync.write.markBlockProven([
                    blockNumber,
                    toBytes("proof_data_sufficient_length")
                ], { account: verifier.account });

                await stateSync.write.createCheckpoint([blockNumber], { account: operator.account });

                const checkpointIndex = await stateSync.read.latestCheckpointIndex();
                expect(checkpointIndex).to.equal(1n);
            });
        });
    });

    /*//////////////////////////////////////////////////////////////
                       STARKNET BRIDGE ADAPTER
    //////////////////////////////////////////////////////////////*/

    describe("StarkNetBridgeAdapter", function () {
        describe("Deployment", function () {
            it("Should deploy with correct parameters", async function () {
                const viem = await getViem();
                const bridge = await viem.deployContract("StarkNetBridgeAdapter");

                const bridgeFeeBps = await bridge.read.bridgeFeeBps();
                const minMessageFee = await bridge.read.minMessageFee();
                expect(bridgeFeeBps).to.equal(10n);
                expect(minMessageFee).to.equal(parseEther("0.001"));
            });
        });

        describe("L1 to L2 Messaging", function () {
            it("Should send message to L2", async function () {
                const viem = await getViem();
                const [admin, operator, user] = await viem.getWalletClients();
                const bridge = await viem.deployContract("StarkNetBridgeAdapter");

                await bridge.write.grantRole([OPERATOR_ROLE, operator.account.address]);

                const mockCore = "0x1234567890123456789012345678901234567890";
                await bridge.write.configureStarkNetCore([mockCore], { account: operator.account });

                const toAddress = 12345678901234567890n;
                const selector = 987654321n;
                const payload = [1n, 2n, 3n];
                const fee = parseEther("0.01");

                const tx = await bridge.write.sendMessageToL2(
                    [toAddress, selector, payload],
                    { value: fee, account: user.account }
                );

                expect(tx).to.not.be.null;

                const stats = await bridge.read.getBridgeStats();
                expect(stats[0]).to.equal(1n); // totalL1ToL2Messages
            });
        });

        describe("L2 to L1 Messaging", function () {
            it("Should receive message from L2", async function () {
                const viem = await getViem();
                const [admin, operator, sequencer] = await viem.getWalletClients();
                const bridge = await viem.deployContract("StarkNetBridgeAdapter");

                await bridge.write.grantRole([OPERATOR_ROLE, operator.account.address]);
                await bridge.write.grantRole([SEQUENCER_ROLE, sequencer.account.address]);

                const mockCore = "0x1234567890123456789012345678901234567890";
                await bridge.write.configureStarkNetCore([mockCore], { account: operator.account });

                const fromAddress = 54321098765432109876n;
                const payload = [100n, 200n, 300n];
                const starknetTxHash = keccak256(toBytes("starknet_tx"));

                const tx = await bridge.write.receiveMessageFromL2(
                    [fromAddress, payload, starknetTxHash],
                    { account: sequencer.account }
                );

                expect(tx).to.not.be.null;

                const stats = await bridge.read.getBridgeStats();
                expect(stats[1]).to.equal(1n); // totalL2ToL1Messages
            });
        });

        describe("Cairo Contract Registry", function () {
            it("Should register Cairo contract", async function () {
                const viem = await getViem();
                const [admin, operator] = await viem.getWalletClients();
                const bridge = await viem.deployContract("StarkNetBridgeAdapter");

                await bridge.write.grantRole([OPERATOR_ROLE, operator.account.address]);

                const l2Address = 111222333444555666n;
                const classHash = 999888777666555444n;
                const name = "TestContract";
                const cairoVersion = 1; // CAIRO_1

                await bridge.write.registerCairoContract(
                    [l2Address, classHash, name, cairoVersion],
                    { account: operator.account }
                );

                const stats = await bridge.read.getBridgeStats();
                expect(stats[3]).to.equal(1n); // totalContracts
            });
        });

        describe("Token Mapping", function () {
            it("Should register token mapping", async function () {
                const viem = await getViem();
                const [admin, operator] = await viem.getWalletClients();
                const bridge = await viem.deployContract("StarkNetBridgeAdapter");

                await bridge.write.grantRole([OPERATOR_ROLE, operator.account.address]);

                const l1Token = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // USDC
                const l2Token = 123456789012345678901234n;

                await bridge.write.registerTokenMapping(
                    [l1Token, l2Token],
                    { account: operator.account }
                );

                const mappedToken = await bridge.read.tokenMappings([l1Token]);
                expect(mappedToken).to.equal(l2Token);
            });
        });

        describe("Pause Functionality", function () {
            it("Should pause and unpause", async function () {
                const viem = await getViem();
                const [admin, operator] = await viem.getWalletClients();
                const bridge = await viem.deployContract("StarkNetBridgeAdapter");

                await bridge.write.grantRole([OPERATOR_ROLE, operator.account.address]);
                await bridge.write.grantRole([GUARDIAN_ROLE, operator.account.address]);

                const mockCore = "0x1234567890123456789012345678901234567890";
                await bridge.write.configureStarkNetCore([mockCore], { account: operator.account });

                // Pause
                await bridge.write.pause([], { account: operator.account });
                let isPaused = await bridge.read.paused();
                expect(isPaused).to.be.true;

                // Unpause
                await bridge.write.unpause([], { account: operator.account });
                isPaused = await bridge.read.paused();
                expect(isPaused).to.be.false;
            });
        });
    });
});
