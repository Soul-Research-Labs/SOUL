import { expect } from "chai";
import hre from "hardhat";
import { parseEther, keccak256, toBytes, toHex, padHex, type Address } from "viem";

/**
 * Base Bridge Adapter Tests
 * 
 * Tests Base L2 integration including:
 * - CrossDomainMessenger configuration
 * - Proof relay to L2
 * - CCTP USDC transfers
 * - Coinbase attestation sync
 * - Withdrawal initiation and completion
 * - State synchronization
 * - Security controls
 */
describe("BaseBridgeAdapter", function () {
    // Role constants
    const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
    const GUARDIAN_ROLE = keccak256(toBytes("GUARDIAN_ROLE"));
    const EXECUTOR_ROLE = keccak256(toBytes("EXECUTOR_ROLE"));
    const CCTP_ROLE = keccak256(toBytes("CCTP_ROLE"));
    const DEFAULT_ADMIN_ROLE = padHex("0x00", { size: 32 });

    // Chain IDs
    const BASE_MAINNET_CHAIN_ID = 8453n;
    const BASE_SEPOLIA_CHAIN_ID = 84532n;
    const ETH_MAINNET_CHAIN_ID = 1n;
    const ETH_SEPOLIA_CHAIN_ID = 11155111n;
    const WITHDRAWAL_PERIOD = 604800n; // 7 days

    // CCTP domains
    const CCTP_ETH_DOMAIN = 0;
    const CCTP_BASE_DOMAIN = 6;

    // Test data
    const testProofHash = keccak256(toBytes("test-proof-hash"));
    const testProof = toHex("test-proof-data");
    const testPublicInputs = toHex("test-public-inputs");
    const testStateRoot = keccak256(toBytes("test-state-root"));
    const testAttestationId = keccak256(toBytes("test-attestation-id"));
    const testSchemaId = keccak256(toBytes("test-schema-id"));

    async function getViem() {
        // @ts-expect-error - Hardhat 3 viem integration
        const { viem } = await hre.network.connect();
        return viem;
    }

    async function deployAdapter(isL1: boolean = true) {
        const viem = await getViem();
        const [admin] = await viem.getWalletClients();
        
        const mockAddress = admin.account.address; // Use admin as mock
        
        const adapter = await viem.deployContract("BaseBridgeAdapter", [
            admin.account.address,  // admin
            mockAddress,            // l1CrossDomainMessenger
            mockAddress,            // l2CrossDomainMessenger
            mockAddress,            // basePortal
            isL1                    // isL1
        ]);
        
        return { adapter, admin, viem };
    }

    /*//////////////////////////////////////////////////////////////
                            DEPLOYMENT
    //////////////////////////////////////////////////////////////*/

    describe("Deployment", function () {
        it("Should deploy with correct initial state", async function () {
            const { adapter } = await deployAdapter(true);

            const isL1 = await adapter.read.isL1();
            expect(isL1).to.be.true;
        });

        it("Should deploy as L2 adapter", async function () {
            const { adapter } = await deployAdapter(false);

            const isL1 = await adapter.read.isL1();
            expect(isL1).to.be.false;
        });

        it("Should grant admin role to deployer", async function () {
            const { adapter, admin } = await deployAdapter();

            const hasRole = await adapter.read.hasRole([DEFAULT_ADMIN_ROLE, admin.account.address]);
            expect(hasRole).to.be.true;
        });

        it("Should grant operator role to deployer", async function () {
            const { adapter, admin } = await deployAdapter();

            const hasRole = await adapter.read.hasRole([OPERATOR_ROLE, admin.account.address]);
            expect(hasRole).to.be.true;
        });

        it("Should grant guardian role to deployer", async function () {
            const { adapter, admin } = await deployAdapter();

            const hasRole = await adapter.read.hasRole([GUARDIAN_ROLE, admin.account.address]);
            expect(hasRole).to.be.true;
        });

        it("Should start with zero counters", async function () {
            const { adapter } = await deployAdapter();

            const stats = await adapter.read.getStats();
            expect(stats[0]).to.equal(0n); // messagesSent
            expect(stats[1]).to.equal(0n); // messagesReceived
            expect(stats[2]).to.equal(0n); // valueBridged
            expect(stats[3]).to.equal(0n); // usdcBridged
            expect(stats[4]).to.equal(0n); // currentNonce
        });

        it("Should set messenger addresses correctly", async function () {
            const { adapter, admin } = await deployAdapter();

            const l1Messenger = await adapter.read.l1CrossDomainMessenger();
            const l2Messenger = await adapter.read.l2CrossDomainMessenger();
            
            expect(l1Messenger.toLowerCase()).to.equal(admin.account.address.toLowerCase());
            expect(l2Messenger.toLowerCase()).to.equal(admin.account.address.toLowerCase());
        });
    });

    /*//////////////////////////////////////////////////////////////
                           CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    describe("Configuration", function () {
        it("Should set L2 target", async function () {
            const { adapter, viem } = await deployAdapter();
            const [_, other] = await viem.getWalletClients();

            await adapter.write.setL2Target([other.account.address]);

            const l2Target = await adapter.read.l2Target();
            expect(l2Target.toLowerCase()).to.equal(other.account.address.toLowerCase());
        });

        it("Should configure CCTP", async function () {
            const { adapter, viem } = await deployAdapter();
            const [_, tokenMessenger, usdc] = await viem.getWalletClients();

            await adapter.write.configureCCTP([
                tokenMessenger.account.address,
                usdc.account.address
            ]);

            const cctpMessenger = await adapter.read.cctpTokenMessenger();
            const usdcToken = await adapter.read.usdcToken();
            
            expect(cctpMessenger.toLowerCase()).to.equal(tokenMessenger.account.address.toLowerCase());
            expect(usdcToken.toLowerCase()).to.equal(usdc.account.address.toLowerCase());
        });

        it("Should emit CCTPConfigured event", async function () {
            const { adapter, viem } = await deployAdapter();
            const [_, tokenMessenger, usdc] = await viem.getWalletClients();
            const publicClient = await viem.getPublicClient();

            const hash = await adapter.write.configureCCTP([
                tokenMessenger.account.address,
                usdc.account.address
            ]);
            const receipt = await publicClient.waitForTransactionReceipt({ hash });

            expect(receipt.logs.length).to.be.greaterThan(0);
        });

        it("Should update L1 messenger", async function () {
            const { adapter, viem } = await deployAdapter();
            const [_, other] = await viem.getWalletClients();

            await adapter.write.setMessenger([other.account.address, true]);

            const l1Messenger = await adapter.read.l1CrossDomainMessenger();
            expect(l1Messenger.toLowerCase()).to.equal(other.account.address.toLowerCase());
        });

        it("Should update L2 messenger", async function () {
            const { adapter, viem } = await deployAdapter();
            const [_, other] = await viem.getWalletClients();

            await adapter.write.setMessenger([other.account.address, false]);

            const l2Messenger = await adapter.read.l2CrossDomainMessenger();
            expect(l2Messenger.toLowerCase()).to.equal(other.account.address.toLowerCase());
        });

        it("Should reject non-admin setting L2 target", async function () {
            const { adapter, viem } = await deployAdapter();
            const [_, other] = await viem.getWalletClients();

            let reverted = false;
            try {
                await adapter.write.setL2Target([other.account.address], {
                    account: other.account
                });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                         PROOF RELAY (L1 -> L2)
    //////////////////////////////////////////////////////////////*/

    describe("Proof Relay", function () {
        it("Should send proof to L2", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);

            const hash = await adapter.write.sendProofToL2([
                testProofHash,
                testProof,
                testPublicInputs,
                1000000n
            ], { value: parseEther("0.01") });

            expect(hash).to.be.a("string");
        });

        it("Should increment message counter", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);

            const statsBefore = await adapter.read.getStats();
            
            await adapter.write.sendProofToL2([
                testProofHash,
                testProof,
                testPublicInputs,
                1000000n
            ], { value: parseEther("0.01") });

            const statsAfter = await adapter.read.getStats();
            expect(statsAfter[0]).to.equal(statsBefore[0] + 1n);
        });

        it("Should track value bridged", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);
            const bridgeValue = parseEther("0.05");

            await adapter.write.sendProofToL2([
                testProofHash,
                testProof,
                testPublicInputs,
                1000000n
            ], { value: bridgeValue });

            const stats = await adapter.read.getStats();
            expect(stats[2]).to.equal(bridgeValue);
        });

        it("Should reject if no L2 target set", async function () {
            const { adapter } = await deployAdapter(true);

            let reverted = false;
            try {
                await adapter.write.sendProofToL2([
                    testProofHash,
                    testProof,
                    testPublicInputs,
                    1000000n
                ], { value: parseEther("0.01") });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject insufficient gas limit", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);

            let reverted = false;
            try {
                await adapter.write.sendProofToL2([
                    testProofHash,
                    testProof,
                    testPublicInputs,
                    50000n // Below MIN_GAS_LIMIT
                ], { value: parseEther("0.01") });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject if called on L2 adapter", async function () {
            const { adapter, viem } = await deployAdapter(false);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);

            let reverted = false;
            try {
                await adapter.write.sendProofToL2([
                    testProofHash,
                    testProof,
                    testPublicInputs,
                    1000000n
                ], { value: parseEther("0.01") });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                         PROOF RECEIVING (L2)
    //////////////////////////////////////////////////////////////*/

    describe("Proof Receiving", function () {
        it("Should receive proof from L1", async function () {
            const { adapter } = await deployAdapter(false);

            const hash = await adapter.write.receiveProofFromL1([
                testProofHash,
                testProof,
                testPublicInputs,
                1n
            ]);

            expect(hash).to.be.a("string");
        });

        it("Should mark proof as relayed", async function () {
            const { adapter } = await deployAdapter(false);

            await adapter.write.receiveProofFromL1([
                testProofHash,
                testProof,
                testPublicInputs,
                1n
            ]);

            const isRelayed = await adapter.read.isProofRelayed([testProofHash]);
            expect(isRelayed).to.be.true;
        });

        it("Should reject duplicate proof relay", async function () {
            const { adapter } = await deployAdapter(false);

            await adapter.write.receiveProofFromL1([
                testProofHash,
                testProof,
                testPublicInputs,
                1n
            ]);

            let reverted = false;
            try {
                await adapter.write.receiveProofFromL1([
                    testProofHash,
                    testProof,
                    testPublicInputs,
                    1n
                ]);
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should increment received counter", async function () {
            const { adapter } = await deployAdapter(false);

            const statsBefore = await adapter.read.getStats();

            await adapter.write.receiveProofFromL1([
                testProofHash,
                testProof,
                testPublicInputs,
                1n
            ]);

            const statsAfter = await adapter.read.getStats();
            expect(statsAfter[1]).to.equal(statsBefore[1] + 1n);
        });
    });

    /*//////////////////////////////////////////////////////////////
                           CCTP TRANSFERS
    //////////////////////////////////////////////////////////////*/

    describe("CCTP USDC Transfers", function () {
        async function setupCCTP() {
            const { adapter, viem, admin } = await deployAdapter(true);
            const [_, tokenMessenger, usdc, recipient] = await viem.getWalletClients();

            // Configure CCTP
            await adapter.write.configureCCTP([
                tokenMessenger.account.address,
                usdc.account.address
            ]);

            // Grant CCTP role to admin
            await adapter.write.grantRole([CCTP_ROLE, admin.account.address]);

            return { adapter, viem, admin, tokenMessenger, usdc, recipient };
        }

        it("Should initiate USDC transfer", async function () {
            const { adapter, recipient } = await setupCCTP();

            const hash = await adapter.write.initiateUSDCTransfer([
                recipient.account.address,
                1000000n, // 1 USDC (6 decimals)
                CCTP_BASE_DOMAIN
            ]);

            expect(hash).to.be.a("string");
        });

        it("Should track USDC bridged", async function () {
            const { adapter, recipient } = await setupCCTP();

            const amount = 1000000n;
            await adapter.write.initiateUSDCTransfer([
                recipient.account.address,
                amount,
                CCTP_BASE_DOMAIN
            ]);

            const stats = await adapter.read.getStats();
            expect(stats[3]).to.equal(amount); // usdcBridged
        });

        it("Should reject zero amount", async function () {
            const { adapter, recipient } = await setupCCTP();

            let reverted = false;
            try {
                await adapter.write.initiateUSDCTransfer([
                    recipient.account.address,
                    0n,
                    CCTP_BASE_DOMAIN
                ]);
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject if CCTP not configured", async function () {
            const { adapter, viem, admin } = await deployAdapter(true);
            const [_, recipient] = await viem.getWalletClients();

            // Grant CCTP role but don't configure CCTP
            await adapter.write.grantRole([CCTP_ROLE, admin.account.address]);

            let reverted = false;
            try {
                await adapter.write.initiateUSDCTransfer([
                    recipient.account.address,
                    1000000n,
                    CCTP_BASE_DOMAIN
                ]);
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject non-CCTP role caller", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [_, tokenMessenger, usdc, other] = await viem.getWalletClients();

            await adapter.write.configureCCTP([
                tokenMessenger.account.address,
                usdc.account.address
            ]);

            let reverted = false;
            try {
                await adapter.write.initiateUSDCTransfer([
                    other.account.address,
                    1000000n,
                    CCTP_BASE_DOMAIN
                ], { account: other.account });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                       ATTESTATION SYNC
    //////////////////////////////////////////////////////////////*/

    describe("Attestation Sync", function () {
        it("Should sync attestation", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, subject] = await viem.getWalletClients();

            const attestationData = toHex("attestation-data");

            const hash = await adapter.write.syncAttestation([
                testAttestationId,
                subject.account.address,
                testSchemaId,
                attestationData
            ]);

            expect(hash).to.be.a("string");
        });

        it("Should store attestation correctly", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, subject] = await viem.getWalletClients();

            const attestationData = toHex("attestation-data");

            await adapter.write.syncAttestation([
                testAttestationId,
                subject.account.address,
                testSchemaId,
                attestationData
            ]);

            const attestation = await adapter.read.getAttestation([testAttestationId]);
            expect(attestation.attestationId).to.equal(testAttestationId);
            expect(attestation.subject.toLowerCase()).to.equal(subject.account.address.toLowerCase());
            expect(attestation.schemaId).to.equal(testSchemaId);
            expect(attestation.synced).to.be.true;
        });

        it("Should emit AttestationSynced event", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, subject] = await viem.getWalletClients();
            const publicClient = await viem.getPublicClient();

            const attestationData = toHex("attestation-data");

            const hash = await adapter.write.syncAttestation([
                testAttestationId,
                subject.account.address,
                testSchemaId,
                attestationData
            ]);
            
            const receipt = await publicClient.waitForTransactionReceipt({ hash });
            expect(receipt.logs.length).to.be.greaterThan(0);
        });

        it("Should reject non-operator attestation sync", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [_, other, subject] = await viem.getWalletClients();

            const attestationData = toHex("attestation-data");

            let reverted = false;
            try {
                await adapter.write.syncAttestation([
                    testAttestationId,
                    subject.account.address,
                    testSchemaId,
                    attestationData
                ], { account: other.account });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                            WITHDRAWALS
    //////////////////////////////////////////////////////////////*/

    describe("Withdrawals", function () {
        it("Should initiate withdrawal from L2", async function () {
            const { adapter } = await deployAdapter(false);

            const hash = await adapter.write.initiateWithdrawal([testProofHash], {
                value: parseEther("0.1")
            });

            expect(hash).to.be.a("string");
        });

        it("Should reject withdrawal initiation on L1", async function () {
            const { adapter } = await deployAdapter(true);

            let reverted = false;
            try {
                await adapter.write.initiateWithdrawal([testProofHash], {
                    value: parseEther("0.1")
                });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                          STATE SYNC
    //////////////////////////////////////////////////////////////*/

    describe("State Sync", function () {
        it("Should sync state to L2", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);

            const hash = await adapter.write.syncStateToL2([
                testStateRoot,
                100n,
                500000n
            ]);

            expect(hash).to.be.a("string");
        });

        it("Should receive state from L1", async function () {
            const { adapter } = await deployAdapter(false);

            await adapter.write.receiveStateFromL1([
                testStateRoot,
                100n
            ]);

            // State sync increments received counter
            const stats = await adapter.read.getStats();
            expect(stats[1] > 0n).to.be.true;
        });

        it("Should reject state sync on L2 adapter", async function () {
            const { adapter, viem } = await deployAdapter(false);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);

            let reverted = false;
            try {
                await adapter.write.syncStateToL2([
                    testStateRoot,
                    100n,
                    500000n
                ]);
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                         PAUSE / UNPAUSE
    //////////////////////////////////////////////////////////////*/

    describe("Pause Controls", function () {
        it("Should pause adapter", async function () {
            const { adapter } = await deployAdapter();

            await adapter.write.pause();

            const isPaused = await adapter.read.paused();
            expect(isPaused).to.be.true;
        });

        it("Should unpause adapter", async function () {
            const { adapter } = await deployAdapter();

            await adapter.write.pause();
            await adapter.write.unpause();

            const isPaused = await adapter.read.paused();
            expect(isPaused).to.be.false;
        });

        it("Should reject operations when paused", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);
            await adapter.write.pause();

            let reverted = false;
            try {
                await adapter.write.sendProofToL2([
                    testProofHash,
                    testProof,
                    testPublicInputs,
                    1000000n
                ], { value: parseEther("0.01") });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject non-guardian pause", async function () {
            const { adapter, viem } = await deployAdapter();
            const [_, other] = await viem.getWalletClients();

            let reverted = false;
            try {
                await adapter.write.pause({ account: other.account });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                        EMERGENCY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    describe("Emergency Functions", function () {
        it("Should emergency withdraw", async function () {
            const { adapter, admin, viem } = await deployAdapter();
            const publicClient = await viem.getPublicClient();

            // Send some ETH to the adapter
            await admin.sendTransaction({
                to: adapter.address,
                value: parseEther("1")
            });

            const balanceBefore = await publicClient.getBalance({ address: admin.account.address });

            await adapter.write.emergencyWithdraw([
                admin.account.address,
                parseEther("0.5")
            ]);

            const balanceAfter = await publicClient.getBalance({ address: admin.account.address });
            expect(balanceAfter > balanceBefore - parseEther("0.1")).to.be.true;
        });

        it("Should reject non-admin emergency withdraw", async function () {
            const { adapter, viem } = await deployAdapter();
            const [_, other] = await viem.getWalletClients();

            let reverted = false;
            try {
                await adapter.write.emergencyWithdraw([
                    other.account.address,
                    parseEther("0.1")
                ], { account: other.account });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    describe("View Functions", function () {
        it("Should check if proof is relayed", async function () {
            const { adapter } = await deployAdapter(false);

            const notRelayed = await adapter.read.isProofRelayed([testProofHash]);
            expect(notRelayed).to.be.false;

            await adapter.write.receiveProofFromL1([
                testProofHash,
                testProof,
                testPublicInputs,
                1n
            ]);

            const isRelayed = await adapter.read.isProofRelayed([testProofHash]);
            expect(isRelayed).to.be.true;
        });

        it("Should return correct stats", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);

            // Send multiple messages
            for (let i = 0; i < 3; i++) {
                const proofHash = keccak256(toBytes(`test-proof-${i}`));
                await adapter.write.sendProofToL2([
                    proofHash,
                    testProof,
                    testPublicInputs,
                    1000000n
                ], { value: parseEther("0.01") });
            }

            const stats = await adapter.read.getStats();
            expect(stats[0]).to.equal(3n); // 3 messages sent
            expect(stats[4]).to.equal(3n); // nonce is 3
        });

        it("Should return attestation details", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, subject] = await viem.getWalletClients();

            const attestationData = toHex("attestation-data");

            await adapter.write.syncAttestation([
                testAttestationId,
                subject.account.address,
                testSchemaId,
                attestationData
            ]);

            const attestation = await adapter.read.getAttestation([testAttestationId]);
            expect(attestation.synced).to.be.true;
            expect(attestation.timestamp > 0n).to.be.true;
        });
    });
});
