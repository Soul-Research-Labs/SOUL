const { expect } = require("chai");
const { ethers } = require("hardhat");

/**
 * Integration Tests for PIL Protocol V2
 * Tests end-to-end flows between SDK patterns and smart contracts
 * Updated to match V2 contract interfaces
 */
describe("PIL Integration Tests", function () {
  let verifier;
  let stateContainer;
  let proofHub;
  let atomicSwap;
  let compliance;
  
  let owner;
  let alice;
  let bob;
  let relayer;

  // Test constants
  const MAX_BATCH_SIZE = 100;
  const BATCH_TIMEOUT = 3600; // 1 hour
  const MINIMUM_STAKE = ethers.parseEther("10");

  before(async function () {
    [owner, alice, bob, relayer] = await ethers.getSigners();

    // Deploy all core contracts
    console.log("Deploying contracts for integration tests...");

    // 1. Verifier
    const Verifier = await ethers.getContractFactory(
      "contracts/core/Groth16VerifierBLS12381.sol:Groth16VerifierBLS12381"
    );
    verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    // 2. State Container (V2)
    const StateContainer = await ethers.getContractFactory(
      "contracts/core/ConfidentialStateContainerV2.sol:ConfidentialStateContainer"
    );
    stateContainer = await StateContainer.deploy(await verifier.getAddress());
    await stateContainer.waitForDeployment();

    // 3. Proof Hub (V2 - with maxBatchSize, batchTimeout, minRelayerStake)
    const ProofHub = await ethers.getContractFactory("CrossChainProofHubV2");
    proofHub = await ProofHub.deploy(MAX_BATCH_SIZE, BATCH_TIMEOUT, MINIMUM_STAKE);
    await proofHub.waitForDeployment();

    // 4. Atomic Swap (V2 - with fee recipient)
    const AtomicSwap = await ethers.getContractFactory(
      "contracts/bridge/PILAtomicSwapV2.sol:PILAtomicSwapV2"
    );
    atomicSwap = await AtomicSwap.deploy(owner.address);
    await atomicSwap.waitForDeployment();

    // 5. Compliance (V2)
    const Compliance = await ethers.getContractFactory(
      "contracts/compliance/PILComplianceV2.sol:PILComplianceV2"
    );
    compliance = await Compliance.deploy();
    await compliance.waitForDeployment();

    console.log("All contracts deployed successfully");
  });

  describe("E2E: Confidential State Lifecycle", function () {
    it("should complete full state registration and transfer flow", async function () {
      // Simulate SDK encryption (in real SDK this uses AES-256-GCM)
      const secretData = "user_private_balance:1000";
      const encryptedState = ethers.toUtf8Bytes(
        Buffer.from(secretData).toString("base64")
      );

      // Generate commitment (SDK would use Pedersen commitment)
      const commitment = ethers.keccak256(
        ethers.solidityPacked(["bytes", "uint256"], [encryptedState, Date.now()])
      );

      // Generate nullifier (SDK would derive from private key)
      const nullifier = ethers.keccak256(
        ethers.solidityPacked(["address", "bytes32"], [alice.address, commitment])
      );

      // Proof data (placeholder - real SDK generates ZK proof)
      const proof = ethers.toUtf8Bytes("0".repeat(768));
      const publicInputs = ethers.toUtf8Bytes("0".repeat(64));

      // Step 1: Alice registers state
      const registerTx = await stateContainer
        .connect(alice)
        .registerState(encryptedState, commitment, nullifier, proof, publicInputs);
      
      await expect(registerTx)
        .to.emit(stateContainer, "StateRegistered")
        .withArgs(commitment, alice.address);

      // Verify state exists
      expect(await stateContainer.stateExists(commitment)).to.be.true;
      expect(await stateContainer.getStateOwner(commitment)).to.equal(alice.address);

      // Step 2: Alice transfers state to Bob
      const newEncryptedState = ethers.toUtf8Bytes(
        Buffer.from("new_encrypted_data").toString("base64")
      );
      const newCommitment = ethers.keccak256(
        ethers.solidityPacked(["bytes", "uint256"], [newEncryptedState, Date.now() + 1])
      );
      const newNullifier = ethers.keccak256(
        ethers.solidityPacked(["address", "bytes32"], [bob.address, newCommitment])
      );

      const transferTx = await stateContainer
        .connect(alice)
        .transferState(
          commitment,
          newEncryptedState,
          newCommitment,
          newNullifier,
          proof,
          publicInputs,
          bob.address
        );

      await expect(transferTx)
        .to.emit(stateContainer, "StateTransferred")
        .withArgs(commitment, newCommitment, bob.address);

      // Verify Bob owns new state
      expect(await stateContainer.getStateOwner(newCommitment)).to.equal(bob.address);
    });
  });

  describe("E2E: Cross-Chain Proof Relay", function () {
    it("should register relayer with stake", async function () {
      const tx = await proofHub
        .connect(relayer)
        .registerRelayer({ value: MINIMUM_STAKE });

      await expect(tx)
        .to.emit(proofHub, "RelayerRegistered")
        .withArgs(relayer.address, MINIMUM_STAKE);

      expect(await proofHub.registeredRelayers(relayer.address)).to.be.true;
    });

    it("should submit proofs and auto-batch them", async function () {
      const destChain = 137; // Polygon

      // Submit multiple proofs (V2 uses auto-batching)
      for (let i = 0; i < 3; i++) {
        const proof = ethers.toUtf8Bytes("0".repeat(768));
        const publicInputs = ethers.toUtf8Bytes("0".repeat(64));

        const tx = await proofHub
          .connect(alice)
          .submitProof(destChain, proof, publicInputs);

        await expect(tx).to.emit(proofHub, "ProofSubmitted");
      }

      // Get current batch and verify it has messages
      const currentBatchId = await proofHub.currentBatchId();
      expect(currentBatchId).to.not.equal(ethers.ZeroHash);
    });

    it("should seal batch and allow relayer to claim", async function () {
      // First seal the current batch (can be done by anyone if conditions met)
      const currentBatchId = await proofHub.currentBatchId();
      
      // Fast-forward time to allow batch sealing (batch timeout)
      await ethers.provider.send("evm_increaseTime", [BATCH_TIMEOUT + 1]);
      await ethers.provider.send("evm_mine");

      // Seal the batch
      const sealTx = await proofHub.connect(owner).sealBatch();
      await expect(sealTx).to.emit(proofHub, "BatchSealed");

      // Relayer claims the sealed batch - emits BatchRelayed
      const claimTx = await proofHub.connect(relayer).claimBatch(currentBatchId);
      await expect(claimTx)
        .to.emit(proofHub, "BatchRelayed")
        .withArgs(currentBatchId, relayer.address);
    });
  });

  describe("E2E: Atomic Swap Flow", function () {
    const ONE_HOUR = 3600;
    const SWAP_AMOUNT = ethers.parseEther("1");
    let swapId;
    let secret;
    let hashlock;

    before(function () {
      // Generate secret and hashlock (V2 uses bytes32 secret)
      secret = ethers.keccak256(ethers.toUtf8Bytes("my_super_secret_123"));
      hashlock = ethers.keccak256(ethers.solidityPacked(["bytes32"], [secret]));
    });

    it("should create atomic swap with ETH", async function () {
      const stealthCommitment = ethers.keccak256(ethers.toUtf8Bytes("stealth"));

      const tx = await atomicSwap
        .connect(alice)
        .createSwapETH(bob.address, hashlock, ONE_HOUR, stealthCommitment, {
          value: SWAP_AMOUNT,
        });

      const receipt = await tx.wait();
      const event = receipt.logs.find((log) => log.fragment?.name === "SwapCreated");
      swapId = event.args[0];

      expect(swapId).to.not.be.undefined;

      // Verify swap details through hashlock lookup
      const lookupSwapId = await atomicSwap.hashLockToSwap(hashlock);
      expect(lookupSwapId).to.equal(swapId);
    });

    it("should allow Bob to claim with correct secret", async function () {
      const bobBalanceBefore = await ethers.provider.getBalance(bob.address);

      const tx = await atomicSwap.connect(bob).claim(swapId, secret);

      await expect(tx).to.emit(atomicSwap, "SwapClaimed");

      const bobBalanceAfter = await ethers.provider.getBalance(bob.address);
      // Account for gas costs - balance should increase by roughly swap amount minus fees
      expect(bobBalanceAfter).to.be.gt(bobBalanceBefore);
    });
  });

  describe("E2E: Compliance KYC Flow", function () {
    it("should authorize compliance provider", async function () {
      await compliance.authorizeProvider(owner.address);
      expect(await compliance.authorizedProviders(owner.address)).to.be.true;
    });

    it("should verify KYC for user", async function () {
      const credentialHash = ethers.keccak256(ethers.toUtf8Bytes("kyc_data_hash"));
      const jurisdiction = ethers.encodeBytes32String("US").slice(0, 6); // bytes2

      // V2 uses verifyKYC with tier enum
      // KYCStatus: None=0, Pending=1, Approved=2, Rejected=3, Expired=4
      // KYCTier: Unverified=0, Basic=1, Standard=2, Enhanced=3, Institutional=4
      const tx = await compliance.verifyKYC(
        alice.address,
        1, // KYCTier.Basic
        credentialHash,
        jurisdiction
      );

      await expect(tx)
        .to.emit(compliance, "KYCVerified")
        .withArgs(alice.address, 1, owner.address);

      // Check KYC record - status should be Approved (2)
      const record = await compliance.kycRecords(alice.address);
      expect(record.status).to.equal(2); // KYCStatus.Approved
      expect(record.tier).to.equal(1); // KYCTier.Basic
    });

    it("should check KYC validity", async function () {
      // Alice should have valid KYC (Approved status = 2)
      const record = await compliance.kycRecords(alice.address);
      expect(record.status).to.equal(2); // Approved
      expect(record.expiresAt).to.be.gt(Math.floor(Date.now() / 1000));
      
      // Bob should not have KYC (None status = 0)
      const bobRecord = await compliance.kycRecords(bob.address);
      expect(bobRecord.status).to.equal(0); // None
    });
  });

  describe("E2E: Multi-Contract Interaction", function () {
    it("should perform compliant state transfer", async function () {
      // This test simulates a full flow:
      // 1. Check KYC compliance
      // 2. Register state
      // 3. Transfer with compliance check

      // Check Alice has valid KYC (Approved = 2)
      const record = await compliance.kycRecords(alice.address);
      const isCompliant = record.status === 2n; // KYCStatus.Approved
      expect(isCompliant).to.be.true;

      // Only proceed if compliant
      if (isCompliant) {
        const encryptedState = ethers.toUtf8Bytes("compliant_encrypted_data");
        const commitment = ethers.keccak256(
          ethers.solidityPacked(["bytes", "uint256"], [encryptedState, Date.now()])
        );
        const nullifier = ethers.keccak256(
          ethers.solidityPacked(["address", "bytes32", "string"], [alice.address, commitment, "compliant"])
        );
        const proof = ethers.toUtf8Bytes("0".repeat(768));
        const publicInputs = ethers.toUtf8Bytes("0".repeat(64));

        // Register compliant state
        await stateContainer
          .connect(alice)
          .registerState(encryptedState, commitment, nullifier, proof, publicInputs);

        expect(await stateContainer.stateExists(commitment)).to.be.true;
      }
    });

    it("should submit multiple proofs for relay", async function () {
      const destChain = 42161; // Arbitrum
      
      // Submit multiple proofs
      const proofCount = 3;
      for (let i = 0; i < proofCount; i++) {
        const proof = ethers.toUtf8Bytes("0".repeat(768));
        const publicInputs = ethers.toUtf8Bytes("0".repeat(64));

        await proofHub.connect(alice).submitProof(destChain, proof, publicInputs);
      }

      // Verify proofs were submitted (they go into current batch)
      const currentBatchId = await proofHub.currentBatchId();
      expect(currentBatchId).to.not.equal(ethers.ZeroHash);
    });
  });

  describe("E2E: Error Handling", function () {
    it("should reject double-spend attempts", async function () {
      const encryptedState = ethers.toUtf8Bytes("double_spend_test");
      const commitment = ethers.keccak256(
        ethers.solidityPacked(["bytes", "string"], [encryptedState, "unique1"])
      );
      const nullifier = ethers.keccak256(
        ethers.solidityPacked(["string"], ["double_spend_nullifier"])
      );
      const proof = ethers.toUtf8Bytes("0".repeat(768));
      const publicInputs = ethers.toUtf8Bytes("0".repeat(64));

      // First registration should succeed
      await stateContainer
        .connect(alice)
        .registerState(encryptedState, commitment, nullifier, proof, publicInputs);

      // Second attempt with same nullifier should fail
      const newCommitment = ethers.keccak256(
        ethers.solidityPacked(["bytes", "string"], [encryptedState, "unique2"])
      );

      await expect(
        stateContainer
          .connect(alice)
          .registerState(encryptedState, newCommitment, nullifier, proof, publicInputs)
      ).to.be.revertedWithCustomError(stateContainer, "NullifierAlreadyUsed");
    });

    it("should reject swap claim with wrong secret", async function () {
      const correctSecret = ethers.keccak256(ethers.toUtf8Bytes("correct_secret"));
      const hashlock = ethers.keccak256(ethers.solidityPacked(["bytes32"], [correctSecret]));
      const stealthCommitment = ethers.keccak256(ethers.toUtf8Bytes("stealth2"));
      const ONE_HOUR = 3600;

      // Create swap
      const tx = await atomicSwap
        .connect(alice)
        .createSwapETH(bob.address, hashlock, ONE_HOUR, stealthCommitment, {
          value: ethers.parseEther("0.1"),
        });
      const receipt = await tx.wait();
      const event = receipt.logs.find((log) => log.fragment?.name === "SwapCreated");
      const swapId = event.args[0];

      // Try to claim with wrong secret
      const wrongSecret = ethers.keccak256(ethers.toUtf8Bytes("wrong_secret"));

      await expect(
        atomicSwap.connect(bob).claim(swapId, wrongSecret)
      ).to.be.revertedWithCustomError(atomicSwap, "InvalidSecret");
    });

    it("should reject unregistered relayer actions", async function () {
      // Non-registered relayer tries to claim batch (they need to register first)
      const currentBatchId = await proofHub.currentBatchId();
      
      await expect(
        proofHub.connect(bob).claimBatch(currentBatchId)
      ).to.be.revertedWithCustomError(proofHub, "RelayerNotRegistered");
    });

    it("should reject KYC from unauthorized provider", async function () {
      const credentialHash = ethers.keccak256(ethers.toUtf8Bytes("fake_kyc"));
      const jurisdiction = ethers.encodeBytes32String("US").slice(0, 6);

      // Bob is not an authorized provider
      await expect(
        compliance.connect(bob).verifyKYC(alice.address, 1, credentialHash, jurisdiction)
      ).to.be.revertedWithCustomError(compliance, "NotAuthorizedProvider");
    });
  });
});
