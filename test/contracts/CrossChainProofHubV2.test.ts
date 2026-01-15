import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("CrossChainProofHubV2", function () {
  let hub: any;
  let verifier: any;
  let owner: SignerWithAddress;
  let relayer1: SignerWithAddress;
  let relayer2: SignerWithAddress;
  let user: SignerWithAddress;

  const MINIMUM_STAKE = ethers.parseEther("10");
  const BATCH_TIMEOUT = 3600; // 1 hour

  beforeEach(async function () {
    [owner, relayer1, relayer2, user] = await ethers.getSigners();

    // Deploy verifier
    const Verifier = await ethers.getContractFactory("Groth16VerifierBLS12381");
    verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    // Deploy hub
    const Hub = await ethers.getContractFactory("CrossChainProofHubV2");
    hub = await Hub.deploy(await verifier.getAddress(), MINIMUM_STAKE);
    await hub.waitForDeployment();
  });

  describe("Deployment", function () {
    it("Should set correct verifier", async function () {
      expect(await hub.verifier()).to.equal(await verifier.getAddress());
    });

    it("Should set correct minimum stake", async function () {
      expect(await hub.minimumStake()).to.equal(MINIMUM_STAKE);
    });

    it("Should set correct owner", async function () {
      expect(await hub.owner()).to.equal(owner.address);
    });
  });

  describe("Relayer Registration", function () {
    it("Should register relayer with stake", async function () {
      await expect(hub.connect(relayer1).registerRelayer({ value: MINIMUM_STAKE }))
        .to.emit(hub, "RelayerRegistered")
        .withArgs(relayer1.address, MINIMUM_STAKE);

      expect(await hub.isRelayer(relayer1.address)).to.be.true;
    });

    it("Should revert with insufficient stake", async function () {
      const insufficientStake = MINIMUM_STAKE - ethers.parseEther("1");

      await expect(
        hub.connect(relayer1).registerRelayer({ value: insufficientStake })
      ).to.be.revertedWithCustomError(hub, "InsufficientStake");
    });

    it("Should revert if already registered", async function () {
      await hub.connect(relayer1).registerRelayer({ value: MINIMUM_STAKE });

      await expect(
        hub.connect(relayer1).registerRelayer({ value: MINIMUM_STAKE })
      ).to.be.revertedWithCustomError(hub, "AlreadyRegistered");
    });

    it("Should allow adding more stake", async function () {
      await hub.connect(relayer1).registerRelayer({ value: MINIMUM_STAKE });
      
      const additionalStake = ethers.parseEther("5");
      await expect(hub.connect(relayer1).addStake({ value: additionalStake }))
        .to.emit(hub, "StakeAdded")
        .withArgs(relayer1.address, additionalStake);

      expect(await hub.getRelayerStake(relayer1.address)).to.equal(MINIMUM_STAKE + additionalStake);
    });
  });

  describe("Relayer Deregistration", function () {
    beforeEach(async function () {
      await hub.connect(relayer1).registerRelayer({ value: MINIMUM_STAKE });
    });

    it("Should initiate withdrawal", async function () {
      await expect(hub.connect(relayer1).initiateWithdrawal())
        .to.emit(hub, "WithdrawalInitiated");
    });

    it("Should complete withdrawal after cooldown", async function () {
      await hub.connect(relayer1).initiateWithdrawal();

      // Fast forward past cooldown (default 7 days)
      await ethers.provider.send("evm_increaseTime", [7 * 24 * 60 * 60 + 1]);
      await ethers.provider.send("evm_mine", []);

      const balanceBefore = await ethers.provider.getBalance(relayer1.address);
      
      await hub.connect(relayer1).completeWithdrawal();

      const balanceAfter = await ethers.provider.getBalance(relayer1.address);
      expect(balanceAfter).to.be.gt(balanceBefore);
    });

    it("Should revert withdrawal before cooldown", async function () {
      await hub.connect(relayer1).initiateWithdrawal();

      await expect(
        hub.connect(relayer1).completeWithdrawal()
      ).to.be.revertedWithCustomError(hub, "CooldownNotComplete");
    });
  });

  describe("Proof Batching", function () {
    beforeEach(async function () {
      await hub.connect(relayer1).registerRelayer({ value: MINIMUM_STAKE });
    });

    it("Should create proof batch", async function () {
      const targetChain = 137; // Polygon
      const proofData = ethers.toUtf8Bytes("proof_data");

      await expect(hub.connect(relayer1).createBatch(targetChain))
        .to.emit(hub, "BatchCreated");
    });

    it("Should add proof to batch", async function () {
      const targetChain = 137;
      const tx = await hub.connect(relayer1).createBatch(targetChain);
      const receipt = await tx.wait();
      const event = receipt.logs.find((log: any) => log.fragment?.name === "BatchCreated");
      const batchId = event.args[0];

      const proof = ethers.toUtf8Bytes("0".repeat(768));
      const publicInputs = ethers.toUtf8Bytes("0".repeat(64));
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment"));

      await expect(hub.connect(user).submitProofToBatch(batchId, proof, publicInputs, commitment))
        .to.emit(hub, "ProofAddedToBatch")
        .withArgs(batchId, commitment);
    });

    it("Should revert when batch is full", async function () {
      const targetChain = 137;
      const tx = await hub.connect(relayer1).createBatch(targetChain);
      const receipt = await tx.wait();
      const event = receipt.logs.find((log: any) => log.fragment?.name === "BatchCreated");
      const batchId = event.args[0];

      // Fill batch (max 100 proofs default)
      const maxBatchSize = await hub.maxBatchSize();
      
      for (let i = 0; i < maxBatchSize; i++) {
        const proof = ethers.toUtf8Bytes("0".repeat(768));
        const publicInputs = ethers.toUtf8Bytes("0".repeat(64));
        const commitment = ethers.keccak256(ethers.toUtf8Bytes(`commitment${i}`));
        await hub.connect(user).submitProofToBatch(batchId, proof, publicInputs, commitment);
      }

      // Try to add one more
      const extraProof = ethers.toUtf8Bytes("0".repeat(768));
      const extraInputs = ethers.toUtf8Bytes("0".repeat(64));
      const extraCommitment = ethers.keccak256(ethers.toUtf8Bytes("extra"));

      await expect(
        hub.connect(user).submitProofToBatch(batchId, extraProof, extraInputs, extraCommitment)
      ).to.be.revertedWithCustomError(hub, "BatchFull");
    });
  });

  describe("Batch Finalization", function () {
    let batchId: string;

    beforeEach(async function () {
      await hub.connect(relayer1).registerRelayer({ value: MINIMUM_STAKE });

      const tx = await hub.connect(relayer1).createBatch(137);
      const receipt = await tx.wait();
      const event = receipt.logs.find((log: any) => log.fragment?.name === "BatchCreated");
      batchId = event.args[0];

      // Add some proofs
      for (let i = 0; i < 3; i++) {
        const proof = ethers.toUtf8Bytes("0".repeat(768));
        const publicInputs = ethers.toUtf8Bytes("0".repeat(64));
        const commitment = ethers.keccak256(ethers.toUtf8Bytes(`commitment${i}`));
        await hub.connect(user).submitProofToBatch(batchId, proof, publicInputs, commitment);
      }
    });

    it("Should finalize batch by relayer", async function () {
      const merkleRoot = ethers.keccak256(ethers.toUtf8Bytes("merkle_root"));

      await expect(hub.connect(relayer1).finalizeBatch(batchId, merkleRoot))
        .to.emit(hub, "BatchFinalized")
        .withArgs(batchId, merkleRoot, 3);
    });

    it("Should only allow batch creator to finalize", async function () {
      await hub.connect(relayer2).registerRelayer({ value: MINIMUM_STAKE });

      const merkleRoot = ethers.keccak256(ethers.toUtf8Bytes("merkle_root"));

      await expect(
        hub.connect(relayer2).finalizeBatch(batchId, merkleRoot)
      ).to.be.revertedWithCustomError(hub, "NotBatchCreator");
    });

    it("Should revert on empty batch", async function () {
      const emptyBatchTx = await hub.connect(relayer1).createBatch(42);
      const emptyReceipt = await emptyBatchTx.wait();
      const emptyEvent = emptyReceipt.logs.find((log: any) => log.fragment?.name === "BatchCreated");
      const emptyBatchId = emptyEvent.args[0];

      const merkleRoot = ethers.keccak256(ethers.toUtf8Bytes("merkle_root"));

      await expect(
        hub.connect(relayer1).finalizeBatch(emptyBatchId, merkleRoot)
      ).to.be.revertedWithCustomError(hub, "EmptyBatch");
    });
  });

  describe("Slashing", function () {
    beforeEach(async function () {
      await hub.connect(relayer1).registerRelayer({ value: MINIMUM_STAKE });
    });

    it("Should slash relayer for invalid proof", async function () {
      const initialStake = await hub.getRelayerStake(relayer1.address);
      const slashAmount = ethers.parseEther("1");
      const evidence = ethers.toUtf8Bytes("invalid_proof_evidence");

      await hub.slashRelayer(relayer1.address, slashAmount, evidence);

      const newStake = await hub.getRelayerStake(relayer1.address);
      expect(newStake).to.equal(initialStake - slashAmount);
    });

    it("Should emit SlashingExecuted event", async function () {
      const slashAmount = ethers.parseEther("1");
      const evidence = ethers.toUtf8Bytes("evidence");

      await expect(hub.slashRelayer(relayer1.address, slashAmount, evidence))
        .to.emit(hub, "RelayerSlashed")
        .withArgs(relayer1.address, slashAmount);
    });

    it("Should only allow owner to slash", async function () {
      const slashAmount = ethers.parseEther("1");
      const evidence = ethers.toUtf8Bytes("evidence");

      await expect(
        hub.connect(user).slashRelayer(relayer1.address, slashAmount, evidence)
      ).to.be.revertedWithCustomError(hub, "OwnableUnauthorizedAccount");
    });

    it("Should deregister relayer if stake below minimum", async function () {
      const slashAmount = MINIMUM_STAKE;
      const evidence = ethers.toUtf8Bytes("evidence");

      await hub.slashRelayer(relayer1.address, slashAmount, evidence);

      expect(await hub.isRelayer(relayer1.address)).to.be.false;
    });
  });

  describe("Configuration", function () {
    it("Should update minimum stake", async function () {
      const newMinStake = ethers.parseEther("20");

      await expect(hub.setMinimumStake(newMinStake))
        .to.emit(hub, "MinimumStakeUpdated")
        .withArgs(newMinStake);

      expect(await hub.minimumStake()).to.equal(newMinStake);
    });

    it("Should update max batch size", async function () {
      const newMaxSize = 200;

      await expect(hub.setMaxBatchSize(newMaxSize))
        .to.emit(hub, "MaxBatchSizeUpdated")
        .withArgs(newMaxSize);

      expect(await hub.maxBatchSize()).to.equal(newMaxSize);
    });

    it("Should update verifier", async function () {
      const NewVerifier = await ethers.getContractFactory("Groth16VerifierBLS12381");
      const newVerifier = await NewVerifier.deploy();
      await newVerifier.waitForDeployment();

      await expect(hub.setVerifier(await newVerifier.getAddress()))
        .to.emit(hub, "VerifierUpdated");
    });
  });

  describe("Queries", function () {
    it("Should return batch info", async function () {
      await hub.connect(relayer1).registerRelayer({ value: MINIMUM_STAKE });

      const tx = await hub.connect(relayer1).createBatch(137);
      const receipt = await tx.wait();
      const event = receipt.logs.find((log: any) => log.fragment?.name === "BatchCreated");
      const batchId = event.args[0];

      const batchInfo = await hub.getBatch(batchId);
      expect(batchInfo.targetChain).to.equal(137);
      expect(batchInfo.creator).to.equal(relayer1.address);
      expect(batchInfo.proofCount).to.equal(0);
    });

    it("Should return relayer info", async function () {
      await hub.connect(relayer1).registerRelayer({ value: MINIMUM_STAKE });

      const relayerInfo = await hub.getRelayerInfo(relayer1.address);
      expect(relayerInfo.stake).to.equal(MINIMUM_STAKE);
      expect(relayerInfo.isActive).to.be.true;
    });
  });

  describe("Pause Functionality", function () {
    it("Should prevent registration when paused", async function () {
      await hub.pause();

      await expect(
        hub.connect(relayer1).registerRelayer({ value: MINIMUM_STAKE })
      ).to.be.revertedWithCustomError(hub, "EnforcedPause");
    });

    it("Should prevent batch creation when paused", async function () {
      await hub.connect(relayer1).registerRelayer({ value: MINIMUM_STAKE });
      await hub.pause();

      await expect(
        hub.connect(relayer1).createBatch(137)
      ).to.be.revertedWithCustomError(hub, "EnforcedPause");
    });
  });
});
